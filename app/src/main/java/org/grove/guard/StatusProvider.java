/*
 * Groveguard — malware scanner, link guard and firewall for Android.
 * Copyright (C) 2026 Groveguard contributors.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package org.grove.guard;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;

import org.grove.guard.fw.Firewall;
import org.grove.guard.fw.Shell;
import org.grove.guard.scan.Detect;
import org.grove.guard.scan.Scanner;
import org.grove.guard.scan.Sigs;
import org.grove.guard.scan.Watcher;

import java.util.List;

/**
 * Read-only status for Canopy Launcher's feed card (or any app): is realtime scanning on, Web protection,
 * the database, threats, the firewall. Contains no file contents or browsing history — only on/off states,
 * counts, and the latest few Activity lines. Observe {@link #STATUS} for changes.
 * <pre>
 *   content://org.grove.guard.status/status   one row, see COLUMNS
 *   content://org.grove.guard.status/events   latest 20 Activity entries: time, kind, title, detail
 * </pre>
 */
public class StatusProvider extends ContentProvider {
    public static final String AUTHORITY = "org.grove.guard.status";
    public static final Uri STATUS = Uri.parse("content://" + AUTHORITY + "/status");
    public static final Uri EVENTS = Uri.parse("content://" + AUTHORITY + "/events");

    public static final String[] COLUMNS = {
            "realtime",        // 1 if realtime scanning is running
            "realtime_wanted", // 1 if switched on (may be starting)
            "web",             // 1 if Web protection (link guard) service is running
            "db_loaded",       // 1 if signatures are loaded
            "signatures",      // approximate number of signatures
            "db_updated",      // ms since epoch of the last successful update (0 = never)
            "scanning",        // 1 while a full scan runs
            "scan_progress",   // 0..100
            "threats",         // number of open threats
            "last_threat",     // name of the newest threat, or null
            "last_threat_time",
            "firewall",        // 1 if the firewall rules are active
            "firewall_wanted", // 1 if switched on (may be waiting for Shizuku after a restart)
            "firewall_mode",   // "block" or "allow"
            "blocked",         // number of apps blocked right now
            "profile",         // active profile name or null
            "backend",         // "shizuku", "root" or null
            "summary",         // one line, e.g. "Protected · 1.7M signatures"
    };

    private static volatile boolean scheduled;

    /** Tell observers (Canopy's feed card) something changed. Cheap; bursts are merged into one notification. */
    public static void changed(final Context c) {
        if (c == null || scheduled) return;
        scheduled = true;
        final Context a = c.getApplicationContext();
        App.MAIN.postDelayed(new Runnable() {
            @Override public void run() {
                scheduled = false;
                try { a.getContentResolver().notifyChange(STATUS, null, false); } catch (Exception ignored) { }
            }
        }, 300);
    }

    @Override public boolean onCreate() { return true; }

    private void enforce() {
        Context c = getContext();
        if (c == null || !Trust.trustedUid(c, android.os.Binder.getCallingUid()))
            throw new SecurityException("Only Grove Launcher may read Groveguard's status");
    }

    /**
     * For the trusted Grove Launcher (identified by Android, not by what it claims):
     * <pre>
     *   call("checkUrl", "https://…", null) → dangerous (bool), host, listed, ready (website list loaded)
     *   call("control", "&lt;action&gt;", extras)  → same actions and extras as the automation broadcasts (no key needed)
     * </pre>
     */
    @Override public android.os.Bundle call(String method, String arg, android.os.Bundle extras) {
        enforce();
        final Context c = getContext();
        android.os.Bundle out = new android.os.Bundle();
        if ("checkRequest".equals(method) && arg != null) {
            // Grove Launcher's browser: every page and request it loads (extras: page = page host, main = boolean, type)
            org.grove.guard.web.WebFilter.Verdict v = org.grove.guard.web.WebFilter.check(c, arg, extras == null ? null : extras.getString("page"),
                    extras != null && extras.getBoolean("main"), extras == null ? null : extras.getString("type"), "Grove Launcher");
            out.putBoolean("block", v.block);
            out.putString("kind", v.kind);
            out.putString("why", v.why);
            return out;
        }
        if ("css".equals(method)) { out.putString("css", org.grove.guard.web.WebFilter.css(c, arg)); return out; }
        if ("webStatus".equals(method)) {
            out.putBoolean("enabled", org.grove.guard.web.WebFilter.enabled(c));
            out.putInt("rules", org.grove.guard.web.WebFilter.activeRules());
            out.putBoolean("paused", arg != null && org.grove.guard.web.WebFilter.paused(c, arg));
            return out;
        }
        if ("checkUrl".equals(method)) {
            String host = org.grove.guard.scan.WebCheck.hostOfAddress(arg);
            if (host == null) { java.util.List<String> h = org.grove.guard.scan.WebCheck.hosts(arg); host = h.isEmpty() ? null : h.get(0); }
            org.grove.guard.scan.WebCheck.Hit hit = host == null ? null : org.grove.guard.scan.WebCheck.check(c, host);
            if (!Sigs.domainsLoaded()) Sigs.ensureLoaded(c);
            out.putBoolean("ready", Sigs.domainsLoaded());
            out.putBoolean("dangerous", hit != null);
            out.putString("host", host);
            if (hit != null) {
                out.putString("listed", hit.listed);
                Events.add(Events.WEB, "Dangerous site opened in Grove Launcher: " + org.grove.guard.scan.WebCheck.defang(hit.host), "Checked by the launcher's browser");
            }
            return out;
        }
        if ("control".equals(method) && arg != null) {
            android.content.Intent i = new android.content.Intent(arg);
            if (extras != null) i.putExtras(extras);
            final android.content.Intent fi = i;
            App.MAIN.post(new Runnable() { @Override public void run() { org.grove.guard.fw.AutomationReceiver.handle(c, fi, null); } });
            out.putBoolean("ok", true);
            return out;
        }
        return out;
    }

    @Override public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs, String sortOrder) {
        enforce();
        Context c = getContext();
        if (c == null) return null;
        if ("events".equals(uri.getLastPathSegment())) {
            MatrixCursor m = new MatrixCursor(new String[]{"time", "kind", "title", "detail"});
            int n = 0;
            for (Events.Event e : Events.all()) {
                if (n++ >= 20) break;
                // don't reveal which (listed) sites you visited to other apps: keep only "Dangerous site opened in Firefox"
                String title = e.title, detail = e.detail;
                if (Events.WEB.equals(e.kind) || Events.INFO.equals(e.kind)) {
                    int i = title.indexOf(": ");
                    if (i > 0) title = title.substring(0, i);
                    if (title.startsWith("Allowed ")) title = "Allowed a site";
                    detail = "";
                }
                m.addRow(new Object[]{e.time, e.kind, title, detail});
            }
            m.setNotificationUri(c.getContentResolver(), STATUS);
            return m;
        }
        MatrixCursor m = new MatrixCursor(COLUMNS, 1);
        List<Detect.Threat> th = Detect.all();
        Detect.Threat last = th.isEmpty() ? null : th.get(0);
        int total = Scanner.progressTotal();
        m.addRow(new Object[]{
                Watcher.running() ? 1 : 0,
                Prefs.on(c, Prefs.REALTIME, false) ? 1 : 0,
                0, // web protection is a browser extension now; the app can't see it
                Sigs.loaded() ? 1 : 0,
                Sigs.count(),
                Sigs.lastUpdate(c),
                Scanner.running() ? 1 : 0,
                total > 0 ? Scanner.progressDone() * 100 / total : 0,
                th.size(),
                last == null ? null : (last.pkg != null ? Detect.appName(c, last.pkg) : last.name()),
                last == null ? 0 : last.time,
                Firewall.active(c) ? 1 : 0,
                Firewall.wanted(c) ? 1 : 0,
                Firewall.mode(c),
                Firewall.blockedCount(c),
                Firewall.activeProfileName(c),
                Shell.backend(c),
                summary(c),
        });
        m.setNotificationUri(c.getContentResolver(), STATUS);
        return m;
    }

    public static String summary(Context c) {
        if (!Detect.all().isEmpty()) return Detect.all().size() == 1 ? "1 threat needs attention" : Detect.all().size() + " threats need attention";
        if (Scanner.running()) return "Scanning…";
        if (!Sigs.downloaded(c)) return "Database not downloaded";
        return Prefs.on(c, Prefs.REALTIME, false) ? "Protected" : "Realtime scanning off";
    }

    @Override public String getType(Uri uri) { return "vnd.android.cursor.item/vnd.org.grove.guard.status"; }
    @Override public Uri insert(Uri uri, ContentValues values) { return null; }
    @Override public int delete(Uri uri, String selection, String[] selectionArgs) { return 0; }
    @Override public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) { return 0; }
}
