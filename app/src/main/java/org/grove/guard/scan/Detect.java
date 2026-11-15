/*
 * Groveguard — malware scanner, link guard and firewall for Android.
 * Copyright (C) 2026 Groveguard contributors.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package org.grove.guard.scan;

import android.app.Notification;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;

import org.grove.guard.App;
import org.grove.guard.Events;
import org.grove.guard.MainActivity;
import org.grove.guard.PromptActivity;
import org.grove.guard.R;
import org.grove.guard.StatusProvider;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * What happens when something bad is found: a notification with actions, and an entry in the Threats list.
 * Threats are referred to by id in the notification actions (Hypatia put raw file paths in intents).
 */
public final class Detect {
    private Detect() { }

    public static final class Threat {
        public String id, path, type, sha256, origin, pkg;
        public long time;
        public int notifId;

        public String name() {
            int i = path.lastIndexOf('/');
            return i >= 0 ? path.substring(i + 1) : path;
        }
    }

    private static final List<Threat> threats = new ArrayList<>();
    private static boolean loaded;
    private static final Map<String, Long> recent = new HashMap<>();

    public static synchronized List<Threat> all() { load(); return new ArrayList<>(threats); }

    public static synchronized Threat find(String id) {
        load();
        for (Threat t : threats) if (t.id.equals(id)) return t;
        return null;
    }

    public static synchronized void remove(Context c, String id) {
        load();
        for (int i = 0; i < threats.size(); i++) {
            if (threats.get(i).id.equals(id)) {
                Threat t = threats.remove(i);
                c.getSystemService(NotificationManager.class).cancel(t.notifId);
                break;
            }
        }
        save();
        StatusProvider.changed(c);
    }

    /** Drops threats that are gone (file deleted, app uninstalled) and clears their notifications. */
    public static void prune(Context c) {
        List<String> gone = new ArrayList<>();
        for (Threat t : all()) {
            boolean exists;
            if (t.pkg != null) {
                try { c.getPackageManager().getApplicationInfo(t.pkg, 0); exists = true; } catch (PackageManager.NameNotFoundException e) { exists = false; }
            } else {
                // without file access every file looks missing; don't drop threats then
                boolean access = App.hasFileAccess(c)
                        || !t.path.startsWith(android.os.Environment.getExternalStorageDirectory().getAbsolutePath());
                exists = !access || new File(t.path).exists();
            }
            if (!exists) gone.add(t.id);
        }
        for (String id : gone) remove(c, id);
    }

    /** Called by every scan when a file matches. */
    public static void report(Context c, File f, String hashType, String sha256, String origin) {
        String path = f.getAbsolutePath();
        Threat t;
        synchronized (Detect.class) {
            load();
            Long prev = recent.get(path + sha256);
            if (prev != null && System.currentTimeMillis() - prev < 15000) return; // same file just alerted
            recent.put(path + sha256, System.currentTimeMillis());
            for (Threat old : threats) if (old.path.equals(path) && old.sha256.equals(sha256)) { old.time = System.currentTimeMillis(); save(); return; }
            t = new Threat();
            t.id = Long.toHexString(System.nanoTime()) + Integer.toHexString(path.hashCode());
            t.path = path; t.type = hashType; t.sha256 = sha256; t.origin = origin; t.time = System.currentTimeMillis();
            t.pkg = packageFor(c, path);
            t.notifId = 0x4000 + (int) (Math.abs(t.id.hashCode()) % 100000);
            threats.add(0, t);
            save();
        }
        Events.add(Events.THREAT, "Threat found: " + (t.pkg != null ? appName(c, t.pkg) : t.name()),
                Scanner.display(f) + " · matched " + hashType + " signature · " + origin);
        notifyThreat(c, t);
        StatusProvider.changed(c);
    }

    private static void notifyThreat(Context c, Threat t) {
        String title = t.pkg != null ? "Malware in app: " + appName(c, t.pkg) : "Malware found: " + t.name();
        String text = Scanner.display(new File(t.path)) + "\nMatched a " + t.type + " signature. ID " + t.sha256.substring(0, 8)
                + "\nSignature matches can occasionally be false alarms — look it up before deleting important files.";
        Notification.Builder b = new Notification.Builder(c, App.CH_ALERTS)
                .setSmallIcon(R.drawable.ic_stat)
                .setColor(0xFFC0392B)
                .setContentTitle(title)
                .setContentText(Scanner.display(new File(t.path)))
                .setStyle(new Notification.BigTextStyle().bigText(text))
                .setCategory(Notification.CATEGORY_ERROR)
                .setVisibility(Notification.VISIBILITY_PRIVATE)
                .setAutoCancel(false)
                .setContentIntent(PendingIntent.getActivity(c, t.notifId, new Intent(c, MainActivity.class).putExtra("tab", 0)
                        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK), PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT));
        b.addAction(action(c, t, PromptActivity.LOOKUP, "Look up", 1));
        if (t.pkg != null) b.addAction(action(c, t, PromptActivity.UNINSTALL, "Uninstall", 2));
        else if (new File(t.path).canWrite()) b.addAction(action(c, t, PromptActivity.DELETE, "Delete", 2));
        b.addAction(action(c, t, PromptActivity.IGNORE, "Ignore", 3));
        c.getSystemService(NotificationManager.class).notify(t.notifId, b.build());
    }

    private static Notification.Action action(Context c, Threat t, String act, String label, int n) {
        Intent i = new Intent(c, PromptActivity.class).setAction(act).putExtra("id", t.id).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        PendingIntent pi = PendingIntent.getActivity(c, t.notifId * 8 + n, i, PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
        return new Notification.Action.Builder(null, label, pi).build();
    }

    /** Which installed app (if any) a file belongs to. */
    public static String packageFor(Context c, String path) {
        if (!path.startsWith("/data/app/") && !path.startsWith("/mnt/expand/")) return null;
        for (ApplicationInfo ai : c.getPackageManager().getInstalledApplications(0)) {
            if (ai.sourceDir == null) continue;
            String dir = new File(ai.sourceDir).getParent();
            if (dir != null && path.startsWith(dir + "/")) return ai.packageName;
        }
        return null;
    }

    public static String appName(Context c, String pkg) {
        try {
            PackageManager pm = c.getPackageManager();
            return pm.getApplicationLabel(pm.getApplicationInfo(pkg, 0)).toString();
        } catch (Exception e) { return pkg; }
    }

    // ---------------------------------------------------------------- storage

    private static File file() { return new File(App.ctx().getFilesDir(), "threats.json"); }

    private static void load() {
        if (loaded) return;
        loaded = true;
        File f = file();
        if (!f.exists()) return;
        try (FileInputStream in = new FileInputStream(f)) {
            byte[] b = new byte[(int) f.length()];
            int off = 0, n;
            while (off < b.length && (n = in.read(b, off, b.length - off)) > 0) off += n;
            JSONArray a = new JSONArray(new String(b, 0, off, StandardCharsets.UTF_8));
            for (int i = 0; i < a.length(); i++) {
                JSONObject o = a.getJSONObject(i);
                Threat t = new Threat();
                t.id = o.getString("id"); t.path = o.getString("path"); t.type = o.optString("type"); t.sha256 = o.optString("sha256");
                t.origin = o.optString("origin"); t.pkg = o.isNull("pkg") ? null : o.optString("pkg", null); t.time = o.optLong("time");
                t.notifId = o.optInt("nid");
                threats.add(t);
            }
        } catch (Exception ignored) { }
    }

    private static void save() {
        try {
            JSONArray a = new JSONArray();
            for (Threat t : threats) {
                JSONObject o = new JSONObject().put("id", t.id).put("path", t.path).put("type", t.type).put("sha256", t.sha256)
                        .put("origin", t.origin).put("time", t.time).put("nid", t.notifId);
                if (t.pkg != null) o.put("pkg", t.pkg);
                a.put(o);
            }
            File tmp = new File(App.ctx().getFilesDir(), "threats.json.tmp");
            try (FileOutputStream out = new FileOutputStream(tmp)) { out.write(a.toString().getBytes(StandardCharsets.UTF_8)); }
            if (!tmp.renameTo(file())) tmp.delete();
        } catch (Exception ignored) { }
    }
}
