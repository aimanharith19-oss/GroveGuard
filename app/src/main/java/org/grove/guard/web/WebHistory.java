/*
 * Groveguard — malware scanner, link guard and firewall for Android.
 * Copyright (C) 2026 Groveguard contributors.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package org.grove.guard.web;

import android.content.Context;

import org.grove.guard.App;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Every website opened in Grove Launcher's browser and every link you check, with whether it was blocked and why.
 * Kept only on this phone (never sent anywhere, not in backups); up to 50,000 visits, oldest dropped first.
 */
public final class WebHistory {
    private WebHistory() { }

    private static final int MAX = 50000;

    public static final class Visit {
        public final long time;
        public final String host, url, why, app;
        public final boolean blocked;

        public Visit(long time, String host, String url, boolean blocked, String why, String app) {
            this.time = time; this.host = host; this.url = url; this.blocked = blocked; this.why = why; this.app = app;
        }
    }

    private static File file(Context c) { return new File(c.getFilesDir(), "web-history.jsonl"); }

    private static long lastHostTime;
    private static String lastHost;

    /** Records a page visit (reloads of the same page within 3 seconds count once). */
    public static void add(final Context c, final String host, final String url, final boolean blocked, final String why, final String app) {
        long now = System.currentTimeMillis();
        synchronized (WebHistory.class) {
            if (url.equals(lastHost) && now - lastHostTime < 3000) return;
            lastHost = url; lastHostTime = now;
        }
        final long t = now;
        App.IO.execute(new Runnable() {
            @Override public void run() {
                synchronized (WebHistory.class) {
                    try (Writer w = new OutputStreamWriter(new FileOutputStream(file(c), true), StandardCharsets.UTF_8)) {
                        w.write(new JSONObject().put("t", t).put("h", host).put("u", url.length() > 2000 ? url.substring(0, 2000) : url)
                                .put("b", blocked).put("w", why == null ? "" : why).put("a", app == null ? "" : app).toString());
                        w.write('\n');
                    } catch (Exception ignored) { }
                    if (file(c).length() > MAX * 260L) trim(c);
                }
                WebFilter.changed();
            }
        });
    }

    /** Records visits sent by the browser extension (keeps their own times). */
    public static void addMany(Context c, List<Visit> list) {
        if (list.isEmpty()) return;
        synchronized (WebHistory.class) {
            try (Writer w = new OutputStreamWriter(new FileOutputStream(file(c), true), StandardCharsets.UTF_8)) {
                for (Visit v : list) {
                    w.write(new JSONObject().put("t", v.time).put("h", v.host).put("u", v.url).put("b", v.blocked).put("w", v.why).put("a", v.app).toString());
                    w.write('\n');
                }
            } catch (Exception ignored) { }
            if (file(c).length() > MAX * 260L) trim(c);
        }
        WebFilter.changed();
    }

    /** All visits, newest first. */
    public static List<Visit> all(Context c) {
        List<Visit> out = new ArrayList<>();
        synchronized (WebHistory.class) {
            File f = file(c);
            if (!f.exists()) return out;
            try (BufferedReader r = new BufferedReader(new InputStreamReader(new FileInputStream(f), StandardCharsets.UTF_8))) {
                String line;
                while ((line = r.readLine()) != null) {
                    try {
                        JSONObject o = new JSONObject(line);
                        out.add(new Visit(o.optLong("t"), o.optString("h"), o.optString("u"), o.optBoolean("b"), o.optString("w"), o.optString("a")));
                    } catch (Exception ignored) { }
                }
            } catch (Exception ignored) { }
        }
        Collections.sort(out, new java.util.Comparator<Visit>() {
            @Override public int compare(Visit x, Visit y) { return Long.compare(y.time, x.time); }
        });
        return out;
    }

    private static void trim(Context c) {
        List<Visit> all = all(c);
        Collections.reverse(all);
        int from = Math.max(0, all.size() - MAX * 9 / 10);
        rewrite(c, all.subList(from, all.size()));
    }

    private static void rewrite(Context c, List<Visit> oldestFirst) {
        File tmp = new File(c.getFilesDir(), "web-history.tmp");
        try (Writer w = new OutputStreamWriter(new FileOutputStream(tmp), StandardCharsets.UTF_8)) {
            for (Visit v : oldestFirst) {
                w.write(new JSONObject().put("t", v.time).put("h", v.host).put("u", v.url).put("b", v.blocked).put("w", v.why).put("a", v.app).toString());
                w.write('\n');
            }
        } catch (Exception e) { return; }
        //noinspection ResultOfMethodCallIgnored
        tmp.renameTo(file(c));
    }

    /** Deletes one visit (matched by time and address). */
    public static void delete(Context c, Visit v) {
        synchronized (WebHistory.class) {
            List<Visit> all = all(c);
            Collections.reverse(all);
            for (int i = 0; i < all.size(); i++) if (all.get(i).time == v.time && all.get(i).url.equals(v.url)) { all.remove(i); break; }
            rewrite(c, all);
        }
        WebFilter.changed();
    }

    /** Deletes everything, or only visits older than {@code olderThanMs} (0 = all). */
    public static void clear(Context c, long olderThanMs) {
        synchronized (WebHistory.class) {
            if (olderThanMs <= 0) { //noinspection ResultOfMethodCallIgnored
                file(c).delete(); }
            else {
                long cut = System.currentTimeMillis() - olderThanMs;
                List<Visit> keep = new ArrayList<>();
                List<Visit> all = all(c);
                Collections.reverse(all);
                for (Visit v : all) if (v.time >= cut) keep.add(v);
                rewrite(c, keep);
            }
        }
        WebFilter.changed();
    }
}
