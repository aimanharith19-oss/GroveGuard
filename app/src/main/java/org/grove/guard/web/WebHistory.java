/*
 * Groveguard — malware scanner, link guard and firewall for Android.
 * Copyright (C) 2026 Groveguard contributors.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package org.grove.guard.web;

import android.content.Context;

import org.grove.guard.App;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * The websites Grove Launcher's browser has opened, shown on the Websites tab. Kept in one small file on the phone;
 * only Grove Launcher can add to it and nothing reads it back out of Groveguard except you, in the app.
 */
public final class WebHistory {
    private WebHistory() { }

    public static final class Visit {
        public final String url, title;
        public final long time;
        Visit(String url, String title, long time) { this.url = url; this.title = title; this.time = time; }
    }

    private static final int MAX = 1000;
    private static final List<Visit> list = new ArrayList<>(); // newest first
    private static boolean loaded;

    private static File file() { return new File(App.ctx().getFilesDir(), "web_history.json"); }

    private static void load() {
        if (loaded) return;
        loaded = true;
        File f = file();
        if (!f.exists() || f.length() > 4L * 1024 * 1024) return;
        try (FileInputStream in = new FileInputStream(f)) {
            ByteArrayOutputStream b = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) > 0) b.write(buf, 0, n);
            JSONArray a = new JSONArray(b.toString("UTF-8"));
            for (int i = 0; i < a.length(); i++) {
                JSONObject o = a.getJSONObject(i);
                list.add(new Visit(o.optString("url"), o.optString("title"), o.optLong("time")));
            }
        } catch (Throwable ignored) { list.clear(); }
    }

    public static void add(String url, String title) {
        if (url == null || !(url.startsWith("http://") || url.startsWith("https://")) || url.length() > 2000) return;
        if (title == null) title = "";
        if (title.length() > 200) title = title.substring(0, 200);
        synchronized (list) {
            load();
            if (!list.isEmpty() && list.get(0).url.equals(url)) list.remove(0);
            list.add(0, new Visit(url, title, System.currentTimeMillis()));
            while (list.size() > MAX) list.remove(list.size() - 1);
        }
        App.IO.execute(SAVE);
    }

    public static List<Visit> all() { synchronized (list) { load(); return new ArrayList<>(list); } }

    public static void clear() {
        synchronized (list) { load(); list.clear(); }
        App.IO.execute(SAVE);
    }

    public static void remove(Visit v) {
        synchronized (list) { load(); list.remove(v); }
        App.IO.execute(SAVE);
    }

    private static final Runnable SAVE = new Runnable() {
        @Override public void run() {
            JSONArray a = new JSONArray();
            synchronized (list) {
                try { for (Visit v : list) a.put(new JSONObject().put("url", v.url).put("title", v.title).put("time", v.time)); } catch (Exception ignored) { }
            }
            try {
                File f = file(), tmp = new File(f.getPath() + ".tmp");
                try (FileOutputStream o = new FileOutputStream(tmp)) { o.write(a.toString().getBytes("UTF-8")); }
                //noinspection ResultOfMethodCallIgnored
                tmp.renameTo(f);
            } catch (Throwable ignored) { }
        }
    };

    /** Host of an address, for showing under the title. */
    public static String host(String url) {
        try { String h = android.net.Uri.parse(url).getHost(); return h == null ? url : h; } catch (Exception e) { return url; }
    }
}
