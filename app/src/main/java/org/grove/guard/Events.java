/*
 * Grove Guard — malware scanner, link guard and firewall for Android.
 * Copyright (C) 2026 Grove Guard contributors.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package org.grove.guard;

import android.content.Context;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * The Activity tab: a short history of what Grove Guard did (scans, updates, alerts, firewall changes).
 * Replaces Hypatia's log text view, which re-opened the app whenever the background scanner wrote to it.
 * Kept in a small file on the phone only.
 */
public final class Events {
    private Events() { }

    public static final String SCAN = "scan", THREAT = "threat", WEB = "web", DB = "db", FW = "fw", INFO = "info", ERROR = "error";
    private static final int MAX = 300;

    public static final class Event {
        public final long time;
        public final String kind, title, detail;

        Event(long time, String kind, String title, String detail) {
            this.time = time; this.kind = kind; this.title = title; this.detail = detail == null ? "" : detail;
        }
    }

    public interface Listener { void onEvent(Event e); }

    private static final List<Event> list = new ArrayList<>();
    private static final CopyOnWriteArrayList<Listener> listeners = new CopyOnWriteArrayList<>();
    private static boolean loaded;

    public static void addListener(Listener l) { listeners.add(l); }

    public static void removeListener(Listener l) { listeners.remove(l); }

    public static void add(String kind, String title, String detail) {
        final Event e = new Event(System.currentTimeMillis(), kind, title, detail);
        synchronized (list) {
            load();
            list.add(0, e);
            while (list.size() > MAX) list.remove(list.size() - 1);
        }
        App.IO.execute(SAVE);
        App.MAIN.post(new Runnable() { @Override public void run() { for (Listener l : listeners) l.onEvent(e); } });
        StatusProvider.changed(App.ctx());
    }

    public static List<Event> all() {
        synchronized (list) { load(); return new ArrayList<>(list); }
    }

    public static void clear() {
        synchronized (list) { load(); list.clear(); }
        App.IO.execute(SAVE);
        App.MAIN.post(new Runnable() { @Override public void run() { for (Listener l : listeners) l.onEvent(null); } });
    }

    private static final Runnable SAVE = new Runnable() { @Override public void run() { save(); } };

    private static File file() { return new File(App.ctx().getFilesDir(), "events.json"); }

    private static void load() {
        if (loaded) return;
        loaded = true;
        try (FileInputStream in = new FileInputStream(file())) {
            byte[] b = new byte[(int) file().length()];
            int off = 0, n;
            while (off < b.length && (n = in.read(b, off, b.length - off)) > 0) off += n;
            JSONArray a = new JSONArray(new String(b, 0, off, StandardCharsets.UTF_8));
            for (int i = 0; i < a.length(); i++) {
                JSONObject o = a.getJSONObject(i);
                list.add(new Event(o.optLong("t"), o.optString("k"), o.optString("ti"), o.optString("d")));
            }
        } catch (Exception ignored) { }
    }

    private static void save() {
        try {
            JSONArray a = new JSONArray();
            synchronized (list) {
                for (Event e : list) a.put(new JSONObject().put("t", e.time).put("k", e.kind).put("ti", e.title).put("d", e.detail));
            }
            File tmp = new File(App.ctx().getFilesDir(), "events.json.tmp");
            try (FileOutputStream out = new FileOutputStream(tmp)) { out.write(a.toString().getBytes(StandardCharsets.UTF_8)); }
            if (!tmp.renameTo(file())) tmp.delete();
        } catch (Exception ignored) { }
    }

    /** Short "5 min ago" style time. */
    public static String ago(Context c, long t) {
        if (t <= 0) return "never";
        long s = (System.currentTimeMillis() - t) / 1000;
        if (s < 60) return "just now";
        if (s < 3600) return (s / 60) + " min ago";
        if (s < 86400) return (s / 3600) + " h ago";
        if (s < 86400 * 30) return (s / 86400) + (s / 86400 == 1 ? " day ago" : " days ago");
        return android.text.format.DateFormat.getMediumDateFormat(c).format(new java.util.Date(t));
    }
}
