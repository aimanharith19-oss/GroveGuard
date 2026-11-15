/*
 * Groveguard — malware scanner, link guard and firewall for Android.
 * Copyright (C) 2026 Groveguard contributors.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package org.grove.guard.scan;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.Environment;
import android.os.FileObserver;
import android.os.Handler;
import android.os.HandlerThread;

import org.grove.guard.Events;
import org.grove.guard.StatusProvider;
import org.grove.guard.fw.Firewall;

import java.io.File;
import java.util.ArrayDeque;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * The realtime scanner: watches your storage (Downloads, where Firefox and other apps save files, included) and
 * scans every file as soon as it's written or moved in; also scans each newly installed or updated app.
 *
 * It has no notification of its own: it runs inside the Web protection accessibility service when that is on,
 * otherwise inside {@link org.grove.guard.RealtimeService}.
 *
 * Fixes over Hypatia: folders created after the scanner started are watched too (Hypatia only watched folders
 * that already existed); newly installed apps really are scanned (Hypatia's receiver ignored them, and Android
 * doesn't deliver that broadcast to manifest receivers any more); a burst of writes to one file is scanned once.
 */
public final class Watcher {
    private Watcher() { }

    private static final int MASK = FileObserver.CLOSE_WRITE | FileObserver.MOVED_TO | FileObserver.CREATE
            | FileObserver.DELETE_SELF | FileObserver.MOVE_SELF;
    private static final int MAX_WATCHES = 6000;

    private static final Map<String, Obs> observers = new HashMap<>();
    private static ExecutorService scanQueue;
    private static HandlerThread thread;
    private static Handler handler;
    private static Context app;
    private static String host;
    private static final AtomicInteger scanned = new AtomicInteger();
    private static final Map<String, Long> lastScan = new HashMap<>();
    private static BroadcastReceiver pkgReceiver;

    public static synchronized boolean running() { return host != null; }

    /** "accessibility" or "service", or null when off. */
    public static synchronized String host() { return host; }

    public static int filesScanned() { return scanned.get(); }

    public static synchronized void start(Context c, String hostName) {
        if (host != null) { host = hostName; return; }
        host = hostName;
        app = c.getApplicationContext();
        scanQueue = Executors.newSingleThreadExecutor();
        thread = new HandlerThread("GroveGuard-watch");
        thread.start();
        handler = new Handler(thread.getLooper());
        handler.post(new Runnable() {
            @Override public void run() {
                Sigs.loadNow(app);
                watchTree(Environment.getExternalStorageDirectory());
            }
        });
        pkgReceiver = new BroadcastReceiver() {
            @Override public void onReceive(Context ctx, Intent i) {
                if (i.getData() == null) return;
                final String pkg = i.getData().getSchemeSpecificPart();
                final boolean replacing = i.getBooleanExtra(Intent.EXTRA_REPLACING, false);
                if (Intent.ACTION_PACKAGE_ADDED.equals(i.getAction()) && !replacing) Firewall.onAppInstalled(app, pkg, false);
                scanQueue.execute(new Runnable() {
                    @Override public void run() {
                        int hits = Scanner.scanApp(app, pkg, replacing ? "app update" : "new app");
                        if (hits == 0) Events.add(Events.SCAN, (replacing ? "Updated app checked: " : "New app checked: ") + Detect.appName(app, pkg), "No known malware");
                    }
                });
            }
        };
        IntentFilter f = new IntentFilter();
        f.addAction(Intent.ACTION_PACKAGE_ADDED);
        f.addAction(Intent.ACTION_PACKAGE_REPLACED);
        f.addDataScheme("package");
        app.registerReceiver(pkgReceiver, f);
        Events.add(Events.SCAN, "Realtime scanning on", "accessibility".equals(hostName)
                ? "Running inside Web protection (no notification)" : "Running as a background service");
        StatusProvider.changed(app);
    }

    public static synchronized void stop() {
        if (host == null) return;
        host = null;
        try { app.unregisterReceiver(pkgReceiver); } catch (Exception ignored) { }
        final Handler h = handler;
        h.post(new Runnable() {
            @Override public void run() {
                synchronized (observers) {
                    for (Obs o : observers.values()) o.stopWatching();
                    observers.clear();
                }
                thread.quitSafely();
            }
        });
        scanQueue.shutdownNow();
        StatusProvider.changed(app);
    }

    private static void watchTree(File root) {
        ArrayDeque<File> stack = new ArrayDeque<>();
        stack.push(root);
        while (!stack.isEmpty()) {
            File d = stack.pop();
            String p = d.getAbsolutePath();
            synchronized (observers) {
                if (observers.containsKey(p) || observers.size() >= MAX_WATCHES) continue;
                Obs o = new Obs(d);
                observers.put(p, o);
                o.startWatching();
            }
            File[] kids = d.listFiles();
            if (kids == null) continue;
            for (File k : kids) {
                // skip hidden folders like .thumbnails and app-private Android/data (unreadable anyway)
                if (k.isDirectory() && !k.getName().startsWith(".") && depth(k) < 12
                        && !(k.getName().equals("Android") && d.equals(root))) stack.push(k);
            }
        }
    }

    private static int depth(File f) {
        int n = 0;
        for (File p = f; p != null; p = p.getParentFile()) n++;
        return n;
    }

    private static final class Obs extends FileObserver {
        final File dir;

        @SuppressWarnings("deprecation")
        Obs(File dir) { super(dir.getAbsolutePath(), MASK); this.dir = dir; }

        @Override public void onEvent(int event, String name) {
            event &= FileObserver.ALL_EVENTS;
            if ((event & (FileObserver.DELETE_SELF | FileObserver.MOVE_SELF)) != 0) {
                final String p = dir.getAbsolutePath();
                handler.post(new Runnable() {
                    @Override public void run() {
                        synchronized (observers) { Obs o = observers.remove(p); if (o != null) o.stopWatching(); }
                    }
                });
                return;
            }
            if (name == null) return;
            final File f = new File(dir, name);
            if ((event & (FileObserver.CREATE | FileObserver.MOVED_TO)) != 0 && f.isDirectory()) {
                if (!name.startsWith(".")) handler.post(new Runnable() { @Override public void run() { watchTree(f); } });
                return;
            }
            if ((event & (FileObserver.CLOSE_WRITE | FileObserver.MOVED_TO)) != 0) queue(f);
        }
    }

    private static void queue(final File f) {
        final String p = f.getAbsolutePath();
        synchronized (lastScan) {
            Long t = lastScan.get(p);
            if (t != null && System.currentTimeMillis() - t < 2000) return;
            lastScan.put(p, System.currentTimeMillis());
            if (lastScan.size() > 2000) lastScan.clear();
        }
        ExecutorService q = scanQueue;
        if (q == null || q.isShutdown()) return;
        try {
            q.execute(new Runnable() {
                @Override public void run() {
                    if (!f.isFile() || f.length() == 0 || f.length() > Scanner.MAX_SIZE_REALTIME) return;
                    Scanner.scanOne(app, f, "realtime", true);
                    if (scanned.incrementAndGet() % 20 == 0) StatusProvider.changed(app);
                }
            });
        } catch (Exception ignored) { }
    }
}
