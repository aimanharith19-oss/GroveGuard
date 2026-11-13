/*
 * Grove Guard — malware scanner, link guard and firewall for Android.
 * Copyright (C) 2026 Grove Guard contributors.
 * Hash-matching approach from Hypatia (Copyright (C) 2017-2018 Divested Computing Group), rewritten.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package org.grove.guard.scan;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.Environment;
import android.os.PowerManager;
import android.os.SystemClock;

import org.grove.guard.App;
import org.grove.guard.Events;
import org.grove.guard.Prefs;
import org.grove.guard.StatusProvider;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Hashes files (MD5, SHA-1 and SHA-256 in one read) and checks them against the signature databases.
 *
 * Fixes over Hypatia: a scan now shows real progress (files are counted first); directory loops through symlinks can't make it scan forever; cancel works immediately; the scan runs on
 * its own thread instead of a deprecated AsyncTask; the wake lock is renewed instead of expiring after 10 minutes
 * (which crashed long scans); and share scans no longer flip a global "cache" flag that other scans also read.
 */
public final class Scanner {
    public static final long MAX_SIZE = 500L * 1000 * 1000, MAX_SIZE_REALTIME = 250L * 1000 * 1000;

    public interface Listener {
        void onProgress(int done, int total, String current);
        void onFinished(Result r);
    }

    public static final class Result {
        public int files, matches;
        public long bytes, millis;
        public boolean cancelled, noDatabase;
        public final List<String> matched = new ArrayList<>();
    }

    /** One file's hashes. */
    public static final class Hashes {
        public String md5, sha1, sha256;
    }

    // ---------------------------------------------------------------- the manual scan (one at a time)

    private static volatile Scanner current;
    private static final CopyOnWriteArrayList<Listener> listeners = new CopyOnWriteArrayList<>();
    private static volatile int pDone, pTotal;
    private static volatile String pCurrent = "";
    private static volatile Result last;

    private volatile boolean cancel;

    public static void addListener(Listener l) { listeners.add(l); }

    public static void removeListener(Listener l) { listeners.remove(l); }

    public static boolean running() { return current != null; }

    public static int progressDone() { return pDone; }

    public static int progressTotal() { return pTotal; }

    public static String progressFile() { return pCurrent; }

    public static Result lastResult() { return last; }

    public static void cancel() { Scanner s = current; if (s != null) s.cancel = true; }

    /** Starts a full scan of the chosen places. */
    public static boolean start(final Context c) {
        if (current != null) return false;
        final Scanner s = new Scanner();
        current = s;
        pDone = 0; pTotal = 0; pCurrent = "Preparing…";
        StatusProvider.changed(c);
        new Thread(new Runnable() {
            @Override public void run() { s.runFull(c.getApplicationContext()); }
        }, "GroveGuard-scan").start();
        return true;
    }

    private void runFull(Context c) {
        PowerManager.WakeLock wl = ((PowerManager) c.getSystemService(Context.POWER_SERVICE))
                .newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "GroveGuard:scan");
        wl.setReferenceCounted(false);
        final Result r = new Result();
        long t0 = SystemClock.elapsedRealtime();
        try {
            wl.acquire(10 * 60 * 1000L);
            if (!Sigs.loaded()) {
                pCurrent = "Loading signatures…";
                post(0, 0);
                Sigs.loadNow(c);
            }
            if (!Sigs.loaded()) { r.noDatabase = true; return; }
            List<File> roots = roots(c);
            // count first so we can show a percentage (cheap: no reading)
            pCurrent = "Counting files…";
            post(0, 0);
            List<File> files = new ArrayList<>();
            collect(roots, files, MAX_SIZE);
            // Android/data and Android/obb: hidden from apps since Android 11, readable through Shizuku or root
            List<String> hidden = new ArrayList<>();
            if (Prefs.on(c, Prefs.SCAN_APPDATA, false) && org.grove.guard.fw.Shell.backend(c) != null) {
                pCurrent = "Listing app data folders…";
                post(0, 0);
                String root = Environment.getExternalStorageDirectory().getAbsolutePath();
                org.grove.guard.fw.Shell.Result lr = org.grove.guard.fw.Shell.run(c, "find " + root + "/Android/data " + root
                        + "/Android/obb -type f -size +0 -size -500000k 2>/dev/null");
                if (lr != null) for (String line : lr.out.split("\n")) if (line.startsWith("/")) hidden.add(line.trim());
            }
            pTotal = files.size() + hidden.size();
            long lastRenew = SystemClock.elapsedRealtime();
            for (File f : files) {
                if (cancel) { r.cancelled = true; break; }
                if (SystemClock.elapsedRealtime() - lastRenew > 5 * 60 * 1000L) { wl.acquire(10 * 60 * 1000L); lastRenew = SystemClock.elapsedRealtime(); }
                pCurrent = display(f);
                Hashes h = hash(f);
                pDone++;
                if (pDone % 25 == 0 || pDone == pTotal) post(pDone, pTotal);
                if (h == null) continue;
                r.files++;
                r.bytes += f.length();
                String type = match(h);
                if (type != null) {
                    r.matches++;
                    r.matched.add(display(f));
                    Detect.report(c, f, type, h.sha256, "full scan");
                }
            }
            for (String path : hidden) {
                if (cancel) { r.cancelled = true; break; }
                File f = new File(path);
                pCurrent = display(f);
                Hashes h = null;
                try (InputStream in = org.grove.guard.fw.Shell.stream(c, "cat " + org.grove.guard.fw.Shell.q(path))) {
                    if (in != null) h = hash(in);
                } catch (Exception ignored) { }
                pDone++;
                if (pDone % 25 == 0 || pDone == pTotal) post(pDone, pTotal);
                if (h == null || "d41d8cd98f00b204e9800998ecf8427e".equals(h.md5)) continue;
                r.files++;
                String type = match(h);
                if (type != null) {
                    r.matches++;
                    r.matched.add(display(f));
                    Detect.report(c, f, type, h.sha256, "full scan (app data)");
                }
            }
        } finally {
            r.millis = SystemClock.elapsedRealtime() - t0;
            if (wl.isHeld()) wl.release();
            last = r;
            current = null;
            if (r.noDatabase) Events.add(Events.ERROR, "Scan didn't run", "No signature database yet — update the database first.");
            else Events.add(r.matches > 0 ? Events.THREAT : Events.SCAN,
                    r.cancelled ? "Scan cancelled" : r.matches > 0 ? "Scan found " + r.matches + (r.matches == 1 ? " threat" : " threats") : "Scan finished — nothing found",
                    String.format(java.util.Locale.getDefault(), "%,d files · %s · %ds", r.files, Sigs.human(r.bytes), r.millis / 1000));
            Prefs.sp(c).edit().putLong("last_scan", System.currentTimeMillis()).apply();
            App.MAIN.post(new Runnable() { @Override public void run() { for (Listener l : listeners) l.onFinished(r); } });
            StatusProvider.changed(c);
        }
    }

    private static void post(final int done, final int total) {
        final String cur = pCurrent;
        App.MAIN.post(new Runnable() { @Override public void run() { for (Listener l : listeners) l.onProgress(done, total, cur); } });
    }

    /** The places chosen on the Protect screen. */
    static List<File> roots(Context c) {
        Set<File> s = new LinkedHashSet<>();
        if (Prefs.on(c, Prefs.SCAN_APPS, true)) {
            for (ApplicationInfo ai : c.getPackageManager().getInstalledApplications(PackageManager.GET_SHARED_LIBRARY_FILES)) {
                if (ai.sourceDir != null) s.add(new File(ai.sourceDir));
                if (ai.splitSourceDirs != null) for (String sp : ai.splitSourceDirs) s.add(new File(sp));
                if (ai.nativeLibraryDir != null) s.add(new File(ai.nativeLibraryDir));
            }
        }
        if (Prefs.on(c, Prefs.SCAN_STORAGE, true)) s.add(Environment.getExternalStorageDirectory());
        if (Prefs.on(c, Prefs.SCAN_SD, false)) {
            File[] vols = new File("/storage").listFiles();
            if (vols != null) for (File v : vols) if (!"emulated".equals(v.getName()) && !"self".equals(v.getName())) s.add(v);
        }
        if (Prefs.on(c, Prefs.SCAN_SYSTEM, false)) {
            for (String p : new String[]{"/system", "/system_ext", "/product", "/vendor", "/odm", "/apex", "/data/local/tmp", "/oem"}) s.add(new File(p));
        }
        return new ArrayList<>(s);
    }

    /** Walks the roots without recursion, skipping directory loops. */
    static void collect(List<File> roots, List<File> out, long maxSize) {
        Set<String> seenDirs = new HashSet<>();
        Set<String> seenFiles = new HashSet<>();
        ArrayDeque<File> stack = new ArrayDeque<>();
        for (File r : roots) stack.push(r);
        while (!stack.isEmpty()) {
            File f = stack.pop();
            String canon;
            try { canon = f.getCanonicalPath(); } catch (IOException e) { canon = f.getAbsolutePath(); }
            if (f.isDirectory()) {
                if (!seenDirs.add(canon)) continue;
                File[] kids = f.listFiles();
                if (kids != null) for (File k : kids) stack.push(k);
            } else if (f.isFile() && f.canRead() && f.length() <= maxSize && f.length() > 0) {
                if (seenFiles.add(canon)) out.add(f);
            }
        }
    }

    // ---------------------------------------------------------------- single files (realtime, shares, new apps)

    /** Scans one file now on the calling thread. Returns the matching hash type or null. Reports detections. */
    public static String scanOne(Context c, File f, String origin, boolean notify) {
        if (!Sigs.loaded()) Sigs.loadNow(c);
        if (!Sigs.loaded()) return null;
        Hashes h = hash(f);
        if (h == null) return null;
        String type = match(h);
        if (type != null && notify) Detect.report(c, f, type, h.sha256, origin);
        return type;
    }

    /** Scans every file of an installed app (APKs and native libraries). */
    public static int scanApp(Context c, String pkg, String origin) {
        try {
            ApplicationInfo ai = c.getPackageManager().getApplicationInfo(pkg, 0);
            List<File> roots = new ArrayList<>();
            if (ai.sourceDir != null) roots.add(new File(ai.sourceDir));
            if (ai.splitSourceDirs != null) for (String sp : ai.splitSourceDirs) roots.add(new File(sp));
            if (ai.nativeLibraryDir != null) roots.add(new File(ai.nativeLibraryDir));
            List<File> files = new ArrayList<>();
            collect(roots, files, MAX_SIZE);
            int hits = 0;
            for (File f : files) if (scanOne(c, f, origin, true) != null) hits++;
            return hits;
        } catch (PackageManager.NameNotFoundException e) {
            return 0;
        }
    }

    public static String match(Hashes h) {
        if (Sigs.matchSha256(h.sha256)) return "SHA-256";
        if (Sigs.matchSha1(h.sha1)) return "SHA-1";
        if (Sigs.matchMd5(h.md5)) return "MD5";
        return null;
    }

    public static Hashes hash(File f) {
        try (InputStream in = new FileInputStream(f)) {
            return hash(in);
        } catch (Exception e) {
            return null;
        }
    }

    public static Hashes hash(InputStream in) throws Exception {
        MessageDigest m5 = MessageDigest.getInstance("MD5"), s1 = MessageDigest.getInstance("SHA-1"), s2 = MessageDigest.getInstance("SHA-256");
        byte[] buf = new byte[1 << 16];
        int n;
        while ((n = in.read(buf)) > 0) { m5.update(buf, 0, n); s1.update(buf, 0, n); s2.update(buf, 0, n); }
        Hashes h = new Hashes();
        h.md5 = PgpVerify.hex(m5.digest()).toLowerCase(java.util.Locale.ROOT);
        h.sha1 = PgpVerify.hex(s1.digest()).toLowerCase(java.util.Locale.ROOT);
        h.sha256 = PgpVerify.hex(s2.digest()).toLowerCase(java.util.Locale.ROOT);
        return h;
    }

    /** "~/Download/x.apk" for files in your storage, the full path otherwise. */
    public static String display(File f) {
        String p = f.getAbsolutePath(), root = Environment.getExternalStorageDirectory().getAbsolutePath();
        return p.startsWith(root + "/") ? "~" + p.substring(root.length()) : p;
    }
}
