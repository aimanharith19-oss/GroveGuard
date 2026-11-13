/*
 * Grove Guard — malware scanner, link guard and firewall for Android.
 * Copyright (C) 2026 Grove Guard contributors.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package org.grove.guard.fw;

import android.content.Context;

import org.grove.guard.Prefs;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.concurrent.TimeUnit;

/** Runs firewall commands through Shizuku or root ("su"), whichever you chose (or whichever works). */
public final class Shell {
    private Shell() { }

    public static final class Result {
        public final int code;
        public final String out;

        Result(int code, String out) { this.code = code; this.out = out == null ? "" : out; }

        public boolean ok() { return code == 0; }
    }

    private static volatile Boolean rootOk;

    /** Which backend will be used right now: "shizuku", "root", or null if none can run commands. */
    public static String backend(Context c) {
        String pref = Prefs.str(c, Prefs.FW_BACKEND, "auto");
        if (!"root".equals(pref) && Shizuku.granted()) return "shizuku";
        if (!"shizuku".equals(pref) && Boolean.TRUE.equals(rootOk)) return "root";
        return null;
    }

    /** Human-readable status line for the backend card. */
    public static String status(Context c) {
        String pref = Prefs.str(c, Prefs.FW_BACKEND, "auto");
        if (!"root".equals(pref)) {
            if (Shizuku.granted()) return "Shizuku is running and Grove Guard is allowed";
            if (Shizuku.running()) return "Shizuku is running — tap to allow Grove Guard";
        }
        if (!"shizuku".equals(pref) && Boolean.TRUE.equals(rootOk)) return "Using root";
        if ("root".equals(pref)) return Boolean.FALSE.equals(rootOk) ? "Root access was denied" : "Tap to ask for root access";
        return Shizuku.installed(c) ? "Shizuku is installed but not running — start it in the Shizuku app"
                : "Needs Shizuku (or root). Tap to get Shizuku";
    }

    /** Asks su for root once (shows the root manager's prompt). Blocking: call from a background thread. */
    public static boolean probeRoot(Context c) {
        Result r = su("id");
        rootOk = r != null && r.out.contains("uid=0");
        if (rootOk) Prefs.set(c, "fw_root_seen", true);
        return rootOk;
    }

    public static boolean rootKnownOk() { return Boolean.TRUE.equals(rootOk); }

    /** Runs a shell script (stderr merged into stdout). Blocking. Returns null if no backend is available. */
    public static Result run(Context c, String script) {
        String b = backend(c);
        String s = "(" + script + ") 2>&1";
        if ("shizuku".equals(b)) return Shizuku.exec(s);
        if ("root".equals(b)) return su(s);
        // root chosen (or used before) but not asked yet since the app started, e.g. right after a reboot
        String pref = Prefs.str(c, Prefs.FW_BACKEND, "auto");
        if (rootOk == null && ("root".equals(pref) || ("auto".equals(pref) && Prefs.on(c, "fw_root_seen", false)))) {
            if (probeRoot(c)) return su(s);
        }
        return null;
    }

    /** Runs a script and returns its stdout as a stream (for reading files the app itself can't open). Null if unavailable. */
    public static java.io.InputStream stream(Context c, String script) {
        String b = backend(c);
        if ("shizuku".equals(b)) return Shizuku.openStream(script);
        if ("root".equals(b)) {
            try {
                final Process p = new ProcessBuilder("su", "-c", script).redirectErrorStream(false).start();
                p.getOutputStream().close();
                return new java.io.FilterInputStream(p.getInputStream()) {
                    @Override public void close() throws java.io.IOException { try { super.close(); } finally { p.destroy(); } }
                };
            } catch (Exception e) { return null; }
        }
        return null;
    }

    private static Result su(String script) {
        Process p = null;
        try {
            p = new ProcessBuilder("su", "-c", script).redirectErrorStream(true).start();
            ByteArrayOutputStream o = new ByteArrayOutputStream();
            try (InputStream in = p.getInputStream()) {
                byte[] buf = new byte[4096];
                int n;
                while ((n = in.read(buf)) > 0) o.write(buf, 0, n);
            }
            if (!p.waitFor(60, TimeUnit.SECONDS)) { p.destroy(); return new Result(-1, o.toString("UTF-8")); }
            return new Result(p.exitValue(), o.toString("UTF-8"));
        } catch (Exception e) {
            return null;
        } finally {
            if (p != null) try { p.getOutputStream().close(); } catch (Exception ignored) { }
        }
    }

    /** Quotes a value for sh. Package names are validated anyway; this is defence in depth. */
    public static String q(String s) { return "'" + s.replace("'", "'\\''") + "'"; }
}
