/*
 * Grove Guard — malware scanner, link guard and firewall for Android.
 * Copyright (C) 2026 Grove Guard contributors.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package org.grove.guard.fw;

import android.content.Context;
import android.os.Build;

import org.grove.guard.Events;
import org.grove.guard.Prefs;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

/**
 * Stops apps running in the background, through Shizuku or root:
 * <pre>
 *   cmd appops set &lt;pkg&gt; RUN_ANY_IN_BACKGROUND ignore   (no background work, jobs, alarms or services)
 *   cmd appops set &lt;pkg&gt; RUN_IN_BACKGROUND ignore
 *   am set-standby-bucket &lt;pkg&gt; restricted               (Android 11+)
 * </pre>
 * Same switches as Android's own "Restricted" battery setting, applied in one go. They survive restarts.
 */
public final class Background {
    private Background() { }

    /** Apps restricted right now (asks Android; falls back to what Grove Guard set). Blocking. */
    public static Set<String> restricted(Context c) {
        Shell.Result r = Shell.run(c, "cmd appops query-op RUN_ANY_IN_BACKGROUND ignore");
        Set<String> out = new HashSet<>();
        if (r != null && r.ok()) {
            for (String line : r.out.split("\n")) {
                String t = line.trim();
                if (t.endsWith(":")) t = t.substring(0, t.length() - 1);
                if (t.startsWith("Package ")) t = t.substring(8).trim();
                if (Firewall.validPkg(t)) out.add(t);
            }
            Prefs.set(c, "bg_restricted", out);
            return out;
        }
        return Prefs.set(c, "bg_restricted");
    }

    /** Restricts or frees apps; {@code stop} also force-stops them now. Returns an error or null. Blocking. */
    public static String set(Context c, Collection<String> pkgs, boolean restrict, boolean stop) {
        StringBuilder sh = new StringBuilder();
        for (String p : pkgs) {
            if (!Firewall.validPkg(p) || p.equals(c.getPackageName())) continue;
            String mode = restrict ? "ignore" : "allow";
            sh.append("cmd appops set ").append(p).append(" RUN_ANY_IN_BACKGROUND ").append(mode).append('\n');
            sh.append("cmd appops set ").append(p).append(" RUN_IN_BACKGROUND ").append(mode).append('\n');
            if (Build.VERSION.SDK_INT >= 30) sh.append("am set-standby-bucket ").append(p).append(restrict ? " restricted" : " active").append(" 2>/dev/null\n");
            if (restrict && stop) sh.append("am force-stop ").append(p).append('\n');
        }
        if (sh.length() == 0) return null;
        Shell.Result r = Shell.run(c, sh.toString());
        if (r == null) return Firewall.noBackend(c);
        Set<String> local = Prefs.set(c, "bg_restricted");
        if (restrict) local.addAll(pkgs); else local.removeAll(pkgs);
        Prefs.set(c, "bg_restricted", local);
        if (r.out.toLowerCase().contains("exception") || r.out.toLowerCase().contains("error")) return r.out.trim().split("\n")[0];
        return null;
    }

    public static String forceStop(Context c, Collection<String> pkgs) {
        StringBuilder sh = new StringBuilder();
        for (String p : pkgs) if (Firewall.validPkg(p) && !p.equals(c.getPackageName())) sh.append("am force-stop ").append(p).append('\n');
        if (sh.length() == 0) return null;
        Shell.Result r = Shell.run(c, sh.toString());
        return r == null ? Firewall.noBackend(c) : null;
    }

    /** Kills every cached background process (apps restart if they're needed). */
    public static String killBackground(Context c) {
        Shell.Result r = Shell.run(c, "am kill-all");
        if (r == null) return Firewall.noBackend(c);
        Events.add(Events.INFO, "Cleared background processes", "");
        return null;
    }
}
