/*
 * Groveguard — malware scanner, link guard and firewall for Android.
 * Copyright (C) 2026 Groveguard contributors.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package org.grove.guard.fw;

import android.content.Context;
import android.os.Build;

import org.grove.guard.Events;

/** Uses Shizuku (or root) to grant Groveguard what it needs, instead of sending you through Android's settings screens. */
public final class Setup {
    private Setup() { }

    /** All-files access, notifications, and no battery restrictions (so realtime scanning isn't killed). Blocking. */
    public static String grantBasics(Context c) {
        String p = c.getPackageName();
        StringBuilder sh = new StringBuilder();
        if (Build.VERSION.SDK_INT >= 30) sh.append("appops set ").append(p).append(" MANAGE_EXTERNAL_STORAGE allow\n");
        else sh.append("pm grant ").append(p).append(" android.permission.READ_EXTERNAL_STORAGE; pm grant ").append(p).append(" android.permission.WRITE_EXTERNAL_STORAGE\n");
        if (Build.VERSION.SDK_INT >= 33) sh.append("pm grant ").append(p).append(" android.permission.POST_NOTIFICATIONS\n");
        sh.append("dumpsys deviceidle whitelist +").append(p).append(" >/dev/null\n");
        sh.append("cmd appops set ").append(p).append(" RUN_ANY_IN_BACKGROUND allow\n");
        Shell.Result r = Shell.run(c, sh.toString());
        if (r == null) return Firewall.noBackend(c);
        Events.add(Events.INFO, "Set up with " + Shell.backend(c), "File access, alerts and battery exemption granted");
        return null;
    }

}
