/*
 * Groveguard — malware scanner, link guard and firewall for Android.
 * Copyright (C) 2026 Groveguard contributors.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package org.grove.guard.fw;

import android.content.Context;
import android.content.Intent;
import android.content.pm.ResolveInfo;
import android.provider.Settings;
import android.view.inputmethod.InputMethodInfo;
import android.view.inputmethod.InputMethodManager;

import org.grove.guard.Events;
import org.grove.guard.scan.Detect;

import java.util.HashSet;
import java.util.Set;

/**
 * Disable, uninstall (also system apps, for your user only — reversible) and restore apps through Shizuku or root.
 * <pre>
 *   pm disable-user --user 0 &lt;pkg&gt;      pm enable &lt;pkg&gt;
 *   pm uninstall -k --user 0 &lt;pkg&gt;      cmd package install-existing &lt;pkg&gt;   (system apps: removed for you, restorable)
 *   pm uninstall &lt;pkg&gt;                  (apps you installed)
 * </pre>
 */
public final class Apps {
    private Apps() { }

    private static final String[] ESSENTIAL = {
            "android", "com.android.systemui", "com.android.settings", "com.android.shell", "com.android.phone",
            "com.android.providers.settings", "com.android.providers.telephony", "com.android.providers.media",
            "com.android.providers.media.module", "com.google.android.providers.media.module",
            "com.android.packageinstaller", "com.google.android.packageinstaller",
            "com.android.permissioncontroller", "com.google.android.permissioncontroller",
            "com.android.networkstack", "com.google.android.networkstack", "com.android.server.telecom",
            "com.android.externalstorage", "com.android.documentsui", "com.google.android.documentsui",
            "com.android.se", "com.android.bluetooth", "com.android.nfc", "com.android.location.fused",
            "com.android.keychain", "com.android.inputdevices", "com.android.wifi.resources",
            Shizuku.MANAGER,
    };

    /** Apps that would break the phone (or Groveguard) if removed or disabled: the home screen, keyboard, system UI… */
    public static Set<String> essential(Context c) {
        Set<String> s = new HashSet<>();
        for (String p : ESSENTIAL) s.add(p);
        s.add(c.getPackageName());
        try {
            ResolveInfo home = c.getPackageManager().resolveActivity(new Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_HOME), 0);
            if (home != null && home.activityInfo != null) s.add(home.activityInfo.packageName);
        } catch (Exception ignored) { }
        try {
            String ime = Settings.Secure.getString(c.getContentResolver(), Settings.Secure.DEFAULT_INPUT_METHOD);
            if (ime != null && ime.contains("/")) s.add(ime.substring(0, ime.indexOf('/')));
            InputMethodManager imm = c.getSystemService(InputMethodManager.class);
            if (imm != null) for (InputMethodInfo i : imm.getEnabledInputMethodList()) if (i.getPackageName() != null && imm.getEnabledInputMethodList().size() == 1) s.add(i.getPackageName());
        } catch (Exception ignored) { }
        return s;
    }

    public static final String DISABLE = "disable", ENABLE = "enable", UNINSTALL = "uninstall", RESTORE = "restore",
            STOP = "stop", CLEAR = "clear";

    /** Runs one action. Returns null on success or the error. Blocking. */
    public static String run(Context c, String action, String pkg, boolean system) {
        if (!Firewall.validPkg(pkg)) return "Invalid package";
        if ((DISABLE.equals(action) || UNINSTALL.equals(action) || CLEAR.equals(action)) && essential(c).contains(pkg))
            return "Protected: removing or disabling it can stop your phone (or Groveguard) from working";
        String label = Detect.appName(c, pkg);
        String cmd;
        switch (action) {
            case DISABLE: cmd = "pm disable-user --user 0 " + pkg; break;
            case ENABLE: cmd = "pm enable " + pkg; break;
            case UNINSTALL: cmd = system ? "pm uninstall -k --user 0 " + pkg : "pm uninstall " + pkg; break;
            case RESTORE: cmd = "cmd package install-existing " + pkg; break;
            case STOP: cmd = "am force-stop " + pkg; break;
            case CLEAR: cmd = "pm clear " + pkg; break;
            default: return "Unknown action";
        }
        Shell.Result r = Shell.run(c, cmd);
        if (r == null) return Firewall.noBackend(c);
        String out = r.out.trim();
        boolean ok = r.ok() && !out.toLowerCase().contains("failure") && !out.toLowerCase().contains("exception") && !out.toLowerCase().contains("error");
        if (!ok) return out.isEmpty() ? "Android refused (exit " + r.code + ")" : out.split("\n")[0];
        String what = DISABLE.equals(action) ? "Disabled " : ENABLE.equals(action) ? "Enabled " : UNINSTALL.equals(action) ? (system ? "Removed " : "Uninstalled ")
                : RESTORE.equals(action) ? "Restored " : STOP.equals(action) ? "Force-stopped " : "Cleared data of ";
        Events.add(Events.INFO, what + label, pkg + (UNINSTALL.equals(action) && system ? " · restore it any time in the Apps tab" : ""));
        return null;
    }
}
