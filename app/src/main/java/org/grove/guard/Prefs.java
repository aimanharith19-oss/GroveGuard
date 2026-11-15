/*
 * Groveguard — malware scanner, link guard and firewall for Android.
 * Copyright (C) 2026 Groveguard contributors.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package org.grove.guard;

import android.content.Context;
import android.content.SharedPreferences;

import java.util.HashSet;
import java.util.Set;

/** All settings live in one preferences file. */
public final class Prefs {
    private Prefs() { }

    // scanner
    public static final String REALTIME = "realtime";            // realtime file scanning wanted
    public static final String EXTENDED = "sig_extended";        // extended MD5 database (~200 MB download)
    public static final String WEB = "web_protection";           // domain database + link guard
    public static final String SOURCE = "db_source";             // id of DatabaseSource, or "custom"
    public static final String CUSTOM_URL = "db_custom_url";
    public static final String CUSTOM_FP = "db_custom_fp";       // full key fingerprint for a custom server
    public static final String ONION = "onion_routing";          // download through Orbot
    public static final String AUTO_UPDATE = "auto_update";      // daily update
    public static final String AUTO_UPDATE_ANY_NET = "auto_update_metered";
    public static final String SCAN_APPS = "scan_apps", SCAN_STORAGE = "scan_storage", SCAN_SD = "scan_sd", SCAN_SYSTEM = "scan_system";
    public static final String SCAN_APPDATA = "scan_appdata";      // Android/data + obb through Shizuku/root
    public static final String WEB_ALL_APPS = "web_all_apps";    // scan on-screen text in every app, not just browser address bars
    public static final String WEB_AUTO_BACK = "web_auto_back";  // leave a dangerous site automatically
    public static final String WEB_ALLOW = "web_allow";          // domains you chose to allow
    // firewall
    public static final String FW_ENABLED = "fw_enabled";        // what you want (survives reboot)
    public static final String FW_MODE = "fw_mode";              // "block" (selected apps blocked) or "allow" (only selected apps allowed)
    public static final String FW_SELECTED = "fw_selected";
    public static final String FW_NEW_APPS = "fw_new_apps";      // block newly installed apps (block mode)
    public static final String FW_REAPPLY = "fw_reapply";        // re-apply after reboot
    public static final String FW_AUTOMATION = "fw_automation";  // other apps may control the firewall by broadcast
    public static final String FW_BACKEND = "fw_backend";        // "auto", "shizuku" or "root"
    public static final String FW_SYSTEM = "fw_show_system";
    public static final String FW_PROFILE = "fw_profile";        // id of the active profile, if any

    public static SharedPreferences sp(Context c) {
        return c.getApplicationContext().getSharedPreferences("guard", Context.MODE_PRIVATE);
    }

    public static boolean on(Context c, String key, boolean def) { return sp(c).getBoolean(key, def); }

    public static void set(Context c, String key, boolean v) { sp(c).edit().putBoolean(key, v).apply(); }

    public static String str(Context c, String key, String def) { return sp(c).getString(key, def); }

    public static void set(Context c, String key, String v) { sp(c).edit().putString(key, v).apply(); }

    public static Set<String> set(Context c, String key) { return new HashSet<>(sp(c).getStringSet(key, new HashSet<String>())); }

    public static void set(Context c, String key, Set<String> v) { sp(c).edit().putStringSet(key, new HashSet<>(v)).apply(); }
}
