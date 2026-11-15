/*
 * Groveguard — malware scanner, link guard and firewall for Android.
 * Copyright (C) 2026 Groveguard contributors.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package org.grove.guard;

import android.app.Application;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.Context;
import android.os.Handler;
import android.os.Looper;

import org.grove.guard.fw.Firewall;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class App extends Application {
    public static final Handler MAIN = new Handler(Looper.getMainLooper());
    /** General background work (database, firewall commands, UI loading). */
    public static final ExecutorService IO = Executors.newFixedThreadPool(3);

    public static final String CH_ALERTS = "alerts";       // malware and dangerous-site alerts
    public static final String CH_BACKGROUND = "background"; // the realtime scanner's required (silent) notification
    public static final String CH_FIREWALL = "firewall";   // firewall needs attention (after reboot, etc.)

    private static App app;

    public static App get() { return app; }

    @Override public void onCreate() {
        super.onCreate();
        app = this;
        NotificationManager nm = getSystemService(NotificationManager.class);
        NotificationChannel alerts = new NotificationChannel(CH_ALERTS, "Threat alerts", NotificationManager.IMPORTANCE_HIGH);
        alerts.setDescription("Malware found in a file, or a dangerous website opened");
        nm.createNotificationChannel(alerts);
        NotificationChannel bg = new NotificationChannel(CH_BACKGROUND, "Background protection (can be turned off)", NotificationManager.IMPORTANCE_MIN);
        bg.setDescription("Android requires this while realtime scanning runs without the Web protection service. "
                + "Turn this category off to hide it; scanning keeps running.");
        bg.setShowBadge(false);
        nm.createNotificationChannel(bg);
        NotificationChannel fw = new NotificationChannel(CH_FIREWALL, "Firewall", NotificationManager.IMPORTANCE_DEFAULT);
        fw.setDescription("When the firewall needs to be turned back on, or another app changed it");
        nm.createNotificationChannel(fw);
        // Hypatia's old channel ids are not used any more
        try { nm.deleteNotificationChannel("DETECTION"); nm.deleteNotificationChannel("FOREGROUND"); } catch (Exception ignored) { }
        Firewall.onAppStart(this);
    }

    public static Context ctx() { return app; }

    /** Can we read your storage? (All-files access on Android 11+, storage permission before.) */
    public static boolean hasFileAccess(Context c) {
        if (android.os.Build.VERSION.SDK_INT >= 30) return android.os.Environment.isExternalStorageManager();
        return c.checkSelfPermission(android.Manifest.permission.READ_EXTERNAL_STORAGE) == android.content.pm.PackageManager.PERMISSION_GRANTED;
    }
}
