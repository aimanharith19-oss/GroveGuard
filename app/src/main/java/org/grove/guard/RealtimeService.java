/*
 * Grove Guard — malware scanner, link guard and firewall for Android.
 * Copyright (C) 2026 Grove Guard contributors.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package org.grove.guard;

import android.app.Notification;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.os.Build;
import android.os.IBinder;
import android.provider.Settings;

import org.grove.guard.scan.Watcher;

/**
 * Keeps the realtime scanner alive when the Web protection service isn't on. Android requires a notification for
 * this; it's posted silently in the "Background protection" category, which you can turn off in Android's
 * notification settings to hide it (scanning keeps running). With Web protection on, this service isn't used.
 */
public class RealtimeService extends Service {

    /** Starts/stops the realtime scanner in the right place for the current settings. Safe to call any time. */
    public static void sync(Context c) {
        Context a = c.getApplicationContext();
        boolean want = Prefs.on(a, Prefs.REALTIME, false);
        if (!want) {
            Watcher.stop();
            a.stopService(new Intent(a, RealtimeService.class));
        } else if (LinkGuardService.isRunning()) {
            Watcher.start(a, "accessibility");
            a.stopService(new Intent(a, RealtimeService.class));
        } else {
            try { a.startForegroundService(new Intent(a, RealtimeService.class)); }
            catch (Exception e) { Events.add(Events.ERROR, "Couldn't start realtime scanning", "Open Grove Guard once, or turn on Web protection."); }
        }
        StatusProvider.changed(a);
        RealtimeTile.refresh(a);
    }

    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        Intent open = new Intent(Settings.ACTION_CHANNEL_NOTIFICATION_SETTINGS)
                .putExtra(Settings.EXTRA_APP_PACKAGE, getPackageName())
                .putExtra(Settings.EXTRA_CHANNEL_ID, App.CH_BACKGROUND)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        Notification n = new Notification.Builder(this, App.CH_BACKGROUND)
                .setSmallIcon(R.drawable.ic_stat)
                .setContentTitle("Realtime scanning")
                .setContentText("Tap to hide this notification")
                .setShowWhen(false)
                .setOngoing(true)
                .setContentIntent(PendingIntent.getActivity(this, 1, open, PendingIntent.FLAG_IMMUTABLE))
                .build();
        if (Build.VERSION.SDK_INT >= 34) startForeground(7, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
        else startForeground(7, n);
        if (!Prefs.on(this, Prefs.REALTIME, false) || LinkGuardService.isRunning()) {
            stopSelf();
            return START_NOT_STICKY;
        }
        Watcher.start(this, "service");
        return START_STICKY;
    }

    @Override public void onDestroy() {
        if ("service".equals(Watcher.host())) Watcher.stop();
        super.onDestroy();
    }

    @Override public IBinder onBind(Intent intent) { return null; }
}
