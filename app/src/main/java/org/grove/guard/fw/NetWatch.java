/*
 * Grove Guard — malware scanner, link guard and firewall for Android.
 * Copyright (C) 2026 Grove Guard contributors.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package org.grove.guard.fw;

import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;
import android.os.Build;

/**
 * Follows Wi-Fi ↔ mobile switches so "Wi-Fi only" blocks are switched on and off. Android wakes Grove Guard
 * through a PendingIntent when Wi-Fi or mobile data comes up (works even when the app isn't running); while
 * the app is running a live callback reacts faster.
 */
public final class NetWatch {
    private NetWatch() { }

    private static ConnectivityManager.NetworkCallback live;
    private static boolean registered;

    public static synchronized void sync(Context ctx) {
        Context c = ctx.getApplicationContext();
        ConnectivityManager cm = c.getSystemService(ConnectivityManager.class);
        if (cm == null) return;
        boolean want = Firewall.wanted(c) && Firewall.anyWifiOnly(c);
        try {
            if (want && !registered) {
                for (int t : new int[]{NetworkCapabilities.TRANSPORT_WIFI, NetworkCapabilities.TRANSPORT_CELLULAR}) {
                    NetworkRequest req = new NetworkRequest.Builder().addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET).addTransportType(t).build();
                    cm.registerNetworkCallback(req, pi(c, t));
                }
                live = new ConnectivityManager.NetworkCallback() {
                    @Override public void onAvailable(Network n) { Firewall.onNetworkChanged(App()); }
                    @Override public void onLost(Network n) { Firewall.onNetworkChanged(App()); }
                };
                cm.registerDefaultNetworkCallback(live);
                registered = true;
            } else if (!want && registered) {
                for (int t : new int[]{NetworkCapabilities.TRANSPORT_WIFI, NetworkCapabilities.TRANSPORT_CELLULAR}) cm.unregisterNetworkCallback(pi(c, t));
                if (live != null) cm.unregisterNetworkCallback(live);
                live = null;
                registered = false;
            }
        } catch (Exception ignored) { }
    }

    private static Context App() { return org.grove.guard.App.ctx(); }

    private static PendingIntent pi(Context c, int transport) {
        int flags = PendingIntent.FLAG_UPDATE_CURRENT | (Build.VERSION.SDK_INT >= 31 ? PendingIntent.FLAG_MUTABLE : 0);
        return PendingIntent.getBroadcast(c, 0x4E00 + transport, new Intent(c, Receiver.class), flags);
    }

    /** Woken by Android when a matching network comes up. Not exported. */
    public static class Receiver extends BroadcastReceiver {
        @Override public void onReceive(Context c, Intent i) {
            final PendingResult pr = goAsync();
            Firewall.onNetworkChanged(c.getApplicationContext());
            org.grove.guard.App.MAIN.postDelayed(new Runnable() { @Override public void run() { pr.finish(); } }, 8000);
        }
    }
}
