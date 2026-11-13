/*
 * Grove Guard — malware scanner, link guard and firewall for Android.
 * Copyright (C) 2026 Grove Guard contributors.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package org.grove.guard;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

import org.grove.guard.fw.Firewall;

/** After a restart or an app update: restart realtime scanning, re-apply the firewall, schedule updates. */
public class BootReceiver extends BroadcastReceiver {
    @Override public void onReceive(Context c, Intent i) {
        String a = i.getAction();
        if (Intent.ACTION_BOOT_COMPLETED.equals(a) || "android.intent.action.QUICKBOOT_POWERON".equals(a)) {
            Firewall.onBoot(c.getApplicationContext());
        }
        if (Intent.ACTION_BOOT_COMPLETED.equals(a) || Intent.ACTION_MY_PACKAGE_REPLACED.equals(a) || "android.intent.action.QUICKBOOT_POWERON".equals(a)) {
            RealtimeService.sync(c);
            Jobs.schedule(c);
        }
    }
}
