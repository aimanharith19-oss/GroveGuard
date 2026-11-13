/*
 * Grove Guard — malware scanner, link guard and firewall for Android.
 * Copyright (C) 2026 Grove Guard contributors.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package org.grove.guard;

import android.content.ComponentName;
import android.content.Context;
import android.service.quicksettings.Tile;
import android.service.quicksettings.TileService;
import android.widget.Toast;

import org.grove.guard.fw.Firewall;

/** Quick Settings switch for the firewall. */
public class FirewallTile extends TileService {

    public static void refresh(Context c) {
        try { requestListeningState(c, new ComponentName(c, FirewallTile.class)); } catch (Exception ignored) { }
    }

    @Override public void onStartListening() { update(); }

    @Override public void onClick() {
        // never change protection from the lock screen without unlocking the phone first
        if (isLocked()) unlockAndRun(new Runnable() { @Override public void run() { doClick(); } });
        else doClick();
    }

    private void doClick() {
        final boolean on = !Firewall.active(this);
        Tile t = getQsTile();
        if (t != null) { t.setState(Tile.STATE_UNAVAILABLE); t.updateTile(); }
        Firewall.setEnabled(this, on, "from the Quick Settings tile", new Firewall.Done() {
            @Override public void done(boolean ok, String message) {
                if (!ok) Toast.makeText(getApplicationContext(), "Firewall: " + message, Toast.LENGTH_LONG).show();
                update();
            }
        });
    }

    private void update() {
        Tile t = getQsTile();
        if (t == null) return;
        boolean active = Firewall.active(this);
        t.setState(active ? Tile.STATE_ACTIVE : Tile.STATE_INACTIVE);
        t.setLabel("Firewall");
        if (android.os.Build.VERSION.SDK_INT >= 29) t.setSubtitle(active ? Firewall.blockedCount(this) + " blocked" : Firewall.wanted(this) ? "Needs Shizuku" : "Off");
        t.updateTile();
    }
}
