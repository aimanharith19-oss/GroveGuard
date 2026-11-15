/*
 * Groveguard — malware scanner, link guard and firewall for Android.
 * Copyright (C) 2026 Groveguard contributors.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package org.grove.guard;

import android.content.ComponentName;
import android.content.Context;
import android.service.quicksettings.Tile;
import android.service.quicksettings.TileService;

import org.grove.guard.scan.Sigs;

/** Quick Settings switch for realtime scanning (the scanner itself shows no notification). */
public class RealtimeTile extends TileService {

    public static void refresh(Context c) {
        try { requestListeningState(c, new ComponentName(c, RealtimeTile.class)); } catch (Exception ignored) { }
    }

    @Override public void onStartListening() { update(); }

    @Override public void onClick() {
        // never change protection from the lock screen without unlocking the phone first
        if (isLocked()) unlockAndRun(new Runnable() { @Override public void run() { doClick(); } });
        else doClick();
    }

    private void doClick() {
        boolean on = !Prefs.on(this, Prefs.REALTIME, false);
        Prefs.set(this, Prefs.REALTIME, on);
        RealtimeService.sync(this);
        Events.add(Events.SCAN, on ? "Realtime scanning turned on" : "Realtime scanning turned off", "From the Quick Settings tile");
        if (on && !Sigs.downloaded(this) && Sigs.networkOk(this, false)) Sigs.update(this, false, null);
        update();
    }

    private void update() {
        Tile t = getQsTile();
        if (t == null) return;
        boolean on = Prefs.on(this, Prefs.REALTIME, false);
        t.setState(on ? Tile.STATE_ACTIVE : Tile.STATE_INACTIVE);
        t.setLabel("Realtime scan");
        if (android.os.Build.VERSION.SDK_INT >= 29)
            t.setSubtitle(!on ? "Off" : !Sigs.downloaded(this) ? "No database" : "On");
        t.updateTile();
    }
}
