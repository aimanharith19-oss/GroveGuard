/*
 * Grove Guard — malware scanner, link guard and firewall for Android.
 * Copyright (C) 2026 Grove Guard contributors.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package org.grove.guard.fw;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.widget.Toast;

import org.grove.guard.Events;
import org.grove.guard.Prefs;
import org.grove.guard.RealtimeService;
import org.grove.guard.scan.Scanner;
import org.grove.guard.scan.Sigs;

import java.util.Set;

/**
 * Lets Canopy Launcher, Tasker, MacroDroid or adb control Grove Guard. Accepts ShizuWall's broadcast actions
 * and extras, so existing automations keep working once you point them at Grove Guard:
 * <pre>
 *  adb shell am broadcast -a shizuwall.CONTROL -n org.grove.guard/.fw.AutomationReceiver --ez state true
 *  adb shell am broadcast -a shizuwall.CONTROL -n org.grove.guard/.fw.AutomationReceiver --ez state true --es apps "com.example.app"
 *  adb shell am broadcast -a shizuwall.PROFILE -n org.grove.guard/.fw.AutomationReceiver --es profile "Work" [--ez force_enable true]
 *  adb shell am broadcast -a shizuwall.APP_INSTALLED -n org.grove.guard/.fw.AutomationReceiver --es apps "com.example.newapp"
 *  adb shell am broadcast -a org.grove.guard.REALTIME -n org.grove.guard/.fw.AutomationReceiver --ez state true
 *  adb shell am broadcast -a org.grove.guard.SCAN -n org.grove.guard/.fw.AutomationReceiver
 *  adb shell am broadcast -a org.grove.guard.UPDATE -n org.grove.guard/.fw.AutomationReceiver
 * </pre>
 * org.grove.guard.FIREWALL and org.grove.guard.PROFILE are accepted as aliases of the ShizuWall actions.
 * Can be switched off in Settings ("Allow other apps to control Grove Guard").
 */
public class AutomationReceiver extends BroadcastReceiver {
    /** Small stand-in so the command code below can call pr.finish() both from a broadcast and a direct call. */
    private static final class PendingResult {
        private final Runnable r;
        PendingResult(Runnable r) { this.r = r; }
        void finish() { if (r != null) r.run(); }
    }

    @Override public void onReceive(final Context ctx, Intent i) {
        final Context c = ctx.getApplicationContext();
        String a = i.getAction();
        if (a == null) return;
        String mode = org.grove.guard.Trust.mode(c);
        if ("off".equals(mode) || ("key".equals(mode) && !org.grove.guard.Trust.keyOk(c, i.getStringExtra("key")))) {
            refused(c, a);
            return;
        }
        final BroadcastReceiver.PendingResult pr = goAsync();
        handle(c, i, new Runnable() { @Override public void run() { pr.finish(); } });
    }

    private static long lastRefusal;

    private static void refused(Context c, String action) {
        if (System.currentTimeMillis() - lastRefusal < 60000) return;
        lastRefusal = System.currentTimeMillis();
        Events.add(Events.ERROR, "Refused a command from another app", action + " · it didn't send Grove Guard's key (Settings > Security)");
    }

    /** Runs a command (from a broadcast with the right key, or from the trusted Grove Launcher through the status provider). */
    public static void handle(final Context c, Intent i, final Runnable done) {
        String a = i.getAction();
        final PendingResult pr = new PendingResult(done);
        Firewall.Done finish = new Firewall.Done() {
            @Override public void done(boolean ok, String message) {
                if (!ok && message != null) Toast.makeText(c, "Grove Guard: " + message, Toast.LENGTH_LONG).show();
                pr.finish();
            }
        };
        switch (a) {
            case "shizuwall.CONTROL":
            case "org.grove.guard.FIREWALL": {
                if (!i.hasExtra("state")) { pr.finish(); return; }
                boolean state = i.getBooleanExtra("state", false);
                String apps = i.getStringExtra("apps");
                if (apps == null || apps.trim().isEmpty()) {
                    Firewall.setEnabled(c, state, "from another app", finish);
                } else {
                    boolean allowMode = Firewall.MODE_ALLOW.equals(Firewall.mode(c));
                    Set<String> sel = Firewall.selected(c);
                    for (String p : apps.split(",")) {
                        String pkg = p.trim();
                        int colon = pkg.indexOf(':'); // ShizuWall's "userId:package" form; only the main profile is handled
                        if (colon >= 0) { if (!"0".equals(pkg.substring(0, colon))) continue; pkg = pkg.substring(colon + 1); }
                        if (!Firewall.validPkg(pkg)) continue;
                        // as in ShizuWall: in allow-list mode the list is the allow list, so the meaning flips
                        if (state != allowMode) sel.add(pkg); else sel.remove(pkg);
                    }
                    Prefs.set(c, Prefs.FW_SELECTED, sel);
                    Prefs.set(c, Prefs.FW_PROFILE, "");
                    if (state || Firewall.active(c)) Firewall.setEnabled(c, true, "apps changed by another app", finish);
                    else finish.done(true, null);
                }
                break;
            }
            case "shizuwall.PROFILE":
            case "org.grove.guard.PROFILE": {
                Firewall.Profile p = Firewall.findProfile(c, i.getStringExtra("profile_id"));
                if (p == null) p = Firewall.findProfile(c, i.getStringExtra("profile"));
                if (p == null) { finish.done(false, "no profile called \"" + i.getStringExtra("profile") + "\""); return; }
                Firewall.applyProfile(c, p, i.getBooleanExtra("force_enable", false), finish);
                break;
            }
            case "shizuwall.APP_INSTALLED":
            case "org.grove.guard.APP_INSTALLED": {
                String apps = i.getStringExtra("apps");
                if (apps != null) for (String p : apps.split(",")) Firewall.onAppInstalled(c, p.trim(), true);
                pr.finish();
                break;
            }
            case "org.grove.guard.REALTIME": {
                if (i.hasExtra("state")) {
                    Prefs.set(c, Prefs.REALTIME, i.getBooleanExtra("state", false));
                    RealtimeService.sync(c);
                    Events.add(Events.SCAN, i.getBooleanExtra("state", false) ? "Realtime scanning turned on" : "Realtime scanning turned off", "From another app");
                }
                pr.finish();
                break;
            }
            case "org.grove.guard.SCAN":
                if (!Scanner.start(c)) Toast.makeText(c, "Grove Guard: a scan is already running", Toast.LENGTH_SHORT).show();
                pr.finish();
                break;
            case "org.grove.guard.UPDATE":
                Sigs.update(c, true, null);
                pr.finish();
                break;
            default:
                pr.finish();
        }
    }
}
