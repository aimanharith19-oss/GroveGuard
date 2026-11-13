/*
 * Grove Guard — malware scanner, link guard and firewall for Android.
 * Copyright (C) 2026 Grove Guard contributors.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package org.grove.guard.ui;

import android.app.Activity;
import android.app.KeyguardManager;
import android.content.Context;
import android.content.Intent;
import android.hardware.biometrics.BiometricManager;
import android.hardware.biometrics.BiometricPrompt;
import android.os.Build;
import android.os.CancellationSignal;
import android.os.SystemClock;

import org.grove.guard.Prefs;

/**
 * App lock: fingerprint (or face) with your Android screen lock (PIN, pattern, password) as the alternative.
 * Uses Android's own BiometricPrompt / confirm-credential screen, so Grove Guard never sees your PIN or fingerprint.
 */
public final class Lock {
    private Lock() { }

    public static final String KEY = "app_lock", TIMEOUT = "app_lock_timeout"; // seconds before asking again (0 = every time)
    public static final int REQ = 0x10C;
    private static long unlockedAt = -1;   // elapsedRealtime of the last unlock, while the app process lives
    private static long leftAt = -1;

    public static boolean enabled(Context c) { return Prefs.on(c, KEY, false); }

    /** The phone has a PIN, pattern or password (needed for the lock). */
    public static boolean deviceSecure(Context c) {
        KeyguardManager km = c.getSystemService(KeyguardManager.class);
        return km != null && km.isDeviceSecure();
    }

    public static boolean needsAuth(Context c) {
        if (!enabled(c)) return false;
        if (unlockedAt < 0) return true;
        if (leftAt < 0) return false; // still in the app
        long timeout = Prefs.sp(c).getInt(TIMEOUT, 0) * 1000L;
        return SystemClock.elapsedRealtime() - leftAt >= timeout;
    }

    public static void onLeave() { if (unlockedAt >= 0) leftAt = SystemClock.elapsedRealtime(); }

    public static void reset() { unlockedAt = -1; leftAt = -1; }

    private static void unlocked() { unlockedAt = SystemClock.elapsedRealtime(); leftAt = -1; }

    public interface Result { void done(boolean ok); }

    private static Result pending;

    /** Shows Android's fingerprint / screen-lock prompt. */
    public static void authenticate(final Activity a, String why, final Result r) {
        if (!deviceSecure(a)) { r.done(false); return; }
        if (Build.VERSION.SDK_INT >= 29) {
            try {
                biometric(a, why, r);
                return;
            } catch (Throwable t) {
                // some phones reject the fingerprint prompt: use the screen-lock screen instead
            }
        }
        confirmCredential(a, why, r);
    }

    private static void biometric(final Activity a, String why, final Result r) {
        {
            BiometricPrompt.Builder b = new BiometricPrompt.Builder(a).setTitle("Unlock Grove Guard").setSubtitle(why);
            if (Build.VERSION.SDK_INT >= 30) b.setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG | BiometricManager.Authenticators.DEVICE_CREDENTIAL);
            else //noinspection deprecation
                b.setDeviceCredentialAllowed(true);
            b.setConfirmationRequired(false);
            final boolean[] fired = {false};
            b.build().authenticate(new CancellationSignal(), a.getMainExecutor(), new BiometricPrompt.AuthenticationCallback() {
                @Override public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult res) {
                    if (fired[0]) return;
                    fired[0] = true;
                    unlocked();
                    r.done(true);
                }

                @Override public void onAuthenticationError(int code, CharSequence msg) {
                    if (fired[0]) return;
                    fired[0] = true;
                    // 5 canceled, 10 user canceled, 13 negative button: you said no. Anything else (no sensor, not set up…): try the screen lock.
                    if (code == 5 || code == 10 || code == 13) r.done(false);
                    else confirmCredential(a, "Use your screen lock", r);
                }
            });
        }
    }

    /** Android's "confirm your PIN / pattern / password" screen (also offers fingerprint on many phones). */
    @SuppressWarnings("deprecation")
    private static void confirmCredential(Activity a, String why, Result r) {
        KeyguardManager km = a.getSystemService(KeyguardManager.class);
        Intent i = km.createConfirmDeviceCredentialIntent("Unlock Grove Guard", why);
        if (i == null) { unlocked(); r.done(true); return; }
        pending = r;
        a.startActivityForResult(i, REQ);
    }

    /** Call from onActivityResult. Returns true if it was the lock's result. */
    public static boolean onResult(int req, int res) {
        if (req != REQ) return false;
        Result r = pending;
        pending = null;
        boolean ok = res == Activity.RESULT_OK;
        if (ok) unlocked();
        if (r != null) r.done(ok);
        return true;
    }
}
