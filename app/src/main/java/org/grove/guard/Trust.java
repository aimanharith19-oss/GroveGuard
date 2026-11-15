/*
 * Groveguard — malware scanner, link guard and firewall for Android.
 * Copyright (C) 2026 Groveguard contributors.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package org.grove.guard;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Build;
import android.os.Process;

import org.grove.guard.scan.PgpVerify;

import java.security.MessageDigest;
import java.security.SecureRandom;

/**
 * Who may read Groveguard's status or control it.
 * <ul>
 *   <li>Grove Launcher ({@code org.canopy.launcher}) is trusted, but only with the signing certificate it had the
 *       first time it connected (pinned; a different app reusing the package name is refused).</li>
 *   <li>Other apps (Tasker, adb…) must send the secret key shown in Settings, unless you allow any app.</li>
 * </ul>
 */
public final class Trust {
    private Trust() { }

    public static final String LAUNCHER = "org.canopy.launcher";
    public static final String CONTROL = "control_mode"; // "key" (default), "any", "off"

    public static String mode(Context c) { return Prefs.str(c, CONTROL, "key"); }

    /** Is the app behind this uid Groveguard itself or the pinned Grove Launcher? */
    public static boolean trustedUid(Context c, int uid) {
        if (uid == Process.myUid()) return true;
        String[] pkgs = c.getPackageManager().getPackagesForUid(uid);
        if (pkgs == null) return false;
        for (String p : pkgs) if (LAUNCHER.equals(p) && certMatches(c, p)) return true;
        return false;
    }

    private static boolean certMatches(Context c, String pkg) {
        String cert = certSha256(c, pkg);
        if (cert == null) return false;
        String key = "trust_cert_" + pkg, pinned = Prefs.str(c, key, "");
        if (pinned.isEmpty()) {
            Prefs.set(c, key, cert);
            Events.add(Events.INFO, "Trusted Grove Launcher", "Its signing certificate is now pinned");
            return true;
        }
        return pinned.equals(cert);
    }

    @SuppressWarnings("deprecation")
    static String certSha256(Context c, String pkg) {
        try {
            Signature[] sigs;
            if (Build.VERSION.SDK_INT >= 28) {
                PackageInfo pi = c.getPackageManager().getPackageInfo(pkg, PackageManager.GET_SIGNING_CERTIFICATES);
                if (pi.signingInfo == null || pi.signingInfo.hasMultipleSigners()) return null;
                sigs = pi.signingInfo.getSigningCertificateHistory();
                if (sigs != null && sigs.length > 0) sigs = new Signature[]{sigs[0]}; // original certificate (survives key rotation)
            } else {
                sigs = c.getPackageManager().getPackageInfo(pkg, PackageManager.GET_SIGNATURES).signatures;
                if (sigs == null || sigs.length != 1) return null;
            }
            return PgpVerify.hex(MessageDigest.getInstance("SHA-256").digest(sigs[0].toByteArray()));
        } catch (Exception e) {
            return null;
        }
    }

    public static void forgetLauncher(Context c) { Prefs.sp(c).edit().remove("trust_cert_" + LAUNCHER).apply(); }

    public static boolean launcherPinned(Context c) { return !Prefs.str(c, "trust_cert_" + LAUNCHER, "").isEmpty(); }

    /** The secret key other apps must send as extra "key". */
    public static String key(Context c) {
        String k = Prefs.str(c, "control_key", "");
        if (k.isEmpty()) k = newKey(c);
        return k;
    }

    public static String newKey(Context c) {
        byte[] b = new byte[16];
        new SecureRandom().nextBytes(b);
        String k = PgpVerify.hex(b).toLowerCase(java.util.Locale.ROOT);
        Prefs.set(c, "control_key", k);
        return k;
    }

    /** Constant-time compare. */
    public static boolean keyOk(Context c, String given) {
        if (given == null) return false;
        return MessageDigest.isEqual(given.getBytes(), key(c).getBytes());
    }
}
