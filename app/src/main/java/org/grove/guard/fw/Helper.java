/*
 * Grove Guard — malware scanner, link guard and firewall for Android.
 * Copyright (C) 2026 Grove Guard contributors.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package org.grove.guard.fw;

import android.os.IBinder;

import java.lang.reflect.Method;

/**
 * Runs inside a shell (Shizuku) or root process, started with
 * {@code CLASSPATH=<Grove Guard apk> app_process /system/bin org.grove.guard.fw.Helper ...}.
 * It calls Android's per-app firewall directly, which the {@code cmd connectivity} tool can't do for the
 * mobile-data ("metered") chain. Uses only framework classes; nothing from the app is loaded.
 * <pre>
 *   uidrule &lt;chain&gt; &lt;rule&gt; &lt;uid&gt;...   prints "OK uid" or "ERR uid message" per uid
 * </pre>
 * Chains: 9 = OEM_DENY_3 (all networks), 12 = METERED_DENY_ADMIN (mobile data). Rule: 0 = default, 2 = deny.
 */
public final class Helper {
    private Helper() { }

    public static void main(String[] args) {
        try {
            if (args.length >= 3 && "uidrule".equals(args[0])) {
                int chain = Integer.parseInt(args[1]), rule = Integer.parseInt(args[2]);
                Object cm = connectivity();
                Method m = cm.getClass().getMethod("setUidFirewallRule", int.class, int.class, int.class);
                for (int i = 3; i < args.length; i++) {
                    int uid = Integer.parseInt(args[i]);
                    try {
                        m.invoke(cm, chain, uid, rule);
                        System.out.println("OK " + uid);
                    } catch (Throwable t) {
                        Throwable c = t.getCause() != null ? t.getCause() : t;
                        String msg = String.valueOf(c);
                        // "rule already set" style errors when clearing are fine
                        if (rule == 0 && msg.toLowerCase().contains("not found")) System.out.println("OK " + uid);
                        else System.out.println("ERR " + uid + " " + msg.replace('\n', ' '));
                    }
                }
            } else {
                System.out.println("ERR usage");
            }
        } catch (Throwable t) {
            Throwable c = t.getCause() != null ? t.getCause() : t;
            System.out.println("ERR all " + String.valueOf(c).replace('\n', ' '));
        }
        System.out.flush();
        System.exit(0);
    }

    private static Object connectivity() throws Exception {
        IBinder b = (IBinder) Class.forName("android.os.ServiceManager").getMethod("getService", String.class).invoke(null, "connectivity");
        if (b == null) throw new IllegalStateException("connectivity service unavailable");
        return Class.forName("android.net.IConnectivityManager$Stub").getMethod("asInterface", IBinder.class).invoke(null, b);
    }
}
