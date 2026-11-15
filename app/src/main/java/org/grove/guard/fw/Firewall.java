/*
 * Groveguard — malware scanner, link guard and firewall for Android.
 * Copyright (C) 2026 Groveguard contributors.
 * Feature set modelled on ShizuWall (github.com/AhmetCanArslan/ShizuWall, GPL-3.0); written from scratch.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package org.grove.guard.fw;

import android.Manifest;
import android.app.Notification;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.ChangedPackages;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Process;
import android.provider.Settings;

import org.grove.guard.App;
import org.grove.guard.Events;
import org.grove.guard.FirewallTile;
import org.grove.guard.MainActivity;
import org.grove.guard.Prefs;
import org.grove.guard.R;
import org.grove.guard.StatusProvider;
import org.grove.guard.scan.Detect;
import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Firewall without a VPN: uses Android's per-app networking switch ("chain 3"), through Shizuku or root.
 * <pre>
 *   cmd connectivity set-chain3-enabled true|false
 *   cmd connectivity set-package-networking-enabled false|true &lt;package&gt;
 * </pre>
 * Two modes: <b>block</b> (the apps you pick have no network) and <b>allow</b> (only the apps you pick have
 * network). Android forgets these rules when the phone restarts, so they're re-applied after boot when Shizuku
 * or root becomes available.
 */
public final class Firewall {
    private Firewall() { }

    public static final String MODE_BLOCK = "block", MODE_ALLOW = "allow";

    public interface Listener { void onFirewallChanged(); }

    public interface Done { void done(boolean ok, String message); }

    private static final CopyOnWriteArrayList<Listener> listeners = new CopyOnWriteArrayList<>();
    private static final Object LOCK = new Object();

    public static void addListener(Listener l) { listeners.add(l); }

    public static void removeListener(Listener l) { listeners.remove(l); }

    private static void changed(Context c) {
        App.MAIN.post(new Runnable() { @Override public void run() { for (Listener l : listeners) l.onFirewallChanged(); } });
        StatusProvider.changed(c);
        FirewallTile.refresh(c);
        org.grove.guard.Jobs.schedule(c); // the new-app check runs only while the firewall is wanted
        NetWatch.sync(c);
    }

    // ---------------------------------------------------------------- state

    public static boolean wanted(Context c) { return Prefs.on(c, Prefs.FW_ENABLED, false); }

    private static int bootCount(Context c) { return Settings.Global.getInt(c.getContentResolver(), Settings.Global.BOOT_COUNT, -1); }

    /** The rules are really in place right now (they were applied since the last restart). */
    public static boolean active(Context c) {
        return wanted(c) && Prefs.sp(c).getInt("fw_applied_boot", -2) == bootCount(c);
    }

    public static String mode(Context c) { return Prefs.str(c, Prefs.FW_MODE, MODE_BLOCK); }

    public static Set<String> selected(Context c) { return Prefs.set(c, Prefs.FW_SELECTED); }

    /** Packages currently blocked by us (as last applied). */
    public static Set<String> applied(Context c) { return Prefs.set(c, "fw_applied"); }

    public static boolean validPkg(String p) { return p != null && p.matches("[A-Za-z0-9_]+(\\.[A-Za-z0-9_]+)+"); }

    /** Apps that can be firewalled: they ask for internet access and have their own user id. */
    public static List<ApplicationInfo> candidates(Context c, boolean includeSystem) {
        PackageManager pm = c.getPackageManager();
        List<ApplicationInfo> out = new ArrayList<>();
        for (PackageInfo pi : pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)) {
            ApplicationInfo ai = pi.applicationInfo;
            if (ai == null || ai.uid < Process.FIRST_APPLICATION_UID) continue; // shared system ids can't be blocked per app
            if (pi.packageName.equals(c.getPackageName())) continue;
            if (!includeSystem && (ai.flags & (ApplicationInfo.FLAG_SYSTEM | ApplicationInfo.FLAG_UPDATED_SYSTEM_APP)) != 0) continue;
            boolean net = false;
            if (pi.requestedPermissions != null) for (String p : pi.requestedPermissions) if (Manifest.permission.INTERNET.equals(p)) { net = true; break; }
            if (net) out.add(ai);
        }
        return out;
    }

    /** What should be blocked under the current settings. */
    static Set<String> targets(Context c) {
        Set<String> sel = selected(c), out = new HashSet<>();
        if (MODE_ALLOW.equals(mode(c))) {
            for (ApplicationInfo ai : candidates(c, true)) if (!sel.contains(ai.packageName) && !ai.packageName.equals(Shizuku.MANAGER)) out.add(ai.packageName);
        } else {
            PackageManager pm = c.getPackageManager();
            boolean wifi = onWifi(c);
            for (String p : sel) {
                try { pm.getApplicationInfo(p, 0); } catch (PackageManager.NameNotFoundException e) { continue; }
                String n = netMode(c, p);
                if (NET_ALL.equals(n) || (NET_WIFI.equals(n) && wifi)) out.add(p);
            }
        }
        return out;
    }

    /** Apps whose mobile data is blocked (block mode, "Mobile data" choice). */
    static Set<String> meteredTargets(Context c) {
        Set<String> out = new HashSet<>();
        if (MODE_ALLOW.equals(mode(c)) || !mobileSupported()) return out;
        PackageManager pm = c.getPackageManager();
        for (String p : selected(c)) {
            if (!NET_MOBILE.equals(netMode(c, p))) continue;
            try { pm.getApplicationInfo(p, 0); out.add(p); } catch (PackageManager.NameNotFoundException ignored) { }
        }
        return out;
    }

    // ---------------------------------------------------------------- which networks an app is blocked on

    public static final String NET_ALL = "all", NET_MOBILE = "mobile", NET_WIFI = "wifi";

    /** Blocking only mobile data needs Android 13 or newer (the "metered" firewall chain). */
    public static boolean mobileSupported() { return android.os.Build.VERSION.SDK_INT >= 33; }

    public static String netMode(Context c, String pkg) {
        for (String e : Prefs.set(c, "fw_net")) {
            int i = e.indexOf('|');
            if (i > 0 && e.substring(0, i).equals(pkg)) {
                String m = e.substring(i + 1);
                if (NET_MOBILE.equals(m) && !mobileSupported()) return NET_ALL;
                return m;
            }
        }
        return NET_ALL;
    }

    public static void setNetMode(final Context ctx, String pkg, String mode, final Done done) {
        final Context c = ctx.getApplicationContext();
        Set<String> s = Prefs.set(c, "fw_net"), out = new HashSet<>();
        for (String e : s) if (!e.startsWith(pkg + "|")) out.add(e);
        if (!NET_ALL.equals(mode)) out.add(pkg + "|" + mode);
        Prefs.set(c, "fw_net", out);
        NetWatch.sync(c);
        if (!active(c)) { changed(c); if (done != null) done.done(true, null); return; }
        App.IO.execute(new Runnable() {
            @Override public void run() {
                String[] r = applyNow(c);
                changed(c);
                if (done != null) {
                    final String[] fr = r;
                    App.MAIN.post(new Runnable() { @Override public void run() { done.done(fr[0] == null, fr[0]); } });
                }
            }
        });
    }

    static boolean anyWifiOnly(Context c) {
        for (String e : Prefs.set(c, "fw_net")) if (e.endsWith("|" + NET_WIFI)) return true;
        return false;
    }

    public static boolean onWifi(Context c) {
        android.net.ConnectivityManager cm = c.getSystemService(android.net.ConnectivityManager.class);
        if (cm == null) return false;
        android.net.Network n = cm.getActiveNetwork();
        android.net.NetworkCapabilities nc = n == null ? null : cm.getNetworkCapabilities(n);
        return nc != null && (nc.hasTransport(android.net.NetworkCapabilities.TRANSPORT_WIFI) || nc.hasTransport(android.net.NetworkCapabilities.TRANSPORT_ETHERNET));
    }

    /** The network changed: Wi-Fi-only blocks follow it. */
    public static void onNetworkChanged(final Context c) {
        if (!active(c) || !anyWifiOnly(c)) return;
        App.IO.execute(new Runnable() {
            @Override public void run() {
                boolean before = Prefs.on(c, "fw_last_wifi", false), now = onWifi(c);
                applyNow(c);
                if (before != now) Prefs.set(c, "fw_last_wifi", now);
                changed(c);
            }
        });
    }

    /** Runs Groveguard's helper as the shell/root user (see {@link Helper}). */
    static String helperCmd(Context c, String args) {
        return "CLASSPATH=" + Shell.q(c.getApplicationInfo().sourceDir) + " app_process /system/bin " + Helper.class.getName() + " " + args;
    }

    static int uidOf(Context c, String pkg) {
        try { return c.getPackageManager().getApplicationInfo(pkg, 0).uid; } catch (PackageManager.NameNotFoundException e) { return -1; }
    }

    // ---------------------------------------------------------------- turning it on and off

    public static void setEnabled(final Context ctx, final boolean on, final String why, final Done done) {
        final Context c = ctx.getApplicationContext();
        App.IO.execute(new Runnable() {
            @Override public void run() {
                String[] r = on ? applyNow(c) : disableNow(c);
                boolean ok = r[0] == null;
                if (ok || !on) Prefs.set(c, Prefs.FW_ENABLED, on);
                if (ok) Events.add(Events.FW, on ? "Firewall on" : "Firewall off", r[1] + (why == null ? "" : " · " + why));
                else Events.add(Events.ERROR, on ? "Couldn't turn the firewall on" : "Couldn't fully turn the firewall off", r[0]);
                changed(c);
                if (done != null) {
                    final boolean fok = ok;
                    final String msg = ok ? r[1] : r[0];
                    App.MAIN.post(new Runnable() { @Override public void run() { done.done(fok, msg); } });
                }
            }
        });
    }

    /** Applies all rules. Returns {error or null, summary}. Blocking. */
    static String[] applyNow(Context c) {
        synchronized (LOCK) {
            Set<String> want = targets(c), had = applied(c);
            Set<String> wantM = meteredTargets(c), hadM = Prefs.set(c, "fw_applied_met");
            if (!Prefs.sp(c).contains("fw_applied_boot") || Prefs.sp(c).getInt("fw_applied_boot", -2) != bootCount(c)) { had = new HashSet<>(); hadM = new HashSet<>(); } // reboot cleared them
            StringBuilder sh = new StringBuilder("cmd connectivity set-chain3-enabled true || echo FAIL:chain3\n");
            for (String p : want) if (validPkg(p)) sh.append("cmd connectivity set-package-networking-enabled false ").append(p).append(" || echo FAIL:").append(p).append('\n');
            for (String p : had) if (!want.contains(p) && validPkg(p)) sh.append("cmd connectivity set-package-networking-enabled true ").append(p).append('\n');
            // mobile data: Android's metered firewall chain, set through the helper
            java.util.Map<Integer, String> uidPkg = new java.util.HashMap<>();
            StringBuilder deny = new StringBuilder(), allow = new StringBuilder();
            for (String p : wantM) { int u = uidOf(c, p); if (u >= Process.FIRST_APPLICATION_UID) { uidPkg.put(u, p); deny.append(' ').append(u); } }
            for (String p : hadM) if (!wantM.contains(p)) { int u = uidOf(c, p); if (u >= Process.FIRST_APPLICATION_UID) allow.append(' ').append(u); }
            if (deny.length() > 0) sh.append(helperCmd(c, "uidrule 12 2" + deny)).append('\n');
            if (allow.length() > 0) sh.append(helperCmd(c, "uidrule 12 0" + allow)).append('\n');
            Shell.Result r = Shell.run(c, sh.toString());
            if (r == null) return new String[]{noBackend(c), null};
            if (r.out.contains("FAIL:chain3")) return new String[]{"Android refused to turn on the firewall: " + firstLine(r.out), null};
            Set<String> failed = new HashSet<>();
            Set<String> okM = new HashSet<>();
            String metErr = null;
            for (String line : r.out.split("\n")) {
                line = line.trim();
                if (line.startsWith("FAIL:")) failed.add(line.substring(5).trim());
                else if (line.startsWith("OK ")) { String p = uidPkg.get(parseInt(line.substring(3))); if (p != null) okM.add(p); }
                else if (line.startsWith("ERR ")) { if (metErr == null) metErr = line.substring(4); }
            }
            Set<String> ok = new HashSet<>(want);
            ok.removeAll(failed);
            Prefs.set(c, "fw_applied", ok);
            Prefs.set(c, "fw_applied_met", okM);
            if (metErr != null) Events.add(Events.ERROR, "Couldn't block mobile data for some apps", metErr);
            Prefs.sp(c).edit().putInt("fw_applied_boot", bootCount(c)).putBoolean("fw_pending_reapply", false).apply();
            NotificationManagerHolder.cancel(c);
            int total = ok.size() + okM.size();
            String summary = total + (total == 1 ? " app blocked" : " apps blocked") + (MODE_ALLOW.equals(mode(c)) ? " (allow-list mode)" : "")
                    + (okM.isEmpty() ? "" : " · " + okM.size() + " on mobile data only");
            if (!failed.isEmpty()) summary += " · " + failed.size() + " couldn't be blocked";
            return new String[]{null, summary};
        }
    }

    static String[] disableNow(Context c) {
        synchronized (LOCK) {
            Set<String> had = applied(c);
            StringBuilder sh = new StringBuilder();
            for (String p : had) if (validPkg(p)) sh.append("cmd connectivity set-package-networking-enabled true ").append(p).append('\n');
            StringBuilder allow = new StringBuilder();
            for (String p : Prefs.set(c, "fw_applied_met")) { int u = uidOf(c, p); if (u >= Process.FIRST_APPLICATION_UID) allow.append(' ').append(u); }
            if (allow.length() > 0) sh.append(helperCmd(c, "uidrule 12 0" + allow)).append('\n');
            sh.append("cmd connectivity set-chain3-enabled false || echo FAIL:chain3\n");
            Shell.Result r = Shell.run(c, sh.toString());
            if (r == null) {
                // nothing we can do without a backend; if the phone restarted since, the rules are gone anyway
                if (Prefs.sp(c).getInt("fw_applied_boot", -2) != bootCount(c)) { clearApplied(c); return new String[]{null, "Rules were already cleared by a restart"}; }
                return new String[]{noBackend(c), null};
            }
            clearApplied(c);
            if (r.out.contains("FAIL:chain3")) return new String[]{"Android didn't confirm: " + firstLine(r.out) + " — restart the phone if apps have no internet.", null};
            return new String[]{null, "All apps have network access again"};
        }
    }

    private static void clearApplied(Context c) {
        Prefs.set(c, "fw_applied", new HashSet<String>());
        Prefs.set(c, "fw_applied_met", new HashSet<String>());
        Prefs.sp(c).edit().remove("fw_applied_boot").putBoolean("fw_pending_reapply", false).apply();
        NotificationManagerHolder.cancel(c);
    }

    private static int parseInt(String s) {
        try { return Integer.parseInt(s.trim().split(" ")[0]); } catch (Exception e) { return -1; }
    }

    private static String firstLine(String s) {
        String t = s.trim();
        int i = t.indexOf('\n');
        return i > 0 ? t.substring(0, i) : t;
    }

    static String noBackend(Context c) {
        if (Shizuku.running() && !Shizuku.granted()) return "Allow Groveguard in Shizuku first (Firewall tab)";
        return "Shizuku isn't running and root isn't available";
    }

    // ---------------------------------------------------------------- per-app changes

    /** Ticks/unticks an app (blocked in block mode, allowed in allow mode) and applies it straight away if the firewall is on. */
    public static void setSelected(final Context ctx, final String pkg, final boolean sel, final Done done) {
        final Context c = ctx.getApplicationContext();
        Set<String> s = selected(c);
        if (sel) s.add(pkg); else s.remove(pkg);
        Prefs.set(c, Prefs.FW_SELECTED, s);
        Prefs.set(c, Prefs.FW_PROFILE, ""); // no longer exactly a saved profile
        if (!active(c)) { changed(c); if (done != null) done.done(true, null); return; }
        App.IO.execute(new Runnable() {
            @Override public void run() {
                String[] r = applyNow(c);
                changed(c);
                if (done != null) {
                    final String e = r[0];
                    App.MAIN.post(new Runnable() { @Override public void run() { done.done(e == null, e); } });
                }
            }
        });
    }

    static String setBlockedNow(Context c, String pkg, boolean block) {
        if (!validPkg(pkg)) return "Invalid package";
        synchronized (LOCK) {
            Shell.Result r = Shell.run(c, "cmd connectivity set-package-networking-enabled " + (block ? "false " : "true ") + pkg);
            if (r == null) return noBackend(c);
            if (!r.ok()) return firstLine(r.out);
            Set<String> a = applied(c);
            if (block) a.add(pkg); else a.remove(pkg);
            Prefs.set(c, "fw_applied", a);
            return null;
        }
    }

    public static void setMode(final Context ctx, String mode) {
        Context c = ctx.getApplicationContext();
        Prefs.set(c, Prefs.FW_MODE, MODE_ALLOW.equals(mode) ? MODE_ALLOW : MODE_BLOCK);
        Prefs.set(c, Prefs.FW_PROFILE, "");
        if (active(c)) setEnabled(c, true, "mode changed", null);
        else changed(c);
    }

    /** New app installed: in block mode it's blocked if you chose that; in allow mode it's blocked until you allow it. */
    public static void onAppInstalled(final Context ctx, final String pkg, final boolean reportedByOtherApp) {
        final Context c = ctx.getApplicationContext();
        if (!validPkg(pkg) || pkg.equals(c.getPackageName())) return;
        boolean hasNet = false;
        try {
            PackageInfo pi = c.getPackageManager().getPackageInfo(pkg, PackageManager.GET_PERMISSIONS);
            if (pi.applicationInfo.uid < Process.FIRST_APPLICATION_UID) return;
            if (pi.requestedPermissions != null) for (String p : pi.requestedPermissions) if (Manifest.permission.INTERNET.equals(p)) hasNet = true;
        } catch (PackageManager.NameNotFoundException e) { return; }
        if (!hasNet || !wanted(c)) return;
        final boolean allowMode = MODE_ALLOW.equals(mode(c));
        if (!allowMode && !Prefs.on(c, Prefs.FW_NEW_APPS, false)) return;
        if (!allowMode) {
            Set<String> s = selected(c);
            if (!s.add(pkg)) return;
            Prefs.set(c, Prefs.FW_SELECTED, s);
        } else if (selected(c).contains(pkg)) return;
        App.IO.execute(new Runnable() {
            @Override public void run() {
                String err = active(c) ? setBlockedNow(c, pkg, true) : null;
                Events.add(err == null ? Events.FW : Events.ERROR, "New app blocked: " + Detect.appName(c, pkg),
                        err == null ? (allowMode ? "Allow it in the Firewall tab if it needs the internet" : "Untick it in the Firewall tab to allow it") : err);
                changed(c);
            }
        });
    }

    /** Catches installs that happened while Groveguard wasn't running (checked by a periodic job and at start). */
    public static void checkChangedPackages(Context c) {
        PackageManager pm = c.getPackageManager();
        int seq = Prefs.sp(c).getInt("fw_pkg_seq", -1);
        ChangedPackages ch = pm.getChangedPackages(Math.max(0, seq));
        if (ch == null) return;
        Prefs.sp(c).edit().putInt("fw_pkg_seq", ch.getSequenceNumber()).apply();
        if (seq < 0) return; // first run: just remember where we are
        long since = Prefs.sp(c).getLong("fw_pkg_check_time", 0);
        Prefs.sp(c).edit().putLong("fw_pkg_check_time", System.currentTimeMillis()).apply();
        for (String p : ch.getPackageNames()) {
            try {
                PackageInfo pi = pm.getPackageInfo(p, 0);
                if (pi.firstInstallTime >= since - 60000 && pi.firstInstallTime == pi.lastUpdateTime) onAppInstalled(c, p, false);
            } catch (PackageManager.NameNotFoundException ignored) { }
        }
    }

    // ---------------------------------------------------------------- after a restart

    public static void onAppStart(final Context c) {
        App.IO.execute(new Runnable() {
            @Override public void run() {
                try { checkChangedPackages(c); } catch (Exception ignored) { }
                NetWatch.sync(c);
                if (wanted(c) && !active(c) && Prefs.on(c, Prefs.FW_REAPPLY, true) && Shell.backend(c) != null) reapply(c, "re-applied after restart");
            }
        });
    }

    public static void onBoot(final Context c) {
        if (!wanted(c)) return;
        if (!Prefs.on(c, Prefs.FW_REAPPLY, true)) {
            Prefs.set(c, Prefs.FW_ENABLED, false);
            clearApplied(c);
            changed(c);
            return;
        }
        Prefs.sp(c).edit().putBoolean("fw_pending_reapply", true).apply();
        App.IO.execute(new Runnable() {
            @Override public void run() {
                if (Shell.run(c, "true") != null) reapply(c, "re-applied after restart");
                else {
                    NotificationManagerHolder.needsBackend(c);
                    changed(c);
                }
            }
        });
    }

    /** Shizuku just connected (or permission was granted): finish a pending re-apply. */
    public static void onBackendReady(final Context c) {
        if (!wanted(c) || active(c)) { App.MAIN.post(new Runnable() { @Override public void run() { changed(c); } }); return; }
        if (!Prefs.on(c, Prefs.FW_REAPPLY, true)) return;
        App.IO.execute(new Runnable() { @Override public void run() { reapply(c, "re-applied when Shizuku started"); } });
    }

    private static void reapply(Context c, String why) {
        String[] r = applyNow(c);
        if (r[0] == null) Events.add(Events.FW, "Firewall on", r[1] + " · " + why);
        else { Events.add(Events.ERROR, "Couldn't re-apply the firewall", r[0]); NotificationManagerHolder.needsBackend(c); }
        changed(c);
    }

    /** Apps blocked right now (all networks + mobile data only). */
    public static int blockedCount(Context c) { return active(c) ? applied(c).size() + Prefs.set(c, "fw_applied_met").size() : 0; }

    public static boolean mobileBlockedNow(Context c, String pkg) { return active(c) && Prefs.set(c, "fw_applied_met").contains(pkg); }

    /** One-line status for the screen, the tile and the launcher feed. */
    public static String summary(Context c) {
        if (!wanted(c)) return "Off";
        if (!active(c)) return "Waiting for Shizuku or root to turn back on";
        int n = applied(c).size() + Prefs.set(c, "fw_applied_met").size();
        return (MODE_ALLOW.equals(mode(c)) ? "Allow-list · " : "") + n + (n == 1 ? " app blocked" : " apps blocked");
    }

    // ---------------------------------------------------------------- profiles

    public static final class Profile {
        public String id, name, mode;
        public Set<String> apps = new HashSet<>();
    }

    public static List<Profile> profiles(Context c) {
        List<Profile> out = new ArrayList<>();
        try {
            JSONArray a = new JSONArray(Prefs.str(c, "fw_profiles", "[]"));
            for (int i = 0; i < a.length(); i++) {
                JSONObject o = a.getJSONObject(i);
                Profile p = new Profile();
                p.id = o.getString("id"); p.name = o.getString("name"); p.mode = o.optString("mode", MODE_BLOCK);
                JSONArray ap = o.optJSONArray("apps");
                if (ap != null) for (int k = 0; k < ap.length(); k++) p.apps.add(ap.getString(k));
                out.add(p);
            }
        } catch (Exception ignored) { }
        return out;
    }

    private static void saveProfiles(Context c, List<Profile> l) {
        try {
            JSONArray a = new JSONArray();
            for (Profile p : l) {
                JSONArray ap = new JSONArray();
                for (String s : p.apps) ap.put(s);
                a.put(new JSONObject().put("id", p.id).put("name", p.name).put("mode", p.mode).put("apps", ap));
            }
            Prefs.set(c, "fw_profiles", a.toString());
        } catch (Exception ignored) { }
    }

    /** Saves the current mode and app selection under a name (replacing a profile of the same name). */
    public static Profile saveProfile(Context c, String name) {
        List<Profile> l = profiles(c);
        Profile p = null;
        for (Profile x : l) if (x.name.equalsIgnoreCase(name)) p = x;
        if (p == null) { p = new Profile(); p.id = Long.toString(System.currentTimeMillis(), 36); l.add(p); }
        p.name = name; p.mode = mode(c); p.apps = selected(c);
        saveProfiles(c, l);
        Prefs.set(c, Prefs.FW_PROFILE, p.id);
        changed(c);
        return p;
    }

    public static void deleteProfile(Context c, String id) {
        List<Profile> l = profiles(c);
        for (int i = 0; i < l.size(); i++) if (l.get(i).id.equals(id)) { l.remove(i); break; }
        saveProfiles(c, l);
        if (id.equals(Prefs.str(c, Prefs.FW_PROFILE, ""))) Prefs.set(c, Prefs.FW_PROFILE, "");
        changed(c);
    }

    public static Profile findProfile(Context c, String idOrName) {
        if (idOrName == null) return null;
        for (Profile p : profiles(c)) if (p.id.equals(idOrName)) return p;
        for (Profile p : profiles(c)) if (p.name.equalsIgnoreCase(idOrName.trim())) return p;
        return null;
    }

    public static String activeProfileName(Context c) {
        Profile p = findProfile(c, Prefs.str(c, Prefs.FW_PROFILE, ""));
        return p == null ? null : p.name;
    }

    /** Switches to a profile; re-applies if the firewall is on (or turns it on if {@code forceEnable}). */
    public static void applyProfile(Context ctx, Profile p, boolean forceEnable, Done done) {
        Context c = ctx.getApplicationContext();
        Prefs.sp(c).edit().putString(Prefs.FW_MODE, p.mode).putStringSet(Prefs.FW_SELECTED, new HashSet<>(p.apps)).putString(Prefs.FW_PROFILE, p.id).apply();
        Events.add(Events.FW, "Profile: " + p.name, p.apps.size() + (MODE_ALLOW.equals(p.mode) ? " allowed apps" : " blocked apps"));
        if (active(c) || forceEnable) setEnabled(c, true, "profile " + p.name, done);
        else { changed(c); if (done != null) done.done(true, null); }
    }

    // ---------------------------------------------------------------- notification when it can't re-apply

    static final class NotificationManagerHolder {
        static final int ID = 0x7100;

        static void needsBackend(Context c) {
            Intent open = new Intent(c, MainActivity.class).putExtra("tab", 1).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            Notification n = new Notification.Builder(c, App.CH_FIREWALL)
                    .setSmallIcon(R.drawable.ic_stat)
                    .setContentTitle("Firewall is off after restart")
                    .setContentText("Start Shizuku and it turns back on by itself")
                    .setStyle(new Notification.BigTextStyle().bigText("Android clears firewall rules when the phone restarts. "
                            + "Start Shizuku (or allow root) and Groveguard re-applies them automatically."))
                    .setContentIntent(PendingIntent.getActivity(c, ID, open, PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT))
                    .setAutoCancel(true)
                    .build();
            c.getSystemService(NotificationManager.class).notify(ID, n);
        }

        static void cancel(Context c) { c.getSystemService(NotificationManager.class).cancel(ID); }
    }
}
