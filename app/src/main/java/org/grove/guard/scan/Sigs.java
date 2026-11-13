/*
 * Grove Guard — malware scanner, link guard and firewall for Android.
 * Copyright (C) 2026 Grove Guard contributors.
 * Database layout and sources from Hypatia (Copyright (C) 2017-2018 Divested Computing Group,
 * Copyleft 2025 MaintainTeam), rewritten.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package org.grove.guard.scan;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.NetworkCapabilities;
import android.os.PowerManager;

import org.grove.guard.App;
import org.grove.guard.Events;
import org.grove.guard.Prefs;
import org.grove.guard.StatusProvider;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.Socket;
import java.net.URL;
import java.text.NumberFormat;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * The signature databases: which server they come from, downloading them, checking their signatures and
 * loading them into memory.
 *
 * Fixes over Hypatia:
 *  - the signing key is pinned by its full fingerprint and shipped inside the app (Hypatia trusted the key file
 *    sent by the same server, matched only the end of a 64-bit key ID, and an empty key ID matched any key);
 *  - a new file is only put in place after its signature checks out, so a failed or half-finished download
 *    never leaves you without a working database;
 *  - one download at a time on a background thread with proper stream closing (no AsyncTask pile-up);
 *  - wake locks are released safely (Hypatia crashed when a slow update outlived its 3-minute wake lock);
 *  - sources don't need the main screen to have been opened first (Hypatia crashed at boot reading them).
 */
public final class Sigs {
    private Sigs() { }

    public static final String MT_FINGERPRINT = "B26EFC8E5B0C292AF882A1415298C0C0C3E73288";

    public static final class Source {
        public final String id, name, url, fingerprint, keyIdSuffix;

        Source(String id, String name, String url, String fingerprint, String keyIdSuffix) {
            this.id = id; this.name = name; this.url = url; this.fingerprint = fingerprint; this.keyIdSuffix = keyIdSuffix;
        }
    }

    public static final Source[] SOURCES = {
            new Source("mt_mirror", "MaintainTeam (GitHub)", "https://maintainteam.github.io/HypatiaDatabases/", MT_FINGERPRINT, null),
            new Source("mt_main", "MaintainTeam (Codeberg)", "https://maintainteam.codeberg.page/HypatiaDatabases/", MT_FINGERPRINT, null),
            // AXP.OS publishes only a short key ID; the full fingerprint is pinned the first time it is seen
            new Source("axp_os", "AXP.OS", "https://lav.axpos.org/db/", null, "14C17E7F99EABF3F"),
    };

    public static final String MD5 = "hypatia-md5-bloom.bin", MD5X = "hypatia-md5-extended-bloom.bin",
            SHA1 = "hypatia-sha1-bloom.bin", SHA256 = "hypatia-sha256-bloom.bin", DOMAINS = "hypatia-domains-bloom.bin";

    public static volatile Bloom md5, md5x, sha1, sha256, domains;
    private static volatile boolean loading, updating;
    private static volatile long count;

    public interface Listener { void onSigsChanged(); }

    private static final CopyOnWriteArrayList<Listener> listeners = new CopyOnWriteArrayList<>();

    public static void addListener(Listener l) { listeners.add(l); }

    public static void removeListener(Listener l) { listeners.remove(l); }

    private static void changed() {
        App.MAIN.post(new Runnable() { @Override public void run() { for (Listener l : listeners) l.onSigsChanged(); } });
        StatusProvider.changed(App.ctx());
    }

    // ---------------------------------------------------------------- state

    public static boolean loaded() { return md5 != null && sha1 != null && sha256 != null; }

    public static boolean domainsLoaded() { return domains != null; }

    public static boolean busy() { return loading || updating; }

    public static boolean updating() { return updating; }

    public static boolean loading() { return loading; }

    public static long count() { return count; }

    public static long lastUpdate(Context c) { return Prefs.sp(c).getLong("db_last_update", 0); }

    public static File dir(Context c) {
        File d = new File(c.getFilesDir(), "signatures");
        //noinspection ResultOfMethodCallIgnored
        d.mkdirs();
        return d;
    }

    public static boolean downloaded(Context c) {
        File d = dir(c);
        return new File(d, MD5).exists() && new File(d, SHA1).exists() && new File(d, SHA256).exists();
    }

    public static Source source(Context c) {
        String id = Prefs.str(c, Prefs.SOURCE, "mt_mirror");
        for (Source s : SOURCES) if (s.id.equals(id)) return s;
        if ("custom".equals(id)) {
            String url = Prefs.str(c, Prefs.CUSTOM_URL, "");
            if (!url.endsWith("/")) url += "/";
            return new Source("custom", "Custom server", url, PgpVerify.normFingerprint(Prefs.str(c, Prefs.CUSTOM_FP, "")), null);
        }
        return SOURCES[0];
    }

    /** Fingerprint the databases must be signed with: built in, entered by you, or pinned the first time. */
    public static String fingerprint(Context c, Source s) {
        if (s.fingerprint != null && !s.fingerprint.isEmpty()) return s.fingerprint;
        return Prefs.str(c, "fp_pin_" + s.id + "_" + s.url.hashCode(), "");
    }

    static List<String> wantedFiles(Context c) {
        List<String> l = new ArrayList<>();
        l.add(MD5); l.add(SHA1); l.add(SHA256);
        if (Prefs.on(c, Prefs.EXTENDED, false)) l.add(MD5X);
        if (Prefs.on(c, Prefs.WEB, false)) l.add(DOMAINS);
        return l;
    }

    // ---------------------------------------------------------------- loading

    /** Loads the downloaded databases in the background (no-op if already loaded and nothing changed). */
    public static void ensureLoaded(final Context c) {
        if (loading || updating) return;
        boolean needWeb = Prefs.on(c, Prefs.WEB, false) && domains == null && new File(dir(c), DOMAINS).exists();
        boolean needExt = Prefs.on(c, Prefs.EXTENDED, false) && md5x == null && new File(dir(c), MD5X).exists();
        if (loaded() && !needWeb && !needExt) return;
        if (!downloaded(c) && !needWeb) return;
        App.IO.execute(new Runnable() { @Override public void run() { loadNow(c.getApplicationContext()); } });
    }

    /** Loads (or reloads) every database file that is present and correctly signed. Runs on the calling thread. */
    public static synchronized void loadNow(Context c) {
        loading = true;
        changed();
        try {
            Source s = source(c);
            String fp = fingerprint(c, s);
            File d = dir(c);
            Bloom nMd5 = null, nMd5x = null, nSha1 = null, nSha256 = null, nDom = null;
            long n = 0;
            boolean bad = false;
            for (String name : wantedFiles(c)) {
                File f = new File(d, name), sig = new File(d, name + ".sig");
                if (!f.exists() || !sig.exists()) continue;
                if (!verified(c, f, sig, fp)) {
                    // don't keep a file we can't trust; the next update downloads it again
                    bad = true;
                    //noinspection ResultOfMethodCallIgnored
                    f.delete();
                    //noinspection ResultOfMethodCallIgnored
                    sig.delete();
                    continue;
                }
                Bloom b;
                try (InputStream in = new BufferedInputStream(new FileInputStream(f), 1 << 16)) { b = Bloom.read(in); }
                catch (OutOfMemoryError oom) { Events.add(Events.ERROR, "Not enough memory for " + name, "Turn off extended signatures."); continue; }
                if (MD5.equals(name)) nMd5 = b;
                else if (MD5X.equals(name)) nMd5x = b;
                else if (SHA1.equals(name)) nSha1 = b;
                else if (SHA256.equals(name)) nSha256 = b;
                else if (DOMAINS.equals(name)) nDom = b;
                if (!DOMAINS.equals(name)) n += b.approximateCount();
            }
            md5 = nMd5; md5x = nMd5x; sha1 = nSha1; sha256 = nSha256; domains = nDom;
            count = n;
            if (bad) Events.add(Events.ERROR, "A database failed its signature check",
                    "It was not used. Update the database, or check the signing key in Settings.");
            if (loaded() && !selfTest()) Events.add(Events.ERROR, "Database self-test failed", "The loaded database doesn't contain the test signatures.");
        } catch (Exception e) {
            Events.add(Events.ERROR, "Couldn't load the database", String.valueOf(e.getMessage()));
        } finally {
            loading = false;
            changed();
        }
    }

    private static boolean verified(Context c, File f, File sig, String fp) {
        if (fp.isEmpty()) return false;
        // the key that ships with the app first, then the one the server sent (must have the same fingerprint)
        if (MT_FINGERPRINT.equals(fp)) {
            try (InputStream k = c.getAssets().open("maintainteam-gpg.key")) {
                if (PgpVerify.verify(f, sig, k, fp)) return true;
            } catch (IOException ignored) { }
        }
        File key = new File(dir(c), "gpg.key");
        if (key.exists()) {
            try (InputStream k = new FileInputStream(key)) { return PgpVerify.verify(f, sig, k, fp); }
            catch (IOException ignored) { }
        }
        return false;
    }

    /** Test signatures every Hypatia database contains (hashes of the text "HypatiaHypatiaHypatia"). */
    public static boolean selfTest() {
        Bloom a = md5, b = sha1, s = sha256;
        return a != null && b != null && s != null
                && a.mightContain("903616d0dbe074aa363d2d49c03f7362") && a.mightContain("faf325d9d4b2a6c9457405eb31870b22")
                && b.mightContain("fc4a3e802894cc2229be77ec6f082d1aab744e54") && b.mightContain("04445ab9332cdca0031184165eb88a0a9dcec4ed")
                && s.mightContain("df44844a0e99ddd935e8419257440a2ca7ef3243435a67416fcbb6cd3ae560c3")
                && s.mightContain("3be403a831795482e82e2f9bc3e57ca34744aca3756e297b056b9f9c41830eaf");
    }

    /** True if this hash is a known-bad file. Empty-file hashes never match. */
    public static boolean matchMd5(String h) {
        if ("d41d8cd98f00b204e9800998ecf8427e".equals(h)) return false;
        Bloom a = md5, x = md5x;
        return (a != null && a.mightContain(h)) || (x != null && x.mightContain(h));
    }

    public static boolean matchSha1(String h) {
        Bloom b = sha1;
        return !"da39a3ee5e6b4b0d3255bfef95601890afd80709".equals(h) && b != null && b.mightContain(h);
    }

    public static boolean matchSha256(String h) {
        Bloom b = sha256;
        return !"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".equals(h) && b != null && b.mightContain(h);
    }

    // ---------------------------------------------------------------- updating

    public interface Progress { void on(String line); }

    /** Downloads any newer databases, checks them and reloads. Runs in the background; {@code p} may be null. */
    public static void update(final Context c, final boolean userAsked, final Progress p) {
        if (updating) return;
        updating = true;
        changed();
        App.IO.execute(new Runnable() {
            @Override public void run() {
                Context ac = c.getApplicationContext();
                PowerManager.WakeLock wl = ((PowerManager) ac.getSystemService(Context.POWER_SERVICE))
                        .newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "GroveGuard:update");
                wl.setReferenceCounted(false);
                wl.acquire(30 * 60 * 1000L);
                boolean changedAny = false;
                try {
                    changedAny = doUpdate(ac, userAsked, p);
                } catch (Exception e) {
                    say(p, "Update failed: " + e.getMessage());
                    Events.add(Events.ERROR, "Database update failed", String.valueOf(e.getMessage()));
                } finally {
                    updating = false;
                    if (wl.isHeld()) wl.release();
                }
                if (changedAny || !loaded() || (Prefs.on(ac, Prefs.WEB, false) && domains == null)) loadNow(ac);
                else changed();
            }
        });
    }

    private static void say(Progress p, String s) { if (p != null) p.on(s); }

    private static boolean doUpdate(Context c, boolean userAsked, Progress p) throws Exception {
        Source s = source(c);
        if (s.url.length() < 10 || !s.url.startsWith("https://")) throw new IOException("The database server address must start with https://");
        boolean onion = Prefs.on(c, Prefs.ONION, false);
        if (onion) {
            requestOrbot(c);
            say(p, "Waiting for Orbot…");
            if (!waitForOrbot()) throw new IOException("Orbot isn't running (Tor routing is on in Settings)");
        }
        File d = dir(c);
        // signing key (needed for servers without a built-in key, and for key rotation)
        File keyNew = new File(d, "gpg.key.new");
        int kr = fetch(s.url + "gpg.key", new File(d, "gpg.key"), keyNew, onion, true);
        if (kr == 200) {
            String fp;
            try (InputStream in = new FileInputStream(keyNew)) { fp = PgpVerify.firstFingerprint(in); }
            String pinned = fingerprint(c, s);
            if (pinned.isEmpty() && s.keyIdSuffix != null && fp.endsWith(s.keyIdSuffix)) {
                Prefs.set(c, "fp_pin_" + s.id + "_" + s.url.hashCode(), fp); // trust on first use, then pinned
                Events.add(Events.DB, "Pinned the " + s.name + " signing key", fp);
            }
            moveInto(keyNew, new File(d, "gpg.key"));
        } else keyNew.delete();
        String fp = fingerprint(c, s);
        if (fp.isEmpty()) throw new IOException("No signing key fingerprint for this server — enter it in Settings > Database");

        int fresh = 0, same = 0, failed = 0;
        for (String name : wantedFiles(c)) {
            File out = new File(d, name), outSig = new File(d, name + ".sig");
            File tmp = new File(d, name + ".new"), tmpSig = new File(d, name + ".sig.new");
            boolean have = out.exists() && outSig.exists();
            say(p, "Checking " + pretty(name) + "…");
            int r;
            try { r = fetch(s.url + name, have ? out : null, tmp, onion, false); }
            catch (IOException e) { say(p, pretty(name) + ": " + e.getMessage()); failed++; continue; }
            if (r == 304) { same++; say(p, pretty(name) + ": up to date"); continue; }
            if (r != 200) { failed++; say(p, pretty(name) + ": server answered " + r); tmp.delete(); continue; }
            try {
                int rs = fetch(s.url + name + ".sig", null, tmpSig, onion, false);
                if (rs != 200) throw new IOException("signature: server answered " + rs);
            } catch (IOException e) { failed++; tmp.delete(); tmpSig.delete(); say(p, pretty(name) + ": " + e.getMessage()); continue; }
            if (!verified(c, tmp, tmpSig, fp)) {
                failed++;
                tmp.delete(); tmpSig.delete();
                say(p, pretty(name) + ": signature check FAILED — not installed");
                continue;
            }
            // refuse an older database than the one installed (a replayed old file would hide newer malware)
            long newT = PgpVerify.sigTime(tmpSig), oldT = outSig.exists() ? PgpVerify.sigTime(outSig) : -1;
            if (newT > 0 && oldT > 0 && newT < oldT) {
                failed++;
                tmp.delete(); tmpSig.delete();
                say(p, pretty(name) + ": older than the installed one — refused");
                continue;
            }
            if (newT > System.currentTimeMillis() / 1000 + 2 * 86400) {
                failed++;
                tmp.delete(); tmpSig.delete();
                say(p, pretty(name) + ": signed with a date in the future — refused");
                continue;
            }
            moveInto(tmpSig, outSig);
            moveInto(tmp, out);
            fresh++;
            say(p, pretty(name) + ": updated (" + human(out.length()) + ")");
        }
        // remove databases that were turned off, to save space and memory
        if (!Prefs.on(c, Prefs.EXTENDED, false)) { new File(d, MD5X).delete(); new File(d, MD5X + ".sig").delete(); }
        if (!Prefs.on(c, Prefs.WEB, false)) { new File(d, DOMAINS).delete(); new File(d, DOMAINS + ".sig").delete(); }

        if (failed == 0) Prefs.sp(c).edit().putLong("db_last_update", System.currentTimeMillis()).apply();
        String summary = (fresh > 0 ? fresh + " updated" : "") + (same > 0 ? (fresh > 0 ? ", " : "") + same + " already current" : "")
                + (failed > 0 ? ((fresh + same) > 0 ? ", " : "") + failed + " failed" : "");
        if (userAsked || fresh > 0 || failed > 0)
            Events.add(failed > 0 ? Events.ERROR : Events.DB, failed > 0 ? "Database update had problems" : "Database updated", summary + " · " + s.name);
        return fresh > 0;
    }

    private static String pretty(String name) {
        switch (name) {
            case MD5: return "MD5 signatures";
            case MD5X: return "Extended MD5 signatures";
            case SHA1: return "SHA-1 signatures";
            case SHA256: return "SHA-256 signatures";
            case DOMAINS: return "Dangerous website list";
            default: return name;
        }
    }

    public static String human(long bytes) {
        if (bytes < 1024 * 1024) return NumberFormat.getInstance().format(bytes / 1024) + " KB";
        return String.format(java.util.Locale.getDefault(), "%.1f MB", bytes / 1048576.0);
    }

    private static void moveInto(File from, File to) throws IOException {
        if (!from.renameTo(to)) {
            //noinspection ResultOfMethodCallIgnored
            to.delete();
            if (!from.renameTo(to)) throw new IOException("Couldn't save " + to.getName());
        }
    }

    /**
     * Downloads {@code url} into {@code tmp}. If {@code existing} is given, asks the server to skip it when unchanged.
     * @return HTTP status (304 = unchanged)
     */
    private static int fetch(String url, File existing, File tmp, boolean onion, boolean quiet) throws IOException {
        HttpURLConnection con = null;
        try {
            con = (HttpURLConnection) (onion ? new URL(url).openConnection(new Proxy(Proxy.Type.SOCKS, new InetSocketAddress("127.0.0.1", 9050)))
                    : new URL(url).openConnection());
            con.setConnectTimeout(onion ? 90000 : 30000);
            con.setReadTimeout(60000);
            con.setRequestProperty("User-Agent", "GroveGuard");
            if (existing != null && existing.exists()) con.setIfModifiedSince(existing.lastModified());
            int code = con.getResponseCode();
            if (code != 200) return code;
            try (InputStream in = new BufferedInputStream(con.getInputStream(), 1 << 16); OutputStream out = new FileOutputStream(tmp)) {
                byte[] buf = new byte[1 << 16];
                int n;
                while ((n = in.read(buf)) > 0) out.write(buf, 0, n);
            }
            long lm = con.getLastModified();
            if (lm > 0) //noinspection ResultOfMethodCallIgnored
                tmp.setLastModified(lm);
            return 200;
        } catch (IOException e) {
            //noinspection ResultOfMethodCallIgnored
            tmp.delete();
            if (quiet) return -1;
            throw e;
        } finally {
            if (con != null) con.disconnect();
        }
    }

    // ---------------------------------------------------------------- network helpers

    public static boolean networkOk(Context c, boolean allowMetered) {
        ConnectivityManager cm = c.getSystemService(ConnectivityManager.class);
        if (cm == null || cm.getActiveNetwork() == null) return false;
        NetworkCapabilities nc = cm.getNetworkCapabilities(cm.getActiveNetwork());
        if (nc == null || !nc.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) return false;
        return allowMetered || !cm.isActiveNetworkMetered();
    }

    public static boolean metered(Context c) {
        ConnectivityManager cm = c.getSystemService(ConnectivityManager.class);
        return cm != null && cm.isActiveNetworkMetered();
    }

    private static void requestOrbot(Context c) {
        android.content.Intent i = new android.content.Intent("org.torproject.android.intent.action.START");
        i.setPackage("org.torproject.android");
        i.putExtra("org.torproject.android.intent.extra.PACKAGE_NAME", c.getPackageName());
        c.sendBroadcast(i);
    }

    private static boolean waitForOrbot() {
        for (int i = 0; i < 60; i++) {
            try (Socket s = new Socket()) {
                s.connect(new InetSocketAddress("127.0.0.1", 9050), 1000);
                return true;
            } catch (IOException e) {
                try { Thread.sleep(1000); } catch (InterruptedException ie) { return false; }
            }
        }
        return false;
    }

    /** Rough download size in MB for the current choice of databases. */
    public static int downloadSizeMb(Context c) {
        int mb = 30;
        if (Prefs.on(c, Prefs.EXTENDED, false)) mb += 170;
        if (Prefs.on(c, Prefs.WEB, false)) mb += 14;
        return mb;
    }
}
