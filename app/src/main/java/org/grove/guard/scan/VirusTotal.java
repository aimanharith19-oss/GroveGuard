/*
 * Groveguard — malware scanner, link guard and firewall for Android.
 * Copyright (C) 2026 Groveguard contributors.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package org.grove.guard.scan;

import android.content.Context;

import org.grove.guard.Events;
import org.grove.guard.Prefs;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Optional second opinion from VirusTotal (70+ antivirus engines), using your own free API key.
 * VirusTotal has no downloadable signature database: each file is looked up by its SHA-256 fingerprint
 * (only the fingerprint is sent, never the file). The free key allows 4 lookups a minute and 500 a day,
 * so it's used for new apps, new risky downloads and files you share — not for whole-phone scans.
 */
public final class VirusTotal {
    private VirusTotal() { }

    public static final String KEY = "vt_key", AUTO = "vt_auto", MIN = "vt_min";

    public static final class Result {
        public boolean known;
        public int malicious, suspicious, total;
        public String label;

        public boolean bad(Context c) { return known && malicious >= Prefs.sp(c).getInt(MIN, 3); }

        public String summary() {
            if (!known) return "Not known to VirusTotal";
            return malicious + " of " + total + " engines flag it" + (label != null && !label.isEmpty() ? " (" + label + ")" : "");
        }
    }

    private static final ExecutorService QUEUE = Executors.newSingleThreadExecutor();
    private static long lastCall;

    public static boolean configured(Context c) { return Prefs.str(c, KEY, "").trim().length() >= 32; }

    public static boolean auto(Context c) { return configured(c) && Prefs.on(c, AUTO, true); }

    /** Looks up a SHA-256 now (blocking, waits for the rate limit). Null if no key or the lookup failed. */
    public static synchronized Result lookup(Context c, String sha256) {
        String key = Prefs.str(c, KEY, "").trim();
        if (key.length() < 32 || sha256 == null) return null;
        // daily allowance of the free key
        String day = new java.text.SimpleDateFormat("yyyyMMdd", Locale.ROOT).format(new java.util.Date());
        if (!day.equals(Prefs.str(c, "vt_day", ""))) Prefs.sp(c).edit().putString("vt_day", day).putInt("vt_used", 0).apply();
        if (Prefs.sp(c).getInt("vt_used", 0) >= 480) return null;
        long wait = 15500 - (System.currentTimeMillis() - lastCall); // 4 per minute
        if (wait > 0) try { Thread.sleep(wait); } catch (InterruptedException e) { return null; }
        lastCall = System.currentTimeMillis();
        Prefs.sp(c).edit().putInt("vt_used", Prefs.sp(c).getInt("vt_used", 0) + 1).apply();
        HttpURLConnection con = null;
        try {
            con = (HttpURLConnection) new URL("https://www.virustotal.com/api/v3/files/" + sha256.toLowerCase(Locale.ROOT)).openConnection();
            con.setRequestProperty("x-apikey", key);
            con.setConnectTimeout(20000);
            con.setReadTimeout(30000);
            int code = con.getResponseCode();
            Result r = new Result();
            if (code == 404) return r;
            if (code == 401 || code == 403) { Events.add(Events.ERROR, "VirusTotal refused the API key", "Check the key in Settings > VirusTotal."); return null; }
            if (code == 429) return null;
            if (code != 200) return null;
            ByteArrayOutputStream o = new ByteArrayOutputStream();
            try (InputStream in = con.getInputStream()) {
                byte[] buf = new byte[8192];
                int n;
                while ((n = in.read(buf)) > 0) o.write(buf, 0, n);
            }
            JSONObject a = new JSONObject(o.toString("UTF-8")).getJSONObject("data").getJSONObject("attributes");
            JSONObject st = a.optJSONObject("last_analysis_stats");
            r.known = true;
            if (st != null) {
                r.malicious = st.optInt("malicious");
                r.suspicious = st.optInt("suspicious");
                r.total = r.malicious + r.suspicious + st.optInt("undetected") + st.optInt("harmless");
            }
            JSONObject cls = a.optJSONObject("popular_threat_classification");
            if (cls != null) r.label = cls.optString("suggested_threat_label", null);
            return r;
        } catch (Exception e) {
            return null;
        } finally {
            if (con != null) con.disconnect();
        }
    }

    private static final String[] RISKY = {".apk", ".apks", ".xapk", ".apkm", ".zip", ".jar", ".dex", ".so", ".exe", ".dll", ".msi", ".bat",
            ".sh", ".js", ".vbs", ".ps1", ".pdf", ".doc", ".docx", ".docm", ".xls", ".xlsx", ".xlsm", ".ppt", ".pptx", ".rar", ".7z", ".bin", ".iso", ".lnk"};

    public static boolean risky(File f) {
        String n = f.getName().toLowerCase(Locale.ROOT);
        for (String e : RISKY) if (n.endsWith(e)) return true;
        return false;
    }

    /** Queues a background check of a file the local database didn't flag; reports it if enough engines do. */
    public static void checkLater(final Context ctx, final File f, final String origin) {
        if (!auto(ctx)) return;
        final Context c = ctx.getApplicationContext();
        QUEUE.execute(new Runnable() {
            @Override public void run() {
                Scanner.Hashes h = Scanner.hash(f);
                if (h == null) return;
                Result r = lookup(c, h.sha256);
                if (r != null && r.bad(c)) Detect.report(c, f, "VirusTotal " + r.malicious + "/" + r.total, h.sha256, origin + " · VirusTotal");
            }
        });
    }
}
