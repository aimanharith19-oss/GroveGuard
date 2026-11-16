/*
 * Groveguard — malware scanner, link guard and firewall for Android.
 * Copyright (C) 2026 Groveguard contributors.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package org.grove.guard.web;

import android.content.Context;

import org.grove.guard.App;
import org.grove.guard.Events;
import org.grove.guard.Prefs;
import org.grove.guard.StatusProvider;
import org.grove.guard.scan.Sigs;
import org.grove.guard.scan.WebCheck;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.StringReader;
import java.io.Writer;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

/**
 * Groveguard's own web filter, used by Grove Launcher's browser (and link checks): uBlock Origin / EasyList filter lists you
 * choose, optional 18+ lists, the dangerous-site list, and your own allow/block rules — with a log of what was checked.
 * Same lists and behaviour as the Groveguard browser extension.
 */
public final class WebFilter {
    private WebFilter() { }

    public static final class ListInfo {
        public final String id, group, name, url;
        public final boolean on, adult;

        ListInfo(String id, String group, String name, String url, boolean on, boolean adult) {
            this.id = id; this.group = group; this.name = name; this.url = url; this.on = on; this.adult = adult;
        }
    }

    private static final String UBO = "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/";
    public static final ListInfo[] LISTS = {
            new ListInfo("ubo-filters", "uBlock filters", "uBlock filters – Ads", UBO + "filters/filters.txt", true, false),
            new ListInfo("ubo-privacy", "uBlock filters", "uBlock filters – Privacy", UBO + "filters/privacy.txt", true, false),
            new ListInfo("ubo-badware", "uBlock filters", "uBlock filters – Badware risks", UBO + "filters/badware.txt", true, false),
            new ListInfo("ubo-quick", "uBlock filters", "uBlock filters – Quick fixes", UBO + "filters/quick-fixes.txt", true, false),
            new ListInfo("ubo-unbreak", "uBlock filters", "uBlock filters – Unbreak", UBO + "filters/unbreak.txt", true, false),
            new ListInfo("easylist", "Ads", "EasyList", UBO + "thirdparties/easylist/easylist.txt", true, false),
            new ListInfo("adguard-mobile", "Ads", "AdGuard – Mobile Ads", "https://filters.adtidy.org/extension/ublock/filters/11.txt", false, false),
            new ListInfo("easyprivacy", "Privacy", "EasyPrivacy", UBO + "thirdparties/easylist/easyprivacy.txt", true, false),
            new ListInfo("pgl", "Multipurpose", "Peter Lowe's Ad and tracking server list", UBO + "thirdparties/pgl.yoyo.org/as/serverlist", true, false),
            new ListInfo("urlhaus", "Malware protection", "Online Malicious URL Blocklist", "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-ag-online.txt", true, false),
            new ListInfo("ubo-annoyances", "Annoyances", "uBlock filters – Annoyances", UBO + "filters/annoyances-others.txt", false, false),
            new ListInfo("ubo-cookies", "Annoyances", "uBlock filters – Cookie notices", UBO + "filters/annoyances-cookies.txt", false, false),
            new ListInfo("easylist-cookies", "Annoyances", "EasyList – Cookie notices", UBO + "thirdparties/easylist/easylist-cookies.txt", false, false),
            new ListInfo("easylist-social", "Annoyances", "EasyList – Social widgets", UBO + "thirdparties/easylist/easylist-social.txt", false, false),
            new ListInfo("easylist-notifications", "Annoyances", "EasyList – Notifications", UBO + "thirdparties/easylist/easylist-notifications.txt", false, false),
            new ListInfo("oisd-nsfw", "Adult content (18+)", "OISD NSFW", "https://nsfw.oisd.nl/", false, true),
            new ListInfo("blp-porn", "Adult content (18+)", "Block List Project – Porn", "https://blocklistproject.github.io/Lists/porn.txt", false, true),
    };

    public static final String ENABLED = "web_blocking", MY_BLOCK = "web_my_block", MY_ALLOW = "web_my_allow", PAUSED = "web_paused";

    private static volatile AdRules rules;
    private static volatile List<DomainSet> adultSets = new ArrayList<>();
    private static volatile List<String> adultNames = new ArrayList<>();
    private static volatile DomainSet adult; // the switched-on 18+ lists, loaded on their own (fast) so they work from the first page
    private static volatile boolean adultLoaded;
    private static volatile int adultTotal;
    private static volatile boolean loading, updating;

    public interface Listener { void onWebChanged(); }

    private static final CopyOnWriteArrayList<Listener> listeners = new CopyOnWriteArrayList<>();

    public static void addListener(Listener l) { listeners.add(l); }

    public static void removeListener(Listener l) { listeners.remove(l); }

    static void changed() {
        App.MAIN.post(new Runnable() { @Override public void run() { for (Listener l : listeners) l.onWebChanged(); } });
    }

    // ---------------------------------------------------------------- settings

    public static boolean enabled(Context c) { return Prefs.on(c, ENABLED, true); }

    /** The 18+ lists are always on: they can't be switched off. */
    public static boolean listOn(Context c, ListInfo l) { return l.adult || Prefs.sp(c).getBoolean("web_list_" + l.id, l.on); }

    public static void setList(final Context c, ListInfo l, boolean on) {
        if (l.adult) on = true; // locked on
        Prefs.set(c, "web_list_" + l.id, on);
        final ListInfo fl = l;
        App.IO.execute(new Runnable() {
            @Override public void run() {
                if (listOn(c, fl) && !file(c, fl).exists()) {
                    String e = download(c, fl);
                    Prefs.set(c, "web_err_" + fl.id, e == null ? "" : e);
                }
                rebuild(c);
            }
        });
    }

    static ListInfo find(String id) { for (ListInfo l : LISTS) if (l.id.equals(id)) return l; return null; }

    public static List<String> myBlock(Context c) { List<String> l = new ArrayList<>(Prefs.set(c, MY_BLOCK)); Collections.sort(l); return l; }

    public static List<String> myAllow(Context c) { List<String> l = new ArrayList<>(Prefs.set(c, MY_ALLOW)); Collections.sort(l); return l; }

    /** list: "block", "allow" or "none". Accepts a site or a full address. */
    public static void setRule(Context c, String site, String list) {
        String h = normalise(site);
        if (h == null) return;
        Set<String> b = Prefs.set(c, MY_BLOCK), a = Prefs.set(c, MY_ALLOW);
        b.remove(h); a.remove(h);
        if ("block".equals(list)) b.add(h); else if ("allow".equals(list)) a.add(h);
        Prefs.set(c, MY_BLOCK, b); Prefs.set(c, MY_ALLOW, a);
        changed();
        StatusProvider.changed(c);
    }

    static String normalise(String s) {
        if (s == null) return null;
        String h = WebCheck.hostOfAddress(s.trim());
        if (h == null) return null;
        if (h.startsWith("*.")) h = h.substring(2);
        return h;
    }

    static boolean inList(Set<String> list, String host) {
        if (host == null || list.isEmpty()) return false;
        String cur = host;
        while (true) {
            if (list.contains(cur)) return true;
            int d = cur.indexOf('.');
            if (d < 0) return false;
            cur = cur.substring(d + 1);
        }
    }

    // ---------------------------------------------------------------- lists on disk

    static File dir(Context c) { File d = new File(c.getFilesDir(), "weblists"); //noinspection ResultOfMethodCallIgnored
        d.mkdirs(); return d; }

    static File file(Context c, ListInfo l) { return new File(dir(c), l.id + (l.adult ? ".dom" : ".gz")); }

    public static long updated(Context c, ListInfo l) { File f = file(c, l); return f.exists() ? f.lastModified() : 0; }

    public static int ruleCount(Context c, ListInfo l) { return Prefs.sp(c).getInt("web_count_" + l.id, 0); }

    public static int activeRules() { AdRules r = rules; int a = adult == null ? 0 : adultTotal; return (r == null ? 0 : r.size()) + a; }

    public static long lastUpdate(Context c) { return Prefs.sp(c).getLong("web_last_update", 0); }

    public static boolean busy() { return loading || updating; }

    private static String fetch(String url, int depth) throws Exception {
        HttpURLConnection con = (HttpURLConnection) new URL(url).openConnection();
        con.setConnectTimeout(30000);
        con.setReadTimeout(60000);
        con.setRequestProperty("User-Agent", "Groveguard");
        try {
            if (con.getResponseCode() != 200) throw new Exception("HTTP " + con.getResponseCode());
            ByteArrayOutputStream o = new ByteArrayOutputStream();
            try (InputStream in = con.getInputStream()) {
                byte[] buf = new byte[1 << 15];
                int n;
                while ((n = in.read(buf)) > 0) o.write(buf, 0, n);
            }
            StringBuilder text = new StringBuilder(o.toString("UTF-8"));
            if (depth < 2) {
                BufferedReader br = new BufferedReader(new StringReader(text.toString()));
                String line;
                List<String> inc = new ArrayList<>();
                while ((line = br.readLine()) != null) if (line.startsWith("!#include ")) inc.add(line.substring(10).trim());
                for (String i : inc) {
                    try { text.append('\n').append(fetch(new URI(url).resolve(i).toString(), depth + 1)); } catch (Exception ignored) { }
                }
            }
            return text.toString();
        } finally {
            con.disconnect();
        }
    }

    /** Downloads and compiles one list. Blocking. Returns an error or null. */
    static String download(Context c, ListInfo l) {
        if (l.adult) return downloadDomains(c, l);
        try {
            AdRules r = new AdRules();
            r.parse(new BufferedReader(new StringReader(fetch(l.url, 0))));
            File tmp = new File(dir(c), l.id + ".tmp");
            try (Writer w = new OutputStreamWriter(new GZIPOutputStream(new FileOutputStream(tmp)), "UTF-8")) { r.write(w); }
            if (!tmp.renameTo(file(c, l))) { //noinspection ResultOfMethodCallIgnored
                file(c, l).delete(); //noinspection ResultOfMethodCallIgnored
                tmp.renameTo(file(c, l)); }
            Prefs.sp(c).edit().putInt("web_count_" + l.id, r.size()).apply();
            return null;
        } catch (Exception e) {
            return l.name + ": " + e.getMessage();
        }
    }

    /** 18+ lists: streamed straight into a compact set (they're hundreds of thousands of sites). */
    private static String downloadDomains(Context c, ListInfo l) {
        HttpURLConnection con = null;
        try {
            con = (HttpURLConnection) new URL(l.url).openConnection();
            con.setConnectTimeout(30000);
            con.setReadTimeout(60000);
            con.setRequestProperty("User-Agent", "Groveguard");
            if (con.getResponseCode() != 200) throw new Exception("HTTP " + con.getResponseCode());
            DomainSet d;
            try (BufferedReader br = new BufferedReader(new InputStreamReader(con.getInputStream(), "UTF-8"), 1 << 16)) { d = DomainSet.parse(br); }
            if (d.size() < 100) throw new Exception("the list looks empty (" + d.size() + " sites)");
            d.save(file(c, l));
            Prefs.sp(c).edit().putInt("web_count_" + l.id, d.size()).apply();
            adultLoaded = false; // reload with the new list
            return null;
        } catch (Throwable e) {
            return l.name + ": " + e.getMessage();
        } finally {
            if (con != null) con.disconnect();
        }
    }

    /** Is any 18+ list switched on? */
    public static boolean adultWanted(Context c) { for (ListInfo l : LISTS) if (l.adult && listOn(c, l)) return true; return false; }

    /** Number of 18+ sites blocked right now (-1 = switched on but not downloaded yet). */
    public static int adultSites(Context c) {
        if (!adultWanted(c)) return 0;
        loadAdult(c);
        return adult == null ? -1 : adultTotal;
    }

    /** Loads the switched-on 18+ lists (milliseconds). */
    static synchronized void loadAdult(Context c) {
        if (adultLoaded) return;
        List<DomainSet> sets = new ArrayList<>();
        List<String> names = new ArrayList<>();
        int total = 0;
        for (ListInfo l : LISTS) {
            if (!l.adult || !listOn(c, l) || !file(c, l).exists()) continue;
            try { DomainSet d = DomainSet.load(file(c, l)); sets.add(d); names.add(l.name); total += d.size(); } catch (Throwable ignored) { }
        }
        adultSets = sets;
        adultNames = names;
        adult = sets.isEmpty() ? null : sets.get(0); // non-null = something loaded
        adultTotal = total;
        adultLoaded = true;
    }

    /** Rebuilds the active rules from the switched-on lists. Blocking. */
    public static synchronized void rebuild(Context c) {
        loading = true;
        try {
            adultLoaded = false;
            loadAdult(c);
            AdRules r = new AdRules();
            for (ListInfo l : LISTS) {
                if (l.adult || !listOn(c, l) || !file(c, l).exists()) continue;
                AdRules one = new AdRules();
                try (BufferedReader br = new BufferedReader(new InputStreamReader(new GZIPInputStream(new FileInputStream(file(c, l))), "UTF-8"))) {
                    one.readCompact(br);
                } catch (Exception ignored) { continue; }
                r.merge(one);
            }
            rules = r;
        } finally {
            loading = false;
            changed();
        }
    }

    public static void ensureLoaded(final Context c) {
        if (rules != null || loading) return;
        App.IO.execute(new Runnable() {
            @Override public void run() {
                rebuild(c);
                boolean missing = Prefs.sp(c).getInt("web_fmt", 1) < 2; // older downloads have no generic cosmetic filters or scriptlets
                if (missing) Prefs.sp(c).edit().putInt("web_fmt", 2).apply();
                final boolean all = missing;
                for (ListInfo l : LISTS) if (listOn(c, l) && !file(c, l).exists()) missing = true;
                if (missing || System.currentTimeMillis() - lastUpdate(c) > 24 * 3600 * 1000L) update(c, all);
            }
        });
    }

    /** Updates switched-on lists older than a day (or all, if force). Runs in the background. */
    public static void update(final Context ctx, final boolean force) {
        if (updating) return;
        updating = true;
        changed();
        final Context c = ctx.getApplicationContext();
        App.IO.execute(new Runnable() {
            @Override public void run() {
                List<String> errors = new ArrayList<>();
                int n = 0;
                try {
                    for (ListInfo l : LISTS) {
                        if (!listOn(c, l)) continue;
                        if (!force && System.currentTimeMillis() - updated(c, l) < 24 * 3600 * 1000L) continue;
                        String e = download(c, l);
                        Prefs.set(c, "web_err_" + l.id, e == null ? "" : e);
                        if (e != null) errors.add(e); else n++;
                    }
                    Prefs.sp(c).edit().putLong("web_last_update", System.currentTimeMillis()).apply();
                } finally {
                    updating = false;
                }
                rebuild(c);
                if (force || n > 0 || !errors.isEmpty())
                    Events.add(errors.isEmpty() ? Events.DB : Events.ERROR, errors.isEmpty() ? "Web filter lists updated" : "Some web filter lists failed",
                            errors.isEmpty() ? n + " lists · " + activeRules() + " filters" : errors.get(0));
            }
        });
    }

    // ---------------------------------------------------------------- checking

    public static final class Verdict {
        public boolean block;
        public String kind = "", why = ""; // kind: you, danger, adult, filter

        Verdict(boolean block, String kind, String why) { this.block = block; this.kind = kind; this.why = why; }
    }

    /** Checks a request (main = the page itself). pageHost may be null. Logs it. */
    public static Verdict check(Context c, String url, String pageHost, boolean main, String type, String app) {
        String host = null, path = "/";
        try {
            URI u = new URI(url);
            host = u.getHost();
            path = (u.getRawPath() == null ? "/" : u.getRawPath()) + (u.getRawQuery() == null ? "" : "?" + u.getRawQuery());
        } catch (Exception ignored) { }
        if (host == null) return new Verdict(false, "", "");
        host = host.toLowerCase(Locale.ROOT);
        Verdict v = decide(c, host, path, url, pageHost, main);
        log(new Entry(System.currentTimeMillis(), main ? "page" : (type == null ? "request" : type), host, url, pageHost, v.block, v.why, app));
        if (main) WebHistory.add(c, host, url, v.block, v.why, app);
        return v;
    }

    private static Verdict decide(Context c, String host, String path, String url, String pageHost, boolean main) {
        if (rules == null) ensureLoaded(c);
        if (!adultLoaded) loadAdult(c); // fast, so 18+ sites are blocked even on the first page after Groveguard starts
        { // 18+ is locked on: checked first, and not lifted by pausing a site or by your allow list
            List<DomainSet> sets = adultSets; List<String> names = adultNames;
            for (int i = 0; i < sets.size() && i < names.size(); i++) {
                String m = sets.get(i).match(host);
                if (m != null) return new Verdict(true, "adult", "18+ list: " + names.get(i) + (m.equals(host) ? "" : " (listed as " + m + ")"));
            }
        }
        if (inList(Prefs.set(c, MY_ALLOW), host)) return new Verdict(false, "you", "your allow list");
        if (inList(Prefs.set(c, MY_BLOCK), host)) return new Verdict(true, "you", "your block list");
        boolean paused = inList(Prefs.set(c, PAUSED), main ? host : pageHost);
        if (main) {
            WebCheck.Hit hit = Sigs.domainsLoaded() ? WebCheck.check(c, host) : null;
            if (hit != null && !paused) return new Verdict(true, "danger", "dangerous-site list" + (hit.listed.equals(host) ? "" : " (" + hit.listed + ")"));
            return new Verdict(false, "", paused ? "site paused" : "");
        }
        if (paused) return new Verdict(false, "", "site paused");
        AdRules r = rules;
        if (enabled(c) && r != null && r.shouldBlockUrl(host, path, pageHost, url)) return new Verdict(true, "filter", "filter lists");
        return new Verdict(false, "", "");
    }

    /** CSS hiding known ads on this site (for the launcher's browser), or null. */
    public static String css(Context c, String pageHost) {
        AdRules r = rules;
        if (r == null || pageHost == null || !enabled(c) || inList(Prefs.set(c, PAUSED), pageHost)) return null;
        return r.cssFor(pageHost);
    }

    // ---------------------------------------------------------------- generic element hiding + scriptlets (for Grove Launcher's browser)

    private static String scriptletLib, surveyor;
    private static AdRules surveyorFor;

    /** JavaScript that runs this page's scriptlets (switches off ad scripts), or null. Run it as early as possible in the page. */
    public static String scriptlets(Context c, String pageHost) {
        AdRules r = rules;
        if (r == null || pageHost == null || !enabled(c) || inList(Prefs.set(c, PAUSED), pageHost) || inList(Prefs.set(c, MY_ALLOW), pageHost)) return null;
        String list = r.scriptletsFor(pageHost);
        if (list == null) return null;
        synchronized (WebFilter.class) {
            if (scriptletLib == null) {
                try (BufferedReader br = new BufferedReader(new InputStreamReader(c.getAssets().open("scriptlets.js"), "UTF-8"))) {
                    StringBuilder sb = new StringBuilder();
                    String line;
                    while ((line = br.readLine()) != null) { if (!line.startsWith("if (typeof module")) sb.append(line).append('\n'); }
                    scriptletLib = sb.toString();
                } catch (Exception e) { return null; }
            }
        }
        return "(function(){" + scriptletLib + "\ngroveScriptlets(" + list + ");})();";
    }

    /** Selectors that must not be hidden on this page, as a JSON array (for the surveyor's window.__ggx). */
    public static String cosmeticExceptions(Context c, String pageHost) {
        AdRules r = rules;
        StringBuilder sb = new StringBuilder("[");
        if (r != null && pageHost != null) for (String s : r.exceptionsFor(pageHost)) { if (sb.length() > 1) sb.append(','); sb.append(AdRules.jsonString(s)); }
        return sb.append(']').toString();
    }

    /**
     * The "surveyor": JavaScript that hides elements matching the generic ".class" / "#id" cosmetic filters, looking only at
     * the names the page really uses (like uBlock Origin). Same for every page, so the caller can keep it; {@link #surveyorVersion} changes when the lists do.
     */
    public static String surveyor(Context c) {
        AdRules r = rules;
        if (r == null || !enabled(c)) return null;
        synchronized (WebFilter.class) {
            if (surveyor != null && surveyorFor == r) return surveyor;
            StringBuilder sb = new StringBuilder(r.genCls.size() * 16 + r.genId.size() * 16 + 2000);
            sb.append("(function(){if(window.__ggs)return;window.__ggs=1;var C=new Set(\"");
            boolean first = true;
            for (String n : r.genCls) { if (!first) sb.append(' '); sb.append(n); first = false; }
            sb.append("\".split(' ')),I=new Set(\"");
            first = true;
            for (String n : r.genId) { if (!first) sb.append(' '); sb.append(n); first = false; }
            sb.append("\".split(' ')),X=new Set(window.__ggx||[]),st=document.createElement('style'),seen=new Set(),q=[],t=0;"
                    + "(document.head||document.documentElement).appendChild(st);"
                    + "function flush(){t=0;if(!q.length)return;var css='';for(var i=0;i<q.length;i+=20)css+=q.slice(i,i+20).join(',')+'{display:none!important}';q=[];st.appendChild(document.createTextNode(css));}"
                    + "function add(s){if(seen.has(s))return;seen.add(s);if(X.has(s))return;q.push(s);if(!t)t=setTimeout(flush,100);}"
                    + "function note(el){if(el.nodeType!==1)return;var id=el.id;if(typeof id==='string'&&id&&I.has(id))add('#'+id);var cl=el.classList;if(cl)for(var i=0;i<cl.length;i++)if(C.has(cl[i]))add('.'+cl[i]);}"
                    + "function scan(r){if(!r||r.nodeType!==1)return;note(r);var a=r.querySelectorAll?r.querySelectorAll('[id],[class]'):[];for(var i=0;i<a.length&&i<20000;i++)note(a[i]);}"
                    + "scan(document.documentElement);"
                    + "new MutationObserver(function(ms){for(var i=0;i<ms.length;i++){var m=ms[i];if(m.type==='attributes')note(m.target);else for(var k=0;k<m.addedNodes.length;k++)scan(m.addedNodes[k]);}})"
                    + ".observe(document.documentElement,{childList:true,subtree:true,attributes:true,attributeFilter:['class','id']});})();");
            surveyor = sb.toString();
            surveyorFor = r;
            return surveyor;
        }
    }

    /** Changes whenever the surveyor script would. */
    public static int surveyorVersion() { AdRules r = rules; return r == null ? 0 : System.identityHashCode(r); }

    public static boolean paused(Context c, String host) { return inList(Prefs.set(c, PAUSED), host); }

    public static void setPaused(Context c, String host, boolean on) {
        String h = normalise(host);
        if (h == null) return;
        Set<String> s = Prefs.set(c, PAUSED);
        if (on) s.add(h); else s.remove(h);
        Prefs.set(c, PAUSED, s);
        changed();
    }

    // ---------------------------------------------------------------- log

    public static final class Entry {
        public final long time;
        public final String type, host, url, page, why, app;
        public final boolean blocked;

        Entry(long time, String type, String host, String url, String page, boolean blocked, String why, String app) {
            this.time = time; this.type = type; this.host = host; this.url = url.length() > 300 ? url.substring(0, 300) + "…" : url;
            this.page = page == null ? "" : page; this.blocked = blocked; this.why = why == null ? "" : why; this.app = app == null ? "" : app;
        }
    }

    private static final LinkedList<Entry> LOG = new LinkedList<>();
    private static final List<Entry> PENDING = new ArrayList<>();
    private static volatile boolean logLoaded, flushScheduled;
    private static final int LOG_KEEP = 3000;
    private static long lastNotify;

    // the log is saved on the phone (web-log.jsonl), so it survives Android closing Groveguard in the background
    private static File logFile() { Context c = App.ctx(); return c == null ? null : new File(c.getFilesDir(), "web-log.jsonl"); }

    private static void loadLog() {
        if (logLoaded) return;
        synchronized (LOG) {
            if (logLoaded) return;
            logLoaded = true;
            File f = logFile();
            if (f == null || !f.exists()) return;
            List<Entry> read = new ArrayList<>();
            try (BufferedReader br = new BufferedReader(new InputStreamReader(new FileInputStream(f), "UTF-8"))) {
                String line;
                while ((line = br.readLine()) != null) {
                    try {
                        org.json.JSONObject o = new org.json.JSONObject(line);
                        read.add(new Entry(o.optLong("t"), o.optString("y"), o.optString("h"), o.optString("u"), o.optString("p"), o.optBoolean("b"), o.optString("w"), o.optString("a")));
                    } catch (Exception ignored) { }
                }
            } catch (Exception ignored) { }
            for (Entry e : read) LOG.addFirst(e); // file is oldest first
            while (LOG.size() > LOG_KEEP) LOG.removeLast();
        }
    }

    private static void scheduleFlush() {
        if (flushScheduled) return;
        flushScheduled = true;
        App.MAIN.postDelayed(new Runnable() {
            @Override public void run() {
                flushScheduled = false;
                App.IO.execute(new Runnable() { @Override public void run() { flushLog(); } });
            }
        }, 2000);
    }

    private static void flushLog() {
        File f = logFile();
        if (f == null) return;
        List<Entry> out;
        synchronized (PENDING) { out = new ArrayList<>(PENDING); PENDING.clear(); }
        if (out.isEmpty()) return;
        synchronized (LOG) {
            try (Writer w = new OutputStreamWriter(new FileOutputStream(f, true), "UTF-8")) {
                for (Entry e : out) w.write(json(e) + "\n");
            } catch (Exception ignored) { }
            if (f.length() > LOG_KEEP * 2L * 400) { // rewrite with only the newest entries
                File tmp = new File(f.getPath() + ".tmp");
                try (Writer w = new OutputStreamWriter(new FileOutputStream(tmp), "UTF-8")) {
                    List<Entry> keep = new ArrayList<>(LOG);
                    for (int i = keep.size() - 1; i >= 0; i--) w.write(json(keep.get(i)) + "\n");
                } catch (Exception ignored) { return; }
                //noinspection ResultOfMethodCallIgnored
                tmp.renameTo(f);
            }
        }
    }

    private static String json(Entry e) {
        try {
            return new org.json.JSONObject().put("t", e.time).put("y", e.type).put("h", e.host).put("u", e.url).put("p", e.page)
                    .put("b", e.blocked).put("w", e.why).put("a", e.app).toString();
        } catch (Exception x) { return "{}"; }
    }

    static void log(Entry e) {
        loadLog();
        synchronized (LOG) {
            LOG.addFirst(e);
            while (LOG.size() > LOG_KEEP) LOG.removeLast();
        }
        synchronized (PENDING) { PENDING.add(e); }
        scheduleFlush();
        long now = System.currentTimeMillis();
        if (now - lastNotify > 1500) { lastNotify = now; changed(); }
    }

    public static List<Entry> log() { loadLog(); synchronized (LOG) { return new ArrayList<>(LOG); } }

    public static void clearLog() {
        loadLog();
        synchronized (PENDING) { PENDING.clear(); }
        synchronized (LOG) { LOG.clear(); File f = logFile(); if (f != null) //noinspection ResultOfMethodCallIgnored
            f.delete(); }
        changed();
    }

    public static int blockedCount() { int n = 0; synchronized (LOG) { for (Entry e : LOG) if (e.blocked) n++; } return n; }
}
