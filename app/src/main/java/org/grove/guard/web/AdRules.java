/*
 * Copyright 2026 The Canopy Launcher authors (Grove Launcher's filter engine, shared with Groveguard)
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Generic URL patterns added for Groveguard.
 */
package org.grove.guard.web;

import java.io.BufferedReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Reads uBlock Origin / EasyList style filter lists (the same lists uBlock Origin uses) and keeps the parts
 * a WebView can apply: domain blocking ("||ads.example^"), exceptions ("@@||…^") and site-specific element
 * hiding ("example.com##.ad-banner"). Scriptlets and other extension-only filters are skipped.
 * Plain Java, so it can also be tested off-device.
 */
public final class AdRules {
    public final Set<String> block = new HashSet<>();
    public final Set<String> block3p = new HashSet<>();
    public final Set<String> allow = new HashSet<>();
    /** host -> CSS selectors to hide on that site (and its subdomains). Entries starting with '@' are whole CSS rules. */
    public final Map<String, List<String>> hide = new HashMap<>();
    /** host -> path patterns ("||host/path*^" rules), and the third-party-only ones. */
    public final Map<String, List<String>> paths = new HashMap<>(), paths3p = new HashMap<>();
    /** Generic URL patterns ("/fbevents.js"), indexed by their longest word: block, third-party-only, exceptions. */
    public final Map<String, List<String>> gen = new HashMap<>(), gen3p = new HashMap<>(), genAllow = new HashMap<>();

    /** Cosmetic filters for every site: simple ".class" / "#id" by name, the rest ("complex") as selectors; exceptions (#@#). */
    public final Set<String> genCls = new HashSet<>(), genId = new HashSet<>(), genCx = new java.util.LinkedHashSet<>(), exGen = new HashSet<>();
    public final Map<String, List<String>> exSite = new HashMap<>();
    /** host -> scriptlets (+js filters) as JSON arrays ["name","arg",…]; host -> scriptlet names switched off there. */
    public final Map<String, List<String>> js = new HashMap<>(), jsEx = new HashMap<>();

    private static final Map<String, String> ALIAS = new HashMap<>();
    private static final Set<String> SCRIPTLETS = new HashSet<>();
    static {
        String[] al = {"set-constant", "set", "abort-on-property-read", "aopr", "abort-on-property-write", "aopw", "abort-current-script", "acs",
                "abort-current-inline-script", "acs", "acis", "acs", "no-setTimeout-if", "nostif", "prevent-setTimeout", "nostif", "no-setInterval-if", "nosiif",
                "prevent-setInterval", "nosiif", "prevent-fetch", "no-fetch-if", "prevent-xhr", "no-xhr-if", "addEventListener-defuser", "aeld",
                "prevent-addEventListener", "aeld", "window.open-defuser", "nowoif", "no-window-open-if", "nowoif", "prevent-window-open", "nowoif",
                "remove-attr", "ra", "remove-class", "rc", "remove-node-text", "rmnt", "prevent-eval-if", "noeval-if", "adjust-setTimeout", "nano-stb",
                "nano-setTimeout-booster", "nano-stb", "adjust-setInterval", "nano-sib", "nano-setInterval-booster", "nano-sib", "silent-noeval", "noeval"};
        for (int i = 0; i < al.length; i += 2) ALIAS.put(al[i], al[i + 1]);
        for (String n : new String[]{"set", "aopr", "aopw", "acs", "nostif", "nosiif", "no-fetch-if", "no-xhr-if", "aeld", "nowoif", "ra", "rc", "rmnt",
                "noeval-if", "noeval", "nano-stb", "nano-sib", "json-prune", "nowebrtc"}) SCRIPTLETS.add(n);
    }
    private static String alias(String n) { String a = ALIAS.get(n); return a == null ? n : a; }

    private static final Set<String> OK_OPTS = new HashSet<>();
    static {
        for (String o : new String[]{"third-party", "3p", "script", "image", "xmlhttprequest", "xhr", "subdocument",
                "frame", "all", "important", "media", "object", "ping", "stylesheet", "css", "font", "websocket", "other"})
            OK_OPTS.add(o);
    }

    public int size() { return block.size() + block3p.size() + count(paths) + count(paths3p) + count(gen) + count(gen3p) + count(hide)
            + genCls.size() + genId.size() + genCx.size() + count(js); }

    /** Adds everything from another rule set. */
    public void merge(AdRules o) {
        block.addAll(o.block); block3p.addAll(o.block3p); allow.addAll(o.allow);
        mergeMap(hide, o.hide); mergeMap(paths, o.paths); mergeMap(paths3p, o.paths3p);
        mergeMap(gen, o.gen); mergeMap(gen3p, o.gen3p); mergeMap(genAllow, o.genAllow);
        genCls.addAll(o.genCls); genId.addAll(o.genId); genCx.addAll(o.genCx); exGen.addAll(o.exGen);
        mergeMap(exSite, o.exSite); mergeMap(js, o.js); mergeMap(jsEx, o.jsEx);
    }

    private static void mergeMap(Map<String, List<String>> to, Map<String, List<String>> from) {
        for (Map.Entry<String, List<String>> e : from.entrySet()) for (String v : e.getValue()) put(to, e.getKey(), v);
    }

    private void generic(String l, boolean ex) {
        int dollar = l.lastIndexOf('$');
        String pat = dollar >= 0 ? l.substring(0, dollar) : l;
        boolean tp = false;
        if (dollar >= 0) for (String o : l.substring(dollar + 1).split(",")) {
            if (!OK_OPTS.contains(o)) return;
            if (o.equals("third-party") || o.equals("3p")) tp = true;
        }
        if (pat.startsWith("/") && pat.endsWith("/") && pat.length() > 2) return; // regex rules: not supported
        boolean anchored = false;
        if (pat.startsWith("|")) { anchored = true; pat = pat.substring(1); }
        if (pat.endsWith("|")) pat = pat.substring(0, pat.length() - 1) + "^";
        pat = pat.toLowerCase();
        String key = null;
        for (String w : pat.split("[^a-z0-9%]+")) if (w.length() >= 4 && (key == null || w.length() > key.length())) key = w;
        if (key == null) return; // too vague to index safely
        put(ex ? genAllow : (tp ? gen3p : gen), key, (anchored ? "|" : "") + pat);
    }

    private static boolean genericHit(Map<String, List<String>> m, String url, String[] words) {
        for (String w : words) {
            if (w.length() < 4) continue;
            List<String> l = m.get(w);
            if (l == null) continue;
            for (String p : l) {
                if (p.startsWith("|")) { if (glob(p, 1, url, 0)) return true; continue; }
                int st = 0;
                while (st < p.length() && p.charAt(st) == '*') st++;
                String first = p.substring(st);
                int cut = 0;
                while (cut < first.length() && first.charAt(cut) != '*' && first.charAt(cut) != '^') cut++;
                String lit = first.substring(0, cut);
                for (int i = url.indexOf(lit); i >= 0; i = url.indexOf(lit, i + 1)) if (glob(first, 0, url, i)) return true;
            }
        }
        return false;
    }

    /** Full check including generic URL patterns. */
    public boolean shouldBlockUrl(String requestHost, String path, String pageHost, String fullUrl) {
        if (shouldBlock(requestHost, path, pageHost)) return true;
        if (fullUrl == null || (gen.isEmpty() && gen3p.isEmpty())) return false;
        String url = fullUrl.toLowerCase();
        String[] words = url.split("[^a-z0-9%]+");
        boolean third = pageHost == null || !site(requestHost.toLowerCase()).equals(site(pageHost.toLowerCase()));
        if (!genericHit(gen, url, words) && !(third && genericHit(gen3p, url, words))) return false;
        if (genericHit(genAllow, url, words)) return false;
        String cur = requestHost.toLowerCase();
        while (true) {
            if (allow.contains(cur)) return false;
            int dot = cur.indexOf('.');
            if (dot < 0 || cur.indexOf('.', dot + 1) < 0) break;
            cur = cur.substring(dot + 1);
        }
        return true;
    }

    private static int count(Map<String, List<String>> m) { int n = 0; for (List<String> l : m.values()) n += l.size(); return n; }

    private static void put(Map<String, List<String>> m, String k, String v) {
        List<String> l = m.get(k);
        if (l == null) m.put(k, l = new ArrayList<>());
        l.add(v);
    }

    public void parse(BufferedReader r) throws IOException {
        String line;
        while ((line = r.readLine()) != null) parseLine(line.trim());
    }

    public void parseLine(String l) {
        if (l.isEmpty() || l.startsWith("!") || l.startsWith("[") || (l.startsWith("#") && !l.startsWith("##") && !l.startsWith("#@#"))) return;
        // hosts-file format (Peter Lowe's list)
        if (l.startsWith("127.0.0.1 ") || l.startsWith("0.0.0.0 ")) {
            String h = l.substring(l.indexOf(' ') + 1).trim();
            if (isDomain(h)) block.add(h.toLowerCase());
            return;
        }
        int cos = l.indexOf("##");
        int exAt = l.indexOf("#@#");
        if (exAt >= 0 && l.indexOf("#?#") < 0 && l.indexOf("#$#") < 0) { cosmeticException(l.substring(0, exAt), l.substring(exAt + 3)); return; }
        if (cos == 0 && l.indexOf("#?#") < 0 && l.indexOf("#$#") < 0) { genericCosmetic(l.substring(2)); return; }
        if (cos > 0 && l.indexOf("#@#") < 0 && l.indexOf("#?#") < 0 && l.indexOf("#$#") < 0) {
            cosmetic(l.substring(0, cos), l.substring(cos + 2));
            return;
        }
        if (cos >= 0 || l.contains("#@#") || l.contains("#?#") || l.contains("#$#") || l.contains("#%#")) return;
        boolean exception = l.startsWith("@@");
        if (exception) l = l.substring(2);
        if (!l.startsWith("||")) { generic(l, exception); return; }
        // host part ends at the first ^, / or *
        int end = 2;
        while (end < l.length() && "^/*$".indexOf(l.charAt(end)) < 0) end++;
        String host = l.substring(2, end);
        if (!isDomain(host) || end >= l.length()) return;
        int dollar = l.indexOf('$', end);
        String pattern = l.substring(end, dollar < 0 ? l.length() : dollar);
        if (!pattern.startsWith("^") || pattern.length() > 1) {
            // a path rule, e.g. ||redditstatic.com/shreddit/*/xpromo-modal-$script
            if (exception || pattern.length() < 2 || pattern.charAt(0) == '*') return;
            boolean tp = false;
            if (dollar >= 0) for (String o : l.substring(dollar + 1).split(",")) {
                if (!OK_OPTS.contains(o)) return;
                if (o.equals("third-party") || o.equals("3p")) tp = true;
            }
            put(tp ? paths3p : paths, host.toLowerCase(), pattern);
            return;
        }
        String rest = l.substring(end + 1);
        boolean thirdParty = false;
        if (!rest.isEmpty()) {
            if (rest.charAt(0) != '$') return; // a path after the domain: not a whole-domain rule
            for (String o : rest.substring(1).split(",")) {
                if (!OK_OPTS.contains(o)) return; // domain=, ~third-party, redirect, removeparam, badfilter…
                if (o.equals("third-party") || o.equals("3p")) thirdParty = true;
            }
        }
        host = host.toLowerCase();
        if (exception) allow.add(host);
        else if (thirdParty) block3p.add(host);
        else block.add(host);
    }

    private static boolean badSelector(String selector) {
        return selector.startsWith("+js(") || selector.contains(":has-text(") || selector.contains(":-abp-")
                || selector.contains(":upward(") || selector.contains(":remove(") || selector.contains(":style(")
                || selector.contains(":xpath(") || selector.contains(":matches-") || selector.contains(":watch-attr(")
                || selector.contains(":min-text-length(") || selector.contains(":others(") || selector.startsWith("^")
                || selector.contains(":matches-path(") || selector.contains(":remove-attr(") || selector.contains(":remove-class(")
                || selector.contains("{") || selector.isEmpty();
    }

    private static boolean isName(String s) {
        if (s.isEmpty()) return false;
        for (int i = 0; i < s.length(); i++) { char c = s.charAt(i); if (!(Character.isLetterOrDigit(c) && c < 128) && c != '_' && c != '-') return false; }
        return true;
    }

    /** ##selector: hidden on every site. */
    private void genericCosmetic(String sel) {
        if (sel.length() > 300 || badSelector(sel) || sel.contains(":has(")) return;
        char c = sel.charAt(0);
        if ((c == '.' || c == '#') && isName(sel.substring(1))) (c == '.' ? genCls : genId).add(sel.substring(1));
        else if (genCx.size() < 3000) genCx.add(sel);
    }

    /** #@#selector (never hidden anywhere) or site#@#selector / site#@#+js(name). */
    private void cosmeticException(String domains, String sel) {
        if (sel.isEmpty()) return;
        if (domains.isEmpty()) { if (!sel.startsWith("+js(")) exGen.add(sel); return; }
        for (String d : domains.split(",")) {
            d = d.trim().toLowerCase();
            if (d.isEmpty() || d.startsWith("~") || !isDomain(d)) continue;
            if (sel.startsWith("+js(")) {
                String body = sel.endsWith(")") ? sel.substring(4, sel.length() - 1) : sel.substring(4);
                put(jsEx, d, alias(body.split(",")[0].trim()));
            } else put(exSite, d, sel);
        }
    }

    /** "a, b\\, c, /re,x/" → arguments. */
    static List<String> splitArgs(String body) {
        List<String> out = new ArrayList<>();
        StringBuilder cur = new StringBuilder();
        boolean re = false;
        for (int i = 0; i < body.length(); i++) {
            char ch = body.charAt(i);
            if (ch == '\\' && i + 1 < body.length()) {
                if (body.charAt(i + 1) == ',') cur.append(','); else cur.append(ch).append(body.charAt(i + 1));
                i++; continue;
            }
            if (ch == '/') { if (re) re = false; else if (cur.toString().trim().isEmpty()) re = true; }
            if (ch == ',' && !re) { out.add(cur.toString().trim()); cur.setLength(0); continue; }
            cur.append(ch);
        }
        out.add(cur.toString().trim());
        for (int i = 0; i < out.size(); i++) {
            String a = out.get(i);
            if (a.length() > 1 && ((a.charAt(0) == '"' && a.endsWith("\"")) || (a.charAt(0) == '\'' && a.endsWith("'")))) out.set(i, a.substring(1, a.length() - 1));
        }
        return out;
    }

    static String jsonString(String s) {
        StringBuilder b = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '"' || c == '\\') b.append('\\').append(c);
            else if (c == '<') b.append("\\u003c"); // never lets a page-injected script end early
            else if (c < 0x20 || c == 0x2028 || c == 0x2029) b.append(String.format("\\u%04x", (int) c));
            else b.append(c);
        }
        return b.append('"').toString();
    }

    /** site##+js(name, arg, …): a scriptlet that switches off an ad script on that site. */
    private void scriptlet(String domains, String body) {
        List<String> args = splitArgs(body);
        String name = alias(args.get(0));
        if (!SCRIPTLETS.contains(name)) return;
        StringBuilder json = new StringBuilder("[").append(jsonString(name));
        for (int i = 1; i < args.size(); i++) json.append(',').append(jsonString(args.get(i)));
        json.append(']');
        for (String d : domains.split(",")) {
            d = d.trim().toLowerCase();
            if (d.isEmpty() || d.startsWith("~") || d.contains("*") || d.contains("/") || !isDomain(d)) continue;
            List<String> l = js.get(d);
            if (l == null || l.size() < 60) put(js, d, json.toString());
        }
    }

    private void cosmetic(String domains, String selector) {
        if (selector.startsWith("+js(") && selector.endsWith(")")) { scriptlet(domains, selector.substring(4, selector.length() - 1)); return; }
        // "selector:style(css)" → a whole CSS rule (e.g. reddit.com##body:style(overflow: auto !important;))
        int st = selector.indexOf(":style(");
        if (st > 0 && selector.endsWith(")") && selector.indexOf(":style(", st + 1) < 0) {
            String sel = selector.substring(0, st), css = selector.substring(st + 7, selector.length() - 1);
            if (!sel.contains(":has-text(") && !sel.contains(":-abp-") && !sel.contains(":upward(") && !css.contains("{") && !css.contains("}")
                    && !css.contains("url(")) {
                for (String d : domains.split(",")) {
                    d = d.trim().toLowerCase();
                    if (d.isEmpty() || d.startsWith("~") || d.contains("*") || d.contains("/") || !isDomain(d)) continue;
                    put(hide, d, "@" + sel + "{" + css + "}");
                }
            }
            return;
        }
        if (badSelector(selector)) return;
        for (String d : domains.split(",")) {
            d = d.trim().toLowerCase();
            if (d.isEmpty() || d.startsWith("~") || d.contains("*") || d.contains("/") || !isDomain(d)) continue;
            List<String> l = hide.get(d);
            if (l == null) hide.put(d, l = new ArrayList<>());
            if (l.size() < 400) l.add(selector);
        }
    }

    static boolean isDomain(String h) {
        if (h.length() < 3 || h.indexOf('.') < 0) return false;
        for (int i = 0; i < h.length(); i++) {
            char c = h.charAt(i);
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_')) return false;
        }
        return true;
    }

    /** example: "a.b.c.com" → "c.com" (rough: good enough to tell first- from third-party). */
    static String site(String host) {
        if (host == null) return "";
        String[] p = host.split("\\.");
        int n = p.length;
        if (n <= 2) return host;
        String tld2 = p[n - 2];
        boolean sld = tld2.length() <= 3 && (tld2.equals("co") || tld2.equals("com") || tld2.equals("net") || tld2.equals("org")
                || tld2.equals("gov") || tld2.equals("edu") || tld2.equals("ac") || tld2.equals("or") || tld2.equals("ne"));
        int keep = sld && p[n - 1].length() == 2 ? 3 : 2;
        StringBuilder sb = new StringBuilder();
        for (int i = n - keep; i < n; i++) { if (sb.length() > 0) sb.append('.'); sb.append(p[i]); }
        return sb.toString();
    }

    /** Like shouldBlock, but also checks path rules against the request's path (+ query). */
    public boolean shouldBlock(String requestHost, String path, String pageHost) {
        if (shouldBlock(requestHost, pageHost)) return true;
        if (requestHost == null || path == null || (paths.isEmpty() && paths3p.isEmpty())) return false;
        String h = requestHost.toLowerCase();
        boolean third = pageHost == null || !site(h).equals(site(pageHost.toLowerCase()));
        String cur = h;
        while (true) {
            if (allow.contains(cur)) return false;
            if (matchAny(paths.get(cur), path) || (third && matchAny(paths3p.get(cur), path))) return true;
            int dot = cur.indexOf('.');
            if (dot < 0 || cur.indexOf('.', dot + 1) < 0) break;
            cur = cur.substring(dot + 1);
        }
        return false;
    }

    private static boolean matchAny(List<String> pats, String path) {
        if (pats == null) return false;
        for (String p : pats) if (glob(p, 0, path, 0)) return true;
        return false;
    }

    /** Adblock pattern match, anchored at the start of the path: '*' = anything, '^' = a separator or the end. */
    static boolean glob(String p, int pi, String s, int si) {
        while (pi < p.length()) {
            char c = p.charAt(pi);
            if (c == '*') {
                while (pi < p.length() && p.charAt(pi) == '*') pi++;
                if (pi == p.length()) return true;
                for (int k = si; k <= s.length(); k++) if (glob(p, pi, s, k)) return true;
                return false;
            }
            if (c == '^') {
                if (si == s.length()) { pi++; continue; }
                char x = s.charAt(si);
                if (Character.isLetterOrDigit(x) || x == '_' || x == '-' || x == '.' || x == '%') return false;
                pi++; si++;
                continue;
            }
            if (si >= s.length() || s.charAt(si) != c) return false;
            pi++; si++;
        }
        return true; // a pattern may end before the URL does
    }

    /** Should a sub-resource from requestHost, loaded by a page on pageHost, be blocked? */
    public boolean shouldBlock(String requestHost, String pageHost) {
        if (requestHost == null) return false;
        String h = requestHost.toLowerCase();
        boolean third = pageHost == null || !site(h).equals(site(pageHost.toLowerCase()));
        String cur = h;
        boolean hit = false;
        while (true) {
            if (allow.contains(cur)) return false;
            if (!hit && (block.contains(cur) || (third && block3p.contains(cur)))) hit = true;
            int dot = cur.indexOf('.');
            if (dot < 0 || cur.indexOf('.', dot + 1) < 0) break;
            cur = cur.substring(dot + 1);
        }
        return hit;
    }

    /** Every entry for host and its parent domains. */
    private static List<String> forHost(Map<String, List<String>> m, String host) {
        List<String> out = new ArrayList<>();
        String cur = host.toLowerCase();
        while (true) {
            List<String> l = m.get(cur);
            if (l != null) out.addAll(l);
            int dot = cur.indexOf('.');
            if (dot < 0) break;
            cur = cur.substring(dot + 1);
        }
        return out;
    }

    private static void hideCss(StringBuilder sb, List<String> sels) {
        // in groups, so one selector the browser doesn't understand only loses its own group
        for (int i = 0; i < sels.size(); i += 20) {
            for (int k = i; k < Math.min(i + 20, sels.size()); k++) { if (k > i) sb.append(",\n"); sb.append(sels.get(k)); }
            sb.append("{display:none!important}\n");
        }
    }

    /** CSS for a page: its own cosmetic filters + the complex generic ones, minus exceptions. Null if none. */
    public String cssFor(String pageHost) {
        if (pageHost == null) return null;
        Set<String> ex = new HashSet<>(forHost(exSite, pageHost));
        List<String> sels = new ArrayList<>();
        StringBuilder raw = new StringBuilder();
        for (String s : forHost(hide, pageHost)) {
            if (s.startsWith("@")) raw.append(s.substring(1)).append('\n');
            else if (!ex.contains(s) && !exGen.contains(s)) sels.add(s);
        }
        for (String s : genCx) if (!ex.contains(s) && !exGen.contains(s)) sels.add(s);
        if (sels.isEmpty() && raw.length() == 0) return null;
        StringBuilder sb = new StringBuilder();
        hideCss(sb, sels);
        return sb.append(raw).toString();
    }

    /** Selectors that must not be hidden on this page (its #@# exceptions and the global ones that are simple names). */
    public List<String> exceptionsFor(String pageHost) {
        List<String> out = forHost(exSite, pageHost);
        for (String s : exGen) if (s.length() > 1 && (s.charAt(0) == '.' || s.charAt(0) == '#') && isName(s.substring(1))) out.add(s);
        return out;
    }

    /** This page's scriptlets as a JSON array of arrays ("[[\"set\",\"a\",\"false\"],…]"), or null. */
    public String scriptletsFor(String pageHost) {
        if (pageHost == null) return null;
        Set<String> off = new HashSet<>(forHost(jsEx, pageHost));
        Set<String> seen = new java.util.LinkedHashSet<>();
        for (String j : forHost(js, pageHost)) {
            int q = j.indexOf('"', 2);
            String name = q > 2 ? j.substring(2, q) : "";
            if (!off.contains(name)) seen.add(j);
        }
        if (seen.isEmpty()) return null;
        StringBuilder sb = new StringBuilder("[");
        for (String j : seen) { if (sb.length() > 1) sb.append(','); sb.append(j); }
        return sb.append(']').toString();
    }

    /** Compact form for storing / bundling: one rule per line. */
    public void write(Appendable out) throws IOException {
        for (String d : block) out.append("b ").append(d).append('\n');
        for (String d : block3p) out.append("t ").append(d).append('\n');
        for (String d : allow) out.append("a ").append(d).append('\n');
        for (Map.Entry<String, List<String>> e : hide.entrySet())
            for (String s : e.getValue()) out.append("c ").append(e.getKey()).append(' ').append(s).append('\n');
        for (String v : genCls) out.append("x ").append(v).append('\n');
        for (String v : genId) out.append("y ").append(v).append('\n');
        for (String v : genCx) out.append("z ").append(v).append('\n');
        for (String v : exGen) out.append("e ").append(v).append('\n');
        for (Map.Entry<String, List<String>> e : exSite.entrySet())
            for (String s : e.getValue()) out.append("f ").append(e.getKey()).append(' ').append(s).append('\n');
        for (Map.Entry<String, List<String>> e : js.entrySet())
            for (String s : e.getValue()) out.append("j ").append(e.getKey()).append(' ').append(s).append('\n');
        for (Map.Entry<String, List<String>> e : jsEx.entrySet())
            for (String s : e.getValue()) out.append("k ").append(e.getKey()).append(' ').append(s).append('\n');
        for (Map.Entry<String, List<String>> e : paths.entrySet())
            for (String s : e.getValue()) out.append("p ").append(e.getKey()).append(' ').append(s).append('\n');
        for (Map.Entry<String, List<String>> e : paths3p.entrySet())
            for (String s : e.getValue()) out.append("q ").append(e.getKey()).append(' ').append(s).append('\n');
        for (Map.Entry<String, List<String>> e : gen.entrySet())
            for (String s : e.getValue()) out.append("g ").append(e.getKey()).append(' ').append(s).append('\n');
        for (Map.Entry<String, List<String>> e : gen3p.entrySet())
            for (String s : e.getValue()) out.append("h ").append(e.getKey()).append(' ').append(s).append('\n');
        for (Map.Entry<String, List<String>> e : genAllow.entrySet())
            for (String s : e.getValue()) out.append("i ").append(e.getKey()).append(' ').append(s).append('\n');
    }

    public void readCompact(BufferedReader r) throws IOException {
        String l;
        while ((l = r.readLine()) != null) {
            if (l.length() < 3 || l.charAt(1) != ' ') continue;
            String v = l.substring(2);
            switch (l.charAt(0)) {
                case 'b': block.add(v); break;
                case 't': block3p.add(v); break;
                case 'a': allow.add(v); break;
                case 'x': genCls.add(v); break;
                case 'y': genId.add(v); break;
                case 'z': genCx.add(v); break;
                case 'e': exGen.add(v); break;
                case 'f': case 'j': case 'k': {
                    int sp = v.indexOf(' ');
                    char k = l.charAt(0);
                    if (sp > 0) put(k == 'f' ? exSite : k == 'j' ? js : jsEx, v.substring(0, sp), v.substring(sp + 1));
                    break;
                }
                case 'p': case 'q': case 'g': case 'h': case 'i': {
                    int sp = v.indexOf(' ');
                    char k = l.charAt(0);
                    if (sp > 0) put(k == 'p' ? paths : k == 'q' ? paths3p : k == 'g' ? gen : k == 'h' ? gen3p : genAllow, v.substring(0, sp), v.substring(sp + 1));
                    break;
                }
                case 'c': {
                    int sp = v.indexOf(' ');
                    if (sp <= 0) break;
                    String host = v.substring(0, sp);
                    List<String> list = hide.get(host);
                    if (list == null) hide.put(host, list = new ArrayList<>());
                    list.add(v.substring(sp + 1));
                    break;
                }
            }
        }
    }
}
