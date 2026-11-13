/*
 * Grove Guard — malware scanner, link guard and firewall for Android.
 * Copyright (C) 2026 Grove Guard contributors.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package org.grove.guard.scan;

import android.content.Context;

import org.grove.guard.Prefs;

import java.net.IDN;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Checks website addresses against the dangerous-domain list.
 *
 * Fixes over Hypatia's link scanner: host names are found inside full URLs ("https://bad.example:8080/x?y")
 * instead of only when a text was exactly a host name; sub-domains are matched against their parent domains
 * (login.bad.example is caught when bad.example is listed); upper-case and internationalised names are
 * normalised; and domains you've allowed are skipped.
 */
public final class WebCheck {
    private WebCheck() { }

    // a host name inside any text: labels of letters/digits/hyphens, a dot, and a TLD of 2+ letters (or xn--)
    private static final Pattern HOST = Pattern.compile(
            "(?<![A-Za-z0-9@-])((?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\\.)+(?:[A-Za-z]{2,63}|xn--[A-Za-z0-9-]{2,59}))(?![A-Za-z0-9-])");
    private static final Pattern SCHEME = Pattern.compile("^[a-z][a-z0-9+.-]*://", Pattern.CASE_INSENSITIVE);

    /** Host names found in a piece of text (URL bar contents, shared text, selected text). */
    public static List<String> hosts(String text) {
        Set<String> out = new LinkedHashSet<>();
        if (text == null) return new ArrayList<>(out);
        String t = text.trim();
        if (t.length() > 20000) t = t.substring(0, 20000);
        Matcher m = HOST.matcher(t);
        while (m.find()) {
            String h = normalise(m.group(1));
            // skip things that look like file names ("photo.jpg", "notes.txt") when there's no scheme or path around them
            if (h != null && !looksLikeFile(h, t, m.start(), m.end())) out.add(h);
        }
        return new ArrayList<>(out);
    }

    /** The host of what's in a browser's address bar ("bad.example/path" or "https://bad.example"), or null. */
    public static String hostOfAddress(String addr) {
        if (addr == null) return null;
        String a = addr.trim();
        if (a.isEmpty() || a.contains(" ")) return null;
        a = SCHEME.matcher(a).replaceFirst("");
        int cut = a.length();
        for (char ch : new char[]{'/', '?', '#', ':'}) { int i = a.indexOf(ch); if (i >= 0 && i < cut) cut = i; }
        a = a.substring(0, cut);
        int at = a.lastIndexOf('@');
        if (at >= 0) a = a.substring(at + 1);
        while (a.endsWith(".")) a = a.substring(0, a.length() - 1);
        try { a = IDN.toASCII(a, IDN.ALLOW_UNASSIGNED); } catch (Exception e) { return null; } // münchen.de → xn--mnchen-3ya.de
        if (!HOST.matcher(a).matches()) return null;
        return normalise(a);
    }

    static String normalise(String h) {
        try {
            String s = IDN.toASCII(h.trim().toLowerCase(Locale.ROOT), IDN.ALLOW_UNASSIGNED);
            while (s.endsWith(".")) s = s.substring(0, s.length() - 1);
            return s.isEmpty() ? null : s;
        } catch (Exception e) {
            return null;
        }
    }

    private static final Set<String> FILE_EXT = new java.util.HashSet<>(java.util.Arrays.asList(
            "jpg", "jpeg", "png", "gif", "webp", "txt", "pdf", "doc", "docx", "xls", "xlsx", "zip", "apk", "mp3", "mp4",
            "mkv", "java", "kt", "xml", "json", "html", "htm", "js", "css", "log", "csv", "jar", "so", "dex", "bin", "sig", "key", "md"));

    private static boolean looksLikeFile(String h, String text, int start, int end) {
        String tld = h.substring(h.lastIndexOf('.') + 1);
        if (!FILE_EXT.contains(tld)) return false;
        String before = text.substring(Math.max(0, start - 8), start).toLowerCase(Locale.ROOT);
        return !before.contains("://") && !before.endsWith("www.");
    }

    public static final class Hit {
        public final String host, listed;
        Hit(String host, String listed) { this.host = host; this.listed = listed; }
    }

    /** Checks a host and its parent domains. Returns the hit, or null if it's not listed (or you allowed it). */
    public static Hit check(Context c, String host) {
        Bloom d = Sigs.domains;
        if (d == null || host == null) return null;
        Set<String> allowed = Prefs.set(c, Prefs.WEB_ALLOW);
        String h = host;
        while (true) {
            if (allowed.contains(h)) return null;
            if (d.mightContain(h)) return new Hit(host, h);
            if (h.startsWith("www.") && d.mightContain(h.substring(4))) return new Hit(host, h.substring(4));
            int dot = h.indexOf('.');
            if (dot < 0 || h.indexOf('.', dot + 1) < 0) return null; // stop at the registrable "name.tld"
            h = h.substring(dot + 1);
        }
    }

    /** Domain as shown to people: "bad[.]example" so it can't be tapped by accident. */
    public static String defang(String host) { return host.replace(".", "[.]"); }
}
