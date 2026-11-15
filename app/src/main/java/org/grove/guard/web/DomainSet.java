/*
 * Groveguard — malware scanner, link guard and firewall for Android.
 * Copyright (C) 2026 Groveguard contributors.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package org.grove.guard.web;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Locale;

/**
 * A big list of blocked sites (the 18+ lists: hundreds of thousands of domains) kept as sorted 64-bit fingerprints:
 * ~8 bytes a site, loads in milliseconds, and a site also matches its sub-domains.
 * Reads hosts files (0.0.0.0 site), Adblock lists (||site^), *.site and plain domain lists.
 */
public final class DomainSet {
    private long[] h = new long[0];

    public int size() { return h.length; }

    static long hash(String s) { // FNV-1a 64
        long x = 0xcbf29ce484222325L;
        byte[] b = s.getBytes(StandardCharsets.UTF_8);
        for (byte v : b) { x ^= (v & 0xff); x *= 0x100000001b3L; }
        return x;
    }

    /** The site in one list line, or null. */
    static String domainOf(String line) {
        String s = line.trim();
        if (s.isEmpty() || s.charAt(0) == '!' || s.charAt(0) == '#' || s.charAt(0) == '[') return null;
        if (s.contains("##") || s.contains("#@#") || s.contains("#?#") || s.startsWith("@@")) return null;
        int sp = s.indexOf('#');
        if (sp > 0) s = s.substring(0, sp).trim();
        if (s.startsWith("||")) {
            s = s.substring(2);
            int e = 0;
            while (e < s.length() && "^/$|".indexOf(s.charAt(e)) < 0) e++;
            String rest = s.substring(e);
            if (!(rest.isEmpty() || rest.equals("^") || rest.startsWith("^$") || rest.equals("^|"))) return null; // path rules: not a whole site
            s = s.substring(0, e);
        } else {
            String[] p = s.split("\\s+");
            if (p.length >= 2 && (p[0].equals("0.0.0.0") || p[0].equals("127.0.0.1") || p[0].equals("::") || p[0].equals("::1"))) s = p[1];
            else if (p.length == 1) s = p[0];
            else return null;
            if (s.startsWith("*.")) s = s.substring(2);
            else if (s.startsWith(".")) s = s.substring(1);
        }
        s = s.toLowerCase(Locale.ROOT);
        if (s.length() < 3 || s.indexOf('.') < 0 || s.equals("localhost") || s.equals("0.0.0.0")) return null;
        for (int i = 0; i < s.length(); i++) {
            char ch = s.charAt(i);
            if (!((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '.' || ch == '-' || ch == '_')) return null;
        }
        return s;
    }

    public static DomainSet parse(BufferedReader r) throws java.io.IOException {
        long[] a = new long[1 << 16];
        int n = 0;
        String line;
        while ((line = r.readLine()) != null) {
            String d = domainOf(line);
            if (d == null) continue;
            if (n == a.length) a = Arrays.copyOf(a, n * 2);
            a[n++] = hash(d);
        }
        return of(a, n);
    }

    private static DomainSet of(long[] a, int n) {
        Arrays.sort(a, 0, n);
        int m = 0;
        for (int i = 0; i < n; i++) if (m == 0 || a[m - 1] != a[i]) a[m++] = a[i];
        DomainSet d = new DomainSet();
        d.h = Arrays.copyOf(a, m);
        return d;
    }

    public static DomainSet merge(java.util.List<DomainSet> sets) {
        int n = 0;
        for (DomainSet s : sets) n += s.h.length;
        long[] a = new long[n];
        int i = 0;
        for (DomainSet s : sets) { System.arraycopy(s.h, 0, a, i, s.h.length); i += s.h.length; }
        return of(a, n);
    }

    /** host or one of its parent domains is listed. */
    public boolean contains(String host) { return match(host) != null; }

    /** The listed entry covering host (host itself or a parent domain), or null. */
    public String match(String host) {
        if (host == null || h.length == 0) return null;
        String s = host.toLowerCase(Locale.ROOT);
        while (true) {
            if (Arrays.binarySearch(h, hash(s)) >= 0) return s;
            int dot = s.indexOf('.');
            if (dot < 0 || s.indexOf('.', dot + 1) < 0) return null; // never test a bare "com"
            s = s.substring(dot + 1);
        }
    }

    public void save(File f) throws java.io.IOException {
        File tmp = new File(f.getPath() + ".tmp");
        try (DataOutputStream o = new DataOutputStream(new BufferedOutputStream(new FileOutputStream(tmp), 1 << 16))) {
            o.writeInt(0x47474453); // "GGDS"
            o.writeInt(h.length);
            for (long v : h) o.writeLong(v);
        }
        if (!tmp.renameTo(f)) { //noinspection ResultOfMethodCallIgnored
            f.delete(); //noinspection ResultOfMethodCallIgnored
            tmp.renameTo(f); }
    }

    public static DomainSet load(File f) throws java.io.IOException {
        try (DataInputStream in = new DataInputStream(new BufferedInputStream(new FileInputStream(f), 1 << 16))) {
            if (in.readInt() != 0x47474453) throw new java.io.IOException("bad file");
            int n = in.readInt();
            if (n < 0 || n > 20_000_000) throw new java.io.IOException("bad size");
            long[] a = new long[n];
            for (int i = 0; i < n; i++) a[i] = in.readLong();
            DomainSet d = new DomainSet();
            d.h = a;
            return d;
        }
    }
}
