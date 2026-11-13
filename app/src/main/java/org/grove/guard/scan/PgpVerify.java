/*
 * Grove Guard — malware scanner, link guard and firewall for Android.
 * Copyright (C) 2026 Grove Guard contributors.
 * Based on Hypatia's GPGDetachedSignatureVerifier (Copyright (C) 2017-2018 Divested Computing Group).
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package org.grove.guard.scan;

import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.File;
import java.util.Iterator;
import java.util.Locale;

/**
 * Checks a detached OpenPGP signature against a public key whose <b>full fingerprint</b> must match.
 * (Hypatia matched only the end of the 64-bit key ID, and an empty key ID matched every key, so a server could
 * sign its own databases with any key it liked.)
 */
public final class PgpVerify {
    private PgpVerify() { }

    /** Normalises "B26E FC8E ..." to upper-case hex without spaces; returns "" if it isn't a 40-hex fingerprint. */
    public static String normFingerprint(String fp) {
        if (fp == null) return "";
        String s = fp.replaceAll("[\\s:]", "").toUpperCase(Locale.ROOT);
        if (s.startsWith("0X")) s = s.substring(2);
        return s.matches("[0-9A-F]{40}") ? s : "";
    }

    public static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format(Locale.ROOT, "%02X", x));
        return sb.toString();
    }

    /** @return true only if {@code sig} is a valid signature of {@code data} by a key in the key ring whose primary key has {@code fingerprint}. */
    public static boolean verify(File data, File sig, InputStream keyFile, String fingerprint) throws IOException {
        String want = normFingerprint(fingerprint);
        if (want.isEmpty()) return false;
        byte[] ring = pinnedRing(readAll(keyFile), want);
        if (ring == null) return false;
        try (InputStream sigIn = PGPUtil.getDecoderStream(new BufferedInputStream(new FileInputStream(sig)))) {
            Object o = new PGPObjectFactory(sigIn, new BcKeyFingerprintCalculator()).nextObject();
            if (!(o instanceof PGPSignatureList)) return false;
            PGPSignatureList list = (PGPSignatureList) o;
            Iterator<?> it = list.iterator();
            if (!it.hasNext()) return false;
            PGPPublicKeyRingCollection col = new PGPPublicKeyRingCollection(new ByteArrayInputStream(ring), new BcKeyFingerprintCalculator());
            Iterator<PGPPublicKeyRing> rings = col.getKeyRings();
            while (rings.hasNext()) {
                Iterator<PGPPublicKey> keys = rings.next().getPublicKeys();
                while (keys.hasNext()) {
                    PGPPublicKey k = keys.next();
                    // re-read the signature for every candidate key (a signature object can only be initialised once)
                    PGPSignature s = freshSignature(sig);
                    if (s == null) return false;
                    try { s.init(new BcPGPContentVerifierBuilderProvider(), k); } catch (Exception wrongKind) { continue; }
                    try (InputStream in = new BufferedInputStream(new FileInputStream(data))) {
                        byte[] buf = new byte[64 * 1024];
                        int n;
                        while ((n = in.read(buf)) > 0) s.update(buf, 0, n);
                    }
                    try { if (s.verify()) return true; } catch (Exception ignored) { }
                }
            }
            return false;
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException("Signature check failed: " + e, e);
        }
    }

    private static PGPSignature freshSignature(File sig) throws IOException {
        try (InputStream sigIn = PGPUtil.getDecoderStream(new BufferedInputStream(new FileInputStream(sig)))) {
            Object o = new PGPObjectFactory(sigIn, new BcKeyFingerprintCalculator()).nextObject();
            if (!(o instanceof PGPSignatureList)) return null;
            return ((PGPSignatureList) o).get(0);
        }
    }

    /** Fingerprint of the first key in a key file, for showing to the user ("" if unreadable). */
    public static String firstFingerprint(InputStream keyFile) {
        try {
            List<Ring> rings = rings(readAll(keyFile));
            return rings.isEmpty() ? "" : rings.get(0).fingerprint;
        } catch (Exception e) { return ""; }
    }

    /** Signature creation time (seconds since 1970) from a v4 signature file, or -1. */
    public static long sigTime(File sig) {
        try {
            byte[] b = dearmor(readAll(new FileInputStream(sig)));
            int p = 0, h = b[p++] & 0xFF;
            if ((h & 0x80) == 0) return -1;
            int tag;
            if ((h & 0x40) != 0) {
                tag = h & 0x3F;
                int o1 = b[p++] & 0xFF;
                if (o1 >= 192 && o1 < 224) p++; else if (o1 == 255) p += 4;
            } else {
                tag = (h >> 2) & 0x0F;
                int lt = h & 3;
                p += lt == 0 ? 1 : lt == 1 ? 2 : lt == 2 ? 4 : 0;
            }
            if (tag != 2 || (b[p] & 0xFF) != 4) return -1;
            int hashedLen = ((b[p + 4] & 0xFF) << 8) | (b[p + 5] & 0xFF);
            int q = p + 6, end = q + hashedLen;
            while (q < end) {
                int l = b[q++] & 0xFF;
                if (l >= 192 && l < 255) { l = ((l - 192) << 8) + (b[q++] & 0xFF) + 192; }
                else if (l == 255) { l = ((b[q] & 0xFF) << 24) | ((b[q + 1] & 0xFF) << 16) | ((b[q + 2] & 0xFF) << 8) | (b[q + 3] & 0xFF); q += 4; }
                int type = b[q] & 0x7F;
                if (type == 2 && l >= 5)
                    return ((b[q + 1] & 0xFFL) << 24) | ((b[q + 2] & 0xFFL) << 16) | ((b[q + 3] & 0xFFL) << 8) | (b[q + 4] & 0xFFL);
                q += l;
            }
        } catch (Exception ignored) { }
        return -1;
    }

    // ---------------------------------------------------------------- minimal OpenPGP packet reader (RFC 4880 / 9580)

    private static final class Ring { String fingerprint; final ByteArrayOutputStream raw = new ByteArrayOutputStream(); }

    /** Returns the raw packets of the key ring whose primary key has this fingerprint, or null. */
    static byte[] pinnedRing(byte[] keyFile, String fingerprint) {
        try {
            for (Ring r : rings(keyFile)) if (fingerprint.equals(r.fingerprint)) return r.raw.toByteArray();
        } catch (Exception ignored) { }
        return null;
    }

    private static List<Ring> rings(byte[] file) throws Exception {
        byte[] b = dearmor(file);
        List<Ring> out = new ArrayList<>();
        Ring cur = null;
        int p = 0;
        while (p < b.length) {
            int start = p;
            int h = b[p++] & 0xFF;
            if ((h & 0x80) == 0) throw new IOException("bad packet");
            int tag;
            long len;
            if ((h & 0x40) != 0) { // new format
                tag = h & 0x3F;
                int o1 = b[p++] & 0xFF;
                if (o1 < 192) len = o1;
                else if (o1 < 224) len = ((o1 - 192) << 8) + (b[p++] & 0xFF) + 192;
                else if (o1 == 255) { len = ((b[p] & 0xFFL) << 24) | ((b[p + 1] & 0xFFL) << 16) | ((b[p + 2] & 0xFFL) << 8) | (b[p + 3] & 0xFFL); p += 4; }
                else throw new IOException("partial length in key file");
            } else { // old format
                tag = (h >> 2) & 0x0F;
                int lt = h & 3;
                if (lt == 0) len = b[p++] & 0xFF;
                else if (lt == 1) { len = ((b[p] & 0xFF) << 8) | (b[p + 1] & 0xFF); p += 2; }
                else if (lt == 2) { len = ((b[p] & 0xFFL) << 24) | ((b[p + 1] & 0xFFL) << 16) | ((b[p + 2] & 0xFFL) << 8) | (b[p + 3] & 0xFFL); p += 4; }
                else len = b.length - p;
            }
            if (len < 0 || p + len > b.length) throw new IOException("truncated packet");
            int bodyStart = p;
            p += (int) len;
            if (tag == 6) { // primary public key starts a new ring
                cur = new Ring();
                cur.fingerprint = fingerprintOf(b, bodyStart, (int) len);
                out.add(cur);
            }
            if (cur != null) cur.raw.write(b, start, p - start);
        }
        return out;
    }

    private static String fingerprintOf(byte[] b, int off, int len) throws Exception {
        int version = b[off] & 0xFF;
        MessageDigest md;
        if (version == 4) {
            md = MessageDigest.getInstance("SHA-1");
            md.update((byte) 0x99);
            md.update((byte) (len >> 8));
            md.update((byte) len);
        } else if (version == 6) {
            md = MessageDigest.getInstance("SHA-256");
            md.update((byte) 0x9B);
            md.update(new byte[]{(byte) (len >>> 24), (byte) (len >>> 16), (byte) (len >>> 8), (byte) len});
        } else return "";
        md.update(b, off, len);
        return hex(md.digest());
    }

    private static byte[] dearmor(byte[] file) throws IOException {
        String head = new String(file, 0, Math.min(file.length, 64), StandardCharsets.US_ASCII);
        if (!head.contains("-----BEGIN PGP")) return file;
        String[] lines = new String(file, StandardCharsets.US_ASCII).split("\r?\n");
        StringBuilder b64 = new StringBuilder();
        boolean body = false, headers = false;
        for (String l : lines) {
            String t = l.trim();
            if (t.startsWith("-----BEGIN PGP")) { headers = true; continue; }
            if (t.startsWith("-----END PGP")) break;
            if (headers) { if (t.isEmpty()) { headers = false; body = true; } else if (!t.contains(":")) { headers = false; body = true; b64.append(t); } continue; }
            if (body) { if (t.startsWith("=") && t.length() <= 5) continue; b64.append(t); }
        }
        return Base64.getDecoder().decode(b64.toString());
    }

    static byte[] readAll(InputStream in) throws IOException {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        try { while ((n = in.read(buf)) > 0) o.write(buf, 0, n); } finally { in.close(); }
        return o.toByteArray();
    }
}
