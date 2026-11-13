/*
 * Grove Guard — malware scanner, link guard and firewall for Android.
 * Copyright (C) 2026 Grove Guard contributors.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package org.grove.guard.scan;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

/**
 * Read-only Bloom filter that understands the file format written by Guava's {@code BloomFilter.writeTo}
 * (strategy MURMUR128_MITZ_64 with a US-ASCII string funnel), which is what the Hypatia signature databases use.
 * Written from the published format so the app doesn't have to bundle Guava.
 */
public final class Bloom {
    private final long[] bits;
    private final long bitSize;
    private final int hashes;
    private final long approxCount;

    private Bloom(long[] bits, int hashes) {
        this.bits = bits;
        this.bitSize = (long) bits.length * 64L;
        this.hashes = hashes;
        long set = 0;
        for (long l : bits) set += Long.bitCount(l);
        // same estimate Guava uses for approximateElementCount()
        double frac = (double) set / (double) bitSize;
        this.approxCount = Math.round(-Math.log1p(-frac) * bitSize / hashes);
    }

    public static Bloom read(InputStream in) throws IOException {
        DataInputStream d = new DataInputStream(in);
        int strategy = d.readByte();
        int hashes = d.readByte() & 0xFF;
        int longs = d.readInt();
        if (strategy != 1) throw new IOException("Unsupported Bloom filter strategy " + strategy);
        if (hashes < 1 || longs < 1) throw new IOException("Corrupt Bloom filter header");
        long[] bits = new long[longs];
        byte[] buf = new byte[8 * 8192];
        int i = 0;
        while (i < longs) {
            int n = Math.min(8192, longs - i);
            d.readFully(buf, 0, n * 8);
            for (int k = 0; k < n; k++) {
                int o = k * 8;
                bits[i + k] = ((long) (buf[o] & 0xFF) << 56) | ((long) (buf[o + 1] & 0xFF) << 48)
                        | ((long) (buf[o + 2] & 0xFF) << 40) | ((long) (buf[o + 3] & 0xFF) << 32)
                        | ((long) (buf[o + 4] & 0xFF) << 24) | ((long) (buf[o + 5] & 0xFF) << 16)
                        | ((long) (buf[o + 6] & 0xFF) << 8) | ((long) (buf[o + 7] & 0xFF));
            }
            i += n;
        }
        return new Bloom(bits, hashes);
    }

    public long approximateCount() { return approxCount; }

    public boolean mightContain(String s) {
        long[] h = murmur3x64_128(s.getBytes(StandardCharsets.US_ASCII));
        long combined = h[0];
        for (int i = 0; i < hashes; i++) {
            long idx = (combined & Long.MAX_VALUE) % bitSize;
            if ((bits[(int) (idx >>> 6)] & (1L << idx)) == 0) return false;
            combined += h[1];
        }
        return true;
    }

    // ---------------------------------------------------------------- MurmurHash3 x64 128-bit, seed 0

    private static final long C1 = 0x87c37b91114253d5L, C2 = 0x4cf5ad432745937fL;

    static long[] murmur3x64_128(byte[] data) {
        long h1 = 0, h2 = 0;
        int len = data.length, blocks = len / 16;
        for (int b = 0; b < blocks; b++) {
            long k1 = le(data, b * 16), k2 = le(data, b * 16 + 8);
            h1 ^= mixK1(k1);
            h1 = Long.rotateLeft(h1, 27); h1 += h2; h1 = h1 * 5 + 0x52dce729;
            h2 ^= mixK2(k2);
            h2 = Long.rotateLeft(h2, 31); h2 += h1; h2 = h2 * 5 + 0x38495ab5;
        }
        int t = blocks * 16, rem = len - t;
        if (rem > 0) {
            long k1 = 0, k2 = 0;
            switch (rem) {
                case 15: k2 ^= (long) (data[t + 14] & 0xFF) << 48;
                case 14: k2 ^= (long) (data[t + 13] & 0xFF) << 40;
                case 13: k2 ^= (long) (data[t + 12] & 0xFF) << 32;
                case 12: k2 ^= (long) (data[t + 11] & 0xFF) << 24;
                case 11: k2 ^= (long) (data[t + 10] & 0xFF) << 16;
                case 10: k2 ^= (long) (data[t + 9] & 0xFF) << 8;
                case 9: k2 ^= (long) (data[t + 8] & 0xFF);
                case 8: k1 ^= (long) (data[t + 7] & 0xFF) << 56;
                case 7: k1 ^= (long) (data[t + 6] & 0xFF) << 48;
                case 6: k1 ^= (long) (data[t + 5] & 0xFF) << 40;
                case 5: k1 ^= (long) (data[t + 4] & 0xFF) << 32;
                case 4: k1 ^= (long) (data[t + 3] & 0xFF) << 24;
                case 3: k1 ^= (long) (data[t + 2] & 0xFF) << 16;
                case 2: k1 ^= (long) (data[t + 1] & 0xFF) << 8;
                case 1: k1 ^= (long) (data[t] & 0xFF);
                default: break;
            }
            h1 ^= mixK1(k1);
            h2 ^= mixK2(k2);
        }
        h1 ^= len; h2 ^= len;
        h1 += h2; h2 += h1;
        h1 = fmix64(h1); h2 = fmix64(h2);
        h1 += h2; h2 += h1;
        return new long[]{h1, h2};
    }

    private static long le(byte[] d, int o) {
        return (d[o] & 0xFFL) | (d[o + 1] & 0xFFL) << 8 | (d[o + 2] & 0xFFL) << 16 | (d[o + 3] & 0xFFL) << 24
                | (d[o + 4] & 0xFFL) << 32 | (d[o + 5] & 0xFFL) << 40 | (d[o + 6] & 0xFFL) << 48 | (d[o + 7] & 0xFFL) << 56;
    }

    private static long mixK1(long k1) { k1 *= C1; k1 = Long.rotateLeft(k1, 31); k1 *= C2; return k1; }

    private static long mixK2(long k2) { k2 *= C2; k2 = Long.rotateLeft(k2, 33); k2 *= C1; return k2; }

    private static long fmix64(long k) {
        k ^= k >>> 33; k *= 0xff51afd7ed558ccdL;
        k ^= k >>> 33; k *= 0xc4ceb9fe1a85ec53L;
        k ^= k >>> 33;
        return k;
    }
}
