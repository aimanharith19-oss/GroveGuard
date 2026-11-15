// Groveguard browser extension — dangerous-site check.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Reads Hypatia's domain database (a Guava Bloom filter, MURMUR128_MITZ_64) — same list the Groveguard app uses.
const M64 = (1n << 64n) - 1n, C1 = 0x87c37b91114253d5n, C2 = 0x4cf5ad432745937fn;
const rotl = (x, r) => ((x << BigInt(r)) | (x >> BigInt(64 - r))) & M64;
const fmix = k => { k ^= k >> 33n; k = (k * 0xff51afd7ed558ccdn) & M64; k ^= k >> 33n; k = (k * 0xc4ceb9fe1a85ec53n) & M64; return k ^ (k >> 33n); };
function le(b, o) { let v = 0n; for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(b[o + i]); return v; }
function murmur(b) {
  let h1 = 0n, h2 = 0n; const n = b.length, blocks = Math.floor(n / 16);
  for (let i = 0; i < blocks; i++) {
    let k1 = le(b, i * 16), k2 = le(b, i * 16 + 8);
    k1 = (k1 * C1) & M64; k1 = rotl(k1, 31); k1 = (k1 * C2) & M64; h1 ^= k1;
    h1 = rotl(h1, 27); h1 = (h1 + h2) & M64; h1 = (h1 * 5n + 0x52dce729n) & M64;
    k2 = (k2 * C2) & M64; k2 = rotl(k2, 33); k2 = (k2 * C1) & M64; h2 ^= k2;
    h2 = rotl(h2, 31); h2 = (h2 + h1) & M64; h2 = (h2 * 5n + 0x38495ab5n) & M64;
  }
  const t = blocks * 16, rem = n - t;
  if (rem > 0) {
    let k1 = 0n, k2 = 0n;
    for (let i = rem - 1; i >= 8; i--) k2 = (k2 << 8n) | BigInt(b[t + i]);
    for (let i = Math.min(rem, 8) - 1; i >= 0; i--) k1 = (k1 << 8n) | BigInt(b[t + i]);
    if (rem > 8) { k2 = (k2 * C2) & M64; k2 = rotl(k2, 33); k2 = (k2 * C1) & M64; h2 ^= k2; }
    k1 = (k1 * C1) & M64; k1 = rotl(k1, 31); k1 = (k1 * C2) & M64; h1 ^= k1;
  }
  h1 ^= BigInt(n); h2 ^= BigInt(n);
  h1 = (h1 + h2) & M64; h2 = (h2 + h1) & M64;
  h1 = fmix(h1); h2 = fmix(h2);
  h1 = (h1 + h2) & M64; h2 = (h2 + h1) & M64;
  return [h1, h2];
}
class Bloom {
  constructor(buf) {
    const b = new Uint8Array(buf);
    if (b[0] !== 1) throw new Error('unsupported bloom strategy');
    this.k = b[1];
    const longs = (b[2] << 24 | b[3] << 16 | b[4] << 8 | b[5]) >>> 0;
    this.bits = b.subarray(6, 6 + longs * 8);
    this.size = BigInt(longs) * 64n;
  }
  has(s) {
    const [h1, h2] = murmur(new TextEncoder().encode(s));
    let c = h1;
    for (let i = 0; i < this.k; i++) {
      const idx = (c & 0x7fffffffffffffffn) % this.size;
      const word = Number(idx >> 6n), bit = Number(idx & 63n);
      if ((this.bits[word * 8 + (7 - (bit >> 3))] & (1 << (bit & 7))) === 0) return false;
      c = (c + h2) & M64;
    }
    return true;
  }
}
/** The host or a parent domain on the list, or null. */
function listed(bloom, host, allowed) {
  let h = host.toLowerCase().replace(/\.+$/, '');
  while (true) {
    if (allowed && allowed.includes(h)) return null;
    if (bloom.has(h)) return h;
    if (h.startsWith('www.') && bloom.has(h.slice(4))) return h.slice(4);
    const d = h.indexOf('.');
    if (d < 0 || h.indexOf('.', d + 1) < 0) return null;
    h = h.slice(d + 1);
  }
}
if (typeof module !== 'undefined') module.exports = { Bloom, listed, murmur };
