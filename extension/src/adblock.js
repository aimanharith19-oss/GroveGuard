// Groveguard browser extension — content blocker using uBlock Origin / EasyList filter lists.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Engine ported from Grove Launcher's AdRules: domain rules (||host^ with $third-party etc.), path rules,
// exceptions (@@), hosts files, and site-specific element hiding (host##selector, :style()).
const UBO = 'https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/';
const LISTS = [
  { id: 'ubo-filters', group: 'uBlock filters', name: 'uBlock filters – Ads', url: UBO + 'filters/filters.txt', on: true },
  { id: 'ubo-privacy', group: 'uBlock filters', name: 'uBlock filters – Privacy', url: UBO + 'filters/privacy.txt', on: true },
  { id: 'ubo-badware', group: 'uBlock filters', name: 'uBlock filters – Badware risks', url: UBO + 'filters/badware.txt', on: true },
  { id: 'ubo-quick', group: 'uBlock filters', name: 'uBlock filters – Quick fixes', url: UBO + 'filters/quick-fixes.txt', on: true },
  { id: 'ubo-unbreak', group: 'uBlock filters', name: 'uBlock filters – Unbreak', url: UBO + 'filters/unbreak.txt', on: true },
  { id: 'easylist', group: 'Ads', name: 'EasyList', url: UBO + 'thirdparties/easylist/easylist.txt', on: true },
  { id: 'adguard-mobile', group: 'Ads', name: 'AdGuard – Mobile Ads', url: 'https://filters.adtidy.org/extension/ublock/filters/11.txt', on: false },
  { id: 'easyprivacy', group: 'Privacy', name: 'EasyPrivacy', url: UBO + 'thirdparties/easylist/easyprivacy.txt', on: true },
  { id: 'pgl', group: 'Multipurpose', name: "Peter Lowe's Ad and tracking server list", url: UBO + 'thirdparties/pgl.yoyo.org/as/serverlist', on: true },
  { id: 'urlhaus', group: 'Malware protection, security', name: 'Online Malicious URL Blocklist', url: 'https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-ag-online.txt', on: true },
  { id: 'ubo-annoyances', group: 'Annoyances', name: 'uBlock filters – Annoyances', url: UBO + 'filters/annoyances-others.txt', on: false },
  { id: 'ubo-cookies', group: 'Annoyances', name: 'uBlock filters – Cookie notices', url: UBO + 'filters/annoyances-cookies.txt', on: false },
  { id: 'easylist-cookies', group: 'Annoyances', name: 'EasyList – Cookie notices', url: UBO + 'thirdparties/easylist/easylist-cookies.txt', on: false },
  { id: 'easylist-social', group: 'Annoyances', name: 'EasyList – Social widgets', url: UBO + 'thirdparties/easylist/easylist-social.txt', on: false },
  { id: 'easylist-notifications', group: 'Annoyances', name: 'EasyList – Notifications', url: UBO + 'thirdparties/easylist/easylist-notifications.txt', on: false },
  { id: 'easylist-annoyances', group: 'Annoyances', name: 'EasyList – Other annoyances', url: UBO + 'thirdparties/easylist/easylist-annoyances.txt', on: false },
];
const OK_OPTS = new Set(['third-party', '3p', 'script', 'image', 'xmlhttprequest', 'xhr', 'subdocument', 'frame', 'all',
  'important', 'media', 'object', 'ping', 'stylesheet', 'css', 'font', 'websocket', 'other']);
const BAD_COS = [':has-text(', ':-abp-', ':upward(', ':remove(', ':style(', ':xpath(', ':matches-', ':watch-attr(',
  ':min-text-length(', ':others(', ':matches-path(', ':remove-attr(', ':remove-class(', '{'];

function isDomain(h) { return h.length >= 3 && h.indexOf('.') >= 0 && /^[A-Za-z0-9._-]+$/.test(h); }

class Rules {
  constructor() { this.block = new Set(); this.block3p = new Set(); this.allow = new Set(); this.hide = new Map(); this.paths = new Map(); this.paths3p = new Map(); this.gen = new Map(); this.gen3p = new Map(); this.genAllow = new Map(); }
  static put(m, k, v) { let l = m.get(k); if (!l) m.set(k, l = []); l.push(v); }
  size() { let n = this.block.size + this.block3p.size + this.allow.size; for (const l of this.paths.values()) n += l.length; for (const l of this.paths3p.values()) n += l.length; for (const l of this.hide.values()) n += l.length; for (const m of [this.gen, this.gen3p, this.genAllow]) for (const l of m.values()) n += l.length; return n; }
  parse(text) { for (const raw of text.split('\n')) this.line(raw.trim()); return this; }
  line(l) {
    if (!l || l[0] === '!' || l[0] === '[' || (l[0] === '#' && !l.startsWith('##'))) return;
    if (l.startsWith('127.0.0.1 ') || l.startsWith('0.0.0.0 ')) { const h = l.slice(l.indexOf(' ') + 1).trim(); if (isDomain(h)) this.block.add(h.toLowerCase()); return; }
    const cos = l.indexOf('##');
    if (cos > 0 && l.indexOf('#@#') < 0 && l.indexOf('#?#') < 0 && l.indexOf('#$#') < 0) { this.cosmetic(l.slice(0, cos), l.slice(cos + 2)); return; }
    if (cos >= 0 || l.includes('#@#') || l.includes('#?#') || l.includes('#$#') || l.includes('#%#')) return;
    let ex = false;
    if (l.startsWith('@@')) { ex = true; l = l.slice(2); }
    if (!l.startsWith('||')) { this.generic(l, ex); return; }
    let end = 2;
    while (end < l.length && '^/*$'.indexOf(l[end]) < 0) end++;
    let host = l.slice(2, end);
    if (!isDomain(host) || end >= l.length) return;
    const dollar = l.indexOf('$', end);
    const pattern = l.slice(end, dollar < 0 ? l.length : dollar);
    if (!pattern.startsWith('^') || pattern.length > 1) {
      if (ex || pattern.length < 2 || pattern[0] === '*') return;
      let tp = false;
      if (dollar >= 0) for (const o of l.slice(dollar + 1).split(',')) { if (!OK_OPTS.has(o)) return; if (o === 'third-party' || o === '3p') tp = true; }
      Rules.put(tp ? this.paths3p : this.paths, host.toLowerCase(), pattern);
      return;
    }
    const rest = l.slice(end + 1);
    let tp = false;
    if (rest) {
      if (rest[0] !== '$') return;
      for (const o of rest.slice(1).split(',')) { if (!OK_OPTS.has(o)) return; if (o === 'third-party' || o === '3p') tp = true; }
    }
    host = host.toLowerCase();
    if (ex) this.allow.add(host); else if (tp) this.block3p.add(host); else this.block.add(host);
  }
  /** Plain URL patterns ("/fbevents.js", "-ad-banner.", "|https://x/*ads"), indexed by their longest word. */
  generic(l, ex) {
    const dollar = l.lastIndexOf('$');
    let pat = dollar >= 0 ? l.slice(0, dollar) : l, tp = false;
    if (dollar >= 0) for (const o of l.slice(dollar + 1).split(',')) { if (!OK_OPTS.has(o)) return; if (o === 'third-party' || o === '3p') tp = true; }
    if (pat.startsWith('/') && pat.endsWith('/') && pat.length > 2) return; // regex rules: not supported
    let anchored = false;
    if (pat.startsWith('|')) { anchored = true; pat = pat.slice(1); }
    if (pat.endsWith('|')) pat = pat.slice(0, -1) + '^';
    const words = pat.toLowerCase().split(/[^a-z0-9%]+/).filter(w => w.length >= 4);
    if (!words.length) return; // too vague to index safely
    const key = words.reduce((a, b) => b.length > a.length ? b : a);
    Rules.put(ex ? this.genAllow : (tp ? this.gen3p : this.gen), key, (anchored ? '|' : '') + pat.toLowerCase());
  }
  cosmetic(domains, sel) {
    const st = sel.indexOf(':style(');
    if (st > 0 && sel.endsWith(')') && sel.indexOf(':style(', st + 1) < 0) {
      const s = sel.slice(0, st), css = sel.slice(st + 7, -1);
      if (s.includes(':has-text(') || s.includes(':-abp-') || s.includes(':upward(') || /[{}]|url\(/.test(css)) return;
      for (let d of domains.split(',')) { d = d.trim().toLowerCase(); if (d && !d.startsWith('~') && !/[*/]/.test(d) && isDomain(d)) Rules.put(this.hide, d, '@' + s + '{' + css + '}'); }
      return;
    }
    if (!sel || sel.startsWith('+js(') || sel.startsWith('^') || BAD_COS.some(b => sel.includes(b))) return;
    for (let d of domains.split(',')) {
      d = d.trim().toLowerCase();
      if (!d || d.startsWith('~') || /[*/]/.test(d) || !isDomain(d)) continue;
      const l = this.hide.get(d);
      if (!l || l.length < 400) Rules.put(this.hide, d, sel);
    }
  }
  merge(o) {
    for (const k of ['block', 'block3p', 'allow']) for (const v of o[k]) this[k].add(v);
    for (const k of ['hide', 'paths', 'paths3p', 'gen', 'gen3p', 'genAllow']) for (const [h, l] of o[k]) for (const v of l) Rules.put(this[k], h, v);
    return this;
  }
  toJSON() { return { b: [...this.block], t: [...this.block3p], a: [...this.allow], c: [...this.hide], p: [...this.paths], q: [...this.paths3p], g: [...this.gen], g3: [...this.gen3p], ga: [...this.genAllow] }; }
  static fromJSON(j) { const r = new Rules(); r.block = new Set(j.b); r.block3p = new Set(j.t); r.allow = new Set(j.a); r.hide = new Map(j.c); r.paths = new Map(j.p); r.paths3p = new Map(j.q); r.gen = new Map(j.g || []); r.gen3p = new Map(j.g3 || []); r.genAllow = new Map(j.ga || []); return r; }
}

function site(host) {
  const p = host.split('.'), n = p.length;
  if (n <= 2) return host;
  const t2 = p[n - 2];
  const sld = t2.length <= 3 && ['co', 'com', 'net', 'org', 'gov', 'edu', 'ac', 'or', 'ne', 'my'].includes(t2) && p[n - 1].length === 2;
  return p.slice(n - (sld ? 3 : 2)).join('.');
}
function glob(p, pi, s, si) {
  while (pi < p.length) {
    const c = p[pi];
    if (c === '*') {
      while (pi < p.length && p[pi] === '*') pi++;
      if (pi === p.length) return true;
      for (let k = si; k <= s.length; k++) if (glob(p, pi, s, k)) return true;
      return false;
    }
    if (c === '^') {
      if (si === s.length) { pi++; continue; }
      if (/[A-Za-z0-9_.%-]/.test(s[si])) return false;
      pi++; si++; continue;
    }
    if (si >= s.length || s[si] !== c) return false;
    pi++; si++;
  }
  return true;
}
function genericHit(m, url, words) {
  for (const w of words) {
    const l = m.get(w);
    if (!l) continue;
    for (const p of l) {
      if (p[0] === '|') { if (glob(p.slice(1), 0, url, 0)) return true; continue; }
      const first = p.replace(/^[*]+/, '');
      for (let i = url.indexOf(first.split(/[*^]/)[0]); i >= 0; i = url.indexOf(first.split(/[*^]/)[0], i + 1)) if (glob(first, 0, url, i)) return true;
    }
  }
  return false;
}
/** Should a request to url (host, path) from a page on pageHost be blocked? */
function shouldBlock(r, host, path, pageHost, fullUrl) {
  host = host.toLowerCase();
  const third = !pageHost || site(host) !== site(pageHost.toLowerCase());
  if (fullUrl && (r.gen.size || r.gen3p.size)) {
    const url = fullUrl.toLowerCase(), words = url.split(/[^a-z0-9%]+/).filter(w => w.length >= 4);
    if (genericHit(r.gen, url, words) || (third && genericHit(r.gen3p, url, words))) {
      if (!genericHit(r.genAllow, url, words)) {
        let cur = host;
        while (true) { if (r.allow.has(cur)) return false; const d = cur.indexOf('.'); if (d < 0 || cur.indexOf('.', d + 1) < 0) break; cur = cur.slice(d + 1); }
        return true;
      }
    }
  }
  let cur = host, hit = false;
  while (true) {
    if (r.allow.has(cur)) return false;
    if (!hit && (r.block.has(cur) || (third && r.block3p.has(cur)))) hit = true;
    if (!hit) {
      const a = r.paths.get(cur), b = third ? r.paths3p.get(cur) : null;
      if ((a && a.some(x => glob(x, 0, path, 0))) || (b && b.some(x => glob(x, 0, path, 0)))) hit = true;
    }
    const d = cur.indexOf('.');
    if (d < 0 || cur.indexOf('.', d + 1) < 0) break;
    cur = cur.slice(d + 1);
  }
  return hit;
}
function cssFor(r, pageHost) {
  const sels = [], raw = [];
  let cur = pageHost.toLowerCase();
  while (true) {
    const l = r.hide.get(cur);
    if (l) for (const s of l) { if (s[0] === '@') raw.push(s.slice(1)); else sels.push(s); }
    const d = cur.indexOf('.');
    if (d < 0) break;
    cur = cur.slice(d + 1);
  }
  if (!sels.length && !raw.length) return null;
  return (sels.length ? sels.join(',\n') + '{display:none!important}\n' : '') + raw.join('\n');
}
/** Downloads a list and every list it !#includes (same folder). */
async function fetchList(url, depth = 0) {
  const res = await fetch(url, { cache: 'no-store' });
  if (!res.ok) throw new Error('HTTP ' + res.status + ' for ' + url);
  let text = await res.text();
  if (depth < 2) {
    const base = url.slice(0, url.lastIndexOf('/') + 1), parts = [];
    for (const m of text.matchAll(/^!#include\s+(\S+)/gm)) {
      try { parts.push(await fetchList(new URL(m[1], base).href, depth + 1)); } catch (e) { /* skip a missing include */ }
    }
    text += '\n' + parts.join('\n');
  }
  return text;
}
if (typeof module !== 'undefined') module.exports = { Rules, LISTS, shouldBlock, cssFor, site, glob };
