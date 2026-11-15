// Groveguard browser extension — background: dangerous-site warning page + uBlock-style content blocking.
// SPDX-License-Identifier: AGPL-3.0-or-later
const api = typeof browser !== 'undefined' ? browser : chrome;
const DANGER = 'https://maintainteam.github.io/HypatiaDatabases/hypatia-domains-bloom.bin';
const DAY = 24 * 3600 * 1000;
let bloom = null, rules = null, adult = null, loading = null;
const counts = new Map(); // tabId -> blocked requests on the current page
const LOG = []; const LOG_MAX = 1000; // recent requests, newest last (kept in memory only)
function log(type, url, page, verdict, why) {
  let host = ''; try { host = new URL(url).hostname; } catch (e) { }
  LOG.push({ t: Date.now(), type, host, url: url.length > 300 ? url.slice(0, 300) + '…' : url, page: page || '', verdict, why: why || '' });
  if (LOG.length > LOG_MAX) LOG.splice(0, LOG.length - LOG_MAX);
}
// ---------------------------------------------------------------- history (every website opened, kept in this browser) + sync to the Groveguard app
const HIST_MAX = 20000;
let HIST = null, histDirty = false, OUTBOX = null;
const BROWSER = navigator.userAgent.includes('Firefox') ? 'Firefox' : navigator.userAgent.includes('Edg/') ? 'Edge' : 'Chromium';
async function histLoad() { if (!HIST) { HIST = (await kv('history')) || []; OUTBOX = (await kv('outbox')) || []; } }
function visit(url, blocked, why) {
  let host = ''; try { host = new URL(url).hostname; } catch (e) { return; }
  const v = { t: Date.now(), h: host, u: url.length > 2000 ? url.slice(0, 2000) : url, b: !!blocked, w: why || '' };
  histLoad().then(() => {
    const last = HIST[HIST.length - 1];
    if (last && last.u === v.u && v.t - last.t < 3000) return;
    HIST.push(v); if (HIST.length > HIST_MAX) HIST.splice(0, HIST.length - HIST_MAX);
    if (cache && cache.appKey) { OUTBOX.push(v); if (OUTBOX.length > 5000) OUTBOX.splice(0, OUTBOX.length - 5000); }
    if (!histDirty) { histDirty = true; setTimeout(histFlush, 2000); }
  });
}
async function histFlush() {
  histDirty = false;
  try { await kv('history', HIST); await kv('outbox', OUTBOX); } catch (e) { }
  syncApp();
}
let syncing = false, appState = '';
/** sends new visits to the Groveguard app on this phone (it listens only on 127.0.0.1, and needs the pairing code) */
async function syncApp() {
  if (syncing || !cache || !cache.appKey) return;
  await histLoad();
  syncing = true;
  try {
    while (OUTBOX.length) {
      const batch = OUTBOX.slice(0, 200);
      const r = await fetch('http://127.0.0.1:47913/v1/visits', { method: 'POST', cache: 'no-store', credentials: 'omit',
        headers: { 'Content-Type': 'text/plain', 'X-Groveguard-Key': cache.appKey, 'X-Groveguard-Browser': BROWSER }, body: JSON.stringify(batch) });
      if (r.status === 403) { appState = 'wrong code'; break; }
      if (!r.ok) { appState = 'error ' + r.status; break; }
      OUTBOX.splice(0, batch.length); appState = 'ok';
      await kv('outbox', OUTBOX);
    }
  } catch (e) { appState = 'app not reachable'; }
  syncing = false;
}
/** host or a parent of it is in the list */
function inList(list, host) { return !!host && !!list && list.some(p => host === p || host.endsWith('.' + p)); }

// ---------------------------------------------------------------- storage (IndexedDB)
function db() {
  return new Promise((ok, no) => {
    const r = indexedDB.open('groveguard', 1);
    r.onupgradeneeded = () => r.result.createObjectStore('kv');
    r.onsuccess = () => ok(r.result); r.onerror = () => no(r.error);
  });
}
async function kv(key, val) {
  const d = await db();
  return new Promise((ok, no) => {
    const tx = d.transaction('kv', val === undefined ? 'readonly' : 'readwrite');
    const s = tx.objectStore('kv');
    const r = val === undefined ? s.get(key) : (val === null ? s.delete(key) : s.put(val, key));
    r.onsuccess = () => ok(r.result); r.onerror = () => no(r.error);
  });
}
async function settings() {
  const s = (await kv('settings')) || {};
  if (!s.lists) { s.lists = {}; for (const l of LISTS) s.lists[l.id] = l.on; }
  if (s.blocking === undefined) s.blocking = true;
  if (s.danger === undefined) s.danger = true;
  if (!s.paused) s.paused = [];
  if (!s.myBlock) s.myBlock = [];
  if (!s.myAllow) s.myAllow = [];
  if (!s.allowed) s.allowed = [];
  if (s.custom === undefined) s.custom = '';
  return s;
}
async function save(s) { await kv('settings', s); }

// ---------------------------------------------------------------- lists
async function downloadDanger() {
  const res = await fetch(DANGER, { cache: 'no-store' });
  if (!res.ok) throw new Error('HTTP ' + res.status);
  const buf = await res.arrayBuffer();
  const b = new Bloom(buf);
  await kv('danger', buf); await kv('danger-updated', Date.now());
  bloom = b;
}
async function downloadList(l) {
  const r = new Rules().parse(await fetchList(l.url));
  await kv('list:' + l.id, r.toJSON());
  const meta = (await kv('meta')) || {};
  meta[l.id] = { updated: Date.now(), rules: r.size() };
  await kv('meta', meta);
}
/** Rebuilds the active rules from the switched-on lists (+ your own filters). */
async function rebuild() {
  const s = await settings(), r = new Rules(), ad = new Rules();
  let anyAdult = false;
  for (const l of LISTS) {
    if (!s.lists[l.id]) continue;
    const j = await kv('list:' + l.id);
    if (!j) continue;
    if (l.adult) { ad.merge(Rules.fromJSON(j)); anyAdult = true; } else r.merge(Rules.fromJSON(j));
  }
  if (s.custom) r.parse(s.custom);
  rules = r;
  adult = anyAdult ? ad : null;
  return r;
}
/** Downloads what's missing or older than a day (force = everything). */
async function updateAll(force) {
  const s = await settings(), meta = (await kv('meta')) || {}, errors = [];
  for (const l of LISTS) {
    if (!s.lists[l.id]) continue;
    if (!force && meta[l.id] && Date.now() - meta[l.id].updated < DAY) continue;
    try { await downloadList(l); } catch (e) { errors.push(l.name + ': ' + e.message); }
  }
  if (s.danger && (force || Date.now() - ((await kv('danger-updated')) || 0) > DAY)) {
    try { await downloadDanger(); } catch (e) { errors.push('Dangerous-site list: ' + e.message); }
  }
  await kv('last-update', Date.now());
  await rebuild();
  return errors;
}
async function ensure() {
  if (rules) return;
  if (!loading) loading = (async () => {
    const buf = await kv('danger');
    if (buf) bloom = new Bloom(buf);
    await rebuild();
    if (!(await kv('meta')) || !buf) await updateAll(false);
  })().finally(() => { loading = null; });
  return loading;
}

// ---------------------------------------------------------------- checks
let cache = null; // settings snapshot for the synchronous request handler
async function refreshCache() { cache = await settings(); }
function hostOf(u) { try { return new URL(u).hostname; } catch (e) { return ''; } }
function pausedOn(host) { return !!host && cache && cache.paused.some(p => host === p || host.endsWith('.' + p)); }

// whole pages: dangerous-site warning
api.webNavigation.onBeforeNavigate.addListener(async details => {
  if (details.frameId !== 0) return;
  counts.set(details.tabId, 0); badge(details.tabId);
  let u; try { u = new URL(details.url); } catch (e) { return; }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return;
  try {
    await ensure();
    const s = cache || await settings();
    if (inList(s.myAllow, u.hostname)) { log('page', details.url, '', 'allowed', 'your allow list'); visit(details.url, false, 'your allow list'); return; }
    if (inList(s.myBlock, u.hostname)) {
      log('page', details.url, '', 'blocked', 'your block list'); visit(details.url, true, 'your block list');
      api.tabs.update(details.tabId, { url: api.runtime.getURL('adult.html') + '?r=you&h=' + encodeURIComponent(u.hostname) });
      return;
    }
    if (adult && !pausedOn(u.hostname) && shouldBlock(adult, u.hostname, u.pathname + u.search, null, details.url)) {
      log('page', details.url, '', 'blocked', '18+ list'); visit(details.url, true, '18+ list');
      api.tabs.update(details.tabId, { url: api.runtime.getURL('adult.html') + '?h=' + encodeURIComponent(u.hostname) });
      return;
    }
    if (!s.danger || !bloom) { log('page', details.url, '', 'allowed', ''); visit(details.url, false, ''); return; }
    const hit = listed(bloom, u.hostname, s.allowed);
    if (!hit) { log('page', details.url, '', 'allowed', ''); visit(details.url, false, ''); return; }
    log('page', details.url, '', 'blocked', 'dangerous-site list'); visit(details.url, true, 'dangerous-site list');
    api.tabs.update(details.tabId, { url: api.runtime.getURL('warning.html') + '?u=' + encodeURIComponent(details.url) + '&l=' + encodeURIComponent(hit) });
  } catch (e) { }
});

// everything inside pages: ads, trackers, malware (blocking needs the rules in memory)
api.webRequest.onBeforeRequest.addListener(d => {
  if (!cache || d.type === 'main_frame') return {};
  const page = hostOf(d.documentUrl || d.originUrl || d.initiator || '');
  let u; try { u = new URL(d.url); } catch (e) { return {}; }
  if (u.protocol !== 'http:' && u.protocol !== 'https:' && u.protocol !== 'ws:' && u.protocol !== 'wss:') return {};
  const block = why => {
    if (d.tabId >= 0) { counts.set(d.tabId, (counts.get(d.tabId) || 0) + 1); badge(d.tabId); }
    log(d.type, d.url, page, 'blocked', why);
    return { cancel: true };
  };
  if (inList(cache.myAllow, u.hostname)) { log(d.type, d.url, page, 'allowed', 'your allow list'); return {}; }
  if (inList(cache.myBlock, u.hostname)) return block('your block list');
  if (!rules || !cache.blocking || pausedOn(page)) { log(d.type, d.url, page, 'allowed', pausedOn(page) ? 'site paused' : ''); return {}; }
  if (shouldBlock(rules, u.hostname, u.pathname + u.search, page, d.url)) return block('filter lists');
  if (adult && shouldBlock(adult, u.hostname, u.pathname, page, null)) return block('18+ list');
  log(d.type, d.url, page, 'allowed', '');
  return {};
}, { urls: ['<all_urls>'] }, ['blocking']);

// element hiding (site-specific cosmetic filters)
api.webNavigation.onCommitted.addListener(d => {
  if (!rules || !cache || !cache.blocking) return;
  const host = hostOf(d.url);
  if (!host || pausedOn(host)) return;
  const css = cssFor(rules, host);
  if (css) try { api.tabs.insertCSS(d.tabId, { code: css, frameId: d.frameId, runAt: 'document_start', cssOrigin: 'user' }).catch(() => {}); } catch (e) {
    try { api.tabs.insertCSS(d.tabId, { code: css, frameId: d.frameId, runAt: 'document_start' }); } catch (e2) { }
  }
});
function badge(tabId) {
  const ba = api.browserAction || api.action;
  if (!ba || !ba.setBadgeText) return;
  const n = counts.get(tabId) || 0;
  try { ba.setBadgeText({ tabId, text: n ? String(n > 999 ? '999+' : n) : '' }); ba.setBadgeBackgroundColor && ba.setBadgeBackgroundColor({ color: '#60A917' }); } catch (e) { }
}
api.tabs.onRemoved.addListener(id => counts.delete(id));

// ---------------------------------------------------------------- messages from the popup, options and warning pages
api.runtime.onMessage.addListener((m, sender, reply) => {
  (async () => {
    const s = await settings();
    if (m.allow) { s.allowed.push(m.allow); await save(s); }
    if (m.setList) { s.lists[m.setList.id] = m.setList.on; await save(s); if (m.setList.on) { const l = LISTS.find(x => x.id === m.setList.id); if (l && !(await kv('list:' + l.id))) { try { await downloadList(l); } catch (e) { } } } await rebuild(); }
    if (m.blocking !== undefined) { s.blocking = m.blocking; await save(s); }
    if (m.danger !== undefined) { s.danger = m.danger; await save(s); }
    if (m.pause) { const i = s.paused.indexOf(m.pause.host); if (m.pause.on && i < 0) s.paused.push(m.pause.host); if (!m.pause.on && i >= 0) s.paused.splice(i, 1); await save(s); }
    if (m.custom !== undefined) { s.custom = m.custom; await save(s); await rebuild(); }
    if (m.unallow) { s.allowed = s.allowed.filter(x => x !== m.unallow); await save(s); }
    if (m.rule) { // { host, list: 'block'|'allow'|'none' } — your own rules, stronger than every filter list
      const h = String(m.rule.host || '').trim().toLowerCase().replace(/^https?:\/\//, '').replace(/[\/:].*$/, '').replace(/^\*\./, '');
      if (h) {
        s.myBlock = s.myBlock.filter(x => x !== h); s.myAllow = s.myAllow.filter(x => x !== h);
        if (m.rule.list === 'block') s.myBlock.push(h); else if (m.rule.list === 'allow') s.myAllow.push(h);
        await save(s);
      }
    }
    if (m.clearLog) LOG.length = 0;
    if (m.history) { await histLoad(); return reply({ history: HIST.slice().reverse(), myBlock: s.myBlock, myAllow: s.myAllow, appKey: s.appKey || '', appState, pending: OUTBOX.length }); }
    if (m.clearHistory !== undefined) { await histLoad(); const cut = m.clearHistory ? Date.now() - m.clearHistory : Infinity; HIST = m.clearHistory ? HIST.filter(v => v.t >= cut) : []; await kv('history', HIST); }
    if (m.clearRecent) { await histLoad(); const cut = Date.now() - m.clearRecent; HIST = HIST.filter(v => v.t < cut); await kv('history', HIST); }
    if (m.deleteVisit) { await histLoad(); HIST = HIST.filter(v => !(v.t === m.deleteVisit.t && v.u === m.deleteVisit.u)); await kv('history', HIST); }
    if (m.appKey !== undefined) {
      const k = String(m.appKey).trim().toUpperCase().replace(/[^A-Z0-9]/g, '');
      s.appKey = k; await save(s); await refreshCache(); await histLoad();
      if (k && m.sendAll) { OUTBOX = HIST.slice(-5000); await kv('outbox', OUTBOX); }
      if (!k) { OUTBOX = []; await kv('outbox', OUTBOX); appState = ''; }
      await syncApp();
      return reply({ appState, pending: OUTBOX.length });
    }
    if (m.log) { await refreshCache(); return reply({ log: LOG.slice(-500).reverse(), myBlock: cache.myBlock, myAllow: cache.myAllow }); }
    let errors = [];
    if (m.update) errors = await updateAll(true);
    await refreshCache();
    reply({
      ok: !errors.length, errors, settings: cache, lists: LISTS, meta: (await kv('meta')) || {},
      rules: rules ? rules.size() : 0, danger: !!bloom, dangerUpdated: (await kv('danger-updated')) || 0,
      lastUpdate: (await kv('last-update')) || 0, blockedHere: m.tabId !== undefined ? (counts.get(m.tabId) || 0) : 0,
    });
  })();
  return true;
});

// ---------------------------------------------------------------- automatic updates (daily)
if (api.alarms) {
  api.alarms.create('update', { periodInMinutes: 60 * 6, delayInMinutes: 2 });
  api.alarms.onAlarm.addListener(a => { if (a.name === 'update') updateAll(false).then(refreshCache).catch(() => {}); });
  api.alarms.create('sync', { periodInMinutes: 5 });
  api.alarms.onAlarm.addListener(a => { if (a.name === 'sync') syncApp(); });
}
refreshCache().then(ensure).catch(() => {});
