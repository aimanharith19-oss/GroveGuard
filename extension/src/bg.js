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
  // linked to the Groveguard app: pages and blocked requests also go to its web tab log
  if (cache && cache.appKey && (type === 'page' || verdict === 'blocked') && LOGBOX.length < 2000)
    LOGBOX.push({ t: Date.now(), type, h: host, u: url.length > 2000 ? url.slice(0, 2000) : url, page: page || '', b: verdict === 'blocked', w: why || '' });
}
const LOGBOX = [];
// ---------------------------------------------------------------- 18+ lists: a plain set of sites (hundreds of thousands — Rules would be too heavy)
function domainOf(line) {
  let s = line.trim();
  if (!s || '!#['.includes(s[0]) || s.includes('##') || s.includes('#@#') || s.startsWith('@@')) return null;
  const hash = s.indexOf('#'); if (hash > 0) s = s.slice(0, hash).trim();
  if (s.startsWith('||')) {
    const m = /^\|\|([^\^\/$|]+)(.*)$/.exec(s); if (!m) return null;
    if (!(m[2] === '' || m[2] === '^' || m[2].startsWith('^$') || m[2] === '^|')) return null;
    s = m[1];
  } else {
    const p = s.split(/\s+/);
    if (p.length >= 2 && ['0.0.0.0', '127.0.0.1', '::', '::1'].includes(p[0])) s = p[1]; else if (p.length === 1) s = p[0]; else return null;
    if (s.startsWith('*.')) s = s.slice(2); else if (s.startsWith('.')) s = s.slice(1);
  }
  s = s.toLowerCase();
  if (s.length < 3 || !s.includes('.') || s === 'localhost' || s === '0.0.0.0' || !/^[a-z0-9._-]+$/.test(s)) return null;
  return s;
}
/** the 18+ list (and its entry) that covers this site, or null */
function adultHit(host) {
  if (!adult || !host) return null;
  let s = host.toLowerCase();
  for (;;) {
    for (const [name, set] of adult) if (set.has(s)) return { name, matched: s };
    const d = s.indexOf('.'); if (d < 0 || s.indexOf('.', d + 1) < 0) return null;
    s = s.slice(d + 1);
  }
}
function mine(list, host) { return host && list ? list.find(p => host === p || host.endsWith('.' + p)) || null : null; }
/** the block page, with why (same wording as Grove Launcher's) */
function blockUrl(kind, host, why, matched) {
  return api.runtime.getURL('adult.html') + '?k=' + kind + '&h=' + encodeURIComponent(host) + '&w=' + encodeURIComponent(why || '') + '&m=' + encodeURIComponent(matched || '');
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
    const st = await pullSettings();
    appState = st === 403 ? 'wrong code' : st === 200 ? 'ok' : 'error ' + st;
    while (appState === 'ok' && OUTBOX.length) {
      const batch = OUTBOX.slice(0, 200);
      const r = await appPost('/v1/visits', batch);
      if (!r.ok) { appState = r.status === 403 ? 'wrong code' : 'error ' + r.status; break; }
      OUTBOX.splice(0, batch.length);
      await kv('outbox', OUTBOX);
    }
    while (appState === 'ok' && LOGBOX.length) { const r = await appPost('/v1/log', LOGBOX.slice(0, 300)); if (!r.ok) break; LOGBOX.splice(0, 300); }
  } catch (e) { appState = 'app not reachable'; }
  syncing = false;
}
function appPost(path, body) {
  return fetch('http://127.0.0.1:47913' + path, { method: 'POST', cache: 'no-store', credentials: 'omit',
    headers: { 'Content-Type': 'text/plain', 'X-Groveguard-Key': cache.appKey, 'X-Groveguard-Browser': BROWSER }, body: JSON.stringify(body) });
}
/** use the app's switches, lists and rules (the app's web tab controls the extension once linked) */
async function pullSettings() {
  const r = await fetch('http://127.0.0.1:47913/v1/settings', { cache: 'no-store', credentials: 'omit', headers: { 'X-Groveguard-Key': cache.appKey } });
  if (!r.ok) return r.status;
  const a = await r.json(), s = await settings();
  let listsChanged = false;
  for (const l of LISTS) if (a.lists && a.lists[l.id] !== undefined && !!s.lists[l.id] !== !!a.lists[l.id]) { s.lists[l.id] = !!a.lists[l.id]; listsChanged = true; }
  s.blocking = !!a.blocking; s.myBlock = a.myBlock || []; s.myAllow = a.myAllow || []; s.paused = a.paused || [];
  s.fromApp = Date.now();
  await save(s); await refreshCache(); await userChanged();
  if (listsChanged) {
    for (const l of LISTS) if (s.lists[l.id] && !(await kv('list:' + l.id))) { try { await downloadList(l); } catch (e) { } }
    await rebuild();
  }
  return 200;
}
// ---------------------------------------------------------------- element hiding + scriptlets
/** a page (cosmetic.js) asking for its cosmetic filters, or reporting the class/id names it uses */
async function cosmetic(m, sender) {
  try {
    if (!sender || !sender.tab) return;
    if (!cache) await refreshCache();
    const host = String(m.cos !== undefined ? m.cos : m.host || '').toLowerCase();
    if (!host || !cache.blocking || pausedOn(host) || inList(cache.myAllow, host)) return;
    const r = await getCos();
    if (!r) return;
    const css = m.survey ? surveyCss(r, host, m.survey.slice(0, 5000)) : cssFor(r, host);
    if (css) insertCss(sender.tab.id, sender.frameId || 0, css);
  } catch (e) { }
}
/** one script holding every site's scriptlets; inside a page it picks that page's and runs them (registered to run before the page's own scripts) */
function scriptletCode(r) {
  const T = {}, X = {};
  for (const [h, l] of r.js) T[h] = l;
  for (const [h, l] of r.jsEx) X[h] = l.map(n => SCRIPTLET_ALIAS[n] || n);
  const j = o => JSON.stringify(o).replace(/</g, '\\u003c');
  return '(function(){var T=' + j(T) + ',X=' + j(X) + ',h=location.hostname.toLowerCase(),out=[],off={},seen={},c,d,i,l,k;' +
    'for(c=h;;){l=X[c];if(l)for(i=0;i<l.length;i++)off[l[i]]=1;d=c.indexOf(".");if(d<0)break;c=c.slice(d+1);}' +
    'for(c=h;;){l=T[c];if(l)for(i=0;i<l.length;i++){k=JSON.stringify(l[i]);if(!off[l[i][0]]&&!seen[k]){seen[k]=1;out.push(l[i]);}}d=c.indexOf(".");if(d<0)break;c=c.slice(d+1);}' +
    'if(out.length)(' + groveScriptlets.toString() + ')(out);})();';
}
const hostPattern = h => '*://*.' + h + '/*';
function scriptletMatches(r) { return [...r.js.keys()].filter(h => /^[a-z0-9.-]+$/.test(h)).map(hostPattern); }
function scriptletExcludes() { return cache.paused.concat(cache.myAllow).filter(h => /^[a-z0-9.-]+$/.test(h)).map(hostPattern); }
/** (fallback, can be late) runs this site's scriptlets inside the page */
async function scriptlets(tabId, frameId, url) {
  try {
    if (!cache) await refreshCache();
    const host = hostOf(url);
    if (!host || !/^https?:/.test(url) || !cache.blocking || pausedOn(host) || inList(cache.myAllow, host)) return;
    const r = await getCos();
    const list = r ? scriptletsFor(r, host) : [];
    if (!list.length) return;
    const viaTag = () => {
      const code = '(' + groveScriptlets.toString() + ')(' + JSON.stringify(list) + ');';
      const inject = 'try{var s=document.createElement("script");s.textContent=' + JSON.stringify(code) + ';(document.head||document.documentElement).appendChild(s);s.remove();}catch(e){}';
      try { api.tabs.executeScript(tabId, { frameId, runAt: 'document_start', code: inject }); } catch (e) { }
    };
    if (api.scripting && api.scripting.executeScript) {
      try {
        const p = api.scripting.executeScript({ target: { tabId, frameIds: [frameId] }, world: 'MAIN', injectImmediately: true, func: groveScriptlets, args: [list] });
        if (p && p.catch) p.catch(() => { if (api.tabs.executeScript) viaTag(); });
      } catch (e) { if (api.tabs.executeScript) viaTag(); }
    } else viaTag();
  } catch (e) { }
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
  for (const l of LISTS) if (l.adult) s.lists[l.id] = true; // 18+ lists are locked on
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
  if (l.adult) {
    const text = await fetchList(l.url), out = [];
    for (const line of text.split('\n')) { const d = domainOf(line); if (d) out.push(d); }
    if (out.length < 100) throw new Error('the list looks empty');
    await kv('list:' + l.id, { domains: out });
    const meta = (await kv('meta')) || {};
    meta[l.id] = { updated: Date.now(), rules: out.length };
    await kv('meta', meta);
    return;
  }
  const r = new Rules().parse(await fetchList(l.url));
  await kv('list:' + l.id, r.toJSON());
  const meta = (await kv('meta')) || {};
  meta[l.id] = { updated: Date.now(), rules: r.size() };
  await kv('meta', meta);
}
/** Rebuilds the active rules from the switched-on lists (+ your own filters). */
async function rebuild() {
  const s = await settings(), r = new Rules(), ad = new Map();
  let anyAdult = false;
  for (const l of LISTS) {
    if (!s.lists[l.id]) continue;
    const j = await kv('list:' + l.id);
    if (!j) continue;
    if (l.adult) { if (j.domains) { ad.set(l.name, new Set(j.domains)); anyAdult = true; } else await kv('list:' + l.id, null); } // old format: download again
    else r.merge(Rules.fromJSON(j));
  }
  if (s.custom) r.parse(s.custom);
  rules = r;
  adult = anyAdult ? ad : null;
  if (typeof registerScriptlets === 'function' && typeof DNR === 'undefined') registerScriptlets();
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
    if ((await kv('fmt')) !== 2) { await kv('fmt', 2); if (await kv('meta')) { await updateAll(true); return; } } // older downloads have no generic cosmetic filters or scriptlets
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
    const ah = adultHit(u.hostname); // locked on: not lifted by pause or your allow list
    if (ah) {
      log('page', details.url, '', 'blocked', '18+ list: ' + ah.name); visit(details.url, true, '18+ list: ' + ah.name);
      return;
    }
    if (inList(s.myAllow, u.hostname)) { log('page', details.url, '', 'allowed', 'your allow list'); visit(details.url, false, 'your allow list'); return; }
    if (inList(s.myBlock, u.hostname)) {
      log('page', details.url, '', 'blocked', 'your block list'); visit(details.url, true, 'your block list');
      // the page itself is stopped before it loads (webRequest main_frame)
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
  if (d.type === 'main_frame') {
    // stop your blocked sites and 18+ sites before the page loads (the dangerous-site warning is handled on navigation)
    let mu; try { mu = new URL(d.url); } catch (e) { return {}; }
    if (!cache || (mu.protocol !== 'http:' && mu.protocol !== 'https:')) return {};
    const ah = adultHit(mu.hostname);
    if (ah) return { redirectUrl: blockUrl('adult', mu.hostname, '18+ list: ' + ah.name, ah.matched) };
    if (inList(cache.myAllow, mu.hostname)) return {};
    const you = mine(cache.myBlock, mu.hostname);
    if (you) return { redirectUrl: blockUrl('you', mu.hostname, 'your block list', you) };
    return {};
  }
  if (!cache) return {};
  const page = hostOf(d.documentUrl || d.originUrl || d.initiator || '');
  let u; try { u = new URL(d.url); } catch (e) { return {}; }
  if (u.protocol !== 'http:' && u.protocol !== 'https:' && u.protocol !== 'ws:' && u.protocol !== 'wss:') return {};
  const block = why => {
    if (d.tabId >= 0) { counts.set(d.tabId, (counts.get(d.tabId) || 0) + 1); badge(d.tabId); }
    log(d.type, d.url, page, 'blocked', why);
    return { cancel: true };
  };
  const ah = adultHit(u.hostname);
  if (ah) return block('18+ list: ' + ah.name);
  if (inList(cache.myAllow, u.hostname)) { log(d.type, d.url, page, 'allowed', 'your allow list'); return {}; }
  if (inList(cache.myBlock, u.hostname)) return block('your block list');
  if (!rules || !cache.blocking || pausedOn(page)) { log(d.type, d.url, page, 'allowed', pausedOn(page) ? 'site paused' : ''); return {}; }
  if (shouldBlock(rules, u.hostname, u.pathname + u.search, page, d.url)) return block('filter lists');
  log(d.type, d.url, page, 'allowed', '');
  return {};
}, { urls: ['<all_urls>'] }, ['blocking']);

// element hiding and scriptlets (Firefox: the rules are in memory)
function getCos() { return rules ? rules : ensure().then(() => rules); }
function insertCss(tabId, frameId, css) {
  try { api.tabs.insertCSS(tabId, { code: css, frameId, runAt: 'document_start', cssOrigin: 'user' }).catch(() => {}); } catch (e) {
    try { api.tabs.insertCSS(tabId, { code: css, frameId, runAt: 'document_start' }); } catch (e2) { }
  }
}
api.webNavigation.onCommitted.addListener(d => { scriptlets(d.tabId, d.frameId, d.url); });
// Firefox: the scriptlets are registered as a content script, so they run before the page's own scripts
let slReg = null, slBusy = null;
function registerScriptlets() {
  const run = async () => {
    try { if (slReg) { const old = slReg; slReg = null; await old.unregister(); } } catch (e) { }
    if (!rules || !api.contentScripts) return;
    if (!cache) await refreshCache();
    if (!cache.blocking) return;
    const matches = scriptletMatches(rules);
    if (!matches.length) return;
    const wrapper = 'try{var s=document.createElement("script");s.textContent=' + JSON.stringify(scriptletCode(rules)) +
      ';(document.head||document.documentElement).appendChild(s);s.remove();}catch(e){}';
    const ex = scriptletExcludes(), o = { matches, js: [{ code: wrapper }], runAt: 'document_start', allFrames: true };
    if (ex.length) o.excludeMatches = ex;
    try { slReg = await api.contentScripts.register(o); } catch (e) { }
  };
  slBusy = (slBusy || Promise.resolve()).then(run, run);
  return slBusy;
}
async function userChanged() { await registerScriptlets(); }
function badge(tabId) {
  const ba = api.browserAction || api.action;
  if (!ba || !ba.setBadgeText) return;
  const n = counts.get(tabId) || 0;
  try { ba.setBadgeText({ tabId, text: n ? String(n > 999 ? '999+' : n) : '' }); ba.setBadgeBackgroundColor && ba.setBadgeBackgroundColor({ color: '#60A917' }); } catch (e) { }
}
api.tabs.onRemoved.addListener(id => counts.delete(id));

// ---------------------------------------------------------------- messages from the popup, options and warning pages
api.runtime.onMessage.addListener((m, sender, reply) => {
  if (m && (m.cos !== undefined || m.survey)) { cosmetic(m, sender); return false; } // from cosmetic.js in a page
  if (sender && sender.tab && sender.url && !sender.url.startsWith(api.runtime.getURL(''))) return false; // only Groveguard's own pages may change settings
  (async () => {
    if (cache && cache.appKey && (m.rule || m.setList || m.pause || m.blocking !== undefined)) {
      // linked: the app is in charge — save the change there too
      const body = m.rule ? { rule: m.rule } : m.setList ? { list: m.setList } : m.pause ? { pause: m.pause } : { blocking: m.blocking };
      appPost('/v1/set', body).catch(() => {});
    }
    const s = await settings();
    if (m.allow) { s.allowed.push(m.allow); await save(s); }
    if (m.setList && (LISTS.find(x => x.id === m.setList.id) || {}).adult) m.setList.on = true; // locked on
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
    if (m.rule || m.pause || m.blocking !== undefined) { await refreshCache(); await userChanged(); }
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
  api.alarms.create('sync', { periodInMinutes: 1 });
  api.alarms.onAlarm.addListener(a => { if (a.name === 'sync') { syncApp(); if (!adult) ensureAdult().catch(() => {}); } });
}
/** the locked-on 18+ lists: download any that aren't here yet */
async function ensureAdult() {
  let got = false;
  for (const l of LISTS) if (l.adult) { const j = await kv('list:' + l.id); if (!j || !j.domains) { try { await downloadList(l); got = true; } catch (e) { } } }
  if (got) await rebuild();
}
refreshCache().then(ensure).then(ensureAdult).then(syncApp).catch(() => {});
setInterval(() => { if (LOGBOX.length) syncApp(); }, 5000);
