// ================================================================ Manifest V3 (Chromium: Vivaldi, Chrome, Edge, Brave)
// Chromium no longer runs Manifest V2 extensions, so blocking is done with declarativeNetRequest rules that the
// browser itself applies. This file turns the lists and your rules into those rules.
const DNR = chrome.declarativeNetRequest;
const SUB = ['sub_frame', 'stylesheet', 'script', 'image', 'font', 'object', 'xmlhttprequest', 'ping', 'media', 'websocket', 'webtransport', 'webbundle', 'other'];
const ALL = ['main_frame'].concat(SUB);
const P_FILTER = 10, P_FALLOW = 12, P_OFF = 15, P_PAUSE = 20, P_BLOCK = 30, P_ALLOW = 40, P_ADULT = 50;
const ID_LISTS = 1000, ID_ADULT = 1000, ID_FILTER = 3000; // < 1000: your rules; 1000-2999: 18+; 3000+: filter lists
const CHUNK = 20000, MAX_RULES = 29000;
const EXT = chrome.runtime.getURL('');
function pageRule(id, priority, domains, kind, why) {
  return { id, priority, action: { type: 'redirect', redirect: { regexSubstitution: EXT + 'adult.html?k=' + kind + '&w=' + encodeURIComponent(why) + '#\\0' } },
    condition: { regexFilter: '^https?://.*', requestDomains: domains, resourceTypes: ['main_frame'] } };
}
/** your rules, paused sites and the main switch (cheap: a handful of rules) */
async function applyUser() {
  const s = cache || await settings(), add = [];
  if (s.myAllow.length) add.push({ id: 10, priority: P_ALLOW, action: { type: 'allow' }, condition: { requestDomains: s.myAllow, resourceTypes: ALL } });
  if (s.myBlock.length) {
    add.push(pageRule(11, P_BLOCK, s.myBlock, 'you', 'your block list'));
    add.push({ id: 12, priority: P_BLOCK, action: { type: 'block' }, condition: { requestDomains: s.myBlock, resourceTypes: SUB } });
  }
  if (s.paused.length) add.push({ id: 13, priority: P_PAUSE, action: { type: 'allowAllRequests' }, condition: { requestDomains: s.paused, resourceTypes: ['main_frame', 'sub_frame'] } });
  if (!s.blocking) add.push({ id: 14, priority: P_OFF, action: { type: 'allow' }, condition: { urlFilter: '*', resourceTypes: ALL } });
  const old = (await DNR.getDynamicRules()).map(r => r.id).filter(id => id < ID_LISTS);
  try { await DNR.updateDynamicRules({ removeRuleIds: old, addRules: add }); } catch (e) { console.warn('Groveguard: your rules', e); }
}
function okFilter(f) { return f && f.length < 1000 && /^[\x21-\x7e]+$/.test(f) && !f.startsWith('||*') && f !== '*' && f !== '|'; }
/** adds rules in batches; a batch the browser refuses is split until the bad rule is found and dropped */
async function addRules(list) {
  let added = 0;
  const put = async part => {
    if (!part.length) return;
    try { await DNR.updateDynamicRules({ addRules: part }); added += part.length; }
    catch (e) { if (part.length === 1) return; const m = part.length >> 1; await put(part.slice(0, m)); await put(part.slice(m)); }
  };
  for (let i = 0; i < list.length; i += 1000) await put(list.slice(i, i + 1000));
  return added;
}
/** the 18+ lists and the filter lists → browser rules (heavy: only when lists change) */
async function applyLists() {
  const r = rules, ad = adult, add = [];
  let id = ID_ADULT;
  if (ad) for (const [name, set] of ad) {
    const d = [...set];
    for (let i = 0; i < d.length; i += CHUNK) {
      const part = d.slice(i, i + CHUNK);
      add.push(pageRule(id++, P_ADULT, part, 'adult', '18+ list: ' + name));
      add.push({ id: id++, priority: P_ADULT, action: { type: 'block' }, condition: { requestDomains: part, resourceTypes: SUB } });
    }
  }
  const adultRules = add.length;
  id = ID_FILTER;
  let skipped = 0;
  if (r) {
    const dom = (set, extra, action, priority) => {
      const d = [...set].filter(h => /^[a-z0-9._-]+$/.test(h));
      for (let i = 0; i < d.length; i += CHUNK) add.push({ id: id++, priority, action: { type: action }, condition: Object.assign({ requestDomains: d.slice(i, i + CHUNK), resourceTypes: action === 'allow' ? ALL : SUB }, extra) });
    };
    dom(r.allow, {}, 'allow', P_FALLOW);
    dom(r.block, {}, 'block', P_FILTER);
    dom(r.block3p, { domainType: 'thirdParty' }, 'block', P_FILTER);
    const pat = (f, extra, action, priority) => {
      if (!okFilter(f)) return;
      if (id - ID_FILTER + adultRules >= MAX_RULES) { skipped++; return; }
      add.push({ id: id++, priority, action: { type: action }, condition: Object.assign({ urlFilter: f, isUrlFilterCaseSensitive: false, resourceTypes: action === 'allow' ? ALL : SUB }, extra) });
    };
    const g = p => p[0] === '|' ? p : p; // "|…" = anchored at the start of the address (same meaning in both engines)
    for (const l of r.genAllow.values()) for (const p of l) pat(g(p), {}, 'allow', P_FALLOW);
    for (const [h, l] of r.paths) for (const p of l) pat('||' + h + p, {}, 'block', P_FILTER);
    for (const [h, l] of r.paths3p) for (const p of l) pat('||' + h + p, { domainType: 'thirdParty' }, 'block', P_FILTER);
    for (const l of r.gen.values()) for (const p of l) pat(g(p), {}, 'block', P_FILTER);
    for (const l of r.gen3p.values()) for (const p of l) pat(g(p), { domainType: 'thirdParty' }, 'block', P_FILTER);
    await kv('cosmetic', r.cosmeticJSON());
    cos = null;
  }
  const old = (await DNR.getDynamicRules()).map(x => x.id).filter(x => x >= ID_LISTS);
  for (let i = 0; i < old.length; i += 5000) await DNR.updateDynamicRules({ removeRuleIds: old.slice(i, i + 5000) });
  const added = await addRules(add);
  await kv('rule-count', { filters: r ? r.size() : 0, browserRules: added, skipped, adult: ad ? [...ad.values()].reduce((n, s) => n + s.size, 0) : 0 });
  return added;
}
/** load the lists, hand them to the browser, then free the memory (the service worker is short-lived anyway) */
let applying = null;
async function rebuild() {
  if (applying) { await applying.catch(() => {}); }
  applying = (async () => { await loadRules(); await applyLists(); await applyUser(); await registerScriptlets(); rules = null; adult = null; })();
  try { await applying; } finally { applying = null; }
}
/** Chromium: the scriptlets are registered as a user script in the page's own world, so they run before the page's scripts.
 *  Needs "Allow user scripts" switched on for Groveguard on the extensions page; without it they still run, but can be late. */
function userScriptsApi() { try { return chrome.userScripts && chrome.userScripts.register ? chrome.userScripts : null; } catch (e) { return null; } }
async function registerScriptlets() {
  const us = userScriptsApi();
  await kv('user-scripts', !!us);
  if (!us) return false;
  try { await us.unregister({ ids: ['gg-scriptlets'] }); } catch (e) { }
  if (!cache) await refreshCache();
  if (!cache.blocking) return true;
  const r = await getCos(), matches = scriptletMatches(r);
  if (!matches.length) return true;
  const o = { id: 'gg-scriptlets', matches, js: [{ code: scriptletCode(r) }], runAt: 'document_start', world: 'MAIN', allFrames: true };
  const ex = scriptletExcludes();
  if (ex.length) o.excludeMatches = ex;
  try { await us.register([o]); } catch (e) { console.warn('Groveguard: scriptlets', e); return false; }
  return true;
}
async function userChanged() { await applyUser(); await registerScriptlets(); }
async function ensure() {
  if (!bloom) { const buf = await kv('danger'); if (buf) bloom = new Bloom(buf); }
  if ((await kv('fmt')) !== 2) { await kv('fmt', 2); if (await kv('meta')) { await updateAll(true); return; } } // older downloads have no generic cosmetic filters or scriptlets
  if (!(await kv('meta')) || !(await kv('danger-updated'))) await updateAll(false);
}
/** the locked-on 18+ lists: download any that aren't here yet */
async function ensureAdult() {
  const meta = (await kv('meta')) || {};
  let got = false;
  for (const l of LISTS) if (l.adult && !meta[l.id]) { try { await downloadList(l); got = true; } catch (e) { } }
  if (got) await rebuild();
}
async function matchedCount(tabId) {
  if (tabId === undefined) return 0;
  try { const m = await DNR.getMatchedRules({ tabId }); return m.rulesMatchedInfo.length; } catch (e) { return 0; }
}
// ---- log (kept across service-worker restarts)
let logReady = null, logSave = 0;
function logLoad() { if (!logReady) logReady = kv('log').then(l => { if (l && l.length) LOG.unshift(...l.slice(-LOG_MAX)); }).catch(() => {}); return logReady; }
function log(type, url, page, verdict, why) {
  logLoad().then(() => {
    logMem(type, url, page, verdict, why);
    if (!logSave) logSave = setTimeout(() => { logSave = 0; kv('log', LOG).catch(() => {}); if (LOGBOX.length) syncApp(); }, 1500);
  });
}
function whyOf(id) {
  if (id === 11 || id === 12) return 'your block list';
  if (id >= ID_ADULT && id < ID_FILTER) return '18+ list';
  return 'filter lists';
}
// blocked requests (only reported for an unpacked "developer mode" install, which is how this extension is loaded)
if (DNR.onRuleMatchedDebug) DNR.onRuleMatchedDebug.addListener(info => {
  const q = info.request, t = info.rule.ruleId;
  if (t === 10 || t === 13 || t === 14 || q.type === 'main_frame') return;
  DNR.getDynamicRules({ ruleIds: [t] }).then(rs => {
    if (rs[0] && rs[0].action.type !== 'block') return;
    log(q.type, q.url, hostOf(q.initiator || q.documentUrl || ''), 'blocked', whyOf(t));
  }).catch(() => {});
});
try { DNR.setExtensionActionOptions({ displayActionCountAsBadgeText: true }); } catch (e) { }

// ---- whole pages: history, log, dangerous-site warning
const warned = new Map();
chrome.webNavigation.onBeforeNavigate.addListener(async d => {
  if (d.frameId !== 0) return;
  let u; try { u = new URL(d.url); } catch (e) { return; }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return;
  try {
    if (!cache) await refreshCache();
    const s = cache;
    // 18+ words in the address (the 18+ lists themselves are browser rules): locked on, even for your allow list
    const aw = adultWords(u.hostname);
    if (aw) {
      warned.set(d.tabId, d.url);
      log('page', d.url, '', 'blocked', '18+ words in the address'); visit(d.url, true, '18+ words in the address');
      chrome.tabs.update(d.tabId, { url: blockUrl('adult', u.hostname, '18+ words in the address', aw) });
      return;
    }
    if (!s.danger || inList(s.myAllow, u.hostname)) return;
    if (!bloom) { const buf = await kv('danger'); if (buf) bloom = new Bloom(buf); }
    if (!bloom) return;
    const hit = listed(bloom, u.hostname, s.allowed);
    if (!hit) return;
    warned.set(d.tabId, d.url);
    log('page', d.url, '', 'blocked', 'dangerous-site list'); visit(d.url, true, 'dangerous-site list');
    chrome.tabs.update(d.tabId, { url: chrome.runtime.getURL('warning.html') + '?u=' + encodeURIComponent(d.url) + '&l=' + encodeURIComponent(hit) });
  } catch (e) { }
});
// element hiding and scriptlets: a light copy of the cosmetic rules, loaded when the service worker wakes
let cos = null;
async function getCos() { if (!cos) { const j = await kv('cosmetic'); cos = j ? Rules.fromJSON(j) : new Rules(); } return cos; }
function insertCss(tabId, frameId, css) { chrome.scripting.insertCSS({ target: { tabId, frameIds: [frameId] }, css, origin: 'USER' }).catch(() => {}); }
chrome.webNavigation.onCommitted.addListener(async d => {
  try {
    if (!cache) await refreshCache();
    if (d.frameId === 0) {
      if (d.url.startsWith(EXT + 'adult.html')) { // a page the browser rules stopped: the real address is after the #
        const q = new URL(d.url), real = decodeURIComponent(q.hash.slice(1)) || q.searchParams.get('h') || '';
        const why = q.searchParams.get('w') || 'blocked';
        if (real) { log('page', real, '', 'blocked', why); visit(real, true, why); }
        return;
      }
      if (/^https?:/.test(d.url)) {
        if (warned.get(d.tabId) === d.url) warned.delete(d.tabId);
        else { const h = hostOf(d.url), w = inList(cache.myAllow, h) ? 'your allow list' : ''; log('page', d.url, '', 'allowed', w); visit(d.url, false, w); }
      }
    }
    scriptlets(d.tabId, d.frameId, d.url);
  } catch (e) { }
});
