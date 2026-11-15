// Groveguard browser extension — background: download the list, check every page you open.
// SPDX-License-Identifier: AGPL-3.0-or-later
const api = typeof browser !== 'undefined' ? browser : chrome;
const LIST = 'https://maintainteam.github.io/HypatiaDatabases/hypatia-domains-bloom.bin';
const WEEK = 7 * 24 * 3600 * 1000;
let bloom = null, loading = null;

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
    const r = val === undefined ? s.get(key) : s.put(val, key);
    r.onsuccess = () => ok(r.result); r.onerror = () => no(r.error);
  });
}
async function download() {
  const res = await fetch(LIST, { cache: 'no-store' });
  if (!res.ok) throw new Error('HTTP ' + res.status);
  const buf = await res.arrayBuffer();
  const b = new Bloom(buf); // validates the header
  await kv('list', buf); await kv('updated', Date.now());
  bloom = b;
}
async function ensure() {
  if (bloom) return bloom;
  if (!loading) loading = (async () => {
    const buf = await kv('list');
    if (buf) bloom = new Bloom(buf);
    const upd = (await kv('updated')) || 0;
    if (!bloom) await download();
    else if (Date.now() - upd > WEEK) download().catch(() => {});
    return bloom;
  })().finally(() => { loading = null; });
  return loading;
}
async function allowed() { return (await kv('allow')) || []; }

async function check(details) {
  if (details.frameId !== 0) return;
  let u;
  try { u = new URL(details.url); } catch (e) { return; }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return;
  try {
    const b = await ensure();
    if (!b) return;
    const hit = listed(b, u.hostname, await allowed());
    if (!hit) return;
    const warn = api.runtime.getURL('warning.html') + '?u=' + encodeURIComponent(details.url) + '&l=' + encodeURIComponent(hit);
    api.tabs.update(details.tabId, { url: warn });
  } catch (e) { /* list not ready yet: let the page load */ }
}
api.webNavigation.onBeforeNavigate.addListener(check);
api.runtime.onMessage.addListener((m, s, reply) => {
  (async () => {
    if (m.allow) { const a = await allowed(); a.push(m.allow); await kv('allow', a); }
    if (m.update) { try { await download(); } catch (e) { return reply({ ok: false, err: String(e) }); } }
    reply({ ok: true, updated: (await kv('updated')) || 0, ready: !!(await ensure().catch(() => null)), allowed: await allowed() });
  })();
  return true;
});
api.runtime.onInstalled.addListener(() => ensure().catch(() => {}));
