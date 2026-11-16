// Groveguard — element hiding. Runs in every page: asks the background for this site's cosmetic filters, then tells it
// which class and id names the page actually uses so only the matching generic filters are applied (fast, like uBlock Origin).
// SPDX-License-Identifier: AGPL-3.0-or-later
(() => {
  if (!/^https?:$/.test(location.protocol)) return;
  const api = typeof browser !== 'undefined' ? browser : chrome;
  const host = location.hostname;
  const send = m => { try { const p = api.runtime.sendMessage(m, () => void api.runtime.lastError); if (p && p.catch) p.catch(() => { }); } catch (e) { } };
  send({ cos: host });
  const seen = new Set();
  let pending = [], timer = 0, total = 0;
  const flush = () => { timer = 0; if (pending.length) { send({ survey: pending, host }); pending = []; } };
  const add = t => { if (!seen.has(t) && total < 20000) { seen.add(t); total++; pending.push(t); if (!timer) timer = setTimeout(flush, 120); } };
  const note = el => {
    if (el.nodeType !== 1) return;
    const id = el.id;
    if (typeof id === 'string' && id) add('i' + id);
    const cl = el.classList;
    if (cl) for (let i = 0; i < cl.length; i++) add('c' + cl[i]);
  };
  const scan = root => {
    if (!root || root.nodeType !== 1) return;
    note(root);
    const all = root.querySelectorAll ? root.querySelectorAll('[id],[class]') : [];
    for (let i = 0; i < all.length && i < 20000; i++) note(all[i]);
  };
  const start = () => {
    scan(document.documentElement);
    new MutationObserver(ms => {
      for (const m of ms) {
        if (m.type === 'attributes') note(m.target);
        else for (const n of m.addedNodes) scan(n);
      }
    }).observe(document.documentElement, { childList: true, subtree: true, attributes: true, attributeFilter: ['class', 'id'] });
  };
  if (document.documentElement) start(); else document.addEventListener('readystatechange', start, { once: true });
})();
