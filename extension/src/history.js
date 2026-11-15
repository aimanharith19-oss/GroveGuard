// SPDX-License-Identifier: AGPL-3.0-or-later
const api = typeof browser !== 'undefined' ? browser : chrome;
const $ = id => document.getElementById(id);
let filter = 'all', data = null, limit = 300;
for (const [id, f] of [['fAll', 'all'], ['fBlk', 'blocked'], ['fOk', 'allowed']]) $(id).onclick = () => {
  filter = f; limit = 300; for (const b of document.querySelectorAll('.chips button')) b.classList.toggle('on', b.id === id); draw();
};
$('q').oninput = () => { limit = 300; draw(); };
$('more').onclick = () => { limit += 300; draw(); };
$('c1').onclick = () => api.runtime.sendMessage({ clearRecent: 3600000 }, load);
$('c7').onclick = () => api.runtime.sendMessage({ clearHistory: 7 * 86400000 }, load);
$('call').onclick = () => { if (confirm('Clear all history?')) api.runtime.sendMessage({ clearHistory: 0 }, load); };
$('link').onclick = () => { $('appst').textContent = 'Linking…'; api.runtime.sendMessage({ appKey: $('key').value, sendAll: true }, r => { appStatus(r); load(); }); };
$('unlink').onclick = () => { $('key').value = ''; api.runtime.sendMessage({ appKey: '' }, r => { appStatus(r); load(); }); };
function appStatus(r) {
  if (!r) return;
  $('appst').textContent = !data || !data.appKey && !$('key').value ? 'Not linked.' :
    r.appState === 'ok' ? 'Linked · history is shown in the Groveguard app' + (r.pending ? ' (' + r.pending + ' waiting)' : '') :
    r.appState === 'wrong code' ? 'Wrong code — check the code in the Groveguard app.' :
    r.appState ? 'Linked, but ' + r.appState + ' — open Groveguard once; ' + r.pending + ' visits will be sent later.' : 'Linked.';
}
function rule(host, list) { api.runtime.sendMessage({ rule: { host, list } }, load); }
function draw() {
  if (!data) return;
  const q = $('q').value.trim().toLowerCase(), box = $('list');
  box.textContent = '';
  let n = 0, day = '', more = false, blocked = 0;
  for (const v of data.history) if (v.b) blocked++;
  for (const v of data.history) {
    if (filter === 'blocked' && !v.b) continue;
    if (filter === 'allowed' && v.b) continue;
    if (q && !v.u.toLowerCase().includes(q)) continue;
    if (n >= limit) { more = true; break; }
    n++;
    const dd = new Date(v.t), ds = dd.toDateString();
    if (ds !== day) {
      day = ds;
      const today = new Date().toDateString(), yest = new Date(Date.now() - 86400000).toDateString();
      const h = document.createElement('div'); h.className = 'day';
      h.textContent = ds === today ? 'today' : ds === yest ? 'yesterday' : dd.toLocaleDateString(undefined, { weekday: 'long', day: 'numeric', month: 'long', year: 'numeric' });
      box.appendChild(h);
    }
    const mine = data.myBlock.includes(v.h) ? 'block' : data.myAllow.includes(v.h) ? 'allow' : '';
    const d = document.createElement('div'); d.className = 'e' + (v.b ? ' blk' : '');
    d.innerHTML = '<div class="h"></div><div class="u w"></div><div class="u a"></div>';
    d.querySelector('.h').textContent = (v.b ? '✕ ' : '✓ ') + v.h;
    d.querySelector('.w').textContent = dd.toLocaleTimeString() + (v.w ? ' · ' + v.w : '');
    d.querySelector('.a').textContent = v.u;
    const b1 = document.createElement('button'); b1.textContent = mine === 'block' ? 'remove block' : 'always block'; b1.className = mine === 'block' ? 'o' : '';
    b1.onclick = () => rule(v.h, mine === 'block' ? 'none' : 'block');
    const b2 = document.createElement('button'); b2.textContent = mine === 'allow' ? 'remove allow' : 'always allow'; b2.className = 'o';
    b2.onclick = () => rule(v.h, mine === 'allow' ? 'none' : 'allow');
    const b3 = document.createElement('button'); b3.textContent = 'delete'; b3.className = 'o';
    b3.onclick = () => api.runtime.sendMessage({ deleteVisit: { t: v.t, u: v.u } }, load);
    d.append(b1, b2, b3);
    box.appendChild(d);
  }
  if (!n) box.innerHTML = '<p class="dim">' + (data.history.length ? 'No visits match.' : 'Nothing yet. Every website you open shows up here, blocked or not.') + '</p>';
  $('more').hidden = !more;
  $('st').textContent = data.history.length.toLocaleString() + ' visits · ' + blocked.toLocaleString() + ' blocked · kept only in this browser';
}
function load() {
  api.runtime.sendMessage({ history: true }, r => {
    data = r; if (!$('key').matches(':focus')) $('key').value = r.appKey; appStatus(r); draw();
  });
}
load();
setInterval(() => { if (!document.hidden && !$('q').matches(':focus') && !$('key').matches(':focus')) load(); }, 5000);
