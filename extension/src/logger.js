// SPDX-License-Identifier: AGPL-3.0-or-later
const api = typeof browser !== 'undefined' ? browser : chrome;
const $ = id => document.getElementById(id);
let filter = 'all', data = null;
for (const [id, f] of [['fAll', 'all'], ['fBlk', 'blocked'], ['fOk', 'allowed'], ['fPage', 'page']]) $(id).onclick = () => {
  filter = f; for (const b of document.querySelectorAll('.chips button')) b.classList.toggle('on', b.id === id); draw();
};
$('q').oninput = draw;
$('clear').onclick = () => api.runtime.sendMessage({ clearLog: true }, load);
function rule(host, list) { api.runtime.sendMessage({ rule: { host, list } }, load); }
function draw() {
  if (!data) return;
  const q = $('q').value.trim().toLowerCase(), box = $('list');
  box.textContent = '';
  let n = 0;
  for (const e of data.log) {
    if (filter === 'blocked' && e.verdict !== 'blocked') continue;
    if (filter === 'allowed' && e.verdict !== 'allowed') continue;
    if (filter === 'page' && e.type !== 'page') continue;
    if (q && !e.url.toLowerCase().includes(q) && !e.page.toLowerCase().includes(q)) continue;
    if (++n > 300) break;
    const mine = data.myBlock.includes(e.host) ? 'block' : data.myAllow.includes(e.host) ? 'allow' : '';
    const d = document.createElement('div'); d.className = 'e' + (e.verdict === 'blocked' ? ' blk' : '');
    d.innerHTML = '<div class="h"></div><div class="u"></div><div class="u w"></div>';
    d.querySelector('.h').textContent = (e.verdict === 'blocked' ? '\u2715 ' : '\u2713 ') + e.host;
    d.querySelector('.u').textContent = e.url;
    d.querySelector('.w').textContent = new Date(e.t).toLocaleTimeString() + ' · ' + e.type + (e.page ? ' on ' + e.page : '') + (e.why ? ' · ' + e.why : '');
    const b1 = document.createElement('button'); b1.textContent = mine === 'block' ? 'remove block' : 'always block'; b1.className = mine === 'block' ? 'o' : '';
    b1.onclick = () => rule(e.host, mine === 'block' ? 'none' : 'block');
    const b2 = document.createElement('button'); b2.textContent = mine === 'allow' ? 'remove allow' : 'always allow'; b2.className = 'o';
    b2.onclick = () => rule(e.host, mine === 'allow' ? 'none' : 'allow');
    d.append(b1, b2);
    box.appendChild(d);
  }
  $('st').textContent = data.log.length + ' recent requests · ' + data.myBlock.length + ' blocked and ' + data.myAllow.length + ' allowed by you';
}
function load() { api.runtime.sendMessage({ log: true }, r => { data = r; draw(); }); }
load();
setInterval(() => { if (!document.hidden && !$('q').matches(':focus')) load(); }, 3000);
