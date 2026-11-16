// SPDX-License-Identifier: AGPL-3.0-or-later
const api = typeof browser !== 'undefined' ? browser : chrome;
const $ = id => document.getElementById(id);
let first = true;
function send(m) { api.runtime.sendMessage(m, show); }
let show = function (r) {
  if (!r) return;
  $('st').textContent = r.rules.toLocaleString() + ' filters active · last update ' + (r.lastUpdate ? new Date(r.lastUpdate).toLocaleString() : 'never')
    + (r.errors && r.errors.length ? ' · failed: ' + r.errors.join('; ') : '');
  const box = $('lists'); box.textContent = '';
  let group = '';
  for (const l of r.lists) {
    if (l.group !== group) { group = l.group; const g = document.createElement('div'); g.className = 'sec'; g.textContent = group.toUpperCase(); box.appendChild(g); }
    const row = document.createElement('label'); row.className = 'row';
    const meta = r.meta[l.id];
    row.innerHTML = '<span><b></b><small></small></span><input type="checkbox">';
    row.querySelector('b').textContent = l.name;
    row.querySelector('small').textContent = meta ? meta.rules.toLocaleString() + ' rules · ' + new Date(meta.updated).toLocaleDateString() : (r.settings.lists[l.id] ? 'not downloaded yet' : 'off');
    if (l.adult) { // 18+ lists are locked on: no switch
      row.querySelector('input').remove();
      row.querySelector('small').textContent = 'always on · ' + (meta ? meta.rules.toLocaleString() + ' sites' : 'downloading…');
      box.appendChild(row); continue;
    }
    const cb = row.querySelector('input'); cb.checked = !!r.settings.lists[l.id];
    cb.onchange = () => { row.querySelector('small').textContent = 'working…'; send({ setList: { id: l.id, on: cb.checked } }); };
    box.appendChild(row);
  }
  if (first) { $('custom').value = r.settings.custom; first = false; }
  for (const [id, arr, key] of [['allowed', r.settings.allowed, 'unallow'], ['paused', r.settings.paused, 'pauseoff']]) {
    const b = $(id); b.textContent = '';
    if (!arr.length) { b.innerHTML = '<p class="dim">None</p>'; continue; }
    for (const h of arr) {
      const row = document.createElement('div'); row.className = 'row';
      row.innerHTML = '<span><b></b></span><button class="o">remove</button>';
      row.querySelector('b').textContent = h;
      row.querySelector('button').onclick = () => send(key === 'unallow' ? { unallow: h } : { pause: { host: h, on: false } });
      b.appendChild(row);
    }
  }
};
function rules(r) {
  for (const [id, arr, label] of [['myBlock', r.settings.myBlock, 'blocked'], ['myAllow', r.settings.myAllow, 'allowed']]) {
    const b = $(id); b.textContent = '';
    for (const h of arr) {
      const row = document.createElement('div'); row.className = 'row';
      row.innerHTML = '<span><b></b><small></small></span><button class="o">remove</button>';
      row.querySelector('b').textContent = h; row.querySelector('small').textContent = label + ' by you';
      row.querySelector('button').onclick = () => send({ rule: { host: h, list: 'none' } });
      b.appendChild(row);
    }
  }
}
const _show = show; show = r => { _show(r); if (r && r.settings) rules(r); };
$('addBlock').onclick = () => { send({ rule: { host: $('ruleHost').value, list: 'block' } }); $('ruleHost').value = ''; };
$('addAllow').onclick = () => { send({ rule: { host: $('ruleHost').value, list: 'allow' } }); $('ruleHost').value = ''; };
$('up').onclick = () => { $('st').textContent = 'Updating all lists…'; send({ update: true }); };
$('apply').onclick = () => send({ custom: $('custom').value });
send({});
