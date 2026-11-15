// SPDX-License-Identifier: AGPL-3.0-or-later
const api = typeof browser !== 'undefined' ? browser : chrome;
let tab = null, host = '';
const $ = id => document.getElementById(id);
function send(m) { if (tab) m.tabId = tab.id; api.runtime.sendMessage(m, show); }
function show(r) {
  if (!r) return;
  $('count').textContent = r.blockedHere;
  $('blocking').checked = r.settings.blocking;
  $('danger').checked = r.settings.danger;
  $('pause').checked = r.settings.paused.includes(host);
  $('st').textContent = (r.rules ? r.rules.toLocaleString() + ' filters active' : 'Downloading filter lists…')
    + ' · updated ' + (r.lastUpdate ? new Date(r.lastUpdate).toLocaleString() : 'never') + (r.errors && r.errors.length ? ' · ' + r.errors.length + ' list(s) failed' : '');
}
api.tabs.query({ active: true, currentWindow: true }, t => {
  tab = t && t[0];
  try { host = new URL(tab.url).hostname; } catch (e) { host = ''; }
  $('host').textContent = host || 'not a website';
  send({});
});
$('blocking').onchange = e => send({ blocking: e.target.checked });
$('danger').onchange = e => send({ danger: e.target.checked });
$('pause').onchange = e => { if (host) send({ pause: { host, on: e.target.checked } }); };
$('up').onclick = () => { $('st').textContent = 'Updating all lists…'; send({ update: true }); };
$('logs').onclick = () => { api.tabs.create({ url: api.runtime.getURL('logger.html') }); window.close(); };
$('lists').onclick = () => { api.runtime.openOptionsPage ? api.runtime.openOptionsPage() : api.tabs.create({ url: 'options.html' }); };
