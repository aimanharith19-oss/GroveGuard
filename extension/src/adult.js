// SPDX-License-Identifier: AGPL-3.0-or-later
const q = new URLSearchParams(location.search), h = q.get('h') || '';
if (q.get('r') === 'you') {
  document.title = 'Site blocked';
  document.querySelector('h1').textContent = 'site blocked';
  document.querySelector('.dim').textContent = 'You added this site to your block list. Remove it in Groveguard \u2192 logs or filter lists \u2192 my rules.';
}
document.getElementById('host').textContent = h.replace(/\./g, '[.]');
document.getElementById('back').onclick = () => { if (history.length > 2) history.go(-2); else location.href = 'about:blank'; };
