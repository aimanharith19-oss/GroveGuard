// SPDX-License-Identifier: AGPL-3.0-or-later
// Block page — same wording as Grove Launcher's, plus the reason (which list, which entry matched).
const q = new URLSearchParams(location.search), h = q.get('h') || '', m = q.get('m') || '';
const kind = q.get('k') || (q.get('r') === 'you' ? 'you' : 'adult'), why = q.get('w') || (kind === 'you' ? 'your block list' : '18+ list');
const $ = id => document.getElementById(id), dot = s => s.replace(/\./g, '[.]');
const title = kind === 'adult' ? '18+ site blocked' : 'site blocked';
document.title = title.charAt(0).toUpperCase() + title.slice(1);
$('t').textContent = title;
if (kind === 'adult') document.body.className = 'adult';
$('host').textContent = dot(h);
$('text').textContent = kind === 'adult' ? 'This site is on an adult-content list switched on in Groveguard.' : 'You added this site to your block list in Groveguard.';
$('why').textContent = 'Reason: ' + why + (m && m !== h ? ' · listed as ' + dot(m) : '');
$('back').onclick = () => { if (history.length > 1) history.back(); else location.href = 'about:blank'; };
