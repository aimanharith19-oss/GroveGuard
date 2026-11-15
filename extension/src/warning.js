// SPDX-License-Identifier: AGPL-3.0-or-later
const api = typeof browser !== 'undefined' ? browser : chrome;
const q = new URLSearchParams(location.search), url = q.get('u') || '', listedAs = q.get('l') || '';
let host = ''; try { host = new URL(url).hostname; } catch (e) {}
document.getElementById('host').textContent = host.replace(/\./g, '[.]');
document.getElementById('why').textContent = 'Reason: dangerous-site list' + (listedAs && listedAs !== host ? ' · listed as ' + listedAs.replace(/\./g, '[.]') : '');
document.getElementById('back').onclick = () => { if (history.length > 2) history.go(-2); else location.href = 'about:blank'; };
document.getElementById('go').onclick = () => api.runtime.sendMessage({ allow: listedAs || host }, () => { location.href = url; });
