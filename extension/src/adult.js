// SPDX-License-Identifier: AGPL-3.0-or-later
const h = new URLSearchParams(location.search).get('h') || '';
document.getElementById('host').textContent = h.replace(/\./g, '[.]');
document.getElementById('back').onclick = () => { if (history.length > 2) history.go(-2); else location.href = 'about:blank'; };
