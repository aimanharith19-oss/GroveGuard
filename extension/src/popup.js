// SPDX-License-Identifier: AGPL-3.0-or-later
const api = typeof browser !== 'undefined' ? browser : chrome;
const st = document.getElementById('st');
function show(r) {
  if (!r) { st.textContent = 'Not ready.'; return; }
  st.textContent = r.ready ? 'On. Dangerous-site list updated ' + (r.updated ? new Date(r.updated).toLocaleDateString() : 'never') + '. ' + r.allowed.length + ' site(s) allowed.'
    : (r.err ? 'Update failed: ' + r.err : 'Downloading the list (about 14 MB)…');
}
api.runtime.sendMessage({}, show);
document.getElementById('up').onclick = () => { st.textContent = 'Updating…'; api.runtime.sendMessage({ update: true }, show); };
