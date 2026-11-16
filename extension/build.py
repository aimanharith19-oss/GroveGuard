#!/usr/bin/env python3
"""Builds groveguard-firefox.xpi (Manifest V2, Firefox) and groveguard-chromium.zip (Manifest V3: Vivaldi, Chrome, Edge, Brave).
The Chromium background script (bg3.js) is generated from src/bg.js + mv3/tail.js so both share the same lists, history and app link."""
import json, os, shutil, sys, zipfile
here = os.path.dirname(os.path.abspath(__file__))
src = os.path.join(here, 'src')
version = json.load(open(os.path.join(here, 'manifest-firefox.json')))['version']

def rp(s, a, b, n=1):
    assert s.count(a) == n, (a, s.count(a))
    return s.replace(a, b)

def bg3():
    s = open(os.path.join(src, 'bg.js')).read()
    head = s[:s.index('// whole pages: dangerous-site warning')]
    msgs = s[s.index('// ---------------------------------------------------------------- messages from the popup'):s.index('// ---------------------------------------------------------------- automatic updates')]
    head = rp(head, 'const api = typeof browser', 'const api = chrome; // Chromium, Manifest V3\nconst api_unused = typeof browser')
    head = rp(head, 'function log(type, url, page, verdict, why) {', 'function logMem(type, url, page, verdict, why) {')
    head = rp(head, 'async function rebuild() {', 'async function loadRules() {')
    head = rp(head, 'async function ensure() {', 'async function ensureOld() {')
    head = rp(head, '  await save(s); await refreshCache();\n  if (listsChanged) {', '  await save(s); await refreshCache(); await applyUser();\n  if (listsChanged) {')
    msgs = rp(msgs, '    let errors = [];', '    if (m.rule || m.pause || m.blocking !== undefined) { await refreshCache(); await applyUser(); }\n    let errors = [];')
    msgs = rp(msgs, "if (m.log) { await refreshCache();", "if (m.log) { await logLoad(); await refreshCache();")
    msgs = rp(msgs, "if (m.clearLog) LOG.length = 0;", "if (m.clearLog) { await logLoad(); LOG.length = 0; await kv('log', []); }")
    msgs = rp(msgs, 'rules: rules ? rules.size() : 0, danger: !!bloom,', "rules: ((await kv('rule-count')) || {}).filters || 0, ruleInfo: (await kv('rule-count')) || null, danger: !!(await kv('danger-updated')),")
    msgs = rp(msgs, 'blockedHere: m.tabId !== undefined ? (counts.get(m.tabId) || 0) : 0,', 'blockedHere: await matchedCount(m.tabId),')
    tail = open(os.path.join(here, 'mv3', 'tail.js')).read()
    start = '''
// ---------------------------------------------------------------- start-up and automatic updates
chrome.alarms.create('update', { periodInMinutes: 60 * 6, delayInMinutes: 2 });
chrome.alarms.create('sync', { periodInMinutes: 1 });
chrome.alarms.onAlarm.addListener(a => {
  if (a.name === 'update') updateAll(false).then(refreshCache).catch(() => {});
  if (a.name === 'sync') refreshCache().then(syncApp).then(ensureAdult).catch(() => {});
});
chrome.runtime.onInstalled.addListener(() => { refreshCache().then(() => updateAll(false)).then(ensureAdult).catch(e => console.warn('Groveguard: first update', e)); });
chrome.runtime.onStartup.addListener(() => { refreshCache().then(ensure).then(applyUser).then(syncApp).catch(() => {}); });
refreshCache().catch(() => {});
'''
    return head + tail + msgs + start

def manifest3():
    m = json.load(open(os.path.join(here, 'manifest-firefox.json')))
    return {
        'manifest_version': 3, 'name': m['name'], 'version': version, 'description': m['description'], 'icons': m['icons'],
        'minimum_chrome_version': '111',
        'permissions': ['declarativeNetRequest', 'declarativeNetRequestFeedback', 'webNavigation', 'tabs', 'alarms', 'scripting', 'unlimitedStorage'],
        'host_permissions': ['<all_urls>'],
        'background': {'service_worker': 'sw.js'},
        'action': {'default_popup': 'popup.html', 'default_title': 'Groveguard', 'default_icon': {'48': 'icon48.png'}},
        'options_ui': {'page': 'options.html', 'open_in_tab': True},
        'web_accessible_resources': [{'resources': m['web_accessible_resources'], 'matches': ['<all_urls>']}],
    }

def pack(out, files):
    with zipfile.ZipFile(out, 'w', zipfile.ZIP_DEFLATED) as z:
        for name in sorted(files):
            zi = zipfile.ZipInfo(name, (2026, 1, 1, 0, 0, 0)); zi.compress_type = zipfile.ZIP_DEFLATED; zi.external_attr = 0o644 << 16
            z.writestr(zi, files[name])

base = {f: open(os.path.join(src, f), 'rb').read() for f in os.listdir(src)}
ff = dict(base); ff['manifest.json'] = open(os.path.join(here, 'manifest-firefox.json'), 'rb').read()
pack(os.path.join(here, 'groveguard-firefox.xpi'), ff)
cr = {k: v for k, v in base.items() if k != 'bg.js'}
cr['bg3.js'] = bg3().encode()
cr['sw.js'] = b"// Groveguard service worker (Manifest V3)\nimportScripts('bloom.js', 'adblock.js', 'bg3.js');\n"
cr['manifest.json'] = json.dumps(manifest3(), indent=2).encode()
pack(os.path.join(here, 'groveguard-chromium.zip'), cr)
un = os.path.join(here, 'build-chromium')
shutil.rmtree(un, ignore_errors=True); os.makedirs(un)
for k, v in cr.items(): open(os.path.join(un, k), 'wb').write(v)
json.dump(manifest3(), open(os.path.join(here, 'manifest-chromium.json'), 'w'), indent=2)
print('built', version)
