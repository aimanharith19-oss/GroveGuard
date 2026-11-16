// Groveguard scriptlets — small pieces of code run inside a page (before its own scripts) to switch off ad scripts,
// anti-adblock checks and pop-ups. They implement the common uBlock Origin "+js(...)" filters, written for Groveguard.
// SPDX-License-Identifier: AGPL-3.0-or-later
// One self-contained function, so it can be handed to the page as-is: groveScriptlets([[name, arg, …], …])
function groveScriptlets(list) {
  'use strict';
  const w = window;
  const MARK = '__gg' + 'sl';
  try { if (w[MARK]) return; Object.defineProperty(w, MARK, { value: 1 }); } catch (e) { return; }
  const magic = 'gg' + Math.floor(Math.random() * 1e9).toString(36);
  const noop = function () { };
  // errors thrown on purpose to stop an ad script shouldn't show up as page errors
  const oe = w.onerror;
  w.onerror = function (msg) { if (typeof msg === 'string' && msg.indexOf(magic) >= 0) return true; return oe ? oe.apply(this, arguments) : false; };
  const abort = () => { throw new ReferenceError(magic); };

  function toRegex(s) {
    if (s === undefined || s === '' || s === '*') return /^/;
    if (s.length > 2 && s[0] === '/' && s.lastIndexOf('/') > 0) {
      const i = s.lastIndexOf('/');
      try { return new RegExp(s.slice(1, i), s.slice(i + 1).replace(/[^gimsuy]/g, '')); } catch (e) { }
    }
    return new RegExp(s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
  }
  /** matcher with optional leading "!" (not) */
  function matcher(s) {
    const not = typeof s === 'string' && s[0] === '!' && s.length > 1;
    const re = toRegex(not ? s.slice(1) : s);
    return v => re.test(String(v)) !== not;
  }
  /** defines a property deep in a chain ("a.b.c"), also when a or b don't exist yet */
  function trap(owner, chain, makeDesc) {
    const i = chain.indexOf('.');
    if (i < 0) {
      try {
        const cur = Object.getOwnPropertyDescriptor(owner, chain);
        if (cur && cur.configurable === false) return;
        Object.defineProperty(owner, chain, makeDesc(owner[chain]));
      } catch (e) { }
      return;
    }
    const prop = chain.slice(0, i), rest = chain.slice(i + 1);
    let v;
    try { v = owner[prop]; } catch (e) { return; }
    if (v instanceof Object) { trap(v, rest, makeDesc); return; }
    try {
      Object.defineProperty(owner, prop, {
        configurable: true, enumerable: true,
        get() { return v; },
        set(nv) { v = nv; if (nv instanceof Object) trap(nv, rest, makeDesc); },
      });
    } catch (e) { }
  }
  function constant(s) {
    switch (s) {
      case 'undefined': return undefined;
      case 'false': return false;
      case 'true': return true;
      case 'null': return null;
      case 'noopFunc': return noop;
      case 'trueFunc': return function () { return true; };
      case 'falseFunc': return function () { return false; };
      case 'emptyArr': case '[]': return [];
      case 'emptyObj': case '{}': return {};
      case 'emptyStr': case "''": case '': return '';
      case 'noopPromiseResolve': return () => Promise.resolve();
      case 'noopPromiseReject': return () => Promise.reject();
      case 'yes': case 'no': return s;
      case 'NaN': return NaN;
    }
    const n = Number(s);
    if (!isNaN(n) && Math.abs(n) <= 0x7fff) return n;
    return undefined;
  }
  function whenReady(fn) {
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', fn, { once: true }); else fn();
  }

  const S = {
    // set(chain, value): a property that always reads as value (e.g. adsEnabled = false)
    'set'(chain, value) {
      if (!chain) return;
      const known = ['undefined', 'false', 'true', 'null', 'noopFunc', 'trueFunc', 'falseFunc', 'emptyArr', '[]', 'emptyObj', '{}', 'emptyStr', "''", '',
        'noopPromiseResolve', 'noopPromiseReject', 'yes', 'no', 'NaN'];
      if (known.indexOf(value) < 0 && isNaN(Number(value))) return;
      const c = constant(value);
      trap(w, chain, () => ({ configurable: true, enumerable: true, get() { return c; }, set() { } }));
    },
    // aopr(chain): a script that reads this property is stopped
    'aopr'(chain) { if (chain) trap(w, chain, () => ({ configurable: true, get: abort, set() { } })); },
    // aopw(prop): a script that sets this property is stopped
    'aopw'(chain) { if (chain) trap(w, chain, cur => ({ configurable: true, get() { return cur; }, set: abort })); },
    // acs(chain, needle): stops the currently running script if its code matches needle and it touches chain
    'acs'(chain, needle) {
      if (!chain) return;
      const hit = matcher(needle);
      const me = document.currentScript;
      const check = () => {
        const s = document.currentScript;
        if (!(s instanceof HTMLScriptElement) || s === me) return;
        let text = s.textContent || '';
        if (!text && s.src) text = s.src;
        if (hit(text)) abort();
      };
      trap(w, chain, cur => {
        let v = cur;
        return { configurable: true, get() { check(); return v; }, set(nv) { check(); v = nv; } };
      });
    },
    // nostif(needle, delay): setTimeout calls whose code matches are dropped
    'nostif'(needle, delay) { timer('setTimeout', needle, delay, 0); },
    'nosiif'(needle, delay) { timer('setInterval', needle, delay, 0); },
    // nano-stb(needle, delay, boost): matching timers run faster (skips "wait 10 seconds" ad timers)
    'nano-stb'(needle, delay, boost) { timer('setTimeout', needle, delay, boost || '0.05'); },
    'nano-sib'(needle, delay, boost) { timer('setInterval', needle, delay, boost || '0.05'); },
    // no-fetch-if("url:pattern method:POST" or "pattern"): matching fetch() calls get an empty answer
    'no-fetch-if'(conds) {
      if (!conds || typeof w.fetch !== 'function') return;
      const tests = conds.split(/\s+/).filter(Boolean).map(c => {
        const m = /^(url|method|mode|credentials|cache|redirect|referrer|body):(.*)$/.exec(c);
        return [m ? m[1] : 'url', matcher(m ? m[2] : c)];
      });
      const real = w.fetch;
      w.fetch = function (input, init) {
        try {
          const req = { url: typeof input === 'string' ? input : (input && input.url) || String(input), method: (init && init.method) || (input && input.method) || 'GET' };
          Object.assign(req, init || {});
          if (tests.every(([k, t]) => t(req[k] === undefined ? '' : req[k]))) return Promise.resolve(new Response('', { status: 200, statusText: 'OK' }));
        } catch (e) { }
        return real.apply(this, arguments);
      };
    },
    // no-xhr-if(pattern): matching XMLHttpRequests get an empty answer
    'no-xhr-if'(conds) {
      if (!conds || !w.XMLHttpRequest) return;
      const m = /(?:^|\s)(?:url:)?(\S+)/.exec(conds);
      const hit = matcher(m ? m[1] : conds);
      const P = w.XMLHttpRequest.prototype, open = P.open, send = P.send;
      const blocked = new WeakSet();
      P.open = function (method, url) { try { if (hit(String(url))) blocked.add(this); } catch (e) { } return open.apply(this, arguments); };
      P.send = function () {
        if (!blocked.has(this)) return send.apply(this, arguments);
        const x = this;
        try {
          Object.defineProperties(x, { readyState: { value: 4, configurable: true }, status: { value: 200, configurable: true },
            statusText: { value: 'OK', configurable: true }, response: { value: '', configurable: true }, responseText: { value: '', configurable: true } });
        } catch (e) { }
        setTimeout(() => { for (const t of ['readystatechange', 'load', 'loadend']) { try { x.dispatchEvent(new Event(t)); } catch (e) { } } }, 1);
      };
    },
    // aeld(type, needle): event listeners of that type whose code matches are never added
    'aeld'(type, needle) {
      const tHit = matcher(type), nHit = matcher(needle);
      const P = w.EventTarget && w.EventTarget.prototype;
      if (!P) return;
      const add = P.addEventListener;
      P.addEventListener = function (t, h) {
        try {
          const code = typeof h === 'function' ? Function.prototype.toString.call(h) : (h && typeof h.handleEvent === 'function' ? Function.prototype.toString.call(h.handleEvent) : '');
          if (tHit(String(t)) && nHit(code)) return;
        } catch (e) { }
        return add.apply(this, arguments);
      };
    },
    // nowoif(pattern): window.open pop-ups (matching pattern, or all) are dropped
    'nowoif'(pattern) {
      const hit = matcher(pattern), real = w.open;
      w.open = function (url) { try { if (hit(String(url === undefined ? '' : url))) return null; } catch (e) { } return real.apply(this, arguments); };
    },
    // ra(attr|attr, selector) / rc(class|class, selector): remove attributes / classes, now and as the page changes
    'ra'(names, selector) { strip(names, selector, (el, n) => el.removeAttribute(n), n => '[' + n + ']'); },
    'rc'(names, selector) { strip(names, selector, (el, n) => el.classList.remove(n), n => '.' + n); },
    // rmnt(nodeName, needle): empties matching nodes (e.g. an inline <script> with ad code) before they run
    'rmnt'(nodeName, needle) {
      if (!nodeName) return;
      const name = nodeName.toLowerCase(), hit = matcher(needle);
      const clean = n => {
        try {
          const nn = n.nodeName.toLowerCase();
          if (name === '#text' ? n.nodeType === 3 : nn === name) { if (hit(n.textContent || '')) n.textContent = ''; }
        } catch (e) { }
      };
      const mo = new MutationObserver(ms => { for (const m of ms) for (const n of m.addedNodes) { clean(n); if (name === '#text' && n.childNodes) n.childNodes.forEach(clean); } });
      mo.observe(document, { childList: true, subtree: true });
      whenReady(() => setTimeout(() => mo.disconnect(), 10000));
    },
    'noeval-if'(needle) {
      const hit = matcher(needle), real = w.eval;
      w.eval = function (code) { if (hit(String(code))) return; return real.apply(this, arguments); };
    },
    'noeval'() { w.eval = function () { }; },
    // json-prune("a.b c", "needle.path"): removes those properties from every JSON the page parses
    'json-prune'(props, needle) {
      if (!props) return;
      const paths = props.split(/\s+/).filter(Boolean), needs = (needle || '').split(/\s+/).filter(Boolean);
      const walk = (o, path, del) => {
        const parts = path.split('.');
        let found = false;
        const go = (obj, i) => {
          if (!(obj instanceof Object)) return;
          const p = parts[i];
          const keys = p === '*' || p === '[]' ? Object.keys(obj) : (p in obj ? [p] : []);
          for (const k of keys) { if (i === parts.length - 1) { found = true; if (del) delete obj[k]; } else go(obj[k], i + 1); }
        };
        go(o, 0);
        return found;
      };
      const prune = o => { try { if (o instanceof Object && needs.every(n => walk(o, n, false))) for (const p of paths) walk(o, p, true); } catch (e) { } return o; };
      const parse = JSON.parse;
      JSON.parse = function () { return prune(parse.apply(this, arguments)); };
      if (w.Response && w.Response.prototype.json) {
        const rj = w.Response.prototype.json;
        w.Response.prototype.json = function () { return rj.apply(this, arguments).then(prune); };
      }
    },
    'nowebrtc'() {
      const fake = function () { };
      fake.prototype = { close: noop, createDataChannel: noop, createOffer: noop, setRemoteDescription: noop, addEventListener: noop, removeEventListener: noop,
        toString() { return '[object RTCPeerConnection]'; } };
      for (const n of ['RTCPeerConnection', 'webkitRTCPeerConnection', 'mozRTCPeerConnection']) if (w[n]) { try { w[n] = fake; } catch (e) { } }
    },
  };
  function timer(fn, needle, delay, boost) {
    const hit = matcher(needle), real = w[fn];
    let dHit = null;
    if (delay !== undefined && delay !== '' && delay !== '*') {
      const not = delay[0] === '!', d = Number(not ? delay.slice(1) : delay);
      if (!isNaN(d)) dHit = v => (Number(v) === d) !== not;
    }
    const factor = boost ? Math.min(Math.max(Number(boost) || 0.05, 0.001), 50) : 0;
    w[fn] = function (cb, ms) {
      try {
        const code = typeof cb === 'function' ? Function.prototype.toString.call(cb) : String(cb);
        if (hit(code) && (!dHit || dHit(ms))) {
          const args = Array.prototype.slice.call(arguments);
          if (factor) args[1] = (Number(ms) || 0) * factor; else args[0] = noop;
          return real.apply(this, args);
        }
      } catch (e) { }
      return real.apply(this, arguments);
    };
  }
  function strip(names, selector, remove, sel) {
    if (!names) return;
    const list = names.split(/\s*\|\s*/).filter(Boolean);
    const q = selector && !/^(stay|complete|asap)$/.test(selector) ? selector : list.map(sel).join(',');
    const run = () => { try { document.querySelectorAll(q).forEach(el => list.forEach(n => remove(el, n))); } catch (e) { } };
    let queued = false;
    whenReady(() => {
      run();
      const mo = new MutationObserver(() => { if (!queued) { queued = true; setTimeout(() => { queued = false; run(); }, 50); } });
      mo.observe(document.documentElement, { childList: true, subtree: true, attributes: true });
      setTimeout(() => mo.disconnect(), 15000);
    });
  }

  for (const item of list || []) {
    const f = S[item[0]];
    if (f) { try { f.apply(null, item.slice(1)); } catch (e) { } }
  }
}
if (typeof module !== 'undefined') module.exports = { groveScriptlets };
