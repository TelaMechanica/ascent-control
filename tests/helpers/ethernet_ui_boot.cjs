// Boot the actual UI for selected Ethernet behavior; no native device actions.
const fs = require('fs'), vm = require('vm');

let failed = 0, passed = 0;
function ok(cond, what) {
  if (cond) { passed++; console.log('ok   ' + what); }
  else { failed++; console.log('FAIL ' + what); }
}

function classList() {
  const s = new Set();
  return { add: c => s.add(c), remove: c => s.delete(c), contains: c => s.has(c),
           has: c => s.has(c),
           toggle: (c, o) => { o === undefined ? (s.has(c) ? s.delete(c) : s.add(c))
                                               : (o ? s.add(c) : s.delete(c)); } };
}
function mk(e) {
  const el = { innerHTML: '', textContent: '', className: '', dataset: {}, style: {},
               options: [], value: '', checked: false, disabled: false, onclick: null, onchange: null, click() { this.onclick?.(); },
               addEventListener(type,listener) { this['on'+type]=listener; }, removeAttribute() {}, querySelector() { return mk(); },
               parentElement: { querySelector() { return mk(); }, classList: classList() } };
  el.classList = classList();
  return Object.assign(el, e || {});
}

function boot(options={}) {
  const nodes = new Map();
  const ctx = {
    document: { querySelector(s) { if (!nodes.has(s)) nodes.set(s, mk()); return nodes.get(s); },
                querySelectorAll() { return []; }, createElement() { return mk(); },
                body: { classList: classList() }, addEventListener() {},
                documentElement: mk() },
    window: options.window || {}, console,
    localStorage: { getItem() { return null; }, setItem() {}, removeItem() {} },
    fetch: options.fetch || (async () => ({ ok: true, json: async () => ({}) })),
    confirm: options.confirm || (()=>false),
    AbortController, atob: value=>Buffer.from(value,'base64').toString('binary'),
    URL: { createObjectURL: () => 'blob:', revokeObjectURL() {} }, Blob: class {},
    setInterval: options.setInterval || (() => 0), clearInterval() {}, setTimeout: options.setTimeout || (() => 0), clearTimeout: options.clearTimeout || (() => {}),
    Number, Math, Object, Array, String, JSON, Boolean, Date, isNaN, parseInt,
    parseFloat, Error, RegExp, Promise, Set, Map,
  };
  ctx.globalThis = ctx;
  vm.createContext(ctx);
  vm.runInContext(fs.readFileSync('runtime/www/i18n.js', 'utf8'), ctx, { filename: 'i18n.js' });
  vm.runInContext(require(require('path').join(process.cwd(),'tests/helpers/ui_source.js'))() +
                  '\n;globalThis.__ui={state,renderDevice,renderLive,liveState,maxEthernetTarget,maxEthernetState,maxEthernetPanel,reloadMaxEthernet,sendMaxEthernetKey,liveVideoSelection,bindMaxEthernet,render};\n',
                  ctx, { filename: 'app.js' });
  return ctx;
}


module.exports={boot};
