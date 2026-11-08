// Render check for BUILD A PRODUCT VARIANT. Executes the real runtime/www/app.js in
// a DOM shim against plan documents of the exact shape the backend returns.
//
// WHAT THIS IS DEFENDING. The panel previously stated a model that was backwards:
// it reported the donor's LACK of Z camera code as a reason the image could not be
// built. A variant is a normal donor PLUS added files, so a normal donor contains no
// camera code by definition -- that is the correct input, not a fault. These checks
// pin the corrected reading in the rendered output, where an operator meets it.
//
// It also pins three things that were contradicting each other on screen:
//   * two independent blockers are shown AS two, each with what would clear it;
//   * the per-donor plan beats the donor-neutral gate sentence, so the panel cannot
//     say "one thing is in the way" directly above "there are TWO separate reasons";
//   * no I ACCEPT THIS RISK control while the feature is blocked, because accepting
//     cannot unlock it and the backend refuses on BLOCKED before it reads the
//     acknowledgement at all.
//
// Run via tests/test_firmware_variant.py, or directly:
//   node tests/firmware_variant_render_check.cjs
// Paths resolve from the repo root, so run it from there.
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
               options: [], value: '', checked: false, disabled: false, onclick: null, onchange: null,
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
                  '\n;globalThis.__ui={state,fwVariantPanel,fwVariantBuildGate,netState,reloadDeviceHistory,backgroundImagePanel,prepareBackgroundImage,backgroundImageState,saveBackgroundImage,advancedOn,renderDevice,renderFirmware,renderFleet,renderSettings,renderDiagnostics,renderLive,liveState,startLivePoll,paintLiveTelemetry,paintLiveVideoStatus,setMode,setNav,render};\n',
                  ctx, { filename: 'app.js' });
  return ctx;
}


module.exports={boot};
if(require.main===module){
const ctx=boot(),ui=ctx.__ui;
for(const fn of ['renderDevice','renderFleet','renderSettings','renderDiagnostics']){
 try{ui[fn]();ok(ctx.document.querySelector('#content').innerHTML.length>10,fn+' renders');}
 catch(error){ok(false,fn+': '+error.stack);}
}
const html=fs.readFileSync('runtime/www/index.html','utf8');
ok(html.includes('id="modeConfiguration"')&&html.includes('id="modeLive"'),'Config and Live remain present');
for(const view of ['device','firmware','rf','hub','rc','fleet'])ok(html.includes('data-view="'+view+'"'),view+' navigation retained');
for(const view of ['picker','netrunner','widgetmanager','widgetlayout'])ok(!html.includes('data-view="'+view+'"'),view+' navigation excluded');
const code=fs.readFileSync('runtime/www/app.js','utf8');
ok(!/\/api\/(service-mode|widgets|picker|netrunner|cot|relay\/press)/.test(code),'No private API requests in public interface');
const hdpro={target:'hdpro',plan:{target:'hdpro',buildable:true,stage1:{mode:'bundled_support',complete:true}},job:null};
ok(ui.fwVariantBuildGate(hdpro,{state:'AVAILABLE',acknowledged:true}).ok,'HD Pro tester build is enabled after donor check and risk acknowledgement');
ok(!ui.fwVariantBuildGate(hdpro,{state:'AVAILABLE',acknowledged:false}).ok,'HD Pro keeps session risk acknowledgement');
hdpro.plan.buildable=false;
ok(!ui.fwVariantBuildGate(hdpro,{state:'AVAILABLE',acknowledged:true}).ok,'HD Pro retains donor refusal');
process.exitCode=failed?1:0;

}
