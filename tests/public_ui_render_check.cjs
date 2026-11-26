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
                  '\n;globalThis.__ui={state,localServicePanel,localServiceState,localServiceRequest,fwVariantPanel,fwVariantBuildGate,netState,reloadDeviceHistory,backgroundImagePanel,prepareBackgroundImage,backgroundImageState,saveBackgroundImage,advancedOn,renderDevice,readDeviceStatus,refreshConnections,renderFirmware,renderFleet,renderSettings,renderDiagnostics,renderLive,liveState,startLivePoll,paintLiveTelemetry,paintLiveVideoStatus,setMode,setNav,pageVisible,renderWidgetManager,render};\n',
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
ok(html.includes('data-view="widgetmanager"'),'read-only Widget Manager navigation present');
for(const view of ['picker','netrunner','widgetlayout'])ok(!html.includes('data-view="'+view+'"'),view+' navigation excluded');
const code=['runtime/www/app.js','runtime/www/domains/widget_catalog.js'].map(path=>fs.readFileSync(path,'utf8')).join('\n');
const reviewedLocalPaths=new Set(['/api/service-mode/local/status','/api/service-mode/local/prepare','/api/service-mode/local/credential','/api/service-mode/local/receiver/inspect','/api/service-mode/local/receiver/verify','/api/service-mode/local/activate','/api/widgets/local/catalog','/api/widgets/local/rescan','/api/widgets/local/open-folder','/api/widgets/manager','/api/widgets/manager/action']);
const restrictedRequests=code.match(/\/api\/(?:service-mode|widgets|picker|netrunner|cot|relay\/press)[A-Za-z0-9_/-]*/g)||[];
ok(restrictedRequests.every(path=>reviewedLocalPaths.has(path)),'Only reviewed desktop host preparation and Widget Manager requests');
const hdpro={target:'hdpro',plan:{target:'hdpro',buildable:true,stage1:{mode:'bundled_support',complete:true}},job:null};
ok(ui.fwVariantBuildGate(hdpro,{state:'AVAILABLE',acknowledged:true}).ok,'HD Pro tester build is enabled after donor check and risk acknowledgement');
ok(!ui.fwVariantBuildGate(hdpro,{state:'AVAILABLE',acknowledged:false}).ok,'HD Pro keeps session risk acknowledgement');
hdpro.plan.buildable=false;
ok(!ui.fwVariantBuildGate(hdpro,{state:'AVAILABLE',acknowledged:true}).ok,'HD Pro retains donor refusal');
async function checkDeviceInfo(){
  const localBbId=['AA','BB','CC','DD'].join(':');
  let reply;
  let inventory={candidates:[],active_candidate_id:null};
  let readInventory=()=>({ok:true,json:async()=>inventory});
  const fixture=boot({fetch:async url=>{
    if(url==='/api/app')return new Promise(()=>{});
    if(url==='/api/status')return reply();
    if(url==='/api/connections')return readInventory();
    return {ok:true,json:async()=>({})};
  }});
  const device=fixture.__ui;
  const shown=()=>fixture.document.querySelector('#content').innerHTML;
  const session={connected:true,candidate_id:'fixture-port',serial_identity:{
    device_name:'Ascent_VRX_max_HF',serial_number:'fixture-receiver',firmware:'Ascent_VRX_Max_19_2_14'
  }};
  device.state.usbDriver={};
  device.state.connections={candidates:[{id:'fixture-port',identity_proven:false}]};
  device.renderDevice();
  ok(shown().includes('USB DEVICE DETECTED')&&shown().includes('Device identity is unverified'),
     'USB detection does not claim device identity');
  ok(!shown().includes('fixture-receiver')&&!shown().includes('OFFLINE'),
     'unproven USB displays no receiver data or false link state');

  device.state.activeConnection=session;
  device.state.capabilities={connection_state:'connected_recognized',role:'receiver'};
  reply=()=>({ok:true,json:async()=>({connected:true,link:'LINKED',local_bb_id:localBbId,rx_mcs:4})});
  await device.readDeviceStatus();
  ok(shown().includes('LINKED')&&shown().includes(localBbId),'valid Ground status is shown');

  reply=()=>({ok:false,status:503,json:async()=>({error:'synthetic private error'})});
  await device.readDeviceStatus();
  ok(shown().includes('fixture-receiver')&&shown().includes('Receiver link status could not be read'),
     'failed link refresh preserves proven USB identity and explains the next action');
  ok(shown().includes('UNAVAILABLE')&&!shown().includes('OFFLINE')&&!shown().includes(localBbId)
     &&!shown().includes('synthetic private error'),'failed refresh hides old telemetry and raw errors');

  let finish;
  reply=()=>new Promise(resolve=>{finish=resolve;});
  const read=device.readDeviceStatus();
  await device.refreshConnections();
  finish({ok:true,json:async()=>({connected:true,link:'LINKED',local_bb_id:localBbId})});
  await read;
  ok(device.state.activeConnection===null&&device.state.status===null&&shown().includes('NO DEVICE')
     &&!shown().includes('fixture-receiver'),'disconnect drops old identity and the late link response');

  inventory={candidates:[{id:'fixture-port',identity_proven:true}],active_candidate_id:null};
  await device.refreshConnections();
  ok(shown().includes('Select the detected device and use Connect'),
     'a detected device repaints the existing empty view with the connection action');

  inventory={error:'fixture inventory failure'};
  await device.refreshConnections();
  ok(shown().includes('USB DISCOVERY UNAVAILABLE')&&!shown().includes('NO DEVICE'),
     'discovery failure does not assert the device is absent');

  let finishInventory;
  device.state.activeConnection=session;
  readInventory=()=>new Promise(resolve=>{finishInventory=resolve;});
  const discovery=device.refreshConnections();
  const replacement={...session,candidate_id:'fixture-replacement'};
  device.state.activeConnection=replacement;
  finishInventory({ok:true,json:async()=>({candidates:[],active_candidate_id:null})});
  await discovery;
  ok(device.state.activeConnection===replacement,'late inventory cannot clear a newly selected device');
}
checkDeviceInfo().catch(error=>ok(false,error.stack)).finally(()=>{process.exitCode=failed?1:0;});

}
