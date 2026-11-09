const t = (typeof window !== 'undefined' && window.t) ? window.t : (s => s);

const i18n = (typeof window !== 'undefined' && window.i18n) ? window.i18n : {
  t: s => s,
  setLocale: async () => ({ ok: true, locale: 'en' }),
  locale: () => 'en',
  locales: () => ({ en: { name: 'English', native: 'English' } }),
  missingKeys: () => [],
};

const $ = s => document.querySelector(s);

const $$ = s => [...document.querySelectorAll(s)];

const esc = v => String(v ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

const hx = v => typeof v === 'number' ? `0x${v.toString(16).toUpperCase().padStart(2,'0')}` : '—';

const safeErr = v => { const x=String(v??'').replace(/[A-Z]:\\[^:\r\n]+/gi,'<local-path>').replace(/\\\\[^:\r\n]+/g,'<network-path>'); if(/failed to fetch/i.test(x)) return 'LOCAL RUNTIME REQUEST FAILED'; return x.slice(0,240); };

const ERROR_SENTENCES = {
  UNAVAILABLE: 'Not available right now.',
  UNKNOWN: 'Not known.',
  UNQUALIFIED: 'This unit is not qualified for that operation.',
  NICKNAME_REJECTED: 'That nickname was not accepted.',
  DRIVER_REQUIRED: 'A driver is required and was not found.',
  BROWSE_FAILED: 'The file chooser could not be opened.',
  BROWSE_TRANSPORT_FAILED: 'The file chooser could not be reached.',
  NO_CORRELATED_NETWORK_BINDING:
    'Ascent Control cannot tell which unit this is. Several units use the same '
    + 'address, so it will not act on whichever one answers. Check the USB-C cable.',
  SHA256_MISMATCH: 'The bytes that arrived are not the file that was offered. Nothing was installed.',
  PACKAGE_UNVERIFIED: 'The map package did not verify, so it was not sent.',
  NO_HOST_ADDRESS: 'No local network address faces the unit, so it has nothing to fetch from.',
  MAP_SERVER_NO_BIND: 'No local address faces the unit, so there is nothing safe to serve on.',
};

const looksLikeCode = v => /^[A-Z][A-Z0-9]*(_[A-Z0-9]+)+$|^[A-Z]{3,}$/.test(String(v ?? '').trim());

function humanError(v){
  if (v && typeof v === 'object') return humanError(v.message || v.error || '');
  const raw = String(v ?? '').trim();
  if (!raw) return 'Something went wrong, and no reason was given.';
  if (!looksLikeCode(raw)) return safeErr(raw);
  if (ERROR_SENTENCES[raw]) return ERROR_SENTENCES[raw];
  const words = raw.toLowerCase().replace(/_/g, ' ');
  return safeErr(words.charAt(0).toUpperCase() + words.slice(1) + '.');
}

const I18N_STATIC = [
  ['[data-view="device"]','DEVICE INFO'], ['[data-view="fleet"]','MANAGE FLEET'],
  ['[data-view="firmware"]','MANAGE FIRMWARE'], ['[data-view="rf"]','MANAGE RF'],
  ['[data-view="hub"]','MANAGE HUB'], ['[data-view="rc"]','MANAGE RC'],
  ['[data-view="maps"]','MAPSTER'], ['[data-view="recovery"]','VTX RECOVERY'],
  ['[data-view="settings"]','APPLICATION SETTINGS'], ['[data-view="diagnostics"]','DIAGNOSTICS'],
  ['#modeConfiguration','CONFIG'], ['#modeLive','LIVE'],
  ['#connectBtn','CONNECT'], ['#refresh','REFRESH DEVICE'],
  ['.connect-label','CONNECTION'],
  // Found on the bench, both silently doing nothing: the WIDGETS rule looked for a
  // [data-widgets-label] attribute that does not exist in the markup, and
  // AUTO-CONNECT was never listed at all.
  ['#widgetsLabel','WIDGETS'], ['#advancedLabel','ADVANCED'],
  ['#autoConnectLabel','AUTO-CONNECT'],
  ['#deviceKicker','DETECTED DEVICE'],
];

function setLabel(el, en){
  if(!el) return;
  if(el.dataset) el.dataset.i18nSource = en;
  el.textContent = t(en);
}

function applyStaticTranslations(){
  I18N_STATIC.forEach(([sel,en])=>{ setLabel($(sel), en); });
  // Anything a dynamic writer labelled earlier in the session.
  (document.querySelectorAll('[data-i18n-source]')||[]).forEach(el=>{
    el.textContent = t(el.dataset.i18nSource);
  });
  // documentElement is absent in the render-check shims, which build a partial DOM.
  if (document.documentElement) document.documentElement.lang = i18n.locale();
}

function syncLanguageControls(){
  const code = i18n.locale();
  ['#langTop','#langSel'].forEach(sel=>{ const el=$(sel); if(el) el.value = code; });
}

async function setLanguage(code){
  const r = await i18n.setLocale(code);
  try{ localStorage.setItem('ascent.language', i18n.locale()); }catch{}
  applyStaticTranslations();
  syncLanguageControls();
  render();
  return r;
}

const state = {
  mode:'configuration',
  view: 'device', status: null, fleet: null, rf: null, devices: null,
  templates: {}, app: null, connections: null, activeConnection: null, rfBands: null,
  // RF band editing. rfEdit is null when not editing; rfStage is 'edit' | 'confirm' | 'writing' | 'done'.
  // rfStale marks the loaded table as a pre-write read that has not been reread.
  rfEdit: null, rfStage: null, rfPreview: null, rfWrite: null, rfProgress: null, rfError: null,
  rfStale: false,
  // Local reusable band plans. rfPlans is the host-local store document; planForm
  // is the open form, if any: 'save' | 'import' | 'export'. A plan never reaches a
  // device on its own -- LOAD fills the editor above and the existing write does
  // the rest, so there is exactly one commit path and one eligibility gate.
  rfPlans: null, planForm: null, planError: null,
  // Service Mode. Lives behind ADVANCED: ordinary work never needs it, and the
  // main workflow should not put SSH vocabulary in front of an operator.
  serviceMode: null, smBusy: false, smProgress: null, smStartedAt: null, smError: null, smShowEnrollment: false,
  // Result of the one-button activation. Held separately from serviceMode so a
  // later state refresh cannot quietly overwrite what the operator was shown.
  smActivation: null, smRevoke: null, smShowManual: false,
  smUseOwnKey: false, smKeyPath: '', smKeyOrigin: null,
  devSm: null, devSmError: null, devSmLoading: false, rfModeError: null,
  widgetCatalog: null, widgetCatalogError: null,
  widgetCatalogLoading: false, widgetDetail: null,
  // NETRUNNER. `netrunner: null` means "not read yet" and is what triggers the
  // read; it is never confused with "read and found nothing", which arrives as
  // an object with reachable:false and a reason.
  netrunner: null, netrunnerLoading: false, netrunnerBusy: null,
  netrunnerSteps: null, netrunnerError: null, nrAsk: null, nrAskError: null,
  nrJoin: null, nrJoinError: null, nrScan: null, nrScanNote: null,
  nrBoot: null, nrBootError: null, nrConfirmReset: false,
  rcZoomOpen: false, devSmPoll: null, mapsVrxRead: false,
  mapStorage: null, mapStorageLoading: false,
  // Own-ship feed to the goggles map auto-runs while connected. mapFeedStarted is
  // our idempotency latch (start once per connection); mapFeedUserOff latches a
  // manual STOP from the MAPS toggle so auto-start does not fight the operator.
  mapFeedStarted: false, mapFeedUserOff: false,
  battery: null, batteryLast: null, batteryWarn: null, battEdit: null, batteryMsg: null, batteryErr: false,
  fcc: null, fccConfirm: null, fccBusy: false, fccResult: null,
  // NETWORK DEVICES (known-IP, operator-asserted). Separate from USB device-session.
  networkDevices: null, networkDevicesLoading: false, networkProbe: {},
  networkEdit: null, networkMsg: null, networkErr: false,
  // The tool PATH only, and it is the only field left. The authorization token
  // was removed outright: Gate2.AUTHORIZATION is a constant compiled into this
  // same source tree, so a field demanding it authenticated nobody and cost the
  // operator a step. What gates this path is the tool itself, the unproven
  // acknowledgement, and the qualification gate.
  faTool: '', faError: null,
  // The first-access prompt is OPENED BY A PRESS, never rendered
  // standing. DEVICE INFO shows one button until an operator asks
  // for something that needs more than a button.
  faPrompt: false,
  featureCompat: null, featureCompatError: null, featureCompatLoading: false,
  widgetRuntime: null, widgetRuntimeLoading: false, widgetRuntimeBusy: false,
  widgetRuntimeError: null,
  widgetRuntimeConfirm: false, widgetRuntimeResult: null,
  usbDriver: null, usbDriverLoading: false,
  widgetImportResult: null,
  widgetLibrary: null, widgetLibraryLoading: false,
  widgetService: null, widgetServiceLoading: false,
  widgetServiceBusy: false, widgetServiceSteps: null,
  widgetServiceError: null,
  receivers: null, rxBusy: false, rxError: null, rxEnrollment: null,
  rxPwOpen: false, rxPwMismatch: false, rxLoading: false,
  // The VRX runtime bridge. `runtime` is the probe document; connecting is explicit
  // and per-session, because a tool that silently starts driving whatever answers on
  // a port is the opposite of the correlation discipline used everywhere else here.
  runtime: null, runtimeBusy: false, runtimeError: null,
  // Context-sensitive nav, local VTX nicknames, and the local save directory.
  // capabilities is the backend's per-page verdict for the connected device class;
  // null means "not yet known", which shows every page.
  capabilities: null, nicknames: null, nickError: null,
  // The nickname form's draft. Kept in state so a re-render -- an identity change,
  // an auto-fill, a completed save -- does not discard what the operator typed.
  saveDir: null, saveDirError: null, saveDirOk: null,
  // Firmware upgrade. fwStage is null | 'confirm' | 'flashing' | 'done'.
  // fwAck holds the soft prompts the operator has explicitly accepted -- the vendor
  // asks the same questions in modals; we require them by name.
  fw: null, fwStage: null, fwAck: [], fwResult: null, fwProgress: null, fwError: null,
  fwPathDraft: '', fwBusy: false,
  // Host-side Hi3516CV610 recovery kit. This page validates and launches fixed
  // bundled assets; it intentionally exposes no direct NAND-write request.
  recovery: null, recoveryBusy: false, recoveryMessage: null, recoveryError: null,
  // A connect is in flight. The connect bar shows it, and the 1 s candidate poll
  // must leave the connect bar alone while it is true.
  connecting: false
};

function pageHead(title, _strapline='') {
  return `<h2 class="page-head">${esc(t(title))}</h2>`;
}

function notice(text, cls='') { return `<div class="notice ${cls}">${esc(t(text))}</div>`; }

function translateMarkup(html){
  if (typeof html !== 'string' || i18n.locale() === 'en') return html;
  return html.replace(/>([^<>]+)</g, (whole, text) => {
    const trimmed = text.trim();
    if (!trimmed) return whole;
    const hit = t(trimmed);
    if (hit === trimmed) return whole;               // not in the catalog
    return whole.replace(text, text.replace(trimmed, hit));
  });
}

function panel(title, body) { return `<div class="panel"><div class="panel-title">${esc(t(title))}</div><div class="panel-body">${translateMarkup(body)}</div></div>`; }

const val = (text, cls='') => ({ __kv:'styled', text, cls });

function valText(v,cls){
  if(v&&v.__kv==='styled') return `<span class="${esc(v.cls||'')}">${esc(t(v.text??'—'))}</span>`;
  return `<span class="${esc(cls||'')}">${esc(t(v??'—'))}</span>`;
}

function kv(k,v,mono=true){
  const tag = mono ? 'code' : 'span';
  const inner = (v && v.__kv === 'styled')
    ? `<${tag} class="${esc(v.cls)}">${esc(t(v.text ?? '—'))}</${tag}>`
    : `<${tag}>${esc(t(v ?? '—'))}</${tag}>`;
  return `<div class="kv"><span>${esc(t(k))}</span>${inner}</div>`;
}

function noticeDetail(text, cls=''){ return advancedOn() ? notice(text, cls) : ''; }

function kvControl(k, html){
  return `<div class="kv"><span>${esc(k)}</span><span class="kv-control">${html}</span></div>`;
}

const VIEW_RELOADS = {
  netrunner:    ['netrunner'],
  picker:       ['picker','pickerDiscover'],
  widgetlayout: ['layout'],
  widgetmanager:['widgetCatalog','widgetLibrary','widgetService','widgetManager'],
  repeater:     ['repeater'],
  recovery:     ['recovery'],
  diagnostics:  ['deviceHistory'],
  maps:         ['maps'],
  live:         ['live'],
  firmware:     ['fw'],
};

function loadingValues(){
  return '<div class="empty">LOADING VALUES\u2026</div>';
}

function setNav(view){
 const allowed=['device','firmware','rf','hub','rc','fleet','repeater','settings','diagnostics'];
 if(!allowed.includes(view))return;state.view=view;
 $$('.nav').forEach(n=>n.classList.toggle('active',n.dataset.view===view));
 for(const key of (VIEW_RELOADS[view]||[]))state[key]=null;
 if(view==='diagnostics'){
   state.deviceHistoryLoading=false;
   state.deviceHistoryRequest=(state.deviceHistoryRequest||0)+1;
   const n=netState();n.doc=null;n.error=null;n.busy=false;n.request=(n.request||0)+1;
 }
 state.fwLoading=false;if(view==='fleet')reloadFleetPage();render();
}

const CONN={NO_DEVICE:'no_device',SCANNING:'scanning',DETECTED:'detected',
            CONNECTED_RECOGNIZED:'connected_recognized',
            CONNECTED_UNRECOGNIZED:'connected_unrecognized'};

const NO_DEVICE_PAGES=['fleet','device','firmware','maps','recovery','settings','diagnostics'];

function connectionState(){
  if(state.activeConnection?.connected&&state.activeConnection?.network_target)return CONN.CONNECTED_UNRECOGNIZED;
  const s=state.capabilities?.connection_state;
  if(s) return s;
  if(state.activeConnection?.connected) return CONN.CONNECTED_UNRECOGNIZED;
  const cs=state.connections?.candidates;
  if(!Array.isArray(cs)) return CONN.SCANNING;
  if(cs.length===0) return CONN.NO_DEVICE;
  return cs.some(c=>c.identity_proven)?CONN.DETECTED:CONN.SCANNING;
}

function pageVisible(view){
  if(state.activeConnection?.connected&&state.activeConnection?.network_target){
    if(view==='repeater')return state.activeConnection.network_target.kind==='repeater';
    return NO_DEVICE_PAGES.includes(view);
  }
  if(view==='widgetmanager'&&!'')return false;
  const p=state.capabilities?.pages?.[view];
  const fromDoc=p?p.visible!==false:null;
  // These device editors never inherit the generic fail-open policy.
  if(view==='hub'||view==='rc'){
    return state.capabilities?.live_device===true && p?.visible===true
      && [CONN.CONNECTED_RECOGNIZED,CONN.CONNECTED_UNRECOGNIZED].includes(connectionState());
  }
  switch(connectionState()){
    // No live identified device. With no document, fail CLOSED to host-local.
    case CONN.NO_DEVICE:
    case CONN.SCANNING:
    case CONN.DETECTED:
      return fromDoc!==null?fromDoc:NO_DEVICE_PAGES.includes(view);
    // A live device. With no document, fail OPEN and show the page.
    case CONN.CONNECTED_RECOGNIZED:
    case CONN.CONNECTED_UNRECOGNIZED:
      return fromDoc!==null?fromDoc:true;
    default:
      // Unreachable: connectionState() returns one of the five named above. A new
      // state must not inherit "visible" from here -- that fall-through was the bug.
      return NO_DEVICE_PAGES.includes(view);
  }
}

function navOrder(){ return $$('.nav').map(n=>n.dataset.view); }

function applyNavVisibility(){
  $$('.nav').forEach(n=>n.classList.toggle('hidden',!pageVisible(n.dataset.view)));
  if(!pageVisible(state.view)){
    // The selected page just became inapplicable. Fall back to the first page
    // that still applies, in nav order, rather than rendering an empty view.
    const fallback=navOrder().find(pageVisible)||'device';
    state.view=fallback;
    $$('.nav').forEach(n=>n.classList.toggle('active',n.dataset.view===fallback));
  }
}

function normalizeMac(s){
  const m=String(s||'').trim().replaceAll('-',':').toUpperCase();
  if(!/^[0-9A-F]{2}(?::[0-9A-F]{2}){3}$/.test(m)) throw Error(`Invalid BB ID ${s}`);
  if(m===['00','00','00','00'].join(':')||m===['FF','FF','FF','FF'].join(':')) throw Error('Sentinel BB ID');
  return m;
}

function fmtMHz(v){
  const n=Number(v);
  if(!Number.isFinite(n)) return '—';
  const mhz=Math.abs(n)>=100000 ? n/1000 : n;
  const digits=Math.abs(mhz-Math.round(mhz))<1e-9 ? 0 : (Math.abs(mhz*10-Math.round(mhz*10))<1e-8 ? 1 : 3);
  return `${mhz.toFixed(digits)} MHz`;
}

function shortFirmware(v){
  const x=String(v||'').trim();
  const m=x.match(/(\d+(?:[._]\d+){2,})$/);
  return m ? m[1].replaceAll('_','.') : (x||'—');
}

function ident(){ return state.activeConnection?.serial_identity || null; }

function productDoc(){ return state.capabilities?.product || null; }

function productLabel(){
  const d=productDoc();
  if(d&&d.display) return d.display;
  return ident()?.device_name || null;
}

function candidateLabel(c){
  return c?.device_product?.display || c?.device_name || null;
}

function transportLabel(){
  const c=state.activeConnection?.candidate||{};
  return c.transport || (ident()?.port ? `SERIAL ${ident().port}` : '—');
}

function connectedBbId(){
  try{ return normalizeMac(state.status?.local_bb_id) }catch{ return null }
}

function nicknameFor(bb, kind){
  let key=null; try{ key=normalizeMac(bb) }catch{ return null }
  const e=state.nicknames?.entries?.[key];
  if(!e) return null;
  if(kind && e.identity!==kind) return null;
  return e.nickname||null;
}

function nicknameCollision(name, bb){
  const fold=String(name??'').normalize('NFC').trim().toLowerCase();
  if(!fold) return null;
  let mine=null; try{ mine=normalizeMac(bb) }catch{ mine=null }
  const folds=state.nicknames?.nickname_folds;
  if(folds && Object.prototype.hasOwnProperty.call(folds,fold)){
    return folds[fold]!==mine ? folds[fold] : null;
  }
  if(folds) return null;
  // Older store shape: no folded index, so compare the names themselves.
  for(const [k,v] of Object.entries(state.nicknames?.nicknames||{})){
    if(k!==mine && String(v??'').normalize('NFC').trim().toLowerCase()===fold) return k;
  }
  return null;
}

function knownDevicesPanel(){
  const entries=state.nicknames?.entries||{};
  const kindLabels=state.nicknames?.identity_kinds||{aircraft_vtx:'AIRCRAFT / VTX',receiver:'GROUND RECEIVER'};
  const liveVrx=connectedBbId();
  let liveVtx=null; try{ liveVtx=normalizeMac(state.enroll?.result?.bb_id) }catch{ liveVtx=null }
  const fleetList=(state.rxfleet?.data?.candidates||[]).map(c=>{ try{return normalizeMac(c.bb_id)}catch{return null} }).filter(Boolean);
  const fleetSet=new Set(fleetList);
  const rows={};
  const touch=(bb,identity)=>{ let k=null; try{k=normalizeMac(bb)}catch{return null}
    if(!rows[k]) rows[k]={bb:k,identity:identity||'aircraft_vtx',stored:false,nickname:''}; return rows[k]; };
  for(const [bb,e] of Object.entries(entries)){ const r=touch(bb,e.identity); if(r){ r.stored=true; r.nickname=e.nickname||''; r.identity=e.identity||r.identity; } }
  if(liveVrx) touch(liveVrx,'receiver');
  for(const bb of fleetList) touch(bb,'aircraft_vtx');
  if(liveVtx) touch(liveVtx,'aircraft_vtx');
  const sourceOf=(bb)=>{ const s=[];
    if(liveVtx&&bb===liveVtx) s.push('LIVE VTX');
    if(liveVrx&&bb===liveVrx) s.push('LIVE VRX');
    if(fleetSet.has(bb)) s.push('ON VRX FLEET');
    if(!s.length) s.push('LOCAL PC');
    return s.join(' + '); };
  const list=Object.values(rows).sort((a,b)=>a.bb<b.bb?-1:1);
  const table=list.length
    ? `<table><thead><tr><th>BB ID</th><th>IDENTITY</th><th>LOCAL NICKNAME</th><th>SOURCE</th><th>ACTION</th></tr></thead><tbody>${list.map(r=>{
        const kind=r.identity;
        return `<tr><td><code>${esc(r.bb)}</code></td><td class="muted">${esc(kindLabels[kind]||kind)}</td>`
          +`<td><input class="text-input" type="text" maxlength="32" autocomplete="off" spellcheck="false" data-bb="${esc(r.bb)}" data-identity="${esc(kind)}" value="${esc(r.nickname)}" placeholder="(NONE)"></td>`
          +`<td class="muted">${esc(sourceOf(r.bb))}</td>`
          +`<td><button class="action" data-rename-bb="${esc(r.bb)}" data-identity="${esc(kind)}">RENAME</button>${r.stored?` <button class="secondary" data-clear-bb="${esc(r.bb)}">CLEAR</button>`:''}</td></tr>`;
      }).join('')}</tbody></table>`
    : `<div class="empty">NO KNOWN DEVICES YET — enroll an aircraft over USB, or connect a receiver.</div>`;
  const nickErr=state.nickError?notice(`LOCAL NICKNAME REJECTED FOR ${esc(state.nickError.bb_id)} — ${safeErr(state.nickError.message)}`,'error'):'';
  const dupWarn=state.nicknames?.unique===false
    ? notice(`TWO OR MORE BB IDS SHARE A NICKNAME: ${esc(Object.values(state.nicknames.duplicate_nicknames||{}).map(b=>b.join(' + ')).join(', '))}. Reverse lookup refuses an ambiguous name — rename one.`,'error') : '';
  return panel('KNOWN DEVICES — THIS PC',
    `<p class="muted">Every BB ID this PC knows — aircraft and receivers — with where it is seen. A unit appears by enrolling an aircraft over USB or connecting a receiver; names are stored on this PC only and are never written to a device. SOURCE — LIVE VTX: aircraft enrolled over USB this session. LIVE VRX: the connected receiver. ON VRX FLEET: in the connected receiver candidate list. LOCAL PC: known here, not currently connected.</p>`
    +nickErr+table+dupWarn
    +(advancedOn()
      ? kv('Stored names',state.nicknames?.count??'—')+kv('Store file',state.nicknames?.store_file||'—')+kv('Nicknames unique',state.nicknames?.unique===false?'NO — SEE ABOVE':'YES — ONE NAME, ONE BB ID')
      : ''));
}

function renderFleet(){
 let out=pageHead('MANAGE FLEET','KNOWN DEVICES — THIS PC');
 out+='<p class="muted">Names and identities saved on this PC. Receiver fleet membership and Picker switching require AC+.</p>';
 out+=knownDevicesPanel();$('#content').innerHTML=out;bindFleetEditors();
}

async function saveNickname(bb, value, identity){
  state.nickError=null;
  const body={bb_id:bb,nickname:value};
  // Only sent when the caller knows the kind. Omitting it keeps an existing entry's
  // kind rather than silently relabelling the unit.
  if(identity) body.identity=identity;
  const {ok,data}=await rfPost('/api/vtx-nicknames',body);
  const good=ok&&data.ok;
  if(!good){ state.nickError={bb_id:bb,error:data.error||'NICKNAME_REJECTED',conflict:data.conflict||null,
                              message:safeErr(data.message||data.error||'NICKNAME_REJECTED')}; }
  else { state.nicknames=data.store; }
  // A name can be the header's, so the header is repainted with the store.
  updateHeader();
  render();
  return good;
}

function bindFleetEditors(){
 $$('.text-input[data-bb]').forEach(el=>el.addEventListener('change',()=>saveNickname(el.dataset.bb,el.value,el.dataset.identity)));
 $$('[data-clear-bb]').forEach(el=>el.addEventListener('click',()=>saveNickname(el.dataset.clearBb,'')));
 $$('[data-rename-bb]').forEach(el=>el.addEventListener('click',()=>{const bb=el.dataset.renameBb;const input=$('.text-input[data-bb="'+CSS.escape(bb)+'"]');saveNickname(bb,input?input.value:'',el.dataset.identity);}));
}

function renderRf(){
  const bands=state.rfBands||{}; const live=state.rf; const q=live?.queries||{};
  let out=pageHead('RF BAND CHANNEL MANAGEMENT','PERSISTENT DEVICE TABLE + LIVE RF STATE');
  if(bands.available){
    const t=bands.data||{}; const keys=['bandA','bandB','bandC','bandD'].filter(k=>Array.isArray(t[k]));
    const total=keys.reduce((n,k)=>n+t[k].length,0);
    out+=`<div class="metric-grid"><div class="metric"><label>RF BOARD TYPE</label><strong>${esc(t.RFBoardType??ident()?.rf_board_code??'—')}</strong></div><div class="metric"><label>RF BOARD</label><strong>${esc(ident()?.rf_board_name||'—')}</strong></div><div class="metric"><label>BANDS</label><strong>${keys.length}</strong></div><div class="metric"><label>CHANNEL ENTRIES</label><strong>${total}</strong></div></div>`;
    const editing=state.rfStage==='edit'||state.rfStage==='confirm';
    const src=editing?state.rfEdit.bands:t;
    const bandCards=keys.map(k=>{
      const arr=src[k]||[]; const lastIdx=arr.length-1;
      const rows=arr.map((v,i)=>{
        // The LAST entry of every band is the per-band default frequency, not a
        // channel. The vendor validator drops it before checking min/max.
        const lbl=i===lastIdx?'DEF':String(i+1).padStart(2,'0');
        const changed=editing&&Array.isArray(t[k])&&t[k][i]!==v;
        if(state.rfStage==='edit'){
          return `<div class="freq-row${changed?' freq-changed':''}"><b>${lbl}</b><input class="freq-input" type="text" inputmode="numeric" data-band="${esc(k)}" data-idx="${i}" value="${esc(v)}"><small>${esc(fmtMHz(v))}</small></div>`;
        }
        return `<div class="freq-row${changed?' freq-changed':''}"><b>${lbl}</b><span>${esc(fmtMHz(v))}</span><small>${esc(v)}</small></div>`;
      }).join('');
      return `<div class="band"><h3>${esc(k.toUpperCase())} <span>${Math.max(0,arr.length-1)} CH + DEF</span></h3><div class="freqs">${rows}</div></div>`;
    }).join('');
    const canWrite=bands.available&&!!ident()?.device_name;
    let bar='';
    if(state.rfStage==='edit'){
      bar=`<div class="toolbar" style="justify-content:flex-start"><button class="action" id="rfReview">REVIEW CHANGES…</button><button class="secondary" id="rfCancel">CANCEL</button><span class="rf-hint">EDIT VALUES IN kHz. DEF IS THE PER-BAND DEFAULT FREQUENCY, NOT A CHANNEL.</span></div>`;
    } else if(state.rfStage==='writing'){
      bar=`<div class="toolbar" style="justify-content:flex-start"><button class="action" disabled>WRITING…</button><span class="rf-hint">DO NOT DISCONNECT THE DEVICE.</span></div>`;
    } else if(canWrite){
      bar=`<div class="toolbar" style="justify-content:flex-start"><button class="action" id="rfEditBtn">EDIT FREQUENCIES</button><span class="rf-hint">WRITES THE PERSISTENT DEVICE TABLE. THE DEVICE REBOOTS.</span></div>`;
    }
    out+=panel(`CONNECTED DEVICE BB FREQUENCY TABLE — ${bands.port||ident()?.port||''}`,bar+`<div class="band-grid">${bandCards}</div>`);
    if(state.rfStage==='confirm') out+=rfConfirmPanel();
    if(state.rfStage==='writing') out+=rfProgressPanel();
    if(state.rfError) out+=rfErrorPanel();
    if(state.rfWrite) out+=rfResultPanel();
    // The panel describes a specific read. A write invalidates it, so it says so
    // rather than showing pre-write values beside a write result or a failure.
    let meta=kv('Table status',state.rfStale?'STALE — PRE-WRITE READ, NOT REFRESHED':'CURRENT',false)
      +kv('Source',bands.source||'Caddx PC Tool serial GET_BB_FREQ',false)+kv('Command','120 / GET_BB_FREQ')
      +kv('Request sequence',bands.protocol?.request_seq??'—')+kv('Response sequence',bands.protocol?.response_seq??'—')
      +kv('Payload length',bands.protocol?.payload_length??'—')
      +kv('Vendor is_defalut',`${t.is_defalut??'—'} — DEVICE-OWNED, CLEARED TO 0 BY ANY WRITE`,false);
    if(state.rfStale) meta+=notice('THESE ARE THE VALUES READ BEFORE THE LAST WRITE. The post-write reread did not complete, so payload length and is_defalut below are not the current device state. Reconnect and reread before trusting them.','warn');
    meta+=noticeDetail('PAYLOAD LENGTH AND MD5 ARE NOT COMPARABLE ACROSS A WRITE — the device re-serializes this file without indentation. Verification compares parsed content in key order instead.');
    out+=panel(state.rfStale?'TABLE METADATA — STALE':'TABLE METADATA',meta);
  } else if(bands.state==='unsupported_by_device_firmware' || bands.error_code==='GET_BB_FREQ_UNSUPPORTED'){
    out+=notice('GET_BB_FREQ IS NOT IMPLEMENTED BY THIS DEVICE FIRMWARE. The serial connection and device identity are valid; the firmware itself returned the Caddx vendor “unknown cmd” response.','warn');
    out+=panel('PERSISTENT BB TABLE',kv('State','UNSUPPORTED BY DEVICE FIRMWARE')+kv('Command','120 / GET_BB_FREQ')+kv('Firmware',ident()?.firmware||'—')+kv('RF board',ident()?.rf_board_name||'—'));
  } else if(ident()?.device_name){
    out+=notice(`PERSISTENT BB TABLE READ FAILED — ${safeErr(bands.message||bands.error||bands.error_code||'NO USABLE RESPONSE')}`,'error');
  } else {
    out+=notice('CONNECT AND IDENTIFY AN ASCENT DEVICE FIRST.','error');
  }
  // Host-local, so it is offered whether or not this firmware answers command 120.
  out+=vendorRfPanel();
  out+=rfPlansPanel();
  out+='';
  out+=`<div class="metric-grid"><div class="metric"><label>SERIAL CONFIG</label><strong class="${ident()?.device_name?'good':'muted'}">${ident()?.device_name?'CONNECTED':'UNAVAILABLE'}</strong></div><div class="metric"><label>BB TABLE</label><strong class="${bands.available?'good':(bands.state==='unsupported_by_device_firmware'?'warnc':'muted')}">${bands.available?'LOADED':(bands.state==='unsupported_by_device_firmware'?'UNSUPPORTED':'UNAVAILABLE')}</strong></div><div class="metric"><label>GROUND LINK</label><strong class="${state.status?'good':'muted'}">${state.status?'RESPONDING':'UNAVAILABLE'}</strong></div><div class="metric"><label>CONTROL UDP</label><strong class="${live?.available?'good':'muted'}">${live?.available?'RESPONDING':'UNAVAILABLE'}</strong></div></div>`;
  const raw=['frequency','wireless_status','power_index'].map(k=>{const x=q[k]||{};return `<tr><td>${esc(k.toUpperCase())}</td><td><code>${esc(x.command!==undefined?hx(x.command):'—')}</code></td><td>${x.ok?'<span class="good">VALID FRAME</span>':'<span class="muted">UNAVAILABLE</span>'}</td><td><code>${esc(x.payload_hex||humanError(x.error)||'—')}</code></td></tr>`}).join('');
  out+=panel('LIVE RF STATE — GROUND CONFIGURATION UDP',`<table><thead><tr><th>QUERY</th><th>CMD</th><th>STATE</th><th>RESPONSE</th></tr></thead><tbody>${raw}</tbody></table>`);
  $('#content').innerHTML=out;
  bindRfEditor();
  bindVendorRf();
  bindPlans();
  '';
}

function vendorRfClock(){ return globalThis.performance?.now?.()??Date.now(); }

function vendorRfIdentity(){
  return JSON.stringify([state.activeConnection?.connected===true,state.connections?.active_candidate_id??null,state.activeConnection?.candidate?.container_id??null,
    state.activeConnection?.network_binding?.source_ip??null,state.activeConnection?.network_binding?.ifindex??null,
    ident()?.device_name??null,ident()?.firmware??null,ident()?.serial_number??null]);
}

function vendorRfMetadata(){ return state.vendorRfMetaIdentity===vendorRfIdentity()?state.vendorRfMeta:null; }

function vendorRfPanel(){
  return '<div id="vendorRfProjection">'+AscentRfDiagnostics.render(vendorRfMetadata(),state.vendorRfReading,vendorRfIdentity(),vendorRfClock(),{panel,kv,esc})+'</div>';
}

function bindVendorRf(){
  $('#rfDiagnosticRead')?.addEventListener('click',async()=>{
    if(state.vendorRfBusy)return;
    const requested=vendorRfIdentity();
    state.vendorRfBusy=true;$('#rfDiagnosticRead').disabled=true;
    try{
      const reading=await AscentRfDiagnostics.readReading(fetchJson,vendorRfIdentity,()=>vendorRfClock());
      if(reading)state.vendorRfReading=reading;
    }catch(e){if(requested===vendorRfIdentity())state.vendorRfReading={identity:requested,received:vendorRfClock(),doc:{state:'unavailable',error:humanError(e)}};}
    finally{state.vendorRfBusy=false;if(state.view==='rf')render();}
  });
}

function refreshVendorRfProjection(){
  if(state.view!=='rf'||!state.vendorRfReading)return;
  const el=$('#vendorRfProjection');if(!el)return;
  el.innerHTML=AscentRfDiagnostics.render(vendorRfMetadata(),state.vendorRfReading,vendorRfIdentity(),vendorRfClock(),{panel,kv,esc});
  bindVendorRf();if(state.vendorRfBusy)$('#rfDiagnosticRead').disabled=true;
}

function rfLiveBands(){
  const t=state.rfBands?.data||{};
  return Object.keys(t).filter(k=>Array.isArray(t[k])&&/^band/i.test(k));
}

function rfEditStart(){
  const t=state.rfBands?.data||{}; const bands={};
  rfLiveBands().forEach(k=>{bands[k]=t[k].slice()});
  state.rfEdit={bands}; state.rfStage='edit';
  state.rfPreview=null; state.rfWrite=null; state.rfError=null; state.rfProgress=null;
  render();
}

function rfEditCancel(){
  state.rfEdit=null; state.rfStage=null; state.rfPreview=null; state.rfError=null;
  render();
}

function rfEditedBands(){
  const t=state.rfBands?.data||{}; const out={};
  const b=state.rfEdit?.bands||{};
  Object.keys(b).forEach(k=>{
    const before=t[k]||[];
    if(before.length!==b[k].length||b[k].some((v,i)=>v!==before[i])) out[k]=b[k];
  });
  return out;
}

function bindRfEditor(){
  $('#rfEditBtn')?.addEventListener('click',rfEditStart);
  $('#rfCancel')?.addEventListener('click',rfEditCancel);
  $('#rfConfirmCancel')?.addEventListener('click',rfEditCancel);
  $('#rfBack')?.addEventListener('click',()=>{state.rfStage='edit';state.rfPreview=null;state.rfError=null;render()});
  $('#rfReview')?.addEventListener('click',rfReview);
  $('#rfApply')?.addEventListener('click',rfApply);
  $('#rfDone')?.addEventListener('click',async()=>{
    state.rfEdit=null;state.rfStage=null;state.rfPreview=null;state.rfWrite=null;state.rfError=null;
    await refresh();
  });
  $$('.freq-input').forEach(el=>{
    el.addEventListener('change',()=>{
      const k=el.dataset.band, i=Number(el.dataset.idx);
      const n=Number(String(el.value).trim());
      if(!Number.isFinite(n)||!Number.isInteger(n)){ el.value=state.rfEdit.bands[k][i]; return; }
      state.rfEdit.bands[k][i]=n;
      const small=el.parentElement.querySelector('small');
      if(small) small.textContent=fmtMHz(n);
      const live=state.rfBands?.data?.[k]||[];
      el.parentElement.classList.toggle('freq-changed',live[i]!==n);
    });
  });
}

async function rfPost(url,body){
  const r=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},
                          body:JSON.stringify(body),cache:'no-store'});
  let d={}; try{d=await r.json()}catch{}
  return {ok:r.ok,status:r.status,data:d};
}

async function rfReview(){
  const edited=rfEditedBands();
  state.rfError=null;
  if(!Object.keys(edited).length){ state.rfError={error:'NO_CHANGES',message:'No frequency values were changed.'}; render(); return; }
  const btn=$('#rfReview'); if(btn){btn.disabled=true;btn.textContent='VALIDATING…'}
  const {ok,data}=await rfPost('/api/rf-bands/write-preview',{table:edited});
  if(!ok||!data.ok){ state.rfError=data||{error:'PREVIEW_FAILED'}; if(btn){btn.disabled=false;btn.textContent='REVIEW CHANGES…'} render(); return; }
  state.rfPreview=data; state.rfStage='confirm'; render();
}

function rfConfirmPanel(){
  const pv=state.rfPreview||{};
  const rows=(pv.changes||[]).flatMap(c=>c.changes.map(x=>
    `<tr><td><code>${esc(c.band)}</code></td><td>${x.is_band_default?'<code>DEF</code>':esc(x.channel)}</td><td><code>${esc(x.before)}</code></td><td><code>${esc(x.after)}</code></td><td>${esc(fmtMHz(x.before))} → ${esc(fmtMHz(x.after))}</td></tr>`)).join('');
  const el=pv.eligibility||{};
  const rc=pv.reconnect||{};
  let body=`<table><thead><tr><th>BAND</th><th>CHANNEL</th><th>FROM kHz</th><th>TO kHz</th><th>CHANGE</th></tr></thead><tbody>${rows}</tbody></table>`;
  body+=kv('Total value changes',pv.change_count??'—')
      +kv('Bands touched',(pv.changes||[]).map(c=>c.band).join(', ')||'—')
      +kv('Key order preserved',pv.key_order_preserved?'YES':'NO')
      +kv('Non-band fields carried through',(pv.preserved_keys||[]).join(', ')||'—')
      +kv('Live table MD5 (must still match at write)',pv.expected_current_md5||'—')
      +kv('Proposed file MD5',pv.proposed_md5||'—')
      +kv('Proposed file length',pv.proposed_length??'—')
      +kv('Write eligibility',el.eligible?'QUALIFIED':`REFUSED — ${(el.reasons||[]).join(', ')||'UNKNOWN'}`);
  const dof=(pv.device_owned_fields||[]).map(f=>`${f.key} ${f.current} → ${f.device_will_set}`).join(', ');
  if(dof) body+=kv('Device-owned fields (device rewrites these itself)',dof,false);
  body+=notice(`THIS WRITES /factory/fpv_bb_freq.json AND REBOOTS THE DEVICE. A timestamped backup of the current table is saved first. Reconnect budget is ${rc.settle_s??11} s settle + ${rc.poll_budget_s??110} s wait. Do not disconnect the device during the write.`,'warn');
  const gate=el.eligible?`<button class="action" id="rfApply">WRITE ${pv.change_count??0} CHANGE${(pv.change_count===1)?'':'S'} TO DEVICE</button>`:`<button class="action" disabled>WRITE REFUSED — NOT QUALIFIED</button>`;
  body+=`<div class="toolbar" style="justify-content:flex-start">${gate}<button class="secondary" id="rfBack">BACK TO EDITOR</button><button class="secondary" id="rfConfirmCancel">DISCARD CHANGES</button></div>`;
  return panel('CONFIRM PERSISTENT RF TABLE WRITE',body);
}

async function rfApply(){
  const pv=state.rfPreview||{};
  const edited=rfEditedBands();
  state.rfStage='writing'; state.rfError=null;
  state.rfProgress={phase:'starting'};
  state.rfStale=true;          // the live read is invalidated the moment we commit
  render();
  const poll=setInterval(async()=>{
    const st=await fetchJson('/api/operation-state',true);
    if(st&&st.progress){ state.rfProgress=st.progress; if(state.rfStage==='writing') render(); }
  },1500);
  try{
    const {ok,data}=await rfPost('/api/rf-bands/write',
      {apply:true,expected_current_md5:pv.expected_current_md5,table:edited});
    if(!ok||!data.ok){ state.rfError=data||{error:'RF_WRITE_FAILED'}; state.rfStage='confirm'; }
    else { state.rfWrite=data; state.rfStage='done'; state.rfEdit=null; }
  } catch(e){
    state.rfError={error:'RF_WRITE_TRANSPORT_FAILED',message:safeErr(e.message||e),
                   evidence:{write_may_have_applied:true}};
    state.rfStage='confirm';
  } finally {
    clearInterval(poll); state.rfProgress=null;
    // Reread on failure too. A failed write may still have applied, so leaving the
    // pre-write table on screen next to the error is the worst thing to show.
    try{ await refreshRfOnly() }catch{}
    render();
  }
}

function applyRfBands(fresh){
  state.rfBands=fresh;
  state.rfStale=!(fresh&&fresh.available&&fresh.state==='ok'&&fresh.integrity?.verified===true);
}

async function refreshRfOnly(){
  applyRfBands(await fetchJson('/api/rf-bands',true));
  try{const cs=await fetchJson('/api/connection-state',true); if(cs?.active?.serial_identity){state.activeConnection={connected:true,...cs.active}; updateHeader();}}catch{}
}

const PLAN_STATE_LABEL={proven:'PROVEN ON THIS HARDWARE',not_established:'NOT ESTABLISHED',
                        incompatible:'INCOMPATIBLE WITH THIS UNIT'};

const PLAN_STATE_CLASS={proven:'good',not_established:'warnc',incompatible:'bad'};

async function reloadPlans(){
  state.rfPlans=await fetchJson('/api/rf-band-plans',true);
  if(state.rfPlans&&state.rfPlans.error) state.rfPlans=null;
}

function planFormPanelBody(){
  const f=state.planForm||{};
  if(f.mode==='save'){
    const src=f.source==='edited'?'THE VALUES CURRENTLY IN THE EDITOR':'THE TABLE READ FROM THIS DEVICE';
    return `<div class="kv"><span>Saving</span><span class="kv-control">${esc(src)}</span></div>`
      +kvControl('Plan name',`<input class="text-input" id="planName" type="text" maxlength="64" value="${esc(f.name||'')}" placeholder="e.g. Range day">`)
      +kvControl('Note (optional)',`<input class="text-input" id="planNote" type="text" maxlength="280" value="${esc(f.note||'')}">`)
      +`<div class="toolbar" style="justify-content:flex-start"><button class="action" id="planSave">SAVE PLAN</button><button class="secondary" id="planCancel">CANCEL</button></div>`;
  }
  if(f.mode==='import'){
    return `<div class="kv"><span>Expected columns</span><span class="kv-control"><code>${esc((state.rfPlans?.limits?.csv_columns||[]).join(', '))}</code></span></div>`
      +kvControl('Plan name',`<input class="text-input" id="planName" type="text" maxlength="64" value="${esc(f.name||'')}" placeholder="leave blank to use the name in the file">`)
      +kvControl('CSV',`<textarea class="text-input" id="planCsv" rows="8" spellcheck="false">${esc(f.csv||'')}</textarea>`)
      +`<div class="toolbar" style="justify-content:flex-start"><button class="action" id="planImport">IMPORT</button><button class="secondary" id="planCancel">CANCEL</button><span class="rf-hint">EVERY ROW IS CHECKED. NOTHING IS ROUNDED, REORDERED OR FILLED IN.</span></div>`;
  }
  if(f.mode==='export'){
    return `<div class="kv"><span>Plan</span><span class="kv-control">${esc(f.name||'')}</span></div>`
      +kvControl('CSV',`<textarea class="text-input" id="planCsv" rows="8" spellcheck="false" readonly>${esc(f.csv||'')}</textarea>`)
      +`<div class="toolbar" style="justify-content:flex-start"><button class="action" id="planCopy">COPY TO CLIPBOARD</button><button class="secondary" id="planCancel">CLOSE</button></div>`;
  }
  return '';
}

function planErrorRows(){
  const e=state.planError; if(!e) return '';
  const rows=(e.evidence?.errors)||[];
  const gaps=(e.evidence?.gaps)||[];
  let out=notice(`PLAN REJECTED — ${safeErr(e.message||e.error||'UNKNOWN')}`,'error');
  if(rows.length){
    out+=`<table><thead><tr><th>LINE</th><th>REASON</th><th>DETAIL</th></tr></thead><tbody>`
      +rows.map(r=>`<tr><td>${esc(r.line)}</td><td><code>${esc(r.code)}</code></td><td>${esc(r.detail)}</td></tr>`).join('')
      +`</tbody></table>`;
    if(e.evidence.error_count>rows.length) out+=notice(`${e.evidence.error_count} ROWS WERE REJECTED; THE FIRST ${rows.length} ARE LISTED.`,'warn');
  }
  if(gaps.length){
    out+=`<table><thead><tr><th>BAND</th><th>WHAT IS MISSING</th></tr></thead><tbody>`
      +gaps.map(g=>{
        const what=g.missing_default?'no DEFAULT row'
          :g.default_without_channels?'a DEFAULT row with no channels'
          :`channel position(s) ${(g.missing_positions||[]).join(', ')}`;
        return `<tr><td>${esc(g.band)}</td><td>${esc(what)}</td></tr>`;
      }).join('')+`</tbody></table>`;
  }
  return out;
}

function rfPlansPanel(){
  const doc=state.rfPlans; const rows=doc?.plans||[];
  const canCapture=!!(doc?.target?.live_table_verified);
  const editing=state.rfStage==='edit';
  let bar=`<div class="toolbar" style="justify-content:flex-start">`;
  if(editing){
    bar+=`<button class="action" id="planFromEdit">SAVE EDITED VALUES AS A PLAN</button>`;
  } else {
    bar+=`<button class="action" id="planFromDevice"${canCapture?'':' disabled'}>SAVE THIS DEVICE TABLE AS A PLAN</button>`;
  }
  bar+=`<button class="secondary" id="planImportOpen">IMPORT FROM CSV…</button></div>`;

  let body=bar;
  if(!canCapture&&!editing) body+=notice('SAVING A PLAN FROM THE DEVICE NEEDS A VERIFIED TABLE READ. REFRESH THE DEVICE TABLE FIRST.','warn');
  body+=planErrorRows();
  if(state.planForm) body+=planFormPanelBody();

  if(rows.length){
    body+=`<table><thead><tr><th>PLAN</th><th>BANDS</th><th>CHANNELS</th><th>COMPATIBILITY</th><th>ACTION</th></tr></thead><tbody>`
      +rows.map(p=>{
        const a=p.assessment||{}; const cls=PLAN_STATE_CLASS[a.state]||'muted';
        const label=PLAN_STATE_LABEL[a.state]||'UNKNOWN';
        const detail=(a.findings||[]).map(f=>f.detail).join(' ');
        const loadable=a.state!=='incompatible'&&!!doc?.target?.live_table_verified;
        return `<tr><td><span class="row-name">${esc(p.name)}</span>${p.note?`<br><small class="muted">${esc(p.note)}</small>`:''}</td>`
          +`<td><code>${esc((p.band_names||[]).join(' '))}</code></td>`
          +`<td>${esc(p.channel_count)}</td>`
          +`<td><span class="${cls}">${esc(label)}</span>${detail?`<br><small class="muted">${esc(detail)}</small>`:''}</td>`
          +`<td><div class="kv-control"><button class="secondary" data-plan-load="${esc(p.name)}"${loadable?'':' disabled'}>LOAD INTO EDITOR</button>`
          +`<button class="secondary" data-plan-export="${esc(p.name)}">EXPORT CSV</button>`
          +`<button class="secondary" data-plan-delete="${esc(p.name)}">DELETE</button></div></td></tr>`;
      }).join('')+`</tbody></table>`;
  } else {
    body+=notice('NO PLANS ARE STORED ON THIS COMPUTER YET.');
  }
  const lim=doc?.limits||{};
  body+=kv('Stored on',"THIS COMPUTER ONLY — PLANS ARE NEVER SENT TO A DEVICE BY THEMSELVES",false)
    +kv('Applying a plan',"LOAD INTO EDITOR, REVIEW, THEN THE USUAL WRITE — SAME CHECKS, SAME REBOOT",false)
    +kv('Per-band maximum',`${lim.single_band_max_channels??'—'} CHANNELS`,false)
    +kv('Total maximum',`${lim.total_max_channels??'—'} CHANNELS ACROSS ALL BANDS`,false);
  body+=notice('WHETHER A FREQUENCY IS LEGAL TO TRANSMIT IS NOT ASSESSED HERE. THIS APPLICATION CANNOT DETERMINE IT. “NOT ESTABLISHED” MEANS UNMEASURED ON THIS HARDWARE — IT IS NEITHER APPROVAL NOR REFUSAL.','warn');
  return panel('BAND PLANS — LOCAL',body);
}

async function planPost(action,body){
  const {ok,data}=await rfPost('/api/rf-band-plans/'+action,body);
  if(!ok||!data.ok){ state.planError=data||{error:'PLAN_OPERATION_FAILED'}; return null; }
  state.planError=null;
  if(data.store) state.rfPlans=data.store;
  return data;
}

function planLoadIntoEditor(name){
  const p=(state.rfPlans?.plans||[]).find(x=>x.name===name);
  const live=state.rfBands?.data||{};
  if(!p) return;
  const bands={};
  rfLiveBands().forEach(k=>{ bands[k]=Array.isArray(p.bands[k])?p.bands[k].slice():live[k].slice() });
  state.rfEdit={bands}; state.rfStage='edit';
  state.rfPreview=null; state.rfWrite=null; state.rfError=null; state.planForm=null; state.planError=null;
  render();
}

function bindPlans(){
  $('#planFromDevice')?.addEventListener('click',()=>{ state.planForm={mode:'save',source:'device',name:'',note:''}; state.planError=null; render(); });
  $('#planFromEdit')?.addEventListener('click',()=>{ state.planForm={mode:'save',source:'edited',name:'',note:''}; state.planError=null; render(); });
  $('#planImportOpen')?.addEventListener('click',()=>{ state.planForm={mode:'import',name:'',csv:''}; state.planError=null; render(); });
  $('#planCancel')?.addEventListener('click',()=>{ state.planForm=null; state.planError=null; render(); });
  ['planName','planNote','planCsv'].forEach(id=>{
    const el=$('#'+id); if(!el||!state.planForm) return;
    const field=id==='planName'?'name':id==='planNote'?'note':'csv';
    el.addEventListener('input',()=>{ state.planForm[field]=el.value; });
  });
  $('#planSave')?.addEventListener('click',async()=>{
    const f=state.planForm||{};
    // An edited-values save sends the whole edited set, not just the changed bands:
    // a plan describes a layout, so it must stand on its own rather than being a
    // difference against whatever table happened to be loaded when it was made.
    const bands=f.source==='edited'?state.rfEdit?.bands:undefined;
    const d=await planPost('save',{name:f.name,note:f.note,bands});
    if(d) state.planForm=null;
    render();
  });
  $('#planImport')?.addEventListener('click',async()=>{
    const f=state.planForm||{};
    const d=await planPost('import',{csv:f.csv,name:f.name||undefined,save:true});
    if(d) state.planForm=null;
    render();
  });
  $('#planCopy')?.addEventListener('click',()=>{
    const el=$('#planCsv'); if(!el) return;
    el.select(); try{ navigator.clipboard.writeText(el.value) }catch{}
  });
  $$('[data-plan-load]').forEach(b=>b.addEventListener('click',()=>planLoadIntoEditor(b.dataset.planLoad)));
  $$('[data-plan-export]').forEach(b=>b.addEventListener('click',async()=>{
    const d=await planPost('export',{name:b.dataset.planExport});
    state.planForm=d?{mode:'export',name:d.plan,csv:d.csv}:null;
    render();
  }));
  $$('[data-plan-delete]').forEach(b=>b.addEventListener('click',async()=>{
    await planPost('delete',{name:b.dataset.planDelete});
    render();
  }));
}

function rfProgressPanel(){
  const p=state.rfProgress||{};
  const phase={starting:'PREPARING',rebooting:'COMMIT SENT — DEVICE REBOOTING',
               settling:'WAITING OUT THE SETTLE DELAY',waiting:'WAITING FOR THE DEVICE TO RETURN',
               idle:'FINISHING'}[p.phase]||String(p.phase||'WORKING').toUpperCase();
  const settle=p.settle_s??11, budget=p.poll_budget_s??110, el=p.elapsed_s??0;
  let body=kv('Stage',phase)+kv('Settle delay',`${settle} s`)+kv('Reconnect budget',`${budget} s after settle`);
  if(p.phase==='waiting') body+=kv('Waited so far',`${el} s of ${budget} s`);
  if(p.last_error) body+=kv('Last probe result',safeErr(p.last_error));
  body+=notice('The device is expected to disappear and come back. This is normal and can take up to two minutes. Do not disconnect it.','warn');
  return panel('WRITE IN PROGRESS',body);
}

function rfErrorPanel(){
  const e=state.rfError||{}; const ev=e.evidence||{};
  let body=kv('Error code',e.error||e.error_code||'UNKNOWN')+kv('Stage',e.stage||'—')
          +kv('Message',safeErr(e.message||'—'));
  if(ev.write_may_have_applied!==undefined) body+=kv('Write may have applied',ev.write_may_have_applied?'YES — VERIFY THE DEVICE BEFORE RETRYING':'NO');
  if(ev.backup?.file) body+=kv('Pre-write backup',ev.backup.file);
  if(ev.reason) body+=kv('Mismatch reason',safeErr(ev.reason),false);
  if(ev.device_owned_fields) body+=kv('Device-owned fields',(ev.device_owned_fields||[]).map(f=>`${f.key} ${f.requested} → ${f.observed}`).join(', ')||'—',false);
  if(ev.reasons||ev.eligibility?.reasons) body+=kv('Qualification reasons',(ev.reasons||ev.eligibility?.reasons||[]).join(', '));
  if(ev.settle_s!==undefined) body+=kv('Budget used',`${ev.settle_s} s settle + ${ev.poll_budget_s} s wait`);
  body+=notice('The write was NOT reported as verified. Treat the device table as unknown until a fresh read succeeds.','error');
  return panel('RF WRITE FAILED',body);
}

function rfResultPanel(){
  const r=state.rfWrite||{};
  if(r.changed===false){
    return panel('NO WRITE PERFORMED',kv('Result','REQUESTED TABLE ALREADY MATCHES THE DEVICE')
      +`<div class="toolbar" style="justify-content:flex-start"><button class="secondary" id="rfDone">CLOSE</button></div>`);
  }
  const rb=r.readback||{};
  let body=kv('Result','VERIFIED')+kv('Readback port',rb.port||'—')
    +kv('Readback MD5 verified',(rb.integrity||{}).verified===true?'YES':'NO')
    +kv('Semantic match (order-aware, device-owned fields excluded)',rb.semantic_match?'YES':'NO')
    +kv('Device-owned fields',(rb.device_owned_fields||[]).map(f=>`${f.key} ${f.requested} → ${f.observed}${f.as_documented?'':' (UNDOCUMENTED)'}`).join(', ')||'—',false)
    +kv('Pre-write backup',r.backup?.file||'—')
    +kv('Uploaded file MD5',r.transaction?.payload_md5||'—')
    +kv('Uploaded file length',r.transaction?.payload_length??'—')
    +kv('Commands',(r.transaction?.stages||[]).map(s=>s.command).join(' → ')||'—');
  body+=`<div class="toolbar" style="justify-content:flex-start"><button class="secondary" id="rfDone">CLOSE</button></div>`;
  return panel('RF WRITE VERIFIED',body);
}

function cfgTargetLabel(target){
  const i=target?.identity||{};
  return [i.device_name||'No identified device',i.serial_number?`Serial ${i.serial_number}`:'Serial not reported',target?.port||''].filter(Boolean).join(' · ');
}

function cfgContextKey(){
  const a=state.activeConnection||{},i=a.serial_identity||{},c=a.candidate||{};
  return JSON.stringify([a.connected,c.serial_container_id,c.serial_com,i.device_name,i.serial_number,i.hardware,i.firmware]);
}

function cfgState(kind){
  state.cfg=state.cfg||{};
  const context=cfgContextKey();
  if(!state.cfg[kind]||state.cfg[kind].context!==context)
    state.cfg[kind]={context,stage:'view',draft:null,preview:null,error:null,result:null,busy:false};
  return state.cfg[kind];
}

function cfgDoc(kind){
  const d=state.cfgDocs?.[kind];
  return d&&(!d._context||d._context===cfgContextKey())?d:null;
}

function cfgDraft(kind){
  const c=cfgState(kind);
  if(!c.draft) c.draft=JSON.parse(JSON.stringify(cfgDoc(kind)?.document||{}));
  return c.draft;
}

async function reloadDeviceConfig(kind){
  const c=cfgState(kind),context=c.context,sequence=c.loadSequence=(c.loadSequence||0)+1;
  const d=await fetchJson(`/api/device-config/${kind}`,true);
  if(cfgState(kind)!==c||sequence!==c.loadSequence) return;
  if(!d?.document){c.error=d?.error||'Local configuration could not be loaded.';return;}
  state.cfgDocs=state.cfgDocs||{}; d._context=context; state.cfgDocs[kind]=d;
}

function cfgProvenancePanel(kind){
  const d=cfgDoc(kind); if(!d) return '';
  const lw=d.last_write, target=d.target?.identity||{};
  let body=kv('Configuration',d.source==='vendor_template'?'Vendor template — saved on this PC':'Saved on this PC',false)
    +kv('Local JSON last updated',d.updated_at||'Not recorded — vendor template',false)
    +kv('Selected target',cfgTargetLabel(d.target),false)
    +kv('Draft scope',d.profile_is_default?'Shared local draft — no aircraft BB ID available':`Local profile ${d.bb_id}`,false)
    +kv('Last upload',lw?lw.at:'Not uploaded from this saved record',false);
  if(lw) body+=kv('Upload record target',lw.target?cfgTargetLabel(lw.target):lw.bb_id||'Not recorded',false)+kv('Saved changes',d.dirty?'Differ from the last acknowledged upload':'Match the last acknowledged upload',false);
  body+=notice('These are local settings, not a device reading. Upload does not verify camera application.');
  if(advancedOn()) body+=kv('Remote destination',d.remote_path)+kv('Local store',d.store_file)
    +kv('Recorded upload target',lw?.target?.identity?.device_name||lw?.bb_id||'Not recorded',false);
  return panel('CONFIGURATION SOURCE',body);
}

function cfgWarnings(list){
  if(!list||!list.length) return '';
  if(!advancedOn()) return panel('CONFIGURATION NOTES',list.map(w=>notice(w.message,'warn')).join(''));
  return panel('VALIDATION NOTES',`<table><thead><tr><th>CODE</th><th>NOTE</th></tr></thead><tbody>`
    +list.map(w=>`<tr><td><code>${esc(w.code)}</code></td><td>${esc(w.message)}</td></tr>`).join('')
    +`</tbody></table>`);
}

function cfgEligibilityPanel(kind){
  const e=cfgDoc(kind)?.eligibility; if(!e) return '';
  const reasons={NO_ACTIVE_QUALIFIED_DEVICE:'Connect the intended air unit.',RAW_IDENTITY_NOT_PROVEN:'Read the selected unit identity first.',
    SERIAL_TRANSPORT_MISSING:'A USB serial connection is required.',PHYSICAL_CONTAINER_ID_MISSING:'USB device correlation is unavailable.',
    DEVICE_ROLE_UNKNOWN:'The device role is unknown.',DEVICE_ROLE_NOT_APPLICABLE:'This configuration does not apply to the selected device.',
    CAMERA_PROFILE_UNKNOWN:'The reported identity does not establish a camera profile.',CAMERA_PROFILE_NOT_APPLICABLE:'The reported camera profile does not use this configuration.'};
  let body=kv('Device upload',e.eligible?'Available for review':'Unavailable',false);
  if(!e.eligible) body+=notice((e.reasons||[]).map(r=>reasons[r]||r).join(' '),'warn');
  body+=notice('Support and camera effect unverified. Upload reboots the unit.');
  if(advancedOn()) body+=kv('Eligibility evidence',(e.reasons||[]).join(', ')||'Reported role and subtype',false)
    +kv('Lane',e.lane||'—',false)+kv('Commit opcode','NONE — the file transfer is the commit',false);
  return panel('UPLOAD',body);
}

function cfgToolbar(kind){
  const c=cfgState(kind); const d=cfgDoc(kind);
  const elig=d?.eligibility?.eligible===true;
  if(c.stage==='view'){
    return `<div class="toolbar" style="justify-content:flex-start;flex-wrap:wrap">`
      +`<button class="action" id="cfgEdit_${kind}">EDIT</button>`
      +`<button class="secondary" id="cfgReset_${kind}">RESET TO VENDOR TEMPLATE</button>`
      +`</div>`;
  }
  if(c.stage==='edit'){
    return `<div class="toolbar" style="justify-content:flex-start;flex-wrap:wrap">`
      +`<button class="secondary" id="cfgSave_${kind}">SAVE LOCALLY</button>`
      +`<button class="action" id="cfgReview_${kind}"${elig?'':' disabled'}>REVIEW AND SEND…</button>`
      +`<button class="secondary" id="cfgCancel_${kind}">CANCEL</button>`
      +(elig?'':`<span class="muted">SEND is unavailable: see the upload reason above</span>`)
      +`</div>`;
  }
  return '';
}

function cfgConfirmPanel(kind){
  const c=cfgState(kind); const pv=c.preview; if(!pv) return '';
  const rows=(pv.diff||[]).map(r=>`<tr><td><code>${esc(r.field)}</code></td><td><code>${esc(String(r.from))}</code></td><td><code>${esc(String(r.to))}</code></td></tr>`).join('');
  let body=(pv.diff||[]).length
    ? `<table><thead><tr><th>FIELD</th><th>SAVED ON THIS PC</th><th>PROPOSED</th></tr></thead><tbody>${rows}</tbody></table>`
    : '<div class="empty">Saved PC draft unchanged — upload still rewrites the file and reboots the air unit</div>';
  body+=kv('Remote destination',pv.remote_path)
    +kv('Bytes on the wire',pv.payload_length)
    +kv('Payload MD5',pv.payload_md5)
    +(advancedOn()?kv('Commands',(pv.lane?.commands||[]).join(' / '))+kv('Commit opcode','NONE',false):'');
  body+=kv('Target',cfgTargetLabel(pv.target),false);
  for(const w of pv.warnings||[]) body+=notice(w.message,'warn');
  body+=notice('Upload reboots the unit. Acceptance and reconnect do not verify application; no vendor readback is available.','warn');
  body+=`<div class="toolbar" style="justify-content:flex-start;flex-wrap:wrap">`
    +`<button class="action" id="cfgApply_${kind}"${c.busy?' disabled':''}>${c.busy?'SENDING…':'SEND TO DEVICE'}</button>`
    +`<button class="secondary" id="cfgBack_${kind}"${c.busy?' disabled':''}>BACK</button></div>`;
  return panel('CONFIRM — WHAT WILL BE SENT',body);
}

function cfgResultPanel(kind){
  const c=cfgState(kind); const r=c.result; if(!r) return '';
  const v=r.verification||{};
  let body=kv('Result','TRANSFER ACKNOWLEDGED',false)
    +kv('Remote path',r.remote_path)
    +kv('Bytes sent',r.transfer?.payload_length)
    +kv('Payload MD5',r.transfer?.payload_md5)
    +kv('Reconnected on',r.reconnect?.port||'—')
    +kv('Verified by readback',v.readback_performed?'YES':'NO — NOT POSSIBLE ON THIS LANE',false)
    +kv('Evidence',v.basis||'—',false);
  body+=notice(v.reason||'','warn');
  body+=`<div class="toolbar" style="justify-content:flex-start"><button class="secondary" id="cfgDone_${kind}">DONE</button></div>`;
  return panel('SEND RESULT',body);
}

function renderHub(){
  const d=cfgDoc('hub'); const c=cfgState('hub');
  let out=pageHead('MANAGE HUB','Camera inputs and startup/reset selection');
  if(!d){ out+=notice(c.error?humanError(c.error):'LOADING HUB CONFIGURATION…',c.error?'error':''); $('#content').innerHTML=out; return; }
  out+=notice('Z40 uses CAM3. Startup input selects the power-on source; reset input selects the reset source.');
  out+=`<details><summary>Hub setup order</summary><p>Hub guide: upload RC, wait for reboot, then upload Hub and wait again. RC channels are on MANAGE RC.</p></details>`;
  out+=cfgProvenancePanel('hub');
  out+=cfgEligibilityPanel('hub');
  if(c.error) out+=notice(humanError(c.error),'error');
  if(c.uploadUncertain) out+=notice('Upload incomplete; the device may have changed. Application is unverified. Review before retrying.','warn');
  if(c.stage==='confirm'||c.busy){ out+=cfgConfirmPanel('hub'); $('#content').innerHTML=out; bindCfg('hub'); return; }
  if(c.stage==='done'){ out+=cfgResultPanel('hub'); $('#content').innerHTML=out; bindCfg('hub'); return; }

  const editing=c.stage==='edit';
  const doc=editing?cfgDraft('hub'):d.document;
  const NODE_LABEL={node0:'CAM1',node1:'CAM2',node2:'CAM3',node3:'HDMI'};
  const rows=['node0','node1','node2','node3'].map(k=>{
    const n=doc[k]||{};
    const nameCell=editing
      ? `<input class="text-input" data-cfg="hub" data-node="${k}" data-field="dev_name" list="hubDevices_${k}" value="${esc(n.dev_name)}" style="max-width:140px">`
      : `<code>${esc(n.dev_name)}</code>`;
    const resCell=editing
      ? `<input class="text-input" data-cfg="hub" data-node="${k}" data-field="res_info" value="${esc(n.res_info)}" style="max-width:160px">`
      : `<code>${esc(n.res_info)}</code>`;
    const sel=editing
      ? `<input type="radio" name="hubSelected" data-cfg="hub" data-node="${k}" data-field="selected"${n.selected===1?' checked':''}>`
      : (n.selected===1?'<span class="good">YES</span>':'NO');
    const pri=editing
      ? `<input type="radio" name="hubPriority" data-cfg="hub" data-node="${k}" data-field="high_priority"${n.high_priority===1?' checked':''}>`
      : (n.high_priority===1?'<span class="good">YES</span>':'NO');
    return `<tr>${advancedOn()?`<td><code>${esc(k)}</code></td>`:''}<td class="row-name">${esc(NODE_LABEL[k])}</td><td>${nameCell}${editing?`<datalist id="hubDevices_${k}">${(k==='node2'?['none','Z40']:k==='node3'?['none','HDMI']:['none','GT_PRO','IR','Z8']).map(v=>`<option value="${v}"></option>`).join('')}</datalist>`:''}</td><td>${resCell}</td><td>${sel}</td><td>${pri}</td></tr>`;
  }).join('');
  out+=panel('CAMERA INPUTS',
    `<table><thead><tr>${advancedOn()?'<th>NODE</th>':''}<th>INPUT</th><th>DEVICE</th><th>RESOLUTION</th><th>STARTUP INPUT</th><th>RESET INPUT</th></tr></thead><tbody>${rows}</tbody></table>`
    +(editing
      ? `<div class="kv"><span>Flight controller</span><span><input class="text-input" data-cfg="hub" data-field="fly_ctrl" value="${esc(doc.fly_ctrl||'')}" style="max-width:200px"></span></div>`
      : kv('Flight controller',doc.fly_ctrl||'—',false))
    +cfgToolbar('hub'));
  out+=cfgWarnings(d.warnings);
  $('#content').innerHTML=out;
  bindCfg('hub');
}

function renderRc(){
  const d=cfgDoc('rc'); const c=cfgState('rc');
  let out=pageHead('MANAGE RC','Flight-controller MSP camera functions');
  if(!d){ out+=notice(c.error?humanError(c.error):'LOADING RC CONFIGURATION…',c.error?'error':''); $('#content').innerHTML=out; return; }
  out+=panel('CONTROL PATH',notice('FC → VTX over MSP → camera/Hub. FC DisplayPort slots and this uploaded RC file are separate control paths.')
    +`<details><summary>MSP paths and FC setup</summary><p>Betaflight MSP DisplayPort uses FC-side osd_rcchannels: four zero-based channel selections feed slots 0–3, with values −1000 to +1000. FC selection 7 means CH8. The Z40 guide assigns slot 0 to zoom and slot 1 to zoom reset. This editor does not change osd_rcchannels.</p><p>The uploaded RC file uses the vendor channel/range route, typically 1000–2000 values. Do not copy signed DisplayPort values into these fields. The traced INAV route needs zoom and zoom-reset channels and a zoom span of at least 500. Which route is active requires bench confirmation.</p><p>These are FC/MSP channels, not EdgeTX USB input numbers or the laptop’s 16 CRSF output slots. This editor does not configure the FC UART, radio or USB controller.</p></details>`);
  out+=cfgProvenancePanel('rc');
  out+=cfgEligibilityPanel('rc');
  if(c.error) out+=notice(humanError(c.error),'error');
  if(c.uploadUncertain) out+=notice('Upload incomplete; the device may have changed. Application is unverified. Review before retrying.','warn');
  if(c.stage==='confirm'||c.busy){ out+=cfgConfirmPanel('rc'); $('#content').innerHTML=out; bindCfg('rc'); return; }
  if(c.stage==='done'){ out+=cfgResultPanel('rc'); $('#content').innerHTML=out; bindCfg('rc'); return; }

  const editing=c.stage==='edit';
  const doc=editing?cfgDraft('rc'):d.document;
  // slot0..slot3 are the four functions RCModeCtrl drives, in this order.
  const SLOTS=[['slot0','ZOOM'],['slot1','ZOOM RESET'],['slot2','CAMERA CHANGE'],['slot3','CAMERA RESET']];
  const rows=SLOTS.map(([k,label])=>{
    const chan=doc[k]; const lo=doc[`${k}_min`]; const hi=doc[`${k}_max`];
    const off=Number(lo)>2100;
    const cell=(field,val)=>editing
      ? `<input class="freq-input" data-cfg="rc" data-field="${field}" value="${esc(val)}" inputmode="numeric" style="max-width:90px">`
      : `<code>${esc(val)}</code>`;
    return `<tr><td class="row-name">${esc(label)}</td>${advancedOn()?`<td><code>${esc(k)}</code></td>`:''}`
      +`<td>${off?'<span class="muted">DISABLED</span>':'<span class="good">ENABLED</span>'}</td>`
      +`<td>${editing?`<select class="text-input" data-cfg="rc" data-field="${k}">${[0,...Array.from({length:18},(_,i)=>i+1)].map(v=>`<option value="${v}"${v===(off?0:Number(chan))?' selected':''}>${v===0?(k==='slot0'?'Choose channel':'Disabled'):`CH${v}${v===18?' (extended)':''}`}</option>`).join('')}</select>`:off?'—':`CH${esc(chan)}`}</td>`
      +`<td>${off?'—':cell(`${k}_min`,lo)}</td><td>${off?'—':cell(`${k}_max`,hi)}</td></tr>`;
  }).join('');
  out+=panel('RC CHANNEL ASSIGNMENTS',
    `<table><thead><tr><th>FUNCTION</th>${advancedOn()?'<th>FILE FIELD</th>':''}<th>STATE</th><th>RC CHANNEL</th><th>LOW (µs)</th><th>HIGH (µs)</th></tr></thead><tbody>${rows}</tbody></table>`
    +notice('JSON: 1000–2000 µs, not signed OSD numbers. Binary MSP requires zoom and reset channels; reset low. DisplayPort slots 1/2 control zoom/reset separately.')
    +cfgToolbar('rc'));
  out+=cfgWarnings(d.warnings);
  $('#content').innerHTML=out;
  bindCfg('rc');
}

function cfgCollectEdits(kind){
  const draft=cfgDraft(kind);
  $$(`[data-cfg="${kind}"]`).forEach(el=>{
    const field=el.dataset.field; const node=el.dataset.node;
    if(el.type==='radio'){
      if(node) (draft[node]=draft[node]||{})[field]=el.checked?1:0;
      return;
    }
    let v=el.value;
    if(node){ draft[node]=draft[node]||{}; draft[node][field]=v; }
    else if(field==='fly_ctrl'){ draft[field]=v; }
    else { const n=Number(v); draft[field]=Number.isFinite(n)?Math.trunc(n):v; }
  });
  if(kind==='rc') for(const slot of ['slot1','slot2','slot3'])
    if(Number(draft[slot])===0){draft[`${slot}_min`]=9990;draft[`${slot}_max`]=9999;}
  return draft;
}

async function cfgPost(kind,action,body={}){
  if(!['hub','rc'].includes(kind)||!['save','reset','write-preview','write'].includes(action)) throw Error('Unknown configuration operation');
  const r=await fetch(`/api/device-config/${kind}/${action}`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  const d=await r.json();
  if(!r.ok||d.ok===false) throw Object.assign(Error(d.message||d.error||'Configuration request failed'),{code:d.code,evidence:d.evidence});
  return d;
}

function bindCfg(kind){
  const c=cfgState(kind), current=()=>cfgState(kind)===c;
  (kind==='rc'?$$('[data-cfg="rc"]'):[]).filter(el=>/^slot[0-3]$/.test(el.dataset.field||'')).forEach(el=>el.addEventListener('change',()=>{
    const draft=cfgCollectEdits('rc'),slot=el.dataset.field;
    if(Number(draft[slot])>0&&Number(draft[`${slot}_min`])>2100){draft[`${slot}_min`]=1000;draft[`${slot}_max`]=2000;}
    render();
  }));
  $(`#cfgEdit_${kind}`)?.addEventListener('click',()=>{c.stage='edit';c.draft=null;c.error=null;render()});
  $(`#cfgCancel_${kind}`)?.addEventListener('click',()=>{c.stage='view';c.draft=null;c.error=null;render()});
  $(`#cfgBack_${kind}`)?.addEventListener('click',()=>{c.stage='edit';c.error=null;render()});
  $(`#cfgDone_${kind}`)?.addEventListener('click',()=>{c.stage='view';c.draft=null;c.result=null;render()});
  $(`#cfgReset_${kind}`)?.addEventListener('click',async()=>{
    try{ await cfgPost(kind,'reset'); if(!current()) return; await reloadDeviceConfig(kind); c.stage='view';c.draft=null;c.error=null; }
    catch(e){ c.error=e } render();
  });
  $(`#cfgSave_${kind}`)?.addEventListener('click',async()=>{
    try{ const doc=cfgCollectEdits(kind); await cfgPost(kind,'save',{document:doc}); if(!current()) return;
         await reloadDeviceConfig(kind); c.stage='view'; c.draft=null; c.error=null; }
    catch(e){ c.error=e } render();
  });
  $(`#cfgReview_${kind}`)?.addEventListener('click',async()=>{
    try{ const doc=cfgCollectEdits(kind);
         const preview=await cfgPost(kind,'write-preview',{document:doc});
         if(!current()) return;
         c.preview=preview; c.stage='confirm'; c.error=null; }
    catch(e){ c.error=e } render();
  });
  $(`#cfgApply_${kind}`)?.addEventListener('click',async()=>{
    c.busy=true; c.error=null; c.uploadUncertain=false; render();
    try{ const result=await cfgPost(kind,'write',{apply:true,document:c.preview.merged,review_token:c.preview.review_token});
         if(!current()) return;
         c.result=result; await reloadDeviceConfig(kind); if(!current()) return; c.stage='done'; }
    catch(e){ if(!current()) return; c.error=e; c.stage='edit'; c.uploadUncertain=true; }
    if(!current()) return;
    c.busy=false; render();
  });
}

function deviceNicknameRow(bb, alias){
  if(!bb) return kv('Nickname',
    val('This unit has not reported a BB ID yet, so there is nothing to attach a '
        +'name to. It appears once the unit answers.','muted'), false);

  if(state.devNickEdit) return kvControl('Nickname',
    `<input id="devNickInput" class="text-input" style="max-width:220px" `
    +`value="${esc(state.devNickDraft??alias??'')}" placeholder="e.g. Gaston" maxlength="32">`
    +` <button class="action" id="devNickSave">SAVE</button>`
    +` <button class="secondary" id="devNickCancel">CANCEL</button>`
    +(state.devNickError?` <span class="bad">${esc(state.devNickError)}</span>`:''));

  return kvControl('Nickname',
    (alias?`<code>${esc(alias)}</code> `:`<span class="muted">NONE SET</span> `)
    +`<button class="secondary" id="devNickEdit">${alias?'RENAME':'NAME THIS UNIT'}</button>`);
}

function bindDeviceNickname(bb){
  const edit=$('#devNickEdit');
  if(edit) edit.onclick=()=>{ state.devNickEdit=true; state.devNickDraft=null; state.devNickError=null; render(); };
  const cancel=$('#devNickCancel');
  if(cancel) cancel.onclick=()=>{ state.devNickEdit=false; state.devNickError=null; render(); };
  const input=$('#devNickInput');
  if(input) input.addEventListener('input',()=>{ state.devNickDraft=input.value; });
  const save=$('#devNickSave');
  if(save) save.onclick=async()=>{
    const name=($('#devNickInput')?.value||'').trim();
    state.devNickDraft=name;
    // Names are unique across the store, so a collision is refused here rather than
    // silently reassigned -- the same rule the DEVICE NICKNAMES page enforces.
    const held=nicknameCollision(name,bb);
    if(name&&held){ state.devNickError=`Already used by ${held}`; render(); return; }
    try{
      const r=await fetch('/api/vtx-nicknames',{method:'POST',
        headers:{'Content-Type':'application/json'},
        body:JSON.stringify({bb_id:bb,nickname:name,identity:'receiver'})});
      const d=await r.json();
      if(!r.ok) throw Error(d.message||d.error||`${r.status}`);
      state.nicknames=await fetchJson('/api/vtx-nicknames',true);
      state.devNickEdit=false; state.devNickError=null;
    }catch(e){ state.devNickError=safeErr(e); }
    render();
  };
}

function receiverReadToken(){
  const i=ident()||{};
  return JSON.stringify([state.widgetCatalogEpoch||0,i.device_name??null,i.serial_number??null,i.hardware??null,i.firmware??null]);
}

function deviceHasGroundServices(){
  return !['air','camera_hub','gimbal'].includes(state.capabilities?.role);
}

// Ethernet observations have their own scope; they never qualify USB actions.
function maxEthernetTarget(){
  const t=state.activeConnection?.network_target;
  return t?.id==='network:max_eth'&&t.kind==='vrx'?t:null;
}
function maxEthernetState(){
  const key=maxEthernetTarget()?.connection_token||null;
  if(!state.maxEthernet||state.maxEthernet.key!==key)state.maxEthernet={key,doc:null,loading:false,error:null,busy:false,result:null};
  return state.maxEthernet;
}
function maxEthernetPanel(controls=false){
  const t=maxEthernetTarget(),s=maxEthernetState();if(!t)return '';
  if(s.key&&!s.doc&&!s.loading&&!s.error)reloadMaxEthernet();
  let body=`<div class="toolbar"><button class="secondary" id="maxEthRead"${s.loading||s.busy?' disabled':''}>${s.loading?'READING…':'READ ETHERNET STATUS'}</button></div>`;
  if(s.error)body+=notice(safeErr(s.error),'warn');
  const d=s.doc,r=d?.reads||{},v=r.status?.values||{};
  if(d){
    body+=kv('Last read',d.captured_at||'Not recorded')
      +kv('Link state',r.status?.ok?v.link:'Not available')
      +kv('Receiver BBID (network read)',r.status?.ok?v.local_bb_id:'Not available');
    if(v.rx_mcs_raw!=null)body+=kv('RX MCS (raw)',v.rx_mcs_raw);
    if(r.mcs?.ok)body+=kv('MCS report (raw)',r.mcs.values.mcs_encoded_raw)+kv('Throughput report (raw)',r.mcs.values.throughput_raw);
    if(r.power?.ok)body+=kv('Power report (raw)',r.power.values.power_raw);
    if(r.channels?.ok)body+=kv('Work channel IDs',(r.channels.values.channel_ids||[]).join(', ')||'None reported');
    if(r.rf_raw?.ok){const rf=r.rf_raw.values;body+=kv('Local SNR / AGC (raw)',`${rf.local_ground.snr_raw} / ${rf.local_ground.agc_a_raw}`);}
    body+=kv('RTSP server',d.rtsp?.responding?d.rtsp.status:'No response to the read')
      +kv('Product / firmware identity','Not read over this connection');
    if(advancedOn())for(const [name,read]of Object.entries(r)){if(!read.ok)body+=kv(name+' read',safeErr(read.error||'Not available'));}
    body+='<p class="muted">Network observations do not establish USB identity, aircraft membership or calibrated RF units. Video playback and receiver key effects are checked separately.</p>';
  }else if(s.loading)body+=notice('Reading the selected receiver.');
  if(controls){
    const available=!!d?.controls?.eligible&&!s.error&&!s.loading&&!s.busy;
    body+='<div id="maxEthKeyPad" tabindex="0" aria-label="Receiver menu controls"><div class="toolbar">'
      +[['UP','↑ UP'],['DOWN','↓ DOWN'],['LEFT','← LEFT'],['RIGHT','→ RIGHT'],['CONFIRM','OK'],['BACK','BACK'],['PAIRING','BIND']].map(([key,label])=>`<button class="secondary" data-maxethkey="${key}"${available?'':' disabled'}>${label}</button>`).join('')+'</div></div>'
      +'<p class="muted">Focus the menu controls to use arrow keys, Enter and Escape. BIND asks before starting pairing. Sending a request does not verify the receiver action.</p>';
  }
  if(s.result)body+=notice(safeErr(s.result.message||s.result.error||'Receiver outcome is unknown.'),s.result.ok?'':'warn');
  return panel('RECEIVER ETHERNET',body);
}
function paintMaxEthernet(){
  const target=$('#maxEthPanel');if(!target)return;
  target.innerHTML=maxEthernetPanel(state.mode==='live');bindMaxEthernet();
}
async function reloadMaxEthernet(){
  const s=maxEthernetState(),key=s.key;if(!key||s.loading||s.busy)return;
  s.loading=true;s.error=null;
  try{
    const d=await fetchJson('/api/network/max/status?connection_token='+encodeURIComponent(key),true,12000,'Ethernet status read timed out.');
    if(maxEthernetTarget()?.connection_token!==key)return;
    if(!d?.ok||d.connection_token!==key)throw Error(d?.message||'Ethernet read did not complete for this connection.');
    s.doc=d;
  }catch(e){if(maxEthernetTarget()?.connection_token===key)s.error=safeErr(e);}
  finally{if(maxEthernetTarget()?.connection_token===key){s.loading=false;paintMaxEthernet();}}
}
async function sendMaxEthernetKey(key){
  const s=maxEthernetState(),token=s.key;
  if(!token||s.busy||s.loading||s.error||!s.doc?.controls?.eligible)return;
  if(key==='PAIRING'&&!confirm('Start pairing on the selected receiver? This can interrupt the existing video link.'))return;
  s.busy=true;s.result=null;paintMaxEthernet();
  try{
    const result=await fetchJson('/api/network/max/key',true,12000,'Key request timed out. Receiver outcome is unknown.',{
      method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({key,connection_token:token,
        ...(key==='PAIRING'?{confirm_pairing:true,acknowledge_non_stock:true}:{})})});
    if(maxEthernetTarget()?.connection_token!==token)return;
    s.result=result;
    if(!result?.ok&&/^MAX_ETH_(TARGET|ROUTE|IDENTITY|RECONNECT)/.test(result?.error||''))s.error=result.message;
  }catch(e){if(maxEthernetTarget()?.connection_token===token)s.result={ok:false,message:safeErr(e)+' Receiver outcome is unknown.'};}
  finally{if(maxEthernetTarget()?.connection_token===token){s.busy=false;paintMaxEthernet();}}
}
function bindMaxEthernet(){
  const read=$('#maxEthRead');if(read)read.onclick=()=>{reloadMaxEthernet();paintMaxEthernet();};
  $$('[data-maxethkey]').forEach(b=>{b.onclick=()=>sendMaxEthernetKey(b.dataset.maxethkey);});
  const pad=$('#maxEthKeyPad');if(pad)pad.onkeydown=e=>{
    if(e.repeat||['INPUT','TEXTAREA','SELECT'].includes(e.target?.tagName))return;
    const key={ArrowUp:'UP',ArrowDown:'DOWN',ArrowLeft:'LEFT',ArrowRight:'RIGHT',Enter:'CONFIRM',Escape:'BACK'}[e.key];
    if(key){e.preventDefault();e.stopPropagation();sendMaxEthernetKey(key);}
  };
}

function renderDevice(){
  const i=ident(); const s=state.status; const d=state.devices||{}; const c=state.activeConnection?.candidate||{};
  const pd=productDoc(); const t=state.activeConnection?.transport||{};
  const nb=state.activeConnection?.network_binding||null;
  const aliasBb=s?.local_bb_id||null;
  const alias=aliasBb?nicknameFor(aliasBb,'receiver'):null;
  let out=pageHead('DEVICE INFO','WHAT IS CONNECTED');
  const nt=state.activeConnection?.network_target;
  if(nt){
    const seen=nt.observed||{};
    $('#content').innerHTML=out+panel('ETHERNET CONNECTION',kv('Preset',nt.label,false)
      +kv('Device address',nt.device_ip,false)+kv('PC address',nt.source_ip||'—',false)
      +kv('PC interface',String(nt.if_index??'—'),false)+kv('Observed at',nt.captured_at||'—',false)
      +(seen.factory?kv('Factory serial',seen.factory.factory_serial,false)+kv('Saved role mode',String(seen.factory.cur_mode),false):'')
      +(seen.status?.decoded?.local_mac4?kv('Local BBID',seen.status.decoded.local_mac4,false):'')
      +'<p class="muted">The preset selects an address. Product and firmware identity have not been read over this transport. USB-only operations are unavailable.</p>')
      +(maxEthernetTarget()?'<div id="maxEthPanel">'+maxEthernetPanel(false)+'</div>':'');
    bindMaxEthernet();
    return;
  }

  /* NOTHING UNTIL THERE IS SOMETHING TO SHOW.

     This page painted its panels while the connection was still being made, so
     an operator met a screen of empty and half-filled fields -- product blank,
     firmware blank, link unknown, Service Mode guessing -- and had to work out
     which were "not known yet" and which were "not there". Values then appeared
     one at a time as reads landed. Reported from the bench as loading elements
     too early.

     A field with nothing in it is not information. Until the receiver is
     connected and identified, this page says which of the four things is
     happening and shows nothing else. The connection state already distinguishes
     them; it just was not being used here. */
  const cs=connectionState();
  if(cs!==CONN.CONNECTED_RECOGNIZED && cs!==CONN.CONNECTED_UNRECOGNIZED){
    /* THE BACKEND'S OWN WORDS FOR THE STATE, not a second set of mine.

       `connection_state_label` already exists and is what the rest of the
       application prints. Inventing "LOOKING FOR A RECEIVER" beside the
       established "SCANNING FOR A DEVICE" would be one state with two
       vocabularies -- the same fault as one fact with two sources, which this
       page has had three times already. The local strings are only the
       fallback for the window before the first capability document lands. */
    const says={
      [CONN.NO_DEVICE]:['NO DEVICE','Connect a receiver over USB.'],
      [CONN.SCANNING]:['SCANNING FOR A DEVICE','Checking what is attached.'],
      [CONN.DETECTED]:['DETECTED — NOT CONNECTED YET',
                       'A receiver is attached and is being identified.'],
    }[cs]||['SCANNING FOR A DEVICE','Checking what is attached.'];
    const label=state.capabilities?.connection_state_label||says[0];
    /* ONE ROW SURVIVES THE GATE, and it is there for a specific past defect:
       DEVICE INFO is the page that stays reachable in every state AND the page
       that explains the sidebar, so it must say WHY pages are hidden rather
       than calling them "not applicable" -- which reads as a claim about the
       device class instead of a fact about there being no live device. It is
       under ADVANCED, where the rest of the sidebar explanation already is. */
    const cap=state.capabilities||{};
    const hidden=(cap.hidden||[]).length
      ? (cap.hidden||[]).join(', ').toUpperCase() : 'NONE';
    $('#content').innerHTML = out
      + panel('DEVICE INFO',
          kv('Status',val(label,cs===CONN.NO_DEVICE?'muted':'warnc'),false)
          + notice(says[1])
          + (advancedOn()
             ? kv('Pages hidden — no live identified device',hidden)
               + notice('THERE IS NO LIVE, IDENTIFIED DEVICE, so the pages that '
                 + 'need one are hidden rather than shown empty — the same set '
                 + 'whether nothing is detected, discovery is still scanning, or '
                 + 'a device is detected but not yet connected. Nothing here is a '
                 + 'claim about a device class. Connect a device and its raw '
                 + 'command-60 identity decides which pages apply; never VID/PID.')
             : ''));
    return;
  }

  /* Changed 2026-09-22. This page carried thirty-nine rows across five panels: SDK
     version, RF board code in hex, vendor detail string, topology correlation basis,
     transport state, adapter status, the peer-field diagnostic, a device-class
     panel explaining the sidebar, and two full Windows inventory tables.

     Almost none of that answers the question an operator opens this page with,
     which is "what am I connected to". The stock PC Tool shows none of it. It is
     kept, because it is what makes a correlation claim checkable and it is how the
     multi-device rules get verified -- but it is evidence, and it now sits behind
     ADVANCED. */

  /* No duplicate "not connected" banner here: the fixed header's connection state is
     the single place that reports it, and this page repeated it directly underneath.
     Warnings that gate a real action are kept on the pages that own those actions. */
  /* DEVICE INFO is the complete place to inspect a device.

     The 2026-09-23 density pass made the wrong element canonical: it moved these
     fields INTO the fixed header and left this page with two rows. The header is an
     identity strip -- image, product name, nickname -- and an identity strip is not
     an inspection surface. Everything real about the connected unit belongs here,
     organised compactly, and nothing on this page is invented: every row renders the
     value the backend supplied or an em dash.

     There is no panel heading. The left rail already says DEVICE INFO, and a "//
     DEVICE" title above the first row repeated it. */
  /* MOST IMPORTANT FIRST, 2026-10-11. "Everything that we do must flow from
     most important to least important to respect the user's time and
     attention." The order is the order of the questions an operator brings:
       1. What is this, what is it running, what is it called, is it linked.
       2. Is anything wrong that needs me -- the USB driver repair and Service
          Mode, which were the LAST things on the page even when they were the
          only reason to open it.
       3. How it is attached, and which services answer -- reference.
     Link moved up into the identity block for the same reason: LINKED or not
     is the second thing anybody asks. Serial and hardware moved down within it:
     they identify a unit for a support ticket, not for flying. */
  out+=`<div class="panel"><div class="panel-body">`
    +kv('Product',productLabel()||'—',false)
    +(pd&&pd.source==='derived'?kv('Name basis','RENDERED FROM THE RAW IDENTITY — NOT A KNOWN VENDOR PRODUCT NAME',false):'')
    +deviceNicknameRow(aliasBb,alias)
    +kv('Firmware',shortFirmware(i?.firmware)||'—',false)
    +kv('Link',s?.link||'OFFLINE',false)
    +kv('Serial',i?.serial_number||'—')
    +kv('Hardware',i?.hardware||'—')
    +`</div></div>`;

  if(['air','camera_hub'].includes(state.capabilities?.role)){
    out+=panel('AIRCRAFT ENROLLMENT',
      '<p class="muted">Read this VTX’s BB ID and name it in MANAGE FLEET. Enrollment is separate from receiver membership.</p>'
      +'<button class="secondary" id="deviceEnrollAircraft">ENROLL AIRCRAFT</button>');
  }

  /* Things that need the operator, before reference material. Both return
     nothing when there is nothing to do, so a healthy unit is not pushed down. */
  out+=usbDriverSection();
  if(deviceHasGroundServices()) out+='';

  out+=panel('LINK AND TRANSPORT',
    kv('Connection',[i?.port||c.serial_com||t.serial_com,
                     (c.network_name||t.adapter_name)?'USB-C / RNDIS':null]
                    .filter(Boolean).join('  ·  ')||'—',false)
    +kv('Local BB ID',s?.local_bb_id||'—')
    +kv('RX MCS',s?.rx_mcs??'—')
    +kv('Transport',c.transport||i?.port||'—',false)
    +kv('Bound source',nb?`${nb.source_ip} (ifIndex ${nb.ifindex})`:'NOT BOUND',false));

  if(deviceHasGroundServices()) out+=panel('SERVICES',
    kv('Ground RPC',s?val('CONNECTED','good'):val('UNAVAILABLE'),false)
    +kv('Control UDP',state.rf?.available?val('RESPONDING','good'):val('UNAVAILABLE'),false)
    /* NO "Picker API" ROW. It reported NOT INSTALLED for something that was
       never built and is not planned: `50100` and `/v1/picker` appear ZERO
       times in the RC4 picker binary and in all five GlassesUI 19.2.4 builds
       (NAMING_ARCHITECTURE_FROZEN_2026-09-23). `_mgmt_get_json()` is a client
       with no server.

       "NOT INSTALLED" reads as "something is missing that could be there". The
       truth is that the Picker is a device-side binary GlassesUI shells out to,
       and there is no API to install. Reporting the absence of a thing that
       does not exist is worse than silence -- it invites someone to go looking
       for it. The live fleet read, which is what actually matters, is reported
       by the rows around this one. */
    +kv('Ground endpoint',state.app?.ground||'—'));

  if(advancedOn()){
    // Restored from the Codex line (76127a2, "expose existing CGC validated replies
    // in Device Info"). My 2026-09-22 rewrite dropped these three rows; they are
    // evidence, so they belong behind ADVANCED rather than gone.
    const rawReply=k=>{
      const q=(state.rf?.queries||{})[k]||{};
      if(!q.ok) return humanError(q.error||'UNAVAILABLE');
      return q.payload_hex||'VALID FRAME, NO PAYLOAD';
    };
    out+=`<div class="split"><div>${panel('VENDOR IDENTITY',
      kv('Reported identity',i?.device_name||'—')
      +kv('SDK version',i?.sdk_version||'—')+kv('CPU temperature',i?.cpu_temp!==undefined&&i?.cpu_temp!==null?`${i.cpu_temp} °C`:'—')
      +kv('RF board',i?.rf_board_name||'—')+kv('RF board code',i?.rf_board_code!==undefined&&i?.rf_board_code!==null?hx(i.rf_board_code):'—')
      +kv('Vendor detail',i?.detail||'—',false)
      +notice('The identity the unit reports is the canonical key. The product name and the nickname are presentation only and are never used for compatibility, qualification or write eligibility.'))}</div>
      <div>${panel('TRANSPORT AND REACHABILITY',
        kv('Physical transport',transportLabel(),false)
        +kv('Serial endpoint',i?.port||c.serial_com||t.serial_com||'—')
        +kv('Serial state',i?.device_name?'IDENTIFIED — COMMAND 60 ANSWERED':'NO VENDOR SERIAL SESSION',false)
        +kv('RNDIS adapter',c.network_name||c.interface_name||c.network_adapter||t.adapter_name||'—',false)
        +kv('Adapter status',t.adapter_status||'—',false)
        +kv('Interface index',(nb&&nb.ifindex!=null)?nb.ifindex:((t.ifindex!=null)?t.ifindex:'—'))
        +kv('Host IPv4 (bound source)',(nb&&nb.source_ip)?nb.source_ip:(t.host_ip_ready?'READY — ADDRESS NOT RESOLVED':'NOT READY'))
        +kv('Device endpoint',state.app?.ground||'—')
        +kv('Topology correlation',t.topology_qualified?'CONTAINER ID — SERIAL AND RNDIS ARE THE SAME PHYSICAL DEVICE':(t.correlation_basis||'UNQUALIFIED').toUpperCase(),false)
        +kv('Transport state',(t.state||'unresolved').toUpperCase(),false)
        +kv('Ground RPC',s?'CONNECTED':'UNAVAILABLE')+'')}</div></div>`;

    out+=panel('GROUND LINK STATE',
      kv('Ground host',s?.host||state.app?.ground||'—')
      +kv('Link state',s?.link||'OFFLINE',false)
      +kv('Local BB ID',s?.local_bb_id||'—')
      +kv('RX MCS',s?.rx_mcs??'—')
      +kv('Peer field (diagnostic only)',s?.peer_diagnostic||'—')
      +kv('Peer authoritative','NO',false)
      +kv('Frequency query (0x51)',rawReply('frequency'))
      +kv('Wireless status query (0x52)',rawReply('wireless_status'))
      +kv('Power-index query (0x53)',rawReply('power_index'))
      +notice('The Caddx Ground Configuration v0.3.5 FE/EF framing is integrated for these three read-only queries. Frames and checksums are validated, but the payloads remain raw until their field meanings are independently qualified. No frequency, dBm or mW value is invented from an unqualified byte.','warn')
      +kv('Channel / hop state','NOT IMPLEMENTED',false)
      +kv('Baseband TX power','NOT IMPLEMENTED',false)
      +notice('Channel/hop state and baseband TX power are read-only here. The opcodes exist and are documented; nothing in this build writes them.','warn'));

    const cap=state.capabilities||{};
    const live=cap.live_device!==false;
    out+=panel('DEVICE CLASS AND APPLICABLE PAGES',
      kv('Connection state',cap.connection_state_label||'—',false)
      +kv('Device class',cap.role_label||'—',false)
      +kv('Derived from',cap.source==='raw_command_60_device_name'?'RAW COMMAND-60 DEVICE NAME':'—')
      +kv('Basis',cap.evidence||'—',false)
      +kv(live?'Pages hidden as not applicable':'Pages hidden — no live identified device',(cap.hidden||[]).length?(cap.hidden||[]).join(', ').toUpperCase():'NONE')
      +((cap.hidden||[]).map(k=>kv(`Why ${k.toUpperCase()} is hidden`,cap.pages?.[k]?.reason||'—',false)).join(''))
      /* WAS 622 AND 355 CHARACTERS OF POLICY. Both explained a rule the
         operator cannot change, on a page they opened to see a device. The
         rule itself is unchanged and is stated once in device_capability;
         what is left here is the part that is about THIS unit right now. */
      +notice(live
        ? 'Pages are shown or hidden from the identity this unit reports. This is an Ascent Control behaviour, not stock PC Tool parity.'
        : 'No identified device, so pages needing one are hidden.'));

    if(d.usb?.length) out+=panel('USB / SERIAL IDENTITIES',`<table><thead><tr><th>NAME</th><th>CLASS</th><th>STATUS</th><th>PNP DEVICE ID</th></tr></thead><tbody>${d.usb.map(x=>`<tr><td>${esc(x.Name||'')}</td><td><code>${esc(x.PNPClass||'')}</code></td><td>${esc(x.Status||'')}</td><td><code>${esc(x.PNPDeviceID||x.DeviceID||'')}</code></td></tr>`).join('')}</tbody></table>`);
    if(d.network?.length) out+=panel('NETWORK INTERFACES',`<table><thead><tr><th>NAME</th><th>DESCRIPTION</th><th>STATUS</th><th>MAC</th><th>LINK</th></tr></thead><tbody>${d.network.map(x=>`<tr><td>${esc(x.Name||'')}</td><td>${esc(x.InterfaceDescription||'')}</td><td>${esc(x.Status||'')}</td><td><code>${esc(x.MacAddress||'')}</code></td><td><code>${esc(x.LinkSpeed||'')}</code></td></tr>`).join('')}</tbody></table>`);
  }
  // Receiver properties, at the end of what the receiver IS. Self-loading, so
  // they are never "not read yet" merely because another page was not visited.
  if(state.rfMode===undefined){ state.rfMode=null;
    Promise.resolve(null).then(()=>{ if(state.view==='device') render(); }); }
  // The Service Mode read is hoisted to render(), because every page needs the
  // answer and this one is not special. Left here as a note so nobody puts a
  // second loader back and gives two pages two different answers.
  // THE REPAIR BELONGS WHERE THE FAILURE IS REPORTED. Service Mode stops at
  // HOST_NETWORK when the receiver's USB network interface has no working
  // driver, and that message is printed on THIS page. Offering the fix on a
  // different page and expecting the operator to go and find it is the same
  // defect as telling them to open Device Manager.
  if(state.usbDriver===null&&!state.usbDriverLoading){
    state.usbDriverLoading=true;
    reloadUsbDriver().then(()=>{ state.usbDriverLoading=false;
      if(state.view==='device') render(); }); }
  /* RF REGION IS NOT ON THE ORDINARY PAGE.

     Every row it produced was an absence: region policy DISABLED, channel
     unlock UNVERIFIED, power unlock UNVERIFIED, last checked never, a CHECK
     STATUS button that confirms nothing, and two paragraphs explaining why no
     change is offered. A panel whose entire content is "we cannot do this" is
     not a feature; it occupies the page the operator came to use.

     What was actually asked for is expanded-RF mode -- the long-press on the
     receiver. Nothing in this repository documents that sequence, so it is not
     implemented, and inventing a procedure for unlocking transmit power is the
     one thing that must not happen here.

     The diagnostic still has value to someone debugging, so it lives under
     ADVANCED rather than being deleted. */
  if(advancedOn()) out+='';
  // deviceServiceModePanel() and usbDriverSection() moved up, under identity.
  // serviceModeInstalledField() used to render here as a THIRD panel about
  // Service Mode, after the status panel and the setup prompt. "Service Mode:
  // BLOCKED" and "Service mode installed: UNKNOWN" are the same fact told
  // twice in different words, and three panels with four buttons is what the
  // operator meant by "I have no idea what is happening". It now appears only
  // under ADVANCED, where reference material belongs.
  /* REMOVED, not demoted again. This said "Service mode installed: YES" while
     the main panel one screen above said "Accepted by this receiver: yes" --
     the same fact in different words, which is how a page ends up seeming to
     disagree with itself. It was already behind ADVANCED and was still the
     third thing on one screen saying one thing. The fact stays where the
     operator acts. */
  $('#content').innerHTML=out;
  bindDeviceNickname(aliasBb);
  bindDeviceRfAndServiceMode();
  bindNet();
}

function bindDeviceRfAndServiceMode(){
 $('#deviceEnrollAircraft')?.addEventListener('click',()=>setNav('fleet'));
}

function fwSeverityLabel(c){
  if(c.passed) return 'PASS';
  return c.severity==='block'?'BLOCKED':(c.severity==='confirm'?'NEEDS ACKNOWLEDGEMENT':'NOTE');
}

function fwCheckRows(v){
  return (v.checks||[]).map(c=>{
    const cls=c.passed?'good':(c.severity==='block'?'bad':(c.severity==='confirm'?'warnc':'muted'));
    return `<tr><td><code>${esc(c.id)}</code></td>`
      +`<td class="${cls}">${esc(fwSeverityLabel(c))}</td>`
      +`<td>${c.vendor?'STOCK TOOL':'OURS'}</td>`
      +`<td>${esc(c.detail||'—')}</td>`
      +`<td><code>${esc(c.citation||'—')}</code></td></tr>`;
  }).join('');
}

function fwSelectionPanel(){
  const fw=state.fw||{}; const sel=fw.selection;
  if(!sel) return panel('FIRMWARE FILE',
    notice('No firmware file selected. The stock tool offers exactly one file type: a device .img, chosen through a native file dialog. It never accepts an archive.')
    +kv('Vendor file filter',fw.vendor_file_filter||'—')
    +fwPickerToolbar());
  const v=sel.validation||{}; const img=sel.image||{}; const t=img.trailing_md5||{};
  let b=kv('File',img.basename||sel.path)
    +kv('Full path',sel.path)
    +kv('Size',`${(img.bytes??0).toLocaleString()} bytes`)
    +kv('Container',img.container?`${img.container} (magic ${img.container_magic_hex})`:`UNRECOGNISED (magic ${img.container_magic_hex||'—'})`)
    +kv('MD5 sent to the device in ArFileInfo.MD5',img.md5||'—')
    +kv('SHA-256',img.sha256||'—')
    +kv('Version parsed from filename',v.file_version_label||'—')
    +kv('Device firmware string',(fw.device||{}).firmware||'—')
    +kv('Remote destination on device',v.remote_path||'—');
  if(t.carries_trailing_digest){
    b+=kv('Image trailing MD5',t.matches?`VERIFIED — ${t.declared}`:`MISMATCH — declares ${t.declared}, body computes ${t.computed_over_body}`,true);
  } else {
    b+=kv('Image trailing MD5','NOT PRESENT IN THIS IMAGE');
  }
  b+=`<table><thead><tr><th>CHECK</th><th>RESULT</th><th>SOURCE</th><th>DETAIL</th><th>CITATION</th></tr></thead><tbody>${fwCheckRows(v)}</tbody></table>`;
  b+=fwPickerToolbar();
  return panel('SELECTED FIRMWARE FILE',b);
}

function fwPickerToolbar(){
  const fw=state.fw||{};
  const browse=fw.browse_supported
    ? `<button class="secondary" id="fwBrowse">BROWSE…</button>`
    : `<button class="secondary" disabled>BROWSE… (WINDOWS ONLY)</button>`;
  return `<div class="toolbar" style="justify-content:flex-start;flex-wrap:wrap">`
    +`<input id="fwPath" class="text-input" type="text" autocomplete="off" spellcheck="false" `
    +`placeholder="Full path to the device .img" value="${esc(state.fwPathDraft||'')}">`
    +browse
    +`<button class="action" id="fwValidate">VALIDATE FILE</button>`
    +(fw.selection?`<button class="secondary" id="fwClear">CLEAR SELECTION</button>`:'')
    +`</div>`;
}

function fwDevicePanel(){
  const fw=state.fw||{}; const d=fw.device||{}; const h=fw.filename_hint||{};
  let b=kv('Reported device name',d.device_name||'—')
    +kv('Firmware',d.firmware||'—')
    +kv('Firmware version',d.device_version_label||'—')
    +kv('Hardware',d.hardware||'—')
    +kv('Serial number',d.serial_number||'—')
    +kv('SDK version',d.sdk_version||'—')
    +kv('Chip temperature',d.cpu_temp_c===undefined||d.cpu_temp_c===null?'—':`${d.cpu_temp_c} °C`)
    +kv('Transfer size the unit accepts',d.receive_max_size===undefined||d.receive_max_size===null?'—':`${d.receive_max_size} bytes`);
  if(h.tip_text) b+=kv('Stock tool on-screen hint',h.tip_text,false);
  b+=kv('Prefix the stock filename check actually uses',h.gate_prefix||'—');
  if(h.tip_text&&!h.prefixes_agree){
    b+=notice('The stock tool derives the on-screen hint and the filename check from the same firmware string with two DIFFERENT regexes, so they disagree on this device. Both are shown because the second one is what prompts.','warn');
  }
  return panel('TARGET DEVICE',b);
}

function fwPlanPanel(){
  const fw=state.fw||{}; const t=fw.timing||{}; const sel=fw.selection||{}; const img=sel.image||{};
  const cs=t.default_chunk_size||1048576;
  const chunks=img.bytes?Math.ceil(img.bytes/cs):0;
  let b=kv('Sequence','60 → 3 "clean" → reconnect → 114 → 115 → 116 × N → 117 → 118 polled → reconnect → 60')
    +kv('Chunk size',`${cs.toLocaleString()} bytes (the size this unit says it accepts; the vendor default when it says nothing)`)
    +kv('Chunks for this image',chunks||'—')
    +kv('Remote path on device',sel.validation?.remote_path||'/tmp/pc/<filename>')
    +kv('ACK guard',`retry every ${t.ack_retry_interval_s} s, fail after ${t.ack_total_timeout_s} s`)
    +kv('Status poll',`command 118 every ${t.status_poll_delay_s} s, at most ${t.status_poll_limit} queries`)
    +kv('Reconnect per reboot',`${t.reconnect_settle_s} s settle + ${t.reconnect_poll_budget_s} s wait`)
    +kv('Reboots',
        'TWO — one into clean mode before the transfer, one by the device itself after the flash')
    +kv('Pre-flash backup directory',fw.backup_directory||'—');
  b+=notice('The device firmware image CANNOT be read back over this protocol, so the pre-flash backup captures recoverable device state — the full identity the unit reports and the verified RF band table — not an image. It does not make the flash reversible.','warn');
  return panel('WHAT WILL BE SENT',b);
}

function advancedOn(){ return $('#advanced')?.checked===true; }

function setAdvanced(on){
  const cb=$('#advanced'); if(cb) cb.checked=on===true;
  $('#advancedMenu')?.classList.toggle('hidden',!(on===true));
  try{ localStorage.setItem('ascent.advanced', on===true?'1':'0'); }catch{}
  render();
}

function fwEligibilityPanel(){
  const el=state.fw?.eligibility||{};
  // The operator reads the outcome and plain causes; the identifier and the
  // technical reasons are diagnostics and sit behind ADVANCED with everything else.
  const plain=(el.plain_reasons||[]).length?el.plain_reasons:(el.eligible?[]:el.reasons||[]);
  let b=kv('Action',el.operation_label||el.operation_id||'—')
    +kv('Can this run now?',el.eligible?'YES':'NOT YET')
    +(el.eligible?'':`<div class="kv"><span>Why not</span><span><ul style="margin:0">`
        +plain.map(x=>`<li>${esc(x)}</li>`).join('')+`</ul></span></div>`)
    +(advancedOn()?kv('Operation id',el.operation_id||'—')
        +kv('Technical reasons',(el.reasons||[]).join('; ')||'—',false):'')
    +kv('Stock tool’s own gate',el.vendor_gate||'—',false);
  const ev=el.evidence||{};
  b+=kv('Serial COM',ev.serial_com||'—')+kv('VID / PID',(ev.vid&&ev.pid)?`${ev.vid}:${ev.pid}`:'—')
   +kv('Linked to a physical USB device',ev.container_id_present?'YES':'NO');
  return panel('UPGRADE QUALIFICATION',b);
}

function fwConfirmPanel(){
  const fw=state.fw||{}; const sel=fw.selection||{}; const v=sel.validation||{};
  const img=sel.image||{}; const t=fw.timing||{};
  const need=v.confirmations_required||[];
  const checks=(v.checks||[]).filter(c=>need.includes(c.id));
  let b=kv('Device',`${(fw.device||{}).device_name||'—'}  ${(fw.device||{}).firmware||''}`)
    +kv('Image',img.basename||'—')
    +kv('Image size',`${(img.bytes??0).toLocaleString()} bytes`)
    +kv('Image MD5',img.md5||'—')
    +kv('Version change',`${(fw.device||{}).device_version_label||'?'} >> ${v.file_version_label||'?'}`)
    +kv('Verdict',(v.version_verdict||{}).verdict||'—');
  if(checks.length){
    // The first column used to print the check's internal id -- `not_a_downgrade`,
    // `filename_matches_device` -- which is an internal enum value in a normal state,
    // and told the operator nothing the vendor wording beside it did not already say.
    // It now asks the question in plain words; the id stays available under ADVANCED
    // so a bug report can still name the exact check.
    b+=`<table><thead><tr><th>WHAT YOU ARE ACCEPTING</th><th>STOCK TOOL WORDING</th><th>ACCEPT</th></tr></thead><tbody>`
      +checks.map(c=>`<tr><td>${esc(c.plain_label||c.vendor_message||'—')}`
        +`${advancedOn()&&c.id?` <span class="muted">[${esc(c.id)}]</span>`:''}</td>`
        +`<td>${esc(c.vendor_message||c.detail||'—')}</td>`
        +`<td><label><input type="checkbox" class="fwAck" data-ack="${esc(c.id)}"${state.fwAck.includes(c.id)?' checked':''}> ACCEPT</label></td></tr>`).join('')
      +`</tbody></table>`;
  }
  b+=notice(`THIS OVERWRITES THE DEVICE FIRMWARE. The device reboots twice and disappears from Windows both times; the COM port number may change. Budget ${t.reconnect_settle_s} s + ${t.reconnect_poll_budget_s} s per reboot, plus the transfer and up to ${t.status_poll_limit} status polls. Keep the device powered and connected throughout. Do not close this application.`,'error');
  b+=notice('Stock-tool advice, reproduced: keep the computer connected to the internet, keep the USB device connected, and make sure the device is powered with sufficient charge. During the upgrade the status light may flash abnormally or the device may restart on its own — that is normal.');
  const outstanding=need.filter(id=>!state.fwAck.includes(id));
  const gate=(fw.eligibility||{}).eligible&&!outstanding.length
    ? `<button class="action" id="fwApply">FLASH ${esc(img.basename||'FIRMWARE')} TO DEVICE</button>`
    : `<button class="action" disabled>${outstanding.length?'ACKNOWLEDGE THE PROMPTS ABOVE':'FLASH REFUSED — NOT QUALIFIED'}</button>`;
  b+=`<div class="toolbar" style="justify-content:flex-start">${gate}<button class="secondary" id="fwCancel">CANCEL</button></div>`;
  return panel('CONFIRM FIRMWARE UPGRADE',b);
}

function fwProgressPanel(){
  const p=state.fwProgress||{}; const t=state.fw?.timing||{};
  const phase={starting:'PREPARING',backed_up:'PRE-FLASH BACKUP WRITTEN',
    find_device:'READING DEVICE IDENTITY',reboot_clean:'REBOOTING INTO CLEAN MODE',
    reconnect_clean:'WAITING FOR THE DEVICE TO RETURN IN CLEAN MODE',
    remote_upgrade:'ENTERING UPGRADE MODE',sendfile_start:'STARTING FILE TRANSFER',
    sendfile_data:'TRANSFERRING FIRMWARE',sendfile_end:'FINISHING TRANSFER',
    upgrade_status:'DEVICE IS WRITING FLASH',
    reconnect_final:'DEVICE REBOOTING AFTER FLASH',
    verify:'REREADING FIRMWARE VERSION',complete:'COMPLETE',idle:'FINISHING'
  }[p.phase]||String(p.phase||'WORKING').toUpperCase();
  let b=kv('Stage',phase)+kv('Overall progress',p.percent===undefined?'—':`${Math.round(p.percent*100)}%`);
  if(p.desc) b+=kv('Stock tool status text',p.desc,false);
  if(p.bytes_total) b+=kv('Transferred',`${(p.bytes_sent||0).toLocaleString()} of ${p.bytes_total.toLocaleString()} bytes — chunk ${p.chunk_index||0} of ${p.chunk_count||'?'}`);
  if(p.device_percent!==undefined) b+=kv('Device-reported percent',`${p.device_percent}%  (${p.device_status||'—'})`);
  if(p.query) b+=kv('Status queries',`${p.query} of ${t.status_poll_limit||200}`);
  if(p.settle_s!==undefined) b+=kv('Reconnect budget',`${p.settle_s} s settle + ${p.poll_budget_s} s wait`);
  if(p.elapsed_s!==undefined&&p.poll_budget_s!==undefined) b+=kv('Waited so far',`${p.elapsed_s} s of ${p.poll_budget_s} s`);
  if(p.strategy) b+=kv('Reconnect strategy',p.strategy==='same_port'?'RETRYING THE PREVIOUS COM PORT':(p.strategy==='usb_search_same_container'?'SEARCHING USB FOR THE SAME PHYSICAL DEVICE':String(p.strategy).toUpperCase()));
  if(p.last_error) b+=kv('Last probe result',safeErr(p.last_error));
  b+=notice('The device is expected to disappear and come back TWICE. This is normal. Do not disconnect it and do not power it off.','warn');
  return panel('FIRMWARE UPGRADE IN PROGRESS',b);
}

function fwErrorPanel(){
  const e=state.fwError||{}; const ev=e.evidence||{};
  let b=kv('Error code',e.error||'UNKNOWN')+kv('Stage',e.stage||'—')
    +kv('Message',safeErr(e.message||'—'),false);
  if(e.error==='FIRMWARE_REJECTED_ANTI_ROLLBACK'){
    b+=notice('REFUSED BY THE DEVICE (-6): the image is not newer than what is installed. This is the unit’s own anti-rollback check; nothing was written.','error');
  }
  /* -5 on a camera-variant unit is usually the FILE NAME, not the image: the
     unit's own updater parses the name and refuses one it cannot read. */
  if((ev.status||{}).status===-5){
    const sugg=((((state.fw||{}).selection||{}).validation||{}).checks||[])
      .map(c=>c.suggested_filename).find(Boolean);
    b+=notice('REFUSED AS THE WRONG MODEL (-5). On Z8/Z40/Hub units this is usually the file name. Nothing was written.'
      +(sugg?` Rename it ${esc(sugg)} and retry.`:''),'error');
  }
  if(ev.device_rejected) b+=kv('Refused by the device',(ev.status||{}).status_code||'YES');
  if(ev.status) b+=kv('Device status',`percent ${ev.status.percent}, status ${ev.status.status} (${ev.status.status_code})`)
                 +kv('Device detail',ev.status.detail||'—',false);
  if(ev.image_was_transferred!==undefined) b+=kv('Image was transferred',ev.image_was_transferred?'YES — THE DEVICE MAY HAVE STARTED WRITING FLASH':'NO');
  if(ev.upgrade_may_have_applied) b+=kv('Upgrade may have applied','YES — VERIFY THE DEVICE BEFORE RETRYING');
  if(ev.backup?.file) b+=kv('Pre-flash backup',ev.backup.file);
  if(ev.outstanding) b+=kv('Unacknowledged prompts',(ev.outstanding||[]).join(', '));
  if(ev.blocking) b+=kv('Blocking checks',(ev.blocking||[]).join(', '));
  if(ev.reasons||ev.eligibility?.reasons) b+=kv('Qualification reasons',(ev.reasons||ev.eligibility?.reasons||[]).join('; '),false);
  if(ev.settle_s!==undefined) b+=kv('Budget used',`${ev.settle_s} s settle + ${ev.poll_budget_s} s wait`);
  if(ev.last_error) b+=kv('Last reconnect probe',safeErr(ev.last_error));
  const stages=(ev.stages||[]).map(s=>s.stage).join(' → ');
  if(stages) b+=kv('Stages reached',stages,false);
  b+=notice('The upgrade was NOT reported as successful. Read the device state before retrying.','error');
  b+=`<div class="toolbar" style="justify-content:flex-start"><button class="secondary" id="fwDone">CLOSE</button></div>`;
  return panel('FIRMWARE UPGRADE FAILED',b);
}

function fwResultPanel(){
  const r=state.fwResult||{}; const st=r.status||{}; const f=st.final||{};
  const vc=r.version_check||{};
  let b=kv('Result',r.verified?'VERIFIED':'COMPLETED — NOT FULLY VERIFIED')
    +kv('Firmware before',r.firmware_before||'—')
    +kv('Firmware after',r.firmware_after||'—')
    +kv('Firmware string changed',r.firmware_changed?'YES':'NO')
    +kv('Version the file declared',vc.expected_from_filename||'—')
    +kv('Version the device now reports',vc.observed_device_version||'—')
    +kv('Version match',vc.comparable===false?'NOT COMPARABLE — THE FILENAME CARRIES NO PARSABLE VERSION'
                                             :(vc.match?'YES':'NO'))
    +kv('Device identity stable across the flash',r.post_flash_identity_stable?'YES':'NO')
    +kv('Final device percent',f.percent===undefined?'—':`${f.percent}%  (${f.status_code||'—'})`)
    +kv('Status queries used',st.queries??'—')
    +kv('Serial port after flash',`${r.port||'—'}${r.port_changed?' (CHANGED)':''}`)
    +kv('Bytes transferred',(r.plan||{}).file_bytes?`${r.plan.file_bytes.toLocaleString()} in ${r.plan.chunk_count} chunk(s) of ${r.plan.chunk_size.toLocaleString()}`:'—')
    +kv('Image MD5 declared to the device',(r.plan||{}).md5||'—')
    +kv('Pre-flash backup',(r.backup||{}).file||'—')
    +kv('Commands',(r.stages||[]).map(s=>s.command).join(' → ')||'—')
    +kv('Elapsed',r.elapsed_s===undefined?'—':`${r.elapsed_s} s`);
  if((r.warnings||[]).length) b+=kv('Warnings',(r.warnings||[]).map(w=>w.message).join('; '),false);
  if(r.post_read?.error) b+=notice(`THE DEVICE FLASHED AND RETURNED, BUT THE FULL POST-FLASH READ FAILED: ${safeErr(r.post_read.error)}. Refresh and read the device before trusting the page state.`,'warn');
  if(!r.firmware_changed) b+=notice('The device reported a successful upgrade but its firmware string did not change. That is expected when reflashing the same version; it is NOT proof a different image was applied.','warn');
  if(vc.comparable===false) b+=notice('The filename carries no version the stock tool can parse, so there is nothing to compare the device against. The flash completed and the device came back, but this application cannot confirm WHICH image is now installed.','warn');
  else if(vc.match===false) b+=notice(`THE DEVICE REPORTS A DIFFERENT VERSION THAN THE IMAGE DECLARED: expected ${esc(vc.expected_from_filename||'—')}, device reports ${esc(vc.observed_device_version||'—')}. Read the device before using it.`,'error');
  if(vc.parity_note) b+=notice(`Comparing these two is this application's check, not the stock tool's. ${vc.parity_note}`);
  b+=`<div class="toolbar" style="justify-content:flex-start"><button class="secondary" id="fwDone">CLOSE</button></div>`;
  return panel('FIRMWARE UPGRADE COMPLETE',b);
}

function fwVerdict(){
  const fw=state.fw||{}; const sel=fw.selection; const v=sel?.validation||{};
  if(!sel) return {state:'none',text:'No firmware file selected.'};
  if((v.blocking||[]).length)
    return {state:'blocked',text:`REFUSED — ${(v.blocking||[]).join(', ')}`};
  if(!(fw.eligibility||{}).eligible)
    return {state:'blocked',
            text:`NOT ELIGIBLE — ${((fw.eligibility||{}).reasons||[]).join(', ')||'this device is not qualified'}`};
  if((v.confirmations_required||[]).length)
    return {state:'confirm',
            text:`READY, with ${(v.confirmations_required||[]).length} warning(s) to accept: ${(v.confirmations_required||[]).join(', ')}`};
  return {state:'ready',text:'READY — all pre-send checks passed.'};
}

function fwActionPanel(){
  const fw=state.fw||{}; const sel=fw.selection; const v=fwVerdict();
  const dev=fw.device||{}; const img=sel?.image||{};
  // Three things an operator must see before flashing, and no more: what they are
  // flashing, what onto, and whether it can be undone. Everything else is evidence.
  let body=kv('Target device',`${dev.device_name||'NO DEVICE'}${dev.firmware?'  ·  '+dev.firmware:''}`,false)
    +(dev.serial_number?kv('Serial',dev.serial_number):'');
  if(sel) body+=kv('File',img.basename||sel.path,false)
                +kv('Size',`${(img.bytes??0).toLocaleString()} bytes`,false);
  body+=fwPickerToolbar();
  const cls=v.state==='ready'?'':(v.state==='confirm'?'warn':(v.state==='none'?'':'error'));
  body+=notice(v.text,cls);
  // Never behind a toggle: a flash CANNOT be read back and the pre-flash backup
  // captures device state, not an image, so it does not make this reversible.
  body+=notice('A flash CANNOT be read back. The pre-flash backup captures device state, not an image, so it does not make the flash reversible.','warn');
  const ready=v.state==='ready'||v.state==='confirm';
  body+=`<div class="toolbar" style="justify-content:flex-start">`
    +(ready?`<button class="action" id="fwStart">REVIEW AND UPGRADE…</button>`
           :`<button class="action" disabled>UPGRADE UNAVAILABLE</button>`)
    +`</div>`;
  return panel('START UPGRADE', body);
}

function fwVariantPanel(){
  const v = state.fwVariant || (state.fwVariant = {donor:null, target:'z40', plan:null,
                                                  features:null, busy:false, error:null});
  const targets = [['z8','Z8'],['z40','Z40'],['hub','Hub'],
                   ['hdpro','HD Pro (legacy Walksnail; separate from HD Pro II)']];
  const feature = (v.features||[]).find(f=>f.feature==='firmware_variant_build');

  let b = notice('No Caddx release testing. Read risks below.', 'warn');

  // A BROWSE BUTTON, like the firmware lane above. Typing a full Windows path by
  // hand was the only way to choose a donor, which is a poor way to pick a file
  // you already have on disk -- and the identical control exists four panels up.
  b += `<div class="kv"><span>Donor image</span><span>`
     + `<input class="text-input" id="fwVarPath" style="min-width:300px" `
     + `placeholder="path to an Ascent_G_Sky .img" value="${esc(v.donor||'')}">`
     + ` <button class="secondary" id="fwVarBrowse"${v.busy?' disabled':''}>BROWSE…</button>`
     + `</span></div>`;
  // A dropdown, not a segmented control: `.segmented` is a two-column grid, so
  // three products wrapped into a 2 + 1 block that read as a group of buttons
  // rather than one choice.
  b += `<div class="kv"><span>Product to build</span><span>`
     + `<select id="fwVarTarget">`
     + targets.map(([id,label])=>
         `<option value="${id}"${v.target===id?' selected':''}>${label}</option>`).join('')
     + `</select></span></div>`;

  if (v.target === 'hdpro' && !v.plan){
    b += notice('HD Pro camera untested.');
  }

  b += `<div class="toolbar" style="justify-content:flex-start;flex-wrap:wrap">`
     + `<button class="secondary" id="fwVarPlan"${v.busy?' disabled':''}>`
     + `${v.busy?'CHECKING THE IMAGE…':'CHECK IF IT CAN BE BUILT'}</button></div>`;

  if (v.error) b += notice(humanError(v.error), 'error');

  if (!v.plan && !v.error && !v.busy){
    // FIRST RUN. Not a fault, and must not read like one.
    b += notice('Point this at an Ascent_G_Sky image and pick a product to see whether it can be turned into one. Checking sends nothing to a device and writes nothing.');
  }

  if (v.plan){
    const p = v.plan;
    const pk = p.packer || {};
    const blockers = p.blockers || [];

    // A VARIANT IS A NORMAL IMAGE PLUS ADDED FILES. The donor is not expected to
    // contain the camera software already -- that is the thing being added. An
    // earlier version of this panel reported the donor's lack of it as a fault,
    // which asked the donor to already be what the operator was trying to build.
    b += kv('Donor', `${p.donor} — ${String(p.donor_product).toUpperCase()} ${p.donor_version||''}`)
       + kv('Would add', p.payload_files == null ? p.payload_adds : `${p.payload_files} files: ${p.payload_adds}`)
       + kv('Camera software available for', (p.authentic_payloads_held||[]).join(', ') || '—');

    if (p.outcome === 'ALREADY_THIS_PRODUCT'){
      b += kv('Can it be built now', 'NOT NEEDED');
      b += notice('This image is already the product you asked for, so there is '
                + 'nothing to add. You can flash it as it is.');
    } else {
      b += kv('Can it be built now',
              p.buildable ? 'YES'
              : (blockers.length === 1 ? 'NO — one thing is in the way'
                 : blockers.length === 2 ? 'NO — two separate things are in the way'
                 : `NO — ${blockers.length} separate things are in the way`));
    }

    // Each blocker stands on its own. They are listed as SEPARATE items, with what
    // would clear each one, because clearing a single blocker does not unlock the
    // build and an operator reading one paragraph will assume it does.
    if (blockers.length){
      b += `<p class="muted">${blockers.length === 1 ? 'What is in the way:'
             : 'These are independent — fixing one does not fix the other:'}</p><ul>`;
      b += blockers.map(x => {
        let li = `<li>${esc(x.what)}`;
        if (x.clears_when) li += `<br><span class="muted">Clears when ${esc(x.clears_when)}.</span>`;
        if (advancedOn()){
          if (x.why) li += `<br><span class="muted">${esc(x.why)}</span>`;
          if (x.id)  li += ` <span class="muted">[${esc(x.id)}]</span>`;
        }
        return li + `</li>`;
      }).join('') + `</ul>`;
    }

    // Stated as an EXPECTATION MET, not as a finding against the donor.
    (p.observations||[]).forEach(o => { b += `<p class="muted">${esc(o)}</p>`; });
    (p.notes||[]).forEach(n => { b += `<p class="muted">${esc(n)}</p>`; });

    if (p.route) b += notice(p.route);

    // The packer's capability, MEASURED on this donor just now rather than quoted
    // from a sentence that can go stale. The round trip is re-run per report.
    if (advancedOn() && !p.camera_port){
      b += kv('Image packer — rebuild container',
              pk.can_rebuild_container ? 'YES' : 'NO')
         + kv('Image packer — regenerate filesystem',
              pk.can_regenerate_filesystem ? 'YES' : 'NO — this is what adding a file needs')
         + kv('This donor rebuilt byte for byte just now',
              pk.donor_round_trips_byte_identical === true ? 'YES'
              : pk.donor_round_trips_byte_identical === false ? 'NO'
              : (pk.round_trip_error ? `Could not run — ${esc(pk.round_trip_error)}`
                                     : 'Not run'));
    }
    if (p.outcome !== 'ALREADY_THIS_PRODUCT') b += fwVariantSlots(v);
  }

  if (feature){
    const blocked = feature.state === 'BLOCKED';
    // ORDER MIRRORS THE BACKEND GATE. require() refuses a blocked feature BEFORE it
    // looks at acknowledgement, so the operator reads "this cannot run" first. The
    // previous order put an I ACCEPT THIS RISK switch above the sentence explaining
    // that accepting changes nothing, which invites exactly the wrong conclusion.
    if (blocked){
      // BLOCKED, not broken.
      //
      // THE PLAN WINS WHEN THERE IS ONE. The feature's own sentence is donor-neutral
      // and says there are two reasons, because in general there are. For a specific
      // donor there may be only one -- a 17.5.8 donor targeting Z40 already has its
      // payload -- and showing both at once had the panel saying "one thing is in the
      // way" directly above "there are TWO separate reasons". The plan is the
      // specific answer, so the generic sentence appears only before a check is run.
      if (!v.plan && v.target !== 'hdpro') b += notice(feature.blocked_because, 'warn');
      if (advancedOn() && feature.blocked_detail && v.target !== 'hdpro')
        b += notice(feature.blocked_detail);
    }

    b += `<div class="kv"><span>Risk</span><span>${esc(feature.risk)}</span></div>`
       + `<div class="kv"><span>If it goes wrong</span><span>${esc(feature.recovery)}</span></div>`;

    // NO ACCEPTANCE CONTROL WHILE BLOCKED. A switch that cannot unlock anything is
    // a switch that misrepresents itself. It returns when the feature can run.
    if (!blocked){
      b += `<label class="switch-row"><span>I ACCEPT THIS RISK</span>`
         + `<input id="fwVarAck" type="checkbox"${feature.acknowledged?' checked':''}>`
         + `<i></i></label>`;
    }

    // Count the blockers from the PLAN when there is one -- it knows whether this
    // donor and target hit one obstacle or two. Fall back to the plural-neutral
    // wording before a check has been run.
    const n = (v.plan && (v.plan.blockers||[]).length) || 0;
    const gate = fwVariantBuildGate(v, feature);
    const why = gate.ok ? 'Builds on this computer. Nothing is sent to a device.'
              : blocked ? (n === 1 ? 'Unavailable until the obstacle above is cleared.'
                         : n === 2 ? 'Unavailable until both obstacles above are cleared.'
                         : n > 2   ? `Unavailable until all ${n} obstacles above are cleared.`
                                   : 'Unavailable until the obstacles above are cleared.')
              : gate.why;
    b += `<div class="toolbar" style="justify-content:flex-start">`
       + `<button class="action" id="fwVarBuild"${gate.ok?'':' disabled'}>`
       + `${fwVariantRunning(v)?'BUILDING…':'BUILD IMAGE'}</button>`
       + `<span class="muted">${esc(why)}</span></div>`;
  }
  b += fwVariantJob(v);
  return panel('BUILD A PRODUCT VARIANT', b);
}

const FW_VAR_SLOT_LABEL = {
  n19: 'Base application (the donor)',
  hub: 'Hub 18.21.4 (Hub application and its files)',
  z8: 'Z8 17.5.8 (camera application)',
  z40: 'Z40 17.5.8 (camera application)',
  n18213: 'Normal 18.21.3 (reference application)',
};

function fwVariantSlots(v){
  const s1 = (v.plan || {}).stage1;
  if (!s1) return '';
  if (s1.mode === 'bundled_support' && s1.complete === true) {
    return kv('Camera support', 'Included and verified')
         + `<p class="muted">Select the donor image. The camera applications and support files are included.</p>`;
  }
  if (s1.mode === 'support_unavailable') return notice(s1.message || 'Camera support files could not be verified.', 'error');
  let b = `<p class="muted">Source images, identified from their contents in `
        + `${esc(s1.folder || 'the donor\'s folder')}:</p>`;
  b += `<div class="kv"><span>Look for them in</span><span>`
     + `<input class="text-input" id="fwVarFolder" style="min-width:300px" `
     + `placeholder="folder holding the source images" value="${esc(v.folder || s1.folder || '')}">`
     + `</span></div>`;
  if (s1.message) b += `<p class="bad">${esc(s1.message)}</p>`;
  (s1.needed || []).forEach(n => {
    const label = FW_VAR_SLOT_LABEL[n.slot] || n.slot;
    const found = (s1.found || {})[n.slot];
    const cands = (s1.candidates || {})[n.slot];
    let val;
    if (found) {
      val = esc(found.name || found.path) + (found.from_donor ? ' <span class="muted">(the donor)</span>' : '');
    } else if (cands && cands.length) {
      const cur = (v.sources || {})[n.slot] || '';
      val = `<select class="fwVarSlot" data-slot="${esc(n.slot)}">`
          + `<option value=""${cur?'':' selected'}>Choose one of ${cands.length}…</option>`
          + cands.map(c => `<option value="${esc(c.path)}"${cur===c.path?' selected':''}>`
                         + `${esc(c.name)}</option>`).join('')
          + `</select>`;
    } else {
      val = `<span class="bad">not found — needs a ${esc(String(n.product).toUpperCase())}`
          + `${n.version ? ' ' + esc(n.version) : ''} image</span>`;
    }
    b += `<div class="kv"><span>${esc(label)}</span><span>${val}</span></div>`;
  });
  return b;
}

function fwVariantSources(v){
  const s1 = (v.plan || {}).stage1;
  if (s1 && s1.mode === 'bundled_support') return s1.complete === true ? {} : null;
  if (!s1 || !(s1.needed || []).length) return null;
  const out = {};
  for (const n of s1.needed) {
    if (n.slot === 'n19') continue;                 // the donor itself
    const f = (s1.found || {})[n.slot];
    const chosen = (v.sources || {})[n.slot];
    if (f) out[n.slot] = f.path;
    else if (chosen) out[n.slot] = chosen;
    else return null;
  }
  return out;
}

function fwVariantRunning(v){ return !!(v.job && v.job.running); }

function fwVariantBuildGate(v, feature){
  if (!feature || feature.state === 'BLOCKED') return {ok:false, why:'Unavailable.'};
  if (!v.plan) return {ok:false, why:'Check the image first.'};
  if (!v.plan.buildable) return {ok:false, why:'This image cannot be built into that product yet.'};
  if (!feature.acknowledged) return {ok:false, why:'Accept the risk above to enable this.'};
  if (!fwVariantSources(v)) return {ok:false, why:(v.plan.stage1 || {}).mode === 'support_unavailable'
    ? 'Camera support files could not be verified.'
    : 'Every source image above has to be found or chosen first.'};
  if (fwVariantRunning(v) || v.starting) return {ok:false, why:'A build is running.'};
  return {ok:true, why:''};
}

const FW_VAR_STAGE_LABEL = {support:'Verify included camera support', extract:'Read the donor and source inputs', gate1:'Gate 1 — rebuild the donor unchanged',
  stage1:'Stage 1 — forward-port the application', verify:'Verify the application',
  staging:'Collect the files to add', gate2:'Gate 2 — build and verify the image'};

function fwVariantJob(v){
  const j = v.job;
  if (!j || (!j.running && !j.result && !(j.stages||[]).length)) return '';
  let b = '';
  if (j.running) b += `<p class="muted">Building ${esc(String(j.target||'').toUpperCase())}. `
                     + `This takes a few minutes and carries on if you leave the page.</p>`;
  const rows = (j.stages || []).map(r => {
    const base = String(r.stage).split(' ')[0];
    const label = (FW_VAR_STAGE_LABEL[base] || base) + String(r.stage).slice(base.length);
    const st = r.status === 'pass' ? 'PASS' : r.status === 'fail' ? 'FAIL' : 'RUNNING…';
    return `<tr><td>${esc(label)}</td><td${r.status==='fail'?' class="bad"':''}>${st}</td></tr>`;
  }).join('');
  if (rows) b += `<table><thead><tr><th>STAGE</th><th>RESULT</th></tr></thead><tbody>${rows}</tbody></table>`;
  const r = j.result;
  if (r && !j.running) {
    if (r.ok && r.image) {
      b += kv('Build result', 'BUILD CHECKS PASSED — hardware qualification is separate')
         + kv('Image', r.image.name || r.image.path)
         + kv('Saved to', r.image.path)
         + kv('SHA-256', r.image.sha256)
         + kv('Size', `${r.image.bytes} bytes`);
      if (r.mkfs_version_note) b += kv('Note', r.mkfs_version_note);
    } else {
      const stage = r.failed_stage ? (FW_VAR_STAGE_LABEL[r.failed_stage] || r.failed_stage) + ': ' : '';
      const why = 'No image. ' + stage + (r.message || r.error || 'the build did not finish');
      b += notice(why, 'error');
      const last = (r.stages || []).filter(x => x.ok === false).slice(-1)[0];
      if (last && advancedOn()) {
        const out = String(last.stderr || last.stdout || '').slice(-1500);
        if (out) b += `<pre class="muted">${esc(out)}</pre>`;
      }
    }
  }
  return b;
}

async function fwVariantPoll(){
  const v = state.fwVariant; if (!v) return;
  if (v.pollTimer) return;
  v.pollTimer = setInterval(async () => {
    const doc = await fetchJson('/api/firmware/builder', true);
    const st = (doc && doc.state) || {};
    v.job = st;
    if (!st.running) { clearInterval(v.pollTimer); v.pollTimer = null; }
    if (state.view === 'firmware') render();
  }, 2000);
}

async function fwVariantBuild(){
  const v = state.fwVariant;
  const sources = fwVariantSources(v);
  if (!sources) return;
  v.starting = true; v.error = null; render();
  const {ok, data} = await rfPost('/api/firmware/variant/build',
                                  {path: v.donor || '', target: v.target, sources});
  v.starting = false;
  if (!ok || !data.ok) { v.error = data; render(); return; }
  v.job = data.state || {running:true, target:v.target, stages:[]};
  render();
  fwVariantPoll();
}

async function fwVariantLoad(){
  const v = state.fwVariant;
  try { v.features = (await fetchJson('/api/experimental/features', true))?.features || []; }
  catch { v.features = []; }
}

async function fwVariantPlan(){
  const v = state.fwVariant;
  v.busy = true; v.error = null; render();
  const {ok, data} = await rfPost('/api/firmware/variant/plan',
                                  {path: v.donor || '', target: v.target,
                                   folder: v.folder || undefined});
  v.busy = false;
  if (ok) { v.plan = data; }
  else { v.plan = null; v.error = data; }
  render();
}

function bindFwVariant(){
  const v = state.fwVariant; if (!v) return;
  const path = $('#fwVarPath');
  if (path) path.addEventListener('input', e => { v.donor = e.target.value; });
  $('#fwVarTarget')?.addEventListener('change', e => {
    v.target = e.target.value; v.plan = null; v.sources = {}; render();
  });
  $('#fwVarBrowse')?.addEventListener('click', async () => {
    // The native dialog returns a PATH. A WebView <input type=file> hands the page
    // file content and never a path, which is no use to a backend that has to open
    // a 17 MB image by name.
    const {ok, data} = await rfPost('/api/firmware/variant/browse', {});
    if (!ok) { v.error = data; render(); return; }
    if (data && data.cancelled) return;            // the operator closed the dialog
    if (data && data.path) {
      v.donor = data.path;
      v.plan = null;                                // a new donor invalidates the old answer
      v.error = null;
      render();
    }
  });
  $('#fwVarPlan')?.addEventListener('click', fwVariantPlan);
  $('#fwVarFolder')?.addEventListener('change', e => {
    v.folder = e.target.value.trim() || null; v.sources = {}; fwVariantPlan();
  });
  $$('.fwVarSlot').forEach(el => el.addEventListener('change', e => {
    v.sources = Object.assign({}, v.sources, {[el.dataset.slot]: e.target.value});
    render();
  }));
  $('#fwVarBuild')?.addEventListener('click', fwVariantBuild);
  $('#fwVarAck')?.addEventListener('change', async e => {
    await rfPost(e.target.checked ? '/api/experimental/acknowledge'
                                  : '/api/experimental/withdraw',
                 {feature: 'firmware_variant_build', accept: true});
    await fwVariantLoad(); render();
  });
}

function renderFirmware(){
  const fw=state.fw;
  let out=pageHead('MANAGE FIRMWARE','UPDATE A UNIT, OR BUILD A PRODUCT VARIANT');
  if(!fw){
    /* THE PAGE HAS TO ASK FOR ITS OWN STATE. Nothing else does on arrival.
       ARRIVING ON A PAGE IS THE REFRESH (VIEW_RELOADS) clears state.fw to null
       on nav, but reloadFirmwarePage() is only registered as a connection-change
       listener -- so after the first load, navigating back to MANAGE FIRMWARE
       cleared the cache and nothing refetched it. The page sat on LOADING VALUES
       until the next connect/disconnect, reported from the bench as the page
       hanging. Same self-loading shape WIDGET MANAGER already uses; the flag stops
       the render loop from starting a second fetch while one is in flight. */
    if(!state.fwLoading){ state.fwLoading=true;
      reloadFirmwarePage().finally(()=>{ state.fwLoading=false; }); }
    out+=loadingValues();
    $('#content').innerHTML=out; return;
  }
  if(state.fwStage==='flashing'){
    $('#content').innerHTML=out+fwProgressPanel();
    return;
  }
  if(state.fwStage==='done'){
    $('#content').innerHTML=out+fwResultPanel()+fwDevicePanel();
    $('#fwDone')?.addEventListener('click',()=>{state.fwStage=null;state.fwResult=null;reloadFirmwarePage()});
    return;
  }
  if(state.fwError){
    out+=fwErrorPanel();
  }
  if(state.fwStage==='confirm'){
    out+=fwConfirmPanel();
    $('#content').innerHTML=out;
    $$('.fwAck').forEach(el=>el.addEventListener('change',()=>{
      const id=el.dataset.ack;
      if(el.checked){ if(!state.fwAck.includes(id)) state.fwAck.push(id); }
      else state.fwAck=state.fwAck.filter(x=>x!==id);
      render();
    }));
    $('#fwApply')?.addEventListener('click',fwApply);
    $('#fwCancel')?.addEventListener('click',()=>{state.fwStage=null;state.fwAck=[];render()});
    $('#fwDone')?.addEventListener('click',()=>{state.fwError=null;render()});
    return;
  }
  if(!(fw.device||{}).firmware){
    out+=notice('Connect a unit to update its firmware. The page is built from the unit it is talking to, so the checks below cannot run until one answers — this is the normal state before a device is plugged in, not a fault. Building a product variant below needs no device.','warn');
  }
  // The action first, above the fold. Everything that explains it is evidence and
  // sits behind ADVANCED -- the previous order put roughly forty rows and a check
  // table between the file picker and the button.
  out+=fwActionPanel();
  out+=fwVariantPanel();
  if(advancedOn()){
    out+=fwDevicePanel();
    out+=fwSelectionPanel();
    if(fw.selection) out+=fwPlanPanel();
    out+=fwEligibilityPanel();
  }
  // Last, and only with ADVANCED on.
  $('#content').innerHTML=out;
  $('#fwPath')?.addEventListener('input',e=>{state.fwPathDraft=e.target.value});
  $('#fwBrowse')?.addEventListener('click',fwBrowse);
  $('#fwValidate')?.addEventListener('click',()=>fwSelect(state.fwPathDraft));
  $('#fwClear')?.addEventListener('click',()=>fwSelect(null,true));
  $('#fwStart')?.addEventListener('click',()=>{state.fwStage='confirm';state.fwAck=[];state.fwError=null;render()});
  $('#fwDone')?.addEventListener('click',()=>{state.fwError=null;render()});
  bindFwVariant();
}

async function reloadFirmwarePage(){
  state.fw=await fetchJson('/api/firmware',true);
  // The experimental feature list is part of this page's state: the risk text and
  // the blocked reason are read from the backend, never written twice in the UI.
  if(!state.fwVariant) state.fwVariant={donor:null,target:'z40',plan:null,
                                        features:null,busy:false,error:null};
  // PAINT AS SOON AS THE PAGE'S OWN STATE LANDS. /api/firmware is host-local and
  // is everything renderFirmware needs; the two reads below are additions to the
  // page and must not hold its first paint -- the variant feature list used to be
  // awaited here, serialising a second fetch in front of a page that was already
  // ready to draw.
  if(state.view==='firmware') render();
  if(state.fwVariant.features===null) fwVariantLoad().then(()=>{
    if(state.view==='firmware') render(); });
  // A build outlives the page. Pick up one already running, without holding
  // the page on the builder document.
  fetchJson('/api/firmware/builder',true).then(d=>{
    const st=d&&d.state; if(!st||!state.fwVariant) return;
    if(st.running||st.result){ state.fwVariant.job=st; if(st.running) fwVariantPoll();
                               if(state.view==='firmware') render(); }
  }).catch(()=>{});
}

async function fwBrowse(){
  const btn=$('#fwBrowse'); if(btn){btn.disabled=true;btn.textContent='WAITING FOR THE FILE DIALOG…'}
  state.fwError=null;
  try{
    const {ok,data}=await rfPost('/api/firmware/browse',{});
    if(!ok||!data.ok){ state.fwError=data||{error:'BROWSE_FAILED'}; render(); return; }
    if(data.cancelled){ render(); return; }
    state.fwPathDraft=data.path;
    await fwSelect(data.path);
    return;
  }catch(e){
    state.fwError={error:'BROWSE_TRANSPORT_FAILED',message:safeErr(e.message||e)};
  }finally{
    if(btn){btn.disabled=false;btn.textContent='BROWSE…'}
  }
  render();
}

async function fwSelect(path,clear){
  state.fwError=null; state.fwStage=null; state.fwAck=[];
  const btn=$('#fwValidate'); if(btn&&!clear){btn.disabled=true;btn.textContent='READING AND HASHING…'}
  const {ok,data}=await rfPost('/api/firmware/select',clear?{clear:true}:{path:path||''});
  if(data&&data.state) state.fw=data.state;
  if(!ok&&!(data&&data.state)) state.fwError=data||{error:'FIRMWARE_SELECT_FAILED'};
  else if(!ok) state.fwError=data;
  if(clear){ state.fwPathDraft=''; }
  render();
}

async function fwApply(){
  const fw=state.fw||{}; const sel=fw.selection||{}; const img=sel.image||{};
  state.fwStage='flashing'; state.fwError=null; state.fwResult=null;
  state.fwProgress={phase:'starting'};
  render();
  const poll=setInterval(async()=>{
    const st=await fetchJson('/api/operation-state',true);
    if(st&&st.progress){ state.fwProgress=st.progress; if(state.fwStage==='flashing') render(); }
  },1000);
  try{
    const {ok,data}=await rfPost('/api/firmware/upgrade',
      {apply:true,expected_image_sha256:img.sha256,acknowledge:state.fwAck});
    if(!ok||!data.ok){ state.fwError=data||{error:'FIRMWARE_UPGRADE_FAILED'}; state.fwStage='confirm'; }
    else { state.fwResult=data; state.fwStage='done'; }
  }catch(e){
    state.fwError={error:'FIRMWARE_UPGRADE_TRANSPORT_FAILED',message:safeErr(e.message||e),
                   evidence:{upgrade_may_have_applied:true}};
    state.fwStage='confirm';
  }finally{
    clearInterval(poll); state.fwProgress=null;
    // Firmware changes invalidate access qualification even when USB returns
    // on the same port/container. Never reuse the pre-flash access prompt.
    state.devSm=null; state.devSmError=null; state.serviceMode=null;state.devSmRequest=null;state.devSmLoading=false;
    state.smActivation=null; state.faPrompt=false; state.faError=null;
    try{
      const cs=await fetchJson('/api/connection-state',true);
      if(cs?.active?.serial_identity) state.activeConnection={connected:true,...cs.active};
    }catch{}
    // Reread on failure too: a failed flash may have applied, and leaving the
    // pre-flash version on screen next to the error is the worst thing to show.
    try{ await reloadFirmwarePage() }catch{}
    render();
  }
}

function batteryWarningsBody(){
  const bw=(state.batteryWarn&&state.batteryWarn.battery_warnings)||{};
  const e=state.battEdit||{};
  const ch=e.chemistry??bw.chemistry??'lipo';
  const src=e.source??bw.source??'preset';
  const cc=String(e.cell_count??bw.cell_count??'auto');
  const lowV=(e.low_mv??bw.low_mv)?((e.low_mv??bw.low_mv)/1000):'';
  const critV=(e.crit_mv??bw.crit_mv)?((e.crit_mv??bw.crit_mv)/1000):'';
  const opt=(v,l,sel)=>`<option value="${v}"${sel===v?' selected':''}>${l}</option>`;
  const cellOpts=['auto','1','2','3','4','5','6']
    .map(v=>opt(v,v==='auto'?'AUTO':v+'S',cc)).join('');
  let b=`<div class="setting-row"><div><h3>Battery warnings</h3>`
    +`<p>Colours the VRX battery voltage shown in the header. Choose your chemistry `
    +`and cell count, or switch to EXACT to type the low and critical volts yourself. `
    +`DC adapter turns the warning off.</p></div><div>`
    +kvControl('Chemistry',`<select class="text-input" id="battChem">`
        +opt('lipo','LiPo',ch)+opt('liion','Li-ion',ch)
        +opt('dc_adapter','DC adapter (no warning)',ch)+`</select>`);
  if(ch!=='dc_adapter'){
    b+=kvControl('Thresholds',`<div class="segmented">`
        +`<button id="battSrcPreset" class="${src==='preset'?'active':''}">PRESET</button>`
        +`<button id="battSrcExact" class="${src==='exact'?'active':''}">EXACT</button></div>`)
      +kvControl('Cell count',`<select class="text-input" id="battCells">${cellOpts}</select>`);
    if(src==='exact')
      b+=kvControl('Low (V)',`<input class="text-input" id="battLow" inputmode="decimal" `
          +`autocomplete="off" value="${esc(String(lowV))}">`)
        +kvControl('Critical (V)',`<input class="text-input" id="battCrit" inputmode="decimal" `
          +`autocomplete="off" value="${esc(String(critV))}">`);
  }
  b+=`<div class="toolbar" style="justify-content:flex-start;margin-top:8px">`
    +`<button class="action" id="battApply">SAVE</button></div></div></div>`;
  if(state.batteryMsg) b+=notice(state.batteryMsg,state.batteryErr?'error':'ok');
  return b;
}

async function applyBatteryWarnings(){
  const g=id=>($('#'+id)||{}).value;
  const ch=g('battChem')||'lipo';
  const src=state.battEdit?.source
    ?? ((state.batteryWarn&&state.batteryWarn.battery_warnings&&state.batteryWarn.battery_warnings.source)||'preset');
  const ccRaw=g('battCells')||'auto';
  const body={chemistry:ch, source:(ch==='dc_adapter'?'preset':src),
              cell_count:(ccRaw==='auto'?'auto':Number(ccRaw))};
  if(ch!=='dc_adapter'&&body.source==='exact'){
    const lv=parseFloat(g('battLow')), cv=parseFloat(g('battCrit'));
    if(!isFinite(lv)||!isFinite(cv)){ state.batteryErr=true;
      state.batteryMsg='Enter both low and critical volts.'; render(); return; }
    body.low_mv=Math.round(lv*1000); body.crit_mv=Math.round(cv*1000);
  }
  const btn=$('#battApply'); if(btn){btn.disabled=true;btn.textContent='SAVING…';}
  const {ok,data}=await rfPost('/api/settings/battery-warnings',body);
  if(!ok||!data.ok){ state.batteryErr=true;
    state.batteryMsg=`NOT SAVED — ${data&&(data.error||data.message)||'unknown error'}`; }
  else{ state.batteryErr=false; state.batteryMsg='BATTERY WARNINGS SAVED.';
    state.batteryWarn={ok:true,battery_warnings:data.battery_warnings,
      presets:(state.batteryWarn&&state.batteryWarn.presets)};
    state.battEdit=null; updateHeader(); }
  render();
}

function networkDevicesBody(){
  if(state.networkDevices===null&&!state.networkDevicesLoading){
    state.networkDevicesLoading=true;
    fetch('/api/network/known-devices',{cache:'no-store'}).then(r=>r.json())
      .then(j=>{state.networkDevices=j;})
      .catch(()=>{state.networkDevices={ok:false,devices:[]};})
      .then(()=>{state.networkDevicesLoading=false; if(state.view==='settings') render();});
  }
  const devs=((state.networkDevices||{}).devices)||[];
  const e=state.networkEdit||{};
  let b=`<div class="setting-row"><div><h3>Network devices</h3>`
    +`<p>Connect to a VRX or Relay by a known IP address over your local network. `
    +`These are operator-asserted IPs — unlike a USB connection they are not `
    +`auto-correlated to a specific unit, so point them only at a unit you know.</p></div><div>`;
  if(devs.length){
    b+=`<table><thead><tr><th>LABEL</th><th>IP</th><th>KIND</th><th>STATUS</th>`
      +`<th>LAPTOP NIC</th><th>FEATURES</th><th>ACTION</th></tr></thead><tbody>`;
    for(const dev of devs){
      const pr=(state.networkProbe||{})[dev.id];
      let status='<span class="muted">—</span>', nic='<span class="muted">—</span>', feats='<span class="muted">—</span>';
      if(pr&&pr._busy){ status='<span class="muted">probing…</span>'; }
      else if(pr){
        status=pr.reachable?valText(val('ON NETWORK','good')):valText(val('NO ANSWER','warnc'));
        nic=pr.nic_resolved?`<code>${esc(String(pr.source_ip))}</code> <span class="muted">if${esc(String(pr.if_index))}</span>`
                           :'<span class="muted">NIC unresolved</span>';
        const on=Object.entries(pr.features||{}).filter(([k,v])=>v===true).map(([k])=>k.replace(/_/g,' '));
        feats=on.length?esc(on.join(', ')):'<span class="muted">none answered</span>';
      }
      b+=`<tr><td class="row-name">${esc(dev.label)}</td><td><code>${esc(dev.device_ip)}</code></td>`
        +`<td>${esc(String(dev.kind||'vrx').toUpperCase())}</td><td>${status}</td><td>${nic}</td><td>${feats}</td>`
        +`<td><button class="secondary" data-net-probe="${esc(dev.id)}">PROBE</button> `
        +`<button class="secondary" data-net-remove="${esc(dev.id)}">REMOVE</button></td></tr>`;
    }
    b+=`</tbody></table>`;
  } else {
    b+=notice('No network devices yet. Add a known VRX/Relay IP below.');
  }
  b+=`<div class="toolbar" style="justify-content:flex-start;margin-top:8px;flex-wrap:wrap">`
    +`<input class="text-input" id="netLabel" placeholder="Label" maxlength="64" value="${esc(e.label||'')}">`
    +`<input class="text-input" id="netIp" placeholder="192.168.1.100" spellcheck="false" value="${esc(e.device_ip||'')}">`
    +`<select class="text-input" id="netKind"><option value="vrx"${e.kind!=='relay'?' selected':''}>VRX</option>`
    +`<option value="relay"${e.kind==='relay'?' selected':''}>Relay</option></select>`
    +`<button class="action" id="netAdd">ADD DEVICE</button></div>`;
  if(state.networkMsg) b+=notice(state.networkMsg,state.networkErr?'error':'ok');
  b+=`</div></div>`;
  return b;
}

function _networkDevicesForSave(){
  return (((state.networkDevices||{}).devices)||[]).map(d=>(
    {id:d.id,label:d.label,device_ip:d.device_ip,kind:d.kind}));
}

async function addNetworkDevice(){
  const label=($('#netLabel')?.value||'').trim();
  const ip=($('#netIp')?.value||'').trim();
  const kind=$('#netKind')?.value==='relay'?'relay':'vrx';
  if(!ip){ state.networkErr=true; state.networkMsg='Enter an IP address.'; render(); return; }
  const id=(label.toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/^-+|-+$/g,''))||ip;
  const devs=_networkDevicesForSave().filter(d=>d.id!==id);
  devs.push({id,label:label||id,device_ip:ip,kind});
  const {ok,data}=await rfPost('/api/network/known-devices',{devices:devs});
  if(!ok||!data.ok){ state.networkErr=true;
    state.networkMsg=`NOT SAVED — ${data&&(data.message||data.error)||'unknown error'}`; }
  else{ state.networkErr=false; state.networkMsg='DEVICE SAVED.';
    state.networkDevices={ok:true,devices:data.devices}; state.networkEdit=null; }
  render();
}

async function removeNetworkDevice(id){
  const devs=_networkDevicesForSave().filter(d=>d.id!==id);
  const {ok,data}=await rfPost('/api/network/known-devices',{devices:devs});
  if(ok&&data.ok){ state.networkErr=false; state.networkMsg='DEVICE REMOVED.';
    state.networkDevices={ok:true,devices:data.devices}; }
  else{ state.networkErr=true; state.networkMsg='REMOVE FAILED.'; }
  render();
}

async function probeNetworkDevice(id){
  const dev=(((state.networkDevices||{}).devices)||[]).find(d=>d.id===id);
  if(!dev) return;
  state.networkProbe={...(state.networkProbe||{}),[id]:{_busy:true}}; render();
  const {data}=await rfPost('/api/network/probe',{device_ip:dev.device_ip});
  state.networkProbe={...(state.networkProbe||{}),[id]:data||{ok:false,error:'PROBE_FAILED'}};
  render();
}

function saveDirBody(){
  const sd=state.saveDir||{}; const d=sd.derived||{};
  let b=`<div class="setting-row"><div><h3>Save directory</h3><p>Local saves are written here: RF and receiver-slot backups and exports. Application settings and local device nicknames always stay in the fixed application-data directory.</p></div><div><input id="saveDirInput" class="text-input" type="text" autocomplete="off" spellcheck="false" value="${esc(sd.path||'')}"><div class="toolbar" style="justify-content:flex-start;margin-top:8px"><button class="action" id="saveDirApply">VALIDATE AND SAVE</button><button class="secondary" id="saveDirReset">RESET TO DEFAULT</button></div></div></div>`;
  b+=kv('Active directory',sd.path||'—')
    +kv('Default directory',sd.default_path||'—')
    +kv('Using default',sd.is_default===undefined?'—':(sd.is_default?'YES':'NO'),false)
    +kv('Directory exists',sd.exists===undefined?'—':(sd.exists?'YES':'NO'),false)
    +kv('Writable now',sd.writable===undefined?'—':(sd.writable?'YES — PROVEN BY A CREATE / WRITE / DELETE PROBE':`NO — ${sd.writable_detail||'reason not reported'}`),false)
    +kv('Setting last changed',sd.updated_at||'NEVER — DEFAULT IN USE')
    +kv('In effect now',sd.in_effect===undefined?'—':(sd.in_effect?'YES':'NO — RESTART REQUIRED'),false)
    +kv('Settings file',sd.settings_file||'—')
    +kv('RF table backups',d.rf_backups||'—')
    +kv('Receiver-slot backups',d.receiver_slot_backups||'—');
  if(state.saveDirError){
    const e=state.saveDirError;
    b+=notice(`DIRECTORY REJECTED — ${e.error||'UNKNOWN'}: ${String(e.message||'').slice(0,240)}`,'error');
  }
  if(state.saveDirOk) b+=notice(state.saveDirOk,'ok');
  // The persisted setting and the directories saves are actually going to are two
  // separate facts. If they disagree, say so rather than show a path nothing uses.
  if(sd.in_effect===false) b+=notice(`THE SAVED SETTING IS NOT IN EFFECT IN THIS SESSION. Saves are currently going to ${String(sd.derived_root||'an earlier directory').slice(0,200)}. Re-apply the directory, or restart the application.`,'warn');
  b+=notice('The path is accepted only after the runtime creates it if needed and proves it writable by writing and deleting a probe file. A rejected path changes nothing.');
  return b;
}

async function applySaveDir(reset){
  const el=$('#saveDirInput'); const btn=$(reset?'#saveDirReset':'#saveDirApply');
  state.saveDirError=null; state.saveDirOk=null;
  if(btn){btn.disabled=true;btn.textContent=reset?'RESETTING…':'VALIDATING…'}
  const body=reset?{reset:true}:{directory:el?el.value:''};
  const {ok,data}=await rfPost('/api/settings/save-directory',body);
  if(!ok||!data.ok){
    state.saveDirError=data||{error:'SAVE_DIR_FAILED'};
    if(data&&data.state) state.saveDir=data.state;
  } else {
    state.saveDir=data.state||state.saveDir;
    state.saveDirOk=reset
      ? 'SAVE DIRECTORY RESET TO THE DEFAULT.'
      : `SAVE DIRECTORY ACCEPTED${data.created?' — DIRECTORY CREATED':''}. FUTURE BACKUPS AND EXPORTS GO HERE.`;
  }
  render();
}

function backgroundImageState(){
  return state.backgroundImage||(state.backgroundImage={busy:false,prepared:null,error:null,message:null});
}

function backgroundImagePanel(){
  const w=backgroundImageState();
  let body='<p>Prepare a 1920×1080 JPEG for the goggles no-signal background.</p>'
    +`<button class="action" id="backgroundChoose"${w.busy?' disabled':''}>${w.busy?'PREPARING…':'CHOOSE IMAGE…'}</button>`;
  if(w.error)body+=notice(w.error,'error');
  if(w.prepared){
    const p=w.prepared;
    body+=kv('Source',`${p.source.width}×${p.source.height}`,false);
    if(p.plan.mode==='crop')body+=notice('The image was centre-cropped to 16:9. Review the preview before saving.');
    body+=`<img alt="Prepared no-signal background" style="max-width:100%;height:auto" src="data:image/jpeg;base64,${esc(p.jpeg_base64)}">`
      +`<div class="toolbar"><button class="action" id="backgroundSave">SAVE JPEG</button><span>${esc(p.filename)}</span></div>`;
  }
  if(w.message)body+=notice(w.message);
  body+=notice('Image preparation runs on this PC. Receiver upload and apply use Service Mode in AC+.');
  return panel('GOGGLES BACKGROUND IMAGE',body);
}

async function prepareBackgroundImage(){
  const w=backgroundImageState();if(w.busy)return;
  w.busy=true;w.error=null;w.message=null;render();
  try{
    const chosen=await fetchJson('/api/wallpaper/browse',false,0,undefined,{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'});
    if(!chosen.cancelled){
      w.prepared=null;
      const prepared=await fetchJson('/api/wallpaper/prepare',false,75000,'Background image preparation timed out.',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({path:chosen.path})});
      if(!prepared.ok||!prepared.prepared||!prepared.jpeg_base64)
        throw Error(prepared.message||'The background image could not be prepared.');
      w.prepared=prepared;
    }
  }catch(e){w.error=humanError(e);}
  finally{w.busy=false;if(state.view==='settings')render();}
}

function saveBackgroundImage(){
  const w=backgroundImageState(),p=w.prepared;if(!p)return;
  const data=Uint8Array.from(atob(p.jpeg_base64),c=>c.charCodeAt(0));
  const url=URL.createObjectURL(new Blob([data],{type:'image/jpeg'}));
  const link=document.createElement('a');link.href=url;link.download=p.filename;link.click();
  setTimeout(()=>URL.revokeObjectURL(url),1000);
  w.message='JPEG download requested.';render();
}

function renderSettings(){
  let out=pageHead('APPLICATION SETTINGS','LOCAL PREFERENCES');
  const theme=document.body.classList.contains('day')?'day':'night';
  out+=`<div class="settings-group">${panel('APPEARANCE',`<div class="setting-row"><div><h3>Theme</h3><p>Night is the default application theme.</p></div><div class="segmented"><button id="nightBtn" class="${theme==='night'?'active':''}">NIGHT</button><button id="dayBtn" class="${theme==='day'?'active':''}">DAY</button></div></div>`
      + `<div class="setting-row"><div><h3>${esc(t('Language'))}</h3>`
      + `<p>Ukrainian, Russian and Simplified Chinese are machine-translated and not yet `
      + `reviewed by a speaker. Anything not yet translated stays in English.</p></div>`
      + `<div><select id="langSel">`
      + Object.entries(i18n.locales()).map(([code,m])=>
          `<option value="${code}"${i18n.locale()===code?' selected':''}>${esc(m.native)}</option>`).join('')
      + `</select></div></div>`)}${panel('LOCAL SAVE DIRECTORY',saveDirBody())}${''}${panel('BATTERY WARNINGS',batteryWarningsBody())}${panel('NETWORK DEVICES',networkDevicesBody())}${''}${panel('CONNECTION',kv('Ground address',state.app?.ground||'192.168.3.102')+`<div class="notice">Ground address is supplied by the launcher in this alpha. Editable connection profiles come after device discovery is qualified.</div>`)}</div>`;
  // Local preparation is available independently of receiver access.
  out+=backgroundImagePanel();
  $('#content').innerHTML=out;
  '';
  '';
  $('#backgroundChoose')?.addEventListener('click',prepareBackgroundImage);
  $('#backgroundSave')?.addEventListener('click',saveBackgroundImage);
  $('#nightBtn').onclick=()=>setTheme('night'); $('#dayBtn').onclick=()=>setTheme('day');
  const ls=$('#langSel'); if(ls) ls.onchange=e=>setLanguage(e.target.value);
  $('#saveDirApply')?.addEventListener('click',()=>applySaveDir(false));
  $('#saveDirReset')?.addEventListener('click',()=>applySaveDir(true));
  // Battery warnings: segmented source + chemistry re-render (to show/hide the
  // exact inputs); SAVE posts. Edits held in state.battEdit until saved.
  $('#battChem')?.addEventListener('change',e=>{
    state.battEdit={...(state.battEdit||{}),chemistry:e.target.value}; render(); });
  $('#battCells')?.addEventListener('change',e=>{
    state.battEdit={...(state.battEdit||{}),
      cell_count:e.target.value==='auto'?'auto':Number(e.target.value)}; });
  $('#battSrcPreset')?.addEventListener('click',()=>{
    state.battEdit={...(state.battEdit||{}),source:'preset'}; render(); });
  $('#battSrcExact')?.addEventListener('click',()=>{
    state.battEdit={...(state.battEdit||{}),source:'exact'}; render(); });
  $('#battApply')?.addEventListener('click',()=>applyBatteryWarnings());
  // NETWORK DEVICES: add / remove / probe (on demand — no device timer).
  $('#netAdd')?.addEventListener('click',()=>addNetworkDevice());
  $('#netLabel')?.addEventListener('input',e=>{state.networkEdit={...(state.networkEdit||{}),label:e.target.value};});
  $('#netIp')?.addEventListener('input',e=>{state.networkEdit={...(state.networkEdit||{}),device_ip:e.target.value};});
  $('#netKind')?.addEventListener('change',e=>{state.networkEdit={...(state.networkEdit||{}),kind:e.target.value};});
  document.querySelectorAll?.('[data-net-probe]')?.forEach?.(btn=>
    btn.addEventListener('click',()=>probeNetworkDevice(btn.dataset.netProbe)));
  document.querySelectorAll?.('[data-net-remove]')?.forEach?.(btn=>
    btn.addEventListener('click',()=>removeNetworkDevice(btn.dataset.netRemove)));
  ;
  $('#widgetDirApply')?.addEventListener('click',()=>'');
  $('#widgetDirReset')?.addEventListener('click',()=>'');
  $('#setupAgain')?.addEventListener('click',async()=>{
    try{ await ''; state.setupRerunError=null; }
    catch(error){ state.setupRerunError=error;render();return; }
    state.setup={doc:null,page:1,draft:{},dirCheck:null,busy:false};
    await Promise.resolve(null);
    render();
  });
}

function netState(){ state.net=state.net||{doc:null,busy:false,error:null,drvBusy:false,drvResult:null}; return state.net; }

const DIAGNOSTICS_READ_TIMEOUT_MS=25000;

async function reloadUsbDriver(){
  const request=state.usbDriverRequest=(state.usbDriverRequest||0)+1;
  try{
    const doc=await fetchJson('/api/usb-driver',true,DIAGNOSTICS_READ_TIMEOUT_MS,
      'USB driver information could not be read in time.');
    if(request===state.usbDriverRequest)state.usbDriver=doc?.error?null:doc;
  }catch(e){if(request===state.usbDriverRequest)state.usbDriver=null;}
}

async function reloadNet(){
  const n=netState(),request=n.request=(n.request||0)+1;
  n.busy=true;n.error=null;
  try{
    const d=await fetchJson('/api/network/adapters',false,DIAGNOSTICS_READ_TIMEOUT_MS,
      'Network adapter information could not be read in time.');
    if(!d||d.error||d.ok===false||typeof d.supported!=='boolean'
       ||(d.supported&&!Array.isArray(d.adapters)))
      throw Error(d?.message||d?.error||'Network adapter information could not be read.');
    if(request===n.request){n.doc=d;n.error=null;}
  }catch(e){if(request===n.request){n.doc=null;n.error=e;}}
  finally{
    if(request===n.request){
      n.busy=false;
      if(state.view==='diagnostics')render();
      // Driver enumeration is independent of the adapter result and its deadline.
      reloadUsbDriver().then(()=>{if(state.view==='diagnostics')render();});
    }
  }
}

function usbDriverSection(){
  const n=netState(); const d=state.usbDriver;
  if(!d||!d.supported||!(d.devices||[]).length) return '';
  let body='';
  (d.devices||[]).forEach(dev=>{
    body+=`<div class="kv"><div class="k">DEVICE</div><div class="v">${esc(dev.name||dev.instance_id||'—')}</div></div>`;
    body+=kv('Windows reports',dev.problem||dev.status||'—',false);
    body+=notice(esc(dev.headline||''),'warn');
    if(dev.remedy==='DESCRIPTOR_CACHE'){
      body+=`<p class="muted">${esc(dev.descriptor_cache?.reason||'')}</p>`;
      body+=`<ul class="muted">${(dev.changes||[]).map(c=>`<li>${esc(c)}</li>`).join('')}</ul>`;
      body+=`<p class="muted">${esc(dev.scope||'')}</p>`;
      body+=`<div class="toolbar" style="justify-content:flex-start">`
        +`<button class="action" data-usb-repair="${esc(dev.instance_id)}"${n.drvBusy?' disabled':''}>`
        +`${esc(dev.action||'REPAIR USB DRIVER')}</button>`
        +`<span class="muted">${n.drvBusy?'Working…':'Windows will ask for Administrator.'}</span></div>`;
    }else{
      body+=notice(esc(dev.manual||drvManual()),'warn');
    }
  });
  if(n.drvResult) body+=usbDriverResult(n.drvResult);
  return panel('USB DRIVER REPAIR',body);
}

function drvManual(){
  return 'Device Manager does the same thing by hand: find the device, Update driver, '
    +'Browse my computer, Let me pick from a list, then choose a driver that lists this '
    +"device's hardware ID.";
}

function usbDriverResult(r){
  const tone={CACHE_CLEARED:'',REBOOT_REQUIRED:'warn',REPLUG_REQUIRED:'warn',
    NOT_APPLICABLE:'warn',ROLLED_BACK:'warn',DESCRIPTOR_STILL_ABSENT:'error',
    DECLINED:'warn',FAILED:'error'}[r.outcome]||'warn';
  const head={CACHE_CLEARED:'Repaired. Windows is reading the receiver again and a network adapter has appeared.',
    REBOOT_REQUIRED:'The receiver answers again, but no network adapter has appeared yet.',
    REPLUG_REQUIRED:'The cached value was cleared. Unplug the receiver and reconnect it.',
    NOT_APPLICABLE:'Nothing to clear — the descriptor cache is not what is stopping this device.',
    ROLLED_BACK:'The cache was not the cause. The original value has been put back.',
    DESCRIPTOR_STILL_ABSENT:'The cache was not the cause, and the original value could not be restored automatically.',
    DECLINED:'Nothing was changed.',FAILED:'The repair did not run.'}[r.outcome]||r.outcome;
  let b=notice(esc(head),tone);
  if(r.reason) b+=`<p class="muted">${esc(r.reason)}</p>`;
  const v=r.verification||{};
  if(r.changed!==undefined) b+=kv('Changed',r.changed?'YES':'NO',false);
  if(r.removed) b+=kv('Value removed',`osvc = ${r.removed}`,false);
  if(v.descriptor_present!==undefined)
    b+=kv('MS_COMP_RNDIS now present',v.descriptor_present?'YES':'NO',false);
  if(v.rndis_driver_applicable!==undefined)
    b+=kv('RNDIS driver applicable',v.rndis_driver_applicable?'YES':'NO',false);
  if(v.adapter_present!==undefined)
    b+=kv('Network adapter present',v.adapter_present?'YES':'NO',false);
  if(r.backup?.path) b+=kv('Backup',r.backup.path,false);
  if(r.manual) b+=notice(esc(r.manual),'warn');
  return b;
}

function netPanel(){
  const n=netState(); const d=n.doc;
  if(n.error) return panel('NETWORK ADAPTERS',notice(humanError(n.error),'error')
    +`<div class="toolbar" style="justify-content:flex-start"><button class="secondary" id="netReload">RETRY</button></div>`);
  if(!d) return panel('NETWORK ADAPTERS',`<p class="muted">Reading…</p>`);
  if(!d.supported) return panel('NETWORK ADAPTERS',notice('Adapter state is a Windows-only read.','warn'))+usbDriverSection();
  const rows=(d.adapters||[]).map(a=>{
    const addr=(a.addresses||[]).map(x=>`${esc(x.ip)}/${x.prefix}`).join(', ')||'—';
    const state=a.ready?'<span class="good">READY</span>'
      :`<span class="bad">${esc((a.problems||[]).join(', ')||'NOT READY')}</span>`;
    const canRepair=!!a.repair&&a.correlated_to_serial;
    const btn=a.repair
      ? `<button class="secondary" data-net-repair="${a.ifindex}"${canRepair?'':' disabled'}>REPAIR</button>`
      : '<span class="muted">—</span>';
    return `<tr><td class="row-name">${esc(a.name||'—')}</td><td>${a.ifindex??'—'}</td>`
      +`<td>${esc(a.status||'—')}</td><td><code>${addr}</code></td>`
      +`<td>${a.correlated_to_serial?'<span class="good">YES</span>':'<span class="muted">NO</span>'}</td>`
      +`<td>${state}</td><td>${btn}</td></tr>`;
  }).join('');
  let body=rows
    ? `<table><thead><tr><th>ADAPTER</th><th>IFINDEX</th><th>STATUS</th><th>IPv4</th><th>CORRELATED</th><th>STATE</th><th></th></tr></thead><tbody>${rows}</tbody></table>`
    : `<p class="muted">No USB network adapter (RNDIS) found. Windows creates one when an Ascent unit is plugged in over USB-C.</p>`;
  if((d.adapters||[]).some(a=>a.repair&&!a.correlated_to_serial))
    body+=notice('REPAIR is offered only for an adapter proven to belong to the SAME physical unit as the serial port in use. Multiple Ascent units expose the same device-side IP, so configuring an uncorrelated adapter can point the host at a different aircraft.','warn');
  if(advancedOn()) body+=kv('Host address',`${d.host_address||'—'}/${d.prefix??''}`,false)
    +kv('Device address',d.device_address||'—',false);
  body+=notice(esc(d.elevation||''));
  body+=`<div class="toolbar" style="justify-content:flex-start"><span class="muted" id="netState"></span></div>`;
  return panel('NETWORK ADAPTERS',body)+usbDriverSection();
}

function bindNet(){
  const n=netState();
  /* RETRY, not REFRESH. It appears only after a failed read, which is a
     different thing from the routine reload that arriving on the page now
     does by itself. */
  const r=$('#netReload');
  if(r) r.onclick=()=>{ n.error=null; n.doc=null; render(); };
  (document.querySelectorAll('[data-usb-repair]')||[]).forEach(b=>{
    b.onclick=async()=>{
      const iid=b.dataset.usbRepair;
      const dev=(state.usbDriver?.devices||[]).find(x=>x.instance_id===iid)||{};
      const lines=(dev.changes||[]).map(c=>'  • '+c).join('\n');
      if(!confirm(`${dev.action||'Repair'} for ${dev.name||iid}?\n\n${lines}\n\n`
        +`${dev.scope||''}\n\nWindows will ask for Administrator.`)) return;
      n.drvBusy=true; n.drvResult=null; render();
      try{
        const res=await fetch('/api/usb-driver/repair',{method:'POST',
          headers:{'Content-Type':'application/json'},
          body:JSON.stringify({instance_id:iid,confirm:true})});
        const d=await res.json();
        if(!res.ok) throw Error(d.message||d.error||`${res.status}`);
        n.drvResult=d;
        // The repair returns the re-read as part of its own result, so the panel
        // below the result is the state after the change, not before it.
        if(d.now) state.usbDriver=d.now;
      }catch(e){ n.drvResult={outcome:'FAILED',reason:humanError(e)}; }
      n.drvBusy=false;
      await reloadNet(); render();
    };
  });
  (document.querySelectorAll('[data-net-repair]')||[]).forEach(b=>{
    b.onclick=async()=>{
      const ifindex=Number(b.dataset.netRepair);
      const a=(n.doc?.adapters||[]).find(x=>x.ifindex===ifindex)||{};
      if(!confirm(`Set ${a.name} (ifIndex ${ifindex}) to ${n.doc.host_address}/${n.doc.prefix}?\n\n`
        +`This ${a.repair?.also||'changes the adapter address'}.\n`
        +`Reversible: ${a.repair?.reversible||'re-enable DHCP in Windows network settings'}.\n\n`
        +`Windows will ask for Administrator.`)) return;
      const st=$('#netState'); if(st) st.textContent='Applying…';
      try{
        const res=await fetch('/api/network/configure',{method:'POST',
          headers:{'Content-Type':'application/json'},
          body:JSON.stringify({apply:true,ifindex})});
        const d=await res.json();
        if(!res.ok) throw Error(d.message||d.error||`${res.status}`);
        await reloadNet(); render();
      }catch(e){ n.error=e; render(); }
    };
  });
}

async function reloadDeviceHistory(){
  const request=state.deviceHistoryRequest=(state.deviceHistoryRequest||0)+1;
  state.deviceHistoryLoading=true;
  try{
    const doc=await fetchJson('/api/device-history',false,DIAGNOSTICS_READ_TIMEOUT_MS,
      'Device history could not be read in time.');
    if(!doc||doc.ok!==true||!Array.isArray(doc.devices))
      throw Error(doc?.message||doc?.error||'Device history could not be read.');
    if(request===state.deviceHistoryRequest)state.deviceHistory=doc;
  }catch(e){
    if(request===state.deviceHistoryRequest)state.deviceHistory={ok:false,message:humanError(e)};
  }finally{
    if(request===state.deviceHistoryRequest){
      state.deviceHistoryLoading=false;
      if(state.view==='diagnostics')render();
    }
  }
}

function deviceHistoryPanel(){
  const d=state.deviceHistory;
  if(d==null&&!state.deviceHistoryLoading)reloadDeviceHistory();
  if(!d) return panel('DEVICE HISTORY',loadingValues());
  if(!d.ok) return panel('DEVICE HISTORY',
    notice(safeErr(d.message||'It could not be read.'),'error')
    +'<button class="secondary" id="histRetry">RETRY</button>');

  const rows=(d.devices||[]);
  let body=kv('Devices remembered',String(d.count||0))
    +kv('Stored at',d.store||'\u2014',false);
  body+=rows.length
    ? `<table><thead><tr><th>PRODUCT</th><th>SERIAL</th><th>BB ID</th>`
      +`<th>FIRMWARE</th><th>UPDATED</th><th>LAST SEEN</th></tr></thead><tbody>`
      +rows.map(r=>`<tr><td class="row-name">${esc(r.product||'\u2014')}</td>`
        +`<td>${esc(r.serial_number||'\u2014')}</td>`
        +`<td><code>${esc(r.bb_id||'\u2014')}</code></td>`
        +`<td>${esc(r.firmware||'\u2014')}</td>`
        /* null is NO CHANGE OBSERVED. Rendered as that and never as "never
           updated": a unit first seen after its update has no before. */
        +`<td>${r.firmware_changed_at
                  ? esc(String(r.firmware_changed_at).replace('T',' ').replace('Z',''))
                    +(r.firmware_previous?`<br><span class="muted">was `
                      +esc(r.firmware_previous)+`</span>`:'')
                  : '<span class="muted">no change seen</span>'}</td>`
        +`<td>${esc(String(r.last_seen||'\u2014').replace('T',' ').replace('Z',''))}</td>`
        +`</tr>`).join('')+`</tbody></table>`
    : '<div class="empty">NOTHING RECORDED YET</div>';
  body+=`<div class="toolbar" style="justify-content:flex-start">`
    +`<button class="secondary" id="histCsv">EXPORT AS CSV</button>`
    +`<button class="secondary" id="histJson">EXPORT AS JSON</button>`
    +`<span class="muted" id="histState"></span></div>`;
  if(d.note) body+=notice(d.note);
  return panel('DEVICE HISTORY',body);
}

function renderDiagnostics(){
 let out=pageHead('DIAGNOSTICS','STOCK PROTOCOL AND HOST STATE');
 out+=deviceHistoryPanel();out+=netPanel();out+=AscentRfDiagnostics.video(vendorRfMetadata(),{panel,kv});
 $('#content').innerHTML=out;bindNet();bindDeviceHistory();
 const n=netState();if(!n.doc&&!n.error&&!n.busy)reloadNet();
}

function liveState(){
  state.live=state.live||{doc:null,busy:false,error:null,result:null,ackNonStock:false};
  return state.live;
}

let _livePollTimer=null;

function stopLivePoll(){
  if(_livePollTimer){ clearInterval(_livePollTimer); _livePollTimer=null; }
}

function startLivePoll(mode){
  stopLivePoll();
  if(mode!=='live') return;
  _livePollTimer=setInterval(async()=>{
    if(state.mode!=='live'){ stopLivePoll(); return; }
    // Only the stick endpoint. reloadLive() also re-reads the CGC document and the
    // OSD, which do not change at this rate and would make the poll expensive.
    try{
      const st=await fetchJson('/api/cgc/hid',true);
      if(st && !st.error){ liveState().hidStream=acceptHidObservation(st); if(state.mode==='live') paintLiveTelemetry(); }
    }catch{ liveState().hidStatusUnavailable=true; if(state.mode==='live') paintLiveTelemetry(); }
  },200);
}

async function reloadLive(){
  const l=liveState();
  try{ l.doc=await fetchJson('/api/cgc/live',true); l.error=null; }
  catch(e){ l.error=e; }
  // The OSD channel is a background reader with its own lifecycle, so its state is
  // polled separately and survives a live re-read.
  try{ l.osd=await fetchJson('/api/cgc/osd',true); }catch{}
  try{ l.hidStream=acceptHidObservation(await fetchJson('/api/cgc/hid',true)); }catch{}
}

function setMode(mode){
  state.mode=mode;
  $('#modeConfiguration')?.classList.toggle('active',mode==='configuration');
  $('#modeLive')?.classList.toggle('active',mode==='live');
  // The sidebar lists Configuration pages. In Live they do not apply, so hide the
  // whole rail nav rather than leave buttons that would switch mode by side effect.
  const nav=$('#nav'); if(nav) nav.classList.toggle('hidden',mode==='live');
  try{ localStorage.setItem('ascent.mode',mode); }catch{}
  render();
  if(mode==='live') reloadLive().then(render);
  startLivePoll(mode);
}

function liveHeaderPanel(){
  const l=liveState(); const e=l.doc?.eligibility;
  let body=kv('Available',e?.eligible?'YES':'NO',false);
  if(advancedOn()) body+=kv('Transport','UDP 9001 — CGC FE/EF control plane',false)
    +kv('Endpoint',e?`${e.endpoint.host}:${e.endpoint.ctrl_port}`:'—')
    +kv('Bound source',e?.binding?`${e.binding.source_ip} (ifIndex ${e.binding.ifindex})`:'NOT BOUND');
  if(e&&!e.eligible) body+=kv('Reasons',(e.reasons||[]).join(', '),false);
  if(advancedOn()) body+=kv('Oracle',e?.oracle||'—',false);
  if(e&&!e.eligible){
    body+=notice('Live control needs the USB network adapter belonging to the SAME physical unit as the serial port, so it can bind the right source address. Multiple Ascent units expose the same device-side IP — destination IP is not identity — so an unbound socket is refused rather than guessed.','warn');
  }
  return panel('LIVE CONTROL PLANE',body);
}

function liveSelfTestPanel(){
  const st=liveState().doc?.self_test; if(!st) return '';

  /* WHEN NOTHING ANSWERED, SAY THAT AND STOP.

     This panel used to print the same four things whatever happened: a verdict
     badge, a paragraph about what "consistent" does and does not prove, a table
     of open research questions keyed L-2/L-3/L-4, and an export button. On a
     read where NOTHING REPLIED, every one of those described the decoding of
     data that did not arrive -- so the operator was handed a research ledger
     when the only fact was "no reply".

     The caveats are real and they are kept. They are evidence about a decoder,
     which is a thing you consult when a number looks wrong, not the first thing
     you meet. They now appear only when there IS something decoded, and only
     with ADVANCED on. */

  if(st.verdict==='no_reply'||!st.replies.length){
    return panel('LIVE READ',
      kv('Result',val('nothing answered','warnc'),false)
      +kv('Asked for',(st.no_reply||[]).join(', ')||'—',false)
      +notice('The receiver did not reply on the control channel. Check that the unit is powered, that USB networking is up, and that this is the unit you meant -- several Ascent units answer on the same address.','warn'));
  }

  /* THE WHOLE SELF-TEST IS ADVANCED, not just its footnotes.

     Half of this panel had already been moved behind ADVANCED -- the note and
     the open-questions table. The three rows left in front of the operator were
     the least useful of the set: a verdict on OUR DECODER rather than on the
     receiver, a reply count, and a list of internal field paths
     (`status.data_rate_mbps`, `power_index.settable_mask`).

     "SUSPECT" means some values we parsed look implausible to us. That is a
     note from the parser to whoever wrote it, and in red, where it reads as a
     fault with the unit. The values an operator actually wants are in LIVE
     READINGS, which is a different panel.

     The no-reply case above stays visible, because "the receiver did not
     answer" IS about the receiver and IS actionable. */
  if(!advancedOn()) return '';

  const badge={suspect:val('SUSPECT','bad'),
               consistent:val('CONSISTENT','good'),
               undecoded:val('UNDECODED','muted')}[st.verdict]||val(st.verdict,'muted');
  let body=kv('Decoder self-test',badge,false)
    +kv('Replies',`${st.replies.length} of ${st.queries_sent}`
      +(st.no_reply.length?` — no reply: ${esc(st.no_reply.join(', '))}`:''),false);
  if(st.suspect_fields.length) body+=kv('Suspect fields',st.suspect_fields.join(', '),false);

  /* The epistemology and the open questions are for someone diagnosing a wrong
     number. ADVANCED is where that person already is. */
  if(advancedOn()){
    body+=notice(esc(st.note),st.verdict==='consistent'?'':'warn');
    if(st.still_open?.length) body+=`<table><thead><tr><th>OPEN</th><th>FIELD</th><th>WHAT TO OBSERVE</th></tr></thead><tbody>`
      +st.still_open.map(o=>`<tr><td class="row-name">${esc(o.id)}</td><td><code>${esc(o.field)}</code></td>`
        +`<td>${esc(o.question)}</td></tr>`).join('')+`</tbody></table>`;
    body+=`<div class="toolbar" style="justify-content:flex-start"><button class="secondary" id="liveExport">EXPORT LIVE CAPTURE</button><span class="muted" id="liveExportState"></span></div>`;
  }
  return panel('LIVE READ',body);
}

async function exportLiveCapture(){
  const el=$('#liveExportState'); if(el) el.textContent='Collecting…';
  try{
    const x=await fetchJson('/api/cgc/live',true);
    const b=new Blob([JSON.stringify(x,null,2)],{type:'application/json'});
    const a=document.createElement('a'); a.href=URL.createObjectURL(b);
    a.download=`ascent_live_capture_${new Date().toISOString().replace(/[:.]/g,'-')}.json`;
    a.click(); setTimeout(()=>URL.revokeObjectURL(a.href),1000);
    if(el) el.textContent='Saved — includes every raw TX/RX frame.';
  }catch(e){ if(el) el.textContent=safeErr(e); }
}

function liveReadPanel(){
  const q=liveState().doc?.queries||{};
  const row=(name,label)=>{
    const x=q[name]||{}; const d=x.reply?.decoded;
    let val='—';
    if(!x.ok) val=humanError(x.error||'UNAVAILABLE');
    else if(x.reply&&!x.reply.ok) val=safeErr(x.reply.message||x.reply.error);
    else if(d&&d.error) val=safeErr(d.message||d.error);
    else if(d) val=JSON.stringify(d);
    return `<tr><td class="row-name">${esc(label)}</td><td><code>${esc(x.command!==undefined?hx(x.command):'—')}</code></td>`
      +`<td>${x.ok&&x.reply?.ok?'<span class="good">REPLY</span>':'<span class="muted">NONE</span>'}</td>`
      +`<td><code>${esc(x.reply?.payload_hex||'—')}</code></td></tr>`;
  };
  // The decoded values are what an operator reads. The raw frame table is the
  // evidence that they are not invented, and it sits behind ADVANCED.
  let body=advancedOn()
    ? `<table><thead><tr><th>QUERY</th><th>CMD</th><th>STATE</th><th>RAW PAYLOAD</th></tr></thead><tbody>`
      +row('channel_hop','CHANNEL / HOP')+row('status','WIRELESS STATUS')+row('power_index','BASEBAND POWER')
      +`</tbody></table>`
    : '';
  const ch=q.channel_hop?.reply?.decoded, st=q.status?.reply?.decoded, pw=q.power_index?.reply?.decoded;
  if(ch&&!ch.error) body+=kv('Band / channel / hop',`${ch.band_label??ch.band} / ${ch.channel} / ${ch.hop_label??ch.hop}`,false);
  if(st&&!st.error){
    body+=kv('RSSI',`${st.rssi1} / ${st.rssi2}`)+kv('Data rate',`${st.data_rate_mbps} Mbps`)
      +kv('Delay',`${st.delay_ms} ms`)+kv('Link',st.connected?'CONNECTED':'NOT CONNECTED',false)
      +kv('Byte 3 (unnamed by the vendor)',st.unknown_byte3);
  }
  if(pw&&!pw.error){
    body+=kv('Power index',`${pw.current_index} — ${pw.current_label}`,false)
      +kv('Device-settable indexes',(pw.settable_indexes||[]).join(', ')||'—');
  }
  if(advancedOn()) body+=noticeDetail('Decoded values here are OURS, not stock. CGC v0.3.5 contains ParseFrequencyResponse, ParseWirelessStatus and ParsePowerIndexResponse and calls none of them — its receive handler validates the envelope and logs the hex. The raw payload column is what the stock tool shows you.');
  return panel('LIVE READINGS',body);
}

function liveKeysPanel(){
  const l=liveState(); const d=l.doc||{};
  const btn=id=>`<button class="secondary" data-livekey="${esc(id)}">${esc(id.replace('_',' '))}</button>`;
  let body=`<div class="toolbar" style="justify-content:flex-start;flex-wrap:wrap">`
    +(d.stock_keys||[]).map(btn).join('')+`</div>`;
  body+=noticeDetail('These seven are the keys the stock tool can send. CGC routes every button and every keyboard binding through VrxRemoteCommand, which has exactly seven members.');
  const extra=d.non_stock_keys||[];
  if(extra.length){
    body+=`<div class="toolbar" style="justify-content:flex-start;flex-wrap:wrap">`
      +`<label class="muted"><input type="checkbox" id="liveAckNonStock"${l.ackNonStock?' checked':''}> ACKNOWLEDGE: NOT STOCK BEHAVIOUR</label>`
      +extra.map(k=>`<button class="secondary" data-livekey="${esc(k)}"${l.ackNonStock?'':' disabled'}>${esc(k.replace('_',' '))}</button>`).join('')
      +`</div>`;
    /* The call-site analysis stays in docs, not in a warning box. What an
       operator needs is the consequence: PAIRING really does disturb a live
       link (measured on a 19.2.14 VRX, 2026-10-04) and the other three have
       never been sent to anything. */
    body+=notice('These four have ZERO call sites in the stock tool, so sending one is beyond parity. PAIRING is measured to disturb a working link. The other three have never been tried on hardware.'
      +'measured to disturb a working link. The other three have never been '
      +'tried on hardware.','warn');
  }
  return panel('REMOTE KEYS',body);
}

function livePowerPanel(){
  const d=liveState().doc||{};
  const cur=d.queries?.power_index?.reply?.decoded?.current_index;
  const opts=(d.power_table||[]).map(e=>
    `<option value="${e.index}"${e.index===cur?' selected':''}>${e.index} — ${esc(e.label)}</option>`).join('');
  let body=`<div class="toolbar" style="justify-content:flex-start;flex-wrap:wrap">`
    +`<select id="livePowerSel">${opts}</select>`
    +`<button class="action" id="livePowerApply">SET POWER INDEX</button></div>`;
  body+=notice('This is an INDEX, not a power \u2014 some entries are AUTO variants at the same milliwatt figure. The milliwatt text is the vendor\u2019s label, not a measurement, and it must not be read against the Sky\u2019s mW-to-dBm table.','warn');
  return panel('BASEBAND POWER',body);
}

function liveModePanel(){
  const d=liveState().doc||{};
  const rows=d.passthrough_labels||[];
  /* It listed the enum with no "nothing selected" entry, so the browser showed
     its first option -- None -- and that read as the current setting. It never
     was one: there IS no read, build_set_mode is the only mode call in the
     protocol. So it opens on a placeholder and says it cannot know. */
  const opts=[`<option value="" selected>\u2014 not read \u2014</option>`].concat(
    rows.map(r=>`<option value="${r.value}">${esc(r.label)}</option>`)).join('');
  let body=`<div class="toolbar" style="justify-content:flex-start;flex-wrap:wrap">`
    +`<select id="liveModeSel">${opts}</select>`
    +`<button class="action" id="liveModeApply">SWITCH PASSTHROUGH</button></div>`;
  /* No "Current setting" row. The protocol has a write for this and no read,
     so the row could only ever say NOT READABLE -- a field that reports
     nothing, taking space on every page load. The placeholder in the selector
     already says the app does not know, and ADVANCED carries the reason. */
  if(advancedOn())
    body+=notice('There is no read for this setting: the protocol has a write '
      +'and nothing to query. Ascent Control cannot show what the VRX is '
      +'currently set to, and will not guess. Check it on the goggles.','warn');
  /* The goggles have their own VRX UART menu and it is NOT established that
     this frame drives it. CGC application modes and the receiver's physical
     UART modes collide numerically and mean different things, so naming this
     list after that menu would turn an unproven correspondence into a claim
     the UI repeats on every page load. */
  /* Unconditional. This is an invariant, not data: CGC application modes and
     the receiver's physical UART modes collide numerically and mean different
     things, and that is true whether or not the backend happened to send the
     goggles' menu. Gating it on a document field meant a panel could render
     without it. */
  const uartMenu=(d.device_uart_menu||[]).join(', ');
  body+=notice('CGC application modes and the receiver\u2019s physical UART modes '
    +'collide numerically and mean different things. This selector is the CGC '
    +'application mode only.'
    +(uartMenu?' The goggles have their own menu headed VRX UART, offering '
      +uartMenu+'; whether this control drives that menu is NOT established, '
      +'so the two are not treated as the same thing.':''),'warn');
  body+=notice('Switches what the device\u2019s serial passthrough carries (frame 0x23, sub-command 2). It does NOT reboot the unit, and the stock tool sends the same frame and waits for no reply \u2014 so nothing here confirms the device accepted it. If the link or OSD does not change, power-cycle the unit and re-read.','warn');
  return panel('SERIAL PASSTHROUGH MODE',body);
}

function liveChannelPanel(){
  const d=liveState().doc||{};
  const ch=d.queries?.channel_hop?.reply?.decoded||{};
  const bands=['A','B','C','D'].map((b,i)=>`<option value="${i}"${ch.band===i?' selected':''}>BAND ${b}</option>`).join('');
  const chans=Array.from({length:(d.channel_max??16)+1},(_,i)=>
    `<option value="${i}"${ch.channel===i?' selected':''}>CH ${i}</option>`).join('');
  /* Three states on 19.2.14, not two, and named the way the goggles name them.
     This offered FIXED/HOPPING and the backend refused anything but 0 or 1, so
     the second hop mode could not be sent at all. */
  const hopRows=d.hop_labels||[{value:0,device_label:'Off',proven:true}];
  // Words only. The value attribute still carries the number because the wire
  // needs one, but the operator never reads it: "Intra-band" is the name on the
  // goggles and "mode 2" is an implementation detail of ours.
  const hops=hopRows.map(h=>`<option value="${h.value}"${ch.hop===h.value?' selected':''}>`
    +`${esc(h.device_label)}</option>`).join('');
  let body=`<div class="toolbar" style="justify-content:flex-start;flex-wrap:wrap">`
    +`<select id="liveBandSel">${bands}</select><select id="liveChanSel">${chans}</select>`
    +`<select id="liveHopSel">${hops}</select>`
    +`<button class="action" id="liveChanApply">SET CHANNEL + HOP</button></div>`;
  if(d.hop_assignment_proven===false)
    body+=notice('Intra-band and Inter-band are the names the goggles use. Which '
      +'of the two this sends has not been confirmed on hardware yet, so they '
      +'may be the other way round. Set one and read the Hop control on the '
      +'goggles to settle it.','warn');
  body+=notice(`Frame 0x50 carries band, channel AND hop state together — the device-side name is SET_CHANNEL_HOP, not "set frequency". The vendor guard is channel 0..${d.channel_max??16}. Changing any of the three can drop the video link; if it does not come back, power-cycle and re-read.`,'warn');
  return panel('CHANNEL AND HOP',body);
}

function liveResultPanel(){
  const l=liveState();
  if(l.error) return notice(humanError(l.error),'error');
  if(!l.result) return '';
  const r=l.result;
  return panel('LAST ACTION',
    kv('Result',r.ok?'FRAME SENT':'FAILED',false)
    +kv('Frame',r.transport?.tx_hex||'—')
    +kv('From',r.transport?.source_ip?`${r.transport.source_ip} (ifIndex ${r.transport.ifindex})`:'—')
    +kv('Beyond stock',r.beyond_stock?'YES':'NO',false)
    +notice(r.note||'Sent fire-and-forget, as the stock tool does. No reply is awaited, so this confirms transmission only — re-read the live values to see whether anything changed.'));
}

function liveOsdPanel(){
  const o=liveState().osd;
  if(!o) return panel('OSD — MSP DISPLAYPORT (UDP 9200)',
    noticeDetail('Not started. UDP 9200 is native MSP: the channel opens with the literal bytes $MSP and the flight controller then pushes frames. Nothing is requested and nothing is acknowledged.')
    +`<div class="toolbar" style="justify-content:flex-start"><button class="action" id="osdStart">START OSD CHANNEL</button></div>`);
  const st=o.stats||{}; const sc=o.screen||{};
  let body=kv('Channel',o.running?'RUNNING':'STOPPED',false)
    +kv('Screens drawn',st.draws??0);
  if(advancedOn()) body+=kv('Endpoint',o.endpoint?`${o.endpoint.host}:${o.endpoint.port}`:'—')
    +kv('Bound source',o.binding?`${o.binding.source_ip} (ifIndex ${o.binding.ifindex})`:'—')
    +kv('Last datagram',o.last_rx||'NONE',false)
    +kv('Grid',`${sc.columns??'—'} × ${sc.rows??'—'} (mode ${sc.mode??'—'})`,false)
    +kv('Datagrams / MSP frames',`${st.datagrams??0} / ${st.frames??0}`)
    +kv('DisplayPort commands',st.displayport??0)
    +kv('Malformed commands',st.issues??0)
    +kv('Unconsumed tail',`${o.tail_bytes??0} bytes`);
  if(o.error) body+=notice(humanError(o.error),'error');
  const rows=sc.text_rows||[];
  const filled=rows.some(r=>r.trim());
  body+=`<pre>${filled?esc(rows.join('\n')):'(nothing received yet — the flight controller has not sent its display)'}</pre>`;
  body+=notice(o.rendering_note||'','warn');
  body+=`<div class="toolbar" style="justify-content:flex-start">`
    +`<button class="secondary" id="osdStop"${o.running?'':' disabled'}>STOP</button>`
    +`<button class="secondary" id="osdStart">${o.running?'RESTART':'START'}</button></div>`;
  return panel('OSD — MSP DISPLAYPORT (UDP 9200)',body);
}

function hostChannel(){
  try{ return (typeof window!=='undefined' && window.chrome && window.chrome.webview) || null; }
  catch{ return null; }
}

function liveVideoSelection(){
  const l=liveState(), profiles=l.doc?.eligibility?.profiles||{};
  const options=l.videoOptions||(l.videoOptions={endpoint:'default',manualUrl:'',transport:'auto',latencyMs:20});
  const ethernet=maxEthernetTarget();
  const profile=ethernet&&(options.endpoint==='default'||options.endpoint==='rj45')
    ?{rtsp_url:'rtsp://'+ethernet.device_ip+'/live.ch01'}
    :options.endpoint==='default'?(profiles.usbc||profiles.rj45):profiles[options.endpoint];
  return {...options,url:options.endpoint==='manual'?options.manualUrl.trim():(profile?.rtsp_url||'')};
}

function liveVideoPanel(){
  const l=liveState(); const v=l.video;
  const host=hostChannel();
  const prof=l.doc?.eligibility?.profiles||{};
  const playback=liveVideoSelection(), url=playback.url;

  /* NO RTSP PANEL ON A RECEIVER THAT SERVES NO RTSP.

     MEASURED 2026-10-10: a port scan of the Industrial Gnd485 at
     192.168.3.102 found 22 and 50000 open and nothing else. Port 554 is
     closed -- it runs no RTSP server. The panel offered
     rtsp://192.168.3.102/live.ch01 anyway, with an OPEN VIDEO WINDOW button,
     on a unit where pressing it can only fail. Reported from the bench as "I
     tried rtsp on industrial and nothing appeared".

     The backend already knows: `eligibility.profiles` carries an rtsp_url only
     for a receiver that has one. An endpoint template is not listener evidence; subtype-gated startup and
     runtime availability are reported separately in diagnostics. */
  if(!maxEthernetTarget()&&!(prof.usbc||prof.rj45||{}).rtsp_url && !advancedOn()) return '';
  // SOURCE IS SHOWN ALWAYS, not behind ADVANCED. Which runtime ran decides whether
  // a bug reproduces, so it is the one technical fact worth an operator's attention:
  // "Bundled" means the copy we ship and test against, "External fallback" means a
  // machine-global install that may be any version with any plugin set.
  /* THE BUTTON IS THE PAGE. Video is what LIVE is for, and the control for it
     was below a renderer name, a component version, a runtime path and a
     GStreamer pipeline string -- four rows an operator cannot act on, in
     front of the one thing they came to press.

     Nothing is deleted: the technical rows move under ADVANCED, which is
     where a support report quotes them from. */
  /* THE BUTTON ONLY EXISTS WHERE IT CAN WORK. Outside the desktop host there
     is no native window for the sink to draw into, so the panel explains
     itself rather than offering a control that cannot do anything -- which
     is what it did before the button moved up here. */
  let body = host
    ? `<div class="toolbar" style="justify-content:flex-start;flex-wrap:wrap">`
      +`<button class="action" id="videoStart"${url?'':' disabled'}>OPEN VIDEO WINDOW</button>`
      +`<button class="secondary" id="videoStop">STOP</button></div>`
    : '';
  if(host){
    const endpoints=[['default','Device default'],...Object.entries(prof).filter(([,p])=>p?.rtsp_url).map(([k])=>[k,k==='usbc'?'USB network':k==='rj45'?'Ethernet':k]),['manual','Manual network endpoint']];
    body+=`<div class="toolbar" style="flex-wrap:wrap"><label>Endpoint <select id="videoEndpoint" class="text-input">${endpoints.map(([k,label])=>`<option value="${esc(k)}"${playback.endpoint===k?' selected':''}>${esc(label)}</option>`).join('')}</select></label>`
      +`<label>Media transport <select id="videoTransport" class="text-input">${[['auto','Automatic'],['tcp','TCP'],['udp','UDP']].map(([k,label])=>`<option value="${k}"${playback.transport===k?' selected':''}>${label}</option>`).join('')}</select></label>`
      +`<label>Buffer <select id="videoBuffer" class="text-input">${[20,100,200,500].map(ms=>`<option value="${ms}"${playback.latencyMs===ms?' selected':''}>${ms} ms</option>`).join('')}</select></label></div>`;
    if(playback.endpoint==='manual') body+=`<label>RTSP endpoint <input id="videoManualUrl" class="text-input" value="${esc(playback.manualUrl)}" placeholder="rtsp://receiver-address/live.ch01"></label><p class="muted">Manual endpoint identity is not verified. Windows routing selects the network interface. For Wi-Fi testing, compare TCP with a 200 ms buffer; these choices affect host playback only.</p>`;
  }
  body+='<div id="liveVideoStatus">';
  body+=kv('Stream',url||'Enter an RTSP endpoint');
  if(v?.playback){
    const label={'decoded-input':'Decoded frames arriving','frames-stale':'Decoded frames stale','waiting-for-frames':'Waiting for decoded frames',starting:'Playback requested',ended:'Stream ended',failed:'Playback failed',warning:'Playback warning','source-timeout':'RTSP source timeout'};
    body+=kv('Video input',label[v.playback.State]||'Unknown',false);
    if(advancedOn()) body+=kv('Buffers reaching video sink',v.playback.SinkBuffers??'—',false)+kv('Decoded format',v.playback.DecodedCaps||'Not observed',false);
  }
  if(advancedOn()){
    body+=kv('Renderer','GStreamer d3d11videosink in a native window',false)
      +kv('Video components',
          v?.source ? (v.version ? `${v.source} — ${v.version}` : v.source) : '—', false)
      +kv('Runtime',v?.runtime||'—',false);
  }
  if(!host){
    body+=notice('Video is only available in the Ascent Control desktop application. This page is not running inside the WebView2 host, so there is no native window for the video sink to draw into.','warn');
    return panel('VIDEO (RTSP)',body+'</div>');
  }
  if(advancedOn() && v?.pipeline) body+=kv('Pipeline',v.pipeline);
  // THE PLAIN SENTENCE FIRST. `plain` is set by the host only when video failed for
  // a reason it could classify -- components missing, a load failure, a plugin gone,
  // an unwritable cache. It never names GStreamer, a path or a plugin, because the
  // operator did not install GStreamer and cannot act on a plugin name. The
  // technical message is kept and shown under ADVANCED, where it is what a support
  // report should quote.
  if(v && !v.ok && v.plain){
    body+=notice(v.plain,'error');
    if(advancedOn() && v.message) body+=notice(safeErr(v.message));
  } else if(v && v.message){
    body+=notice(safeErr(v.message),v.ok===false?'error':'');
  }
  /* NO AIRCRAFT, NO PICTURE -- AND SAY SO BEFORE THE WINDOW OPENS.
     An available receiver RTSP server can run without anything transmitting
     to it, so the stream connects, carries nothing, and the operator gets a
     black window with no explanation. Reported from the bench twice. The link
     state is already read for the header; it was simply never consulted here.
     This is NOT a failure and is not coloured as one: an unlinked receiver
     with no aircraft powered is the normal state on a bench. */
  const link=state.status?.link;
  if(link&&link!=='LINKED'){
    /* WRITTEN WRONG ONCE AND CORRECTED BY THE BENCH THE SAME HOUR.
       The first version said the stream "will connect and stay black until a
       VTX is powered on". That is false: the receiver composites its own
       display into the video output, so an unlinked unit still streams its
       OSD -- the operator was watching MAPSTER over RTSP with no aircraft
       linked at all while this text claimed there was nothing to see.
       What is actually absent is the AIRCRAFT CAMERA. */
    body+=notice('No aircraft is linked, so there is no camera picture. The '
      +'stream still carries the receiver\u2019s own display, so anything on '
      +'screen — MAPSTER, the OSD — appears here.');
  }
  body+=noticeDetail('Video opens in its own window: WebView2 composes above all other content, so it cannot be layered inside this page.');
  return panel('VIDEO (RTSP)',body+'</div>');
}

function acceptHidObservation(document){
  const l=liveState();
  if(!RcSource.accept(l.hidStream?.rc_source,document?.rc_source)) return l.hidStream;
  l.hidStatusUnavailable=false;
  return document;
}

function hidSourceRequest(body){
  const source=liveState().hidStream?.rc_source;
  return {...body,epoch:source?.epoch,descriptor_id:source?.descriptor_id,receiver_token:source?.receiver_token};
}

function rcIdentityPanel(source,compact=false){
  const p=RcSource.present(source);
  if(compact){
    const observed=Number.isFinite(source?.generated_at_ms)?new Date(source.generated_at_ms).toISOString():'not recorded';
    return `<p class="muted">Last host RC status (${esc(observed)}): ${esc(p.input)} · ${esc(p.features.join(' / ')||'No host RC feature assignment')}</p>`;
  }
  const art=RcSource.graphic(source);
  const graphic=art?`<img class="rc-art" src="${esc(art)}" alt="Controller illustration for reported model ${esc(p.name)}" onerror="this.hidden=true;this.nextElementSibling.hidden=false"><span class="rc-art-neutral" hidden>RC</span>`:`<div class="rc-art-neutral" aria-label="Controller artwork unavailable">RC</div>`;
  return panel('RC CONTROLLER',`<div class="rc-identity">${graphic}`
    +`<div><strong>${esc(p.name)}</strong><div>${esc(p.detection)}</div><div class="muted">${esc(p.profile)}</div></div></div>`
    +kv('Manufacturer',source?.manufacturer||'Not reported')
    +kv('Collection',source?.collection_usage_page===1?(source.collection_usage===4?'Joystick':source.collection_usage===5?'Game Pad':'Unknown'):'Not reported')
    +kv('Controls',Number.isInteger(source?.axis_count)&&Number.isInteger(source?.button_count)?`${source.axis_count??0} axes · ${source.button_count??0} buttons${source.hat_count?' · hat detected; mapping unavailable':''}`:'Unknown')
    +kv('Input',p.input)+kv('Mapping',p.mapping)+kv('Output',p.output)
    +kv('Assigned features',p.features.join(' / ')||'None')
    +`<p class="muted">Detection and output do not establish a physical device effect.</p>`);
}

function liveSticksPanel(){
  const l=liveState(); const hid=l.hid; const st=l.hidStream?.stream;
  const host=hostChannel();
  if(!host) return panel('STICKS (HID)',
    notice('Raw HID access needs the desktop application. This page is not running inside the WebView2 host.','warn'));

  let body='<div id="liveHidReader">';
  // The reader half, in the host.
  body+=kv('Reader',!l.hidStatusUnavailable&&l.hidStream?.rc_source?.device_present
      ? `REGISTERED — ${hid?.product||'device'} (${hid?.axisCount??0} axes`
        + `${hid?.buttonCount?`, ${hid.buttonCount} buttons`:''})`
      : 'STOPPED',false)
    +kv('Reports posted',hid?.posted??0);
  if(hid?.lastError) body+=kv('Reader error',safeErr(hid.lastError),false);
  // A REFUSED START WAS COMPLETELY INVISIBLE. The host replies {ok:false,message}
  // when it will not read a device -- too few axes, a path that will not open --
  // and this panel rendered `running`, `posted` and `lastError` but never
  // `message`. lastError stays null in that case because the refusal is a RETURN
  // VALUE, not a stored error, so pressing USE on a device the host declines
  // looked exactly like pressing a dead button. Reported from the bench.
  if(hid && hid.ok === false && hid.message) body+=notice(safeErr(hid.message),'error');
  body+='</div>';
  const devs=hid?.devices;
  if(Array.isArray(devs)){
    body+=devs.length
      ? `<table><thead><tr><th>DEVICE</th><th>VID:PID</th><th>AXES</th><th></th></tr></thead><tbody>`
        +devs.map(d=>`<tr><td class="row-name">${esc(d.Product||d.product||'')}</td>`
          +`<td><code>${esc(((d.VendorId??d.vendorId)||0).toString(16).padStart(4,'0').toUpperCase())}:`
          +`${esc(((d.ProductId??d.productId)||0).toString(16).padStart(4,'0').toUpperCase())}</code></td>`
          +`<td>${esc(d.AxisCount??d.axisCount)}</td>`
          +`<td><button class="secondary" data-hidpath="${esc(d.Path||d.path)}">USE</button></td></tr>`).join('')
        +`</tbody></table>`
      : '<div class="empty">NO HID DEVICE WITH GENERIC DESKTOP AXES WAS FOUND</div>';
  }
  body+=`<div class="toolbar" style="justify-content:flex-start;flex-wrap:wrap">`
    +`<button class="secondary" id="hidList">FIND STICKS</button>`
    +`<button class="secondary" id="hidStop"${hid?.running?'':' disabled'}>STOP READER</button></div>`;

  body+='<div id="liveHidAxes">';
  // Live axes, as the CRSF chain sees them.
  const axes=st?.axes||hid?.lastAxes;
  const inputCurrent=!l.hidStatusUnavailable&&RcSource.present(l.hidStream?.rc_source).input==='Input live';
  if(axes&&axes.length){
    const ch=st?.channels;
    body+=`<table><thead><tr><th>INPUT (HID)</th><th>NORMALIZED 0–2048</th><th>INPUT STATE</th></tr></thead><tbody>`
      +axes.slice(0,8).map((a,i)=>`<tr><td><code>${esc(st?.inputs?.[i]?.logical_channel||st?.inputs?.[i]?.label||`Axis ${i}`)}</code></td><td><code>${esc(a)}</code></td>`
        +`<td>${inputCurrent?'CURRENT':'HISTORICAL / STALE'}</td></tr>`).join('')
      +`</tbody></table>`;
  }

  body+='</div>';
  // Calibration. CGC has none -- its parser trusts the descriptor -- so a stick
  // that does not reach its declared endpoints never produces full CRSF travel.
  const cal=st?.calibration;
  if(hid?.running){
    let cb='';
    if(st?.calibrating){
      cb+=notice('SWEEP EVERY AXIS to its limits, then release the sticks and press MARK CENTRE.','warn');
    }
    cb+='<div id="liveHidCalibration">';
    if(cal){
      cb+=`<table><thead><tr><th>AXIS</th><th>OBSERVED</th><th>TRAVEL</th><th>STATE</th></tr></thead><tbody>`
        +cal.axes.map(a=>`<tr><td><code>${a.axis}</code></td>`
          +`<td><code>${a.observed_min??'—'} … ${a.observed_max??'—'}</code></td>`
          +`<td>${a.travel}</td>`
          +`<td>${a.usable?'<span class="good">CALIBRATED</span>':'<span class="muted">NOT ENOUGH TRAVEL</span>'}</td></tr>`).join('')
        +`</tbody></table>`;
      cb+=kv('Samples',cal.samples)+kv('All axes calibrated',cal.complete?'YES':'NO',false);
      // "NO" IS NOT A BLOCKER AND MUST NOT READ AS ONE.
      //
      // complete gates nothing: AxisCalibration.apply passes an axis without
      // enough observed travel through UNTOUCHED rather than rescaling it from a
      // narrow window, because amplifying noise into full-scale control output is
      // worse than leaving an axis uncalibrated. FINISH is available either way.
      // Reported from the bench as "I'm guessing I can't finish calibration",
      // which is exactly the wrong conclusion to invite.
      if(!cal.complete){
        const stuck=(cal.axes||[]).filter(a=>!a.usable).map(a=>a.axis);
        cb+=notice('You can still press FINISH. An axis that did not move far enough '
          + 'is left uncalibrated and passed through as the device reports it — it is '
          + 'not rescaled from a narrow window, because that would amplify noise into '
          + 'full-scale control output. The axes that did move are calibrated normally.'
          + (stuck.length ? ` Not calibrated: ${stuck.join(', ')}.` : ''));
        // The specific case that produced this report: a hat/POV is a Generic
        // Desktop usage inside the axis range, so it is enumerated as an axis and
        // never sweeps like one. Windows shows it as a POV and counts one fewer
        // axis, which is why the two disagree.
        if(stuck.length && !st.source_identity?.layout)
          cb+=notice('Legacy reader data may include a hat or POV switch, reported as '
            + 'an axis here but cannot sweep like one, so it will always show as not '
            + 'calibrated. Windows counts it separately, which is why it may show one '
            + 'fewer axis than this page.');
      }
    } else cb+='<div class="empty">NOT CALIBRATED — THE DECLARED DESCRIPTOR RANGE IS IN USE</div>';
    cb+='</div>';
    cb+=`<div class="toolbar" style="justify-content:flex-start;flex-wrap:wrap">`
      +(st?.calibrating
        ? `<button class="secondary" id="calCentre">MARK CENTRE</button>`
          +`<button class="action" id="calFinish">FINISH</button>`
        : `<button class="action" id="calStart">CALIBRATE…</button>`)
      +(cal?`<button class="secondary" id="calClear">CLEAR</button>`:'')+`</div>`;
    if(advancedOn()&&cal) cb+=notice(cal.note);
    body+=panel('CALIBRATION',cb).replace(/^<div class="panel">/,'<div class="panel">');
  }

  // Binding editor: assign each channel without hand-writing JSON.
  if(hid?.running&&st){
    const axes=st.axes||[]; const nb=st.source_identity?.layout?.axes?.length??(hid.axisCount||axes.length);
    const rows=(st.channel_map||[]).map(r=>{
      // THE SELECTED VALUE MUST ROUND-TRIP, or APPLY MAP destroys the map.
      //
      // A fixed channel comes back as {source:'fixed', value:992} with no index,
      // so the old expression produced 'fixed' -- which matches no option, so the
      // <select> fell back to "— UNASSIGNED —". Pressing APPLY MAP then read that
      // back and wrote UNASSIGNED for every fixed channel. Load the vendor map on
      // a 7-axis stick and nine channels were wiped by looking at them.
      const cur = !r.assigned ? ''
                : r.source==='fixed' ? `fixed:${r.value}`
                : r.source==='button' ? `button:${r.index}`
                : r.index!==undefined ? `${r.source}:${r.index}`
                : r.source;
      const opt=(val,label)=>`<option value="${esc(val)}"${val===cur?' selected':''}>${esc(label)}</option>`;
      let opts=`<option value=""${r.assigned?'':' selected'}>— UNASSIGNED —</option>`;
      for(let i=0;i<nb;i++) opts+=opt(`axis:${i}`,`${st.inputs?.[i]?.logical_channel||st.inputs?.[i]?.label||`Axis ${i}`} (input ${i})`);
      // THE DEVICE'S REAL BUTTON COUNT, not a hardcoded eight. A
      // transmitter-style controller can have dozens of switches, and offering
      // only the first eight put the rest out of reach for no reason. Falls back
      // to eight only when the host has not reported a count.
      const nbtn=st.source_identity?.layout?.buttons?.length??((hid.buttonCount??0)||8);
      // ONE ENTRY PER BUTTON. Offering each button twice -- once per mode -- made
      // a 27-button controller produce 54 options, which is not a list anyone can
      // use. The mode moved to its own LATCHING column instead, so the source
      // picker answers "which control" and the checkbox answers "how it behaves".
      for(let i=0;i<nbtn;i++) opts+=opt(`button:${i}`,`${l.hidStream?.rc_source?.profile_kind==='edgetx_classic'?`CH${i+9}`:`Button ${i}`} (input ${i})`);
      opts+=opt('fixed:172','Fixed LOW (172)')+opt('fixed:992','Fixed CENTRE (992)')
           +opt('fixed:1811','Fixed HIGH (1811)');
      // A fixed value that is not one of the three presets still has to be
      // selectable, or it would silently become UNASSIGNED on the next apply --
      // the same way every fixed channel used to.
      if(r.source==='fixed' && ![172,992,1811].includes(r.value))
        opts+=opt(`fixed:${r.value}`,`Fixed ${r.value}`);
      // LATCHING is only meaningful for a button: an axis is continuous and a
      // fixed value does not change, so the box is disabled rather than hidden --
      // a column that appears and disappears per row is harder to read than one
      // that is plainly not applicable.
      const isBtn = r.source==='button';
      return `<tr><td><code>${r.channel}</code>${r.channel===5?' <span class="muted">ARM</span>':''}</td>`
        +`<td><select data-mapch="${r.channel}">${opts}</select>`
        // DETECT sits beside the picker rather than in its own column: it is a
        // different way of answering the same question -- "which control drives
        // this channel" -- so it belongs with the control it fills in.
        +`${st.detecting===r.channel
            ? ` <button class="secondary" data-mapdetectcancel="1">MOVE A CONTROL… CANCEL</button>`
            : ` <button class="secondary" data-mapdetect="${r.channel}"${st.detecting?' disabled':''}>DETECT</button>`}`
        +`</td>`
        +`<td><input type="checkbox" data-maplatch="${r.channel}"`
        +`${isBtn&&r.mode==='toggle'?' checked':''}${isBtn?'':' disabled'}></td>`
        +`<td><code data-live-channel="${r.channel}">${esc(st.channels?st.channels[r.channel-1]:'—')}</code></td></tr>`;
    }).join('');
    let eb=`<table><thead><tr><th>OUTPUT 1–16</th><th>SOURCE</th><th>LATCHING</th><th>VALUE</th></tr></thead><tbody>${rows}</tbody></table>`;
    eb+=`<div class="toolbar" style="justify-content:flex-start;flex-wrap:wrap">`
      +`<button class="action" id="mapApply">APPLY MAP</button>`
      +`<button class="secondary" id="mapVendor">FILL FROM AXES IN ORDER</button></div>`;
    eb+=notice('Assign every channel. An unassigned channel refuses the stream rather than being centred, because centre is a real switch position and channel 5 is commonly ARM.');
    /* Was 452 characters. The jitter threshold and the reason LATCHING exists
       are design notes; what an operator needs is what each control does. */
    eb+=notice('DETECT fills a channel from whatever you move next \u2014 sweep '
      + 'a stick or press a button. LATCHING makes a button behave as a switch '
      + 'that stays on, which is what makes ARM usable. APPLY MAP saves what is '
      + 'shown here.');
    body+=panel('CHANNEL BINDING',eb);
  }

  // The transmit half, in the backend.
  // The channel map. No default exists, and the reason is on the page.
  const mapOk=st?.map_complete===true;
  body+='<div id="liveHidMap">';
  body+=kv('Channel map',mapOk?'COMPLETE — 16 of 16 assigned':`INCOMPLETE — channels ${(st?.map_unassigned||[]).join(', ')||'?'} unassigned`,false);
  if(st?.channel_map){
    body+=`<table><thead><tr><th>OUTPUT 1–16</th><th>INPUT SOURCE</th><th>VALUE</th></tr></thead><tbody>`
      +st.channel_map.map(r=>`<tr><td><code>${r.channel}</code>${r.channel===5?' <span class="muted">ARM</span>':''}</td>`
        +`<td>${r.assigned?esc(`${r.source}${r.index!==undefined?' '+r.index:''}`):'<span class="bad">UNASSIGNED</span>'}</td>`
        +`<td><code>${esc(st.channels?st.channels[r.channel-1]:'—')}</code></td></tr>`).join('')
      +`</tbody></table>`;
  }
  if(st?.mapping_revalidation){
    body+=notice('Controller or descriptor changed. Previous mapping is historical; assign and Apply the current inputs before transmitting.','warn');
    body+=`<details><summary>Previous mapping (historical, inactive)</summary><table><thead><tr><th>OUTPUT</th><th>PREVIOUS INPUT</th></tr></thead><tbody>`
      +st.mapping_revalidation.channels.map(r=>`<tr><td>${r.channel}</td><td>${esc(r.assigned?`${r.source} ${r.index??r.value??''}`:'Unassigned')}</td></tr>`).join('')+`</tbody></table></details>`;
  }
  body+='</div>';
  if(!mapOk){
    body+=notice('Assign every output channel before transmitting. Unassigned channels are never centred or zeroed: either can change a switch, including ARM. Filling from axes in order is an explicit camera/gimbal choice, never a default.','warn');
    body+=`<div class="toolbar" style="justify-content:flex-start"><button class="secondary" id="hidVendorMap">FILL FROM AXES IN ORDER (CAMERA / GIMBAL WORK ONLY)</button></div>`;
  }
  body+='<div id="liveHidStream">';
  body+=kv('Stream',RcSource.present(l.hidStatusUnavailable?null:l.hidStream?.rc_source).output,false)
    +kv('Frames sent',st?.frames_sent??0)
    +kv('Stick age',st?.axes_age_ms!=null?`${st.axes_age_ms} ms${st.axes_stale?' — STALE':''}`:'—',false)
    +kv('Stale cut-off',st?`${st.stale_after_ms} ms`:'—',false)
    +kv('Times stopped on stale',st?.stale_stops??0);
  if(st?.halt_reason) body+=notice(safeErr(st.halt_reason),'warn');
  if(st?.last_error) body+=notice(safeErr(st.last_error),'error');
  body+='</div>';
  body+=`<div class="toolbar" style="justify-content:flex-start;flex-wrap:wrap">`
    +`<select id="crsfRate"><option value="50">50 Hz</option><option value="100">100 Hz</option>`
    +`<option value="150">150 Hz</option></select>`
    +`<button class="action" id="crsfStreamStart"${(inputCurrent&&!st?.running&&mapOk)?'':' disabled'}>START TRANSMITTING</button>`
    +`<button class="secondary" id="crsfStreamStop"${st?.running?'':' disabled'}>STOP TRANSMITTING</button></div>`;
  body+=notice('TRANSMISSION STOPS WHEN THE STICKS GO STALE. It does not hold the last position and it does not send centre — centre is a real command, whereas silence lets the receiver’s own configured failsafe take over, which is the one set up for exactly this case. CGC has no staleness handling at all; this is ours.','warn');
  body+=noticeDetail('Input axes use their HID usage identities and normalized range 0–2048. EdgeTX input CH1–CH32 are separate from the 16 ASCENT/CRSF output slots. Output follows the explicit channel map; nothing is assigned or centred automatically.');
  return '<div id="liveRcIdentity">'+rcIdentityPanel(l.hidStatusUnavailable?null:l.hidStream?.rc_source)+'</div>'+panel('STICKS (HID)',body);
}

function liveCrsfPanel(){
  /* A FRAMING PROBE, NOT A FEATURE.

     The panel says so itself: nothing acknowledges a frame, one frame is not a
     control link, there is no joystick reader, and what the button proves is
     that a correctly framed packet reaches the device. That is a test of OUR
     encoder, and the rows beneath it -- sync byte, CRC polynomial, 11-bit
     packing -- are the encoder's specification.

     Useful to whoever is debugging the frame. Nothing an operator can act on,
     and a SEND button on the control channel is not something to leave in
     front of someone who has no reason to press it. */
  if(!advancedOn()) return '';
  const r=liveState().crsf;
  let body=notice('CRSF on UDP 9100 is send-only: ONE FRAME IS NOT A CONTROL LINK. This probe sends one frame; receiver reception and physical effect remain unverified. Use the HID stream for continuous input.','warn');
  body+=kv('Frame','RC_CHANNELS_PACKED — 26 bytes, sync 0xC8, CRC-8 poly 0xD5',false)
    +kv('Channels','16 × 11-bit, little-endian packed',false);
  if(r){
    body+=kv('Last frame',r.frame_hex||'—')
      +kv('Basis',r.basis||'—',false)
      +kv('Sent to',r.endpoint?`${r.endpoint.host}:${r.endpoint.port}`:'—');
  }
  body+=`<div class="toolbar" style="justify-content:flex-start">`
    +`<button class="secondary" id="crsfCentre">SEND ONE CENTRED FRAME</button></div>`;
  return panel('CRSF (UDP 9100)',body);
}

function renderLive(){
  const l=liveState();
  let out=pageHead('LIVE','CGC v0.3.5 CONTROL PLANE — UDP 9001');
  if(maxEthernetTarget()){
    out+=liveVideoPanel()+'<div id="maxEthPanel">'+maxEthernetPanel(true)+'</div>'+liveResultPanel();
    $('#content').innerHTML=out;bindLive();bindMaxEthernet();return;
  }
  if(!l.doc){ out+=notice('READING LIVE STATE…'); $('#content').innerHTML=out; return; }
  /* ADVANCED is reachable here too. The toggle lives in the config nav, which is
     hidden in LIVE, yet several rows below gate on advancedOn() -- so without a
     LIVE-side control the operator could not reveal them without leaving LIVE.
     Same state, same persistence; flipping it re-renders LIVE. */
  out+=`<div class="toolbar" style="justify-content:flex-start"><span class="rf-hint">ADVANCED</span>`
    +`<div class="segmented"><button id="liveAdvOff"${!advancedOn()?' class="active"':''}>OFF</button>`
    +`<button id="liveAdvOn"${advancedOn()?' class="active"':''}>ON</button></div></div>`;
  /* VIDEO FIRST. It is what this page is for, and it was fifth -- below the
     control-plane header, a decoder self-test, a result panel and the raw
     readings. Three of those are ADVANCED-only evidence for somebody chasing
     a wrong number, which is not the person who opened LIVE to look at the
     picture. */
  const ok=l.doc?.eligibility?.eligible===true;
  out+=liveHeaderPanel();
  if(ok) out+=liveVideoPanel();
  out+=liveSelfTestPanel();
  out+=liveResultPanel();
  out+=liveReadPanel();
  if(ok){ out+=liveOsdPanel(); out+=liveKeysPanel();
          out+=liveChannelPanel(); out+=livePowerPanel(); out+=liveModePanel();
          out+='<div id="liveHidControls">'+liveSticksPanel()+'</div>'; out+=liveCrsfPanel(); }
  else out+=notice('Controls are hidden because live control is not available for the selected device. Nothing here would reach the right unit.','warn');
  $('#content').innerHTML=out;
  l.hidControlsKey=liveHidControlsKey();
  bindLive();
}

// Polling must not replace buttons, input drafts or their event handlers.
function liveHidControlsKey(){
  const l=liveState(), st=l.hidStream?.stream;
  return JSON.stringify([l.hidStream?.rc_source?.epoch,l.hid?.running,
    st?.calibrating,!!st?.calibration,st?.detecting,st?.map_complete,
    (st?.channel_map||[]).map(r=>[r.source,r.index,r.value,r.mode,r.assigned])]);
}
function paintLiveVideoStatus(){
  const target=$('#liveVideoStatus'); if(!target)return;
  const fragment=document.createElement('div');fragment.innerHTML=liveVideoPanel();
  const source=fragment.querySelector('#liveVideoStatus');
  if(source)target.innerHTML=source.innerHTML;
}
function paintLiveTelemetry(forceControls=false){
  const l=liveState(), key=liveHidControlsKey();
  const target=$('#liveHidControls');if(!target)return;
  if(forceControls||key!==l.hidControlsKey){
    target.innerHTML=liveSticksPanel();l.hidControlsKey=key;
    bindLiveHid(livePost,liveAction);return;
  }
  const fragment=document.createElement('div');fragment.innerHTML=liveSticksPanel();
  for(const id of ['liveRcIdentity','liveHidReader','liveHidAxes','liveHidCalibration','liveHidMap','liveHidStream']){
    const source=fragment.querySelector('#'+id), destination=$('#'+id);
    if(source&&destination)destination.innerHTML=source.innerHTML;
  }
  for(const id of ['crsfStreamStart','crsfStreamStop','hidStop']){
    const source=fragment.querySelector('#'+id), destination=$('#'+id);
    if(source&&destination)destination.disabled=source.disabled;
  }
  $$('[data-live-channel]').forEach(node=>{
    node.textContent=l.hidStream?.stream?.channels?.[Number(node.dataset.liveChannel)-1]??'—';
  });
}
async function livePost(url,body){
  const r=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify(body||{}),cache:'no-store'});
  const d=await r.json();if(!r.ok)throw Error(d.message||d.error||`${r.status}`);return d;
}
async function liveAction(fn){
  const l=liveState();l.busy=true;l.error=null;render();
  try{l.result=await fn();await reloadLive();}catch(e){l.error=e;}
  l.busy=false;render();
}
function bindLiveHid(post,act){
  const l=liveState();
  $('#hidList')?.addEventListener('click',()=>{
    const h=hostChannel(); if(h) h.postMessage({type:'hid',action:'list'}); });
  $('#hidStop')?.addEventListener('click',()=>{
    const h=hostChannel(); if(h) h.postMessage({type:'hid',action:'stop'}); });
  $$('[data-hidpath]').forEach(b=>b.addEventListener('click',()=>{
    const h=hostChannel(); if(h) h.postMessage({type:'hid',action:'start',path:b.dataset.hidpath}); }));
  $('#crsfStreamStart')?.addEventListener('click',()=>act(async()=>{
    l.hidStream=acceptHidObservation(await post('/api/cgc/hid/stream',
      hidSourceRequest({action:'start',apply:true,rate_hz:Number($('#crsfRate').value)}))); return l.hidStream; }));
  $('#hidVendorMap')?.addEventListener('click',()=>act(async()=>{
    l.hidStream=acceptHidObservation(await post('/api/cgc/hid/vendor-map',hidSourceRequest({apply:true}))); return l.hidStream; }));
  $('#mapVendor')?.addEventListener('click',()=>act(async()=>{
    l.hidStream=acceptHidObservation(await post('/api/cgc/hid/vendor-map',hidSourceRequest({apply:true}))); return l.hidStream; }));
  for(const [id,action] of [['calStart','start'],['calFinish','finish'],
                            ['calCentre','centre'],['calClear','clear']]){
    $('#'+id)?.addEventListener('click',()=>act(async()=>{
      l.hidStream=acceptHidObservation(await post('/api/cgc/hid/calibrate',hidSourceRequest({action}))); return l.hidStream; }));
  }
  // Enable the LATCHING box the moment a button is chosen, rather than only after
  // the next APPLY round trip -- otherwise choosing a button leaves a box that is
  // visibly disabled and the operator cannot tell it will become available.
  $$('[data-mapdetect]').forEach(b=>b.addEventListener('click',()=>act(async()=>{
    l.hidStream=acceptHidObservation(await post('/api/cgc/hid/detect',
      hidSourceRequest({action:'start',channel:Number(b.dataset.mapdetect)}))); return l.hidStream; })));
  $('[data-mapdetectcancel]')?.addEventListener('click',()=>act(async()=>{
    l.hidStream=acceptHidObservation(await post('/api/cgc/hid/detect',{action:'cancel'})); return l.hidStream; }));
  $$('[data-mapch]').forEach(sel=>sel.addEventListener('change',()=>{
    const box=$(`[data-maplatch="${sel.dataset.mapch}"]`);
    if(!box) return;
    const isBtn=String(sel.value||'').startsWith('button:');
    box.disabled=!isBtn;
    if(!isBtn) box.checked=false;
  }));
  $('#mapApply')?.addEventListener('click',()=>act(async()=>{
    // Read every selector into the 16-entry map the backend expects.
    const channels=Array(16).fill(null);
    $$('[data-mapch]').forEach(sel=>{
      const ch=Number(sel.dataset.mapch); const v=sel.value;
      if(!v) return;
      const [kind,num]=v.split(':');
      const latch=$(`[data-maplatch="${ch}"]`)?.checked===true;
      channels[ch-1]= kind==='fixed' ? {source:'fixed',value:Number(num)}
        : kind==='button' ? {source:'button',index:Number(num),
                             mode: latch ? 'toggle' : 'momentary',
                             low:172,high:1811}
        : {source:'axis',index:Number(num)};
    });
    l.hidStream=acceptHidObservation(await post('/api/cgc/hid/map',hidSourceRequest({channels}))); return l.hidStream; }));
  $('#crsfStreamStop')?.addEventListener('click',()=>act(async()=>{
    l.hidStream=acceptHidObservation(await post('/api/cgc/hid/stream',{action:'stop'})); return l.hidStream; }));
}

function bindLive(){
  const l=liveState();
  const ex=$('#liveExport'); if(ex) ex.onclick=exportLiveCapture;
  $('#liveAdvOff')?.addEventListener('click',()=>setAdvanced(false));
  $('#liveAdvOn')?.addEventListener('click',()=>setAdvanced(true));
  const post=livePost, act=liveAction;

  $('#osdStart')?.addEventListener('click',()=>act(async()=>{
    await post('/api/cgc/osd',{action:'start'}); l.osd=await fetchJson('/api/cgc/osd',true); return l.result; }));
  $('#osdStop')?.addEventListener('click',()=>act(async()=>{
    await post('/api/cgc/osd',{action:'stop'}); l.osd=await fetchJson('/api/cgc/osd',true); return l.result; }));
  $('#crsfCentre')?.addEventListener('click',()=>act(async()=>{
    l.crsf=await post('/api/cgc/crsf',{apply:true}); return l.crsf; }));
  const prof=l.doc?.eligibility?.profiles||{};
  for(const [id,key] of [['videoEndpoint','endpoint'],['videoTransport','transport'],['videoBuffer','latencyMs']]){
    $('#'+id)?.addEventListener('change',e=>{liveVideoSelection();l.videoOptions[key]=key==='latencyMs'?Number(e.target.value):e.target.value;render();});
  }
  $('#videoManualUrl')?.addEventListener('input',e=>{liveVideoSelection();l.videoOptions.manualUrl=e.target.value;const button=$('#videoStart');if(button)button.disabled=!e.target.value.trim();});
  $('#videoStart')?.addEventListener('click',()=>{
    const h=hostChannel(); if(!h) return;
    const playback=liveVideoSelection();
    l.video={ok:null,message:'Opening the video window…'};paintLiveVideoStatus();
    try{h.postMessage({type:'video',action:'start',url:playback.url,transport:playback.transport,latencyMs:playback.latencyMs});}
    catch(e){l.video={ok:false,message:'Unable to open the video window: '+safeErr(e)};paintLiveVideoStatus();}
  });
  bindLiveHid(post,act);
  $('#videoStop')?.addEventListener('click',()=>{
    const h=hostChannel(); if(!h) return;
    h.postMessage({type:'video',action:'stop'});
  });
  $('#liveAckNonStock')?.addEventListener('change',ev=>{ l.ackNonStock=!!ev.target.checked; render(); });
  $$('[data-livekey]').forEach(b=>b.addEventListener('click',()=>act(()=>
    post('/api/cgc/key',{key:b.dataset.livekey,acknowledge_non_stock:l.ackNonStock}))));
  $('#livePowerApply')?.addEventListener('click',()=>act(()=>
    post('/api/cgc/power',{apply:true,index:Number($('#livePowerSel').value)})));
  $('#liveModeApply')?.addEventListener('click',()=>{
    // The placeholder carries value="", and Number("") is 0 -- which is a real
    // mode (None). Sending it because nobody chose anything would change the
    // device by accident, so an empty selection is refused here.
    const raw=$('#liveModeSel')?.value;
    if(raw===''||raw==null){
      liveState().error='Choose a mode first. Nothing was sent.';
      render(); return;
    }
    act(()=>post('/api/cgc/mode',{apply:true,mode:Number(raw)}));
  });
  $('#liveChanApply')?.addEventListener('click',()=>act(()=>
    post('/api/cgc/channel',{apply:true,band:Number($('#liveBandSel').value),
      channel:Number($('#liveChanSel').value),hop:Number($('#liveHopSel').value)})));
}

async function reloadRepeater(){
  const context=receiverReadToken();
  const d=await fetchJson('/api/repeater',true);
  if(context!==receiverReadToken())return;
  state.repeater=(d&&!d.error&&d.ok!==false)?d:null;
  state.repeaterError=state.repeater?null:(d?.message||d?.error||null);
}

function repeaterOpsTable(ops){
  return `<table><thead><tr><th>OPERATION</th><th>OPCODE</th><th>EVIDENCE</th>`
    +`<th>READBACK</th><th>OFFERED</th></tr></thead><tbody>`
    +(ops||[]).map(o=>`<tr><td>${esc(o.name)}${o.writes?' <span class="muted">(write)</span>':''}</td>`
      +`<td><code>${esc(o.opcode)}</code></td>`
      +`<td>${valText(val(o.confidence,o.confidence==='HIGH'?'good':'warnc'))}</td>`
      +`<td class="muted">${esc(o.readback?`${o.readback} (${o.readback_confidence})`:'—')}</td>`
      +`<td>${valText(val(o.offered?'YES':'NO',o.offered?'good':'muted'))}`
      +(o.why_not?`<div class="muted">${esc(o.why_not)}</div>`:'')+`</td></tr>`).join('')
    +`</tbody></table>`;
}

function renderRepeater(){
  if(state.activeConnection?.network_target?.kind==='repeater'){
    $('#content').innerHTML=pageHead('REPEATER','ETHERNET CONTROL')+repeaterNetworkPanel();
    bindRepeaterNetwork();return;
  }
  const d=state.repeater;
  if(!d&&!state.repeaterError&&!state.repeaterLoading){
    state.repeaterLoading=true;
    reloadRepeater().then(()=>{ state.repeaterLoading=false;
      if(state.view==='repeater') render(); });
  }
  let body='';
  if(!d){
    body=notice('Repeater state is unavailable.'+(state.repeaterError
         ?' '+safeErr(state.repeaterError):''),'warn');
    $('#content').innerHTML=pageHead('REPEATER','RELAY / REPEATER CONTROL')
      +panel('REPEATER',body);
    return;
  }

  if(d.device){
    body+=kv('Device',`${d.device.device_name||'—'}  ·  serial ${d.device.serial_number||'—'}`,false)
        +kv('Firmware',d.device.firmware||'—',false);
  }
  body+=kv('State',val(d.state.replace(/_/g,' '),
        d.state==='READY'?'good':'muted'),false);
  body+=notice(safeErr(d.message||''),d.state==='READY'?'warn':'');

  /* Said on every paint. The decode is static analysis, and a page that does not
     keep saying so is one an operator eventually reads as tested. */
  if(d.hardware_verified===false){
    body+=notice('Receiver command table — NOT VERIFIED ON HARDWARE. These commands come from a disassembly; none has been sent by this build.','warn');
  }

  body+=repeaterNetworkPanel();
  body+='';

  body+=repeaterOpsTable(d.operations);

  if(d.state==='READY'){
    const live=(d.operations||[]).filter(o=>o.offered&&!o.writes);
    body+=`<div class="toolbar" style="justify-content:flex-start">`
      +live.map(o=>`<button class="action" data-rep-read="${esc(o.opcode)}">READ ${esc(o.name)}</button>`).join('')
      +`</div>`;
  }

  if(state.repeaterResult){
    const r=state.repeaterResult;
    let rb='';
    if(r.ok===false){
      rb=kv('Refused',val(r.error||'REFUSED','bad'),false)+notice(safeErr(r.message||''),'error');
    }else{
      const x=r.response||{};
      rb=kv('Opcode',x.name||'—',false)
        +kv('Status',val(x.status_text||'—',x.ok?'good':'warnc'),false);
      if(x.bb_power!==undefined) rb+=kv('Relay baseband power',String(x.bb_power),false);
      if(x.not_relay_mode) rb+=notice('This receiver is not in a relay mode. No command from this application can change that: relay mode is provisioned out of band and the unit exits after doing it. Retrying will not help.','error');
      if(x.unverified) rb+=notice('This reading came from an operation whose opcode is inferred rather than observed. Treat the value as unconfirmed.','warn');
    }
    body+=panel('RESULT',rb+`<div class="toolbar" style="justify-content:flex-start">`
      +`<button class="secondary" id="repClear">CLOSE</button></div>`);
  }

  $('#content').innerHTML=pageHead('REPEATER','RELAY / REPEATER CONTROL')
    +panel('REPEATER',body);
  bindRepeater();
  bindRepeaterNetwork();
  '';
}

function repeaterNetworkState(){
  if(!state.repeaterNetwork) state.repeaterNetwork={ip:'',busy:false,result:null,error:null};
  const target=state.activeConnection?.network_target;
  const key=target?.connection_token;
  if(target?.kind==='repeater'&&state.repeaterNetwork.targetKey!==key){
    state.repeaterNetwork={ip:target.device_ip,busy:false,result:target.observed||null,error:null,targetKey:key};
  }
  return state.repeaterNetwork;
}

function repeaterNetworkPanel(){
  const n=repeaterNetworkState(), d=n.result;
  const target=state.activeConnection?.network_target;
  let body='<p class="muted">Enter the Relay Ethernet address. USB and Service Mode are not required.</p>';
  body+=`<div class="toolbar" style="gap:12px 16px;margin:12px 0 16px;align-items:flex-end"><label style="display:flex;flex-direction:column;gap:8px">Relay IPv4 address<input id="repNetworkIp" value="${esc(n.ip)}" placeholder="192.168.1.105"${n.busy||n.actionBusy||target?' disabled':''}></label>`
    +`<button class="action" id="repNetworkRead"${n.busy||n.actionBusy?' disabled':''}>${n.busy?'READING…':'READ ETHERNET STATUS'}</button></div>`;
  if(n.error) body+=notice(humanError(n.error),'error');
  if(d){
    if(target?.requires_reconnect)body+='<details><summary>LAST READ BEFORE RECONNECT</summary>';
    body+=kv('Read from',`${d.device_ip} · PC ${d.source_ip||'—'} · interface ${d.if_index??'—'}`,false)
      +kv('Observed at',d.captured_at||'—',false)
      +(target?'<p class="muted">This connection uses Ethernet only.</p>':'<p class="muted">Selected IP, independent of USB. Bind and swap buttons below use USB.</p>');
    if(d.factory) body+=kv('Factory serial',d.factory.factory_serial,false)+kv('Saved role mode',String(d.factory.cur_mode),false);
    else body+=notice('Factory read failed: '+safeErr(d.factory_error||'No reply.'),'warn');
    const rows=Object.values(d.qos?.radios||{});
    if(rows.length){
      body+=`<table><thead><tr><th>Radio</th><th>Local BBID</th><th>Frequency (MHz)</th><th>Reported throughput (kb/s)</th></tr></thead><tbody>`
        +rows.map(r=>`<tr><td>${esc(r.work_id)}</td><td>${esc(r.local_mac||'—')}</td><td>${esc(r.frequency_mhz??'—')}</td><td>${esc(r.throughput_kbps??'—')}</td></tr>`).join('')+`</tbody></table>`
        +'<p class="muted">Aircraft/VRX sides and active RF link are not verified by these replies.</p>'
        +'<details><summary>RADIO DIAGNOSTICS</summary>'
        +rows.map(r=>kv('Radio '+r.work_id+' raw codes',`Role ${r.role_raw??'—'} · link ${r.link_state??'—'} · MCS code ${r.mcs_encoded_raw??'—'}`,false)).join('')+'</details>';
      for(const r of rows){
        const errors=Object.entries(r.errors||{});
        if(errors.length) body+=notice('Work ID '+r.work_id+': '+errors.map(([k,v])=>k+': '+safeErr(v)).join('; '),'warn');
      }
    }
    if(!d.reachable) body+=notice('Ethernet unavailable; state unknown.','warn');
    if(target?.requires_reconnect)body+='</details>';
  }
  if(target?.kind==='repeater'){
    const waiting=Date.now()<(n.nextControlAt||0);
    const ready=d?.factory&&['0','1'].every(k=>d?.qos?.radios?.[k]?.status_ok);
    const disabled=n.busy||n.actionBusy||waiting||target.requires_reconnect||!ready;
    body+=`<div class="toolbar"><button class="action" data-rep-network-action="hf"${disabled?' disabled':''}>HF BIND</button>`
      +`<button class="action" data-rep-network-action="mf"${disabled?' disabled':''}>MF BIND</button>`
      +`<button class="secondary" id="repNetworkSwap"${disabled?' disabled':''}>REVERSE ROLES…</button></div>`;
    if(n.confirmSwap&&!disabled)body+=`<p>Reverse roles on ${esc(target.device_ip)}? The Relay will reboot.</p><div class="toolbar"><button class="action" data-rep-network-action="swap">CONFIRM REVERSE AND REBOOT</button><button class="secondary" id="repNetworkSwapCancel">CANCEL</button></div>`;
    if(n.actionBusy)body+=kv('Ethernet action',n.actionBusy==='swap'?'Saving role change and requesting reboot…':'Sending '+n.actionBusy.toUpperCase()+' bind · five-second hold…',false);
    if(waiting)body+='<p class="muted">Wait for the bind window to finish before another control.</p>';
    const result=n.actionResult||target.last_action;
    if(result){
      body+=panel('LAST ETHERNET ACTION',kv('Target',result.device_ip||target.device_ip,false)
        +kv('Result',result.ok===false?humanError(result.message||result.error):result.requires_reconnect?'Role change saved; reboot requested. Reconnect when the Relay returns.':'Request acknowledged. Check the receiver LED; pairing is not verified.',false));
    }
  }
  return panel('ETHERNET CONNECTION AND QOS',body);
}

function bindRepeaterNetwork(){
  const n=repeaterNetworkState();
  $('#repNetworkIp')?.addEventListener('input',e=>{n.ip=e.target.value;n.result=null;n.error=null;});
  $('#repNetworkRead')?.addEventListener('click',async()=>{
    n.ip=($('#repNetworkIp')?.value||'').trim();n.busy=true;n.error=null;n.result=null;render();
    try{
      const response=await fetch('/api/repeater/network-read',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({device_ip:n.ip}),cache:'no-store'});
      const result=await response.json();
      if(!response.ok||result.ok===false)n.error=result.message||result.error||'Ethernet read failed.';
      else{
        n.result=result;
        if(result.requires_reconnect&&state.activeConnection?.network_target){state.activeConnection.network_target.requires_reconnect=true;updateHeader();}
      }
    }catch(e){n.error='Ethernet read did not complete: '+(e?.message||e);}
    n.busy=false;if(state.view==='repeater')render();
  });
  $('#repNetworkSwap')?.addEventListener('click',()=>{n.confirmSwap=true;render();});
  $('#repNetworkSwapCancel')?.addEventListener('click',()=>{n.confirmSwap=false;render();});
  document.querySelectorAll?.('[data-rep-network-action]')?.forEach?.(button=>button.addEventListener('click',async()=>{
    const target=state.activeConnection?.network_target;
    const action=button.dataset.repNetworkAction;
    const key=target?.connection_token;
    if(!key||n.actionBusy)return;
    n.actionBusy=action;n.confirmSwap=false;n.actionResult=null;render();
    try{
      const response=await fetch('/api/repeater/network-control',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action,connection_token:key,confirm_reboot:action==='swap'}),cache:'no-store'});
      const result=await response.json();
      if(state.activeConnection?.network_target?.connection_token!==key)return;
      n.actionResult=result;
      if(result.requires_reconnect){const current=state.activeConnection.network_target;current.requires_reconnect=true;current.last_action=result;updateHeader();}
      if(result.wait_seconds){n.nextControlAt=Date.now()+result.wait_seconds*1000;setTimeout(()=>{if(state.view==='repeater'&&state.activeConnection?.network_target?.connection_token===key)render();},result.wait_seconds*1000+100);}
    }catch(error){if(state.activeConnection?.network_target?.connection_token===key)n.actionResult={ok:false,message:'The request did not complete; receiver outcome is unknown. Check the LED before trying again.'};}
    finally{n.actionBusy=null;if(state.view==='repeater')render();}
  }));
}

function bindRepeater(){
  $('#repClear')?.addEventListener('click',()=>{ state.repeaterResult=null; render(); });
  document.querySelectorAll?.('[data-rep-read]')?.forEach?.(b=>{
    b.addEventListener('click',async()=>{
      const op=parseInt(b.dataset.repRead,16);
      try{
        const r=await fetch('/api/repeater/read',{method:'POST',
          headers:{'Content-Type':'application/json'},
          body:JSON.stringify({opcode:op}),cache:'no-store'});
        state.repeaterResult=await r.json();
      }catch(e){ state.repeaterResult={ok:false,error:'REQUEST_FAILED',
        message:'The read did not complete.'}; }
      render();
    });
  });
}

function render(){
 if(state.mode==='live'){renderLive();return;}
 const views={device:renderDevice,firmware:renderFirmware,rf:renderRf,hub:renderHub,rc:renderRc,fleet:renderFleet,repeater:renderRepeater,settings:renderSettings,diagnostics:renderDiagnostics};
 applyNavVisibility();(views[state.view]||renderDevice)();
}

async function fetchJson(url, allowError=false, timeoutMs=0, timeoutMessage='Status read timed out; current receiver state is unknown.', requestOptions={}){
  const controller=timeoutMs>0&&typeof AbortController!=='undefined'?new AbortController():null;
  let timer=null,timedOut=false;
  try{
    const read=(async()=>{
      const r=await fetch(url,{cache:'no-store',...requestOptions,...(controller?{signal:controller.signal}:{})});
      const d=await r.json();
      if(!r.ok&&!allowError) throw Error(d.error||`${r.status}`);
      return d;
    })();
    return timeoutMs>0?await Promise.race([read,new Promise((_,reject)=>{
      timer=setTimeout(()=>{timedOut=true;controller?.abort();reject(Error(timeoutMessage));},timeoutMs);
    })]):await read;
  }catch(e){
    const error=(timedOut||controller?.signal.aborted)?Error(timeoutMessage):e;
    if(allowError)return {error:String(error)};
    throw error;
  }finally{if(timer!==null)clearTimeout(timer);}
}

function setConnectButton(mode, detail){
  const b=$('#connectBtn'); if(!b) return;
  const spec={
    idle:      ['CONNECT',          'action',    false],
    detected:  ['CONNECT',          'action',    false],
    connecting:['CONNECTING…',      'secondary', true ],
    connected: ['DISCONNECT',       'secondary', false],
    failed:    ['CONNECT — RETRY',  'action',    false],
    none:      ['CONNECT',          'action',    true ],
  }[mode] || spec_default();
  setLabel(b, spec[0]);        // not b.textContent -- see setLabel()
  b.className=spec[1];
  b.disabled=spec[2];
  b.title=detail||'';
}

function spec_default(){ return ['CONNECT','action',false]; }

function showConnectProblem(message){
  const k=$('#deviceKicker'), n=$('#deviceName');
  if(k) k.textContent='CONNECT FAILED';
  if(n) n.textContent=safeErr(message);
}

async function refreshConnections(){
  state.connections=await fetchJson('/api/connections',true);
  const sel=$('#connectionSelect'); if(!sel)return;
  const prev=sel.value||'auto'; const cs=state.connections?.candidates||[];
  const profiles=state.connections?.network_profiles||[];
  // AUTO must name the ACTIVE device when one is connected, not merely the first detected
  // candidate -- otherwise, with two Ascent devices present (e.g. a VRX on COM10 and a VTX
  // on COM21), the selector could label itself one device while Device Info shows another.
  const activeId=state.connections?.active_candidate_id;
  const activeCand=activeId?[...cs,...profiles].find(c=>c.id===activeId):null;
  const autoLabel=activeCand?activeCand.label:(cs.length?cs[0].label:'NO ASCENT DEVICE');
  sel.innerHTML=`<option value="auto">AUTO — ${esc(autoLabel)}</option>`+cs.map(c=>`<option value="${esc(c.id)}">${esc(c.label)}</option>`).join('')
    +profiles.map(c=>`<option value="${esc(c.id)}">${esc(c.label)} · ${esc(c.device_ip)}</option>`).join('');
  if([...sel.options].some(o=>o.value===prev)) sel.value=prev;
  if(!state.connectionSelectorInitialized&&String(activeId||'').startsWith('network:'))sel.value=activeId;
  state.connectionSelectorInitialized=true;
  const first=cs[0];
  // THE BACKEND OWNS WHETHER A SESSION IS OPEN. connection_inventory() reports
  // active_candidate_id = SESSION.device.candidate_id only while SESSION.connected,
  // and null otherwise. A unit that was connected and has since dropped (unplugged,
  // or a session the backend closed) shows up here as null while state.activeConnection
  // still says connected -- and nothing was reconciling the two, so the header kept
  // naming the gone unit and the CONNECT/DISCONNECT button stayed on DISCONNECT,
  // clickable, with nothing to disconnect. Clear the stale local belief (unless a
  // connect is mid-flight, or the inventory itself failed and cannot speak to it) and
  // let the not-connected branches below repaint the strip and the button.
  // === null, not == null: connection_inventory ALWAYS carries this key (null only
  // when no session is open), so an explicit null is the real disconnect signal.
  // An ABSENT key means "this response cannot speak to it" (the 503 error path, or
  // a partial document) and must NOT be read as a disconnect.
  if(state.activeConnection?.connected && !state.connecting
     && state.connections && !state.connections.error
     && state.connections.active_candidate_id===null){
    state.activeConnection=null;
    const batt=$('#deviceBattery'); if(batt) batt.innerHTML='';  // connected-only readout
    // RE-ARM AUTO-CONNECT on a genuine disconnect edge. autoConnectTried latches true
    // after the one launch attempt so a failed connect never retry-loops against
    // hardware -- but a device that was connected and has now DROPPED (USB pulled, or
    // swapped for another unit) is a real change, not a retry. Resetting here lets the
    // chained maybeAutoConnect() acquire the NEW identified device automatically, so a
    // cold pull + different device needs no manual REFRESH/CONNECT. It does not loop:
    // this fires only on the connected->null transition, and a fresh connect re-latches.
    state.autoConnectTried=false;
    // DROP THE DEVICE DOCUMENT TOO, or DEVICE INFO stays stale until a NEW device
    // connects. connectionState() reads state.capabilities FIRST, so leaving the old
    // 'connected_recognized' document in place keeps DEVICE INFO rendering the pulled
    // unit's Product/Firmware/Serial/Service-Mode rows (the strip and photo clear
    // because refreshConnections repaints them directly, but the page body does not).
    // Null it so connectionState() falls to the candidate-based NO_DEVICE/DETECTED, then
    // emit the connection change -- the same reset a connect sends, toward disconnected:
    // it invalidates device-scoped state (Service Mode, RF region) and repaints the page.
    state.capabilities=null;
    applyNavVisibility();
    emitConnectionChange();
  }
  if(state.connecting){
    // A connect is in flight. This poll runs every second and used to overwrite
    // CONNECTING… with DETECTED:… almost immediately, which is why the button
    // greyed out and nothing else appeared to happen. Leave the connect bar alone.
  } else if(!state.activeConnection?.connected && String(sel.value).startsWith('network:')){
    setConnectButton('idle','Connect to the selected Ethernet address');
  } else if(!state.activeConnection?.connected && first?.identity_proven){
    setConnectButton('detected',`Connect to ${candidateLabel(first)}`);
    setLabel($('#deviceKicker'),'DETECTED DEVICE');
    $('#deviceName').textContent=candidateLabel(first);
    const img=$('#deviceImage'); if(first.device_image){img.src=first.device_image;img.classList.remove('hidden');applyRenderProvenance(img,first.device_image_provenance)}else{img.removeAttribute('src');img.classList.add('hidden');img.removeAttribute('title')}
  } else if(!state.activeConnection?.connected && !first?.identity_proven){
    setConnectButton(cs.length?'idle':'none',
      cs.length?'Identifying…':'No Ascent device detected');
    setLabel($('#deviceKicker'),'DETECTED DEVICE');
    setLabel($('#deviceName'), cs.length?'IDENTIFYING ASCENT DEVICE…':'NO DEVICE');
    const img=$('#deviceImage'); img.removeAttribute('src');img.classList.add('hidden');
  }
}

async function connectSelected(){
  const btn=$('#connectBtn'); btn.disabled=true;
  const chosen=$('#connectionSelect').value;
  const reconnect=!!state.activeConnection?.network_target?.requires_reconnect;
  const selected=chosen==='auto'&&reconnect?state.activeConnection.candidate_id:chosen;
  const switching=selected!=='auto'&&(selected!==state.activeConnection?.candidate_id||reconnect);
  if(state.activeConnection?.connected&&switching){
    try{
      const response=await fetch('/api/disconnect',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}',cache:'no-store'});
      const result=await response.json();
      if(!response.ok||result.ok===false)throw Error(result.message||'The previous target could not be disconnected.');
    }catch(error){btn.disabled=false;showConnectProblem(error.message||error);return;}
    state.activeConnection=null;state.capabilities=null;state.status=null;
  }
  if(state.activeConnection?.connected){
    try{await fetch('/api/disconnect',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}',cache:'no-store'});
        state.activeConnection=null; setConnectButton('idle'); await refresh();}
    finally{btn.disabled=false;}
    return;
  }
  // A real connect opens the serial session and runs the full vendor identify.
  // On hardware that takes long enough that a greyed-out button on its own reads
  // as hung, so the button and the state text both say what is happening.
  state.connecting=true;
  setConnectButton('connecting',selected.startsWith('network:')?'Reading the selected Ethernet address…':'Opening the serial session and identifying…');
  try{
    const r=await fetch('/api/connect',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({candidate_id:selected}),cache:'no-store'});
    const d=await r.json();
    if(!r.ok||!d.connected) throw Error(d.message||d.error||'DEVICE IDENTITY FAILED');
    state.activeConnection=d; state.connecting=false;
    if(d.network_target){state.capabilities=null;state.status=null;await emitConnectionChange();}
    Promise.resolve(null);updateHeader();render();
    setConnectButton('connected',
      `Connected to ${d.network_target?d.network_target.label+' · '+d.network_target.device_ip:d.serial_identity?.device_name||'this device'} — press to disconnect`);
    await refresh();
  } catch(e){ setConnectButton('failed',safeErr(e.message||e)); showConnectProblem(e.message||e); }
  finally{state.connecting=false;$('#connectBtn').disabled=false;}
}

const BATT_PRESETS={lipo:{low:3500,crit:3300},liion:{low:3200,crit:3000},
                    dc_adapter:{low:null,crit:null}};

function batteryAutoCells(mv){
  if(!mv||mv<=0) return null;
  let best=null,bestErr=null;
  for(let c=1;c<=6;c++){ const pc=mv/c;
    if(pc>=3000&&pc<=4300){ const e=Math.abs(pc-3700);
      if(bestErr===null||e<bestErr){best=c;bestErr=e;} } }
  return best;
}

function batteryThresholds(w,mv){
  w=w||{}; const ch=w.chemistry||'lipo';
  if(ch==='dc_adapter') return {low:null,crit:null,cells:null};
  let cc=w.cell_count; if(cc==='auto'||cc==null) cc=batteryAutoCells(mv);
  if(w.source==='exact') return {low:w.low_mv||null,crit:w.crit_mv||null,cells:cc};
  const per=BATT_PRESETS[ch]||BATT_PRESETS.lipo;
  if(!cc) return {low:null,crit:null,cells:null};
  return {low:per.low*cc,crit:per.crit*cc,cells:cc};
}

function batteryHeaderHtml(){
  const last=state.batteryLast;
  if(!ident()||!last||typeof last.battery_mv!=='number') return '';
  const cur=state.battery;
  const fresh=!!(cur&&cur.ok&&typeof cur.battery_mv==='number');
  const b=fresh?cur:last;
  const w=state.batteryWarn&&state.batteryWarn.battery_warnings;
  const th=batteryThresholds(w,b.battery_mv);
  let cls='good';
  if(th.crit!=null&&b.battery_mv<th.crit) cls='bad';
  else if(th.low!=null&&b.battery_mv<th.low) cls='warnc';
  const perCell=th.cells?` · ${(b.battery_mv/th.cells/1000).toFixed(2)}V/cell`:'';
  const v=`${(b.battery_v).toFixed(1)}V${perCell}`;
  if(fresh)
    return `<span class="${cls}" title="${esc(`VRX battery${th.cells?` (${th.cells}S)`:''}`)}">${v}</span>`;
  const age=Math.round((Date.now()-(last.at||Date.now()))/1000);
  const ageTxt=age>=60?`${Math.round(age/60)}m`:`${age}s`;
  return `<span class="${cls}" style="opacity:.55" `
    +`title="${esc(`VRX battery${th.cells?` (${th.cells}S)`:''} — last reading ${ageTxt} ago`)}">`
    +`${v} <span class="muted">·${ageTxt}</span></span>`;
}

async function pollBattery(){
  if(!ident()){
    if(state.battery||state.batteryLast){ state.battery=null; state.batteryLast=null; updateHeader(); }
    return;
  }
  let doc=null;
  try{ doc=await fetchJson('/api/vrx/battery',true); }
  catch{ doc=null; }
  if(doc&&doc.ok&&typeof doc.battery_mv==='number') state.batteryLast={...doc,at:Date.now()};
  state.battery=doc;
  updateHeader();
}

function updateHeader(){
  const i=ident();
  const nick=$('#deviceNickname');
  const raw=state.status?.local_bb_id;
  const nm=raw?nicknameFor(raw,'receiver'):null;
  if(nick) nick.textContent=nm||'';
  // VRX battery voltage lives in its own node, right-aligned at the far edge of the
  // header (#deviceBattery, pushed right by .batt-readout) -- not appended to the
  // device name, where it sat directly against the model text ("…HF15.4V"). The name
  // node is therefore always plain text (what the render-check shim reads).
  const _battEl=$('#deviceBattery');
  if(_battEl) _battEl.innerHTML = i ? batteryHeaderHtml() : '';
  const nt=state.activeConnection?.network_target;
  if(nt&&state.activeConnection?.connected){
    $('#deviceKicker').textContent='ETHERNET TARGET';
    $('#deviceName').textContent=nt.label+' · '+nt.device_ip;
    const img=$('#deviceImage');img.removeAttribute('src');img.classList.add('hidden');img.removeAttribute('title');
    if(nt.requires_reconnect){$('#deviceKicker').textContent='RECONNECT REQUIRED';setConnectButton('failed','Reconnect after the role-change reboot');}
    else setConnectButton('connected','Selected Ethernet target — press to disconnect');
  }else if(i){
    $('#deviceKicker').textContent='CONNECTED DEVICE';
    $('#deviceName').textContent=productLabel()||'ASCENT DEVICE';
    const img=$('#deviceImage');
    if(i.device_image){
      img.src=i.device_image;img.classList.remove('hidden');
      /* A borrowed render must say so. No factory render exists for every model,
         and showing a sibling's silently is what misleads an operator about which
         unit they are holding -- this bench lost hours to WF/HF confusion. The
         picture is shown because the owner asked for it; the caption is how it
         stays honest. Uses the existing alt/title, so no new markup or CSS. */
      applyRenderProvenance(img,i.device_image_provenance);
    }
    else{img.removeAttribute('src');img.classList.add('hidden');img.removeAttribute('title')}
    setConnectButton('connected',
      `Connected to ${i.device_name||'this device'} — press to disconnect`);
  }
}

function applyRenderProvenance(img,pv){
  pv=pv||{};
  if(pv.exact===false){
    const d=pv.depicts||'another model';
    img.alt='Stand-in render: '+d;
    img.title='No factory render exists for this model. Showing the '+d+
              ' render. This is not a picture of this unit.';
  }else{img.alt='Connected device';img.removeAttribute('title')}
}

const connectionListeners=[];

function onConnectionChange(fn){ connectionListeners.push(fn); return fn; }

async function emitConnectionChange(){
 state.repeater=null;state.repeaterError=null;state.repeaterLoading=false;state.relayBind=null;
 updateHeader();render();for(const fn of connectionListeners){try{await fn();}catch{}}
}

onConnectionChange(()=>reloadDeviceConfig('hub').catch(()=>{}));

onConnectionChange(()=>reloadDeviceConfig('rc').catch(()=>{}));

async function reloadFleetPage(){
 state.nicknames=await fetchJson('/api/vtx-nicknames',true);
 if(state.view==='fleet')render();
}

async function reloadRfPage(){
  state.vendorRfReading=null;
  const metaIdentity=vendorRfIdentity();
  const meta=await fetchJson('/api/rf-diagnostics',true).catch(()=>null);
  state.vendorRfMeta=metaIdentity===vendorRfIdentity()?meta:null;
  state.vendorRfMetaIdentity=metaIdentity;
  state.rf=await fetchJson('/api/rf',true);
  applyRfBands(await fetchJson('/api/rf-bands',true));
  await Promise.resolve(null);
  // Plans are host-local, but their compatibility verdict is computed against the
  // connected unit, so the list is re-read whenever the identity may have changed.
  await reloadPlans();
  if(state.view==='rf') render();
}

onConnectionChange(reloadFleetPage);

onConnectionChange(reloadRfPage);

onConnectionChange(reloadFirmwarePage);

async function refresh(){
  $('#status').textContent='REFRESHING READ-ONLY DEVICE STATE…';
  try{state.app=await fetchJson('/api/app'); $('#build').textContent=state.app.version;}catch{}
  try{const cs=await fetchJson('/api/connection-state',true); if(cs?.active?.serial_identity||cs?.active?.network_target){state.activeConnection={connected:true,...cs.active};}}catch{}
  // Clearing a stale "connected" is the 1 s poll's job (refreshConnections, against
  // connection_inventory's active_candidate_id), not this read's: this is also the
  // app-load refresh, where activeConnection is legitimately absent and must not be
  // treated as a drop.
  // Page visibility is settled BEFORE discovery, not after it. /api/connections runs
  // the Windows PowerShell inventory (two processes, 8 s timeout each) and schedules
  // the command-60 identity probes, so on hardware it takes seconds -- and while it
  // was awaited above this line, applyNavVisibility() had never run once and the nav
  // buttons sat in their index.html state, showing all six. That is the whole of the
  // SCANNING... screenshot: not a misclassified state, an unapplied one. This read is
  // host-local, issues no device command and cannot block on it.
  state.capabilities=await fetchJson('/api/device-capabilities',true);
  applyNavVisibility();
  await refreshConnections();
  // Re-read now that discovery has reported. The page set is identical across the
  // three not-connected states, so this changes no visibility -- it is what lets
  // DEVICE INFO say which of them we are actually in rather than defaulting to
  // SCANNING.
  state.capabilities=await fetchJson('/api/device-capabilities',true);
  applyNavVisibility();
  // Every mounted page is told the connection state here, before the slow reads
  // below, and each page's own data lands as soon as its read returns.
  await emitConnectionChange();
  const i=ident();
  try{
    state.status=await fetchJson('/api/status');
    updateHeader();   // the nickname follows the Ground STATUS read
  }catch(e){state.status=null; updateHeader();}
  // VRX battery rides the same refresh as /api/status -- read on connect and on
  // manual refresh, never on a page timer (the no-device-timer invariant). Fail-soft.
  await pollBattery();
  state.saveDir=await fetchJson('/api/settings/save-directory',true);
  // Read beside the save directory, so SETTINGS never paints an empty folder
  // field that looks like "not configured" when it simply was not fetched.
  ;
  // Battery-warning config rides the same read, so the header colouring thresholds
  // are known before the first battery poll lands.
  state.batteryWarn=await fetchJson('/api/settings/battery-warnings',true);
  state.devices=await fetchJson('/api/windows-devices',true);
  state.fw=await fetchJson('/api/firmware',true);
  await Promise.all(['rf','hub','rc'].map(async n=>{state.templates[n]=await fetchJson(`/api/template/${n}`,true)}));
  // Host-local documents plus their per-device eligibility. Both are cheap reads
  // that issue no device command, so they are safe here and safe to repeat.
  await Promise.all(['hub','rc'].map(k=>reloadDeviceConfig(k).catch(()=>{})));
  updateHeader();
  /* The capability line used to sit in the page footer on every route: inert text
     shaped like a status control. It is real information, so it moved to DIAGNOSTICS
     where capability state is reported and labelled, rather than being advertised
     under every page. */
  $('#status').textContent=''; render();
}

function setTheme(theme){
  document.body.classList.toggle('day',theme==='day'); localStorage.setItem('ascentTheme',theme); render();
}

$$('.nav').forEach(n=>n.onclick=()=>setNav(n.dataset.view));

$('#advanced').onchange=e=>{ $('#advancedMenu').classList.toggle('hidden',!e.target.checked); try{ localStorage.setItem('ascent.advanced',e.target.checked?'1':'0'); }catch{} render(); };

$('#refresh').onclick=refresh;

$('#connectBtn').onclick=connectSelected;

$('#connectionSelect')?.addEventListener?.('change',()=>{
  state.connectionSelectorInitialized=true;
  const selected=$('#connectionSelect').value;
  if(selected!=='auto'&&selected!==state.activeConnection?.candidate_id)setConnectButton('idle','Connect to the selected target');
});

(()=>{ const h=hostChannel(); if(!h||!h.addEventListener) return;
  h.addEventListener('message',ev=>{
    const d=ev&&ev.data; if(!d) return;
    if(d.type==='video'){
      const previous=liveState().video||{};
      liveState().video={...previous,...d,pipeline:d.pipeline??previous.pipeline};
    } else if(d.type==='hid'){
      const prev=liveState().hid||{};
      // A start/stop reply carries no device list; keep the last one so the
      // table does not vanish the moment a stick is selected.
      liveState().hid={...prev,...d,devices:d.devices??prev.devices};
    } else return;
    if(state.mode==='live'){
      if(d.type==='video')paintLiveVideoStatus();else paintLiveTelemetry(true);
    }
  });
})();

$('#modeConfiguration').onclick=()=>setMode('configuration');

$('#modeLive').onclick=()=>setMode('live');

state.mode=(()=>{ try{ return localStorage.getItem('ascent.mode')==='live'?'live':'configuration'; }catch{ return 'configuration'; } })();

(()=>{ try{ const on=localStorage.getItem('ascent.advanced')==='1';
  const cb=$('#advanced'); if(cb) cb.checked=on;
  $('#advancedMenu')?.classList.toggle('hidden',!on); }catch{} })();

const saved=localStorage.getItem('ascentTheme');

if(saved==='day')document.body.classList.add('day'); else document.body.classList.remove('day');

setMode(state.mode);

applyNavVisibility();

refresh();

setInterval(()=>refreshConnections()
  .then(()=>maybeAutoConnect())
  .then(()=>pollBattery())
  .then(()=>Promise.resolve(null))
  .then(()=>Promise.resolve(null))
  .then(()=>Promise.resolve(null))
  .then(()=>refreshVendorRfProjection())
  .catch(()=>{}),1000);

state.autoConnect=false;

state.autoConnectTried=false;

async function loadAutoConnect(){
  const box=$('#autoConnect'); if(!box) return;
  try{
    const d=await fetchJson('/api/settings/auto-connect',true);
    state.autoConnect=d?.auto_connect===true;
  }catch{ state.autoConnect=false; }
  box.checked=state.autoConnect;
  box.onchange=async()=>{
    state.autoConnect=box.checked;
    try{
      await fetch('/api/settings/auto-connect',{method:'POST',
        headers:{'Content-Type':'application/json'},
        body:JSON.stringify({enabled:box.checked}),cache:'no-store'});
    }catch{ /* the switch still reflects the session; the file just did not take */ }
  };
}

async function maybeAutoConnect(){
  if(String($('#connectionSelect')?.value||'').startsWith('network:'))return;
  if(!state.autoConnect||state.autoConnectTried) return;
  if(state.connecting||state.activeConnection?.connected) return;
  const first=(state.connections?.candidates||[])[0];
  if(!first?.identity_proven) return;        // wait for a real identity
  state.autoConnectTried=true;
  const sel=$('#connectionSelect'); if(sel) sel.value='auto';
  await connectSelected();
}

loadAutoConnect();

(async function restoreLanguage(){
  // Asked before the first paint: an installation that has not been told where
  // to keep its data must not render a page that writes.
  try{ await Promise.resolve(null); }catch{}
  let saved = 'en';
  try{ saved = localStorage.getItem('ascent.language') || 'en'; }catch{}
  const top=$('#langTop'); if(top) top.onchange = e => setLanguage(e.target.value);
  if(saved !== 'en' && window.i18n){
    await i18n.setLocale(saved);
    applyStaticTranslations();
    syncLanguageControls();
    render();
  } else {
    applyStaticTranslations();
    syncLanguageControls();
  }
})();

function bindDeviceHistory(){
 $('#histRetry')?.addEventListener('click',()=>{state.deviceHistory=null;render();});
 const histExport=fmt=>fetch('/api/device-history/export',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({format:fmt}),cache:'no-store'}).then(r=>r.json()).then(j=>{
 const text=fmt==='csv'?(j.csv||''):JSON.stringify(j.document,null,1);const blob=new Blob([text],{type:fmt==='csv'?'text/csv':'application/json'});const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='ascent-device-history.'+fmt;a.click();URL.revokeObjectURL(a.href);
 }).catch(e=>{const st=$('#histState');if(st)st.textContent=safeErr(e);});
 const csv=$('#histCsv'),json=$('#histJson');if(csv)csv.onclick=()=>histExport('csv');if(json)json.onclick=()=>histExport('json');
}
