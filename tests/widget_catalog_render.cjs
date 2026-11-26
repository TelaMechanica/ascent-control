// Execute the real first-party DOM/controller; forbid every HTML insertion.
const assert=require('assert'),fs=require('fs'),vm=require('vm');
class Element {
  constructor(tag){this.tagName=tag;this.children=[];this.style={};this.attrs={};this._text='';this.disabled=false;}
  set innerHTML(value){throw Error('HTML insertion is forbidden');}
  get innerHTML(){throw Error('HTML serialization is not used');}
  set textContent(value){this._text=String(value);this.children=[];}
  get textContent(){return this._text+this.children.map(child=>child.textContent).join(' ');}
  appendChild(child){this.children.push(child);return child;}
  replaceChildren(...children){this._text='';this.children=children;}
  setAttribute(name,value){this.attrs[name]=value;}
}
const document={createElement:tag=>new Element(tag)};
const source=fs.readFileSync('runtime/www/domains/widget_catalog.js','utf8');
const ctx={setTimeout,clearTimeout,Date,Number,Set,Object,Array};ctx.globalThis=ctx;vm.createContext(ctx);vm.runInContext(source,ctx);
const blank=(status='OK')=>({schema:'ascent.widget_catalog.v0',status,complete:status==='OK',entries:[],read_only:true,
  registration_performed:false,activation_performed:false,installation_checked:false,scanned_entries:0,ignored_entries:0});
const doc=(phase='COMPLETE',result=blank(),generation=1)=>({schema:'ascent.widget_catalog_host.v0',phase,generation,result,
  registration_performed:false,activation_performed:false,installation_checked:false,observed_at:'2026-11-17T10:11:12+00:00'});
const walk=root=>[root,...root.children.flatMap(walk)];
const button=(root,text)=>walk(root).find(node=>node.tagName==='button'&&node.textContent===text);
const flush=async()=>{for(let i=0;i<8;i++)await Promise.resolve();};
function mount(request, options={}){
 const root=new Element('section'),timers=new Map();let id=0;
 const page=ctx.AscentWidgetCatalog.mount({root,document,request,...options,
   schedule:callback=>{const token=++id;timers.set(token,callback);return token;},cancel:token=>timers.delete(token)});
 return {root,timers,page};
}
(async()=>{
 const payload=blank();payload.entries=[{source_name:'<img src=x onerror=synthetic()>',status:'VALIDATED_PREVIEW',
  package:{id:'<script>synthetic()</script>',version:'0.1.0',validated:true,executable:false,publisher_verified:false}}];
 const calls=[];const first=mount(async(path,method)=>{calls.push([path,method]);return doc('COMPLETE',payload);});await flush();
 assert(first.root.textContent.includes('<img src=x onerror=synthetic()>'));
 assert(first.root.textContent.includes('<script>synthetic()</script>'));
 assert(walk(first.root).every(node=>!['script','img','iframe','a','object','embed'].includes(node.tagName)));
 assert(first.root.textContent.includes('Receiver installation has not been checked'));
 assert(first.root.textContent.includes('Publisher identity is not verified'));
 assert(first.root.textContent.includes('2026-11-17T10:11:12.000Z'));
 assert.equal(calls.length,1);assert.equal(first.timers.size,0);
 assert.equal(button(first.root,'Rescan').disabled,false);first.page.close();

 for(const status of ['DUPLICATE_COPY','VERSION_CONFLICT']){
  const report=blank();report.entries=[{...payload.entries[0],status}];
  const view=mount(async()=>doc('COMPLETE',report));await flush();
  assert(view.root.textContent.includes('<script>synthetic()</script>'));
  assert(view.root.textContent.includes('0.1.0'));assert(!view.root.textContent.includes('Locally validated preview'));view.page.close();
 }
 const empty=mount(async()=>doc());await flush();assert(empty.root.textContent.includes('No ZIP widget packages found'));empty.page.close();
 const missing=mount(async()=>doc('COMPLETE',blank('FOLDER_MISSING')));await flush();
 assert(missing.root.textContent.includes('Widgets folder was not found'));assert(!missing.root.textContent.includes('No ZIP widget packages found'));missing.page.close();
 for(const status of ['FOLDER_UNSAFE','FOLDER_CHANGED','ENTRY_LIMIT','BYTE_LIMIT']){
  const view=mount(async()=>doc('COMPLETE',blank(status)));await flush();
  assert(!view.root.textContent.includes('No ZIP widget packages found'));view.page.close();
 }
 for(const phase of ['SCANNING','SCAN_DELAYED','NOT_STARTED','FAILED','CLOSED']){
  const view=mount(async()=>doc(phase,null));await flush();
  assert(!view.root.textContent.includes('No ZIP widget packages found'));
  assert.equal(view.timers.size,['SCANNING','SCAN_DELAYED'].includes(phase)?1:0);
  view.page.close();assert.equal(view.timers.size,0);
 }
 const denied=mount(async()=>({error:'DESKTOP_HOST_SESSION_REQUIRED'}));await flush();
 assert(denied.root.textContent.includes('desktop host session'));denied.page.close();
 const raw=mount(async()=>{throw Error('synthetic-private-path-error');});await flush();
 assert(!raw.root.textContent.includes('synthetic-private-path-error'));assert(raw.root.textContent.includes('could not be read'));raw.page.close();
 const invalid=doc();invalid.activation_performed=true;
 const bad=mount(async()=>invalid);await flush();assert(bad.root.textContent.includes('could not be read'));bad.page.close();

 let finish;const late=mount(()=>new Promise(resolve=>{finish=resolve;}));const before=late.root.textContent;
 late.page.close();finish(doc());await flush();assert.equal(late.root.textContent,before);assert.equal(late.timers.size,0);

 let count=0;const requests=[];
 const active=mount(async(path,method)=>{requests.push([path,method]);
  if(path.endsWith('open-folder'))return {ok:true,open_requested:true};
  if(path.endsWith('rescan'))return doc('SCANNING',null,2);
  return count++===0?doc():doc('COMPLETE',blank(),3);
 });await flush();
 await button(active.root,'Rescan').onclick();await flush();assert.equal(active.timers.size,1);
 const poll=[...active.timers.values()][0];active.timers.clear();poll();await flush();assert.equal(active.timers.size,0);
 await button(active.root,'Open Widgets folder').onclick();await flush();assert(active.root.textContent.includes('Folder opening requested'));
 assert.deepEqual(requests,[['/api/widgets/local/catalog','GET'],['/api/widgets/local/rescan','POST'],
  ['/api/widgets/local/catalog','GET'],['/api/widgets/local/open-folder','POST'],['/api/widgets/local/catalog','GET']]);
 active.page.close();

 let reads=0;
 const followup=mount(async path=>{
  if(path.endsWith('open-folder'))return {ok:true,open_requested:true};
  if(++reads>1)throw Error('synthetic-status-failure');
  return doc();
 });await flush();await button(followup.root,'Open Widgets folder').onclick();await flush();
 assert(followup.root.textContent.includes('Folder opening requested'));
 assert(followup.root.textContent.includes('Catalog status could not be read'));
 assert(!followup.root.textContent.includes('Folder-opening request did not finish'));followup.page.close();
 const unknown=mount(async()=>doc('COMPLETE',blank('toString')));await flush();
 assert(unknown.root.textContent.includes('Catalog result is unavailable'));
 assert(!unknown.root.textContent.includes('[native code]'));unknown.page.close();
 const noTime=doc();noTime.observed_at='0';
 const uncertain=mount(async()=>noTime);await flush();assert(!uncertain.root.textContent.includes('Last scan completed at'));uncertain.page.close();

 const target={serial_number:'1234',device_name:'Ascent_VRX_pro'};
 const receiverCalls=[];
 let confirm=false;
 const receiver=mount(async(path,method,body)=>{
  if(path==='/api/widgets/manager')return {ok:true,receiver:target,files_present:false,
    available_releases:[{id:'netrunner-pro-2.10.1',version:'2.10.1',action:'install'}]};
  if(path==='/api/widgets/manager/action'){receiverCalls.push(body);return {ok:true};}
  return doc();
 },{receiverActions:true,confirmAction:()=>confirm});
 await flush();assert.equal(receiverCalls.length,0);
 await button(receiver.root,'Check selected receiver').onclick();
 await button(receiver.root,'Install 2.10.1').onclick();assert.equal(receiverCalls.length,0);
 confirm=true;
 await button(receiver.root,'Install 2.10.1').onclick();
 assert.equal(receiverCalls.length,1);
 assert.equal(receiverCalls[0].expected_target,target);
 assert.equal(receiverCalls[0].release_id,'netrunner-pro-2.10.1');
 assert(receiver.root.textContent.includes('NetRunner files verified'));
 receiver.page.close();

 const badArchive=mount(async path=>{
  if(path==='/api/widgets/manager')return {ok:true,receiver:target,files_present:false,
    available_releases:[],release_archives:[
      {id:'netrunner-max-2.10.2',version:'2.10.2',state:'invalid'},
      {id:'netrunner-max-2.10.1',version:'2.10.1',state:'missing'}]};
  return doc();
 },{receiverActions:true});
 await flush();await button(badArchive.root,'Check selected receiver').onclick();
 assert(badArchive.root.textContent.includes('ZIP could not be verified'));
 assert(badArchive.root.textContent.includes('Add missing NetRunner downloads'));
 assert(!badArchive.root.textContent.includes('Install 2.10.2'));
 badArchive.page.close();

 const {boot}=require('./public_ui_render_check.cjs');const ui=boot().__ui;
 ui.state.connections={candidates:[]};ui.state.capabilities={pages:{widgetmanager:{visible:false}}};
 assert.equal(ui.pageVisible('widgetmanager'),true);
 ui.state.activeConnection={connected:true,network_target:{kind:'repeater'}};
 assert.equal(ui.pageVisible('widgetmanager'),true);
 const html=fs.readFileSync('runtime/www/index.html','utf8');
 assert(html.indexOf('data-view="widgetmanager"')<html.indexOf('id="advancedMenu"'));
 assert(html.includes('domains/widget_catalog.js'));
 console.log('Widget catalog DOM, truth, request, navigation and late-result checks passed');
})().catch(error=>{console.error(error);process.exitCode=1;});
