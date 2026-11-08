const assert=require('assert/strict');
const {boot}=require('./public_ui_render_check.cjs');
const flush=async()=>{for(let i=0;i<12;i++)await Promise.resolve();};
const reply=(doc,ok=true)=>({ok,status:ok?200:503,json:async()=>doc});
function setup(){
  const pending={},calls=[],timers=new Map();let timer=0;
  const ctx=boot({fetch:(url)=>{
    calls.push(url);
    if(url==='/api/device-history'||url==='/api/network/adapters')
      return new Promise(resolve=>(pending[url]||(pending[url]=[])).push(resolve));
    return Promise.resolve(reply({supported:true,devices:[]}));
  },setTimeout:fn=>{timers.set(++timer,fn);return timer;},clearTimeout:id=>timers.delete(id)});
  return {ctx,ui:ctx.__ui,pending,calls,timers,html:()=>ctx.document.querySelector('#content').innerHTML};
}

(async()=>{
  const x=setup();x.ui.setNav('diagnostics');
  assert.equal(x.pending['/api/device-history'].length,1,'page entry starts history read');
  assert.equal(x.pending['/api/network/adapters'].length,1,'page entry starts adapter read');
  x.ui.render();x.ui.render();
  assert.equal(x.pending['/api/device-history'].length,1,'rerender does not duplicate history request');
  assert.equal(x.pending['/api/network/adapters'].length,1,'rerender does not duplicate network request');
  x.pending['/api/device-history'][0](reply({ok:true,count:0,devices:[]}));
  x.pending['/api/network/adapters'][0](reply({supported:true,adapters:[]}));
  await flush();
  assert.match(x.html(),/NOTHING RECORDED YET/);
  assert.match(x.html(),/No USB network adapter/);
  assert.doesNotMatch(x.html(),/LOADING VALUES|Reading…/);
  x.ui.setNav('settings');x.ui.setNav('diagnostics');
  assert.equal(x.pending['/api/device-history'].length,2,'reentry rereads history');
  assert.equal(x.pending['/api/network/adapters'].length,2,'reentry rereads adapters');

  const failed=setup();failed.ui.setNav('diagnostics');
  failed.pending['/api/device-history'][0](reply({error:'History failed'},false));
  failed.pending['/api/network/adapters'][0](reply({error:'Network failed'},false));
  await flush();
  assert.match(failed.html(),/History failed/);assert.match(failed.html(),/Network failed/);
  assert.doesNotMatch(failed.html(),/LOADING VALUES|Reading…/);
  assert.match(failed.html(),/histRetry/);assert.match(failed.html(),/netReload/);

  failed.ctx.document.querySelector('#histRetry').onclick();
  failed.ctx.document.querySelector('#netReload').onclick();
  assert.equal(failed.pending['/api/device-history'].length,2,'history retry starts a new read');
  assert.equal(failed.pending['/api/network/adapters'].length,2,'adapter retry starts a new read');

  const timeout=setup();timeout.ui.setNav('diagnostics');
  for(const callback of [...timeout.timers.values()])callback();
  await flush();
  assert.match(timeout.html(),/Device history could not be read in time/);
  assert.match(timeout.html(),/Network adapter information could not be read in time/);
  assert.doesNotMatch(timeout.html(),/LOADING VALUES|Reading…/);

  const stale=setup();stale.ui.setNav('diagnostics');
  stale.ui.setNav('settings');stale.ui.setNav('diagnostics');
  stale.pending['/api/device-history'][1](reply({ok:true,count:0,devices:[]}));
  stale.pending['/api/network/adapters'][1](reply({supported:true,adapters:[]}));
  await flush();
  stale.pending['/api/device-history'][0](reply({ok:true,count:99,devices:[{product:'OLD REQUEST'}]}));
  stale.pending['/api/network/adapters'][0](reply({supported:true,adapters:[{name:'OLD ADAPTER'}]}));
  await flush();
  assert.equal(stale.ui.state.deviceHistory.count,0);
  assert.doesNotMatch(stale.html(),/OLD REQUEST|OLD ADAPTER/);

  const wallpaper=setup();wallpaper.ui.setNav('settings');
  assert.match(wallpaper.html(),/GOGGLES BACKGROUND IMAGE/);
  assert.match(wallpaper.html(),/CHOOSE IMAGE/);
  assert.match(wallpaper.html(),/Receiver upload and apply use Service Mode in AC\+/);
  const requests=[];
  const prepared={ok:true,prepared:true,source:{width:1200,height:800},plan:{mode:'crop'},jpeg_base64:'/9j/',filename:'fpv_new_bg_1920x1080.jpg'};
  const image=boot({fetch:async(url,options)=>{
    requests.push({url,options});
    if(url==='/api/wallpaper/browse')return reply({ok:true,path:'synthetic.png'});
    if(url==='/api/wallpaper/prepare')return reply(prepared);
    return reply({});
  }});
  image.__ui.setNav('settings');await image.__ui.prepareBackgroundImage();
  assert.equal(image.__ui.backgroundImageState().prepared.filename,prepared.filename);
  assert.match(image.document.querySelector('#content').innerHTML,/SAVE JPEG/);
  assert.match(image.document.querySelector('#content').innerHTML,/centre-cropped/);
  assert.equal(requests.filter(r=>r.url==='/api/wallpaper/prepare')[0].options.method,'POST');
  assert(!requests.some(r=>r.url.includes('/deploy')),'local preparation never deploys');
  console.log('Diagnostics entry, completion, errors, timeout, reentry, stale results and local background panel passed.');
})().catch(error=>{console.error(error);process.exitCode=1;});
