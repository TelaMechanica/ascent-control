const assert=require('node:assert/strict');
const {boot}=require('./helpers/ethernet_ui_boot.cjs');
(async()=>{
 const messages=[],requests=[];let deferRead=null;
 const info={ok:true,connection_token:'session-a',captured_at:'2026-11-08T00:00:00Z',controls:{eligible:true},
  reads:{status:{ok:true,values:{local_bb_id:[242,0,0,1].map(b=>b.toString(16).padStart(2,'0')).join(':'),link:'LINKED',rx_mcs_raw:7}}},
  rtsp:{responding:true,status:'RTSP/1.0 200 OK <script>bad</script>'}};
 const ctx=boot({window:{chrome:{webview:{postMessage:p=>messages.push(p),addEventListener(){}}}},fetch:async(url,opts)=>{
  if(url.startsWith('/api/network/max/status'))return {ok:true,json:async()=>deferRead?new Promise(resolve=>{deferRead.resolve=resolve;}):info};
  if(url==='/api/network/max/key'){requests.push(JSON.parse(opts.body));return{ok:true,json:async()=>({ok:true,state:'SENT',message:'Request sent; action not verified.'})};}
  return{ok:true,json:async()=>({})};
 }});
 await new Promise(resolve=>setImmediate(resolve));
 const u=ctx.__ui;u.state.activeConnection={connected:true,network_target:{id:'network:max_eth',kind:'vrx',device_ip:'192.0.2.10',connection_token:'session-a'}};
 u.state.mode='live';u.liveState().doc={eligibility:{eligible:false,profiles:{usbc:{rtsp_url:'rtsp://192.0.2.20/live.ch01'},rj45:{rtsp_url:'rtsp://192.0.2.30/live.ch01'}}}};
 u.maxEthernetState().doc=info;u.renderLive();
 const content=ctx.document.querySelector('#content');assert.match(content.innerHTML,/OPEN VIDEO WINDOW/);
 assert.match(content.innerHTML,/data-maxethkey="PAIRING"/);assert.doesNotMatch(content.innerHTML,/id="livePowerApply"/);
 assert.equal(u.liveVideoSelection().url,'rtsp://192.0.2.10/live.ch01','default follows selected Ethernet target');
 ctx.document.querySelector('#videoStart').onclick();assert.equal(messages[0].url,'rtsp://192.0.2.10/live.ch01');
 let writes=0,html=content.innerHTML;Object.defineProperty(content,'innerHTML',{get:()=>html,set:v=>{writes++;html=v;}});
 await u.reloadMaxEthernet();assert.equal(writes,0,'status completion preserves video controls');
 assert.doesNotMatch(ctx.document.querySelector('#maxEthPanel').innerHTML,/<script>/,'receiver text is escaped');
 await u.sendMaxEthernetKey('CONFIRM');assert.equal(requests.length,1);assert.equal(requests[0].connection_token,'session-a');
 await u.sendMaxEthernetKey('PAIRING');assert.equal(requests.length,1,'cancelling pairing sends nothing');
 ctx.confirm=()=>true;await u.sendMaxEthernetKey('PAIRING');assert.equal(requests.length,2);
 assert.equal(requests[1].confirm_pairing,true);assert.equal(requests[1].acknowledge_non_stock,true);
 assert.equal(writes,0,'key request state never replaces video controls');
 const pad=ctx.document.querySelector('#maxEthKeyPad');let prevented=0;
 pad.onkeydown({key:'ArrowUp',repeat:false,target:{tagName:'DIV'},preventDefault(){prevented++;},stopPropagation(){}});
 await new Promise(resolve=>setImmediate(resolve));assert.equal(requests.at(-1).key,'UP');assert.equal(prevented,1);
 const before=requests.length;pad.onkeydown({key:'Enter',repeat:false,target:{tagName:'INPUT'}});pad.onkeydown({key:'ArrowUp',repeat:true,target:{tagName:'DIV'}});
 assert.equal(requests.length,before,'typing and held keys cannot produce menu requests');
 deferRead={};const pending=u.reloadMaxEthernet();await new Promise(resolve=>setImmediate(resolve));
 u.state.activeConnection.network_target={...u.state.activeConnection.network_target,connection_token:'session-b'};
 deferRead.resolve(info);await pending;assert.equal(u.maxEthernetState().key,'session-b');assert.equal(u.maxEthernetState().doc,null,'late reading never enters a different connection');
 console.log('Ethernet video, scoped info, escaped data, key confirmation, keyboard and stale responses: all checks passed');
})().catch(e=>{console.error(e);process.exitCode=1;});
