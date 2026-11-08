// Actual UI code, host events and polling; no receiver or native playback I/O.
const assert=require('node:assert/strict');
const {boot}=require('./public_ui_render_check.cjs');
(async()=>{
 let poll,hostMessage;const sent=[];
 const bridge={postMessage:d=>sent.push(d),addEventListener:(name,fn)=>{hostMessage=fn;}};
 let hid={stream:{axes:[1234],channels:[992],map_complete:false},rc_source:{epoch:'reader-one'}};
 const ctx=boot({window:{chrome:{webview:bridge}},setInterval:fn=>{poll=fn;return 1;},fetch:async()=>({ok:true,json:async()=>hid})});
 // Let boot's initial async reads settle before entering the Live fixture.
 await new Promise(resolve=>setImmediate(resolve));
 const ui=ctx.__ui,l=ui.liveState();
 ui.state.mode='live';l.doc={eligibility:{eligible:true,profiles:{usbc:{rtsp_url:'rtsp://192.0.2.1/live.ch01'},rj45:{rtsp_url:'rtsp://192.0.2.2/live.ch01'}}}};
 l.hidStream=hid;ui.renderLive();
 const content=ctx.document.querySelector('#content');
 let contentWrites=0,html=content.innerHTML;
 Object.defineProperty(content,'innerHTML',{get:()=>html,set:v=>{contentWrites++;html=v;}});
 const button=ctx.document.querySelector('#videoStart');const listener=button.onclick;
 ui.startLivePoll('live');
 // A poll between mouse-down and click must leave the pressed button attached.
 for(let i=0;i<5;i++)await poll();
 assert.equal(contentWrites,0,'HID polling must not replace the Live page');
 assert.equal(button.onclick,listener,'polling must not rebind the video button');
 button.onclick();assert.equal(sent.length,1);assert.equal(sent[0].action,'start');
 assert.equal(sent[0].url,'rtsp://192.0.2.1/live.ch01');
 assert.equal(contentWrites,0,'starting playback must not replace its button');
 hostMessage({data:{type:'video',ok:true,message:'Playing',playback:{State:'decoded-input'}}});
 hostMessage({data:{type:'video',ok:false,message:'Source timeout',playback:{State:'source-timeout'}}});
 assert.equal(l.video.playback.State,'source-timeout');assert.equal(contentWrites,0,'host status must not replace Live controls');
 // Unsaved manual text and map selection are not touched by telemetry.
 const manual=ctx.document.querySelector('#videoManualUrl'),map=ctx.document.querySelector('[data-mapch="1"]');
 manual.value='rtsp://192.0.2.3/custom';map.value='button:3';await poll();
 assert.equal(manual.value,'rtsp://192.0.2.3/custom');assert.equal(map.value,'button:3');
 l.videoOptions={endpoint:'manual',manualUrl:manual.value,transport:'tcp',latencyMs:200};
 button.onclick();assert.equal(sent.length,2);assert.equal(sent[1].url,manual.value);assert.equal(sent[1].transport,'tcp');assert.equal(sent[1].latencyMs,200);
 ctx.document.querySelector('#videoStop').onclick();assert.equal(sent[2].action,'stop');
 bridge.postMessage=()=>{throw Error('bridge unavailable');};button.onclick();
 assert.equal(l.video.ok,false);assert.match(l.video.message,/bridge unavailable/);assert.equal(contentWrites,0);
 // A HID source/descriptor change only rebuilds its own controls, never video.
 hid={stream:{axes:[42],map_complete:false},rc_source:{epoch:'reader-two'}};await poll();assert.equal(contentWrites,0);
 console.log('Live polling, click dispatch, endpoint choices, host status, drafts, stop and bridge failures PASS');
})().catch(e=>{console.error(e);process.exitCode=1;});
