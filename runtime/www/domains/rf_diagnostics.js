/* Read-only diagnostic projection and one deliberate request. No timer/store. */
(function(root){
'use strict';
const staleAfterMs=30000; // host reading age only, not BB measurement cadence
function readingState(record,identity,now){
  if(!record)return 'unavailable';
  if(record.identity!==identity)return 'disconnected';
  if(!Number.isFinite(record.received)||(now<record.received||now-record.received>staleAfterMs))return 'stale';
  return record.doc.state||'unavailable';
}
async function readReading(fetchJson,identity,clock){
  const selected=identity();
  const doc=await fetchJson('/api/rf-diagnostics/read',true);
  if(selected!==identity())return null;
  return {identity:selected,received:clock(),doc};
}
function render(meta,record,identity,now,h){
  const {panel,kv,esc}=h, st=readingState(record,identity,now);
  const doc=st==='disconnected'?{}:record?.doc||{}, status=doc.status||{};
  const show=st==='valid_decode'||st==='partial_decode';
  let b=kv('Reading',st==='valid_decode'?'VALID DECODE — measurement age unknown':st==='partial_decode'?'PARTIAL READING — see read results':st.toUpperCase(),false)
    +kv('Link',show?status.link||'Unavailable':'Unavailable',false)
    +kv('RX MCS',show?status.rx_mcs??'Unavailable':'Unavailable')
    +kv('Baseband measurement interval','Unknown',false)
    +kv('Host reading age',record&&record.identity===identity?`${Math.max(0,Math.floor((now-record.received)/1000))} s`:'Unavailable',false);
  const rf=doc.debug_rf||{};
  for(const [key,label] of [['local_ground','GROUND'],['peer','PEER / SKY ROLE']]){
    const r=rf[key], available=show&&r&&(key==='local_ground'||doc.peer_usable);
    b+=kv(label+' raw SNR',available?r.snr_raw:'Unavailable')
      +kv(label+' AGC A / B',available?`${r.agc_a_raw} / ${r.agc_b_raw}`:'Unavailable',false)
      +kv(label+' TX MCS / channel ID',available?`${r.tx_mcs_raw} / ${r.tx_channel_id_raw}`:'Unavailable',false)
      +kv(label+' TX power raw code',available?r.tx_power_raw??'Unavailable':'Unavailable')
      +kv(label+' LDPC raw counters',available?`${r.ldpc_tlv_err_raw} / ${r.ldpc_num_err_raw}`:'Unavailable',false);
  }
  const channels=doc.work_channels;
  b+=kv('Active baseband channel IDs',show&&channels?channels.channel_ids.join(', ')||'Empty list':'Unavailable',false)
    +kv('Frequency conversion / calibration coverage','Unqualified',false)
    +kv('TX power units / temperature / latency / bitrate / distance','Unavailable — protocol qualification required',false)
    +`<p class="muted">Raw AGC is not RSSI dBm. Raw SNR scaling and counter lifetime are unqualified; counters are not packet-loss percent. Active IDs are separate from firmware tables and UI frequencies. Manual read only.</p>`;
  for(const [name,read] of Object.entries(doc.reads||{})){
    if(read.state!=='valid_decode')b+=kv(name,esc(read.code||read.message||read.state),false);
  }
  if(doc.error)b+=kv('Read result',esc(doc.error),false);
  b+=`<button class="secondary" id="rfDiagnosticRead"${meta?.eligible?'':' disabled'}>READ RF DIAGNOSTICS</button>`;
  if(!meta?.eligible)b+=`<p class="muted">${esc(meta?.state||'Unavailable')}: this receiver/firmware has no qualified diagnostic layout.</p>`;
  return panel('READ-ONLY RF DIAGNOSTICS',b);
}
function video(meta,h){
  const {panel,kv}=h,v=meta?.video;
  if(!v)return '';
  return panel('RECEIVER VIDEO CAPABILITY EVIDENCE',
    kv('Evidence scope',v.scope,false)+kv('RTSP implementation',v.rtsp_stack||'Unqualified',false)
    +kv('Stock startup condition',v.stock_rtsp_start_condition||'Unknown',false)
    +kv('Current board subtype / RTSP listener','Unknown / not observed',false)
    +kv('UVC code / enabled',v.uvc_code_present?'Present in reference firmware / unknown':'Unqualified',false)
    +kv('UVC + RTSP performance','Hardware unverified',false)
    +kv('Wi-Fi driver / stock startup',`${v.wifi_driver||'Unknown'} / ${v.wifi_stock_boot||'Unknown'}`,false));
}
const api={readingState,readReading,render,video,staleAfterMs};
if(typeof module!=='undefined'&&module.exports)module.exports=api;
root.AscentRfDiagnostics=api;
})(typeof globalThis!=='undefined'?globalThis:this);
