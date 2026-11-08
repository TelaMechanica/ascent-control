/* Shared presentation only. Backend stream owns source identity and lifecycle. */
const RcSource = (()=>{
  const approvedAssets=Object.freeze({
    radiomaster_zorro:'assets/rc/png/radiomaster_zorro.png',
    radiomaster_boxer:'assets/rc/png/radiomaster_boxer.png',
    radiomaster_pocket:'assets/rc/png/radiomaster_pocket.png',
    radiomaster_gx12:'assets/rc/png/radiomaster_gx12.png',
    radiomaster_ax12:'assets/rc/png/radiomaster_ax12.png',
    radiomaster_tx16s:'assets/rc/png/radiomaster_tx16s.png',
    tbs_tango2:'assets/rc/png/tbs_tango_2.png',
    rog_ally:'assets/rc/png/rog_ally.png'
  }); // Operator-supplied originals; provenance is in assets/rc/PROVENANCE.json.
  function present(s,now=Date.now()){
    if(!s) return {name:'RC controller',detection:'Controller observation unavailable',profile:'Profile unknown',input:'Input unknown',mapping:'Mapping unknown',output:'Output unknown',features:[],graphic:'neutral'};
    const observed=Number.isFinite(s.generated_at_ms)&&now>=s.generated_at_ms&&now-s.generated_at_ms<=s.stale_after_ms;
    const fresh=!!(observed&&s.input_fresh&&Number.isFinite(s.generated_at_ms)&&Number.isFinite(s.input_age_ms)
      &&s.input_age_ms+Math.max(0,now-s.generated_at_ms)<=s.stale_after_ms);
    return {name:s.display_name||'HID controller',
      detection:!observed?'Reader observation stale':s.device_present?'Controller detected':'No RC reader connected',
      profile:s.profile_kind==='edgetx_classic'?'EdgeTX Classic profile (inferred)':s.profile_kind==='edgetx_variant'?'EdgeTX-compatible variant (inferred)':s.recognized_family==='EdgeTX'?'EdgeTX RC detected (inferred)':s.likely_rc?'Generic RC HID':'Game controller · generic HID',
      input:fresh?'Input live':s.device_present?'Input stale or not yet observed':'Input unavailable',
      mapping:s.mapping_present?'Mapped · 16 output slots':'Mapping requires assignment or revalidation',
      output:!observed?'CRSF output observation stale':s.stream_running?'CRSF output active · send-only':'CRSF output stopped',
      features:s.assigned_features||[],graphic:s.graphic_key||'neutral'};
  }
  // Asset lookup
  // is presentation-only; an image can neither permit nor refuse control output.
  function graphic(s,assets=approvedAssets){
    for(const key of [s?.model,s?.graphic_key,'neutral']) if(key&&assets[key])return assets[key];
    return null;
  }
  function accept(current,next){
    if(!Number.isFinite(current?.generated_monotonic_ms)) return true;
    return Number.isFinite(next?.generated_monotonic_ms)&&next.generated_monotonic_ms>=current.generated_monotonic_ms;
  }
  return {present,graphic,accept};
})();
if(typeof module!=='undefined')module.exports=RcSource;
