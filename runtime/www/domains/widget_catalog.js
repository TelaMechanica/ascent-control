/* Trusted first-party catalog UI. Package metadata is text, never markup/assets. */
(function (global) {
  'use strict';
  const paths = Object.freeze({status:'/api/widgets/local/catalog', rescan:'/api/widgets/local/rescan', open:'/api/widgets/local/open-folder'});
  const phases = new Set(['NOT_STARTED','SCANNING','SCAN_DELAYED','FAILED','COMPLETE','CLOSED']);
  const packageStates = Object.freeze({
    VALIDATED_PREVIEW:'Locally validated preview', PACKAGE_REJECTED:'Package rejected',
    UNSAFE_NAME:'Filename refused', UNSAFE_ENTRY:'File type refused', FILE_CHANGED:'File changed during scan',
    FILE_UNAVAILABLE:'File could not be read', PACKAGE_TOO_LARGE:'Package exceeds size limit',
    SOURCE_NAME_CONFLICT:'Filename conflicts with another entry', DUPLICATE_COPY:'Duplicate package copy',
    VERSION_CONFLICT:'Conflicting content for this version', INSPECTION_FAILED:'Package check failed'
  });
  const folderStates = Object.freeze({
    FOLDER_MISSING:'Widgets folder was not found. Use Open Widgets folder to request it.',
    FOLDER_UNSAFE:'Widgets folder is not an ordinary local folder. Folder discovery was refused.',
    FOLDER_UNAVAILABLE:'Widgets folder could not be read.', FOLDER_CHANGED:'Folder changed during the scan. Rescan to check again.',
    ENTRY_LIMIT:'Folder has too many entries. No complete catalog is available.',
    PACKAGE_LIMIT:'Folder has too many ZIP packages. No complete catalog is available.',
    BYTE_LIMIT:'Package bytes exceed the scan limit. No complete catalog is available.'
  });
  function mount({root, document, request, receiverActions=false, confirmAction, schedule=global.setTimeout, cancel=global.clearTimeout}) {
    let closed=false, pending=false, epoch=0, timer=null, observation=null, error='', actionResult='';
    const node=(tag,text,cls)=>{const value=document.createElement(tag);if(text!==undefined)value.textContent=text;if(cls)value.className=cls;return value;};
    root.replaceChildren();
    root.appendChild(node('h2','WIDGET MANAGER','page-head'));
    const panel=node('div',undefined,'panel');panel.appendChild(node('div','LOCAL WIDGET CATALOG','panel-title'));
    const body=node('div',undefined,'panel-body');panel.appendChild(body);root.appendChild(panel);
    body.appendChild(node('p','Add widget ZIPs to this app’s Widgets folder, then Rescan. Discovery does not install or run widgets.'));
    body.appendChild(node('p','Use Open Widgets folder to view this app’s package directory.'));
    const actions=node('div',undefined,'toolbar');body.appendChild(actions);
    const open=node('button','Open Widgets folder','secondary');open.type='button';actions.appendChild(open);
    const rescan=node('button','Rescan','secondary');rescan.type='button';actions.appendChild(rescan);
    const status=node('p');status.setAttribute('role','status');status.setAttribute('aria-live','polite');body.appendChild(status);
    const time=node('p',undefined,'muted');body.appendChild(time);
    const result=node('p');body.appendChild(result);
    const table=node('table');table.style.tableLayout='fixed';const header=node('thead');const heading=node('tr');
    for(const label of ['Package','Version','File','Package check']){const column=node('th',label);column.setAttribute('scope','col');heading.appendChild(column);}
    header.appendChild(heading);table.appendChild(header);const rows=node('tbody');table.appendChild(rows);body.appendChild(table);
    body.appendChild(node('p','Publisher identity is not verified. Receiver installation has not been checked. Widget execution is unavailable in this preview.','notice'));
    if(receiverActions){
      const receiverPanel=node('div',undefined,'panel');
      receiverPanel.appendChild(node('div','NETRUNNER','panel-title'));
      const controls=node('div',undefined,'panel-body');receiverPanel.appendChild(controls);
      const inspect=node('button','Check selected receiver','secondary');inspect.type='button';
      controls.appendChild(inspect);
      const receiverStatus=node('p');receiverStatus.setAttribute('role','status');
      receiverStatus.tabIndex=-1;controls.appendChild(receiverStatus);
      const releases=node('div',undefined,'toolbar');controls.appendChild(releases);
      root.appendChild(receiverPanel);
      const errors={
        RECEIVER_SELECTION_REQUIRED:'Connect and select a receiver.',
        RECEIVER_ENROLLMENT_REQUIRED:'Verify receiver access in Service Mode first.',
        RECEIVER_BINDING_CHANGED:'The selected receiver changed. Check it again.',
        NETRUNNER_PROFILE_UNSUPPORTED:'NetRunner downloads for this receiver are unavailable here.',
        WIDGET_DOWNLOAD_REQUIRED:'Add the NetRunner ZIP to the Widgets folder.',
        WIDGET_ARCHIVE_INVALID:'The NetRunner ZIP could not be verified. Replace it with the official download.',
        NETRUNNER_INSTALLED_RELEASE_UNKNOWN:'The installed files could not be matched to an approved release. Check the receiver state before changing versions.',
        NETRUNNER_RELEASE_DIRECTION_INVALID:'The installed version no longer matches this action. Check the selected receiver again.',
        NETRUNNER_ALREADY_PRESENT:'NetRunner files are already present. Check the selected receiver before changing versions.',
        RECEIVER_ENROLLMENT_CHANGED:'Receiver access changed. Verify access in Service Mode before trying again.',
        DEVICE_BUSY:'Another receiver operation is active.'
      };
      const actionLabels={install:'Install',update:'Update',rollback:'Roll back'};
      async function readReceiver(){
        inspect.disabled=true;releases.replaceChildren();receiverStatus.textContent='Checking selected receiver…';
        try{
          const info=await request('/api/widgets/manager','GET');
          if(closed)return;
          if(info?.ok!==true){
            receiverStatus.textContent=errors[info?.error]||'NetRunner status is unavailable.';
            return;
          }
          receiverStatus.textContent=info.installed_version?'Installed NetRunner '+info.installed_version:
            info.files_present?'Installed NetRunner version could not be verified.':'NetRunner files are absent.';
          for(const archive of info.release_archives||[]){
            if(typeof archive.id!=='string'||!/^[a-z0-9][a-z0-9.-]{0,63}$/.test(archive.id))continue;
            const filename=archive.id+'.zip';
            if(archive.state==='invalid'){
              receiverStatus.textContent+=' Replace '+filename+' with the official download.';
            }else if(archive.state==='missing'){
              receiverStatus.textContent+=' Add '+filename+' to the Widgets folder.';
            }
          }
          if(!info.available_releases?.length)return;
          for(const release of info.available_releases){
            const label=actionLabels[release.action];
            if(!label||typeof release.id!=='string'||typeof release.version!=='string')continue;
            const button=node('button',label+' '+release.version,'secondary');button.type='button';
            button.onclick=async()=>{
              if(inspect.disabled||!confirmAction?.(label+' NetRunner '+release.version+
                  ' on receiver '+info.receiver.serial_number+'?'))return;
              inspect.disabled=true;releases.replaceChildren();
              receiverStatus.textContent=label+' requested for NetRunner '+release.version+'…';
              receiverStatus.focus();
              try{
                const result=await request('/api/widgets/manager/action','POST',{
                  widget_id:'netrunner',action:release.action,release_id:release.id,
                  confirm:true,expected_target:info.receiver
                });
                if(closed)return;
                receiverStatus.textContent=result?.ok===true?'NetRunner files verified for '+release.version+'. Check the selected receiver to refresh status.':
                  errors[result?.error]||'NetRunner action was not confirmed. Check the receiver before retrying.';
              }catch{
                if(!closed)receiverStatus.textContent='NetRunner action was not confirmed. Check the receiver before retrying.';
              }finally{if(!closed)inspect.disabled=false;}
            };
            releases.appendChild(button);
          }
        }catch{
          if(!closed)receiverStatus.textContent='NetRunner status is unavailable.';
        }finally{if(!closed)inspect.disabled=false;}
      }
      inspect.onclick=readReceiver;
    }
    function valid(doc){
      if(!doc||doc.schema!=='ascent.widget_catalog_host.v0'||!phases.has(doc.phase)||
         !Number.isSafeInteger(doc.generation)||doc.generation<0||doc.registration_performed!==false||
         doc.activation_performed!==false||doc.installation_checked!==false)return false;
      if(doc.phase==='COMPLETE'){
        const report=doc.result;
        if(!report||report.schema!=='ascent.widget_catalog.v0'||report.read_only!==true||
           report.registration_performed!==false||report.activation_performed!==false||
           report.installation_checked!==false||!Array.isArray(report.entries)||report.entries.length>64)return false;
        if(report.status==='OK'&&report.complete!==true)return false;
        if(report.status!=='OK'&&report.entries.length)return false;
      }
      return true;
    }
    const label=(labels,key,fallback)=>typeof key==='string'&&Object.prototype.hasOwnProperty.call(labels,key)?labels[key]:fallback;
    const text=(value,limit)=>typeof value==='string'&&value.length<=limit?value:'Not reported';
    function say(value){if(status.textContent!==value)status.textContent=value;}
    function draw(){
      open.disabled=rescan.disabled=pending||observation?.phase==='CLOSED';
      rows.replaceChildren();time.textContent='';result.textContent=actionResult;
      if(error){say(error);return;}
      if(!observation){say(pending?'Reading catalog status…':'Catalog has not been read.');return;}
      const phase=observation.phase;
      if(phase==='SCANNING')say('Checking widget packages…');
      else if(phase==='SCAN_DELAYED')say('Folder scan is taking longer than expected.');
      else if(phase==='FAILED')say('Catalog scan failed. Rescan to check again.');
      else if(phase==='CLOSED')say('Catalog host is closing.');
      else if(phase==='NOT_STARTED')say('Catalog scan has not started.');
      else {
        const report=observation.result;
        say(report.status==='OK'?(report.entries.length?'Widget package checks completed.':'No ZIP widget packages found.'):
          label(folderStates,report.status,'Catalog result is unavailable.'));
        if(typeof observation.observed_at==='string'&&observation.observed_at.length<=64&&/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/.test(observation.observed_at)&&Number.isFinite(Date.parse(observation.observed_at)))
          time.textContent='Last scan completed at '+new Date(observation.observed_at).toISOString();
        for(const entry of report.entries){
          const row=node('tr');
          const verified=['VALIDATED_PREVIEW','DUPLICATE_COPY','VERSION_CONFLICT'].includes(entry?.status)&&entry.package?.validated===true&&
            entry.package.executable===false&&entry.package.publisher_verified===false;
          const values=[verified?text(entry.package.id,64):'Not validated',verified?text(entry.package.version,64):'Not established',
            text(entry?.source_name,255),label(packageStates,entry?.status,'Package check unavailable')];
          if(entry?.status==='VALIDATED_PREVIEW'&&!verified)values[3]='Package check unavailable';
          for(const [index,value] of values.entries()){const cell=node('td');cell.style.overflowWrap='anywhere';if(index<3)cell.className='mono';const isolated=node('bdi',value);cell.appendChild(isolated);row.appendChild(cell);}
          rows.appendChild(row);
        }
      }
    }
    function clearTimer(){if(timer!==null){cancel(timer);timer=null;}}
    function failure(code,action){
      if(code==='DESKTOP_HOST_SESSION_REQUIRED')return 'This catalog requires the desktop host session.';
      if(code==='FOLDER_OPEN_UNSUPPORTED')return 'Folder opening is available in the Windows desktop application.';
      if(code==='FOLDER_OPEN_REFUSED')return 'Folder opening was not confirmed. Check the Widgets folder before retrying.';
      if(code==='CATALOG_NOT_STARTED')return 'Catalog host is not available.';
      return action==='open'?'Folder-opening request did not finish. Check whether the folder opened before retrying.':
        action==='rescan'?'Rescan request did not finish. Catalog state is not established.':'Catalog status could not be read.';
    }
    async function read(action){
      if(closed||pending||observation?.phase==='CLOSED')return;
      clearTimer();pending=true;const serial=++epoch;error='';actionResult='';
      if(action)observation=null;
      draw();
      let actionAccepted=false;
      try{
        let reply=await request(action?paths[action]:paths.status,action?'POST':'GET');
        if(closed||serial!==epoch)return;
        if(reply?.error)throw {code:reply.error};
        if(action==='open'){
          if(reply?.ok!==true||reply.open_requested!==true)throw {code:'OPEN_NOT_CONFIRMED'};
          actionAccepted=true;actionResult='Folder opening requested.';
          reply=await request(paths.status,'GET');
          if(closed||serial!==epoch)return;
          if(reply?.error)throw {code:reply.error};
        }
        if(!valid(reply))throw {code:'INVALID_CATALOG_REPLY'};
        observation=reply;
      }catch(problem){
        if(closed||serial!==epoch)return;
        observation=null;error=failure(problem?.code,actionAccepted?null:action);
      }finally{
        if(!closed&&serial===epoch){
          pending=false;draw();
          if(observation&&['SCANNING','SCAN_DELAYED'].includes(observation.phase))
            timer=schedule(()=>{timer=null;read();},750);
        }
      }
    }
    open.onclick=()=>read('open');rescan.onclick=()=>read('rescan');
    draw();read();
    return {close(){closed=true;epoch++;clearTimer();}};
  }
  global.AscentWidgetCatalog=Object.freeze({mount});
})(globalThis);
