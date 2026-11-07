"""Bounded descriptor identity and RC presentation. No device I/O or control owner."""
from __future__ import annotations
import hashlib
import json
import re

CLASSIC_USAGES=tuple(range(0x30,0x38))


def controller_collection(page,usage):
    return page==1 and usage in (4,5)


def descriptor(document):
    if not isinstance(document,dict):raise ValueError('HID descriptor document required')
    if any(k in document for k in ('collection_usage_page','collection_usage')) and not controller_collection(document.get('collection_usage_page'),document.get('collection_usage')):
        raise ValueError('Joystick or Game Pad collection required')
    axes=document.get('axes',[])
    buttons=document.get('buttons',[])
    hats=document.get('hats',[])
    if not isinstance(hats,list) or len(hats)>16:raise ValueError('Invalid HID hats')
    if not isinstance(axes,list) or not isinstance(buttons,list):raise ValueError('HID input lists required')
    if not 1<=len(axes)<=128 or len(buttons)>1024:raise ValueError('Invalid HID descriptor dimensions')
    result=[];seen=set()
    for kind,items in (('axis',axes),('button',buttons),('hat',hats)):
        target=[]
        for item in items:
            if not isinstance(item,dict):raise ValueError('HID usage metadata required')
            if any(type(v) is not int for k,v in item.items() if v is not None and k in ('usage_page','usage','report_id','link_collection','bit_size','logical_min','logical_max','data_index')):
                raise ValueError('HID metadata fields must be integers')
            if 'usage_max' in item and item['usage_max']!=item.get('usage'):raise ValueError('HID ranges must be expanded before identity assignment')
            row={key:int(item.get(key,0)) for key in ('usage_page','usage','report_id','link_collection','bit_size','logical_min','logical_max')}
            if not 0<=row['usage_page']<=65535 or not 1<=row['usage']<=65535 or not 0<=row['report_id']<=255:raise ValueError('Invalid HID usage')
            key=f"{kind}:{row['usage_page']:04x}:{row['usage']:04x}:{row['report_id']}:{row['link_collection']}"
            if item.get('data_index') is not None:
                index=item['data_index']
                if type(index) is not int or not 0<=index<=65535:raise ValueError('Invalid HID data index')
                row['data_index']=index;key+=f':data:{index}'
            if key in seen:raise ValueError('Duplicate HID input identity')
            if not 0<=row['link_collection']<=65535 or not 0<=row['bit_size']<=32:raise ValueError('Invalid HID report metadata')
            if kind in ('axis','hat') and row['logical_max']<=row['logical_min']:raise ValueError('Invalid HID logical range')
            if kind=='hat' and (row['usage_page'],row['usage'])!=(1,0x39):raise ValueError('Invalid hat usage')
            if kind=='axis' and (row['usage_page'],row['usage'])==(1,0x39):raise ValueError('Hat must be separate from analog axes')
            seen.add(key);target.append(dict(row,input_id=key))
        result.append(target)
    for rows in result:
        indices=[(r['report_id'],r['data_index']) for r in rows if 'data_index' in r]
        if len(indices)!=len(set(indices)):raise ValueError('Repeated HID data field')
        counts={}
        for row in rows:counts[row['usage']]=counts.get(row['usage'],0)+1
        positions={}
        for row in rows:
            usage=row['usage'];positions[usage]=positions.get(usage,0)+1
            name={0x30:'X',0x31:'Y',0x32:'Z',0x33:'Rx',0x34:'Ry',0x35:'Rz',0x36:'Slider',0x37:'Dial',0x39:'Hat'}.get(usage,f'Usage {usage:04x}')
            row['label']=name+(f' {positions[usage]}' if counts[usage]>1 else '')
    canonical=dict(axes=result[0],buttons=result[1],report_length=int(document.get('report_length',0)))
    if hats:canonical['hats']=result[2]
    for key in ('collection_usage_page','collection_usage'):
        if key in document:
            if type(document[key]) is not int or not 0<=document[key]<=65535:raise ValueError('Invalid HID collection')
            canonical[key]=document[key]
    fingerprint=hashlib.sha256(json.dumps(canonical,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    return canonical,fingerprint


def recognition(device,layout):
    usages=[(a['usage_page'],a['usage']) for a in layout.get('axes',[])]
    buttons=[(b['usage_page'],b['usage']) for b in layout.get('buttons',[])]
    classic=(len(usages)==8 and set(usages)=={(1,u) for u in CLASSIC_USAGES}
             and len(buttons)==24 and set(buttons)=={(9,u) for u in range(1,25)})
    hint=device.get('vendor_id')==0x1209 and device.get('product_id')==0x4f54
    product=device.get('product') or ''
    manufacturer=device.get('manufacturer') or ''
    family=hint or bool(re.search(r'\b(open|edge)tx\b',manufacturer+' '+product,re.I))
    integrated=bool(re.search(r'\bsroc\s*x1\b',product,re.I) and re.search(r'\buxv technologies\b',manufacturer,re.I))
    rc_shape=len(usages)==8 and len(buttons)==24
    likely_rc=integrated or family or rc_shape or bool(re.search(r'\btbs\b',manufacturer+' '+product,re.I))
    profile='integrated_rc_hid' if integrated else 'edgetx_classic' if family and classic else 'edgetx_variant' if family else 'generic_rc_hid' if likely_rc else 'generic_hid'
    model=None
    if re.search(r'\bradiomaster\b',product,re.I):
        match=re.search(r'\b(zorro|boxer|pocket|gx12|ax12|tx16s?)\b',product,re.I)
        if match:model='radiomaster_'+match.group(1).lower()
    elif re.search(r'\btbs\b.*\btango\s*2\b',product,re.I):model='tbs_tango2'
    if integrated:model='sroc'
    return dict(manufacturer=manufacturer or None,collection_usage_page=layout.get('collection_usage_page'),collection_usage=layout.get('collection_usage'),axis_count=len(usages),button_count=len(buttons),hat_count=len(layout.get('hats',[])),hat_mapping_supported=False,recognized_family='EdgeTX' if family else None,likely_rc=likely_rc,supported_hid=bool(usages),canonical_classic=classic,physical_identity_known=False,
                profile_kind=profile,
                recognition_basis='USB/text family inference; descriptor profile assessed separately' if family else 'RC-shaped HID; firmware family unknown' if likely_rc else 'HID observation; family unknown',
                display_name=('UXV '+product if integrated else product) or 'HID controller',
                graphic_key='generic_rc' if likely_rc else 'generic_controller',model=model,model_basis='reported product string; presentation only' if model else None)


def status(source,stream,assigned_features=()):
    present=source.get('present',False);known=bool(source.get('device',{}).get('device_id'))
    current=present and bool(source.get('fingerprint'))
    fresh=bool(current and stream.get('axes') and not stream.get('axes_stale'))
    info=recognition(source.get('device',{}),source.get('layout',{}))
    return dict(info,device_present=present,device_identity_known=known,identity_scope='host endpoint observation; path/serial may be shared; not physical identity',
                descriptor_current=current,input_fresh=fresh,mapping_present=bool(stream.get('map_complete')),
                stream_running=bool(stream.get('running')),assigned_features=list(assigned_features),
                epoch=source.get('epoch'),descriptor_id=source.get('fingerprint'),
                physical_effect_verified=None,legacy_input=bool(not current and stream.get('axes')))
