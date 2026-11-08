# Public profile: shared CRSF owner retained; private consumers absent.
"""Current receiver/controller observations via real consumers; no hardware or output I/O."""
import copy
import json
import itertools
from pathlib import Path
import sys
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'runtime'))
import caddx_hid as H
import hid_source as S
import dev_harness as D


ORDERS=itertools.count(1)

def connection(epoch='one',reverse=False,device='path-observation',product='EdgeTX Joystick'):
    axes=[dict(usage_page=1,usage=u,logical_min=0,logical_max=2048,bit_size=12,report_id=0,link_collection=0) for u in range(0x30,0x38)]
    if reverse:axes.reverse()
    return dict(action='connect',epoch=epoch,epoch_order=next(ORDERS),device=dict(device_id=device,product=product,vendor_id=0x1209,product_id=0x4f54),
        descriptor=dict(axes=axes,buttons=[dict(usage_page=9,usage=u,logical_min=0,logical_max=1) for u in range(1,25)],report_length=16))


def stream():return H.CrsfStream(lambda _:pytest.fail('unexpected output'))
def sample(epoch='one',sequence=1):return dict(epoch=epoch,sequence=sequence,axes=[1024]*8,raw_axes=[1024]*8,buttons=[False]*24)
def mapping():return H.ChannelMap([dict(source='axis',index=i) for i in range(8)]+[dict(source='button',index=i) for i in range(8)])


def test_classic_reversed_cap_order_preserves_arrays_but_exposes_canonical_usage_identity():
    s=stream();s.source_event(connection(reverse=True));s.source_sample(sample())
    state=s.state();assert [i['logical_channel'] for i in state['inputs']]==[f'CH{i}' for i in range(8,0,-1)]
    assert [i['usage'] for i in state['inputs']]==list(range(0x37,0x2f,-1))
    assert [i['logical_channel'] for i in state['button_inputs']]==[f'CH{i}' for i in range(9,33)]
    assert len(state['buttons'])==24 and all(i['raw']==1024 for i in state['inputs'])
    s.set_channel_map(mapping());assert s.channel_map.entries[0]['input_id']==state['inputs'][0]['input_id']
    assert s.rc_source_status()['profile_kind']=='edgetx_classic'


@pytest.mark.parametrize('mutation',['device','order','range','usage','buttons'])
def test_changed_observation_invalidates_mapping_calibration_and_current_input(mutation):
    s=stream();s.source_event(connection());s.source_sample(sample());s.set_channel_map(mapping());s.start_calibration(8)
    new=connection('two')
    if mutation=='device':new['device']['device_id']='other'
    if mutation=='order':new['descriptor']['axes'].reverse()
    if mutation=='range':new['descriptor']['axes'][0]['logical_max']=4096
    if mutation=='usage':new['descriptor']['axes'][0]['usage']=0x38
    if mutation=='buttons':new['descriptor']['buttons'].pop()
    s.source_event(new);st=s.state()
    assert st['mapping_revalidation']['channels'][0]['source']=='axis'
    assert not st['map_complete'] and st['calibration'] is None and st['axes'] is None and not st['running']
    assert not s.rc_source_status()['input_fresh']
    with pytest.raises(H.HidError,match='inactive reader'):s.source_sample(sample())


def test_same_compatible_reconnect_preserves_map_but_requires_new_observation():
    s=stream();s.source_event(connection());s.source_sample(sample());s.set_channel_map(mapping())
    s.source_event(dict(action='disconnect',epoch='one'))
    assert not s.rc_source_status()['device_present'] and s.state()['axes'] is None
    s.source_event(connection('two'));assert s.channel_map.complete and not s.rc_source_status()['input_fresh']
    assert s.source_event(dict(action='disconnect',epoch='one')) is False
    s.source_sample(sample('two'));assert s.rc_source_status()['input_fresh']


def test_duplicate_missing_usage_and_invalid_range_refused_without_replacing_current_source():
    s=stream();s.source_event(connection())
    for bad in ('duplicate','missing','range'):
        c=connection('two')
        if bad=='duplicate':c['descriptor']['axes'][1]=copy.deepcopy(c['descriptor']['axes'][0])
        if bad=='missing':c['descriptor']['axes'][0].pop('usage')
        if bad=='range':c['descriptor']['axes'][0]['logical_max']=0
        with pytest.raises(H.HidError) as e:s.source_event(c)
        assert e.value.code=='HID_DESCRIPTOR_INVALID' and s._hid_source['epoch']=='one'


def test_late_partial_malformed_and_unscoped_samples_never_refresh_source():
    s=stream();s.source_event(connection());s.source_sample(sample())
    for body in (sample(sequence=1),dict(sample(sequence=2),axes=[1]),dict(sample(sequence=2),raw_axes=[1]*8),sample('other')):
        before=s._axes_at
        with pytest.raises(H.HidError):s.source_sample(body)
        assert s._axes_at==before
    with pytest.raises(H.HidError):s.update_axes([1024]*8)


def test_status_staleness_and_profile_unknown_do_not_claim_absence_or_physical_effect(monkeypatch):
    s=stream();c=connection(product='Unidentified controller');c['device']['vendor_id']=42
    s.source_event(c);s.source_sample(sample());s.set_channel_map(mapping())
    assert s.rc_source_status()['recognized_family'] is None
    monkeypatch.setattr(H.time,'monotonic',lambda:s._axes_at+1)
    st=s.rc_source_status();assert st['device_present'] and not st['input_fresh'] and st['mapping_present']
    assert st['physical_effect_verified'] is None


@pytest.mark.parametrize('product,model',[('RadioMaster GX12','radiomaster_gx12'),('RadioMaster Zorro','radiomaster_zorro'),('RadioMaster Boxer','radiomaster_boxer'),('RadioMaster Pocket','radiomaster_pocket'),('RadioMaster AX12','radiomaster_ax12'),('RadioMaster TX16S','radiomaster_tx16s'),('TBS Tango 2','tbs_tango2'),('Other GX12',None)])
def test_model_is_presentation_hint_not_control_authorization(product,model):
    s=stream();s.source_event(connection(product=product));assert s.rc_source_status()['model']==model
    assert not s.channel_map.complete and not s.running


def test_real_backend_facades_share_one_status_owner(monkeypatch):
    s=stream();monkeypatch.setattr(D,'CRSF_STREAM',s);monkeypatch.setattr(D,'cgc_eligibility',lambda:{})
    D.hid_source(connection());D.hid_axes(sample());D.hid_channel_map({'channels':mapping().entries,'epoch':s._hid_source['epoch'],'descriptor_id':s._hid_source['fingerprint']})
    status=D.hid_state()['rc_source'];zoom=D.rc_source_document()
    assert status['epoch']==zoom['epoch']=='one' and status['profile_kind']==zoom['profile_kind']=='edgetx_classic'
    D.hid_source(dict(action='disconnect',epoch='one'))
    assert not D.hid_state()['rc_source']['input_fresh']


def test_selected_receiver_change_refuses_before_opening_a_socket(monkeypatch):
    s=stream();s._output_scope='old';monkeypatch.setattr(D,'CRSF_STREAM',s)
    monkeypatch.setattr(D,'_hid_receiver_scope',lambda:'new')
    monkeypatch.setattr(D.socket,'socket',lambda *a:pytest.fail('must refuse before socket'))
    with pytest.raises(H.HidError) as e:D._crsf_socket_send(b'not-sent')
    assert e.value.code=='HID_RECEIVER_CHANGED'


def test_base_has_shared_source_without_private_picker_or_zoom_consumer(monkeypatch):
    s=stream();s.source_event(connection());s.source_sample(sample())
    monkeypatch.setattr(D,'CRSF_STREAM',s)
    doc=D.rc_source_document()
    assert doc['epoch']=='one' and doc['assigned_features']==[]
    assert not hasattr(D,'picker_document') and not hasattr(D,'RC_ZOOM')


def test_unexpanded_ranges_and_fractional_metadata_are_refused():
    for update in ({'usage_max':0x37},{'usage':48.5}):
        c=connection();c['descriptor']['axes'][0].update(update)
        with pytest.raises(ValueError):S.descriptor(c['descriptor'])


def test_mapping_from_prior_input_identity_is_refused_after_layout_change():
    s=stream();s.source_event(connection());s.source_sample(sample());s.set_channel_map(mapping())
    old=copy.deepcopy(s.channel_map.entries)
    s.source_event(connection('two',reverse=True));s.source_sample(sample('two'))
    with pytest.raises(H.HidError) as e:s.set_channel_map(H.ChannelMap(old))
    assert e.value.code=='HID_MAPPING_IDENTITY_CHANGED' and not s.channel_map.complete


def test_source_state_is_a_copy_not_another_mutable_owner():
    s=stream();s.source_event(connection());state=s.state()
    state['source_identity']['layout']['axes'][0]['usage']=0x38
    assert s._hid_source['layout']['axes'][0]['usage']==0x30


def test_target_change_during_socket_setup_refuses_before_datagram(monkeypatch):
    s=stream();s._output_scope='old';monkeypatch.setattr(D,'CRSF_STREAM',s)
    observations=iter(['old','new'])
    monkeypatch.setattr(D,'_hid_receiver_scope',lambda:next(observations))
    monkeypatch.setattr(D,'_require_binding',lambda *args:('192.0.2.2',7))
    monkeypatch.setattr(D,'_pin_windows_ipv4_interface',lambda *args:None)
    class Socket:
        def __enter__(self):return self
        def __exit__(self,*a):pass
        def bind(self,*a):pass
        def connect(self,*a):pass
        def send(self,*a):pytest.fail('datagram must not be sent')
    monkeypatch.setattr(D.socket,'socket',lambda *a:Socket())
    with pytest.raises(H.HidError) as e:D._crsf_socket_send(b'not sent')
    assert e.value.code=='HID_RECEIVER_CHANGED'


def test_delayed_connect_cannot_replace_a_newer_reader_registration():
    s=stream();old=connection();new=connection('two')
    s.source_event(new)
    with pytest.raises(H.HidError) as e:s.source_event(old)
    assert e.value.code=='HID_SOURCE_OLD' and s._hid_source['epoch']=='two'


def test_stale_live_configuration_cannot_apply_to_reconnected_descriptor(monkeypatch):
    s=stream();monkeypatch.setattr(D,'CRSF_STREAM',s);monkeypatch.setattr(D,'cgc_eligibility',lambda:{})
    s.source_event(connection());s.source_sample(sample())
    body=dict(channels=mapping().entries,epoch='one',descriptor_id=s._hid_source['fingerprint'])
    s.source_event(connection('two',reverse=True))
    with pytest.raises(H.HidError) as e:D.hid_channel_map(body)
    assert e.value.code=='HID_SOURCE_CHANGED' and not s.channel_map.complete
    # Stop remains safe even when the page is stale.
    assert D.hid_stream({'action':'stop'})['stream']['running'] is False


def test_supplied_artwork_originals_have_provenance_and_do_not_gate_controls():
    root=Path(__file__).resolve().parents[1]/'runtime/www/assets/rc'
    provenance=json.loads((root/'PROVENANCE.json').read_text())
    import hashlib
    assert len(provenance['files'])==16
    assert not any('controller' in row['path'].lower() for row in provenance['files'])
    for item in provenance['files']:
        raw=(root/item['path']).read_bytes()
        assert len(raw)==item['bytes'] and hashlib.sha256(raw).hexdigest()==item['sha256']
    generic=connection(product='Unrecognized controller');generic['device']['vendor_id']=99
    s=stream();s.source_event(generic);s.source_sample(sample());s.set_channel_map(mapping())
    assert s.state()['map_complete'] and s.rc_source_status()['model'] is None


def test_hid_envelope_cannot_mix_input_and_status_epochs(monkeypatch):
    import threading
    s=stream();s.source_event(connection());s.source_sample(sample())
    monkeypatch.setattr(D,'CRSF_STREAM',s);monkeypatch.setattr(D,'cgc_eligibility',lambda:{})
    original=s.state;started=threading.Event();finished=threading.Event();workers=[];first=[True]
    def change():
        started.set();s.source_event(connection('two'));finished.set()
    def observed():
        result=original()
        if first[0]:
            first[0]=False;t=threading.Thread(target=change);workers.append(t);t.start()
            assert started.wait(1)
            finished.wait(.03) # A source switch must wait for the envelope boundary.
        return result
    monkeypatch.setattr(s,'state',observed)
    result=D.hid_state()
    for worker in workers:worker.join(1)
    assert finished.is_set()
    assert result['stream']['source_identity']['epoch']==result['rc_source']['epoch']=='one'


def test_queued_live_start_cannot_follow_a_receiver_selection_change(monkeypatch):
    s=stream();s.source_event(connection());s.source_sample(sample());s.set_channel_map(mapping())
    monkeypatch.setattr(D,'CRSF_STREAM',s);monkeypatch.setattr(D,'_cgc_guard',lambda:None)
    monkeypatch.setattr(D,'_hid_receiver_identity_token',lambda:'new-selected-receiver')
    body=dict(action='start',apply=True,epoch='one',descriptor_id=s._hid_source['fingerprint'],receiver_token='previous-selected-receiver')
    with pytest.raises(H.HidError) as e:D.hid_stream(body)
    assert e.value.code=='HID_RECEIVER_CHANGED' and not s.running


def test_receiver_change_during_start_preparation_refuses_before_thread(monkeypatch):
    s=stream();s.source_event(connection());s.source_sample(sample());s.set_channel_map(mapping())
    monkeypatch.setattr(D,'CRSF_STREAM',s);monkeypatch.setattr(D,'_cgc_guard',lambda:None)
    tokens=iter(['initial','changed'])
    monkeypatch.setattr(D,'_hid_receiver_identity_token',lambda:next(tokens))
    monkeypatch.setattr(D,'_hid_receiver_scope',lambda:'prepared scope')
    with pytest.raises(H.HidError) as e:D.hid_stream(dict(action='start',apply=True,epoch='one',descriptor_id=s._hid_source['fingerprint'],receiver_token='initial'))
    assert e.value.code=='HID_RECEIVER_CHANGED' and not s.running
