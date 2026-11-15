"""One session owner for explicit IP presets; never borrow USB identity or writes."""
from pathlib import Path
import sys,copy,types
from unittest.mock import patch
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'runtime'))
import dev_harness as host
import device_session as model
import caddx_relay_network_control as control


def target():
    return {'id':'network:repeater_eth','kind':'repeater','device_ip':'192.168.1.105',
            'source_ip':'192.0.2.2','if_index':29,'connection_token':'selected-context',
            'observed':{'factory':{'factory_serial':'9001','cur_mode':3},'qos':{'connected':True,'radios':{
                '0':{'status_ok':True,'local_mac':bytes.fromhex('f200000e').hex(':'),'role_raw':0},
                '1':{'status_ok':True,'local_mac':bytes.fromhex('f2000009').hex(':'),'role_raw':1}}}}}


@pytest.fixture
def session(monkeypatch):
    mirror={}
    cache=model.InventoryCache(lambda:{'usb':[],'network':[]})
    session=model.DeviceSession(mirror=mirror,inventory=cache,policy={'ground':'192.168.3.102'})
    monkeypatch.setattr(host,'SESSION',session)
    monkeypatch.setattr(host.smaudit,'append',lambda record:record)
    monkeypatch.setattr(host,'serial_read_bundle',lambda *a,**k:pytest.fail('Ethernet connect opened USB'))
    monkeypatch.setattr(host,'resolve_nic_for_ip',lambda ip:{'source_ip':'192.0.2.2','if_index':29})
    return session,mirror


def test_repeater_preset_replaces_usb_context_without_fabricated_identity(session,monkeypatch):
    s,mirror=session
    s.connect(candidate={'id':'usb','serial_com':'COM41'},identity={'device_name':'Ascent_Relay','serial_number':'4_9001'},ground_status={'local_bb_id':'old'})
    observed=target()['observed']
    monkeypatch.setattr(host,'repeater_network_read',lambda body:{**copy.deepcopy(observed),'reachable':True,'source_ip':'192.0.2.2','if_index':29,'captured_at':'now'})
    result=host.connect_host('network:repeater_eth')
    assert result['connected'] and result['serial_identity'] is None
    assert not result['identity_proven'] and result['network_binding'] is None
    assert result['network_target']['device_ip']=='192.168.1.105'
    assert result['network_target']['connection_token']
    assert s.serial_port() is None and s.network_binding() is None
    assert mirror['serial_identity'] is None and mirror['ground_status'] is None
    assert mirror['rf_bands'] is None and s.still_present({'usb':[]})
    generation=s.generation;s.clear()
    assert not s.connected and s.generation>generation and mirror['network_target'] is None


def test_max_preset_reads_one_bound_status_without_claiming_a_model(session,monkeypatch):
    calls=[]
    def status(ip,wid,name,**kw):
        calls.append((ip,wid,name,kw));return {'length_match':True,'error':None,'decoded':{'local_mac4':bytes.fromhex('F2000002').hex(':')}}
    monkeypatch.setattr(host.relayqos,'read_qos',status)
    result=host.connect_host('network:max_eth')
    assert result['connected'] and result['serial_identity'] is None
    assert calls==[('192.168.1.100',0,'status',{'source_ip':'192.0.2.2','if_index':29})]
    assert result['network_target']['label']=='MAX ETH'


def test_failed_ip_connect_clears_prior_target_and_never_falls_back_to_usb(session,monkeypatch):
    monkeypatch.setattr(host,'repeater_network_read',lambda body:{'reachable':False})
    result=host.connect_host('network:repeater_eth')
    assert not result['connected'] and not session[0].connected
    with pytest.raises(ValueError):host.connect_host('network:custom_unoffered')


def test_network_session_survives_unavailable_usb_inventory(session,monkeypatch):
    session[0].connect(candidate={'id':'network:repeater_eth','network_target':target()},identity={})
    snap=types.SimpleNamespace(ok=False,error='USB unavailable',meta=lambda:{'available':False})
    monkeypatch.setattr(host,'INVENTORY_CACHE',types.SimpleNamespace(get=lambda:snap))
    result=host.connection_inventory()
    assert result['active_candidate_id']=='network:repeater_eth'
    assert [p['label']for p in result['network_profiles']]==['REPEATER ETH','MAX ETH']
    assert result['usb_inventory_error']=='USB unavailable'


def test_control_requires_current_context_and_releases_all_locks(session,monkeypatch):
    s,_=session;t=target();s.connect(candidate={'id':t['id'],'network_target':t},identity={})
    monkeypatch.setattr(host,'DEVICE_OPERATION_STATE',{'active':False})
    calls=[]
    def perform(observed_target,action):
        assert host.NETWORK_SESSION_LOCK.locked() and host.DEVICE_MUTATION_LOCK.locked() and host.SERIAL_GATE.busy
        calls.append((observed_target,action));return {'ok':True,'action':action,'requires_reconnect':True}
    monkeypatch.setattr(host.relaynetwork,'perform',perform)
    assert host.repeater_network_control({'connection_token':'stale','action':'hf'})['error']=='TARGET_CHANGED'
    assert host.repeater_network_control({'connection_token':'selected-context','action':'swap'})['error']=='CONFIRM_REBOOT'
    result=host.repeater_network_control({'connection_token':'selected-context','action':'swap','confirm_reboot':True})
    assert result['ok'] and len(calls)==1 and s.device.network_target['requires_reconnect']
    assert not host.NETWORK_SESSION_LOCK.locked() and not host.DEVICE_MUTATION_LOCK.locked() and not host.SERIAL_GATE.busy
    assert host.repeater_network_control({'connection_token':'selected-context','action':'hf'})['error']=='RECONNECT_REQUIRED'


def test_control_refuses_route_changes_before_any_device_call(session,monkeypatch):
    t=target();session[0].connect(candidate={'id':t['id'],'network_target':t},identity={})
    monkeypatch.setattr(host,'resolve_nic_for_ip',lambda ip:{'source_ip':'192.0.2.3','if_index':31})
    with patch.object(host.relaynetwork,'perform')as perform:
        result=host.repeater_network_control({'connection_token':'selected-context','action':'hf'})
    assert result['error']=='NETWORK_ROUTE_CHANGED';perform.assert_not_called()


def test_network_pages_follow_transport_without_inventing_identity(session,monkeypatch):
    t=target();session[0].connect(candidate={'id':t['id'],'network_target':t},identity={})
    monkeypatch.setattr(host,'discovery_summary',lambda:{'reported':True,'candidates':0,'identified':0})
    doc=host.device_capabilities()
    assert doc['connection_state']=='connected_unrecognized'
    assert doc['source']=='selected_network_target' and not doc['name_consulted']
    assert doc['pages']['repeater']['visible'] and not doc['pages']['rf']['visible']
    assert not doc['pages']['hub']['visible'] and not doc['pages']['rc']['visible']


def test_changed_receiver_at_same_ip_requires_reconnect(session,monkeypatch):
    t=target();session[0].connect(candidate={'id':t['id'],'network_target':t},identity={})
    monkeypatch.setattr(host.relayfactory,'read_identity_role',lambda *a,**k:{'factory_serial':'different','cur_mode':3})
    monkeypatch.setattr(host.relayqos,'read_all_radios',lambda *a,**k:copy.deepcopy(t['observed']['qos']))
    result=host.repeater_network_read({'device_ip':t['device_ip']})
    assert result['requires_reconnect'] and session[0].device.network_target['requires_reconnect']
    assert host.repeater_network_control({'connection_token':t['connection_token'],'action':'hf'})['error']=='RECONNECT_REQUIRED'


def test_connect_and_disconnect_publish_after_connection_gate_releases(session,monkeypatch):
    monkeypatch.setattr(host,'_blocking_operation_active',lambda:False)
    monkeypatch.setattr(host,'HOST_STATE',{'shutting_down':False})
    def connect(cid):
        assert host.NETWORK_SESSION_LOCK.locked()
        return {'connected':True,'network_target':target()}
    monkeypatch.setattr(host,'connect_host',connect)
    for path,body in [('/api/connect',{'candidate_id':'network:repeater_eth'}),('/api/disconnect',{})]:
        handler=object.__new__(host.Handler);handler.path=path;handler._read_json_body=lambda:body
        handler.server=types.SimpleNamespace(server_address=('127.0.0.1',58000))
        handler.headers={'Host':'127.0.0.1:58000'}
        responses=[]
        def response(doc,status=200):
            assert not host.NETWORK_SESSION_LOCK.locked()
            responses.append((doc,status))
        handler.json_response=response;handler.do_POST()
        assert responses and responses[0][1]==200


def test_active_network_action_refuses_connect_and_disconnect(session,monkeypatch):
    monkeypatch.setattr(host,'_blocking_operation_active',lambda:False)
    monkeypatch.setattr(host,'HOST_STATE',{'shutting_down':False})
    monkeypatch.setattr(host,'DEVICE_OPERATION_STATE',{'active':False})
    with patch.object(host,'connect_host')as connect:
        host.NETWORK_SESSION_LOCK.acquire()
        try:
            for path in ['/api/connect','/api/disconnect']:
                handler=object.__new__(host.Handler);handler.path=path;handler._read_json_body=lambda:{'candidate_id':'network:max_eth'}
                handler.server=types.SimpleNamespace(server_address=('127.0.0.1',58000))
                handler.headers={'Host':'127.0.0.1:58000'}
                replies=[];handler.json_response=lambda doc,status=200:replies.append((doc,status))
                handler.do_POST();assert replies[0][1]==409 and replies[0][0]['error']=='DEVICE_BUSY'
        finally:host.NETWORK_SESSION_LOCK.release()
    connect.assert_not_called()
