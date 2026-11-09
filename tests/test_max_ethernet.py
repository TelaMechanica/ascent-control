"""Ethernet scope, bounded framing and explicit short-key dispatch; no hardware."""
import copy
from contextlib import nullcontext
import socket
import struct
import sys
import threading
from pathlib import Path
from types import SimpleNamespace
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'runtime'))
import max_ethernet as E
import caddx_relay_qos as F
import dev_harness as D


def target():
    return {'id':'network:max_eth','kind':'vrx','device_ip':'192.0.2.10','source_ip':'192.0.2.2','if_index':7,
            'connection_token':'session-one','observed':{'status':{'decoded':{'local_mac4':':'.join(f'{b:02X}' for b in bytes((242,0,0,1)))}}}}


def status(identity=b'\xf2\0\0\x01',link=2):
    out=bytearray(300);out[6:10]=identity;out[252]=link;out[253]=7;out[254:258]=b'\x66\0\0\0';return bytes(out)


class Wire:
    def __init__(self,data=b''):
        self.data=data;self.sent=[];self.bound=None;self.peer=None;self.closed=False
    def __enter__(self):return self
    def __exit__(self,*args):self.closed=True
    def bind(self,value):self.bound=value
    def settimeout(self,value):assert 0<value<=1.2
    def connect(self,value):self.peer=value
    def sendall(self,value):self.sent.append(value)
    def send(self,value):self.sent.append(value);return len(value)
    def recv(self,count):
        part=self.data[:min(count,11)];self.data=self.data[len(part):];return part


def install_wire(monkeypatch,wire):
    monkeypatch.setattr(E.socket,'socket',lambda *_:wire)
    monkeypatch.setattr(E.framing,'_pin_interface',lambda sock,index:None)


def test_rpc_reassembles_split_reply_and_pins_selected_endpoint(monkeypatch):
    wire=Wire(F.build_frame(E.READS['status'][0],status(),meta1=0xab82));install_wire(monkeypatch,wire)
    assert E.read_rpc(target(),'status')==status()
    assert wire.bound==('192.0.2.2',0)and wire.peer==('192.0.2.10',50000)and wire.closed
    assert wire.sent==[F.build_frame(E.READS['status'][0],b'\0\0')]


@pytest.mark.parametrize('change',['command','result','length','checksum','trailer','truncated'])
def test_bad_rpc_cannot_be_decoded(monkeypatch,change):
    command=E.READS['status'][0];payload=status();meta1=meta2=0
    if change=='command':command+=1
    if change=='result':meta2=1
    if change=='length':payload+=b'x'
    data=bytearray(F.build_frame(command,payload,meta1,meta2))
    if change=='checksum':data[17]^=1
    if change=='trailer':data[-1]=0
    if change=='truncated':data=data[:25]
    wire=Wire(bytes(data));install_wire(monkeypatch,wire)
    with pytest.raises((E.EthernetError,F.RelayQosError)):E.read_rpc(target(),'status')
    assert wire.closed


@pytest.mark.parametrize('key,value',[('device_ip','127.0.0.1'),('device_ip','224.0.0.1'),('source_ip',None),('if_index',True),('if_index',0),('kind','repeater'),('id','network:repeater_eth')])
def test_invalid_target_refuses_before_any_socket(monkeypatch,key,value):
    t=target();t[key]=value
    monkeypatch.setattr(E.socket,'socket',lambda *_:pytest.fail('unexpected socket'))
    with pytest.raises(E.EthernetError):E.read_rpc(t,'status')


def test_status_does_not_promote_peer_placeholder_or_unlinked_mcs():
    linked=E.decode('status',status());assert linked['link']=='LINKED'and linked['rx_mcs_raw']==7
    assert not any('peer'in k for k in linked)
    assert E.decode('status',status(link=0))['rx_mcs_raw']is None


@pytest.mark.parametrize('key',E.KEYS)
def test_only_short_named_key_datagram_is_sent_once(monkeypatch,key):
    wire=Wire();install_wire(monkeypatch,wire);result=E.send_key(target(),key)
    assert wire.peer==('192.0.2.10',9001)and wire.bound==('192.0.2.2',0)
    assert len(wire.sent)==1 and len(wire.sent[0])==13 and wire.sent[0][7]==0
    assert result['state']=='SENT'and result['execution_verified']is False and result['pairing_verified']is False


@pytest.mark.parametrize('body',[{'key':'REBOOT'},{'key':'UPGRADE'},{'key':'CONFIRM','press':'LONG'},{'key':'UP','host':'192.0.2.11'},{'key':'PAIRING'},{'key':'PAIRING','confirm_pairing':'true','acknowledge_non_stock':True}])
def test_unoffered_or_unconfirmed_request_refuses(body):
    with pytest.raises(E.EthernetError):E.key_request(body)


def test_pair_requires_explicit_boolean_confirmation():
    assert E.key_request({'key':'PAIRING','confirm_pairing':True,'acknowledge_non_stock':True})=='PAIRING'


def test_missing_anchor_keeps_readings_but_does_not_admit_keys():
    t=target();t['observed']={}
    doc=E.document(t,reader=lambda _,name:status()if name=='status'else bytes(E.READS[name][2]),rtsp=lambda _:{'responding':True})
    assert doc['reads']['status']['ok']and not doc['controls']['eligible']
    assert doc['rtsp']['responding']and not doc['identity_proven']


def test_selection_change_discards_read_result():
    count=0;called=[]
    def check():
        nonlocal count
        count+=1
        if count==2:raise E.EthernetError('MAX_ETH_TARGET_CHANGED','changed')
    with pytest.raises(E.EthernetError):E.document(target(),check=check,reader=lambda _,name:called.append(name)or status(),rtsp=lambda _:pytest.fail('late read'))
    assert called==['status']


def test_bad_field_is_partial_without_fake_units():
    def reader(_,name):
        if name=='status':return status()
        if name=='channels':raise TimeoutError('no reply')
        if name=='mcs':return b'\5\0\0\0'+struct.pack('<I',235)
        return bytes(E.READS[name][2])
    doc=E.document(target(),reader=reader,rtsp=lambda _:{'responding':True})
    assert doc['controls']['eligible']and not doc['reads']['channels']['ok']
    assert doc['reads']['mcs']['values']=={'mcs_encoded_raw':5,'throughput_raw':235}


@pytest.fixture
def host(monkeypatch):
    t=target();session=SimpleNamespace(device=SimpleNamespace(network_target=t),generation=4)
    monkeypatch.setattr(D,'SESSION',session)
    monkeypatch.setattr(D.maxeth,'fast_route',lambda _:dict(source_ip=t['source_ip'],if_index=t['if_index']))
    monkeypatch.setattr(D,'NETWORK_SESSION_LOCK',threading.Lock());monkeypatch.setattr(D,'DEVICE_MUTATION_LOCK',threading.Lock())
    monkeypatch.setattr(D,'DEVICE_OPERATION_STATE',{'active':False})
    monkeypatch.setattr(D,'SERIAL_GATE',SimpleNamespace(hold=lambda *a,**k:nullcontext()))
    monkeypatch.setattr(D.maxeth,'read_rpc',lambda *a,**k:status())
    calls=[];monkeypatch.setattr(D.maxeth,'send_key',lambda *a:calls.append(a)or{'ok':True,'execution_verified':False})
    return t,session,calls


def test_current_target_is_reproved_before_key(host):
    t,session,calls=host
    result=D.max_ethernet_key({'key':'CONFIRM','connection_token':t['connection_token']})
    assert result['ok']and len(calls)==1 and not D.DEVICE_MUTATION_LOCK.locked()and not D.NETWORK_SESSION_LOCK.locked()


@pytest.mark.parametrize('failure',['token','route','identity','generation','busy'])
def test_no_key_reaches_changed_or_busy_target(host,monkeypatch,failure):
    t,session,calls=host;body={'key':'UP','connection_token':t['connection_token']}
    if failure=='token':body['connection_token']='old-session'
    if failure=='route':monkeypatch.setattr(D.maxeth,'fast_route',lambda _:dict(source_ip='192.0.2.3',if_index=8))
    if failure=='identity':monkeypatch.setattr(D.maxeth,'read_rpc',lambda *a:status(b'\xf2\0\0\2'))
    if failure=='generation':
        def changed(*a):session.generation+=1;return status()
        monkeypatch.setattr(D.maxeth,'read_rpc',changed)
    if failure=='busy':D.DEVICE_OPERATION_STATE['active']=True
    result=D.max_ethernet_key(body)
    assert not result['ok']and not calls
    assert not D.DEVICE_MUTATION_LOCK.locked()and not D.NETWORK_SESSION_LOCK.locked()


def test_pair_cooldown_does_not_replay(host):
    t,session,calls=host;body={'key':'PAIRING','connection_token':t['connection_token'],'confirm_pairing':True,'acknowledge_non_stock':True}
    assert D.max_ethernet_key(body)['ok']
    assert not D.max_ethernet_key(body)['ok']and len(calls)==1


def test_actual_ethernet_ui_keeps_transport_scopes_and_video_controls():
    import subprocess
    root=Path(__file__).resolve().parents[1]
    r=subprocess.run(['node','tests/max_ethernet_ui_check.cjs'],cwd=root,capture_output=True,text=True)
    assert r.returncode==0,r.stdout+r.stderr
