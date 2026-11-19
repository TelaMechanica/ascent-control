"""Fixed network action surface, fresh readback gates and recorded reply semantics."""
from pathlib import Path
import sys,struct
from unittest.mock import patch
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'runtime'))
import caddx_relay_network_control as control
import caddx_relay_qos as qos
from test_network_connection_presets import target


class Socket:
    def __init__(self,raw):self.raw=raw;self.sent=[]
    def __enter__(self):return self
    def __exit__(self,*args):pass
    def bind(self,value):self.source=value
    def connect(self,value):self.endpoint=value
    def settimeout(self,value):pass
    def setsockopt(self,*args):pass
    def sendall(self,value):self.sent.append(value)
    def recv(self,count):result,self.raw=self.raw[:count],self.raw[count:];return result


def fresh_status(host,wid,name,**kwargs):
    r=target()['observed']['qos']['radios'][str(wid)]
    return {'error':None,'length_match':True,'decoded':{'local_mac4':r['local_mac'],'role_raw':r['role_raw'],'slot0_link_state':0}}


@pytest.mark.parametrize('action,pin',[('hf',0),('mf',48)])
@pytest.mark.parametrize('link_states',[(0,0),(0,2),(2,0),(2,2)])
def test_fixed_bind_actions_have_restore_guard_and_never_claim_execution(action,pin,link_states):
    s=Socket(qos.build_frame(0x0c000004,b''))
    def status(host,wid,name,**kwargs):
        reply=fresh_status(host,wid,name,**kwargs)
        reply['decoded']['slot0_link_state']=link_states[wid]
        return reply
    with patch.object(control.factory,'read_identity_role',return_value=target()['observed']['factory']),patch.object(control.qos,'read_qos',side_effect=status),patch.object(control.socket,'socket',return_value=s),patch.object(control.time,'sleep')as hold:
        result=control.perform(target(),action)
    assert s.endpoint==('192.168.1.105',50000) and s.source==('192.0.2.2',0)
    assert len(s.sent)==1
    text=s.sent[0][18:-1].decode()
    assert f'G=/sys/class/gpio/gpio{pin};' in text and 'sleep 1' in text
    assert "trap 'echo in"in text and '= in || exit 1'in text
    assert result['execution_verified'] is False and result['pairing_verified'] is False
    assert result['hold_seconds'] == 1
    hold.assert_called_once_with(1.2)


def test_swap_keeps_idle_link_requirement():
    status=fresh_status(None,0,'status')
    status['decoded']['slot0_link_state']=2
    with patch.object(control.factory,'read_identity_role',return_value=target()['observed']['factory']),patch.object(control.qos,'read_qos',return_value=status),patch.object(control.socket,'socket') as sock:
        with pytest.raises(control.NetworkControlError,match='Reverse Roles requires both radio links to be idle'):
            control.perform(target(),'swap')
    sock.assert_not_called()


def test_swap_reads_saved_mode_before_reboot():
    h=bytearray(16);struct.pack_into('<HHHH',h,0,0xfafa,1,0,1);struct.pack_into('<H',h,14,1)
    s=Socket(bytes(h)+b'\x01')
    with patch.object(control.factory,'read_identity_role',return_value=target()['observed']['factory']),patch.object(control.qos,'read_qos',side_effect=fresh_status),patch.object(control.factory,'_query',side_effect=[b'9001',b'\x03',b'\x02']),patch.object(control.socket,'socket',return_value=s):
        result=control.perform(target(),'swap')
    assert [v[16:]for v in s.sent]==[b'\x17\0\x02',b'\x09']
    assert result['saved_mode']==2 and result['requires_reconnect']
    assert not result['execution_verified']


def test_stale_identity_stops_before_any_mutation_socket():
    with patch.object(control.factory,'read_identity_role',return_value={'factory_serial':'different','cur_mode':3}),patch.object(control.socket,'socket')as sock:
        with pytest.raises(control.NetworkControlError,match='identity'):control.perform(target(),'hf')
    sock.assert_not_called()


@pytest.mark.parametrize('action',['shell','GPIO22','hf;reboot',None])
def test_arbitrary_control_text_is_not_offered(action):
    with patch.object(control.factory,'read_identity_role')as read:
        with pytest.raises(control.NetworkControlError):control.perform(target(),action)
    read.assert_not_called()
