"""Source-binding call order with fake sockets; no receiver contacted."""
from types import SimpleNamespace
import os
import socket
import struct
import pytest
from ascent_core.service_access import AccessDenied
from ascent_core.service_channel import windows_source_socket, IP_UNICAST_IF


def target(index=17):
    return SimpleNamespace(interface_index=index, source_ip='192.0.2.20', host='192.0.2.21')


def test_socket_interface_and_source_are_pinned_before_connect():
    events=[]
    class Stream:
        def setsockopt(self,*args):events.append(('option',args))
        def bind(self,value):events.append(('bind',value))
        def settimeout(self,value):events.append(('timeout',value))
        def connect(self,value):events.append(('connect',value))
        def close(self):events.append(('close',))
    stream=windows_source_socket(target(),lambda:events.append(('check',)),socket_factory=lambda *args:Stream())
    assert events==[('check',),('option',(socket.IPPROTO_IP,IP_UNICAST_IF,struct.pack('!I',17))),
        ('bind',('192.0.2.20',0)),('timeout',2),('check',),('connect',('192.0.2.21',22)),('check',)]


@pytest.mark.parametrize('index',[None,0,-1,True,2**24])
def test_invalid_interface_does_not_open_socket(index):
    with pytest.raises(AccessDenied):
        windows_source_socket(target(index),lambda:None,socket_factory=lambda *args:pytest.fail('must not open'))


def test_revocation_after_connect_closes_socket():
    events=[];checks=[]
    class Stream:
        def setsockopt(self,*args):pass
        def bind(self,*args):pass
        def settimeout(self,*args):pass
        def connect(self,*args):events.append('connected')
        def close(self):events.append('closed')
    def check():
        checks.append(1)
        if len(checks)==3:raise AccessDenied('RECEIVER_BINDING_CHANGED')
    with pytest.raises(AccessDenied):windows_source_socket(target(),check,socket_factory=lambda *args:Stream())
    assert events==['connected','closed']


@pytest.mark.skipif(os.environ.get('ASCENT_TEST_LOOPBACK_SSH') != '1',
                    reason='Explicit owned localhost fixture opt-in')
def test_relay_rechecks_revocation_while_connection_is_open():
    from threading import Event
    from ascent_core.service_channel import SelectedSshChannel
    revoked, observed = Event(), Event()
    upstream, peer = socket.socketpair()
    def check():
        if revoked.is_set():
            observed.set()
            raise AccessDenied('RECEIVER_BINDING_CHANGED')
    try:
        with pytest.raises(AccessDenied, match='RECEIVER_BINDING_CHANGED'):
            with SelectedSshChannel(connector=lambda target, guard: upstream).open(target(), check) as address:
                with socket.create_connection(address, timeout=1) as client:
                    peer.settimeout(1)
                    client.sendall(b'synthetic-first-step')
                    assert peer.recv(64) == b'synthetic-first-step'
                    revoked.set()
                    assert observed.wait(1), 'revocation must be observed during the open channel'
                    assert client.recv(1) == b''
    finally:
        upstream.close()
        peer.close()
