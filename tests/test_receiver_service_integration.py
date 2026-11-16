"""Real SSH/forwarder/controller using owned localhost fixture; no receiver I/O."""
from contextlib import contextmanager
import getpass
import os
from pathlib import Path
import shutil
import socket
import time
import pytest
from ascent_core.receiver_ssh import ReadinessSsh, AuthenticationProof
from ascent_core.service_access import AccessDenied, ReceiverBinding
from ascent_core.service_channel import SelectedSshChannel, LOOPBACK
from ascent_core.service_credentials import ManagedCredential
from ascent_core.service_enrollment import ProtectedEnrollments
from ascent_core.service_receiver import ReceiverService
from ascent_core.service_records import host_key_fingerprint
from ascent_core.service_target import ReceiverTarget
from test_service_credentials import FakeProtection
from test_service_loopback_ssh import fixture_server

pytestmark=[pytest.mark.skipif(os.environ.get('ASCENT_TEST_LOOPBACK_SSH')!='1',reason='Explicit owned localhost SSH fixture opt-in'),
            pytest.mark.parametrize('fixture_server', ['noop'], indirect=True)]


class Selector:
    def __init__(self,target):self.target=target
    def capture(self):return self.target
    def check(self,target):
        if target!=self.target:raise AccessDenied('RECEIVER_BINDING_CHANGED')
    check_selection=check


def compose(server,tmp_path,*,wrong_client=False):
    root,port,ssh,_=server
    keyscan=shutil.which('ssh-keyscan');assert keyscan
    tools=tmp_path/'tools';(tools/'OpenSSH').mkdir(parents=True)
    (tools/'OpenSSH/ssh.exe').symlink_to(ssh)
    (tools/'OpenSSH/ssh-keyscan.exe').symlink_to(keyscan)
    @contextmanager
    def directory():
        folder=tmp_path/'working';folder.mkdir(exist_ok=True)
        yield folder,{'PATH':os.defpath,'LANG':'C'},tools
    name='wrong-client' if wrong_client else 'client'
    credential=ManagedCredential((root/(name+'.pub')).read_text().strip(),(root/name).read_bytes())
    @contextmanager
    def materialize(current):
        assert current==credential
        yield root/name,{'PATH':os.defpath,'LANG':'C'},tools
    target=ReceiverTarget(ReceiverBinding(1,'synthetic-receiver','synthetic-binding'),LOOPBACK,LOOPBACK,1,
                          'synthetic-port','synthetic-firmware','synthetic-receiver')
    selector=Selector(target)
    def connector(selected,check):
        check();return socket.create_connection((LOOPBACK,port),timeout=2)
    transport=ReadinessSsh(channel=SelectedSshChannel(connector=connector),username=getpass.getuser(),
                          key_directory=directory,materializer=materialize)
    class Vault:
        def load(self):return credential
    store=ProtectedEnrollments(tmp_path/'records',protector=FakeProtection())
    state=[True]
    controller=ReceiverService(selector=selector,credentials=lambda kind:Vault(),enrollments=store,
                               transport=transport,enabled=lambda:state[0])
    return controller,transport,store,selector,state,credential


def test_actual_observation_authentication_and_trust_commit(fixture_server,tmp_path):
    controller,transport,store,selector,_,_=compose(fixture_server,tmp_path)
    observation=controller.inspect()
    assert observation['ssh_authenticated'] is False
    assert observation['host_key_algorithm']=='ecdsa-sha2-nistp256'
    assert store.lookup(selector.target.binding.receiver_identity) is None
    result=controller.verify(observation['observation_id'],observation['host_fingerprint'],confirmed=True)
    assert result['ssh_authenticated'] is True and result['receiver_mutation_available'] is False
    assert store.lookup(selector.target.binding.receiver_identity) is not None
    assert not transport._proofs


def test_wrong_client_never_creates_trust_record(fixture_server,tmp_path):
    controller,transport,store,selector,_,_=compose(fixture_server,tmp_path,wrong_client=True)
    observation=controller.inspect()
    with pytest.raises(AccessDenied,match='READINESS_NOT_VERIFIED'):
        controller.verify(observation['observation_id'],observation['host_fingerprint'],confirmed=True)
    assert store.lookup(selector.target.binding.receiver_identity) is None
    assert not transport._proofs


def test_confirmation_and_observation_are_not_authentication(fixture_server,tmp_path):
    controller,transport,store,selector,_,_=compose(fixture_server,tmp_path)
    observation=controller.inspect()
    with pytest.raises(AccessDenied,match='CONFIRMATION_REQUIRED'):
        controller.verify(observation['observation_id'],observation['host_fingerprint'],confirmed=False)
    assert store.lookup(selector.target.binding.receiver_identity) is None
    with pytest.raises(AccessDenied,match='FINGERPRINT_CONFIRMATION_CHANGED'):
        controller.verify(observation['observation_id'],'SHA256:'+'A'*43,confirmed=True)
    assert not transport._proofs


def test_provider_loss_prevents_connection(fixture_server,tmp_path):
    controller,_,store,selector,state,_=compose(fixture_server,tmp_path)
    observation=controller.inspect();state[0]=False
    with pytest.raises(AccessDenied,match='PROVIDER_UNAVAILABLE'):
        controller.verify(observation['observation_id'],observation['host_fingerprint'],confirmed=True)
    assert store.lookup(selector.target.binding.receiver_identity) is None


def test_forged_and_replayed_proofs_refused(fixture_server,tmp_path):
    controller,transport,_,selector,_,credential=compose(fixture_server,tmp_path)
    observation=controller.inspect();target=selector.target
    host_key=(fixture_server[0]/'ecdsa-host.pub').read_text().strip()
    client=host_key_fingerprint(credential.public_key)
    forged=AuthenticationProof(target.binding,observation['host_fingerprint'],client,time.monotonic(),transport)
    with pytest.raises(AccessDenied,match='PROOF_INVALID'):transport.consume(forged,target,observation['host_fingerprint'],client)
    proof=transport.authenticate(target,host_key,credential,lambda:selector.check(target))
    transport.consume(proof,target,observation['host_fingerprint'],client)
    with pytest.raises(AccessDenied,match='PROOF_INVALID'):transport.consume(proof,target,observation['host_fingerprint'],client)


@pytest.mark.parametrize('invalid', [None, [], {}, 7, '', 'x'*129])
def test_invalid_observation_refused_before_lookup(fixture_server,tmp_path,invalid):
    controller,_,store,selector,_,_=compose(fixture_server,tmp_path)
    with pytest.raises(AccessDenied,match='OBSERVATION_INVALID'):
        controller.verify(invalid,'unused',confirmed=True)
    assert store.lookup(selector.target.binding.receiver_identity) is None


def test_context_change_after_local_save_is_reported_honestly(fixture_server,tmp_path):
    controller,_,store,selector,_,_=compose(fixture_server,tmp_path)
    observation=controller.inspect()
    original_save=store.save_new
    def changed(record):
        result=original_save(record)
        def deny(target):raise AccessDenied('RECEIVER_BINDING_CHANGED')
        selector.check=deny
        return result
    store.save_new=changed
    with pytest.raises(AccessDenied,match='TRUST_RECORD_SAVED_CONTEXT_CHANGED'):
        controller.verify(observation['observation_id'],observation['host_fingerprint'],confirmed=True)
    assert store.lookup(selector.target.binding.receiver_identity) is not None
