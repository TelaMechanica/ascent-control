"""Opt-in loopback integration: generated temporary keys, never receiver access."""
import getpass
import ipaddress
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
from threading import RLock
import time
import pytest
from ascent_core.service_access import AccessDenied, ReceiverBinding, ServiceAccess, ServiceState
from ascent_core.service_records import HostKeyObservation, host_key_fingerprint
from ascent_core.service_loopback_ssh import LoopbackReadOnlySshBackend, LoopbackSshProbe

pytestmark = pytest.mark.skipif(os.environ.get('ASCENT_TEST_LOOPBACK_SSH') != '1',
    reason='Explicit localhost SSH fixture opt-in required; no hardware access')


@pytest.fixture
def fixture_server():
    ssh, sshd, keygen = (shutil.which(name) for name in ('ssh', 'sshd', 'ssh-keygen'))
    assert all((ssh, sshd, keygen)), 'Opt-in requires installed OpenSSH client/server/keygen'
    # AuthorizedKeys StrictModes rejects shared temporary ancestors. Keep the
    # fixture beneath this owned workspace; do not weaken StrictModes to pass.
    parent = Path(__file__).resolve().parents[1] / 'artifacts'
    parent.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='ssh-fixture-', dir=parent) as folder:
        root = Path(folder)
        for name in ('host', 'client', 'wrong-client', 'wrong-host'):
            subprocess.run([keygen, '-q', '-t', 'ed25519', '-N', '', '-C', 'synthetic-fixture',
                            '-f', str(root/name)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        (root/'authorized').write_bytes((root/'client.pub').read_bytes())
        (root/'authorized').chmod(0o600)
        host = str(ipaddress.IPv4Address(0x7f000001))
        with socket.socket() as reserve:
            reserve.bind((host, 0))
            port = reserve.getsockname()[1]
        config = '\n'.join([f'ListenAddress {host}', f'Port {port}', f'HostKey "{root/"host"}"',
            f'PidFile "{root/"pid"}"', f'AuthorizedKeysFile "{root/"authorized"}"',
            'PasswordAuthentication no', 'KbdInteractiveAuthentication no', 'UsePAM no',
            'StrictModes yes', 'PermitUserEnvironment no', 'AllowAgentForwarding no',
            'AllowTcpForwarding no', 'X11Forwarding no', 'PermitTTY no',
            'PermitUserRC no', 'Subsystem sftp internal-sftp -R',
            'ForceCommand internal-sftp -R', 'LogLevel ERROR']) + '\n'
        (root/'sshd.conf').write_text(config)
        with (root/'private-server.log').open('wb') as log:
            server = subprocess.Popen([sshd, '-D', '-e', '-f', str(root/'sshd.conf')],
                                      stdout=subprocess.DEVNULL, stderr=log)
            try:
                for _ in range(50):
                    assert server.poll() is None, 'Synthetic SSH fixture failed to start; inspect local-only log'
                    try:
                        with socket.create_connection((host, port), timeout=.1):
                            break
                    except OSError:
                        time.sleep(.02)
                else:
                    pytest.fail('Synthetic SSH fixture readiness timeout')
                yield root, port, ssh, server
            finally:
                if server.poll() is None:
                    server.terminate()
                    server.wait(timeout=5)


def backend_fixture(server):
    root, port, ssh, _ = server
    binding = ReceiverBinding(1, 'synthetic-receiver', f'loopback-fixture-{port}')
    state = [ServiceState(True, True, binding)]
    public = (root/'host.pub').read_text().strip()
    record = [{'schema': 'ascent.service-enrollment.v0', 'receiver_identity': binding.receiver_identity,
        'credential_revision': 1, 'host_key_sha256': host_key_fingerprint(public), 'enrolled': True}]
    observation = [HostKeyObservation(binding, public)]
    probe = LoopbackSshProbe(binding=binding, port=port, username=getpass.getuser(),
                            identity_file=root/'client', ssh_binary=ssh)
    backend = LoopbackReadOnlySshBackend(probe=probe, state=lambda: state[0],
        record_for=lambda identity: json.dumps(record[0]).encode() if record[0] is not None else None,
        observation_for=lambda selected: observation[0])
    access = ServiceAccess(state=lambda: state[0], backend=backend, operation_lock=RLock())
    return access, backend, probe, state, record, observation, binding


def test_real_pinned_handshake_and_fresh_second_connection(fixture_server):
    access, backend, _, _, _, _, binding = backend_fixture(fixture_server)
    with access.lease(binding) as lease:
        for _ in range(2):
            assert backend.verify_step(lease) == {'authenticated_transport': True,
                'loopback_only': True, 'operation': 'completed-noop', 'connection_reused': False}
    assert backend._sessions == {}


def test_server_cannot_impersonate_pinned_key(fixture_server):
    access, backend, _, _, record, observed, binding = backend_fixture(fixture_server)
    wrong = (fixture_server[0]/'wrong-host.pub').read_text().strip()
    record[0]['host_key_sha256'] = host_key_fingerprint(wrong)
    observed[0] = HostKeyObservation(binding, wrong)
    # Offline checks pass against the supplied key, but the real server cannot
    # prove possession of that different private key. No TOFU fallback.
    with access.lease(binding) as lease, pytest.raises(AccessDenied, match='NOOP_FAILED'):
        backend.verify_step(lease)


def test_unenrolled_client_key_cannot_authenticate(fixture_server):
    access, backend, probe, _, _, _, binding = backend_fixture(fixture_server)
    probe._identity_file = fixture_server[0]/'wrong-client'
    with access.lease(binding) as lease, pytest.raises(AccessDenied, match='NOOP_FAILED'):
        backend.verify_step(lease)


def test_revocation_prevents_next_real_connection(fixture_server):
    access, backend, probe, state, _, _, binding = backend_fixture(fixture_server)
    with access.lease(binding) as lease:
        backend.verify_step(lease)
        state[0] = ServiceState(False, False, binding)
        def forbidden(*args): pytest.fail('revocation must prevent invoking SSH')
        probe.noop = forbidden
        with pytest.raises(AccessDenied, match='UNAVAILABLE'): backend.verify_step(lease)


def test_change_during_real_step_discards_result(fixture_server):
    access, backend, probe, _, record, _, binding = backend_fixture(fixture_server)
    original = probe.noop
    def changed(*args):
        original(*args)
        record[0]['credential_revision'] += 1
    probe.noop = changed
    with access.lease(binding) as lease, pytest.raises(AccessDenied, match='REVISION_CHANGED'):
        backend.verify_step(lease)


def test_timeout_is_stable_and_redacted(fixture_server, monkeypatch):
    access, backend, _, _, _, _, binding = backend_fixture(fixture_server)
    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired('synthetic-sensitive-command', 5)
    monkeypatch.setattr(subprocess, 'run', timeout)
    with access.lease(binding) as lease, pytest.raises(AccessDenied, match='SSH_STEP_TIMEOUT') as caught:
        backend.verify_step(lease)
    assert 'synthetic-sensitive-command' not in str(caught.value)


def test_server_loss_never_reuses_old_authenticated_result(fixture_server):
    access, backend, _, _, _, _, binding = backend_fixture(fixture_server)
    with access.lease(binding) as lease:
        assert backend.verify_step(lease)['authenticated_transport'] is True
        server = fixture_server[3]
        server.terminate()
        server.wait(timeout=5)
        with pytest.raises(AccessDenied, match='NOOP_FAILED'):
            backend.verify_step(lease)


def test_process_failure_diagnostic_is_redacted(fixture_server, monkeypatch):
    access, backend, _, _, _, _, binding = backend_fixture(fixture_server)
    def unavailable(*args, **kwargs):
        raise OSError('synthetic-sensitive-identity-path')
    monkeypatch.setattr(subprocess, 'run', unavailable)
    with access.lease(binding) as lease, pytest.raises(AccessDenied, match='SSH_STEP_UNAVAILABLE') as caught:
        backend.verify_step(lease)
    assert 'synthetic-sensitive-identity-path' not in str(caught.value)
