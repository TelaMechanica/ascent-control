"""Offline fixtures exercise actual record parsing/pin comparison, not SSH."""
import base64
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
from threading import RLock
import pytest
from ascent_core.service_access import AccessDenied, ReceiverBinding, ServiceAccess, ServiceState
from ascent_core.service_records import EnrollmentRecord, HostKeyObservation, OfflineServiceBackend, host_key_fingerprint


def public_key(seed=1):
    blob = struct.pack('>I', 11) + b'ssh-ed25519' + struct.pack('>I', 32) + bytes([seed]) * 32
    return 'ssh-ed25519 ' + base64.b64encode(blob).decode() + ' synthetic-fixture'


def fixture_backend():
    binding = ReceiverBinding(1, 'synthetic-receiver', 'synthetic-transport')
    state = [ServiceState(True, True, binding)]
    record = [{'schema': 'ascent.service-enrollment.v0', 'receiver_identity': binding.receiver_identity,
               'credential_revision': 1, 'host_key_sha256': host_key_fingerprint(public_key()), 'enrolled': True}]
    observed = [HostKeyObservation(binding, public_key())]
    backend = OfflineServiceBackend(state=lambda: state[0],
        record_for=lambda identity: json.dumps(record[0]).encode() if record[0] is not None else None,
        observation_for=lambda selected: observed[0])
    access = ServiceAccess(state=lambda: state[0], backend=backend, operation_lock=RLock())
    return access, backend, state, record, observed, binding


def test_verified_fixture_is_explicitly_not_authenticated_transport():
    access, backend, _, _, _, binding = fixture_backend()
    with access.lease(binding) as lease:
        assert backend.verify_step(lease) == {'enrollment_record_matches': True,
            'host_key_pin_matches': True, 'authenticated_transport': False, 'offline_only': True}
    with pytest.raises(AccessDenied, match='CLOSED'):
        backend.verify_step(lease)


@pytest.mark.parametrize('change,error', [('missing', 'ENROLLMENT_REQUIRED'), ('unenrolled', 'ENROLLMENT_REQUIRED'), ('identity', 'ENROLLMENT_IDENTITY_CHANGED'), ('pin', 'HOST_KEY_MISMATCH'), ('old-pin', 'ENROLLMENT_PIN_INVALID')])
def test_fail_closed_record_conditions(change, error):
    access, backend, _, record, _, binding = fixture_backend()
    if change == 'missing': record[0] = None
    elif change == 'unenrolled': record[0]['enrolled'] = False
    elif change == 'identity': record[0]['receiver_identity'] = 'other-receiver'
    elif change == 'pin': record[0]['host_key_sha256'] = host_key_fingerprint(public_key(2))
    else: record[0]['host_key_sha256'] = 'SHA256:' + 'a' * 16
    with pytest.raises(AccessDenied, match=error):
        with access.lease(binding): pytest.fail('must not yield')
    assert backend._sessions == {}


@pytest.mark.parametrize('change,error', [('revision', 'ENROLLMENT_REVISION_CHANGED'), ('pin', 'HOST_KEY_MISMATCH'), ('enrollment', 'ENROLLMENT_REQUIRED'), ('observed-binding', 'HOST_KEY_BINDING_CHANGED')])
def test_recheck_each_offline_step(change, error):
    access, backend, _, record, observed, binding = fixture_backend()
    with access.lease(binding) as lease:
        backend.verify_step(lease)
        if change == 'revision': record[0]['credential_revision'] += 1
        elif change == 'pin': observed[0] = HostKeyObservation(binding, public_key(2))
        elif change == 'enrollment': record[0] = None
        else: observed[0] = HostKeyObservation(ReceiverBinding(2, binding.receiver_identity, binding.transport_identity), public_key())
        with pytest.raises(AccessDenied, match=error): backend.verify_step(lease)
    assert backend._sessions == {}


@pytest.mark.parametrize('raw', [b'{}', b'[]', b'not-json', b'{"schema":1,"schema":2}', b'x' * 16385])
def test_malformed_records_refused(raw):
    with pytest.raises(AccessDenied): EnrollmentRecord.parse(raw)


@pytest.mark.parametrize('line', ['', 'ssh-ed25519 invalid', public_key() + '\n', public_key().replace('ssh-ed25519 ', 'ssh-rsa ', 1)])
def test_invalid_or_unsupported_host_keys_refused(line):
    with pytest.raises(AccessDenied): host_key_fingerprint(line)


def test_comments_do_not_change_pin():
    assert host_key_fingerprint(public_key()) == host_key_fingerprint(public_key().split(' synthetic')[0])


def test_fingerprint_matches_independent_openssh_tool(tmp_path):
    tool = shutil.which('ssh-keygen')
    assert tool, 'Offline OpenSSH fingerprint cross-check requires ssh-keygen'
    path = tmp_path / 'synthetic.pub'
    path.write_text(public_key() + '\n')
    result = subprocess.run([tool, '-l', '-E', 'sha256', '-f', str(path)], check=True, capture_output=True, text=True)
    assert result.stdout.split()[1] == host_key_fingerprint(public_key())


def test_state_change_during_observation_is_refused():
    access, backend, state, _, observed, binding = fixture_backend()
    def changing(selected):
        state[0] = ServiceState(False, False, binding)
        return observed[0]
    backend._observation_for = changing
    with pytest.raises(AccessDenied, match='BINDING_CHANGED'):
        with access.lease(binding): pytest.fail('must not yield stale state')
    assert backend._sessions == {}


@pytest.mark.parametrize('source,expected', [('record', 'ENROLLMENT_RECORD_UNAVAILABLE'), ('observation', 'HOST_KEY_OBSERVATION_UNAVAILABLE')])
def test_supplier_errors_do_not_reveal_diagnostic_paths(source, expected):
    access, backend, _, _, _, binding = fixture_backend()
    def unavailable(*args):
        raise OSError('synthetic-sensitive-location')
    if source == 'record': backend._record_for = unavailable
    else: backend._observation_for = unavailable
    with pytest.raises(AccessDenied, match=expected) as caught:
        with access.lease(binding): pytest.fail('must not yield')
    assert 'synthetic-sensitive-location' not in str(caught.value)
    assert caught.value.__suppress_context__ is True
