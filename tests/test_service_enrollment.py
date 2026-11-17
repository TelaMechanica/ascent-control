"""Trust-record storage semantics with fake protection; not an SSH/DPAPI proof."""
import json
import pytest
from ascent_core.service_access import AccessDenied
from ascent_core.service_credentials import CredentialError
from ascent_core.service_enrollment import ReceiverEnrollment, ProtectedEnrollments
from ascent_core.service_records import host_key_fingerprint
from test_service_credentials import FakeProtection, synthetic


def record(identity='synthetic-receiver-a'):
    key = synthetic().public_key
    return ReceiverEnrollment(identity, key, host_key_fingerprint(key))


def test_no_record_is_distinct_from_corruption(tmp_path):
    store = ProtectedEnrollments(tmp_path, protector=FakeProtection())
    assert store.lookup('synthetic-receiver-a') is None
    current = record(); store.save_new(current)
    saved = next(tmp_path.glob('*.dpapi')); saved.write_bytes(b'corrupt')
    with pytest.raises(CredentialError): store.lookup(current.receiver_identity)
    assert saved.read_bytes() == b'corrupt'


def test_create_and_idempotent_verification_preserve_record(tmp_path):
    store = ProtectedEnrollments(tmp_path, protector=FakeProtection()); current = record()
    for _ in range(2):
        assert store.save_new(current) == current
    assert len(list(tmp_path.glob('*.dpapi'))) == 1
    assert all('synthetic-receiver' not in p.name for p in tmp_path.iterdir())


def test_no_silent_host_key_replacement(tmp_path):
    store = ProtectedEnrollments(tmp_path, protector=FakeProtection()); current = record()
    store.save_new(current)
    changed = ReceiverEnrollment(current.receiver_identity, current.host_public_key, 'SHA256:' + 'A' * 43)
    with pytest.raises(AccessDenied, match='HOST_KEY_CHANGED'):
        store.save_new(changed)
    assert store.lookup(current.receiver_identity) == current


@pytest.mark.parametrize('fingerprint', ['SHA256:'+'!'*43, 'SHA256:'+'A'*42+'B', 'bad'])
def test_malformed_client_fingerprint_never_persists(tmp_path, fingerprint):
    store = ProtectedEnrollments(tmp_path, protector=FakeProtection()); current = record()
    with pytest.raises(CredentialError):
        store.save_new(ReceiverEnrollment(current.receiver_identity, current.host_public_key, fingerprint))
    assert not list(tmp_path.iterdir())


def test_tampered_record_fails_integrity():
    doc = json.loads(record().encode()); doc['record']['receiver_identity'] = 'synthetic-other'
    with pytest.raises(CredentialError): ReceiverEnrollment.decode(json.dumps(doc).encode())


def test_public_key_comment_does_not_replace_or_conflict_with_pin(tmp_path):
    store = ProtectedEnrollments(tmp_path, protector=FakeProtection()); current = record()
    saved = store.save_new(current)
    assert store.save_new(ReceiverEnrollment(current.receiver_identity, current.host_public_key + ' synthetic-comment', current.client_fingerprint)) == saved
