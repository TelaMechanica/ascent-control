"""Storage fault tests use a reversible fake; they are not DPAPI evidence."""
import base64
from pathlib import Path
import struct
import pytest
from ascent_core.service_credentials import CredentialError, ManagedCredential, ProtectedCredentialStore, CurrentUserDpapi


def synthetic():
    public = struct.pack('>I', 11) + b'ssh-ed25519' + struct.pack('>I', 32) + bytes([7]) * 32
    return ManagedCredential('ssh-ed25519 ' + base64.b64encode(public).decode(),
        b'-----BEGIN OPENSSH PRIVATE KEY-----\nsynthetic-canary-only\n-----END OPENSSH PRIVATE KEY-----\n')


class FakeProtection:
    def protect(self, raw): return b'synthetic-wrapped:' + base64.b64encode(raw)
    def unprotect(self, raw):
        if not raw.startswith(b'synthetic-wrapped:'): raise CredentialError('CREDENTIAL_UNPROTECT_FAILED')
        return base64.b64decode(raw.split(b':', 1)[1], validate=True)


def test_roundtrip_and_metadata_minimization(tmp_path):
    store = ProtectedCredentialStore(tmp_path/'store', protector=FakeProtection())
    assert store.status() == {'credential_present': False, 'receiver_access': False}
    status = store.create(synthetic())
    assert status['credential_present'] is True and status['receiver_access'] is False
    assert set(status) == {'credential_present', 'fingerprint', 'protection', 'receiver_access'}
    assert store.load() == synthetic()
    assert b'synthetic-canary-only' not in (tmp_path/'store/credential.dpapi').read_bytes()
    assert 'synthetic-canary-only' not in repr(store.load())


@pytest.mark.parametrize('failure', ['raise', 'none', 'plaintext', 'unreadable'])
def test_protection_failure_never_writes_plaintext(tmp_path, failure):
    class Broken(FakeProtection):
        def protect(self, raw):
            if failure == 'raise': raise OSError('synthetic-sensitive-path')
            if failure == 'none': return None
            if failure == 'plaintext': return raw
            return b'not-decryptable'
    store = ProtectedCredentialStore(tmp_path/'store', protector=Broken())
    with pytest.raises(CredentialError, match='PROTECT_FAILED') as caught:
        store.create(synthetic())
    assert 'synthetic-sensitive-path' not in str(caught.value)
    assert not (tmp_path/'store').exists()


def test_existing_state_never_replaced(tmp_path):
    store = ProtectedCredentialStore(tmp_path, protector=FakeProtection())
    store.create(synthetic())
    original = (tmp_path/'credential.dpapi').read_bytes()
    with pytest.raises(CredentialError, match='ALREADY_PRESENT'): store.create(synthetic())
    assert (tmp_path/'credential.dpapi').read_bytes() == original
    assert not list(tmp_path.glob('.protected-*'))


def test_corrupt_state_retained_and_not_reinitialized(tmp_path):
    file = tmp_path/'credential.dpapi'
    file.write_bytes(b'corrupt-protected-record')
    store = ProtectedCredentialStore(tmp_path, protector=FakeProtection())
    with pytest.raises(CredentialError, match='FILE_INVALID'): store.status()
    with pytest.raises(CredentialError, match='ALREADY_PRESENT'): store.create(synthetic())
    assert file.read_bytes() == b'corrupt-protected-record'


def test_link_refused(tmp_path):
    file = tmp_path/'credential.dpapi'
    file.symlink_to(tmp_path/'missing')
    with pytest.raises(CredentialError, match='FILE_INVALID'):
        ProtectedCredentialStore(tmp_path, protector=FakeProtection()).load()


def test_non_windows_default_has_no_plaintext_fallback(tmp_path):
    import os
    if os.name == 'nt': pytest.skip('Non-Windows refusal check')
    with pytest.raises(CredentialError, match='WINDOWS_PROTECTION_REQUIRED'):
        ProtectedCredentialStore(tmp_path/'store').create(synthetic())
    assert not (tmp_path/'store').exists()


@pytest.mark.parametrize('raw', [b'{}', b'[]', b'null', b'{"schema":1,"schema":2}', b'bad'])
def test_invalid_decrypted_records_refused(raw):
    with pytest.raises(CredentialError): ManagedCredential.decode(raw)


def test_corrupt_private_payload_with_old_checksum_is_refused():
    import json
    doc = json.loads(synthetic().encode())
    doc['private_key'] = doc['private_key'].replace('synthetic-canary-only', 'changed-canary-only')
    with pytest.raises(CredentialError, match='DATA_INVALID'):
        ManagedCredential.decode(json.dumps(doc).encode())


def test_legacy_adoption_checks_profile_before_opening_store(tmp_path):
    from ascent_core.service_access import AccessDenied
    from ascent_core.service_credentials import adopt_windows_credential

    root = tmp_path/'protected'
    store = ProtectedCredentialStore(root, protector=FakeProtection())
    with pytest.raises(AccessDenied, match='CLIENT_KEY_ALGORITHM_INCOMPATIBLE'):
        adopt_windows_credential(store, synthetic(), device_name='Ascent_VRX',
                                 firmware='Ascent_G_Gnd_19_2_14')
    assert not root.exists()


@pytest.mark.parametrize('returncode', [0, 1])
def test_legacy_adoption_verifies_pair_before_protecting(tmp_path, monkeypatch, returncode):
    from contextlib import contextmanager
    from types import SimpleNamespace
    from ascent_core import service_credentials, windows_key_material

    key = synthetic()
    store = ProtectedCredentialStore(tmp_path/'protected', protector=FakeProtection())

    @contextmanager
    def materialize(credential):
        assert credential == key
        yield tmp_path/'identity', {}, tmp_path/'System32'

    monkeypatch.setattr(windows_key_material, 'materialized_credential', materialize)
    monkeypatch.setattr(service_credentials.subprocess, 'run', lambda *a, **kw:
                        SimpleNamespace(returncode=returncode, stdout=key.public_key))
    if returncode:
        with pytest.raises(CredentialError, match='KEY_PAIR_MISMATCH'):
            service_credentials.adopt_windows_credential(store, key, device_name='Ascent_VRX_Max')
        assert not (tmp_path/'protected').exists()
    else:
        status = service_credentials.adopt_windows_credential(store, key, device_name='Ascent_VRX_Max')
        assert store.load() == key and status['receiver_access'] is False
