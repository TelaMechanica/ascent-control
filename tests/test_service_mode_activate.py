"""Regression tests for one-button Service Mode activation and its trust boundary.

Focus (per review): a first access that installs the key but then FAILS verification
must (a) report that the receiver was modified / key installed, and (b) write NO trust
record. Verification is the only path that records trust.
"""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'runtime'))
import dev_harness as app  # noqa: E402
from ascent_core.service_access import AccessDenied  # noqa: E402


class _Store:
    def status(self):
        return {'credential_present': True}

    def load(self):
        return type('K', (), {'public_key': 'ssh-ed25519 AAAAC3NzaSYNTHETICKEY test'})()


class _Service:
    def __init__(self, *, verify_raises):
        self.verify_raises = verify_raises
        self.verify_calls = 0
        self.records = []  # trust records written by verify()

    def inspect(self):
        return {'observation_id': 'obs-token', 'host_fingerprint': 'SHA256:synthetic',
                'receiver_name': 'TestRX', 'firmware': '19.2.14',
                'ssh_authenticated': False, 'trusted_record_present': False}

    def verify(self, observation_id, fingerprint, *, confirmed, key_type='ed25519'):
        self.verify_calls += 1
        if self.verify_raises:
            raise AccessDenied('RECEIVER_SSH_AUTH_FAILED')
        rec = {'receiver_name': 'TestRX'}
        self.records.append(rec)
        return rec


def _wire(monkeypatch, *, verify_raises, install_result):
    svc = _Service(verify_raises=verify_raises)
    monkeypatch.setattr(app, '_receiver_service', lambda: svc)
    monkeypatch.setattr(app, '_host_credential_store', lambda: _Store())
    from ascent_core import first_access as fa
    monkeypatch.setattr(fa, 'install_key', lambda **kw: dict(install_result))
    monkeypatch.setattr(app, 'SESSION',
                        type('S', (), {'device': type('D', (), {'identity': {
                            'device_name': 'TestRX', 'firmware': '19.2.14'}})()})())
    monkeypatch.setitem(app.ACTIVE_CONNECTION, 'candidate', {'serial_com': 'COM9'})
    return svc


def test_verify_failure_after_install_reports_modified_and_writes_no_record(monkeypatch):
    svc = _wire(monkeypatch, verify_raises=True,
                install_result={'ok': True, 'installed': 1, 'platform': 'max',
                                'receiver_modified': True, 'detail': 'installed'})
    result = app.local_service_activate({})
    assert result['ok'] is False
    assert result['stage'] == 'verify'
    assert result['key_installed'] is True
    assert result['receiver_modified'] is True
    assert svc.records == []          # the only trust-writing path did not run to completion
    assert svc.verify_calls == 1


def test_success_records_trust_and_reports_verified(monkeypatch):
    svc = _wire(monkeypatch, verify_raises=False,
                install_result={'ok': True, 'installed': 1, 'platform': 'max',
                                'receiver_modified': True, 'detail': 'installed'})
    result = app.local_service_activate({})
    assert result['ok'] is True
    assert result['key_installed'] is True
    assert result['verification']['receiver_name'] == 'TestRX'
    assert len(svc.records) == 1       # trust recorded only via verify()


def test_first_access_failure_before_commands_leaves_receiver_unmodified(monkeypatch):
    svc = _wire(monkeypatch, verify_raises=False,
                install_result={'ok': False, 'stage': 'privilege',
                                'detail': 'uid=0 not confirmed'})
    result = app.local_service_activate({})
    assert result['ok'] is False
    assert result['receiver_modified'] is False
    assert result['key_installed'] is False
    assert svc.records == []
    assert svc.verify_calls == 0       # never reached verify
