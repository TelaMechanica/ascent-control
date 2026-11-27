"""One-button Service Mode activation, orchestrator-backed (public wiring).

These test the WIRING in dev_harness that composes the bench-proven orchestrator
(ascent_core.service_mode_orchestrator, covered standalone by
test_service_mode_orchestrator.py) onto the public primitives. The properties that
matter here, each one a codex static-review finding:

 * finding 1: verify() authenticates against a FRESH observation taken AFTER the
   key is installed -- never a stale pre-install one -- and first access is never
   attempted when the firmware is not qualified.
 * finding 3: a verify failure after install is reported as a receiver that MAY
   hold leftover state (RECOVERY_REQUIRED -> receiver_modified), and a pre-install
   failure as a receiver that was not modified; the only trust-writing path
   (verify) must not have completed in either failure.
"""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'runtime'))
import dev_harness as app  # noqa: E402
from ascent_core.service_access import AccessDenied  # noqa: E402

VALID = {'device_id': 'rx1', 'device_name': 'Ascent_VRX_max_HF',
         'firmware': 'Ascent_VRX_Max_19_2_14'}            # in the validated set
UNQUALIFIED = {'device_id': 'rx9', 'device_name': 'Ascent_VRX_max_HF',
               'firmware': 'Ascent_VRX_Max_99_9_9'}       # not validated, not attemptable


class _Store:
    def status(self): return {'credential_present': True}
    def load(self): return type('K', (), {'public_key': 'ssh-ed25519 AAAASYNTH test'})()


class _Service:
    """Trusted-host SDK double. Hands out a FRESH observation id on every inspect()
    so a test can prove verify() used the one taken adjacent to it."""
    def __init__(self, *, verify_raises=False, trusted=False, log=None):
        self.verify_raises = verify_raises
        self.trusted = trusted
        self.inspect_calls = 0
        self.verify_token = None
        self.records = []
        self._log = log if log is not None else []

    def inspect(self):
        self.inspect_calls += 1
        self._log.append(('inspect', self.inspect_calls))
        return {'observation_id': f'obs-{self.inspect_calls}',
                'host_fingerprint': 'SHA256:synthetic', 'receiver_name': 'TestRX',
                'firmware': '19.2.14', 'ssh_authenticated': False,
                'trusted_record_present': self.trusted}

    def verify(self, observation_id, fingerprint, *, confirmed, key_type='ed25519'):
        self.verify_token = observation_id
        self._log.append(('verify', observation_id))
        if self.verify_raises:
            raise AccessDenied('RECEIVER_SSH_AUTH_FAILED')
        res = {'ssh_authenticated': True, 'trust_record_saved': True, 'receiver_name': 'TestRX'}
        self.records.append(res)
        return res


def _wire(monkeypatch, *, target=VALID, verify_raises=False, trusted=False,
          install_result=None, ready=True):
    log = []
    svc = _Service(verify_raises=verify_raises, trusted=trusted, log=log)
    monkeypatch.setattr(app, '_receiver_service', lambda: svc)
    monkeypatch.setattr(app, '_service_mode_identify', lambda: dict(target))
    monkeypatch.setattr(app, '_service_mode_correlated_adapter',
                        lambda: {'ifindex': 29, 'ready': ready})
    monkeypatch.setattr(app, '_selected_service_credential', lambda kind: _Store())
    from ascent_core import first_access as fa
    installed = install_result if install_result is not None else {
        'ok': True, 'installed': 1, 'platform': 'max', 'detail': 'installed'}

    def _install(**kw):
        log.append(('install_key', kw.get('target')))
        return dict(installed)
    monkeypatch.setattr(fa, 'install_key', _install)
    return svc, log


def test_success_records_trust_and_verifies_against_a_fresh_observation(monkeypatch):
    svc, log = _wire(monkeypatch)
    result = app.local_service_activate({})
    assert result['ok'] is True
    assert result['verification']['receiver_name'] == 'TestRX'
    assert len(svc.records) == 1                      # trust recorded only via verify()
    # THE FIX: the token verify() used came from an inspect() that ran AFTER
    # install_key, not a stale pre-install observation.
    kinds = [e[0] for e in log]
    assert kinds.index('install_key') < kinds.index('verify')
    last_inspect_before_verify = max(
        e[1] for e in log[:kinds.index('verify')] if e[0] == 'inspect')
    assert svc.verify_token == f'obs-{last_inspect_before_verify}'


def test_unqualified_firmware_blocks_before_any_first_access(monkeypatch):
    svc, log = _wire(monkeypatch, target=UNQUALIFIED)
    result = app.local_service_activate({})
    assert result['ok'] is False
    assert result['state'] == 'BLOCKED'
    assert not any(e[0] == 'install_key' for e in log)   # the exploit never fired
    assert svc.verify_token is None and svc.records == []


def test_verify_failure_after_install_reports_modified_and_writes_no_record(monkeypatch):
    svc, log = _wire(monkeypatch, verify_raises=True)
    result = app.local_service_activate({})
    assert result['ok'] is False
    assert result['state'] == 'RECOVERY_REQUIRED'         # may hold leftover state
    assert result['receiver_modified'] is True
    assert svc.records == []                               # trust never recorded
    assert any(e[0] == 'install_key' for e in log)        # but the key WAS installed


def test_first_access_failure_leaves_receiver_unmodified(monkeypatch):
    svc, log = _wire(monkeypatch, install_result={'ok': False, 'stage': 'privilege',
                                                  'detail': 'uid=0 not confirmed'})
    result = app.local_service_activate({})
    assert result['ok'] is False
    assert result['state'] == 'BLOCKED'
    assert result['receiver_modified'] is False
    assert svc.verify_token is None and svc.records == []


def test_already_enrolled_reverifies_without_reinstalling(monkeypatch):
    svc, log = _wire(monkeypatch, trusted=True)
    result = app.local_service_activate({})
    assert result['ok'] is True
    assert result['already_verified'] is True
    assert not any(e[0] == 'install_key' for e in log)    # idempotent: no second key


def test_declined_elevation_is_operator_blocked_not_a_fault(monkeypatch):
    svc, log = _wire(monkeypatch, ready=False)
    monkeypatch.setattr(app, '_configure_rndis_elevated',
                        lambda *a, **k: (_ for _ in ()).throw(
                            RuntimeError('the elevation prompt was dismissed')))
    result = app.local_service_activate({})
    assert result['ok'] is False
    assert result['state'] == 'BLOCKED'
    assert result['failure_class'] == 'OPERATOR_DECLINED'
    assert not any(e[0] == 'install_key' for e in log)
