"""State-transition coverage for one-button Service Mode activation.

The two properties worth most here are negative ones: success is never reported
without a proven authentication, and initial access is never assumed to work.
"""
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "runtime"))

from ascent_core import activation_orchestrator as smo


TARGET = {"device_id": "CID-1", "device_name": "Ascent_VRX_max_HF",
          "firmware": "Ascent_VRX_Max_19_2_14"}


class Harness:
    """Collaborators that record what the orchestrator did to them."""

    def __init__(self, **over):
        self.calls = []
        self.ready = over.get("ready", True)
        self.target = over.get("target", TARGET)
        self.supported = over.get("supported", True)
        self.verify_result = over.get("verify_result", {"verified": True})
        self.already = over.get("already", False)
        self.configure_exc = over.get("configure_exc")
        self.identify_exc = over.get("identify_exc")
        self.enroll_exc = over.get("enroll_exc")
        self.verify_exc = over.get("verify_exc")
        # What the cleanup reports back. The orchestrator reads
        # `cleanup_complete` to decide whether anything is still outstanding,
        # so a test has to be able to say "the cleanup did not confirm".
        self.revoke_result = over.get("revoke_result", {"ok": True})
        self.audit = []

    def _rec(self, name):
        self.calls.append(name)

    def transport_ready(self):
        self._rec("transport_ready"); return {"ready": self.ready}

    def configure_transport(self):
        self._rec("configure_transport")
        if self.configure_exc: raise self.configure_exc
        return {"ok": True}

    def rollback_transport(self):
        self._rec("rollback_transport"); return {"ok": True}

    def identify(self):
        self._rec("identify")
        if self.identify_exc: raise self.identify_exc
        return self.target

    def firmware_supported(self, name, fw):
        self._rec("firmware_supported"); return self.supported

    def enroll_begin(self):
        self._rec("enroll_begin")
        if self.enroll_exc: raise self.enroll_exc
        return {"ok": True}

    def enroll_verify(self):
        self._rec("enroll_verify")
        if self.verify_exc: raise self.verify_exc
        return self.verify_result

    def revoke(self):
        self._rec("revoke"); return self.revoke_result

    def already_verified(self):
        return self.already

    def build(self, initial_access=None):
        return smo.Orchestrator(
            transport_ready=self.transport_ready,
            configure_transport=self.configure_transport,
            rollback_transport=self.rollback_transport,
            identify=self.identify,
            firmware_supported=self.firmware_supported,
            enroll_begin=self.enroll_begin,
            enroll_verify=self.enroll_verify,
            revoke=self.revoke,
            already_verified=self.already_verified,
            initial_access=initial_access,
            audit_sink=self.audit.append,
            clock=lambda: 1000.0)


class OkAccess:
    def establish(self, target): return {"ok": True}


class BadAccess:
    def establish(self, target): return {"ok": False, "detail": "no shell"}


class ThrowingAccess:
    def establish(self, target): raise RuntimeError("transport died")


@pytest.fixture
def validated(monkeypatch):
    """Pretend Gate 2 passed for 19.2.14 ONLY inside a test."""
    monkeypatch.setattr(smo, "INITIAL_ACCESS_VALIDATED_FIRMWARE",
                        frozenset({"Ascent_VRX_Max_19_2_14"}))


# --------------------------------------------------------------------------- #
# The shipped posture
# --------------------------------------------------------------------------- #

def test_the_validated_firmware_set_ships_empty():
    """Gate 2 has produced no hardware evidence, so nothing is validated."""
    assert set(smo.INITIAL_ACCESS_VALIDATED_FIRMWARE) == set()


def test_18_21_7_is_not_validated():
    assert smo.firmware_initial_access_validated(
        "Ascent_VRX_max_HF", "Ascent_VRX_Max_18_21_7") is False


@pytest.mark.parametrize("bad", [None, "", "   ", 19.2, b"19.2.14", object()])
def test_firmware_gate_fails_closed_on_junk(bad):
    assert smo.firmware_initial_access_validated("Ascent_VRX_max_HF", bad) is False
    # The DEVICE NAME is junk-proofed too. Asserted against a firmware string
    # that IS in the validated set, so this cannot pass merely because the
    # default set is empty -- it has to be the name check doing the work.
    import unittest.mock as _mock
    with _mock.patch.object(smo, "INITIAL_ACCESS_VALIDATED_FIRMWARE",
                            frozenset({"18.21.7"})):
        assert smo.firmware_initial_access_validated("Ascent_VRX_max_HF",
                                                     "18.21.7") is True
        assert smo.firmware_initial_access_validated(bad, "18.21.7") is False


def test_without_gate_2_activation_blocks_rather_than_pretending(validated):
    """The connected bench unit's firmware is not on the list -> BLOCKED, not success."""
    h = Harness(target={**TARGET, "firmware": "Ascent_VRX_Max_18_21_7"})
    res = h.build(initial_access=OkAccess()).activate()
    assert res["state"] == smo.BLOCKED
    assert res["failure_class"] == smo.FAIL_INITIAL_ACCESS_UNAVAILABLE
    assert res["verified"] is False
    assert "enroll_begin" not in h.calls


def test_no_adapter_blocks_even_when_firmware_is_validated(validated):
    h = Harness()
    res = h.build(initial_access=None).activate()
    assert res["state"] == smo.BLOCKED
    assert res["failure_class"] == smo.FAIL_INITIAL_ACCESS_UNAVAILABLE
    assert "enroll_begin" not in h.calls


# --------------------------------------------------------------------------- #
# Success, and what it requires
# --------------------------------------------------------------------------- #

def test_full_path_reaches_verified(validated):
    h = Harness(ready=False)
    res = h.build(initial_access=OkAccess()).activate()
    assert res["state"] == smo.VERIFIED
    assert res["verified"] is True
    assert res["failure_class"] is None
    assert [s["step"] for s in res["steps"]] == list(smo.STEPS)
    assert "configure_transport" in h.calls
    assert "rollback_transport" not in h.calls


def test_success_requires_the_verifier_to_confirm_authentication(validated):
    """A truthy response is not success. Only verified=True is."""
    h = Harness(verify_result={"ok": True})          # ok, but NOT verified
    res = h.build(initial_access=OkAccess()).activate()
    assert res["state"] == smo.RECOVERY_REQUIRED
    assert res["failure_class"] == smo.FAIL_AUTHENTICATION
    assert res["verified"] is False
    assert "revoke" in h.calls, "a key that will not authenticate must be cleaned up"


def test_verified_never_claims_persistence(validated):
    h = Harness()
    res = h.build(initial_access=OkAccess()).activate()
    assert res["state"] == smo.VERIFIED
    assert res["persistence"] == {"reboot": "NOT_TESTED",
                                  "firmware_upgrade": "NOT_TESTED"}


def test_result_invariant_rejects_unbacked_success():
    with pytest.raises(ValueError):
        smo._result(smo.VERIFIED, steps=[], verified=False)
    with pytest.raises(ValueError):
        smo._result(smo.BLOCKED, steps=[], verified=True)


# --------------------------------------------------------------------------- #
# Firmware qualification
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("supported", [False, None])
def test_unsupported_and_unknown_firmware_both_block(validated, supported):
    """None means 'no evidence'. It must not read as permission."""
    h = Harness(supported=supported)
    res = h.build(initial_access=OkAccess()).activate()
    assert res["state"] == smo.BLOCKED
    assert res["failure_class"] == smo.FAIL_FIRMWARE_INCOMPATIBLE
    assert "enroll_begin" not in h.calls


# --------------------------------------------------------------------------- #
# Transport, elevation, rollback
# --------------------------------------------------------------------------- #

def test_declined_elevation_is_blocked_not_failed():
    h = Harness(ready=False, configure_exc=PermissionError("UAC dismissed"))
    res = h.build(initial_access=OkAccess()).activate()
    assert res["state"] == smo.BLOCKED
    assert res["failure_class"] == smo.FAIL_OPERATOR_DECLINED


def test_other_transport_errors_are_host_network():
    h = Harness(ready=False, configure_exc=OSError("adapter vanished"))
    res = h.build(initial_access=OkAccess()).activate()
    assert res["failure_class"] == smo.FAIL_HOST_NETWORK


def test_transport_we_configured_is_rolled_back_on_a_later_failure(validated):
    h = Harness(ready=False, supported=False)
    res = h.build(initial_access=OkAccess()).activate()
    assert res["failure_class"] == smo.FAIL_FIRMWARE_INCOMPATIBLE
    assert res["rolled_back"] is True
    assert "rollback_transport" in h.calls


def test_transport_we_did_not_configure_is_never_rolled_back(validated):
    """Rolling back an address we did not add would destroy operator configuration."""
    h = Harness(ready=True, supported=False)
    res = h.build(initial_access=OkAccess()).activate()
    assert res["rolled_back"] is False
    assert "rollback_transport" not in h.calls


def test_missing_device_fails_before_touching_the_network(validated):
    """Identity comes from serial and needs no network, so it is the FIRST gate.

    This is what stops a session with nothing selected reporting "could not reach
    the receiver over USB networking" -- a diagnostic that sends the operator after
    their cabling for a problem that is nothing of the kind. Nothing is configured,
    so there is nothing to roll back.
    """
    h = Harness(ready=False, identify_exc=RuntimeError("no device"))
    res = h.build(initial_access=OkAccess()).activate()
    assert res["failure_class"] == smo.FAIL_NO_DEVICE
    assert [s["step"] for s in res["steps"]] == [smo.STEP_IDENTIFY]
    assert "configure_transport" not in h.calls
    assert "rollback_transport" not in h.calls


# --------------------------------------------------------------------------- #
# Initial-access failures
# --------------------------------------------------------------------------- #

def test_initial_access_refusal_does_not_enroll(validated):
    h = Harness()
    res = h.build(initial_access=BadAccess()).activate()
    assert res["failure_class"] == smo.FAIL_INITIAL_ACCESS_FAILED
    assert "enroll_begin" not in h.calls


def test_initial_access_exception_is_contained(validated):
    h = Harness()
    res = h.build(initial_access=ThrowingAccess()).activate()
    assert res["failure_class"] == smo.FAIL_INITIAL_ACCESS_FAILED
    assert res["state"] == smo.BLOCKED


# --------------------------------------------------------------------------- #
# Partial state and recovery
# --------------------------------------------------------------------------- #

def test_enrollment_failure_that_cleans_up_is_not_a_recovery_state(validated):
    """CHANGED by owner decision, 2026-10-09: RECOVERY REQUIRED must mean
    cleanup is outstanding or uncertain.

    Every enrollment failure used to report INCOMPLETE_ENROLLMENT, which is a
    RECOVERY_REQUIRED state, even when the cleanup had just confirmed the
    receiver was left clean. An operator was told "use RECOVER to remove
    anything left behind" about a receiver with nothing left behind.

    The cleanup still runs, and its own result now decides which failure this
    is.
    """
    h = Harness(enroll_exc=RuntimeError("write refused"))
    res = h.build(initial_access=OkAccess()).activate()
    assert res["failure_class"] == smo.FAIL_ENROLLMENT_FAILED
    assert res["state"] == smo.BLOCKED
    assert res["rolled_back"] is True
    assert "revoke" in h.calls, "the cleanup must still run"


def test_enrollment_failure_with_an_UNCONFIRMED_cleanup_still_requires_recovery(validated):
    """The safe direction is unchanged. Claiming a cleanup happened when it may
    not have is the error that leaves a key on a unit nobody knows about."""
    h = Harness(enroll_exc=RuntimeError("write refused"),
                revoke_result={"cleanup_complete": False})
    res = h.build(initial_access=OkAccess()).activate()
    assert res["failure_class"] == smo.FAIL_INCOMPLETE_ENROLLMENT
    assert res["state"] == smo.RECOVERY_REQUIRED
    assert res["rolled_back"] is False


def test_verification_exception_requires_recovery(validated):
    h = Harness(verify_exc=RuntimeError("host key changed"))
    res = h.build(initial_access=OkAccess()).activate()
    assert res["state"] == smo.RECOVERY_REQUIRED
    assert res["failure_class"] == smo.FAIL_AUTHENTICATION
    assert "revoke" in h.calls


# --------------------------------------------------------------------------- #
# Idempotence
# --------------------------------------------------------------------------- #

def test_second_press_reverifies_and_never_reenrolls(validated):
    h = Harness(already=True)
    res = h.build(initial_access=OkAccess()).activate()
    assert res["state"] == smo.VERIFIED
    assert "enroll_begin" not in h.calls, "a second press must not mint a second key"
    assert "enroll_verify" in h.calls


def test_an_already_enrolled_unit_does_not_need_initial_access(validated):
    """Once enrolled, first-access is irrelevant -- so it must not gate re-verification."""
    h = Harness(already=True, target={**TARGET, "firmware": "Ascent_VRX_Max_18_21_7"})
    res = h.build(initial_access=None).activate()
    assert res["state"] == smo.VERIFIED


def test_repeated_activation_does_not_reconfigure_ready_transport(validated):
    h = Harness(ready=True, already=True)
    h.build(initial_access=OkAccess()).activate()
    assert "configure_transport" not in h.calls


# --------------------------------------------------------------------------- #
# Audit and model integrity
# --------------------------------------------------------------------------- #

def test_every_run_emits_one_device_scoped_audit_record(validated):
    h = Harness()
    h.build(initial_access=OkAccess()).activate()
    assert len(h.audit) == 1
    assert h.audit[0]["device_id"] == "CID-1"
    assert h.audit[0]["outcome"] == smo.VERIFIED


def test_failures_are_audited_with_their_class(validated):
    h = Harness(supported=False)
    h.build(initial_access=OkAccess()).activate()
    assert h.audit[0]["failure_class"] == smo.FAIL_FIRMWARE_INCOMPATIBLE


def test_every_failure_class_maps_to_a_real_ui_state():
    for cls in smo.FAILURE_CLASSES:
        assert smo._FAILURE_UI[cls] in smo.UI_STATES
        assert smo.FAILURE_TEXT[cls].strip()


def test_only_verified_counts_as_success():
    assert smo.SUCCESS_STATES == frozenset({smo.VERIFIED})
    for s in smo.UI_STATES:
        if s != smo.VERIFIED:
            assert s not in smo.SUCCESS_STATES
