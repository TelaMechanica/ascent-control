"""One-button Service Mode activation.

ONE operator action, then: transport readiness, device identification, firmware
qualification, authorized initial access, key enrollment, and SSH authentication
verification -- with rollback when any of it fails.

This module ORCHESTRATES. It owns no credentials, no network manager and no
enrollment mechanism of its own; every collaborator is injected and defaults to the
component that already exists. Adding a second SSH key store or a second way to
append an authorized_keys line is exactly what this file exists to prevent.

Two things it refuses to do, both deliberate:

* **It never reports success before real public-key authentication succeeds.**
  Reachability, an SSH banner, or a completed command sequence are not success. The
  connected bench receiver answers on tcp/22 with a dropbear banner while holding no
  credential of ours whatsoever.

* **It never assumes initial access works.** First privileged access is a separate,
  firmware-gated capability supplied by an adapter. There is no production adapter,
  and the validated-firmware set is EMPTY until hardware evidence fills it. Absent
  adapter or unlisted firmware yields BLOCKED -- never a fake success, and never a
  disabled button presented as working.
"""
from __future__ import annotations

import time
from typing import Callable, Protocol

# --------------------------------------------------------------------------- #
# UI state machine
# --------------------------------------------------------------------------- #

READY = "READY"                           # nothing in progress; may or may not be set up
ACTIVATING = "ACTIVATING"                 # a run is in flight
VERIFIED = "VERIFIED"                     # key-authenticated session proven
BLOCKED = "BLOCKED"                       # a prerequisite outside our control is unmet
RECOVERY_REQUIRED = "RECOVERY_REQUIRED"   # partial state we could not clean up

UI_STATES = (READY, ACTIVATING, VERIFIED, BLOCKED, RECOVERY_REQUIRED)

#: The only state that means "it works". Named so a caller cannot drift into
#: treating ACTIVATING or READY as success.
SUCCESS_STATES = frozenset({VERIFIED})

# --------------------------------------------------------------------------- #
# Steps, in order
# --------------------------------------------------------------------------- #

STEP_TRANSPORT = "TRANSPORT"
STEP_IDENTIFY = "IDENTIFY"
STEP_FIRMWARE = "FIRMWARE"
STEP_INITIAL_ACCESS = "INITIAL_ACCESS"
STEP_ENROLL = "ENROLL"
STEP_VERIFY = "VERIFY"

# IDENTIFY precedes TRANSPORT deliberately. Identity comes from command 60 over the
# CDC serial port and needs no network at all, whereas addressing the RNDIS sibling
# needs to know WHICH device was selected. Running transport first made a session
# with no device selected report "could not reach the receiver over USB networking",
# which points the operator at their cabling for a problem that is nothing of the
# kind.
STEPS = (STEP_IDENTIFY, STEP_TRANSPORT, STEP_FIRMWARE,
         STEP_INITIAL_ACCESS, STEP_ENROLL, STEP_VERIFY)

# --------------------------------------------------------------------------- #
# Failure classes.
#
# These are kept apart because they have different remedies and are routinely
# conflated. "No shell came back" is the worked example: it is a privilege result if
# the network was good and a network result otherwise, and guessing wrong sends the
# next engineer in the wrong direction entirely.
# --------------------------------------------------------------------------- #

FAIL_NO_DEVICE = "NO_DEVICE"
FAIL_HOST_NETWORK = "HOST_NETWORK"
FAIL_OPERATOR_DECLINED = "OPERATOR_DECLINED"
FAIL_FIRMWARE_INCOMPATIBLE = "FIRMWARE_INCOMPATIBLE"
FAIL_INITIAL_ACCESS_UNAVAILABLE = "INITIAL_ACCESS_UNAVAILABLE"
FAIL_INITIAL_ACCESS_FAILED = "INITIAL_ACCESS_FAILED"
FAIL_INCOMPLETE_ENROLLMENT = "INCOMPLETE_ENROLLMENT"
#: Enrollment failed AND the cleanup afterwards completed. Nothing is outstanding,
#: so this is an ordinary failure rather than a recovery state.
#:
#: It exists because there was no way to say that. Every enrollment failure
#: reported INCOMPLETE_ENROLLMENT, which maps to RECOVERY_REQUIRED, even when
#: `_recover()` had just confirmed the receiver was left clean. An operator was
#: told "Setup stopped partway, use RECOVER to remove anything left behind" about
#: a receiver with nothing left behind -- and, on the bench, beside a local key
#: that the same cleanup had already removed.
FAIL_ENROLLMENT_FAILED = "ENROLLMENT_FAILED"
FAIL_AUTHENTICATION = "AUTHENTICATION"

FAILURE_CLASSES = (FAIL_NO_DEVICE, FAIL_HOST_NETWORK, FAIL_OPERATOR_DECLINED,
                   FAIL_FIRMWARE_INCOMPATIBLE, FAIL_INITIAL_ACCESS_UNAVAILABLE,
                   FAIL_INITIAL_ACCESS_FAILED, FAIL_INCOMPLETE_ENROLLMENT,
                   FAIL_ENROLLMENT_FAILED, FAIL_AUTHENTICATION)

#: Which UI state a failure class resolves to. A class that leaves device-side state
#: behind maps to RECOVERY_REQUIRED; one that does not is BLOCKED.
_FAILURE_UI = {
    FAIL_NO_DEVICE: BLOCKED,
    FAIL_HOST_NETWORK: BLOCKED,
    FAIL_OPERATOR_DECLINED: BLOCKED,
    FAIL_FIRMWARE_INCOMPATIBLE: BLOCKED,
    FAIL_INITIAL_ACCESS_UNAVAILABLE: BLOCKED,
    FAIL_INITIAL_ACCESS_FAILED: BLOCKED,
    # Enrollment reached the device and the cleanup did NOT confirm it was
    # undone. Something may be installed; say so.
    FAIL_INCOMPLETE_ENROLLMENT: RECOVERY_REQUIRED,
    # Enrollment reached the device and the cleanup confirmed it was undone.
    # Nothing is outstanding, so RECOVERY_REQUIRED would be a false alarm --
    # and a false alarm about leftover access is worse than a plain failure,
    # because it sends an operator looking for something that is not there.
    FAIL_ENROLLMENT_FAILED: BLOCKED,
    # A key was installed and will not authenticate. That is leftover state.
    FAIL_AUTHENTICATION: RECOVERY_REQUIRED,
}

FAILURE_TEXT = {
    FAIL_NO_DEVICE:
        "No receiver is selected. Connect one first.",
    FAIL_HOST_NETWORK:
        "This computer could not reach the receiver over USB networking.",
    FAIL_OPERATOR_DECLINED:
        "Windows needs Administrator to configure the USB network adapter, and the "
        "prompt was dismissed. Approve it and activate again.",
    # Covers two different situations, and the step's own `supported` field
    # tells them apart: None is "nobody has looked", False is "we looked and it
    # cannot". Saying "no evidence" for a measured negative would discard a
    # hardware finding -- on the Gnd485, that / is squashfs ro and the key has
    # nowhere to live.
    FAIL_FIRMWARE_INCOMPATIBLE:
        "This receiver cannot carry Service Mode, or nothing has established "
        "that it can. The step detail says which.",
    # NAMES WHICH HALF IS MISSING. This used to say Service Mode was not
    # available for the firmware, which was read as "this receiver cannot do
    # it". The receiver may be perfectly capable and already reachable over
    # SSH -- what is unqualified is obtaining first access automatically, and
    # a key the receiver ALREADY trusts does not need that step at all.
    FAIL_INITIAL_ACCESS_UNAVAILABLE:
        "This receiver's SSH access works, but setting up a NEW key on it "
        "automatically is not qualified on this firmware. A key it already "
        "trusts can be used instead \u2014 see MANUAL STEPS.",
    FAIL_INITIAL_ACCESS_FAILED:
        "First-time activation did not complete on this receiver.",
    FAIL_INCOMPLETE_ENROLLMENT:
        "Setup stopped partway. Use RECOVER to remove anything left behind.",
    FAIL_ENROLLMENT_FAILED:
        "Setup did not complete, and nothing was left on the receiver.",
    FAIL_AUTHENTICATION:
        # The commonest cause is not a bad key. A firmware update replaces the
        # root filesystem, taking both our authorized_keys line and the
        # receiver's host key with it; naming that costs nothing and not
        # naming it cost an hour on the bench.
        ("The key was installed but the receiver did not accept it. If this "
         "receiver was updated since it last connected, that is the likely "
         "cause: a firmware update replaces the root filesystem, so the "
         "enrolled key and the receiver's SSH identity both change."),
}

# --------------------------------------------------------------------------- #
# Initial access -- a separate, firmware-gated capability
# --------------------------------------------------------------------------- #

#: Firmware releases where automated first access is HARDWARE-VALIDATED.
#:
#: EMPTY, and it stays empty until Gate 2 produces device-side evidence. Static
#: binary analysis is not entry here: the primitive being present in an image does
#: not prove the guards still route into it at runtime. 18.21.7 in particular is
#: NOT listed -- that is a standing instruction, not an oversight.
INITIAL_ACCESS_VALIDATED_FIRMWARE: frozenset[str] = frozenset()


class InitialAccessAdapter(Protocol):
    """Obtains the first privileged session on a receiver.

    No production implementation exists. The orchestrator is built to accept one so
    that the day Gate 2 passes, the capability drops in behind its own review
    boundary without the surrounding flow being redesigned.
    """

    def establish(self, target: dict) -> dict:
        """Return {'ok': bool, 'detail': str}. Must not raise for ordinary failure."""


def firmware_initial_access_validated(device_name, firmware) -> bool:
    """Is automated first access hardware-validated for this unit?

    Takes the DEVICE NAME as well as the firmware. Two platforms can carry the
    same version number and mean entirely different software, so a version on
    its own cannot qualify anything.

    Fails closed on anything unrecognised, including None and non-strings.
    """
    if not isinstance(device_name, str) or not device_name.strip():
        return False
    if not isinstance(firmware, str) or not firmware.strip():
        return False
    return firmware.strip() in INITIAL_ACCESS_VALIDATED_FIRMWARE


# --------------------------------------------------------------------------- #
# Result
# --------------------------------------------------------------------------- #

def _result(ui_state, *, steps, failure=None, detail=None, device_id=None,
            verified=False, rolled_back=None, persistence=None, audit=None):
    if ui_state not in UI_STATES:
        raise ValueError(f"unknown UI state {ui_state!r}")
    if verified and ui_state != VERIFIED:
        raise ValueError("verified=True is only valid with the VERIFIED state")
    if ui_state == VERIFIED and not verified:
        raise ValueError("VERIFIED must be backed by a proven authentication")
    return {
        "state": ui_state,
        "verified": bool(verified),
        "failure_class": failure,
        "detail": detail or (FAILURE_TEXT.get(failure) if failure else None),
        "device_id": device_id,
        "steps": steps,
        "rolled_back": rolled_back,
        # Persistence is NEVER folded into success. Each kind is its own gate.
        "persistence": persistence or {
            "reboot": "NOT_TESTED",
            "firmware_upgrade": "NOT_TESTED",
        },
        "audit": audit,
    }


class Orchestrator:
    """Composes existing components into one activation.

    Every collaborator is injected. `activate` is idempotent: a receiver already
    verified is re-verified rather than re-enrolled, so repeated presses never
    generate a second key, re-add a network address, or rewrite authorized_keys.
    """

    def __init__(self, *,
                 transport_ready: Callable[[], dict],
                 configure_transport: Callable[[], dict],
                 rollback_transport: Callable[[], dict],
                 identify: Callable[[], dict],
                 firmware_supported: Callable[[str, str], bool | None],
                 enroll_begin: Callable[[], dict],
                 enroll_verify: Callable[[], dict],
                 revoke: Callable[[], dict],
                 already_verified: Callable[[], bool] | None = None,
                 initial_access: InitialAccessAdapter | None = None,
                 reboot_persistence: Callable[[], dict] | None = None,
                 initial_access_validated: Callable[[str, str], bool] | None = None,
                 probe_ssh: Callable[[dict], dict] | None = None,
                 host_key_matches: Callable[[], bool | None] | None = None,
                 stage1_attemptable: Callable[[str, str], dict | None] | None = None,
                 unproven_acknowledged: bool = False,
                 audit_sink: Callable[[dict], None] | None = None,
                 clock: Callable[[], float] = time.time):
        self._transport_ready = transport_ready
        self._configure_transport = configure_transport
        self._rollback_transport = rollback_transport
        self._identify = identify
        self._firmware_supported = firmware_supported
        self._enroll_begin = enroll_begin
        self._enroll_verify = enroll_verify
        self._revoke = revoke
        self._already_verified = already_verified or (lambda: False)
        self._initial_access = initial_access
        # Injected so the firmware evidence lives in ONE place. The default is this
        # module's own fail-closed check, which keeps the orchestrator testable
        # standalone without becoming a second allow-list in production.
        self._reboot_persistence = reboot_persistence
        self._initial_access_validated = (
            initial_access_validated or firmware_initial_access_validated)
        # Optional. Without it the orchestrator behaves exactly as before, which
        # keeps every existing test honest rather than silently relaxed.
        self._probe_ssh = probe_ssh
        # Optional, and None means "not established" -- never False. Without it
        # the orchestrator behaves exactly as it did, so no existing test is
        # silently relaxed by this existing.
        self._host_key_matches = host_key_matches
        # Both default to the refusing value. An orchestrator built without them
        # cannot perform an unqualified attempt at all, so no existing caller or
        # test becomes more permissive by this change existing.
        self._stage1_attemptable = stage1_attemptable
        self._unproven_acknowledged = bool(unproven_acknowledged)
        self._audit_sink = audit_sink
        self._clock = clock

    # -- helpers ----------------------------------------------------------- #

    def _audit(self, device_id, outcome, failure, steps):
        rec = {"at": self._clock(), "device_id": device_id,
               "outcome": outcome, "failure_class": failure,
               "steps": list(steps)}
        if self._audit_sink is not None:
            self._audit_sink(rec)
        return rec

    def _fail(self, failure, steps, device_id=None, detail=None, rolled_back=None):
        ui = _FAILURE_UI[failure]
        cause = None

        # A FIRMWARE UPGRADE IS NOT LEFTOVER STATE, AND SAYING IT IS SENDS
        # SOMEBODY LOOKING FOR A KEY THAT NO LONGER EXISTS.
        #
        # FAIL_AUTHENTICATION maps to RECOVERY_REQUIRED on the reasoning "a key
        # was installed and will not authenticate, that is leftover state".
        # True in the ordinary case. False after an upgrade: the rootfs was
        # replaced, so our authorized_keys line went with it and there is
        # nothing on the receiver to recover. The operator is told to clean up
        # something that is already gone, which is the same false-alarm class
        # the FAIL_ENROLLMENT_FAILED comment above warns about.
        #
        # service_mode.classify_persistence has decided this from two booleans
        # since it was written and NOTHING HAS EVER CALLED IT. The host key is
        # the second boolean: /etc/dropbear is restored to a symlink by an
        # upgrade, forcing new host keys, so the key and the identity move
        # TOGETHER on an upgrade and neither moves on a reboot.
        if failure == FAIL_AUTHENTICATION and self._host_key_matches is not None:
            try:
                matches = self._host_key_matches()
            except Exception:
                matches = None          # unknown stays unknown
            if matches is False:
                # Both signals moved together (an upgrade replaced the rootfs,
                # taking our authorized_keys line and the host key with it), so
                # nothing was left behind and the leftover-state alarm is
                # withdrawn. The failure itself is unchanged and still reported.
                # The engineering build names the cause via a persistence
                # classifier; the public build withdraws the alarm without naming
                # it (host_key_matches is not wired here, so this branch is dormant).
                cause = None
                ui = BLOCKED
                rolled_back = True
        audit = self._audit(device_id, ui, failure, steps)
        res = _result(ui, steps=steps, failure=failure, detail=detail,
                      device_id=device_id, rolled_back=rolled_back, audit=audit)
        if cause:
            res["persistence_cause"] = cause
        return res

    # -- the one button ----------------------------------------------------- #

    def activate(self) -> dict:
        steps: list[dict] = []
        transport_configured_by_us = False
        device_id = None

        def note(step, status, **extra):
            steps.append({"step": step, "status": status, **extra})

        def undo_transport():
            if not transport_configured_by_us:
                return False
            try:
                self._rollback_transport()
                return True
            except Exception:
                return False

        # 1. IDENTIFY ------------------------------------------------------- #
        try:
            target = self._identify()
        except Exception as exc:
            note(STEP_IDENTIFY, "FAILED", detail=str(exc))
            return self._fail(FAIL_NO_DEVICE, steps)
        if not target:
            note(STEP_IDENTIFY, "FAILED")
            return self._fail(FAIL_NO_DEVICE, steps)

        device_id = target.get("device_id")
        note(STEP_IDENTIFY, "OK", device_id=device_id,
             device_name=target.get("device_name"), firmware=target.get("firmware"))

        # 2. TRANSPORT ------------------------------------------------------ #
        try:
            ready = self._transport_ready()
        except Exception as exc:
            note(STEP_TRANSPORT, "FAILED", detail=str(exc))
            return self._fail(FAIL_HOST_NETWORK, steps, device_id=device_id)

        if not ready.get("ready"):
            try:
                self._configure_transport()
                transport_configured_by_us = True
                note(STEP_TRANSPORT, "CONFIGURED")
            except PermissionError as exc:
                # A dismissed elevation prompt is an operator situation, not a fault.
                note(STEP_TRANSPORT, "BLOCKED", detail=str(exc))
                return self._fail(FAIL_OPERATOR_DECLINED, steps, device_id=device_id)
            except Exception as exc:
                note(STEP_TRANSPORT, "FAILED", detail=str(exc))
                return self._fail(FAIL_HOST_NETWORK, steps, device_id=device_id)
        else:
            note(STEP_TRANSPORT, "ALREADY_READY")

        # 3. FIRMWARE QUALIFICATION ----------------------------------------- #
        supported = self._firmware_supported(target.get("device_name"),
                                             target.get("firmware"))
        probe = None
        if supported is not True and self._probe_ssh is not None:
            # NO EVIDENCE IN THE TABLE IS NOT THE SAME AS NO EVIDENCE.
            #
            # Stage-2 capability was answered only from a table keyed on
            # firmware version, so every upgrade turned a working receiver into
            # an unqualified one until a row was added by hand. That happened on
            # the bench: the industrial Ground was measured answering SSH on
            # 16.5.3, the operator upgraded it to 19.2.14, and the gate reported
            # no evidence for the same unit on the same cable.
            #
            # The transport is up by this point, so the unit can simply be
            # asked. A live observation is the strongest grade this project
            # recognises and it cannot go stale.
            #
            # `False` is still a refusal: that means something was checked and
            # found wrong, and a reachable port does not overturn it. Only the
            # genuinely-unknown case is allowed to be settled by measurement.
            if supported is None:
                probe = self._probe_ssh(target)
                if probe.get("banner"):
                    note(STEP_FIRMWARE, "OK", firmware=target.get("firmware"),
                         evidence="observed", banner=probe.get("banner"))
                    supported = True
        if supported is not True:
            note(STEP_FIRMWARE, "BLOCKED", supported=supported,
                 firmware=target.get("firmware"),
                 probe=(probe or {}).get("error"),
                 # The difference an operator needs: a measured negative is a
                 # finding about this hardware, not a gap in our records, and
                 # retrying will not change it.
                 reason=("this receiver has been measured as unable to hold a "
                         "persistent key" if supported is False else
                         "nothing has established that this receiver can carry "
                         "Service Mode"))
            return self._fail(FAIL_FIRMWARE_INCOMPATIBLE, steps, device_id=device_id,
                              rolled_back=undo_transport())
        if probe is None:
            note(STEP_FIRMWARE, "OK", firmware=target.get("firmware"),
                 evidence="recorded")

        # IDEMPOTENCE -------------------------------------------------------- #
        # Already set up: re-verify, never re-enroll. A second press must not mint a
        # second key or append a second authorized_keys line.
        if self._already_verified():
            note(STEP_ENROLL, "SKIPPED_ALREADY_ENROLLED")
            return self._verify_only(steps, device_id)

        # 4. INITIAL ACCESS -------------------------------------------------- #
        #
        # QUALIFIED is unchanged and still proceeds on its own.
        #
        # UNQUALIFIED is where this used to be a dead end, and the dead end was
        # circular: the gate wanted first access proven on this platform and
        # version, and the only way to prove it was to perform it. A platform
        # whose updater has never been examined stays blocked -- that is the
        # safeguard and it is intact -- but a platform with its OWN prior result
        # is a different case from one with none at all.
        #
        # So an attempt may proceed when BOTH hold:
        #   * the platform has its own first-access evidence (never the MAX's;
        #     the two platforms have separate entries), and
        #   * the operator acknowledged, on THIS request, that the version is
        #     unproven.
        #
        # Neither alone is enough. The acknowledgement is per-request for the
        # same reason the capability is: one enabled once must not apply to a
        # later activation on a receiver it was never considered for.
        qualified = bool(self._initial_access_validated(target.get("device_name"),
                                                        target.get("firmware")))
        attemptable = None
        if not qualified and self._stage1_attemptable is not None:
            attemptable = self._stage1_attemptable(target.get("device_name"),
                                                   target.get("firmware"))
        if not qualified:
            if not attemptable:
                note(STEP_INITIAL_ACCESS, "BLOCKED",
                     reason="first access is not qualified on this firmware, and "
                            "this platform has no first-access evidence of its own",
                     device_name=target.get("device_name"),
                     firmware=target.get("firmware"))
                return self._fail(FAIL_INITIAL_ACCESS_UNAVAILABLE, steps,
                                  device_id=device_id, rolled_back=undo_transport())
            if not self._unproven_acknowledged:
                note(STEP_INITIAL_ACCESS, "BLOCKED",
                     reason="first access is unproven on this firmware and was "
                            "not acknowledged as unproven on this request",
                     device_name=target.get("device_name"),
                     firmware=target.get("firmware"),
                     platform=attemptable.get("platform"))
                return self._fail(FAIL_INITIAL_ACCESS_UNAVAILABLE, steps,
                                  device_id=device_id, rolled_back=undo_transport())
        if self._initial_access is None:
            note(STEP_INITIAL_ACCESS, "BLOCKED", reason="no adapter")
            return self._fail(FAIL_INITIAL_ACCESS_UNAVAILABLE, steps,
                              device_id=device_id, rolled_back=undo_transport())
        if not qualified:
            # Recorded AFTER the adapter check and immediately before the call,
            # so the trail says an attempt was made only when one actually was.
            # Noting it earlier claimed an attempt on a run that could never
            # reach the device, which is the same defect as reporting success
            # from a command that did not run.
            note(STEP_INITIAL_ACCESS, "UNPROVEN_ATTEMPT",
                 reason="attempted on platform evidence; this firmware version "
                        "has not been shown to accept it",
                 device_name=target.get("device_name"),
                 firmware=target.get("firmware"),
                 platform=attemptable.get("platform"),
                 basis=attemptable.get("grade"))
        try:
            got = self._initial_access.establish(target)
        except Exception as exc:
            note(STEP_INITIAL_ACCESS, "FAILED", detail=str(exc))
            return self._fail(FAIL_INITIAL_ACCESS_FAILED, steps, device_id=device_id,
                              rolled_back=undo_transport())
        if not (got or {}).get("ok"):
            note(STEP_INITIAL_ACCESS, "FAILED", detail=(got or {}).get("detail"))
            return self._fail(FAIL_INITIAL_ACCESS_FAILED, steps, device_id=device_id,
                              rolled_back=undo_transport())
        note(STEP_INITIAL_ACCESS, "OK")

        # 5. ENROLL ---------------------------------------------------------- #
        try:
            self._enroll_begin()
        except Exception as exc:
            # CARRY THE EVIDENCE, not just the sentence. A ServiceModeError may
            # bring findings gathered while the session was still open -- the
            # mount state of /root, whether it is writable, where the daemon
            # actually reads keys from. Dropping them means the one chance to
            # ask is spent and the answer discarded, which is what happened on
            # the Industrial: the session closed moments later and the question
            # could not be asked again without obtaining access afresh.
            note(STEP_ENROLL, "FAILED", detail=str(exc),
                 **{k: v for k, v in (getattr(exc, "evidence", None) or {}).items()
                    if k in ("diagnosis", "verification")})
            # THE CLEANUP'S OWN RESULT DECIDES WHICH FAILURE THIS IS.
            #
            # `_recover()` already distinguishes "the receiver was left clean"
            # from "we could not confirm that", and that distinction was then
            # thrown away: both reported INCOMPLETE_ENROLLMENT, which is a
            # RECOVERY_REQUIRED state. So an operator was told to go and remove
            # something from a receiver the application had just confirmed was
            # clean.
            #
            # Uncertainty still maps to RECOVERY_REQUIRED, which is the safe
            # direction: claiming a cleanup happened when it may not have is
            # the error that leaves a key on a unit nobody knows about.
            recovered = self._recover()
            return self._fail(
                FAIL_ENROLLMENT_FAILED if recovered else FAIL_INCOMPLETE_ENROLLMENT,
                steps, device_id=device_id, rolled_back=recovered)
        note(STEP_ENROLL, "OK")

        # 6. VERIFY ---------------------------------------------------------- #
        return self._verify_only(steps, device_id, enrolled_this_run=True)

    def _verify_only(self, steps, device_id, *, enrolled_this_run=False):
        def note(step, status, **extra):
            steps.append({"step": step, "status": status, **extra})
        try:
            res = self._enroll_verify()
        except Exception as exc:
            note(STEP_VERIFY, "FAILED", detail=str(exc))
            return self._fail(FAIL_AUTHENTICATION, steps, device_id=device_id,
                              rolled_back=self._recover() if enrolled_this_run else None)

        # The ONLY success criterion. A truthy response is not enough -- the verifier
        # must say the key authenticated.
        if not (res or {}).get("verified"):
            note(STEP_VERIFY, "FAILED", detail="authentication not confirmed")
            return self._fail(FAIL_AUTHENTICATION, steps, device_id=device_id,
                              rolled_back=self._recover() if enrolled_this_run else None)

        note(STEP_VERIFY, "OK")

        # DID IT SURVIVE A POWER CYCLE? THE RECEIVER CAN ANSWER THAT.
        #
        # `persistence.reboot` was hardcoded NOT_TESTED and NOTHING ever set it
        # to anything else, so a panel gating on INTACT could never report
        # persistence however many times the unit was restarted. An operator
        # rebooted and re-checked and was told, again, that it had not been
        # tested. The gate was unsatisfiable, which is worse than absent: it
        # looked like an answer.
        #
        # The fact is cheap to establish and needs no new ceremony. We have just
        # authenticated with the managed credential. If the receiver's uptime is
        # SHORTER than the time since it was enrolled, it has been restarted
        # since the key was installed -- and the key still works, because we are
        # talking to it. That is exactly the evidence a person would gather by
        # hand, and it is what proved the Industrial.
        persistence = None
        if self._reboot_persistence is not None:
            try:
                persistence = self._reboot_persistence()
            except Exception:
                persistence = None       # unknown stays unknown, never INTACT

        audit = self._audit(device_id, VERIFIED, None, steps)
        return _result(VERIFIED, steps=steps, device_id=device_id, verified=True,
                       persistence=persistence, audit=audit)

    def _recover(self):
        """Undo a partial enrollment. Never raises; the caller is already failing.

        Returns True ONLY when the cleanup actually completed. "revoke did not
        raise" is not the same as "the device no longer holds the key": the
        device-side removal normally travels over the SSH path, and the usual
        reason recovery runs at all is that SSH just failed. Reporting that as
        recovered would claim the receiver was left clean when it was not.
        """
        try:
            out = self._revoke()
        except Exception:
            return False
        if isinstance(out, dict) and "cleanup_complete" in out:
            return bool(out["cleanup_complete"])
        return True
