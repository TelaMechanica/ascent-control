"""
Regional RF mode ("FCC Hack") -- policy, state model, and a gate that cannot write.

### Read the evidence document before changing anything here

`docs/REGIONAL_RF_MODE_EVIDENCE_2026-10-07.md` is the static trace, and §8 is
the part that matters. The mechanism is now understood end to end:

* the state is a byte the firmware calls **`bb_std`**, in its settings structure;
* the record-button gesture **sets it to 7** -- a constant, stored
  unconditionally, so it is a SET and not a toggle -- then persists and reboots;
* a second, far more controllable setter reads a decimal from a file on the
  record medium, applies it, and deletes the file so it acts once;
* `bb_std` travels with bandwidth, channel number, band group and frequency on
  every channel set, which is the channel-side link;
* **`crack_power` is a separate persisted key that the gesture never touches.**

That last point is why this module refuses to collapse the two values. The
gesture is a CHANNEL-side change only. Calling it a complete "FCC Hack" would
mislead an operator into expecting the power limit to move, and nothing in the
firmware would correct them.

**Automation is still closed**, and the reason has narrowed rather than
disappeared: an idempotent setter exists, but no readback has been implemented,
the settings file has not been named, and what the value 7 actually selects is
unproven. Writing without a readback is the blind write this gate exists to
prevent -- knowing HOW to write is not knowing WHETHER to.

### Expanded RF Mode (FCC Hack) -- channel AND power

**Corrected 2026-10-08.** The user hardware-confirmed that the stock
record-button long press unlocks BOTH additional channels and additional
transmit-power choices. An earlier reading of this module claimed the change was
channel-only; that claim is withdrawn. It rested on `crack_power` -- a persisted
config KEY -- not being written by the key-9 path, which does not establish that
effective power is unchanged, and it ignored nine untraced readers of `bb_std`.

The two halves are still tracked SEPARATELY, but for the opposite reason than
before: not because one is believed absent, but because **the mechanism for the
power half is not established**, so the application must be able to say which
half it has actually verified.

* `channel_unlock` -- SOURCE-PROVEN mechanism (`bb_std`), user-confirmed effect
* `power_unlock`   -- user-confirmed effect, mechanism NOT established

A receiver is fully UNLOCKED only when both are established, or when hardware
qualification proves one authoritative state controls both. A channel-only
observation is a partial observation and is reported as one.

### Why automation is refused

Automatic enablement needs BOTH a reliable current-state read and an idempotent
set-enabled operation. Neither exists. The only trigger found is a physical
gesture whose set-vs-toggle semantics are unknown, and a blind toggle is the one
thing that must never be automated: on a receiver that is already configured it
would turn the mode OFF.

`IdempotentEnable` is an interface with no implementation, deliberately. A
toggle cannot satisfy it -- `register_operation()` refuses anything that does not
assert both `reads_current_state` and `idempotent`, and a test mutates that to
prove the refusal is real rather than decorative.
"""
from __future__ import annotations

SCHEMA = "ascent.regional_rf_mode.v1"

# --------------------------------------------------------------------------- #
# User policy. Three values, and the default is the one that does nothing.
# --------------------------------------------------------------------------- #

POLICY_AUTOMATIC = "AUTOMATIC"
POLICY_ASK = "ASK"
POLICY_DISABLED = "DISABLED"
POLICIES = (POLICY_AUTOMATIC, POLICY_ASK, POLICY_DISABLED)

#: Never preselect automatic enablement. The setting is opt-in and unchecked.
DEFAULT_POLICY = POLICY_DISABLED

POLICY_LABELS = {
    POLICY_AUTOMATIC: "ENABLE AUTOMATICALLY ON COMPATIBLE VRXs",
    POLICY_ASK: "ASK ME FOR EACH VRX",
    POLICY_DISABLED: "LEAVE DISABLED",
}

SETTING_TITLE = "Enable expanded RF mode?"
SETTING_CHECKBOX = "ENABLE FCC HACK ON COMPATIBLE VRXs"
SETTING_DESCRIPTION = (
    "Ascent Control can attempt to enable the receiver's expanded RF mode when a "
    "supported VRX is discovered. This may expose frequencies or power settings "
    "that are restricted in your location.")
#: Shown wherever the policy is chosen, and again in the review before FINISH
#: when automatic was selected.
ACKNOWLEDGEMENT = (
    "You are responsible for operating only on frequencies and power levels "
    "permitted in your location. “FCC Hack” is product/community "
    "terminology and does not mean the resulting configuration is FCC-certified "
    "or lawful everywhere.")

# --------------------------------------------------------------------------- #
# Observed receiver state. Two values, five possibilities each.
# --------------------------------------------------------------------------- #

ENABLED = "ENABLED"
DISABLED = "DISABLED"
PARTIAL = "PARTIAL"
UNKNOWN = "UNKNOWN"
UNSUPPORTED = "UNSUPPORTED"
OBSERVED_STATES = (ENABLED, DISABLED, PARTIAL, UNKNOWN, UNSUPPORTED)

#: The states from which a write may even be considered. UNKNOWN is not among
#: them, and that is the whole point: a failed read must never read as DISABLED.
WRITABLE_FROM = frozenset({DISABLED})

UNAVAILABLE_BANNER = "AUTOMATIC FCC MODE UNAVAILABLE — CONTROL PATH NOT YET PROVEN"
UNAVAILABLE_BODY = (
    "Ascent Control cannot safely determine or set this receiver's current RF "
    "mode. Use the verified physical-button procedure.")

PROGRESS_STAGES = ("Checking receiver", "Reading RF mode",
                   "Enabling expanded RF mode", "Verifying RF mode", "Complete")


#: What the static trace established, as data rather than prose, so the UI can
#: explain the position without a second copy of it drifting out of date.
#: Every entry is SOURCE-PROVEN unless its text says otherwise.
MECHANISM = {
    "state_field": "bb_std",
    "state_is_a_toggle": False,
    # WITHDRAWN 2026-10-08: this previously read gesture_affects="channel" and
    # power_touched_by_gesture=False. Both were negative claims built on a
    # partial scan and are contradicted by bench observation.
    "gesture_affects": "channel_and_power",
    "channel_mechanism_proven": True,
    "power_mechanism_proven": False,
    "power_effect_user_confirmed": True,
    "power_lead": ("The VRX power menu is supplied, not computed locally, and "
                   "its locked options match the Sky's seven-row lower mW->dBm "
                   "ladder entry for entry. The Sky's table selector is an open "
                   "item."),
    "file_setter": True,
    "readback_implemented": False,
    "value_semantics_proven": False,
    "evidence": "docs/REGIONAL_RF_MODE_EVIDENCE_2026-10-07.md",
    "note": ("Expanded RF Mode changes both the channel table and the power "
             "range. The channel mechanism is traced; the power mechanism is "
             "not, so a channel-only observation must not be reported as full "
             "verification."),
}

#: PER RELEASE, because the two releases disagree and carrying one forward onto
#: the other would write the wrong value. 19.2.14's release note says it plainly:
#: "remove the long-press crack function; update the crack value".
#:
#: `gesture_present` on 19.2.14 is False and that is VERIFIED, not assumed: the
#: binary is stripped, so the absence of the enum names proves nothing, and the
#: test was a structural scan for the remap's instruction shape with the 19.2.4
#: binary as a positive control. The control finds the one known instance;
#: 19.2.14 has none.
MECHANISM_BY_RELEASE = {
    "19.2.4": {
        "gesture_present": True,
        "gesture_sets_value": 7,
        "gesture_is_unconditional": True,
        "file_setter_present": True,
    },
    "19.2.14": {
        "gesture_present": False,          # removed by the vendor
        "gesture_sets_value": 4,           # when the handler is reached at all
        "gesture_is_unconditional": False,  # 4 or 7, on a runtime check
        "file_setter_present": True,       # the surviving route
    },
}


def mechanism_for(firmware_release):
    """What is known for ONE release. Never a borrowed answer.

    Returns None for a release no trace covers. That is deliberate: the two
    releases traced disagree about both the trigger and the value, so guessing
    across them is how the wrong constant gets written to a receiver.
    """
    if not isinstance(firmware_release, str):
        return None
    return MECHANISM_BY_RELEASE.get(firmware_release)


class RegionalRfError(RuntimeError):
    def __init__(self, code: str, message: str, evidence: dict | None = None):
        super().__init__(message)
        self.code, self.evidence = code, evidence or {}


# --------------------------------------------------------------------------- #
# The operation registry
# --------------------------------------------------------------------------- #

#: Registered enable operations, keyed by (device_name, firmware_release).
#: EMPTY, and `register_operation` is the only way in.
_OPERATIONS: dict[tuple, object] = {}


def register_operation(device_name, firmware_release, op) -> None:
    """Admit an enable operation for one exact target.

    Refuses anything that cannot both READ the current state and SET it
    idempotently. A blind toggle fails here, by construction, and that refusal
    is the single most important line in this module: automating a toggle would
    turn the mode OFF on a receiver that already has it on, and the operator
    would have asked for the opposite.
    """
    if not getattr(op, "reads_current_state", False):
        raise RegionalRfError(
            "OPERATION_CANNOT_READ",
            "An enable operation must be able to read the current state first.")
    if not getattr(op, "idempotent", False):
        raise RegionalRfError(
            "OPERATION_NOT_IDEMPOTENT",
            "A toggle cannot be used for automatic enablement: on a receiver "
            "that is already configured it would turn the mode off.")
    _OPERATIONS[(device_name, firmware_release)] = op


def operation_for(device_name, firmware_release):
    """The qualified operation for an exact target, or None. Never fuzzy."""
    if not isinstance(device_name, str) or not isinstance(firmware_release, str):
        return None
    return _OPERATIONS.get((device_name, firmware_release))


def automation_available(device_name=None, firmware_release=None) -> bool:
    return operation_for(device_name, firmware_release) is not None


# --------------------------------------------------------------------------- #
# Observed state
# --------------------------------------------------------------------------- #

def observed_state(device_id=None, *, channel=UNKNOWN, power=UNKNOWN,
                   checked_at=None, device_name=None, firmware=None,
                   last_attempt=None, last_verification=None) -> dict:
    """One receiver's observed state. Both halves, never merged.

    `requested` is deliberately absent from this structure. Asking for something
    is not a state, and the one bug this model exists to prevent is a request
    being displayed as though it were a verified outcome.
    """
    for v in (channel, power):
        if v not in OBSERVED_STATES:
            raise RegionalRfError("OBSERVED_STATE_INVALID", f"not a state: {v!r}")
    return {
        "schema": SCHEMA,
        "device_id": device_id,
        "device_name": device_name,
        "firmware": firmware,
        "channel_unlock": channel,
        "power_unlock": power,
        "checked_at": checked_at,
        "last_attempt": last_attempt,
        "last_verification": last_verification,
        "automation_available": automation_available(device_name, firmware),
        "summary": describe_partial(channel, power),
    }


def describe_partial(channel: str, power: str) -> str:
    """Say exactly which halves are on. Never call one half the whole thing."""
    if channel == ENABLED and power == ENABLED:
        return "Channel and power unlock are both enabled."
    if channel == ENABLED and power != ENABLED:
        return ("Channel unlock only. This is not a complete expanded RF mode: "
                "the power limit is unchanged.")
    if power == ENABLED and channel != ENABLED:
        return ("Power unlock only. This is not a complete expanded RF mode: "
                "the channel list is unchanged.")
    if UNKNOWN in (channel, power):
        return "The receiver's expanded RF mode could not be determined."
    if channel == UNSUPPORTED and power == UNSUPPORTED:
        return "This receiver does not support expanded RF mode."
    return "Expanded RF mode is off."


# --------------------------------------------------------------------------- #
# The combined feature state
#
# Separate from the two per-half observations above, because an operator asks one
# question -- "is Expanded RF Mode on?" -- and the honest answer has six values,
# not two. REBOOT_REQUIRED and VERIFYING exist because this operation restarts
# the receiver: there is a real interval during which the request has been sent,
# the receiver is coming back, and nothing is yet known. Collapsing that into
# either LOCKED or UNLOCKED is how "it said it worked" happens.
# --------------------------------------------------------------------------- #

STATE_LOCKED = "LOCKED"
STATE_UNLOCKED = "UNLOCKED"
STATE_UNKNOWN = "UNKNOWN"
STATE_UNSUPPORTED = "UNSUPPORTED"
STATE_REBOOT_REQUIRED = "REBOOT_REQUIRED"
STATE_VERIFYING = "VERIFYING"
FEATURE_STATES = (STATE_LOCKED, STATE_UNLOCKED, STATE_UNKNOWN, STATE_UNSUPPORTED,
                  STATE_REBOOT_REQUIRED, STATE_VERIFYING)

#: The lifecycle of one attempt, kept distinct so a UI cannot report a send as a
#: result. Each is a different thing to tell an operator.
STAGE_REQUESTED = "REQUESTED"
STAGE_SENT = "SENT"
STAGE_REBOOTING = "REBOOTING"
STAGE_RECONNECTED = "RECONNECTED"
STAGE_VERIFIED = "VERIFIED"
ATTEMPT_STAGES = (STAGE_REQUESTED, STAGE_SENT, STAGE_REBOOTING,
                  STAGE_RECONNECTED, STAGE_VERIFIED)

PRODUCT_NAME = "Expanded RF Mode (FCC Hack)"
PRODUCT_DESCRIPTION = (
    "Enables the stock expanded channel and power ranges on supported "
    "receivers. The receiver must restart to apply the change.")
ENABLE_LABEL = "ENABLE EXPANDED RF MODE (FCC HACK)"
ENABLE_EXPLAINER = (
    "This performs the same stock unlock normally triggered by holding the "
    "receiver's record button. It expands both channel and power choices and "
    "requires a receiver restart.")

#: Shown before every application, under every policy. The operation restarts a
#: receiver, so there is no policy under which it happens without this.
RESTART_TITLE = "Enable Expanded RF Mode and restart this receiver?"
RESTART_CONFIRM = "ENABLE & RESTART"
RESTART_DECLINE = "NOT NOW"

POWER_UNPROVEN_LABEL = "POWER UNLOCK — NOT PROVEN"
POWER_UNPROVEN_DETAIL = (
    "The expanded power range is confirmed on hardware, but Ascent Control "
    "cannot yet read it back, so it is not offered as a control and is not "
    "counted as verification.")


def feature_state(*, channel, power, supported=None, attempt_stage=None) -> dict:
    """The one answer, from the two observations. Pure.

    UNLOCKED requires BOTH halves. That is the whole point of the function: the
    power half is user-confirmed but not yet readable by this application, so in
    practice it returns a partial result and says so, rather than reporting a
    channel reading as a complete unlock.
    """
    if supported is False or UNSUPPORTED in (channel, power):
        return _feature(STATE_UNSUPPORTED, channel, power,
                        "This receiver does not support Expanded RF Mode.")
    if attempt_stage in (STAGE_SENT, STAGE_REBOOTING):
        return _feature(STATE_REBOOT_REQUIRED, channel, power,
                        "The receiver is restarting to apply the change.")
    if attempt_stage == STAGE_RECONNECTED:
        return _feature(STATE_VERIFYING, channel, power,
                        "Checking the receiver's channel and power ranges.")
    if channel == ENABLED and power == ENABLED:
        return _feature(STATE_UNLOCKED, channel, power,
                        "Expanded channel and power ranges are enabled.")
    if UNKNOWN in (channel, power):
        # Includes the ordinary case today: channel readable, power not.
        return _feature(STATE_UNKNOWN, channel, power,
                        describe_partial(channel, power))
    if channel == DISABLED and power == DISABLED:
        return _feature(STATE_LOCKED, channel, power,
                        "Expanded RF Mode is off.")
    return _feature(STATE_UNKNOWN, channel, power, describe_partial(channel, power))


def _feature(state, channel, power, summary) -> dict:
    return {"schema": SCHEMA, "state": state, "channel_unlock": channel,
            "power_unlock": power, "summary": summary,
            "fully_verified": state == STATE_UNLOCKED,
            "states": list(FEATURE_STATES)}


# --------------------------------------------------------------------------- #
# The decision
# --------------------------------------------------------------------------- #

#: Every reason a write is refused. Each is its own code so the UI can say which,
#: and so a test can assert that a given condition produces THAT one.
DEFER_NO_OPERATION = "NO_PROVEN_OPERATION"
DEFER_POLICY = "POLICY_NOT_AUTOMATIC"
DEFER_UNKNOWN_STATE = "CURRENT_STATE_UNKNOWN"
DEFER_ALREADY_ENABLED = "ALREADY_ENABLED"
DEFER_UNSUPPORTED = "UNSUPPORTED_TARGET"
DEFER_AMBIGUOUS = "AMBIGUOUS_RECEIVER"
DEFER_EXCLUSIVE = "EXCLUSIVE_OPERATION_ACTIVE"
DEFER_ARMED = "RECEIVER_ARMED"
DEFER_NOT_FOREGROUND = "APP_NOT_IN_FOREGROUND"
DEFER_SETUP_INCOMPLETE = "FIRST_RUN_NOT_FINISHED"


def decide(*, policy, state, device_name=None, firmware=None,
           supported=None, single_unambiguous_receiver=True,
           exclusive_operation=None, armed=None, foreground=True,
           first_run_complete=True) -> dict:
    """May a write be issued right now? Pure, and it defaults to no.

    ORDER MATTERS AND IS TESTED. The checks that do not depend on talking to the
    receiver come first, so that a refusal is reached without touching anything.
    `DEFER_NO_OPERATION` is first of all, because with no proven operation every
    later question is academic -- and that is this build's actual situation.

    `armed=None` means "not known", and that defers. The brief is explicit: if
    armed state is uncertain, defer rather than guess. Same for `supported`.
    """
    if not automation_available(device_name, firmware):
        return _defer(DEFER_NO_OPERATION, UNAVAILABLE_BODY)
    if not first_run_complete:
        return _defer(DEFER_SETUP_INCOMPLETE,
                      "First-run setup has not been finished and confirmed.")
    if policy != POLICY_AUTOMATIC:
        return _defer(DEFER_POLICY, "Automatic enablement is not selected.")
    if supported is not True:
        return _defer(DEFER_UNSUPPORTED,
                      "This receiver and firmware are not qualified.")
    if not single_unambiguous_receiver:
        return _defer(DEFER_AMBIGUOUS,
                      "More than one receiver could be meant, so nothing was changed.")
    if exclusive_operation:
        return _defer(DEFER_EXCLUSIVE,
                      f"{exclusive_operation} is in progress.")
    if not foreground:
        return _defer(DEFER_NOT_FOREGROUND, "Ascent Control is not in the foreground.")
    if armed is not False:
        # None (unknown) and True (armed) both stop here. Only a positive,
        # trustworthy "not armed" allows a write.
        return _defer(DEFER_ARMED,
                      "The receiver is flying, or its flight state could not be "
                      "determined.")
    ch = (state or {}).get("channel_unlock", UNKNOWN)
    pw = (state or {}).get("power_unlock", UNKNOWN)
    if UNKNOWN in (ch, pw):
        return _defer(DEFER_UNKNOWN_STATE, UNAVAILABLE_BODY)
    if UNSUPPORTED in (ch, pw):
        return _defer(DEFER_UNSUPPORTED, "This receiver does not support the mode.")
    if ch == ENABLED and pw == ENABLED:
        return _defer(DEFER_ALREADY_ENABLED,
                      "Expanded RF mode is already enabled on this receiver.")
    if ch not in WRITABLE_FROM and pw not in WRITABLE_FROM:
        return _defer(DEFER_UNKNOWN_STATE, UNAVAILABLE_BODY)
    return {"write": True, "reason": None, "message": None,
            "stages": list(PROGRESS_STAGES)}


def _defer(reason: str, message: str) -> dict:
    return {"write": False, "reason": reason, "message": message,
            "stages": list(PROGRESS_STAGES)}


def verify(before: dict, after: dict) -> dict:
    """A command returning success is not a verification.

    The brief is explicit and this function is where it is enforced: a toast, a
    menu changing, a boolean being written and extra options appearing in a list
    are all NOT evidence. Only an observed change in the receiver's effective
    configuration counts, and `after` must be a fresh READ, not the request.
    """
    ch, pw = (after or {}).get("channel_unlock"), (after or {}).get("power_unlock")
    if ch not in OBSERVED_STATES or pw not in OBSERVED_STATES:
        raise RegionalRfError("VERIFY_NO_READBACK",
                              "Verification needs a fresh read of the receiver.")
    if UNKNOWN in (ch, pw):
        return {"verified": False, "reason": "READBACK_UNKNOWN",
                "message": "The receiver's state could not be read back, so the "
                           "change is not confirmed."}
    changed = (ch != (before or {}).get("channel_unlock")
               or pw != (before or {}).get("power_unlock"))
    return {"verified": bool(changed) and (ch == ENABLED or pw == ENABLED),
            "reason": None if changed else "NO_OBSERVED_CHANGE",
            "channel_unlock": ch, "power_unlock": pw,
            "summary": describe_partial(ch, pw)}
