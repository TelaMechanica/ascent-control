"""
Known receivers -- which units this PC has seen, and their Service Mode state.

WHY A SECOND STORE, AND NOT AN EXTENSION OF THE NICKNAME STORE.
`vtx_nicknames.py` is the naming master. It is keyed by **BbId** and it is frozen
(`docs/NAMING_ARCHITECTURE_FROZEN_2026-09-23.md`). It cannot be the registry key,
for a reason that is a property of the hardware and not a preference: a VRX on
serial exposes **no BbId at all** -- command 60 does not carry one, and the only
BbId a connected unit offers is `ground_local_bb_id`, read over the Ground RPC,
which is a *receiver* identity that may not be available when enrollment happens.
Re-keying a frozen presentation store so it could carry enrollment state would
also make a nickname load-bearing for security, which the naming freeze forbids
outright.

So: two stores, one reference. This registry may hold a `nickname_bb_id` pointing
INTO the nickname store. It never copies the nickname text, so the two cannot
disagree, and this file never writes to the nickname store.

WHAT IT MUST NEVER CONTAIN. No private keys, no passwords, no password hashes or
salts, no shell commands, no Wi-Fi SSIDs, no public addresses. `assert_clean()`
enforces this on every write rather than trusting callers, and the test suite
asserts that the enforcement itself works.

IDENTITY. See `IDENTITY_RULES`. A MAC address is an observation and never an
identity; `192.168.3.102` is never an identity, because every Ascent unit
presents it.
"""
from __future__ import annotations

import json
import tempfile
import threading
from functools import wraps
import os
import re
import time
import uuid
from pathlib import Path

import local_settings
import receiver_identity as rxident

SCHEMA = "ascent.known_receivers.v1"
SCHEMA_VERSION = 1
STORE_FILENAME = "known_devices.json"

# One registry owner: serialize file handles so Windows readers cannot block replacement.
_STORE_LOCK = threading.RLock()

def _serialized(fn):
    @wraps(fn)
    def locked(*args, **kwargs):
        with _STORE_LOCK:
            return fn(*args, **kwargs)
    return locked


# Enrollment state, distinct from the live Service Mode session state.
NOT_SET_UP = "NOT SET UP"
ENROLLED = "ENROLLED"
REVOKED = "REVOKED"
ENROLLMENT_STATES = (NOT_SET_UP, ENROLLED, REVOKED)

# What the optional manual password path is known to be. Never the password.
PW_UNVERIFIED = "UNVERIFIED"
PW_USER_REPORTED = "USER REPORTED"
PW_UNKNOWN = "UNKNOWN"
PASSWORD_STATES = (PW_UNVERIFIED, PW_USER_REPORTED, PW_UNKNOWN)

DEFAULT_SNOOZE_SECONDS = 7 * 24 * 3600          # a week; a bench unit is reconnected often

IDENTITY_RULES = (
    "1. usb_container_id -- the USB ContainerId of the serial interface. Stable per "
    "physical unit on this PC and already what Service Mode pins host keys against.",
    "2. command_60_identity + serial_number -- device-reported, as a COMPOSITE. The "
    "serial alone is not treated as unique: observed values are short and look "
    "batch-scoped, so it corroborates and never decides on its own.",
    "3. host_key_fingerprint -- the pinned SSH host key. Cryptographic, but only "
    "meaningful after enrollment, so it confirms rather than discovers.",
    "4. bb_id -- only where its provenance is recorded, because a connected VRX "
    "usually does not expose one.",
    "5. observed MAC addresses -- EVIDENCE ONLY. Never a primary key, never "
    "sufficient to match, and a new one never creates a second record.",
    "NEVER: the device IP. Every Ascent unit presents 192.168.3.102.",
)

_MAC_RE = re.compile(r"^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$", re.I)
# Broad where the word is only ever a credential; SPECIFIC for "command" and
# "shell", because `command_60_identity` is a legitimate field and a pattern that
# needs a growing allowlist of innocent names will eventually allowlist a real
# one by mistake.
_SECRET_KEYS = re.compile(
    r"passw|secret|private_key|token|credential|ssid|psk"
    r"|\bsalt\b|\bhash\b|command_line|cmdline|shell_command|\bargv\b|\bshell\b",
    re.I)
_SECRET_VALUE = re.compile(
    r"-----BEGIN|\$[1256ay]\$[./A-Za-z0-9]{6,}|ssh-(ed25519|rsa)\s+[A-Za-z0-9+/=]{20,}")


class RegistryError(RuntimeError):
    def __init__(self, code: str, message: str, evidence=None):
        super().__init__(message)
        self.code = code
        self.evidence = evidence or {}


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def store_path() -> Path:
    """Beside the naming master, for the same reason it is: this is a setting,
    not a save artefact, and moving the save directory must not make enrolled
    receivers look unknown."""
    return local_settings.config_root() / STORE_FILENAME


# --------------------------------------------------------------------------- #
# The thing that must never hold a secret
# --------------------------------------------------------------------------- #

def assert_clean(doc) -> None:
    """Refuse to persist anything that looks like a credential.

    Enforced on the document rather than at each call site, because a call site
    is where the rule gets forgotten. The allowlisted keys below are the ones
    whose NAMES match the secret pattern but whose VALUES are states or
    references -- `manual_password_status` holds "UNVERIFIED", never a password.
    """
    allowed = {"manual_password_status", "host_key_fingerprint", "host_key_pin_present"}

    def walk(node, path="$"):
        if isinstance(node, dict):
            for k, v in node.items():
                if _SECRET_KEYS.search(str(k)) and k not in allowed:
                    raise RegistryError(
                        "REGISTRY_SECRET_REFUSED",
                        f"{path}.{k} looks like a credential field; the receiver "
                        f"registry holds metadata only",
                        {"field": f"{path}.{k}"})
                walk(v, f"{path}.{k}")
        elif isinstance(node, list):
            for i, v in enumerate(node):
                walk(v, f"{path}[{i}]")
        elif isinstance(node, str):
            if _SECRET_VALUE.search(node):
                raise RegistryError(
                    "REGISTRY_SECRET_REFUSED",
                    f"{path} contains key or hash material; the receiver registry "
                    f"holds metadata only", {"field": path})

    walk(doc)


# --------------------------------------------------------------------------- #
# Normalisation
# --------------------------------------------------------------------------- #

def norm_container_id(value) -> str:
    return str(value or "").strip().upper()


def norm_mac(value) -> str:
    t = str(value or "").strip().lower().replace("-", ":")
    return t if _MAC_RE.match(t) else ""


def norm_text(value, limit: int = 120) -> str:
    return str(value or "").strip()[:limit]


def new_device_id() -> str:
    """Locally generated and opaque. Deliberately not derived from any device
    value, so a record survives a device field changing."""
    return f"rx-{uuid.uuid4().hex[:16]}"


# --------------------------------------------------------------------------- #
# The document
# --------------------------------------------------------------------------- #

def empty_document() -> dict:
    return {"schema": SCHEMA, "schema_version": SCHEMA_VERSION, "devices": []}


def _quarantine(path: Path, why: str) -> Path:
    """Move a damaged store aside rather than overwrite it.

    A corrupt registry is a bug report. Overwriting it destroys the only copy of
    whatever caused it, and the operator finds out only that their enrolled
    receivers are suddenly unknown.
    """
    stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    dest = path.with_name(f"{path.name}.corrupt-{stamp}")
    try:
        os.replace(path, dest)
    except OSError:
        return path
    return dest


@_serialized
def load_document() -> dict:
    """Never raises. A damaged store is quarantined and reported, not fatal.

    This store must not be able to take the application down, and it must never
    be able to damage the nickname store -- it does not write to it at all.
    """
    p = store_path()
    if not p.is_file():
        return dict(empty_document(), quarantined=None)
    try:
        raw = p.read_text(encoding="utf-8")
    except OSError as e:
        return dict(empty_document(), quarantined=None,
                    load_error=f"{type(e).__name__}")
    try:
        doc = json.loads(raw)
    except ValueError:
        moved = _quarantine(p, "not JSON")
        return dict(empty_document(), quarantined=str(moved),
                    load_error="the registry was not readable JSON")
    if not isinstance(doc, dict) or not isinstance(doc.get("devices"), list):
        moved = _quarantine(p, "wrong shape")
        return dict(empty_document(), quarantined=str(moved),
                    load_error="the registry did not have the expected shape")

    version = doc.get("schema_version")
    if version is None:
        version = 0
    if not isinstance(version, int) or version > SCHEMA_VERSION:
        # Forward-dated: a newer build wrote it. Quarantining would delete that
        # build's data, so refuse to use it and say so instead.
        return dict(empty_document(), quarantined=None,
                    load_error=(f"the registry was written by a newer version "
                                f"(schema_version {version}); it has been left "
                                f"untouched and is not being used"))
    if version < SCHEMA_VERSION:
        doc = _migrate(doc, version)

    doc["devices"] = [d for d in doc["devices"] if isinstance(d, dict)]
    for d in doc["devices"]:
        d.setdefault("device_id", new_device_id())
        d.setdefault("observed_macs", [])
        d.setdefault("service_mode", {"state": NOT_SET_UP, "host_key_pin_present": False,
                                      "manual_password_status": PW_UNKNOWN})
        d.setdefault("prompt", {"dismissed": False, "snoozed_until": None})
    doc.setdefault("quarantined", None)
    return doc


def _migrate(doc: dict, from_version: int) -> dict:
    """Explicit, one step at a time, and it never discards a field it does not
    recognise -- a future field would otherwise be erased by an older build."""
    if from_version < 1:
        doc["schema"] = SCHEMA
        doc["schema_version"] = 1
        for d in doc.get("devices") or []:
            if isinstance(d, dict):
                d.setdefault("kind", "VRX")
    return doc


@_serialized
def save_document(doc: dict) -> None:
    """Atomic, and refuses to write a secret."""
    out = {"schema": SCHEMA, "schema_version": SCHEMA_VERSION,
           "devices": [d for d in (doc.get("devices") or []) if isinstance(d, dict)]}
    assert_clean(out)
    p = store_path()
    tmp = None
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=p.parent,
                                         prefix=p.name + ".", suffix=".tmp", delete=False) as f:
            tmp = Path(f.name)
            f.write(json.dumps(out, indent=2) + "\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, p)
        tmp = None
    except OSError as exc:
        raise RegistryError("REGISTRY_WRITE_FAILED", "The local receiver registry could not be saved.",
                            {"error_type": type(exc).__name__}) from exc
    finally:
        if tmp is not None:
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass



# --------------------------------------------------------------------------- #
# Matching -- the hierarchy in IDENTITY_RULES, applied
# --------------------------------------------------------------------------- #

def evidence_from_candidate(candidate: dict, identity: dict | None = None,
                            bb_id: str | None = None) -> dict:
    """The identity evidence this backend actually exposes, and nothing invented.

    The container identity comes from `receiver_identity.resolve`, the SAME
    resolver the host-key pin store uses. It is not re-derived here: the two
    stores choosing their own fallbacks is exactly the defect that let a pin be
    looked up under a key it was not stored under.
    """
    ident = identity or candidate.get("identity") or {}
    resolved = rxident.resolve(candidate)
    canonical = (resolved["canonical_id"]
                 if resolved["source"] == rxident.SOURCE_CONTAINER_ID else "")
    return {
        "usb_container_id": norm_container_id(canonical),
        "canonical_id": resolved["canonical_id"] or "",
        "identity_source": resolved["source"],
        "identity_confidence": resolved["confidence"],
        "identity_conflict": resolved["conflict_reason"],
        "command_60_identity": norm_text(ident.get("device_name")
                                         or candidate.get("device_name")),
        "serial_number": norm_text(ident.get("serial_number")),
        "firmware": norm_text(ident.get("firmware")),
        "product": norm_text(candidate.get("device_product")),
        "bb_id": norm_text(bb_id),
    }


#: Fields that identify WHICH UNIT a record is about. A change in one of these
#: is a different receiver, never the same receiver having changed. Contrast
#: `firmware` and `product`, which are mutable facts about one unit.
IDENTITY_FIELDS = ("command_60_identity", "serial_number")


def _identity_contradicts(record: dict, evidence: dict) -> bool:
    """Does the live device disagree with what this record says it is?

    Only a positive disagreement counts. An empty value on either side is "not
    known yet", not a conflict -- a probe that never read the serial must not
    invalidate a record, which is the same reasoning that stops `upsert` erasing
    a known value with an empty one.
    """
    for field in IDENTITY_FIELDS:
        seen = norm_text(evidence.get(field))
        known = norm_text(record.get(field))
        if seen and known and seen != known:
            return True
    return False


def match(doc: dict, evidence: dict) -> tuple[dict | None, str]:
    """Return (record, basis). Fails closed: ambiguity returns no match.

    Order follows IDENTITY_RULES. A MAC is never consulted here -- it cannot
    select a record, only annotate one that was already selected.
    """
    devices = doc.get("devices") or []
    conflicted = False
    cid = evidence.get("usb_container_id") or ""
    if cid:
        hits = [d for d in devices if norm_container_id(d.get("usb_container_id")) == cid]
        if len(hits) == 1:
            # A ContainerId is NOT a unit identity on this hardware, and treating
            # it as one is how this store came to describe the wrong receiver.
            #
            # These receivers expose no USB serial -- the instance id ends in a
            # topology path like `7&2AB797F4&0&0002` -- so Windows derives the
            # ContainerId from the hub and port. Move a different receiver into
            # the same port and it inherits the same ContainerId. Measured: this
            # store held `Ascent_VRX_max_WF`, serial 0128, firmware 19.2.14 at a
            # ContainerId whose device answered command 60 as `Ascent_VRX_max_HF`,
            # serial 1128, firmware 18.21.7 -- and it recorded that as
            # `identity_confidence: high`.
            #
            # So the match is confirmed against the identity the DEVICE gives,
            # which this project already holds authoritative. A contradiction is
            # a different physical unit at the same topology position, and that
            # fails closed rather than selecting a record about another receiver.
            if not _identity_contradicts(hits[0], evidence):
                return hits[0], "usb_container_id"
            # A different unit is in this port. Fall through to identity, which
            # is the authoritative thing -- the SAME receiver swapped back must
            # be recognised rather than accumulating a new record per swap.
            # (Caught by a test, not by review: four swaps produced five records.)
            conflicted = True
        elif len(hits) > 1:
            return None, "ambiguous_usb_container_id"
        else:
            # A KNOWN container identity that matches nothing means a receiver
            # this PC has not seen -- full stop. Falling through to the composite
            # here would merge two different units of the same model whose
            # serials are batch-shaped and identical, which is exactly what the
            # composite is not allowed to decide. Caught by a test, not by review.
            #
            # The CONFLICT case above is different and does fall through: there,
            # the locator is known to belong to someone else, so the live
            # identity is the only evidence left and it is the stronger one.
            return None, "no_match"

    name = evidence.get("command_60_identity") or ""
    serial = evidence.get("serial_number") or ""
    if name and serial:
        # COMPOSITE only. Observed serials are short and look batch-scoped, so the
        # serial alone is not treated as unique -- and even this pair is accepted
        # only when it selects exactly one record.
        hits = [d for d in devices
                if norm_text(d.get("command_60_identity")) == name
                and norm_text(d.get("serial_number")) == serial]
        if len(hits) == 1:
            return hits[0], "command_60_identity+serial_number"
        if len(hits) > 1:
            return None, "ambiguous_identity_serial"

    bb = evidence.get("bb_id") or ""
    if bb:
        hits = [d for d in devices if norm_text(d.get("bb_id")) == bb]
        if len(hits) == 1:
            return hits[0], "bb_id"
        if len(hits) > 1:
            return None, "ambiguous_bb_id"

    return None, ("container_id_identity_conflict" if conflicted else "no_match")


# --------------------------------------------------------------------------- #
# Observing a receiver
# --------------------------------------------------------------------------- #

def observe_mac(record: dict, interface: str, address: str) -> bool:
    """Record a MAC as an OBSERVATION on an already-matched record.

    A receiver legitimately has several -- eth0, usb0, wlan0 -- and they change.
    A new one must never create a second record or look like a new device, which
    is why this only ever runs after `match()` has already decided.
    """
    mac = norm_mac(address)
    if not mac:
        return False
    now = utc_now()
    for row in record.setdefault("observed_macs", []):
        if norm_mac(row.get("address")) == mac and norm_text(row.get("interface")) == norm_text(interface):
            row["last_seen"] = now
            return False
    record["observed_macs"].append({"interface": norm_text(interface, 32),
                                    "address": mac,
                                    "first_seen": now, "last_seen": now})
    return True


def conflict(record: dict, evidence: dict, host_key_fingerprint: str | None) -> str | None:
    """Identity evidence that disagrees with what is on file.

    Fails closed: the caller must NOT merge, must NOT create a second record,
    and must route to the existing host-key-change workflow. A known USB
    identity presenting a different host key is the case this exists for.
    """
    pinned = norm_text(record.get("host_key_fingerprint"))
    if pinned and host_key_fingerprint and pinned != norm_text(host_key_fingerprint):
        return "HOST_KEY_CHANGED"
    known_serial = norm_text(record.get("serial_number"))
    seen_serial = norm_text(evidence.get("serial_number"))
    if known_serial and seen_serial and known_serial != seen_serial:
        return "SERIAL_CHANGED"
    known_name = norm_text(record.get("command_60_identity"))
    seen_name = norm_text(evidence.get("command_60_identity"))
    if known_name and seen_name and known_name != seen_name:
        return "IDENTITY_CHANGED"
    return None


def _release_locator(doc: dict, cid: str, keep, now: str) -> None:
    """A locator describes WHERE a unit is, so exactly one record may hold it.

    Called when a container id has changed hands. Without it the arriving record
    and the departing one both carry the id, every later observation reads as
    `ambiguous_usb_container_id`, and a new record is created on every connect
    -- measured as four swaps producing five records before this existed.

    Only the locator is cleared. The departing record keeps its identity, its
    history and its Service Mode state, because that receiver still exists; it
    is simply no longer in this port.
    """
    if not cid:
        return
    for d in doc.get("devices") or []:
        if d is keep:
            continue
        if norm_container_id(d.get("usb_container_id")) == cid:
            d["usb_container_id"] = ""
            d["canonical_id"] = ""
            d["identity_source"] = ""
            d["identity_confidence"] = ""
            d["locator_released_at"] = now


def upsert(doc: dict, evidence: dict, *, kind: str = "VRX",
           nickname_bb_id: str | None = None) -> tuple[dict, bool]:
    """Find or create a record. Returns (record, created)."""
    record, basis = match(doc, evidence)
    now = utc_now()
    if basis == "container_id_identity_conflict" or (
            record is not None and basis == "command_60_identity+serial_number"):
        _release_locator(doc, evidence.get("usb_container_id") or "", record, now)
    if record is not None:
        record["last_seen"] = now
        record["match_basis"] = basis
        # Fill in evidence learned later, but never overwrite a known value with
        # an empty one -- a probe that did not read the serial must not erase it.
        for k in ("identity_source", "identity_confidence", "canonical_id"):
            if evidence.get(k):
                record[k] = evidence[k]
        for k in ("command_60_identity", "serial_number", "bb_id"):
            v = evidence.get(k)
            if v and not record.get(k):
                record[k] = v
        # The locator follows the receiver. A unit matched by its own identity
        # after being moved back into a port must RE-TAKE that port's container
        # id, not keep the empty one it was left with when it was displaced.
        cid = evidence.get("usb_container_id") or ""
        if cid:
            record["usb_container_id"] = cid
        # Mutable facts about ONE unit, refreshed rather than only filled.
        #
        # Identity is settled by now: match() refuses a container hit whose
        # command-60 identity contradicts the record, so reaching here means this
        # IS the same receiver. Firmware and product can legitimately change on
        # the same receiver -- it gets flashed -- and the fill-only rule meant a
        # record kept the firmware it was first seen with forever. That matters
        # because firmware is what the Service Mode gates are evaluated against,
        # so a stale value silently answers a question about the wrong release.
        for k in ("firmware", "product"):
            v = evidence.get(k)
            if v and v != record.get(k):
                # A FIRMWARE CHANGE IS THE MOST CONSEQUENTIAL THING THAT CAN
                # HAPPEN TO A RECEIVER AND NOTHING RECORDED IT.
                #
                # An update replaces the root filesystem: the enrolled SSH
                # key, the receiver's host key and everything under
                # /opt/ascent go with it. On 2026-10-10 that happened, every
                # form of access stopped at once, and the application could
                # say only "the device refused this computer's key" -- an hour
                # went into hunting a key fault that did not exist. The one
                # fact that would have answered it in a sentence, "this unit's
                # firmware changed since it last connected", was overwritten
                # in place and never kept.
                #
                # So the previous value is kept with the time it changed. This
                # is also the "last updated date" asked for from the bench.
                if k == "firmware" and record.get(k):
                    record.setdefault("firmware_history", []).append({
                        "firmware": record[k],
                        "replaced_at": now,
                        "first_seen": record.get("firmware_since")
                                      or record.get("first_seen"),
                    })
                    # Bounded. A unit flashed repeatedly must not grow the
                    # store without limit; the newest entries are the ones
                    # anybody reads.
                    record["firmware_history"] = record["firmware_history"][-20:]
                    record["firmware_changed_at"] = now
                if k == "firmware":
                    record["firmware_since"] = now
                record[k] = v
        if nickname_bb_id and not record.get("nickname_bb_id"):
            record["nickname_bb_id"] = nickname_bb_id
        return record, False

    record = {
        "device_id": new_device_id(), "kind": kind,
        "product": evidence.get("product") or "",
        "command_60_identity": evidence.get("command_60_identity") or "",
        "serial_number": evidence.get("serial_number") or "",
        "firmware": evidence.get("firmware") or "",
        "usb_container_id": evidence.get("usb_container_id") or "",
        "canonical_id": evidence.get("canonical_id") or "",
        "identity_source": evidence.get("identity_source") or "",
        "identity_confidence": evidence.get("identity_confidence") or "",
        "bb_id": evidence.get("bb_id") or "",
        # When the firmware now recorded was first seen, and what came before
        # it. A record created now has no previous firmware, so the history is
        # empty and `firmware_changed_at` is null -- which is different from
        # "it has never been updated" and is not claimed to mean that.
        "firmware_since": now,
        "firmware_changed_at": None,
        "firmware_history": [],
        # A REFERENCE into the frozen nickname store, never a copy of the text.
        # Copying it would create two sources that can disagree.
        "nickname_bb_id": nickname_bb_id or None,
        "observed_macs": [],
        "first_seen": now, "last_seen": now,
        "match_basis": "created",
        "host_key_fingerprint": None,
        "service_mode": {"state": NOT_SET_UP, "host_key_pin_present": False,
                         "manual_password_status": PW_UNKNOWN,
                         "last_connected": None, "enrolled_at": None},
        "prompt": {"dismissed": False, "snoozed_until": None},
    }
    doc.setdefault("devices", []).append(record)
    return record, True


# --------------------------------------------------------------------------- #
# Prompt policy
# --------------------------------------------------------------------------- #

def prompt_due(record: dict, *, created: bool, supported: bool,
               exclusive_operation: bool, conflict_code: str | None,
               now: float | None = None) -> tuple[bool, str]:
    """Whether to show NEW VRX DETECTED. Returns (show, why_not).

    Every negative is named, because "the prompt did not appear" is otherwise
    indistinguishable from a bug.
    """
    if conflict_code:
        # A changed host key is NOT a new device, and must never take the
        # new-device path -- that path would offer to enroll an unknown unit
        # under a known one's record.
        return False, f"identity conflict: {conflict_code}"
    if not supported:
        return False, "not a supported VRX"
    if exclusive_operation:
        return False, "an exclusive operation is in progress"
    sm = record.get("service_mode") or {}
    if sm.get("state") == ENROLLED:
        return False, "already enrolled"
    p = record.get("prompt") or {}
    if p.get("dismissed"):
        return False, "dismissed for this receiver"
    snoozed = p.get("snoozed_until")
    if snoozed:
        t = now if now is not None else time.time()
        if t < float(snoozed):
            return False, "snoozed"
    if not created and not p.get("ever_shown"):
        return True, ""
    if created:
        return True, ""
    return False, "already prompted for this receiver"


def mark_prompted(record: dict) -> None:
    record.setdefault("prompt", {})["ever_shown"] = True
    record["prompt"]["last_shown"] = utc_now()


def snooze(record: dict, seconds: int = DEFAULT_SNOOZE_SECONDS) -> None:
    """NOT NOW. Persisted, so a reconnect does not re-ask immediately."""
    record.setdefault("prompt", {})["snoozed_until"] = time.time() + max(60, int(seconds))
    record["prompt"]["dismissed"] = False


def dismiss(record: dict) -> None:
    """DON'T ASK FOR THIS VRX. Permanent, per receiver, and reversible."""
    record.setdefault("prompt", {})["dismissed"] = True
    record["prompt"]["snoozed_until"] = None


def undismiss(record: dict) -> None:
    """Reversible from Settings or the receiver's Service Mode panel."""
    record.setdefault("prompt", {})["dismissed"] = False
    record["prompt"]["snoozed_until"] = None


# --------------------------------------------------------------------------- #
# Enrollment state
# --------------------------------------------------------------------------- #

def record_enrolled(record: dict, *, host_key_fingerprint: str | None,
                    verified: bool) -> None:
    """Mark a receiver enrolled -- ONLY after verification.

    `verified` is the reconnect-with-the-managed-key result. A partially failed
    setup must never be recorded as ready, so an unverified call is refused
    rather than quietly downgraded: a caller that got this wrong would otherwise
    produce a record claiming working access that nobody has tested.
    """
    if not verified:
        raise RegistryError("ENROLLMENT_UNVERIFIED",
                            "enrollment is recorded only after a verified reconnect")
    sm = record.setdefault("service_mode", {})
    sm["state"] = ENROLLED
    sm["enrolled_at"] = utc_now()
    sm["last_connected"] = utc_now()
    sm["host_key_pin_present"] = bool(host_key_fingerprint)
    if host_key_fingerprint:
        record["host_key_fingerprint"] = norm_text(host_key_fingerprint, 200)


def record_key_refused(record: dict) -> None:
    """The receiver answered and REFUSED the managed key. Withdraw ENROLLED.

    THIS IS THE ONE THAT STRANDED A RECEIVER. `record_enrolled` is written on
    a verified reconnect and nothing ever wrote the opposite, so the record
    said ENROLLED for ever -- including after a firmware update replaced the
    root filesystem and took authorized_keys with it.

    Everything downstream then believed it. installed.state read YES, so the
    page said "Accepted by this receiver: yes", so ACTIVATE concluded the unit
    already trusted this computer and ran a plain activation with NO
    passphrase, so first access never ran, so nothing could be installed, so
    the verify failed -- and the failure was reported as "it did not answer"
    about a receiver that was answering immediately and saying no.

    Measured on the bench 2026-10-11: dropbear 2022.82 up, offering
    publickey, "Permission denied (publickey,password)", while the panel said
    the key was accepted. Clearing this one field by hand was all it took;
    ACTIVATE then asked for the passphrase and authenticated.

    NOT REVOKED. Revoked means somebody deliberately removed our access and is
    a different history. This is "the key we hold is not accepted any more",
    which puts the receiver back where it was before enrolment.
    """
    sm = record.setdefault("service_mode", {})
    if sm.get("state") != ENROLLED:
        return
    sm["state"] = NOT_SET_UP
    sm["key_refused_at"] = utc_now()
    # The pin is a separate fact and is NOT cleared here: the host key can be
    # unchanged while authorized_keys is gone, which is exactly what a firmware
    # update did on this bench. Clearing it would throw away a good pin.
    sm["host_key_pin_present"] = bool(record.get("host_key_fingerprint"))


def record_revoked(record: dict) -> None:
    sm = record.setdefault("service_mode", {})
    sm["state"] = REVOKED
    sm["revoked_at"] = utc_now()
    sm["last_connected"] = sm.get("last_connected")


def record_connected(record: dict) -> None:
    record.setdefault("service_mode", {})["last_connected"] = utc_now()


def set_password_status(record: dict, status: str) -> None:
    """What the operator reported, never the password.

    USER REPORTED means only that: the operator said they set one. Nothing here
    holds it, verifies it, or can use it.
    """
    if status not in PASSWORD_STATES:
        raise RegistryError("UNKNOWN_PASSWORD_STATE",
                            f"status must be one of {PASSWORD_STATES}")
    record.setdefault("service_mode", {})["manual_password_status"] = status
