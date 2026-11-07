"""Local, reusable RF band plans.

A *plan* is a named set of band arrays held on this computer. It is operator
convenience only: a way to keep a frequency layout, carry it between units, and
hand it to the existing persistent-table write instead of retyping 107 numbers.

Three properties are deliberate and load-bearing.

**One validator.** Every band array a plan accepts is checked by
``caddx_vendor_write.validate_band_collection`` -- the same function the write
path's serializer calls. There is no second copy of the vendor editor rules here,
so a plan cannot be stored under rules the writer would reject.

**Plans never transmit.** Nothing in this module opens a port or builds a frame.
Applying a plan means loading its values into the existing editor and running the
existing qualified cmd-121 transaction, whose eligibility gate is untouched. A
plan is not a capability and never widens one.

**Compatibility is proven or it is absent.** ``CAPABILITY_PROFILES`` carries only
what this project has actually measured from its own hardware, keyed on the exact
(RF board code, hardware string) pair -- no prefix, substring or pattern matching.
Hardware that is not in that table returns
``Compatibility limits not established`` and is never guessed in either direction.

Nothing here states or implies that any frequency is legal to transmit. That is
not a property of a JSON file and this module does not model it.
"""

from __future__ import annotations

import csv
import io
import json
import os
import re
import threading
import time
import unicodedata
from pathlib import Path

import local_settings
from caddx_vendor_write import (
    BAND_SINGLE_MAX,
    BAND_TOTAL_MAX,
    FREQ_STEP_KHZ,
    CaddxWriteError,
    is_band_key,
    validate_band_collection,
)

SCHEMA = "ascent.rf_band_plans.v1"
STORE_FILENAME = "ascent_rf_band_plans.json"

# Beside the naming master (ascent_device_nicknames.json) in the same fixed
# application-data root, resolved by the shared helper rather than by a path
# assembled here. Plans are a setting, not a save artefact, so they do not follow
# the configurable save directory -- relocating saves must not lose an operator's
# band layouts.
NAME_MAX_CHARS = 64
NOTE_MAX_CHARS = 280
MAX_PLANS = 200
MAX_STORE_BYTES = 1024 * 1024
CSV_COLUMNS = ("plan", "band", "position", "role", "frequency_khz")
ROLE_CHANNEL = "CHANNEL"
ROLE_DEFAULT = "DEFAULT"

# Band keys are the vendor's own: "band" plus a short alphanumeric suffix. Kept
# narrow so an imported file cannot introduce a key the device table has no slot
# for; the write path refuses unknown top-level keys anyway, but refusing at
# import names the offending row instead of failing much later at commit.
_BAND_KEY_RE = re.compile(r"^band[A-Za-z0-9]{1,8}$")

_LOCK = threading.RLock()


class RfPlanError(RuntimeError):
    """Fail-closed error for a band-plan operation."""

    def __init__(self, code: str, message: str, *, evidence: dict | None = None):
        super().__init__(message)
        self.code = code
        self.evidence = evidence or {}


# --------------------------------------------------------------------------------------
# Hardware capability profiles
#
# Locally proven facts ONLY. The single entry below is read from this project's own
# bench artefact fixtures/vrxmax_cmd115_116_integrity.json -- the MD5-verified
# command-116 document off the VRX Max WF on 2026-09-06 -- and describes the table
# that unit SHIPPED WITH.
#
# What that proves, exactly: the device accepted and persisted these values. What it
# does NOT prove: that any other frequency is accepted, or that any frequency inside
# the extent but absent from the shipped table is accepted. So a value outside the
# observed extent is reported as NOT ESTABLISHED, never as rejected, and never as
# permitted. Widen an entry only from a further measured acceptance on that exact
# hardware.
# --------------------------------------------------------------------------------------

CAPABILITY_PROFILES = {
    (0xA0, "Ascent-VRX-Max-V2.2-10.0"): {
        "label": "Ascent VRX Max WF, RF board 160",
        "evidence": "fixtures/vrxmax_cmd115_116_integrity.json, MD5-verified command-116 read, 2026-09-06",
        "bands": {
            "bandA": {"channels": 29, "min_khz": 4495000, "max_khz": 5440000, "default_khz": 5839000},
            "bandB": {"channels": 14, "min_khz": 5475000, "max_khz": 5985000, "default_khz": 5839000},
            "bandC": {"channels": 35, "min_khz": 6015000, "max_khz": 7320000, "default_khz": 5839000},
            "bandD": {"channels": 29, "min_khz": 3100000, "max_khz": 4160000, "default_khz": 4200000},
        },
    },
}

NO_PROFILE_MESSAGE = "Compatibility limits not established"


def capability_profile(rf_board_code, hardware):
    """The proven profile for an exact hardware pair, or None.

    Exact equality on both keys. No normalization, no prefix or substring match, no
    regex: a hardware string this project has not measured is unknown, and an unknown
    unit must not inherit a neighbour's limits because the two names look alike.
    """
    if not isinstance(rf_board_code, int) or isinstance(rf_board_code, bool):
        return None
    if not isinstance(hardware, str) or not hardware:
        return None
    return CAPABILITY_PROFILES.get((rf_board_code, hardware))


# --------------------------------------------------------------------------------------
# Storage
# --------------------------------------------------------------------------------------

def store_path() -> Path:
    return local_settings.config_root() / STORE_FILENAME


def _utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def canonical_name(value) -> str:
    """Uniqueness key for a plan name.

    NFC then casefold, mirroring the nickname store: two spellings of one accented
    name fold together and case alone cannot create a second plan. The operator's own
    capitalization is what gets stored and shown; this is never a storage key.
    """
    return unicodedata.normalize("NFC", str(value or "")).strip().casefold()


def normalize_name(value) -> str:
    name = unicodedata.normalize("NFC", str(value or "")).strip()
    if not name:
        raise RfPlanError("PLAN_NAME_REQUIRED", "a plan needs a name")
    if len(name) > NAME_MAX_CHARS:
        raise RfPlanError("PLAN_NAME_TOO_LONG", f"plan names are limited to {NAME_MAX_CHARS} characters")
    # Control characters would make the name unrenderable and unsearchable; refuse
    # rather than stripping, so an import never silently stores something else.
    if any(unicodedata.category(ch) == "Cc" for ch in name):
        raise RfPlanError("PLAN_NAME_INVALID", "plan names cannot contain control characters")
    return name


def normalize_note(value) -> str:
    if value is None:
        return ""
    note = unicodedata.normalize("NFC", str(value)).strip()
    if len(note) > NOTE_MAX_CHARS:
        raise RfPlanError("PLAN_NOTE_TOO_LONG", f"plan notes are limited to {NOTE_MAX_CHARS} characters")
    if any(unicodedata.category(ch) == "Cc" and ch not in "\n" for ch in note):
        raise RfPlanError("PLAN_NOTE_INVALID", "plan notes cannot contain control characters")
    return note


def normalize_bands(raw) -> dict:
    """Validated band arrays for a plan, through the writer's own validator.

    Refuses anything the persistent-table write would refuse, and refuses band keys
    outside the vendor's own shape. Never coerces: a float, a numeric string, a bool
    or an out-of-step value is an error naming the band, not a silent repair.
    """
    if not isinstance(raw, dict) or not raw:
        raise RfPlanError("PLAN_BANDS_REQUIRED", "a plan needs at least one band array")
    bands: dict = {}
    for key in raw:
        name = str(key)
        if not _BAND_KEY_RE.match(name) or not is_band_key(name):
            raise RfPlanError("PLAN_BAND_KEY_INVALID", f"{name} is not a vendor band key",
                              evidence={"band": name})
        values = raw[key]
        if not isinstance(values, list):
            raise RfPlanError("PLAN_BAND_NOT_LIST", f"{name} must be a list of kHz integers",
                              evidence={"band": name})
        for item in values:
            if isinstance(item, bool) or not isinstance(item, int):
                raise RfPlanError("PLAN_FREQUENCY_NOT_INTEGER",
                                  f"{name} contains a non-integer frequency",
                                  evidence={"band": name})
        bands[name] = list(values)
    try:
        total = validate_band_collection(bands, stage="plan")
    except CaddxWriteError as e:
        # Re-raised under this module's error type but with the writer's own code and
        # message, so the operator sees the same rule text at plan time and write time.
        raise RfPlanError(e.code, str(e), evidence=dict(e.evidence)) from None
    if total <= 0:
        raise RfPlanError("PLAN_BANDS_REQUIRED", "a plan needs at least one channel")
    return bands


def normalize_compatibility(raw) -> dict:
    """The hardware a plan was captured from.

    Only two fields are kept and both are hardware-shaped product facts: the RF board
    code and the command-60 hardware string. No serial number, no BB ID, no firmware
    hash, no path and no host identity is recorded about the machine or the unit.
    """
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise RfPlanError("PLAN_COMPATIBILITY_INVALID", "compatibility must be an object")
    code = raw.get("rf_board_code")
    hardware = raw.get("hardware")
    out: dict = {}
    if code is not None:
        if isinstance(code, bool) or not isinstance(code, int):
            raise RfPlanError("PLAN_COMPATIBILITY_INVALID", "rf_board_code must be an integer")
        out["rf_board_code"] = code
    if hardware is not None:
        text = str(hardware).strip()
        if len(text) > 64:
            raise RfPlanError("PLAN_COMPATIBILITY_INVALID", "hardware string is implausibly long")
        if text:
            out["hardware"] = text
    return out


def _read_document() -> dict | None:
    path = store_path()
    try:
        if path.stat().st_size > MAX_STORE_BYTES:
            return None
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _entry_from_raw(raw) -> dict | None:
    """One stored row, or None if it is unusable. Bad rows are dropped, never coerced."""
    if not isinstance(raw, dict):
        return None
    try:
        name = normalize_name(raw.get("name"))
        bands = normalize_bands(raw.get("bands"))
        note = normalize_note(raw.get("note"))
        compat = normalize_compatibility(raw.get("compatibility"))
    except RfPlanError:
        return None
    created = raw.get("created_at")
    updated = raw.get("updated_at")
    return {
        "name": name,
        "note": note,
        "bands": bands,
        "compatibility": compat,
        "created_at": created if isinstance(created, str) else _utc_now(),
        "updated_at": updated if isinstance(updated, str) else _utc_now(),
    }


def load_all() -> dict:
    """Every stored plan, keyed by canonical name. Unreadable rows are dropped."""
    with _LOCK:
        doc = _read_document()
    if not isinstance(doc, dict) or doc.get("schema") != SCHEMA:
        return {}
    raw_plans = doc.get("plans")
    if not isinstance(raw_plans, dict):
        return {}
    out: dict = {}
    for value in raw_plans.values():
        entry = _entry_from_raw(value)
        if entry is None:
            continue
        out[canonical_name(entry["name"])] = entry
    return out


def _write_all(plans: dict) -> None:
    doc = {
        "schema": SCHEMA,
        "updated_at": _utc_now(),
        "plans": {key: plans[key] for key in sorted(plans)},
    }
    with _LOCK:
        path = store_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(doc, indent=2, ensure_ascii=False, sort_keys=True), encoding="utf-8")
        os.replace(tmp, path)


def save_plan(*, name, bands, note=None, compatibility=None, replace: bool = False) -> dict:
    """Create or update one plan. A name collision refuses unless `replace` is set."""
    entry_name = normalize_name(name)
    key = canonical_name(entry_name)
    entry = {
        "name": entry_name,
        "note": normalize_note(note),
        "bands": normalize_bands(bands),
        "compatibility": normalize_compatibility(compatibility),
    }
    with _LOCK:
        plans = load_all()
        existing = plans.get(key)
        if existing is not None and not replace:
            raise RfPlanError("PLAN_NAME_IN_USE",
                              f"a plan named {existing['name']!r} already exists",
                              evidence={"existing_name": existing["name"]})
        if existing is None and len(plans) >= MAX_PLANS:
            raise RfPlanError("PLAN_LIMIT_REACHED",
                              f"the local store holds at most {MAX_PLANS} plans")
        entry["created_at"] = existing["created_at"] if existing else _utc_now()
        entry["updated_at"] = _utc_now()
        plans[key] = entry
        _write_all(plans)
    return entry


def delete_plan(name) -> dict:
    key = canonical_name(name)
    with _LOCK:
        plans = load_all()
        entry = plans.pop(key, None)
        if entry is None:
            raise RfPlanError("PLAN_NOT_FOUND", "no plan by that name is stored")
        _write_all(plans)
    return entry


def get_plan(name) -> dict:
    entry = load_all().get(canonical_name(name))
    if entry is None:
        raise RfPlanError("PLAN_NOT_FOUND", "no plan by that name is stored")
    return entry


# --------------------------------------------------------------------------------------
# Compatibility assessment
# --------------------------------------------------------------------------------------

def assess(plan: dict, *, rf_board_code=None, hardware=None, live_bands=None) -> dict:
    """How a plan relates to a target unit. Advisory; it gates nothing.

    The write path's own QUALIFY is what permits or refuses a commit, and this
    function neither feeds nor relaxes it. Its job is to tell the operator, before
    they open the editor, which of three states they are in:

      * ``proven``        - this exact hardware has a measured profile and every value
                            sits inside what that hardware was measured to hold;
      * ``not_established``- values sit outside the measured extent, or the hardware
                            has no profile at all. NOT a refusal and NOT permission.
      * ``incompatible``  - a structural mismatch the write would certainly reject,
                            such as a band the live table has no slot for.
    """
    findings: list[dict] = []
    profile = capability_profile(rf_board_code, hardware)
    bands = plan.get("bands") or {}

    if isinstance(live_bands, dict) and live_bands:
        missing = [k for k in bands if k not in live_bands]
        if missing:
            findings.append({
                "severity": "incompatible",
                "code": "BAND_ABSENT_FROM_DEVICE_TABLE",
                "detail": "the connected unit's table has no slot for " + ", ".join(sorted(missing)),
                "bands": sorted(missing),
            })
        unset = [k for k in live_bands if is_band_key(k) and k not in bands]
        if unset:
            findings.append({
                "severity": "note",
                "code": "DEVICE_BANDS_NOT_IN_PLAN",
                "detail": "the plan does not mention " + ", ".join(sorted(unset)) + "; those bands would be left as they are",
                "bands": sorted(unset),
            })

    if profile is None:
        findings.append({
            "severity": "not_established",
            "code": "NO_CAPABILITY_PROFILE",
            "detail": NO_PROFILE_MESSAGE + " for this hardware. Nothing here says these values are accepted, or that they are not.",
        })
    else:
        for key in sorted(bands):
            limits = profile["bands"].get(key)
            if limits is None:
                findings.append({
                    "severity": "not_established",
                    "code": "BAND_NOT_IN_PROFILE",
                    "detail": f"{key} is not part of the measured profile for this hardware",
                    "bands": [key],
                })
                continue
            channels = bands[key][:-1]
            low, high = min(channels), max(channels)
            if low < limits["min_khz"] or high > limits["max_khz"]:
                findings.append({
                    "severity": "not_established",
                    "code": "OUTSIDE_PROVEN_EXTENT",
                    "detail": (f"{key} spans {low}-{high} kHz; the measured extent on this hardware is "
                               f"{limits['min_khz']}-{limits['max_khz']} kHz. Outside it is unmeasured, "
                               "not known-bad."),
                    "bands": [key],
                })

    severities = {f["severity"] for f in findings}
    if "incompatible" in severities:
        state = "incompatible"
    elif "not_established" in severities:
        state = "not_established"
    else:
        state = "proven"
    return {
        "state": state,
        "profile": profile["label"] if profile else None,
        "profile_evidence": profile["evidence"] if profile else None,
        "findings": findings,
        # Said once, plainly, on every assessment. Frequency legality is a matter of
        # licence and jurisdiction, and this application has no way to determine it.
        "transmission_legality": "not assessed",
    }


# --------------------------------------------------------------------------------------
# CSV interchange
#
# Import treats its input as untrusted. Every refusal names the row. Nothing is
# truncated, rounded, reordered or coerced to make a file load: a file either
# describes a valid plan exactly or it is rejected with the reasons listed.
# --------------------------------------------------------------------------------------

def to_csv(plan: dict) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(CSV_COLUMNS)
    for key in sorted(plan.get("bands") or {}):
        values = plan["bands"][key]
        last = len(values) - 1
        for index, value in enumerate(values):
            role = ROLE_DEFAULT if index == last else ROLE_CHANNEL
            position = last if index == last else index + 1
            writer.writerow([plan.get("name", ""), key, position, role, value])
    return buf.getvalue()


def from_csv(text, *, name=None) -> dict:
    if not isinstance(text, str) or not text.strip():
        raise RfPlanError("CSV_EMPTY", "no CSV content was supplied")
    if len(text) > MAX_STORE_BYTES:
        raise RfPlanError("CSV_TOO_LARGE", "the CSV input is larger than this store accepts")
    reader = csv.reader(io.StringIO(text))
    try:
        header = next(reader)
    except StopIteration:
        raise RfPlanError("CSV_EMPTY", "no CSV content was supplied") from None
    columns = tuple(h.strip().lower() for h in header)
    if columns != CSV_COLUMNS:
        raise RfPlanError("CSV_HEADER_UNEXPECTED",
                          "the header row must be exactly: " + ",".join(CSV_COLUMNS),
                          evidence={"expected": list(CSV_COLUMNS), "found": list(columns)})

    errors: list[dict] = []
    names: set = set()
    channels: dict = {}
    defaults: dict = {}
    seen: set = set()

    for line_no, row in enumerate(reader, start=2):
        if not row or all(not str(c).strip() for c in row):
            continue
        if len(row) != len(CSV_COLUMNS):
            errors.append({"line": line_no, "code": "CSV_ROW_WIDTH",
                           "detail": f"expected {len(CSV_COLUMNS)} columns, found {len(row)}"})
            continue
        plan_name, band, position, role, freq = (str(c).strip() for c in row)
        if plan_name:
            names.add(plan_name)
        if not _BAND_KEY_RE.match(band):
            errors.append({"line": line_no, "code": "CSV_BAND_KEY_INVALID",
                           "detail": f"{band!r} is not a vendor band key"})
            continue
        role_u = role.upper()
        if role_u not in (ROLE_CHANNEL, ROLE_DEFAULT):
            errors.append({"line": line_no, "code": "CSV_ROLE_INVALID",
                           "detail": f"role must be {ROLE_CHANNEL} or {ROLE_DEFAULT}, found {role!r}"})
            continue
        # Integers only, and written as integers. "5475000.0" and " 5475000 " are
        # different assertions about the operator's intent than 5475000, so neither
        # is quietly accepted.
        if not re.fullmatch(r"-?\d+", freq):
            errors.append({"line": line_no, "code": "CSV_FREQUENCY_NOT_INTEGER",
                           "detail": f"frequency {freq!r} is not a plain integer in kHz"})
            continue
        khz = int(freq)
        if role_u == ROLE_DEFAULT:
            if band in defaults:
                errors.append({"line": line_no, "code": "CSV_DEFAULT_DUPLICATED",
                               "detail": f"{band} has more than one {ROLE_DEFAULT} row"})
                continue
            defaults[band] = khz
            continue
        if not re.fullmatch(r"\d+", position):
            errors.append({"line": line_no, "code": "CSV_POSITION_INVALID",
                           "detail": f"position {position!r} is not a positive integer"})
            continue
        slot = int(position)
        if slot < 1:
            errors.append({"line": line_no, "code": "CSV_POSITION_INVALID",
                           "detail": "channel positions start at 1"})
            continue
        if (band, slot) in seen:
            errors.append({"line": line_no, "code": "CSV_POSITION_DUPLICATED",
                           "detail": f"{band} position {slot} appears more than once"})
            continue
        seen.add((band, slot))
        channels.setdefault(band, {})[slot] = khz

    if errors:
        raise RfPlanError("CSV_INVALID", f"the CSV was rejected; {len(errors)} row(s) could not be read",
                          evidence={"errors": errors[:50], "error_count": len(errors)})
    if not channels:
        raise RfPlanError("CSV_NO_CHANNELS", "the CSV contained no channel rows")

    bands: dict = {}
    gaps: list[dict] = []
    for band in sorted(channels):
        slots = channels[band]
        expected = list(range(1, max(slots) + 1))
        missing = [s for s in expected if s not in slots]
        if missing:
            gaps.append({"band": band, "missing_positions": missing})
            continue
        if band not in defaults:
            gaps.append({"band": band, "missing_default": True})
            continue
        bands[band] = [slots[s] for s in expected] + [defaults[band]]
    orphan_defaults = sorted(b for b in defaults if b not in channels)
    for band in orphan_defaults:
        gaps.append({"band": band, "default_without_channels": True})
    if gaps:
        raise RfPlanError("CSV_INCOMPLETE",
                          "the CSV does not describe a complete band set",
                          evidence={"gaps": gaps})

    chosen = name if name is not None else (sorted(names)[0] if len(names) == 1 else None)
    if chosen is None:
        raise RfPlanError("CSV_PLAN_NAME_AMBIGUOUS",
                          "give the import a name, or use a file whose plan column holds one name",
                          evidence={"names": sorted(names)[:10]})
    return {
        "name": normalize_name(chosen),
        "note": "",
        "bands": normalize_bands(bands),
        "compatibility": {},
    }


def limits_document() -> dict:
    """The rules the UI states, taken from the writer rather than restated."""
    return {
        "single_band_max_channels": BAND_SINGLE_MAX,
        "total_max_channels": BAND_TOTAL_MAX,
        "frequency_step_khz": FREQ_STEP_KHZ,
        "csv_columns": list(CSV_COLUMNS),
        "max_plans": MAX_PLANS,
    }


def selftest() -> None:
    assert store_path().parent == local_settings.config_root()
    assert store_path().name == STORE_FILENAME
    assert capability_profile(0xA0, "Ascent-VRX-Max-V2.2-10.0") is not None
    assert capability_profile(0xA0, "Ascent-VRX-Max-V2.2-10") is None
    assert capability_profile(160, "ascent-vrx-max-v2.2-10.0") is None
