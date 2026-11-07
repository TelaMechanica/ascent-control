"""Host-local application settings, persisted outside the device path.

Two roots exist and they are deliberately different things:

  * ``config_root()`` -- fixed, never configurable. Holds this settings file and the
    local VTX nickname store. It cannot be relocated, because a setting that says
    where things live must itself live somewhere findable.
  * ``save_root()`` -- the operator-configurable directory used for local *saves*:
    RF/receiver-slot backups and probe exports. Defaults to
    ``config_root()``, which is exactly the pre-existing behaviour.

Nothing here touches a device, and no value here ever reaches a vendor payload. A
directory is accepted only after it has been proven writable by an actual create /
write / delete round trip on the real filesystem -- never by inspecting permission
bits, which do not predict Windows ACL or redirected-folder outcomes.
"""
from __future__ import annotations

import json
import os
import tempfile
import threading
import time
from pathlib import Path

SCHEMA = "ascent.local_settings.v1"
SETTINGS_FILENAME = "settings.json"
# A path long enough to break Win32 APIs is rejected up front rather than failing
# later inside an unrelated write.
MAX_PATH_CHARS = 240

_LOCK = threading.RLock()
_ROOT = Path(__file__).resolve().parent


class LocalSettingsError(ValueError):
    """A rejected settings change. ``code`` is stable and UI-facing."""

    def __init__(self, code: str, message: str, *, evidence: dict | None = None):
        super().__init__(message)
        self.code = code
        self.evidence = evidence or {}


def _utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def config_root() -> Path:
    """Fixed application-data root. Not configurable, by design."""
    base = os.environ.get("LOCALAPPDATA") or str(_ROOT / "localdata")
    return Path(base) / "Ascent Control"


def settings_path() -> Path:
    return config_root() / SETTINGS_FILENAME


def load() -> dict:
    """Read the settings document. A missing or unreadable file is not an error."""
    p = settings_path()
    with _LOCK:
        try:
            doc = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {"schema": SCHEMA}
    if not isinstance(doc, dict) or doc.get("schema") != SCHEMA:
        # An unknown schema is treated as absent rather than guessed at.
        return {"schema": SCHEMA}
    return doc


def _write(doc: dict) -> None:
    p = settings_path()
    with _LOCK:
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(doc, indent=2, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, p)


def configured_save_directory() -> str | None:
    """The stored override, exactly as recorded, or None if never set."""
    value = load().get("save_directory")
    return value if isinstance(value, str) and value.strip() else None


def save_root() -> Path:
    """The directory local saves go to right now.

    The stored override is returned as recorded even if it has since been deleted or
    become unwritable. Falling back to the default silently would send a backup
    somewhere the operator did not choose and then report success.
    """
    configured = configured_save_directory()
    return Path(configured) if configured else config_root()


def _normalize(raw: object) -> Path:
    if not isinstance(raw, str):
        raise LocalSettingsError("SAVE_DIR_REQUIRED", "A directory path is required.")
    text = raw.strip().strip('"')
    if not text:
        raise LocalSettingsError("SAVE_DIR_REQUIRED", "A directory path is required.")
    if len(text) > MAX_PATH_CHARS:
        raise LocalSettingsError("SAVE_DIR_TOO_LONG",
                                 f"Path is longer than {MAX_PATH_CHARS} characters.")
    if "\x00" in text:
        raise LocalSettingsError("SAVE_DIR_INVALID", "Path contains a NUL character.")
    candidate = Path(os.path.expandvars(os.path.expanduser(text)))
    if not candidate.is_absolute():
        raise LocalSettingsError("SAVE_DIR_NOT_ABSOLUTE",
                                 "The save directory must be an absolute path.")
    return candidate


def probe_writable(directory: Path) -> dict:
    """Prove writability by creating, writing and removing a real file.

    Returns ``{"writable": bool, ...}``. The probe file is always removed; a failure to
    remove it is itself reported rather than swallowed.
    """
    try:
        with tempfile.NamedTemporaryFile(dir=str(directory), prefix=".ascent_write_probe_",
                                         suffix=".tmp", delete=False) as fh:
            probe = Path(fh.name)
            fh.write(b"ascent-control write probe")
            fh.flush()
            os.fsync(fh.fileno())
    except OSError as e:
        return {"writable": False, "error": f"{type(e).__name__}: {e.strerror or e}"}
    try:
        probe.unlink()
    except OSError as e:
        return {"writable": False, "error": f"probe file could not be removed: {e.strerror or e}"}
    return {"writable": True}


def validate_save_directory(raw: object) -> dict:
    """Validate a candidate save directory without persisting it.

    Creates the directory if it does not exist -- a directory that cannot be created
    cannot be proven writable, and the operator asked for it by name.
    """
    candidate = _normalize(raw)
    if candidate.exists() and not candidate.is_dir():
        raise LocalSettingsError("SAVE_DIR_NOT_A_DIRECTORY",
                                 "That path exists and is not a directory.",
                                 evidence={"path": str(candidate)})
    created = not candidate.exists()
    if created:
        try:
            candidate.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            raise LocalSettingsError("SAVE_DIR_NOT_CREATABLE",
                                     f"The directory could not be created: {e.strerror or e}",
                                     evidence={"path": str(candidate)}) from e
    probe = probe_writable(candidate)
    if not probe.get("writable"):
        raise LocalSettingsError("SAVE_DIR_NOT_WRITABLE",
                                 f"The directory is not writable: {probe.get('error')}",
                                 evidence={"path": str(candidate), "probe": probe})
    return {"ok": True, "path": str(candidate), "created": created,
            "write_probe": "create/write/delete round trip succeeded"}


def set_save_directory(raw: object) -> dict:
    """Validate then persist. Nothing is stored unless the write probe passed."""
    result = validate_save_directory(raw)
    doc = load()
    doc.update({"schema": SCHEMA, "save_directory": result["path"],
                "save_directory_updated_at": _utc_now()})
    _write(doc)
    return {**result, "persisted": True, "settings_file": str(settings_path())}


def reset_save_directory() -> dict:
    doc = load()
    doc.pop("save_directory", None)
    doc.pop("save_directory_updated_at", None)
    doc["schema"] = SCHEMA
    _write(doc)
    return {"ok": True, "path": str(config_root()), "is_default": True, "persisted": True,
            "settings_file": str(settings_path())}


AUTO_CONNECT_KEY = "auto_connect"


def auto_connect() -> bool:
    """Whether to connect to the first identified Ascent device on startup.

    Off unless the operator turned it on. A tool that reaches for a serial port
    by itself the moment it launches is a surprise the first time it happens on
    a bench with two units attached, so this is remembered rather than assumed.
    """
    return bool(load().get(AUTO_CONNECT_KEY) is True)


def set_auto_connect(enabled: object) -> dict:
    doc = load()
    doc[AUTO_CONNECT_KEY] = bool(enabled)
    doc["updated_at"] = _utc_now()
    _write(doc)
    return {"ok": True, "auto_connect": bool(enabled)}


REGIONAL_RF_POLICY_KEY = "regional_rf_mode_policy"


def regional_rf_policy() -> str:
    """The operator's expanded-RF-mode policy. Opt-in, and off unless chosen.

    Stored as a string rather than a boolean because there are three answers --
    automatic, ask per receiver, and leave disabled -- and a boolean would force
    "ask" to be encoded somewhere else and then disagree with this.

    An unrecognised stored value reads as DISABLED rather than raising. A
    settings file written by a newer build, or edited by hand, must not be able
    to turn on an opt-in RF behaviour by accident.
    """
    import regional_rf_mode as rrf
    v = load().get(REGIONAL_RF_POLICY_KEY)
    return v if v in rrf.POLICIES else rrf.DEFAULT_POLICY


def set_regional_rf_policy(policy: object) -> dict:
    import regional_rf_mode as rrf
    if policy not in rrf.POLICIES:
        raise LocalSettingsError(
            "REGIONAL_RF_POLICY_INVALID",
            f"policy must be one of {', '.join(rrf.POLICIES)}")
    doc = load()
    doc[REGIONAL_RF_POLICY_KEY] = policy
    doc["updated_at"] = _utc_now()
    _write(doc)
    return {"ok": True, "policy": policy}


# --------------------------------------------------------------------------- #
# Battery warnings — colours the VRX battery voltage in the header.
# --------------------------------------------------------------------------- #
BATTERY_WARNINGS_KEY = "battery_warnings"

#: Per-cell thresholds (mV) by chemistry. dc_adapter carries no thresholds: a
#: bench supply has no low-battery state to warn about.
BATTERY_CHEMISTRIES = {
    "lipo":       {"nominal_mv": 3700, "low_mv": 3500, "crit_mv": 3300},
    "liion":      {"nominal_mv": 3600, "low_mv": 3200, "crit_mv": 3000},
    "dc_adapter": {"nominal_mv": None, "low_mv": None, "crit_mv": None},
}
_BATTERY_DEFAULT = {"chemistry": "lipo", "source": "preset",
                    "cell_count": "auto", "low_mv": 0, "crit_mv": 0}


def _is_int(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _normalize_battery_warnings(raw) -> dict:
    """Coerce any stored/supplied value to a valid config, field by field.

    A document from a newer build or edited by hand can never yield an invalid
    chemistry, source, cell count or threshold -- each bad field falls back to its
    default rather than raising. This is the read-side guard; the setter is stricter.
    """
    d = dict(_BATTERY_DEFAULT)
    if isinstance(raw, dict):
        if raw.get("chemistry") in BATTERY_CHEMISTRIES:
            d["chemistry"] = raw["chemistry"]
        if raw.get("source") in ("preset", "exact"):
            d["source"] = raw["source"]
        cc = raw.get("cell_count")
        if cc == "auto" or (_is_int(cc) and 1 <= cc <= 6):
            d["cell_count"] = cc
        for k in ("low_mv", "crit_mv"):
            v = raw.get(k)
            if _is_int(v) and 0 <= v <= 60000:
                d[k] = v
    return d


def battery_warnings() -> dict:
    """Operator battery-warning config. Unknown/missing reads as safe defaults."""
    return _normalize_battery_warnings(load().get(BATTERY_WARNINGS_KEY))


def set_battery_warnings(body: object) -> dict:
    if not isinstance(body, dict):
        raise LocalSettingsError("BATTERY_WARNINGS_INVALID",
                                 "battery warnings must be an object")
    if body.get("chemistry") is not None and body["chemistry"] not in BATTERY_CHEMISTRIES:
        raise LocalSettingsError("BATTERY_CHEMISTRY_INVALID",
                                 f"chemistry must be one of {', '.join(BATTERY_CHEMISTRIES)}")
    if body.get("source") is not None and body["source"] not in ("preset", "exact"):
        raise LocalSettingsError("BATTERY_SOURCE_INVALID",
                                 "source must be 'preset' or 'exact'")
    cc = body.get("cell_count")
    if cc is not None and cc != "auto" and not (_is_int(cc) and 1 <= cc <= 6):
        raise LocalSettingsError("BATTERY_CELL_COUNT_INVALID",
                                 "cell_count must be 'auto' or 1..6")
    merged = {**battery_warnings(), **{k: v for k, v in body.items() if v is not None}}
    if merged.get("source") == "exact":
        lo, cr = merged.get("low_mv"), merged.get("crit_mv")
        for name, v in (("low_mv", lo), ("crit_mv", cr)):
            if not (_is_int(v) and 0 < v <= 60000):
                raise LocalSettingsError("BATTERY_THRESHOLD_INVALID",
                                         f"{name} must be a millivolt value for exact mode")
        if cr >= lo:
            raise LocalSettingsError("BATTERY_THRESHOLD_ORDER",
                                     "critical must be below low")
    norm = _normalize_battery_warnings(merged)
    doc = load()
    doc[BATTERY_WARNINGS_KEY] = norm
    doc["updated_at"] = _utc_now()
    _write(doc)
    return {"ok": True, "battery_warnings": norm}


def auto_cell_count(battery_mv, per_cell_min=3000, per_cell_max=4300, nominal=3700):
    """Best cell count 1..6 whose per-cell voltage is plausible, else None.

    Picks the count landing per-cell closest to nominal within [min,max]. None when
    nothing fits -- then the caller shows no per-cell figure rather than a guess.
    """
    if not _is_int(battery_mv) or battery_mv <= 0:
        return None
    best, best_err = None, None
    for c in range(1, 7):
        pc = battery_mv / c
        if per_cell_min <= pc <= per_cell_max:
            err = abs(pc - nominal)
            if best_err is None or err < best_err:
                best, best_err = c, err
    return best


def effective_battery_thresholds(warnings: dict, battery_mv=None) -> dict:
    """Absolute low/crit mV for header colouring, or None when warnings are off.

    preset -> per-cell x cell_count (auto-derived from battery_mv when 'auto');
    exact -> the typed absolutes; dc_adapter -> no thresholds.
    """
    w = _normalize_battery_warnings(warnings)
    if w["chemistry"] == "dc_adapter":
        return {"low_mv": None, "crit_mv": None, "cell_count": None}
    cc = w["cell_count"]
    if cc == "auto":
        cc = auto_cell_count(battery_mv) if battery_mv else None
    if w["source"] == "exact":
        return {"low_mv": w["low_mv"] or None, "crit_mv": w["crit_mv"] or None,
                "cell_count": cc}
    per = BATTERY_CHEMISTRIES[w["chemistry"]]
    if not cc:
        return {"low_mv": None, "crit_mv": None, "cell_count": None}
    return {"low_mv": per["low_mv"] * cc, "crit_mv": per["crit_mv"] * cc,
            "cell_count": cc}


# --------------------------------------------------------------------------- #
# KNOWN-IP DEVICE REGISTRY — the network-aware features surface.
#
# Operator-asserted IPs, deliberately SEPARATE from the USB device-session. A USB
# connect is ContainerId-correlated ("which physical unit"); a known IP is not --
# the operator is telling the application which unit sits at an address. That trade
# is explicit and lives only on this surface; nothing here touches the USB path.
# --------------------------------------------------------------------------- #
KNOWN_DEVICES_KEY = "known_devices"


def _valid_ipv4(s: object) -> bool:
    import ipaddress
    try:
        ipaddress.IPv4Address(str(s))
        return True
    except Exception:
        return False


def _seed_known_devices() -> list:
    """Defaults, mirrored from caddx_cgc.PROFILES (rj45 + usbc) so the two known
    profiles exist before anyone configures anything. Lazy import, with a hardcoded
    fallback so a registry read never depends on importing the protocol module."""
    try:
        import caddx_cgc
        seed = []
        for pid, prof in caddx_cgc.PROFILES.items():
            ip = prof.get("device_ip")
            if _valid_ipv4(ip):
                seed.append({"id": pid, "label": prof.get("display_name") or pid,
                             "device_ip": ip, "kind": "vrx"})
        if seed:
            return seed
    except Exception:
        pass
    return [{"id": "rj45", "label": "RJ45", "device_ip": "192.168.1.100", "kind": "vrx"},
            {"id": "usbc", "label": "USB-C", "device_ip": "192.168.3.102", "kind": "vrx"}]


def _normalize_known_device(raw: object) -> dict | None:
    """One registry entry, coerced; None if it has no valid IPv4."""
    if not isinstance(raw, dict):
        return None
    ip = str(raw.get("device_ip") or "").strip()
    if not _valid_ipv4(ip):
        return None
    kind = raw.get("kind") if raw.get("kind") in ("vrx", "relay") else "vrx"
    did = (str(raw.get("id") or "").strip() or ip)
    label = (str(raw.get("label") or "").strip() or did)[:64]
    return {"id": did, "label": label, "device_ip": ip, "kind": kind}


def known_devices() -> list:
    """The known-IP registry. Absent -> seeded defaults; set-to-empty stays empty.

    The absent/empty distinction matters: an operator who removes every device must
    not have the defaults silently reappear, but a fresh install should ship the two
    known profiles.
    """
    stored = load().get(KNOWN_DEVICES_KEY)
    if stored is None:
        return _seed_known_devices()
    if not isinstance(stored, list):
        return _seed_known_devices()
    out, seen = [], set()
    for r in stored:
        n = _normalize_known_device(r)
        if n and n["id"] not in seen:
            seen.add(n["id"])
            out.append(n)
    return out


def set_known_devices(body: object) -> dict:
    """Replace the whole registry with a validated list. Stricter than the reader."""
    if not isinstance(body, dict) or not isinstance(body.get("devices"), list):
        raise LocalSettingsError("KNOWN_DEVICES_INVALID",
                                 "the request must carry a 'devices' list")
    out, seen = [], set()
    for r in body["devices"]:
        n = _normalize_known_device(r)
        if n is None:
            raise LocalSettingsError("KNOWN_DEVICE_INVALID",
                                     "each device needs a valid IPv4 device_ip",
                                     evidence={"entry": r if isinstance(r, dict) else str(r)})
        if n["id"] in seen:
            raise LocalSettingsError("KNOWN_DEVICE_DUPLICATE",
                                     f"duplicate device id {n['id']!r}")
        seen.add(n["id"])
        out.append(n)
    doc = load()
    doc[KNOWN_DEVICES_KEY] = out
    doc["updated_at"] = _utc_now()
    _write(doc)
    return {"ok": True, "devices": out}


def known_devices_document() -> dict:
    """UI-facing registry state, with the operator-asserted-IP caveat stated."""
    return {
        "ok": True,
        "devices": known_devices(),
        "correlation": "operator_asserted_ip",
        "note": ("These are operator-asserted IPs. Unlike a USB connect, they are "
                 "NOT ContainerId-correlated -- you are telling the application which "
                 "unit is at this address, so point them only at a unit you know."),
    }


def save_directory_document() -> dict:
    """UI-facing state of this one setting, including live writability."""
    configured = configured_save_directory()
    active = save_root()
    doc = load()
    exists = active.is_dir()
    writable = probe_writable(active) if exists else {"writable": False,
                                                      "error": "directory does not exist yet"}
    return {
        "available": True,
        "setting": "local_save_directory",
        "path": str(active),
        "default_path": str(config_root()),
        "is_default": configured is None,
        "configured_path": configured,
        "updated_at": doc.get("save_directory_updated_at"),
        "exists": exists,
        "writable": bool(writable.get("writable")),
        "writable_detail": writable.get("error"),
        "settings_file": str(settings_path()),
        "note": ("Applies to local saves only: RF and receiver-slot backups and "
                 "exports. Application settings and device nicknames always "
                 "stay in the fixed application-data directory."),
    }


def selftest() -> None:
    """Import-safe checks. No device, no subprocess, no Windows."""
    import tempfile as _tf

    assert config_root().is_absolute()
    assert settings_path().name == SETTINGS_FILENAME
    assert settings_path().parent == config_root()

    for bad, code in ((None, "SAVE_DIR_REQUIRED"), ("", "SAVE_DIR_REQUIRED"),
                      ("   ", "SAVE_DIR_REQUIRED"), (17, "SAVE_DIR_REQUIRED"),
                      ("relative/path", "SAVE_DIR_NOT_ABSOLUTE"),
                      ("/x" * MAX_PATH_CHARS, "SAVE_DIR_TOO_LONG")):
        try:
            validate_save_directory(bad)
        except LocalSettingsError as e:
            assert e.code == code, (bad, e.code, code)
        else:
            raise AssertionError(f"accepted {bad!r}")

    with _tf.TemporaryDirectory() as td:
        target = Path(td) / "nested" / "saves"
        out = validate_save_directory(str(target))
        assert out["created"] is True and Path(out["path"]) == target
        assert not any(target.iterdir()), "write probe left a file behind"
        again = validate_save_directory(str(target))
        assert again["created"] is False

        f = Path(td) / "afile"
        f.write_text("x", encoding="utf-8")
        try:
            validate_save_directory(str(f))
        except LocalSettingsError as e:
            assert e.code == "SAVE_DIR_NOT_A_DIRECTORY"
        else:
            raise AssertionError("accepted a file as a directory")


if __name__ == "__main__":
    selftest()
    print("local_settings selftest OK")


# --------------------------------------------------------------------------- #
# WHERE WIDGET PACKAGES COME FROM
#
# WIDGET MANAGER MUST NOT ASK AN OPERATOR TO TYPE A PATH. It used to carry a
# free-text box for "C:\path\to\widget.zip", which asks somebody who does not
# use a command line to know where a file is and to spell it correctly, and
# makes the application's reach over their disk a function of whatever they
# type. A named folder is the whole surface instead: the application looks
# there and nowhere else, and the operator changes it in SETTINGS once.
#
# READ-ONLY, deliberately. A save directory has to be writable because things
# are written to it. This one is only ever scanned, so requiring write access
# would refuse a perfectly good read-only share or a mounted card.
# --------------------------------------------------------------------------- #

WIDGET_LIBRARY_DEFAULT = "widgets"


def configured_widget_library() -> str | None:
    value = load().get("widget_library")
    return str(value) if value else None


def widget_library_root() -> Path:
    """The folder scanned for widget packages.

    Defaults to a `widgets` folder beside everything else this installation
    keeps, so there IS a place to put them before anyone configures anything.
    """
    configured = configured_widget_library()
    if configured:
        return Path(configured)
    return save_root() / WIDGET_LIBRARY_DEFAULT


def ensure_default_widget_library() -> Path | None:
    """Create OUR OWN default folder, and only that one.

    The distinction matters and the first version got it wrong in both
    directions at once. A folder the OPERATOR nominated on some other drive
    must not be created for them: a typo would silently produce an empty
    folder on the wrong disk instead of saying the path is wrong. But the
    DEFAULT lives inside this application's own data directory -- we chose the
    location, we are the only thing that uses it, and reporting "the widget
    folder does not exist yet, create it" about a path the operator never
    picked and cannot be expected to know is telling them to do our filing.

    Returns the path on success, or None when it could not be created -- which
    is reported rather than raised, because a missing widget folder must not
    stop the page that merely wants to list what is in it.
    """
    if configured_widget_library():
        return None
    root = save_root() / WIDGET_LIBRARY_DEFAULT
    try:
        root.mkdir(parents=True, exist_ok=True)
    except OSError:
        return None
    return root


def validate_widget_library(raw: object) -> dict:
    """Validate a candidate widget folder without persisting it.

    Unlike the save directory this is NOT created and NOT write-probed: it is
    only ever read from. A folder that does not exist yet is reported as such
    rather than conjured, because an operator pointing at the wrong drive
    should be told, not have an empty folder made for them there.
    """
    candidate = _normalize(raw)
    if candidate.exists() and not candidate.is_dir():
        raise LocalSettingsError("WIDGET_DIR_NOT_A_DIRECTORY",
                                 "That path exists and is not a directory.",
                                 evidence={"path": str(candidate)})
    exists = candidate.is_dir()
    readable = False
    if exists:
        try:
            next(candidate.iterdir(), None)
            readable = True
        except OSError as e:
            raise LocalSettingsError(
                "WIDGET_DIR_NOT_READABLE",
                f"The folder could not be read: {e.strerror or e}",
                evidence={"path": str(candidate)}) from e
    return {"ok": True, "path": str(candidate), "exists": exists,
            "readable": readable}


def set_widget_library(raw: object) -> dict:
    result = validate_widget_library(raw)
    doc = load()
    doc.update({"schema": SCHEMA, "widget_library": result["path"],
                "widget_library_updated_at": _utc_now()})
    _write(doc)
    return {**result, "persisted": True, "settings_file": str(settings_path())}


def reset_widget_library() -> dict:
    doc = load()
    doc.pop("widget_library", None)
    doc.pop("widget_library_updated_at", None)
    doc["schema"] = SCHEMA
    _write(doc)
    return {"ok": True, "path": str(widget_library_root()), "is_default": True,
            "persisted": True, "settings_file": str(settings_path())}


# Saved operator intent only. The standard-VRX driver/handoff executor remains
# unavailable; a host-local enabled draft never changes receiver boot behavior.
NETRUNNER_HANDOFF_KEY = "netrunner_usb_handoff_draft"






