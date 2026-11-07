"""Host-local store for the two device configuration documents.

This mirrors the vendor exactly, and the mirroring is the point rather than a
convenience. The PC Tool keeps `mipi_hub.json` and `msp_rc_cfg.json` as *local files*
(`resource\\param\\...`), loads its editors from them, writes them back with
`File.WriteAllText` (`CamHubCtrl.cs:258`, `RCModeCtrl.cs:641`), and only then sends the
file to the device. There is no read opcode for either resource, so the local document
is the only durable representation either tool has -- see
`runtime/caddx_device_config.py` for the evidence.

Consequences that shape this module:

* **The store owns local drafts and acknowledged-upload records, never current
  device state.** Every document therefore carries `last_write`, recording
  whether it has ever been sent, to which BB ID, and when. A document that has been
  edited since its last successful send is reported `dirty`, and the UI must say so
  rather than implying the device is in the shown state.
* **A document is per-unit, not global.** Two aircraft can hold different hub wiring,
  and `CLAUDE.md` "Multi-device correlation" forbids merging state across physical
  units. Documents are keyed by the connected unit's BB ID where one is known, with a
  `default` profile used when it is not and stated as such.
* Seeded from `runtime/vendor_templates/`, which are real vendor documents. Seeding
  copies them; it never presents the template as a device reading.
"""

from __future__ import annotations

import copy
import json
import threading
import time
from pathlib import Path

import local_settings
import caddx_device_config as cfg

STORE_FILENAME = "device_configs.json"
SCHEMA = "device_configs/1"
DEFAULT_PROFILE = "default"

KINDS = {
    "hub": {
        "basename": cfg.HUB_BASENAME,
        "remote_path": cfg.HUB_REMOTE_PATH,
        "template": "mipi_hub.json",
        "validate": cfg.validate_hub_document,
        "operation_id": cfg.HUB_OPERATION_ID,
        "label": "CAMERA HUB",
    },
    "rc": {
        "basename": cfg.RC_BASENAME,
        "remote_path": cfg.RC_REMOTE_PATH,
        "template": "msp_rc_cfg.json",
        "validate": cfg.validate_rc_document,
        "operation_id": cfg.RC_OPERATION_ID,
        "label": "RC / MSP",
    },
}

_LOCK = threading.RLock()
_TEMPLATE_DIR = Path(__file__).resolve().parent / "vendor_templates"


class ConfigStoreError(RuntimeError):
    def __init__(self, code: str, message: str, evidence=None):
        super().__init__(message)
        self.code = code
        self.evidence = evidence or {}


def store_path() -> Path:
    # Same reasoning as the nickname store: a configuration document is a setting, not
    # a save artefact, so relocating the save directory must not orphan it.
    return local_settings.config_root() / STORE_FILENAME


def template_document(kind: str) -> dict:
    meta = KINDS[kind]
    raw = (_TEMPLATE_DIR / meta["template"]).read_text(encoding="utf-8")
    return json.loads(raw)


def _empty() -> dict:
    return {"schema": SCHEMA, "profiles": {}}


def _load_raw() -> dict:
    try:
        doc = json.loads(store_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return _empty()
    if not isinstance(doc, dict) or doc.get("schema") != SCHEMA:
        return _empty()
    if not isinstance(doc.get("profiles"), dict):
        return _empty()
    return doc


def _save_raw(doc: dict) -> None:
    path = store_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(doc, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(path)


def profile_key(bb_id: str | None) -> str:
    """Key a document to a physical unit when we can name one."""
    if not bb_id:
        return DEFAULT_PROFILE
    key = str(bb_id).strip().upper().replace("-", ":")
    return key or DEFAULT_PROFILE


def get(kind: str, bb_id: str | None = None) -> dict:
    """The stored document for this unit, seeded from the vendor template if absent."""
    if kind not in KINDS:
        raise ConfigStoreError("UNKNOWN_CONFIG_KIND", f"unknown configuration kind {kind!r}")
    meta = KINDS[kind]
    key = profile_key(bb_id)
    with _LOCK:
        store = _load_raw()
        entry = (store["profiles"].get(key) or {}).get(kind)
        seeded = False
        if not entry or not isinstance(entry.get("document"), dict):
            entry = {
                "document": template_document(kind),
                "source": "vendor_template",
                "updated_at": None,
                "last_write": None,
            }
            seeded = True

    doc = entry["document"]
    try:
        validation = meta["validate"](doc)
        errors = []
    except cfg.DeviceConfigError as e:
        validation = {"ok": False, "warnings": []}
        errors = [{"code": e.code, "message": str(e), "evidence": e.evidence}]

    last = entry.get("last_write")
    dirty = bool(last) and last.get("document_sha256") != _sha(doc)
    return {
        "available": True,
        "kind": kind,
        "label": meta["label"],
        "profile": key,
        "profile_is_default": key == DEFAULT_PROFILE,
        "bb_id": None if key == DEFAULT_PROFILE else key,
        "document": doc,
        "source": entry.get("source", "vendor_template"),
        "seeded_from_template": seeded,
        "updated_at": entry.get("updated_at"),
        "revision": entry.get("revision", 0),
        "remote_path": meta["remote_path"],
        "basename": meta["basename"],
        "store_file": str(store_path()),
        "valid": not errors,
        "errors": errors,
        "warnings": validation.get("warnings", []),
        "last_write": last,
        "dirty": dirty,
        # Stated on every read so no consumer can imply otherwise.
        "readback_supported": False,
        "readback_reason": (
            "No device JSON retrieval is implemented in the traced vendor configuration "
            "path. This document is the saved local JSON, not a reading of the device."),
    }


def _sha(doc: dict) -> str:
    import hashlib
    return hashlib.sha256(cfg.serialize_document(doc)).hexdigest()


def put(kind: str, document: dict, *, bb_id: str | None = None,
        source: str = "operator_edit") -> dict:
    """Validate and store. Raises DeviceConfigError if the document is not sendable."""
    if kind not in KINDS:
        raise ConfigStoreError("UNKNOWN_CONFIG_KIND", f"unknown configuration kind {kind!r}")
    meta = KINDS[kind]
    meta["validate"](document)          # raises DeviceConfigError
    cfg.serialize_document(document)    # raises on oversize
    key = profile_key(bb_id)
    with _LOCK:
        store = _load_raw()
        prof = store["profiles"].setdefault(key, {})
        previous = prof.get(kind) or {}
        prof[kind] = {
            "document": copy.deepcopy(document),
            "source": source,
            "revision": previous.get("revision", 0) + 1,
            "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            # A stored edit never clears the write record -- that is what makes the
            # document show as dirty rather than as never-sent.
            "last_write": previous.get("last_write"),
        }
        _save_raw(store)
    return get(kind, bb_id)


def record_write(kind: str, document: dict, *, bb_id: str | None, result: dict,
                 reviewed_baseline: dict | None = None,
                 reviewed_revision: int | None = None) -> dict:
    """Record a successful send. This is the only thing that clears `dirty`."""
    key = profile_key(bb_id)
    with _LOCK:
        store = _load_raw()
        prof = store["profiles"].setdefault(key, {})
        entry = prof.get(kind) or {"document": copy.deepcopy(
            reviewed_baseline if reviewed_baseline is not None else document),
                                   "source": "operator_edit", "updated_at": None}
        # A direct reviewed send may differ from the saved draft. Promote the
        # sent document only while the saved baseline still matches the review;
        # a concurrent local edit remains authoritative and is marked dirty.
        if (reviewed_baseline is not None
                and _sha(entry["document"]) == _sha(reviewed_baseline)
                and (reviewed_revision is None or entry.get("revision", 0) == reviewed_revision)):
            entry["document"] = copy.deepcopy(document)
            entry["source"] = "acknowledged_upload"
            entry["revision"] = entry.get("revision", 0) + 1
            entry["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        entry["last_write"] = {
            "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "bb_id": None if key == DEFAULT_PROFILE else key,
            "target": copy.deepcopy(result.get("target")),
            "remote_path": KINDS[kind]["remote_path"],
            "document_sha256": _sha(document),
            "payload_md5": result.get("payload_md5"),
            "payload_length": result.get("payload_length"),
            # Recorded explicitly so a reader of the store cannot mistake a completed
            # transfer for a verified device state.
            "verified_by_readback": False,
        }
        prof[kind] = entry
        _save_raw(store)
    return get(kind, bb_id)


def reset_to_template(kind: str, *, bb_id: str | None = None) -> dict:
    return put(kind, template_document(kind), bb_id=bb_id, source="vendor_template")


def selftest() -> dict:
    for kind in KINDS:
        doc = template_document(kind)
        KINDS[kind]["validate"](doc)
    return {"ok": True, "kinds": sorted(KINDS)}


if __name__ == "__main__":
    print(selftest())
