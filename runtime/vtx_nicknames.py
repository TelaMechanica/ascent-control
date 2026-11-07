"""Local BB ID -> nickname mapping, by identity kind.

Scope, from CLAUDE.md's Gesture V5 identity model: this maps the BB ID of a
**physical unit**, and every entry records *which kind* of unit that is --
``aircraft_vtx`` for an Aircraft/VTX, ``receiver`` for a ground receiver. The two
kinds share a key space but never a label, and a lookup may be restricted to one.

**PRIMARY and FALLBACK are roles, not kinds, and are never stored here.** A VRX's own
BB ID is a ``receiver`` entry; that same BB ID *plays* the PRIMARY or FALLBACK role when
some aircraft's ``user_cfg.json`` names it at ``bb_mac_addr_0`` / ``bb_mac_addr_1``. The
role lives in that document, on that aircraft. ``normalize_identity`` refuses
``primary``/``fallback`` outright so a role can never be smuggled in as a kind.

Four hard rules, each pinned by tests:

  1. **Local only.** A nickname is host-side metadata. It is never injected into a
     vendor payload, a written device file, or any frame that travels toward a device.
     No module in the write paths imports this one.
  2. **Alongside, never instead.** Callers display a nickname next to the raw BB ID.
     A nickname is not an identity and never keys anything -- correlation, capability
     and qualification all continue to use the BB ID.
  3. **Keyed by BB ID, not by port.** The store lives in the fixed application-data
     directory and is keyed by the canonical 4-byte BB ID, so it survives restarts and
     does not care which COM port the unit enumerates on.
  4. **One nickname, one BB ID.** Nicknames are unique across the whole store,
     compared case-insensitively, exactly as an account-creation username field
     behaves. This is what makes the reverse lookup sound: it is intended to become
     the selection mechanism for assigning PRIMARY/FALLBACK receivers, and a name that
     resolved to two units could select the wrong aircraft's receiver.
"""
from __future__ import annotations

import json
import os
import re
import threading
import time
import unicodedata
from pathlib import Path

import local_settings

SCHEMA = "ascent.device_nicknames.v3"
# v1 had no per-entry identity kind. Its rows are Aircraft/VTX by definition -- that
# was the whole scope of the store -- so they load as `aircraft_vtx` rather than being
# discarded. Reading an older store must not lose an operator's names.
#
# v2 is v3's shape exactly; only the NAME changed. Both the file and the schema id
# said "vtx" while the store had already widened to hold receivers too, so the name
# described the original scope rather than the contents -- and a file called
# vtx_nicknames.json holding a VRX row is a small lie that invites a bigger one.
LEGACY_SCHEMAS = ("ascent.vtx_nicknames.v2", "ascent.vtx_nicknames.v1")
STORE_FILENAME = "ascent_device_nicknames.json"
# Read once, on first load, and never written again. An operator who named units
# under the old file keeps those names.
LEGACY_STORE_FILENAMES = ("vtx_nicknames.json",)
MAX_NICKNAME_CHARS = 32
# A local nickname store is not a database. Past this, something is wrong with the caller
# rather than with the operator's naming habits.
MAX_ENTRIES = 512

IDENTITY_AIRCRAFT_VTX = "aircraft_vtx"
IDENTITY_RECEIVER = "receiver"
IDENTITY_KINDS = (IDENTITY_AIRCRAFT_VTX, IDENTITY_RECEIVER)
DEFAULT_IDENTITY = IDENTITY_AIRCRAFT_VTX
IDENTITY_LABELS = {
    IDENTITY_AIRCRAFT_VTX: "AIRCRAFT / VTX BB ID",
    IDENTITY_RECEIVER: "GROUND RECEIVER BB ID",
}
# Role names, not unit kinds. Accepting one of these as an identity would be exactly
# the conflation the identity model forbids, so they are named and refused.
_ROLE_WORDS = ("primary", "fallback", "primary_receiver", "fallback_receiver",
               "bb_mac_addr_0", "bb_mac_addr_1")

_BBID_RE = re.compile(r"[0-9A-F]{2}(?::[0-9A-F]{2}){3}")
# Broadcast/unset baseband addresses are not units and must never acquire a name.
_SENTINEL_BBIDS = ((':'.join(('00', '00', '00', '00'))), (':'.join(('FF', 'FF', 'FF', 'FF'))))

_LOCK = threading.RLock()


class NicknameInUse(ValueError):
    """Raised when a nickname is already held by a different BB ID.

    A ``ValueError`` subclass so every existing caller's ``except ValueError`` still
    catches it, while the HTTP layer can report the specific collision.
    """

    def __init__(self, nickname: str, bb_id: str):
        super().__init__("this nickname is already in use")
        self.nickname = nickname
        self.bb_id = bb_id


def _utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def normalize_bb_id(value: object) -> str:
    """Canonical 4-byte BB ID text, uppercase, colon-separated.

    This is the store key. Accepts ``-`` or ``:`` separators and any case so that a
    value read from a device document, a Ground STATUS frame or the UI all land on the
    same key.
    """
    text = str(value or "").strip().replace("-", ":").upper()
    if not _BBID_RE.fullmatch(text):
        raise ValueError("expected exact 4-byte BB ID")
    if text in _SENTINEL_BBIDS:
        raise ValueError("sentinel BB ID")
    return text


def normalize_identity(value: object) -> str:
    """Canonical identity kind, defaulting to Aircraft/VTX when unstated.

    ``None`` means "the caller did not say", which is the v1 store's meaning and the
    store's original scope. A PRIMARY/FALLBACK *role* is not a kind and is refused.
    """
    if value is None:
        return DEFAULT_IDENTITY
    text = re.sub(r"[^a-z0-9]+", "_", str(value).strip().lower()).strip("_")
    if not text:
        return DEFAULT_IDENTITY
    if text in _ROLE_WORDS:
        raise ValueError("PRIMARY and FALLBACK are receiver roles, not identity kinds; "
                         "store the unit as 'receiver'")
    if text not in IDENTITY_KINDS:
        raise ValueError(f"identity must be one of {', '.join(IDENTITY_KINDS)}")
    return text


def safe_nickname(value: object) -> str:
    """Validate an operator-supplied nickname.

    Control and format characters are refused outright: a nickname is rendered in the
    UI and appears in local JSON, and neither should have to defend against embedded
    bidi or newline payloads.
    """
    if not isinstance(value, str):
        raise ValueError("nickname must be a string")
    text = unicodedata.normalize("NFC", value).strip()
    if not text:
        raise ValueError("nickname length")
    if len(text) > MAX_NICKNAME_CHARS:
        raise ValueError("nickname length")
    if any(unicodedata.category(ch) in ("Cc", "Cf", "Cs", "Co") for ch in text):
        raise ValueError("nickname contains control/format characters")
    return text


def nickname_fold(value: object) -> str:
    """The case-insensitive comparison key for one nickname.

    ``casefold`` rather than ``lower`` so that names differing only by case cannot
    coexist in any script, and NFC first so two spellings of the same accented name
    fold together. This is the uniqueness key, never a storage key -- the operator's
    own capitalization is what gets stored and displayed.
    """
    return unicodedata.normalize("NFC", str(value or "")).strip().casefold()


def store_path() -> Path:
    """Fixed application-data location.

    Deliberately *not* under the configurable save directory: nicknames are a setting,
    not a save artefact, and relocating saves must not make named aircraft disappear.
    """
    return local_settings.config_root() / STORE_FILENAME


def legacy_store_paths() -> list:
    """Earlier filenames, newest first. Read-only."""
    root = local_settings.config_root()
    return [root / name for name in LEGACY_STORE_FILENAMES]


def _read_document() -> dict | None:
    """The current store, or the newest legacy file if the current one is absent.

    Migration is read-through rather than a copy on startup: the old file is left
    exactly where it is until something is actually written, so a failed upgrade
    cannot lose an operator's names.
    """
    for path in (store_path(), *legacy_store_paths()):
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
    return None


def load_all() -> dict:
    """Every stored entry, keyed by canonical BB ID. Bad rows are dropped, not raised."""
    with _LOCK:
        doc = _read_document()
        if doc is None:
            return {}
    if not isinstance(doc, dict) or doc.get("schema") not in (SCHEMA, *LEGACY_SCHEMAS):
        return {}
    raw = doc.get("nicknames")
    if not isinstance(raw, dict):
        return {}
    out: dict[str, dict] = {}
    for key, entry in raw.items():
        try:
            bb = normalize_bb_id(key)
            if isinstance(entry, str):
                entry = {"nickname": entry}
            if not isinstance(entry, dict):
                continue
            nickname = safe_nickname(entry.get("nickname"))
            # A row naming an unknown kind -- or a role masquerading as one -- is
            # dropped rather than coerced. Silently relabelling a receiver as an
            # aircraft is the conflation this store exists to prevent.
            identity = normalize_identity(entry.get("identity"))
        except ValueError:
            continue
        meta = entry.get("metadata")
        out[bb] = {"nickname": nickname, "identity": identity,
                   "updated_at": entry.get("updated_at"),
                   # Additive, backward-compatible: a nickname-only legacy row has no
                   # metadata and reads as {}. Preserved verbatim so a later simple
                   # set_nickname rename does not drop a rich USB-enroll record.
                   "metadata": meta if isinstance(meta, dict) else {}}
    return out


def _write_all(entries: dict) -> None:
    doc = {"schema": SCHEMA, "updated_at": _utc_now(), "nicknames": entries}
    p = store_path()
    with _LOCK:
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(doc, indent=2, ensure_ascii=False, sort_keys=True),
                       encoding="utf-8")
        os.replace(tmp, p)


def find_conflict(nickname: object, exclude_bb_id: object = None,
                  entries: dict | None = None) -> str | None:
    """The BB ID already holding ``nickname``, or None. Case-insensitive.

    ``exclude_bb_id`` is the BB ID being written, so re-saving a unit's own existing
    name does not collide with itself -- the same exemption a signup form makes when
    you submit your current username unchanged.
    """
    fold = nickname_fold(nickname)
    if not fold:
        return None
    try:
        mine = normalize_bb_id(exclude_bb_id) if exclude_bb_id is not None else None
    except ValueError:
        mine = None
    for bb, entry in sorted((entries if entries is not None else load_all()).items()):
        if bb == mine:
            continue
        if nickname_fold(entry.get("nickname")) == fold:
            return bb
    return None


def duplicate_folds(entries: dict | None = None) -> dict:
    """Folded nicknames held by more than one BB ID, as fold -> [BB ID, ...].

    Uniqueness is enforced on write, but a store written before it was enforced can
    still contain collisions. Reporting them is what lets the reverse lookup fail
    closed on a name it cannot resolve to exactly one unit instead of guessing.
    """
    seen: dict[str, list[str]] = {}
    for bb, entry in sorted((entries if entries is not None else load_all()).items()):
        seen.setdefault(nickname_fold(entry.get("nickname")), []).append(bb)
    return {fold: bbs for fold, bbs in seen.items() if len(bbs) > 1}


def get(bb_id: object) -> str | None:
    """The nickname for one BB ID, or None. Never raises on lookup."""
    try:
        key = normalize_bb_id(bb_id)
    except ValueError:
        return None
    entry = load_all().get(key)
    return entry.get("nickname") if entry else None


def get_bb_id(nickname: object, identity: object = None) -> str | None:
    """Reverse lookup: the BB ID holding ``nickname``, or None. Case-insensitive.

    The counterpart to :func:`get`. The Picker "select by nickname" path
    (dev_harness.picker_select) is its first live caller: an operator picks "Drone
    A" and this resolves the exact BB ID that is switched to (aircraft/VTX kind).
    The future PRIMARY/FALLBACK provisioning UI selects a receiver the same way.

    Pass ``identity`` to restrict the answer to one kind of unit -- a PRIMARY or
    FALLBACK slot may only ever be filled by a ``receiver``, and resolving an
    Aircraft/VTX name into a receiver slot would write the wrong identity into
    ``user_cfg.json``.

    **Fails closed.** Returns None for an unknown name, and also for a name held by
    more than one BB ID, which a store written before uniqueness was enforced can
    still contain. An ambiguous target is never resolved by guessing.
    """
    fold = nickname_fold(nickname)
    if not fold:
        return None
    want = normalize_identity(identity) if identity is not None else None
    hits = [bb for bb, entry in sorted(load_all().items())
            if nickname_fold(entry.get("nickname")) == fold
            and (want is None or entry.get("identity") == want)]
    return hits[0] if len(hits) == 1 else None


def set_nickname(bb_id: object, nickname: object, identity: object = None) -> dict:
    """Store or clear one nickname.

    An empty or None nickname clears the entry; clearing an absent entry is a no-op
    success rather than an error, so a UI can send the same request either way.

    A nickname already held by a *different* BB ID raises :class:`NicknameInUse`.
    Re-saving a BB ID's own current nickname is always allowed, whatever its case, so
    a form that resubmits an unchanged row does not trip the check on itself.

    ``identity`` is the kind of unit this BB ID belongs to. Omitting it on an existing
    entry keeps that entry's kind rather than silently relabelling the unit.
    """
    key = normalize_bb_id(bb_id)
    clearing = nickname is None or (isinstance(nickname, str) and not nickname.strip())
    with _LOCK:
        entries = load_all()
        if clearing:
            removed = entries.pop(key, None)
            _write_all(entries)
            return {"ok": True, "bb_id": key, "nickname": None, "identity": None,
                    "cleared": removed is not None, "count": len(entries)}
        text = safe_nickname(nickname)
        kind = (normalize_identity(identity) if identity is not None
                else (entries.get(key) or {}).get("identity") or DEFAULT_IDENTITY)
        held_by = find_conflict(text, exclude_bb_id=key, entries=entries)
        if held_by is not None:
            raise NicknameInUse(text, held_by)
        if key not in entries and len(entries) >= MAX_ENTRIES:
            raise ValueError(f"nickname store is full ({MAX_ENTRIES} entries)")
        # Preserve any rich metadata already on this entry -- a simple rename must
        # not wipe a USB-enroll identity record (serial/model/fw/provenance).
        prior_meta = (entries.get(key) or {}).get("metadata") or {}
        entries[key] = {"nickname": text, "identity": kind, "updated_at": _utc_now(),
                        "metadata": prior_meta}
        _write_all(entries)
        return {"ok": True, "bb_id": key, "nickname": text, "identity": kind,
                "cleared": False, "count": len(entries)}


class IdentityConflict(ValueError):
    """Raised when a rich identity write would silently rewrite an identity
    relationship (BB ID<->serial). A ``ValueError`` subclass so existing
    ``except ValueError`` callers still catch it; carries a ``code`` for the API.
    """

    def __init__(self, code: str, detail: str, *, bb_id=None, serial=None):
        super().__init__(detail)
        self.code = code
        self.detail = detail
        self.bb_id = bb_id
        self.serial = serial


def find_serial_conflict(serial: object, exclude_bb_id: object = None,
                         entries: dict | None = None) -> str | None:
    """The BB ID already recorded with this manufacturing ``serial``, or None.

    The serial is the physical-unit anchor: one serial must map to one BB ID. This
    is what makes a crossed-cable / swapped-unit mistake fail closed instead of
    silently re-pointing an existing identity.
    """
    s = str(serial).strip() if serial else ""
    if not s:
        return None
    try:
        mine = normalize_bb_id(exclude_bb_id) if exclude_bb_id is not None else None
    except ValueError:
        mine = None
    for bb, entry in sorted((entries if entries is not None else load_all()).items()):
        if bb == mine:
            continue
        if str((entry.get("metadata") or {}).get("serial") or "").strip() == s:
            return bb
    return None


def set_identity_record(bb_id: object, nickname: object, *, identity: object = None,
                        serial: object = None, model: object = None,
                        hardware_rev: object = None, firmware_version: object = None,
                        provenance: object = None, last_update: object = None,
                        now: str | None = None) -> dict:
    """Store/augment a rich ``aircraft_vtx`` identity record (USB Update+Enroll).

    Backward-compatible: augments an existing legacy nickname-only row, never drops
    prior metadata. Conflict discipline (no silent identity rewrites):
      * same BB ID + same (or no prior) serial -> update/augment;
      * same BB ID + conflicting serial        -> IdentityConflict SERIAL_MISMATCH;
      * same serial + conflicting BB ID         -> IdentityConflict SERIAL_CLAIMED;
      * nickname held by another BB ID          -> NicknameInUse (existing rule).
    ``in_receiver_t2`` is intentionally NOT persisted here: it is current, per-receiver
    state (recomputed from a receiver's live T2), not durable unit identity.
    """
    key = normalize_bb_id(bb_id)
    text = safe_nickname(nickname)
    if not text:
        raise ValueError("a nickname is required for an identity record")
    with _LOCK:
        entries = load_all()
        existing = entries.get(key) or {}
        prior = existing.get("metadata") or {}
        kind = (normalize_identity(identity) if identity is not None
                else existing.get("identity") or DEFAULT_IDENTITY)
        s_new = str(serial).strip() if serial else None
        s_old = str(prior.get("serial")).strip() if prior.get("serial") else None
        if s_new and s_old and s_new != s_old:
            raise IdentityConflict(
                "SERIAL_MISMATCH",
                f"{key} is already recorded with serial {s_old!r}, not {s_new!r}",
                bb_id=key, serial=s_old)
        if s_new:
            other = find_serial_conflict(s_new, exclude_bb_id=key, entries=entries)
            if other is not None:
                raise IdentityConflict(
                    "SERIAL_CLAIMED",
                    f"serial {s_new!r} is already recorded for {other}",
                    bb_id=other, serial=s_new)
        held_by = find_conflict(text, exclude_bb_id=key, entries=entries)
        if held_by is not None:
            raise NicknameInUse(text, held_by)
        if key not in entries and len(entries) >= MAX_ENTRIES:
            raise ValueError(f"nickname store is full ({MAX_ENTRIES} entries)")
        meta = dict(prior)  # augment, never drop
        for field, val in (("serial", s_new), ("model", model),
                           ("hardware_rev", hardware_rev),
                           ("firmware_version", firmware_version),
                           ("provenance", provenance),
                           ("last_update", last_update or now or _utc_now())):
            if val is not None:
                meta[field] = val
        entries[key] = {"nickname": text, "identity": kind,
                        "updated_at": now or _utc_now(), "metadata": meta}
        _write_all(entries)
        return {"ok": True, "bb_id": key, "nickname": text, "identity": kind,
                "metadata": meta, "count": len(entries)}


def document() -> dict:
    """UI-facing view. ``nicknames`` is BB ID -> nickname text."""
    entries = load_all()
    dupes = duplicate_folds(entries)
    return {
        "available": True,
        "schema": SCHEMA,
        # Both kinds live here, and every entry says which it is. There is deliberately
        # no single unqualified identity label: the identity model forbids one.
        "identity": "bb_id_by_identity_kind",
        "identity_kinds": {k: IDENTITY_LABELS[k] for k in IDENTITY_KINDS},
        "default_identity": DEFAULT_IDENTITY,
        "count": len(entries),
        "nicknames": {k: v["nickname"] for k, v in sorted(entries.items())},
        "entries": {k: dict(v) for k, v in sorted(entries.items())},
        # The reverse view, folded exactly as the uniqueness check folds. A UI shows an
        # "already in use" hint from this without a round trip per keystroke; the store
        # still decides on submit.
        "nickname_folds": {nickname_fold(v["nickname"]): k
                           for k, v in sorted(entries.items())},
        "unique": not dupes,
        "duplicate_nicknames": {f: list(b) for f, b in dupes.items()},
        "store_file": str(store_path()),
        "max_length": MAX_NICKNAME_CHARS,
        "note": ("Local host metadata for a unit's own BB ID, tagged with the kind of "
                 "unit it is. Never written to a device, never sent in a vendor "
                 "payload, and never a substitute for the raw BB ID. PRIMARY and "
                 "FALLBACK are receiver roles recorded in an aircraft's user_cfg.json, "
                 "not kinds stored here."),
    }


def selftest() -> None:
    """Import-safe checks. No device, no subprocess."""
    assert normalize_bb_id("f2-00-00-18") == (':'.join(('F2', '00', '00', '18')))
    assert normalize_bb_id((':'.join(('F2', '00', '00', '18')))) == (':'.join(('F2', '00', '00', '18')))
    for bad in (None, "", "A4:1D:36", (':'.join(('02', 'F2', '00', '00', '00', '19'))), "ZZ:1D:36:9D",
                (':'.join(('00', '00', '00', '00'))), (':'.join(('FF', 'FF', 'FF', 'FF'))), "f2000018"):
        try:
            normalize_bb_id(bad)
        except ValueError:
            pass
        else:
            raise AssertionError(f"accepted BB ID {bad!r}")

    assert safe_nickname("  Ship 3  ") == "Ship 3"
    for bad in (None, "", "   ", 7, "x" * (MAX_NICKNAME_CHARS + 1), "line\nbreak",
                "zero​width"):
        try:
            safe_nickname(bad)
        except ValueError:
            pass
        else:
            raise AssertionError(f"accepted nickname {bad!r}")

    # Identity kinds: unstated means Aircraft/VTX, and a role is never a kind.
    assert normalize_identity(None) == IDENTITY_AIRCRAFT_VTX
    assert normalize_identity("Aircraft VTX") == IDENTITY_AIRCRAFT_VTX
    assert normalize_identity("RECEIVER") == IDENTITY_RECEIVER
    for bad in ("primary", "FALLBACK", "primary_receiver", "bb_mac_addr_0", "goggles"):
        try:
            normalize_identity(bad)
        except ValueError:
            pass
        else:
            raise AssertionError(f"accepted identity {bad!r}")

    # Folding is case-insensitive and NFC-stable.
    assert nickname_fold("  Ship 3 ") == nickname_fold("SHIP 3") == "ship 3"

    assert store_path().parent == local_settings.config_root()
    assert store_path().name == STORE_FILENAME


if __name__ == "__main__":
    selftest()
    print("vtx_nicknames selftest OK")


def deployment_projection(entries: dict | None = None) -> dict:
    """
    The AIRCRAFT-only subset of this store, as a flat ``BbId -> nickname`` map.

    Ascent Control holds the richer master: identity kind, timestamps, both kinds of
    unit. What a VRX needs is narrower, and the boundary is a decision rather than an
    accident (user, 2026-09-23): the deployed alias store carries **aircraft entries
    only**, because GlassesUI joins it against live aircraft fleet rows. Receiver
    names are fleet-management metadata for the laptop and are not deployed unless a
    future VRX UI asks for them.

    This is a projection and nothing more. It does not know a transport, a filename or
    a wire schema -- the VRX-side effort owns the persistence contract and has not
    frozen it, so inventing one here would be guessing at someone else's interface.
    What it does settle is the part that IS ours: which entries leave the laptop.
    """
    entries = load_all() if entries is None else entries
    aircraft = {bb: e["nickname"] for bb, e in sorted(entries.items())
                if e.get("identity") == IDENTITY_AIRCRAFT_VTX and e.get("nickname")}
    withheld = sorted(bb for bb, e in entries.items()
                      if e.get("identity") != IDENTITY_AIRCRAFT_VTX)
    return {
        "aliases": aircraft,
        "count": len(aircraft),
        "withheld_receiver_bb_ids": withheld,
        "withheld_count": len(withheld),
        "note": ("Aircraft entries only. Receiver names stay on this PC: GlassesUI "
                 "joins the deployed map against aircraft fleet rows, and a receiver "
                 "row has nothing there to join to."),
    }
