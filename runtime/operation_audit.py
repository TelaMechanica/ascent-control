#!/usr/bin/env python3
"""A security-relevant event log that survives the backend exiting.

WHY THIS EXISTS. Every Service Mode activation, failure class and recovery
decision used to go into `SERVICE_MODE_AUDIT`, a plain Python list in
`dev_harness`. When the backend process exited, it went with it. So when a
managed credential was destroyed on 2026-10-08 by a revoke path that deleted the
local key without confirming the device had been cleared, there was no record of
the attempt, the outcome, or the decision -- only file timestamps, and a host log
that had stopped twenty hours earlier. The operator's question, "how did you not
maintain a record", had no better answer than: nothing wrote one.

WHAT IS RECORDED. Timestamp, the receiver identity AS THE DEVICE REPORTED IT,
the operation, its outcome, a failure classification and a recovery state.

WHAT IS NEVER RECORDED. Key material of either kind, authorization tokens,
passwords, or session contents. `redact()` is applied to every free-text field
and a deny-list of key names is dropped outright, because the useful thing to
write down about a credential is its fingerprint, never the credential.

INCOMPLETE TRANSACTIONS. An operation writes `begin` before it acts and a
terminal record after. A `begin` with no terminal partner is an operation that
was interrupted -- a crash, a power loss, a killed backend -- and
`open_transactions()` finds them. That is the shape the previous design could not
represent at all: it had no way to say "something started and we do not know how
it ended", which is exactly what happened.
"""
from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path

import local_settings
from log_redaction import redact

#: One JSON object per line. Append-only; a truncated final line is tolerated on
#: read rather than discarding the whole file.
AUDIT_FILENAME = "service_mode_audit.jsonl"

#: Bounded so a long-lived install cannot grow it without limit. Rotation keeps
#: the most recent records, because a defect is investigated backwards.
MAX_RECORDS = 5000
TRIM_TO = 4000

#: Terminal outcomes. Anything not in here leaves a transaction open.
OUTCOME_BEGIN = "BEGIN"

#: Never written, whatever a caller passes.
_FORBIDDEN_KEYS = frozenset({
    "private_key", "public_key", "key", "password", "passphrase", "secret",
    "token", "authorization", "stdin", "stdout", "payload", "command",
})

_LOCK = threading.RLock()


def audit_path() -> Path:
    return local_settings.config_root() / AUDIT_FILENAME


def _utc() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _safe(value, depth: int = 0):
    """Redact free text, drop forbidden keys, and bound the structure."""
    if depth > 4:
        return "..."
    if isinstance(value, str):
        return redact(value)[:600]
    if isinstance(value, bool) or value is None or isinstance(value, (int, float)):
        return value
    if isinstance(value, dict):
        return {k: _safe(v, depth + 1) for k, v in value.items()
                if str(k).lower() not in _FORBIDDEN_KEYS}
    if isinstance(value, (list, tuple)):
        return [_safe(v, depth + 1) for v in list(value)[:40]]
    return redact(str(value))[:600]


def record(operation: str, outcome: str, *, device=None, failure_class=None,
           recovery_state=None, detail=None, transaction_id=None, **extra) -> dict:
    """Build one record. Pure -- writing is `append`.

    `device` is the identity the DEVICE reported, not a cached record: a log
    that names the wrong receiver is worse than one that names none, and this
    store exists because the cached identity was wrong.
    """
    dev = device or {}
    rec = {
        "at": _utc(),
        "operation": str(operation)[:64],
        "outcome": str(outcome)[:64],
        "failure_class": (str(failure_class)[:64] if failure_class else None),
        "recovery_state": (str(recovery_state)[:64] if recovery_state else None),
        "transaction_id": (str(transaction_id)[:64] if transaction_id else None),
        "device": {
            "command_60_identity": _safe(dev.get("command_60_identity")
                                         or dev.get("device_name")),
            "serial_number": _safe(dev.get("serial_number")),
            "firmware": _safe(dev.get("firmware")),
            "device_id": _safe(dev.get("device_id")),
            "host_key_fingerprint": _safe(dev.get("host_key_fingerprint")),
        },
        "detail": _safe(detail) if detail is not None else None,
    }
    for k, v in extra.items():
        if str(k).lower() in _FORBIDDEN_KEYS or k in rec:
            continue
        rec[k] = _safe(v)
    return rec


def append(rec: dict) -> dict:
    """Write one record durably. Never raises: an audit failure must not become
    an operational failure, and a caller mid-revoke cannot handle it anyway."""
    try:
        p = audit_path()
        with _LOCK:
            p.parent.mkdir(parents=True, exist_ok=True)
            with open(p, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec, separators=(",", ":")) + "\n")
                fh.flush()
                os.fsync(fh.fileno())      # survives a power loss, not just an exit
            _trim_if_needed(p)
    except Exception:                                            # noqa: BLE001
        pass
    return rec


def _trim_if_needed(p: Path) -> None:
    try:
        if p.stat().st_size < 512 * 1024:
            return
        rows = read_all()
        if len(rows) <= MAX_RECORDS:
            return
        keep = rows[-TRIM_TO:]
        tmp = p.with_suffix(".jsonl.tmp")
        tmp.write_text("".join(json.dumps(r, separators=(",", ":")) + "\n"
                               for r in keep), encoding="utf-8")
        os.replace(tmp, p)
    except Exception:                                            # noqa: BLE001
        pass


def read_all() -> list:
    """Every record, oldest first. A truncated final line is skipped, not fatal:
    that line is exactly what a crash mid-write leaves behind, and losing the
    whole history to it would defeat the point."""
    try:
        text = audit_path().read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            doc = json.loads(line)
        except ValueError:
            continue
        if isinstance(doc, dict):
            out.append(doc)
    return out


def open_transactions() -> list:
    """Transactions that began and never reached a terminal record.

    This is what an interrupted operation looks like after the fact, and the
    reason a `begin` is written before acting rather than one record after.
    """
    begun, ended = {}, set()
    for r in read_all():
        tid = r.get("transaction_id")
        if not tid:
            continue
        if r.get("outcome") == OUTCOME_BEGIN:
            begun[tid] = r
        else:
            ended.add(tid)
    return [r for tid, r in begun.items() if tid not in ended]


def new_transaction_id() -> str:
    import uuid
    return uuid.uuid4().hex[:16]
