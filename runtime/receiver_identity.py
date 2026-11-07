"""
One receiver identity, resolved once, used by everything.

WHY THIS MODULE EXISTS. The host-key pin store and the known-receiver registry
each reconstructed identity from the candidate independently, and they chose
different fallbacks. In the normal path both landed on the same Windows
ContainerId, so nothing looked wrong -- but when the ContainerId lookup failed
on the serial row, the pin key became `device:CID:{...}` while the registry key
stayed `{...}`. A pin looked up under a key it was not stored under reads as
absent, `HostKeyPin.verify` returns `first_contact`, and the receiver is
silently re-pinned. The protection against a swapped or re-imaged unit fails
OPEN, quietly, in exactly the case where enumeration is already unreliable.

So identity is resolved HERE, once, and both stores consume the result. Neither
is allowed to derive it again.

CANONICAL FORMAT IS UNCHANGED ON PURPOSE. When a ContainerId exists the
canonical key is the raw normalised ContainerId -- byte for byte what
`_service_mode_target()` produced before this module existed. Every pin already
written by `e6d7bcf` on the normal path therefore remains valid and is found
without migration.
"""
from __future__ import annotations

SOURCE_CONTAINER_ID = "container_id"
SOURCE_GROUPED_ROOT = "grouped_root"
SOURCE_NONE = "none"

CONFIDENCE_HIGH = "high"        # a unique USB ContainerId
CONFIDENCE_MEDIUM = "medium"    # the grouped physical root, no ContainerId
CONFIDENCE_NONE = "none"

IDENTITY_CONFLICT = "IDENTITY_CONFLICT"

# The three places Windows reports a ContainerId for one physical unit. They are
# already uppercased at source in the candidate builder; normalising again is a
# no-op there and makes this module correct for any caller.
CONTAINER_FIELDS = ("serial_container_id", "container_id", "network_container_id")

# A grouped root must be more than the prefix to be worth pinning against.
_MIN_ROOT_SPECIFICITY = 8


def normalize(value) -> str:
    return str(value or "").strip().upper()


def resolve(candidate: dict | None) -> dict:
    """Resolve one candidate to a single identity.

    Returns `canonical_id`, `source`, `confidence`, `legacy_aliases` and
    `conflict_reason`. A conflict yields `canonical_id = None`, which every
    caller must treat as "do nothing", not as "pick one".
    """
    cand = candidate or {}
    seen: dict[str, list[str]] = {}
    for field in CONTAINER_FIELDS:
        v = normalize(cand.get(field))
        if v:
            seen.setdefault(v, []).append(field)

    aliases = _legacy_aliases(cand)

    if len(seen) > 1:
        # Two different physical containers reported for one candidate. That is
        # not a receiver we can name, and guessing would attach one unit's pin
        # to another's record.
        return {"canonical_id": None, "source": SOURCE_NONE,
                "confidence": CONFIDENCE_NONE, "legacy_aliases": [],
                "conflict_reason": IDENTITY_CONFLICT,
                "conflict_detail": {v: f for v, f in seen.items()}}

    if len(seen) == 1:
        canonical = next(iter(seen))
        return {"canonical_id": canonical, "source": SOURCE_CONTAINER_ID,
                "confidence": CONFIDENCE_HIGH,
                "legacy_aliases": [a for a in aliases if a != canonical],
                "conflict_reason": None,
                "container_fields": seen[canonical]}

    root = str(cand.get("id") or "").strip()
    if root and len(root) >= _MIN_ROOT_SPECIFICITY and root != "device:":
        # No ContainerId anywhere. The grouped root is what the rest of the
        # application already uses to mean "this physical device", so it is the
        # fallback for BOTH stores rather than each inventing one.
        return {"canonical_id": root, "source": SOURCE_GROUPED_ROOT,
                "confidence": CONFIDENCE_MEDIUM,
                "legacy_aliases": [a for a in aliases if a != root],
                "conflict_reason": None}

    # Nothing stable. The registry may still record a provisional observation;
    # Service Mode must refuse to enroll or pin.
    return {"canonical_id": None, "source": SOURCE_NONE,
            "confidence": CONFIDENCE_NONE, "legacy_aliases": [],
            "conflict_reason": "STABLE_DEVICE_ID_REQUIRED"}


def _legacy_aliases(cand: dict) -> list[str]:
    """Every exact key the PRE-EXISTING target builder could have produced.

    That builder was `serial_container_id or id`, so for any given candidate it
    could have written a pin under the raw ContainerId or under the grouped
    root -- and the grouped root is itself `device:CID:<ContainerId>` whenever a
    ContainerId was known to the grouper. Both forms are emitted here so a pin
    written by an earlier build is found rather than read as a new device.

    This is not only about one bench receiver: any installation that enrolled
    under `e6d7bcf` may hold either form.
    """
    out = []
    for value in (normalize(cand.get("serial_container_id")),
                  str(cand.get("id") or "").strip()):
        if value and value not in out:
            out.append(value)
    return out


def is_usable(identity: dict) -> bool:
    return bool(identity.get("canonical_id")) and not identity.get("conflict_reason")
