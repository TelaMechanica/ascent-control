"""Features an operator must knowingly accept risk for before they will run.

WHY A GATE RATHER THAN A WARNING

A warning is read once and dismissed. This refuses to act at all until the caller
has acknowledged the specific feature, by name, in this session. The acknowledgement
is NOT persisted: a risk accepted on Tuesday is not a risk accepted today, and a
third-party tester who inherits a settings file has accepted nothing.

WHAT EACH ENTRY MUST SAY

`risk` is what can go wrong in the operator's terms, not the mechanism. `recovery`
is what they do about it afterwards, and it is required -- a feature whose failure
has no stated recovery is one nobody should be able to acknowledge, because the
honest answer is "we do not know what happens next".

THIS IS NOT AUTHORIZATION

The gate records that a person accepted a stated risk. It does not make an operation
safe, it does not widen what the device will accept, and it is not a substitute for
the per-operation QUALIFY check -- an acknowledged feature whose target is
unqualified still fails closed on qualification.
"""

from __future__ import annotations

import threading
import time

# Acknowledgements live for the life of the backend process and are not written to
# disk. Restarting Ascent Control clears them, which is the intended behaviour.
_LOCK = threading.Lock()
_ACKED: dict[str, dict] = {}


class ExperimentalFeatureError(RuntimeError):
    """A named refusal, shaped like the rest of the API's errors."""

    def __init__(self, code: str, message: str, detail: dict | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.detail = detail or {}

    def as_dict(self) -> dict:
        return {"ok": False, "error": self.code, "message": self.message,
                **({"detail": self.detail} if self.detail else {})}


FEATURES: dict[str, dict] = {
    "firmware_variant_build": {
        "title": "Build a product-variant firmware image",
        "summary": ("Construct a Z8, Z40, Hub or HD Pro image from a donor Ascent G_Sky image "
                    "and its included camera support profile."),
        "risk": ("A firmware image built here has not been through Caddx's own "
                 "release testing. Flashing a wrong or incomplete one can leave an "
                 "aircraft with no camera, or unable to start at all. There is no "
                 "recovery console on this hardware."),
        "recovery": ("Re-flash a known-good vendor image over USB-C. Keep one on the "
                     "bench BEFORE building anything here. If the unit will not start "
                     "at all, there is no software fix and it is a return to Caddx."),
        # NOT a hardcoded state. feature_state() measures the packer, so the day a
        # filesystem builder lands this unblocks itself. The previous version was a
        # literal "BLOCKED" beside prose that had already gone stale once.
        "state": None,
        # TWO LAYERS, deliberately. The first is what an operator needs: what it
        # means and what would change it. The second is the evidence, and it belongs
        # behind ADVANCED with the rest of the evidence -- a repo path and the phrase
        # "preserved-node-span surgery" tell a tester nothing they can act on, and
        # burying the one useful sentence inside them is how a clear refusal becomes
        # noise.
        "blocked_because": (
            "Ascent Control cannot build these images yet, and there are TWO separate "
            "reasons. First, making a Z8, Z40 or Hub image means ADDING roughly "
            "thirty files to a standard one, and the builder can currently only "
            "change files that are already there. Second, the camera software itself "
            "has to come from a genuine image of that product — it cannot be written "
            "from scratch. Neither is something you can do anything about from here, "
            "and fixing one would not fix the other."),
        "blocked_detail": (
            "TWO INDEPENDENT BLOCKERS. Clearing either one leaves the other standing.\n"
            "\n"
            "1. FILESYSTEM BUILDER. A variant conversion adds 31 files for Z8 or Z40 "
            "and 37 for a Hub. The packer proven in this project rewrites existing "
            "UBIFS nodes in place at unchanged length, so it cannot add one. Adding a "
            "file requires regenerating the filesystem from a directory tree, which "
            "has not been built or gated.\n"
            "\n"
            "2. PAYLOAD. The sensor driver is machine code compiled into the vendor "
            "application, so a payload has to be taken from an authentic image of "
            "that product. Whether one is held AT THE DONOR'S VERSION is a per-donor "
            "question, and MANAGE FIRMWARE answers it for the file you selected.\n"
            "\n"
            "WHAT IS ALREADY PROVEN, so it is not confused with the above: the packer "
            "takes an image apart and rebuilds it byte for byte on every donor this "
            "project holds, and the panel re-runs that round trip on YOUR donor each "
            "time it reports. That is evidence about the container — the ASW "
            "descriptors, the UBI erase blocks, the headers and CRCs. It is NOT "
            "evidence about the filesystem, because a round trip carries the "
            "filesystem through untouched and never looks inside it. "
            "docs/PACKER_GATE_STATUS.md."),
    },
}


def feature_state(name: str) -> str:
    """BLOCKED or AVAILABLE, measured rather than declared.

    A literal state in the table is a fact that rots: the first version of this gate
    was still describing a 19.2.4-only round-trip proof after the packer had been
    proven on five bases. Asking the tool what it can do means the answer cannot
    disagree with the code.
    """
    if name != "firmware_variant_build":
        return FEATURES.get(name, {}).get("state") or "AVAILABLE"
    try:
        from caddx_firmware_variant import packer_capability
        cap = packer_capability()
    except Exception:
        return "BLOCKED"          # cannot measure -> fail closed
    return "AVAILABLE" if cap.get("can_regenerate_filesystem") else "BLOCKED"


def features() -> dict:
    """Every gated feature, its stated risk, and whether this session accepted it."""
    with _LOCK:
        acked = dict(_ACKED)
    out = []
    for name, f in FEATURES.items():
        out.append({"feature": name, **f,
                    "state": feature_state(name),
                    "acknowledged": name in acked,
                    "acknowledged_at": acked.get(name, {}).get("at")})
    return {"ok": True, "features": out,
            "note": ("Acknowledgements last for this run of Ascent Control only and are "
                     "never written to disk. Restarting clears them.")}


def acknowledge(body: dict) -> dict:
    """Record that the operator accepted one named feature's stated risk.

    The feature must be named explicitly and `accept` must be exactly True. A
    truthy-ish value is not acceptance: "1", "yes" and "on" are what a careless
    caller sends, and this is the one place where guessing the intent is wrong.
    """
    name = str(body.get("feature") or "").strip()
    if name not in FEATURES:
        raise ExperimentalFeatureError(
            "UNKNOWN_FEATURE", f"there is no experimental feature called {name!r}",
            {"known": sorted(FEATURES)})
    if body.get("accept") is not True:
        raise ExperimentalFeatureError(
            "ACCEPT_REQUIRED",
            "the request must set accept=true, which records that the operator read "
            "the stated risk and chose to proceed")
    with _LOCK:
        _ACKED[name] = {"at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    return {"ok": True, "feature": name, "acknowledged": True,
            "risk": FEATURES[name]["risk"], "recovery": FEATURES[name]["recovery"]}


def withdraw(body: dict) -> dict:
    """Take an acknowledgement back. Present because a gate you cannot close is a
    gate that was only ever decoration."""
    name = str(body.get("feature") or "").strip()
    with _LOCK:
        existed = _ACKED.pop(name, None) is not None
    return {"ok": True, "feature": name, "acknowledged": False, "was_acknowledged": existed}


def is_acknowledged(name: str) -> bool:
    with _LOCK:
        return name in _ACKED


def require(name: str) -> None:
    """Refuse unless this session acknowledged `name`, and unless the feature is
    actually usable. The order matters: a feature that cannot work is refused for
    THAT reason, so acknowledging risk never reads as "and now it will run"."""
    f = FEATURES.get(name)
    if f is None:
        raise ExperimentalFeatureError("UNKNOWN_FEATURE",
                                       f"there is no experimental feature called {name!r}")
    if feature_state(name) == "BLOCKED":
        raise ExperimentalFeatureError(
            "FEATURE_BLOCKED", f["blocked_because"],
            {"feature": name, "acknowledged": is_acknowledged(name)})
    if not is_acknowledged(name):
        raise ExperimentalFeatureError(
            "RISK_NOT_ACKNOWLEDGED",
            f"{f['title']} is experimental. Read the risk and acknowledge it before "
            f"this will run.",
            {"feature": name, "risk": f["risk"], "recovery": f["recovery"]})
