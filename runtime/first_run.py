"""
First-run setup -- four pages, run once, and never at the expense of an existing
installation.

### The failure this is built around

An onboarding flow that mistakes an existing user for a new one is worse than no
onboarding at all: it offers to choose a data location for someone who already
has data, a device-history policy for someone who already has history, and a
Service Mode policy for receivers already enrolled. So the first question this
module answers is not "what should the defaults be" but **"has this installation
been used before?"**, and it answers it by looking for the artefacts a used
installation leaves -- settings, a known-receiver registry, nicknames, a widget
layout, a managed key, host-key pins. Any one of them means NOT new.

`RUN SETUP AGAIN` exists for the case where someone wants the pages back, and it
is explicitly non-destructive: re-running rotates no keys, forgets no devices,
moves no data and touches no receiver. It changes preferences and nothing else.

### Why this is not an MSI custom action

An installer runs as whoever is installing, which is not necessarily who will
use the application, and it runs before there is any device to talk about. The
wizard needs the application's own per-user context and should appear on first
LAUNCH. It also has to be skippable without breaking anything -- see below.

### Cancellation is a supported outcome

Closing the wizard is not an error state and must not leave the application
unusable or half-configured. It yields the safe defaults:

* the default data location,
* session-only device observations,
* ask before preparing a receiver,
* Expanded RF Mode disabled.

Those are the same values a fresh document has, so cancelling is indistinguishable
from accepting the defaults -- deliberately. Ordinary non-widget work keeps
working either way; only the widget flows ask again later, which they would have
anyway.

### Schema versioning

`SCHEMA_VERSION` is what stops a later release replaying the wizard at everyone.
A document at the current version is finished. A document at an older version is
MIGRATED -- its answers are kept and any new question gets its safe default --
and the wizard still does not reappear. Only the absence of a document, together
with the absence of every other artefact, counts as new.
"""
from __future__ import annotations

import os
import time
import tempfile
from pathlib import Path

import local_settings

SCHEMA = "ascent.first_run.v1"
SCHEMA_VERSION = 1
SETUP_KEY = "first_run"

# --------------------------------------------------------------------------- #
# Policies
# --------------------------------------------------------------------------- #

HISTORY_REMEMBER = "REMEMBER"
HISTORY_SESSION_ONLY = "SESSION_ONLY"
HISTORY_POLICIES = (HISTORY_REMEMBER, HISTORY_SESSION_ONLY)

SERVICE_ASK = "ASK"
SERVICE_AUTOMATIC = "AUTOMATIC"
SERVICE_NEVER = "NEVER"
SERVICE_POLICIES = (SERVICE_ASK, SERVICE_AUTOMATIC, SERVICE_NEVER)

RF_ASK = "ASK"
RF_AUTOMATIC = "AUTOMATIC"
RF_DISABLED = "DISABLED"
RF_POLICIES = (RF_ASK, RF_AUTOMATIC, RF_DISABLED)

#: The values a cancelled or absent setup yields. Every one of them is the
#: option that does the least.
DEFAULTS = {
    "data_directory": None,          # None means "the default location"
    "device_history": HISTORY_SESSION_ONLY,
    "service_mode": SERVICE_ASK,
    "expanded_rf": RF_DISABLED,
    "fcc_after_service_mode": "DISABLED",
}

PAGES = (
    {"n": 1, "id": "data",     "title": "Where should backups and exports be saved?"},
    {"n": 2, "id": "history",  "title": "Remember Ascent devices on this PC?"},
    {"n": 3, "id": "service",  "title": "Prepare receivers for widgets?"},
    {"n": 4, "id": "review",   "title": "Review"},
)


class FirstRunError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


# --------------------------------------------------------------------------- #
# Is this installation new?
# --------------------------------------------------------------------------- #

#: Artefacts a used installation leaves behind. Finding ANY of them means this
#: is not a first run, whatever the setup document says -- a missing or corrupt
#: setup document on a populated profile is a damaged record, not a new user.
USED_MARKERS = (
    "settings.json",
    "known_devices.json",
    "ascent_device_nicknames.json",
    "vtx_nicknames.json",
    "ascent_widget_layout.json",
    "known_device_hostkeys.json",
    "service_mode",
)


def existing_artefacts(root: Path | None = None) -> list[str]:
    """Which markers are present. Named rather than counted, so a caller can say
    what it found instead of asserting a verdict."""
    root = root or local_settings.config_root()
    found = []
    for name in USED_MARKERS:
        try:
            if (root / name).exists():
                found.append(name)
        except OSError:
            continue
    return found


def load(root: Path | None = None) -> dict:
    doc = local_settings.load().get(SETUP_KEY)
    return doc if isinstance(doc, dict) else {}


def status(root: Path | None = None) -> dict:
    """Should the wizard run, and why. The 'why' is the useful part.

    Four outcomes, and they are deliberately not a boolean:

    * `NEW`       nothing has been written by anything. Show the wizard.
    * `COMPLETE`  a document at the current version. Do not show it.
    * `MIGRATED`  a document at an older version. Keep the answers, fill the new
                  questions with their safe defaults, do NOT show it.
    * `ADOPTED`   no document, but the profile is populated. This is the case
                  that matters: an existing user whose setup record predates the
                  wizard. Adopt the safe defaults silently and do not show it.
    """
    doc = load(root)
    markers = existing_artefacts(root)
    if doc.get("rerun_requested") is True:
        return {"schema": SCHEMA, "run_wizard": True, "reason": "RERUN",
                "artefacts": markers, "policies": policies(root)}
    if doc.get("completed") and doc.get("version") == SCHEMA_VERSION:
        return {"schema": SCHEMA, "run_wizard": False, "reason": "COMPLETE",
                "version": doc.get("version"), "artefacts": markers,
                "policies": policies(root)}
    if doc.get("completed") and doc.get("version") != SCHEMA_VERSION:
        return {"schema": SCHEMA, "run_wizard": False, "reason": "MIGRATED",
                "version": doc.get("version"), "target_version": SCHEMA_VERSION,
                "artefacts": markers, "policies": policies(root)}
    if markers:
        return {"schema": SCHEMA, "run_wizard": False, "reason": "ADOPTED",
                "artefacts": markers, "policies": policies(root),
                "detail": ("This installation has been used before, so the "
                           "existing settings are kept and setup is not shown.")}
    return {"schema": SCHEMA, "run_wizard": True, "reason": "NEW",
            "artefacts": [], "policies": policies(root),
            "pages": [dict(p) for p in PAGES]}


def policies(root: Path | None = None) -> dict:
    """The effective policies, whatever the setup state. Always answerable.

    A caller asking "may I prepare a receiver" must get an answer even when the
    wizard was never run, never finished, or was cancelled. Absent answers fall
    back to DEFAULTS rather than to None.
    """
    doc = load(root)
    answers = doc.get("answers") if isinstance(doc.get("answers"), dict) else {}
    out = dict(DEFAULTS)
    for k, allowed in (("device_history", HISTORY_POLICIES),
                       ("service_mode", SERVICE_POLICIES),
                       ("expanded_rf", RF_POLICIES),
                       ("fcc_after_service_mode", ("ENABLE", "DISABLED"))):
        v = answers.get(k)
        if v in allowed:
            out[k] = v
    out["data_directory"] = local_settings.configured_save_directory()
    return out


# --------------------------------------------------------------------------- #
# Recording answers
# --------------------------------------------------------------------------- #

def _validated(answers: dict) -> dict:
    out = {}
    for key, allowed in (("device_history", HISTORY_POLICIES),
                         ("service_mode", SERVICE_POLICIES),
                         ("expanded_rf", RF_POLICIES),
                       ("fcc_after_service_mode", ("ENABLE", "DISABLED"))):
        if key in answers:
            if answers[key] not in allowed:
                raise FirstRunError(f"{key.upper()}_INVALID",
                                    f"{key} must be one of {', '.join(allowed)}")
            out[key] = answers[key]
    if "data_directory" in answers:
        d = answers["data_directory"]
        if d is not None and not isinstance(d, str):
            raise FirstRunError("DATA_DIRECTORY_INVALID",
                                "the data location must be a path or omitted")
        out["data_directory"] = d or None
    return out


def save_answers(answers: dict, *, completed: bool) -> dict:
    """Record what the operator chose. Preferences only.

    A selected backup/export folder is validated and created if needed, and the
    shared save-directory preference is persisted. Existing files, the fixed
    profile and credentials are never moved; no receiver operation is performed.
    Those are separate, individually confirmed operations, and keeping them out
    of here is what makes RUN SETUP AGAIN safe to offer.
    """
    doc = local_settings.load()
    prev = doc.get(SETUP_KEY) if isinstance(doc.get(SETUP_KEY), dict) else {}
    merged = dict(prev.get("answers") or {})
    validated = _validated(answers or {})
    if "data_directory" in validated:
        raw = validated["data_directory"]
        if raw is None or not raw.strip():
            doc.pop("save_directory", None)
            doc.pop("save_directory_updated_at", None)
            validated["data_directory"] = None
        else:
            verdict = validate_data_directory(raw)
            if not verdict["ok"]:
                raise FirstRunError("DATA_DIRECTORY_INVALID", "; ".join(verdict["errors"]))
            try:
                result = local_settings.validate_save_directory(raw)
            except local_settings.LocalSettingsError as exc:
                raise FirstRunError(exc.code, str(exc)) from exc
            doc["save_directory"] = result["path"]
            doc["save_directory_updated_at"] = local_settings._utc_now()
            validated["data_directory"] = result["path"]
    merged.update(validated)
    doc[SETUP_KEY] = {
        "version": SCHEMA_VERSION,
        "completed": bool(completed),
        "rerun_requested": False,
        "answers": merged,
        "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "first_completed_at": prev.get("first_completed_at")
                              or (time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                                  if completed else None),
    }
    local_settings._write(doc)
    return {"ok": True, "completed": bool(completed), "policies": policies()}


def cancel() -> dict:
    """Closing the wizard. Records the safe defaults as a completed setup.

    Marked completed on purpose: otherwise the wizard reappears at every launch,
    which turns one declined dialog into a permanent one. The recorded answers
    are the defaults, so cancelling and accepting the defaults are the same
    outcome -- which is what makes it safe to treat a closed window as a choice.
    """
    return dict(save_answers({k: v for k, v in DEFAULTS.items() if k != "data_directory"}, completed=True), cancelled=True)


def rerun() -> dict:
    """RUN SETUP AGAIN. Clears only the completion flag.

    Answers are kept so the pages open showing what is actually in force, and
    nothing on disk or on any receiver is touched.
    """
    doc = local_settings.load()
    prev = doc.get(SETUP_KEY) if isinstance(doc.get(SETUP_KEY), dict) else {}
    doc[SETUP_KEY] = dict(prev, version=SCHEMA_VERSION, completed=False, rerun_requested=True,
                          answers=dict(prev.get("answers") or {}))
    local_settings._write(doc)
    return {"ok": True, "run_wizard": True, "policies": policies(),
            "note": ("Nothing has been changed on this computer or on any "
                     "receiver. Only the setup questions were reopened.")}


# --------------------------------------------------------------------------- #
# Step 1 -- the data location
#
# Validation only. Nothing here moves anything: changing the location on a
# populated installation is copy -> verify -> atomic switch -> rollback, which is
# its own confirmed operation, and `plan_move()` describes it rather than doing
# it. A validator that quietly relocated data would be the worst possible place
# to put that behaviour.
# --------------------------------------------------------------------------- #

#: Checked before anything else. The installed-program directory is never
#: mutable data storage: it is read-only for ordinary users on a correct install,
#: an upgrade replaces its contents, and an uninstall deletes them.
PROGRAM_DIR_MARKERS = ("program files", "program files (x86)", "/usr/", "/opt/",
                       "/bin/", "/sbin/")

#: Private key material and DPAPI-protected blobs stay out of the general data
#: directory even when the operator moves it. They live beside the fixed config
#: root, because a data directory can be on a synchronised or removable volume
#: and a private key must not follow it there.
CREDENTIALS_STAY_PUT = (
    "Service Mode keys and pinned device identities stay in the fixed "
    "application folder on this PC and are not moved.")

MIN_FREE_BYTES = 256 * 1024 * 1024


def _looks_like(path_text: str, needles) -> bool:
    low = path_text.replace("\\", "/").lower()
    return any(n.replace("\\", "/").lower() in low for n in needles)


def validate_data_directory(raw) -> dict:
    """Can Ascent Control keep its data here?

    Returns a verdict with separate `errors` and `warnings`. A warning does not
    block -- a network share is a legitimate if unwise choice -- but it is shown
    before the operator commits rather than discovered afterwards.
    """
    out = {"schema": SCHEMA, "requested": raw, "resolved": None,
           "ok": False, "errors": [], "warnings": [],
           "credentials_note": CREDENTIALS_STAY_PUT}
    if raw is None or (isinstance(raw, str) and not raw.strip()):
        out["resolved"] = str(local_settings.config_root())
        out["ok"] = True
        out["default"] = True
        return out
    if not isinstance(raw, str):
        out["errors"].append("The location must be a folder path.")
        return out

    try:
        p = Path(raw).expanduser()
    except (OSError, ValueError):
        out["errors"].append("That is not a usable folder path.")
        return out
    out["resolved"] = str(p)

    # Path.is_absolute() is PLATFORM-dependent, and this module is tested on
    # Linux while it runs on Windows. "C:/Program Files/..." is not absolute to a
    # POSIX Path, so relying on it alone reported a Windows program-files path as
    # merely "relative" and never reached the refusal below it. Accept a drive
    # letter or a UNC prefix explicitly.
    text = str(p).replace("\\", "/")
    windows_absolute = (len(text) > 2 and text[1] == ":" and text[2] == "/"
                        and text[0].isalpha()) or text.startswith("//")
    if not (p.is_absolute() or windows_absolute):
        out["errors"].append("Use a full path, not a relative one.")
        return out
    if _looks_like(str(p), PROGRAM_DIR_MARKERS):
        out["errors"].append(
            "This is where the application itself is installed. Data kept there "
            "is removed when Ascent Control is updated or uninstalled.")
        return out

    # Creation and write access, proved by doing it rather than by asking.
    try:
        p.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        out["errors"].append(f"The folder could not be created ({e.strerror or e}).")
        return out
    try:
        fd, name = tempfile.mkstemp(prefix=".ascent-write-probe-", dir=p)
        os.close(fd)
        probe = Path(name)
        probe.write_bytes(b"ascent")
        probe.unlink()
    except OSError as e:
        out["errors"].append(f"The folder is not writable ({e.strerror or e}).")
        return out

    try:
        free = os.statvfs(str(p)).f_bavail * os.statvfs(str(p)).f_frsize
        out["free_bytes"] = free
        if free < MIN_FREE_BYTES:
            out["warnings"].append(
                f"Only {free // (1024*1024)} MB free here. Map packages are "
                f"large and may not fit.")
    except (OSError, AttributeError):
        out["warnings"].append("The free space on this volume could not be read.")

    low = str(p).replace("\\", "/").lower()
    if low.startswith("//") or low.startswith("\\\\"):
        out["warnings"].append(
            "This is a network location. Ascent Control will be slower and will "
            "not work when the network is unavailable.")
    for marker, why in (("onedrive", "OneDrive"), ("dropbox", "Dropbox"),
                        ("google drive", "Google Drive"), ("icloud", "iCloud")):
        if marker in low:
            out["warnings"].append(
                f"This folder is synchronised by {why}. Files may be copied to "
                f"other machines or locked while syncing.")
            break
    for marker in ("/media/", "/mnt/", "/run/media/"):
        if marker in low:
            out["warnings"].append(
                "This looks like a removable drive. Ascent Control will not "
                "find its data when the drive is disconnected.")
            break

    out["ok"] = True
    return out


MOVE_UNAVAILABLE = "DATA_MOVE_NOT_IMPLEMENTED"


def plan_move(target) -> dict:
    """What moving the data location would involve. Does not move anything.

    Stated in full and then refused, because the operation is only safe if every
    step is real: copy to the new location, VERIFY the copy, switch atomically,
    and keep the old copy until the switch is proven so there is something to
    roll back to. A partial implementation of that is worse than none -- it is
    how a half-copied profile happens.
    """
    v = validate_data_directory(target)
    return {"schema": SCHEMA, "available": False, "blocked": MOVE_UNAVAILABLE,
            "validation": v,
            "steps": ["Copy the existing data to the new location.",
                      "Verify every copied file.",
                      "Switch to the new location in one step.",
                      "Keep the previous copy until the switch is confirmed.",
                      "Roll back to it if anything fails."],
            "message": ("Relocating the whole profile is not available. The "
                        "backup/export destination can be changed separately; "
                        "existing files remain in their previous folders."),
            "credentials_note": CREDENTIALS_STAY_PUT}
