"""Run the Mode A firmware builder from Ascent Control.

WHY THIS FILE EXISTS AND WHAT IT CANNOT CHANGE.

firmware/mode_a/ builds a z8, z40 or hub image by regenerating an exact donor's
UBIFS volumes and transplanting an application into them. It is a set of Python
CLIs. The established Linux/WSL backend creates UBIFS with mkfs.ubifs under
fakeroot so device ownership and permissions survive. A qualified native Windows
tool bundle can instead use the same writer with an explicit metadata inventory,
Windows ARM tools and pinned Python dependencies. No Windows host file metadata
is treated as device metadata.

Native discovery verifies the bundle and covered builder scripts before it is
selected. When no qualified native bundle exists, the existing WSL path remains.
Both paths run the same application and image gates and report their verdicts.

WHAT IS CHECKED BEFORE ANYTHING RUNS. A build takes minutes and writes a
firmware image. Finding out at the end that `mkfs.ubifs` was missing is the
failure this preflight exists to prevent, so every dependency is probed first
and reported by name, with what would fix it.

NOTHING HERE FLASHES ANYTHING. This module produces a file and a report. The
gates inside the builder decide whether that file is trustworthy; this module
reports their verdict and never substitutes its own.
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
import posixpath
import shutil
import stat
import subprocess

import firmware_native_backend as native_backend
import firmware_camera_support as camera_support

#: The builder's own scripts, as shipped. Only runtime/** reaches the MSI, so
#: the tree under firmware/mode_a/ is staged beside this file at build time and
#: a test pins that the two have not drifted.
BUILDER_SUBDIR = os.path.join("device_tools", "mode_a")

#: mtd-utils as apt ships it. Recorded rather than inferred: this is the exact
#: version that produced the verified 19.2.14 images, per
#: docs/evidence/mode_a/gate1_report_19_2_14.json ("mkfs.ubifs (mtd-utils) 2.2.0").
MKFS_PACKAGE = "mtd-utils"
MKFS_BIN = "mkfs.ubifs"
MKFS_KNOWN_GOOD = "2.2.0"

#: Searched in order. The apt locations first, because that is the supported way
#: to get it; a hand-built copy is honoured but is not what we tell people to do.
MKFS_SEARCH = ("/usr/sbin/mkfs.ubifs", "/sbin/mkfs.ubifs", "/usr/bin/mkfs.ubifs")

TARGETS = {
    "gate1": {
        "label": "Rebuild the donor and prove it is unchanged",
        "script": "mode_a_build.py",
        "inputs": ("donor",),
        "describe": ("Regenerates the donor's filesystems and checks the result "
                     "against the original. Nothing is transplanted. This is the "
                     "gate every other build has to pass first."),
    },
    "z8": {
        "label": "Z8 candidate",
        "script": "z8_build.py",
        "inputs": ("donor", "hub", "z8"),
        "describe": "Transplants the Z8 application onto the 19.2.14 base.",
    },
    "z40": {
        "label": "Z40 candidate",
        "script": "z40_build.py",
        "inputs": ("donor", "hub", "z40"),
        "describe": "Transplants the Z40 application onto the 19.2.14 base.",
    },
    "hub": {
        "label": "Hub candidate",
        "script": "hub_build.py",
        "inputs": ("donor", "hub", "n18213"),
        "describe": "Transplants the Hub application onto the 19.2.14 base.",
    },
}

# HD Pro is available for tester builds; hardware qualification remains separate.
CAMERA_PORTS = {}
TARGETS['hdpro'] = {'label': 'HD Pro (legacy Walksnail)', 'script': 'hdpro_build.py',
                    'inputs': ('donor',), 'describe': 'Build the exact 19.2.14 HD Pro test profile.'}


def hdpro_assets_dir():
    from pathlib import Path
    return Path(__file__).resolve().parent.parent / 'firmware' / 'hdpro'


def inspect_hdpro_assets():
    from pathlib import Path
    root = hdpro_assets_dir()
    manifest = Path(__file__).resolve().parent.parent / 'tools' / 'hdpro_port_assets.json'
    # The MSI ships the same explicit resource inventory beside the resources.
    if not manifest.is_file():
        manifest = root / 'assets.json'
    doc = json.loads(manifest.read_text(encoding='utf-8'))
    for name, digest in doc['files'].items():
        path = root / name
        if not path.resolve().is_relative_to(root.resolve()):
            raise BuilderError('HDPRO_ASSET_INVALID', 'HD Pro asset path escapes its package.')
        _plain_staging_path(str(path))
        if _sha256(str(path)) != digest:
            raise BuilderError('HDPRO_ASSET_INVALID', 'HD Pro resource identity differs: ' + name)
    return root


def camera_port_blocker(target: str | None) -> dict | None:
    """Return a planning-only camera's current blocker without probing the host."""
    value = CAMERA_PORTS.get(target)
    return dict(value) if value else None


def _require_camera_payload(target: str) -> None:
    blocker = camera_port_blocker(target)
    if blocker:
        raise BuilderError(blocker["id"], blocker["what"], blocker)

#: The full per-target pipeline, read off the scripts' own argparse and the
#: gate-2 reports of the delivered candidates (docs/evidence/z8/gate2_report.json,
#: docs/evidence/mode_a/gate2_report_z40_candidate1.json, and the Hub
#: Candidate1 gate-2 report):
#:
#:   extract   extract.py <image> <dir>   -> <dir>/usrdata/fpv/ar_ldyhs_sky
#:   gate1     mode_a_build.py <donor> ...             -> gate-1 report
#:   stage1    <t>_build.py --hub --n19 --<slot>       -> an ELF, NOT an image
#:   verify    verify_<t>_app.py <hub> <n19> <new> <stage-1 report>
#:   staging   the delta's add/replace files, copied out of the extracted
#:             Hub 18.21.4 usrdata -- every tuning file, config and module in
#:             all three deltas comes from there (the reports' `sources` paths
#:             say so: x/hub/usrdata/..., x/hub18214/..., hubfs/_fpv_...)
#:   gate2     z8_gate2.py --tuning-dir | hub_gate2.py --staging |
#:             mode_a_build.py --gate2 --source DEVPATH=FILE   -> the image
#:
#: The delta tables themselves are NOT copied here. They are read out of the
#: scripts that enforce them (`delta`), so the two cannot drift.
PIPELINE = {
    "z8":  {"stage1": "z8_build.py",  "verify": "verify_z8_app.py",
            "gate2": "z8_gate2.py",   "delta": ("z8_gate2.py", "Z8_DELTA"),
            "staging": "tuning_dir",  "slot": "z8"},
    "z40": {"stage1": "z40_build.py", "verify": "verify_z40_app.py",
            "gate2": "mode_a_build.py", "delta": ("mode_a_build.py", "PHASE1_DELTA"),
            "staging": "sources",     "slot": "z40"},
    "hub": {"stage1": "hub_build.py", "verify": "verify_hub_app.py",
            "gate2": "hub_gate2.py",  "delta": ("hub_gate2.py", "HUB_DELTA"),
            "staging": "flat",        "slot": "n18213"},
}

#: Where the staged add/replace files are extracted FROM.
STAGING_SOURCE_SLOT = "hub"

#: The application every stage-1 builder reads out of a source image.
APP_DEVPATH = "/fpv/ar_ldyhs_sky"


#: What each target's FIRST stage needs, beyond the donor. These are source
#: images the application is transplanted FROM, and the builders take them as
#: --hub/--n19/--z8/--z40/--n18213.
#:
#: A BUILD IS TWO STAGES AND THE UI ONLY EVER COLLECTED ONE FILE. Stage 1
#: forward-ports the authentic application onto the newer base and emits an
#: ELF; stage 2 regenerates the donor's filesystem with that ELF and the
#: tuning binaries in it. Wiring the targets as single-stage was why BUILD
#: could not work however correct the plan looked.
STAGE1_INPUTS = {
    # n19 IS THE DONOR. Stage 1 forward-ports onto the stock 19.2.14
    # application, and gate 2 refuses any donor but 19.2.14 f166927f..., so
    # the two must be the same file; resolve_stage1_inputs() fills it from the
    # donor when it is given one rather than searching for a second copy.
    #
    # The source versions are pinned because the OUTPUT of a build is the same
    # product: a folder holding Ascent_G_Sky_19_2_14_hub_6.img and the 18.21.4
    # Hub donor would otherwise make the hub slot ambiguous with the build's
    # own result.
    "z8":  (("hub", "hub", "18.21.4"), ("n19", "normal", None), ("z8", "z8", "17.5.8")),
    "z40": (("hub", "hub", "18.21.4"), ("n19", "normal", None), ("z40", "z40", "17.5.8")),
    "hub": (("hub", "hub", "18.21.4"), ("n19", "normal", None),
            ("n18213", "normal", "18.21.3")),
}


def inspect_camera_support(builder_dir: str, target: str):
    """A present package must validate; absent packages retain source-image input."""
    try:
        return camera_support.inspect_support_pack(builder_dir, target)
    except camera_support.CameraSupportError as exc:
        raise BuilderError("CAMERA_SUPPORT_INVALID", str(exc), {"target": target}) from exc


def discover_images(folder: str, *, analyse=None) -> list:
    """Identify every .img in a folder FROM ITS BYTES, never from its name.

    Four files in this project's corpus share the name
    Ascent_G_Sky_19_2_5.img and two of them are an 18.21.4 Hub donor, so a
    filename cannot answer which image is which -- and picking the wrong one
    as a transplant source is not a failure that shows up at build time.

    Returns one row per file, including the ones that could not be read, so a
    folder with an unreadable image says so rather than quietly skipping it.
    """
    if analyse is None:
        import caddx_firmware_variant as cfv
        analyse = cfv.analyse
    rows = []
    try:
        names = sorted(os.listdir(folder))
    except OSError as e:
        raise BuilderError("IMAGE_FOLDER_UNREADABLE", str(e), {"folder": folder})
    for name in names:
        if not name.lower().endswith(".img"):
            continue
        path = os.path.join(folder, name)
        try:
            rep = analyse(path)
            v = rep.get("verdict") or {}
            av = rep.get("app_version") or {}
            rows.append({"path": path, "name": name,
                         "product": v.get("product"),
                         # APP_VERSION out of the image, not the filename. The
                         # header version can differ from it on this line --
                         # the project label, the filename and the internal
                         # version are three different things.
                         "version": av.get("APP_VERSION") if isinstance(av, dict) else None,
                         "sub_version": av.get("APP_SUB_VERSION")
                                        if isinstance(av, dict) else None,
                         "board_type": av.get("BOARD_TYPE")
                                       if isinstance(av, dict) else None,
                         "sha256": rep.get("sha256"), "ok": True})
        except Exception as e:                       # noqa: BLE001 - reported
            # NOT A FAILURE WHEN IT IS SIMPLY A DIFFERENT KIND OF IMAGE.
            # Receiver images are RKFW and Sky/Relay/Ground are ASW; a folder
            # holding both is normal, and listing the receiver images as
            # broken would be wrong about perfectly good files.
            msg = str(e)
            other = "not an ASW container" in msg
            rows.append({"path": path, "name": name, "ok": False,
                         "other_kind": other,
                         "error": ("a receiver or non-Sky image, which this "
                                   "builder does not read") if other
                                  else f"{type(e).__name__}: {msg}"})
    return rows


def resolve_stage1_inputs(target: str, images: list, *, donor: dict | None = None) -> dict:
    """Which discovered image fills each stage-1 slot, and what is missing.

    Never guesses. A slot with two candidates is reported as ambiguous rather
    than resolved by picking the first, because the two differ in exactly the
    way that matters and the build would not notice. Two rows with the SAME
    sha256 are one image under two names and count once.

    `donor`, when given, fills the n19 slot: stage 1 forward-ports onto the
    donor's own application (see STAGE1_INPUTS).
    """
    spec = STAGE1_INPUTS.get(target)
    if spec is None:
        return {"target": target, "needed": [], "found": {}, "missing": [],
                "ambiguous": {}, "candidates": {}, "complete": False}
    usable = [r for r in images if r.get("ok")]
    found, missing, ambiguous, candidates = {}, [], {}, {}
    for slot, product, version in spec:
        if slot == "n19" and donor:
            found[slot] = dict(donor, from_donor=True)
            continue
        cands, seen = [], set()
        for r in usable:
            if r.get("product") != product:
                continue
            if version is not None and not str(r.get("version") or "").startswith(version):
                continue
            key = r.get("sha256") or r.get("path") or r.get("name")
            if key in seen:
                continue
            seen.add(key)
            cands.append(r)
        if not cands:
            missing.append({"slot": slot, "product": product, "version": version})
        elif len(cands) > 1:
            ambiguous[slot] = [c["name"] for c in cands]
            candidates[slot] = cands
        else:
            found[slot] = cands[0]
    return {"target": target,
            "needed": [{"slot": s, "product": p, "version": v} for s, p, v in spec],
            "found": found, "missing": missing, "ambiguous": ambiguous,
            "candidates": candidates,
            "complete": not missing and not ambiguous}


class BuilderError(Exception):
    def __init__(self, code: str, message: str, evidence=None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.evidence = evidence or {}


# --------------------------------------------------------------------------- #
# Where the builder runs
# --------------------------------------------------------------------------- #

def host_is_windows() -> bool:
    return os.name == "nt"


def _hidden_run(*args, **kwargs):
    """subprocess.run that never flashes a console window.

    The backend runs as pythonw.exe -- a GUI process with no console of its own
    -- so any console child it spawns without asking for a hidden window gets a
    brand-new VISIBLE one. preflight() probes wsl.exe, fakeroot and several
    mkfs.ubifs candidates at firmware-page load; every one of those was a
    console flash. CREATE_NO_WINDOW + a hidden STARTUPINFO suppresses it, the
    same treatment service_mode and dev_harness already apply to their spawns.
    On Linux the flags do not exist and this is a plain passthrough.
    """
    if host_is_windows():
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        si.wShowWindow = 0  # SW_HIDE
        kwargs.setdefault("startupinfo", si)
        kwargs["creationflags"] = (kwargs.get("creationflags", 0)
                                   | subprocess.CREATE_NO_WINDOW)
    return subprocess.run(*args, **kwargs)


def wsl_path(windows_path: str, *, runner=_hidden_run) -> str:
    """Translate C:\\... to /mnt/c/... using WSL's own wslpath.

    Done by asking WSL rather than by string surgery, because a drive mapped
    somewhere other than /mnt is a real configuration and a hand-rolled
    translation gets it wrong silently -- the build would then run against a
    path that does not exist and report a missing donor.
    """
    r = runner(["wsl.exe", "--", "wslpath", "-a", "-u", str(windows_path)],
               capture_output=True, text=True, timeout=30)
    out = (r.stdout or "").strip()
    if r.returncode != 0 or not out:
        raise BuilderError("PATH_TRANSLATION_FAILED",
                           f"WSL could not translate {windows_path}.",
                           {"stderr": (r.stderr or "")[:400]})
    return out


def _probe(argv, runner) -> tuple[int, str]:
    try:
        r = runner(argv, capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError) as e:
        return 1, str(e)
    return r.returncode, ((r.stdout or "") + (r.stderr or "")).strip()


# One probe runs in the interpreter that will execute every builder stage.
# It imports the real native-backed modules and checks the exact existing ARM
# tool locations used by the builders; host/Windows Python is not a substitute.
_BUILDER_ENV_PROBE = r"""# ASCENT_FIRMWARE_ENVIRONMENT
import importlib, importlib.metadata, json, subprocess, sys
from pathlib import Path
versions, errors, tools = {}, {}, {}
for package, module in (("capstone", "capstone.arm"),
                        ("pyelftools", "elftools.elf.elffile"),
                        ("unicorn", "unicorn.arm_const")):
    try:
        importlib.import_module(module)
        versions[package] = importlib.metadata.version(package)
    except Exception as exc:
        errors[package] = type(exc).__name__ + ": " + str(exc)
root = Path("/opt/gcc-arm-none-eabi-10-2020-q4-major/bin")
for name in ("as", "ld", "nm", "objcopy", "objdump"):
    try:
        result = subprocess.run([str(root / ("arm-none-eabi-" + name)), "--version"],
                                capture_output=True, text=True, timeout=10)
        tools[name] = {"ok": result.returncode == 0,
                       "version": result.stdout.splitlines()[0] if result.stdout else result.stderr[:200]}
    except (OSError, subprocess.SubprocessError) as exc:
        tools[name] = {"ok": False, "error": type(exc).__name__ + ": " + str(exc)}
print(json.dumps({"python": sys.executable, "versions": versions, "errors": errors, "tools": tools}))
"""


def _builder_python_environment(pre, runner, *, windows, application=True):
    """Return the measured environment, selected path and last probe error."""
    if windows:
        rc, home_path = _probe(pre + ["sh", "-c",
            'printf "%s/bin/python3" "$HOME/.local/share/ascent-control/firmware-builder"'], runner)
        dedicated = home_path.strip() if rc == 0 and home_path.startswith("/") and "\n" not in home_path else None
    else:
        dedicated = os.path.expanduser("~/.local/share/ascent-control/firmware-builder/bin/python3")
    candidates = [p for p in (dedicated, "python3") if p]
    last, error = {}, "Python environment probe did not run"
    for python in candidates:
        rc, output = _probe(pre + [python, "-I", "-c", _BUILDER_ENV_PROBE], runner)
        if rc != 0:
            error = output[:500]
            continue
        try:
            env = json.loads(output)
            if not isinstance(env, dict) or not isinstance(env.get("python"), str):
                raise ValueError("missing interpreter identity")
            if not all(isinstance(env.get(n), dict) for n in ("versions", "errors", "tools")):
                raise ValueError("incomplete environment result")
            if not env["python"].startswith("/") or "\n" in env["python"]:
                raise ValueError("invalid interpreter identity")
            if not {"capstone", "pyelftools", "unicorn"}.issubset(env["versions"].keys() | env["errors"].keys()):
                raise ValueError("incomplete dependency observations")
        except (ValueError, TypeError) as exc:
            error = "Invalid Python environment probe: " + str(exc)
            continue
        last = env
        error = "; ".join(env["errors"].keys())
        if not application or not env["errors"]:
            return env, env["python"], error
    return last, None, error


#: The toolchain probe shells out five or six times. That is nothing once and
#: it is a lot when a page polls, which is what made the test suite flaky the
#: moment packer_capability() started calling this. Cached briefly, because the
#: answer is about the MACHINE and not about the request.
#:
#: Short on purpose: somebody who has just run `apt install mtd-utils` should
#: see the gate open without restarting the application. 30 s is long enough to
#: stop a poll storm and short enough that nobody notices it.
_PREFLIGHT_TTL_S = 30.0
_preflight_cache: dict = {"at": 0.0, "doc": None, "key": None}


def preflight_cache_clear() -> None:
    """Forget the cached probe. For tests, and for an explicit re-check."""
    _preflight_cache.update({"at": 0.0, "doc": None, "key": None})


def preflight(*, runner=_hidden_run, builder_dir: str | None = None,
              use_cache: bool = True, target: str | None = None) -> dict:
    """Can a build run on this machine, and if not, exactly what is missing?

    Every answer names the thing and what fixes it. "It did not work" is the
    one output this function must never produce.
    """
    if target == 'hdpro':
        try:
            inspect_hdpro_assets()
        except (OSError, ValueError, KeyError, BuilderError) as exc:
            return {'can_build': False, 'error': 'HDPRO_ASSET_INVALID', 'checks': [],
                    'blockers': [{'name': 'HD Pro resources', 'detail': str(exc), 'fix': 'Restore the release resources.'}]}
    port = camera_port_blocker(target)
    if port:
        return {"schema": "ascent.firmware_builder.preflight.v1",
                "target": target, "can_build": False, "via": None,
                "error": port["id"], "checks": [],
                "blockers": [{"name": port["id"], "detail": port["what"],
                              "fix": port["clears_when"]}], "camera_port": port}
    # Only the default probe is cached. A caller that injected its own runner
    # is testing something specific and must never be handed a stored answer
    # produced by a different runner.
    key = (builder_dir or default_builder_dir(), target)
    cacheable = use_cache and runner is _hidden_run
    if cacheable:
        import time as _t
        c = _preflight_cache
        if (c["doc"] is not None and c["key"] == key
                and (_t.monotonic() - c["at"]) < _PREFLIGHT_TTL_S):
            return dict(c["doc"])

    doc = {"schema": "ascent.firmware_builder.preflight.v1",
           "can_build": False, "via": None, "checks": [], "blockers": []}

    def check(name, ok, detail, fix=None):
        doc["checks"].append({"name": name, "ok": bool(ok), "detail": detail,
                              "fix": fix})
        if not ok:
            doc["blockers"].append({"name": name, "detail": detail, "fix": fix})
        return ok

    on_windows = host_is_windows()
    doc["via"] = "wsl" if on_windows else "native"

    if on_windows:
        try:
            bundle = native_backend.inspect_bundle(builder_dir or default_builder_dir(), target=target)
        except native_backend.NativeBundleError as exc:
            doc["via"] = "windows-native"
            check("Native builder bundle", False, str(exc),
                  "Restore the verified native builder tools, then check again.")
            return doc
        if bundle is not None:
            doc.update(via="windows-native", native_bundle=bundle,
                       builder_dir=builder_dir or default_builder_dir(),
                       mkfs_path=bundle["helper"], python_path=bundle["python"])
            rc, output = _probe([bundle["helper"], "--ascent-capabilities"], runner)
            try:
                capabilities = json.loads(output) if rc == 0 else {}
            except (ValueError, TypeError):
                capabilities = {}
            check("Native filesystem helper", isinstance(capabilities, dict)
                  and capabilities.get("schema") == "ascent.ubifs.helper.v1"
                  and capabilities.get("inventory_schema") == "ascent.ubifs.inventory.v1"
                  and capabilities.get("metadata") is True
                  and capabilities.get("host") == "windows",
                  "Metadata helper responds" if capabilities else "Metadata helper did not respond",
                  "Restore the verified native builder tools, then check again.")
            rc, version = _probe([bundle["helper"], "--version"], runner)
            check("mkfs.ubifs", rc == 0, version or "Native filesystem helper unavailable",
                  "Restore the verified native builder tools.")
            doc["mkfs_version"], doc["mkfs_version_note"] = version, None
            rc, output = _probe(native_backend.probe_argv(bundle), runner)
            try:
                env = json.loads(output) if rc == 0 else {}
                if not isinstance(env, dict):
                    env = {}
            except (ValueError, TypeError):
                env = {}
            versions, errors, tools = env.get("versions", {}), env.get("errors", {}), env.get("tools", {})
            expected = {"capstone": "5.0.9", "pyelftools": "0.33", "unicorn": "2.1.4"}
            python_ok = (rc == 0 and isinstance(versions, dict) and versions == expected
                         and isinstance(errors, dict) and not errors)
            check("Python build dependencies", python_ok,
                  "Pinned native Python dependencies import" if python_ok else "Native Python dependency probe failed",
                  "Restore the verified native builder Python dependencies.")
            doc["python_dependencies"], doc["python_dependency_errors"] = versions, errors
            doc["arm_tools"] = tools
            tools_ok = (isinstance(tools, dict) and all(isinstance(tools.get(name), dict)
                        and tools[name].get("ok") is True for name in ("as", "ld", "nm", "objcopy", "objdump")))
            check("ARM application tools", tools_ok,
                  "Native ARM tools respond" if tools_ok else "Native ARM tools unavailable",
                  "Restore the verified native ARM tools.")
            doc["can_build"] = not doc["blockers"]
            if cacheable:
                import time as _t
                _preflight_cache.update({"at": _t.monotonic(), "doc": dict(doc), "key": key})
            return doc
        rc, out = _probe(["wsl.exe", "--", "true"], runner)
        if not check("WSL", rc == 0,
                     "WSL answers" if rc == 0 else "wsl.exe did not run: " + out[:200],
                     "Install WSL and a Linux distribution, then reopen this page."):
            if cacheable:
                import time as _t
                _preflight_cache.update({"at": _t.monotonic(), "doc": dict(doc),
                                         "key": key})
            return doc
        pre = ["wsl.exe", "--"]
    else:
        pre = []

    rc, out = _probe(pre + ["fakeroot", "--version"], runner)
    check("fakeroot", rc == 0,
          out.splitlines()[0] if rc == 0 and out else "not found",
          "Install it: sudo apt install fakeroot")

    # PATH first, then the apt locations. mkfs.ubifs lives in sbin, which is
    # not on a normal user's PATH, so the explicit list is what usually finds
    # it -- but a user-local or hand-built copy on PATH is honoured too rather
    # than being reported missing while it sits right there.
    cands = list(MKFS_SEARCH)
    if on_windows:
        # Resolve inside WSL, never against the Windows host PATH. The fixed
        # command contains no operator-supplied text and does not source profiles.
        rc, out = _probe(pre + ["sh", "-c",
            'command -v mkfs.ubifs || { test -x "$HOME/.local/bin/mkfs.ubifs" && '
            'printf "%s\\n" "$HOME/.local/bin/mkfs.ubifs"; }'], runner)
        resolved = out.strip()
        on_path = resolved if rc == 0 and resolved.startswith("/") and "\n" not in resolved else None
    else:
        on_path = shutil.which(MKFS_BIN)
    if on_path:
        cands.insert(0, on_path)
    found, version = None, None
    for cand in cands:
        rc, out = _probe(pre + [cand, "--version"], runner)
        if rc == 0:
            found, version = cand, out.strip()
            break
    ok = found is not None
    detail = f"{version} at {found}" if ok else f"{MKFS_BIN} not found"
    note = None
    if ok and MKFS_KNOWN_GOOD not in (version or ""):
        # Reported, never blocked. A different version may well be fine; the
        # point is that the verified 19.2.14 images were built with 2.2.0 and a
        # result from another version should not be silently compared to them.
        note = (f"This is not {MKFS_KNOWN_GOOD}, which is the version that "
                f"produced the verified 19.2.14 images. The build is allowed; "
                f"the difference is recorded in the report.")
    check(MKFS_BIN, ok, detail,
          f"Install it: sudo apt install {MKFS_PACKAGE}")
    doc["mkfs_path"] = found
    doc["mkfs_version"] = version
    doc["mkfs_version_note"] = note

    bdir = builder_dir or default_builder_dir()
    have = os.path.isdir(bdir) and os.path.isfile(
        os.path.join(bdir, TARGETS["gate1"]["script"]))
    check("builder scripts", have,
          bdir if have else f"not shipped with this build ({bdir})",
          "Reinstall Ascent Control.")
    doc["builder_dir"] = bdir

    application = target != "gate1"
    env, python, error = _builder_python_environment(pre, runner, windows=on_windows,
                                                    application=application)
    doc["python_path"] = python
    doc["python_dependencies"] = env.get("versions", {})
    doc["python_dependency_errors"] = env.get("errors", {})
    check("Python build dependencies" if application else "Builder Python", bool(python),
          ("Isolated interpreter: " + python) if python else (error or "Python unavailable"),
          "Install WSL python3/python3-venv if absent, then run the supplied Mode A setup_builder_env.py; it installs pinned dependencies in an ASCENT-only environment.")
    doc["arm_tools"] = env.get("tools", {})
    if application:
        missing_tools = [n for n in ("as", "ld", "nm", "objcopy", "objdump")
                         if not doc["arm_tools"].get(n, {}).get("ok")]
        check("ARM application tools", not missing_tools,
              "Missing: " + ", ".join("arm-none-eabi-" + n for n in missing_tools)
              if missing_tools else "Assembler, linker, symbol, extraction and disassembly tools answer",
              "Install the GCC ARM 10-2020-q4-major toolchain at /opt/gcc-arm-none-eabi-10-2020-q4-major; these are the existing builder's required tools.")

    doc["can_build"] = not doc["blockers"]
    if cacheable:
        import time as _t
        _preflight_cache.update({"at": _t.monotonic(), "doc": dict(doc), "key": key})
    return doc


def default_builder_dir() -> str:
    runtime = os.path.dirname(os.path.abspath(__file__))
    bundled = os.path.join(runtime, BUILDER_SUBDIR)
    source = os.path.join(os.path.dirname(runtime), "firmware", "mode_a")
    return bundled if os.path.isdir(bundled) or not os.path.isdir(source) else source


# --------------------------------------------------------------------------- #
# Running a build
# --------------------------------------------------------------------------- #

def _dev_join(base: str, *parts: str) -> str:
    """Join a path that will be opened INSIDE the builder's Linux environment.

    posixpath, never os.path: on Windows os.path.join puts a backslash between
    a translated /mnt/c/... directory and a script name, and WSL then looks for
    a file whose name contains a backslash.
    """
    return posixpath.join(str(base), *[str(p) for p in parts])


def build_argv(target: str, *, builder_dir: str, mkfs: str, inputs: dict,
               out_path: str, report_path: str, gate2: bool = False) -> list[str]:
    """The exact gate-1 command line, as a list. Pure, so it can be asserted on.

    Built as a LIST and never as a string: a donor path with a space in it is
    ordinary on Windows, and string concatenation is how that becomes two
    arguments and a confusing failure.

    z8, z40 and hub ARE NOT ONE COMMAND. They used to be wired here as if they
    were, which passed gate-1 style arguments to z40_build.py (whose CLI is
    --hub --n19 --z40 --out --report, so it exited 2) and reported z8/hub's
    stage-1 ELF as if it were an image. They are refused here by name and
    built by run_variant_build(), which runs every stage.
    """
    _require_camera_payload(target)
    spec = TARGETS.get(target)
    if not spec:
        raise BuilderError("TARGET_UNKNOWN",
                           f"{target!r} is not one of: " + ", ".join(sorted(TARGETS)))
    if target in PIPELINE:
        raise BuilderError("TWO_STAGE_TARGET",
                           f"{target} is built in stages (gate 1, stage 1, staging, "
                           f"gate 2); use run_variant_build",
                           {"stages": list(STAGES)})
    if not inputs.get("donor"):
        raise BuilderError("INPUT_MISSING", "This build needs donor.",
                           {"needs": ["donor"]})
    return gate1_argv(builder_dir=builder_dir, mkfs=mkfs, donor=inputs["donor"],
                      work=inputs.get("work") or (out_path + ".work"),
                      out_path=out_path, report_path=report_path)


def gate1_argv(*, builder_dir: str, mkfs: str, donor: str, work: str,
               out_path: str, report_path: str) -> list[str]:
    """mode_a_build.py <donor> --mkfs --verifier --work --out --report.

    -I: the builder is run isolated -- a stray .py beside a donor must not be
    importable. ALWAYS PASS --verifier: left to its default, an installed
    machine dies on an import late in gate 1 after the expensive part ran.
    """
    return ["python3", "-I", _dev_join(builder_dir, "mode_a_build.py"), donor,
            "--mkfs", mkfs, "--verifier", _dev_join(builder_dir, "ascent_g_sky_image_tool.py"),
            "--work", work, "--out", out_path, "--report", report_path]


def extract_argv(*, builder_dir: str, image: str, out_dir: str) -> list[str]:
    """extract.py <image> <dir>: both UBIFS volumes, contents only."""
    return ["python3", "-I", _dev_join(builder_dir, "extract.py"), image, out_dir]


def stage1_argv(target: str, *, builder_dir: str, inputs: dict,
                out_path: str, report_path: str) -> list[str]:
    """Forward-port the authentic application onto the newer base.

    Stage 1 of two. Its inputs are the ar_ldyhs_sky ELFs EXTRACTED from the
    source images (fextent.Image opens them with ELFFile), and it emits an
    ELF, NOT an image: gate 2 then regenerates the donor's filesystem with
    that ELF in it.
    """
    spec = STAGE1_INPUTS.get(target)
    if spec is None:
        raise BuilderError("TARGET_UNKNOWN",
                           f"{target!r} has no first stage; expected one of "
                           + ", ".join(sorted(STAGE1_INPUTS)))
    missing = [slot for slot, _, _ in spec if not inputs.get(slot)]
    if missing:
        raise BuilderError("INPUT_MISSING",
                           "this build needs " + ", ".join(missing),
                           {"needs": [slot for slot, _, _ in spec]})
    argv = ["python3", "-I", _dev_join(builder_dir, PIPELINE[target]["stage1"])]
    for slot, _, _ in spec:
        argv += ["--" + slot, inputs[slot]]
    return argv + ["--out", out_path, "--report", report_path]


def verify_argv(target: str, *, builder_dir: str, hub_app: str, n19_app: str,
                new_app: str, stage1_report: str, direct_source: str | None = None) -> list[str]:
    """verify_<t>_app.py <hub_app> <n19_app> <new_app> <stage-1 report>.

    Independent of the builder's own report; exit 0 only on RESULT: PASS.
    """
    if target not in PIPELINE:
        raise BuilderError("TARGET_UNKNOWN", f"{target!r} has no verifier")
    result = ["python3", "-I", _dev_join(builder_dir, PIPELINE[target]["verify"]),
              hub_app, n19_app, new_app, stage1_report]
    if target in ("z40", "z8") and direct_source:
        result.append(direct_source)
    return result


def staged_name(target: str, devpath: str) -> str:
    """The file name each gate-2 driver looks for in its staging directory.

    z8_gate2.py: --tuning-dir / basename.  hub_gate2.py: --staging /
    devpath.replace("/", "_").  z40 takes explicit --source pairs, so the
    basename is used for tidiness only.
    """
    kind = PIPELINE[target]["staging"]
    return devpath.replace("/", "_") if kind == "flat" else posixpath.basename(devpath)


def gate2_argv(target: str, *, builder_dir: str, mkfs: str, donor: str,
               gate1_report: str, app: str, staging_dir: str, staged: list,
               work: str, out_path: str, report_path: str) -> list[str]:
    """Stage 2: regenerate the donor's usrdata with the ELF and staged files.

    `staged` is the list of device paths that were staged (non-app, non-mkdir
    delta entries); only z40 needs it, because mode_a_build.py --gate2 takes
    each file as an explicit --source DEVPATH=FILE.
    """
    if target not in PIPELINE:
        raise BuilderError("TARGET_UNKNOWN", f"{target!r} has no second stage")
    verifier = _dev_join(builder_dir, "ascent_g_sky_image_tool.py")
    script = _dev_join(builder_dir, PIPELINE[target]["gate2"])
    common = ["--work", work, "--mkfs", mkfs, "--verifier", verifier,
              "--out", out_path, "--report", report_path]
    if target == "z8":
        return ["python3", "-I", script, donor, "--gate1-report", gate1_report,
                "--app", app, "--tuning-dir", staging_dir] + common
    if target == "hub":
        return ["python3", "-I", script, donor, "--gate1-report", gate1_report,
                "--app", app, "--staging", staging_dir] + common
    argv = ["python3", "-I", script, donor] + common + [
        "--gate2", "--gate1-report", gate1_report,
        "--source", f"{APP_DEVPATH}={app}"]
    for devpath in staged:
        argv += ["--source", f"{devpath}={_dev_join(staging_dir, staged_name(target, devpath))}"]
    return argv


def read_delta(target: str, builder_dir: str) -> dict:
    """The gate-2 delta table, read out of the script that enforces it.

    Parsed with ast.literal_eval, never imported or executed: this runs in the
    host process (on Windows, in the bundled Python), and the scripts import
    Linux-side machinery this process neither has nor needs.
    """
    if target not in PIPELINE:
        raise BuilderError("TARGET_UNKNOWN", f"{target!r} has no delta")
    fname, var = PIPELINE[target]["delta"]
    path = os.path.join(builder_dir, fname)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            tree = ast.parse(fh.read(), filename=path)
    except (OSError, SyntaxError) as e:
        raise BuilderError("DELTA_UNREADABLE", f"could not read {fname}: {e}",
                           {"path": path})
    for node in tree.body:
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name) and node.targets[0].id == var):
            try:
                return ast.literal_eval(node.value)
            except ValueError as e:
                raise BuilderError("DELTA_UNREADABLE",
                                   f"{fname}:{var} is not a literal table: {e}")
    raise BuilderError("DELTA_UNREADABLE", f"{fname} defines no {var}")


def staging_list(delta: dict) -> list:
    """Device paths that need a staged source file: not the app, not a mkdir."""
    return [p for p, e in delta.items() if p != APP_DEVPATH and e[0] != "mkdir"]


def _plain_staging_path(path: str, *, directory=False):
    """Reject links, Windows reparse points and non-plain path components."""
    from pathlib import Path
    current = Path(os.path.abspath(path))
    chain = [current, *current.parents]
    for entry in reversed(chain):
        info = entry.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise BuilderError("STAGING_SOURCE_UNSAFE", "Staging requires ordinary files and directories.")
        is_leaf = entry == current
        if not (stat.S_ISDIR(info.st_mode) if not is_leaf or directory else stat.S_ISREG(info.st_mode)):
            raise BuilderError("STAGING_SOURCE_UNSAFE", "Staging requires an ordinary source file.")
    return current.lstat()


def _copy_plain_staged_file(src: str, dst: str):
    before = _plain_staging_path(src)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    handle = os.open(src, flags)
    with os.fdopen(handle, "rb") as source:
        actual = os.fstat(source.fileno())
        if (actual.st_dev, actual.st_ino) != (before.st_dev, before.st_ino) or not stat.S_ISREG(actual.st_mode):
            raise BuilderError("STAGING_SOURCE_UNSAFE", "The source changed while staging.")
        with open(dst, "xb") as destination:
            shutil.copyfileobj(source, destination)


def stage_files(target: str, delta: dict, usrdata_root: str, staging_dir: str,
                *, copy=shutil.copyfile) -> list:
    """Copy each delta file out of the extracted Hub usrdata. HOST-SIDE.

    The hashes are NOT checked here: gate 2 pins every entry by SHA-256 and
    size and refuses a mismatch itself. A missing file is refused here, by
    name, because gate 2 would only report an unopenable path.
    """
    _plain_staging_path(usrdata_root, directory=True)
    os.makedirs(staging_dir, exist_ok=True)
    _plain_staging_path(staging_dir, directory=True)
    out = []
    for devpath in staging_list(delta):
        if "\\" in devpath or ":" in devpath or any(p in (".", "..") for p in devpath.split("/")):
            raise BuilderError("STAGING_SOURCE_UNSAFE", "Invalid staging source path.")
        src = os.path.join(usrdata_root, *devpath.strip("/").split("/"))
        if not os.path.isfile(src):
            raise BuilderError("STAGING_SOURCE_MISSING",
                               f"{devpath} is not in the Hub source image",
                               {"looked_for": src})
        dst = os.path.join(staging_dir, staged_name(target, devpath))
        _plain_staging_path(src)
        if os.path.lexists(dst):
            raise BuilderError("STAGING_DESTINATION_EXISTS", "A staging file already exists; use a fresh build directory.")
        if copy is shutil.copyfile:
            _copy_plain_staged_file(src, dst)
        else:
            copy(src, dst)
        out.append({"devpath": devpath, "file": dst, "bytes": os.path.getsize(dst)})
    return out


def output_name(target: str, version: str | None, sub: str | int | None = None) -> str:
    """Ascent_G_Sky_<A>_<B>_<C>_<z40|z8|hub>_<N>.img -- a name the unit's own
    updater parses. "candidate.img" and "Ascent_G_Sky_variant_<t>.img" are
    refused on the unit with -5, which is why this exists.

    `version` is the donor's APP_VERSION read from its bytes, not its filename.
    """
    if target == 'hdpro':
        if version != '19.2.14':
            raise BuilderError('DONOR_VERSION_UNSUPPORTED', 'HD Pro requires normal 19.2.14.')
        return 'Ascent_G_Sky_19_2_14_HDPro_1.img'
    import caddx_firmware_upgrade as cfu
    parts = str(version or "").split(".")
    if len(parts) < 3 or not all(x.isdigit() for x in parts[:3]):
        raise BuilderError("VERSION_UNKNOWN",
                           f"the donor's version {version!r} cannot name an image "
                           f"the updater accepts")
    n = str(sub) if sub not in (None, "") and str(sub).isdigit() else "1"
    name = (f"Ascent_G_Sky_{parts[0]}_{parts[1]}_{parts[2]}_"
            f"{cfu.VARIANT_TOKENS[target][0]}_{n}.img")
    if not cfu.variant_filename_ok(name, target):
        raise BuilderError("OUTPUT_NAME_REFUSED", f"{name} would be refused by the updater")
    return name


def check_output_name(name: str, target: str) -> str:
    if target == 'hdpro':
        if name != 'Ascent_G_Sky_19_2_14_HDPro_1.img':
            raise BuilderError('OUTPUT_NAME_REFUSED', 'Use Ascent_G_Sky_19_2_14_HDPro_1.img for this exact donor profile.')
        return name
    import caddx_firmware_upgrade as cfu
    base = os.path.basename(str(name or ""))
    if not base.lower().endswith(".img"):
        base += ".img"
    if not cfu.variant_filename_ok(base, target):
        raise BuilderError("OUTPUT_NAME_REFUSED",
                           f"{base} is a name the {target} updater refuses (-5). It must "
                           f"look like Ascent_G_Sky_<A>_<B>_<C>_{target}_<N>.img",
                           {"name": base})
    return base


def make_translator(*, windows: bool | None = None, runner=_hidden_run, backend=None):
    """Host path -> the path the builder sees. Identity on Linux; wslpath on
    Windows, cached, so a dozen arguments do not cost a dozen WSL launches."""
    if windows is None:
        windows = host_is_windows()
    if not windows or (backend or {}).get("via") == "windows-native":
        return lambda p: str(p)
    cache: dict = {}

    def tr(p):
        p = str(p)
        if p not in cache:
            cache[p] = wsl_path(p, runner=runner)
        return cache[p]
    return tr


STAGES = ("extract", "gate1", "stage1", "verify", "staging", "gate2")


def _run_step(runner, argv, wrap, timeout):
    try:
        r = runner(wrap(argv), capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None, "", f"timed out after {timeout} s"
    except OSError as e:
        return None, "", str(e)
    return r.returncode, (r.stdout or ""), (r.stderr or "")


def _read(path):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read()
    except OSError:
        return ""


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _verified_image_identity(path: str, report: dict) -> dict:
    """Tie the disk artifact to the image bytes already accepted by gate 2."""
    image = report.get("image") if isinstance(report, dict) else None
    if not isinstance(image, dict) or type(image.get("bytes")) is not int or not isinstance(image.get("sha256"), str):
        raise BuilderError("OUTPUT_IDENTITY_MISMATCH", "Gate 2 omitted the verified image identity.")
    _plain_staging_path(path)
    digest, size = _sha256(path), os.path.getsize(path)
    if digest != image["sha256"] or size != image["bytes"]:
        raise BuilderError("OUTPUT_IDENTITY_MISMATCH", "The image on disk differs from the verified image; no image is offered.")
    return {"sha256": digest, "bytes": size}


def run_variant_build(target: str, *, donor: str, sources: dict, work_dir: str,
                      out_name: str, builder_dir: str, mkfs: str,
                      runner=_hidden_run, translate=None, wrap=None,
                      on_stage=None, copy=shutil.copyfile,
                      timeout: int = 3600, python_path: str = "python3", backend=None) -> dict:
    """gate 1 -> stage 1 -> verify -> staging -> gate 2, as one job.

    All arguments are HOST paths except `mkfs`, which preflight found inside
    the builder's environment. Every path handed to the builder goes through
    `translate` -- inputs, outputs, the builder directory, the verifier --
    because on Windows the builder runs in WSL and a C:\\ path does not exist
    there.

    `image` is set ONLY when gate 2's own report says PASS and the gate-2
    process exited 0 and the file exists. The stage-1 product is an ELF and is
    reported as `app`, never as `image`. A failing stage stops the job and is
    reported with the builder's own output, unaltered.
    """
    if target == 'hdpro':
        assets = inspect_hdpro_assets()
        out_name = check_output_name(out_name, target)
        os.makedirs(work_dir, exist_ok=True)
        output = os.path.join(work_dir, out_name)
        report_path = output + '.report.json'
        tr = translate or str
        argv = [python_path, '-I', tr(str(assets / 'hdpro_build.py')), '--donor', tr(donor),
                '--mode-a', tr(builder_dir), '--helper', tr(mkfs), '--work', tr(os.path.join(work_dir, 'hdpro-work')),
                '--out', tr(output), '--report', tr(report_path)]
        emit = on_stage or (lambda *_a: None)
        emit('gate2', 'running', 'HD Pro donor, application and image checks')
        rc, stdout, stderr = _run_step(runner, argv, wrap or (lambda a: wrap_for_host(a, backend=backend)), timeout)
        summary = summarise_report(_read(report_path))
        result = {'ok': False, 'target': target, 'image': None, 'hardware_qualified': False,
                  'stages': [{'stage': 'gate2', 'exit_code': rc, 'stdout': stdout[-4000:], 'stderr': stderr[-4000:]}]}
        if rc == 0 and summary['pass'] is True:
            identity = _verified_image_identity(output, summary['report'])
            result.update(ok=True, gate2_report=summary['report'], image={'kind':'image', 'path':output,
                          'name':out_name, **identity, 'gate2_report_path':report_path})
        else:
            result.update(error='STAGE_FAILED', failed_stage='gate2', message='HD Pro image checks failed; no image is offered.')
        result['stages'][0]['ok'] = result['ok']
        emit('gate2', 'pass' if result['ok'] else 'fail', 'HD Pro donor, application and image checks')
        return result
    _require_camera_payload(target)
    if target not in PIPELINE:
        raise BuilderError("TARGET_UNKNOWN",
                           f"{target!r} is not one of: " + ", ".join(sorted(PIPELINE)))
    slot = PIPELINE[target]["slot"]
    support = inspect_camera_support(builder_dir, target)
    use_support = support is not None and not any(sources.values())
    need = {} if use_support else {"hub": sources.get("hub"), slot: sources.get(slot)}
    missing = [k for k, v in need.items() if not v] + ([] if donor else ["donor"])
    if missing:
        raise BuilderError("INPUT_MISSING", "this build needs " + ", ".join(missing),
                           {"needs": ["donor", "hub", slot]})
    out_name = check_output_name(out_name, target)
    tr = translate or (lambda p: str(p))
    host_wrap = wrap or (lambda argv: wrap_for_host(argv, backend=backend))

    def wrap(argv):
        # Bind every stage to the exact interpreter that passed preflight.
        # The caller supplies this host capability, never an HTTP command body.
        bound = list(argv)
        if bound and bound[0] == "python3":
            bound[0] = python_path
        return host_wrap(bound)

    emit = on_stage or (lambda *_a, **_k: None)
    bdir = tr(builder_dir)
    delta = read_delta(target, builder_dir)

    j = os.path.join
    x_dir = j(work_dir, "extract")
    paths = {
        "gate1_img": j(work_dir, "gate1_rebuilt.img"),
        "gate1_report": j(work_dir, "gate1_report.json"),
        "gate1_work": j(work_dir, "gate1_work"),
        "app": j(work_dir, f"{target}_ar_ldyhs_sky.elf"),
        "app_report": j(work_dir, f"{target}_app_build_report.json"),
        "staging": j(work_dir, "staging"),
        "gate2_work": j(work_dir, "gate2_work"),
        "out": j(work_dir, out_name),
        "gate2_report": j(work_dir, out_name[:-4] + "_gate2_report.json"),
    }
    os.makedirs(work_dir, exist_ok=True)

    def app_of(name):
        return j(x_dir, name, "usrdata", "fpv", "ar_ldyhs_sky")

    stages = []
    result = {"ok": False, "target": target, "stages": stages, "image": None,
              "app": None, "out_name": out_name, "work_dir": work_dir}

    def step(name, argv, *, report=None, detail=None):
        emit(name, "running", detail)
        rc, out, err = _run_step(runner, argv, wrap, timeout)
        rec = {"stage": name, "exit_code": rc, "argv": argv,
               "stdout": out[-4000:], "stderr": err[-4000:]}
        if detail:
            rec["detail"] = detail
        ok = rc == 0
        if report is not None:
            summ = summarise_report(_read(report))
            rec["verdict"] = summ.get("pass")
            rec["report_parse_error"] = summ.get("parse_error")
            rec["report_path"] = report
            ok = ok and summ.get("pass") is True
            if name == "gate2":
                result["gate2_report"] = summ.get("report")
        rec["ok"] = ok
        stages.append(rec)
        emit(name, "pass" if ok else "fail", detail)
        return ok

    def fail(name, message):
        result["failed_stage"] = name
        result["error"] = "STAGE_FAILED"
        result["message"] = message
        return result

    # Validate and materialize included support before running a donor stage.
    # Source-image mode remains available for source-only checkouts.
    if use_support:
        emit("support", "running", None)
        try:
            roots = camera_support.materialize_target(support["pack_dir"], target, x_dir)
            for role in ("hub", slot):
                if role not in roots or not os.path.isfile(app_of(role)):
                    raise camera_support.CameraSupportError("Camera support application is missing")
        except (camera_support.CameraSupportError, OSError) as exc:
            stages.append({"stage": "support", "ok": False, "stderr": str(exc)})
            emit("support", "fail", None)
            return fail("support", str(exc))
        result["camera_support"] = {"pack_id": support["pack_id"], "source_versions": support["source_versions"]}
        stages.append({"stage": "support", "ok": True, "pack_id": support["pack_id"]})
        emit("support", "pass", None)
        extract_inputs = (("n19", donor),)
    else:
        extract_inputs = (("n19", donor), ("hub", sources["hub"]), (slot, sources[slot]))
    # ---- extract: the donor application and any external source images ----
    for name, image in extract_inputs:
        if not step("extract", extract_argv(builder_dir=bdir, image=tr(image),
                                            out_dir=tr(j(x_dir, name))),
                    detail=name):
            return fail("extract", f"could not extract {name} ({os.path.basename(image)})")
        if not os.path.isfile(app_of(name)):
            stages[-1]["ok"] = False
            return fail("extract", f"{name} has no /fpv/ar_ldyhs_sky")

    # ---- gate 1: the donor rebuilds and verifies, unmodified ----------------
    if not step("gate1", gate1_argv(builder_dir=bdir, mkfs=mkfs, donor=tr(donor),
                                    work=tr(paths["gate1_work"]),
                                    out_path=tr(paths["gate1_img"]),
                                    report_path=tr(paths["gate1_report"])),
                report=paths["gate1_report"]):
        return fail("gate1", "gate 1 did not pass on this donor; nothing was transplanted")

    # ---- stage 1: the forward-ported application (an ELF) -------------------
    s1_inputs = {"hub": tr(app_of("hub")), "n19": tr(app_of("n19")),
                 slot: tr(app_of(slot))}
    emit("stage1", "running", None)
    rc, out, err = _run_step(runner, stage1_argv(target, builder_dir=bdir, inputs=s1_inputs,
                                                 out_path=tr(paths["app"]),
                                                 report_path=tr(paths["app_report"])),
                             wrap, timeout)
    built_app = rc == 0 and os.path.isfile(paths["app"])
    rec = {"stage": "stage1", "exit_code": rc, "ok": built_app,
           "stdout": out[-4000:], "stderr": err[-4000:], "report_path": paths["app_report"]}
    stages.append(rec)
    emit("stage1", "pass" if built_app else "fail", None)
    if not built_app:
        return fail("stage1", "stage 1 produced no application")
    result["app"] = {"kind": "elf", "path": paths["app"], "sha256": _sha256(paths["app"]),
                     "bytes": os.path.getsize(paths["app"]),
                     "expected_sha256": (delta.get(APP_DEVPATH) or (None, None))[1]}

    # ---- verify: the independent static + emulated checks -------------------
    if not step("verify", verify_argv(target, builder_dir=bdir,
                                      hub_app=s1_inputs["hub"], n19_app=s1_inputs["n19"],
                                      new_app=tr(paths["app"]),
                                      stage1_report=tr(paths["app_report"]),
                                      direct_source=s1_inputs.get(target))):
        return fail("verify", "the application did not verify")

    # ---- staging: delta files out of the extracted Hub usrdata --------------
    emit("staging", "running", None)
    try:
        staged = stage_files(target, delta, j(x_dir, "hub", "usrdata"),
                             paths["staging"], copy=copy)
    except (BuilderError, OSError) as e:
        stages.append({"stage": "staging", "ok": False,
                       "stderr": getattr(e, "message", str(e))})
        emit("staging", "fail", None)
        return fail("staging", getattr(e, "message", str(e)))
    stages.append({"stage": "staging", "ok": True, "files": staged})
    emit("staging", "pass", None)

    # ---- gate 2: the image --------------------------------------------------
    ok = step("gate2", gate2_argv(target, builder_dir=bdir, mkfs=mkfs, donor=tr(donor),
                                  gate1_report=tr(paths["gate1_report"]),
                                  app=tr(paths["app"]), staging_dir=tr(paths["staging"]),
                                  staged=staging_list(delta),
                                  work=tr(paths["gate2_work"]),
                                  out_path=tr(paths["out"]),
                                  report_path=tr(paths["gate2_report"])),
              report=paths["gate2_report"])
    if not ok:
        return fail("gate2", "gate 2 did not pass; no image is offered")
    if not os.path.isfile(paths["out"]):
        stages[-1]["ok"] = False
        return fail("gate2", "gate 2 reported PASS but wrote no image")
    try:
        identity = _verified_image_identity(paths["out"], result.get("gate2_report"))
    except BuilderError as exc:
        stages[-1]["ok"] = False
        return fail("gate2", exc.message)
    actual_sha, actual_bytes = identity["sha256"], identity["bytes"]
    result["image"] = {"kind": "image", "path": paths["out"], "name": out_name,
                       "sha256": actual_sha,
                       "bytes": actual_bytes,
                       "gate2_report_path": paths["gate2_report"]}
    result["ok"] = True
    return result


def wrap_for_host(argv: list[str], *, backend=None) -> list[str]:
    """Run checked native stages directly; retain the existing WSL fallback."""
    if (backend or {}).get("via") == "windows-native":
        return native_backend.stage_argv(argv, backend["native_bundle"])
    return (["wsl.exe", "--"] + argv) if host_is_windows() else list(argv)




def summarise_report(report_text: str) -> dict:
    """What the builder decided, taken from ITS report and not re-derived.

    A missing or unparsable report is reported as unknown. It is never treated
    as a pass, and it is never treated as a failure either: the build may well
    have succeeded and the report may be the only thing that went wrong, and an
    operator needs to be told which of those happened.
    """
    out = {"pass": None, "report": None, "parse_error": None}
    if not report_text:
        out["parse_error"] = "the builder wrote no report"
        return out
    try:
        rep = json.loads(report_text)
    except (ValueError, TypeError) as e:
        # Unparsable => UNKNOWN, never a pass. The old code regex-scanned the raw
        # text for a `"PASS": true` token, which (a) contradicts this docstring
        # and (b) on a truncated report could match a NESTED sub-check's PASS
        # rather than the top-level verdict -- "bad image reported as good" for
        # any consumer that trusts pass without also checking the exit code.
        # Red-team 2026-10-12 (docs/... variant findings). pass stays None.
        out["parse_error"] = f"the report is not valid JSON ({e})"
        return out
    out["report"] = rep
    if isinstance(rep, dict) and "PASS" in rep:
        # `is True`, not bool(): a non-bool truthy PASS is not a clean pass.
        out["pass"] = rep["PASS"] is True
    return out
