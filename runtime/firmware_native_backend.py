"""Checked native Windows tool bundle for the existing offline image pipeline.

No downloads or setup occur during discovery. A missing or unqualified bundle
leaves the existing WSL backend available; a malformed present bundle refuses.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import sys

SCHEMA = "ascent.firmware.native_bundle.v1"
TARGETS = {"gate1", "z8", "z40", "hub"}


class NativeBundleError(ValueError):
    pass


def _inside(root, relative):
    if (not isinstance(relative, str) or not relative or "\\" in relative
            or ":" in relative or "\x00" in relative
            or PurePosixPath(relative).is_absolute()
            or str(PurePosixPath(relative)) != relative
            or any(part in (".", "..") for part in relative.split("/"))):
        raise NativeBundleError("Invalid native bundle path")
    path = root.joinpath(*relative.split("/"))
    if not path.resolve().is_relative_to(root.resolve()):
        raise NativeBundleError("Native bundle path escapes its directory")
    return path


def inspect_bundle(builder_dir, *, bundle_dir=None, target=None):
    """Verify every shipped byte and the exact scripts covered by qualification."""
    root = (Path(bundle_dir) if bundle_dir else
            Path(builder_dir).parent / "native_builder" / "windows-x64")
    manifest = root / "manifest.json"
    if not manifest.exists():
        return None
    try:
        document = json.loads(manifest.read_text(encoding="utf-8"))
        if not isinstance(document, dict) or document.get("schema") != SCHEMA:
            raise NativeBundleError("Unknown native builder bundle schema")
        qualified = document.get("targets")
        if (not isinstance(qualified, list) or not qualified
                or any(value not in TARGETS for value in qualified)
                or len(set(qualified)) != len(qualified)):
            raise NativeBundleError("Invalid native builder qualification targets")
        wanted = {target} if target in TARGETS else TARGETS
        if not wanted.issubset(qualified):
            return None
        files, scripts = document.get("files"), document.get("builder_files")
        if not isinstance(files, dict) or not files or not isinstance(scripts, dict) or not scripts:
            raise NativeBundleError("Native builder hashes are missing")
        observed = {p.relative_to(root).as_posix() for p in root.rglob("*")
                    if p.is_file() and p != manifest and "__pycache__" not in p.parts}
        if observed != set(files):
            raise NativeBundleError("Native builder file inventory differs")
        for name, digest in files.items():
            if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise NativeBundleError("Invalid native builder file hash")
            path = _inside(root, name)
            if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                raise NativeBundleError("Native builder file hash differs")
        required_scripts = {p.name for p in Path(builder_dir).glob("*.py")}
        if set(scripts) != required_scripts:
            raise NativeBundleError("Native builder script coverage differs")
        for name, digest in scripts.items():
            path = _inside(Path(builder_dir), name)
            if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                raise NativeBundleError("Native builder qualification does not cover these scripts")
        helper = _inside(root, document.get("helper"))
        dependencies = _inside(root, document.get("dependencies"))
        arm_tools = _inside(root, document.get("arm_tools"))
        if helper.relative_to(root).as_posix() not in files or not dependencies.is_dir() or not arm_tools.is_dir():
            raise NativeBundleError("Native builder components are missing")
        for name in ("as", "ld", "nm", "objcopy", "objdump"):
            if (arm_tools / ("arm-none-eabi-" + name + ".exe")).relative_to(root).as_posix() not in files:
                raise NativeBundleError("Native ARM tool inventory is incomplete")
        python = Path(sys.executable).with_name("python.exe")
        if not python.is_file():
            python = Path(sys.executable)
        return {"bundle_dir": str(root.resolve()), "helper": str(helper.resolve()),
                "dependencies": str(dependencies.resolve()), "arm_tools": str(arm_tools.resolve()),
                "python": str(python), "targets": qualified,
                "manifest_sha256": hashlib.sha256(manifest.read_bytes()).hexdigest()}
    except NativeBundleError:
        raise
    except (OSError, ValueError, TypeError) as exc:
        raise NativeBundleError("Cannot verify native builder bundle: " + str(exc)) from exc


# Isolated child processes receive only paths selected by the checked host bundle.
# The HTTP build request cannot supply these settings or Python source.
STAGE_BOOTSTRAP = r'''
import json, os, runpy, sys
settings = json.loads(sys.argv[1])
sys.path.insert(0, settings["dependencies"])
os.environ["ASCENT_ARM_TOOLCHAIN_DIR"] = settings["arm_tools"]
os.environ["ASCENT_MKFS_INVENTORY"] = "1"
sys.dont_write_bytecode = True
sys.argv = settings["argv"]
runpy.run_path(sys.argv[0], run_name="__main__")
'''


def stage_argv(argv, bundle):
    """Wrap an existing isolated Python stage without a shell or WSL process."""
    if len(argv) < 3 or argv[1] != "-I" or not str(argv[2]).endswith(".py"):
        raise NativeBundleError("Native backend requires an isolated Python script")
    settings = {key: bundle[key] for key in ("dependencies", "arm_tools")}
    settings["argv"] = list(argv[2:])
    return [bundle["python"], "-I", "-c", STAGE_BOOTSTRAP,
            json.dumps(settings, ensure_ascii=False)]


ENVIRONMENT_PROBE = r'''
import importlib, importlib.metadata, json, subprocess, sys
from pathlib import Path
settings = json.loads(sys.argv[1])
sys.path.insert(0, settings["dependencies"])
sys.dont_write_bytecode = True
versions, errors, tools = {}, {}, {}
for package, module in (("capstone", "capstone.arm"), ("pyelftools", "elftools.elf.elffile"), ("unicorn", "unicorn.arm_const")):
    try:
        importlib.import_module(module)
        versions[package] = importlib.metadata.version(package)
    except Exception as exc:
        errors[package] = type(exc).__name__ + ": " + str(exc)
for name in ("as", "ld", "nm", "objcopy", "objdump"):
    result = subprocess.run([str(Path(settings["arm_tools"]) / ("arm-none-eabi-" + name + ".exe")), "--version"], capture_output=True, text=True, timeout=10)
    tools[name] = {"ok": result.returncode == 0, "version": result.stdout.splitlines()[0] if result.stdout else result.stderr[:200]}
print(json.dumps({"python": sys.executable, "versions": versions, "errors": errors, "tools": tools}))
'''


def probe_argv(bundle):
    settings = {key: bundle[key] for key in ("dependencies", "arm_tools")}
    return [bundle["python"], "-I", "-c", ENVIRONMENT_PROBE, json.dumps(settings)]
