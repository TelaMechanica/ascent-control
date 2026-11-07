"""Resolve the existing ARM tools for Linux or an external Windows tool bundle."""
from __future__ import annotations

import os
from pathlib import Path

DEFAULT_LINUX_TOOLS = Path("/opt/gcc-arm-none-eabi-10-2020-q4-major/bin")
NAMES = frozenset(("as", "ld", "nm", "objcopy", "objdump"))


def tools_directory():
    configured = os.environ.get("ASCENT_ARM_TOOLCHAIN_DIR")
    if configured:
        directory = Path(configured)
        if not directory.is_absolute():
            raise ValueError("ARM toolchain directory must be absolute")
        return directory
    return DEFAULT_LINUX_TOOLS


def tool(name, directory=None):
    if name not in NAMES:
        raise ValueError("Unknown ARM builder tool")
    return str(Path(directory or tools_directory()) /
               ("arm-none-eabi-" + name + (".exe" if os.name == "nt" else "")))
