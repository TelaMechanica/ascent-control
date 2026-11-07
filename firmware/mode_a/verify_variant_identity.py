"""Offline execution gate for the pinned updater's actual command-60 identity hook.

Runs the original hardware selector plus the new hook in Unicorn. Only libc calls
are substituted. No receiver, network, serial, or firmware process is opened.
"""
from __future__ import annotations
import hashlib
from pathlib import Path
import tempfile
from emu import Emu, STACK_TOP, SENTINEL
from unicorn.arm_const import UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7, UC_ARM_REG_R8, UC_ARM_REG_SP, UC_ARM_REG_PC
from variant_identity import EXPECTED_SHA, CALL_VA


class IdentityEmu(Emu):
    def _libc(self, name):
        if name == "strncpy":
            a = self._args(3)
            self.mu.mem_write(a[0], self.cstr(a[1])[:a[2]].ljust(a[2], b"\0"))
            return a[0]
        if name == "snprintf":
            a = self._args(8)
            value = self._fmt(self.cstr(a[2]), a[3:])
            if a[1]:
                self.mu.mem_write(a[0], value[:a[1] - 1] + b"\0")
            return len(value)
        return super()._libc(name)


def verify_identity(updater: bytes, subtype: str) -> dict:
    if hashlib.sha256(updater).hexdigest() != EXPECTED_SHA[subtype]:
        raise ValueError("identity execution gate received an unpinned updater")
    cases = []
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "updater.elf"
        path.write_bytes(updater)
        for flag in (0, 1):
            for board, base, hw in ((0x10, "Ascent_GT_pro", "Ascent-GT-Pro"),
                                    (0x30, "Ascent_GT_MAX_HF", "Ascent-GT-MAX-HF"),
                                    (0x80, "Ascent_GT_MAX_WF", "Ascent-GT-MAX-WF"),
                                    (0x20, "Ascent_GT", None)):
                e = IdentityEmu(path, {0x1b6f8: "strcmp", 0x1b578: "strncpy",
                    0x1b4c4: "snprintf", 0x1b674: "strlen", 0x1b0d8: "printf", 0x1b270: "memcpy"})
                # Fixed donor literal references: hardware role and alternate-brand flag.
                ota = e.u32(0x22640) + 0x22536
                extra = e.u32(0x2264c) + 0x2258a
                e.mu.mem_write(ota + 4, b"\x04")
                e.mu.mem_write(extra + 109, bytes([flag]))
                name = e.alloc(80, b"\0" * 64 + b"N" * 16)
                hardware = STACK_TOP - 0x1000 + 764
                e.mu.mem_write(hardware - 16, b"L" * 16 + b"UNCHANGED\0".ljust(32, b"\0") + b"R" * 16)
                regs = (UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7, UC_ARM_REG_R8)
                for reg in regs:
                    e.mu.reg_write(reg, 0x12340000 + reg)
                # Execute the real patched call-site BL, then stop before the next stock instruction.
                e.call(CALL_VA, name, 64, 0x10, board, stop={CALL_VA + 4})
                wanted = base.replace("Ascent_", "Roi_") if flag else base
                if not flag and hw:
                    wanted += "_" + subtype
                    wanted_hw = f"{hw}-{subtype}-V1.0-{board >> 4}.{board & 15}"
                else:
                    wanted_hw = "UNCHANGED"
                assert e.cstr(name).decode() == wanted, (flag, board, e.cstr(name), wanted)
                assert e.cstr(hardware).decode() == wanted_hw
                assert bytes(e.mu.mem_read(name + 64, 16)) == b"N" * 16
                assert bytes(e.mu.mem_read(hardware - 16, 16)) == b"L" * 16
                assert bytes(e.mu.mem_read(hardware + 32, 16)) == b"R" * 16
                assert e.reg(UC_ARM_REG_SP) == STACK_TOP - 0x1000
                assert e.reg(UC_ARM_REG_PC) == CALL_VA + 4
                for reg in regs:
                    assert e.reg(reg) == 0x12340000 + reg
                cases.append({"brand_flag": flag, "board": board, "name": wanted,
                              "hardware": wanted_hw, "bounds_registers_stack": "PASS"})
    return {"PASS": True, "subtype": subtype, "cases": cases,
            "scope": "host emulation; physical camera behavior NOT TESTED"}
