#!/usr/bin/env python3
"""Z8 direct-attached IMX586 transplant into 19.2.14 ar_ldyhs_sky.

SEPARATE engine. It REUSES the proven Z40 Mode A machinery by importing z40_build as a
library (the relocation engine, two-pass code allocation, GOT handling, ELF emit, Thumb
encoders, object_starts) and SUBCLASSES its Build. It does NOT modify z40_build.py, the
frozen Z40 Candidate1, or any Z40 artefact. The shared build-config module globals that the
reused parent methods read are set on the imported module object at build time (process-local;
the file on disk is untouched).

Z8 architecture (ratified; see docs/Z8_19_2_14_MINIMAL_PATCH_PLAN.md §8):
  - single IMX586, E1 0x16, E2 586, no renumbering, no Farsight, no PS5280, no dual handover,
    no Hub probe/node/routing, no sensor_prepare_dual, GPIO58 only.

Build parallels the Z40 build with four swaps: object g_sns_farsight_obj -> g_sns_imx586_obj
(single), one added table row (no row-0x0b retarget), GPIO58 bracket inside do_init_vi_vpss
(instead of sensor_prepare_dual + zoom_process), z8 tuning filename.
"""
from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
import z40_build as Z
from z40_build import die, enc_bl, enc_bw, NOP16, assemble, object_starts
import fextent as FE

# ----------------------------------------------------------------- Z8 configuration --
IMX586_UNIT = (0x100b5c, 0x1031f0)      # contiguous single-imx586 driver (35 funcs, clean)
IMX586_DATA = (0x2995e0, 0x299fa8)      # exclusive imx586 .data (incl g_sns_imx586_obj, u32LastZoomRatio)
IMX586_BSS = (0x2d1b50, 0x2d3008)       # exclusive imx586 .bss (os02k10 ctx at 0x2d1b40 is below)
MODE_TBL = (0x290504, 0x2905b8)         # g_imx586_mode_tbl (.data.rel.ro, pure data)
HUB_TABLE = 0x2936fc                    # Hub sensor-table base (same as Z40 build)
HUB_GOT = 0x2916cc
N19_GOT = 0x263700
GOT_MAP_SYM = {0x514: 0x4f4, 0x54c: 0x52c}          # stderr, __stack_chk_guard (same offsets as Z40)
GLUE_DATA = [(0x294b28, 4, "data"), (0x294b2c, 4, "data"), (0x29df98, 36, "bss"),
             (0x29fde4, 4, "bss"), (0x29fde8, 4, "bss")]     # shared zoom/msp glue data (as Z40)
RODATA_CONSTS = [(0x1c24e4, 12)]                     # VPSS low-delay attr {1,200,0} (as Z40)
GLUE_NAMED = ["fpv_sky_streamzoom_init", "fpv_msp_rc_config_init", "fpv_msp_rc_config_get",
              "fpv_set_msp_rc_zoomctrl", "fpv_set_msp_zoomctrl", "fpv_get_msp_zoomctrl",
              "mspSerialParaINAVRcSlot", "fpv_set_vpss_rotation", "init_vpss", "uninit_vpss",
              "set_gpio_val", "single_imx586_load_pq_bin", "StreamZoom_load_pq_bin"]
GLUE_STATICS = {"set_scale": 0x6986c, "zoom_thread": 0x6a874,
                "vpss_start_helper": 0x674e4, "zoom_process": 0x69dc8}   # shared streamzoom helpers
# G1 call redirects (supersedes §8.4): resolve Hub dual-sensor / Hub-expander leaf ops to the
# single-sensor Z8 behavior. farsight digital-zoom -> the carried single imx586_zoom_ctrl; the
# sensor-handover / init-exposure / expander ops -> a no-op stub (those paths never run on Z8).
FAR_TO_IMX = {"farsight_imx586_zoom_ctrl": "imx586_zoom_ctrl"}
FAR_TO_NOP = {"farsight_set_sel_sensor", "farsight_imx586_set_init_exposure",
              "farsight_ps5280_set_init_exposure"}
HUB_EXPANDER_ADDRS = {0x69980, 0x699e4}      # Hub I2C expander helpers -> z8_nop
CALL_REDIRECT = {"fpv_hub_check_current_cam": "z8_cam"}   # force the z8 filename branch
NEW_RX_VA = 0x2b0000
ATTR_SIZES = {2: 0x44, 3: 0xc8, 4: 0x2c, 5: 0x78, 6: 0x20, 7: 0x20}   # isp,combo,vichn,videv,vipipe,mipiext


class Z8Build(Z.Build):
    dual_sensor_lanes = False
    direct_camera_routing = False  # Single sensor: no Z40 handover.
    def __init__(self, hub_path, n19_path, z8_path):
        super().__init__(hub_path, n19_path)
        self.z8_path = z8_path
        self.z40_path = z8_path          # parent _sources reads self.z40_path for the rotation fmt string

    # ---- carry closure --------------------------------------------------------------
    def carry_functions(self):
        H = self.H
        roots = dict(GLUE_STATICS)
        roots.update({n: H.syms[n][0] for n in GLUE_NAMED})
        imx = [n for n, v in H.syms.items() if n.startswith("imx586_") and v[2] == "STT_FUNC"]
        roots.update({n: H.syms[n][0] for n in imx})
        obj = H.syms["g_sns_imx586_obj"]
        for i, w in enumerate(struct.unpack_from("<12I", H.data, H.off(obj[0]))):
            if w and H.section_of(w) == ".text":
                roots[f"imx586_cb{i}"] = w
        funcs, queue = {}, list(roots.items())
        while queue:
            n, a = queue.pop()
            e = a & ~1
            if any(f.entry == e for f in funcs.values()):
                continue
            f = FE.extent(H, a)
            funcs[n] = f
            for _, _, t in f.pic:
                if H.section_of(t) == ".text":
                    queue.append((f"fptr_{t:#x}", t))
            for _, t, k in f.calls:
                if t and IMX586_UNIT[0] <= (t & ~1) < IMX586_UNIT[1] and (t & ~1) not in H.func_starts:
                    queue.append((f"static_{t:#x}", t))
        canon = {(a & ~1): n for n, a in roots.items()}
        funcs = {canon.get(f.entry, n): f for n, f in funcs.items()}
        for n, f in funcs.items():
            if IMX586_UNIT[0] <= f.entry < IMX586_UNIT[1] and not (IMX586_UNIT[0] <= f.lo and f.hi <= IMX586_UNIT[1]):
                die(f"{n} spills out of the imx586 unit")
        return funcs

    # ---- target mapping -------------------------------------------------------------
    def map_text(self, t):
        e = t & ~1
        if IMX586_UNIT[0] <= e < IMX586_UNIT[1]:
            return self.unit_new + (t - IMX586_UNIT[0])
        for n, f in self.glue_blocks.items():
            if f["lo"] <= e < f["hi"]:
                return f["new"] + (t - f["lo"])
        return None

    def map_call(self, t, kind):
        """G1: redirect Hub dual-sensor / expander leaf calls to single-sensor Z8 behavior."""
        if t is not None:
            tt = t & ~1
            name = self.H.name_of(t)
            if tt == 0x698b4:
                # The shared initializer contains an unreachable Z40 handover
                # branch. Single-sensor Z8 must never inherit its full restart.
                return ("redirect", "dual_sensor_restart_unavailable", self.sym['z8_nop'])
            if name in FAR_TO_IMX:
                self.report.setdefault("g1_redirects", []).append({"from": name, "to": FAR_TO_IMX[name]})
                return ("redirect", name, self.sym[FAR_TO_IMX[name]])
            if name in FAR_TO_NOP:
                self.report.setdefault("g1_redirects", []).append({"from": name, "to": "z8_nop"})
                return ("redirect", name, self.sym["z8_nop"])
            if tt in HUB_EXPANDER_ADDRS:
                self.report.setdefault("g1_redirects", []).append({"from": f"hub_expander@{tt:#x}", "to": "z8_nop"})
                return ("redirect", "hub_expander", self.sym["z8_nop"])
            if name == "fpv_hub_check_current_cam":
                return ("redirect", name, self.sym["z8_cam"])
        return super().map_call(t, kind)

    def map_data(self, t, user):
        H = self.H
        if t == HUB_GOT:
            return ("got_base", N19_GOT)
        sec = H.section_of(t)
        if sec == ".text":
            m = self.map_text(t)
            if m is None:
                die(f"function pointer {t:#x} in {user} not carried")
            return ("fptr", m)
        if IMX586_DATA[0] <= t < IMX586_DATA[1]:
            return ("data_block", self.data_new + (t - IMX586_DATA[0]))
        if IMX586_BSS[0] <= t < IMX586_BSS[1]:
            return ("bss_block", self.bss_new + (t - IMX586_BSS[0]))
        if MODE_TBL[0] <= t < MODE_TBL[1]:
            return ("mode_tbl", self.mode_tbl_new + (t - MODE_TBL[0]))
        for a, ln in RODATA_CONSTS:
            if a == t:
                return ("rodata_const", self.const_new[a])
        for a, ln, _ in GLUE_DATA:
            if a <= t < a + ln:
                return ("glue_data", self.glue_new[a] + (t - a))
        if sec == ".rodata":
            o = H.off(t)
            end = H.data.index(b"\0", o)
            s = H.data[o:end]
            if len(s) >= 2 and all(32 <= c < 127 or c in (9, 10, 13) for c in s):
                return ("string", self.string(t))
            return ("rodata_const", self._carry_rodata_const(t))   # binary ISP/sensor table
        die(f"data reference {t:#x} ({sec}) from {user} cannot be mapped")

    def _all_rodata_starts(self):
        """Comprehensive set of .rodata object starts: every address pointing into .rodata from
        code (PIC ldr+add-pc, movw/movt) and from pointer words in .data/.data.rel.ro/.got.
        Gives tight object boundaries for sizing the scattered ISP tables."""
        H = self.H
        from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
        from capstone.arm import ARM_OP_MEM, ARM_OP_IMM, ARM_REG_PC
        lo, hi = self._ro_lo, self._ro_hi
        starts = set()
        tx = H.elf.get_section_by_name(".text")
        md = Cs(CS_ARCH_ARM, CS_MODE_THUMB); md.detail = True; md.skipdata = True
        pend = {}; mov = {}
        for ins in md.disasm(tx.data(), tx["sh_addr"]):
            if not ins.id:
                continue
            m, o = ins.mnemonic, ins.operands
            if m.startswith("ldr") and len(o) == 2 and o[1].type == ARM_OP_MEM and o[1].mem.base == ARM_REG_PC:
                a = ((ins.address + 4) & ~3) + o[1].mem.disp
                off = H.off(a)
                if off is not None:
                    pend[o[0].reg] = struct.unpack_from("<I", H.data, off)[0]
            elif m.startswith("add") and len(o) == 2 and o[1].type == ARM_OP_IMM is False and getattr(o[1], "reg", None) == ARM_REG_PC and o[0].reg in pend:
                v = (pend.pop(o[0].reg) + ins.address + 4) & 0xFFFFFFFF
                if lo <= v < hi:
                    starts.add(v)
            elif m.startswith("movw") and len(o) == 2 and o[1].type == ARM_OP_IMM:
                mov[o[0].reg] = o[1].imm
            elif m.startswith("movt") and len(o) == 2 and o[1].type == ARM_OP_IMM and o[0].reg in mov:
                v = (o[1].imm << 16) | mov.pop(o[0].reg)
                if lo <= v < hi:
                    starts.add(v)
        for sn in (".data", ".data.rel.ro", ".got", ".rodata"):
            s = H.elf.get_section_by_name(sn)
            if not s:
                continue
            d = s.data()
            for i in range(0, len(d) - 3, 4):
                v = struct.unpack_from("<I", d, i)[0]
                if lo <= v < hi:
                    starts.add(v)
        return sorted(starts)

    def _carry_rodata_const(self, t):
        """Carry one binary .rodata object (ISP/sensor table) at its exact extent, taken as the
        gap to the next global object start, relocating any internal pointer. Cached by address."""
        if not hasattr(self, "_roconst"):
            self._roconst = {}
            rs = self.H.elf.get_section_by_name(".rodata")
            self._ro_lo, self._ro_hi = rs["sh_addr"], rs["sh_addr"] + rs["sh_size"]
            self._ro_starts = self._all_rodata_starts()
        if t in self._roconst:
            return self._roconst[t]
        import bisect as _b
        i = _b.bisect_right(self._ro_starts, t)
        end = self._ro_starts[i] if i < len(self._ro_starts) else self._ro_hi
        if not (self._ro_lo <= t < end <= self._ro_hi):
            die(f"rodata const {t:#x} extent [{t:#x},{end:#x}) implausible")
        raw = self.H.data[self.H.off(t):self.H.off(end)]
        new = self.rx_alloc(b"\0" * len(raw), align=4)
        self._roconst[t] = new
        self._roconst_pending = getattr(self, "_roconst_pending", [])
        self._roconst_pending.append((t, new, len(raw)))
        return new

    # ---- layout ---------------------------------------------------------------------
    def layout(self, funcs):
        H = self.H
        unit_bytes = H.data[H.off(IMX586_UNIT[0]):H.off(IMX586_UNIT[1])]
        self.unit_new = self.rx_alloc(b"\0" * len(unit_bytes), align=16, mod=IMX586_UNIT[0] % 16)
        self.unit_funcs = [f for f in funcs.values() if IMX586_UNIT[0] <= f.entry < IMX586_UNIT[1]]
        # expose carried imx586 unit functions by name (redirect targets need e.g. imx586_zoom_ctrl)
        for nm, v in H.syms.items():
            if nm.startswith("imx586_") and v[2] == "STT_FUNC" and IMX586_UNIT[0] <= (v[0] & ~1) < IMX586_UNIT[1]:
                self.sym[nm] = (self.unit_new + ((v[0] & ~1) - IMX586_UNIT[0])) | 1
        self.glue_blocks = {}
        for n, f in sorted(funcs.items(), key=lambda kv: kv[1].entry):
            if IMX586_UNIT[0] <= f.entry < IMX586_UNIT[1]:
                continue
            lo, hi = f.lo, f.hi
            for m, g in self.glue_blocks.items():
                if not (hi <= g["lo"] or lo >= g["hi"]):
                    die(f"glue spans overlap: {n} and {m}")
            new = self.rx_alloc(b"\0" * (hi - lo), align=16, mod=lo % 16)
            self.glue_blocks[n] = {"lo": lo, "hi": hi, "new": new, "func": f}
            self.sym[n] = new + (f.entry - lo) | 1
        for n in GLUE_NAMED + list(GLUE_STATICS):
            if n not in self.sym:
                die(f"glue function {n} missing from carry closure")
        # read-only constants + the mode table (pure data, carried RX)
        self.const_new = {a: self.rx_alloc(H.data[H.off(a):H.off(a) + ln], align=4) for a, ln in RODATA_CONSTS}
        self.mode_tbl_new = self.rx_alloc(H.data[H.off(MODE_TBL[0]):H.off(MODE_TBL[1])], align=8)
        self.sym["g_imx586_mode_tbl"] = self.mode_tbl_new
        # RW: imx586 .data image, .bss, glue data
        self.data_new = self.rw_alloc(IMX586_DATA[1] - IMX586_DATA[0], align=16)
        self.bss_new = self.rw_alloc(IMX586_BSS[1] - IMX586_BSS[0], align=16)
        self.glue_new = {}
        for a, ln, kind in GLUE_DATA:
            img = H.data[H.off(a):H.off(a) + ln] if kind == "data" else None
            self.glue_new[a] = self.rw_alloc(ln, align=8, image=img)
        # private flag for g_vi_src_switching (GOT slot +0x8bc), as in the Z40 build
        self.private_flag = self.rw_alloc(4, align=4)
        # GOT cells: +0x484 -> u32LastZoomRatio (imx586 .data); +0x8bc -> private flag
        targets = {0x484: self.data_new + (0x299fa4 - IMX586_DATA[0]), 0x8bc: self.private_flag}
        self.got_cells = {off: self.rx_alloc(struct.pack("<I", tgt), align=4) for off, tgt in targets.items()}
        self.sym["g_sns_imx586_obj"] = self.data_new + (H.syms["g_sns_imx586_obj"][0] - IMX586_DATA[0])
        self.rodata_new = self.unit_new          # unused (no rodata block); keep attribute defined
        self.complete_got_cells(funcs)

    def fill_carried(self):
        H = self.H
        ub = self.relocate_block(IMX586_UNIT[0], IMX586_UNIT[1], self.unit_new, self.unit_funcs, "imx586_unit")
        o = self.unit_new - NEW_RX_VA
        self.rx[o:o + len(ub)] = ub
        for n, g in self.glue_blocks.items():
            b = self.relocate_block(g["lo"], g["hi"], g["new"], [g["func"]], n)
            o = g["new"] - NEW_RX_VA
            self.rx[o:o + len(b)] = b
        # mode table: pure data, but scan for any pointer (fail-closed if found)
        mt = self.relocate_words(H.data[H.off(MODE_TBL[0]):H.off(MODE_TBL[1])], MODE_TBL[0], "mode_tbl", destination=self.mode_tbl_new)
        o = self.mode_tbl_new - NEW_RX_VA
        self.rx[o:o + len(mt)] = mt
        # imx586 .data image (relocates g_sns_imx586_obj vtable pointers into the carried unit)
        dimg = self.relocate_words(H.data[H.off(IMX586_DATA[0]):H.off(IMX586_DATA[1])], IMX586_DATA[0], "imx586_data", destination=self.data_new)
        self.rw_images.append((self.data_new, dimg))
        # binary .rodata consts carried on demand during the above relocations: fill + relocate
        # any internal pointers, looping because a const may reference another (adds more pending)
        done = set()
        while getattr(self, "_roconst_pending", []):
            batch, self._roconst_pending = self._roconst_pending, []
            for t, new, ln in batch:
                if t in done:
                    continue
                done.add(t)
                rb = self.relocate_words(H.data[H.off(t):H.off(t) + ln], t, f"rodata_const_{t:#x}", destination=new)
                o = new - NEW_RX_VA
                self.rx[o:o + len(rb)] = rb

    # ---- GOT cell remap hook (relocate_block consults GOT_CELL_TARGETS global) -------
    #   The parent relocate_block does: elif off in GOT_CELL_TARGETS: nv = (self.got_cells[off]-N19_GOT).
    #   We populate the module global GOT_CELL_TARGETS (keyed by offset) in build() so that path fires.

    # ---- sensor table: one added row -> g_sns_imx586_obj -----------------------------
    def build_table(self):
        N, H = self.N, self.H
        tbl = bytearray(N.data[N.off(0x265780):N.off(0x265780) + 0x2a0])
        for i in range(21):
            t, obj = struct.unpack_from("<II", tbl, 32 * i)
            if t == 0x16:
                die("19.2.14 already has a type 0x16 row")
        # Z8 leaves stock row 0x0b UNTOUCHED (no farsight, no ps5280 retarget)
        hrow = None
        for i in range(22):
            w = struct.unpack_from("<8I", H.data, H.off(HUB_TABLE) + 32 * i)
            if w[0] == 0x11:
                hrow = w
        if hrow is None:
            die("Hub IMX586 row (E1 0x11) not found")
        # carry all six attribute structs from the Hub imx586 row (standalone single sensor)
        attrs = {k: (self.rw_alloc(ln, align=4, image=H.data[H.off(hrow[k]):H.off(hrow[k]) + ln])
                     if k == 3 else self.rx_alloc(H.data[H.off(hrow[k]):H.off(hrow[k]) + ln], align=4))
                 for k, ln in ATTR_SIZES.items()}
        row = struct.pack("<8I", 0x16, self.sym["g_sns_imx586_obj"], attrs[2], attrs[3], attrs[4],
                          attrs[5], attrs[6], attrs[7])
        self.table_new = self.rx_alloc(bytes(tbl) + row, align=8)
        self.report["notes"].append({"table": hex(self.table_new), "rows": 22,
                                     "row_0x16": [hex(x) for x in struct.unpack("<8I", row)],
                                     "row_0x0b": "untouched (stock)"})

    # ---- new functions and trampolines ----------------------------------------------
    def _sources(self, final):
        SRC, ext = super()._sources(final)
        N = self.N
        # z8_cam: strcmp(arg,"Z8")==0 -> 1 else 0  (replaces z40_cam use for the hub-check redirect)
        SRC["z8_cam"] = ("push {r4, lr}\nldr r1, =s_Z8\nldr ip, =strcmp_arm\nblx ip\nclz r0, r0\n"
                         "lsrs r0, r0, #5\npop {r4, pc}\n.ltorg\n")
        # z8_nop: neutralized stub for sensor-handover / init-exposure / Hub-expander leaf ops
        SRC["z8_nop"] = "movs r0, #0\nbx lr\n"
        # z8_main_sensor: force imx586 + gctx 2000x1500@50, NO sensor_prepare_dual
        SRC["z8_main_sensor"] = ("push {r4, lr}\nmov r4, r0\nbl z8_init\nmov r0, r4\nldr r1, =s_imx586\n"
                                 "ldr ip, =strcpy_arm\nblx ip\nbl get_fpv_gctx\nmovw r2, #2000\nmovw r3, #1500\n"
                                 "strd r2, r3, [r0, #0x20]\nmovs r3, #50\nstr r3, [r0, #0x28]\n"
                                 "ldr r0, =s_imx586\npop {r4, pc}\n.ltorg\n")
        # z8_init: same memcpy-table initializer as z40_init
        SRC["z8_init"] = SRC.pop("z40_init") if "z40_init" in SRC else (
            "push {r4, r5, r6, lr}\nldr r4, =init_tbl\nldr r5, =init_end\n1:\ncmp r4, r5\nbhs 2f\n"
            "ldmia r4!, {r0, r1, r2}\nldr ip, =memcpy_arm\nblx ip\nb 1b\n2:\npop {r4, r5, r6, pc}\n.ltorg\n")
        # GPIO58 LOW helper: replaces the removable "here-1" debug print after set_vi_vpss_mode
        SRC["z8_gpio_lo"] = ("push {r0, r1, r2, r3, lr}\nmovs r0, #58\nmovs r1, #0\nbl set_gpio_val\n"
                             "pop {r0, r1, r2, r3, pc}\n.ltorg\n")
        # GPIO58 HIGH trampoline at the sensor-start -> MIPI-RX join (0x6613a): set GPIO58=1, then
        # re-execute the displaced "ldr r0,=0x40046d0c; bl 0x65cac" (enable mipi-rx-clock) and
        # continue at 0x66140 (mov r4,r0). lr is dead here (frame-saved), so no preservation needed.
        SRC["tramp_gpio_hi"] = ("movs r0, #58\nmovs r1, #1\nbl set_gpio_val\n"
                                "movw r0, #0x6d0c\nmovt r0, #0x4004\nbl helper65cac\nb.w dovv_cont\n.ltorg\n")
        ext["helper65cac"] = 0x65cac | 1
        ext["dovv_cont"] = 0x66140 | 1
        # drop the Z40-only new functions that do not apply to Z8
        for dead in ("z40_cam", "z8_unreachable", "sensor_prepare_dual", "z40_main_sensor"):
            SRC.pop(dead, None)
        # z8 strings: add "Z8"; the imx586 string already present; override pqfile to z8 filename
        mk = self.new_string if final else (lambda b: NEW_RX_VA)
        ext["s_Z8"] = mk(b"Z8")
        ext["s_pqfile"] = mk(b"cam_imx586_50fps_z8_xg1.bin")
        # the fopen trampoline uses s_pqfile; re-point its source string (already references s_pqfile label)
        return SRC, ext

    # ---- 19.2.14 hook sites ---------------------------------------------------------
    def apply_hooks(self, ext):
        self.apply_lane_hook(ext)
        N = self.N
        A = lambda src, addr, syms=ext: assemble(src, addr, {k: v for k, v in syms.items()})
        # H1a main: force imx586 (NO sensor_prepare_dual)
        self.expect(0x5a6aa, "bl")
        if N.name_of(0x658c8) != "uav_ar_sys_detect_sensor":
            die("H1a: unexpected callee at main+0x5a6aa")
        self.patch(0x5a6aa, A("mov r0, r6\nbl z8_main_sensor\nmov r8, r0\nb.w h1_join\n", 0x5a6aa,
                              dict(ext, h1_join=0x5a6fc | 1)), 0x5a6e6 - 0x5a6aa,
                   "H1a main: force imx586 + gctx 2000x1500@50 (no sensor_prepare_dual)")
        # H1b main: record cfg -> msp_rc_config_init, streamzoom_init
        self.expect(0x5a7ba, "bl")
        self.patch(0x5a7ba, enc_bl(0x5a7ba, ext["tramp_rec"]), 4, "H1b main: tramp_rec")
        # H2 get_sensor_type: imx586 -> 0x16
        g = N.syms["get_sensor_type"][0] & ~1
        self.patch(g, enc_bw(g, ext["tramp_gst"]), 4, "H2 get_sensor_type: imx586 -> E1 0x16")
        # H3 init_vi_vpss: case 0x16 2000x1500@50
        self.expect(0x67138, "ldr", "r0")
        self.patch(0x67138, enc_bw(0x67138, ext["tramp_ivv"]), 4, "H3 init_vi_vpss: case 0x16 2000x1500@50")
        # H4 vi_register_sensor: 22-row table + sizes
        for a, m, frag, new in [(0x66b38, "sub", "#0x2ac", "subw sp, sp, #0x2cc"),
                                (0x66b46, "mov", "#0x2a0", "mov.w r2, #0x2c0"),
                                (0x66b56, "mov", "#0x2a0", "mov.w r0, #0x2c0"),
                                (0x66b7c, "mov", "#0x2a0", "mov.w r2, #0x2c0"),
                                (0x66b9c, "add", "#0x2ac", "addw sp, sp, #0x2cc")]:
            ins = self.expect(a, m, frag)
            self.patch(a, A(new + "\n", a), ins.size, f"H4 vi_register_sensor {ins.op_str} -> {new}")
        for a, frag, new in [(0x66b4c, "#0x2a4", "str r3, [sp, #0x2c4]"), (0x66b8e, "#0x2a4", "ldr r3, [sp, #0x2c4]")]:
            ins = self.expect(a, "str" if new.startswith("str") else "ldr", frag)
            self.patch(a, A(new + "\n", a), ins.size, f"H4 canary {ins.op_str} -> {new}")
        self.expect(0x66b76, "movs", "#0x15")
        self.patch(0x66b76, A("movs r2, #0x16\n", 0x66b76), 2, "H4 row count 0x15 -> 0x16")
        tgt, lit = self.pic_target(0x66b3c, 0x66b44)
        if tgt != 0x265780:
            die("H4 table literal mismatch")
        self.patch(lit, struct.pack("<I", (self.table_new - (0x66b44 + 4)) & 0xFFFFFFFF), 4,
                   "H4 table source -> new 22-row table")
        # H5 fpv_sys_get_sensor_type: imx586 -> 586
        f0 = N.syms["fpv_sys_get_sensor_type"][0] & ~1
        self.patch(f0, enc_bw(f0, ext["tramp_fsgst"]), 6, "H5 fpv_sys_get_sensor_type: imx586 -> E2 586")
        # H6 fpv_config_init default fps 60 -> 50
        self.expect(0x5f6c4, "movs", "r2, #0x3c")
        self.patch(0x5f6c4, A("movs r2, #50\n", 0x5f6c4), 2, "H6 fpv_config_init default fps 60 -> 50")
        # H7 fpv_sys_ch0_res_remap: fps always 50
        c0, csz = N.syms["fpv_sys_ch0_res_remap"][0] & ~1, N.syms["fpv_sys_ch0_res_remap"][1]
        self.patch(c0, A("str r0, [r3]\nldr ip, [sp]\nstr r1, [ip]\nldr ip, [sp, #4]\nmovs r1, #50\n"
                         "str r1, [ip]\nmovs r0, #0\nbx lr\n", c0), csz,
                   "H7 fpv_sys_ch0_res_remap: out_w=w, out_h=h, out_fps=50, return 0")
        # H8 uav_ar_sys_set_sensor_res: rotation tail
        self.expect(0x65686, "ldr", "r0")
        self.patch(0x65686, A("str.w fp, [r4, #0x68]\nbl uninit_vpss\nmovw r0, #10000\nldr ip, =usleep_arm\nblx ip\n"
                              "bl init_vpss\nmov r0, fp\nbl uar_ar_set_sensor_want_rotation\nmovs r0, #0\n"
                              "add sp, #20\npop.w {r4, r5, r6, r7, r8, r9, sl, fp, pc}\n.ltorg\n", 0x65686),
                   0x656cc - 0x65686, "H8 uav_ar_sys_set_sensor_res: rotation tail")
        # H9 MSP parser: INAV RC slot
        self.expect(0x6ccda, "bl")
        self.patch(0x6ccda, enc_bl(0x6ccda, ext["tramp_msp"]), 4, "H9 MSP parser: mspSerialParaINAVRcSlot")
        # H10 load_pq_bin: accept imx586; z8 filename
        self.expect(0x66c62, "cmp", "r0, #0")
        self.patch(0x66c62, enc_bw(0x66c62, ext["tramp_acc"]), 4, "H10a load_pq_bin: accept 'imx586'")
        self.expect(0x66cdc, "blx")
        self.patch(0x66cdc, enc_bl(0x66cdc, ext["tramp_fopen"]), 4,
                   "H10b load_pq_bin: filename -> /usrdata/fpv/tunning/cam_imx586_50fps_z8_xg1.bin")
        # H11 init_vb: 2000x1500 pools (same proven values as Z40)
        self.expect(0x6536e, "vstr")
        self.patch(0x6536e, A("movw r3, #0xdc80\nmovt r3, #0x39\nstr r3, [r4, #8]\nmovs r3, #0\nstr r3, [r4, #12]\n"
                              "movs r3, #4\nstr r3, [r4, #16]\nmovw r3, #0xc3a0\nmovt r3, #0x45\nstr r3, [r4, #56]\n"
                              "movs r3, #0\nstr r3, [r4, #60]\nmovs r3, #4\nstr r3, [r4, #64]\nb.w vb_join\n",
                              0x6536e, dict(ext, vb_join=0x65350 | 1)), 0x653be - 0x6536e,
                   "H11 init_vb: pool0 3792000x4 (RAW 2000x1500), pool1 4572064x4 (YUV 2000x1500)")
        # Dedicated Z8 uses offline VI / online VPSS (mode 1).
        self.expect(0x66110, "movs", "r0, #3")
        self.patch(0x66110, A("movs r0, #1\n", 0x66110), 2, "H12a direct-camera vi_vpss_mode 3 -> 1 (native Z8)")
        # Z8 GPIO58 LOW: replace the removable "here-1" debug print (ldr+add+blx puts, 8 bytes at
        # 0x66116) with a call to z8_gpio_lo. Fires after set_vi_vpss_mode, before sensor start.
        self.expect(0x66116, "ldr", "r0")
        self.expect(0x66118, "add", "r0, pc")
        self.expect(0x6611a, "blx")
        self.patch(0x66116, A("bl z8_gpio_lo\n", 0x66116), 0x6611e - 0x66116,
                   "Z8 GPIO58 LOW after set_vi_vpss_mode (replaces here-1 debug)")
        # H12b do_init_vi_vpss: scale coef after VPSS channel loop
        self.expect(0x66856, "ldr", "r3, [r5, #4]")
        self.patch(0x66856, enc_bl(0x66856, ext["tramp_scale"]), 4,
                   "H12b do_init_vi_vpss: ss_mpi_vpss_set_chn_scale_coef_type(0,0,1)")
        # Z8 GPIO58 HIGH: trampoline at the sensor-start -> MIPI-RX join (0x6613a). Replace the
        # 6-byte "ldr r0,=0x40046d0c (2); bl 0x65cac (4)" with "b.w tramp_gpio_hi (4); nop (2)".
        self.expect(0x6613a, "ldr", "r0")
        self.expect(0x6613c, "bl")
        if self.pic_target(0x6613a, 0x6613a)[0] is not None:
            pass
        lit = ((0x6613a + 4) & ~3) + self.N.disasm1(0x6613a).operands[1].mem.disp
        if self.N.u32(lit) != 0x40046d0c:
            die(f"GPIO58-high: expected ldr r0,=0x40046d0c at 0x6613a, got {self.N.u32(lit):#x}")
        if self.N.disasm1(0x6613c).operands[0].imm != 0x65cac:
            die("GPIO58-high: expected bl 0x65cac at 0x6613c")
        self.patch(0x6613a, enc_bw(0x6613a, ext["tramp_gpio_hi"]), 0x66140 - 0x6613a,
                   "Z8 GPIO58 HIGH at sensor-start -> MIPI-RX join (tramp_gpio_hi)")


def build(hub, n19, z8):
    # point the reused parent machinery at the Z8 configuration (process-local; file untouched)
    Z.FARSIGHT_UNIT = IMX586_UNIT
    Z.RODATA_BLOCK = (IMX586_UNIT[0], IMX586_UNIT[0])     # empty: no separate rodata block for Z8
    Z.DATA_BLOCK = IMX586_DATA
    Z.BSS_BLOCK = IMX586_BSS
    Z.GLUE_DATA = GLUE_DATA
    Z.RODATA_CONSTS = RODATA_CONSTS
    Z.HUB_GOT = HUB_GOT
    Z.N19_GOT = N19_GOT
    Z.GOT_MAP_SYM = GOT_MAP_SYM
    Z.GOT_CELL_TARGETS = {0x484: ("imx586_data", 0x299fa4), 0x8bc: ("private_flag", None)}
    Z.GLUE_STATICS = dict(GLUE_STATICS, zoom_process=0)   # zoom_process key must exist; expander off
    Z.EXPANDER_HELPERS = set()
    Z.EXPANDER_SEQS = []
    Z.CALL_REDIRECT = {}
    Z.NEW_RX_VA = NEW_RX_VA
    b = Z8Build(hub, n19, z8)
    funcs = b.carry_functions()
    b.layout(funcs)
    b.alloc_new_code()
    b.fill_carried()
    b.build_table()
    ext = b.final_new_code()
    b.apply_hooks(ext)
    starts = object_starts(b.H)
    for x in b.report["refused"]:
        if int(x["value"], 16) in starts:
            die(f"unrelocated word {x} equals a real object start")
    b.report["nonpointer_words_verified"] = b.report.pop("refused")
    elf = b.emit()
    b.report["carried_functions"] = {n: {"hub_entry": hex(f.entry), "hub_span": [hex(f.lo), hex(f.hi)]}
                                     for n, f in funcs.items()}
    b.report["new_functions"] = b.newfuncs
    b.report["sym"] = {k: hex(v) for k, v in b.sym.items()}
    b.report["layout"] = {
        "unit_new": hex(b.unit_new), "unit_hub": [hex(x) for x in IMX586_UNIT],
        "data_new": hex(b.data_new), "data_hub": [hex(x) for x in IMX586_DATA],
        "bss_new": hex(b.bss_new), "bss_hub": [hex(x) for x in IMX586_BSS],
        "mode_tbl_new": hex(b.mode_tbl_new), "mode_tbl_hub": [hex(x) for x in MODE_TBL],
        "glue_data": {hex(a): hex(b.glue_new[a]) for a, _, _ in GLUE_DATA},
        "const_new": {hex(k): hex(v) for k, v in b.const_new.items()},
        "private_flag": hex(b.private_flag),
        "got_cells": {hex(k): hex(v) for k, v in b.got_cells.items()},
        "table_new": hex(b.table_new),
        "glue_blocks": {n: {"hub": [hex(g["lo"]), hex(g["hi"])], "new": hex(g["new"])}
                        for n, g in b.glue_blocks.items()},
        "rodata_consts": {hex(k): hex(v) for k, v in getattr(b, "_roconst", {}).items()}}
    return b, elf


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--hub", required=True)
    ap.add_argument("--n19", required=True)
    ap.add_argument("--z8", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--report", required=True)
    a = ap.parse_args()
    b, elf = build(a.hub, a.n19, a.z8)
    Path(a.out).write_bytes(elf)
    b.report["output"] = {"sha256": hashlib.sha256(elf).hexdigest(), "bytes": len(elf)}
    Path(a.report).write_text(json.dumps(b.report, indent=1, default=str))
    print(json.dumps({"output": b.report["output"], "relocations": len(b.report["relocations"]),
                      "patches": len(b.report["patches"])}, indent=1))
