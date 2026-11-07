#!/usr/bin/env python3
"""Z40-on-19.2.14 ar_ldyhs_sky builder (phase 1). Plan: Z40_19_2_14_MINIMAL_PATCH_PLAN.md F4-F12.

Transplants the Hub 18.21.4 Farsight closure into the stock 19.2.14 application and applies
the hook-site patches. Fails closed on any reference it cannot map. Produces a report of
every relocation, every patch site and every verification.

Nothing here touches a device.
"""
from __future__ import annotations

import hashlib
import json
import os
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import fextent as FE  # noqa: E402

from arm_tools import tools_directory, tool as arm_tool

TOOLS = tools_directory()


class BuildError(SystemExit):
    pass


def die(msg):
    raise BuildError(f"FAIL-CLOSED: {msg}")


# ------------------------------------------------------------------ carry spec -----
FARSIGHT_UNIT = (0x1031f0, 0x1066a0)
RODATA_BLOCK = (0x238c28, 0x24a550)          # exclusive Farsight ISP tables
DATA_BLOCK = (0x299fa8, 0x29a974)            # exclusive Farsight .data (incl. g_sns_farsight_obj)
BSS_BLOCK = (0x2d3008, 0x2d44c8)             # exclusive Farsight .bss
GLUE_DATA = [(0x294b28, 4, "data"), (0x294b2c, 4, "data"), (0x29df98, 36, "bss"),
             (0x29fde4, 4, "bss"), (0x29fde8, 4, "bss"),
             (0x29fdec, 36, "bss")]       # vendor four-row DisplayPort accumulator
RODATA_CONSTS = [(0x1c24e4, 12), (0x19dc37, 6)] # low-delay attr; binary OSD frame signature
HUB_GOT = 0x2916cc
N19_GOT = 0x263700
GOT_MAP_SYM = {0x514: 0x4f4, 0x54c: 0x52c}   # stderr, __stack_chk_guard
GOT_CELL_TARGETS = {0x334: ("data", 0x29a970), 0x8bc: ("private_flag", None)}
GLUE_STATICS = {"zoom_process": 0x69dc8, "restart_vin": 0x698b4, "set_scale": 0x6986c,
                "zoom_thread": 0x6a874, "vpss_start_helper": 0x674e4,
                "route_online_clock": 0x673f0, "route_enable_chn": 0x676b4}
GLUE_NAMED = ["fpv_sky_streamzoom_init", "fpv_msp_rc_config_init", "fpv_msp_rc_config_get",
              "fpv_set_msp_rc_zoomctrl", "fpv_set_msp_zoomctrl", "mspSerialParaINAVRcSlot",
              "mspSerialParaOsdRcSlot",
              "fpv_set_vpss_rotation", "init_vpss", "uninit_vpss", "set_gpio_val",
              "single_imx586_load_pq_bin", "StreamZoom_load_pq_bin",
              "uninit_pre_route", "init_next_route"]
CALL_REDIRECT = {"fpv_hub_check_current_cam": "z40_cam", "imx586_zoom_ctrl": "z8_unreachable"}
EXPANDER_HELPERS = {0x69980, 0x699e4}
# zoom_process expander read-modify-write sequences -> SoC GPIO (equal length, NOP padded)
EXPANDER_SEQS = [(0x6a0b6, 0x6a0d2, 0), (0x6a1bc, 0x6a1dc, 1)]   # (start, end, gpio52 value)

NEW_RX_VA = 0x2b0000


# ------------------------------------------------------------------ Thumb encoders --
def enc_bl(addr, target, *, to_arm=False):
    """BL (Thumb->Thumb) or BLX imm (Thumb->ARM)."""
    if to_arm:
        if target & 3:
            die(f"BLX target {target:#x} not word aligned")
        off = target - ((addr + 4) & ~3)
    else:
        off = (target & ~1) - (addr + 4)
    if not -(1 << 24) <= off < (1 << 24):
        die(f"branch out of range {addr:#x}->{target:#x}")
    s = (off >> 24) & 1
    i1 = (off >> 23) & 1
    i2 = (off >> 22) & 1
    imm10 = (off >> 12) & 0x3FF
    imm11 = (off >> 1) & 0x7FF
    j1 = (~(i1 ^ s)) & 1
    j2 = (~(i2 ^ s)) & 1
    h1 = 0xF000 | (s << 10) | imm10
    if to_arm:
        h2 = 0xC000 | (j1 << 13) | (j2 << 11) | (imm11 & ~1)
    else:
        h2 = 0xD000 | (j1 << 13) | (j2 << 11) | imm11
    return struct.pack("<HH", h1, h2)


def enc_bw(addr, target):
    off = (target & ~1) - (addr + 4)
    if not -(1 << 24) <= off < (1 << 24):
        die(f"b.w out of range {addr:#x}->{target:#x}")
    s = (off >> 24) & 1
    i1, i2 = (off >> 23) & 1, (off >> 22) & 1
    j1, j2 = (~(i1 ^ s)) & 1, (~(i2 ^ s)) & 1
    return struct.pack("<HH", 0xF000 | (s << 10) | ((off >> 12) & 0x3FF),
                       0x9000 | (j1 << 13) | (j2 << 11) | ((off >> 1) & 0x7FF))


NOP16 = b"\x00\xbf"


# ------------------------------------------------------------------ assembler ------
def assemble(src: str, addr: int, syms: dict, *, name="snippet") -> bytes:
    """Assemble Thumb-2 code at a fixed address; external symbols are absolute."""
    with tempfile.TemporaryDirectory() as td:
        s = Path(td, "a.s")
        def is_data(k):
            return k.startswith("s_") or k.endswith("_arm") or k in ("init_tbl", "init_end", "ivv_msg")
        thumb = {k: v for k, v in syms.items() if not is_data(k)}
        data = {k: v for k, v in syms.items() if is_data(k)}
        for k, v in thumb.items():
            if not v & 1:
                die(f"code symbol {k}={v:#x} lacks the Thumb bit")
        hdr = "".join(f".thumb_set {k}, {v & ~1:#x}\n" for k, v in thumb.items() if k in src)
        s.write_text(".syntax unified\n.thumb\n.cpu cortex-a7\n.fpu neon-vfpv4\n" + hdr +
                     ".section .text\n.global _start\n_start:\n" + src + "\n")
        syms = data
        o, elf, binf = Path(td, "a.o"), Path(td, "a.elf"), Path(td, "a.bin")
        r = subprocess.run([arm_tool("as", TOOLS), "-o", str(o), str(s)],
                           capture_output=True, text=True)
        if r.returncode:
            die(f"assembler failed for {name}: {r.stderr}")
        ld = [arm_tool("ld", TOOLS), "-Ttext", hex(addr), "-e", "_start", "-o", str(elf), str(o)]
        for k, v in syms.items():
            ld.append(f"--defsym={k}={v:#x}")
        r = subprocess.run(ld, capture_output=True, text=True)
        if r.returncode:
            die(f"link failed for {name}: {r.stderr}")
        nm = subprocess.run([arm_tool("nm", TOOLS), str(elf)], capture_output=True, text=True).stdout
        if "veneer" in nm:
            die(f"linker inserted an interworking/range veneer in {name}: {[l for l in nm.splitlines() if 'veneer' in l]}")
        subprocess.run([arm_tool("objcopy", TOOLS), "-O", "binary", "-j", ".text",
                        str(elf), str(binf)], check=True)
        return binf.read_bytes()


# ------------------------------------------------------------------ the build ------
class Build:
    dual_sensor_lanes = True
    direct_camera_routing = True
    def __init__(self, hub_path, n19_path):
        self.H = FE.Image(hub_path)
        self.N = FE.Image(n19_path)
        self.out = bytearray(self.N.data)
        self.report = {"relocations": [], "patches": [], "refused": [], "notes": []}
        self.rx = bytearray()           # new RX segment bytes
        self.rw_size = 0                # new RW (bss extension) size
        self.rw_images = []             # (rw_off, bytes) copied by z40_init
        self.sym = {}                   # name -> new address (thumb functions have |1)
        self.str_pool = {}              # bytes -> new address
        n_rw = [s for s in self.N.elf.iter_segments() if s["p_type"] == "PT_LOAD"][1]
        self.rw_end = n_rw["p_vaddr"] + n_rw["p_memsz"]
        self.rw_base = (self.rw_end + 15) & ~15

    # --- allocation -------------------------------------------------------------
    def rx_alloc(self, data: bytes, align=4, mod=0):
        """Place bytes in the new RX segment so that (addr % align) == mod."""
        while (NEW_RX_VA + len(self.rx)) % align != mod:
            self.rx += b"\x00"
        a = NEW_RX_VA + len(self.rx)
        self.rx += data
        return a

    def rw_alloc(self, size, align=8, image: bytes | None = None):
        self.rw_size = (self.rw_size + align - 1) & ~(align - 1)
        a = self.rw_base + self.rw_size
        if image is not None:
            self.rw_images.append((a, bytes(image)))
        self.rw_size += size
        return a

    def string(self, hub_addr):
        o = self.H.off(hub_addr)
        s = self.H.data[o:self.H.data.index(b"\0", o) + 1]
        if s not in self.str_pool:
            self.str_pool[s] = self.rx_alloc(s, align=1)
        return self.str_pool[s]

    # --- analysis ---------------------------------------------------------------
    def carry_functions(self):
        H = self.H
        roots = dict(GLUE_STATICS)
        roots.update({n: H.syms[n][0] for n in GLUE_NAMED})
        far = [n for n, v in H.syms.items() if n.startswith("farsight_") and v[2] == "STT_FUNC"]
        roots.update({n: H.syms[n][0] for n in far})
        obj = H.syms["g_sns_farsight_obj"]
        for i, w in enumerate(struct.unpack_from("<12I", H.data, H.off(obj[0]))):
            if w and H.section_of(w) == ".text":
                roots[f"farsight_cb{i}"] = w
        funcs, queue = {}, list(roots.items())
        while queue:
            n, a = queue.pop()
            e = a & ~1
            if any(f.entry == e for f in funcs.values()):
                continue
            from capstone.arm import ARM_REG_R3
            # The vendor direct-route helper tail-calls sensor->restart after
            # restoring LR. Its exact site/register is audited; all other
            # unclassified indirect tails retain the normal refusal.
            tails = {0x6972c: ARM_REG_R3} if n == "init_next_route" else None
            f = FE.extent(H, a, indirect_tails=tails)
            if n == 'init_next_route' and (f.insns.get(0x6972c) != (2, 'bx', 'r3')
                    or f.insns.get(0x69700) != (2, 'ldr', 'r3, [r0, #0x14]')):
                die('direct route sensor-restart callback tail changed')
            funcs[n] = f
            for _, _, t in f.pic:
                if H.section_of(t) == ".text":
                    queue.append((f"fptr_{t:#x}", t))
            for _, t, k in f.calls:
                if t and FARSIGHT_UNIT[0] <= (t & ~1) < FARSIGHT_UNIT[1] and (t & ~1) not in H.func_starts:
                    queue.append((f"static_{t:#x}", t))
        canon = {(a & ~1): n for n, a in roots.items()}
        funcs = {canon.get(f.entry, n): f for n, f in funcs.items()}
        for n, f in funcs.items():
            inunit = FARSIGHT_UNIT[0] <= f.entry < FARSIGHT_UNIT[1]
            if inunit and not (FARSIGHT_UNIT[0] <= f.lo and f.hi <= FARSIGHT_UNIT[1]):
                die(f"{n} spills out of the Farsight unit")
        return funcs

    # --- target mapping ---------------------------------------------------------
    def map_text(self, t):
        """Hub text address (function or function pointer) -> new address."""
        e = t & ~1
        if FARSIGHT_UNIT[0] <= e < FARSIGHT_UNIT[1]:
            return self.unit_new + (t - FARSIGHT_UNIT[0])
        for n, f in self.glue_blocks.items():
            if f["lo"] <= e < f["hi"]:
                return f["new"] + (t - f["lo"])
        return None

    def map_call(self, t, kind):
        H, N = self.H, self.N
        if self.direct_camera_routing and t not in H.plt:
            if (t & ~1) == 0x6712c:
                return ("direct_sensor_row", "selected donor row", 0x65a99)
            if (t & ~1) == 0x67358:
                return ("direct_sensor_object", "selected donor object", self.sym["direct_sensor_object"])
            # Direct cameras preserve the ISP session during a sensor switch.
            # The normal donor teardown closes/unregisters the one-time driver.
            if H.name_of(t) in ("uninit_vi_vpss", "init_vi_vpss"):
                name = "uninit_pre_route" if H.name_of(t) == "uninit_vi_vpss" else "init_next_route"
                return ("direct_route", name, self.sym[name])
        if t in H.plt:
            nm = H.plt[t]
            if nm not in N.plt_labels:
                die(f"PLT symbol {nm} absent from 19.2.14")
            arm = N.plt_target(nm, to_arm=True)
            label = N.plt_labels[nm]
            if kind == "tail" and arm == label:
                # A Thumb B.W cannot switch to an ARM-only donor stub. Preserve
                # LR via a literal-load interworking veneer, rather than BLX.
                veneers = self.report.setdefault("plt_tail_veneers", {})
                if nm not in veneers:
                    address = self.rx_alloc(b'\xdf\xf8\x00\xf0' + struct.pack('<I', arm), align=4)
                    veneers[nm] = {"address": hex(address), "arm_target": hex(arm)}
                return ("plt_tail_veneer", nm, int(veneers[nm]["address"], 16) | 1)
            return ("plt", nm, arm if kind == "blx" or arm == label else label)
        m = self.map_text(t)
        if m is not None:
            return ("carried", hex(t), m)
        name = H.name_of(t)
        if name in CALL_REDIRECT:
            return ("redirect", name, self.sym[CALL_REDIRECT[name]])
        if (t & ~1) in EXPANDER_HELPERS:
            die(f"expander helper call {t:#x} survived sequence replacement")
        if name and name in N.syms and N.syms[name][2] == "STT_FUNC":
            return ("n19", name, N.syms[name][0] | 1)
        die(f"call target {t:#x} ({name}) cannot be mapped")

    def map_data(self, t, user):
        H = self.H
        if self.direct_camera_routing and t in (0x29fdc0, 0x29fdc4):
            # Existing selected-sensor owner in the donor; never a copied cache.
            return ("shared_selected_sensor", {0x29fdc0: 0x2709e0, 0x29fdc4: 0x2709e4}[t])
        if t == HUB_GOT:
            return ("got_base", N19_GOT)
        sec = H.section_of(t)
        if sec == ".text":
            m = self.map_text(t)
            if m is None:
                die(f"function pointer {t:#x} in {user} not carried")
            return ("fptr", m)
        if RODATA_BLOCK[0] <= t < RODATA_BLOCK[1]:
            return ("rodata_block", self.rodata_new + (t - RODATA_BLOCK[0]))
        for a, ln in RODATA_CONSTS:
            if a == t:
                return ("rodata_const", self.const_new[a])
        if DATA_BLOCK[0] <= t < DATA_BLOCK[1]:
            return ("data_block", self.data_new + (t - DATA_BLOCK[0]))
        if BSS_BLOCK[0] <= t < BSS_BLOCK[1]:
            return ("bss_block", self.bss_new + (t - BSS_BLOCK[0]))
        for a, ln, _ in GLUE_DATA:
            if a <= t < a + ln:
                return ("glue_data", self.glue_new[a] + (t - a))
        if sec == ".rodata":
            o = H.off(t)
            end = H.data.index(b"\0", o)
            s = H.data[o:end]
            if all(32 <= c < 127 or c in (9, 10) for c in s):
                return ("string", self.string(t))
        die(f"data reference {t:#x} ({sec}) from {user} cannot be mapped")

    # --- relocation of one carried block ---------------------------------------
    def relocate_block(self, lo, hi, new, funcs_in_block, label):
        H = self.H
        blk = bytearray(H.data[H.off(lo):H.off(hi)])
        lit_use = {}
        def put(addr, b):
            o = addr - lo
            blk[o:o + len(b)] = b
        for f in funcs_in_block:
            # expander sequence replacement (zoom_process only)
            for s, e, val in EXPANDER_SEQS if f.entry == GLUE_STATICS["zoom_process"] else []:
                nA = new + (s - lo)
                code = assemble(f"movs r0, #58\nmovs r1, #0\nbl set_gpio_val\n"
                                f"movs r0, #52\nmovs r1, #{val}\nbl set_gpio_val\n",
                                nA, {"set_gpio_val": self.sym["set_gpio_val"]}, name="expander_seq")
                if len(code) > e - s:
                    die("GPIO sequence longer than expander sequence")
                code += NOP16 * ((e - s - len(code)) // 2)
                put(s, code)
                self.report["patches"].append({"site": f"zoom_process {s:#x}-{e:#x}", "what":
                                               f"hub expander 0x21 bit1 RMW -> GPIO58=0, GPIO52={val}",
                                               "new_addr": hex(nA)})
            skip = set()
            if label == "init_next_route":
                instruction = H.disasm1(0x6944e)
                if instruction.mnemonic != "cmp" or instruction.op_str != "r3, #0x11":
                    die("direct route IMX586 enum comparison changed")
                put(0x6944e, assemble("cmp r3,#0x16\n", new + 0x6944e - lo, {}))
                self.report["patches"].append({"site": "direct init_next_route 0x6944e",
                                               "what": "IMX586 vendor enum 0x11 -> donor extension 0x16"})
            for s, e, _ in EXPANDER_SEQS if f.entry == GLUE_STATICS["zoom_process"] else []:
                skip |= set(range(s, e))
            for a, t, kind in f.calls:
                if a in skip:
                    continue
                if t is None:
                    continue                      # blx reg: target computed at runtime (function pointer)
                if self.map_text(t) is not None and lo <= (t & ~1) < hi:
                    continue                      # internal, layout preserved
                size = f.insns[a][0]
                if size != 4:
                    die(f"16-bit external branch at {a:#x} in {label}")
                mk = self.map_call(t, kind)
                nA = new + (a - lo)
                if kind in ("bl",):
                    arm_plt = mk[0] == "plt" and mk[2] == self.N.plt_target(mk[1], to_arm=True)
                    put(a, enc_bl(nA, mk[2], to_arm=arm_plt))
                elif kind == "blx":
                    put(a, enc_bl(nA, mk[2], to_arm=True))
                elif kind == "tail":
                    if mk[0] == "plt":
                        mk = ("plt", mk[1], mk[2])
                    put(a, enc_bw(nA, mk[2]))
                else:
                    die(f"conditional external branch at {a:#x} ({kind})")
                self.report["relocations"].append({"kind": "call", "at": hex(a), "new_at": hex(nA),
                                                   "hub_target": hex(t), "map": [mk[0], mk[1], hex(mk[2])]})
            for a, lit, t in f.pic:
                mk = self.map_data(t, label)
                nA = new + (a - lo)
                val = (mk[1] - (nA + 4)) & 0xFFFFFFFF
                if lit in lit_use and lit_use[lit] != ("pic", val):
                    die(f"literal {lit:#x} shared by conflicting uses")
                lit_use[lit] = ("pic", val)
                if not lo <= lit < hi:
                    die(f"literal {lit:#x} outside its block")
                put(lit, struct.pack("<I", val))
                self.report["relocations"].append({"kind": "pic", "at": hex(a), "hub_target": hex(t),
                                                   "map": [mk[0], hex(mk[1])]})
            for a, lit, off, base in f.gotloads:
                if base != HUB_GOT:
                    die(f"register-indexed load at {a:#x} with PIC base {base:#x} and literal index: unclassified")
                if off in GOT_MAP_SYM:
                    nv = GOT_MAP_SYM[off]
                elif off in self.got_cells:
                    nv = (self.got_cells[off] - N19_GOT) & 0xFFFFFFFF
                else:
                    die(f"GOT slot offset {off:#x} at {a:#x} unknown")
                if lit in lit_use and lit_use[lit] != ("got", nv):
                    die(f"GOT literal {lit:#x} conflicting")
                lit_use[lit] = ("got", nv)
                put(lit, struct.pack("<I", nv))
                self.report["relocations"].append({"kind": "got", "at": hex(a), "hub_slot_off": hex(off),
                                                   "new_off": hex(nv)})
            if f.absw:
                die(f"movw/movt absolute address in {label}: {f.absw}")
            # literal words that look like addresses but were not relocated
            for lit, (val, size, user) in f.lits.items():
                if lit in lit_use or val is None or size != 4:
                    continue
                if 0x10000 <= val < 0x2e0000 and H.section_of(val):
                    self.report["refused"].append({"block": label, "lit": hex(lit), "value": hex(val),
                                                   "section": H.section_of(val), "user": hex(user)})
        return bytes(blk)

    # --- pointer words inside carried data -------------------------------------
    def relocate_words(self, data: bytes, base_hub: int, label: str, *, destination=None) -> bytes:
        H = self.H
        section = H.section_of(base_hub)
        # ISP calibration arrays are scalar data. Packed coefficients frequently
        # look like addresses (e.g. CAC mode 1 + threshold 35 = 0x00230001).
        # Their pointers are relocated at the code/owner field, never by scanning
        # the numbers stored in the pointed-to tables.
        if section == ".rodata" or 0x290504 <= base_hub < base_hub + len(data) <= 0x2905b8:
            if section == ".rodata" and H.section_of(base_hub + len(data) - 1) != section:
                die(f"scalar ISP table crosses section boundary: {label}")
            self.report.setdefault("scalar_tables_preserved", []).append(
                {"source": hex(base_hub), "destination": hex(destination) if destination is not None else None,
                 "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
            if destination is None:
                die(f"scalar table lacks emitted destination proof: {label}")
            return bytes(data)
        sensor_data = 0x2995e0 <= base_hub < base_hub + len(data) <= 0x29a974
        sensor_pointer_fields = set()
        if sensor_data:
            # Both private sensor-data regions contain calibration scalars plus
            # explicit 48-byte ot_isp_sns_obj callback records. Only those record
            # fields are pointers; black-level pairs such as 0x0023001e are not.
            for name in ("g_sns_imx586_obj", "g_sns_farsight_obj"):
                address, size, _ = H.syms[name]
                if size != 48:
                    die(f"sensor callback record changed: {name}")
                sensor_pointer_fields.update(range(address, address + size, 4))
            if destination is None:
                die(f"sensor data lacks emitted destination proof: {label}")
            self.report.setdefault("sensor_data_images", []).append(
                {"source": hex(base_hub), "destination": hex(destination), "bytes": len(data),
                 "callback_fields": sorted(hex(a) for a in sensor_pointer_fields
                                           if base_hub <= a < base_hub + len(data))})
        out = bytearray(data)
        for i in range(0, len(data) - 3, 4):
            if sensor_data and base_hub + i not in sensor_pointer_fields:
                continue
            v = struct.unpack_from("<I", data, i)[0]
            if sensor_data and v and (H.section_of(v) != ".text" or not v & 1):
                die(f"non-callback value in sensor callback record at {base_hub + i:#x}")
            sec = H.section_of(v) if 0x10000 <= v < 0x2e0000 else None
            if not sec:
                continue
            try:
                mk = self.map_data(v, f"{label}+{i:#x}")
            except BuildError as e:
                self.report["refused"].append({"block": label, "offset": hex(i), "value": hex(v),
                                               "section": sec, "reason": str(e)})
                continue
            struct.pack_into("<I", out, i, mk[1])
            self.report["relocations"].append({"kind": "dataword", "block": label, "offset": hex(i),
                                               "hub_value": hex(v), "map": [mk[0], hex(mk[1])]})
        return bytes(out)

    # --- layout ------------------------------------------------------------------
    def layout(self, funcs):
        H = self.H
        # Farsight unit: one block, layout preserved (address % 16 kept)
        unit_bytes = H.data[H.off(FARSIGHT_UNIT[0]):H.off(FARSIGHT_UNIT[1])]
        self.unit_new = self.rx_alloc(b"\0" * len(unit_bytes), align=16, mod=FARSIGHT_UNIT[0] % 16)
        self.unit_funcs = [f for f in funcs.values() if FARSIGHT_UNIT[0] <= f.entry < FARSIGHT_UNIT[1]]
        # glue: one block per function span
        self.glue_blocks = {}
        for n, f in sorted(funcs.items(), key=lambda kv: kv[1].entry):
            if FARSIGHT_UNIT[0] <= f.entry < FARSIGHT_UNIT[1]:
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
        # read-only data
        rb = H.data[H.off(RODATA_BLOCK[0]):H.off(RODATA_BLOCK[1])]
        self.rodata_new = self.rx_alloc(b"\0" * len(rb), align=16, mod=RODATA_BLOCK[0] % 16)
        self.const_new = {a: self.rx_alloc(H.data[H.off(a):H.off(a) + ln], align=4) for a, ln in RODATA_CONSTS}
        # RW: farsight .data image, .bss, glue data, private flag
        self.data_new = self.rw_alloc(DATA_BLOCK[1] - DATA_BLOCK[0], align=16)
        self.bss_new = self.rw_alloc(BSS_BLOCK[1] - BSS_BLOCK[0], align=16)
        self.glue_new = {}
        for a, ln, kind in GLUE_DATA:
            img = H.data[H.off(a):H.off(a) + ln] if kind == "data" else None
            self.glue_new[a] = self.rw_alloc(ln, align=8, image=img)
        self.private_flag = self.rw_alloc(4, align=4)
        # GOT-style pointer cells (read-only: they hold link-time constant addresses)
        cells = {}
        for off, (kind, hubaddr) in GOT_CELL_TARGETS.items():
            tgt = self.private_flag if kind == "private_flag" else self.data_new + (hubaddr - DATA_BLOCK[0])
            cells[off] = self.rx_alloc(struct.pack("<I", tgt), align=4)
        self.got_cells = cells
        self.sym["g_sns_farsight_obj"] = self.data_new + (H.syms["g_sns_farsight_obj"][0] - DATA_BLOCK[0])
        self.complete_got_cells(funcs)

    def complete_got_cells(self, funcs):
        """Carry every resolved non-libc GOT target, including callback functions.

        Conditional control flow must not turn a function-pointer GOT load into
        an unclassified scalar. Unknown targets still refuse the build.
        """
        for function in funcs.values():
            for address, literal, offset, base in function.gotloads:
                if base != HUB_GOT:
                    die(f"unclassified GOT base {base:#x} at {address:#x}")
                if offset in GOT_MAP_SYM or offset in self.got_cells:
                    continue
                target = self.H.u32(HUB_GOT + offset)
                if not target or self.H.section_of(target) is None:
                    die(f"GOT slot {offset:#x} contains non-address {target:#x}")
                kind, mapped = self.map_data(target, f"gotcell_{offset:#x}")
                self.got_cells[offset] = self.rx_alloc(struct.pack("<I", mapped), align=4)
                self.report.setdefault("discovered_got_cells", {})[hex(offset)] = {
                    "hub_target": hex(target), "map": kind, "resolved": hex(mapped)}

    def fill_carried(self):
        H = self.H
        ub = self.relocate_block(FARSIGHT_UNIT[0], FARSIGHT_UNIT[1], self.unit_new, self.unit_funcs,
                                 "farsight_unit")
        o = self.unit_new - NEW_RX_VA
        self.rx[o:o + len(ub)] = ub
        for n, g in self.glue_blocks.items():
            b = self.relocate_block(g["lo"], g["hi"], g["new"], [g["func"]], n)
            o = g["new"] - NEW_RX_VA
            self.rx[o:o + len(b)] = b
        rb = self.relocate_words(H.data[H.off(RODATA_BLOCK[0]):H.off(RODATA_BLOCK[1])], RODATA_BLOCK[0],
                                 "rodata_block", destination=self.rodata_new)
        o = self.rodata_new - NEW_RX_VA
        self.rx[o:o + len(rb)] = rb
        dimg = self.relocate_words(H.data[H.off(DATA_BLOCK[0]):H.off(DATA_BLOCK[1])], DATA_BLOCK[0],
                                   "data_block", destination=self.data_new)
        self.rw_images.append((self.data_new, dimg))

    # --- 19.2.14 helpers ---------------------------------------------------------
    def n19(self, name):
        return self.N.syms[name][0] | 1

    def plt_arm(self, name):
        if name not in self.N.plt_labels:
            die(f"19.2.14 has no PLT entry for {name}")
        return self.N.plt_target(name, to_arm=True)

    def expect(self, addr, mnem_prefix, opfrag=""):
        ins = self.N.disasm1(addr)
        if not ins.mnemonic.startswith(mnem_prefix) or opfrag not in ins.op_str:
            die(f"patch site {addr:#x}: expected '{mnem_prefix} {opfrag}', found '{ins.mnemonic} {ins.op_str}'")
        return ins

    def patch(self, addr, code: bytes, span: int, what: str):
        if len(code) > span:
            die(f"patch at {addr:#x} ({what}) needs {len(code)} > {span} bytes")
        code = code + NOP16 * ((span - len(code)) // 2)
        o = self.N.off(addr)
        old = bytes(self.out[o:o + span])
        self.out[o:o + span] = code
        self.report["patches"].append({"site": hex(addr), "span": span, "what": what,
                                       "old": old.hex(), "new": code.hex()})

    def pic_target(self, ldr_addr, add_addr):
        ins = self.N.disasm1(ldr_addr)
        lit = ((ldr_addr + 4) & ~3) + ins.operands[1].mem.disp
        return (self.N.u32(lit) + add_addr + 4) & 0xFFFFFFFF, lit

    def new_string(self, s: bytes):
        s = s if s.endswith(b"\0") else s + b"\0"
        if s not in self.str_pool:
            self.str_pool[s] = self.rx_alloc(s, align=1)
        return self.str_pool[s]

    # --- new functions and trampolines --------------------------------------------
    def _sources(self, final):
        N = self.N
        Z = FE.Image(self.z40_path)
        # strings from the dedicated 17.5.8 Z40 binary (behavioural reference)
        rot_fmt_addr, _ = (lambda i: ((Z.u32(((0x6785e + 4) & ~3) + i.operands[1].mem.disp) + 0x67860 + 4)
                                      & 0xFFFFFFFF, None))(Z.disasm1(0x6785e))
        o = Z.off(rot_fmt_addr)
        rot_fmt = Z.data[o:Z.data.index(b"\0", o) + 1]
        mk = self.new_string if final else (lambda b: NEW_RX_VA)
        S = {"Z40": mk(b"Z40"), "imx586": mk(b"imx586"), "ps5280": mk(b"ps5280"),
             "dm8c": mk(b"devmem 0x1794008c 32 0x1130"),
             "dm84": mk(b"devmem 0x17940084 32 0x1213"),
             "rotfmt": mk(rot_fmt),
             "slash": mk(b"%s/%s"),
             "tundir": mk(b"/usrdata/fpv/tunning"),
             "pqfile": mk(b"cam_imx586_50fps_z40_xg1.bin"),
             "scaleerr": mk(b"ss_mpi_vpss_set_chn_scale_coef_type, err, ret=0x%x\n")}
        if self.direct_camera_routing:
            S['pspqfile'] = mk(b'cam_ps5280_50fps_z40.bin')
        if final:
            self.report["notes"].append({"rotation_printf_format_from_z40_17_5_8": rot_fmt.decode(errors="replace")})
            tbl = bytearray()
            for dst, img in self.rw_images:
                src = self.rx_alloc(img, align=4)
                tbl += struct.pack("<III", dst, src, len(img))
            init_tbl = self.rx_alloc(bytes(tbl), align=4)
            init_end = init_tbl + len(tbl)
        else:
            init_tbl = init_end = NEW_RX_VA

        ext = {"strcmp_arm": self.plt_arm("strcmp"), "strcpy_arm": self.plt_arm("strcpy"),
               "system_arm": self.plt_arm("system"), "usleep_arm": self.plt_arm("usleep"),
               "printf_arm": self.plt_arm("printf"), "memcpy_arm": self.plt_arm("memcpy"),
               "sprintf_arm": self.plt_arm("sprintf"), "fopen_arm": self.plt_arm("fopen"),
               "get_uav_ctx": self.n19("get_uav_ctx"), "get_fpv_gctx": self.n19("get_fpv_gctx"),
               "fpv_record_cfg": self.n19("fpv_record_cfg"), "fpv_bb_is_locked": self.n19("fpv_bb_is_locked"),
               "scale_coef": self.n19("ss_mpi_vpss_set_chn_scale_coef_type"),
               "set_gpio_val": self.sym["set_gpio_val"], "fpv_set_vpss_rotation": self.sym["fpv_set_vpss_rotation"],
               "uninit_vpss": self.sym["uninit_vpss"], "init_vpss": self.sym["init_vpss"],
               "msp_inav": self.sym["mspSerialParaINAVRcSlot"],
               "msp_rc_init": self.sym["fpv_msp_rc_config_init"],
               "streamzoom_init": self.sym["fpv_sky_streamzoom_init"]}
        for k, v in S.items():
            ext["s_" + k] = v
        ext["init_tbl"], ext["init_end"] = init_tbl, init_end

        # sources (labels resolved by the assembler; absolute externals by --defsym)
        gst = N.disasm1(N.syms["get_sensor_type"][0] & ~1)
        if gst.size != 4 or not gst.mnemonic.startswith(("push", "stmdb")):
            die(f"get_sensor_type entry is '{gst.mnemonic} {gst.op_str}', not a 4-byte push")
        fs0 = N.syms["fpv_sys_get_sensor_type"][0] & ~1
        self.expect(fs0, "push", "{r4, lr}")
        self.expect(fs0 + 2, "bl")
        ivv_msg, _ = self.pic_target(0x67138, 0x6713a)
        lpq = N.syms["load_pq_bin"][0] & ~1
        SRC = {
         "direct_sensor_object":
            "push {r3,lr}\nbl direct_sensor_row\nldr r0,[r0,#4]\npop {r3,pc}\n",
         "z40_cam": "push {r4, lr}\nldr r1, =s_Z40\nldr ip, =strcmp_arm\nblx ip\nclz r0, r0\nlsrs r0, r0, #5\npop {r4, pc}\n.ltorg\n",
         "z8_unreachable": "mov.w r0, #-1\nbx lr\n",
         "sensor_prepare_dual":
            "push {r4, lr}\nldr r0, =s_dm8c\nldr ip, =system_arm\nblx ip\nldr r0, =s_dm84\nldr ip, =system_arm\nblx ip\n"
            "ldr r4, =100000\nmov r0, r4\nldr ip, =usleep_arm\nblx ip\n"
            "movs r0, #58\nmovs r1, #0\nbl set_gpio_val\nmovs r0, #52\nmovs r1, #0\nbl set_gpio_val\n"
            "mov r0, r4\nldr ip, =usleep_arm\nblx ip\nmovs r0, #0\npop {r4, pc}\n.ltorg\n",
         "uar_ar_set_sensor_want_rotation":
            "push {r4, lr}\nmov r1, r0\nmov r4, r0\nldr r0, =s_rotfmt\nldr ip, =printf_arm\nblx ip\n"
            "bl get_uav_ctx\nstr r4, [r0, #0x68]\nmovs r1, #0\nmov r0, r1\nbl fpv_set_vpss_rotation\n"
            "movs r0, #0\npop {r4, pc}\n.ltorg\n",
         "z40_init":
            "push {r4, r5, r6, lr}\nldr r4, =init_tbl\nldr r5, =init_end\n1:\ncmp r4, r5\nbhs 2f\n"
            "ldmia r4!, {r0, r1, r2}\nldr ip, =memcpy_arm\nblx ip\nb 1b\n2:\npop {r4, r5, r6, pc}\n.ltorg\n",
         "z40_main_sensor":
            "push {r4, lr}\nmov r4, r0\nbl z40_init\nmov r0, r4\nldr r1, =s_imx586\nldr ip, =strcpy_arm\nblx ip\n"
            "bl sensor_prepare_dual\nbl get_fpv_gctx\nmovw r2, #2000\nmovw r3, #1500\nstrd r2, r3, [r0, #0x20]\n"
            "movs r3, #50\nstr r3, [r0, #0x28]\nldr r0, =s_imx586\npop {r4, pc}\n.ltorg\n",
         "tramp_rec":
            "push {r4, lr}\nbl fpv_record_cfg\nbl msp_rc_init\nbl streamzoom_init\npop {r4, pc}\n",
         "tramp_gst":
            "push {r0, r1, r2, r3, r4, lr}\nldr r1, =s_imx586\nldr ip, =strcmp_arm\nblx ip\ncmp r0, #0\n"
            "pop {r0, r1, r2, r3, r4, lr}\nbne 1f\nmovs r0, #0x16\nbx lr\n1:\n"
            f".inst.w 0x{struct.unpack('<HH', N.data[N.off(gst.address):N.off(gst.address)+4])[0]:04x}"
            f"{struct.unpack('<HH', N.data[N.off(gst.address):N.off(gst.address)+4])[1]:04x}\n"
            "b.w gst_cont\n.ltorg\n",
         "tramp_fsgst":
            "push {r4, lr}\nbl get_fpv_gctx\nldr r1, =s_imx586\nldr ip, =strcmp_arm\nblx ip\ncmp r0, #0\n"
            "pop {r4, lr}\nbne 1f\nmovw r0, #586\nbx lr\n1:\npush {r4, lr}\nbl get_fpv_gctx\nb.w fsgst_cont\n.ltorg\n",
         "tramp_ivv":
            "cmp r3, #0x16\nbeq 1f\nldr r0, =ivv_msg\nb.w ivv_err\n1:\n"
            "mov.w r2, #2000\nmovw r3, #1500\nstrd r2, r3, [r4, #0x44]\nmovs r3, #50\nstr r3, [r4, #0x4c]\n"
            "ldr r3, [r4, #0x38]\nstr r3, [r4, #0x50]\nldr r3, [r4, #0x3c]\nstr r3, [r4, #0x54]\nb.w ivv_join\n.ltorg\n",
         "tramp_scale":
            "push {r4, lr}\nmovs r0, #0\nmovs r1, #0\nmovs r2, #1\nbl scale_coef\ncbnz r0, 1f\n"
            "ldr r3, [r5, #4]\ncmp r3, #0\npop {r4, pc}\n1:\nmov r1, r0\nldr r0, =s_scaleerr\npop {r4, lr}\n"
            "b.w dovv_err\n.ltorg\n",
         "tramp_msp":
            "push {r4, lr}\naddw r0, sp, #0x51c\nmov r1, r7\nbl msp_inav\nbl fpv_bb_is_locked\npop {r4, pc}\n",
         "tramp_acc":
            "cmp r0, #0\nbne 1f\nb.w lpq_ok\n1:\nmov r0, NAMEREG\nldr r1, =s_imx586\nldr ip, =strcmp_arm\nblx ip\n"
            "cmp r0, #0\nbne 2f\nb.w lpq_ok\n2:\nb.w lpq_bad\n.ltorg\n",
         "tramp_fopen":
            "push {r0, r1, r2, lr}\nldr r1, =s_slash\nldr r2, =s_tundir\nldr r3, =s_pqfile\nldr ip, =sprintf_arm\n"
            "blx ip\npop {r0, r1, r2, lr}\nldr ip, =fopen_arm\nbx ip\n.ltorg\n",
        }
        if self.direct_camera_routing:
            # H9 receives the complete, already decoded MSP frame. Keep binary
            # MSP_RC and DisplayPort on the existing receiver/zoom-state owner.
            ext['msp_osd'] = self.sym['mspSerialParaOsdRcSlot']
            SRC['tramp_msp'] = (
                'push {r4,r5,r6,lr}\naddw r4,sp,#0x524\nmov r5,r7\n'
                'mov r0,r4\nmov r1,r5\nbl displayport_zoom_frame\n'
                'mov r0,r4\nmov r1,r5\nbl msp_inav\n'
                'bl fpv_bb_is_locked\npop {r4,r5,r6,pc}\n')
            # The vendor parser bounds length/signature/range/row sequence, but
            # strtol alone accepts malformed text as zero. Validate exactly
            # five characters here; only the vendor's buffered fields reach
            # strtol, never the unbounded raw receive buffer.
            # Recheck the MSP checksum too; unrelated MSP traffic passes through.
            SRC['displayport_zoom_v1'] = (
                'cmp r1,#15\nbne 9f\npush {r4,r5,r6,lr}\n'
                'mov r4,r0\nmov r5,r1\nmovs r2,#0\nmovs r3,#3\n'
                '1:\nldrb r0,[r4,r3]\neors r2,r0\nadds r3,#1\n'
                'cmp r3,#14\nbne 1b\nldrb r0,[r4,#14]\ncmp r0,r2\nbne 8f\n'
                'movs r2,#9\nmovs r3,#0\n'
                '2:\nldrb r0,[r4,r2]\ncmp r3,#0\nbne 3f\n'
                'cmp r0,#32\nbeq 5f\ncmp r0,#43\nbeq 4f\n'
                'cmp r0,#45\nbeq 4f\n'
                '3:\nsubs r0,#48\ncmp r0,#9\nbhi 8f\nmovs r3,#2\nb 5f\n'
                '4:\nmovs r3,#1\n'
                '5:\nadds r2,#1\ncmp r2,#14\nbne 2b\ncmp r3,#2\nbne 8f\n'
                'mov r0,r4\nmov r1,r5\nbl displayport_rc_range\n'
                '8:\npop {r4,r5,r6,pc}\n9:\nbx lr\n')
            from rc_displayport_transport import assembly_sources
            SRC.update(assembly_sources())
            # Normal 19.x can reload PQ after the initial camera bring-up.
            # Resolve each read from the existing selected-camera context;
            # an unconditional IMX file can switch ISP mode back under PS5280.
            SRC['tramp_fopen'] = (
                'push {r0,r1,r2,r3,r4,lr}\nmov r4,r0\nbl get_uav_ctx\n'
                'adds r0,#8\nldr r1,=s_ps5280\nldr ip,=strcmp_arm\nblx ip\n'
                'cmp r0,#0\nbne 1f\nldr r3,=s_pspqfile\nb 2f\n'
                '1: ldr r3,=s_pqfile\n2: mov r0,r4\nldr r1,=s_slash\n'
                'ldr r2,=s_tundir\nldr ip,=sprintf_arm\nblx ip\n'
                'pop {r0,r1,r2,r3,r4,lr}\nldr ip,=fopen_arm\nbx ip\n.ltorg\n')
        else:
            SRC.pop('direct_sensor_object')
        ext["direct_sensor_row"] = 0x65a99
        # Normal 19.x lacks the vendor IMX586 lane override on board revision 17.
        # Keep its getter/selection behavior and correct only the selected IMX586 row.
        SRC["lane_original"] = "push {r3,r4,r5,r6,r7,lr}\nmovs r0,#0\nb.w lane_cont\n"
        SRC["lane_imx586"] = (
            "push {r4,r5,r6,lr}\nbl lane_original\nmov r4,r0\ncbz r4,9f\n"
            "ldr r1,[r4]\ncmp r1,#0x16\nbne 9f\nbl get_uav_ctx\nmov r5,r0\n"
            "ldr r1,[r5]\ncmp r1,#2\nbne 9f\nadd r0,r5,#8\nldr r1,=s_imx586\n"
            "ldr ip,=strcmp_arm\nblx ip\ncmp r0,#0\nbne 9f\nldr r3,[r5,#4]\n"
            "cmp r3,#16\nblt 9f\nbeq 1f\nmovw r1,#0\nmovt r1,#2\n"
            "movw r2,#1\nmovt r2,#3\nb 2f\n1: movw r1,#0\nmovt r1,#1\n"
            "movw r2,#2\nmovt r2,#3\n2: ldr r0,[r4,#12]\ncbz r0,9f\n"
            "str r1,[r0,#0x24]\nstr r2,[r0,#0x28]\n9: mov r0,r4\npop {r4,r5,r6,pc}\n.ltorg\n")
        if self.dual_sensor_lanes:
            SRC["lane_imx586"] = SRC["lane_imx586"].replace(
                "ldr r1,[r4]\ncmp r1,#0x16\nbne 9f\n",
                "ldr r1,[r4]\ncmp r1,#0x16\nbeq 1f\ncmp r1,#0x0b\nbeq 2f\n"
                "cmp r1,#0x0c\nbne 9f\n2: ldr r6,=s_ps5280\nb 3f\n"
                "1: ldr r6,=s_imx586\n3:\n").replace(
                    "add r0,r5,#8\nldr r1,=s_imx586\n", "add r0,r5,#8\nmov r1,r6\n")
        ext["lane_cont"] = 0x65a9c | 1
        # load_pq_bin name register: the strcmp chain moves the name into r0 before each compare
        chain = self.expect(0x66c5a, "mov", "r0")
        namereg = chain.op_str.split(",")[1].strip()
        SRC["tramp_acc"] = SRC["tramp_acc"].replace("NAMEREG", namereg)
        ext.update({"gst_cont": (gst.address + 4) | 1, "fsgst_cont": (fs0 + 6) | 1,
                    "ivv_msg": ivv_msg, "ivv_err": 0x66fee | 1, "ivv_join": 0x6701c | 1,
                    "dovv_err": 0x663d4 | 1, "lpq_ok": 0x66c66 | 1, "lpq_bad": 0x66cee | 1})
        return SRC, ext

    def alloc_new_code(self):
        SRC, ext = self._sources(final=False)
        sizes, dummy = {}, dict(ext)
        for n in SRC:
            dummy.setdefault(n, NEW_RX_VA | 1)
        for n in SRC:
            d2 = {k: v for k, v in dummy.items() if k != n}
            sizes[n] = len(assemble(SRC[n], NEW_RX_VA + 0x100000, d2, name=n)) + 8
        self.new_addrs = {n: self.rx_alloc(b"\0" * sizes[n], align=4) for n in SRC}
        self.new_sizes = sizes
        for n, a in self.new_addrs.items():
            self.sym[n] = a | 1

    def final_new_code(self):
        SRC, ext = self._sources(final=True)
        for n, a in self.new_addrs.items():
            ext[n] = a | 1
        for n in SRC:
            d2 = {k: v for k, v in ext.items() if k != n}
            code = assemble(SRC[n], self.new_addrs[n], d2, name=n)
            if len(code) > self.new_sizes[n]:
                die(f"{n} grew between passes")
            o = self.new_addrs[n] - NEW_RX_VA
            self.rx[o:o + len(code)] = code
        self.newfuncs = {n: (hex(self.new_addrs[n]), self.new_sizes[n]) for n in SRC}
        return ext

    # --- 19.2.14 hook sites ------------------------------------------------------
    def apply_lane_hook(self, ext):
        site = 0x65a98
        original = self.N.data[self.N.off(site):self.N.off(site) + 4]
        if original != b'\xf8\xb5\x00\x20':
            die("sensor getter prologue changed; lane hook refused")
        self.patch(site, enc_bw(site, ext["lane_imx586"]), 4,
                   "IMX586 lane policy: vendor board16/board>16 values on each selected-row read")

    def apply_hooks(self, ext):
        self.apply_lane_hook(ext)
        N = self.N
        A = lambda src, addr, syms=ext: assemble(src, addr, {k: v for k, v in syms.items()})
        # H1a main: replace detect/save/fallback/geometry chain with the dedicated Z40 sequence
        self.expect(0x5a6aa, "bl")
        if N.name_of(0x658c8) != "uav_ar_sys_detect_sensor":
            die("H1a: unexpected callee at main+0x5a6aa")
        self.patch(0x5a6aa, A("mov r0, r6\nbl z40_main_sensor\nmov r8, r0\nb.w h1_join\n", 0x5a6aa,
                              dict(ext, h1_join=0x5a6fc | 1)), 0x5a6e6 - 0x5a6aa,
                   "H1a main: strcpy(gctx,'imx586'); sensor_prepare_dual; gctx 2000x1500@50 (17.5.8 Z40)")
        # H1b main: after fpv_record_cfg -> fpv_msp_rc_config_init, fpv_sky_streamzoom_init
        self.expect(0x5a7ba, "bl")
        self.patch(0x5a7ba, enc_bl(0x5a7ba, ext["tramp_rec"]), 4, "H1b main: tramp_rec")
        # H2 get_sensor_type: 'imx586' -> 0x16
        g = N.syms["get_sensor_type"][0] & ~1
        self.patch(g, enc_bw(g, ext["tramp_gst"]), 4, "H2 get_sensor_type: imx586 -> E1 0x16")
        # H3 init_vi_vpss: case 0x16 before the unknown-type exit
        self.expect(0x67138, "ldr", "r0")
        self.expect(0x6713a, "add", "r0, pc")
        self.patch(0x67138, enc_bw(0x67138, ext["tramp_ivv"]), 4, "H3 init_vi_vpss: case 0x16 2000x1500@50")
        # H4 vi_register_sensor: 22-row table + sizes
        for a, m, frag, new in [(0x66b38, "sub", "#0x2ac", "subw sp, sp, #0x2cc"),
                                (0x66b46, "mov", "#0x2a0", "mov.w r2, #0x2c0"),
                                (0x66b56, "mov", "#0x2a0", "mov.w r0, #0x2c0"),
                                (0x66b7c, "mov", "#0x2a0", "mov.w r2, #0x2c0"),
                                (0x66b9c, "add", "#0x2ac", "addw sp, sp, #0x2cc")]:
            ins = self.expect(a, m, frag)
            self.patch(a, A(new + "\n", a), ins.size, f"H4 vi_register_sensor {ins.mnemonic} {ins.op_str} -> {new}")
        for a, frag, new in [(0x66b4c, "#0x2a4", "str r3, [sp, #0x2c4]"), (0x66b8e, "#0x2a4", "ldr r3, [sp, #0x2c4]")]:
            ins = self.expect(a, "str" if new.startswith("str") else "ldr", frag)
            self.patch(a, A(new + "\n", a), ins.size, f"H4 canary {ins.op_str} -> {new}")
        ins = self.expect(0x66b76, "movs", "#0x15")
        self.patch(0x66b76, A("movs r2, #0x16\n", 0x66b76), 2, "H4 row count 0x15 -> 0x16")
        tgt, lit = self.pic_target(0x66b3c, 0x66b44)
        if tgt != 0x265780:
            die("H4 table literal mismatch")
        self.patch(lit, struct.pack("<I", (self.table_new - (0x66b44 + 4)) & 0xFFFFFFFF), 4,
                   "H4 table source -> new 22-row table")
        # H5 fpv_sys_get_sensor_type: 'imx586' -> 586
        f0 = N.syms["fpv_sys_get_sensor_type"][0] & ~1
        self.patch(f0, enc_bw(f0, ext["tramp_fsgst"]), 6, "H5 fpv_sys_get_sensor_type: imx586 -> E2 586")
        # H6 fpv_config_init default fps 60 -> 50
        self.expect(0x5f6c4, "movs", "r2, #0x3c")
        self.patch(0x5f6c4, A("movs r2, #50\n", 0x5f6c4), 2, "H6 fpv_config_init default fps 60 -> 50")
        # H7 fpv_sys_ch0_res_remap: w,h passthrough; fps always 50 (17.5.8 Z40 form)
        c0, csz = N.syms["fpv_sys_ch0_res_remap"][0] & ~1, N.syms["fpv_sys_ch0_res_remap"][1]
        self.patch(c0, A("str r0, [r3]\nldr ip, [sp]\nstr r1, [ip]\nldr ip, [sp, #4]\nmovs r1, #50\n"
                         "str r1, [ip]\nmovs r0, #0\nbx lr\n", c0), csz,
                   "H7 fpv_sys_ch0_res_remap: out_w=w, out_h=h, out_fps=50, return 0")
        # H8 uav_ar_sys_set_sensor_res: Z40 tail (vpss re-init + rotation), literal pool at 0x656cc kept
        self.expect(0x65686, "ldr", "r0")
        self.patch(0x65686, A("str.w fp, [r4, #0x68]\nbl uninit_vpss\nmovw r0, #10000\nldr ip, =usleep_arm\nblx ip\n"
                              "bl init_vpss\nmov r0, fp\nbl uar_ar_set_sensor_want_rotation\nmovs r0, #0\n"
                              "add sp, #20\npop.w {r4, r5, r6, r7, r8, r9, sl, fp, pc}\n.ltorg\n", 0x65686),
                   0x656cc - 0x65686, "H8 uav_ar_sys_set_sensor_res: Z40 tail")
        # H9 MSP parser: INAV RC slot before fpv_bb_is_locked
        self.expect(0x6ccda, "bl")
        self.patch(0x6ccda, enc_bl(0x6ccda, ext["tramp_msp"]), 4, "H9 MSP parser: mspSerialParaINAVRcSlot")
        # H10 load_pq_bin: accept imx586; override filename (17.5.8 Z40)
        self.expect(0x66c62, "cmp", "r0, #0")
        self.patch(0x66c62, enc_bw(0x66c62, ext["tramp_acc"]), 4, "H10a load_pq_bin: accept 'imx586'")
        ins = self.expect(0x66cdc, "blx")
        if N.name_of(ins.operands[0].imm) not in ("plt:fopen",) and N.plt.get(ins.operands[0].imm - 4) != "fopen" \
                and N.plt.get(ins.operands[0].imm) != "fopen":
            die(f"H10b: callee at 0x66cdc is not fopen ({ins.op_str})")
        self.patch(0x66cdc, enc_bl(0x66cdc, ext["tramp_fopen"]), 4,
                   "H10b load_pq_bin: filename -> /usrdata/fpv/tunning/cam_imx586_50fps_z40_xg1.bin")
        # H11 init_vb default branch: Z40 pools (Hub B051)
        self.expect(0x6536e, "vstr")
        self.patch(0x6536e, A("movw r3, #0xdc80\nmovt r3, #0x39\nstr r3, [r4, #8]\nmovs r3, #0\nstr r3, [r4, #12]\n"
                              "movs r3, #4\nstr r3, [r4, #16]\nmovw r3, #0xc3a0\nmovt r3, #0x45\nstr r3, [r4, #56]\n"
                              "movs r3, #0\nstr r3, [r4, #60]\nmovs r3, #4\nstr r3, [r4, #64]\nb.w vb_join\n",
                              0x6536e, dict(ext, vb_join=0x65350 | 1)), 0x653be - 0x6536e,
                   "H11 init_vb: pool0 3792000x4 (RAW 2000x1500), pool1 4572064x4 (YUV 2000x1500)")
        # Dedicated direct-camera images use mode 1, independently of Hub.
        self.expect(0x66110, "movs", "r0, #3")
        self.patch(0x66110, A("movs r0, #1\n", 0x66110), 2, "H12a direct-camera vi_vpss_mode 3 -> 1 (native Z40)")
        self.expect(0x66856, "ldr", "r3, [r5, #4]")
        self.expect(0x66858, "cmp", "r3, #0")
        self.patch(0x66856, enc_bl(0x66856, ext["tramp_scale"]), 4,
                   "H12b do_init_vi_vpss: ss_mpi_vpss_set_chn_scale_coef_type(0,0,1)")

    def build_table(self):
        N, H = self.N, self.H
        tbl = bytearray(N.data[N.off(0x265780):N.off(0x265780) + 0x2a0])
        found0b = False
        for i in range(21):
            t, obj = struct.unpack_from("<II", tbl, 32 * i)
            if t == 0x0b:
                if obj != N.syms["g_sns_ps5280_obj_4lane"][0]:
                    die("row 0x0b object is not ps5280_4lane")
                struct.pack_into("<I", tbl, 32 * i + 4, self.sym["g_sns_farsight_obj"])
                found0b = True
            if t == 0x16:
                die("19.2.14 already has a type 0x16 row")
        if not found0b:
            die("row 0x0b not found")
        # Hub IMX586 row (type 0x11): its four specific attrs + two shared (taken from 19.2.14 row 0x0b)
        hrow = None
        for i in range(22):
            w = struct.unpack_from("<8I", H.data, H.off(0x2936fc) + 32 * i)
            if w[0] == 0x11:
                hrow = w
        if hrow is None:
            die("Hub IMX586 row not found")
        n0b = next(struct.unpack_from("<8I", tbl, 32 * i) for i in range(21) if struct.unpack_from("<I", tbl, 32 * i)[0] == 0x0b)
        sizes = {2: 0x44, 3: 0xc8, 4: 0x2c, 6: 0x20}
        attrs = {}
        for k, ln in sizes.items():
            image = H.data[H.off(hrow[k]):H.off(hrow[k]) + ln]
            attrs[k] = self.rw_alloc(ln, align=4, image=image) if k == 3 else self.rx_alloc(image, align=4)
        # shared attrs: +0x14 (index 5) and +0x1c (index 7) must equal 19.2.14 row 0x0b content
        for k, ln in ((5, 0x78), (7, 0x20)):
            if H.data[H.off(hrow[k]):H.off(hrow[k]) + ln] != N.data[N.off(n0b[k]):N.off(n0b[k]) + ln]:
                die(f"shared attr index {k} differs between Hub IMX586 row and 19.2.14 row 0x0b")
        row = struct.pack("<8I", 0x16, self.sym["g_sns_farsight_obj"], attrs[2], attrs[3], attrs[4],
                          n0b[5], attrs[6], n0b[7])
        self.table_new = self.rx_alloc(bytes(tbl) + row, align=8)
        self.report["notes"].append({"table": hex(self.table_new), "rows": 22, "row_0x16": [hex(x) for x in
                                     struct.unpack("<8I", row)]})

    # --- ELF emission -----------------------------------------------------------
    def emit(self):
        N = self.N
        out = self.out
        rw_end_new = self.rw_base + self.rw_size
        if rw_end_new > NEW_RX_VA:
            die(f"RW extension {rw_end_new:#x} collides with new RX segment {NEW_RX_VA:#x}")
        # append RX segment page-aligned at a file offset congruent to its VA
        while len(out) % 0x1000:
            out += b"\0"
        rx_off = len(out)
        out += self.rx
        ph = []
        e_phoff, e_phnum = struct.unpack_from("<I", out, 0x1c)[0], struct.unpack_from("<H", out, 0x2c)[0]
        for i in range(e_phnum):
            ph.append(list(struct.unpack_from("<8I", out, e_phoff + 32 * i)))
        PT_LOAD, PT_PHDR, PT_INTERP = 1, 6, 3
        kinds = [p[0] for p in ph]
        if kinds.count(PT_LOAD) != 2 or PT_PHDR not in kinds:
            die("unexpected program header layout")
        loads = [p for p in ph if p[0] == PT_LOAD]
        rw = loads[1]
        rw[5] = rw_end_new - rw[2]                       # p_memsz grows: anonymous zero memory
        newload = [PT_LOAD, rx_off, NEW_RX_VA, NEW_RX_VA, len(self.rx), len(self.rx), 5, 0x1000]
        order = [p for p in ph if p[0] not in (PT_PHDR, PT_LOAD)]
        interp_i = next(i for i, p in enumerate(order) if p[0] == PT_INTERP)
        order = order[:interp_i + 1] + [loads[0], rw, newload] + order[interp_i + 1:]
        if len(order) != e_phnum:
            die("phdr count changed")
        for i, p in enumerate(order):
            struct.pack_into("<8I", out, e_phoff + 32 * i, *p)
        self.report["elf"] = {"rx_va": hex(NEW_RX_VA), "rx_file_off": hex(rx_off), "rx_size": len(self.rx),
                              "rw_ext_base": hex(self.rw_base), "rw_ext_size": self.rw_size,
                              "rw_memsz_old_end": hex(self.rw_end), "rw_memsz_new_end": hex(rw_end_new),
                              "phdr_order": [hex(p[0]) for p in order]}
        return bytes(out)


def object_starts(H):
    """Every address in the donor that a pointer could legitimately hold: function entries
    (both Thumb and even), every PIC/GOT target anywhere in .text, every dynamic symbol."""
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
    from capstone.arm import ARM_OP_MEM, ARM_OP_REG, ARM_REG_PC
    t = H.elf.get_section_by_name(".text")
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB); md.detail = True; md.skipdata = True
    out, pend = set(), {}
    for ins in md.disasm(t.data(), t["sh_addr"]):
        if not ins.id:
            continue
        o = ins.operands
        if ins.mnemonic.startswith("ldr") and len(o) == 2 and o[1].type == ARM_OP_MEM and o[1].mem.base == ARM_REG_PC:
            lit = ((ins.address + 4) & ~3) + o[1].mem.disp
            off = H.off(lit)
            if off is not None:
                pend[o[0].reg] = struct.unpack_from("<I", H.data, off)[0]
        elif ins.mnemonic.startswith("add") and len(o) == 2 and o[1].type == ARM_OP_REG and o[1].reg == ARM_REG_PC \
                and o[0].reg in pend:
            out.add((pend.pop(o[0].reg) + ins.address + 4) & 0xFFFFFFFF)
    gs = H.elf.get_section_by_name(".got")
    gd = gs.data()
    out |= {struct.unpack_from("<I", gd, i)[0] for i in range(0, len(gd), 4)}
    out |= {a | 1 for a in H.func_starts} | set(H.func_starts) | {v[0] for v in H.syms.values()}
    return out


def build(hub, n19, z40):
    b = Build(hub, n19)
    b.z40_path = z40
    funcs = b.carry_functions()
    b.layout(funcs)
    b.alloc_new_code()            # addresses for z40_cam, z8_unreachable, tramps, ...
    b.fill_carried()              # relocate carried code/data (needs redirect targets)
    from direct_camera import install_z40_hardware
    install_z40_hardware(b)
    b.build_table()               # mutable combo attrs must join the RW init image table
    ext = b.final_new_code()      # strings, z40_init table (needs relocated data image), final code
    b.apply_hooks(ext)
    starts = object_starts(b.H)
    for x in b.report["refused"]:
        v = int(x["value"], 16)
        if v in starts:
            die(f"unrelocated word {x} equals a real object start")
    b.report["nonpointer_words_verified"] = b.report.pop("refused")
    elf = b.emit()
    b.report["carried_functions"] = {n: {"hub_entry": hex(f.entry), "hub_span": [hex(f.lo), hex(f.hi)]}
                                     for n, f in funcs.items()}
    b.report["new_functions"] = b.newfuncs
    b.report["sym"] = {k: hex(v) for k, v in b.sym.items()}
    b.report["layout"] = {"unit_new": hex(b.unit_new), "unit_hub": [hex(x) for x in FARSIGHT_UNIT],
                          "rodata_new": hex(b.rodata_new), "rodata_hub": [hex(x) for x in RODATA_BLOCK],
                          "data_new": hex(b.data_new), "data_hub": [hex(x) for x in DATA_BLOCK],
                          "bss_new": hex(b.bss_new), "bss_hub": [hex(x) for x in BSS_BLOCK],
                          "glue_data": {hex(a): hex(b.glue_new[a]) for a, _, _ in GLUE_DATA},
                          "private_flag": hex(b.private_flag),
                          "got_cells": {hex(k): hex(v) for k, v in b.got_cells.items()},
                          "glue_blocks": {n: {"hub": [hex(g["lo"]), hex(g["hi"])], "new": hex(g["new"])}
                                          for n, g in b.glue_blocks.items()},
                          "table_new": hex(b.table_new), "const_new": {hex(k): hex(v) for k, v in b.const_new.items()},
                          "rw_images": [[hex(d), len(i)] for d, i in b.rw_images]}
    b.report["strings_carried"] = len(b.str_pool)
    return b, elf


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--hub", required=True)
    ap.add_argument("--n19", required=True)
    ap.add_argument("--z40", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--report", required=True)
    a = ap.parse_args()
    b, elf = build(a.hub, a.n19, a.z40)
    Path(a.out).write_bytes(elf)
    b.report["output"] = {"sha256": hashlib.sha256(elf).hexdigest(), "bytes": len(elf)}
    Path(a.report).write_text(json.dumps(b.report, indent=1))
    print(json.dumps({"output": b.report["output"], "nonpointer_words_verified": len(b.report["nonpointer_words_verified"]),
                      "relocations": len(b.report["relocations"]), "patches": len(b.report["patches"]),
                      "elf": b.report["elf"]}, indent=1))
