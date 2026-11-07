#!/usr/bin/env python3
"""Hub direct-interposer transplant into 19.2.14 ar_ldyhs_sky.

Separate engine. REUSES the proven Mode A machinery (z40_build.Build relocation/emit/GOT, Thumb
encoders, object_starts) by import + subclass; does NOT modify z40_build.py/z8_build.py, Z40/Z8
Candidate1, or any frozen artefact. Hub conditionals live only here.

Transplant (plan §5.1/§5.2, closures §7):
  * contiguous sensor unit (0x100b5c,0x1066a0) = imx586 + farsight, carried whole.
  * hub-layer (34 fns) + the 12 hub-aware changed functions + their static closure, carried as
    glue; the 12 changed 19.2.14 entries are REDIRECTED (b.w) to the carried hub versions.
  * `main` gets targeted hub hooks (fpv_hub_init etc.); venc_create/stream_get kept stock.
  * Hub keeps dual-sensor + expander (NO G1 neutralization).
  * Data model: shared stock globals -> the single 19.2.14 instance (3 anonymous via SHARED_MAP,
    named-objects-in-19.2.14 by name); hub-specific data/bss carried per object; fail-closed on
    any shared-but-unmapped reference.
  * String swap: /factory/mipi_hub.json -> /usrdata/fpv/mipi_hub.json (component-5 config, §5.4a).
"""
from __future__ import annotations

import bisect
import hashlib
import json
import os
import struct
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import z40_build as Z
from z40_build import die, enc_bl, enc_bw, NOP16, assemble, object_starts
import fextent as FE
import subprocess, tempfile
from z40_build import TOOLS
from arm_tools import tool as arm_tool


def assemble_arm(src: str, addr: int, *, name="arm_shim") -> bytes:
    """Assemble position-independent ARM code at a fixed address (for BLX-reachable shims)."""
    with tempfile.TemporaryDirectory() as td:
        from pathlib import Path as _P
        sp = _P(td, "a.s")
        sp.write_text(".syntax unified\n.arm\n.cpu cortex-a7\n.fpu neon-vfpv4\n"
                      ".section .text\n.global _start\n_start:\n" + src + "\n")
        o, elf, binf = _P(td, "a.o"), _P(td, "a.elf"), _P(td, "a.bin")
        r = subprocess.run([arm_tool("as", TOOLS), "-o", str(o), str(sp)],
                           capture_output=True, text=True)
        if r.returncode:
            die(f"arm as failed for {name}: {r.stderr}")
        r = subprocess.run([arm_tool("ld", TOOLS), "-Ttext", hex(addr), "-e", "_start",
                            "-o", str(elf), str(o)], capture_output=True, text=True)
        if r.returncode:
            die(f"arm ld failed for {name}: {r.stderr}")
        subprocess.run([arm_tool("objcopy", TOOLS), "-O", "binary", "-j", ".text",
                        str(elf), str(binf)], check=True)
        return binf.read_bytes()


# Localized compatibility shims (self-contained, ARM, in new code space). They reproduce libc/
# pthread primitives stock 19.2.14 does not import, WITHOUT touching the ELF dynamic/hash tables.
# Called only from carried hub code (all via blx -> ARM). Return-value semantics proven against the
# exact callers: fork caller tests >=0 / !=0; waitpid caller tests ==-1, so errors are mapped to -1
# (movlt); execvp caller only acts if it returns. r7 is callee-saved so it is preserved; push {r7,lr}
# keeps 8-byte stack alignment.
SHIM_SRC = {
 "sh_fork": "push {r7, lr}\nmov r7, #120\nmov r0, #17\nmov r1, #0\nmov r2, #0\nmov r3, #0\n"
            "svc #0\ncmp r0, #0\nmovlt r0, #-1\npop {r7, lr}\nbx lr\n",            # clone(SIGCHLD,0)=fork
 "sh_waitpid": "push {r7, lr}\nmov r3, #0\nmov r7, #114\nsvc #0\ncmp r0, #0\nmovlt r0, #-1\n"
               "pop {r7, lr}\nbx lr\n",                                              # wait4(pid,st,opt,0)
 "sh_execvp": "push {r7, lr}\nmov r2, #0\nmov r7, #11\nsvc #0\npop {r7, lr}\nbx lr\n",  # execve(path,argv,0)
 "sh_pthread_self": "mrc p15, 0, r0, c13, c0, 3\nbx lr\n",                           # TPIDRURO = pthread_self
 "sh_getpagesize": "mov r0, #4096\nbx lr\n",                                         # ARMv7 4KB pages
}
MISSING_PLT = {"fork": "sh_fork", "execvp": "sh_execvp", "waitpid": "sh_waitpid",
               "pthread_self": "sh_pthread_self", "getpagesize": "sh_getpagesize"}
# Literal values that equal a real object address by coincidence but are proven scalars, so the
# object_starts tripwire must not treat them as un-relocated pointers:
#   0x7a120 == 500000 == usleep(500000) (500 ms delay) in query_vi_pipe_status and fpv_hub_init;
#   it collides with ss_mpi_vi_get_chn_attr's address in the hub binary. Relocating it would
#   corrupt the delay. Proven: both uses are `mov r0,rX; blx usleep`.
NON_POINTER_LITS = {0x7a120}

SENSOR_UNIT = (0x100b5c, 0x1066a0)      # imx586 + farsight drivers, contiguous .text
SENSOR_DATA = (0x2995e0, 0x29a974)      # the two drivers' private .data (above stock os02k10)
SENSOR_BSS  = (0x2d1b50, 0x2d44c8)      # the two drivers' private .bss (zero-init)
HUB_GOT = 0x2916cc
N19_GOT = 0x263700
GOT_MAP_SYM = {0x514: 0x4f4, 0x54c: 0x52c}
GLUE_DATA = [(0x294b28, 4, "data"), (0x294b2c, 4, "data"), (0x29df98, 36, "bss"),
             (0x29fde4, 4, "bss"), (0x29fde8, 4, "bss")]
RODATA_CONSTS = []
NEW_RX_VA = 0x2b0000
# the 3 anonymous .bss globals shared with stock 19.2.14 code -> stock instance (deterministic)
SHARED_MAP = {0x29df6c: 0x26ed36, 0x29fdc0: 0x2709e0, 0x29fdc4: 0x2709e4}
# hub GOT cells that hold the address of a carried hub global (resolved to a new RX cell).
GOT_CELL_SYMS = {0x8bc: "g_vi_src_switching"}
# the 12 hub-aware changed functions carried & redirected (byte-identical 18.21.3<->19.2.14)
REDIRECT_FUNCS = ["uav_ar_sys_detect_sensor", "do_init_vi_vpss", "init_vi_vpss", "init_vb",
                  "get_sensor_type", "fpv_sys_get_sensor_type", "fpv_sys_ch0_res_remap",
                  "load_pq_bin", "fpv_config_init", "sample_comm_vi_set_vi_vpss_mode",
                  "uar_ar_set_sensor_want_angle", "uav_ar_sys_set_sensor_res"]
# §2a hub subsystem + §2b shared glue — the explicit named carry set (NOT a symbol-diff; a diff
# sweeps in unrelated firmware-version deltas such as init_next_route). main is HOOKED in place,
# never carried wholesale. venc_create/venc_stream_get stay stock. Helpers are added to CARRY_EXTRA
# deliberately when map_call fails closed on a non-carried hub-only target (the Z8 convergence).
HUB_LAYER = ["fpv_hub_init", "fpv_hub_check_current_cam", "fpv_hub_link_switch",
             "fpv_hub_linked_zoom_cam", "fpv_hub_cam_reset_set", "fpv_hub_led_set",
             "fpv_hub_led_get", "fpv_hub_test_init", "get_fpv_hub_ctx", "check_sensor_link",
             "vi_src_switch", "query_vi_pipe_status", "sensor_type_sync", "get_zoom_pd_name",
             "mspSerialParaHubRcSlot", "factroytest_src_switch_process"]
HUB_GLUE = ["fpv_sky_streamzoom_init", "mspSerialParaINAVRcSlot", "fpv_set_vpss_rotation",
            "init_vpss", "uninit_vpss", "set_gpio_val", "single_imx586_load_pq_bin",
            "StreamZoom_load_pq_bin", "fpv_set_msp_rc_zoomctrl", "fpv_set_msp_zoomctrl",
            "fpv_msp_rc_config_get", "fpv_msp_rc_config_init"]
CARRY_EXTRA = ["write_devmem"]   # named hub-only helpers found via fail-closed map_call (LT6911UXE devmem writer)
# §5.4a config delivery: hub-only configs read from /factory are redirected to /usrdata/fpv so
# component 5 can carry them. fpv_config.json is STOCK-SHARED (stock fpv_config_init reads it) and
# is deliberately NOT swapped. Replacement strings live in the new RX string pool (length-free).
STRING_SWAP = {
    b"/factory/mipi_hub.json": b"/usrdata/fpv/mipi_hub.json",
    b"/factory/msp_rc_cfg.json": b"/usrdata/fpv/msp_rc_cfg.json",
}


class HubBuild(Z.Build):
    direct_camera_routing = False  # Physical interposer keeps its own routing.
    def __init__(self, hub_path, n19_path, n18213_path):
        super().__init__(hub_path, n19_path)
        self.base = FE.Image(n18213_path)          # normal 18.21.3, to find hub-only functions
        self.hub_objname = {v[0] & ~1: n for n, v in self.H.syms.items() if v[2] == "STT_OBJECT"}
        self._dataobj = {}                          # cache: hub object-start -> new address
        self._data_pending = []
        self._obj_iv = None                         # sorted STT_OBJECT intervals (built lazily)
        self._stock_dref_set = None
        self._ro_starts = None

    # ---- carry closure --------------------------------------------------------------
    def _hub_only(self, a):
        """A .text target with no 19.2.14 counterpart symbol: an unlabeled hub continuation."""
        e = a & ~1
        if self.H.section_of(e) != ".text":
            return False
        return e not in self.H.func_starts and e not in self.H.plt

    def _next_start(self, entry):
        """Lowest registered function start strictly above `entry` (bounds the extent flood)."""
        nxt = min((s for s in self._starts if s > entry), default=self._text_hi)
        return nxt

    def _extent(self, entry):
        """Extent bounded to [entry, next_start): every branch out of that range becomes an
        external call (tail/cond-ext), so adjacent/outlined functions are never merged in."""
        hi = self._next_start(entry)
        return FE.extent(self.H, entry | 1, internal_ok=lambda t: entry <= (t & ~1) < hi)

    def carry_functions(self):
        H = self.H
        roots = {}
        for n in HUB_LAYER + HUB_GLUE + REDIRECT_FUNCS + CARRY_EXTRA + ["main"]:   # explicit named set
            if n not in H.syms or H.syms[n][2] != "STT_FUNC":
                die(f"carry root {n} absent from hub binary")
            roots[n] = H.syms[n][0]
        for on in ("g_sns_imx586_obj", "g_sns_farsight_obj"):
            for i, w in enumerate(struct.unpack_from("<12I", H.data, H.off(H.syms[on][0]))):
                if w and H.section_of(w) == ".text":
                    roots[f"{on}_cb{i}"] = w
        # Exported sensor functions can enter callback tables through GOT cells,
        # rather than a BL or direct PC-relative function pointer. Copying their
        # bytes with the unit is insufficient: every such body needs relocation.
        for name, (address, _, kind) in H.syms.items():
            if kind == 'STT_FUNC' and SENSOR_UNIT[0] <= (address & ~1) < SENSOR_UNIT[1]:
                roots[name] = address
        tx = H.elf.get_section_by_name(".text")
        self._text_hi = tx["sh_addr"] + tx["sh_size"]
        self._starts = set(H.func_starts)                # all symbol starts bound the floods
        self.anon = {}                                   # entry -> name, unlabeled hub continuations
        entries = {a & ~1: n for n, a in roots.items()}
        self._starts |= set(entries)
        # fixpoint: extent each carried function bounded by the current known starts; any hub-only
        # unlabeled call/tail target is a new carried function; repeat until nothing new appears.
        funcs = {}
        while True:
            new = []
            funcs = {}
            for e, n in sorted(entries.items()):
                try:
                    f = self._extent(e)
                except Exception as ex:
                    die(f"cannot analyse carried function {n} @{e:#x}: {ex}")
                funcs[n] = f
                for _, _, t in f.pic:
                    e2 = t & ~1
                    if H.section_of(t) != ".text" or e2 in entries:
                        continue
                    if SENSOR_UNIT[0] <= e2 < SENSOR_UNIT[1]:
                        new.append((e2, f"fptr_{e2:#x}"))
                    elif self._hub_only(t):       # hub-only function reached via pointer (e.g. a thread routine)
                        new.append((e2, f"anon_{e2:#x}"))
                for _, t, k in f.calls:
                    if not t:
                        continue
                    e2 = t & ~1
                    if e2 in entries:
                        continue
                    # Sensor-unit callees are copied with the unit even when
                    # symbolized. They still need their own PIC/literal analysis;
                    # treating a named helper as stock leaves its old PC offsets.
                    if SENSOR_UNIT[0] <= e2 < SENSOR_UNIT[1]:
                        new.append((e2, H.func_starts.get(e2, f"anon_{e2:#x}")))
                    elif self._hub_only(t):
                        new.append((e2, f"anon_{e2:#x}"))
            fresh = [(e, n) for e, n in new if e not in entries]
            if not fresh:
                break
            for e, n in fresh:
                entries[e] = n
                self._starts.add(e)
                if not n.startswith("fptr_"):
                    self.anon[e] = n
                H.func_starts.setdefault(e, n)
        return funcs

    # ---- target mapping -------------------------------------------------------------
    def map_text(self, t):
        e = t & ~1
        if SENSOR_UNIT[0] <= e < SENSOR_UNIT[1]:
            return self.unit_new + (t - SENSOR_UNIT[0])
        for n, f in self.glue_blocks.items():
            if f["lo"] <= e < f["hi"]:
                return f["new"] + (t - f["lo"])
        return None

    def map_call(self, t, kind):
        H, N = self.H, self.N
        if (t & ~1) == (H.syms["json_load_file"][0] & ~1):
            return ("redirect", "json_load_file", self.sym["hub_config_load"])
        if t in H.plt:
            nm = H.plt[t]
            if not hasattr(self, "_n19plt"):
                self._n19plt = set(N.plt.values())
            if nm not in self._n19plt:                 # import absent from stock 19.2.14
                if nm in MISSING_PLT:
                    tgt = self.sym[MISSING_PLT[nm]]    # ARM shim (word-aligned, no thumb bit)
                    self.report.setdefault("shim_redirects", []).append(
                        {"import": nm, "hub_plt": hex(t), "call_kind": kind, "shim": hex(tgt)})
                    return ("redirect", nm, tgt)
                die(f"carried code calls {nm} via PLT; 19.2.14 lacks it and no shim is defined")
        return super().map_call(t, kind)

    def alloc_shims(self):
        """Place the ARM compatibility shims in new code space (before fill_carried, so the
        redirect targets exist)."""
        self.config_paths = {
            name: self.rx_alloc(path + b"\0", align=4)
            for name, path in {
                "s_rc_seed": b"/usrdata/fpv/msp_rc_cfg.json",
                "s_rc_factory": b"/factory/msp_rc_cfg.json",
                "s_hub_seed": b"/usrdata/fpv/mipi_hub.json",
                "s_hub_factory": b"/factory/mipi_hub.json",
            }.items()
        }
        self.shims = {}
        sizes = {n: len(assemble_arm(src, NEW_RX_VA, name=n)) for n, src in SHIM_SRC.items()}
        for name, src in SHIM_SRC.items():
            addr = self.rx_alloc(b"\0" * sizes[name], align=4)   # BLX needs target & 3 == 0
            if addr & 3:
                die(f"shim {name} not word aligned: {addr:#x}")
            code = assemble_arm(src, addr, name=name)
            o = addr - NEW_RX_VA
            self.rx[o:o + len(code)] = code
            self.sym[name] = addr                       # ARM target: no thumb bit
            self.shims[name] = {"addr": hex(addr), "len": len(code)}

    def _sources(self, final):
        """New Thumb functions: hub_init copies the initialized-RW images at runtime (the RW
        extension is anonymous zero memory); hub_preinit runs it, then enters carried hub main."""
        if final:
            tbl = bytearray()
            for dst, img in self.rw_images:
                src = self.rx_alloc(img, align=4)
                tbl += struct.pack("<III", dst, src, len(img))
            init_tbl = self.rx_alloc(bytes(tbl), align=4)
            init_end = init_tbl + len(tbl)
        else:
            init_tbl = init_end = NEW_RX_VA
        ext = {"memcpy_arm": self.plt_arm("memcpy"), "init_tbl": init_tbl, "init_end": init_end,
               "main_carried": self.sym["main"],
               "json_load_stock": self.n19("json_load_file"),
               "strcmp_arm": self.plt_arm("strcmp"),
               "access_arm": self.plt_arm("access"),
               "errno_arm": self.plt_arm("__errno_location"), **self.config_paths}
        SRC = {
            # Prefer the vendor-uploaded persistent document; use the packaged seed only
            # when it does not exist. Invalid/unreadable factory documents stay failures.
            # No file writes and no change to stock/shared JSON consumers.
            "hub_config_load":
                "push {r4-r8, lr}\nmov r4, r0\nmov r5, r1\nmov r6, r2\nmov r7, r3\n"
                "ldr r1, =s_rc_seed\nldr ip, =strcmp_arm\nblx ip\ncmp r0, #0\nbeq 1f\n"
                "mov r0, r4\nldr r1, =s_hub_seed\nldr ip, =strcmp_arm\nblx ip\n"
                "cmp r0, #0\nbne 4f\nldr r8, =s_hub_factory\nb 2f\n"
                "1:\nldr r8, =s_rc_factory\n"
                "2:\nmov r0, r8\nmovs r1, #0\nldr ip, =access_arm\nblx ip\n"
                "cmp r0, #0\nbeq 3f\nldr ip, =errno_arm\nblx ip\nldr r0, [r0]\n"
                "cmp r0, #2\nbeq 4f\n"
                "3:\nmov r4, r8\n"
                "4:\nmov r0, r4\nmov r1, r5\nmov r2, r6\nmov r3, r7\n"
                "pop {r4-r8, lr}\nb.w json_load_stock\n.ltorg\n",
            "hub_init":
                "push {r4, r5, r6, lr}\nldr r4, =init_tbl\nldr r5, =init_end\n"
                "1:\ncmp r4, r5\nbhs 2f\nldmia r4!, {r0, r1, r2}\nldr ip, =memcpy_arm\nblx ip\nb 1b\n"
                "2:\npop {r4, r5, r6, pc}\n.ltorg\n",
            "hub_preinit":
                "push {r0, r1, r2, lr}\nbl hub_init\npop {r0, r1, r2, lr}\nb.w main_carried\n.ltorg\n",
        }
        return SRC, ext

    def apply_hooks(self, ext):
        """Entry redirects only: no PLT, no stock call site, no dynamic table is touched."""
        N = self.N
        e = N.syms["main"][0] & ~1
        self.patch(e, enc_bw(e, self.sym["hub_preinit"]), 4,
                   "main: stock entry -> hub_preinit (rw-image init, then carried hub main)")
        for n in REDIRECT_FUNCS:                        # the 12 hub-aware changed functions
            e = N.syms[n][0] & ~1
            self.patch(e, enc_bw(e, self.sym[n]), 4, f"{n}: stock entry -> carried hub version")

    def string(self, hub_addr):
        o = self.H.off(hub_addr)
        raw = self.H.data[o:self.H.data.index(b"\0", o)]
        rep = STRING_SWAP.get(raw)
        if rep is not None:
            key = rep + b"\0"
            if key not in self.str_pool:
                self.str_pool[key] = self.rx_alloc(key, align=1)
            self.report.setdefault("string_swaps", []).append(
                {"from": raw.decode(), "to": rep.decode(), "hub_addr": hex(hub_addr)})
            return self.str_pool[key]
        return super().string(hub_addr)

    def _stock_drefs(self):
        """Addresses in .data/.bss/.data.rel.ro referenced by any hub function that survives as
        stock 19.2.14 (name present in 19.2.14 and NOT carried). An anonymous object in this set
        is shared with stock; one outside it is hub-private. Computed once."""
        if self._stock_dref_set is not None:
            return self._stock_dref_set
        H, N = self.H, self.N
        carried = {f.entry for f in self._funcs.values()}
        s = set()
        for n, v in H.syms.items():
            if v[2] != "STT_FUNC" or (v[0] & ~1) in carried:
                continue
            if n not in N.syms or N.syms[n][2] != "STT_FUNC":
                continue                              # hub-only function: it does not survive as stock
            try:
                f = FE.extent(H, v[0] | 1)
            except Exception:
                continue
            for _, _, t in f.pic:
                if H.section_of(t) in (".data", ".bss", ".data.rel.ro"):
                    s.add(t)
            for lit, (val, sz, u) in f.lits.items():
                if val and H.section_of(val) in (".data", ".bss", ".data.rel.ro"):
                    s.add(val)
        self._stock_dref_set = s
        return s

    def _containing_obj(self, t):
        """(name, start, end) of the hub STT_OBJECT containing t, or None if t is anonymous."""
        if self._obj_iv is None:
            iv = sorted((v[0] & ~1, (v[0] & ~1) + (v[1] or 1), n)
                        for n, v in self.H.syms.items() if v[2] == "STT_OBJECT" and v[1])
            self._obj_iv = iv
            self._obj_lo = [x[0] for x in iv]
        i = bisect.bisect_right(self._obj_lo, t) - 1
        if 0 <= i < len(self._obj_iv):
            lo, hi, n = self._obj_iv[i]
            if lo <= t < hi:
                return (n, lo, hi)
        return None

    def map_data(self, t, user):
        H, N = self.H, self.N
        if t == HUB_GOT:
            return ("got_base", N19_GOT)
        sec = H.section_of(t)
        if sec == ".text":
            m = self.map_text(t)
            if m is not None:
                return ("fptr", m)
            nm = H.name_of(t)                          # fptr to a stock 19.2.14 function -> n19 addr
            if nm and nm in N.syms and N.syms[nm][2] == "STT_FUNC":
                return ("fptr", N.syms[nm][0] | 1)
            die(f"function pointer {t:#x} ({nm}) in {user} not carried and absent from 19.2.14")
        if SENSOR_DATA[0] <= t < SENSOR_DATA[1]:      # sensor drivers' private .data block
            return ("sdata", self.sdata_new + (t - SENSOR_DATA[0]))
        if SENSOR_BSS[0] <= t < SENSOR_BSS[1]:        # sensor drivers' private .bss block
            return ("sbss", self.sbss_new + (t - SENSOR_BSS[0]))
        if t in SHARED_MAP:                           # 3 anonymous shared stock globals -> n19 instance
            return ("n19data", SHARED_MAP[t])
        obj = self._containing_obj(t)
        if obj:
            nm, lo, hi = obj
            if nm in N.syms and N.syms[nm][2] == "STT_OBJECT":
                # the same logical global exists in stock 19.2.14 -> use the single stock instance,
                # never a carried copy (state must not diverge).
                return ("n19data", (N.syms[nm][0] & ~1) + (t - lo))
            return ("carried_data", self._carry_data_obj(t))   # hub-only named object -> carry
        # anonymous object (no hub symbol). Only real program-data sections hold carryable objects;
        # a value landing in ELF metadata (.dynsym/.dynstr/.hash/...) is a coincidental scalar, not
        # a pointer -- refuse it so relocate_words leaves the word untouched.
        if sec not in (".rodata", ".data", ".data.rel.ro", ".bss"):
            die(f"reference {t:#x} into non-data section {sec} from {user} is not a carryable object")
        if sec == ".rodata":                          # read-only: strings and const tables are safe
            o = H.off(t)
            end = H.data.index(b"\0", o)
            s = H.data[o:end]
            if len(s) >= 2 and all(32 <= c < 127 or c in (9, 10, 13) for c in s):
                return ("string", self.string(t))
            return ("carried_data", self._carry_data_obj(t))
        if sec == ".data.rel.ro":                      # read-only const-pointer table, relocated
            return ("carried_data", self._carry_data_obj(t))
        # anonymous MUTABLE state (.data/.bss). Safe to carry privately iff no stock-surviving
        # function (one whose name exists in 19.2.14 and is NOT carried) references it; such an
        # object is hub-only. If a stock-surviving function DOES touch it, carrying a private copy
        # would split state -- fail closed so it is added to SHARED_MAP deliberately.
        if t in self._stock_drefs():
            die(f"anonymous {sec} object at {t:#x} from {user} is shared with stock-surviving "
                f"code but not in SHARED_MAP: classify it before building")
        return ("carried_data", self._carry_data_obj(t))

    # ---- per-object data carry (hub-specific .data/.bss/.data.rel.ro/.rodata) --------
    def _obj_starts(self, sec):
        key = f"_objs_{sec}"
        if not hasattr(self, key):
            s = self.H.elf.get_section_by_name(sec)
            lo, hi = s["sh_addr"], s["sh_addr"] + s["sh_size"]
            starts = set()
            if self._ro_starts is None:
                self._ro_starts = self._all_data_starts()
            starts = sorted(a for a in self._ro_starts if lo <= a < hi) + [hi]
            setattr(self, key, (lo, hi, sorted(set(starts))))
        return getattr(self, key)

    def _all_data_starts(self):
        H = self.H
        from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
        from capstone.arm import ARM_OP_MEM, ARM_OP_IMM, ARM_REG_PC
        starts = set()
        tx = H.elf.get_section_by_name(".text")
        md = Cs(CS_ARCH_ARM, CS_MODE_THUMB); md.detail = True; md.skipdata = True
        pend, mov = {}, {}
        datalo = 0x198b00
        for ins in md.disasm(tx.data(), tx["sh_addr"]):
            if not ins.id:
                continue
            m, o = ins.mnemonic, ins.operands
            if m.startswith("ldr") and len(o) == 2 and o[1].type == ARM_OP_MEM and o[1].mem.base == ARM_REG_PC:
                a = ((ins.address + 4) & ~3) + o[1].mem.disp
                of = H.off(a)
                if of is not None:
                    pend[o[0].reg] = struct.unpack_from("<I", H.data, of)[0]
            elif m.startswith("add") and len(o) == 2 and getattr(o[1], "reg", None) == ARM_REG_PC and o[0].reg in pend:
                v = (pend.pop(o[0].reg) + ins.address + 4) & 0xFFFFFFFF
                if v >= datalo:
                    starts.add(v)
            elif m.startswith("movw") and len(o) == 2 and o[1].type == ARM_OP_IMM:
                mov[o[0].reg] = o[1].imm
            elif m.startswith("movt") and len(o) == 2 and o[1].type == ARM_OP_IMM and o[0].reg in mov:
                v = (o[1].imm << 16) | mov.pop(o[0].reg)
                if v >= datalo:
                    starts.add(v)
        for sn in (".data", ".data.rel.ro", ".got", ".rodata", ".bss"):
            s = H.elf.get_section_by_name(sn)
            if s and s["sh_type"] != "SHT_NOBITS":
                d = s.data()
                for i in range(0, len(d) - 3, 4):
                    v = struct.unpack_from("<I", d, i)[0]
                    if v >= datalo:
                        starts.add(v)
        for n, v in H.syms.items():                   # every named object is an object start
            if v[2] == "STT_OBJECT":
                starts.add(v[0] & ~1)
        return starts

    def _anon_end(self, t, sec):
        lo, hi, starts = self._obj_starts(sec)
        i = bisect.bisect_right(starts, t)
        return starts[i] if i < len(starts) else hi

    def _carry_data_obj(self, t):
        """Carry the whole data object containing t (named -> symbol extent; anonymous -> next
        object start), once, and return the new address of t. Pointer words inside .data /
        .data.rel.ro / .rodata are relocated in fill_carried; .bss is zero-init."""
        H = self.H
        sec = H.section_of(t)
        obj = self._containing_obj(t)
        lo, hi = (obj[1], obj[2]) if obj else (t, self._anon_end(t, sec))
        if lo in self._dataobj:
            return self._dataobj[lo] + (t - lo)
        ln = hi - lo
        if ln <= 0 or ln > 0x10000:
            die(f"data object [{lo:#x},{hi:#x}) ({sec}) implausible length {ln:#x}")
        nobits = H.elf.get_section_by_name(sec)["sh_type"] == "SHT_NOBITS"
        if nobits:                                     # .bss -> zero-init RW
            new = self.rw_alloc(ln, align=8)
        else:                                          # content carried; relocated later
            new = self.rx_alloc(b"\0" * ln, align=4)
            self._data_pending.append((lo, new, ln))
        self._dataobj[lo] = new
        return new + (t - lo)

    # ---- layout ---------------------------------------------------------------------
    def layout(self, funcs):
        H = self.H
        self._funcs = funcs
        unit_bytes = H.data[H.off(SENSOR_UNIT[0]):H.off(SENSOR_UNIT[1])]
        self.unit_new = self.rx_alloc(b"\0" * len(unit_bytes), align=16, mod=SENSOR_UNIT[0] % 16)
        self.unit_funcs = [f for f in funcs.values() if SENSOR_UNIT[0] <= f.entry < SENSOR_UNIT[1]]
        self.sdata_new = self.rw_alloc(SENSOR_DATA[1] - SENSOR_DATA[0], align=16)
        self.sbss_new = self.rw_alloc(SENSOR_BSS[1] - SENSOR_BSS[0], align=16)
        self.glue_blocks = {}
        for n, f in sorted(funcs.items(), key=lambda kv: kv[1].entry):
            if SENSOR_UNIT[0] <= f.entry < SENSOR_UNIT[1]:
                continue
            lo, hi = f.lo, f.hi
            for m, g in self.glue_blocks.items():
                if not (hi <= g["lo"] or lo >= g["hi"]):
                    die(f"glue spans overlap: {n} and {m}")
            new = self.rx_alloc(b"\0" * (hi - lo), align=16, mod=lo % 16)
            self.glue_blocks[n] = {"lo": lo, "hi": hi, "new": new, "func": f}
            self.sym[n] = new + (f.entry - lo) | 1
        # expose carried functions by name (for redirects + hub-ctx)
        for n, g in self.glue_blocks.items():
            self.sym.setdefault(n, g["new"] + (g["func"].entry - g["lo"]) | 1)
        self.glue_new = {}
        for a, ln, kind in GLUE_DATA:
            img = H.data[H.off(a):H.off(a) + ln] if kind == "data" else None
            self.glue_new[a] = self.rw_alloc(ln, align=8, image=img)
        self.private_flag = 0
        self.rodata_new = self.unit_new
        # GOT cells: every GOT slot the carried code uses that is not a known libc slot
        # (GOT_MAP_SYM). Resolve each through map_data so a slot naming a stock-shared global gets
        # the single 19.2.14 instance and a hub-only global gets its carried copy -- never guessed.
        used = {}
        for f in funcs.values():
            for a, lit, val, base in f.gotloads:
                if base == HUB_GOT and val not in GOT_MAP_SYM:
                    used[val] = True
        self.got_cells = {}
        for off in used:
            hub_addr = struct.unpack_from("<I", H.data, H.off(HUB_GOT + off))[0]
            if not hub_addr or H.section_of(hub_addr) is None:
                die(f"GOT slot {off:#x} holds non-address {hub_addr:#x}")
            kind, tgt = self.map_data(hub_addr, f"gotcell_{off:#x}")
            self.got_cells[off] = self.rx_alloc(struct.pack("<I", tgt), align=4)
            self.report.setdefault("got_cells", {})[hex(off)] = {"hub_target": hex(hub_addr),
                                                                 "map": kind, "resolved": hex(tgt)}
        Z.GOT_CELL_TARGETS = {off: ("hub", None) for off in used}

    def fill_carried(self):
        H = self.H
        ub = self.relocate_block(SENSOR_UNIT[0], SENSOR_UNIT[1], self.unit_new, self.unit_funcs, "sensor_unit")
        o = self.unit_new - NEW_RX_VA
        self.rx[o:o + len(ub)] = ub
        # sensor drivers' private .data (pointer words relocated); .bss stays zero-init
        sd = self.relocate_words(H.data[H.off(SENSOR_DATA[0]):H.off(SENSOR_DATA[1])], SENSOR_DATA[0], "sensor_data", destination=self.sdata_new)
        self.rw_images.append((self.sdata_new, sd))
        for n, g in self.glue_blocks.items():
            b = self.relocate_block(g["lo"], g["hi"], g["new"], [g["func"]], n)
            o = g["new"] - NEW_RX_VA
            self.rx[o:o + len(b)] = b
        done = set()
        while self._data_pending:
            batch, self._data_pending = self._data_pending, []
            for t, new, ln in batch:
                if t in done:
                    continue
                done.add(t)
                rb = self.relocate_words(H.data[H.off(t):H.off(t) + ln], t, f"dataobj_{t:#x}", destination=new)
                o = new - NEW_RX_VA
                if 0 <= o < len(self.rx):
                    self.rx[o:o + len(rb)] = rb
                else:
                    self.rw_images.append((new, rb))

    # relocate_block/relocate_words call map_data which may return ("n19data", addr): the parent
    # treats the tuple[1] as the absolute target. n19data addresses are plain 19.2.14 addresses.


def build(hub, n19, n18213):
    Z.FARSIGHT_UNIT = SENSOR_UNIT
    Z.RODATA_BLOCK = (SENSOR_UNIT[0], SENSOR_UNIT[0])
    Z.DATA_BLOCK = (0, 0)
    Z.BSS_BLOCK = (0, 0)
    Z.GLUE_DATA = GLUE_DATA
    Z.RODATA_CONSTS = RODATA_CONSTS
    Z.HUB_GOT = HUB_GOT
    Z.N19_GOT = N19_GOT
    Z.GOT_MAP_SYM = GOT_MAP_SYM
    Z.GOT_CELL_TARGETS = {}   # set authoritatively in layout() from actual GOT use
    Z.GLUE_STATICS = {"zoom_process": 0}
    Z.EXPANDER_HELPERS = set()
    Z.EXPANDER_SEQS = []
    Z.CALL_REDIRECT = {}
    Z.NEW_RX_VA = NEW_RX_VA
    b = HubBuild(hub, n19, n18213)
    funcs = b.carry_functions()
    b.layout(funcs)
    b.alloc_shims()               # ARM compat shims (redirect targets) -> b.sym, before fill
    b.alloc_new_code()            # size hub_init / hub_preinit (Thumb) -> b.sym
    b.fill_carried()              # relocate carried code/data; map_call redirects missing imports
    from sensor_lifecycle import install_hub_farsight_reentry
    install_hub_farsight_reentry(b)
    ext = b.final_new_code()      # assemble hub_init/hub_preinit (init table from rw_images)
    b.apply_hooks(ext)            # main -> hub_preinit; 12 entry redirects
    # non-pointer literal words that happen to look like addresses must not equal a real object
    starts = object_starts(b.H)
    for x in b.report["refused"]:
        v = int(x["value"], 16)
        if v in starts and v not in NON_POINTER_LITS:
            die(f"unrelated word {x} equals a real object start")
    b.report["nonpointer_words_verified"] = b.report.pop("refused")

    # ---- closure proofs the task requires ----
    rep = b.report
    rep["sym"] = {k: hex(v) for k, v in b.sym.items()}
    rep["carried_functions"] = {n: {"hub_entry": hex(f.entry)} for n, f in funcs.items()}
    rep["carried_count"] = len(funcs)
    rep["anon_carried"] = {hex(a): n for a, n in b.anon.items()}
    rep["shims"] = b.shims
    # (1) every carried caller of a missing import lands on the intended shim
    want = set(MISSING_PLT)
    carried_missing = []
    for n, f in funcs.items():
        for a, t, k in f.calls:
            if t and t in b.H.plt and b.H.plt[t] in want:
                carried_missing.append((n, hex(a), b.H.plt[t], k))
    redirected = {(r["import"], r["hub_plt"]) for r in rep.get("shim_redirects", [])}
    for n, a, nm, k in carried_missing:
        tt = [x for x, v in b.H.plt.items() if v == nm][0]
        if (nm, hex(tt)) not in redirected:
            die(f"carried caller {n}@{a} of {nm} was NOT redirected to a shim")
    rep["shim_caller_proof"] = {"missing_import_callsites": len(carried_missing),
                                "redirected": len(rep.get("shim_redirects", [])),
                                "all_redirected": True}
    # (2) no unrelated stock path redirected: shims have zero stock callers (stock never imports
    # them) and the only ELF patches are the 13 entry redirects; record the full patch list.
    rep["entry_patches"] = [pp["site"] + " " + pp["what"] for pp in rep["patches"]]
    # (3) carrying main + the 12 did not broaden reachability: the whole carry set resolved
    # fail-closed; record that main is present and the carried set size is bounded.
    rep["main_carried"] = "main" in funcs
    rep["reachability_bound"] = {"named_roots": len(HUB_LAYER + HUB_GLUE + REDIRECT_FUNCS) + 1,
                                 "anon_discovered": len(b.anon),
                                 "total_carried": len(funcs)}
    elf = b.emit()
    return b, funcs, elf


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--hub", required=True); ap.add_argument("--n19", required=True)
    ap.add_argument("--n18213", required=True); ap.add_argument("--out", required=True)
    ap.add_argument("--report", required=True)
    a = ap.parse_args()
    b, funcs, elf = build(a.hub, a.n19, a.n18213)
    Path(a.out).write_bytes(elf)
    import hashlib
    b.report["output"] = {"path": a.out, "size": len(elf),
                          "sha256": hashlib.sha256(elf).hexdigest()}
    Path(a.report).write_text(json.dumps(b.report, indent=1, default=str))
    print(json.dumps({"carried": len(funcs), "shims": list(b.shims),
                      "patches": len(b.report["patches"]), "out_size": len(elf),
                      "out_sha256": b.report["output"]["sha256"][:16]}, indent=1))
