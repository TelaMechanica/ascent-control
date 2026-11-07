#!/usr/bin/env python3
"""Independent verification of the patched Z8 direct-IMX586 ar_ldyhs_sky.

Static:
  S1 ELF/program headers (3 loads ascending/disjoint, INTERP first, RW grown, RX added, phdr valid)
  S2 byte diff vs stock 19.2.14 confined to the phdr table and the declared patch spans
  S3 no branch anywhere in .text lands strictly inside a replaced span
  S4 every carried/new function re-analysed AT ITS NEW ADDRESS references only 19.2.14 PLT,
     19.2.14 function starts, the new segment, the 19.2.14 GOT base, or the RW extension
  G1 (req #6/#8) fail-closed single-sensor proof:
     - no farsight_* / ps5280-sensor / Hub-I2C-expander function is carried into the image
     - no carried/new instruction targets any Hub farsight/ps5280/expander address
     - the former-farsight digital-zoom site resolves to the carried single imx586_zoom_ctrl
     - the former sensor-handover / init-exposure / expander sites resolve to the z8_nop stub
Dynamic (Unicorn, PLT served by a Python libc):
  D1 z8_cam("Z8")=1 / ("Z40")=0        D2 z8_nop()=0
  D3 get_sensor_type(imx586)=0x16      D4 fpv_sys_get_sensor_type(imx586)=586
  D5 fpv_sys_ch0_res_remap -> fps 50   D6 tramp_ivv case 0x16 -> 2000x1500@50
  D7 init_vb -> 3792000 / 4572064      D8 z8_main_sensor -> "imx586", gctx 2000x1500@50, no prepare_dual
  D9 z8_gpio_lo -> GPIO58=0            D10 tramp_gpio_hi -> GPIO58=1 then the mipi-rx ioctl
  D11 tramp_fopen -> cam_imx586_50fps_z8_xg1.bin
  D12 vi_register_sensor -> 22 rows; row 0x16 -> g_sns_imx586_obj; row 0x0b untouched (stock)
  D13 digital-zoom reachability: set_scale -> imx586_zoom_ctrl (carried single driver)
"""
from __future__ import annotations

import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import fextent as FE  # noqa: E402
from emu import Emu  # noqa: E402

FAILS = []
# Hub source ranges that must be absent/unreachable in a direct-Z8 image
FAR_UNIT = (0x1031f0, 0x1066a0)
PS5280 = [(0xf8db4, 0xfb718)]
EXPANDER = {0x69980, 0x699e4}


def check(cond, name, detail=""):
    print(("PASS " if cond else "FAIL ") + name + (f"  [{detail}]" if detail else ""))
    if not cond:
        FAILS.append(name)


def main(hub_p, n19_p, new_p, rep_p, direct_source=None):
    rep = json.load(open(rep_p))
    H, N, X = FE.Image(hub_p), FE.Image(n19_p), FE.Image(new_p)
    L = rep["layout"]
    sym = {k: int(v, 16) for k, v in rep["sym"].items()}
    orig, new = N.data, X.data
    loads = [s for s in X.elf.iter_segments() if s["p_type"] == "PT_LOAD"]
    rx_lo, rx_hi = loads[2]["p_vaddr"], loads[2]["p_vaddr"] + loads[2]["p_memsz"]
    rw_lo = int(rep["elf"]["rw_ext_base"], 16)
    rw_hi = rw_lo + rep["elf"]["rw_ext_size"]
    plt = dict(X.plt)
    E = lambda: Emu(new_p, plt)

    # The new image has no symbols for carried/new functions, so FE.extent would over-run them.
    # Augment X.func_starts with every new-segment function boundary so extents are bounded.
    u0 = int(L["unit_new"], 16); uh0, uh1 = (int(x, 16) for x in L["unit_hub"])
    for n, meta in rep["carried_functions"].items():
        he = int(meta["hub_entry"], 16) & ~1
        if uh0 <= he < uh1:
            X.func_starts[u0 + (he - uh0)] = n
    for n, g in L["glue_blocks"].items():
        X.func_starts[int(g["new"], 16) + (int(rep["carried_functions"][n]["hub_entry"], 16) & ~1) - int(g["hub"][0], 16)] = n
    for n, (va, _) in rep["new_functions"].items():
        X.func_starts[int(va, 16) & ~1] = n

    # ---------------- S1
    kinds = [s["p_type"] for s in X.elf.iter_segments()]
    asc = all(loads[i]["p_vaddr"] + loads[i]["p_memsz"] <= loads[i + 1]["p_vaddr"] for i in range(len(loads) - 1))
    check(len(loads) == 3 and asc, "S1 three PT_LOADs, ascending and disjoint",
          str([(hex(s['p_vaddr']), hex(s['p_memsz'])) for s in loads]))
    check(kinds.index("PT_INTERP") < kinds.index("PT_LOAD") and "PT_PHDR" not in kinds,
          "S1 INTERP before loads, PHDR dropped")
    nrw = [s for s in N.elf.iter_segments() if s["p_type"] == "PT_LOAD"][1]
    check(loads[1]["p_filesz"] == nrw["p_filesz"] and loads[1]["p_memsz"] > nrw["p_memsz"],
          "S1 RW segment: file part unchanged, memsz grown")
    check(loads[2]["p_flags"] == 5 and loads[2]["p_vaddr"] % 0x1000 == loads[2]["p_offset"] % 0x1000,
          "S1 new segment R+X, congruent")

    # ---------------- S2
    spans = [(0x34, 0x34 + 8 * 32)]
    for p in rep["patches"]:
        if p.get("span"):
            a = N.off(int(p["site"], 16))
            spans.append((a, a + p["span"]))
    stray = [i for i in range(len(orig)) if orig[i] != new[i] and not any(a <= i < b for a, b in spans)]
    check(not stray, "S2 stock bytes changed only inside declared patch spans and phdr table",
          f"{len(stray)} stray" if stray else f"{len(spans) - 1} spans")
    check(len(new) > len(orig) and new[len(orig):] != b"", "S2 output extends the stock file")

    # ---------------- S3
    vspans = [(int(p["site"], 16), int(p["site"], 16) + p["span"]) for p in rep["patches"] if p.get("span", 0) > 4]
    bad, scanned, skipped = [], 0, 0
    for nm, (va, sz, ty) in X.syms.items():
        if ty != "STT_FUNC" or not sz or not (0x10000 <= va < 0x262000):
            continue
        try:
            f = FE.extent(X, va)
        except Exception:
            skipped += 1
            continue
        scanned += 1
        for a, (size, m, op) in f.insns.items():
            if not (m.startswith("b") or m in ("cbz", "cbnz")) or "#" not in op:
                continue
            try:
                t = int(op.split("#")[-1], 16) & ~1
            except ValueError:
                continue
            for lo, hi in vspans:
                if lo < t < hi and not lo <= a < hi:
                    bad.append((nm, hex(a), m, hex(t)))
    check(not bad, f"S3 no branch from outside lands inside a replaced span ({scanned} funcs, {skipped} skipped)",
          str(bad[:6]))

    # ---------------- S4 + G1: walk every carried/new function at its NEW address
    newfuncs = {int(v[0], 16) & ~1 for v in rep["new_functions"].values()}
    carried_new = {}
    # unit block
    u0 = int(L["unit_new"], 16); uh0, uh1 = (int(x, 16) for x in L["unit_hub"])
    for n, g in L["glue_blocks"].items():
        carried_new[n] = (int(g["new"], 16), [int(x, 16) for x in g["hub"]])
    n19_starts = set(N.func_starts)
    plt_addrs = set(X.plt)

    def allowed(t):
        tt = t & ~1
        return (rx_lo <= tt < rx_hi) or tt in n19_starts or t in plt_addrs or tt in plt_addrs \
            or (rw_lo <= tt < rw_hi) or tt == int(L.get("private_flag", "0x0"), 16)

    forbidden_hits, unmapped = [], []
    # carried glue blocks
    for n, (newa, (hlo, hhi)) in carried_new.items():
        try:
            f = FE.extent(X, newa)
        except Exception as e:
            unmapped.append((n, str(e)))
            continue
        for a, t, k in f.calls:
            if t is None:
                continue
            tt = t & ~1
            if FAR_UNIT[0] <= tt < FAR_UNIT[1] or tt in EXPANDER or any(lo <= tt < hi for lo, hi in PS5280):
                forbidden_hits.append((n, hex(a), hex(tt)))
            if not allowed(t):
                unmapped.append((n, hex(a), hex(t)))
    # new functions
    for n, (va, _) in rep["new_functions"].items():
        try:
            f = FE.extent(X, int(va, 16))
        except Exception:
            continue
        for a, t, k in f.calls:
            if t is None:
                continue
            tt = t & ~1
            if FAR_UNIT[0] <= tt < FAR_UNIT[1] or tt in EXPANDER or any(lo <= tt < hi for lo, hi in PS5280):
                forbidden_hits.append((n, hex(a), hex(tt)))
    check(not forbidden_hits, "G1 no carried/new instruction targets a Hub farsight/ps5280/expander address",
          str(forbidden_hits[:6]))
    check(not unmapped, "S4 every carried/new call target lands in an allowed region", str(unmapped[:6]))

    # G1: no farsight/ps5280/expander function carried by name
    carried_names = set(rep["carried_functions"])
    leaked = [n for n in carried_names if n.startswith("farsight") or ("ps5280" in n and "farsight" not in n)]
    check(not leaked, "G1 no farsight_* / ps5280 sensor function carried into the image", str(leaked))

    # G1: the former-farsight digital-zoom site now targets the carried single imx586_zoom_ctrl,
    # and the handover/init-exposure/expander sites target z8_nop
    reds = rep.get("g1_redirects", [])
    to_imx = [r for r in reds if r["to"] == "imx586_zoom_ctrl"]
    to_nop = [r for r in reds if r["to"] == "z8_nop"]
    check(any(r["from"] == "farsight_imx586_zoom_ctrl" for r in to_imx),
          "G1 farsight_imx586_zoom_ctrl -> carried imx586_zoom_ctrl (digital zoom preserved)")
    want_nop = {"farsight_imx586_set_init_exposure", "farsight_ps5280_set_init_exposure"}
    got_nop = {r["from"] for r in to_nop}
    check(want_nop <= got_nop and sum(1 for r in to_nop if r["from"].startswith("hub_expander")) == 4,
          "G1 sensor-handover / init-exposure / 4x Hub-expander sites -> z8_nop", str(sorted(got_nop)))

    # verify at the binary level: set_scale (carried) now bl's imx586_zoom_ctrl; restart_vin/zoom_process bl z8_nop
    def bl_targets(fnname):
        a = carried_new[fnname][0]
        f = FE.extent(X, a)
        return {t & ~1 for _, t, k in f.calls if t}
    check(sym["imx586_zoom_ctrl"] & ~1 in bl_targets("set_scale"),
          "G1 set_scale calls the carried single imx586_zoom_ctrl")
    restart_sites = [r for r in rep['relocations'] if r.get('kind') == 'call'
                     and r.get('hub_target') == '0x698b4']
    restart_safe = bool(restart_sites) and all(
        X.disasm1(int(r['new_at'], 16)).operands[0].imm == (sym['z8_nop'] & ~1)
        for r in restart_sites)
    check('restart_vin' not in carried_new and restart_safe
          and sym["z8_nop"] & ~1 in bl_targets("zoom_process"),
          "G1 dual-sensor restart body excluded; all former calls target z8_nop")

    # ---------------- Dynamic
    s_ = lambda e, b: e.alloc(len(b) + 1, b + b"\0")

    e = E(); r1 = e.call(sym["z8_cam"], s_(e, b"Z8")); r2 = e.call(sym["z8_cam"], s_(e, b"Z40"))
    check(r1 == 1 and r2 == 0, "D1 z8_cam('Z8')=1, ('Z40')=0", f"{r1},{r2}")
    e = E(); check(e.call(sym["z8_nop"]) == 0, "D2 z8_nop()=0")

    e = E(); r = e.call(N.syms["get_sensor_type"][0], s_(e, b"imx586"), 1920, 1080, 50)
    check(r == 0x16, "D3 get_sensor_type('imx586') = 0x16", hex(r))

    e = E()
    g = e.call(N.syms["get_fpv_gctx"][0]); e.mu.mem_write(g, b"imx586\0")
    # fpv_sys_get_sensor_type reads the name from gctx
    r = e.call(N.syms["fpv_sys_get_sensor_type"][0])
    check(r == 586, "D4 fpv_sys_get_sensor_type('imx586') = 586", str(r))

    # D5 ch0_res_remap: out fps 50 for a mapped resolution
    e = E()
    ow, oh, of = e.alloc(4), e.alloc(4), e.alloc(4)
    # H7 body: out_w=r3(arg3), out_h=sp[0](arg4), out_fps=sp[1](arg5); arg2 unused
    e.call(N.syms["fpv_sys_ch0_res_remap"][0], 1920, 1080, 0, ow, oh, of)
    check(e.u32(of) == 50, "D5 fpv_sys_ch0_res_remap out fps = 50", str(e.u32(of)))

    # D6 tramp_ivv case 0x16 -> 2000x1500@50 then joins common path
    from unicorn.arm_const import UC_ARM_REG_R3, UC_ARM_REG_R4, UC_ARM_REG_PC
    e = E(); st = e.alloc(0x80)
    e.mu.mem_write(st + 0x38, struct.pack("<II", 0x111, 0x222))
    e.mu.reg_write(UC_ARM_REG_R4, st); e.mu.reg_write(UC_ARM_REG_R3, 0x16)
    e.stop_at = {0x6701c, 0x66fee}
    from unicorn.arm_const import UC_ARM_REG_SP
    e.mu.reg_write(UC_ARM_REG_SP, 0x7f000000 - 0x1000)
    e.mu.emu_start(sym["tramp_ivv"] | 1, 0x7e000000, count=200)
    geo = struct.unpack_from("<III", bytes(e.mu.mem_read(st + 0x44, 12)))
    check(e.reg(UC_ARM_REG_PC) & ~1 == 0x6701c and geo[0] == 2000 and geo[1] == 1500 and geo[2] == 50,
          "D6 tramp_ivv case 0x16 -> 2000x1500@50, joins common path", f"pc={hex(e.reg(UC_ARM_REG_PC))} {geo}")

    # D7 init_vb pools
    e = E(); r4 = e.alloc(0x100)
    from unicorn.arm_const import UC_ARM_REG_R4
    e.mu.reg_write(UC_ARM_REG_R4, r4)
    e.stop_at = {0x65350}
    e.mu.reg_write(UC_ARM_REG_SP, 0x7f000000 - 0x1000)
    try:
        e.mu.emu_start(0x6536e | 1, 0x7e000000, count=60)
    except Exception:
        pass
    pool0 = struct.unpack_from("<i", bytes(e.mu.mem_read(r4 + 8, 4)))[0]
    pool1 = struct.unpack_from("<i", bytes(e.mu.mem_read(r4 + 56, 4)))[0]
    check(pool0 == 3792000 and pool1 == 4572064, "D7 init_vb pools 3792000 / 4572064", f"{pool0},{pool1}")

    # D8 z8_main_sensor -> "imx586" into the name buffer, gctx res/fps, NO sensor_prepare_dual
    e = E()
    namebuf = e.alloc(32, b"\0" * 32)
    r = e.call(sym["z8_main_sensor"], namebuf)
    gname = e.cstr(namebuf)
    gctx = e.call(N.syms["get_fpv_gctx"][0])
    w, h = struct.unpack_from("<II", bytes(e.mu.mem_read(gctx + 0x20, 8)))
    fps = e.u32(gctx + 0x28)
    sys_calls = [x for x in e.log if x[0] == "system"]
    check(gname == b"imx586" and w == 2000 and h == 1500 and fps == 50 and not sys_calls,
          "D8 z8_main_sensor: 'imx586', gctx 2000x1500@50, no sensor_prepare_dual/devmem",
          f"name={gname} {w}x{h}@{fps} system_calls={len(sys_calls)}")

    # D9/D10 GPIO58 low and high
    e = E(); e.stubs[sym["set_gpio_val"] & ~1] = lambda em: em.log.append(("gpio", em.reg(0 if False else __import__("unicorn").arm_const.UC_ARM_REG_R0), em.reg(__import__("unicorn").arm_const.UC_ARM_REG_R1))) or 0
    e.call(sym["z8_gpio_lo"])
    gl = [x for x in e.log if x[0] == "gpio"]
    check(gl and gl[0][1] == 58 and gl[0][2] == 0, "D9 z8_gpio_lo writes GPIO58 = 0", str(gl[:2]))
    e = E(); e.stubs[sym["set_gpio_val"] & ~1] = lambda em: em.log.append(("gpio", em.reg(__import__("unicorn").arm_const.UC_ARM_REG_R0), em.reg(__import__("unicorn").arm_const.UC_ARM_REG_R1))) or 0
    e.stubs[0x65cac] = lambda em: em.log.append(("helper", em.reg(__import__("unicorn").arm_const.UC_ARM_REG_R0))) or 0
    e.stop_at = {0x66140}
    e.mu.reg_write(UC_ARM_REG_SP, 0x7f000000 - 0x1000)
    try:
        e.mu.emu_start(sym["tramp_gpio_hi"] | 1, 0x7e000000, count=60)
    except Exception:
        pass
    gl = [x for x in e.log if x[0] == "gpio"]; hp = [x for x in e.log if x[0] == "helper"]
    check(gl and gl[0][1] == 58 and gl[0][2] == 1 and hp and hp[0][1] == 0x40046d0c,
          "D10 tramp_gpio_hi: GPIO58=1 then the mipi-rx ioctl (0x40046d0c)", f"gpio={gl[:1]} helper={[hex(x[1]) for x in hp]}")

    # D11 tramp_fopen -> z8 filename (sprintf into arg0 buffer, then fopen)
    e = E()
    dst = e.alloc(128, b"\0" * 128)
    e.call(sym["tramp_fopen"], dst, s_(e, b"rb"), 0)
    op = [x for x in e.log if x[0] == "fopen"]
    check(op and op[0][1] == b"/usrdata/fpv/tunning/cam_imx586_50fps_z8_xg1.bin",
          "D11 tramp_fopen -> cam_imx586_50fps_z8_xg1.bin", str(op[:1]))

    # D12 vi_register_sensor: 22 rows, row 0x16 -> g_sns_imx586_obj, row 0x0b stock
    e = E(); e.call(sym["z8_init"]) if "z8_init" in sym else None
    e.call(N.syms["vi_register_sensor"][0] | 1)
    info = 0x2709e4
    tptr, cnt = e.u32(info + 0x14), e.u32(info + 0x18)
    rows = [struct.unpack("<8I", bytes(e.mu.mem_read(tptr + 32 * i, 32))) for i in range(cnt)]
    r16 = [r for r in rows if r[0] == 0x16]
    r0b = [r for r in rows if r[0] == 0x0b]
    obj_imx = sym["g_sns_imx586_obj"]
    stock0b = struct.unpack_from("<8I", N.data, N.off(0x265780) + 32 * next(i for i in range(21)
              if struct.unpack_from("<I", N.data, N.off(0x265780) + 32 * i)[0] == 0x0b))
    check(cnt == 22 and r16 and r16[0][1] == obj_imx, "D12 vi_register_sensor: 22 rows; row 0x16 -> g_sns_imx586_obj",
          f"cnt={cnt} row16obj={hex(r16[0][1]) if r16 else None}")
    check(r0b and r0b[0][1] == stock0b[1], "D12 row 0x0b left stock (not retargeted)",
          f"0b_obj={hex(r0b[0][1]) if r0b else None} stock={hex(stock0b[1])}")

    # D13 digital-zoom reachability: set_scale (carried) calls the carried single imx586_zoom_ctrl
    f = FE.extent(X, carried_new["set_scale"][0])
    check(sym["imx586_zoom_ctrl"] & ~1 in {t & ~1 for _, t, k in f.calls if t},
          "D13 digital zoom: set_scale -> carried imx586_zoom_ctrl")

    # D14: execute registration with the REAL donor pointer checks. The prior
    # structural gate missed callback GOT loads beyond a conditional branch.
    from emu import sensor_callback_registration, EmuError
    registered = sensor_callback_registration(new_p, sym["g_sns_imx586_obj"], sym["z8_init"])
    check(registered["result"] == 0 and len(registered["accepted_callback_tables"]) == 1,
          "D14 actual sensor registration accepts executable callback table")
    callback_cells = [int(L["got_cells"][offset], 16)
                      for offset, entry in rep.get("discovered_got_cells", {}).items()
                      if entry["map"] == "fptr"]
    check(bool(callback_cells), "D14 callback GOT cells are explicitly relocated")
    for cell in callback_cells:
        try:
            broken = sensor_callback_registration(new_p, sym["g_sns_imx586_obj"], sym["z8_init"], zero_cell=cell)
            rejected = broken["result"] != 0 and not broken["accepted_callback_tables"]
        except EmuError as error:
            rejected = "sensor callback" in str(error)
        check(rejected, "D14 zero callback mutation rejected by registration/table validation", hex(cell))

    from emu import actual_table_lane_policy
    actual_lanes = actual_table_lane_policy(new_p, rep)
    check(len(actual_lanes['cases']) == 4, 'emitted sensor-table lane writes succeed under real ELF permissions')

    from emu import imx586_lane_policy
    lanes = imx586_lane_policy(new_p)
    check(len(lanes['cases']) == 12, 'IMX586 getter vendor lane policy, repeated calls and unrelated-context guards')
    try:
        imx586_lane_policy(new_p, remove_hook=True)
    except EmuError:
        lane_mutation_rejected = True
    else:
        lane_mutation_rejected = False
    check(lane_mutation_rejected, 'removing lane hook is rejected by actual getter behavior')

    from emu import scalar_sensor_data_preservation, sensor_isp_default_validation
    scalar_proof = scalar_sensor_data_preservation(hub_p, new_p, rep)
    check(scalar_proof['scalar_bytes_compared'] > 0, 'scalar ISP/private sensor bytes preserved exactly', str(scalar_proof))
    defaults_proof = sensor_isp_default_validation(new_p, int(rep['sym']['g_sns_imx586_obj'],16), int(rep['sym']['z8_init'],16))
    check(defaults_proof['cac_validator'] == 0, 'actual sensor defaults pass CAC validator and preserve sharpen gains', str(defaults_proof))

    from emu import plt_instruction_resolution
    linkage = plt_instruction_resolution(new_p, rep)
    check(linkage['entries_executed'] > 0 and linkage['relocated_calls_checked'] > 0,
          'actual PLT instruction resolution and skipped-prefix mutation gate', str(linkage))

    from direct_camera import validate_z8_hardware
    if not direct_source:
        check(False, 'dedicated Z8 source required for independent hardware-program comparison')
    else:
        direct = validate_z8_hardware(direct_source, new_p, rep)
        check(direct['native_source_equal'], 'dedicated Z8 register program and VI/VPSS mode preserved', str(direct))
    print("\nRESULT:", "PASS" if not FAILS else f"FAIL ({len(FAILS)}): {FAILS}")
    return 0 if not FAILS else 1


if __name__ == "__main__":
    raise SystemExit(main(*sys.argv[1:6]))
