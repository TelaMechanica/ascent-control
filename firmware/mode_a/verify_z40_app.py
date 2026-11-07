#!/usr/bin/env python3
"""Independent verification of the patched Z40 ar_ldyhs_sky.

Static:
  S1 ELF/program headers: loads ascending and disjoint, INTERP first, RW .bss grown, RX added
  S2 byte diff vs stock 19.2.14 confined to the phdr table and the declared patch spans
  S3 no branch anywhere in .text lands strictly inside a replaced span
  S4 every carried function, re-analysed AT ITS NEW ADDRESS, references only:
     19.2.14 PLT, 19.2.14 function starts, new-segment functions, the 19.2.14 GOT base,
     the new RX segment, or the RW extension -- and each PIC/GOT target has the same
     identity (string bytes / block offset / function) as in Hub
  S5 no 19.2.14 function named like a Hub-only/excluded function is called
Dynamic (Unicorn, PLT calls served by a Python libc):
  D1 z40_cam            D2 get_sensor_type    D3 fpv_sys_get_sensor_type
  D4 fpv_sys_ch0_res_remap                     D5 tramp_ivv (case 0x16 / other)
  D6 init_vb Z40 pools  D7 z40_init images    D8 sensor_prepare_dual -> devmem + GPIO58/52
  D9 tramp_fopen        D10 tramp_acc         D11 fpv_msp_rc_config_init defaults
  D12 vi_register_sensor -> 22 rows, 0x0b and 0x16 bound to g_sns_farsight_obj
"""
from __future__ import annotations

import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import fextent as FE  # noqa: E402
from emu import Emu, EmuError  # noqa: E402
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB  # noqa: E402

FAILS = []


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

    # ---------------- S1
    loads = [s for s in X.elf.iter_segments() if s["p_type"] == "PT_LOAD"]
    kinds = [s["p_type"] for s in X.elf.iter_segments()]
    ok = all(loads[i]["p_vaddr"] + loads[i]["p_memsz"] <= loads[i + 1]["p_vaddr"] for i in range(len(loads) - 1))
    check(len(loads) == 3 and ok, "S1 three PT_LOADs, ascending and disjoint",
          str([(hex(s['p_vaddr']), hex(s['p_memsz'])) for s in loads]))
    check(kinds.index("PT_INTERP") < kinds.index("PT_LOAD") and "PT_PHDR" not in kinds, "S1 INTERP before loads, PHDR dropped")
    nrw = [s for s in N.elf.iter_segments() if s["p_type"] == "PT_LOAD"][1]
    check(loads[1]["p_filesz"] == nrw["p_filesz"] and loads[1]["p_offset"] == nrw["p_offset"]
          and loads[1]["p_memsz"] > nrw["p_memsz"], "S1 RW segment: file part unchanged, memsz grown")
    check(loads[2]["p_flags"] == 5 and loads[2]["p_vaddr"] % 0x1000 == loads[2]["p_offset"] % 0x1000,
          "S1 new segment R+X, congruent offset/vaddr")
    e_phoff = struct.unpack_from("<I", new, 0x1c)[0]
    check(e_phoff == struct.unpack_from("<I", orig, 0x1c)[0] and loads[0]["p_vaddr"] <= 0x10000 + e_phoff,
          "S1 phdr table unmoved and inside first LOAD (AT_PHDR stays valid)")

    # ---------------- S2
    spans = [(0x34, 0x34 + 8 * 32)]
    for p in rep["patches"]:
        if p.get("span"):
            a = N.off(int(p["site"], 16))
            spans.append((a, a + p["span"]))
    stray = [i for i in range(len(orig)) if orig[i] != new[i] and not any(a <= i < b for a, b in spans)]
    check(not stray, "S2 stock bytes changed only inside declared patch spans and phdr table",
          f"{len(stray)} stray" if stray else f"{len(spans) - 1} spans")
    check(new[:len(orig)] != orig and len(new) > len(orig), "S2 output extends the stock file")

    # ---------------- S3  (control-flow based: decode only real code, via function extents)
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
                    bad.append((nm, hex(a), m, hex(t), hex(lo)))
    check(not bad, f"S3 no branch from outside lands inside a replaced span ({scanned} functions, {skipped} skipped)",
          str(bad[:6]))

    # ---------------- S4
    rx_lo = loads[2]["p_vaddr"]; rx_hi = rx_lo + loads[2]["p_memsz"]
    rw_lo = int(rep["elf"]["rw_ext_base"], 16); rw_hi = rw_lo + rep["elf"]["rw_ext_size"]
    newfuncs = {int(v[0], 16) for v in rep["new_functions"].values()}
    n19_starts = set(N.func_starts)
    def region_map(hub_t):
        for k, (lo, hi) in (("rodata", L["rodata_hub"]), ("data", L["data_hub"]), ("bss", L["bss_hub"])):
            lo, hi = int(lo, 16), int(hi, 16)
            if lo <= hub_t < hi:
                return int(L[f"{k}_new"], 16) + (hub_t - lo)
        gsz = {0x294b28: 4, 0x294b2c: 4, 0x29df98: 36, 0x29fde4: 4, 0x29fde8: 4,
               0x29fdec: 36}
        for h, nn in L["glue_data"].items():
            h = int(h, 16)
            if h <= hub_t < h + gsz[h]:
                return int(nn, 16) + (hub_t - h)
        for h, nn in L["const_new"].items():
            if int(h, 16) == hub_t:
                return int(nn, 16)
        return None
    def text_map(hub_t):
        u0, u1 = (int(x, 16) for x in L["unit_hub"])
        if u0 <= (hub_t & ~1) < u1:
            return int(L["unit_new"], 16) + (hub_t - u0)
        for g in L["glue_blocks"].values():
            lo, hi = (int(x, 16) for x in g["hub"])
            if lo <= (hub_t & ~1) < hi:
                return int(g["new"], 16) + (hub_t - lo)
        return None
    carried = rep["carried_functions"]
    for hs in list(H.func_starts):
        m = text_map(hs)
        if m is not None:
            X.func_starts[m & ~1] = "carried:" + H.func_starts[hs]
    for c in carried.values():
        m = text_map(int(c["hub_entry"], 16))
        X.func_starts.setdefault(m & ~1, "carried")
    for v in rep["new_functions"].values():
        X.func_starts.setdefault(int(v[0], 16), "new")
    n_ref = n_ok = 0
    problems = []
    from capstone.arm import ARM_REG_R3
    route_tail = text_map(0x6972c)
    direct_entry = int(rep.get('direct_camera_hardware', {}).get('new_entry', '0'), 16)
    if direct_entry:
        X.func_starts[direct_entry] = 'dedicated_direct_register_program'
    for name, c in carried.items():
        he = int(c["hub_entry"], 16)
        ne = text_map(he)
        if he == (H.syms['farsight_init'][0] & ~1) and direct_entry:
            ins = X.disasm1(ne)
            check(ins.mnemonic == 'b.w' and ins.operands[0].imm == direct_entry,
                  'direct Farsight initialization uses the dedicated camera program')
            continue  # Independently executed against the dedicated source below.
        fh = FE.extent(H, he, indirect_tails={0x6972c: ARM_REG_R3})
        fn = FE.extent(X, ne, indirect_tails={route_tail: ARM_REG_R3})
        # calls
        seqs = [(0x6a0b6, 0x6a0d2), (0x6a1bc, 0x6a1dc)] if fh.entry == 0x69dc8 else []
        inseq = lambda off: any(lo - fh.entry <= off < hi - fh.entry for lo, hi in seqs)
        for lo, hi in seqs:
            got = [t for a, t, k in fn.calls if lo - fh.entry <= a - fn.entry < hi - fh.entry]
            ok = len(got) == 2 and all((t & ~1) == (sym["set_gpio_val"] & ~1) for t in got)
            n_ref += 1; n_ok += ok
            if not ok:
                problems.append((name, "gpio sequence", hex(lo), [hex(t) for t in got]))
        hc = sorted((a - fh.entry, t, k) for a, t, k in fh.calls if not inseq(a - fh.entry))
        nc = sorted((a - fn.entry, t, k) for a, t, k in fn.calls if not inseq(a - fn.entry))
        if len(hc) != len(nc):
            problems.append((name, "call count", len(hc), len(nc)))
        for (ho, ht, hk), (no, nt, nk) in zip(hc, nc):
            n_ref += 1
            if ho != no:
                problems.append((name, "call offset", ho, no)); continue
            if nt is None:
                n_ok += 1; continue
            if (ht & ~1) == 0x6712c and (nt & ~1) == 0x65a98:
                ok = True  # Same selected-row owner; anonymous donor accessor.
            elif nt in X.plt:
                hn = H.plt.get(ht)
                xn = X.plt.get(nt)
                ok = hn == xn
            elif (nt & ~1) in newfuncs or rx_lo <= nt < rx_hi:
                tm = text_map(ht)
                ok = (tm is not None and (tm & ~1) == (nt & ~1)) or \
                     H.name_of(ht) in ("fpv_hub_check_current_cam", "imx586_zoom_ctrl") or \
                     (ht & ~1) in (0x69980, 0x699e4) or \
                     ((ht & ~1) == 0x67358 and (nt & ~1) == (sym['direct_sensor_object'] & ~1)) or \
                     (H.name_of(ht) in ('uninit_vi_vpss', 'init_vi_vpss') and
                      (nt & ~1) == (sym['uninit_pre_route' if H.name_of(ht) == 'uninit_vi_vpss' else 'init_next_route'] & ~1))
            elif (nt & ~1) in n19_starts:
                ok = H.name_of(ht) == N.name_of(nt) or ((ht & ~1) == 0x6712c and (nt & ~1) == 0x65a98)
            else:
                ok = False
            if ok:
                n_ok += 1
            else:
                problems.append((name, "call", hex(fh.entry + ho), hex(ht), hex(nt)))
        # pic
        hp = sorted((a - fh.entry, t) for a, _, t in fh.pic)
        np_ = sorted((a - fn.entry, t) for a, _, t in fn.pic)
        for (ho, ht), (no, nt) in zip(hp, np_):
            n_ref += 1
            if ht == 0x2916cc:
                ok = nt == 0x263700
            elif ht in (0x29fdc0, 0x29fdc4):
                ok = nt == {0x29fdc0: 0x2709e0, 0x29fdc4: 0x2709e4}[ht]
            elif H.section_of(ht) == ".text":
                ok = text_map(ht) == nt
            else:
                rm = region_map(ht)
                if rm is not None:
                    ok = rm == nt
                else:     # string: same bytes
                    o = H.off(ht); s = H.data[o:H.data.index(b"\0", o)]
                    o2 = X.off(nt)
                    ok = o2 is not None and X.data[o2:o2 + len(s) + 1] == s + b"\0" and rx_lo <= nt < rx_hi
            if ok:
                n_ok += 1
            else:
                problems.append((name, "pic", hex(fh.entry + ho), hex(ht), hex(nt)))
        if len(hp) != len(np_):
            problems.append((name, "pic count", len(hp), len(np_)))
        # got
        hg = sorted((a - fh.entry, off) for a, _, off, _ in fh.gotloads)
        ng = sorted((a - fn.entry, off) for a, _, off, _ in fn.gotloads)
        expect = {0x514: 0x4f4, 0x54c: 0x52c}
        for (ho, hoff), (no, noff) in zip(hg, ng):
            n_ref += 1
            if hoff in expect:
                ok = noff == expect[hoff]
            else:
                cell = 0x263700 + noff & 0xFFFFFFFF
                ok = L["got_cells"].get(hex(hoff)) == hex(cell)
            if ok:
                n_ok += 1
            else:
                problems.append((name, "got", hex(fh.entry + ho), hex(hoff), hex(noff)))
    check(not problems, f"S4 carried-code references re-derived at new addresses: {n_ok}/{n_ref} identical in identity",
          str(problems[:8]))

    # ---------------- S5
    forbidden = ("fpv_hub_", "get_fpv_hub_ctx", "check_sensor_link", "vi_src_switch", "query_vi_pipe_status",
                 "sensor_type_sync", "get_zoom_pd_name", "mspSerialParaHubRcSlot", "factroytest",
                 "write_devmem", "imx586_", "g_sns_imx586_obj")
    called = set()
    for name, c in carried.items():
        fn = FE.extent(X, text_map(int(c["hub_entry"], 16)), indirect_tails={route_tail: ARM_REG_R3})
        for _, t, _ in fn.calls:
            if t and (t & ~1) in n19_starts:
                called.add(N.name_of(t))
    leak = sorted(n for n in called if n and any(n.startswith(f) for f in forbidden))
    check(not leak, "S5 no Hub-only / Z8 / dead function reachable from carried code", str(leak))
    check(not any(k.startswith(("fpv_hub", "imx586_", "query_vi", "vi_src", "sensor_type_sync"))
                  for k in carried), "S5 carry set contains no excluded function", "")

    # ---------------- dynamic
    plt = {}
    for a, n in X.plt.items():
        plt[a] = n
    E = lambda: Emu(new_p, plt)
    s_ = lambda e, s: e.alloc(len(s) + 1, s + b"\0")
    # D1
    e = E()
    r1 = e.call(sym["z40_cam"], s_(e, b"Z40")); r2 = e.call(sym["z40_cam"], s_(e, b"Z8"))
    check(r1 == 1 and r2 == 0, "D1 z40_cam('Z40')=1, ('Z8')=0", f"{r1},{r2}")
    # D2
    gst = N.syms["get_sensor_type"][0] | 1
    e = E()
    uav = e.call(N.syms["get_uav_ctx"][0] | 1)
    e.w32(uav + 0x28, 4)                                    # 4 MIPI lanes
    r_imx = e.call(gst, s_(e, b"imx586"), 2000, 1500, 50)
    r_ps50 = e.call(gst, s_(e, b"ps5280"), 1920, 1080, 50)
    r_ps60 = e.call(gst, s_(e, b"ps5280"), 1920, 1080, 60)
    r_os = e.call(gst, s_(e, b"os02k10"), 1920, 1080, 60)
    e0 = Emu(n19_p, {a: n for a, n in N.plt.items()})
    uav0 = e0.call(N.syms["get_uav_ctx"][0] | 1); e0.w32(uav0 + 0x28, 4)
    r_os0 = e0.call(gst, e0.alloc(8, b"os02k10\0"), 1920, 1080, 60)
    r_ps500 = e0.call(gst, e0.alloc(8, b"ps5280\0"), 1920, 1080, 50)
    check(r_imx == 0x16, "D2 get_sensor_type('imx586') = 0x16", hex(r_imx))
    check(r_ps50 == 0x0b == r_ps500, "D2 ps5280 4-lane @50 = 0x0b, as stock", f"{r_ps50:#x}/{r_ps500:#x}")
    check(r_ps60 == 0x0c, "D2 ps5280 4-lane @60 = 0x0c (non-Farsight row)", hex(r_ps60))
    check(r_os == r_os0, "D2 os02k10 numbering unchanged vs stock", f"{r_os:#x}/{r_os0:#x}")
    # D3
    fs = N.syms["fpv_sys_get_sensor_type"][0] | 1
    e = E(); g = e.call(N.syms["get_fpv_gctx"][0] | 1)
    e.mu.mem_write(g, b"imx586\0"); a1 = e.call(fs)
    e.mu.mem_write(g, b"ps5280\0"); a2 = e.call(fs)
    e.mu.mem_write(g, b"os04j10\0"); a3 = e.call(fs)
    check((a1, a2, a3) == (586, 2, 8), "D3 fpv_sys_get_sensor_type: imx586=586, ps5280=2, os04j10=8", f"{a1},{a2},{a3}")
    # D4
    e = E(); ow, oh, of = e.alloc(4), e.alloc(4), e.alloc(4)
    res = []
    for w, h, f in ((1920, 1080, 60), (1920, 1080, 100), (1280, 720, 120), (2560, 1440, 30)):
        rv = e.call(N.syms["fpv_sys_ch0_res_remap"][0] | 1, w, h, f, ow, oh, of)
        res.append((e.u32(ow), e.u32(oh), e.u32(of), rv))
    check(all(x[2] == 50 and x[3] == 0 for x in res) and res[0][:2] == (1920, 1080), "D4 ch0_res_remap fps=50 for every request",
          str(res))
    # D5
    e = E(); ctx = e.alloc(0x100)
    for o, v in ((0x38, 11), (0x3c, 22), (0x40, 33)):
        e.w32(ctx + o, v)
    e.mu.reg_write(FE.ARM_REG_R4 if hasattr(FE, "ARM_REG_R4") else 70, ctx)
    from unicorn.arm_const import UC_ARM_REG_R4, UC_ARM_REG_R3, UC_ARM_REG_R0, UC_ARM_REG_PC
    def run_ivv(r3):
        e.mu.reg_write(UC_ARM_REG_R4, ctx)
        e.mu.reg_write(UC_ARM_REG_R3, r3)
        e.stop_at = {0x6701c, 0x66fee}
        e.mu.emu_start(sym["tramp_ivv"] | 1, 0x7e000000, count=1000)
        return e.reg(UC_ARM_REG_PC)
    pc1 = run_ivv(0x16)
    vals = [e.u32(ctx + o) for o in (0x44, 0x48, 0x4c, 0x50, 0x54)]
    pc2 = run_ivv(0x15)
    check(pc1 & ~1 == 0x6701c and vals == [2000, 1500, 50, 11, 22], "D5 init_vi_vpss case 0x16 -> 2000x1500@50, joins common path",
          f"pc={pc1:#x} {vals}")
    check(pc2 & ~1 == 0x66fee, "D5 other unknown types still take the stock error path", hex(pc2))
    # D6
    e = E(); cfg = e.alloc(0x308)
    e.mu.reg_write(UC_ARM_REG_R4, cfg)
    e.stop_at = {0x65350}
    e.mu.emu_start(0x6536e | 1, 0x7e000000, count=200)
    pools = [e.u32(cfg + o) for o in (8, 12, 16, 0x38, 0x3c, 0x40)]
    check(pools == [3792000, 0, 4, 4572064, 0, 4], "D6 init_vb Z40 pools", str(pools))
    # D7
    e = E(); e.call(sym["z40_init"])
    okimg = True
    for d, n in rep["layout"]["rw_images"]:
        d = int(d, 16)
        img = bytes(e.mu.mem_read(d, n))
        okimg &= any(img == bytes(e.mu.mem_read(int(x, 16), n)) for x in [hex(d)])
    obj = int(rep["sym"]["g_sns_farsight_obj"], 16)
    cb = struct.unpack("<12I", e.mu.mem_read(obj, 48))
    fpt = [c for c in cb if c]
    check(all(rx_lo <= (c & ~1) < rx_hi and c & 1 for c in fpt) and len(fpt) == 8,
          "D7 z40_init: g_sns_farsight_obj populated, 8 Thumb callbacks in the new segment", str([hex(c) for c in cb]))
    zr = [struct.unpack("<f", e.mu.mem_read(int(x, 16), 4))[0] for x in (L["glue_data"]["0x294b28"], L["glue_data"]["0x294b2c"])]
    check(zr == [1.0, 1.0], "D7 zoom ratio words initialised to 1.0", str(zr))
    # D8
    e = E(); e.call(sym["sensor_prepare_dual"])
    sysc = [x[1] for x in e.log if x[0] == "system"]
    gw = [(p.decode() if p else None, d.decode()) for p, d in e.writes]
    sl = [x[1] for x in e.log if x[0] == "usleep"]
    check(sysc == [b"devmem 0x1794008c 32 0x1130", b"devmem 0x17940084 32 0x1213"], "D8 pinmux writes, order as 17.5.8 Z40", str(sysc))
    val = [w for w in gw if w[0] and w[0].endswith("/value")]
    check([v for v in val] == [("/sys/class/gpio/gpio58/value", "0"), ("/sys/class/gpio/gpio52/value", "0")],
          "D8 GPIO58=0 then GPIO52=0 through carried set_gpio_val", str(gw))
    check(sl == [100000, 100000], "D8 two 100 ms delays", str(sl))
    # D9
    e = E(); buf = e.alloc(256, b"/usrdata/fpv/tunning/cam_x.bin\0"); mode = s_(e, b"rb")
    r = e.call(sym["tramp_fopen"], buf, mode)
    op = [x for x in e.log if x[0] == "fopen"]
    check(op and op[0][1] == b"/usrdata/fpv/tunning/cam_imx586_50fps_z40_xg1.bin" and op[0][2] == b"rb",
          "D9 load_pq_bin opens the Z40 IMX586 xg1 tuning file", str(op))
    # D10
    nreg = rep["notes"]
    for case, r0, name, exp in (("match os04j10", 0, b"x", 0x66c66), ("imx586", 1, b"imx586", 0x66c66),
                                ("unknown", 1, b"foo", 0x66cee)):
        e = E()
        ins = N.disasm1(0x66c5a); reg = ins.op_str.split(",")[1].strip()
        from unicorn.arm_const import UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7, UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10
        rr = {"r4": UC_ARM_REG_R4, "r5": UC_ARM_REG_R5, "r6": UC_ARM_REG_R6, "r7": UC_ARM_REG_R7,
              "r8": UC_ARM_REG_R8, "sb": UC_ARM_REG_R9, "sl": UC_ARM_REG_R10}[reg]
        e.mu.reg_write(rr, s_(e, name)); e.mu.reg_write(UC_ARM_REG_R0, r0)
        e.stop_at = {0x66c66, 0x66cee}
        from unicorn.arm_const import UC_ARM_REG_SP
        e.mu.reg_write(UC_ARM_REG_SP, 0x7f000000 - 0x1000)
        e.mu.emu_start(sym["tramp_acc"] | 1, 0x7e000000, count=500)
        check(e.reg(UC_ARM_REG_PC) & ~1 == exp, f"D10 load_pq_bin name acceptance: {case}", hex(e.reg(UC_ARM_REG_PC)))
    # D11 -- differential against the Hub 18.21.4 original. On a missing file the Hub function
    # zeroes all 36 bytes and returns 0; the -1/1000/2000 defaults apply per key only when the
    # file loads and a key is absent. The carried copy must reproduce every case exactly.
    from unicorn.arm_const import UC_ARM_REG_R1
    def rc_run(img, path, cfg_va, scenario):
        e = Emu(path, img.plt)
        handles = {}
        def load(em):
            em.log.append(("json_load_file", em.cstr(em.reg(UC_ARM_REG_R0))))
            return 0 if scenario == "missing" else em.alloc(4)
        def oget(em):
            key = em.cstr(em.reg(UC_ARM_REG_R1))
            em.log.append(("json_object_get", key))
            if scenario != "full":
                return 0
            h = em.alloc(4); handles[h] = key; return h
        def ival(em):
            k = handles[em.reg(UC_ARM_REG_R0)]
            return (sum(k) * 7 + len(k)) & 0x7f
        for nm, fn in (("json_load_file", load), ("json_object_get", oget), ("json_integer_value", ival)):
            e.stubs[img.syms[nm][0] & ~1] = fn
        for nm in ("json_delete",):
            if nm in img.syms:
                e.stubs[img.syms[nm][0] & ~1] = lambda em: 0
        r = e.call(img.syms["fpv_msp_rc_config_init"][0] if "fpv_msp_rc_config_init" in img.syms
                   else sym["fpv_msp_rc_config_init"], max_insn=5_000_000)
        return r, bytes(e.mu.mem_read(cfg_va, 36)), [x for x in e.log if x[0] != "call"]
    for scen in ("missing", "keys-absent", "full"):
        hr = rc_run(H, hub_p, 0x29df98, scen)
        xr = rc_run(X, new_p, int(L["glue_data"]["0x29df98"], 16), scen)
        check(hr == xr and (scen != "missing" or (hr[1] == bytes(36) and hr[0] == 0)),
              f"D11 fpv_msp_rc_config_init {scen}: carried == Hub original",
              f"hub={hr[0]},{hr[1].hex()} new={xr[0]},{xr[1].hex()} json={[x[1] for x in xr[2] if x[0]=='json_load_file']}")
    # D12
    e = E(); e.call(sym["z40_init"])
    e.call(N.syms["vi_register_sensor"][0] | 1)
    info = 0x2709e4
    tptr, cnt = e.u32(info + 0x14), e.u32(info + 0x18)
    rows = [struct.unpack("<8I", e.mu.mem_read(tptr + 32 * i, 32)) for i in range(cnt)]
    r0b = [r for r in rows if r[0] == 0x0b]; r16 = [r for r in rows if r[0] == 0x16]
    check(cnt == 22 and r0b and r16 and r0b[0][1] == obj == r16[0][1],
          "D12 vi_register_sensor: 22 rows; 0x0b and 0x16 -> g_sns_farsight_obj", f"cnt={cnt}")
    types = sorted(r[0] for r in rows)
    stock = sorted(struct.unpack_from("<I", orig, N.off(0x265780) + 32 * i)[0] for i in range(21))
    check(types == sorted(stock + [0x16]), "D12 every stock sensor type still present, only 0x16 added")

    # D13: execute registration with the REAL donor pointer checks. The prior
    # structural gate missed callback GOT loads beyond a conditional branch.
    from emu import sensor_callback_registration, EmuError
    registered = sensor_callback_registration(new_p, sym["g_sns_farsight_obj"], sym["z40_init"])
    check(registered["result"] == 0 and len(registered["accepted_callback_tables"]) == 1,
          "D13 actual sensor registration accepts executable callback table")
    callback_cells = [int(L["got_cells"][offset], 16)
                      for offset, entry in rep.get("discovered_got_cells", {}).items()
                      if entry["map"] == "fptr"]
    check(bool(callback_cells), "D13 callback GOT cells are explicitly relocated")
    for cell in callback_cells:
        try:
            broken = sensor_callback_registration(new_p, sym["g_sns_farsight_obj"], sym["z40_init"], zero_cell=cell)
            rejected = broken["result"] != 0 and not broken["accepted_callback_tables"]
        except EmuError as error:
            rejected = "sensor callback" in str(error)
        check(rejected, "D13 zero callback mutation rejected by registration/table validation", hex(cell))

    from emu import actual_table_lane_policy
    actual_lanes = actual_table_lane_policy(new_p, rep)
    check(len(actual_lanes['cases']) == 16, 'emitted sensor-table lane writes succeed under real ELF permissions')

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
    defaults_proof = sensor_isp_default_validation(new_p, int(rep['sym']['g_sns_farsight_obj'],16), int(rep['sym']['z40_init'],16))
    check(defaults_proof['cac_validator'] == 0, 'actual sensor defaults pass CAC validator and preserve sharpen gains', str(defaults_proof))

    from emu import plt_instruction_resolution
    linkage = plt_instruction_resolution(new_p, rep)
    check(linkage['entries_executed'] > 0 and linkage['relocated_calls_checked'] > 0,
          'actual PLT instruction resolution and skipped-prefix mutation gate', str(linkage))

    from direct_camera import validate_z40_hardware, validate_direct_handover
    if not direct_source:
        check(False, 'dedicated Z40 source required for independent hardware-program comparison')
    else:
        direct = validate_z40_hardware(direct_source, new_p, rep)
        check(direct['register_writes'] == 428 and direct['ae_defaults_equal'],
              'dedicated camera register program and AE timing match actual source', str(direct))
        route = validate_direct_handover(new_p, rep)
        check(len(route['transitions']) == 2, 'actual direct handover preserves ISP and restarts both sensors', str(route))
        from direct_camera import validate_z40_tuning_loads
        tuning = validate_z40_tuning_loads(new_p, Path(hub_p).parent/'tunning')
        check(tuning['ordinary_loader_calls'] == 4, 'ordinary/deferred PQ reload follows current camera profile', str(tuning))

    from rc_displayport import validate_displayport_zoom
    zoom = validate_displayport_zoom(new_p, rep)
    check(zoom['zoom_updates'] >= 4, 'actual H9 DisplayPort frames update existing zoom owner', str(zoom))

    print("\nRESULT:", "PASS" if not FAILS else f"FAIL ({len(FAILS)}): {FAILS}")
    return 0 if not FAILS else 1


if __name__ == "__main__":
    raise SystemExit(main(*sys.argv[1:6]))
