#!/usr/bin/env python3
"""Mode A: fresh UBIFS regeneration for an exact Ascent G_Sky donor.

Gate 1 (this file's default): rebuild the donor with NO semantic change and prove it.

  donor.img --(extract both UBIFS volumes with full metadata)--> staging trees
            --(mkfs.ubifs under fakeroot, donor-derived geometry)--> UBIFS images
            --(UBI layer written from donor fields)--> UBI components
            --(ASW: donor header, CRC@0x70 and size@0x74 recomputed)--> rebuilt.img
  then: existing fail-closed verifier + semantic inventory comparison + window check.

An overlay (files to add or replace) is accepted ONLY by gate 2, which this file
refuses to run until gate 1 has passed on the same donor hash. Nothing here writes to
a device. Nothing here modifies the donor.

The existing verifier (firmware/ascent_g_sky_image_tool.py on the Ascent Control
consolidated branch) is imported READ-ONLY from its path; its SHA-256 is recorded in
the report so a result is tied to the exact verifier that produced it.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import shutil
import shlex
import struct
import subprocess
import sys
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import ubifs_inventory as INV  # noqa: E402
import deflate_distance as DD  # noqa: E402

DEVICE_WINDOW = 2048   # crypto/deflate.c inflates with an 11-bit window

# Resolve the adjacent verifier before starting expensive reconstruction work.
DEFAULT_VERIFIER = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "ascent_g_sky_image_tool.py")
ASW_HDR = 0x80
ASW_CRC_OFF, ASW_SIZE_OFF = 0x70, 0x74
UBI_FS_COMPONENTS = (4, 5)
LAYOUT_VOL = 0x7FFFEFFF
VTBL_REC = 172
GATE1_DONORS = {
    # donor sha256 -> marker file name written only when gate 1 passes
}


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def load_verifier(path: str):
    spec = importlib.util.spec_from_file_location("ascent_image_tool", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod, sha(Path(path).read_bytes())


# ------------------------------------------------------------------ extraction ----
def extract_tree(inv: dict, root: Path) -> None:
    """Materialize an inventory as a directory tree. Run under fakeroot so that
    ownership survives to mkfs.ubifs; modes and times are set explicitly."""
    entries = inv["entries"]
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True)
    # directories first (shallow to deep), then files and links, then times deep-first
    for path in sorted(entries, key=lambda p: p.count("/")):
        r = entries[path]
        kind = r["mode"] & INV.S_IFMT
        dst = root if path == "/" else root / path.lstrip("/")
        if kind == INV.S_IFDIR:
            dst.mkdir(exist_ok=True)
        elif kind == INV.S_IFREG:
            dst.write_bytes(r["content"])
        elif kind == INV.S_IFLNK:
            os.symlink(r["target"], dst)
        else:
            raise SystemExit(f"REFUSED: special file {path} (mode {oct(r['mode'])}) not handled")
    for path in sorted(entries, key=lambda p: -p.count("/")):
        r = entries[path]
        dst = root if path == "/" else root / path.lstrip("/")
        kind = r["mode"] & INV.S_IFMT
        if kind != INV.S_IFLNK:
            os.chmod(dst, r["mode"] & 0o7777)
        os.chown(dst, r["uid"], r["gid"], follow_symlinks=False)
        at = r["atime"][0] * 10**9 + r["atime"][1]
        mt = r["mtime"][0] * 10**9 + r["mtime"][1]
        os.utime(dst, ns=(at, mt), follow_symlinks=False)


def mkfs_args(sb: dict, src: Path, out: Path) -> list[str]:
    """Geometry comes from the donor superblock, field by field."""
    if sb["key_hash"] != 0 or sb["key_fmt"] != 0:
        raise SystemExit("REFUSED: donor key hash/format is not r5/simple")
    if sb["default_compr"] != 2:
        raise SystemExit("REFUSED: donor default compressor is not zlib")
    args = ["-r", str(src), "-o", str(out),
            "-m", str(sb["min_io_size"]), "-e", str(sb["leb_size"]),
            "-c", str(sb["max_leb_cnt"]), "-x", "zlib", "-k", "r5",
            "-f", str(sb["fanout"]), "-l", str(sb["log_lebs"]), "-p", str(sb["orph_lebs"]),
            "-j", str(sb["max_bud_bytes"])]
    if sb["space_fixup"]:
        args.append("-F")
    return args


# --------------------------------------------------------------------- UBI layer --
def build_ubi_component(T, donor_blob: bytes, ubifs_img: bytes, *, name: str) -> tuple[bytes, dict]:
    """UBI component from donor-derived headers and a fresh UBIFS image.

    Layout mirrors the donor exactly as measured: PEB 0/1 = the two volume-table
    copies, PEB 2+n = LEB n of volume 0. EC/VID fields are the donor's; only the
    volume table's reserved_pebs follows the new LEB count, and its record CRC is
    recomputed."""
    dubi = T.parse_ubi(donor_blob, name=name)
    peb, vid_off, data_off = dubi["peb_size"], dubi["vid_hdr_offset"], dubi["data_offset"]
    leb = peb - data_off
    blocks = dubi["blocks"]
    layout = [b for b in blocks if b["vid"] and b["vid"]["vol_id"] == LAYOUT_VOL]
    data_blocks = sorted((b for b in blocks if b["vid"] and b["vid"]["vol_id"] == 0),
                         key=lambda b: b["vid"]["lnum"])
    # measured-layout assertions: refuse anything we have not seen
    if [b["pnum"] for b in layout] != [0, 1] or \
            [b["pnum"] for b in data_blocks] != list(range(2, 2 + len(data_blocks))) or \
            [b["vid"]["lnum"] for b in data_blocks] != list(range(len(data_blocks))):
        raise SystemExit(f"REFUSED: {name} donor UBI layout is not the measured simple layout")

    sb = T.ubifs_superblock(ubifs_img)
    new_lebs = sb["leb_cnt"]
    if len(ubifs_img) > new_lebs * leb:
        raise SystemExit(f"REFUSED: {name} mkfs output longer than leb_cnt*leb_size")
    payload = ubifs_img + b"\xff" * (new_lebs * leb - len(ubifs_img))

    # volume table: donor payload, record 0 reserved_pebs := new_lebs, CRC recomputed
    vt = bytearray(donor_blob[layout[0]["pnum"] * peb + data_off:(layout[0]["pnum"] + 1) * peb])
    vt2 = donor_blob[layout[1]["pnum"] * peb + data_off:(layout[1]["pnum"] + 1) * peb]
    if bytes(vt) != vt2:
        raise SystemExit(f"REFUSED: {name} donor vtbl copies differ")
    old_res = struct.unpack_from(">I", vt, 0)[0]
    struct.pack_into(">I", vt, 0, new_lebs)
    struct.pack_into(">I", vt, VTBL_REC - 4, T.ubi_crc32(bytes(vt[:VTBL_REC - 4])))

    tmpl_data_vid = dict(data_blocks[0]["vid"])
    out = bytearray()
    for i in range(2 + new_lebs):
        donor_b = blocks[i] if i < len(blocks) else blocks[-1]
        block = bytearray(b"\xff") * peb
        block[0:64] = T.serialize_ec_hdr(donor_b)
        if i < 2:
            block[vid_off:vid_off + 64] = T.serialize_vid_hdr(layout[i]["vid"])
            block[data_off:] = vt
        else:
            v = dict(tmpl_data_vid)
            v["lnum"] = i - 2
            block[vid_off:vid_off + 64] = T.serialize_vid_hdr(v)
            block[data_off:] = payload[(i - 2) * leb:(i - 1) * leb]
        out += block
    meta = {"donor_lebs": len(data_blocks), "new_lebs": new_lebs,
            "reserved_pebs": {"donor": old_res, "new": new_lebs},
            "bytes": {"donor": len(donor_blob), "new": len(out)}}
    return bytes(out), meta


def assemble_asw(T, donor: bytes, new_components: dict[int, bytes]) -> bytes:
    asw = T.parse_asw(donor)
    comps = sorted(asw["components"], key=lambda c: c["offset"])
    out = bytearray(donor[:ASW_HDR])
    for c in comps:
        if len(out) != c["offset"]:
            # an earlier component changed size: a component would move
            raise SystemExit(f"REFUSED: component {c['id']} would move "
                             f"({c['offset']} -> {len(out)}); only the last component may grow")
        blob = new_components.get(c["id"], donor[c["offset"]:c["offset"] + c["bytes"]])
        out += blob
    struct.pack_into("<I", out, ASW_SIZE_OFF, len(out))
    struct.pack_into("<I", out, ASW_CRC_OFF, zlib.crc32(bytes(out[ASW_HDR:])) & 0xFFFFFFFF)
    return bytes(out)


# ------------------------------------------------------------------ verification --
def check_asw_seal(data: bytes) -> dict:
    crc = struct.unpack_from("<I", data, ASW_CRC_OFF)[0]
    size = struct.unpack_from("<I", data, ASW_SIZE_OFF)[0]
    calc = zlib.crc32(data[ASW_HDR:]) & 0xFFFFFFFF
    if crc != calc:
        raise SystemExit(f"FAIL ASW_CRC: stored {crc:#x} computed {calc:#x}")
    if size != len(data):
        raise SystemExit(f"FAIL ASW_SIZE: stored {size} file {len(data)}")
    return {"crc": f"{crc:#010x}", "size": size}


def volume_of(T, data: bytes, cid: int) -> tuple[bytes, dict]:
    asw = T.parse_asw(data)
    c = next(c for c in asw["components"] if c["id"] == cid)
    blob = data[c["offset"]:c["offset"] + c["bytes"]]
    ubi = T.parse_ubi(blob, name=f"component{cid}")
    return T.ubi_volume_data(ubi, blob, 0), ubi


def compare_inventories(a: dict, b: dict) -> list[str]:
    va, vb = INV.semantic_view(a), INV.semantic_view(b)
    diffs = []
    for p in sorted(set(va) | set(vb)):
        if p not in va:
            diffs.append(f"ADDED {p}")
        elif p not in vb:
            diffs.append(f"REMOVED {p}")
        elif va[p] != vb[p]:
            fields = sorted(k for k in set(va[p]) | set(vb[p]) if va[p].get(k) != vb[p].get(k))
            diffs.append(f"CHANGED {p}: " + ", ".join(f"{k} {va[p].get(k)} -> {vb[p].get(k)}" for k in fields))
    return diffs


def check_window(vol: bytes, cid: int) -> dict:
    """Decode every zlib data block and fail if any back-reference exceeds the device
    window. zlib's own inflate cannot be used for this (see deflate_distance.py)."""
    s = INV.sweep(vol)
    mx, n = 0, 0
    for (inum, blk), (_, node) in s["data"].items():
        if struct.unpack_from("<H", node, 44)[0] != INV.COMPR_ZLIB:
            continue
        out, md = DD.inflate_measure(node[48:])
        if len(out) != struct.unpack_from("<I", node, 40)[0]:
            raise SystemExit(f"FAIL DEFLATE_LEN component {cid} inode {inum} block {blk}")
        if md > DEVICE_WINDOW:
            raise SystemExit(f"FAIL DEFLATE_WINDOW component {cid} inode {inum} block {blk}: "
                             f"distance {md} > {DEVICE_WINDOW}")
        mx, n = max(mx, md), n + 1
    return {"zlib_blocks": n, "max_distance": mx, "limit": DEVICE_WINDOW}


SB_FIELDS_MUST_MATCH = ("key_hash", "key_fmt", "flags", "min_io_size", "leb_size", "max_leb_cnt",
                        "max_bud_bytes", "log_lebs", "orph_lebs", "jhead_cnt", "fanout",
                        "lsave_cnt", "fmt_version", "default_compr", "space_fixup")


def fakeroot_mkfs_argv(script: str, mkfs: Path, args: list[str]) -> list[str]:
    """Keep extraction and mkfs in one fakeroot session, preserving every argument.

    Both the installed script path and Windows work directories can contain spaces,
    quotes or shell metacharacters. Quote argv elements rather than interpolating
    their contents into executable shell text.
    """
    extract = shlex.join([sys.executable, "-I", "-c", script])
    build = shlex.join([str(mkfs), *map(str, args)])
    return ["fakeroot", "--", "sh", "-c", extract + " && " + build]


def rebuild_filesystem(inv, superblock, work, stage, output, mkfs, cid):
    """Use explicit metadata in native mode; preserve the fakeroot default."""
    mode = os.environ.get("ASCENT_MKFS_INVENTORY", "")
    if mode not in ("", "1"):
        raise SystemExit("REFUSED: unknown filesystem backend mode")
    if mode == "1":
        from fs_backend import export_inventory
        manifest, payload = export_inventory(inv, work / f"inventory{cid}")
        cmd = [str(mkfs), "--ascent-inventory", str(manifest),
               *mkfs_args(superblock, payload, output)]
    else:
        import pickle
        pick = work / f"inv{cid}.pickle"
        pick.write_bytes(pickle.dumps(inv))
        script = (f"import pickle,sys; sys.path.insert(0,{str(HERE)!r}); import mode_a_build as M; "
                  f"M.extract_tree(pickle.load(open({str(pick)!r},'rb')), M.Path({str(stage)!r}))")
        cmd = fakeroot_mkfs_argv(script, mkfs, mkfs_args(superblock, stage, output))
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode:
        raise SystemExit(f"FAIL mkfs/extract component {cid}: {result.stderr[-2000:]}")
    if not mode:
        pick.unlink()


def gate1(donor_path: Path, work: Path, mkfs: Path, verifier_path: str, out_path: Path) -> dict:
    T, verifier_sha = load_verifier(verifier_path)
    donor = donor_path.read_bytes()
    donor_char = T.characterize(donor_path)
    T.verify(donor, donor=donor_char)                       # donor itself must pass first
    report = {"gate": "mode_a_gate1_donor_noop_rebuild", "donor": donor_path.name,
              "donor_sha256": sha(donor), "verifier": verifier_path,
              "verifier_sha256": verifier_sha, "mkfs": str(mkfs),
              "mkfs_version": subprocess.run([str(mkfs), "--version"], capture_output=True,
                                             text=True).stdout.strip(),
              "components": {}}
    work.mkdir(parents=True, exist_ok=True)
    new_components = {}
    for cid in UBI_FS_COMPONENTS:
        vol, dubi = volume_of(T, donor, cid)
        dsb = T.ubifs_superblock(vol)
        inv = INV.inventory(vol, with_content=True)
        stage = work / f"stage{cid}"
        out_ubifs = work / f"comp{cid}.ubifs"
        rebuild_filesystem(inv, dsb, work, stage, out_ubifs, mkfs, cid)
        ubifs_img = out_ubifs.read_bytes()
        dc = next(c for c in T.parse_asw(donor)["components"] if c["id"] == cid)
        donor_blob = donor[dc["offset"]:dc["offset"] + dc["bytes"]]
        comp, meta = build_ubi_component(T, donor_blob, ubifs_img, name=f"component{cid}")
        new_components[cid] = comp
        nsb = T.ubifs_superblock(ubifs_img)
        sb_diff = {k: (dsb[k], nsb[k]) for k in SB_FIELDS_MUST_MATCH if dsb[k] != nsb[k]}
        report["components"][cid] = {"ubi": meta, "superblock_mismatch": sb_diff,
                                     "superblock_leb_cnt": {"donor": dsb["leb_cnt"], "new": nsb["leb_cnt"]},
                                     "superblock_lpt_lebs": {"donor": dsb["lpt_lebs"], "new": nsb["lpt_lebs"]}}
    rebuilt = assemble_asw(T, donor, new_components)
    out_path.write_bytes(rebuilt)

    # ---- verification, fail closed ----
    checks = {}
    checks["existing_verifier"] = T.verify(rebuilt, donor=donor_char)
    checks["asw_seal"] = check_asw_seal(rebuilt)
    dasw, rasw = T.parse_asw(donor), T.parse_asw(rebuilt)
    hdr_delta = [i for i in range(ASW_HDR) if donor[i] != rebuilt[i]]
    if any(not (ASW_CRC_OFF <= i < ASW_SIZE_OFF + 4) for i in hdr_delta):
        raise SystemExit(f"FAIL ASW_HEADER: bytes outside CRC/size changed: {hdr_delta}")
    checks["asw_header_delta_bytes"] = hdr_delta
    for dc, rc in zip(dasw["components"], rasw["components"]):
        if (dc["id"], dc["offset"], dc["partition_bytes"], dc["upgrade"], dc["dual"]) != \
                (rc["id"], rc["offset"], rc["partition_bytes"], rc["upgrade"], rc["dual"]):
            raise SystemExit(f"FAIL DESCRIPTOR {dc['id']}")
        if dc["id"] not in UBI_FS_COMPONENTS and dc["sha256"] != rc["sha256"]:
            raise SystemExit(f"FAIL NON_FS_COMPONENT_CHANGED {dc['id']}")
    checks["non_fs_components_identical"] = [c["id"] for c in dasw["components"]
                                             if c["id"] not in UBI_FS_COMPONENTS]
    for cid in UBI_FS_COMPONENTS:
        dvol, dubi = volume_of(T, donor, cid)
        rvol, rubi = volume_of(T, rebuilt, cid)
        for f in ("image_seq", "peb_size", "vid_hdr_offset", "data_offset", "leb_size"):
            if dubi[f] != rubi[f]:
                raise SystemExit(f"FAIL UBI_META {cid} {f}")
        dv = {k: v for k, v in dubi["vtbl"][0].items() if k != "reserved_pebs"}
        rv = {k: v for k, v in rubi["vtbl"][0].items() if k != "reserved_pebs"}
        if dv != rv:
            raise SystemExit(f"FAIL VTBL_META {cid}: {dv} vs {rv}")
        dinv, rinv = INV.inventory(dvol), INV.inventory(rvol)   # window check included
        diffs = compare_inventories(dinv, rinv)
        report["components"][cid]["semantic_diffs"] = diffs
        report["components"][cid]["entries"] = len(rinv["entries"])
        report["components"][cid]["nonfs_nodes"] = {"donor": dinv["nonfs_nodes"], "new": rinv["nonfs_nodes"]}
        ct = [p for p in dinv["entries"] if dinv["entries"][p]["ctime"] != rinv["entries"].get(p, {}).get("ctime")]
        report["components"][cid]["ctime_differs_entries"] = len(ct)
        report["components"][cid]["deflate_window"] = check_window(rvol, cid)
        if report["components"][cid]["superblock_mismatch"]:
            raise SystemExit(f"FAIL SUPERBLOCK {cid}: {report['components'][cid]['superblock_mismatch']}")
        if diffs:
            raise SystemExit(f"FAIL SEMANTIC {cid}: {len(diffs)} differences, first: {diffs[:5]}")
    checks["semantic_inventory"] = "identical (ctime excluded: a rebuild cannot set it)"
    checks["deflate_window_11bit"] = "every zlib block decoded; max back-reference <= 2048 (see components)"
    report["checks"] = checks
    report["rebuilt_sha256"] = sha(rebuilt)
    report["rebuilt_bytes"] = len(rebuilt)
    report["byte_identical_to_donor"] = rebuilt == donor
    report["byte_delta_by_component"] = {
        c["id"]: sum(1 for a, b in zip(donor[c["offset"]:c["offset"] + c["bytes"]],
                                       rebuilt[c["offset"]:c["offset"] + c["bytes"]]) if a != b)
        for c in dasw["components"]}
    report["PASS"] = True
    return report


# ======================================================================= gate 2 ====
# The frozen phase-1 Z40 delta. Nothing outside this table may change, and every entry
# is pinned by SHA-256 and size. Component 5 (usrdata) is the ONLY component regenerated;
# components 0/1/2/4 are copied from the donor byte for byte.
CAMERA_SUBTYPE = "z40"
PHASE1_COMPONENT = 5
PHASE1_DELTA = {
    "/fpv/ar_ldyhs_sky": ("replace", "33b0b2365ab1207140b5af8376229b78d6aeb70349506460d56c86eb4b33eeb4", 2600056),
    "/fpv/tunning/cam_imx586_50fps_z40_xg1.bin":
        ("add", "a3fbd5a0bb4726e70a0147c73d3dab76e2cd4dff628dc6771b6b0e2125ad5f3a", 144722),
    "/fpv/tunning/cam_imx586_50fps_z40_xg2.bin":
        ("add", "2d0a8da754e03e4b35c92e8794f76e10b8e4ab12dab3aca80cd4fd7acb150db7", 144722),
    "/fpv/tunning/cam_imx586_50fps_z40_xg4.bin":
        ("add", "4f6f5f4cee5d29ad01d5ca0af67f7fb514ecea63fc6745772eeae1be12362b09", 144722),
    # Hub 18.21.4 tuning is the frozen compatibility choice pending hardware
    # validation. The 17.5.8 Z40 copy (fb2f2d56...) is the bench fallback.
    "/fpv/tunning/cam_ps5280_50fps_z40.bin":
        ("add", "8965b2a0ac37f2e012238d209bcad0dc33988dc112600565f0d17139dd46e048", 144722),
}
GATE2_DONOR_SHA = "f166927ff1e0"      # prefix; full hash is taken from the gate-1 report
UBIFS_DIR_BASE = 160                  # UBIFS directory i_size = 160 + sum(ALIGN(57+len, 8))


def dent_size(name: str) -> int:
    return (56 + len(name.encode()) + 1 + 7) & ~7


def _regen_fs_component(T, donor: bytes, cid: int, inv: dict, work: Path, mkfs: Path):
    """Extract `inv` and mkfs it with the donor's own superblock geometry, in one
    fakeroot session; then wrap it in a UBI component built from donor headers."""
    vol, _ = volume_of(T, donor, cid)
    dsb = T.ubifs_superblock(vol)
    stage, out_ubifs = work / f"stage{cid}", work / f"comp{cid}.ubifs"
    rebuild_filesystem(inv, dsb, work, stage, out_ubifs, mkfs, cid)
    ubifs_img = out_ubifs.read_bytes()
    dc = next(c for c in T.parse_asw(donor)["components"] if c["id"] == cid)
    comp, meta = build_ubi_component(T, donor[dc["offset"]:dc["offset"] + dc["bytes"]], ubifs_img,
                                     name=f"component{cid}")
    nsb = T.ubifs_superblock(ubifs_img)
    sb_diff = {k: (dsb[k], nsb[k]) for k in SB_FIELDS_MUST_MATCH if dsb[k] != nsb[k]}
    if sb_diff:
        raise SystemExit(f"FAIL SUPERBLOCK {cid}: {sb_diff}")
    meta["superblock_leb_cnt"] = {"donor": dsb["leb_cnt"], "new": nsb["leb_cnt"]}
    meta["superblock_lpt_lebs"] = {"donor": dsb["lpt_lebs"], "new": nsb["lpt_lebs"]}
    meta["ubifs_image_bytes"] = len(ubifs_img)
    return comp, meta


def apply_phase1_delta(inv: dict, sources: dict[str, bytes]) -> dict:
    """Return a new inventory with exactly the PHASE1_DELTA applied. Replaced files keep
    every donor attribute but content and size; added files take the metadata of their
    sibling files, which must be uniform or the gate refuses to guess."""
    import copy
    entries = copy.deepcopy(inv["entries"])
    file_paths = {pp for pp, e in PHASE1_DELTA.items() if e[0] != "mkdir"}
    if set(sources) != file_paths:
        raise SystemExit(f"REFUSED: overlay paths {sorted(sources)} are not the frozen delta")
    for path in sorted((pp for pp, e in PHASE1_DELTA.items() if e[0] == "mkdir"),
                       key=lambda pp: pp.count("/")):               # new dirs first, shallow->deep
        m = PHASE1_DELTA[path][3]
        parent = path.rsplit("/", 1)[0]
        if parent not in entries or entries[parent]["mode"] & INV.S_IFMT != INV.S_IFDIR:
            raise SystemExit(f"REFUSED: parent of {path} is not an existing directory")
        if path in entries:
            raise SystemExit(f"REFUSED: {path} already exists in the donor")
        if m["mode"] & INV.S_IFMT != INV.S_IFDIR:
            raise SystemExit(f"REFUSED: mkdir {path} metadata mode {oct(m['mode'])} is not a directory")
        entries[path] = {"inum": None, "mode": m["mode"], "uid": m["uid"], "gid": m["gid"],
                         "nlink": m.get("nlink", 2), "size": 0, "mtime": m["mtime"],
                         "atime": m["atime"], "ctime": m["mtime"], "flags": m["flags"]}
    for path, entry in PHASE1_DELTA.items():
        op, want_sha, want_size = entry[0], entry[1], entry[2]
        meta = entry[3] if len(entry) > 3 else None
        if op == "mkdir":
            continue
        data = sources[path]
        if sha(data) != want_sha or len(data) != want_size:
            raise SystemExit(f"REFUSED: {path} source is {sha(data)}/{len(data)}, "
                             f"frozen delta requires {want_sha}/{want_size}")
        parent = path.rsplit("/", 1)[0]
        if parent not in entries or entries[parent]["mode"] & INV.S_IFMT != INV.S_IFDIR:
            raise SystemExit(f"REFUSED: parent of {path} is not an existing directory")
        if op == "replace":
            r = entries.get(path)
            if r is None or r["mode"] & INV.S_IFMT != INV.S_IFREG or r["nlink"] != 1:
                raise SystemExit(f"REFUSED: {path} is not an existing single-link regular file")
            r.update(content=data, size=len(data), sha256=want_sha)
        elif meta is not None:                         # explicit metadata from the source image
            if path in entries:
                raise SystemExit(f"REFUSED: {path} already exists in the donor")
            entries[path] = {"inum": None, "mode": meta["mode"], "uid": meta["uid"],
                             "gid": meta["gid"], "nlink": 1, "size": len(data), "mtime": meta["mtime"],
                             "atime": meta["atime"], "ctime": meta["mtime"], "flags": meta["flags"],
                             "sha256": want_sha, "content": data}
        else:                                          # inherit uniform sibling metadata (z8/z40 path)
            if path in entries:
                raise SystemExit(f"REFUSED: {path} already exists in the donor")
            sibs = [r for p, r in inv["entries"].items()
                    if p.rsplit("/", 1)[0] == parent and r["mode"] & INV.S_IFMT == INV.S_IFREG]
            meta2 = {(r["mode"], r["uid"], r["gid"], r["flags"], r["mtime"], r["atime"]) for r in sibs}
            if len(meta2) != 1:
                raise SystemExit(f"REFUSED: siblings of {path} do not share one metadata tuple: {meta2}")
            mode, uid, gid, flags, mtime, atime = meta2.pop()
            entries[path] = {"inum": None, "mode": mode, "uid": uid, "gid": gid, "nlink": 1,
                             "size": len(data), "mtime": mtime, "atime": atime, "ctime": mtime,
                             "flags": flags, "sha256": want_sha, "content": data}
    # Added entries change directory inode size and subdirectory link counts.
    # The Linux writer derives these from the staged tree; the native writer
    # receives explicit inode metadata and must be given the same final values.
    for directory, record in entries.items():
        if record["mode"] & INV.S_IFMT != INV.S_IFDIR:
            continue
        children = [(path, child) for path, child in entries.items()
                    if path != "/" and (path.rsplit("/", 1)[0] or "/") == directory]
        record["size"] = 160 + sum(dent_size(path.rsplit("/", 1)[1]) for path, _ in children)
        record["nlink"] = 2 + sum(child["mode"] & INV.S_IFMT == INV.S_IFDIR for _, child in children)
    return {**inv, "entries": entries}


def expected_semantic_delta(dinv: dict) -> dict:
    """Every semantic difference the frozen delta may cause, computed, not whitelisted:
    path -> {field: (old, new)} for changes, path -> 'ADDED' for additions."""
    exp = {}
    grow: dict[str, int] = {}
    nlink_grow: dict[str, int] = {}
    added_dirs = {pp for pp, e in PHASE1_DELTA.items() if e[0] == "mkdir"}
    for path, entry in PHASE1_DELTA.items():
        op = entry[0]
        if op == "replace":
            r = dinv["entries"][path]
            exp[path] = {key: (r[key], value) for key, value in
                         (("sha256", entry[1]), ("size", entry[2])) if r[key] != value}
        elif op == "mkdir":
            exp[path] = "ADDED"
            parent, name = path.rsplit("/", 1)
            grow[parent] = grow.get(parent, 0) + dent_size(name)
            nlink_grow[parent] = nlink_grow.get(parent, 0) + 1     # a new subdir bumps parent nlink
        else:
            exp[path] = "ADDED"
            parent, name = path.rsplit("/", 1)
            if parent not in added_dirs:               # files inside a new dir are subsumed by ADDED
                grow[parent] = grow.get(parent, 0) + dent_size(name)
    for parent in set(grow) | set(nlink_grow):
        if parent in added_dirs:
            continue
        d = dinv["entries"][parent]
        chg = {}
        if parent in grow:
            chg["size"] = (d["size"], d["size"] + grow[parent])
        if parent in nlink_grow:
            chg["nlink"] = (d["nlink"], d["nlink"] + nlink_grow[parent])
        exp[parent] = chg
    return exp


def verify_gate2(T, donor: bytes, donor_char: dict, img: bytes) -> dict:
    """Gate 2 verification, fail closed. Raises SystemExit naming the first failure."""
    v = {}
    try:
        v["existing_verifier"] = T.verify(img, donor=donor_char)    # EC/VID/vtbl/node CRCs, index
    except T.ImageError as e:
        raise SystemExit(f"FAIL EXISTING_VERIFIER: {e}")
    v["asw_seal"] = check_asw_seal(img)
    hdr_delta = [i for i in range(ASW_HDR) if donor[i] != img[i]]
    if any(not (ASW_CRC_OFF <= i < ASW_SIZE_OFF + 4) for i in hdr_delta):
        raise SystemExit(f"FAIL ASW_HEADER: bytes outside CRC/size changed: {hdr_delta}")
    v["asw_header_delta_offsets"] = hdr_delta
    dasw, rasw = T.parse_asw(donor), T.parse_asw(img)
    comps = {}
    for dc, rc in zip(dasw["components"], rasw["components"]):
        if (dc["id"], dc["offset"], dc["partition_bytes"], dc["upgrade"], dc["dual"]) != \
                (rc["id"], rc["offset"], rc["partition_bytes"], rc["upgrade"], rc["dual"]):
            raise SystemExit(f"FAIL DESCRIPTOR {dc['id']}")
        if rc["bytes"] > rc["partition_bytes"] and rc["bytes"] != dc["bytes"]:
            raise SystemExit(f"FAIL PARTITION_OVERFLOW {rc['id']}: {rc['bytes']} > {rc['partition_bytes']}")
        same = img[rc["offset"]:rc["offset"] + rc["bytes"]] == donor[dc["offset"]:dc["offset"] + dc["bytes"]]
        if dc["id"] != PHASE1_COMPONENT and not same:
            raise SystemExit(f"FAIL COMPONENT_CHANGED {dc['id']}: only component {PHASE1_COMPONENT} may change")
        comps[dc["id"]] = {"offset": rc["offset"], "partition_bytes": rc["partition_bytes"],
                           "donor_bytes": dc["bytes"], "new_bytes": rc["bytes"],
                           "donor_sha256": dc["sha256"], "new_sha256": rc["sha256"],
                           "byte_identical_to_donor": same}
    v["components"] = comps
    # UBI metadata of the regenerated component
    dvol, dubi = volume_of(T, donor, PHASE1_COMPONENT)
    rvol, rubi = volume_of(T, img, PHASE1_COMPONENT)
    for f in ("image_seq", "peb_size", "vid_hdr_offset", "data_offset", "leb_size"):
        if dubi[f] != rubi[f]:
            raise SystemExit(f"FAIL UBI_META {f}")
    dv = {k: x for k, x in dubi["vtbl"][0].items() if k != "reserved_pebs"}
    rv = {k: x for k, x in rubi["vtbl"][0].items() if k != "reserved_pebs"}
    if dv != rv:
        raise SystemExit(f"FAIL VTBL_META: {dv} vs {rv}")
    dsb, rsb = T.ubifs_superblock(dvol), T.ubifs_superblock(rvol)
    sb_diff = {k: (dsb[k], rsb[k]) for k in SB_FIELDS_MUST_MATCH if dsb[k] != rsb[k]}
    if sb_diff:
        raise SystemExit(f"FAIL SUPERBLOCK: {sb_diff}")
    if rubi["vtbl"][0]["reserved_pebs"] != rsb["leb_cnt"]:
        raise SystemExit("FAIL VTBL_RESERVED_PEBS != UBIFS leb_cnt")
    v["ubi"] = {"vtbl_reserved_pebs": {"donor": dubi["vtbl"][0]["reserved_pebs"],
                                       "new": rubi["vtbl"][0]["reserved_pebs"]},
                "ubifs_leb_cnt": {"donor": dsb["leb_cnt"], "new": rsb["leb_cnt"]},
                "ubifs_max_leb_cnt": rsb["max_leb_cnt"],
                "lpt_lebs": {"donor": dsb["lpt_lebs"], "new": rsb["lpt_lebs"]},
                "image_seq": rubi["image_seq"]}
    # semantic inventory, rootfs and usrdata
    rootfs_d = compare_inventories(INV.inventory(volume_of(T, donor, 4)[0]),
                                   INV.inventory(volume_of(T, img, 4)[0]))
    if rootfs_d:
        raise SystemExit(f"FAIL ROOTFS_SEMANTIC: {rootfs_d[:5]}")
    dinv, rinv = INV.inventory(dvol, with_content=True), INV.inventory(rvol, with_content=True)
    exp = expected_semantic_delta(dinv)
    dview, rview = INV.semantic_view(dinv), INV.semantic_view(rinv)
    actual = {}
    for p in sorted(set(dview) | set(rview)):
        if p not in dview:
            actual[p] = "ADDED"
        elif p not in rview:
            actual[p] = "REMOVED"
        elif dview[p] != rview[p]:
            actual[p] = {k: (dview[p].get(k), rview[p].get(k)) for k in set(dview[p]) | set(rview[p])
                         if dview[p].get(k) != rview[p].get(k)}
    if actual != exp:
        unexpected = {p: actual.get(p) for p in set(actual) | set(exp) if actual.get(p) != exp.get(p)}
        raise SystemExit(f"FAIL UNEXPECTED_FS_DELTA: {unexpected}")
    # added files: content, size and sibling metadata exactly
    added = {}
    for path, entry in PHASE1_DELTA.items():
        op, want_sha, want_size = entry[0], entry[1], entry[2]
        meta = entry[3] if len(entry) > 3 else None
        r = rinv["entries"][path]
        if op == "mkdir":                               # new directory with explicit metadata
            if r["mode"] & INV.S_IFMT != INV.S_IFDIR:
                raise SystemExit(f"FAIL MKDIR_NOT_DIR {path}: mode {oct(r['mode'])}")
            for k in ("mode", "uid", "gid", "flags", "mtime", "atime"):
                if r[k] != meta[k]:
                    raise SystemExit(f"FAIL ADDED_METADATA {path} {k}: {r[k]} != {meta[k]}")
            if r["nlink"] != meta.get("nlink", 2):
                raise SystemExit(f"FAIL ADDED_METADATA {path} nlink: {r['nlink']} != {meta.get('nlink', 2)}")
            added[path] = {"op": op, "mode": oct(r["mode"]), "uid": r["uid"], "gid": r["gid"],
                           "nlink": r["nlink"], "mtime": r["mtime"]}
            continue
        if r["sha256"] != want_sha or r["size"] != want_size or sha(r["content"]) != want_sha:
            raise SystemExit(f"FAIL CONTENT {path}")
        if op == "add" and meta is not None:            # explicit metadata from the source image
            for k in ("mode", "uid", "gid", "flags", "mtime", "atime"):
                if r[k] != meta[k]:
                    raise SystemExit(f"FAIL ADDED_METADATA {path} {k}: {r[k]} != {meta[k]}")
            if r["nlink"] != 1:
                raise SystemExit(f"FAIL ADDED_METADATA {path} nlink: {r['nlink']} != 1")
        elif op == "add":                               # inherit uniform sibling metadata (z8/z40)
            parent = path.rsplit("/", 1)[0]
            sib = next(x for p, x in dinv["entries"].items()
                       if p.rsplit("/", 1)[0] == parent and x["mode"] & INV.S_IFMT == INV.S_IFREG)
            for k in ("mode", "uid", "gid", "nlink", "flags", "mtime", "atime"):
                want = 1 if k == "nlink" else sib[k]
                if r[k] != want:
                    raise SystemExit(f"FAIL ADDED_METADATA {path} {k}: {r[k]} != {want}")
        else:
            d = dinv["entries"][path]
            for k in ("mode", "uid", "gid", "nlink", "flags", "mtime", "atime"):
                if r[k] != d[k]:
                    raise SystemExit(f"FAIL REPLACED_METADATA {path} {k}")
        added[path] = {"op": op, "sha256": r["sha256"], "size": r["size"], "mode": oct(r["mode"]),
                       "uid": r["uid"], "gid": r["gid"], "nlink": r["nlink"], "mtime": r["mtime"]}
    v["fs_delta"] = {"files": added, "collateral": {p: x for p, x in exp.items() if p not in PHASE1_DELTA},
                     "entries": {"donor": len(dinv["entries"]), "new": len(rinv["entries"])},
                     "symlinks": {"donor": sum(1 for x in dinv["entries"].values() if "target" in x),
                                  "new": sum(1 for x in rinv["entries"].values() if "target" in x)},
                     "hardlinks": {"donor": dinv["hardlinks"], "new": rinv["hardlinks"]},
                     "nonfs_nodes": {"donor": dinv["nonfs_nodes"], "new": rinv["nonfs_nodes"]}}
    if dinv["hardlinks"] != rinv["hardlinks"]:
        raise SystemExit("FAIL HARDLINKS changed")
    # inode numbers: allocation detail, reported, never silently ignored
    same_inum = sum(1 for p in dinv["entries"] if p in rinv["entries"]
                    and dinv["entries"][p]["inum"] == rinv["entries"][p]["inum"])
    v["fs_delta"]["inode_numbers"] = {"common_paths": len(set(dinv["entries"]) & set(rinv["entries"])),
                                      "same_inum": same_inum}
    v["deflate_window"] = check_window(rvol, PHASE1_COMPONENT)
    v["growth"] = explain_growth(dvol, rvol, dinv, rinv, dubi, rubi)
    return v


def explain_growth(dvol, rvol, dinv, rinv, dubi, rubi) -> dict:
    """Attribute the usrdata volume's LEB growth to node bytes, by file."""
    ds, rs = INV.sweep(dvol), INV.sweep(rvol)

    def per_inode(s):
        out = {}
        for (inum, _b), (_q, node) in s["data"].items():
            out[inum] = out.get(inum, 0) + ((len(node) + 7) & ~7)
        return out
    dpi, rpi = per_inode(ds), per_inode(rs)

    def node_bytes(s, kind):
        return sum((len(n) + 7) & ~7 for _, n in s[kind].values())
    files = {}
    for path in PHASE1_DELTA:
        old = dinv["entries"].get(path)
        new = rinv["entries"][path]
        files[path] = {"logical_bytes": {"donor": old["size"] if old else 0, "new": new["size"]},
                       "data_node_bytes": {"donor": dpi.get(old["inum"], 0) if old else 0,
                                           "new": rpi.get(new["inum"], 0)}}
    d_total = {k: node_bytes(ds, k) for k in ("ino", "dent", "data")}
    r_total = {k: node_bytes(rs, k) for k in ("ino", "dent", "data")}
    delta_files = sum(f["data_node_bytes"]["new"] - f["data_node_bytes"]["donor"] for f in files.values())
    other_data = (r_total["data"] - d_total["data"]) - delta_files
    leb = dubi["leb_size"]
    return {"per_file": files,
            "data_node_bytes_delta_from_delta_files": delta_files,
            "data_node_bytes_delta_elsewhere": other_data,
            "fs_node_bytes": {"donor": d_total, "new": r_total},
            "lebs": {"donor": dubi["volumes"][0]["lebs"], "new": rubi["volumes"][0]["lebs"],
                     "leb_size": leb,
                     "delta_bytes_in_lebs": (rubi["volumes"][0]["lebs"] - dubi["volumes"][0]["lebs"]) * leb}}


def gate2(donor_path: Path, gate1_report: Path, sources: dict[str, Path], work: Path, mkfs: Path,
          verifier_path: str, out_path: Path) -> dict:
    from variant_identity import patch_updater, UPDATER_PATH, EXPECTED_SHA
    global PHASE1_DELTA
    T, verifier_sha = load_verifier(verifier_path)
    donor = donor_path.read_bytes()
    g1 = json.loads(gate1_report.read_text())
    if not g1.get("PASS") or g1.get("donor_sha256") != sha(donor) or g1.get("verifier_sha256") != verifier_sha:
        raise SystemExit("REFUSED: gate 1 has not passed on this donor with this verifier")
    if not sha(donor).startswith(GATE2_DONOR_SHA):
        raise SystemExit("REFUSED: the frozen phase-1 delta is defined against 19.2.14 f166927f... only")
    donor_char = T.characterize(donor_path)
    T.verify(donor, donor=donor_char)
    src = {p: Path(s).read_bytes() for p, s in sources.items()}
    work.mkdir(parents=True, exist_ok=True)
    dvol, _ = volume_of(T, donor, PHASE1_COMPONENT)
    donor_inventory = INV.inventory(dvol, with_content=True)
    updater = patch_updater(donor_inventory["entries"][UPDATER_PATH]["content"], CAMERA_SUBTYPE)
    from verify_variant_identity import verify_identity
    identity_execution = verify_identity(updater, CAMERA_SUBTYPE)
    # Add one explicit pinned replacement; retain every existing camera/file guard.
    PHASE1_DELTA = dict(PHASE1_DELTA)
    PHASE1_DELTA[UPDATER_PATH] = ("replace", EXPECTED_SHA[CAMERA_SUBTYPE], len(updater))
    src[UPDATER_PATH] = updater
    inv = apply_phase1_delta(donor_inventory, src)
    comp, meta = _regen_fs_component(T, donor, PHASE1_COMPONENT, inv, work, mkfs)
    img = assemble_asw(T, donor, {PHASE1_COMPONENT: comp})
    report = {"gate": "mode_a_gate2_z40_phase1", "donor": donor_path.name, "donor_sha256": sha(donor),
              "gate1_report_sha256": sha(gate1_report.read_bytes()),
              "verifier": verifier_path, "verifier_sha256": verifier_sha,
              "mkfs_version": subprocess.run([str(mkfs), "--version"], capture_output=True,
                                             text=True).stdout.strip(),
              "sources": {p: {"path": str(s), "sha256": sha(src[p]), "bytes": len(src[p])}
                          for p, s in sources.items()},
              "build": {"component": PHASE1_COMPONENT, **meta}}
    report["camera_identity"] = {"subtype": CAMERA_SUBTYPE, "updater_sha256": sha(updater),
                                 "rootfs_unchanged": True,
                                 "method": "pinned command-60 hook; original hardware selector retained",
                                 "execution_gate": identity_execution}
    report["verification"] = verify_gate2(T, donor, donor_char, img)   # raises before any write
    out_path.write_bytes(img)
    report["image"] = {"file": out_path.name, "sha256": sha(img), "bytes": len(img)}
    report["PASS"] = True
    return report


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("donor", type=Path)
    ap.add_argument("--work", type=Path, required=True)
    ap.add_argument("--mkfs", type=Path, required=True)
    ap.add_argument("--verifier", default=DEFAULT_VERIFIER)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--report", type=Path, required=True)
    ap.add_argument("--gate2", action="store_true", help="build the frozen Z40 phase-1 candidate")
    ap.add_argument("--gate1-report", type=Path)
    ap.add_argument("--source", action="append", default=[], metavar="DEVPATH=FILE")
    a = ap.parse_args(argv)
    if a.gate2:
        if not a.gate1_report:
            raise SystemExit("REFUSED: --gate2 needs --gate1-report")
        sources = dict(x.split("=", 1) for x in a.source)
        rep = gate2(a.donor, a.gate1_report, sources, a.work, a.mkfs, a.verifier, a.out)
        a.report.write_text(json.dumps(rep, indent=1, default=str))
        print(json.dumps({"PASS": rep["PASS"], **rep["image"]}, indent=1))
        return 0
    if a.source:
        raise SystemExit("REFUSED: an overlay is accepted only by --gate2")
    rep = gate1(a.donor, a.work, a.mkfs, a.verifier, a.out)
    a.report.write_text(json.dumps(rep, indent=1, default=str))
    print(json.dumps({k: rep[k] for k in ("PASS", "donor_sha256", "rebuilt_sha256",
                                         "byte_identical_to_donor", "byte_delta_by_component")},
                     indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
