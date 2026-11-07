#!/usr/bin/env python3
"""Ascent G_Sky image tool — inspect, unpack, verify, roundtrip.

A reusable capability rather than another one-off firmware archaeology exercise.
Everything it reports is MEASURED from the donor in front of it. Nothing is carried
over from another base: an 18.21.8 geometry applied to a 19.2.14 image is how a
packer produces a file that passes its own checks and bricks a unit.

ORDER OF WORK, and it is not negotiable:

    inspect  -> characterize a donor and print what it actually is
    unpack   -> take it apart, keeping every number needed to put it back
    verify   -> fail closed on anything structurally wrong
    roundtrip-> unpack and repack with ZERO semantic changes, then prove the
                result is byte-identical, or explain every differing byte

`patch` does not exist yet and must not be added until roundtrip passes on the base
being targeted. A round-trip proof is per-base and does not transfer.

WHAT VERIFY IS. It is the spine, not a fourth command: unpack, roundtrip and any
future patch all need the same fail-closed checks, so there is one implementation
and three callers. A check that exists in one path and not another is a check that
will be skipped exactly when it matters.

PRIOR ART IN THIS REPO, so nobody rebuilds it. firmware/sky_rndis_provision/ already
writes UBIFS: its preserved-node-span surgery round-trips stock 19.2.4 to the exact
SHA-256 6c3e7c67..., 17,216,417 bytes. That method rewrites existing nodes IN PLACE
at unchanged length and therefore cannot add a file. This tool exists for the cases
that one cannot serve, and for bases it was never proven on.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
import zlib
from pathlib import Path

# ------------------------------------------------------------------ containers --
ASW_MAGIC = b"ASW\0"
ASW_HDR_BYTES = 0x80
ASW_DESC_BASE = 0x14
ASW_DESC_SIZE = 12
ASW_DESC_COUNT = 5

UBI_EC_MAGIC = b"UBI#"
UBI_VID_MAGIC = b"UBI!"
UBI_VTBL_RECORD = 172          # sizeof(struct ubi_vtbl_record)
UBIFS_MAGIC = b"\x31\x18\x10\x06"
UBIFS_SB_NODE = 6
UBIFS_MST_NODE = 7
# UBIFS node types, from the on-disk format: 0 INO, 1 DATA, 2 DENT, 3 XENT, 4 TRUN,
# 5 PAD, 6 SB, 7 MST, 8 REF, 9 IDX, 10 CS, 11 ORPH. IDX is 9 -- reading it as 5
# landed on a padding node and produced a child_cnt of 1956 on the first real image.
UBIFS_PAD_NODE = 5
UBIFS_IDX_NODE = 9
UBIFS_KEY_LEN = 8        # UBIFS_SK_LEN, the simple key format

# Bounds. A header outside these is refused rather than acted on: width and count
# fields size allocations, and a corrupt one must not become a huge read.
MAX_IMAGE_BYTES = 256 * 1024 * 1024
MAX_PEBS = 8192


class ImageError(RuntimeError):
    """A named, reportable refusal. Every check in this tool fails this way."""

    def __init__(self, code: str, message: str, detail: dict | None = None):
        super().__init__(message)
        self.code, self.message, self.detail = code, message, detail or {}

    def __str__(self) -> str:
        d = f"  {self.detail}" if self.detail else ""
        return f"{self.code}: {self.message}{d}"


def _u32le(b, o): return struct.unpack_from("<I", b, o)[0]
def _u32be(b, o): return struct.unpack_from(">I", b, o)[0]
def _u64le(b, o): return struct.unpack_from("<Q", b, o)[0]
def _sha(b): return hashlib.sha256(b).hexdigest()


def ubi_crc32(buf: bytes) -> int:
    """UBI and UBIFS both use crc32 seeded with 0xFFFFFFFF and NO final inversion,
    which is zlib's result inverted. Verified against the stored EC header CRC of
    19.2.14's rootfs block 0 (0xea799ab3) rather than taken from a header file."""
    return (~zlib.crc32(buf)) & 0xFFFFFFFF


# ----------------------------------------------------------------------- ASW ----
def parse_asw(data: bytes) -> dict:
    """The outer container, read from its own descriptor table.

    Component extents come from the table, never from filenames or another version.
    The table carries an offset and a PARTITION size -- the partition is what the
    component may occupy on the device, not how many bytes it occupies here -- so the
    on-disk extent of each component runs to the next descriptor's offset.
    """
    if len(data) < ASW_HDR_BYTES:
        raise ImageError("NOT_AN_IMAGE", "too small to be an ASW image")
    if data[:4] != ASW_MAGIC:
        raise ImageError("BAD_ASW_MAGIC", "this is not an ASW container",
                         {"first_four": data[:4].hex()})
    major, minor, patch = _u32le(data, 8), _u32le(data, 12), _u32le(data, 16)
    descs = []
    for i in range(ASW_DESC_COUNT):
        o = ASW_DESC_BASE + i * ASW_DESC_SIZE
        descs.append({"id": data[o], "upgrade": data[o + 1], "dual": data[o + 2],
                      "partition_bytes": _u32le(data, o + 4),
                      "offset": _u32le(data, o + 8), "desc_at": o})
    for d in descs:
        if not (0 < d["offset"] <= len(data)):
            raise ImageError("COMPONENT_OUT_OF_RANGE",
                             "a component descriptor points outside the file", d)
    order = sorted(descs, key=lambda d: d["offset"])
    for i, d in enumerate(order):
        end = order[i + 1]["offset"] if i + 1 < len(order) else len(data)
        d["bytes"] = end - d["offset"]
        d["sha256"] = _sha(data[d["offset"]:end])
    return {"magic": "ASW", "board_type": data[4],
            "version": f"{major}.{minor}.{patch}",
            "header_tail": data[0x60:0x80].hex(),
            "file_bytes": len(data), "sha256": _sha(data),
            "components": sorted(descs, key=lambda d: d["id"])}


# ----------------------------------------------------------------------- UBI ----
def _ec_hdr(peb: bytes, pnum: int) -> dict:
    if peb[:4] != UBI_EC_MAGIC:
        raise ImageError("BAD_EC_MAGIC", f"erase block {pnum} has no UBI# header")
    crc = _u32be(peb, 60)
    if crc != ubi_crc32(peb[:60]):
        raise ImageError("BAD_EC_CRC", f"erase block {pnum} EC header CRC is wrong")
    return {"version": peb[4], "ec": struct.unpack_from(">Q", peb, 8)[0],
            "vid_hdr_offset": _u32be(peb, 16), "data_offset": _u32be(peb, 20),
            "image_seq": _u32be(peb, 24)}


def _vid_hdr(peb: bytes, off: int, pnum: int) -> dict | None:
    """None means this block carries no volume -- an unmapped spare, which is normal."""
    if peb[off:off + 4] != UBI_VID_MAGIC:
        return None
    crc = _u32be(peb, off + 60)
    if crc != ubi_crc32(peb[off:off + 60]):
        raise ImageError("BAD_VID_CRC", f"erase block {pnum} VID header CRC is wrong")
    # struct ubi_vid_hdr: magic@0 version@4 vol_type@5 copy_flag@6 compat@7 vol_id@8
    # lnum@12 padding1@16 data_size@20 used_ebs@24 data_pad@28 data_crc@32
    # padding2@36 sqnum@40 padding3@48 hdr_crc@60. data_size sits at 20, not 16 --
    # the four bytes at 16 are padding, and reading through them shifted every field
    # after it.
    return {"version": peb[off + 4], "vol_type": peb[off + 5], "copy_flag": peb[off + 6],
            "compat": peb[off + 7], "vol_id": _u32be(peb, off + 8),
            "lnum": _u32be(peb, off + 12), "data_size": _u32be(peb, off + 20),
            "used_ebs": _u32be(peb, off + 24), "data_pad": _u32be(peb, off + 28),
            "data_crc": _u32be(peb, off + 32),
            "sqnum": struct.unpack_from(">Q", peb, off + 40)[0]}


def parse_ubi(blob: bytes, *, name: str) -> dict:
    """Every erase block, its headers, and the volume layout — measured, not assumed.

    PEB size is DERIVED here rather than hardcoded. A tool that assumes 128 KiB is a
    tool that silently misreads the first base that is not.
    """
    peb_size = _derive_peb_size(blob, name)
    if len(blob) % peb_size:
        raise ImageError("UBI_NOT_BLOCK_ALIGNED",
                         f"{name} is not a whole number of {peb_size}-byte blocks",
                         {"bytes": len(blob), "peb": peb_size})
    n = len(blob) // peb_size
    if n > MAX_PEBS:
        raise ImageError("UBI_TOO_MANY_PEBS", f"{name} declares {n} erase blocks")

    blocks, image_seqs, vtbl_copies = [], set(), []
    for i in range(n):
        peb = blob[i * peb_size:(i + 1) * peb_size]
        ec = _ec_hdr(peb, i)
        image_seqs.add(ec["image_seq"])
        vid = _vid_hdr(peb, ec["vid_hdr_offset"], i)
        rec = {"pnum": i, **ec, "vid": vid}
        blocks.append(rec)
        # The volume table lives in the layout volume, vol_id 0x7FFFEFFF, two copies.
        if vid and vid["vol_id"] == 0x7FFFEFFF:
            vtbl_copies.append(peb[ec["data_offset"]:])

    if len(image_seqs) != 1:
        raise ImageError("UBI_IMAGE_SEQ_MIXED",
                         f"{name} carries more than one image_seq", {"seen": sorted(image_seqs)})
    if len(vtbl_copies) == 2 and vtbl_copies[0] != vtbl_copies[1]:
        raise ImageError("UBI_VTBL_COPIES_DIFFER",
                         f"{name}'s two volume-table copies are not identical")

    volumes = {}
    for b in blocks:
        v = b["vid"]
        if not v or v["vol_id"] == 0x7FFFEFFF:
            continue
        volumes.setdefault(v["vol_id"], []).append(b)

    return {"name": name, "bytes": len(blob), "peb_size": peb_size, "peb_count": n,
            "image_seq": next(iter(image_seqs)),
            "vid_hdr_offset": blocks[0]["vid_hdr_offset"],
            "data_offset": blocks[0]["data_offset"],
            "leb_size": peb_size - blocks[0]["data_offset"],
            "vtbl_copies": len(vtbl_copies),
            "vtbl": _parse_vtbl(vtbl_copies[0]) if vtbl_copies else [],
            "volumes": {vid: {"lebs": len(bs),
                              "vol_type": bs[0]["vid"]["vol_type"],
                              "max_lnum": max(b["vid"]["lnum"] for b in bs)}
                        for vid, bs in sorted(volumes.items())},
            "blocks": blocks}


def _derive_peb_size(blob: bytes, name: str) -> int:
    """Find the block size by locating the second UBI# header.

    Measured rather than assumed, because that is the whole discipline here.
    """
    for candidate in (0x20000, 0x10000, 0x40000, 0x4000, 0x8000):
        if len(blob) % candidate == 0 and blob[candidate:candidate + 4] == UBI_EC_MAGIC:
            return candidate
    if blob[:4] == UBI_EC_MAGIC and len(blob) in (0x20000, 0x10000):
        return len(blob)
    raise ImageError("UBI_PEB_SIZE_UNKNOWN",
                     f"could not derive an erase-block size for {name}")


def _parse_vtbl(buf: bytes) -> list[dict]:
    out = []
    for i in range(0, min(len(buf), UBI_VTBL_RECORD * 128), UBI_VTBL_RECORD):
        rec = buf[i:i + UBI_VTBL_RECORD]
        if len(rec) < UBI_VTBL_RECORD:
            break
        reserved = _u32be(rec, 0)
        if reserved == 0:
            continue
        crc = _u32be(rec, UBI_VTBL_RECORD - 4)
        if crc != ubi_crc32(rec[:UBI_VTBL_RECORD - 4]):
            raise ImageError("UBI_VTBL_RECORD_CRC", f"volume-table record {i // UBI_VTBL_RECORD} CRC is wrong")
        # struct ubi_vtbl_record: reserved_pebs@0 alignment@4 data_pad@8 vol_type@12
        # upd_marker@13 name_len@14(be16) name@16[128] flags@144 crc@168. Reading
        # name_len at 12 picked up vol_type and printed the whole padded field.
        nlen = struct.unpack_from(">H", rec, 14)[0]
        if nlen > 128:
            raise ImageError("UBI_VTBL_NAME_LEN",
                             f"volume-table record {i // UBI_VTBL_RECORD} declares a "
                             f"{nlen}-byte name in a 128-byte field")
        out.append({"vol_id": i // UBI_VTBL_RECORD, "reserved_pebs": reserved,
                    "alignment": _u32be(rec, 4), "data_pad": _u32be(rec, 8),
                    "vol_type": rec[12], "upd_marker": rec[13], "name_len": nlen,
                    "name": rec[16:16 + nlen].decode("utf-8", "replace"),
                    "flags": rec[144]})
    return out


# --------------------------------------------------------------------- UBIFS ----
def ubifs_superblock(vol: bytes) -> dict:
    """The superblock is the geometry the device itself will use. It is read, never
    inferred -- min_io, LEB size and max_leb_cnt are what a rebuild must reproduce,
    and SPACE_FIXUP decides whether a rebuild needs -F."""
    off = vol.find(UBIFS_MAGIC)
    while off != -1:
        if len(vol) >= off + 4096 and vol[off + 20] == UBIFS_SB_NODE:
            node_len = _u32le(vol, off + 16)
            node = vol[off:off + node_len]
            if _u32le(node, 4) == ubi_crc32(node[8:]):
                return {"at": off, "node_len": node_len,
                        "key_hash": node[26], "key_fmt": node[27],
                        "flags": _u32le(node, 28), "min_io_size": _u32le(node, 32),
                        "leb_size": _u32le(node, 36), "leb_cnt": _u32le(node, 40),
                        "max_leb_cnt": _u32le(node, 44),
                        "max_bud_bytes": _u64le(node, 48),
                        "log_lebs": _u32le(node, 56), "lpt_lebs": _u32le(node, 60),
                        "orph_lebs": _u32le(node, 64), "jhead_cnt": _u32le(node, 68),
                        "fanout": _u32le(node, 72), "lsave_cnt": _u32le(node, 76),
                        "fmt_version": _u32le(node, 80),
                        "default_compr": struct.unpack_from("<H", node, 84)[0],
                        "space_fixup": bool(_u32le(node, 28) & 0x4)}
        off = vol.find(UBIFS_MAGIC, off + 1)
    raise ImageError("UBIFS_NO_SUPERBLOCK", "no valid UBIFS superblock node was found")


def ubi_volume_data(ubi: dict, blob: bytes, vol_id: int = 0) -> bytes:
    """Logical blocks in LOGICAL order. UBI stores them wherever a block was free, so
    physical order is not filesystem order; a gap is zero-filled rather than closed,
    because shifting later blocks down corrupts silently while a zero gap fails a CRC
    loudly."""
    peb, data_off = ubi["peb_size"], ubi["data_offset"]
    lebs = {}
    for b in ubi["blocks"]:
        v = b["vid"]
        if v and v["vol_id"] == vol_id:
            lebs[v["lnum"]] = blob[b["pnum"] * peb + data_off:(b["pnum"] + 1) * peb]
    if not lebs:
        raise ImageError("UBI_VOLUME_ABSENT", f"no volume {vol_id} in this component")
    leb_size = peb - data_off
    return b"".join(lebs.get(i, b"\0" * leb_size) for i in range(max(lebs) + 1))


def count_ubifs_nodes(vol: bytes) -> dict:
    """Every recognized node and whether its CRC holds. Nodes that fail are counted,
    not hidden: a healthy image has none, and a count above zero is the finding."""
    seen, bad, off, n = {}, 0, 0, len(vol)
    leb_cap = len(vol)
    while off < n - 24:
        if vol[off:off + 4] != UBIFS_MAGIC:
            off += 8
            continue
        ln = _u32le(vol, off + 16)
        if not (24 <= ln <= leb_cap and off + ln <= n):
            off += 8
            continue
        node = vol[off:off + ln]
        ntype = vol[off + 20]
        seen[ntype] = seen.get(ntype, 0) + 1
        if _u32le(node, 4) != ubi_crc32(node[8:]):
            bad += 1
        off += 8
    return {"by_type": dict(sorted(seen.items())), "total": sum(seen.values()), "bad_crc": bad}


def check_index_topology(vol: bytes, leb_size: int) -> dict:
    """Walk every index node's branches and prove each one points at a real node.

    THIS IS THE CHECK THAT CRCs CANNOT DO. A mutation can rewrite a node's contents
    and recompute its CRC, so every checksum in the image still holds while the index
    branch that refers to it now states the wrong length or the wrong key. Nothing
    above would notice. Here, a branch whose target is absent, the wrong length, or
    keyed differently is a hard refusal.

    Branch layout, UBIFS_IDX_NODE: ch(24) child_cnt(le16) level(le16) then
    child_cnt branches of {lnum le32, offs le32, len le32, key[8]}.
    """
    branches = targets = 0
    off, n = 0, len(vol)
    while off < n - 24:
        if vol[off:off + 4] != UBIFS_MAGIC:
            off += 8
            continue
        node_len = _u32le(vol, off + 16)
        if not (24 <= node_len <= leb_size and off + node_len <= n):
            off += 8
            continue
        if vol[off + 20] != UBIFS_IDX_NODE:
            off += 8
            continue
        node = vol[off:off + node_len]
        if _u32le(node, 4) != ubi_crc32(node[8:]):
            off += 8
            continue
        child_cnt = struct.unpack_from("<H", node, 24)[0]
        stride = 12 + UBIFS_KEY_LEN
        for b in range(child_cnt):
            bo = 28 + b * stride
            if bo + stride > node_len:
                raise ImageError("IDX_BRANCH_TRUNCATED",
                                 f"index node at {off} declares {child_cnt} children but "
                                 f"branch {b} runs past the node")
            lnum, offs, blen = struct.unpack_from("<III", node, bo)
            key = node[bo + 12:bo + 12 + UBIFS_KEY_LEN]
            branches += 1
            abs_off = lnum * leb_size + offs
            if abs_off + 24 > n:
                raise ImageError("IDX_BRANCH_OUT_OF_RANGE",
                                 "an index branch points past the end of the volume",
                                 {"lnum": lnum, "offs": offs})
            if vol[abs_off:abs_off + 4] != UBIFS_MAGIC:
                raise ImageError("IDX_BRANCH_TARGET_ABSENT",
                                 "an index branch points at something that is not a node",
                                 {"lnum": lnum, "offs": offs})
            target_len = _u32le(vol, abs_off + 16)
            if target_len != blen:
                raise ImageError("IDX_BRANCH_LENGTH_MISMATCH",
                                 "an index branch states a length its target does not have",
                                 {"lnum": lnum, "offs": offs,
                                  "branch_len": blen, "target_len": target_len})
            # The key the branch carries must be the key the target node holds. For
            # data, inode and dirent nodes the key sits at ch+8 .. ch+8+8.
            tkey = vol[abs_off + 24:abs_off + 24 + UBIFS_KEY_LEN]
            if vol[abs_off + 20] in (0, 1, 2) and tkey != key:
                raise ImageError("IDX_BRANCH_KEY_MISMATCH",
                                 "an index branch is keyed differently from its target",
                                 {"lnum": lnum, "offs": offs,
                                  "branch_key": key.hex(), "target_key": tkey.hex()})
            targets += 1
        off += 8
    return {"branches": branches, "targets_resolved": targets}


# -------------------------------------------------------------------- verify ----
# The spine. unpack, roundtrip and any future patch all call this, so a check cannot
# exist in one path and be skipped in another -- which is exactly when it would have
# mattered. Every failure is a named refusal; nothing warns and continues.

def verify(data: bytes, *, donor: dict | None = None) -> dict:
    """Structural verification of a whole image. Fails closed, loudly, by name.

    `donor` is a prior characterize() result. When given, component identity is
    compared against it, which is what catches a component that moved or was
    silently replaced -- the thing a size-and-CRC check alone will not see.
    """
    checks: list[str] = []

    asw = parse_asw(data)                      # magic, bounds, descriptor sanity
    checks.append("asw_header")
    if asw["file_bytes"] != len(data):
        raise ImageError("ASW_SIZE_MISMATCH", "declared size is not the file size")

    offsets = [c["offset"] for c in asw["components"]]
    if len(set(offsets)) != len(offsets):
        raise ImageError("ASW_DUPLICATE_OFFSET", "two components share an offset")
    checks.append("asw_component_extents")

    if donor is not None:
        dmap = {c["id"]: c for c in donor["components"]}
        for c in asw["components"]:
            d = dmap.get(c["id"])
            if d is None:
                raise ImageError("COMPONENT_UNEXPECTED",
                                 f"component {c['id']} is not in the donor")
            if c["offset"] != d["offset"]:
                raise ImageError("COMPONENT_MOVED",
                                 f"component {c['id']} moved",
                                 {"donor": d["offset"], "image": c["offset"]})
        checks.append("component_identity_vs_donor")

    for c in asw["components"]:
        blob = data[c["offset"]:c["offset"] + c["bytes"]]
        if blob[:4] != UBI_EC_MAGIC:
            continue
        ubi = parse_ubi(blob, name=f"component{c['id']}")   # EC/VID/VTBL CRCs
        checks.append(f"ubi{c['id']}_headers")

        if ubi["vtbl_copies"] != 2:
            raise ImageError("UBI_VTBL_COPIES",
                             f"component {c['id']} has {ubi['vtbl_copies']} volume-table "
                             f"copies; UBI keeps two")
        for v in ubi["vtbl"]:
            live = ubi["volumes"].get(v["vol_id"])
            if live is None:
                continue
            # reserved_pebs is what the device will honour. A volume holding more
            # blocks than its table reserves is a filesystem that will not mount.
            if live["lebs"] > v["reserved_pebs"]:
                raise ImageError("UBI_RESERVED_PEBS",
                                 f"volume {v['vol_id']} uses {live['lebs']} blocks but "
                                 f"reserves {v['reserved_pebs']}")
        checks.append(f"ubi{c['id']}_vtbl")

        vol = ubi_volume_data(ubi, blob, 0)
        sb = ubifs_superblock(vol)                            # superblock CRC
        if sb["leb_size"] != ubi["leb_size"]:
            raise ImageError("UBIFS_LEB_MISMATCH",
                             f"component {c['id']} superblock says LEB {sb['leb_size']} "
                             f"but UBI geometry gives {ubi['leb_size']}")
        if sb["leb_cnt"] > sb["max_leb_cnt"]:
            raise ImageError("UBIFS_LEB_CNT", "leb_cnt exceeds max_leb_cnt")
        if sb["min_io_size"] <= 0 or sb["min_io_size"] & (sb["min_io_size"] - 1):
            raise ImageError("UBIFS_MIN_IO", f"min_io {sb['min_io_size']} is not a power of two")
        checks.append(f"ubifs{c['id']}_superblock")

        nodes = count_ubifs_nodes(vol)
        if nodes["bad_crc"]:
            raise ImageError("UBIFS_NODE_CRC",
                             f"component {c['id']} has {nodes['bad_crc']} nodes whose CRC "
                             f"does not hold")
        if nodes["by_type"].get(UBIFS_SB_NODE, 0) < 1:
            raise ImageError("UBIFS_NO_SUPERBLOCK_NODE", "no superblock node")
        if nodes["by_type"].get(UBIFS_MST_NODE, 0) != 2:
            raise ImageError("UBIFS_MASTER_NODES",
                             f"component {c['id']} has "
                             f"{nodes['by_type'].get(UBIFS_MST_NODE, 0)} master nodes; "
                             f"UBIFS keeps two")
        checks.append(f"ubifs{c['id']}_nodes")

        idx = check_index_topology(vol, ubi["leb_size"])
        if idx["branches"] == 0:
            raise ImageError("IDX_NO_BRANCHES",
                             f"component {c['id']} has no index branches at all")
        checks.append(f"ubifs{c['id']}_index_topology({idx['branches']})")

        if donor is not None:
            du = donor["ubi"].get(c["id"]) or donor["ubi"].get(str(c["id"]))
            if du:
                for field in ("image_seq", "peb_size", "leb_size"):
                    if ubi[field] != du["ubi"][field]:
                        raise ImageError(f"UBI_{field.upper()}_CHANGED",
                                         f"component {c['id']} {field} changed",
                                         {"donor": du["ubi"][field], "image": ubi[field]})
                if sb["space_fixup"] != du["ubifs"]["space_fixup"]:
                    raise ImageError("UBIFS_SPACE_FIXUP_CHANGED",
                                     f"component {c['id']} SPACE_FIXUP changed; a rebuild "
                                     f"that drops it needs mkfs.ubifs -F")
                checks.append(f"ubi{c['id']}_geometry_vs_donor")

    return {"ok": True, "checks": checks, "sha256": asw["sha256"],
            "components": len(asw["components"])}


# ------------------------------------------------------------ serialize / repack --
# Writing the headers back from PARSED FIELDS, not copying bytes. Copying would make
# a round trip trivially true and prove nothing; rebuilding from the values is what
# demonstrates the parse is complete and the serializer is faithful. A Mode A rebuild
# has to write these headers, so this is the part that must be right.
#
# Padding is 0xFF, which is erased flash. Writing zeros there would produce a valid
# UBI image that differs from the donor everywhere it pads -- a "successful" rebuild
# with a byte-delta nobody could explain.

UBI_PAD_BYTE = 0xFF


def serialize_ec_hdr(ec: dict) -> bytes:
    h = bytearray(64)
    h[0:4] = UBI_EC_MAGIC
    h[4] = ec["version"]
    struct.pack_into(">Q", h, 8, ec["ec"])
    struct.pack_into(">I", h, 16, ec["vid_hdr_offset"])
    struct.pack_into(">I", h, 20, ec["data_offset"])
    struct.pack_into(">I", h, 24, ec["image_seq"])
    struct.pack_into(">I", h, 60, ubi_crc32(bytes(h[:60])))
    return bytes(h)


def serialize_vid_hdr(v: dict) -> bytes:
    h = bytearray(64)
    h[0:4] = UBI_VID_MAGIC
    h[4], h[5], h[6], h[7] = v["version"], v["vol_type"], v["copy_flag"], v["compat"]
    struct.pack_into(">I", h, 8, v["vol_id"])
    struct.pack_into(">I", h, 12, v["lnum"])
    struct.pack_into(">I", h, 20, v["data_size"])
    struct.pack_into(">I", h, 24, v["used_ebs"])
    struct.pack_into(">I", h, 28, v["data_pad"])
    struct.pack_into(">I", h, 32, v["data_crc"])
    struct.pack_into(">Q", h, 40, v["sqnum"])
    struct.pack_into(">I", h, 60, ubi_crc32(bytes(h[:60])))
    return bytes(h)


def rebuild_ubi(ubi: dict, blob: bytes) -> bytes:
    """Reassemble a UBI component from parsed headers plus each block's payload."""
    peb, vid_off, data_off = ubi["peb_size"], ubi["vid_hdr_offset"], ubi["data_offset"]
    out = bytearray()
    for b in ubi["blocks"]:
        at = b["pnum"] * peb
        block = bytearray([UBI_PAD_BYTE]) * peb
        block[0:64] = serialize_ec_hdr(b)
        if b["vid"] is not None:
            block[vid_off:vid_off + 64] = serialize_vid_hdr(b["vid"])
        block[data_off:peb] = blob[at + data_off:at + peb]
        out += block
    return bytes(out)


def rebuild_asw(data: bytes) -> bytes:
    """Reassemble the whole image from its own descriptor table.

    The header and any non-UBI component are carried verbatim -- there is nothing
    parsed about them to rebuild from yet. UBI components are rebuilt from fields.
    """
    asw = parse_asw(data)
    out = bytearray(data[:ASW_HDR_BYTES])
    for c in sorted(asw["components"], key=lambda d: d["offset"]):
        blob = data[c["offset"]:c["offset"] + c["bytes"]]
        if len(out) < c["offset"]:
            out += data[len(out):c["offset"]]        # inter-component bytes, verbatim
        if blob[:4] == UBI_EC_MAGIC:
            ubi = parse_ubi(blob, name=f"component{c['id']}")
            out += rebuild_ubi(ubi, blob)
        else:
            out += blob
    if len(out) < len(data):
        out += data[len(out):]                       # trailing bytes, verbatim
    return bytes(out)


def roundtrip(path: str | Path) -> dict:
    """Unpack and repack with ZERO semantic changes, then compare byte for byte.

    This is the gate. Until it passes on a given base, nothing may be built on that
    base -- and passing it on one base says nothing about another.
    """
    data = load(path)
    donor = characterize(path)
    verify(data, donor=donor)
    rebuilt = rebuild_asw(data)
    same = rebuilt == data
    delta = []
    if not same:
        for i in range(min(len(data), len(rebuilt))):
            if data[i] != rebuilt[i]:
                delta.append(i)
                if len(delta) >= 64:
                    break
    # A rebuilt image must still pass every check in its own right, or "identical"
    # would be the only thing ever checked.
    verify(rebuilt, donor=donor)
    return {"ok": same, "byte_identical": same,
            "input_sha256": _sha(data), "rebuilt_sha256": _sha(rebuilt),
            "input_bytes": len(data), "rebuilt_bytes": len(rebuilt),
            "first_differing_offsets": delta,
            "differing_byte_count": None if same else sum(
                1 for a, b in zip(data, rebuilt) if a != b)}


# --------------------------------------------------------------------- commands --
def load(path: str | Path) -> bytes:
    p = Path(path)
    if not p.is_file():
        raise ImageError("UNREADABLE", f"{p} is not a file")
    if p.stat().st_size > MAX_IMAGE_BYTES:
        raise ImageError("IMAGE_TOO_LARGE", f"{p} is larger than any Ascent image")
    return p.read_bytes()


def characterize(path: str | Path) -> dict:
    """Everything a rebuild of THIS donor would need, measured from it."""
    data = load(path)
    asw = parse_asw(data)
    out = {"file": Path(path).name, **asw, "ubi": {}}
    for c in asw["components"]:
        blob = data[c["offset"]:c["offset"] + c["bytes"]]
        if blob[:4] != UBI_EC_MAGIC:
            continue
        ubi = parse_ubi(blob, name=f"component{c['id']}")
        vol = ubi_volume_data(ubi, blob, 0)
        sb = ubifs_superblock(vol)
        nodes = count_ubifs_nodes(vol)
        ubi.pop("blocks")
        out["ubi"][c["id"]] = {"ubi": ubi, "ubifs": sb, "nodes": nodes,
                               "volume_bytes": len(vol), "volume_sha256": _sha(vol)}
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="ascent_g_sky_image_tool")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("inspect", help="characterize a donor image")
    p.add_argument("image")
    p.add_argument("--json", action="store_true")
    v = sub.add_parser("verify", help="fail closed on anything structurally wrong")
    v.add_argument("image")
    v.add_argument("--donor", help="compare component identity and geometry against this")
    r = sub.add_parser("roundtrip", help="repack with zero changes and compare")
    r.add_argument("image")
    r.add_argument("--out", help="write the rebuilt image here")
    a = ap.parse_args(argv)
    try:
        if a.cmd == "inspect":
            r = characterize(a.image)
            if a.json:
                print(json.dumps(r, indent=2))
            else:
                print(f"{r['file']}  {r['file_bytes']} bytes  {r['sha256']}")
                print(f"  ASW board_type={r['board_type']} version={r['version']}")
                for c in r["components"]:
                    print(f"   component {c['id']}: off=0x{c['offset']:08x} "
                          f"bytes={c['bytes']:<9} partition={c['partition_bytes']:<9} "
                          f"{c['sha256'][:16]}")
                for cid, u in r["ubi"].items():
                    ub, fs = u["ubi"], u["ubifs"]
                    print(f"   component {cid} UBI: peb={ub['peb_size']} leb={ub['leb_size']} "
                          f"pebs={ub['peb_count']} image_seq={ub['image_seq']} "
                          f"vtbl_copies={ub['vtbl_copies']}")
                    for v in ub["vtbl"]:
                        print(f"      vol {v['vol_id']} {v['name']!r} reserved_pebs="
                              f"{v['reserved_pebs']} type={v['vol_type']} align={v['alignment']}")
                    print(f"   component {cid} UBIFS: min_io={fs['min_io_size']} "
                          f"leb_size={fs['leb_size']} leb_cnt={fs['leb_cnt']} "
                          f"max_leb_cnt={fs['max_leb_cnt']} max_bud_bytes={fs['max_bud_bytes']}")
                    print(f"      fanout={fs['fanout']} fmt={fs['fmt_version']} "
                          f"compr={fs['default_compr']} SPACE_FIXUP={fs['space_fixup']}")
                    print(f"      nodes={u['nodes']['total']} bad_crc={u['nodes']['bad_crc']} "
                          f"by_type={u['nodes']['by_type']}")
        elif a.cmd == "verify":
            donor = characterize(a.donor) if a.donor else None
            res = verify(load(a.image), donor=donor)
            print(f"VERIFIED  {res['sha256']}")
            for c in res["checks"]:
                print(f"  ok  {c}")
            if donor is None:
                print("  note: no --donor given, so component identity and geometry "
                      "were not compared against anything")
        elif a.cmd == "roundtrip":
            res = roundtrip(a.image)
            if res["byte_identical"]:
                print(f"BYTE IDENTICAL  {res['rebuilt_sha256']}  {res['rebuilt_bytes']} bytes")
                print("  the ASW and UBI layers rebuild faithfully on this base.")
                print("  NOT proven: UBIFS regeneration -- LEB payloads were carried "
                      "verbatim. A Mode A rebuild is a separate gate.")
            else:
                print(f"DIFFERS  {res['differing_byte_count']} bytes", file=sys.stderr)
                print(f"  first at {res['first_differing_offsets'][:16]}", file=sys.stderr)
                return 1
            if a.out:
                Path(a.out).write_bytes(rebuild_asw(load(a.image)))
                print(f"  wrote {a.out}")
    except ImageError as e:
        print(f"REFUSED  {e}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
