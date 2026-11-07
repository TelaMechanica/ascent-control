"""Semantic inventory of a UBIFS volume, from a node sweep.

Independent of ubi_reader and of the image tool on purpose: two parsers that agree are
evidence, one parser agreeing with itself is not.

Method: sweep every node (8-byte aligned, CRC-checked), keep the highest-sqnum node per
key, then walk directory entries from the root inode. A freshly made image has no
obsolete nodes, so highest-sqnum resolution is exact for the images this gate handles;
anything that would make it inexact (a deletion dent, a truncation node, an xattr) is
refused rather than interpreted.

Compressed data blocks are inflated with zlib to hash content. NOTE: zlib resolves a
back-reference from the output of the same call, so inflating with windowBits=-11 does
NOT enforce the device's 11-bit window. That limit is enforced separately, by decoding
every stream and measuring its largest distance (deflate_distance.py, used by the gate).
"""
from __future__ import annotations

import hashlib
import struct
import zlib

UBIFS_MAGIC = b"\x31\x18\x10\x06"
INO, DATA, DENT, XENT, TRUN, PAD, SB, MST, REF, IDX, CS, ORPH = 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11
COMPR_NONE, COMPR_LZO, COMPR_ZLIB, COMPR_ZSTD = 0, 1, 2, 3
BLOCK = 4096
ROOT_INO = 1
S_IFMT, S_IFDIR, S_IFREG, S_IFLNK = 0o170000, 0o040000, 0o100000, 0o120000
S_IFCHR, S_IFBLK, S_IFIFO, S_IFSOCK = 0o020000, 0o060000, 0o010000, 0o140000


class InventoryError(RuntimeError):
    def __init__(self, code: str, msg: str):
        super().__init__(f"{code}: {msg}")
        self.code = code


def _crc(buf: bytes) -> int:
    return (~zlib.crc32(buf)) & 0xFFFFFFFF


def inflate_device(payload: bytes, out_len: int) -> bytes:
    d = zlib.decompressobj(-11)
    try:
        out = d.decompress(payload) + d.flush()
    except zlib.error as exc:
        raise InventoryError("DEFLATE_ERROR", f"stream does not inflate: {exc}")
    if len(out) != out_len:
        raise InventoryError("DATA_LEN", f"inflated {len(out)} bytes, node declares {out_len}")
    return out


def sweep(vol: bytes) -> dict:
    """Latest node per key. Returns {'ino': {inum: node}, 'dent': {(parent, hash, name): node},
    'data': {(inum, block): node}, 'counts': {...}}."""
    ino, dent, data, counts, nonfs = {}, {}, {}, {}, []
    off, n = 0, len(vol)
    while off <= n - 24:
        if vol[off:off + 4] != UBIFS_MAGIC:
            off += 8
            continue
        ln = struct.unpack_from("<I", vol, off + 16)[0]
        if not (24 <= ln <= n - off):
            off += 8
            continue
        node = vol[off:off + ln]
        if struct.unpack_from("<I", node, 4)[0] != _crc(node[8:]):
            off += 8
            continue
        ntype = node[20]
        sqnum = struct.unpack_from("<Q", node, 8)[0]
        counts[ntype] = counts.get(ntype, 0) + 1
        if ntype in (XENT, TRUN):
            raise InventoryError("UNSUPPORTED_NODE", f"node type {ntype} at {off}: refusing to interpret")
        if ntype == INO:
            inum = struct.unpack_from("<I", node, 24)[0]
            if inum == 0 or ln < 160:
                # Not a filesystem inode. Seen in both 19.2.14 volumes: a 64-byte node
                # with type 0 and an all-zero key directly after the superblock in
                # LEB 0. Recorded, never interpreted.
                nonfs.append({"off": off, "len": ln, "sqnum": sqnum})
                off += (ln + 7) & ~7
                continue
            if inum not in ino or ino[inum][0] < sqnum:
                ino[inum] = (sqnum, node)
        elif ntype == DENT:
            parent = struct.unpack_from("<I", node, 24)[0]
            target = struct.unpack_from("<Q", node, 40)[0]
            nlen = struct.unpack_from("<H", node, 50)[0]
            name = node[56:56 + nlen].decode("utf-8", "surrogateescape")
            if target == 0:
                raise InventoryError("DELETION_DENT", f"deletion entry for {name!r}: not a fresh image")
            k = (parent, name)
            if k not in dent or dent[k][0] < sqnum:
                dent[k] = (sqnum, node)
        elif ntype == DATA:
            inum = struct.unpack_from("<I", node, 24)[0]
            blk = struct.unpack_from("<I", node, 28)[0] & 0x1FFFFFFF
            k = (inum, blk)
            if k not in data or data[k][0] < sqnum:
                data[k] = (sqnum, node)
        off += (ln + 7) & ~7
    return {"ino": ino, "dent": dent, "data": data, "counts": counts, "nonfs": nonfs}


def _ino_fields(node: bytes) -> dict:
    (creat, size, atime, ctime, mtime) = struct.unpack_from("<QQQQQ", node, 40)
    (an, cn, mn, nlink, uid, gid, mode, flags, dlen, xcnt) = struct.unpack_from("<10I", node, 80)
    compr = struct.unpack_from("<H", node, 132)[0]
    return {"size": size, "atime": (atime, an), "ctime": (ctime, cn), "mtime": (mtime, mn),
            "nlink": nlink, "uid": uid, "gid": gid, "mode": mode, "flags": flags,
            "data_len": dlen, "xattr_cnt": xcnt, "compr_type": compr,
            "inline": node[160:160 + dlen], "creat_sqnum": creat}


def _file_bytes(inum: int, size: int, data: dict) -> bytes:
    out = bytearray()
    nblocks = (size + BLOCK - 1) // BLOCK
    for b in range(nblocks):
        rec = data.get((inum, b))
        if rec is None:
            out += b"\0" * min(BLOCK, size - b * BLOCK)          # hole
            continue
        node = rec[1]
        dsize = struct.unpack_from("<I", node, 40)[0]
        ctype = struct.unpack_from("<H", node, 44)[0]
        payload = node[48:]
        if ctype == COMPR_NONE:
            chunk = payload[:dsize]
        elif ctype == COMPR_ZLIB:
            chunk = inflate_device(payload, dsize)
        else:
            raise InventoryError("UNSUPPORTED_COMPR", f"inode {inum} block {b} uses compressor {ctype}")
        out += chunk
    if len(out) < size:
        out += b"\0" * (size - len(out))
    return bytes(out[:size])


def inventory(vol: bytes, *, with_content: bool = False) -> dict:
    """{path: record}. Records carry everything a filesystem rebuild must preserve."""
    s = sweep(vol)
    ino = {k: _ino_fields(v[1]) for k, v in s["ino"].items()}
    children: dict[int, list] = {}
    for (parent, name), (_, node) in s["dent"].items():
        target = struct.unpack_from("<Q", node, 40)[0]
        children.setdefault(parent, []).append((name, target, node[49]))
    if ROOT_INO not in ino:
        raise InventoryError("NO_ROOT", "root inode absent")
    out, seen_links = {}, {}
    stack = [("", ROOT_INO)]
    while stack:
        path, inum = stack.pop()
        f = ino.get(inum)
        if f is None:
            raise InventoryError("DANGLING_DENT", f"{path or '/'} -> inode {inum} has no inode node")
        if f["xattr_cnt"]:
            raise InventoryError("XATTR", f"{path or '/'} carries xattrs: not handled by this gate")
        kind = f["mode"] & S_IFMT
        rec = {"inum": inum, "mode": f["mode"], "uid": f["uid"], "gid": f["gid"],
               "nlink": f["nlink"], "size": f["size"], "mtime": f["mtime"], "atime": f["atime"],
               "ctime": f["ctime"], "flags": f["flags"]}
        if kind == S_IFREG:
            content = _file_bytes(inum, f["size"], s["data"])
            rec["sha256"] = hashlib.sha256(content).hexdigest()
            if with_content:
                rec["content"] = content
            if f["nlink"] > 1:
                seen_links.setdefault(inum, []).append(path)
        elif kind == S_IFLNK:
            rec["target"] = f["inline"].decode("utf-8", "surrogateescape")
        elif kind in (S_IFCHR, S_IFBLK):
            raw = f["inline"]
            rec["rdev"] = struct.unpack_from("<I", raw, 0)[0] if len(raw) == 4 else (
                struct.unpack_from("<Q", raw, 0)[0] if len(raw) == 8 else None)
        out[path or "/"] = rec
        if kind == S_IFDIR:
            for name, target, _t in sorted(children.get(inum, [])):
                stack.append((f"{path}/{name}", target))
    orphans = set(ino) - {r["inum"] for r in out.values()}
    if orphans:
        raise InventoryError("ORPHAN_INODES", f"inodes not reachable from root: {sorted(orphans)[:8]}")
    return {"entries": out, "node_counts": s["counts"], "hardlinks": seen_links,
            "nonfs_nodes": s["nonfs"]}


def semantic_view(inv: dict, *, times: bool = True) -> dict:
    """Comparable projection: drops inode numbers (allocation detail) and ctime
    (a rebuild cannot set it). mtime/atime are compared unless times=False."""
    view = {}
    for p, r in inv["entries"].items():
        v = {k: r[k] for k in ("mode", "uid", "gid", "nlink", "size", "flags")}
        for k in ("sha256", "target", "rdev"):
            if k in r:
                v[k] = r[k]
        if times:
            v["mtime"], v["atime"] = r["mtime"], r["atime"]
        view[p] = v
    return view
