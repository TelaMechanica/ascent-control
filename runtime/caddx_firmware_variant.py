"""Offline identification of an Ascent Sky firmware image, and whether it is a
product variant (Z8, Z40, Hub) or a normal G_Sky build.

WHY THIS EXISTS

Four different files in this project's own corpus are named `Ascent_G_Sky_19_2_5.img`
and two of them are an 18.21.4 **Hub** donor. CLAUDE.md already forbids identifying a
base by filename or version chronology, and `device_capability.firmware_profile_gate`
has to answer "is this a Z8 build or a Z40 build?" for a GT Max HF and currently
returns `None -- unknown` because the command-60 identity cannot say. The image itself
can say. This reads it.

WHAT IT IS NOT

It is not a converter and it does not write anything. It opens a local file the
operator chose, reads it, and reports. There is no device I/O on this path at all,
which is why it needs no write qualification and cannot brick anything.

HOW A CONVERSION IS SUPPOSED TO WORK -- and an error this file used to make

A variant is built by ADDING the variant's files to a normal donor. The donor
supplies the base system; the payload supplies the camera stack. A normal donor
containing no Z camera code is therefore the NORMAL, EXPECTED, CORRECT state -- it is
the definition of a normal donor, not a fault in it.

An earlier version of `plan_variant_build` reported exactly that absence as a blocker,
which asked the donor to already be what we were trying to build. That is now an
OBSERVATION. The real blockers are stated below and neither of them is a property of
the donor's contents.

WHAT A VARIANT ACTUALLY IS -- measured, not assumed

Against authentic vendor images (17.5.8 normal / z8_2 / z40_2, and the 18.21.4 Hub_6
donor), the three products differ from a normal build like this:

    z8    normal + an IMX586 sensor implementation compiled into the application
    z40   normal + a Farsight dual-sensor implementation (IMX586 <-> PS5280)
    Hub   z8 + z40 together, PLUS an HDMI input bridge and a MIPI hub

and all three additionally carry Z camera tuning assets and, for z8/z40, a
subproduct-aware updater. `/etc/app.version` names the subproduct in `DEVICE_SUB_NAME`
for a variant and omits it for a normal build.

THE PARSER IS OURS

A reference implementation was supplied with the Z8/Z40 porting kit. It is
research-grade -- undocumented, unbounded, and it raises on anything unexpected, which
is wrong for a file the operator picked by hand. This is a separate implementation in
this project's style, bounded everywhere, and `tests/test_firmware_variant.py` proves
it agrees with the reference byte for byte on every authentic image this project holds.
"""

from __future__ import annotations

import hashlib
import struct
import zlib
from pathlib import Path

# ---------------------------------------------------------------- ASW container --
# An Ascent Sky image is an ASW container: a 0x80-byte header carrying a magic, a
# board type and a version string, then five component descriptors at 0x14, each
# twelve bytes of {id, upgrade, dual, partition, offset}.
ASW_MAGIC = b"ASW\0"
ASW_DESC_BASE = 0x14
ASW_DESC_SIZE = 12
ASW_DESC_COUNT = 5

# UBI geometry for this device family. A physical erase block is 128 KiB; the volume
# identifier header sits at 0x800 and the logical erase block data at 0x1000.
UBI_PEB = 0x20000
UBI_VID_OFF = 0x800
UBI_DATA_OFF = 0x1000
UBI_LEB = UBI_PEB - UBI_DATA_OFF
UBI_EC_MAGIC = b"UBI#"
UBI_VID_MAGIC = b"UBI!"

# UBIFS node magic, and the three node types this reader needs.
UBIFS_MAGIC = b"\x31\x18\x10\x06"
NODE_INO = 0
NODE_DATA = 1
NODE_DENT = 2
UBIFS_BLOCK = 4096

# The two components that carry a filesystem. 4 is the rootfs, 5 is /usrdata (which
# mounts as /fpv). 0 is boot, 1 is env, 2 is a kernel placeholder -- none of which
# this analysis reads.
COMPONENT_ROOTFS = 4
COMPONENT_USRDATA = 5

# A hostile or truncated file must cost bounded work. These are far above anything a
# genuine Sky image needs: the largest real component is ~8 MiB of UBI.
MAX_IMAGE_BYTES = 256 * 1024 * 1024
MAX_FILES = 4000
MAX_FILE_BYTES = 64 * 1024 * 1024


class FirmwareVariantError(RuntimeError):
    """A named, reportable reason the image could not be analysed.

    Carries a stable `code` so the UI can say something specific rather than
    surfacing a parser exception at the operator.
    """

    def __init__(self, code: str, message: str, detail: dict | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.detail = detail or {}

    def as_dict(self) -> dict:
        return {"ok": False, "error": self.code, "message": self.message,
                **({"detail": self.detail} if self.detail else {})}


# ------------------------------------------------------------------- container --

def _u32le(buf: bytes, off: int) -> int:
    return struct.unpack_from("<I", buf, off)[0]


def _u32be(buf: bytes, off: int) -> int:
    return struct.unpack_from(">I", buf, off)[0]


def asw_header(data: bytes) -> dict:
    """Magic, board type and version from the ASW header.

    The version is NOT a string. It is three little-endian u32s at 0x08, 0x0C and
    0x10 -- `11 00 00 00 05 00 00 00 08 00 00 00` is 17.5.8. Reading it as ASCII
    yields an empty field, which looks like a parser failure rather than what it is.

    This is reported ALONGSIDE `/etc/app.version`, not instead of it, because the
    two can legitimately disagree: a project image built on a vendor donor keeps the
    donor's internal version while the filename and the project label say something
    else. Seeing both is how that is spotted.
    """
    if len(data) < 0x80:
        raise FirmwareVariantError("NOT_AN_IMAGE",
                                   "the file is too small to be an ASW firmware image")
    if data[:4] != ASW_MAGIC:
        raise FirmwareVariantError(
            "NOT_ASW",
            "this is not an ASW container. Sky, Relay and Ground images are ASW; "
            "receiver images are RKFW and are not read by this analysis.",
            {"first_four_bytes": data[:4].hex()})
    major, minor, patch = (_u32le(data, 0x08), _u32le(data, 0x0C), _u32le(data, 0x10))
    return {"magic": "ASW", "board_type": data[4],
            "header_version": f"{major}.{minor}.{patch}"}


def components(data: bytes) -> dict[int, bytes]:
    """Split the container into its five components by descriptor offset.

    Each component runs from its own offset to the next descriptor's offset, and the
    last to the end of the file -- the descriptors carry no length. Offsets are
    therefore sorted before slicing, and an offset outside the file is refused rather
    than producing a silently empty component.
    """
    descs = []
    for i in range(ASW_DESC_COUNT):
        off = ASW_DESC_BASE + i * ASW_DESC_SIZE
        if off + ASW_DESC_SIZE > len(data):
            raise FirmwareVariantError("HEADER_TRUNCATED",
                                       "the component descriptor table is incomplete")
        descs.append({"id": data[off], "offset": _u32le(data, off + 8)})
    for d in descs:
        if not (0 < d["offset"] <= len(data)):
            raise FirmwareVariantError(
                "COMPONENT_OUT_OF_RANGE",
                "a component descriptor points outside the file",
                {"id": d["id"], "offset": d["offset"], "file_bytes": len(data)})
    ordered = sorted(descs, key=lambda d: d["offset"])
    out: dict[int, bytes] = {}
    for i, d in enumerate(ordered):
        end = ordered[i + 1]["offset"] if i + 1 < len(ordered) else len(data)
        out[d["id"]] = data[d["offset"]:end]
    return out


# ------------------------------------------------------------------------- UBI --

def ubi_volume0(blob: bytes) -> bytes:
    """Concatenate volume 0's logical erase blocks, in logical order.

    UBI stores logical blocks in whatever physical block was free, so the physical
    order on disk is not the logical order of the filesystem. Reassembling by `lnum`
    is the whole job. A gap is filled with zeroes rather than skipped: shifting every
    later block down would corrupt the filesystem silently, and a zero-filled gap
    fails a node CRC loudly.
    """
    if not blob or len(blob) % UBI_PEB:
        raise FirmwareVariantError(
            "UBI_NOT_BLOCK_ALIGNED",
            "the component is not a whole number of 128 KiB erase blocks",
            {"bytes": len(blob)})
    lebs: dict[int, bytes] = {}
    for i in range(len(blob) // UBI_PEB):
        peb = blob[i * UBI_PEB:(i + 1) * UBI_PEB]
        if peb[:4] != UBI_EC_MAGIC:
            raise FirmwareVariantError("UBI_BAD_EC_HEADER",
                                       f"erase block {i} has no UBI# header")
        if peb[UBI_VID_OFF:UBI_VID_OFF + 4] != UBI_VID_MAGIC:
            # A block with no volume header is an unmapped spare, which is normal.
            continue
        if _u32be(peb, UBI_VID_OFF + 8) != 0:
            continue
        lebs[_u32be(peb, UBI_VID_OFF + 12)] = peb[UBI_DATA_OFF:]
    if not lebs:
        raise FirmwareVariantError("UBI_NO_VOLUME",
                                   "the component carries no UBI volume 0")
    return b"".join(lebs.get(i, b"\0" * UBI_LEB) for i in range(max(lebs) + 1))


# ----------------------------------------------------------------------- UBIFS --

def _node_crc_ok(node: bytes) -> bool:
    """UBIFS CRC-32 covers everything after the 8-byte magic+crc prefix."""
    return _u32le(node, 4) == ((~zlib.crc32(node[8:])) & 0xFFFFFFFF)


def _scan_nodes(vol: bytes) -> tuple[dict, dict, dict]:
    """Collect the newest directory entry, data and inode nodes.

    This is a journal, not a tree walk: the same path or block can appear many times
    and the highest sequence number is the live one. CRC-failing nodes are dropped --
    they are the erased remains of earlier writes, and treating one as current is how
    a reader invents a file that is not there.
    """
    dents: dict[tuple[int, str], tuple] = {}
    datas: dict[tuple[int, int], tuple] = {}
    inos: dict[int, tuple] = {}
    limit = len(vol) - 24
    off = 0
    while off < limit:
        if vol[off:off + 4] != UBIFS_MAGIC:
            off += 8
            continue
        length = _u32le(vol, off + 16)
        if not (24 <= length <= UBI_LEB and off + length <= len(vol)):
            off += 8
            continue
        node = vol[off:off + length]
        if not _node_crc_ok(node):
            off += 8
            continue
        seq = struct.unpack_from("<Q", vol, off + 8)[0]
        ntype = vol[off + 20]
        if ntype == NODE_DENT and length >= 57:
            parent = _u32le(vol, off + 24)
            inum = struct.unpack_from("<Q", vol, off + 40)[0]
            nlen = struct.unpack_from("<H", vol, off + 50)[0]
            if 0 < nlen <= 255 and 56 + nlen <= length:
                name = vol[off + 56:off + 56 + nlen].decode("utf-8", "surrogateescape")
                key = (parent, name)
                if key not in dents or seq > dents[key][0]:
                    dents[key] = (seq, inum)
        elif ntype == NODE_DATA and length >= 48:
            inum = _u32le(vol, off + 24)
            block = _u32le(vol, off + 28) & 0x1FFFFFFF
            usize = _u32le(vol, off + 40)
            ctype = struct.unpack_from("<H", vol, off + 44)[0]
            key = (inum, block)
            if key not in datas or seq > datas[key][0]:
                datas[key] = (seq, usize, ctype, off, length)
        elif ntype == NODE_INO and length >= 108:
            inum = _u32le(vol, off + 24)
            if inum not in inos or seq > inos[inum][0]:
                inos[inum] = (seq, off)
        off += 8
    return dents, datas, inos


def _paths(dents: dict) -> dict[int, str]:
    """Walk the directory entries into absolute paths, inode 1 being the root.

    Cycle-safe by construction: an inode is given a path once and never revisited, so
    a corrupt image that points a directory at its own ancestor terminates instead of
    looping.
    """
    children: dict[int, list] = {}
    for (parent, name), (_seq, inum) in dents.items():
        children.setdefault(parent, []).append((name, inum))
    paths = {1: "/"}
    stack = [1]
    while stack:
        parent = stack.pop()
        base = paths[parent]
        for name, inum in children.get(parent, []):
            if inum in paths:
                continue
            paths[inum] = ("/" + name) if base == "/" else base.rstrip("/") + "/" + name
            stack.append(inum)
            if len(paths) > MAX_FILES:
                raise FirmwareVariantError("TOO_MANY_FILES",
                                           "the image declares more files than a Sky "
                                           "image ever has; refusing to continue")
    return paths


def regular_files(vol: bytes, *, want: set[str] | None = None) -> dict[str, bytes]:
    """Extract regular files from a UBIFS volume.

    `want` limits decompression to the paths actually needed. That matters: this runs
    on an operator's machine while they wait, and inflating an entire 8 MiB usrdata to
    read `/etc/app.version` and one binary is work nobody asked for.
    """
    dents, datas, inos = _scan_nodes(vol)
    paths = _paths(dents)
    by_inode: dict[int, list] = {}
    for (inum, block), rec in datas.items():
        by_inode.setdefault(inum, []).append((block, rec))

    out: dict[str, bytes] = {}
    for inum, path in paths.items():
        if inum not in inos:
            continue
        if want is not None and path not in want:
            continue
        mode = _u32le(vol, inos[inum][1] + 104)
        if mode & 0o170000 != 0o100000:          # regular files only
            continue
        blocks = []
        for block, (_seq, usize, ctype, off, length) in by_inode.get(inum, []):
            raw = vol[off + 48:off + length]
            if ctype == 2:
                try:
                    dec = zlib.decompress(raw, -15)
                except zlib.error:
                    # One unreadable block makes the whole file untrustworthy. Drop
                    # the file rather than return a hole as though it were content.
                    blocks = None
                    break
            elif ctype == 0:
                dec = raw[:usize]
            else:
                blocks = None
                break
            if len(dec) != usize:
                blocks = None
                break
            blocks.append((block, dec))
        if blocks is None:
            continue
        if not blocks:
            out[path] = b""
            continue
        buf = bytearray()
        for block, dec in sorted(blocks):
            if len(buf) < block * UBIFS_BLOCK:
                buf.extend(b"\0" * (block * UBIFS_BLOCK - len(buf)))
            buf.extend(dec)
            if len(buf) > MAX_FILE_BYTES:
                raise FirmwareVariantError("FILE_TOO_LARGE",
                                           f"{path} exceeds the size any Sky file has")
        out[path] = bytes(buf)
    return out


# --------------------------------------------------------------- variant model --
# Markers measured against authentic vendor images on 2026-10-04. Each is a byte
# string that appears in the Sky application when a sensor path is compiled in, and
# is wholly absent when it is not -- normal 17.5.8, 19.2.5 and 19.2.14 all score zero
# on the Z markers, while z8_2, z40_2 and Hub_6 do not.
APP_PATH = "/fpv/ar_ldyhs_sky"
UPDATER_PATH = "/fpv/ar_fpvhs_upgrade"
APP_VERSION_PATH = "/etc/app.version"

SENSOR_MARKERS = {
    "imx586": b"imx586_init",
    "farsight": b"farsight_init",
    "ps5280": b"ps5280",
    "os02h10": b"os02h10",
}
# The Hub is a wider product, not a bigger Z: an HDMI-to-MIPI bridge and a MIPI hub
# multiplexer, neither of which a standalone Z8 or Z40 carries.
HUB_PATHS = (
    "/fpv/boot_lt6911uxe/lt6911uxe_upgrade",
    "/fpv/fpv_mipihub_ctrl.sh",
    "/fpv/mipi_hub.json",
)
Z_TUNING_PATHS = (
    "/fpv/tunning/cam_imx586_50fps_z8_xg1.bin",
    "/fpv/tunning/cam_imx586_50fps_z8_xg2.bin",
    "/fpv/tunning/cam_imx586_50fps_z8_xg4.bin",
    "/fpv/tunning/cam_imx586_50fps_z40_xg1.bin",
    "/fpv/tunning/cam_imx586_50fps_z40_xg2.bin",
    "/fpv/tunning/cam_imx586_50fps_z40_xg4.bin",
    "/fpv/tunning/cam_ps5280_50fps_z40.bin",
)
UPDATER_VARIANT_MARKERS = (b"DEVICE_SUB_NAME", b"AR_FPV_UPGRADE_DeviceInfoWithSubName")


def parse_app_version(blob: bytes) -> dict:
    """`/etc/app.version` is `KEY=VALUE` lines. Unknown keys are kept, not dropped --
    a newer image may carry fields this build has never seen and hiding them would
    make the panel lie by omission."""
    out: dict[str, str] = {}
    for line in blob.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if not line or "=" not in line:
            continue
        key, _, value = line.partition("=")
        out[key.strip()] = value.strip()
    return out


def classify(app_version: dict, sensors: dict, hub: dict, tuning: int,
             updater_variant_aware: bool) -> dict:
    """Name the product this image is, and say how confident that is.

    Fail-closed: the declared subproduct and the compiled evidence must agree. If
    `/etc/app.version` says one thing and the application binary says another, this
    reports INCONSISTENT rather than believing either -- an image that is not what it
    says it is, is exactly the thing worth refusing to summarise.
    """
    declared = (app_version.get("DEVICE_SUB_NAME") or "").strip()
    declared_l = declared.lower()
    has_imx = sensors.get("imx586", 0) > 0
    has_far = sensors.get("farsight", 0) > 0
    has_hub = hub["present"] == len(HUB_PATHS)

    # z40 is NOT z8 plus something. The authentic 17.5.8 z40 image reaches the
    # IMX586 only through `farsight_imx586_*` wrappers and contains no bare
    # `imx586_init` at all -- it scores farsight=2, imx586=0. So Farsight alone is
    # the z40 signature and IMX586 alone is the z8 one.
    #
    # Both markers together occur in exactly one authentic image, the Hub, which is
    # caught above by its own components. A build carrying both WITHOUT the Hub
    # hardware is a configuration no vendor image in this project has ever shown, so
    # it is refused below rather than guessed at -- preferring either product there
    # would be this tool inventing a variant.
    if has_hub:
        evident = "hub"
    elif has_far and has_imx:
        evident = "both-without-hub"
    elif has_far:
        evident = "z40"
    elif has_imx:
        evident = "z8"
    else:
        evident = "normal"

    if evident == "both-without-hub":
        return {"product": "inconsistent", "declared": declared or None,
                "evident": evident, "confidence": "none",
                "note": ("this image carries both the IMX586 and the Farsight camera "
                         "stacks but none of the Hub components. No authentic vendor "
                         "image has that shape, so no product is claimed for it.")}

    # A partial Hub payload is not a Hub and not a Z. Say so rather than rounding it
    # to whichever product it most resembles.
    if 0 < hub["present"] < len(HUB_PATHS):
        return {"product": "inconsistent", "declared": declared or None,
                "evident": evident, "confidence": "none",
                "note": (f"only {hub['present']} of {len(HUB_PATHS)} Hub components are "
                         f"present. A partial Hub payload is not a product; nothing is "
                         f"inferred from it.")}

    if declared_l and evident != "unknown" and declared_l != evident:
        # The Hub declares DEVICE_SUB_NAME=Hub and also carries both Z stacks, which
        # is agreement, not conflict. Everything else must match.
        return {"product": "inconsistent", "declared": declared, "evident": evident,
                "confidence": "none",
                "note": (f"/etc/app.version declares {declared!r} but the application "
                         f"binary looks like {evident!r}. This image is not what it "
                         f"says it is; nothing further is inferred from it.")}

    product = evident
    if product == "normal":
        # DO NOT restate the old inversion here. A normal build lacking the camera
        # code is the DEFINITION of a normal build, not a reason it cannot become a
        # variant. A conversion ADDS that code. What makes it hard is stated where
        # it belongs -- plan_variant_build() -- and is about our tooling, not about
        # this file's contents.
        note = ("A normal G_Sky build: no IMX586 or Farsight camera code and no Z "
                "tuning assets. That is the expected shape for a normal image, and "
                "it is the correct starting point for a conversion \u2014 a variant "
                "is this plus an added camera stack. What it would take is reported "
                "separately.")
    elif product == "hub":
        note = ("A Hub build: both Z camera stacks plus an HDMI input bridge and a "
                "MIPI hub. The Hub is a separate product, not a superset you can "
                "reduce to a standalone Z8 or Z40.")
    elif product in ("z8", "z40"):
        note = (f"A standalone {product.upper()} build: the camera code is compiled in "
                f"and the Z tuning assets are present.")
    else:
        note = ("The sensor evidence does not match any product this build knows. "
                "Nothing is inferred.")

    confidence = "declared+evident" if declared_l else "evident-only"
    return {"product": product, "declared": declared or None, "evident": evident,
            "confidence": confidence, "note": note,
            "z_tuning_assets": f"{tuning}/{len(Z_TUNING_PATHS)}",
            "updater_variant_aware": updater_variant_aware}


def analyse(path: str | Path) -> dict:
    """Identify a local firmware image. Reads only; writes nothing, contacts nothing."""
    p = Path(path)
    try:
        size = p.stat().st_size
    except OSError as exc:
        raise FirmwareVariantError("UNREADABLE", f"the file could not be read: {exc}")
    if size > MAX_IMAGE_BYTES:
        raise FirmwareVariantError("IMAGE_TOO_LARGE",
                                   "the file is larger than any Ascent image",
                                   {"bytes": size})
    data = p.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    header = asw_header(data)
    comps = components(data)

    wanted_usrdata = {APP_PATH, UPDATER_PATH, *HUB_PATHS, *Z_TUNING_PATHS}
    rootfs = regular_files(ubi_volume0(comps[COMPONENT_ROOTFS]),
                           want={APP_VERSION_PATH}) if COMPONENT_ROOTFS in comps else {}
    usrdata = regular_files(ubi_volume0(comps[COMPONENT_USRDATA]),
                            want=wanted_usrdata) if COMPONENT_USRDATA in comps else {}

    app_version = parse_app_version(rootfs.get(APP_VERSION_PATH, b""))
    app = usrdata.get(APP_PATH, b"")
    updater = usrdata.get(UPDATER_PATH, b"")
    sensors = {name: app.count(marker) for name, marker in SENSOR_MARKERS.items()}
    hub_present = [q for q in HUB_PATHS if q in usrdata]
    tuning = sum(1 for q in Z_TUNING_PATHS if q in usrdata)
    updater_aware = all(m in updater for m in UPDATER_VARIANT_MARKERS) if updater else False

    hub = {"present": len(hub_present), "of": len(HUB_PATHS), "paths": hub_present}
    verdict = classify(app_version, sensors, hub, tuning, updater_aware)

    return {
        "ok": True,
        "file": p.name,
        "bytes": size,
        "sha256": digest,
        "container": header,
        "app_version": app_version,
        "sensors": sensors,
        "hub": hub,
        "verdict": verdict,
        "note": ("Read from the image itself. Filename and version string are not "
                 "evidence: four files in this project's corpus share the name "
                 "Ascent_G_Sky_19_2_5.img and two of them are an 18.21.4 Hub donor."),
    }


# ---------------------------------------------------------- variant build plan --
# What turning a donor into a product variant would actually take, reported from the
# donor itself rather than from a wish. Measured against authentic vendor images on
# 2026-10-04: the whole delta is 31 files for z8/z40 and 37 for Hub -- /etc/app.version
# plus a set under /fpv -- of which the load-bearing one is the application binary.
VARIANT_PAYLOAD = {
    "z8":  {"files": 31, "app_markers": ("imx586",),
            "adds": "an IMX586 sensor implementation compiled into ar_ldyhs_sky"},
    "z40": {"files": 31, "app_markers": ("farsight",),
            "adds": "a Farsight dual-sensor implementation (IMX586 <-> PS5280)"},
    "hub": {"files": 37, "app_markers": ("imx586", "farsight"),
            "adds": ("both Z camera stacks, plus an HDMI input bridge (LT6911UXE) "
                     "and a four-input MIPI hub")},
}

# (product, version) pairs this project actually holds an authentic payload for.
#
# A payload cannot be SYNTHESISED -- the sensor driver is machine code compiled into
# the vendor's application, so it has to come from an authentic image that already has
# it. That is a statement about where the payload comes FROM. It is NOT a statement
# that the donor must already contain it: the donor is a normal image and the payload
# is added to it.
HELD_PAYLOADS = (("z8", "17.5.8"), ("z40", "17.5.8"), ("hub", "18.21.4"))


def packer_capability(donor: str | Path | None = None) -> dict:
    """What the image packer can actually do, MEASURED rather than asserted.

    Every field here is derived at call time -- the two structural ones by asking the
    tool what functions it has, and the evidence one by actually running a round trip
    on the donor in front of us. Nothing is a hardcoded sentence that can go stale
    while the code moves underneath it, which is precisely what happened to the first
    version of this panel: it was still saying "the round-trip proof is for 19.2.4
    only" after the packer had been proven byte-identical on five bases including
    19.2.14.

    The distinction that matters, and the one the panel kept blurring:

      can_rebuild_container   take an image apart and put it back -- ASW descriptors,
                              UBI erase blocks, headers and CRCs. PROVEN byte-identical.
      can_regenerate_filesystem   build a UBIFS volume from a directory tree. This is
                              what ADDING A FILE requires, and it does not exist.

    A byte-identical round trip is strong evidence for the first and NO evidence for
    the second, because the round trip carries LEB payloads through verbatim -- it
    never looks inside the filesystem at all.
    """
    import importlib.util
    import sys

    # Use the same staged verifier as the installed Mode A execution path.
    # The development-only firmware/ tree is deliberately absent from the MSI.
    import firmware_builder
    tool_path = Path(firmware_builder.default_builder_dir()) / "ascent_g_sky_image_tool.py"
    cap = {
        "tool_present": tool_path.is_file(),
        "can_rebuild_container": False,
        "can_regenerate_filesystem": False,
        "can_write_modified_image": False,
        "donor_round_trips_byte_identical": None,
        "round_trip_error": None,
    }
    if not cap["tool_present"]:
        return cap

    spec = importlib.util.spec_from_file_location("_ascent_image_tool", tool_path)
    tool = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("_ascent_image_tool", tool)
    spec.loader.exec_module(tool)

    # Structural capability, by introspection. When someone lands a Mode A builder
    # these flip on their own; nobody has to remember to edit a string here.
    cap["can_rebuild_container"] = all(
        hasattr(tool, n) for n in ("rebuild_asw", "rebuild_ubi", "roundtrip"))
    # FILESYSTEM REGENERATION NOW HAS A SECOND, REAL SOURCE.
    #
    # The introspection below was written against this one tool, and for that
    # tool the answer is still no -- it carries LEB payloads through verbatim
    # and never looks inside a filesystem. What changed is that the Mode A
    # builder landed beside it: it regenerates both UBIFS volumes with
    # mkfs.ubifs under fakeroot, which is exactly the capability this flag
    # names.
    #
    # MEASURED, NOT DECLARED, and the standard is deliberately "can it run
    # HERE" rather than "does the file exist". mkfs.ubifs and fakeroot are
    # Linux-only, so on a machine without them the builder is present and
    # unusable, and reporting that as a capability would unblock a button that
    # cannot work. firmware_builder.preflight() answers the runnable question
    # and names what is missing when the answer is no.
    cap["can_regenerate_filesystem"] = any(
        hasattr(tool, n) for n in ("build_ubifs", "mkfs_ubifs", "rebuild_ubifs",
                                   "write_ubifs_volume"))
    cap["mode_a_builder"] = None
    if not cap["can_regenerate_filesystem"]:
        try:
            import firmware_builder
            pre = firmware_builder.preflight()
            cap["mode_a_builder"] = {
                "can_build": bool(pre.get("can_build")),
                "blockers": pre.get("blockers") or [],
                "mkfs_version": pre.get("mkfs_version"),
            }
            cap["can_regenerate_filesystem"] = bool(pre.get("can_build"))
        except Exception as exc:                      # measured; fails closed
            cap["mode_a_builder"] = {"can_build": False,
                                     "error": f"{type(exc).__name__}: {exc}"}
    cap["can_write_modified_image"] = any(
        hasattr(tool, n) for n in ("patch", "write_image", "apply_patch"))

    # Evidence for THIS donor, measured now. A round-trip proof is per-base and does
    # not transfer, so the honest thing to show an operator is the result for the file
    # they actually selected -- not a list of bases somebody else proved.
    if donor is not None:
        try:
            cap["donor_round_trips_byte_identical"] = bool(
                tool.roundtrip(donor).get("byte_identical"))
        except Exception as exc:                      # a donor we cannot parse
            cap["round_trip_error"] = f"{type(exc).__name__}: {exc}"

    return cap


def plan_variant_build(donor: str | Path, target: str) -> dict:
    """What it would take to make `target` from `donor`, and what stops it.

    Read-only and ungated on purpose: knowing whether something is possible should
    never require accepting the risk of doing it.

    THE MODEL. A variant is a normal donor PLUS an added variant payload. The donor
    supplies the base system and the payload supplies the camera stack. So a normal
    donor contains no Z camera code, and that is correct -- it is what "normal donor"
    means. This function reports that as an observation.

    There are exactly TWO blockers and they are INDEPENDENT. Clearing one does not
    clear the other, and the panel must not merge them into a single "cannot build":

      1. FILESYSTEM BUILDER. Adding a file means regenerating a UBIFS volume. The
         proven packer rewrites existing nodes in place at unchanged length; it cannot
         add one. A donor-geometry rebuild (Mode A) has not been built or gated.

      2. PAYLOAD. An authentic variant payload is needed at a version that matches the
         donor. Payloads cannot be synthesised -- the sensor driver is compiled machine
         code -- so one has to come from an authentic image of that product.
    """
    target = str(target or "").strip().lower()
    # A camera being researched is selectable for planning, but never classified
    # as an existing firmware product or admitted to the Z8/Z40 transplant path.
    import firmware_builder
    if target == 'hdpro':
        report = analyse(donor)
        import hashlib
        exact = hashlib.sha256(Path(donor).read_bytes()).hexdigest() == 'f166927ff1e0090666236f6003bdd306961304e7dec606d347a63d3894fbd7d0'
        blockers = [] if exact else [{'id':'DONOR_HASH_MISMATCH', 'what':'HD Pro requires the exact normal 19.2.14 donor.'}]
        try:
            firmware_builder.inspect_hdpro_assets()
        except (OSError, ValueError, KeyError, firmware_builder.BuilderError) as exc:
            blockers.append({'id':'HDPRO_ASSET_INVALID', 'what':str(exc)})
        return {'target':'hdpro', 'target_label':'HD Pro (legacy Walksnail)', 'donor':str(donor),
                'donor_product':report['verdict']['product'], 'donor_version':report['app_version'].get('APP_VERSION',''),
                'buildable':not blockers, 'outcome':'BUILDABLE' if not blockers else 'BLOCKED', 'blockers':blockers,
                'payload_files':1, 'payload_adds':'the HD Pro camera profile', 'authentic_payloads_held':[],
                'observations':[], 'notes':['Available for tester builds. Physical camera operation and image quality are not yet qualified.'],
                'cautions':[], 'packer':{}, 'hardware_qualified':False, 'verdict':report['verdict']}
    port = firmware_builder.camera_port_blocker(target)
    if port:
        report = analyse(donor)
        blockers = [port]
        if report["verdict"]["product"] != "normal":
            blockers.append({"id": "DONOR_NOT_NORMAL",
                             "what": "HD Pro planning requires a normal G_Sky base image.",
                             "clears_when": "a normal G_Sky donor is selected"})
        return {"target": target, "target_label": port["label"], "donor": str(donor),
                "donor_product": report["verdict"]["product"],
                "donor_version": report["app_version"].get("APP_VERSION", ""),
                "payload_files": None,
                "payload_adds": "a legacy HD Pro camera implementation for Ascent",
                "authentic_payloads_held": [], "packer": {},
                "outcome": "CAMERA_DRIVER_PORT_REQUIRED", "buildable": False,
                "blockers": blockers, "cautions": [], "observations": [],
                "notes": ["An experimental CV610 port and isolated image passed offline checks; neither is an admitted AC build payload."],
                "route": "The existing image builder was reused for offline experiments. Camera profile qualification and packaged pipeline admission remain pending.",
                "camera_port": port, "verdict": report["verdict"]}
    if target not in VARIANT_PAYLOAD:
        raise FirmwareVariantError("TARGET_UNKNOWN",
                                   f"{target!r} is not a product this builds",
                                   {"known": sorted(VARIANT_PAYLOAD)})
    report = analyse(donor)
    spec = VARIANT_PAYLOAD[target]
    donor_version = report["app_version"].get("APP_VERSION", "")
    donor_product = report["verdict"]["product"]
    cap = packer_capability(donor)

    blockers, observations, notes = [], [], []

    # ---- the donor's own suitability ------------------------------------------
    if donor_product == target:
        notes.append(f"this donor is already a {target.upper()} image, so there is "
                     f"nothing to add")
    elif donor_product != "normal":
        blockers.append({
            "id": "DONOR_NOT_NORMAL",
            "what": f"the donor is a {donor_product.upper()} build, not a normal "
                    f"G_Sky image",
            "why": "a conversion adds a variant payload to a normal base; starting "
                   "from another variant would stack two camera stacks that were "
                   "never built to coexist",
            "clears_when": "a normal G_Sky donor is selected",
        })

    # ---- the donor's missing variant code is EXPECTED, not a fault -------------
    missing = [m for m in spec["app_markers"] if report["sensors"].get(m, 0) == 0]
    if missing:
        observations.append(
            f"the donor's application contains no {' or '.join(missing)} code. That "
            f"is expected and correct \u2014 it is a normal image, and {spec['adds']} is "
            f"part of what a conversion would ADD to it.")
    elif donor_product != target:
        # Only surprising if we thought this was a clean base. If the donor IS the
        # target the code being present is simply what that product is.
        notes.append(
            f"the donor already contains {' and '.join(spec['app_markers'])} code, "
            f"which is unusual for a {donor_product} image and worth understanding "
            f"before treating this file as a clean base")

    # ---- blocker 1: the filesystem builder ------------------------------------
    # Skipped when the donor already IS the target: there is nothing to add, so the
    # thing we cannot do is not on the path. Reporting it anyway would be a blocker
    # against an operation nobody is performing.
    if donor_product != target and not cap["can_regenerate_filesystem"]:
        rt = cap["donor_round_trips_byte_identical"]
        evidence = ("This donor was taken apart and rebuilt byte for byte just now, "
                    "so the container layers are sound for this exact base."
                    if rt else
                    "This donor did not rebuild byte for byte, so even the container "
                    "layers are unproven for this base."
                    if rt is False else
                    "The round trip could not be run on this donor.")
        # A FILESYSTEM BUILDER NOW EXISTS, so this blocker had to stop saying
        # that nothing can add a file. firmware/mode_a regenerates both UBIFS
        # volumes with mkfs.ubifs under fakeroot, and gate 1 reproduces the
        # donor's own volume before gate 2 is allowed to produce a new one --
        # which is word for word what the old "clears_when" asked for.
        #
        # What can still block it is the TOOLCHAIN, because mkfs.ubifs and
        # fakeroot are Linux-only and may simply not be installed. That is a
        # different sentence with a different remedy, and printing the old one
        # sent somebody looking for work that was already done.
        mode_a = cap.get("mode_a_builder") or {}
        missing = [b.get("name") for b in (mode_a.get("blockers") or [])]
        fixes = [b.get("fix") for b in (mode_a.get("blockers") or []) if b.get("fix")]
        blockers.append({
            "id": "FILESYSTEM_TOOLCHAIN" if missing else "FILESYSTEM_BUILDER",
            "what": (f"building a {target.upper()} adds {spec['files']} files, and the "
                     f"filesystem builder cannot run on this computer: "
                     + ", ".join(m for m in missing if m) + " missing")
                    if missing else
                    (f"building a {target.upper()} adds {spec['files']} files, "
                     f"and the filesystem builder is not available"),
            "why": ("the builder regenerates the image's filesystems with mkfs.ubifs "
                    "under fakeroot. Both are Linux-only, so on Windows they run "
                    "through WSL and have to be installed there. " + evidence)
                   if missing else
                   ("the proven packer rewrites existing filesystem nodes in place at "
                    "unchanged length; adding a file needs the filesystem regenerated. "
                    + evidence),
            "clears_when": ("; ".join(fixes) if fixes else
                            "the Mode A filesystem builder is available"),
        })

    # ---- blocker 2: the payload ------------------------------------------------
    held = [v for pr, v in HELD_PAYLOADS if pr == target]
    if donor_product != target:
        if not held:
            blockers.append({
                "id": "PAYLOAD_NOT_HELD",
                "what": f"this project holds no authentic {target.upper()} payload at "
                        f"any version",
                "why": "the camera stack is compiled machine code and cannot be "
                       "written from scratch; it has to come from an authentic "
                       f"{target.upper()} image",
                "clears_when": f"an authentic {target.upper()} image is obtained, "
                               f"ideally at the donor's version",
            })
        elif donor_version not in held:
            blockers.append({
                "id": "PAYLOAD_VERSION_MISMATCH",
                "what": f"the only authentic {target.upper()} payload held here is "
                        f"{held[0]}, and this donor is "
                        f"{donor_version or 'an unknown version'}",
                # NOT "obtain a payload at the donor's version" any more. Closing
                # that gap is precisely what the Mode A transplant does: it
                # forward-ports the authentic application onto the newer base,
                # relocating it and verifying every carried reference. Z40
                # Candidate1 was produced exactly this way -- 17.5.8 payload,
                # 19.2.14 donor -- and passed gate 2
                # (docs/evidence/mode_a/gate2_report_z40_candidate1.json).
                #
                # So this is reported as a CAUTION and no longer as a blocker: it
                # is real that a cross-version result is less checkable, and it is
                # false that it cannot be built.
                "severity": "caution",
                "why": "a payload and the base it runs on share kernel interfaces "
                       "and library versions. The Mode A transplant forward-ports "
                       "the application across that gap and verifies every carried "
                       "reference, which is how the existing Z40 candidate was "
                       "built; what it cannot do is prove the camera starts. That "
                       "is a bench question.",
                "clears_when": "a bench run confirms the camera on the built image",
            })
        else:
            notes.append(f"an authentic {target.upper()} payload at this donor's "
                         f"version ({donor_version}) IS held \u2014 the version side of "
                         f"this is clear")

    # A CAUTION IS NOT A BLOCKER. Separated here rather than at each append so
    # there is one place that decides what stops a build, and the panel cannot
    # drift from it.
    cautions = [b for b in blockers if b.get("severity") == "caution"]
    blockers = [b for b in blockers if b.get("severity") != "caution"]

    # ---- what the lowest-risk route would be ----------------------------------
    # Deliberately NOT "the only method that is theoretically possible". A
    # cross-version transplant is possible; it is just not checkable here, which is a
    # statement about our evidence and not about physics.
    route = (f"Lowest-risk route: a donor and an authentic {target.upper()} payload at "
             f"the SAME version, so the two agree on everything they share. A version "
             f"gap is what the Mode A transplant exists to close \u2014 it forward-ports "
             f"the application and verifies every carried reference, which is how the "
             f"existing Z40 candidate was built from a 17.5.8 payload on a 19.2.14 "
             f"donor. What no build can establish is that the camera starts; that is "
             f"a bench question and it stays one.")

    # "nothing to do" is not "yes you can do it". An operator who selected a Hub
    # donor and asked for a Hub must be told the file they already have IS the answer,
    # not handed a green light for a conversion that would do nothing.
    if donor_product == target:
        outcome = "ALREADY_THIS_PRODUCT"
    elif blockers:
        outcome = "BLOCKED"
    else:
        outcome = "BUILDABLE"

    return {"ok": True, "target": target, "donor": report["file"],
            "donor_product": donor_product, "donor_version": donor_version,
            "payload_files": spec["files"], "payload_adds": spec["adds"],
            "authentic_payloads_held": [f"{pr}@{v}" for pr, v in HELD_PAYLOADS],
            "packer": cap,
            "outcome": outcome,
            "buildable": outcome == "BUILDABLE",
            "blockers": blockers, "cautions": cautions,
            "observations": observations, "notes": notes,
            "route": route,
            "verdict": report["verdict"]}
