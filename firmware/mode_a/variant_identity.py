"""Pinned camera-subtype identity correction for the normal 19.2.14 updater.

Only the command-60 GetSkyProductName call is redirected. The original selector runs
first; only its GT Pro/MAX HF/MAX WF results are qualified. Serial, version, update
acceptance, CLI and IPC are untouched. The hook uses existing zero-filled RX padding;
no new segment, rootfs/config change, relocation, or older updater replacement.
"""
from __future__ import annotations
import hashlib
import struct

DONOR_SHA = "61ddd37b5a6a074a320fd250c3a543b6267bf06999348f258ef5a28fa232cba2"
UPDATER_PATH = "/fpv/ar_fpvhs_upgrade"
HOOK_VA = 0x48710
# The exact donor call receives name/capacity in r0/r1 and board versions in r2/r3.
# Its caller owns a 32-byte hardware label at incoming SP+764; the hook saves 40 bytes.
# Changing that caller requires a new donor pin and a new call-site/bounds execution gate.
# Assembly sources: firmware/mode_a/hooks/*-identity-hook.s
# Link at 0x48710 with compare=0x1b6f8, copy=0x1b578, format=0x1b4c4.
CALL_VA = 0x1f3a4
CALL_BYTES = b')\xf0\xb4\xf9'
EXPECTED_SHA = {'z8': 'de0047bd3a2bc02fccb924cd2031d8bbfe138ccda9941f4672f047d13e4484a8', 'z40': 'be7a45d0b1673380d001e9a231cd34d276ca71f2fb168f91bfdea88bc3e7449e', 'Hub': '33eeecb038ee99358cd2661a1c8cced4170570f703d9a59341952ed7be13f6e9'}
# Reproducible project hook sources: hooks/{z8,z40,Hub}-identity-hook.s.
# tests/test_camera_identity_hooks.py reassembles and compares every payload byte.
PAYLOADS = {
    'z8': bytes.fromhex('2de9f04184b004460d4616461f46d9f705ff20461b49d2f7e8ef30b920461a492a46d2f722ef194a18e020461849d2f7dcef30b9204617492a46d2f716ef164a0ce020461549d2f7d0ef30b9204614492a46d2f70aef134a00e00ee0c9a82021c6f3031306f00f060096c7f30316019607f00f070297d2f79eee002004b0bde8f0810000b8870400c6870400d7870400f5870400068804001a8804003b8804004c88040060880400417363656e745f47545f70726f00417363656e745f47545f70726f5f7a3800417363656e742d47542d50726f2d7a382d5625642e25642d25642e256400417363656e745f47545f4d41585f484600417363656e745f47545f4d41585f48465f7a3800417363656e742d47542d4d41582d48462d7a382d5625642e25642d25642e256400417363656e745f47545f4d41585f574600417363656e745f47545f4d41585f57465f7a3800417363656e742d47542d4d41582d57462d7a382d5625642e25642d25642e2564000000bf'),
    'z40': bytes.fromhex('2de9f04184b004460d4616461f46d9f705ff20461b49d2f7e8ef30b920461a492a46d2f722ef194a18e020461849d2f7dcef30b9204617492a46d2f716ef164a0ce020461549d2f7d0ef30b9204614492a46d2f70aef134a00e00ee0c9a82021c6f3031306f00f060096c7f30316019607f00f070297d2f79eee002004b0bde8f0810000b8870400c6870400d8870400f7870400088804001d8804003f8804005088040065880400417363656e745f47545f70726f00417363656e745f47545f70726f5f7a343000417363656e742d47542d50726f2d7a34302d5625642e25642d25642e256400417363656e745f47545f4d41585f484600417363656e745f47545f4d41585f48465f7a343000417363656e742d47542d4d41582d48462d7a34302d5625642e25642d25642e256400417363656e745f47545f4d41585f574600417363656e745f47545f4d41585f57465f7a343000417363656e742d47542d4d41582d57462d7a34302d5625642e25642d25642e25640000'),
    'Hub': bytes.fromhex('2de9f04184b004460d4616461f46d9f705ff20461b49d2f7e8ef30b920461a492a46d2f722ef194a18e020461849d2f7dcef30b9204617492a46d2f716ef164a0ce020461549d2f7d0ef30b9204614492a46d2f70aef134a00e00ee0c9a82021c6f3031306f00f060096c7f30316019607f00f070297d2f79eee002004b0bde8f0810000b8870400c6870400d8870400f7870400088804001d8804003f8804005088040065880400417363656e745f47545f70726f00417363656e745f47545f70726f5f48756200417363656e742d47542d50726f2d4875622d5625642e25642d25642e256400417363656e745f47545f4d41585f484600417363656e745f47545f4d41585f48465f48756200417363656e742d47542d4d41582d48462d4875622d5625642e25642d25642e256400417363656e745f47545f4d41585f574600417363656e745f47545f4d41585f57465f48756200417363656e742d47542d4d41582d57462d4875622d5625642e25642d25642e25640000'),
}

def patch_updater(donor: bytes, subtype: str) -> bytes:
    if subtype not in PAYLOADS:
        raise ValueError("unsupported camera subtype")
    if hashlib.sha256(donor).hexdigest() != DONOR_SHA:
        raise ValueError("identity patch requires the exact normal 19.2.14 updater")
    blob = PAYLOADS[subtype]
    out = bytearray(donor)
    assert not any(out[0x38710:0x38b40])
    assert len(blob) <= 0x38b40 - 0x38710
    assert out[0xf3a4:0xf3a8] == bytes.fromhex("03f0c2f8")
    out[0xf3a4:0xf3a8] = CALL_BYTES
    out[0x38710:0x38710 + len(blob)] = blob
    # Header 3 is the original RX LOAD. Its padding remains before the RW file data.
    struct.pack_into("<II", out, 52 + 3 * 32 + 16,
                     0x38710 + len(blob), 0x38710 + len(blob))
    result = bytes(out)
    if hashlib.sha256(result).hexdigest() != EXPECTED_SHA[subtype]:
        raise ValueError("identity patch output pin mismatch")
    return result
