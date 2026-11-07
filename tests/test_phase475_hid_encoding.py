"""Bench-preparation wire fixtures only; no USB, socket, runtime, or hardware access."""
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "runtime"))
import caddx_crsf as crsf


# CRC-8/DVB-S2: polynomial D5, init 00, no reflection, xorout 00.
# This known-answer check is independent of the frame builder/decoder round trip.
def test_crc_dvb_s2_known_answer():
    assert crsf.crc8_d5(b"123456789") == 0xBC


# Frozen host fixture, not a captured hardware frame. Sixteen channels at 992;
# 26-byte CGC shape, CRC AD. Use to compare a later bench packet byte-for-byte.
CENTRED_WIRE = bytes.fromhex(
    "c8 18 16 e0 03 1f f8 c0 07 3e f0 81 0f 7c "
    "e0 03 1f f8 c0 07 3e f0 81 0f 7c ad"
)


def test_centred_frame_matches_fixed_wire_fixture():
    assert crsf.centred_frame() == CENTRED_WIRE
    assert crsf.decode_channels(CENTRED_WIRE) == [992] * 16


@pytest.mark.parametrize("offset", [2, *range(3, 25), 25])
def test_frame_type_payload_and_crc_corruption_are_rejected(offset):
    damaged = bytearray(CENTRED_WIRE)
    damaged[offset] ^= 1
    with pytest.raises(crsf.CrsfError) as failure:
        crsf.decode_channels(bytes(damaged))
    assert failure.value.code in {"CRSF_BAD_TYPE", "CRSF_BAD_CRC"}
