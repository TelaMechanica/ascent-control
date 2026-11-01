"""CRSF RC-channels frames, for the CGC CRSF plane on UDP 9100.

Oracle: `CrsfHelper` in CGC v0.3.5 (`CaddxGroundConfiguration.dll` `d42ff30c…`).
Every constant below is that class's own.

The frame is standard CRSF `RC_CHANNELS_PACKED`, but transcribe rather than assume:
the vendor pins a specific sync byte, a specific CRC span, and a specific HID→CRSF
mapping, and a generic CRSF implementation will differ on at least the last of those.

    C8 18 16 <22 payload bytes> <crc>        26 bytes total
    |  |  |                     `- CRC-8 poly 0xD5 over bytes [2..24], i.e. type+payload
    |  |  `- FrameTypeRcChannels = 22 (0x16)
    |  `- RcChannelsFrameLength = 24 (type + 22 payload + crc)
    `- DefaultSyncByte = 200 (0xC8)

Payload is sixteen 11-bit channels, little-endian bit packed, 22 bytes exactly.
"""

from __future__ import annotations

SYNC = 0xC8              # CrsfHelper.DefaultSyncByte
FRAME_TYPE_RC = 0x16     # CrsfHelper.FrameTypeRcChannels = 22
FRAME_LENGTH = 24        # CrsfHelper.RcChannelsFrameLength
CHANNEL_COUNT = 16       # CrsfHelper.RcChannelCount
PAYLOAD_LENGTH = 22      # CrsfHelper.RcChannelsPayloadLength
FRAME_TOTAL = 26         # sync + len + 24

# CrsfHelper's own bounds. CRSF_MID is what unused channels are centred on.
HID_LOGICAL_MAX = 2048   # CrsfHelper.HidLogicalMax
CRSF_MIN = 172
CRSF_MID = 992
CRSF_MAX = 1811

CHANNEL_MASK = 0x7FF     # 11 bits


class CrsfError(RuntimeError):
    def __init__(self, code: str, message: str, evidence=None):
        super().__init__(message)
        self.code = code
        self.evidence = evidence or {}


def crc8_d5(data: bytes) -> int:
    """CRC-8 with polynomial 0xD5, initial value 0. `CrsfHelper.Crc8D5`.

    Not the more common 0x07 or 0x31 -- a wrong polynomial produces frames a
    receiver silently discards, which looks exactly like a dead link.
    """
    crc = 0
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = ((crc << 1) ^ 0xD5) & 0xFF if crc & 0x80 else (crc << 1) & 0xFF
    return crc


def map_hid_axis(value: int) -> int:
    """HID logical 0..2048 -> CRSF 172..1811. `CrsfHelper.MapHidAxis`.

    `172 + (v * 1639 + 1024) / 2048` in integer arithmetic. 1639 is the CRSF span
    and the +1024 is round-to-nearest. Reproduced exactly rather than as a float
    scale, because the rounding differs at many points.
    """
    v = min(HID_LOGICAL_MAX, max(0, int(value)))
    return CRSF_MIN + (v * 1639 + 1024) // 2048


def pack_channels(channels) -> bytes:
    """Sixteen 11-bit values, little-endian bit packed into 22 bytes."""
    vals = list(channels)
    if len(vals) != CHANNEL_COUNT:
        raise CrsfError('CRSF_CHANNEL_COUNT',
                        f'exactly {CHANNEL_COUNT} channels are required, got {len(vals)}',
                        {'count': len(vals)})
    out = bytearray(PAYLOAD_LENGTH)
    for i, raw in enumerate(vals):
        value = int(raw) & CHANNEL_MASK
        bit = i * 11
        idx, shift = bit // 8, bit % 8
        word = value << shift
        out[idx] |= word & 0xFF
        out[idx + 1] |= (word >> 8) & 0xFF
        if idx + 2 < PAYLOAD_LENGTH:
            out[idx + 2] |= (word >> 16) & 0xFF
    return bytes(out)


def build_rc_channels(channels, *, sync: int = SYNC) -> bytes:
    """Build one RC_CHANNELS_PACKED frame from sixteen raw CRSF values."""
    payload = pack_channels(channels)
    frame = bytearray([sync & 0xFF, FRAME_LENGTH, FRAME_TYPE_RC]) + payload + bytearray(1)
    # CRC covers the type byte and the payload: bytes [2..24], 23 bytes.
    frame[25] = crc8_d5(bytes(frame[2:25]))
    return bytes(frame)


def build_from_axes(axes, *, sync: int = SYNC) -> bytes:
    """Build from HID axes, as `BuildRcChannelsPacket(AdaptiveJoystickFrame, …)` does.

    The first eight axes are mapped; channels 8..15 are centred at CRSF_MID. The
    vendor requires at least eight axes and refuses a shorter frame -- a stick box
    reporting six axes is a configuration error, not something to pad silently.
    """
    axes = list(axes)
    if len(axes) < 8:
        raise CrsfError('CRSF_TOO_FEW_AXES',
                        f'at least 8 HID axes are required, got {len(axes)}',
                        {'axes': len(axes)})
    mapped = [map_hid_axis(a) for a in axes[:8]] + [CRSF_MID] * 8
    return build_rc_channels(mapped, sync=sync)


def centred_frame() -> bytes:
    """All sixteen channels at CRSF centre. A safe idle/failsafe pattern."""
    return build_rc_channels([CRSF_MID] * CHANNEL_COUNT)


def decode_channels(frame: bytes) -> list[int]:
    """Unpack our own frame again. Ours -- CGC never parses a CRSF frame."""
    frame = bytes(frame)
    if len(frame) != FRAME_TOTAL:
        raise CrsfError('CRSF_BAD_LENGTH', f'expected {FRAME_TOTAL} bytes, got {len(frame)}')
    if frame[2] != FRAME_TYPE_RC:
        raise CrsfError('CRSF_BAD_TYPE', f'frame type 0x{frame[2]:02X} is not RC_CHANNELS')
    want = crc8_d5(frame[2:25])
    if frame[25] != want:
        raise CrsfError('CRSF_BAD_CRC', f'crc is 0x{frame[25]:02X}, computed 0x{want:02X}')
    payload = frame[3:25]
    out = []
    for i in range(CHANNEL_COUNT):
        bit = i * 11
        idx, shift = bit // 8, bit % 8
        word = payload[idx] | (payload[idx + 1] << 8)
        if idx + 2 < PAYLOAD_LENGTH:
            word |= payload[idx + 2] << 16
        out.append((word >> shift) & CHANNEL_MASK)
    return out


def selftest() -> dict:
    f = centred_frame()
    assert len(f) == FRAME_TOTAL and f[0] == SYNC and f[1] == FRAME_LENGTH and f[2] == FRAME_TYPE_RC
    assert decode_channels(f) == [CRSF_MID] * CHANNEL_COUNT
    assert map_hid_axis(0) == CRSF_MIN
    assert map_hid_axis(HID_LOGICAL_MAX) == CRSF_MAX
    ramp = list(range(16))
    assert decode_channels(build_rc_channels(ramp)) == ramp
    return {'ok': True, 'frame_bytes': FRAME_TOTAL}


if __name__ == '__main__':
    print(selftest())
