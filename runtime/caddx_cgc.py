"""Caddx Ground Configuration v0.3.5 control plane — UDP 9001 FE/EF.

Oracle: **CGC v0.3.5**, `CaddxGroundConfiguration.dll`
sha256 `d42ff30c9f5ba5f7d05d726a65b82ff9d4dacdb87a3a598a04875502863c4584`, 704,000 bytes,
from `CaddxGroundConfiguration-0.3.5-full.nupkg` (`aa14cd3a…`), decompiled with
ilspycmd 8.2.0.7535 to 171 unobfuscated files. Verification of every claim:
`docs/CGC_V035_VERIFICATION_2026-09-18.md`.

**Use the nupkg's assembly, not `Downloads\\CGC\\`.** That unpacked tree is v0.3.3
(`sq.version`), a different DLL (`e93ad2ed…`, 722,944 bytes). Handoff §6: do not
silently promote 0.3.3 behaviour to 0.3.5. Everything here is 0.3.5.

--------------------------------------------------------------------------------
WHAT IS PARITY AND WHAT IS OURS
--------------------------------------------------------------------------------

Parity (CGC does exactly this):
  * the frame, the additive big-endian payload sum, and the direction bytes;
  * the eleven remote-key builders, with Upgrade and Force720p60 as long-press
    variants of Pairing and Back;
  * the five wireless commands `0x50`-`0x54` and their payload shapes;
  * the `0x23` passthrough mode switch;
  * the argument guards: channel 0..16, power index 0..19.

**Ours, beyond stock — the response decoders.** `AscentVrxProtocol` contains
`ParseFrequencyResponse`, `ParseWirelessStatus` and `ParsePowerIndexResponse`, and
**nothing in CGC v0.3.5 calls any of them.** Its receive handler
(`VrxDeviceSession.OnControlDataReceived`) validates the envelope and writes the hex to
the log; it never decodes a payload. So CGC ships a *raw* control plane. The decoders
below are transcribed from that dead vendor code, which makes the field layouts
first-party, but **running them is not parity** and must not be described as such. It is
strictly more than the stock tool does, in the same way our RF readback verification is.

--------------------------------------------------------------------------------
POWER INDEX: A SELECTOR, NOT A POWER
--------------------------------------------------------------------------------

`powerIndex` is 0..19 and indexes `GetPowerValueMw`, a host-side **display-string**
table. Six of its twenty entries are `AUTO` variants — 13, 14, 15, 16, 17 and 19 — which
carry the same milliwatt figure as a non-AUTO entry but select adaptive behaviour. So
the map is not injective and the index encodes a *mode* as well as a level.

Under the five-concept power discipline (`CLAUDE.md`: keep **logical power request**,
**baseband dBm report**, **calibration-table value**, **conducted RF output** and
**EIRP** separate) this index is a *logical power request* and nothing else. Do not map
it onto the Sky's 18-row mW→dBm table at VA `0x2649e8`: that is the Sky's, this is the
receiver's, an AUTO entry has no single dBm, and `CLAUDE.md` already records that the
CX489 Relay map is a third and different table. Render the vendor's own string.
"""

from __future__ import annotations

import enum
import struct

# --------------------------------------------------------------------------- #
# Frame
# --------------------------------------------------------------------------- #

HEADER = b'\xFE\xEF'
TAIL = b'\x0D\x0A'

# AscentVrxProtocol.BuildFrame's `command` argument is the byte at offset 2. The
# vendor overloads that position for three different things, which is why it is
# called "direction" in CLAUDE.md and "command" in the assembly.
DIR_WRITE = 0x22          # BuildKeyFrame, BuildSetFrequency, BuildSetPowerIndex
DIR_READ = 0xA2           # BuildReadRequest
DIR_PASSTHROUGH = 0x23    # VrxPacketBuilder.BuildSetModePacket -- CMD_PASSTHROUGH = 35

KEY_TYPE_SIM = 0x40       # AscentVrxProtocol.KEY_TYPE_SIM
SUB_CMD_SET_MODE = 0x02   # VrxPacketBuilder.SUB_CMD_SET_MODE

MIN_FRAME = 9             # TryParseFrame rejects anything shorter


class CgcError(RuntimeError):
    def __init__(self, code: str, message: str, evidence=None):
        super().__init__(message)
        self.code = code
        self.evidence = evidence or {}


def checksum(payload: bytes) -> int:
    """Additive unsigned 16-bit sum over the payload bytes only.

    `AscentVrxProtocol.CalcChecksum` is a plain `+=` loop over `data`; the ushort
    accumulator wraps. It is not XOR-like and it does not cover header or length.
    """
    return sum(payload) & 0xFFFF


def build_frame(direction: int, payload: bytes = b'') -> bytes:
    """`FE EF | dir | BE16 len | payload | BE16 sum | 0D 0A`."""
    payload = bytes(payload)
    n = len(payload)
    return (HEADER + bytes([direction & 0xFF]) + struct.pack('>H', n) + payload
            + struct.pack('>H', checksum(payload)) + TAIL)


def parse_frame(raw: bytes) -> dict:
    """Envelope validation, transcribed from `TryParseFrame`.

    Returns a dict; raises `CgcError` rather than returning None so the reason a
    frame was refused survives to the operator. The vendor returns null for all
    five of these and logs one undifferentiated line.
    """
    raw = bytes(raw)
    if len(raw) < MIN_FRAME:
        raise CgcError('CGC_FRAME_TOO_SHORT', f'{len(raw)} bytes, minimum is {MIN_FRAME}')
    if raw[0:2] != HEADER:
        raise CgcError('CGC_BAD_HEADER', f'expected FE EF, got {raw[0]:02X} {raw[1]:02X}')
    if raw[-2:] != TAIL:
        raise CgcError('CGC_BAD_TAIL', f'expected 0D 0A, got {raw[-2]:02X} {raw[-1]:02X}')
    direction = raw[2]
    n = (raw[3] << 8) | raw[4]
    expected = 5 + n + 2 + 2
    if len(raw) != expected:
        raise CgcError('CGC_LENGTH_MISMATCH',
                       f'header declares {n} payload bytes so the frame should be '
                       f'{expected}, got {len(raw)}')
    payload = raw[5:5 + n]
    got = (raw[5 + n] << 8) | raw[5 + n + 1]
    want = checksum(payload)
    if got != want:
        raise CgcError('CGC_CHECKSUM_MISMATCH',
                       f'payload sum is 0x{want:04X}, frame carries 0x{got:04X}')
    cmd = payload[0] if n >= 1 else None
    return {
        'direction': direction,
        'payload': payload,
        'payload_hex': payload.hex(' ').upper(),
        'length': n,
        # The vendor sets WirelessCmdType only when payload[0] is a defined member.
        'wireless_cmd': cmd if (cmd is not None and cmd in _WIRELESS_VALUES) else None,
    }


# --------------------------------------------------------------------------- #
# Wireless command family -- WirelessCmdType, exactly five members
# --------------------------------------------------------------------------- #

class Wireless(enum.IntEnum):
    """`WirelessCmdType`. Five members; CGC defines no 0x55/0x56/0x57.

    The device-side DWARF names (from the live Gnd485 `ar_ldy_gnd`) are more precise
    than these host-side ones and `CLAUDE.md` prefers them: `0x50` sets channel *and
    hop state*, not a bare frequency, and `0x53`/`0x54` are baseband power rather than
    an opaque index. Both names are given so neither is lost.
    """
    SET_CHANNEL_HOP = 0x50   # host name: SetFrequency
    GET_CHANNEL_HOP = 0x51   # host name: GetFrequency
    GET_STATUS = 0x52        # host name: GetStatus
    GET_BB_PWR = 0x53        # host name: GetPowerIndex
    SET_BB_PWR = 0x54        # host name: SetPowerIndex


_WIRELESS_VALUES = {int(w) for w in Wireless}

# Present in stock Ground firmware but absent from CGC's enum. Listed so a reply
# carrying one is recognised rather than reported as corrupt; we do not send them.
GROUND_ONLY_OPCODES = {0x55: 'GET_STATUS_SKY', 0x56: 'GET_DISTANCE', 0x57: 'GET_OSD_DATA'}


class Band(enum.IntEnum):
    A = 0
    B = 1
    C = 2
    D = 3


class Hop(enum.IntEnum):
    """Hop state. THREE values on 19.2.14, not two.

    This modelled 0/1 only and `build_set_channel_hop` refused anything else,
    so the second hop mode could not be sent at all. The device's own UI names
    them, read from `/ar8030soc/GlassesUI` on 2026-10-04: the control is
    labelled **Hop** and the states are **Off**, **Intra-band** and
    **Inter-band**. The binary also carries `hop_mode=%d`, `to hop mode-2` and
    `hop mode-2 to hop off`, so the cycle is off -> mode 1 -> mode 2.

    WHICH NUMBER IS WHICH IS INFERRED, NOT PROVEN. The two names appear in
    source order -- Intra-band then Inter-band -- in the one non-alphabetical
    cluster in the binary (between `scan ch!` and `update_band_status`); every
    other occurrence is a Qt translation table, which is sorted and therefore
    says nothing. That ordering, and "mode-2" being the far end of the cycle,
    put Intra at 1 and Inter at 2. It is one bench press to confirm, and the UI
    says so rather than presenting it as established.
    """
    OFF = 0
    INTRA_BAND = 1
    INTER_BAND = 2

    # The names this file used before the device's own were known. Kept so
    # existing callers and fixtures do not break; OFF/INTRA_BAND/INTER_BAND are
    # the ones to use.
    FIXED = 0
    HOPPING = 1


# What the goggles print, by value. None means "no entry on the device".
HOP_DISPLAY_NAMES = {0: "Off", 1: "Intra-band", 2: "Inter-band"}
HOP_NAME_SOURCE = ("GlassesUI 19.2.14, the Hop control, read from the device "
                   "binary on 2026-10-04")
HOP_ASSIGNMENT_PROVEN = False
HOP_ASSIGNMENT_NOTE = (
    "Which of Intra-band and Inter-band is 1 and which is 2 is inferred from "
    "source order in the device binary, not confirmed on hardware. Set it and "
    "read the Hop control on the goggles to settle it.")


def hop_labels() -> list:
    return [{"value": v, "device_label": HOP_DISPLAY_NAMES[v],
             "proven": v == 0 or HOP_ASSIGNMENT_PROVEN}
            for v in sorted(HOP_DISPLAY_NAMES)]


CHANNEL_MAX = 16      # BuildSetFrequency: `if (channel > 16) throw` -- 信道范围 0~16
POWER_INDEX_MAX = 19  # BuildSetPowerIndex: `if (powerIndex > 19) throw` -- 功率索引范围 0~19


def build_get(cmd: Wireless) -> bytes:
    """`BuildReadRequest`: direction 0xA2, 8-byte payload, cmd then seven zeros."""
    return build_frame(DIR_READ, bytes([int(cmd)]) + b'\0' * 7)


def build_set_channel_hop(band: Band | int, channel: int, hop: Hop | int) -> bytes:
    if not (0 <= int(channel) <= CHANNEL_MAX):
        raise CgcError('CGC_CHANNEL_OUT_OF_RANGE',
                       f'channel {channel}; the vendor guard is 0..{CHANNEL_MAX}',
                       {'channel': channel, 'max': CHANNEL_MAX})
    if int(band) not in (0, 1, 2, 3):
        raise CgcError('CGC_BAND_INVALID', f'band {band}; expected 0..3 (A..D)')
    if int(hop) not in (0, 1, 2):
        raise CgcError('CGC_HOP_INVALID',
                       f'hop {hop}; expected 0 (Off), 1 or 2 (the two hop modes)',
                       {'labels': HOP_DISPLAY_NAMES})
    return build_frame(DIR_WRITE, bytes([int(Wireless.SET_CHANNEL_HOP), int(band),
                                         int(channel), int(hop), 0, 0, 0, 0]))


def build_set_power_index(index: int) -> bytes:
    if not (0 <= int(index) <= POWER_INDEX_MAX):
        raise CgcError('CGC_POWER_INDEX_OUT_OF_RANGE',
                       f'power index {index}; the vendor guard is 0..{POWER_INDEX_MAX}',
                       {'index': index, 'max': POWER_INDEX_MAX})
    return build_frame(DIR_WRITE, bytes([int(Wireless.SET_BB_PWR), int(index)]) + b'\0' * 6)


# --------------------------------------------------------------------------- #
# Remote keys -- KeyNum + the eleven builders
# --------------------------------------------------------------------------- #

class Key(enum.IntEnum):
    UP = 0
    DOWN = 1
    LEFT = 2
    RIGHT = 3
    CONFIRM = 4
    PAIRING = 5
    RECORDING = 6
    BACK = 7
    INVALID = 8      # defined but unused by any builder
    DEBUG3 = 9


# The eleven builders CGC exposes, as (key, press_type). Upgrade and Force720p60 are
# LONG-PRESS variants of Pairing and Back -- `BuildKeyUpgrade` is
# `BuildKeyFrame(KeyNum.Pairing, 1)` and `BuildKeyForce720p60` is
# `BuildKeyFrame(KeyNum.Back, 1)`. They are not keys of their own.
REMOTE_KEYS: dict[str, tuple[Key, int]] = {
    'UP': (Key.UP, 0),
    'DOWN': (Key.DOWN, 0),
    'LEFT': (Key.LEFT, 0),
    'RIGHT': (Key.RIGHT, 0),
    'CONFIRM': (Key.CONFIRM, 0),
    'PAIRING': (Key.PAIRING, 0),
    'UPGRADE': (Key.PAIRING, 1),
    'RECORDING': (Key.RECORDING, 0),
    'BACK': (Key.BACK, 0),
    'FORCE_720P60': (Key.BACK, 1),
    'DEBUG3': (Key.DEBUG3, 0),
}

# TRACED 2026-09-18 -- these four are UNREACHABLE in stock CGC v0.3.5, not merely
# untraced. Handoff §8.7 warned that builder existence is not UI reachability; the
# answer is that four of the eleven have no caller at all.
#
# The only path from the UI to a key frame is
# `IVrxDeviceSession.SendRemoteCommand(VrxRemoteCommand)` ->
# `VrxCommandPacketFactory.Build`, and `VrxRemoteCommand` has exactly SEVEN members:
# Up, Down, Left, Right, Confirm, Back, Recording. `RemoteCommandMapper` maps both
# keyboard (arrows/WASD/Return/Back/R) and button names onto that same seven-member
# enum. `BuildKeyPairing`, `BuildKeyUpgrade`, `BuildKeyForce720p60` and
# `BuildKeyDebug3` have **zero call sites** in the whole assembly -- dead code, like
# the three response parsers above them.
#
# BENCH-ESTABLISHED 2026-10-04: **PAIRING works.** Sent from Ascent Control under
# REMOTE KEY against a 19.2.14 VRX, the device acted on it. That does NOT
# contradict the zero-call-sites finding above, and the two must not be merged:
# that one is about what the PC Tool's own code can reach, this one is about what
# the DEVICE accepts. "The shipped tool never sends it" and "the unit honours it"
# are both true. Only PAIRING has been tried; UPGRADE, FORCE720P60 and DEBUG3
# remain correct-by-construction and unexercised.
#
# Consequence for us: sending any of these four is **not stock parity**. It is
# exposing a capability the shipped tool does not. Pairing in particular can disturb
# a working link -- now known to be a real effect rather than a cautious guess. They stay defined here because the frames are correct and a bench
# may want them deliberately, but a caller must opt in explicitly and the UI must not
# present them as ordinary controls.
REMOTE_KEYS_UNREACHABLE_IN_STOCK = frozenset({'PAIRING', 'UPGRADE', 'FORCE_720P60', 'DEBUG3'})

# The seven the stock tool can actually send, in `VrxRemoteCommand` order.
REMOTE_KEYS_STOCK = ('UP', 'DOWN', 'LEFT', 'RIGHT', 'CONFIRM', 'BACK', 'RECORDING')

# Keyboard bindings RemoteCommandMapper.TryMapKey accepts, for parity.
STOCK_KEYBOARD = {'ArrowUp': 'UP', 'w': 'UP', 'ArrowDown': 'DOWN', 's': 'DOWN',
                  'ArrowLeft': 'LEFT', 'a': 'LEFT', 'ArrowRight': 'RIGHT', 'd': 'RIGHT',
                  'Enter': 'CONFIRM', 'Backspace': 'BACK', 'r': 'RECORDING'}


def build_key(name: str) -> bytes:
    """`BuildKeyFrame`: direction 0x22, 4-byte payload `[0x40, key, press, 0]`."""
    try:
        key, press = REMOTE_KEYS[name]
    except KeyError:
        raise CgcError('CGC_UNKNOWN_KEY', f'{name!r} is not one of the eleven vendor keys',
                       {'known': sorted(REMOTE_KEYS)}) from None
    return build_frame(DIR_WRITE, bytes([KEY_TYPE_SIM, int(key), press, 0]))


# --------------------------------------------------------------------------- #
# Passthrough mode -- 0x23
# --------------------------------------------------------------------------- #

class Passthrough(enum.IntEnum):
    """`VrxPacketBuilder.PassthroughMode`.

    **Do not merge this with the MAX receiver's physical-UART enum** (`0` COMMAND,
    `1` MAVLINK, `2` BYPASS). They collide numerically and mean different things --
    `CLAUDE.md`, Ground (UDP). This one is the CGC *application* mode.
    """
    NONE = 0
    MAVLINK = 1
    CRSF = 2
    SBUS = 3
    USER = 4
    OSD = 5


# English labels for the CGC application passthrough modes. These are OUR
# enum -- `VrxPacketBuilder.PassthroughMode`, carried by frame 0x23 sub-command
# 2 -- rendered as words instead of shouted enum members and bare numbers.
DISPLAY_NAMES = {
    0: "None",
    1: "MAVLink",
    2: "CRSF",
    3: "SBUS",
    4: "User",
    5: "OSD",
}

# WHAT THESE ARE NOT.
#
# The goggles have their own menu, headed **VRX UART**, offering None, Command,
# VTX CRSF, VTX MavLink and VTX UART (read from /ar8030soc/GlassesUI,
# 2026-10-04, alongside `slotUartPassthroughClick`). It is tempting to treat
# that as the same setting and relabel this list with those words. **Do not.**
#
# `CLAUDE.md` is explicit that the CGC application mode and the receiver's
# physical-UART enum collide numerically and mean different things, and nothing
# here establishes that this frame drives that menu. Five entries against six,
# and the two orders do not line up. Relabelling would turn an unproven
# correspondence into a claim the UI makes on every page load -- and if it is
# wrong, an operator selects one thing believing it is another.
#
# So the goggles' list is recorded for comparison and nothing more.
DEVICE_UART_MENU = ("None", "Command", "VTX CRSF", "VTX MavLink", "VTX UART")
DEVICE_UART_MENU_SOURCE = ("GlassesUI 19.2.x, the VRX UART menu, read from the "
                           "device binary on 2026-10-04")
DEVICE_UART_CORRESPONDENCE_PROVEN = False


def mode_labels() -> list:
    """The CGC application passthrough modes, as English words."""
    return [{"value": int(m), "label": DISPLAY_NAMES.get(int(m), m.name),
             "enum_name": m.name} for m in Passthrough]


def build_set_mode(mode: Passthrough | int) -> bytes:
    """`BuildSetModePacket`: direction 0x23, payload `[0x02, mode, 0, 0, 0]`."""
    if int(mode) not in {int(m) for m in Passthrough}:
        raise CgcError('CGC_MODE_INVALID', f'passthrough mode {mode}; expected 0..5')
    return build_frame(DIR_PASSTHROUGH, bytes([SUB_CMD_SET_MODE, int(mode), 0, 0, 0]))


# --------------------------------------------------------------------------- #
# Response decoding -- OURS. CGC writes these and never calls them.
# --------------------------------------------------------------------------- #
#
# `DataContent` includes the command byte at [0], and `AssertCmdType(frame, expected,
# minDataLen)` requires `len(DataContent) >= minDataLen + 1`. The minimums below are
# the vendor's.

def _require(frame: dict, cmd: Wireless, min_data_len: int) -> bytes:
    payload = frame.get('payload') or b''
    if frame.get('wireless_cmd') != int(cmd):
        raise CgcError('CGC_CMD_TYPE_MISMATCH',
                       f'expected 0x{int(cmd):02X}, frame carries '
                       f'0x{(payload[0] if payload else 0xFF):02X}')
    if len(payload) < min_data_len + 1:
        raise CgcError('CGC_PAYLOAD_TOO_SHORT',
                       f'0x{int(cmd):02X} needs at least {min_data_len + 1} payload '
                       f'bytes, got {len(payload)}')
    return payload


def decode_channel_hop(frame: dict) -> dict:
    """`ParseFrequencyResponse`, min length 3 (+1)."""
    p = _require(frame, Wireless.GET_CHANNEL_HOP, 3)
    return {'band': int(p[1]), 'band_label': Band(p[1]).name if p[1] in (0, 1, 2, 3) else None,
            'channel': int(p[2]),
            'hop': int(p[3]),
            # The goggles' own word, and None for a value the device does not
            # name -- which is more useful than an enum member name, and does
            # not invent a label for a byte nobody has seen.
            'hop_label': HOP_DISPLAY_NAMES.get(int(p[3])),
            'hop_label_proven': int(p[3]) == 0 or HOP_ASSIGNMENT_PROVEN}


def decode_status(frame: dict) -> dict:
    """`ParseWirelessStatus`, min length 6 (+1).

    Note `DataContent[3]` is read by nothing: the vendor skips from rssi2 at [2] to
    the data rate at [4]. It is left unnamed here rather than guessed at, and the raw
    byte is returned so a bench capture can settle it.
    """
    p = _require(frame, Wireless.GET_STATUS, 6)
    return {'rssi1': int(p[1]), 'rssi2': int(p[2]), 'unknown_byte3': int(p[3]),
            'data_rate_mbps': int(p[4]), 'delay_ms': int(p[5]),
            'connected': p[6] == 1}


def decode_power_index(frame: dict) -> dict:
    """`ParsePowerIndexResponse`, min length 5 (+1).

    Bytes [2..5] are a little-endian uint32 bitmask of the indexes this device will
    accept. The vendor iterates all 32 bits; only 0..19 are meaningful, so a bit above
    19 is reported separately rather than silently dropped.
    """
    p = _require(frame, Wireless.GET_BB_PWR, 5)
    mask = int.from_bytes(p[2:6], 'little')
    settable = [i for i in range(32) if mask & (1 << i)]
    return {
        'current_index': int(p[1]),
        'current_label': power_label(p[1]),
        'settable_indexes': [i for i in settable if i <= POWER_INDEX_MAX],
        'settable_out_of_range': [i for i in settable if i > POWER_INDEX_MAX],
        'settable_mask': mask,
    }


# --------------------------------------------------------------------------- #
# DECODE PLAUSIBILITY
#
# Every decoder above is transcribed from vendor code that has NEVER EXECUTED -- CGC
# ships these three parsers and calls none of them, logging raw hex instead. So the
# field offsets are first-party but unproven, and the first live read is their first
# exercise anywhere.
#
# An offset that is one byte out does not fail loudly. It returns a number, and a
# number looks like an answer. So each decoded field is checked against what it can
# physically be, and the verdict is reported with the value.
#
# A check that passes proves only that the value is CONSISTENT with the offset being
# right. It cannot prove the offset IS right -- the same discipline as the CoT wire
# decoder, and the reason this reports "consistent" rather than "correct".
# --------------------------------------------------------------------------- #

def plausibility(cmd: int, decoded: dict | None) -> dict:
    """Range-check one decoded reply. Returns findings, never raises."""
    if decoded is None:
        return {"applies": False, "checks": [], "suspect": [],
                "note": "No decoder for this reply."}

    checks = []

    def ck(name, ok, value, why):
        checks.append({"field": name, "ok": bool(ok), "value": value, "why": why})

    if cmd == int(Wireless.GET_CHANNEL_HOP):
        ck("band", decoded.get("band_label") is not None, decoded.get("band"),
           "must be one of the four declared bands")
        ck("channel", 0 <= (decoded.get("channel") or -1) <= CHANNEL_MAX,
           decoded.get("channel"), f"must lie in 0..{CHANNEL_MAX}")
        ck("hop", decoded.get("hop_label") is not None, decoded.get("hop"),
           "must be 0 or 1")
    elif cmd == int(Wireless.GET_STATUS):
        # RSSI scale is unknown (L-3), so this only asserts it is a byte that is not
        # pinned at an extreme -- 0 or 255 on both channels usually means the offset
        # is wrong, not that the link is perfect or dead.
        r1, r2 = decoded.get("rssi1"), decoded.get("rssi2")
        ck("rssi1/rssi2", not (r1 in (0, 255) and r2 in (0, 255)), [r1, r2],
           "both pinned at 0 or 255 suggests a wrong offset, not a real link")
        ck("data_rate_mbps", 0 <= (decoded.get("data_rate_mbps") or -1) <= 200,
           decoded.get("data_rate_mbps"), "a plausible link rate in Mbps")
        ck("delay_ms", 0 <= (decoded.get("delay_ms") or -1) <= 250,
           decoded.get("delay_ms"), "a plausible latency in ms")
        ck("connected", isinstance(decoded.get("connected"), bool),
           decoded.get("connected"), "byte 6 must read as 0 or 1")
    elif cmd == int(Wireless.GET_BB_PWR):
        ck("current_index", 0 <= (decoded.get("current_index") or -1) <= POWER_INDEX_MAX,
           decoded.get("current_index"), f"must lie in 0..{POWER_INDEX_MAX}")
        ck("current_label", decoded.get("current_label") is not None,
           decoded.get("current_label"), "the index must exist in the power table")
        ck("settable_mask", bool(decoded.get("settable_indexes")),
           decoded.get("settable_mask"), "a device that accepts no index at all is suspect")
        ck("settable_out_of_range", not decoded.get("settable_out_of_range"),
           decoded.get("settable_out_of_range"),
           f"bits above {POWER_INDEX_MAX} are not meaningful and suggest a wrong offset")

    suspect = [c["field"] for c in checks if not c["ok"]]
    return {
        "applies": True, "checks": checks, "suspect": suspect,
        "verdict": "suspect" if suspect else "consistent",
        "note": ("Every field is within what it can physically be, which is consistent "
                 "with the transcribed offsets being right. It does not prove they are: "
                 "an offset one byte out still returns a number."
                 if not suspect else
                 f"{len(suspect)} field(s) are outside what they can physically be. "
                 "The most likely cause is a wrong offset in the transcribed decoder, "
                 "not a strange device. Send the raw hex on."),
    }


# The two things the first bench read is expected to SETTLE rather than confirm.
OPEN_OBSERVATIONS = [
    {"id": "L-2", "field": "unknown_byte3",
     "question": ("GET_STATUS DataContent[3] is read by nothing in the vendor code -- it "
                  "skips rssi2 at [2] straight to the data rate at [4]. Capture it across "
                  "linked and unlinked states and see whether it moves.")},
    {"id": "L-3", "field": "rssi1/rssi2",
     "question": ("Raw bytes with no stated scale. Do NOT label them dBm until a capture "
                  "at known ranges settles it.")},
    {"id": "L-4", "field": "settable_indexes",
     "question": ("Confirm a real device reports a subset rather than all 20, and that it "
                  "refuses an index outside that subset.")},
]

DECODERS = {
    int(Wireless.GET_CHANNEL_HOP): decode_channel_hop,
    int(Wireless.GET_STATUS): decode_status,
    int(Wireless.GET_BB_PWR): decode_power_index,
}


def decode(frame: dict) -> dict | None:
    """Decode a parsed frame if we know how; None otherwise. Never raises on shape."""
    fn = DECODERS.get(frame.get('wireless_cmd'))
    if fn is None:
        return None
    try:
        return fn(frame)
    except CgcError as e:
        return {'error': e.code, 'message': str(e)}


# --------------------------------------------------------------------------- #
# Power index table -- AscentVrxProtocol.GetPowerValueMw
# --------------------------------------------------------------------------- #
#
# The vendor's own display strings, verbatim. Read the module docstring before using
# the milliwatt figures for anything: six entries are AUTO modes, so the map is not
# injective and the index is a mode selector as much as a level.
POWER_TABLE: dict[int, str] = {
    0: '25mW', 1: '100mW', 2: '150mW', 3: '200mW', 4: '300mW', 5: '350mW',
    6: '500mW', 7: '700mW', 8: '1000mW', 9: '1500mW', 10: '2500mW', 11: '3000mW',
    12: '4000mW', 13: '1000mW AUTO', 14: '2000mW AUTO', 15: '4000mW AUTO',
    16: '100mW AUTO', 17: '500mW AUTO', 18: '5000mW', 19: '5000mW AUTO',
}
POWER_AUTO_INDEXES = frozenset({13, 14, 15, 16, 17, 19})


def power_label(index: int) -> str:
    return POWER_TABLE.get(int(index), f'Unknown({int(index)})')


def power_entry(index: int) -> dict:
    """Structured view. `milliwatts` is the vendor's own figure, never a measurement."""
    label = power_label(index)
    mw = None
    head = label.split('mW')[0]
    if head.isdigit():
        mw = int(head)
    return {'index': int(index), 'label': label, 'milliwatts_declared': mw,
            'auto': int(index) in POWER_AUTO_INDEXES,
            'note': ('AUTO selects adaptive behaviour at this level; the index encodes a '
                     'mode as well as a level' if int(index) in POWER_AUTO_INDEXES else None)}


# --------------------------------------------------------------------------- #
# Endpoint profiles -- DeviceConnectionProfileCatalog
# --------------------------------------------------------------------------- #

PROFILES = {
    'rj45': {'index': 0, 'display_name': 'RJ45', 'subnet_prefix': '192.168.1',
             'device_ip': '192.168.1.100', 'ctrl_port': 9001, 'crsf_port': 9100,
             'osd_port': 9200, 'rtsp_url': 'rtsp://192.168.1.100/live.ch01'},
    'usbc': {'index': 1, 'display_name': 'USB-C', 'subnet_prefix': '192.168.3',
             'device_ip': '192.168.3.102', 'ctrl_port': 9001, 'crsf_port': 9100,
             'osd_port': 9200, 'rtsp_url': 'rtsp://192.168.3.102/live.ch01'},
}


def selftest() -> dict:
    # The §8.8 Pair frame, byte for byte.
    assert build_key('PAIRING').hex(' ').upper() == 'FE EF 22 00 04 40 05 00 00 00 45 0D 0A'
    assert build_key('UPGRADE')[6] == 0x05 and build_key('UPGRADE')[7] == 0x01
    assert build_key('FORCE_720P60')[6] == 0x07 and build_key('FORCE_720P60')[7] == 0x01
    # Round trip.
    f = parse_frame(build_get(Wireless.GET_BB_PWR))
    assert f['direction'] == DIR_READ and f['wireless_cmd'] == 0x53
    # Decode a synthetic power reply: index 8, settable mask bits 0,1,6,8.
    reply = build_frame(DIR_READ, bytes([0x53, 8]) + (0x0143).to_bytes(4, 'little'))
    d = decode_power_index(parse_frame(reply))
    assert d['current_index'] == 8 and d['settable_indexes'] == [0, 1, 6, 8]
    assert d['current_label'] == '1000mW'
    assert len(POWER_TABLE) == 20 and len(REMOTE_KEYS) == 11
    assert len(REMOTE_KEYS_STOCK) == 7
    assert set(REMOTE_KEYS_STOCK) | REMOTE_KEYS_UNREACHABLE_IN_STOCK == set(REMOTE_KEYS)
    assert len(_WIRELESS_VALUES) == 5
    return {'ok': True, 'keys': len(REMOTE_KEYS), 'power_entries': len(POWER_TABLE)}


if __name__ == '__main__':
    print(selftest())
