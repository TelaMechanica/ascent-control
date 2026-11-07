"""
MSP v2 frames carried in the VRX's FC-OSD ring.

WHERE THIS COMES FROM. The Ground answers CGC opcode `0x57`
(`WIRELESS_DATA_TYPE_GET_OSD_DATA`) on UDP/9001 with up to 2048 bytes of the
ring the flight controller's MSP stream lands in. Confirmed on hardware
2026-10-04: the reply payload begins `24 58 3e` -- `$X>`, MSP **v2** -- not
character cells, and not a vendor format.

WHY IT MATTERS. The flight controller already sends its position to the VTX
over MSP so the VTX can burn it into the OSD. If that reaches this ring as
`MSP_RAW_GPS`, it is a FIRST-PARTY, STRUCTURED position: no control link
required, no CRSF or MAVLink decode, and nothing scraped out of rendered
glyphs. Reading characters back off an OSD is not done here and should not be
added -- the numbers exist as numbers.

WHAT WAS ACTUALLY OBSERVED, with a live GPS-equipped VTX bound to the VRX
(2026-10-04, 199 reads over 40 s, 42 kB):

  * every single frame was function 182. Not one `MSP_RAW_GPS`;
  * the 182 payloads carry subcommand **53 (0x35)**. That is the documented
    FULL_FRAME variant -- see `caddx_msp_osd.FULL_FRAME_SUBCOMMAND`, which has
    decoded it all along. An earlier note here called it an unknown Caddx
    format; that was wrong, and wrong because this file was written without
    reading the module next to it;
  * `0x56 GET_DISTANCE` answers all zeros, so the Ground has no position of
    its own either.

So on this firmware the position reaches the VRX as a RENDERED CHARACTER GRID
and not as `MSP_RAW_GPS`. The grid is fully decodable -- `caddx_msp_osd` does
it -- so the data is there; it is simply text rather than an int32 pair.

That makes the first-party tier two steps, not one:

  1a  `MSP_RAW_GPS` if it is ever present. Structured, exact, preferred.
  1b  the OSD grid, read as text, when 1a is absent.

1b is second for a reason worth keeping in view: it depends on which elements
the pilot enabled in their OSD, and a misread digit is a WRONG position rather
than a missing one. So it validates hard -- a strict coordinate shape, both
hemispheres, plausibility bounds -- and refuses rather than guesses. It is
labelled as coming from the OSD wherever it is shown.
"""
from __future__ import annotations

import struct

MSP_RAW_GPS = 106
MSP_COMP_GPS = 107
MSP_DISPLAYPORT = 182

MSP_NAMES = {
    101: "MSP_STATUS", 102: "MSP_RAW_IMU", 105: "MSP_RC",
    MSP_RAW_GPS: "MSP_RAW_GPS", MSP_COMP_GPS: "MSP_COMP_GPS",
    108: "MSP_ATTITUDE", 109: "MSP_ALTITUDE", 110: "MSP_ANALOG",
    130: "MSP_BATTERY_STATE", MSP_DISPLAYPORT: "MSP_DISPLAYPORT",
}

_V2_MAGIC = b"$X"

# CRC-8/DVB-S2, which is what MSP v2 uses. Table-driven because this runs over
# every candidate offset in a ring read, not once per frame.
_CRC8_TABLE = []
for _b in range(256):
    _c = _b
    for _ in range(8):
        _c = ((_c << 1) ^ 0xD5) & 0xFF if _c & 0x80 else (_c << 1) & 0xFF
    _CRC8_TABLE.append(_c)
del _b, _c


def crc8_dvb_s2(data: bytes) -> int:
    """MSP v2's checksum, over `flag` through the end of the payload."""
    crc = 0
    for byte in data:
        crc = _CRC8_TABLE[crc ^ byte]
    return crc


def iter_frames(buf: bytes):
    """Yield (function, payload) for every MSP v2 frame in `buf`.

    Resynchronising by design. This is a RING: a read can begin mid-frame and
    can contain tail bytes of a frame whose head was in the previous read, so
    anything that is not a clean header is skipped a byte at a time rather
    than treated as corruption.

    Layout: `$X` <dir> <flag> <function u16le> <size u16le> <payload> <crc8>.

    THE CRC IS CHECKED, and in a resynchronising reader it is the only thing that
    can be. Scanning byte by byte for `$X` means a false match inside payload data
    produces a frame with a plausible function and size; so does a genuine header
    whose payload was torn across the ring wrap. Either can decode as
    MSP_RAW_GPS and yield a fabricated latitude and longitude, which is what the
    aircraft marker on the map is drawn from. A rejected frame costs one missed
    update at 20 Hz. An accepted bad one puts the aircraft somewhere it is not.
    """
    i, n = 0, len(buf)
    while i + 8 <= n:
        if buf[i:i + 2] != _V2_MAGIC:
            i += 1
            continue
        function = int.from_bytes(buf[i + 4:i + 6], "little")
        size = int.from_bytes(buf[i + 6:i + 8], "little")
        end = i + 8 + size
        if size > 2048 or end + 1 > n:
            # Truncated by the ring boundary. Not an error -- the rest of this
            # frame is simply in another read.
            i += 1
            continue
        if crc8_dvb_s2(buf[i + 3:end]) != buf[end]:
            # Advance by one, not past the frame: a failing CRC means this was
            # probably never a frame, so the real header may start inside it.
            i += 1
            continue
        yield function, buf[i + 8:end]
        i = end + 1


MSP_RC = 105

# MSP channel values are microseconds, conventionally 1000..2000 with 1500 centre.
# CRSF is 172..1811 with 992 centre. One binding should not have to care which
# source it is reading, so observed values are converted on the way in and
# everything downstream speaks CRSF.
MSP_RC_MIN_US, MSP_RC_MAX_US = 1000, 2000
CRSF_MIN, CRSF_MAX = 172, 1811


def decode_rc(payload: bytes) -> list[int] | None:
    """Channel values from an MSP_RC frame, converted to the CRSF range.

    NOTHING IN THIS PROJECT HAS YET SEEN A FLIGHT CONTROLLER PUSH ONE. The OSD
    reader on UDP 9200 decodes every MSP frame and discards anything that is not
    DisplayPort, so if MSP_RC does arrive it is already being received and thrown
    away -- which is why decoding it costs nothing and settles the question on the
    bench instead of in an argument.

    Returns None rather than raising on a short or odd-length payload: this runs
    inside a background reader on a push stream, and one malformed frame must not
    stop the reader.
    """
    if not payload or len(payload) < 2 or len(payload) % 2:
        return None
    out = []
    span_us = MSP_RC_MAX_US - MSP_RC_MIN_US
    span_crsf = CRSF_MAX - CRSF_MIN
    for i in range(0, len(payload), 2):
        us = int.from_bytes(payload[i:i + 2], 'little')
        us = max(MSP_RC_MIN_US, min(MSP_RC_MAX_US, us))
        out.append(CRSF_MIN + round((us - MSP_RC_MIN_US) * span_crsf / span_us))
    return out


def decode_raw_gps(payload: bytes) -> dict | None:
    """`MSP_RAW_GPS`: fix, numSat, lat, lon, alt, speed, course.

    Betaflight/iNav send latitude and longitude as int32 in units of 1e-7
    degrees, and `course` in decidegrees. A short payload is refused rather
    than padded: a half-read position is worse than none.
    """
    if len(payload) < 16:
        return None
    fix, sats, lat, lon, alt, speed, course = struct.unpack_from(
        "<BBiihhh", payload, 0)
    return {
        "fix": int(fix), "satellites": int(sats),
        "lat": lat / 1e7, "lon": lon / 1e7,
        "alt_m": int(alt), "speed_cms": int(speed),
        "course_deg": (course % 3600) / 10.0,
    }


def position_from_ring(buf: bytes) -> dict:
    """The best position in one ring read, and what was seen if there is none.

    Returns `available` plus the functions observed, because "no GPS frame"
    and "nothing in the ring at all" are different problems and the operator
    is entitled to know which one they have.
    """
    seen: dict[int, int] = {}
    best = None
    for function, payload in iter_frames(buf):
        seen[function] = seen.get(function, 0) + 1
        if function == MSP_RAW_GPS:
            got = decode_raw_gps(payload)
            if got:
                best = got
    functions = [{"function": f, "name": MSP_NAMES.get(f, "unknown"), "count": c}
                 for f, c in sorted(seen.items())]
    if best is None:
        return {"available": False, "functions": functions,
                "reason": ("the OSD ring carries MSP, but no MSP_RAW_GPS frame"
                           if seen else "no MSP frames in the OSD ring")}
    # A fix of 0 means the receiver has no lock. The numbers are present and
    # meaningless, so they are not offered as a position.
    if best["fix"] == 0 or (best["lat"] == 0.0 and best["lon"] == 0.0):
        return {"available": False, "functions": functions,
                "reason": "the flight controller reports no GPS lock",
                "satellites": best["satellites"]}
    return {"available": True, "source": "MSP_RAW_GPS", "functions": functions, **best}


# --------------------------------------------------------------------------- #
# Tier 1b -- the position as it appears in the OSD text
#
# Used only when MSP_RAW_GPS is absent, which on this firmware is always. The
# grid is first-party data on a first-party path and needs no control link,
# but it is TEXT: a misread digit is a wrong position rather than a missing
# one, so everything below is built to refuse rather than guess.
# --------------------------------------------------------------------------- #

import re as _re

# Betaflight/iNav render coordinates with a leading hemisphere glyph and a
# fixed number of decimals. Both forms are accepted; nothing else is.
#   lat  47.1234567      N47.1234567      47.12345
_COORD = _re.compile(
    r"(?<![\d.])([NSEW])?\s*([+-]?\d{1,3}\.\d{4,7})(?![\d])", _re.I)

LAT_MAX, LON_MAX = 90.0, 180.0


def coordinates_from_text(text: str) -> dict:
    """Find one latitude/longitude pair in rendered OSD text.

    Deliberately strict:

      * at least four decimal places. Three is ~100 m and is far more likely
        to be an altitude, a speed or a voltage than a position;
      * a latitude must be within +/-90 and a longitude within +/-180, and
        the two must come from DIFFERENT numbers;
      * exactly one plausible pair. Two candidate pairs means the parse is
        ambiguous and it returns nothing, because picking one would be a
        coin toss resolved in favour of a wrong map position;
      * 0,0 is refused -- it is what a controller renders with no lock.
    """
    hits = []
    for m in _COORD.finditer(text or ""):
        hemi, num = (m.group(1) or "").upper(), m.group(2)
        try:
            v = float(num)
        except ValueError:
            continue
        hits.append({"hemi": hemi, "value": v, "pos": m.start()})
    if len(hits) < 2:
        return {"available": False, "reason": "no coordinate pair in the OSD text"}

    pairs = []
    for i in range(len(hits) - 1):
        a, b = hits[i], hits[i + 1]
        lat, lon = a, b
        # An explicit hemisphere settles which is which; otherwise order does.
        if a["hemi"] in ("E", "W") or b["hemi"] in ("N", "S"):
            lat, lon = b, a
        la = -lat["value"] if lat["hemi"] == "S" else lat["value"]
        lo = -lon["value"] if lon["hemi"] == "W" else lon["value"]
        if abs(la) > LAT_MAX or abs(lo) > LON_MAX:
            continue
        if la == 0.0 and lo == 0.0:
            continue
        pairs.append((la, lo))

    if not pairs:
        return {"available": False, "reason": "no plausible coordinate pair in the OSD"}
    if len({(round(a, 6), round(b, 6)) for a, b in pairs}) > 1:
        return {"available": False,
                "reason": ("more than one coordinate pair in the OSD text, so the "
                           "reading is ambiguous and was refused")}
    la, lo = pairs[0]
    return {"available": True, "source": "OSD_TEXT", "lat": la, "lon": lo,
            "note": ("read from the rendered OSD, not from a structured GPS "
                     "message: this firmware sends no MSP_RAW_GPS")}
