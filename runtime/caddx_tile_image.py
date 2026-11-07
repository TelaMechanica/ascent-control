"""
Tile image validation for the Ascent MAX renderer's storage contract.

The renderer that consumes these packages has hard limits, and a package that
violates them is not slightly wrong -- it fails to draw. So every tile is checked
before it is written, from its own bytes, and a tile that cannot be shown is
recorded as missing rather than stored.

The contract, as specified:

  * 256x256 pixels, normalised. The current engine caps at 256 per dimension, so a
    512x512 "retina" tile must not be stored.
  * JPEG or PNG containers only. JPEG suits photographic/aerial bases, PNG suits
    lossless or transparent layers.
  * A partial or malformed tile is NEVER silently stretched. It fails, or it is
    explicitly marked missing.

Dimensions are read from the container header in pure standard library, because the
shipped interpreter is an embeddable CPython with no pip and therefore no Pillow.
That is enough to *enforce* every clause above. It is not enough to *resample*, and
this module does not pretend otherwise: an off-size tile is reported with its real
dimensions and the source that served it, so the operator is told which source is
incompatible instead of receiving a package that will not render.
"""
from __future__ import annotations

import struct

# The renderer's hard cap. Not a map-format limit in general -- a property of the
# current engine, recorded here so the reason travels with the number.
ENGINE_TILE_PX = 256

JPEG = "image/jpeg"
PNG = "image/png"
SUPPORTED = (JPEG, PNG)


class TileImageError(ValueError):
    def __init__(self, code: str, message: str, evidence: dict | None = None):
        super().__init__(message)
        self.code = code
        self.evidence = evidence or {}


def _png_size(data: bytes) -> tuple[int, int]:
    # An IHDR chunk always follows the 8-byte signature: length, 'IHDR', w, h.
    if len(data) < 24 or data[12:16] != b"IHDR":
        raise TileImageError("TILE_TRUNCATED", "PNG has no readable IHDR chunk")
    w, h = struct.unpack(">II", data[16:24])
    return w, h


def _jpeg_size(data: bytes) -> tuple[int, int]:
    """Walk the marker segments to the frame header. No decoding, no dependency."""
    i, n = 2, len(data)
    while i + 9 < n:
        if data[i] != 0xFF:
            i += 1
            continue
        marker = data[i + 1]
        if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
            i += 2
            continue
        if i + 4 > n:
            break
        seg_len = struct.unpack(">H", data[i + 2:i + 4])[0]
        # SOF0..SOF15, excluding the non-frame markers DHT/JPG/DAC.
        if 0xC0 <= marker <= 0xCF and marker not in (0xC4, 0xC8, 0xCC):
            if i + 9 > n:
                break
            h, w = struct.unpack(">HH", data[i + 5:i + 9])
            return w, h
        i += 2 + seg_len
    raise TileImageError("TILE_TRUNCATED", "JPEG has no readable frame header")


def sniff(data: bytes) -> dict:
    """
    Container and pixel dimensions, from the bytes alone.

    A provider's declared Content-Type is not trusted here: the file that gets
    stored is what the renderer must read, so the file itself is what is measured.
    """
    if not data:
        raise TileImageError("TILE_EMPTY", "tile is zero bytes")
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        w, h = _png_size(data)
        fmt = PNG
    elif data[:3] == b"\xff\xd8\xff":
        w, h = _jpeg_size(data)
        fmt = JPEG
    elif data[:6] in (b"GIF87a", b"GIF89a"):
        raise TileImageError("TILE_FORMAT_UNSUPPORTED",
                             "GIF is not supported by the renderer; JPEG or PNG only",
                             {"format": "image/gif"})
    elif data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        raise TileImageError("TILE_FORMAT_UNSUPPORTED",
                             "WebP is not supported by the renderer; JPEG or PNG only",
                             {"format": "image/webp"})
    elif data[:5] in (b"<?xml", b"<html", b"<HTML") or data[:1] == b"<":
        # Providers return errors with HTTP 200 and an XML/HTML body. Measured: the
        # PL Ortofoto WMTS layer answers an <ExceptionReport> this way. Stored
        # unchecked it becomes a "tile" the renderer silently cannot draw.
        raise TileImageError("TILE_PROVIDER_ERROR",
                             "the provider returned a text/XML error document, not an "
                             "image, with a success status",
                             {"head": data[:160].decode("utf-8", "replace")})
    else:
        raise TileImageError("TILE_FORMAT_UNKNOWN",
                             "tile is neither JPEG nor PNG",
                             {"head": data[:8].hex()})
    return {"format": fmt, "width": w, "height": h, "bytes": len(data)}


def check(data: bytes, *, source: str | None = None) -> dict:
    """
    Validate one tile against the renderer's storage contract.

    Raises rather than repairing. A tile that is the wrong size cannot be fixed
    without resampling, and silently storing it stretched is the one thing the
    contract explicitly forbids -- the renderer would draw a plausible, wrong map.
    """
    info = sniff(data)
    if info["format"] not in SUPPORTED:
        raise TileImageError("TILE_FORMAT_UNSUPPORTED",
                             f"{info['format']} is not supported; JPEG or PNG only", info)
    if info["width"] > ENGINE_TILE_PX or info["height"] > ENGINE_TILE_PX:
        raise TileImageError(
            "TILE_TOO_LARGE",
            f"{info['width']}x{info['height']} exceeds the renderer's "
            f"{ENGINE_TILE_PX}px limit"
            + (f"; source {source!r} serves oversized tiles" if source else "")
            + ". Storing it would require resampling, which this build cannot do "
              "(the shipped interpreter has no imaging library). Choose a source "
              "that serves 256x256 tiles.",
            dict(info, source=source, limit=ENGINE_TILE_PX))
    if info["width"] != ENGINE_TILE_PX or info["height"] != ENGINE_TILE_PX:
        raise TileImageError(
            "TILE_WRONG_SIZE",
            f"{info['width']}x{info['height']} is not {ENGINE_TILE_PX}x{ENGINE_TILE_PX}"
            + (f"; source {source!r}" if source else "")
            + ". It is not stretched to fit: the renderer would draw a plausible, "
              "wrong map.",
            dict(info, source=source, expected=ENGINE_TILE_PX))
    return info


def is_storable(data: bytes, *, source: str | None = None) -> tuple[bool, dict]:
    """check() as a verdict, for the packer's per-tile loop."""
    try:
        return True, check(data, source=source)
    except TileImageError as e:
        return False, {"code": e.code, "message": str(e), "evidence": e.evidence}
