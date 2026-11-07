"""MGRS <-> WGS84, for entering a map centre by grid reference.

Pure arithmetic: no dependency, no network, no data files. Implemented because an
operator working from a map or a briefing has an MGRS string, not a decimal
latitude, and retyping it as degrees is where transcription errors get made.

Chain is MGRS -> UTM -> geodetic. The UTM projection here is the standard
Krueger series to fourth order on WGS84, which is accurate to well under a metre
inside a zone -- far finer than a map tile at any zoom this tool produces, where
one pixel is ~0.6 m at z18.

Two conventions that are easy to get wrong and are tested:

* **The 100 km square lettering repeats every three zones**, and the row letters
  are offset by half the alphabet on even-numbered zones. Getting the parity wrong
  puts you 100 km north or south -- a plausible-looking answer in the wrong field.
* **`I` and `O` are omitted** from both column and row alphabets, because they are
  confusable with 1 and 0.

The polar regions (UPS, bands A/B/Y/Z) are **not** implemented. They are refused by
name rather than silently mis-projected.
"""

from __future__ import annotations

import math
import re

# WGS84
_A = 6378137.0
_F = 1 / 298.257223563
_E2 = _F * (2 - _F)
_K0 = 0.9996

_BANDS = "CDEFGHJKLMNPQRSTUVWX"          # 8-degree latitude bands, -80..84, no I or O
_COL = "ABCDEFGHJKLMNPQRSTUVWXYZ"        # no I, no O
_ROW = "ABCDEFGHJKLMNPQRSTUV"            # no I, no O, 20 letters

_MGRS_RE = re.compile(
    r'^\s*(\d{1,2})\s*([C-HJ-NP-X])\s*([A-HJ-NP-Z])([A-HJ-NP-V])\s*(\d*)\s*$',
    re.IGNORECASE)


class MgrsError(ValueError):
    pass


def _band(lat: float) -> str:
    if lat < -80 or lat > 84:
        raise MgrsError(f'latitude {lat} is outside the MGRS grid zones (-80..84); '
                        f'the polar UPS bands A, B, Y and Z are not supported')
    idx = int((lat + 80) // 8)
    return _BANDS[min(idx, len(_BANDS) - 1)]


def _zone(lat: float, lon: float) -> int:
    zone = int((lon + 180) // 6) + 1
    # The two standard exceptions. Getting these wrong puts a position in the
    # neighbouring zone, which is a 6-degree error in longitude.
    if 56 <= lat < 64 and 3 <= lon < 12:
        zone = 32
    elif 72 <= lat < 84:
        if 0 <= lon < 9:
            zone = 31
        elif 9 <= lon < 21:
            zone = 33
        elif 21 <= lon < 33:
            zone = 35
        elif 33 <= lon < 42:
            zone = 37
    return zone


def to_utm(lat: float, lon: float) -> tuple[int, str, float, float]:
    """(zone, band, easting, northing) on WGS84."""
    band = _band(lat)
    zone = _zone(lat, lon)
    lon0 = math.radians((zone - 1) * 6 - 180 + 3)
    p, l = math.radians(lat), math.radians(lon)
    n = _F / (2 - _F)
    n2, n3, n4 = n * n, n ** 3, n ** 4
    aa = _A / (1 + n) * (1 + n2 / 4 + n4 / 64)
    a1 = n / 2 - 2 * n2 / 3 + 5 * n3 / 16
    a2 = 13 * n2 / 48 - 3 * n3 / 5
    a3 = 61 * n3 / 240
    a4 = 49561 * n4 / 161280
    e = math.sqrt(_E2)
    t = math.sinh(math.atanh(math.sin(p)) - e * math.atanh(e * math.sin(p)))
    xi = math.atan(t / math.cos(l - lon0))
    eta = math.atanh(math.sin(l - lon0) / math.sqrt(1 + t * t))
    east = _K0 * aa * (eta + a1 * math.cos(2 * xi) * math.sinh(2 * eta)
                       + a2 * math.cos(4 * xi) * math.sinh(4 * eta)
                       + a3 * math.cos(6 * xi) * math.sinh(6 * eta)
                       + a4 * math.cos(8 * xi) * math.sinh(8 * eta)) + 500000.0
    north = _K0 * aa * (xi + a1 * math.sin(2 * xi) * math.cosh(2 * eta)
                        + a2 * math.sin(4 * xi) * math.cosh(4 * eta)
                        + a3 * math.sin(6 * xi) * math.cosh(6 * eta)
                        + a4 * math.sin(8 * xi) * math.cosh(8 * eta))
    if lat < 0:
        north += 10000000.0
    return zone, band, east, north


def from_utm(zone: int, north_hemisphere: bool, east: float, north: float) -> tuple[float, float]:
    lon0 = math.radians((zone - 1) * 6 - 180 + 3)
    if not north_hemisphere:
        north -= 10000000.0
    n = _F / (2 - _F)
    n2, n3, n4 = n * n, n ** 3, n ** 4
    aa = _A / (1 + n) * (1 + n2 / 4 + n4 / 64)
    b1 = n / 2 - 2 * n2 / 3 + 37 * n3 / 96
    b2 = n2 / 48 + n3 / 15
    b3 = 17 * n3 / 480
    d1 = 2 * n - 2 * n2 / 3 - 2 * n3
    d2 = 7 * n2 / 3 - 8 * n3 / 5
    d3 = 56 * n3 / 15
    xi = north / (_K0 * aa)
    eta = (east - 500000.0) / (_K0 * aa)
    xi2 = (xi - b1 * math.sin(2 * xi) * math.cosh(2 * eta)
           - b2 * math.sin(4 * xi) * math.cosh(4 * eta)
           - b3 * math.sin(6 * xi) * math.cosh(6 * eta))
    eta2 = (eta - b1 * math.cos(2 * xi) * math.sinh(2 * eta)
            - b2 * math.cos(4 * xi) * math.sinh(4 * eta)
            - b3 * math.cos(6 * xi) * math.sinh(6 * eta))
    chi = math.asin(max(-1.0, min(1.0, math.sin(xi2) / math.cosh(eta2))))
    lat = chi + (d1 * math.sin(2 * chi) + d2 * math.sin(4 * chi) + d3 * math.sin(6 * chi))
    lon = lon0 + math.atan(math.sinh(eta2) / math.cos(xi2))
    return math.degrees(lat), math.degrees(lon)


def to_mgrs(lat: float, lon: float, precision: int = 5) -> str:
    """Format as MGRS. `precision` is digits per axis: 5 = 1 m, 4 = 10 m, 1 = 10 km."""
    if precision not in (0, 1, 2, 3, 4, 5):
        raise MgrsError('precision must be 0..5 digits per axis')
    zone, band, east, north = to_utm(lat, lon)
    # Column letters cycle A-Z (less I, O) in three 8-letter sets by zone mod 3.
    col_set = (zone - 1) % 3
    col = _COL[col_set * 8 + int(east // 100000) - 1]
    # Row letters run A..V, and start half an alphabet along on even zones.
    row_base = 0 if zone % 2 else 5
    row = _ROW[(row_base + int(north // 100000)) % 20]
    if precision == 0:
        return f'{zone}{band}{col}{row}'
    div = 10 ** (5 - precision)
    e = int((east % 100000) // div)
    n = int((north % 100000) // div)
    return f'{zone}{band}{col}{row}{e:0{precision}d}{n:0{precision}d}'


def from_mgrs(text: str) -> tuple[float, float]:
    """Parse an MGRS string to (lat, lon). Accepts spaces and either case."""
    m = _MGRS_RE.match(text or '')
    if not m:
        raise MgrsError(f'{text!r} is not an MGRS grid reference. Expected something '
                        f'like 18SUJ2348706483 (zone, band, two square letters, then '
                        f'an even number of digits).')
    zone = int(m.group(1))
    band = m.group(2).upper()
    col, row = m.group(3).upper(), m.group(4).upper()
    digits = m.group(5)
    if not 1 <= zone <= 60:
        raise MgrsError(f'UTM zone {zone} is out of range (1..60)')
    if len(digits) % 2:
        raise MgrsError('the numeric part must have the same number of digits for '
                        'easting and northing')
    if col not in _COL or row not in _ROW:
        raise MgrsError(f'{col}{row} is not a valid 100 km square '
                        f'(I and O are never used)')

    col_set = (zone - 1) % 3
    ci = _COL.index(col) - col_set * 8
    if not 0 <= ci <= 7:
        raise MgrsError(f'100 km column {col} does not occur in zone {zone}')
    east_100k = (ci + 1) * 100000

    row_base = 0 if zone % 2 else 5
    ri = (_ROW.index(row) - row_base) % 20
    north_100k = ri * 100000

    half = len(digits) // 2
    if half:
        mul = 10 ** (5 - half)
        east_100k += int(digits[:half]) * mul
        north_100k += int(digits[half:]) * mul

    # The row letters repeat every 2,000 km, so the band fixes which cycle we are in.
    band_idx = _BANDS.index(band)
    approx_lat = -80 + band_idx * 8 + 4
    _, _, _, band_north = to_utm(approx_lat, (zone - 1) * 6 - 180 + 3)
    if approx_lat < 0:
        band_north -= 10000000.0
    cycles = round((band_north - north_100k) / 2000000.0)
    north = north_100k + cycles * 2000000.0
    north_hemisphere = band >= 'N'
    if not north_hemisphere:
        north += 10000000.0
    return from_utm(zone, north_hemisphere, east_100k, north)


def selftest() -> dict:
    # Washington Monument, a standard reference point.
    lat, lon = 38.8894838, -77.0352791
    s = to_mgrs(lat, lon, 5)
    assert s.startswith('18S'), s
    back = from_mgrs(s)
    assert abs(back[0] - lat) < 2e-5 and abs(back[1] - lon) < 2e-5, (s, back)
    # Round trip a spread of points, both hemispheres and both zone parities.
    for la, lo in ((51.4778, -0.0015), (-33.8568, 151.2153), (35.6586, 139.7454),
                   (-22.9519, -43.2105), (64.1355, -21.8954), (1.3521, 103.8198)):
        r = from_mgrs(to_mgrs(la, lo, 5))
        assert abs(r[0] - la) < 2e-5 and abs(r[1] - lo) < 2e-5, (la, lo, r)
    return {'ok': True}


if __name__ == '__main__':
    print(selftest())
