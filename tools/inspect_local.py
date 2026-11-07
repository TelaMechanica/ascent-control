"""Offline review CLI for shared ASCENT helpers. No device or network operations."""
from pathlib import Path
import argparse
import json
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "runtime"))
import caddx_fw_version as version
import caddx_mgrs as mgrs
import caddx_tile_image as tile


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    v = commands.add_parser("version", help="Parse or compare firmware version labels")
    v.add_argument("value")
    v.add_argument("--compare")
    g = commands.add_parser("grid-encode", help="Convert WGS84 coordinates to MGRS")
    g.add_argument("latitude", type=float)
    g.add_argument("longitude", type=float)
    g.add_argument("--precision", type=int, choices=range(6), default=5)
    d = commands.add_parser("grid-decode", help="Convert MGRS to WGS84 coordinates")
    d.add_argument("reference")
    t = commands.add_parser("tile", help="Check local PNG/JPEG header and tile dimensions")
    t.add_argument("path", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "version":
            result = version.describe(args.value)
            if args.compare is not None:
                result["comparison"] = version.compare(args.value, args.compare)
                result["compared_with"] = args.compare
                result["known"] = result["known"] and version.parse(args.compare) is not None
            status = 0 if result["known"] else 2
        elif args.command == "grid-encode":
            result = {"mgrs": mgrs.to_mgrs(args.latitude, args.longitude, args.precision)}
            status = 0
        elif args.command == "grid-decode":
            lat, lon = mgrs.from_mgrs(args.reference)
            result = {"latitude": lat, "longitude": lon}
            status = 0
        else:
            result = tile.check(args.path.read_bytes())
            status = 0
    except (ValueError, OSError, tile.TileImageError) as exc:
        result = {"error": str(exc)}
        if hasattr(exc, "code"):
            result["code"] = exc.code
        status = 2
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return status


if __name__ == "__main__":
    raise SystemExit(main())
