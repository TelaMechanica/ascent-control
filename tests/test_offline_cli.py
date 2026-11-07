"""Exercise the runnable entry point with synthetic inputs, without hardware."""
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
ROOT = Path(__file__).resolve().parents[1]


def run(*args):
    result = subprocess.run([sys.executable, str(ROOT / "tools/inspect_local.py"), *args], cwd=ROOT.parent, capture_output=True, text=True)
    return result.returncode, json.loads(result.stdout)


class OfflineCLI(unittest.TestCase):
    def test_numeric_version_comparison_and_unknown(self):
        code, result = run("version", "19.2.14", "--compare", "19.2.4")
        self.assertEqual(code, 0)
        self.assertEqual(result["comparison"], 1)
        code, result = run("version", "unknown", "--compare", "19.2.4")
        self.assertEqual(code, 2)
        self.assertIsNone(result["comparison"])

    def test_grid_round_trip_and_unsupported_polar_region(self):
        code, result = run("grid-encode", "0", "0")
        self.assertEqual(code, 0)
        code, result = run("grid-decode", result["mgrs"])
        self.assertEqual(code, 0)
        self.assertLess(abs(result["latitude"]), 0.00002)
        self.assertLess(abs(result["longitude"]), 0.00002)
        code, result = run("grid-encode", "87", "10")
        self.assertEqual(code, 2)
        self.assertIn("UPS", result["error"])

    def test_tile_headers_and_file_errors(self):
        with tempfile.TemporaryDirectory() as work:
            path = Path(work) / "synthetic.png"
            # Header fixture only: the checker does not decode image content.
            path.write_bytes(bytes([137])+b"PNG\r\n"+bytes([26])+b"\n"+struct.pack(">I",13)+b"IHDR"+struct.pack(">II",256,256))
            code, result = run("tile", str(path))
            self.assertEqual(code, 0)
            self.assertEqual(result["width"], 256)
            path.write_bytes(b"invalid")
            code, result = run("tile", str(path))
            self.assertEqual(code, 2)
            self.assertIn("code", result)
            code, result = run("tile", str(Path(work) / "missing.png"))
            self.assertEqual(code, 2)
            self.assertIn("error", result)
