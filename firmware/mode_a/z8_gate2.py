#!/usr/bin/env python3
"""Mode A Gate 2 for the Z8 direct-IMX586 candidate.

Reuses the proven Gate 2 machinery in mode_a_build.py (ASW/UBI/UBIFS CRC, index topology,
semantic inventory, compression-window, component hashes, fail-closed checks) without modifying
it: imports the module and overrides PHASE1_DELTA with the Z8 filesystem delta (process-local).
z40_build.py, Z40 Candidate1 and Z40 evidence are untouched.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import mode_a_build as M

Z8_DELTA = {
    "/fpv/ar_ldyhs_sky": ("replace", "e5995decf482824d4c3d815365fad7fdbb9c1392abecc031aa612489b3d7b280", 2761840),
    "/fpv/tunning/cam_imx586_50fps_z8_xg1.bin":
        ("add", "be8442b295ea7a57a09bd52e1fdd5e34bbdaa7798016378935742f0f3e9d85ec", 144722),
    "/fpv/tunning/cam_imx586_50fps_z8_xg2.bin":
        ("add", "085d84d0334fa81919b308405bbbaeec778f5ab09c7c9f973f0c29b4febaab4b", 144722),
    "/fpv/tunning/cam_imx586_50fps_z8_xg4.bin":
        ("add", "a7364b734de962ba5b3ad27adb8e42dafe923422580181fcb82b43bae33ae817", 144722),
}


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("donor", type=Path)
    ap.add_argument("--gate1-report", type=Path, required=True)
    ap.add_argument("--app", type=Path, required=True)          # verified z8 ar_ldyhs_sky
    ap.add_argument("--tuning-dir", type=Path, required=True)   # dir holding the 3 z8 tuning files
    ap.add_argument("--work", type=Path, required=True)
    ap.add_argument("--mkfs", type=Path, required=True)
    ap.add_argument("--verifier", default=M.DEFAULT_VERIFIER)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--report", type=Path, required=True)
    a = ap.parse_args()

    M.CAMERA_SUBTYPE = 'z8'
    M.PHASE1_DELTA = Z8_DELTA                                   # process-local override; file untouched
    sources = {"/fpv/ar_ldyhs_sky": str(a.app)}
    for p in Z8_DELTA:
        if p.startswith("/fpv/tunning/"):
            sources[p] = str(a.tuning_dir / Path(p).name)
    rep = M.gate2(a.donor, a.gate1_report, sources, a.work, a.mkfs, a.verifier, a.out)
    rep["gate"] = "mode_a_gate2_z8_direct"
    a.report.write_text(json.dumps(rep, indent=1, default=str))
    print(json.dumps({"PASS": rep["PASS"], **rep["image"]}, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
