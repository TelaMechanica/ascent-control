#!/usr/bin/env python3
"""Mode A Gate 2 for the Hub direct-interposer candidate (19.2.14 base, f166927f...).

Reuses mode_a_build.py's Gate 2 machinery (ASW/UBI/UBIFS CRC, index topology, semantic inventory,
compression-window, fail-closed mutation tests), overriding PHASE1_DELTA with the Hub filesystem
delta (process-local). The Hub delta uses explicit per-file metadata and one new directory
(/fpv/boot_lt6911uxe) -- supported by mode_a_build's backward-compatible 4-tuple / "mkdir" forms;
3-tuple deltas (z8/z40) are unaffected. z8/z40 builders and candidates are untouched.

Delta = replace the transplanted app + the hub-pinmux sys_config.ko; add the hub runtime the app
needs (configs use persistent /factory uploads first, packaged /usrdata/fpv seeds only when absent; LT6911UXE
firmware; imx586/farsight tuning). No boot script changes: hub bring-up is app-driven.
"""
from __future__ import annotations
import json, sys
from pathlib import Path
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import mode_a_build as M

HUB_DELTA = {
    "/fpv/ar_ldyhs_sky": ("replace", "9c7117c8f863309484e7b0137f99b22090e79f4215c6a636b9714b11c862c829", 2656876),
    "/fpv/ko_cv610_20s/sys_config.ko": ("replace", "3cf9abbee1682ff12b2bf4db5230a70ba0cfa15ad48c92eb5a36a18c67bc5464", 13592),
    "/fpv/boot_lt6911uxe": ("mkdir", "", 0, {'mode': 16893, 'uid': 0, 'gid': 0, 'flags': 1, 'mtime': (1784863661, 0), 'atime': (1784863661, 0), 'nlink': 2}),
    "/fpv/mipi_hub.json": ("add", "50b28cfa85335b31ac1d82be6a76a2960a77ab6f025b500f5abd2c8c871b6191", 580, {'mode': 33204, 'uid': 0, 'gid': 0, 'flags': 1, 'mtime': (1784863661, 0), 'atime': (1784863661, 0), 'nlink': 1}),
    "/fpv/mipi_hub.ini": ("add", "edb6b910ad9ae387c2b7c76bce7833a8ce5440817812d026c14f1c8e2ffeaa6d", 173, {'mode': 33204, 'uid': 0, 'gid': 0, 'flags': 1, 'mtime': (1784863661, 0), 'atime': (1784863661, 0), 'nlink': 1}),
    "/fpv/msp_rc_cfg.json": ("add", "6e3809b8722fdb0a8dbcb25ad482db7af3e85e0cb9e82ddbf7e98c356ea138f7", 252, {'mode': 33204, 'uid': 0, 'gid': 0, 'flags': 1, 'mtime': (1784863661, 0), 'atime': (1784863661, 0), 'nlink': 1}),
    "/fpv/fpv_mipihub_ctrl.sh": ("add", "766a4a0300a968712f495736c32f869fa116d1269cb71292f9371e8fe433e513", 6623, {'mode': 33277, 'uid': 0, 'gid': 0, 'flags': 1, 'mtime': (1784863661, 0), 'atime': (1784863661, 0), 'nlink': 1}),
    "/fpv/boot_lt6911uxe/LT6911UXE_H2CSI_1920x1080_SV2_8_26020601.bin": ("add", "4171b74e9888c91f9f312587cbb95f392fa2b25af5a9c626a1fdaa2c99c73918", 32768, {'mode': 33204, 'uid': 0, 'gid': 0, 'flags': 1, 'mtime': (1784863661, 0), 'atime': (1784863661, 0), 'nlink': 1}),
    "/fpv/boot_lt6911uxe/edid_1920x1080.bin": ("add", "eaa8909b38428ab148a0c36a6c804c02d305dc22ca20f00b3776e849394d63c1", 120, {'mode': 33204, 'uid': 0, 'gid': 0, 'flags': 1, 'mtime': (1784863661, 0), 'atime': (1784863661, 0), 'nlink': 1}),
    "/fpv/boot_lt6911uxe/lt6911uxe_upgrade": ("add", "22ba1da054cc18ec7135037c480f3da17a0329221cfac9b418a173ec10eb96a6", 12192, {'mode': 33277, 'uid': 0, 'gid': 0, 'flags': 1, 'mtime': (1784863661, 0), 'atime': (1784863661, 0), 'nlink': 1}),
    "/fpv/tunning/cam_imx586_50fps_z8_xg1.bin": ("add", "be8442b295ea7a57a09bd52e1fdd5e34bbdaa7798016378935742f0f3e9d85ec", 144722, {'mode': 33277, 'uid': 0, 'gid': 0, 'flags': 1, 'mtime': (1784863661, 0), 'atime': (1784863661, 0), 'nlink': 1}),
    "/fpv/tunning/cam_imx586_50fps_z8_xg2.bin": ("add", "085d84d0334fa81919b308405bbbaeec778f5ab09c7c9f973f0c29b4febaab4b", 144722, {'mode': 33277, 'uid': 0, 'gid': 0, 'flags': 1, 'mtime': (1784863661, 0), 'atime': (1784863661, 0), 'nlink': 1}),
    "/fpv/tunning/cam_imx586_50fps_z8_xg4.bin": ("add", "a7364b734de962ba5b3ad27adb8e42dafe923422580181fcb82b43bae33ae817", 144722, {'mode': 33277, 'uid': 0, 'gid': 0, 'flags': 1, 'mtime': (1784863661, 0), 'atime': (1784863661, 0), 'nlink': 1}),
    "/fpv/tunning/cam_imx586_50fps_z40_xg1.bin": ("add", "a3fbd5a0bb4726e70a0147c73d3dab76e2cd4dff628dc6771b6b0e2125ad5f3a", 144722, {'mode': 33277, 'uid': 0, 'gid': 0, 'flags': 1, 'mtime': (1784863661, 0), 'atime': (1784863661, 0), 'nlink': 1}),
    "/fpv/tunning/cam_imx586_50fps_z40_xg2.bin": ("add", "2d0a8da754e03e4b35c92e8794f76e10b8e4ab12dab3aca80cd4fd7acb150db7", 144722, {'mode': 33277, 'uid': 0, 'gid': 0, 'flags': 1, 'mtime': (1784863661, 0), 'atime': (1784863661, 0), 'nlink': 1}),
    "/fpv/tunning/cam_imx586_50fps_z40_xg4.bin": ("add", "4f6f5f4cee5d29ad01d5ca0af67f7fb514ecea63fc6745772eeae1be12362b09", 144722, {'mode': 33277, 'uid': 0, 'gid': 0, 'flags': 1, 'mtime': (1784863661, 0), 'atime': (1784863661, 0), 'nlink': 1}),
    "/fpv/tunning/cam_ps5280_50fps_z40.bin": ("add", "8965b2a0ac37f2e012238d209bcad0dc33988dc112600565f0d17139dd46e048", 144722, {'mode': 33277, 'uid': 0, 'gid': 0, 'flags': 1, 'mtime': (1784863661, 0), 'atime': (1784863661, 0), 'nlink': 1}),
}


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("donor", type=Path)
    ap.add_argument("--gate1-report", type=Path, required=True)
    ap.add_argument("--app", type=Path, required=True)        # verified hub ar_ldyhs_sky
    ap.add_argument("--staging", type=Path, required=True)    # dir of staged add/replace files
    ap.add_argument("--work", type=Path, required=True)
    ap.add_argument("--mkfs", type=Path, required=True)
    ap.add_argument("--verifier", default=M.DEFAULT_VERIFIER)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--report", type=Path, required=True)
    a = ap.parse_args()

    M.CAMERA_SUBTYPE = 'Hub'
    M.PHASE1_DELTA = HUB_DELTA                                # process-local override; file untouched
    sources = {"/fpv/ar_ldyhs_sky": str(a.app)}
    for p, entry in HUB_DELTA.items():
        if p == "/fpv/ar_ldyhs_sky" or entry[0] == "mkdir":
            continue                                         # mkdir has no source file
        sources[p] = str(a.staging / p.replace("/", "_"))
    rep = M.gate2(a.donor, a.gate1_report, sources, a.work, a.mkfs, a.verifier, a.out)
    rep["gate"] = "mode_a_gate2_hub_direct"
    a.report.write_text(json.dumps(rep, indent=1, default=str))
    print(json.dumps({"PASS": rep["PASS"], **rep["image"]}, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
