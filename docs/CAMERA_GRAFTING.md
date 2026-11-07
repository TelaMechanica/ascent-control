# Standalone camera grafting source

The source in `firmware/mode_a` builds Z8, Z40 and Hub application grafts against the frozen normal 19.2.14 donor layout. It includes independent ELF/emulation verifiers and two image gates. Gate 1 rebuilds the donor without semantic changes; gate 2 applies only the frozen per-target delta and verifies the resulting image. These are offline host checks, not hardware qualification. An unknown donor or failed check requires investigation; do not bypass the check.

The desktop MSI includes a manifest-pinned camera support pack with the extracted applications and support data needed for donor-only Z8/Z40/Hub builds. The complete donor image is supplied by the user. The standalone source-image CLI below remains available. Project permissions are in LICENSE; vendor and third-party material retain their own rights and terms.

## Tools and dependencies

Use Python 3.10 or later. From the repository root on Linux x86_64:

```sh
python -m venv .venv
. .venv/bin/activate
python -m pip install --require-hashes -r firmware/mode_a/requirements-builder.txt
python -m pip install -r requirements-dev.txt
```

The adjacent Windows requirements file pins Windows x86_64 wheels. Python packages are Capstone 5.0.9, pyelftools 0.33 and Unicorn 2.1.4. Platform-specific wheel hashes are intentional. No package installation happens automatically.

Application assembly requires the external Arm GNU Embedded 10-2020-q4-major toolchain (`arm-none-eabi-as`, `ld`, `nm`, `objcopy`, `objdump`). Obtain the official release from Arm and validate its published archive checksum before extraction. Set `ASCENT_ARM_TOOLCHAIN_DIR` to its absolute `bin` directory. The default is `/opt/gcc-arm-none-eabi-10-2020-q4-major/bin`. No compiler binaries are included here. CI uses distribution-provided ARM binutils for synthetic fixtures only; it does not qualify firmware outputs with that toolchain.

Full image reconstruction additionally requires external `mkfs.ubifs` and `fakeroot` on Linux. The Windows desktop release instead includes a pinned native bundle and metadata adapter, with source and license inventories. Use the Firmware panel for donor-only builds without WSL. These standalone instructions describe the Linux CLI route. Keep external tools under their own licenses.

## Inputs and extraction

Use separate empty work directories. The pinned source roles are:

| Role | Source image |
| --- | --- |
| `n19` | Normal 19.2.14 donor |
| `hub` | Hub 18.21.4 |
| `z40` | Dedicated Z40 17.5.8 |
| `z8` | Dedicated Z8 17.5.8 |
| `n18213` | Normal 18.21.3, required for Hub comparison |

Run extraction for each role needed by the selected target:

```sh
python firmware/mode_a/extract.py inputs/normal19.2.14.img work/n19
python firmware/mode_a/extract.py inputs/hub18.21.4.img work/hub
python firmware/mode_a/extract.py inputs/z40-17.5.8.img work/z40
python firmware/mode_a/extract.py inputs/z8-17.5.8.img work/z8
python firmware/mode_a/extract.py inputs/normal18.21.3.img work/n18213
```

The application path beneath each extraction is `usrdata/fpv/ar_ldyhs_sky`. Extraction records symlink targets in its manifest rather than requiring host symlinks. Full inode metadata for reconstruction is re-read from the donor image, not inferred from the extracted host directory.

## Gate 1, application build and verification

Export `MKFS` as an environment variable containing the absolute path to an external `mkfs.ubifs`. First establish an unchanged-donor reconstruction:

```sh
python firmware/mode_a/mode_a_build.py inputs/normal19.2.14.img --work work/gate1 --mkfs "$MKFS" --out work/gate1.img --report work/gate1.json
```

Build and independently verify the selected application. These examples show all three alternatives:

```sh
python firmware/mode_a/z40_build.py --hub work/hub/usrdata/fpv/ar_ldyhs_sky --n19 work/n19/usrdata/fpv/ar_ldyhs_sky --z40 work/z40/usrdata/fpv/ar_ldyhs_sky --out work/z40.elf --report work/z40.json
python firmware/mode_a/verify_z40_app.py work/hub/usrdata/fpv/ar_ldyhs_sky work/n19/usrdata/fpv/ar_ldyhs_sky work/z40.elf work/z40.json work/z40/usrdata/fpv/ar_ldyhs_sky
python firmware/mode_a/z8_build.py --hub work/hub/usrdata/fpv/ar_ldyhs_sky --n19 work/n19/usrdata/fpv/ar_ldyhs_sky --z8 work/z8/usrdata/fpv/ar_ldyhs_sky --out work/z8.elf --report work/z8.json
python firmware/mode_a/verify_z8_app.py work/hub/usrdata/fpv/ar_ldyhs_sky work/n19/usrdata/fpv/ar_ldyhs_sky work/z8.elf work/z8.json work/z8/usrdata/fpv/ar_ldyhs_sky
python firmware/mode_a/hub_build.py --hub work/hub/usrdata/fpv/ar_ldyhs_sky --n19 work/n19/usrdata/fpv/ar_ldyhs_sky --n18213 work/n18213/usrdata/fpv/ar_ldyhs_sky --out work/hub.elf --report work/hub.json
python firmware/mode_a/verify_hub_app.py work/hub/usrdata/fpv/ar_ldyhs_sky work/n19/usrdata/fpv/ar_ldyhs_sky work/hub.elf work/hub.json
```

Require a successful exit and `RESULT: PASS` from the application verifier before gate 2. The Z40 verifier also reads the four adjacent Hub tuning files. Preserve the extracted directory layout and full source ELFs: symbol tables, relocations and original instruction streams support independent checks.

## Gate 2

Z8 uses the three tuning files in the extracted Hub tuning directory:

```sh
python firmware/mode_a/z8_gate2.py inputs/normal19.2.14.img --gate1-report work/gate1.json --app work/z8.elf --tuning-dir work/hub/usrdata/fpv/tunning --work work/z8-gate2 --mkfs "$MKFS" --out work/z8.img --report work/z8-gate2.json
```

Z40 accepts an explicit source for every frozen overlay path. Build that argument list from the checked-in delta table, resolving the application locally and the four tuning files from Hub extraction:

```sh
python - <<'PY'
import subprocess, sys
from pathlib import Path
sys.path.insert(0, 'firmware/mode_a')
import mode_a_build as M
args = [sys.executable, 'firmware/mode_a/mode_a_build.py', 'inputs/normal19.2.14.img', '--gate2', '--gate1-report', 'work/gate1.json', '--work', 'work/z40-gate2', '--mkfs', __import__('os').environ['MKFS'], '--out', 'work/z40.img', '--report', 'work/z40-gate2.json']
for path in M.PHASE1_DELTA:
    source = Path('work/z40.elf') if path == '/fpv/ar_ldyhs_sky' else Path('work/hub/usrdata') / path.lstrip('/')
    args += ['--source', path + '=' + str(source)]
subprocess.run(args, check=True)
PY
```

Hub expects its 15 non-application assets in a flat staging directory, with `/` in each device path replaced by `_`. Prepare the staging directory from your extracted Hub image:

```sh
python - <<'PY'
import shutil, sys
from pathlib import Path
sys.path.insert(0, 'firmware/mode_a')
from hub_gate2 import HUB_DELTA
out = Path('work/hub-staging'); out.mkdir(exist_ok=False)
for path, spec in HUB_DELTA.items():
    if path == '/fpv/ar_ldyhs_sky' or spec[0] == 'mkdir':
        continue
    shutil.copyfile(Path('work/hub/usrdata') / path.lstrip('/'), out / path.replace('/', '_'))
PY
python firmware/mode_a/hub_gate2.py inputs/normal19.2.14.img --gate1-report work/gate1.json --app work/hub.elf --staging work/hub-staging --work work/hub-gate2 --mkfs "$MKFS" --out work/hub.img --report work/hub-gate2.json
```

Gate 2 checks source hashes, image geometry, semantic differences, updater identity and device deflate constraints. Reports may contain paths from your local inputs; inspect them before sharing. No command here flashes a device.

## Regression tests and provenance

```sh
python -m pytest tests -q
python tools/check_camera_source.py
python tools/check_public_runtime.py
python tools/check_tree.py
```

Camera synthetic tests exercise real relocation logic, address-shaped scalar preservation, cross-basic-block GOT provenance and actual PLT instruction resolution. GOT/PLT assembly tests need the Arm tools. These tests do not prove behavior on physical cameras.

`image_tests` retains adversarial full-image tests. Run each file separately with `PYTHONPATH=firmware/mode_a` and its documented image environment variables. Without those external images, tests skip; skips are not qualification evidence. Hub tests select a Hub delta at import time, so do not combine target image suites in one Python process.

`CAMERA_SOURCE_RECEIPT.json` pins the exported source inventory. `tools/check_camera_source.py` verifies its hashes and permits only adjacent source modules, the Python standard library and the three declared external packages. Dynamic image parser loading is limited by the CLI verifier path; the adjacent parser is included. The three `hooks/*-identity-hook.s` files are project assembly sources for the embedded identity-hook bytes in `variant_identity.py`; these are not vendor updater binaries. Existing source comments and technical attribution are preserved. This export contains no AC Service Mode implementation.

## Smaller local inputs

The desktop release includes the reviewed support pack: 19 deduplicated payloads,
11,292,206 bytes, excluding donor, outputs and manifest. They include four
vendor ELFs and 15 Hub assets. Their hashes, sizes and source provenance are
recorded by the pack manifest and validated before use. Source-only CLI users
can still supply the full source images through the commands above.

HD Pro uses a separate exact-donor profile and portable application patch,
included in this first release for tester builds. See
[HD Pro instructions](../firmware/hdpro/README.md). It does not require Z8/Z40/Hub
source images. Physical camera operation remains unqualified.
