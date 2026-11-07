# Ascent Control shared code

This repository contains six shared Python helpers, their offline CLI and regression tests, plus standalone Z8, Z40 and Hub firmware grafting source. Python 3.10 or later is required. The six shared helpers use only the standard library; camera grafting uses additional pinned dependencies and external tools.

## Included code

| Module | Behavior |
| --- | --- |
| `runtime/caddx_fw_version.py` | Parse firmware labels and compare numeric versions; preserve unknown results. |
| `runtime/caddx_crsf.py` | Encode/decode RC channel frames and HID channel mapping. |
| `runtime/caddx_msp.py` | Parse MSP frames, checksums and GPS/OSD data. |
| `runtime/caddx_msp_osd.py` | Reassemble MSP streams and decode DisplayPort character grids. |
| `runtime/caddx_mgrs.py` | Convert MGRS, UTM and WGS84 coordinates; reject unsupported polar regions. |
| `runtime/caddx_tile_image.py` | Inspect PNG/JPEG headers and enforce tile dimensions; does not decode pixels. |

The six shared helpers run locally without WSL or attached hardware. Camera-grafting tool requirements are documented separately. This repository does not include the full desktop application, Service Mode, receiver installation, widget deployment, vendor firmware or an MSI.

## Camera grafting source

[Camera CLI instructions](docs/CAMERA_GRAFTING.md) cover source-image extraction, unchanged-donor gate 1, application build and independent verification, and target-specific gate 2. Vendor images and extracted assets are supplied locally and are not included. The current grafts target normal 19.2.14; these host checks do not establish hardware qualification.

## Run the offline tools

From the repository root:

```sh
python tools/inspect_local.py version 19.2.14 --compare 19.2.4
python tools/inspect_local.py grid-encode 0 0
python tools/inspect_local.py grid-decode 31NAA6602100000
python tools/inspect_local.py tile path/to/tile.png
```

Commands print JSON. Exit status 2 indicates invalid, unsupported or unknown input. The version comparison is numeric, so `19.2.14` is newer than `19.2.4`. The grid example uses a synthetic location. The tile command checks the container header and dimensions only.

To use a module directly:

```python
import sys
sys.path.insert(0, "runtime")
import caddx_crsf
import caddx_fw_version

print(caddx_fw_version.compare("19.2.14", "19.2.4"))
print(caddx_crsf.crc8_d5(bytes([1, 2, 3])))
```

## Run tests and source checks

```sh
python -m pip install -r requirements-dev.txt
python -m pip install --require-hashes -r firmware/mode_a/requirements-builder.txt
python -m pytest tests -q
python tools/check_public_runtime.py
python tools/check_camera_source.py
python tools/check_tree.py
```

Default tests use synthetic inputs and do not connect to devices. Camera GOT/PLT tests require external ARM binutils; see the camera instructions. The source receipt pins imported bytes; the runtime checker verifies the inventory and standard-library dependency closure.

## Source and permissions

[Source inventory](docs/SOURCE_REVIEW.md) lists the imported modules, hashes and dependency scope. Existing technical attribution is retained. Final project use/license terms remain under review; third-party material retains its own terms.

Service Mode and dependent widget deployment are not included. See [current status](docs/STATUS.md) and [tasks](docs/TASKS.md) for the remaining application migration. This is a technical source snapshot, not a downloadable desktop release.
