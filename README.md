# Ascent Control shared code

This repository contains six executable Python helpers used by Ascent Control, their regression tests, and package/dependency contracts. Python 3.10 or later is required. The helpers and offline CLI use only the standard library.

## Included code

| Module | Behavior |
| --- | --- |
| `runtime/caddx_fw_version.py` | Parse firmware labels and compare numeric versions; preserve unknown results. |
| `runtime/caddx_crsf.py` | Encode/decode RC channel frames and HID channel mapping. |
| `runtime/caddx_msp.py` | Parse MSP frames, checksums and GPS/OSD data. |
| `runtime/caddx_msp_osd.py` | Reassemble MSP streams and decode DisplayPort character grids. |
| `runtime/caddx_mgrs.py` | Convert MGRS, UTM and WGS84 coordinates; reject unsupported polar regions. |
| `runtime/caddx_tile_image.py` | Inspect PNG/JPEG headers and enforce tile dimensions; does not decode pixels. |

The code runs locally without WSL or attached hardware. It does not include the full desktop application, Service Mode, receiver installation, widget deployment, vendor firmware or an MSI.

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
python -m pytest tests -q
python tools/check_public_runtime.py
python tools/check_tree.py
```

Tests use synthetic inputs and do not connect to devices. The source receipt pins imported bytes; the runtime checker verifies the inventory and standard-library dependency closure.

## Source and permissions

[Source review](docs/SOURCE_REVIEW.md) records origin, scope and the operator-reported Caddx verbal approval for CRSF/MSP. Existing provenance comments are retained. That report does not claim blanket rights to vendor firmware or private capabilities. Final project use/license terms remain under review; no broad resale or redistribution permission is added by publishing these files.

Service Mode remains private pending Caddx guidance. Widget releases that depend on it remain gated. See [current status](docs/STATUS.md) and [tasks](docs/TASKS.md) for the remaining application migration. This is a technical source snapshot, not a downloadable desktop release.
