# ASCENT Control

ASCENT Control is a Windows application for ASCENT device configuration, live
status, firmware inspection and management, RF and RC management where supported,
and a local fleet registry. This repository contains the public desktop source,
Windows MSI build tooling, shared protocol helpers and camera-image builders.

Service Mode and operations that depend on it, including receiver widget
deployment and Picker, belong to AC+ and are excluded from this repository.

## Download and test

Download the Windows x64 MSI from [Releases](https://github.com/TelaMechanica/ascent-control/releases).
The installer includes its Python and media runtimes, native firmware tools,
Z8/Z40/Hub camera support and the HD Pro tester profile. WSL and separate camera
source images are unnecessary for the included donor-only builders. Supply your
own exact normal 19.2.14 donor image. The app does not include that full image.

HD Pro is included for tester builds in this first release. Its output is
`Ascent_G_Sky_19_2_14_HDPro_1.img`. Build checks establish donor identity,
application patch identity and image/filesystem integrity; physical boot, capture,
timing and image quality remain unqualified. See [HD Pro details](firmware/hdpro/README.md).

The MSI is unsigned. Microsoft Edge WebView2 Runtime is required by the desktop
host. Report reproducible problems through [Issues](https://github.com/TelaMechanica/ascent-control/issues),
including the application version, steps and sanitized error text. For image
builder reports include the target, donor hash and output hash. Remove personal
paths and device identifiers before uploading logs.

## Tested hardware and firmware

**19.2.14 is AC's primary tested firmware baseline.** The following hardware was
connected to AC on the listed firmware and updated using the corresponding image:

| Hardware | Firmware when connected | Image installed using AC |
|---|---|---|
| Conventional VRX / Ground | 16.5.3, 17.5.3, 18.21.3, 19.2.4 | `Ascent_G_Gnd_19_2_14.img` |
| VRX Max HF | 18.21.7 | `Ascent_VRX_Max_19_2_14.img` |
| VRX Max WF | 19.2.4 | `Ascent_VRX_Max_19_2_14.img` |
| GT Pro / Sky | 19.2.13 | `Ascent_G_Sky_19_2_14.img` |
| Relay | 19.2.9 | `Ascent_Relay_19_2_14.img` |
| GT Pro Z40 | 16.5.8; subsequent custom 19.2.14 reflashes | `Ascent_G_Sky_19_2_14_z40_1.img` |

Connection testing also includes **VRX Pro on 18.21.10**.

## Build the Windows MSI

Install .NET SDK 8.0.424 on Windows x64. From PowerShell in a fresh checkout:

```powershell
.\tools\Build-Installer.ps1 -OutputDir .\artifacts\release
```

The script downloads hash-pinned public release inputs and stages pinned Python
and GStreamer dependencies. It restores WiX 5.0.2, freezes the reviewed source
inventory, builds the desktop host, verifies the packaged runtime, tests the media
runtime, builds an MSI and administratively extracts it to compare every payload
file. It does not install or launch AC or access hardware. Use a fresh output
folder for repeat builds; previous output is preserved.

For offline input archives, pass `-NativeArchive` and `-CameraArchive` with the
matching release ZIP paths. `-DependencyCache` accepts only the exact per-file
Python and GStreamer hashes recorded in `release/public-payload.json`.
The Windows build workflow uses these same checks from a fresh Git checkout.

## Source checks

```sh
python -m pip install -r requirements-dev.txt
python -m pip install --require-hashes -r firmware/mode_a/requirements-builder.txt
python -m pytest tests -q
python tools/check_public_runtime.py
python tools/check_camera_source.py
python tools/check_tree.py
```

Camera relocation tests use ARM binutils. No default test connects to hardware.
See [camera CLI instructions](docs/CAMERA_GRAFTING.md) for standalone source tools.
The original six standard-library shared helpers and their source-hash contract
remain available through `tools/inspect_local.py`.

## Permissions and third-party material

Copyright 2026 TelaMechanica, the sole ASCENT Control contributor. Original
project material is provided under the [Personal and Private Use License](LICENSE):
personal, hobbyist development, educational and private professional use, with
attribution. Third-party sale, redistribution and product reuse are restricted.
The [scope inventory](PROJECT_LICENSE_SCOPE.json) identifies original project
material; separately licensed material retains its own terms.

Read [third-party notices](THIRD-PARTY-NOTICES.md) and the
[source inventory](THIRD-PARTY-SOURCES.json). Matching source archives accompany
native helper/tool binaries in the release. Vendor-origin camera material retains
its existing rights; the project license grants no rights to vendor IP.
