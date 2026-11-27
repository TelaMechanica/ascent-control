# ASCENT Control

ASCENT Control is a Windows application for ASCENT device configuration, live
status, firmware inspection and management, RF and RC management where supported,
and a local fleet registry. This repository contains the public desktop source,
Windows MSI build tooling, shared protocol helpers and camera-image builders.

## Editions and release status

ASCENT Control ships as two Windows products built from one core:

- **AC** — the base edition.
- **AC+** — adds **one-touch Service Mode** for managed receiver access.

Both share one Windows installer lineage and differ only by an edition stamp
written at the install root. Service Mode is available in **AC+ only**; the AC
edition does not expose it.

| Version | Editions | Scope |
|---|---|---|
| 0.50.2 | AC, AC+ | AC base; AC+ adds one-touch Service Mode (below). Paired Windows MSI release. |
| [0.43.63](https://github.com/TelaMechanica/ascent-control/releases/tag/v0.43.63) | AC | Prior public AC with local Widget SDK preview inspection |

Download the current installers from
[Releases](https://github.com/TelaMechanica/ascent-control/releases).

### One-touch Service Mode (AC+)

AC+ provides single-press Service Mode activation: transport readiness → first
access → key enrollment → SSH verification, with rollback on failure. First access
is a **physical/USB (serial)** path that installs this computer's managed key on the
selected receiver through a publicly disclosed vendor updater mechanism; steady-state
access is ordinary SSH public-key. Trust is recorded **only** by the authenticated
verify step, and on any failure the activation reports the receiver's state honestly
— modified, unknown, or not modified — and never claims a safe retry when the
outcome is unknown.

Automatic first access is gated by recorded firmware evidence: it proceeds on
qualified firmware (currently VRX / VRX Max on 19.2.14 and VRX Pro on 18.21.10),
proceeds only with an explicit operator acknowledgment on unproven firmware of a
proven platform, and is otherwise blocked. **This release has not been re-qualified
on hardware for every unit — re-qualify Service Mode on your own receiver before
relying on it.** See `ascent_core/activation_orchestrator.py`,
`ascent_core/first_access.py` and `/api/service-mode/local/activate`.

See the [public transition status](docs/PUBLIC_TRANSITION_STATUS.md) and
[AC+ development review](docs/CONSOLIDATED_REVIEW_0.43.63_DEV3.md).

## Widget SDK and standalone widgets

ASCENT Control scans its **Widgets** folder at startup. In **Widget
Manager**, select **Open Widgets folder**, copy in a supported ZIP package and
select **Rescan**. The manager validates and lists package metadata. This preview
supports discovery and inspection only.

| Widget | Standalone repository status |
|---|---|
| [Picker](https://github.com/TelaMechanica/ascent-picker) | Public source subset and host checks. Installable release pending. |
| [Netrunner](https://github.com/TelaMechanica/ascent-netrunner) | Public source subset and host checks. Installable release pending. |

For a sample package and the manifest format, see the
[Widget SDK quick start](docs/sdk/README.md). The
[confinement proposal](docs/SDK_CONFINEMENT_PROPOSAL.md) tracks the isolation work
needed before third-party execution.

## Download and test

Download the Windows x64 MSI from [Releases](https://github.com/TelaMechanica/ascent-control/releases).
The installer includes its Python and media runtimes, native firmware tools,
Z8/Z40/Hub camera support and HD Pro donor inspection. WSL and separate camera
source images are unnecessary for the included donor-only builders. Supply your
own exact normal 19.2.14 donor image. The app does not include that full image.

HD Pro image building is withheld after confirmed CPU and boot defects in the
earlier tester payload. Donor inspection remains available; corrected camera
operation is not yet qualified. Z8, Z40 and Hub retain their separate builders.
See [HD Pro status](firmware/hdpro/README.md).

The MSI is unsigned. Microsoft Edge WebView2 Runtime is required by the desktop
host. Report reproducible problems through [Issues](https://github.com/TelaMechanica/ascent-control/issues),
including the application version, steps and sanitized error text. For image
builder reports include the target, donor hash and output hash. Remove personal
paths and device identifiers before uploading logs.

## Tested hardware and firmware

**19.2.14 is AC's primary tested firmware baseline.** Our development records
include these hardware connections and images used in firmware-update tests:

| Hardware | Firmware when connected | Target Firmware |
|---|---|---|
| VRX | 16.5.3, 17.5.3, 18.21.3, 19.2.4 | `Ascent_G_Gnd_19_2_14.img` |
| VRX Max HF | 18.21.7 | `Ascent_VRX_Max_19_2_14.img` |
| VRX Max WF | 18.20.5, 19.2.4 | `Ascent_VRX_Max_19_2_14.img` |
| VRX Pro | 18.21.10 | N/A |
| GT Pro / GT Max | 17.5.3, 17.5.14, 17.5.15, 19.2.4, 19.2.5, 19.2.13 | `Ascent_G_Sky_19_2_14.img` |
| Relay | 19.2.9 | `Ascent_Relay_19_2_14.img` |
| GT Pro Z40 | 16.5.8; subsequent custom 19.2.14 reflashes | `Ascent_G_Sky_19_2_14_z40_1.img` |

The history includes completed flashes and recorded attempts.

### HiSilicon platform coverage

GT Pro / GT Max, Z40 and Relay development includes the **Hi3516CV610** application
and video platform. Firmware analysis also established distinct **20S, 10B and 00S**
compatibility classes, each with legacy and V1 silicon identities:

| Hi3516CV610 class | Identities examined | Evidence |
|---|---|---|
| 20S | Legacy and V1 | Firmware boot tables and compatibility checks |
| 10B | Legacy and V1 | Firmware boot tables and compatibility checks |
| 00S | Legacy and V1 | Firmware boot tables and compatibility checks |

These six identities are firmware-analysis coverage; individual silicon steppings
were not recorded for every physical flash above. One finding was the expansion
from compatibility mask `0x07` in the examined stock 19.2.4 image to `0x3F` in
18.21.8: firmware version numbering alone does not establish silicon compatibility.
VRX, VRX Max and VRX Pro use the separate **Rockchip RK3568** receiver platform.

## Build the released Windows MSI

Use a fresh checkout of the published release tag with .NET SDK 8.0.424 on Windows x64:

```powershell
git clone --branch v0.50.2 --single-branch https://github.com/TelaMechanica/ascent-control.git ascent-control-05002
cd ascent-control-05002
```

Pass `-Edition ac` or `-Edition acplus` to build each edition; omit it for AC.

Then run:

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

Camera relocation tests use ARM binutils. No default test connects to hardware. See [publication privacy review](docs/PRIVACY_REVIEW.md) before posting source, history or attachments.
See [camera CLI instructions](docs/CAMERA_GRAFTING.md) for standalone source tools.
The original six standard-library shared helpers and their source-hash contract
remain available through `tools/inspect_local.py`.

## Permissions and third-party material

Copyright 2026 TelaMechanica, the sole ASCENT Control contributor. Original public
AC code is licensed under **[GNU GPL version 3 only](LICENSE)**. Commercial use,
modification and redistribution are allowed under its terms, including applicable
copyright notices and corresponding-source obligations. See [COPYRIGHT](COPYRIGHT)
and the [scope inventory](PROJECT_LICENSE_SCOPE.json).

Original code inserted into vendor firmware by the image builders has a narrow
[additional firmware-linking permission](FIRMWARE-LINKING-PERMISSION.txt). It keeps
our code under GPLv3 while allowing combination with vendor firmware where the
user has the required vendor rights. It grants no rights to vendor material.

Read [third-party notices](THIRD-PARTY-NOTICES.md) and the
[source inventory](THIRD-PARTY-SOURCES.json). Third-party components retain their
own licenses. Matching source archives accompany native helper/tool binaries.
Private components remain outside this public license grant. The public AC+
foundations and SDK preview are included in current source; they are not included
in the 0.43.62 MSI. See the [current transition status](docs/PUBLIC_TRANSITION_STATUS.md).

MAX Ethernet connections also offer RTSP viewing, scoped link/channel information and confirmed short menu/pairing requests. See [Ethernet coverage and bench limits](docs/MAX_ETHERNET.md).

## Released maintenance scope

The 0.43.62 maintenance release packages MAX Ethernet RTSP, scoped receiver
observations and confirmed short menu/pairing requests already in source.
Operator-confirmed Ethernet playback is bounded evidence; physical menu/pairing
and other firmware combinations remain unqualified. Pro telemetry tap, receiver
widgets and Picker are not included in the 0.43.62 public MSI. The public source
checkpoint does not add their private implementations.

Repeater Ethernet is also included: identity/role and per-radio QoS reads,
HF/MF bind requests, and explicitly confirmed role reversal/reboot. The selected
interface, current connection token and fresh target checks remain mandatory.
USB shell-based button control and privileged deployment stay outside public AC.
