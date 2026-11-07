# Legacy Walksnail HD Pro engineering port

This directory contains an experimental CV610 sensor adapter for the camera
identified as `cam_imx385` in the inspected Avatar firmware. Physical sensor
identity, board wiring, boot, frames and image quality have not been qualified.
It is separate from HD Pro II and from the Z8/Z40/Hub implementations.

The C files implement the recovered 60/100 fps register programs, exposure/gain
encoding, B051 ISP/AE/AWB callbacks, register scheduling, explicit Linux I²C
transport and a candidate 37.125 MHz clock selection. The Python startup/capture
helpers use the existing Z8/Z40 ELF emitter against one exact 19.2.14 application.
The capture profile and neutral/reference-family IQ defaults are diagnostic
assumptions, not calibration. No other camera's tuning file is loaded.

`legacy_pro_patch.py` applies a reviewed, hashed engineering patch to that exact
donor application without an ARM compiler. Both donor and output identities are
checked before creating an output, and existing files are never overwritten:

```sh
python legacy_pro_patch.py --donor ar_ldyhs_sky \
  --spec hdpro-19.2.14-patch.json \
  --extension hdpro-19.2.14-extension.bin --out ar_ldyhs_sky-hdpro-experiment
```

The patch specification and extension are generated from a validated build;
they are not interchangeable between donors or revisions. Full-image experiments
use the existing Mode A metadata-aware filesystem regeneration and image verifier.
Do not place these helpers in `firmware/mode_a` or its shipped copy: the native
builder qualification binds its complete Python-file inventory.

Evidence and repeatable build/validation scripts are kept under
`artifacts/hd-pro-driver-port-2026-11-07-r1/`. SDK interface headers are separately
pinned and hash verified there, with their original notices; no SDK MPI
implementation is included here. The compiled objects use the donor's ARMv8-A,
Thumb-2, base AAPCS/softfp ABI. Public OpenIPC interface/reference provenance is
recorded in the evidence inventory.

AC includes this profile as an HD Pro tester build from the exact normal
19.2.14 donor. The build checks donor identity, performs the unchanged-donor
rebuild, applies the pinned application patch, regenerates the filesystem and
independently verifies the resulting image. These checks do not establish
physical camera operation or image quality.

Use the Firmware panel to check the donor and build HD Pro. Output is
`Ascent_G_Sky_19_2_14_HDPro_1.img`. Report boot, capture, timing and image-quality
results through GitHub issues, including the AC version and image SHA-256.
Do not attach private device identifiers or personal paths.
