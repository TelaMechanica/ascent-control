# Current status

The 0.43.54 public desktop release is being prepared on the desktop/MSI branch.
The integrated repository contains the Windows host, public backend and UI,
firmware builders, pinned native-tool inputs and package verification tools.
Service Mode and dependent receiver/widget operations remain private in AC+.

The native Windows HD Pro donor-only build passed with WSL refused. Its image
passed donor round-trip, pinned application patch, filesystem readback and
unchanged-component checks. The final combined suite passed 515 tests and 55 subtests. Runtime inventory,
camera source/import and privacy checks also pass.
The earlier MSI candidate passed administrative extraction and privacy checks;
the first-release MSI is rebuilt after the HD Pro tester build is connected.

Z8/Z40/Hub donor-only pipelines passed offline native Windows runs with WSL
refused. HD Pro is included in this first release for tester image creation and
issue reporting. Physical camera qualification remains separate from build
integrity checks. No release engineering check constitutes a hardware PASS.

Project permissions are in LICENSE. Dependency notices and corresponding-source
inventories are included with the source and release assets.
