# ASCENT Control 0.43.54

First public desktop source and Windows x64 MSI release.

- Configuration, live status, device information and firmware management.
- Native Windows device inventory included and exercised from the package.
- RF management and RC/HID management where supported.
- Local fleet records and nicknames; receiver membership and Picker remain in AC+.
- Native Windows Z8, Z40 and Hub image creation from a supplied exact normal
  19.2.14 donor, using included camera support. No WSL or separate camera images.
- HD Pro tester image creation using the included pinned camera profile.
- Rebuildable Windows MSI tooling, explicit package inventories, dependency
  notices and corresponding-source release assets.

HD Pro physical boot, capture and image quality are not yet qualified. Build
checks verify image integrity and exact donor/patch identities. Please file
reproducible issues with versions, hashes and sanitized errors. No Service Mode
or dependent widget deployment implementation is included. The MSI is unsigned;
installed-UI and upgrade qualification remain follow-up testing.
