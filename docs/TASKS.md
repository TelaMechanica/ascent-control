# Work queue

- Maintenance release owner: release/maintenance-04362; firmware admission,
  release identity/manifests, documentation and offline validation.
- Complete full source regression, source/privacy inventory and Windows build,
  extracted-package validation and privacy scan before publishing 0.43.62.
- Qualify menu/pairing, installed UI and upgrade behavior with operator evidence.
- Correct and independently retest HD Pro CPU/startup/capture before readmission.
- Preserve the private Service Mode/dependent widget boundary and failed evidence.

Default checks are offline. Hardware execution needs separate authorization.


Installer completion option: fix/installer-launch-option owns installer UI and
its host/package checks. Future interactive installer builds offer an unchecked
Launch AC checkbox on successful completion. Quiet installs, repairs and
removal do not launch the app. The released 0.43.62 MSI is unchanged.
