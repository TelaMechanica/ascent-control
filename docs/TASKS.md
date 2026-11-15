# Work queue

- Maintenance release owner: release/maintenance-04362; firmware admission,
  release identity/manifests, documentation and offline validation.
- Complete full source regression, source/privacy inventory and Windows build,
  extracted-package validation and privacy scan before publishing 0.43.62.
- Qualify menu/pairing, installed UI and upgrade behavior with operator evidence.
- Correct and independently retest HD Pro CPU/startup/capture before readmission.
- Preserve the private Service Mode/dependent widget boundary and failed evidence.

Default checks are offline. Hardware execution needs separate authorization.

## Local AC+ scaffold ownership

Codex owns ascent_core/service_access.py, ascent_core/widget_sdk.py,
tools/widget_sdk.py, release/product-bases.json, tests/test_framework_scaffold.py,
and their review/SDK documentation. Review Service Mode backend and credential
handling before importing implementation. Complete publisher trust, confinement,
updates and installer preservation before calling this a released SDK/AC+ base.
