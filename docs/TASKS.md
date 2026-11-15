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

Offline backend increment ownership: Codex owns ascent_core/service_records.py,
tests/test_service_records.py and docs/SERVICE_MODE_OFFLINE_BACKEND.md. Review
legacy pin migration and additional key types before adopting this in the app;
review real enrollment/credential storage and transport authentication separately.
Do not add signing or production widget execution through this increment.

Codex owns the loopback-only SSH proof in ascent_core/service_loopback_ssh.py,
tests/test_service_loopback_ssh.py and docs/SERVICE_MODE_LOOPBACK_SSH.md. SSH tests
are opt-in and use temporary owned localhost fixtures. Before real receiver work,
review Windows/Dropbear transport, source-interface binding and actual credentials;
fixture SFTP support must not be mistaken for receiver capability.

Windows parity owner: Codex. Scope includes Windows path/environment/diagnostic
handling, portable worker, opt-in WSL/Windows integration test and clear fixture
ancestor skips. Carry results into the consolidated product milestone review;
do not require another external review for each small implementation increment.

Local preparation integration owner: Codex. Files owned include service_credentials,
windows_tools, runtime local-preparation routes/Settings UI, desktop launch proof
and scoped WebView header hook, explicit payload/project inputs, and accompanying
storage/HTTP/render/Windows checks. Preserve failed compile/test/cache evidence.
Next product work is receiver enrollment/transport integration with protected state
and source-interface binding; no hardware action until separately authorized.
Consolidate security/product review before publication rather than external review
for each small increment. No installer release from development-channel source.
