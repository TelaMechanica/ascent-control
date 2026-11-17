# Work queue

## Current continuation

- Public transition cleanup owner: Codex. Scope: README, current status/queue,
  transition handoff and synthetic HID private-configuration regression tests.
  Preserve historical reports and existing runtime behavior.
- AC+ foundations and SDK inspector are merged through PR #24; private HID
  family configuration was separated through PR #25. Repeat privacy checks for
  all new source, commit history and publication text.
- Review confinement acceptance criteria before admitting an untrusted renderer
  or executor. C03/C04 browser evidence and C05-C10 runtime/lifecycle evidence
  remain incomplete. Keep execution disabled while these are unresolved.
- Next safe work: bounded host-only test specifications, resource/message budgets
  and a synthetic adversarial corpus. Do not call a proposal acceptance hardware
  qualification or an architecture freeze.
- Complete credential/trust migration, installed upgrade/rollback preservation,
  publisher trust and independent widget conformance before release packaging.
- Preserve private initial access and receiver widgets; no hardware operations.

Cleanup validation: 140 targeted checks and full host 846 passed/24 skipped/
55 subtests passed; source/runtime/camera checks pass. Issue #26 tracks the
README/status/HID regression scope. Publish only after final source/history/
metadata privacy review and green source CI on the exact outgoing head.

Standalone inventory tooling owner: Codex. Scope: tools/check_public_runtime.py,
tests/test_widget_source_inventory.py, standalone schema documentation and checked
source/license inventories. Preserve the existing desktop branch and publication
privacy gates. Validate exact local native subsets without inventing desktop
manifests. Complete host/control/display/package/license/lifecycle boundaries before
creating widget repositories; no extraction publication or hardware operation.
Issue #28 tracks this tooling scope. Targeted46/full892 pass (24 skipped,
55 subtests); both actual native subsets pass the explicit inventory profile.
Remaining work is full host/control/display, provenance and package lifecycle;
Mapster extraction stays deferred.

Read-only catalog owner: Codex. Scope: source-only widget_catalog/widget_catalog_io,
immutable-byte SDK inspection, catalog CLI, adversarial and owned Windows fixture
tests and local-catalog documentation. Preserve the declarative SDK contract and
native/receiver gates. No automatic registration, startup route, UI import flow or
activation is introduced. Issue #30 tracks this source-only increment.
74 combined catalog/SDK checks, 18 actual Windows cases and 925 full host tests pass
(24 skipped, 55 subtests). The 500 malformed cases have no unexpected result or descriptor
growth. Finish frozen history/privacy/source CI and the normal source merge.
Next: trusted folder configuration/startup rescan ownership and text-only UI,
without exposing arbitrary folder paths or admitting untrusted content to the
trusted main WebView.

## Historical ownership and checkpoints

Earlier local-publication and draft-PR instructions below are superseded by the
merged source checkpoint. Retain their implementation ownership and evidence.

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

Receiver readiness increment owner: Codex. Scope: service_target, service_channel,
receiver_ssh, service_receiver, service_enrollment, windows_key_material, protected
store/P-256 extensions, DeviceSession identity invalidation and synthetic tests.
No initial-access adapter or receiver mutation is imported. Investigate the
one-off full-suite Windows SSH failure; keep its evidence and subsequent passes.
Connect the controller to the authenticated host Settings flow, qualify Windows
source/interface pinning and validate a fresh package before any hardware gate.

Current continuation: host routes, Settings and Windows loopback binding pass;
787 tests/55 subtests pass. Freeze dev.2 documentation/source, scan the exact
source and portable delivery for personal identifiers, then finish its internal
delivery. Continue toward AC+ and the widget SDK in the public AC repository.
All publication contents and metadata require the privacy review described in
STATUS. Preserve existing SDK limits and hardware gates.

Static follow-up ownership: widget_sdk JSON rejection, service_channel cooperative
revocation and their adversarial tests. Final792tests/55subtests pass. Carry both
fixes into the next frozen delivery; preserve the prior dev.2 ZIP. Remaining
static/product gates include completed SDK confinement and update contracts,
installer transition design, credential/trust migration and consolidated review.
Do not represent source inspection as executed upgrade or hardware qualification.

Publication-gate ownership: tools/privacy_review.py, tests/test_privacy_review.py,
release/privacy-findings.json, source CI and docs/PRIVACY_REVIEW.md. Local denylists
and raw scan evidence stay private. Installer data-boundary tests are host/static
contracts only. Finish final combined regression and exact-source/commit review,
then present the consolidated review candidate at the governing publication gate.
Do not enable an executor or rewrite product architecture through this work.

Interpreter-probe follow-up ownership: BackendHost bounded/concurrent probe reads,
tools/testing/interpreter_probe, Test-InterpreterProbe.ps1 and its opt-in test.
Six actual Windows fixture modes pass; retain pre-fix watchdog failures. Rebuild
the real isolated desktop host, complete final regression, commit only reviewed
candidate files with public identity and present the concrete consolidated review
candidate before public posting. No hardware or MSI authorization is inferred.

Consolidated dev.3 verification complete:853host tests/55subtests, fresh Windows
publish and actual C# host workflow pass. Freeze exact reviewed source with public
project commit identity; review outgoing history and PR text for personal data.
Use a draft development PR for the operator-selected public AC destination. Keep
merge/release, initial access, migration, installer transitions and production
SDK execution gated; no hardware action or architecture freeze through this work.

Implementation milestone:6eb6d0273523001e0146c71d7a220ae1338aa41f (45reviewed files).
Preserve earlier failures and dev.1/dev.2 outputs. The next developer can start
from the consolidated review document and remaining gates without importing old
private history or treating fixture success as receiver qualification.

Tracking/review: https://github.com/TelaMechanica/ascent-control/pull/24 (draft).
Initial push/PR source CI passed at77efdaabb07c66998a78492eae635a6e0d768c04.
Keep the draft review boundary and remaining product/hardware gates explicit.

Claude consolidated-review follow-up owner: Codex; PR24 reviewed a11ed1b5. Scope:
M2 correction, M4 exact prose verification, native token policy/negative tests,
denylist regression, bounded M3 patterns and confinement proposal. No executor,
merge, MSI or receiver operation through this increment. Browser/frame isolation
and OS containment remain acceptance work; see CLAUDE_REVIEW_RESPONSE_DEV3.md.

Review follow-up implementation:cf6b2b0e1c386b2125c2f39f3d1b33c5bf8f314e.
865host tests/55subtests and21compiled policy cases pass. Publish the scrubbed
follow-up in PR24 and retain the explicit real-browser/worker acceptance gates.


Catalog coordinator owner: Codex, issue #32. Scope: widget_catalog_host.py,
concurrency/failure tests, SDK documentation and source/license inventories.
Next: capture the host-owned Widgets directory once, wire authenticated startup/
rescan/status/shutdown, then a text-only Widget Manager. Keep raw caller paths,
package views, activation, installation and execution outside this interface.


Trusted catalog startup owner: Codex, issue #34. Backend lifecycle/authenticated
status/rescan, native exact-path policy, curated read-only payload inputs and
concurrency/HTTP/package-boundary checks. Next: fixed-folder opening action and
text-only Widget Manager, with package metadata escaped as text and no package
view, activation, install or execution. Keep private key recovery work separate.
