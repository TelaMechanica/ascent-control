# AC+ and widget SDK consolidated development review

Candidate: internal 0.43.63-dev.3, based on public AC 0.43.62. The operator selected
the public AC repository as the destination for AC+ and the widget SDK, with a
personal-information scrub required for every posting. This is a development
source review candidate, not a released AC+ product, stable SDK or MSI.

## Implemented scope

The shared desktop owns protected local credentials and authenticated backend
startup. Current-user DPAPI has no plaintext fallback. New stores are create-only;
existing or corrupt records are preserved. Temporary key material uses an owned
restricted directory; crash cleanup and secure disk/memory erasure are not claimed.

Settings receiver readiness uses the existing DeviceSession identity/generation,
fresh USB/source-interface binding, explicit fingerprint observation/confirmation
and a pinned SSH no-op before saving an immutable protected trust record. Ed25519
and P-256 are supported in separate fixed stores. Requests cannot select a login,
command, key path or network endpoint. There is no first-access installer, general
receiver-command dispatcher, private widget implementation or credential migration.
Receiver Service Mode availability is not promoted by a successful preparation.

The SDK preview validates exact package inventories and bounded declarative text
views. It never installs, extracts or executes a widget. The reproducible example,
inspection CLI and proposed publisher-trust discussion are in docs/sdk. Signatures,
capability grants, publisher acceptance and confinement remain distinct decisions;
no manifest or edition label grants host credentials or unrestricted operations.

Source CI now includes a privacy gate. Its source/export/history modes check
content, filenames, encoded binary strings, bounded nested ZIPs, commit metadata
and optional historical blobs. Reports retain findings as hashes/categories.
Exact-content dispositions document reviewed generic false positives; known
personal identifiers and incomplete scans cannot be waived. A private local
identifier list is never committed. See PRIVACY_REVIEW.md for scope and limits.

## Verification

- Final combined Linux/Windows host suite: **853 passed, 55 subtests passed**.
  It includes owned localhost SSH, Windows source/interface fixtures, protected
  storage, real packaged-backend preparation and the actual C# interpreter probe.
- A separate actual C# host/backend workflow passed authenticated startup,
  impostor refusal, anonymous-request refusal, Windows credential preparation,
  existing-state preservation, secret-free host logs and clean shutdown, using
  disposable profiles. No persistent bytecode was added to the package.
- Fresh self-contained Windows desktop publish passed explicit package validation:
  382 payload files, 19 camera payloads, zero private runtime modules. File version
  is 0.43.63.3; the source/payload base version remains 0.43.63, internal-development.
- SDK malformed-input screening rejected 1,000 deterministic cases without
  unexpected exceptions. Source/runtime, camera-boundary and whitespace checks pass.
- Static installer contracts preserve the existing shared product identity, bound
  authored folder removal to the shortcut folder and reject user-data cleanup or
  custom-action additions. Host settings survive an application-location change.
  These are not actual install, uninstall, upgrade or rollback results.

Three reproduced defects were repaired with failed evidence retained locally:
oversized JSON integers now return PackageInvalid; an open SSH relay rechecks
cooperative liveness; interpreter probing concurrently drains both pipes, caps
captured version output and reaches its timeout. The executable fixture originally
stalled on stderr flooding and a hung child; all six modes now pass, with hung and
excessive-output cases returning in about 5.1 seconds. Blocking socket calls still
have bounded rather than instantaneous cancellation.

## Publication and product limits

Review the final exact source, commit history/metadata and attachments with the
private identifier list before posting. Generic source findings must retain their
exact-content dispositions; vendor dependency findings require their own byte
verification and review. Raw local logs, keys, profiles, private denylists and
unreviewed build outputs are excluded from source/review attachments. Automated
screening is not exhaustive recognition of every possible personal name.

The development branch can be reviewed separately from merging or releasing.
Actual GUI/accessibility acceptance, receiver/daemon and USB behavior, legacy trust
and credential migration, installer/provider/data transitions and hardware
qualification remain open. Widget execution, isolation, independent updates,
rollback and publisher trust are unfinished. An operator-accepted confinement
finding remains required before a production executor. This candidate does not
freeze Phase 5 architecture or raise readiness/hardware qualification scores.
