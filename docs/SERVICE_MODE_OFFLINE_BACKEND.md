# Service Mode offline record and host-key backend

This development increment connects the existing ServiceAccess/ServiceLease seam
to OfflineServiceBackend. Trusted host callbacks supply current application state,
serialized enrollment records and binding-tagged public-key observations. The
backend does not discover devices, read installed credentials, enroll, write pins,
open SSH/network connections or execute commands. It is not wired into the app.

## Verification actually implemented

EnrollmentRecord.parse accepts only the bounded v0 record schema, a positive
credential revision, a receiver identity, enrolled=true and a full SHA256 pin.
Duplicate/unknown JSON fields, invalid types, missing records and legacy pins fail
closed. A record for another receiver cannot authorize the selection. The host
must protect record storage and provenance; a JSON record is not cryptographic
proof of enrollment or authorization on a live device.

The first host-key parser supports only Ed25519 SSH wire-format keys, validates
the embedded algorithm/length and computes the full SHA256 fingerprint. The test
suite independently compares it with the installed OpenSSH ssh-keygen utility,
using generated synthetic public bytes. It creates no private key and makes no
SSH connection. Other key algorithms remain unsupported in this increment; this
must not be advertised as covering all receiver firmware.

The backend compares the observed key to the stored pin, with no first-contact
acceptance or silent replacement. An observation is supplied offline and therefore
proves no private-key possession: authenticated SSH handshake verification is a
separate future gate. Record/observation read errors become stable codes rather
than exposing supplier exception paths.

Each verify_step calls lease.check before and after backend checks and reloads the
record and observation. It refuses changed credential revisions, lost enrollment,
key mismatch, stale observation binding, closed sessions or changed selection.
The result explicitly reports authenticated_transport=false and offline_only=true.

## Side-effecting backend contract

Before EVERY future side-effecting step, the trusted backend must call check,
revalidate its live transport/receiver/credential binding and enforce the operation
boundary's authorization. Steps must be bounded or cooperatively cancellable.
A check cannot undo a partially executed or completed write, and cannot preempt a
blocking call. No side-effecting operation is implemented by this offline backend.

## Compatibility review item

The older private implementation's fingerprint_only hashes the base64 text and
abbreviates its hexadecimal digest to 16 characters. This is not the new full
OpenSSH-style SHA256 fingerprint. The new schema never interprets that old value
as a full pin, never silently trusts a freshly seen key, and does not migrate data.
A safe migration must prove existing identity/pin continuity or require explicit
re-verification. This increment changes no installed state, historical record or
public runtime path. Alias migration, ECDSA/RSA support and enrollment persistence
require separate review before replacing any existing Service Mode implementation.

## Standards consulted

- [RFC 4253](https://www.rfc-editor.org/rfc/rfc4253): SSH public-key wire representation.
- [RFC 8709](https://www.rfc-editor.org/rfc/rfc8709): Ed25519 key representation.
- [OpenSSH ssh-keygen manual](https://man.openbsd.org/ssh-keygen): offline public-key
  fingerprint inspection and SHA256 selection.

These standards do not establish that our future host transport is authenticated.
The 24 new tests are offline proofs only. Key storage, real enrollment and handshake,
legacy migration, binary/metadata review, widget confinement, signing, installer
preservation and hardware qualification remain open. No alternate session-access
key or key-path diagnostics are imported.
