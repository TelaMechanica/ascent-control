# AC+ Service Mode and public SDK review checkpoint

Status: historical initial scaffold checkpoint; the current draft is PR #24.
Packaging and host integration have advanced; see the dated supersession below.

The operator selected public AC as the sanitized foundation, AC and AC+ public
bases going forward, Service Mode first, and a public widget SDK. Individual
widgets remain private until selected for release. This supersedes the earlier
proposal that the entire AC+ base necessarily remain private; it does not publish
any existing private component by implication.

## Implemented in this increment

- Review-only product-base manifest: shared core, zero bundled widgets, Service
  Mode as the first AC+ capability; no privilege inferred from branding.
- Host-only Service Mode session boundary with live state and receiver/transport/
  selection binding checks before and after acquisition, lock ownership and
  deterministic cleanup. Backend injection exists only as a trusted host seam.
- Offline SDK package inspector and reproducible synthetic example. No execution,
  credential access, receiver networking or installation is provided by the SDK.
- Adversarial offline tests for state loss, stale targets, archive path attacks,
  payload corruption and attempts to request privileged APIs.

## What this is not yet

This does not port or activate the old Service Mode implementation, build two
installers, implement AC-to-AC+ upgrades, authenticate packages, render widgets,
provide atomic widget updates, or prove isolation. Existing public app behavior
and payload allowlists were unchanged at this initial scaffold checkpoint.
**Superseded for dev.3:** the desktop now explicitly packages the trusted shared
service-access/credential/receiver-readiness modules listed in the project and
payload manifest. The loopback-only backend and SDK inspector remain source-only.
See CONSOLIDATED_REVIEW_0.43.63_DEV3.md for current packaged-host evidence. This does
not establish working receiver Service Mode or a released SDK.

The old implementation must be reviewed component by component. In particular,
its alternate long-lived session-access key, credential persistence, enrollment
paths and diagnostics need an explicit disposition before importing code. No old
private history, raw captures, local state or operational keys are imported here.

## Claude review request

Please challenge the implementation rather than treating document agreement as
proof. Check these questions before recommending the next increment:

1. Does the host-only session contract preserve selection, transport, enrollment
   and host-key responsibilities without implying they are already implemented?
   What remains needed for revocation during an in-flight operation?
2. Are validator bounds and portable path checks sufficient for this limited
   non-extracting inspector? Identify malformed ZIP/JSON cases still accepted.
3. Does any package declaration become an authority? Can any package reach Service
   Mode sessions, secrets or raw receiver commands through this code?
4. Is the public/private boundary clear, with no old private implementation or
   identifying data imported? Inspect binaries and metadata as well as source
   before any eventual build is approved.
5. Choose/revise an open publisher-trust model without confusing authenticity,
   user capability grants, runtime confinement or paid licensing.
6. Define the smallest next Service Mode backend integration that can preserve
   existing enrollment/key/host-identity guards with synthetic offline proofs.
7. Keep production third-party execution gated on an operator-accepted confinement
   finding. Ordinary same-user processes and localhost origin checks were already
   insufficient in disposable experiments; preliminary WASM tests are not a
   Windows host integration proof.

Do not approve publication merely because host tests pass. Installer/provider
preservation, current-schema data migration, private dependency review and hardware
qualification retain their separate gates. The existing release remains intact.

## Independent review follow-up

The operator supplied Claude's independently verified conditional GO for the next
bounded increment, explicitly not publication. The follow-up normalizes corrupt
DEFLATE/EOF failures, adds cooperative lease liveness and tests a synthetic backend
for missing enrollment, pinned-key mismatch, binding changes and revocation at the
next step. These fixture comparisons do not qualify real cryptography, enrollment,
transport or credential protection. See sdk/PUBLISHER_TRUST.md before signing work.
The lease API now yields a ServiceLease object rather than a bare session; this is
an intentional change within the unpublished 0.x scaffold. No installed caller is
migrated or affected. Blocking operations still cannot be forcibly interrupted.

## Next bounded increment: offline record backend

See SERVICE_MODE_OFFLINE_BACKEND.md. Actual bounded JSON/SSH-public-key parsing and
pin comparison now back the host seam; fixtures supply the records/observations.
This is not a real transport authentication proof or live app integration. Review
missing enrollment, stale binding, revision changes, redacted supplier failures
and the independent OpenSSH fingerprint cross-check. The legacy abbreviated pin
format and additional key algorithms are held for explicit compatibility review.

## R4 localhost authenticated transport checkpoint

See SERVICE_MODE_LOOPBACK_SSH.md and service_loopback_ssh.py. This is a real
OpenSSH fixture handshake with pinned server key and authorized synthetic client
key, followed by an empty internal read-only SFTP channel. No receiver or installed
credentials are used. The SFTP fixture is not a receiver protocol recommendation.
Review fresh-connection semantics, isolated client options, post-operation refusal,
fixture cleanup, timeout/error handling and the explicit remaining receiver gates.
