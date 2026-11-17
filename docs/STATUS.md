# Current status

The 0.43.62 maintenance candidate includes shared MAX Ethernet functions and
withholds the defective HD Pro tester build. See RELEASE_0.43.62.md for scope.
Local full host regression: 620 passed and 55 subtests passed. Source/privacy,
runtime inventory and camera-boundary checks passed. Windows package and fresh
GitHub source checks must pass before publication. Tracking issue: #20.

Original public code remains GPL-3.0-only with the recorded firmware permission.
AC+ implementation, receiver deployment and Picker remain private. Host checks
and package validation do not establish hardware qualification.

Repeater Ethernet identity/role/QoS and guarded bind/role requests remain public.
Desktop publish inputs now include the MAX Ethernet worker and coverage document;
manifest-to-publish regression checks guard against future omissions.

## AC+ and SDK development review

Local review branch starts from published public v0.43.62. The Service Mode host
boundary, empty product-base manifest and non-executing SDK inspector are review
scaffolds only. No private runtime, installer change or hardware operation is
included. See ACPLUS_SERVICE_MODE_REVIEW.md and sdk/README.md. Publication is held
for the requested Claude review checkpoint. GitHub issue/PR creation is deferred
until publication is authorized; this candidate is kept local.

Review verification: 647 host tests and 55 subtests passed; the 27 new scaffold
cases pass. Source privacy, public runtime inventory, camera dependency checks
and whitespace validation passed. A separate local scan checked 35 known identity
tokens from earlier contaminated data and found none in 789 candidate files.
The initial sandbox run could not open synthetic localhost sockets; its failed
record is retained separately from the passing unrestricted host retest. These
checks do not establish hardware qualification or production widget isolation.
Implementation checkpoint: 25899cdfce29a42eacf09d7cdfc91e1aff08ff9c.

## Conditional-GO review follow-up

Corrupt DEFLATE and EOF now produce PackageInvalid. Cooperative ServiceLease.check
observes revocation/selection changes between bounded steps and rejects closed
leases. Synthetic backend tests cover absent enrollment, pinned-key mismatch,
independent binding refusal and liveness; they do not verify actual enrollment or
SSH. Final full host suite: 658 passed and 55 subtests passed. Combined scaffold
checks: 38 passed. Public privacy/runtime/camera checks remain green. The proposed
open publisher-trust contract is documented before any signing implementation.
No publication, installed app change, credential access or receiver action.

## Offline Service Mode record backend

Actual record parsing and host-key pin comparison now connect to ServiceAccess,
using fixture-fed trusted host suppliers. The backend has no SSH, enrollment/key
writes, command dispatch or installed app wiring. Full suite: 682 passed and 55
subtests passed; new backend tests: 24 passed. Public privacy/runtime/camera checks
pass. Fingerprint output agrees with an independent offline OpenSSH utility test.
Legacy abbreviated pins and unsupported key algorithms are explicitly refused;
compatibility migration remains open. See SERVICE_MODE_OFFLINE_BACKEND.md.

## R4 localhost authenticated SSH proof

Loopback-only OpenSSH integration now proves pinned host-key possession and
synthetic client-key authentication, with a fresh connection per guarded step.
The channel opens/closes internal read-only SFTP with no file requests or user
shell. This is a fixture mechanism, not receiver SFTP support or transport release.
Opt-in full suite: 690 passed and 55 subtests passed. Eight new fixture cases pass
(six real integration, two injected error paths); default targeted run skips all
eight as designed. Source privacy/runtime/camera checks pass; 35 known identity
tokens across797files, zero findings. No installed state, receiver or MSI change.
Expected supplier exceptions and session-registry strong-reference ownership are
now documented. See SERVICE_MODE_LOOPBACK_SSH.md for limits and opt-in command.

## Windows localhost client parity

Five Windows worker cases pass with OpenSSH9.5p2 and packaged Python3.12.7: fresh
handshakes, impostor host/client rejection, provider revocation and revision-change
refusal. Windows requires a task-owned ProgramData and a discard pipe for stderr
on this setup. R4 comments and writable-ancestor fixture handling are addressed.
See SERVICE_MODE_WINDOWS_PARITY.md. The transport remains outside the shipped app;
real credentials, receiver binding and installer/bench gates remain open.

Final combined Linux/Windows opt-in suite:698passed/55subtests,36.88seconds.
Source privacy/runtime/camera checks pass;35known identity tokens across801files,
zero findings. Seven new environment/process unit checks plus the Windows parity
integration test are included. Results are host proofs, not hardware qualification.

## Service Mode local preparation integrated — internal0.43.63-dev.1

Settings now owns check/create of a new current-user DPAPI credential. Receiver
setup remains unavailable and service_mode_available remains false. The trusted
desktop proves backend possession of a fresh launch secret before loading its
page; local preparation requests require that secret and explicit creation consent.
No key import, raw fallback, alternate session key or receiver write is included.

Final full host suite:724passed/55subtests,52.86seconds, including real temporary
Windows DPAPI, actual packaged-backend HTTP preparation and Linux/Windows SSH
fixtures. Actual C# BackendHost separately passed authenticated startup, impostor
backend refusal, denied anonymous HTTP, real local preparation, existing-credential
preservation, no secret in logs and clean shutdown. Post-run payload verification
passes with no bytecode caches. The initial old UI digest failure is retained;
previous pin preserved and scoped render/HTTP tests accompany the new pin.

Portable development publish and376explicit payload entries verify. Source privacy,
runtime/camera checks pass. Across807source and921package files,35known identity
tokens have zero matches. Two vendor test-path strings in the unchanged pinned
CPython DLL are the same reviewed literals from the previous public package;
no new/operator identity finding or old private repository URL remains. GUI visual
acceptance, receiver enrollment/transport, legacy migration, extra key types,
installer/provider/data preservation, signing and widget execution remain open.
The MSI script refuses the internal-development channel; publication stays held.

## Receiver readiness controller — host qualification in progress

The next increment captures receiver identity and fresh source/interface binding
from the existing DeviceSession owner, invalidates material identity changes,
and adds strict P-256 host-key parsing alongside Ed25519. Protected receiver
records are immutable and are saved by the host controller only after a live
pinned SSH no-op and final context checks. This controller is not yet connected
to application routes or Settings; no receiver access is enabled by these files.

Owned Linux fixtures: 90 targeted checks pass. The new Windows P-256 key,
transient-key cleanup and actual DPAPI record checks pass alongside existing
Windows SSH/application checks. Full retest: 775 passed, 55 subtests passed.
The preceding full run had one Windows SSH authentication failure; independent
Windows runs and the full retest pass, but its cause remains unestablished. Failed
evidence is retained privately; this intermittent result remains an investigation
item rather than an inferred fix. No hardware test or publication occurred.

Local artifact directories are excluded from Git/source snapshots. Next: native
source-interface socket qualification, guarded application/Settings integration,
packaged-build and privacy validation, then operator bench qualification and
consolidated pre-publication review. Existing preparation build remains dev.1.

### Receiver readiness connected — internal 0.43.63-dev.2 host validated

The previously host-only controller now has authenticated host routes and a
Settings flow for explicit fingerprint observation/confirmation and a fixed SSH
no-op. Credential type selects fixed separate Ed25519/P-256 stores; no path, login,
command or endpoint is accepted from requests. The existing device-operation lock
excludes readiness from firmware/RF work. No first-access installation or receiver
mutation is implemented. Combined new HTTP/SSH/render checks:34passed. Actual
Windows loopback source/interface socket pinning passes; USB receiver behavior
remains NOT TESTED. Full regression passes: 787 tests and 55 subtests, including
Windows SSH and the isolated packaged backend. Fresh internal portable output
passes source/payload verification with 382 explicit files and 19 camera payloads.
No GUI or receiver qualification is inferred. Documentation and delivery inventory
are being reconciled before the frozen internal dev.2 delivery.

## Public AC+ and widget SDK destination

The operator-selected destination is the public AC repository, with AC+ and the
widget SDK developed in the shared application. Every proposed new or changed
publication file, attachment and commit metadata requires sanitization for personal
names, account/computer names, personal paths, BBIDs/device identifiers, credentials
and other personal data. Review source and extracted binaries/archives, including
UTF-16 strings. Keep local denylist values and raw findings outside public history.
Record bounded scan evidence and review unresolved findings before posting.
The SDK remains a non-executing inspector; confinement, updates and release
composition are unfinished. A public destination does not establish release readiness.

## Static/security follow-up — 2026-11-16

Two bounded findings reproduced and repaired: oversized JSON integer conversion
now becomes PackageInvalid in the SDK inspector, and open SSH relay channels
recheck provider/selection liveness while idle and before forwarding each chunk.
These cooperative checks do not make blocking socket calls instantly cancellable.
Failed reproductions remain local; no hardware operation was used.

Targeted scaffold/channel checks:39passed. Full Linux/Windows opted-in host suite:
792passed/55subtests in63.82seconds with the fresh isolated package. Static parsing:
150Python,31JSON,11JavaScript,5XML/project and4PowerShell files pass. Deterministic
SDK malformed-manifest screening:1000rejected, zero unexpected errors. Package
verification382files/19camera payloads and source/runtime/camera checks pass.
The earlier internal dev.2 ZIP is preserved and does not contain these two fixes.
Installer inspection finds no credential/settings removal rule; actual upgrades,
rollback, GUI acceptance and hardware compatibility remain unqualified. SDK
confinement/execution/updates and final publication review remain open.

## Publication privacy gate and installer boundary — 2026-11-16

The public-source CI now runs tools/privacy_review.py with exact-content reviewed
findings. It scans filenames/content, UTF-8/UTF-16 binary strings, bounded nested
ZIP contents and optionally commit metadata/new historical blobs. Reports contain
hashes/categories rather than matched values or names. Incomplete scans cannot
be waived; changed content cannot inherit a prior disposition. Private operator
identifier lists remain local and ignored. See PRIVACY_REVIEW.md.

Current-source review retains seven documented false-positive/synthetic findings.
The outgoing committed range adds three instances of the same validation/prose/
synthetic-fixture patterns. Local scan with36known identifiers found zero known
personal-identifier matches. Source CI has no private denylist; final local review
remains mandatory. Historical screening is separate from current-tree screening.

New installer tests preserve the existing public UpgradeCode, bound authored
removal to the shortcut folder, reject user-data/custom-action cleanup and verify
settings remain available after changing the application location. These are
static/host contracts; actual installed transitions remain unqualified.

## Bounded interpreter probing — internal 0.43.63-dev.3 candidate

Actual owned Windows executable tests reproduced two startup stalls in the
interpreter probe: a child that never exits and a child that fills stderr while
the parent reads stdout to EOF. The host now drains both pipes concurrently,
limits captured version output to64characters and applies the existing5second
probe deadline before waiting indefinitely for either pipe. All6fixture modes
pass after the fix; hung/excessive-output cases return in about5.1seconds.
The test harness compiles the actual BackendHost/BoundedLogWriter sources and
uses no Python, installed application state, credentials or receiver. Original
failed/watchdog evidence is preserved. A new isolated desktop build and final
combined regression are required before the consolidated candidate is frozen.

## Consolidated dev.3 source review candidate — 2026-11-16

Final853host tests/55subtests pass, including the actual owned C# probe. The fresh
Windows desktop publish verifies382payload files/19camera payloads; a separate
actual C# host workflow verifies authenticated backend startup, impostor/anonymous
refusal, real disposable-profile credential preparation/preservation, clean
shutdown and no secret/bytecode persistence. See CONSOLIDATED_REVIEW_0.43.63_DEV3.md.

The operator's current destination is AC+ and SDK development in public AC GitHub,
with an identifying-information scrub for all posted files. This candidate is
prepared for a draft source-review PR. Merge, product release, MSI, production
widget execution and hardware gates remain separate. Earlier local-review hold
notes describe prior checkpoints; they do not establish a production release.

Reviewed implementation commit:6eb6d0273523001e0146c71d7a220ae1338aa41f.
It commits45explicitly selected files; the isolated candidate tree is clean.
Completion notes/source inventory are recorded separately. Final outgoing source,
historical blobs, commit metadata and PR text are rechecked after committing.

Public draft review PR: https://github.com/TelaMechanica/ascent-control/pull/24.
The first push and pull-request source checks both passed at
77efdaabb07c66998a78492eae635a6e0d768c04. The PR stays draft; no merge, release tag,
MSI or public binary artifact was created. Final documentary checkpoint is
rechecked separately; implementation remains6eb6d0273523001e0146c71d7a220ae1338aa41f.

## Consolidated Claude review follow-up

Operator-supplied review of a11ed1b5 found no HIGH defect and gave GO for a source
checkpoint/proposal, with execution/production/MSI NO-GO. See
CLAUDE_REVIEW_RESPONSE_DEV3.md and SDK_CONFINEMENT_PROPOSAL.md. Historical packaging
prose is superseded; the three machine-label dispositions were re-inspected as
actual comments, not workstation names. A real denylist recheck invalidates an old
exact-content disposition when the label becomes a known identifier.

The native hook now delegates to the actual compiled ServiceHostRequestPolicy:
exact trusted-view identity, main document, Fetch/XHR and five method/path pairs.
21native cases pass, plus source wiring/JS absence checks and2actual widget-origin
HTTP negatives. Real initiating-frame/header-visibility behavior is NOT PROVEN.
No executor is introduced. Contextual eight-hex identity fields and additional
private-key markers are screened; anonymous hex/non-GitHub tokens still require
local denylist/manual review. The private pre-post pass remains mandatory.

Final follow-up:865host tests/55subtests in82.07seconds, Windows desktop compile
and explicit package verification pass. Owned fixture evidence is not receiver
qualification, browser confinement, an operator merge decision or production GO.
Prior evidence, accepted UI pins and dev.3 delivery remain intact.
