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
