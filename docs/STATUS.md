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
