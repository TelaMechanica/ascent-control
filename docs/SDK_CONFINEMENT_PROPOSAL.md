# Widget confinement proposal — awaiting operator decision

Status: proposal only. No executor is enabled by this document. Reviewer GO for
PR #24 at a11ed1b5 permits a bounded proposal; production execution remains NO-GO.
This is not a Phase 5 architecture freeze or operator acceptance of an executor.

## Decision requested

Accept or revise these boundaries and acceptance criteria for an isolated host-only
prototype. Use synthetic canaries and an independently authored example in disposable
profiles. No operational credentials, ServiceLease, real receiver identity, raw
commands, desktop launch token, initial-access installation or hardware operations.

## Proposed boundary

The trusted desktop/backend retain all credentials, target selection and privileged
decisions. Untrusted widget content must never enter the trusted main WebView,
including frames, workers or same-origin widget documents. Use a distinct renderer
view/process boundary, origin and profile with no token hook, native host objects,
privileged scripts, inherited credential state or unrestricted native messaging.
Origin separation alone does not establish OS confinement.

The first example should use declarative text. If execution is subsequently accepted,
evaluate a dedicated worker with a pinned WebAssembly engine, no ambient WASI
filesystem/network/environment imports, a narrow message protocol and a Windows
restricted/AppContainer layer. This is an evaluation direction, not a chosen dependency
or proven Windows integration. Ordinary same-user processes or a WebView alone are
NO-GO as the security boundary. No guest Python/native/JavaScript runs in the host.

Start with zero grants. The first candidate API is host.version.read, returning only
a version string. A publisher signature, edition or manifest grants no permission.
No API returns a backend, ServiceLease, credential handle, raw path/socket/command or
live Python/.NET object. Require exact message schemas, size/resource limits, deadlines,
instance correlation and rejection after revocation. Recheck grants at dispatch and
completion. Worker termination cannot corrupt trusted state.

Configuration belongs to stable widget identity, not package variant. Installation
and updates validate dependencies and new grants before atomic switching, preserve
configuration and retain the previous version until acceptance. Rollback and reverse
flavor transitions require explicit migration tests; the inspector implements none.

## Required acceptance evidence

| ID | Criterion | Current scope |
|---|---|---|
| C01 | Token policy rejects other views/origins/ports/paths/methods and non-Fetch/XHR resources | PASS:21 compiled native-policy cases; no browser/frame proof |
| C02 | Widget-origin HTTP without token cannot construct credential/session adapters | PASS:2 actual loopback-handler negatives |
| C03 | Real widget/frame/worker/pop-up/redirect attempts cannot receive native headers, including same-origin attempts | NOT RUN; no widget renderer admitted |
| C04 | Page JS cannot observe token through bootstrap, messages, reflected endpoints or host objects | Source/HTTP checks only; browser evidence required |
| C05 | Worker cannot access canary profile/credential files, registry, inherited environment, unauthorized network/loopback or child processes | NOT RUN; no executor |
| C06 | Imports/messages/serialization cannot yield credential/backend/ServiceLease objects | NOT RUN; requires actual prototype, not mocked denial |
| C07 | Finite memory/CPU/output/message/time/concurrency limits survive abusive workloads and forced termination | NOT RUN; budgets required before acceptance |
| C08 | Independently authored example works with minimal grants; unknown API/escalation refused | NOT RUN; inspector success insufficient |
| C09 | Revocation, selection changes and restarts invalidate subsequent operations and stale messages | NOT RUN for executor |
| C10 | Install/update/rollback/reverse-flavor transitions preserve owned data and require new publisher/key/capability consent | NOT RUN |

Record Windows/runtime and source/dependency hashes, denied canary attempts, measured
resource bounds, cleanup failures and retests. A failed isolation test keeps execution
disabled; no fallback to an ordinary process. Merge of scaffolding does not approve
this proposal, prove receiver behavior or authorize production execution.

## Primary-source basis

Microsoft's [WebView2 security guidance](https://learn.microsoft.com/en-us/microsoft-edge/webview2/concepts/security)
requires evaluating document trust before exposing native facilities. Its
[frame documentation](https://learn.microsoft.com/en-us/microsoft-edge/webview2/concepts/frames)
describes frame participation in WebView network events. Our current policy matrix
does not establish initiating-frame isolation.

[AppContainer isolation](https://learn.microsoft.com/en-us/windows/win32/secauthz/appcontainer-isolation)
documents OS resource controls; this motivates a restricted worker evaluation, not a
claim our app creates one correctly. The [WASI security model](https://wasi.dev/security)
makes imports/capabilities explicit. The proposed import allowlist and Windows
combination still need implementation and adversarial tests. No unreviewed runtime
version, signature format or custom cryptography is selected here.
