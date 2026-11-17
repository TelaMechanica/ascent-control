# Service Mode local preparation in the application

Development build 0.43.63-dev.3 retains the Settings workflow to check/create a
protected local credential and adds explicit receiver fingerprint observation,
confirmation and a guarded SSH no-op. Existing credentials are preserved; key
import, rotation and initial-access installation remain unavailable. The ordinary public
device functions retain their current guards. Receiver Service Mode availability
remains false, and unavailable receiver routes remain refused.

## Protection and authority

The Windows desktop creates a random per-host launch secret, supplies it privately
to its child backend, and verifies a fresh HMAC challenge before trusting the page.
The backend consumes/removes the environment entry. Neither app JSON, URLs, logs
nor widget SDKs receive the secret. A static app-name response is not sufficient
backend authentication. Requests to local preparation require exactly one valid
secret header in addition to the existing browser-origin checks. A product label,
manifest or request flag cannot substitute for that secret. Creation additionally
requires explicit confirmation and accepts no caller-supplied paths, keys or commands.

The trusted main WebView attaches the header only for this backend's local
preparation route prefix while displaying its own origin. This is not widget
confinement: untrusted widget content must never be admitted to that WebView or
receive this hook. No third-party execution is added here.

The managed store uses current-user DPAPI, never machine-wide protection. Protect,
unprotect and round-trip failures refuse storage: there is no raw-key fallback.
Only protected bytes reach the persistent create-only file. An encrypted internal
checksum detects malformed/corrupted plaintext payloads after unprotect. Existing
and corrupt files are preserved; no silent replacement, repair or migration occurs.

Key generation uses the current token's SID, obtained from the trusted Windows
whoami tool rather than an environment username, to restrict a temporary directory
before invoking the fixed Ed25519 keygen command. ACL failure stops generation.
The temporary plaintext generation file is removed by normal teardown. This does
not promise crash cleanup, secure disk erasure, Python memory wiping or protection
against another process running with the same Windows identity. DPAPI is at-rest
protection, independent from the still-gated widget execution isolation.

The old private source conditionally wrote raw bytes when DPAPI returned failure,
and its ACL helper ignored tool failures. This was a source audit finding; no
installed operator key was inspected, and no claim is made that fallback actually
occurred. The old implementation/alternate long-lived session key was not imported.

## State and UI ownership

Settings owns local preparation; there is no new primary Service Mode destination
or layout redesign. Unknown, absent, protected and busy states are explicit. Only a
successful DPAPI read supports the protected-state claim. The new-store scope is
named so absence does not imply old credentials elsewhere on the PC are absent.
Initial-access installation remains unavailable. Successful local preparation
never implies receiver authentication. The readiness flow separately requires a
selected receiver, fresh source/interface binding, explicit fingerprint confirmation
and a pinned authenticated SSH no-op before saving an immutable protected record.
It accepts no caller-selected endpoint, command, login or key path. Ed25519 and
P-256 use separate fixed credential stores. The existing device-operation lock
excludes concurrent firmware/RF operations. No receiver mutation is implemented.

The previous app.js digest remains in pin history. New rendered scope/escaping and
real-handler authorization checks accompany the intentional addition. Visual,
keyboard/accessibility and actual WebView interaction still need manual acceptance.
Historical corpus originals are preserved; its integration record explains the
bounded addition and deferred terminology/navigation work.

## Package and release boundary

The development payload explicitly allows only the shared credential dependencies:
the shared service-access, credential, protected-record, target, enrollment and
SSH-channel modules explicitly enumerated in the payload manifest.
The publisher checks exact shared-core inventory and Python import/execution rules.
Loopback probes, SDK executors, test workers and private widgets are not packaged.
Source and payload hashes are frozen. The internal-development release channel
blocks the MSI script until the publication review is complete. The internal
portable build is not a new public release or a qualified AC+ installer.

Host and Windows test results are recorded in STATUS.md and the canonical
engineering milestone. Windows tests use task-owned profiles and generated keys;
no installed settings/credentials or real receiver is used. Actual C# startup and
backend workflow checks do not constitute GUI or hardware qualification.

## Remaining integration

Source/interface binding and protected enrollment records pass synthetic host
checks. Real USB receiver behavior, daemon compatibility, operational commands,
legacy trust migration and installer/provider/data preservation remain open. Signing and isolated widget
execution retain their separate decisions. AC/AC+ release composition/branding
and independent widget updates are not established by this local preparation card.
No Phase5 architecture freeze or publication approval is implied.

Protection semantics follow Microsoft's [CryptProtectData](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata)
and [CryptUnprotectData](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptunprotectdata)
contracts. Those references do not qualify our overall application or receiver.
