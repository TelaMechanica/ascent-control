# Widget SDK 0.1 development preview

This is a source-review scaffold, not a released SDK or an installed widget runtime.
Its package inspection tool runs offline using Python's standard library. The
example is declarative text; no package code is loaded or executed.

From the repository root:

```sh
python tools/widget_sdk.py example hello-widget.zip
python tools/widget_sdk.py validate hello-widget.zip
```

The example command creates a new file and refuses to overwrite one. It produces
identical bytes on repeat builds with the same source. Keep generated archives
outside source commits. Validation reports `publisher_verified: false` and
`executable: false`; success does not mean a publisher or runtime is trusted.

The provisional manifest has exactly these fields:

| Field | Meaning |
|---|---|
| schema | `ascent.widget.v0` |
| id | Stable lowercase package identity |
| version | Three-part 0.x development version |
| sdk | `0.1`, provisional compatibility contract |
| display_name | Human-readable package name |
| capabilities | Declared subset of documented host operations |
| files | Exact payload inventory with SHA-256 digests |
| view | JSON file containing a text view |

The prototype recognizes `host.version.read` as a reserved API declaration, but
has no execution dispatcher. The example requests no capabilities. Only a JSON
text view is admitted; there is no Python, JavaScript, native or WASM execution.
Future renderers must render text as text, never as HTML. Package inspection does
not extract files, install, replace, migrate or remove packages.

Validation rejects unsafe Windows/ZIP paths, case collisions, links, extra files,
duplicate JSON keys, unsupported fields, undeclared/mismatched payloads and
oversized archives. These protections are not a completed installer security
review. Atomic updates, rollback, signed provenance, user-grant persistence,
confinement and independently released end-to-end updates remain unimplemented.

## Service Mode boundary

`ascent_core/service_access.py` is a trusted host adapter contract. Packages must
never receive its backend, session, credentials or raw receiver commands. It
requires application-owned provider/enabled state and a current receiver binding,
and rechecks both after acquiring a session. The selected-device lock is held
through the lease. A production backend must retain verified enrollment, pinned
host keys and existing device/transport guards. The shared application now has a
separate guarded [receiver-readiness no-op](../SERVICE_MODE_LOCAL_PREPARATION.md);
that host controller is not exposed to SDK packages. This inspector has no widget
operation dispatcher and does not activate Service Mode on a receiver.

Revocation during an already running operation requires cancellation and bounded
operation semantics in the eventual backend; the lease alone does not solve that
problem. A same-user process or limited Python object API is not confinement.

## Public and private ownership

The proposed public release family has AC and an empty AC+ base using one core.
`release/product-bases.json` records this intent; it does not modify the existing
MSI or grant privileges through an edition label. Service Mode is the first AC+
capability to integrate. Widgets are optional and remain private until the
operator selects particular versions for publication. No private implementation
is imported in this scaffold.

No payment, activation licensing, account requirement or license server is added.
Distribution decisions are separate from operation authorization and the existing
source license. Publisher trust is also separate from capabilities: an open SDK
must permit independently developed packages. The production trust model remains
an explicit review decision: vendor roots, user-managed publisher trust, or a
hybrid. Development trust must never silently become production trust. A valid
signature will not authorize access to credentials or unrestricted operations.

The 0.x contract may change with documented migration notes. A stable SDK release
requires an independently authored example, production isolation findings,
per-operation authorization, updates/rollback and conformance tests. Receiver-side
third-party execution is outside this preview.

## Review follow-up: cooperative session liveness

A trusted host lease now yields `ServiceLease(session, check)`. The backend calls
`check()` before each bounded step. It observes provider/enablement or selection
changes at that boundary and refuses use after the lease closes. It cannot abort
a blocking operation or undo an already committed device change. Owned synthetic and localhost SSH
backend tests exercise this lease contract. The application's separately tested
readiness controller does not make the lease or a package manifest a widget
execution authority. The proposed open publisher-trust contract is in
PUBLISHER_TRUST.md.
