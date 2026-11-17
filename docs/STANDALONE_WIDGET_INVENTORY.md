# Standalone native-widget source inventory

The existing runtime checker has an explicit profile for Picker and Netrunner
native-subset exports. The default invocation still validates the desktop and
its original shared-helper/source contracts. No automatic profile detection,
empty desktop receipt or fallback is used.

From a reviewed standalone candidate root:

```sh
python tools/check_public_runtime.py --root . --widget-inventory release/widget-source.json
python tools/check_tree.py
python tools/privacy_review.py --root .
```

Repeat privacy review with the private operator denylist before posting. Generic
CI cannot replace it. Run the native builds/tests and source/artifact TAK/CoT
exclusion checks separately. Do not upload raw logs, private lists or captures.

## Explicit schema

The inventory is JSON with exactly these fields:

| Field | Contract |
|---|---|
| schema | `ascent.widget.source_inventory.v1` |
| widget | `picker` or `netrunner` |
| stage | `native-subset`; no release scope is accepted |
| files | Exact relative-path map of SHA-256, byte count and role records |
| include_roots | Unique canonical relative directories for local C includes |
| system_headers | Exact declared system-header names, including all conditional branches |
| python_imports | Unique explicitly reviewed standard-library import roots |

Each file record has exactly `sha256`, `bytes` and `role`. Roles are `runtime`,
`test`, `tool`, `document` and `build`. Runtime sources must be C/header/include
files or Python, with at least one runtime file. C/header/include source cannot be hidden
as documentation or a tool. Paths are canonical, case-distinct and portable;
links and private-state/key file types are refused.

Every ordinary source-tree file must be listed except the inventory itself and
Git metadata. There are no implicit ignored build outputs or bytecode exclusions.
Keep generated artifacts and logs outside the source root. The inventory does not
hash itself; it is an explicit review input tracked separately from file content.
It is not an authenticated publisher signature or a source of operation grants.
The inventory itself cannot be placed in Git metadata or private-state directories.

C quoted includes must resolve unambiguously to declared files inside the tree.
Runtime code cannot include a test header. Undeclared system headers, computed or
alternative include directives and includes escaping the root are refused.
Python runtime imports must be declared standard-library roots or reviewed local
top-level runtime modules. Relative/dynamic imports and direct dynamic execution
require further review. These are static dependency checks, not a sandbox proof
or complete program-behavior analysis. Tools and build plans are hash-pinned;
passing inventory does not authorize running them.

## Scope of a pass

The output explicitly retains `release_approved: false`. A native-subset pass
establishes exact source/hash/dependency agreement for this profile. It does not
claim a complete widget, privacy clearance, license provenance, a safe installer,
TAK exclusion, hardware compatibility or third-party execution confinement.

The locally reviewed extraction contains a Netrunner handoff policy library and
Picker receiver switching core, not full standalone products. Complete the host
controls, shared-renderer boundary, license/asset provenance, package ownership
and lifecycle/data-preservation checks before repository publication. Mapster
and Mapster-TAK extraction are deferred. Their private source and operational
fixtures are not inputs to this tooling change.
