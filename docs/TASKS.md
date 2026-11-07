# Migration work queue

- MIG-01: preserve original state locally and create a privacy-audited, fresh-history source import.
- MIG-02: shared application/extension/widget manifest and dependency contracts; refuse Mapster+ on base product.
- MIG-03: atomic upgrade/rollback and stable data/configuration ownership.
- MIG-04: extract private capability providers and remove unconditional private imports from the public application.
- MIG-05: component-owned advanced mapping extraction and removal from public build/dependency closure.
- MIG-06: public/privacy/package inventory CI and shared agent handoff workflow.
- MIG-07: reproducible public/private builds and clean install/upgrade acceptance; retain all hardware gates.

These are implementation tasks, not completed claims. Assign concrete GitHub issues and attach evidence as work lands.

## Developer preview preparation 2026 11 06

Current documentation scope: README.md, docs/STATUS.md, docs/TASKS.md and docs/PUBLICATION_POLICY.md. Preserve pending runtime-import review. Complete file-level provenance and intended source-available license review before promoting a public developer preview. Keep AC+ private pending operator-reported Caddx guidance and explicit publication scope. This batch changes no application behavior and creates no installer.


## Executable source review snapshot 2026 11 06

Current scope: six retained runtime helpers and their tests/source receipt, offline CLI and meaningful command tests, runtime inventory/closure checker, technical README/status and source review. Record operator-reported verbal Caddx CRSF/MSP approval. Preserve the pending historical source branch; no original history rewrite. Run the full pytest suite (including retained function-based protocol tests), source closure/hash and privacy checks before merge. Service Mode and dependent widget releases remain private/gated; do not publish them. Continue the full application migration separately.
