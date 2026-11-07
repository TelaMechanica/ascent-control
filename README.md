# Ascent Control

Public shared application and extension interfaces. Ascent Control+ is a private in-place capability upgrade to this same application; it is not a fork. Widgets are independently versioned packages.

## Migration status

The existing internal application is being migrated. This repository initially contains the shared package/dependency contracts and development workflow; it is **not yet the complete public application export**. Do not advertise a finished public installer from this branch. The existing internal release is maintained separately during extraction.

Widget and application-extension installation must validate product dependencies, versions and active providers. Mapster+ requires Ascent Control+; a UI toggle or supplied edition string cannot satisfy this requirement. Data/configuration remains owned by the same application and widget family across upgrades.

Read AGENTS.md, docs/STATUS.md and docs/TASKS.md before work. Both coding agents follow those same instructions. Run `python -m unittest discover -s tests -v` for the initial contract checks.

A project-wide license has not yet been selected. No blanket license grant is added by this migration; third-party material retains its own terms.

## Public preview and licensing

See [publication policy](docs/PUBLICATION_POLICY.md) for the source review process, intended use restrictions and private product boundary. The intended model is source-available; final terms are not yet applied. Public availability does not mean vendor material is licensed for reuse.
