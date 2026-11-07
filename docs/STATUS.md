# Current status

## Public preview preparation 2026 11 06

Public main contains package/dependency planning contracts, tests and development workflow. The shared-runtime source import is still in a separate pending PR. No complete desktop source export or public installer is available from main.

The operator selected a developer preview rather than rushing an MSI. [Publication policy](PUBLICATION_POLICY.md) records provenance review, intended source-available use restrictions and the requirement that Ascent Control+ remain private pending operator-reported Caddx guidance and explicit publication authorization. No license grant is added by this documentation update.

Provenance review and final license terms remain preview gates. Package activation/rollback, private capability separation, public dependency inventory and install/upgrade qualification remain product release gates. The next handoff is to finish file-level provenance evidence for the pending runtime import and finalize the reviewed license scope before promotion.

## Previous migration checkpoint

Migration foundation, not a completed public application export. Shared dependency/upgrade planning contract:14tests passed locally. Base product cannot install or execute the private mapping variant without both the verified application extension and its loaded provider, even when a manifest omits the dependency. Upgrade plans keep the widget configuration-family identity.

Atomic storage/rollback, publisher trust, legacy integration, provider extraction, public/private build inventory and hardware checks are not completed by these unit tests. The running internal application has not been changed. Public project-wide licensing remains pending.

Next: claim concrete issues, import the privacy-audited source privately, and extract providers while retaining one shared application. Read AGENTS.md/current issue/PR before work; record actual commands, failures, limits and next steps at handoff.
