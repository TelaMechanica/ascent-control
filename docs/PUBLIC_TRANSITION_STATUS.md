# AC+ and widget SDK public transition

## What is public

The public repository is `TelaMechanica/ascent-control`. PR #24's reviewed source
head is `8e5691c39d6b06287904bcacbf05daa024a44659`. PR #25's merge checkpoint is
`a6d87d63887fe46ab7b956de1ed649df0f0dddcc`, which contains that reviewed head.
Both PRs are merged; the source is on `main`, not only on a review branch.

| Area | Current state | Remaining release evidence |
|---|---|---|
| Public Windows AC | 0.43.62 downloadable MSI | Later development source needs separate release qualification |
| AC+ foundations | Host-only credential preparation and guarded receiver-readiness code | Actual receiver/daemon qualification, migration and installed transitions |
| SDK preview | Offline package inspector and deterministic declarative example | Independent example/conformance and production lifecycle |
| Widget execution | Disabled; no executor | Real browser/OS confinement, resource limits and revocation evidence |
| Private integrations | Initial-access installation and receiver widget implementations excluded | Separate reviewed ownership/composition; no private source import |

Current `release/public-payload.json` has the `internal-development` channel.
`tools/Build-Installer.ps1` intentionally refuses that channel. Source publication
is complete for the reviewed foundation; the full AC+ product and executable SDK
are unfinished. The released MSI does not acquire development features through a
source merge. No new release tag or installer is claimed by this checkpoint.

## Review and privacy

The operator supplied an independent review of a11ed1b5 and a follow-up review of
8e5691c. The follow-up reports no blocking findings. Source/host checks do not
prove browser confinement, hardware behavior or production readiness. Preserve
[the consolidated review](CONSOLIDATED_REVIEW_0.43.63_DEV3.md) and
[its response](CLAUDE_REVIEW_RESPONSE_DEV3.md) as scoped historical evidence.

Publication checks cover source, commit identities/history, PR text and any
attachments. A local operator denylist pass remains mandatory before posting;
CI's generic scan cannot substitute for it. Dispositions pin exact bytes and
cannot waive known personal identifiers. See [privacy procedure](PRIVACY_REVIEW.md).

PR #25 removes private controller-family identifiers from current HID source.
Optional local configuration is ignored by Git and absent from the explicit public
payload. With no private file, family refusal is empty. This preserves generic
public HID handling; it is not a hardware allowlist or an authorization boundary.
A private build must supply and validate its own configuration. Ignoring a file is
not sufficient sanitization for archives or attachments. Previously published
low-entropy hashes remain in history; removal from current source does not erase
that disclosure. No history rewrite or private configuration publication is planned.

## Next bounded increment

The [confinement proposal](SDK_CONFINEMENT_PROPOSAL.md) remains an unproven design.
C01's native predicate and C02's tokenless HTTP refusal have host-test evidence;
C03 and the browser part of C04 require real frame/worker/pop-up/redirect tests.
C05-C10 require actual containment, serialization, budgets, independent example,
revocation and lifecycle evidence. No test-only predicate can replace these.

Before admitting widget content, specify concrete limits and pass/fail evidence:

1. Keep untrusted content out of the trusted main WebView, including same-origin
   frames. Use separate identity/profile/origin and no privileged native hooks.
2. Specify exact message schema, instance identity, version-only response, bounded
   input/output, deadlines and rejection after revocation before implementing a broker.
3. Evaluate the proposed OS/runtime boundary with synthetic canary files and denied
   loopback/network/process/environment access; do not fall back to an ordinary process.
4. Run abusive workloads and an independently authored minimal-grant example.
5. Prove update/rollback/configuration preservation and new-grant consent separately.

The current native hook allows only the main document paths `/` and `/index.html`.
A future path-routing change needs explicit policy review and regression tests;
do not broaden it silently. Merge approval does not enable widget execution,
approve this proposal, authorize hardware work or freeze Phase 5 architecture.
