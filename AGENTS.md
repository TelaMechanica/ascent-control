# Shared instructions for coding agents

Read README.md, docs/STATUS.md and docs/TASKS.md first. GitHub code, issues, pull requests and checked-in status are authoritative; chat memory is not. Do not assume an older local directory or branch is current.

- Start from the selected repository/branch. Use one feature branch/worktree per active agent or issue. Do not have two agents mutate the same working tree.
- Claim an issue and record the files/scope you own. Commit explicit file lists; never sweep unrelated work into a commit. Preserve surviving work and failed evidence.
- Open a reviewable PR with problem, behavior, tests, limits and next handoff. Update docs/STATUS.md and the issue before stopping, including failures and exact commit IDs.
- Keep one shared application. Product upgrades and widget upgrades preserve their data owners and validate dependencies before changes. Widget family/configuration identity is not the package variant name.
- Reject missing/inactive capabilities at the operation boundary. Interface visibility, environment variables and edition labels do not authorize operations. Preserve target/identity/binding checks.
- Do not introduce personal account names, local home/cloud-folder paths, real device identifiers, credentials, keys or raw bench captures into code, fixtures, docs, commit metadata or history. Use generated synthetic fixtures and portable paths.
- Hardware tests require explicit operator authorization. Host tests, mocks, listeners and transport replies are not physical qualification. Record evidence scope truthfully.
- Make bounded changes, run appropriate behavioral checks, then the applicable full suite. Do not weaken checks to obtain a pass. Keep failed runs and append retests.
- Do not force-push protected branches or publish private material. Migration branches are not releases; public export needs its own content/dependency/package checks.
