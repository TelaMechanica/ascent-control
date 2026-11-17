# Review files before public posting

Every proposed source file, attachment and commit needs a privacy review for
personal/account/computer names, personal paths, BBIDs and other device
identifiers, credentials and other identifying information. Do not rely on a
filename, an earlier scan or a GitHub repository label as evidence of sanitization.
The scanner never rewrites or uploads files.

Run the normal source checks, then review the exact candidate tree:

```sh
python tools/check_tree.py
python tools/privacy_review.py --root . --git-source --metadata-since origin/main --reviewed-findings release/privacy-findings.json
```

`--git-source` includes tracked and unignored new files. It excludes Git-ignored
local evidence; it is not the correct mode for reviewing attachments or a frozen
export. `--metadata-since` checks commit messages and author/committer identities
for commits newer than the named base. Review the intended commit range after
committing as well; a working-tree scan does not sanitize old history. Use
`--history-since origin/main` instead of `--metadata-since` to additionally scan
every unique new historical blob, including deleted files. Historical findings
need their own exact-content dispositions; the current-source review list is
insufficient for older versions of the same file. The command
validates the base as a commit and does not accept Git options as a revision.

For an exact export, extracted package or attachment directory, omit
`--git-source`. Every ordinary file is checked, including normally ignored files:

```sh
python tools/privacy_review.py --root ../private-review/export --denylist ../private-review/identifiers.json
```

The optional denylist is a private JSON array of known personal names, computer
names, account names, BBIDs, serial numbers and other identifying strings. Keep it
outside source/history and all attachments. Do not paste real identifiers into
public tests or reports. Current account/computer identifiers are also derived
locally and are not serialized. Synthetic test identifiers are generated locally.
Generic shape checks cannot recognize every personal name or identifier.

The report includes item/content hashes, byte counts and finding categories. It
does not echo matched values or filenames. Keep any local mapping from an item
hash to a filename private too: names can themselves identify people/devices.
File item IDs hash the relative path; archive item IDs hash the containing label,
entry index and name. Never post raw test/build logs without their own review.

UTF-8 and both UTF-16 byte orders/alignments are checked, including binary strings
and file/ZIP names. Nested ZIPs are read in memory without extracting or executing.
Unsupported/truncated containers, encrypted or unreadable entries, symbolic links,
unsafe archive paths and resource-limit refusals prevent a pass. Resource bounds
are explicit in the tool; an incomplete scan cannot be accepted through a privacy
disposition. Known personal-identifier matches cannot be waived either. Non-ZIP
compressed formats need a separate inspected export.

Findings require review. `release/privacy-findings.json` pins the current seven
reviewed source findings to exact item IDs, bytes and categories: format-validation
markers and a synthetic key fixture, product prose resembling machine labels,
synthetic locally administered network addresses, and an incidental pattern in a
public image. It contains no matched values. A changed file or additional finding
cannot inherit that disposition. Reviewed findings remain visible and `clean`
remains false; `review_passed` distinguishes reviewed content from no detections.
Source CI runs this gate. CI lacks the private operator denylist; repeat locally
with that list before posting. Export/package findings require their own review;
source dispositions cannot automatically authorize different packaged paths.

After removing actual personal information, repeat against the final exact bytes,
review commit metadata/history and attachments, retain the content hashes and
record scope/limits. Pin any reviewed dependency finding to its verified bytes;
never silently edit a third-party DLL or suppress a whole file type. Manual
content review remains required even when automated checks pass.

The consolidated-review follow-up adds named eight-hex identity-field checks and
DSA/PGP/encrypted-private-key markers. Unlabelled eight-hex values remain ambiguous
with CRC values, colors and masks; private denylist/manual review is still required.
Non-GitHub service-token shapes are not comprehensively covered. Source CI cannot
substitute for the local operator denylist pass before every posting.
