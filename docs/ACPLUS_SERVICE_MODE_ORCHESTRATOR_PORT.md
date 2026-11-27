# AC+ Service Mode — orchestrator port and 0.50.2 hardening

**Date:** 2026-11-27. **Branch:** `feature/acplus-service-mode-enable`.
**Context:** PR #69 (AC+ one-touch Service Mode, 0.50.2). This record documents the
static-review findings, the fixes, and — most importantly — the honest verification
boundary, so nobody later mistakes "the suite is green" for "proven on hardware."

## TL;DR

The one-button Service Mode that shipped in the public base (`local_service_activate`)
was a thin re-implementation with its own history, **separate from the bench-proven
engineering orchestrator**, and it was broken by construction. This change replaces it
by porting the engineering orchestrator onto the public base and wiring it to the
existing public primitives and firmware policy. Four static-review findings fixed.

**Verification boundary (read this):** the orchestration logic and its firmware policy
are unit-tested with doubles; the first-access primitive is bench-proven on *prior*
builds (MAX/VRX 19.2.14, Pro 18.21.10). **There is no factory-fresh, one-press bench
record for the exact 0.50.2 public build.** The strongest honest claim is "functional:
proven orchestrator design, re-qualify on your unit" — never "proven on this build."

## The static-review findings (codex, 2026-11-27) and their fixes

1. **(blocker) One-touch did not establish the transport handoff.** The old wrapper
   took a receiver observation *before* enrollment and reused that same observation at
   verification. The observation expires 60 s after `inspect()`
   (`service_receiver.py`), while the serial first-access between them alone has a 45 s
   timeout, and the wrapper performed no serial→RNDIS transport switch. So even a
   perfect run routinely died at `RECEIVER_OBSERVATION_EXPIRED`. **Fix:** port the
   engineering orchestrator; verification now takes a **fresh** observation adjacent to
   the check, after install and with the transport up. Locked by
   `tests/test_service_mode_activate.py::...verifies_against_a_fresh_observation`.
2. **(high) Edition override beat the installed stamp.** `_resolve_edition` read env
   `ASCENT_EDITION` before the install-root stamp, so an inherited env var could flip an
   installed AC to acplus. **Fix:** the installed stamp WINS; env override only resolves
   an unstamped/dev build. Edition only governs *exposure*; authorization stays at the
   host-session / operation boundary. `tests/test_public_desktop_boundary.py`.
3. **(high) Failure could be reported "receiver untouched" without evidence.** **Fix:**
   the orchestrator's honest taxonomy — `RECOVERY_REQUIRED` = device-side state may be
   left behind (→ `receiver_modified: true`); `BLOCKED` = prerequisite unmet, nothing
   changed. Uncertainty maps to RECOVERY_REQUIRED (the safe direction).
4. **(high) Pair verifier never inspected the edition stamp.** Two mis-stamped MSIs
   would pass. **Fix:** `Verify-PairedInstallerRelease.ps1` now admin-extracts each MSI
   and asserts `ascent_edition.txt` == expected edition and the two differ;
   `windows-publish.yml` runs publish-only for **both** editions.

## The orchestrator port

`ascent_core/activation_orchestrator.py` is the engineering state machine (from the
consolidated tree, commit `9cb725a`), ported verbatim except:
- its engineering-only `import service_mode` (persistence-cause classifier) is dropped;
  that branch is dormant in the public wiring (no `host_key_matches` injected).
- it was **renamed** from `service_mode_orchestrator` → `activation_orchestrator`
  because the public build verifier (`tools/verify_public_build.py`) blocks any import
  whose name starts with `service_mode` (the private engineering module). The name is a
  build-boundary constraint, not a style choice.

Its 33-test engineering suite ported verbatim as `tests/test_activation_orchestrator.py`
and passes unchanged — proof the port is faithful.

### Public wiring (`dev_harness.py`, `_build_service_mode_orchestrator`)

Every collaborator is the existing public primitive; the orchestrator owns no policy:

| Orchestrator step | Public primitive |
|---|---|
| identify | `SESSION.device` / `ACTIVE_CONNECTION` (receiver role only) |
| transport ready / configure / rollback | the single ContainerId-correlated RNDIS adapter + `_configure_rndis_elevated`; **never guesses among several** (fails safe to "configure USB networking first"); dismissed UAC → `PermissionError` → `OPERATOR_DECLINED` |
| firmware_supported (stage 2) | `service_firmware.stage2_supported` |
| initial_access_validated (stage 1) | `service_firmware.stage1_supported` |
| stage1_attemptable | `service_firmware.stage1_attemptable` (+ per-request `acknowledge_unproven`) |
| initial_access.establish | `first_access.install_key` — the public exploit does first-access AND enrollment atomically, so `enroll_begin` is a confirming no-op |
| enroll_verify | **fresh** `service.inspect()` → `service.verify(...)`; translates `ssh_authenticated`/`trust_record_saved` → `verified` |
| already_verified | `inspect().trusted_record_present` (idempotent re-verify, no second key) |
| revoke | best-effort; no device-side removal exists publicly, so reports `cleanup_complete: false` → RECOVERY_REQUIRED (never claims a clean receiver it can't confirm) |

`_service_mode_ui_result` adds the hash-pinned UI's expected fields (`ok` derived ONLY
from `state == VERIFIED`, `receiver_modified`, `first_access`, `verification`) on top of
the orchestrator's rich result, so the UI is untouched. The ack-attempt tier (19.2.17)
is backend-ready but **not yet UI-exposed** — the pinned UI sends an empty body, so it
cannot pass `acknowledge_unproven`; unproven firmware shows BLOCKED there until the UI
gains an acknowledgment control (future, hash re-pin).

## Firmware policy (operator decisions, 2026-11-27)

`service_firmware.py` already held the two-tier model. Decisions recorded:

- **Validated (auto-proceed, `stage1_supported`):** VRX, VRX MAX HF/WF @ **19.2.14**
  (operator end-to-end confirmation 2026-10-27); VRX Pro @ **18.21.10** — **added this
  change**, operator-designated. Honest caveat: the 2026-10-30 Pro bench reached
  VERIFIED with an independent pinned-key SSH check but the first-access *tool timed
  out*, so the checkpoint graded it PARTIAL; the operator elevated it to validated for
  distribution. A matching stage-2 row was added (the SSH auth demonstrates a readable
  `authorized_keys`; reboot persistence is gated separately).
- **Acknowledge-to-attempt (`stage1_attemptable`):** **19.2.17** and any other unproven
  firmware on a platform with prior first-access evidence — proceeds only with a
  per-request operator acknowledgment that it is unproven.
- **Blocked:** everything else (fail-closed).

## Build/boundary lessons (so the next change doesn't relearn them)

- A new `ascent_core/*.py` must be: (1) added to `src/Ascent.Desktop/Ascent.Desktop.csproj`
  as a `<Content><Link>` (the publish inventory the payload is checked against), (2)
  pinned in `release/public-payload.json` `source_files` AND `files[]`, and (3) named to
  avoid the `BLOCKED` prefixes in `tools/verify_public_build.py` (`service_mode`,
  `widget_`, `picker`, `netrunner`, `private_receiver`, `receiver_operations`,
  `receiver_fleet`, `update_enroll`, …).
- Test files are mostly NOT pinned in `source_files`, so they need no payload entry.
- Stage the commit as an explicit file list; never `git add -A` (the tree carries
  unrelated untracked files such as `tools/privacy_gate_binary.py`).

## Re-review round 2 (codex, 2026-11-27) — findings and fixes

A second static review of the wiring (commit `e9ae15f`) raised five:

1. **(blocker) AC+ Windows publish failed the GStreamer registry assertion.** My
   both-edition publish-only loop ran both editions in **one `pwsh` process**;
   `Test-GStreamerPayload.ps1` loads the native gstreamer library and calls `gst_init`
   in-process, so the second edition reused the first's initialised library and its
   registry never got written. **Fix:** run each edition in its own `pwsh` process
   (`windows-publish.yml`). The payloads are identical; this was a process-state leak the
   loop introduced.
2. **(high) Freshness test too weak.** It passed even if the only observation were
   pre-install. **Fix:** the test now asserts verify's `obs-<N>` exceeds the count of
   inspects taken *before* install — i.e. the observation came from a post-install
   inspect.
3. **(high) Modification reported with too much certainty.** `install_key` collapses
   first-access and the authorized_keys write, so a `verify_install`-stage failure (the
   write ran, readback failed) was reported as "not modified." **Fix:**
   `_service_mode_modification` derives an honest `modification_state` from install_key's
   own stage — `modified` (write ran / leftover possible), `unknown` (a shell may have
   been obtained), `untouched` (provably no write). `unknown` never projects to
   "not modified"; the pinned UI's boolean gets the safe direction, the precise state is
   in `modification_state`.
4. **(high) Pro policy graded VERIFIED on a PARTIAL bench.** **Fix:** new
   `OPERATOR_DESIGNATED` grade; the Pro 18.21.10 Stage-1 row keeps the observed managed
   auth, the original PARTIAL first-access grade, and the operator designation as
   **separate fields**, and discloses that the (platform, version) key also admits other
   MAX models on 18.21.10.
5. **(medium) Stamp placement unverified.** **Fix:** both the pair verifier and the
   publish-only check now require the stamp **beside the application** (install root),
   anchored on `AscentControl.exe`/`.dll`, not merely somewhere in the tree.

Observations also addressed: a typed `ElevationDeclined(RuntimeError)` replaces the
English-substring match for a dismissed UAC prompt; `local_service_activate` has a
catch-all so an unexpected wiring fault returns a clean error instead of a 500 (lock/state
still restored by `finally`).

## Re-review round 3 (codex, on ce6f289) — findings and fixes

Codex confirmed round 2's #1 (green in PR CI), #2, #4, #5. Remaining, now fixed:

- **#1 release-side.** The PR publish-only check was isolated, but the **tag-time**
  release build (`windows-msi.yml`) still ran both editions in one `pwsh` process — same
  GStreamer-init leak. **Fix:** each edition builds in its own `pwsh -File` process there
  too. (The paired MSI verifier + extraction only run in this release job, not in
  publish-only — expected.)
- **#3 (High) completed — UI change + re-pin.** The binary UI genuinely could not
  represent "unknown": it read the boolean and told the operator "the key was installed,
  retry is safe" even when the outcome was unknown. Fixed by making the activation panel
  read `modification_state` and show three honest cases — modified / **unknown** ("a
  privileged session was reached but the outcome could not be confirmed; inspect before
  retrying") / untouched. This is a deliberate, functional change to the hash-pinned UI
  (`runtime/www/app.js`); `tests/locked_ui.py` re-pinned with a dated history entry. No
  CSS/navigation/markup change.
- **Observations.** The PowerShell UAC-cancel detection now classifies on the stable
  Win32 code 1223 / HRESULT 0x800704C7 (English message only as a last-resort fallback).
  `local_service_activate` now runs `orchestrator.activate()` first and shapes the result
  separately, so a shaping error can no longer discard a known activation outcome.

## Re-review round 3-delta (codex, on 486d680) — two partials, fixed

Codex confirmed the release-build isolation and the outcome-preserving shaping, and left
two partials:

- **UI reporting still over-claimed on ambiguity.** Fixes: only an explicit `untouched`
  renders "not modified"; an absent or unrecognised `modification_state` (or a bare legacy
  boolean) renders uncertainty copy that asserts nothing; and the ambiguous message no
  longer claims "a privileged session was reached" (unknown also covers a mid-access
  exception where no session was reached). `app.js` re-pinned again.
- **UAC-cancel classifier.** The English message was an unconditional alternative that
  could override a known non-cancel code, and only the outer exception was inspected.
  Fixes: walk the `InnerException` chain for Win32 1223 / HRESULT -2147023673; a present
  Win32 code is authoritative; the message match runs ONLY when no Win32 code is exposed
  anywhere.

## Status

Full public suite: **1075 passed, 25 skipped, 55 subtests**. The AC+ publish blocker is
fixed in source for **both** the PR and release workflows; the PR publish-only run went
green, and the release build must be confirmed green on its tag. Do NOT merge or publish a
release until CI is green and codex re-clears — and the "re-qualify on your unit" caveat
travels with any release notes.
