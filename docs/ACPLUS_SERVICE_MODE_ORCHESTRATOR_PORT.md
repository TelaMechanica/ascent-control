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

## Status

Full public suite: **1073 passed, 25 skipped, 55 subtests**. Do NOT merge or publish a
release until this lands and codex re-clears the wiring — and the "re-qualify on your
unit" caveat travels with any release notes.
