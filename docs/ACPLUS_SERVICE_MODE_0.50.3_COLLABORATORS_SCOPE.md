# AC+ Service Mode — 0.50.3 collaborator scope

**Status:** scoping only, no code. Grounded in the 0.50.2 source.
**Context:** the 0.50.2 public AC+ wires the bench-proven activation orchestrator
(`ascent_core/activation_orchestrator.py`) to the public primitives in
`runtime/dev_harness.py::_build_activation_orchestrator`. The orchestrator accepts
four **optional** diagnostic/recovery collaborators and one **required** `revoke`.
The public 0.50.2 build passes `revoke` as an honest stub and omits the other four,
so the engineering lab build is richer on recovery and diagnostics. This document
scopes closing that gap in a 0.50.3, by item, with the real cost driver named.

## The one fact that drives all the cost

The public post-enrollment SSH transport is a **readiness-noop by design.**
`service_receiver.verify()` authenticates against a fresh observation and returns
`{'operation': 'readiness-noop', 'receiver_mutation_available': False,
'initial_access_available': False}` (`service_receiver.py:318-320`). It proves the
managed key authenticates; it does **not** expose arbitrary command execution on the
receiver. The only command-executing channel in the public tree is
`first_access_session.run_command` (`first_access_session.py:531`), which rides the
**first-access** path (the disclosed updater mechanism), not the steady-state SSH
session.

So each collaborator splits by one question: **does it need to run a command on the
receiver, or is it host-side data / a read-only banner?**

| Collaborator | Needs receiver command exec? | Tier |
|---|---|---|
| `audit_sink` | No — host-side only | **A (trivial)** |
| `host_key_matches` | No — compares data already captured host-side | **A (low)** |
| `probe_ssh` | No — read-only SSH *banner* grab (no exec) | **B (low–med)** |
| `reboot_persistence` | Yes — one read-only command (`/proc/uptime`) | **C (med)** |
| `revoke` (real cleanup) | Yes — a *write* (`authorized_keys` line removal) | **C (med, structurally partial)** |

## Tier A — host-side only, no device capability, ship first

### `audit_sink: Callable[[dict], None]`
The orchestrator already **builds** the record and calls the sink
(`activation_orchestrator.py:292-298`): `{at, device_id, outcome, failure_class,
steps}`. Wiring it is host-side only — append each record to a local, append-only
Service Mode activation log (rotate-bounded), surfaced in DIAGNOSTICS.
- **Work:** a `_ServiceModeAuditLog` writer + pass it as `audit_sink=`; UI read path.
- **Risk:** none on the device. Privacy: scrub device identifiers per the existing
  log-sanitisation rule before anything is exportable.
- **Device dependency:** none.

### `host_key_matches: Callable[[], bool | None]`
Used on an authentication failure to withdraw the "leftover state" alarm when a
firmware upgrade took both our `authorized_keys` line **and** the host key together
(`activation_orchestrator.py:320-335`). The two inputs it compares already exist
host-side: the enrolled host key is stored on `ReceiverEnrollment`
(`service_receiver.py:296-298`, `existing.host_public_key`) and the current host
fingerprint comes from `inspect()`. No receiver command is required — it is a
comparison of data we already hold.
- **Work:** a resolver that looks up the saved enrollment for the target and compares
  its host key to a fresh `inspect()` fingerprint; return `True`/`False`/`None`.
- **Risk:** low; return `None` (unknown) on any doubt — the orchestrator treats
  unknown as "no change to the message."
- **Device dependency:** none (rides existing `inspect()`).

## Tier B — read-only network probe, no command exec

### `probe_ssh: Callable[[dict], dict] -> {banner, error}`
Used only when firmware qualification is **UNKNOWN** (`stage2_supported is None`) to
settle it by live observation: a reachable sshd banner upgrades UNKNOWN → supported
(`activation_orchestrator.py:402-424`). A measured `False` is never overturned. This
is a TCP connect + SSH identification-string read over the already-correlated
adapter — **no command execution, no auth side effects.**
- **Work:** a small banner probe bound to the correlated RNDIS interface
  (`_service_mode_correlated_adapter`), returning `{'banner': ...}` or `{'error': ...}`.
- **Risk:** low; read-only, no key material, no writes.
- **Device dependency:** reachable sshd only (no new primitive).

## Tier C — needs an authenticated command-executing SSH channel

Both items below require the capability the public `verify()` transport deliberately
withholds: running a command over the enrolled SSH session. This is the real
architectural decision of 0.50.3 — whether to add an **authenticated SSH exec** to
the public service transport (today it is a readiness-noop).

### `reboot_persistence: Callable[[], dict]`
Evidence that the key survived a power cycle (`activation_orchestrator.py:576-596`).
The method is already specified in-code and is read-only: we have just authenticated,
so read the receiver uptime (`/proc/uptime`); if uptime < time-since-enrollment, it
was rebooted since the key was installed **and the key still works** (we are talking
to it). That is exactly the evidence that proved the Industrial unit by hand.
- **Work:** add a single read-only command execution to the service transport
  (`cat /proc/uptime`), plus the enroll timestamp (host-side trust record already
  carries enrollment time, or add it). Return `{reboot: INTACT|UNKNOWN, ...}`.
- **Risk:** low-ish — one read-only command, no writes — but it does mean upgrading
  the transport from readiness-noop to "can run a read command," which widens the
  public build's capability surface. Decide that deliberately.
- **Device dependency:** authenticated SSH exec (read-only).

### `revoke` — real receiver-side cleanup (today an honest stub)
0.50.2 returns `{'cleanup_complete': False}` (`dev_harness.py:273-278`) so a
verify failure maps to RECOVERY_REQUIRED rather than falsely claiming the receiver
was left clean. A real `revoke` removes our managed `authorized_keys` line
(`enrollment_commands.py` already builds the append command; a removal is its
inverse) over an authenticated session.
- **Structural limit — do not over-promise:** `_recover()` runs *because* something
  failed, and the usual failure is SSH itself (`activation_orchestrator.py:605-609`).
  When SSH is down there is **no channel to remove the line**, so the honest
  RECOVERY_REQUIRED outcome **remains** for that case even after this work. Real
  revoke only helps the subset where auth still succeeds but a later step failed
  (e.g. trust-record write). It is a *narrowing* of the recovery-required set, not an
  elimination of it.
- **Work:** an authorized_keys line-removal command over authenticated SSH exec;
  return `{'cleanup_complete': True}` only on verified readback that the line is gone.
- **Risk:** this is the only **device write** in the set. It removes *our own*
  owner-authored key line — squarely inside the settled managed-key provisioning
  authorization (CLAUDE.md §7(c), 2026-11-27), not a new capability. Still: write,
  readback, and never report `cleanup_complete: True` without the readback.
- **Device dependency:** authenticated SSH exec (write + readback).

## Recommended sequencing for 0.50.3

1. **Tier A first (audit_sink, host_key_matches).** No device capability, low risk,
   immediately improves the operator-facing honesty of failures and gives an audit
   trail. These are safe to ship without any bench time.
2. **Tier B (probe_ssh).** Read-only; removes the "every firmware upgrade re-blocks a
   working unit until a table row is added by hand" papercut. No writes.
3. **Tier C last, and as one decision.** `reboot_persistence` and `revoke` both hinge
   on adding an authenticated SSH-exec to the public service transport. That is a
   deliberate widening of the public build (today it is a readiness-noop), so decide
   it explicitly. If taken: do the read-only `reboot_persistence` before the writing
   `revoke`, and keep the SSH-down RECOVERY_REQUIRED outcome honest throughout.

## What stays true regardless

- None of this makes 0.50.2's activation unsound — it is the proven state machine with
  a leaner collaborator set. These are diagnostic/recovery **enhancements**.
- The "re-qualify on your own receiver" caveat is independent of this work: it is about
  this exact build not being independently bench-proven end to end, not about the
  collaborators.
- Tier C requires bench validation before it can be called proven; the user has
  deferred bench testing until more features are ready, so Tier C ships (if at all) as
  "implemented, re-qualify on your unit," never as "bench-proven."
