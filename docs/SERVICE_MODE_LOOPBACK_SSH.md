# Service Mode real SSH proof on owned localhost fixtures

Status: development review, Linux/OpenSSH host proof only. No receiver transport,
production credentials, operational key store or desktop runtime wiring. The
module is not included in the public MSI. Default tests do not start SSH servers.

Run the explicit integration suite from a checkout with OpenSSH client, server
and keygen available, and an owned workspace with restrictive parent permissions:

```sh
ASCENT_TEST_LOOPBACK_SSH=1 python -m pytest tests/test_service_loopback_ssh.py -q
```

The tests create an unprivileged server bound only to IPv4 loopback and an
OS-assigned high port. Host/client/wrong-key pairs are freshly generated in an
owned temporary workspace, removed at fixture teardown and never included in
review artifacts. No installed authorized_keys, known_hosts, private key, daemon
configuration or receiver is used or modified. The fixture requires the host's
existing OpenSSH privilege-separation prerequisites; it changes no system setup.

## What is now proved

Unlike the offline supplied-key comparison, a successful step completes an
OpenSSH transport handshake against exactly the pinned Ed25519 key and public-key
client authentication with the fixture's authorized identity. It opens and closes
the server's internal read-only SFTP subsystem with null input: no SFTP file
request, shell command, user shell, user startup script or data operation is sent.
The server forces internal-sftp -R and disables user rc, forwarding and PTYs.

The client has an isolated empty configuration, explicit identity, isolated
known_hosts, strict host-key verification, no TOFU/update-host-keys, no agent,
password, interactive or GSSAPI fallback, no proxy/jump, no multiplexed connection
reuse and no local command or forwarding. Public-key authentication is the only
permitted client method. stdout/stderr are discarded; errors expose stable codes.
The subprocess has a five-second outer deadline and tighter connection limits.

LoopbackReadOnlySshBackend invokes the existing record/lease guards before and
after each completed handshake. Every step creates a fresh connection. Its
successful result says authenticated_transport=true, loopback_only=true,
operation=completed-noop and connection_reused=false. This is evidence about that
completed fixture connection; it does not mean a live authenticated session is
cached. A subsequent server loss or revocation cannot reuse an earlier success.

## Boundaries and failures tested

Real fixture tests cover successful fresh connections, a server unable to prove
the pinned private key, a client with an unauthorized key, revocation before the
next connection, a credential revision change during a completed connection and
server loss. Timeout and process-error tests inject failures and verify stable
redacted errors; those two cases are mocks, not independent SSH timeout evidence.

The R3 supplier exception contract is now explicit: expected OSError/ValueError
are normalized; programmer exceptions abort and must not be serialized as user
messages. Session registry strong references are retained until close.

## Limits before real receiver integration

This is a loopback-only development probe. A trusted host supplies the tool path,
fixture identity and endpoint binding; packages have no access to the backend.
It does not qualify Windows tool behavior, receiver SSH daemons, interface/source
address binding, real credential storage/protection, enrollment provenance, host
identity continuity, supported command execution or cancellation on a receiver.
Receiver Dropbear may not provide SFTP; the fixture's SFTP channel is NOT a proposed
receiver protocol or deployment mechanism. A future receiver adapter needs its
own reviewed read-only operation contract, retaining existing transport guards.

Revocation cannot forcibly interrupt a blocking call; this bounded step may finish
before its result is refused. Before every future side-effecting step, check live
state and transport/receiver/credentials and operation permissions. A later check
cannot roll back partial/completed effects. This increment has no such operation.

Alternate long-lived session keys, key-path diagnostics, ECDSA/RSA, legacy pin
migration, signing, widget execution, installer/provider preservation and hardware
qualification remain separate gates. Signing policy is still not operator-accepted
for implementation. No publication or Phase 5 freeze is implied.

## Primary references

[OpenSSH ssh_config](https://man.openbsd.org/ssh_config) documents strict host-key,
identity, configuration and forwarding controls; [ssh](https://man.openbsd.org/ssh)
documents subsystem requests; [sshd_config](https://man.openbsd.org/sshd_config)
documents forced internal SFTP and user-rc control;
[sftp-server](https://man.openbsd.org/sftp-server) documents read-only mode.
These references support configuration choices, not receiver qualification.
