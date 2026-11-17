# Windows OpenSSH localhost parity checkpoint

The same guarded fixture handshake now passes with the installed Windows OpenSSH
9.5p2 client and the packaged Windows Python 3.12.7 runtime. This is Windows-client
to owned WSL-localhost server proof, not receiver or installed-app qualification.
No receiver, installed credentials, user SSH configuration or system service setup
is used or modified. Server/client fixture keys remain temporary and unpublished.

## Actual Windows fixes

Option-file paths use forward-slash Windows spelling before quoting. Windows
SystemRoot and a minimal system executable path are supplied explicitly. This
client silently exited255 without ProgramData even for a version-only invocation;
ProgramData, USERPROFILE and temporary-directory variables now point at the empty
owned fixture directory, rather than inheriting actual user/global profile roots.
No agent, password, askpass, proxy or ambient identity fallback is enabled.

A clean non-verbose run exposed a second issue: Windows OpenSSH exited255 when
stderr was NUL, but succeeded with a pipe. The Windows subprocess now drains stderr
in8192-byte chunks and discards it without keeping, printing or writing diagnostic
bytes. Timeout handling kills and reaps the owned process. Linux behavior retains
its existing DEVNULL path. Unit tests cover minimal environment isolation, missing
SystemRoot, discard-pipe configuration and timeout kill/reap behavior. These are
observations on this installed build, not claims about all Windows SSH versions.

## Reproducible platform check

The portable worker is tools/testing/windows_ssh_worker.py. An opt-in WSL test
starts the existing owned Linux fixture and launches the worker through Windows
PowerShell using a trusted Windows Python executable. Set ASCENT_WINDOWS_PYTHON to
its WSL-mounted executable path and explicitly enable ASCENT_TEST_WINDOWS_SSH=1.
Use ASCENT_TEST_LOOPBACK_SSH=1 to include Linux handshake cases in the same full run.
No tool installation, administrator SSH server or hardware is required by the
harness. The fixture requires the already-installed OpenSSH tools and prerequisites.

The worker copies only synthetic client keys to its owned Windows temporary
directory, removes inherited key ACLs and grants current-user read access. It
proves two fresh authenticated steps, rejects the wrong server and client keys,
refuses after provider loss, and discards a completed result after credential
revision change. Keys are removed when its temporary directory exits. Local-only
failure logs may contain account paths; tests never upload or package those logs.

The R4 fixture now clearly skips when a writable ancestor would cause StrictModes
failure, rather than weakening StrictModes or misreporting the environment as an
authentication defect. noop also documents its required caller-side pin comparison.

## Remaining product work

This module still is not shipped or wired into the AC application. It provides no
credential/enrollment persistence, real receiver endpoint or source-interface
binding, legacy-pin migration, additional host-key algorithms, installed upgrade
proof, signing or widget execution. The read-only SFTP channel remains a fixture
mechanism; Dropbear receiver support must use its own reviewed operation contract.

The Windows proof closes the client-parity uncertainty for this setup. It does not
close device qualification or authorize publication. The next product milestone
remains reviewed Service Mode credential/transport integration into an internal
AC+ application, followed by installer/data preservation and authorized bench work.
