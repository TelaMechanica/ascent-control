"""Minimal Windows OpenSSH environment and bounded diagnostic discard.

No ambient credential/profile inheritance. Callers select trusted tools only.
"""
import os
from pathlib import PureWindowsPath
import subprocess
from threading import Thread
from .service_access import AccessDenied


def _environment(root, *, windows, system_root=None):
    environment = {'LANG': 'C', 'LC_ALL': 'C', 'PATH': os.defpath}
    if windows:
        if not system_root or not PureWindowsPath(system_root).is_absolute():
            raise AccessDenied('SSH_WINDOWS_ENVIRONMENT_REQUIRED')
        environment['SystemRoot'] = system_root
        environment['PATH'] = str(PureWindowsPath(system_root)/'System32')
        # Windows OpenSSH needs ProgramData even with an explicit -F.
        # Both profile roots point to the empty task-owned directory.
        for name in ('ProgramData', 'USERPROFILE', 'TEMP', 'TMP'):
            environment[name] = str(root)
    return environment


def _windows_run(args, environment):
    # This Windows OpenSSH build rejects NUL stderr. Drain a pipe without keeping
    # bytes, printing them or writing potentially identifying diagnostics to disk.
    with subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                          stderr=subprocess.PIPE, env=environment,
                          creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0)) as process:
        def discard():
            while process.stderr.read(8192):
                pass
        reader = Thread(target=discard, daemon=True)
        reader.start()
        try:
            return process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            raise
        finally:
            reader.join(timeout=1)

