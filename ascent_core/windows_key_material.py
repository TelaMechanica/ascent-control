"""Transient private-key files for trusted Windows host operations only.

No plaintext persistent fallback or alternate long-lived key. Normal teardown
removes files; crash cleanup and secure memory/disk erasure are not guaranteed.
"""
from contextlib import contextmanager
import csv
import os
from pathlib import Path
import re
import subprocess
import tempfile
from .service_credentials import CredentialError, ManagedCredential
from .windows_tools import _environment


@contextmanager
def private_key_directory():
    if os.name != 'nt': raise CredentialError('WINDOWS_PROTECTION_REQUIRED')
    system = os.environ.get('SystemRoot')
    if not system: raise CredentialError('WINDOWS_PROTECTION_REQUIRED')
    with tempfile.TemporaryDirectory(prefix='ascent-private-key-') as folder:
        root = Path(folder)
        tools = Path(system)/'System32'
        env = _environment(root, windows=True, system_root=system)
        try:
            response = subprocess.run([str(tools/'whoami.exe'), '/user', '/fo', 'csv', '/nh'],
                stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=5,
                check=True, env=env, creationflags=subprocess.CREATE_NO_WINDOW)
            sid = list(csv.reader(response.stdout.splitlines()))[0][-1]
            if not re.fullmatch(r'S-1-(?:[0-9]+-)*[0-9]+', sid): raise ValueError('SID')
            result = subprocess.run([str(tools/'icacls.exe'), str(root), '/inheritance:r',
                '/grant:r', '*' + sid + ':(OI)(CI)F'], stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5,
                env=env, creationflags=subprocess.CREATE_NO_WINDOW)
            if result.returncode: raise ValueError('ACL')
        except (OSError, ValueError, IndexError, subprocess.SubprocessError):
            raise CredentialError('KEY_DIRECTORY_PROTECTION_FAILED') from None
        yield root, env, tools


@contextmanager
def materialized_credential(credential):
    if not isinstance(credential, ManagedCredential): raise CredentialError('CREDENTIAL_DATA_INVALID')
    credential.encode()
    try:
        with private_key_directory() as (root, env, tools):
            path = root/'identity'
            with path.open('xb') as output: output.write(credential.private_key)
            yield path, env, tools
    except OSError:
        raise CredentialError('CREDENTIAL_MATERIALIZATION_FAILED') from None
