"""Trusted read-only SSH engine over a selected, source-bound channel.

Only host-key observation and a fixed readiness no-op are implemented. No raw
command, upload, bootstrap, credential import or widget-facing execution API.
"""
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import subprocess
from threading import Event, RLock, Thread
import time
from .service_access import AccessDenied
from .service_records import SUPPORTED_HOST_KEYS, host_key_fingerprint
from .windows_key_material import private_key_directory, materialized_credential
from .windows_tools import _windows_run


def _option_path(path):
    text = path.as_posix()
    if any(c in text for c in ('\r', '\n', '\0', '%', '"', '\\')):
        raise AccessDenied('SSH_PATH_UNSUPPORTED')
    return '"' + text + '"'


def _capture_keyscan(args, env):
    data = bytearray(); oversized = Event()
    with subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, env=env, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0)) as process:
        def drain(pipe, keep):
            try:
                while True:
                    chunk = pipe.read(4096)
                    if not chunk: break
                    if keep:
                        if len(data) + len(chunk) > 16384:
                            oversized.set()
                            process.kill()
                            break
                        data.extend(chunk)
            except OSError:
                pass
        threads = [Thread(target=drain, args=(process.stdout, True), daemon=True),
                   Thread(target=drain, args=(process.stderr, False), daemon=True)]
        for thread in threads: thread.start()
        try: result = process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill(); process.wait()
            raise AccessDenied('SSH_OBSERVATION_TIMEOUT') from None
        finally:
            for thread in threads: thread.join(timeout=1)
        if oversized.is_set(): raise AccessDenied('SSH_OBSERVATION_TOO_LARGE')
        return result, bytes(data)


@dataclass(frozen=True, repr=False)
class AuthenticationProof:
    binding: object
    host_fingerprint: str
    client_fingerprint: str
    completed: float
    issuer: object


class ReadinessSsh:
    def __init__(self, *, channel, username='root', key_directory=private_key_directory,
                 materializer=materialized_credential, run=_windows_run, capture=_capture_keyscan):
        if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_-]{0,63}', username): raise ValueError('Invalid host-owned login')
        self._channel = channel
        self._username = username
        self._key_directory = key_directory
        self._materializer = materializer
        self._run = run
        self._capture = capture
        self._proofs = {}
        self._lock = RLock()

    def observe(self, target, check):
        # Prefer ECDSA for compatibility with existing receiver daemons; observe
        # one type per channel because ssh-keyscan opens separate TCP sessions.
        for algorithm in ('ecdsa', 'ed25519'):
            check()
            with self._key_directory() as (root, env, tools):
                with self._channel.open(target, check) as (host, port):
                    args = [str(tools/'OpenSSH/ssh-keyscan.exe'), '-T', '2', '-p', str(port), '-t', algorithm, host]
                    code, output = self._capture(args, env)
            check()
            if code != 0: continue
            try:
                lines = output.decode('ascii').splitlines()
            except UnicodeError: raise AccessDenied('SSH_HOST_IDENTITY_INVALID') from None
            for line in lines:
                parts = line.split()
                if len(parts) == 3 and parts[1] in SUPPORTED_HOST_KEYS:
                    public_key = ' '.join(parts[1:])
                    host_key_fingerprint(public_key)
                    return public_key
        raise AccessDenied('SSH_HOST_IDENTITY_UNOBSERVED')

    def authenticate(self, target, host_public_key, credential, check):
        check()
        host_fingerprint = host_key_fingerprint(host_public_key)
        client_fingerprint = host_key_fingerprint(credential.public_key)
        alias = 'ascent-receiver-' + hashlib.sha256(target.binding.receiver_identity.encode()).hexdigest()
        with self._materializer(credential) as (identity, env, tools):
            root = identity.parent
            config, known, empty = root/'config', root/'known', root/'empty'
            config.write_text(''); empty.write_text('')
            known.write_text(alias + ' ' + ' '.join(host_public_key.split()[:2]) + '\n')
            options = {
                'BatchMode':'yes', 'IdentitiesOnly':'yes', 'IdentityAgent':'none', 'CertificateFile':'none',
                'StrictHostKeyChecking':'yes', 'UserKnownHostsFile':_option_path(known),
                'GlobalKnownHostsFile':_option_path(empty), 'HostKeyAlias':alias,
                'HostKeyAlgorithms':host_public_key.split()[0], 'UpdateHostKeys':'no', 'VerifyHostKeyDNS':'no',
                'KnownHostsCommand':'none', 'PreferredAuthentications':'publickey', 'PasswordAuthentication':'no',
                'KbdInteractiveAuthentication':'no', 'GSSAPIAuthentication':'no', 'AddKeysToAgent':'no',
                'ForwardAgent':'no', 'ForwardX11':'no', 'ClearAllForwardings':'yes', 'ControlMaster':'no',
                'ControlPath':'none', 'ProxyCommand':'none', 'ProxyJump':'none', 'PermitLocalCommand':'no',
                'CanonicalizeHostname':'no', 'ConnectTimeout':'2', 'ConnectionAttempts':'1',
                'ServerAliveInterval':'1', 'ServerAliveCountMax':'1',
            }
            check()
            with self._channel.open(target, check) as (host, port):
                args = [str(tools/'OpenSSH/ssh.exe'), '-F', str(config), '-n', '-T']
                for name, value in options.items(): args += ['-o', name+'='+value]
                # Fixed no-op only: no caller-supplied command or SFTP requirement.
                args += ['-i', str(identity), '-p', str(port), '-l', self._username, host, 'true']
                if self._run(args, env) != 0: raise AccessDenied('SSH_READINESS_NOT_VERIFIED')
            check()
        proof = AuthenticationProof(target.binding, host_fingerprint, client_fingerprint, time.monotonic(), self)
        with self._lock: self._proofs[id(proof)] = proof
        return proof

    def consume(self, proof, target, host_fingerprint, client_fingerprint):
        with self._lock: registered = self._proofs.pop(id(proof), None)
        if (registered is not proof or not isinstance(proof, AuthenticationProof) or proof.issuer is not self or
                proof.binding != target.binding or proof.host_fingerprint != host_fingerprint or
                proof.client_fingerprint != client_fingerprint or not 0 <= time.monotonic()-proof.completed <= 15):
            raise AccessDenied('SSH_AUTHENTICATION_PROOF_INVALID')

    def discard(self, proof):
        with self._lock: self._proofs.pop(id(proof), None)
