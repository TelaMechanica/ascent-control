"""Loopback-only real SSH proof, not a receiver transport or widget API.

Each fixed channel open/close uses a fresh OpenSSH connection. Caller supplies only task-owned
synthetic credentials. No arbitrary host/command or ambient credential fallback.
This module is deliberately not packaged or wired into the desktop application.
"""
import hmac
import ipaddress
import os
from pathlib import Path
import re
import subprocess
import tempfile
from .windows_tools import _environment, _windows_run
from .service_access import AccessDenied
from .service_records import HostKeyObservation, OfflineServiceBackend, host_key_fingerprint




class LoopbackSshProbe:
    def __init__(self, *, binding, port, username, identity_file, ssh_binary):
        if type(port) is not int or not 1024 <= port <= 65535:
            raise ValueError('Fixture port invalid')
        if not isinstance(username, str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_-]{0,63}', username):
            raise ValueError('Fixture username invalid')
        if not Path(ssh_binary).is_absolute() or not Path(identity_file).is_absolute():
            raise ValueError('Trusted fixture paths must be absolute')
        self._binding = binding
        self._port = port
        self._username = username
        self._identity_file = Path(identity_file)
        self._ssh = Path(ssh_binary)

    def noop(self, binding, public_key):
        # Trusted backend must compare this key to the enrollment pin first.
        if binding != self._binding:
            raise AccessDenied('SSH_FIXTURE_BINDING_CHANGED')
        host_key_fingerprint(public_key)
        key = ' '.join(public_key.split()[:2])
        try:
            with tempfile.TemporaryDirectory(prefix='ascent-pinned-host-') as folder:
                root = Path(folder)
                config, known, empty = root/'config', root/'known', root/'empty'
                config.write_text('')
                empty.write_text('')
                known.write_text('ascent-loopback-fixture ' + key + '\n')
                known.chmod(0o600)
                def option_path(path):
                    value = path.as_posix()
                    if any(c in value for c in ('\r', '\n', '\x00', '%', '"', '\\')):
                        raise AccessDenied('SSH_FIXTURE_PATH_UNSUPPORTED')
                    return '"' + value + '"'
                options = {
                    'BatchMode': 'yes', 'IdentitiesOnly': 'yes', 'IdentityAgent': 'none',
                    'CertificateFile': 'none', 'StrictHostKeyChecking': 'yes',
                    'UserKnownHostsFile': option_path(known), 'GlobalKnownHostsFile': option_path(empty),
                    'HostKeyAlias': 'ascent-loopback-fixture', 'HostKeyAlgorithms': 'ssh-ed25519',
                    'UpdateHostKeys': 'no', 'VerifyHostKeyDNS': 'no', 'KnownHostsCommand': 'none',
                    'PreferredAuthentications': 'publickey', 'PasswordAuthentication': 'no',
                    'KbdInteractiveAuthentication': 'no', 'GSSAPIAuthentication': 'no',
                    'AddKeysToAgent': 'no', 'ForwardAgent': 'no', 'ForwardX11': 'no',
                    'ClearAllForwardings': 'yes', 'ControlMaster': 'no', 'ControlPath': 'none',
                    'ProxyCommand': 'none', 'ProxyJump': 'none', 'PermitLocalCommand': 'no',
                    'CanonicalizeHostname': 'no', 'ConnectTimeout': '2', 'ConnectionAttempts': '1',
                    'ServerAliveInterval': '1', 'ServerAliveCountMax': '1',
                }
                args = [str(self._ssh), '-F', str(config), '-n', '-T', '-s']
                for name, value in options.items():
                    args += ['-o', name + '=' + value]
                args += ['-i', str(self._identity_file), '-p', str(self._port), '-l', self._username,
                         str(ipaddress.IPv4Address(0x7f000001)), 'sftp']
                environment = _environment(root, windows=os.name == 'nt',
                                           system_root=os.environ.get('SystemRoot'))
                if os.name == 'nt':
                    returncode = _windows_run(args, environment)
                else:
                    returncode = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL, timeout=5, check=False, env=environment).returncode
        except subprocess.TimeoutExpired:
            raise AccessDenied('SSH_STEP_TIMEOUT') from None
        except OSError:
            raise AccessDenied('SSH_STEP_UNAVAILABLE') from None
        if returncode != 0:
            raise AccessDenied('SSH_AUTHENTICATED_NOOP_FAILED')


class LoopbackReadOnlySshBackend(OfflineServiceBackend):
    """Guard token is not a persistent connection. Only verify_step does SSH.

    A successful result describes the completed no-op connection, never a live
    cached session. Each step reauthenticates against the same pinned key.
    """
    def __init__(self, *, probe, **suppliers):
        super().__init__(**suppliers)
        self._probe = probe

    def verify_step(self, lease):
        super().verify_step(lease)
        session = lease.session
        try:
            observed = self._observation_for(session.binding)
        except (OSError, ValueError):
            raise AccessDenied('HOST_KEY_OBSERVATION_UNAVAILABLE') from None
        if not isinstance(observed, HostKeyObservation) or observed.binding != session.binding:
            raise AccessDenied('HOST_KEY_BINDING_CHANGED')
        if not hmac.compare_digest(host_key_fingerprint(observed.public_key), session.record.host_key_sha256):
            raise AccessDenied('HOST_KEY_MISMATCH')
        lease.check()
        self._probe.noop(session.binding, observed.public_key)
        # Refuse to publish a result after revocation or credential/selection change.
        super().verify_step(lease)
        return {'authenticated_transport': True, 'loopback_only': True,
                'operation': 'completed-noop', 'connection_reused': False}
