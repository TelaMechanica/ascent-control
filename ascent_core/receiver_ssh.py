"""Trusted read-only SSH engine over a selected, source-bound channel.

Host key observation, readiness and fixed network inventory are host-owned.
The operation caller supplies an enrolled receiver, not remote command text.
"""
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import subprocess
from tempfile import TemporaryFile
from threading import Event, RLock, Thread
import time
from .service_access import AccessDenied
from .service_records import SUPPORTED_HOST_KEYS, host_key_fingerprint
from .windows_key_material import private_key_directory, materialized_credential
from .windows_tools import _windows_run


_NETRUNNER_TOOLS = ('ascent_wifi_channels', 'wpa_cli', 'wpa_supplicant')
_NETRUNNER_ROOT = '/usrdata/ascent/netrunner'


def _netrunner_stage_path(filename, transaction):
    if filename not in _NETRUNNER_TOOLS:
        raise AccessDenied('NETRUNNER_TOOL_NOT_ALLOWED')
    if not isinstance(transaction, str) or not re.fullmatch('[0-9a-f]{16}', transaction):
        raise AccessDenied('NETRUNNER_STAGE_ID_INVALID')
    return f'{_NETRUNNER_ROOT}/.{filename}.new-{transaction}'


def _option_path(path):
    text = path.as_posix()
    if any(c in text for c in ('\r', '\n', '\0', '%', '"', '\\')):
        raise AccessDenied('SSH_PATH_UNSUPPORTED')
    return '"' + text + '"'


def _capture_keyscan(args, env, *, source=subprocess.DEVNULL):
    data = bytearray(); oversized = Event()
    with subprocess.Popen(args, stdin=source, stdout=subprocess.PIPE,
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

    @contextmanager
    def _authenticated_args(self, target, host_public_key, credential, check, *, stdin=False):
        check()
        host_key_fingerprint(host_public_key)
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
                args = [str(tools/'OpenSSH/ssh.exe'), '-F', str(config), '-T']
                if not stdin:
                    args.append('-n')
                for name, value in options.items(): args += ['-o', name+'='+value]
                args += ['-i', str(identity), '-p', str(port), '-l', self._username, host]
                yield args, env
            check()

    def read_network_inventory(self, enrollment):
        command = (
            "echo __LINK__; (ip -o link show 2>/dev/null || "
            "/sbin/ip -o link show 2>/dev/null || ifconfig -a 2>/dev/null || "
            "/bin/busybox ifconfig -a 2>/dev/null); "
            "echo __ADDR__; (ip -o -4 addr show 2>/dev/null || "
            "/sbin/ip -o -4 addr show 2>/dev/null || ifconfig 2>/dev/null || "
            "/bin/busybox ifconfig 2>/dev/null); "
            "echo __LEASE__; (ls /var/lib/dhcp*/*.leases /tmp/*.leases "
            "/var/lib/misc/*.leases 2>/dev/null; pidof udhcpc dhcpcd 2>/dev/null); "
            "echo __NETWORK_INVENTORY_END__"
        )
        with self._authenticated_args(enrollment.target, enrollment.host_public_key,
                                      enrollment.credential, enrollment.check) as (args, env):
            code, output = self._capture([*args, command], env)
        if code != 0:
            raise AccessDenied('NETWORK_INVENTORY_NOT_VERIFIED')
        try:
            lines = output.decode('utf-8').splitlines()
        except UnicodeError:
            raise AccessDenied('NETWORK_INVENTORY_INVALID') from None
        markers = [line for line in lines if line in
                   ('__LINK__', '__ADDR__', '__LEASE__', '__NETWORK_INVENTORY_END__')]
        if markers != ['__LINK__', '__ADDR__', '__LEASE__', '__NETWORK_INVENTORY_END__'] or lines[-1] != markers[-1]:
            raise AccessDenied('NETWORK_INVENTORY_INCOMPLETE')
        return '\n'.join(lines[:-1]) + '\n'

    def inspect_netrunner_tools(self, enrollment):
        """Read the installed tool hashes without executing any receiver binary."""
        root = _NETRUNNER_ROOT
        commands = ['set -e', f'test ! -L {root}']
        for name in _NETRUNNER_TOOLS:
            path = f'{root}/{name}'
            commands.append(f'test ! -L {path}; if [ -f {path} ]; then '
                            f'printf "%s " {name}; sha256sum {path} | cut -d \' \' -f1; '
                            f'elif [ ! -e {path} ]; then echo {name} absent; else exit 7; fi')
        commands.append('echo NETRUNNER_INVENTORY_COMPLETE')
        with self._authenticated_args(enrollment.target, enrollment.host_public_key,
                                      enrollment.credential, enrollment.check) as (args, env):
            code, output = self._capture([*args, '; '.join(commands)], env)
        if code != 0:
            raise AccessDenied('NETRUNNER_INVENTORY_UNVERIFIED')
        try:
            lines = output.decode('ascii').splitlines()
        except UnicodeError:
            raise AccessDenied('NETRUNNER_INVENTORY_UNVERIFIED') from None
        if len(lines) != len(_NETRUNNER_TOOLS) + 1 or lines[-1] != 'NETRUNNER_INVENTORY_COMPLETE':
            raise AccessDenied('NETRUNNER_INVENTORY_UNVERIFIED')
        inventory = {}
        for name, line in zip(_NETRUNNER_TOOLS, lines):
            observed, _, digest = line.partition(' ')
            if observed != name or not re.fullmatch('absent|[0-9a-f]{64}', digest):
                raise AccessDenied('NETRUNNER_INVENTORY_UNVERIFIED')
            inventory[name] = None if digest == 'absent' else digest
        return inventory

    def prepare_netrunner_stage(self, enrollment):
        root = _NETRUNNER_ROOT
        command = (f'set -e; umask 077; test ! -L /usrdata/ascent; test ! -L {root}; '
                   f'mkdir -p {root}; test "$(readlink -f {root})" = {root}; '
                   'echo NETRUNNER_STAGING_READY')
        with self._authenticated_args(enrollment.target, enrollment.host_public_key,
                                      enrollment.credential, enrollment.check) as (args, env):
            code, output = self._capture([*args, command], env)
        if code != 0 or output.strip() != b'NETRUNNER_STAGING_READY':
            raise AccessDenied('NETRUNNER_STAGING_NOT_READY')

    def stage_netrunner_tool(self, enrollment, *, filename, transaction, payload, expected_digest):
        """Stage one verified asset without replacing the installed NetRunner tools."""
        staged = _netrunner_stage_path(filename, transaction)
        if (not isinstance(payload, bytes) or not 0 < len(payload) <= 4 * 1024 * 1024
                or hashlib.sha256(payload).hexdigest() != expected_digest):
            raise AccessDenied('NETRUNNER_TOOL_DIGEST_MISMATCH')
        root = _NETRUNNER_ROOT
        command = (
            'set -e; set -C; umask 077; '
            f'test -d {root}; test ! -L {root}; test "$(readlink -f {root})" = {root}; '
            f'test ! -e {staged}; test ! -L {staged}; cat > {staged}; '
            f'test "$(sha256sum {staged} | cut -d \' \' -f1)" = {expected_digest}; '
            'echo NETRUNNER_STAGE_VERIFIED'
        )
        with self._authenticated_args(enrollment.target, enrollment.host_public_key,
                                      enrollment.credential, enrollment.check, stdin=True) as (args, env):
            with TemporaryFile() as source:
                source.write(payload)
                source.seek(0)
                code, output = self._capture([*args, command], env, source=source)
        if code != 0 or output.strip() != b'NETRUNNER_STAGE_VERIFIED':
            raise AccessDenied('NETRUNNER_TOOL_STAGE_UNCONFIRMED')

    def verify_netrunner_stage(self, enrollment, *, transaction, expected_files):
        """Verify the full staged set on the enrolled receiver before activation."""
        if set(expected_files) != set(_NETRUNNER_TOOLS):
            raise AccessDenied('NETRUNNER_TOOL_INVENTORY_INVALID')
        checks = []
        for name in _NETRUNNER_TOOLS:
            digest = expected_files[name]
            if not isinstance(digest, str) or not re.fullmatch('[0-9a-f]{64}', digest):
                raise AccessDenied('NETRUNNER_TOOL_DIGEST_MISMATCH')
            path = _netrunner_stage_path(name, transaction)
            checks.append(f'test -f {path}; test ! -L {path}; '
                          f'test "$(sha256sum {path} | cut -d \' \' -f1)" = {digest}')
        root = _NETRUNNER_ROOT
        command = (f'set -e; test ! -L {root}; test "$(readlink -f {root})" = {root}; '
                   + '; '.join(checks) + '; echo NETRUNNER_BUNDLE_VERIFIED')
        with self._authenticated_args(enrollment.target, enrollment.host_public_key,
                                      enrollment.credential, enrollment.check) as (args, env):
            code, output = self._capture([*args, command], env)
        if code != 0 or output.strip() != b'NETRUNNER_BUNDLE_VERIFIED':
            raise AccessDenied('NETRUNNER_BUNDLE_UNCONFIRMED')

    def activate_netrunner_stage(self, enrollment, *, transaction, expected_files, expected_current):
        """Activate a verified bundle with a compare-and-swap check on live files."""
        names = _NETRUNNER_TOOLS
        if set(expected_files) != set(names) or (expected_current and set(expected_current) != set(names)):
            raise AccessDenied('NETRUNNER_TOOL_INVENTORY_INVALID')
        for digest in (*expected_files.values(), *(expected_current or {}).values()):
            if not isinstance(digest, str) or not re.fullmatch('[0-9a-f]{64}', digest):
                raise AccessDenied('NETRUNNER_TOOL_DIGEST_MISMATCH')
        root = _NETRUNNER_ROOT
        backup = f'{root}/.previous-{transaction}'
        staged = {name: _netrunner_stage_path(name, transaction) for name in names}
        tests = []
        restore = []
        copy = []
        moves = []
        for name, path in staged.items():
            live = f'{root}/{name}'
            previous = f'{backup}/{name}'
            digest = expected_files[name]
            tests.extend((f'test -f {path}', f'test ! -L {path}', f'test ! -L {live}',
                          f'test "$(sha256sum {path} | cut -d \' \' -f1)" = {digest}'))
            if expected_current:
                tests.extend((f'test -f {live}',
                              f'test "$(sha256sum {live} | cut -d \' \' -f1)" = {expected_current[name]}'))
                copy.append(f'cp -p {live} {previous}')
                restore.append(f'mv -f {previous} {live}')
            else:
                tests.append(f'test ! -e {live}')
                restore.append(f'rm -f {live}')
            moves.append(f'chmod 755 {path}; mv -f {path} {live}')
        lock = f'{root}/.install-lock'
        unlock = f'rmdir {lock}'
        command = '; '.join([
            'set -e', 'umask 077', f'test ! -L {root}', f'test "$(readlink -f {root})" = {root}',
            f'mkdir {lock}', f"trap '{unlock}' 0", *tests, f'mkdir {backup}', *copy,
            "trap '" + '; '.join(['set +e', *restore, unlock]) + "' 0",
            "trap 'exit 73' HUP INT TERM", *moves, 'sync',
            f"trap '{unlock}' 0", 'echo NETRUNNER_BUNDLE_ACTIVATED',
        ])
        with self._authenticated_args(enrollment.target, enrollment.host_public_key,
                                      enrollment.credential, enrollment.check) as (args, env):
            code, output = self._capture([*args, command], env)
        if code != 0 or output.strip() != b'NETRUNNER_BUNDLE_ACTIVATED':
            raise AccessDenied('NETRUNNER_ACTIVATION_UNCONFIRMED')

    def authenticate(self, target, host_public_key, credential, check):
        host_fingerprint = host_key_fingerprint(host_public_key)
        client_fingerprint = host_key_fingerprint(credential.public_key)
        with self._authenticated_args(target, host_public_key, credential, check) as (args, env):
            if self._run([*args, 'true'], env) != 0:
                raise AccessDenied('SSH_READINESS_NOT_VERIFIED')
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
