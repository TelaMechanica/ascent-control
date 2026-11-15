"""Current-user DPAPI credential storage: no plaintext fallback or receiver access.

Trusted application code only; never expose this object or raw keys to widgets.
Default implementations refuse non-Windows hosts. Tests inject synthetic adapters.
"""
import ctypes
from dataclasses import dataclass, field
import json
import hashlib
import hmac
import os
from pathlib import Path
import stat
import subprocess
import tempfile
from threading import RLock
from .service_records import host_key_fingerprint

MAX_BYTES = 65536
MAGIC = b'ASCENT-DPAPI-1\n'


class CredentialError(RuntimeError):
    pass


class CurrentUserDpapi:
    def _call(self, raw, *, decrypt):
        if os.name != 'nt':
            raise CredentialError('WINDOWS_PROTECTION_REQUIRED')
        if not isinstance(raw, bytes) or not 1 <= len(raw) <= MAX_BYTES:
            raise CredentialError('CREDENTIAL_DATA_INVALID')
        from ctypes import wintypes
        class Blob(ctypes.Structure):
            _fields_ = [('size', wintypes.DWORD), ('data', ctypes.POINTER(ctypes.c_ubyte))]
        source_buffer = (ctypes.c_ubyte * len(raw)).from_buffer_copy(raw)
        source = Blob(len(raw), source_buffer)
        result = Blob()
        crypt = ctypes.WinDLL('crypt32', use_last_error=True)
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.LocalFree.argtypes = [ctypes.c_void_p]
        kernel.LocalFree.restype = ctypes.c_void_p
        # UI_FORBIDDEN only. Never LOCAL_MACHINE: protection is current-user scope.
        function = crypt.CryptUnprotectData if decrypt else crypt.CryptProtectData
        function.argtypes = [ctypes.POINTER(Blob), ctypes.c_void_p, ctypes.c_void_p,
                             ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(Blob)]
        function.restype = wintypes.BOOL
        if not function(ctypes.byref(source), None, None, None, None, 1, ctypes.byref(result)):
            raise CredentialError('CREDENTIAL_UNPROTECT_FAILED' if decrypt else 'CREDENTIAL_PROTECT_FAILED')
        try:
            if not 1 <= result.size <= MAX_BYTES:
                raise CredentialError('CREDENTIAL_DATA_INVALID')
            return ctypes.string_at(result.data, result.size)
        finally:
            kernel.LocalFree(result.data)

    def protect(self, raw): return self._call(raw, decrypt=False)
    def unprotect(self, raw): return self._call(raw, decrypt=True)


@dataclass(frozen=True)
class ManagedCredential:
    public_key: str
    private_key: bytes = field(repr=False)

    def encode(self):
        if not isinstance(self.private_key, bytes) or not 1 <= len(self.private_key) <= 16384:
            raise CredentialError('CREDENTIAL_DATA_INVALID')
        try:
            private = self.private_key.decode('ascii')
            host_key_fingerprint(self.public_key)
        except (ValueError, RuntimeError):
            raise CredentialError('CREDENTIAL_DATA_INVALID') from None
        if not private.startswith('-----BEGIN OPENSSH PRIVATE KEY-----\n') or not private.rstrip().endswith('-----END OPENSSH PRIVATE KEY-----'):
            raise CredentialError('CREDENTIAL_DATA_INVALID')
        return json.dumps({'schema': 'ascent.host-credential.v1', 'public_key': self.public_key,
                           'private_key': private,
                           'sha256': hashlib.sha256(self.public_key.encode() + b'\0' + self.private_key).hexdigest()}, sort_keys=True).encode()

    @classmethod
    def decode(cls, raw):
        try:
            def unique(pairs):
                doc = {}
                for key, value in pairs:
                    if key in doc: raise ValueError('duplicate')
                    doc[key] = value
                return doc
            doc = json.loads(raw, object_pairs_hook=unique)
            if not isinstance(doc, dict) or set(doc) != {'schema', 'public_key', 'private_key', 'sha256'} or doc['schema'] != 'ascent.host-credential.v1':
                raise ValueError('schema')
            credential = cls(doc['public_key'], doc['private_key'].encode('ascii'))
            credential.encode()
            expected = hashlib.sha256(credential.public_key.encode() + b'\0' + credential.private_key).hexdigest()
            if not isinstance(doc['sha256'], str) or not hmac.compare_digest(expected, doc['sha256']):
                raise ValueError('checksum')
            return credential
        except (ValueError, TypeError, AttributeError, RecursionError):
            raise CredentialError('CREDENTIAL_DATA_INVALID') from None


class ProtectedCredentialStore:
    """Single protected envelope, create-only; preserves existing and corrupt data."""
    def __init__(self, root, *, protector=None):
        self._root = Path(root)
        self._path = self._root/'credential.dpapi'
        self._protector = protector if protector is not None else CurrentUserDpapi()
        self._lock = RLock()

    def _read(self):
        try:
            info = self._path.lstat()
            if not stat.S_ISREG(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
                raise CredentialError('CREDENTIAL_FILE_INVALID')
            with self._path.open('rb') as source: raw = source.read(MAX_BYTES + 1)
        except FileNotFoundError:
            raise CredentialError('CREDENTIAL_NOT_PRESENT') from None
        except OSError:
            raise CredentialError('CREDENTIAL_READ_FAILED') from None
        if len(raw) > MAX_BYTES or not raw.startswith(MAGIC):
            raise CredentialError('CREDENTIAL_FILE_INVALID')
        return raw[len(MAGIC):]

    def load(self):
        with self._lock:
            try: raw = self._protector.unprotect(self._read())
            except CredentialError: raise
            except Exception: raise CredentialError('CREDENTIAL_UNPROTECT_FAILED') from None
            return ManagedCredential.decode(raw)

    def create(self, credential):
        with self._lock:
            # Encrypt before creating the store directory or any persistent file.
            encoded = credential.encode()
            try: protected = self._protector.protect(encoded)
            except CredentialError: raise
            except Exception: raise CredentialError('CREDENTIAL_PROTECT_FAILED') from None
            if not isinstance(protected, bytes) or not protected or len(protected) + len(MAGIC) > MAX_BYTES or protected == encoded:
                raise CredentialError('CREDENTIAL_PROTECT_FAILED')
            try:
                if self._protector.unprotect(protected) != encoded:
                    raise CredentialError('CREDENTIAL_PROTECT_FAILED')
            except Exception:
                raise CredentialError('CREDENTIAL_PROTECT_FAILED') from None
            try:
                self._root.mkdir(parents=True, exist_ok=True)
                if self._root.is_symlink(): raise CredentialError('CREDENTIAL_FILE_INVALID')
                fd, name = tempfile.mkstemp(prefix='.protected-', dir=self._root)
                temporary = Path(name)
                try:
                    with os.fdopen(fd, 'wb') as target:
                        target.write(MAGIC + protected)
                        target.flush()
                        os.fsync(target.fileno())
                    # Atomic create-only link: never replaces prior/corrupt state.
                    os.link(temporary, self._path)
                finally:
                    temporary.unlink(missing_ok=True)
            except FileExistsError:
                raise CredentialError('CREDENTIAL_ALREADY_PRESENT') from None
            except OSError:
                raise CredentialError('CREDENTIAL_WRITE_FAILED') from None
        return self.status()

    def status(self):
        try:
            credential = self.load()
        except CredentialError as error:
            if str(error) == 'CREDENTIAL_NOT_PRESENT':
                return {'credential_present': False, 'receiver_access': False}
            raise
        return {'credential_present': True, 'fingerprint': host_key_fingerprint(credential.public_key),
                'protection': 'dpapi-current-user', 'receiver_access': False}


def generate_windows_credential(store):
    """Explicit local preparation, not enrollment; no imported or alternate key.

    Plaintext exists only in an ACL-restricted temporary generation directory and
    process memory. This does not promise crash cleanup or Python memory wiping.
    """
    if os.name != 'nt':
        raise CredentialError('WINDOWS_PROTECTION_REQUIRED')
    if store.status().get('credential_present'):
        raise CredentialError('CREDENTIAL_ALREADY_PRESENT')
    import csv
    import re
    from .windows_tools import _environment, _windows_run
    from .service_access import AccessDenied
    system = os.environ.get('SystemRoot')
    if not system:
        raise CredentialError('WINDOWS_PROTECTION_REQUIRED')
    try:
        with tempfile.TemporaryDirectory(prefix='ascent-managed-key-') as folder:
            root = Path(folder)
            env = _environment(root, windows=True, system_root=system)
            tools = Path(system)/'System32'
            result = subprocess.run([str(tools/'whoami.exe'), '/user', '/fo', 'csv', '/nh'],
                stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=5,
                check=True, env=env, creationflags=subprocess.CREATE_NO_WINDOW)
            sid = list(csv.reader(result.stdout.splitlines()))[0][-1]
            if not re.fullmatch(r'S-1-(?:[0-9]+-)*[0-9]+', sid):
                raise CredentialError('KEY_DIRECTORY_PROTECTION_FAILED')
            restricted = subprocess.run([str(tools/'icacls.exe'), str(root), '/inheritance:r',
                '/grant:r', '*' + sid + ':(OI)(CI)F'], stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5,
                env=env, creationflags=subprocess.CREATE_NO_WINDOW)
            if restricted.returncode:
                raise CredentialError('KEY_DIRECTORY_PROTECTION_FAILED')
            private = root/'managed-key'
            args = [str(tools/'OpenSSH/ssh-keygen.exe'), '-q', '-t', 'ed25519', '-N', '',
                    '-C', 'ascent-control-service-mode', '-f', str(private)]
            if _windows_run(args, env):
                raise CredentialError('CREDENTIAL_GENERATION_FAILED')
            credential = ManagedCredential((root/'managed-key.pub').read_text().strip(), private.read_bytes())
            return store.create(credential)
    except CredentialError:
        raise
    except (OSError, ValueError, IndexError, subprocess.SubprocessError, AccessDenied):
        raise CredentialError('CREDENTIAL_GENERATION_FAILED') from None
