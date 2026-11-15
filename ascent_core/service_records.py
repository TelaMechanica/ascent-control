"""Read-only offline Service Mode guards. No keys, enrollment writes or SSH.

Record and observation suppliers are trusted host adapters, never package input.
Checking a supplied public key against a pin does not prove possession of its
private key; that requires a future authenticated transport handshake.
"""
import base64
import binascii
from dataclasses import dataclass
import hashlib
import hmac
import json
import re
import struct
from .service_access import AccessDenied, ReceiverBinding

MAX_RECORD_BYTES = 16384


def host_key_fingerprint(line):
    """Full OpenSSH-style SHA256 over an Ed25519 SSH wire-format public key.

    Deliberately limited to Ed25519 for this offline increment. Other algorithms
    and old abbreviated application fingerprints require separate review.
    """
    if not isinstance(line, str) or len(line) > 4096 or '\n' in line or '\r' in line:
        raise AccessDenied('HOST_KEY_INVALID')
    parts = line.split()
    if len(parts) < 2 or parts[0] != 'ssh-ed25519':
        raise AccessDenied('HOST_KEY_UNSUPPORTED')
    try:
        raw = base64.b64decode(parts[1], validate=True)
    except (binascii.Error, ValueError):
        raise AccessDenied('HOST_KEY_INVALID') from None
    expected = struct.pack('>I', 11) + b'ssh-ed25519' + struct.pack('>I', 32)
    if len(raw) != len(expected) + 32 or not raw.startswith(expected):
        raise AccessDenied('HOST_KEY_INVALID')
    return 'SHA256:' + base64.b64encode(hashlib.sha256(raw).digest()).decode('ascii').rstrip('=')


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise AccessDenied('ENROLLMENT_RECORD_INVALID')
        result[key] = value
    return result


@dataclass(frozen=True)
class EnrollmentRecord:
    receiver_identity: str
    credential_revision: int
    host_key_sha256: str

    @classmethod
    def parse(cls, raw):
        if not isinstance(raw, bytes) or len(raw) > MAX_RECORD_BYTES:
            raise AccessDenied('ENROLLMENT_RECORD_INVALID')
        try:
            doc = json.loads(raw, object_pairs_hook=_unique)
        except (ValueError, UnicodeError, RecursionError):
            raise AccessDenied('ENROLLMENT_RECORD_INVALID') from None
        fields = {'schema', 'receiver_identity', 'credential_revision', 'host_key_sha256', 'enrolled'}
        if not isinstance(doc, dict) or set(doc) != fields or doc['schema'] != 'ascent.service-enrollment.v0':
            raise AccessDenied('ENROLLMENT_RECORD_INVALID')
        if doc['enrolled'] is not True:
            raise AccessDenied('ENROLLMENT_REQUIRED')
        identity = doc['receiver_identity']
        revision = doc['credential_revision']
        pin = doc['host_key_sha256']
        if not isinstance(identity, str) or not 1 <= len(identity) <= 256 or any(ord(c) < 32 for c in identity):
            raise AccessDenied('ENROLLMENT_RECORD_INVALID')
        if type(revision) is not int or revision < 1:
            raise AccessDenied('ENROLLMENT_RECORD_INVALID')
        if not isinstance(pin, str) or not re.fullmatch(r'SHA256:[A-Za-z0-9+/]{43}', pin):
            raise AccessDenied('ENROLLMENT_PIN_INVALID')
        # Reject noncanonical base64 pad bits rather than accepting aliases.
        digest = base64.b64decode(pin[7:] + '=', validate=True)
        if base64.b64encode(digest).decode().rstrip('=') != pin[7:]:
            raise AccessDenied('ENROLLMENT_PIN_INVALID')
        return cls(identity, revision, pin)


@dataclass(frozen=True)
class HostKeyObservation:
    binding: ReceiverBinding
    public_key: str


@dataclass(frozen=True)
class OfflineVerifiedSession:
    binding: ReceiverBinding
    record: EnrollmentRecord


class OfflineServiceBackend:
    """Read-only guard backend connected to ServiceAccess; not an SSH session.

    Suppliers must read trusted host state/observations afresh each call. They
    must not do network work in this increment. No TOFU, alias migration, pin
    replacement, command dispatch or key-path diagnostics are implemented.
    """
    def __init__(self, *, state, record_for, observation_for):
        self._state = state
        self._record_for = record_for
        self._observation_for = observation_for
        self._sessions = {}

    def _verify(self, binding):
        current = self._state()
        if not current.provider_loaded or not current.enabled:
            raise AccessDenied('SERVICE_MODE_UNAVAILABLE')
        if current.binding != binding:
            raise AccessDenied('RECEIVER_BINDING_CHANGED')
        try:
            raw = self._record_for(binding.receiver_identity)
        except (OSError, ValueError):
            raise AccessDenied('ENROLLMENT_RECORD_UNAVAILABLE') from None
        if raw is None:
            raise AccessDenied('ENROLLMENT_REQUIRED')
        record = EnrollmentRecord.parse(raw)
        if record.receiver_identity != binding.receiver_identity:
            raise AccessDenied('ENROLLMENT_IDENTITY_CHANGED')
        try:
            observed = self._observation_for(binding)
        except (OSError, ValueError):
            raise AccessDenied('HOST_KEY_OBSERVATION_UNAVAILABLE') from None
        if not isinstance(observed, HostKeyObservation) or observed.binding != binding:
            raise AccessDenied('HOST_KEY_BINDING_CHANGED')
        fingerprint = host_key_fingerprint(observed.public_key)
        if not hmac.compare_digest(record.host_key_sha256, fingerprint):
            raise AccessDenied('HOST_KEY_MISMATCH')
        # Even trusted suppliers may take time: never return stale selection.
        if self._state() != current:
            raise AccessDenied('RECEIVER_BINDING_CHANGED')
        return record

    def acquire(self, binding):
        record = self._verify(binding)
        session = OfflineVerifiedSession(binding, record)
        self._sessions[id(session)] = session
        return session

    def verify_step(self, lease):
        """Guard a bounded read-only step. No side-effecting dispatcher exists.

        Future side-effecting operations MUST call check before each step and
        recheck backend binding/credentials. Already started effects cannot be
        rolled back by a later check; blocking calls need bounded cancellation.
        """
        lease.check()
        session = lease.session
        if self._sessions.get(id(session)) is not session:
            raise AccessDenied('SERVICE_SESSION_CLOSED')
        current = self._verify(session.binding)
        if current != session.record:
            raise AccessDenied('ENROLLMENT_REVISION_CHANGED')
        lease.check()
        return {'enrollment_record_matches': True, 'host_key_pin_matches': True,
                'authenticated_transport': False, 'offline_only': True}

    def close(self, session):
        self._sessions.pop(id(session), None)
