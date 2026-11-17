"""Protected receiver trust records. No bootstrap, network or private-key storage.

Only the trusted host may commit a verified receipt. An SDK manifest or HTTP body
cannot construct an authorized receipt or select a storage path.
"""
from dataclasses import dataclass
import hashlib
import hmac
import json
from .service_access import AccessDenied
from .service_credentials import CredentialError, ProtectedEnvelopeStore
from .service_records import host_key_fingerprint, validate_sha256_fingerprint


def _unique(pairs):
    doc = {}
    for key, value in pairs:
        if key in doc: raise ValueError('duplicate')
        doc[key] = value
    return doc


@dataclass(frozen=True, repr=False)
class ReceiverEnrollment:
    receiver_identity: str
    host_public_key: str
    client_fingerprint: str

    def encode(self):
        if not isinstance(self.receiver_identity, str) or not 1 <= len(self.receiver_identity) <= 256:
            raise CredentialError('ENROLLMENT_RECORD_INVALID')
        if any(ord(c) < 32 for c in self.receiver_identity):
            raise CredentialError('ENROLLMENT_RECORD_INVALID')
        try:
            host_key_fingerprint(self.host_public_key)
            # Client fingerprint uses the same full SHA256 representation. It is
            # compared against the actual managed key by the trusted controller.
            validate_sha256_fingerprint(self.client_fingerprint)
        except (ValueError, RuntimeError):
            raise CredentialError('ENROLLMENT_RECORD_INVALID') from None
        fields = {'schema': 'ascent.receiver-enrollment.v1', 'receiver_identity': self.receiver_identity,
                  'host_public_key': ' '.join(self.host_public_key.split()[:2]),
                  'client_fingerprint': self.client_fingerprint}
        data = json.dumps(fields, sort_keys=True, separators=(',', ':')).encode()
        return json.dumps({'record': fields, 'sha256': hashlib.sha256(data).hexdigest()}, sort_keys=True).encode()

    @classmethod
    def decode(cls, raw):
        try:
            doc = json.loads(raw, object_pairs_hook=_unique)
            if not isinstance(doc, dict) or set(doc) != {'record', 'sha256'}: raise ValueError('envelope')
            record = doc['record']
            if not isinstance(record, dict) or set(record) != {'schema', 'receiver_identity', 'host_public_key', 'client_fingerprint'} or record['schema'] != 'ascent.receiver-enrollment.v1':
                raise ValueError('schema')
            digest = hashlib.sha256(json.dumps(record, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
            if not isinstance(doc['sha256'], str) or not hmac.compare_digest(digest, doc['sha256']):
                raise ValueError('integrity')
            result = cls(record['receiver_identity'], record['host_public_key'], record['client_fingerprint'])
            result.encode()
            return result
        except (ValueError, TypeError, AttributeError, RecursionError):
            raise CredentialError('ENROLLMENT_RECORD_INVALID') from None


class ProtectedEnrollments:
    def __init__(self, root, *, protector=None):
        self._root = root
        self._protector = protector

    def _store(self, receiver_identity):
        if not isinstance(receiver_identity, str) or not 1 <= len(receiver_identity) <= 256:
            raise CredentialError('ENROLLMENT_RECORD_INVALID')
        name = hashlib.sha256(receiver_identity.encode()).hexdigest() + '.dpapi'
        return ProtectedEnvelopeStore(self._root, name=name, codec=ReceiverEnrollment, protector=self._protector)

    def lookup(self, receiver_identity):
        try:
            record = self._store(receiver_identity).load()
        except CredentialError as error:
            if str(error) == 'CREDENTIAL_NOT_PRESENT': return None
            raise
        if record.receiver_identity != receiver_identity:
            raise AccessDenied('ENROLLMENT_IDENTITY_CHANGED')
        return record

    def save_new(self, record):
        """Low-level immutable persistence, NOT an authentication decision.

        The trusted controller must validate a live transport proof and selected
        context first. This object is not exposed to requests or widget APIs.
        """
        if not isinstance(record, ReceiverEnrollment):
            raise CredentialError('ENROLLMENT_RECORD_INVALID')
        # Normalize comments/representation before comparing immutable trust data.
        record = ReceiverEnrollment.decode(record.encode())
        existing = self.lookup(record.receiver_identity)
        if existing is not None:
            if existing != record:
                raise AccessDenied('HOST_KEY_CHANGED')
            return existing
        return self._store(record.receiver_identity).create(record)
