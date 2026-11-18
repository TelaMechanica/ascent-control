"""Host-owned receiver enrollment/readiness controller. No bootstrap implementation.

Caller must already have an authorized client key on the receiver. First-access
installation remains a separate private adapter, not implied by this controller.
"""
from dataclasses import dataclass
import secrets
from threading import RLock
import time
from .service_access import AccessDenied
from .service_enrollment import ReceiverEnrollment
from .service_records import host_key_fingerprint
from .service_key_policy import compatible_key_types, require_compatible_key_type


@dataclass(frozen=True, repr=False)
class Observation:
    target: object
    public_key: str
    fingerprint: str
    expires: float


class ReceiverService:
    def __init__(self, *, selector, credentials, enrollments, transport, enabled):
        self._selector = selector
        self._credentials = credentials
        self._enrollments = enrollments
        self._transport = transport
        self._enabled = enabled
        self._observations = {}
        self._lock = RLock()

    def _require(self):
        if self._enabled() is not True: raise AccessDenied('SERVICE_MODE_PROVIDER_UNAVAILABLE')

    def inspect(self):
        self._require()
        target = self._selector.capture()
        def check():
            self._require(); self._selector.check_selection(target)
        public_key = self._transport.observe(target, check)
        self._selector.check(target)
        fingerprint = host_key_fingerprint(public_key)
        existing = self._enrollments.lookup(target.binding.receiver_identity)
        if existing and host_key_fingerprint(existing.host_public_key) != fingerprint:
            raise AccessDenied('HOST_KEY_CHANGED')
        token = secrets.token_urlsafe(24)
        now = time.monotonic()
        with self._lock:
            self._observations = {k:v for k,v in self._observations.items() if v.expires > now}
            if len(self._observations) >= 8: self._observations.clear()
            self._observations[token] = Observation(target, public_key, fingerprint, now+60)
        return {'observation_id':token, 'host_fingerprint':fingerprint,
                'host_key_algorithm':public_key.split()[0], 'receiver_name':target.device_name,
                'firmware':target.firmware, 'trusted_record_present':existing is not None,
                'ssh_authenticated':False, 'initial_access_available':False,
                'compatible_client_key_types':compatible_key_types(target.device_name, target.firmware)}

    def verify(self, observation_id, confirmed_fingerprint, *, confirmed, key_type='ed25519'):
        self._require()
        if confirmed is not True: raise AccessDenied('RECEIVER_TRUST_CONFIRMATION_REQUIRED')
        if not isinstance(observation_id, str) or not 1 <= len(observation_id) <= 128:
            raise AccessDenied('RECEIVER_OBSERVATION_INVALID')
        if not isinstance(confirmed_fingerprint, str) or len(confirmed_fingerprint) > 128:
            raise AccessDenied('RECEIVER_FINGERPRINT_CONFIRMATION_CHANGED')
        if key_type not in ('ed25519', 'ecdsa'):
            raise AccessDenied('CLIENT_KEY_TYPE_UNSUPPORTED')
        with self._lock: observation = self._observations.pop(observation_id, None)
        if observation is None or time.monotonic() >= observation.expires:
            raise AccessDenied('RECEIVER_OBSERVATION_EXPIRED')
        if observation.fingerprint != confirmed_fingerprint:
            raise AccessDenied('RECEIVER_FINGERPRINT_CONFIRMATION_CHANGED')
        target = observation.target
        self._selector.check(target)
        require_compatible_key_type(key_type, target.device_name, target.firmware)
        credential = self._credentials(key_type).load()
        public_key = getattr(credential, 'public_key', None)
        parts = public_key.split() if isinstance(public_key, str) else []
        actual_type = {'ssh-ed25519':'ed25519', 'ecdsa-sha2-nistp256':'ecdsa'}.get(parts[0] if parts else None)
        require_compatible_key_type(actual_type, target.device_name, target.firmware)
        if actual_type != key_type:
            raise AccessDenied('CLIENT_KEY_ALGORITHM_MISMATCH')
        client_fingerprint = host_key_fingerprint(credential.public_key)
        existing = self._enrollments.lookup(target.binding.receiver_identity)
        if existing and (existing.client_fingerprint != client_fingerprint or
                         host_key_fingerprint(existing.host_public_key) != observation.fingerprint):
            raise AccessDenied('ENROLLMENT_CREDENTIAL_CHANGED')
        def check():
            self._require(); self._selector.check_selection(target)
        proof = None
        try:
            proof = self._transport.authenticate(target, observation.public_key, credential, check)
            self._selector.check(target)
            check()
            self._transport.consume(proof, target, observation.fingerprint, client_fingerprint)
            check()
            record = ReceiverEnrollment(target.binding.receiver_identity, observation.public_key, client_fingerprint)
            self._enrollments.save_new(record)
            try:
                self._selector.check(target)
                check()
            except AccessDenied:
                # This is a local immutable write for the original identity,
                # not an atomic receiver operation that can be rolled back.
                raise AccessDenied('TRUST_RECORD_SAVED_CONTEXT_CHANGED') from None
            return {'ssh_authenticated':True, 'operation':'readiness-noop', 'trust_record_saved':True,
                    'receiver_name':target.device_name, 'firmware':target.firmware,
                    'receiver_mutation_available':False, 'initial_access_available':False}
        finally:
            if proof is not None: self._transport.discard(proof)
