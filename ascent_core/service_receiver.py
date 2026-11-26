"""Host-owned receiver enrollment/readiness controller. No bootstrap implementation.

Caller must already have an authorized client key on the receiver. First-access
installation remains a separate private adapter, not implied by this controller.
"""
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
from pathlib import Path
import re
from typing import Callable
import secrets
from threading import RLock
import time
from .service_access import AccessDenied
from .service_credentials import CredentialError
from .service_enrollment import ReceiverEnrollment
from .service_records import host_key_fingerprint
from .service_key_policy import CLIENT_KEY_TYPES, compatible_key_types, require_compatible_key_type


@dataclass(frozen=True, repr=False)
class Observation:
    target: object
    public_key: str
    fingerprint: str
    expires: float


@dataclass(frozen=True, repr=False)
class EnrolledReceiver:
    target: object
    host_public_key: str
    credential: object
    check: Callable[[], None]


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

    def _load_compatible_credential(self, target, key_type):
        require_compatible_key_type(key_type, target.device_name, target.firmware)
        credential = self._credentials(key_type).load()
        public_key = getattr(credential, 'public_key', None)
        parts = public_key.split() if isinstance(public_key, str) else []
        actual_type = {'ssh-ed25519':'ed25519', 'ecdsa-sha2-nistp256':'ecdsa'}.get(parts[0] if parts else None)
        require_compatible_key_type(actual_type, target.device_name, target.firmware)
        if actual_type != key_type:
            raise AccessDenied('CLIENT_KEY_ALGORITHM_MISMATCH')
        return credential

    @contextmanager
    def enrolled(self, target, *, key_type):
        """Bind a trusted host operation to existing enrollment and selection."""
        self._require()
        self._selector.check(target)
        identity = target.binding.receiver_identity
        record = self._enrollments.lookup(identity)
        if record is None:
            raise AccessDenied('RECEIVER_ENROLLMENT_REQUIRED')
        if key_type is None:
            kinds = compatible_key_types(target.device_name, target.firmware) or CLIENT_KEY_TYPES
        else:
            kinds = (key_type,)
        for kind in kinds:
            try:
                credential = self._load_compatible_credential(target, kind)
            except CredentialError as error:
                if str(error) != 'CREDENTIAL_NOT_PRESENT':
                    raise
                continue
            if host_key_fingerprint(credential.public_key) == record.client_fingerprint:
                break
        else:
            raise AccessDenied('ENROLLMENT_CREDENTIAL_CHANGED')
        active = True

        def check():
            if not active:
                raise AccessDenied('SERVICE_LEASE_CLOSED')
            self._require()
            self._selector.check_selection(target)
            if self._enrollments.lookup(identity) != record:
                raise AccessDenied('RECEIVER_ENROLLMENT_CHANGED')

        check()
        try:
            yield EnrolledReceiver(target, record.host_public_key, credential, check)
        finally:
            active = False

    def read_network_inventory(self, target, *, key_type):
        """Read NetRunner's interface inputs through the selected trust binding."""
        with self.enrolled(target, key_type=key_type) as enrollment:
            return self._transport.read_network_inventory(enrollment)

    @staticmethod
    def _netrunner_releases(target, release_pins):
        if not target.serial_number:
            raise AccessDenied('RECEIVER_IDENTITY_REQUIRED')

        if target.device_name == 'Ascent_VRX_pro':
            if (target.hardware, target.firmware) != ('Ascent-VRX-Pro-V3.0-1.0', 'Ascent_VRX_Pro_18_21_10'):
                raise AccessDenied('NETRUNNER_PROFILE_UNSUPPORTED')
            profile = 'pro-18.21.10'
        elif target.device_name in ('Ascent_VRX_max_HF', 'Ascent_VRX_max_WF', 'Ascent_VRX_Max'):
            profile = 'max'
        else:
            raise AccessDenied('NETRUNNER_PROFILE_UNSUPPORTED')

        supported = {name: pin for name, pin in release_pins.items()
                     if pin.get('widget_id') == 'netrunner' and pin.get('profile', 'max') == profile}
        return profile, supported

    @staticmethod
    def _widget_target_document(target):
        return {'device_id': target.binding.receiver_identity, 'device_name': target.device_name,
                'serial_number': target.serial_number, 'hardware': target.hardware,
                'firmware': target.firmware, 'host': target.host, 'source_ip': target.source_ip}

    def netrunner_widget_status(self, *, library, release_pins):
        from .widget_sdk import PackageInvalid, read_release_payload

        self._require()
        target = self._selector.capture()
        _, supported = self._netrunner_releases(target, release_pins)
        root = Path(library)
        with self.enrolled(target, key_type=None) as enrollment:
            observed = self._transport.inspect_netrunner_tools(enrollment)
            enrollment.check()
        installed = next((pin['version'] for pin in supported.values() if pin['files'] == observed), None)
        present = any(digest is not None for digest in observed.values())
        available = []
        archives = []
        for release_id, pin in supported.items():
            try:
                read_release_payload(root / (release_id + '.zip'),
                                     archive_digest=pin['sha256'], file_digests=pin['files'])
                archive_state = 'verified'
            except FileNotFoundError:
                archive_state = 'missing'
            except (OSError, PackageInvalid):
                archive_state = 'invalid'
            archives.append({'id': release_id, 'version': pin['version'], 'state': archive_state})
            if archive_state != 'verified' or pin['version'] == installed:
                continue
            if not present:
                action = 'install'
            elif installed:
                requested = tuple(map(int, pin['version'].split('.')))
                previous = tuple(map(int, installed.split('.')))
                action = 'update' if requested > previous else 'rollback'
            else:
                continue
            available.append({'id': release_id, 'version': pin['version'], 'action': action})
        return {'receiver': self._widget_target_document(target), 'installed_version': installed,
                'files_present': present, 'available_releases': available, 'release_archives': archives}

    def apply_netrunner_widget_action(self, *, reviewed_target, library, release_id, release_pins, action):
        self._require()
        target = self._selector.capture()
        if reviewed_target != self._widget_target_document(target):
            raise AccessDenied('RECEIVER_BINDING_CHANGED')
        return self.apply_selected_netrunner_download(expected_binding=target.binding, key_type=None,
            library=library, release_id=release_id, release_pins=release_pins, action=action)

    def apply_selected_netrunner_download(self, *, expected_binding, key_type, library,
                                         release_id, release_pins, action):
        """Resolve a local widget download using the current enrolled receiver."""
        self._require()
        target = self._selector.capture()
        if target.binding != expected_binding:
            raise AccessDenied('RECEIVER_BINDING_CHANGED')
        profile, supported = self._netrunner_releases(target, release_pins)
        if release_id is None:
            release_id = {'max': 'netrunner-max-2.10.1', 'pro-18.21.10': 'netrunner-pro-2.10.1'}[profile]
        if (not isinstance(release_id, str) or not re.fullmatch(r'[a-z0-9][a-z0-9.-]{0,63}', release_id)
                or release_id not in supported):
            raise AccessDenied('NETRUNNER_RELEASE_NOT_APPROVED')
        pin = supported[release_id]
        archive = Path(library) / (release_id + '.zip')
        if not archive.exists() and not archive.is_symlink():
            raise AccessDenied('WIDGET_DOWNLOAD_REQUIRED')
        versions = {entry['version']: entry['files'] for entry in supported.values()}
        return self.apply_netrunner_download(target, key_type=key_type, archive=archive,
            archive_digest=pin['sha256'], version=pin['version'], approved_versions=versions, action=action)

    def apply_netrunner_download(self, target, *, key_type, archive, archive_digest,
                                 version, approved_versions, action):
        """Stage and apply a receiver-profile release selected by the application."""
        from .widget_sdk import stage_release_payload

        pins = approved_versions.get(version)
        if pins is None:
            raise AccessDenied('NETRUNNER_RELEASE_NOT_APPROVED')
        with stage_release_payload(archive, archive_digest=archive_digest, file_digests=pins) as staged:
            verified_files = {name: (staged / name).read_bytes() for name in pins}
            return self.manage_netrunner_release(target, key_type=key_type, verified_files=verified_files,
                version=version, approved_versions=approved_versions, action=action)

    def manage_netrunner_release(self, target, *, key_type, verified_files,
                                 version, approved_versions, action):
        """Use an application-owned release and the receiver's observed installed version."""
        if action not in ('install', 'update', 'rollback'):
            raise AccessDenied('NETRUNNER_ACTION_INVALID')
        names = ('ascent_wifi_channels', 'wpa_cli', 'wpa_supplicant')
        if (set(verified_files) != set(names) or any(
                not isinstance(blob, bytes) or not 0 < len(blob) <= 4 * 1024 * 1024
                for blob in verified_files.values())):
            raise AccessDenied('NETRUNNER_TOOL_INVENTORY_INVALID')
        digests = {name: hashlib.sha256(verified_files[name]).hexdigest() for name in names}
        if approved_versions.get(version) != digests:
            raise AccessDenied('NETRUNNER_RELEASE_NOT_APPROVED')
        with self.enrolled(target, key_type=key_type) as enrollment:
            observed = self._transport.inspect_netrunner_tools(enrollment)
            enrollment.check()
            if action == 'install':
                if any(digest is not None for digest in observed.values()):
                    raise AccessDenied('NETRUNNER_ALREADY_PRESENT')
                expected = None
            else:
                matches = [number for number, files in approved_versions.items() if files == observed]
                if len(matches) != 1:
                    raise AccessDenied('NETRUNNER_INSTALLED_RELEASE_UNKNOWN')
                previous = tuple(map(int, matches[0].split('.')))
                requested = tuple(map(int, version.split('.')))
                if requested == previous or (requested > previous) != (action == 'update'):
                    raise AccessDenied('NETRUNNER_RELEASE_DIRECTION_INVALID')
                expected = observed
            return self._install_netrunner_tools(enrollment, verified_files, digests, expected)

    def _install_netrunner_tools(self, enrollment, verified_files, digests, expected_current):
        """Transfer and activate an application-verified package within one enrollment."""
        transaction = secrets.token_hex(8)
        self._transport.prepare_netrunner_stage(enrollment)
        for name in digests:
            self._transport.stage_netrunner_tool(enrollment, filename=name,
                transaction=transaction, payload=verified_files[name], expected_digest=digests[name])
        self._transport.verify_netrunner_stage(enrollment, transaction=transaction, expected_files=digests)
        self._transport.activate_netrunner_stage(enrollment, transaction=transaction,
            expected_files=digests, expected_current=expected_current)
        enrollment.check()
        return transaction

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
        credential = self._load_compatible_credential(target, key_type)
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
