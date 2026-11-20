"""Host-only receiver target capture using the existing selected-device owner.

No device I/O, enrollment or authorization is established by capturing this target.
The caller supplies the application's identity resolver/classifier, never manifests.
"""
from dataclasses import dataclass
import hashlib
import ipaddress
import json
from .service_access import AccessDenied, ReceiverBinding

_FIELDS = ('device_name', 'serial_number', 'hardware', 'hardware_version', 'firmware')


@dataclass(frozen=True, repr=False)
class ReceiverTarget:
    binding: ReceiverBinding
    host: str
    source_ip: str
    interface_index: int
    serial_port: str
    firmware: str | None
    device_name: str
    serial_number: str | None = None
    hardware: str | None = None


class SelectedReceiver:
    def __init__(self, *, session, resolve_identity, classify, endpoint):
        self._session = session
        self._resolve = resolve_identity
        self._classify = classify
        self._endpoint = endpoint

    def capture(self):
        session = self._session
        device, epoch = session.device, session.generation
        if device is None:
            raise AccessDenied('RECEIVER_SELECTION_REQUIRED')
        if device.network_target is not None:
            raise AccessDenied('SERVICE_MODE_USB_IDENTITY_REQUIRED')
        identity = dict(device.identity)
        if self._classify(identity.get('device_name')).get('role') != 'receiver':
            raise AccessDenied('RECEIVER_IDENTITY_REQUIRED')
        resolved = self._resolve(device.connect_record)
        canonical = resolved.get('canonical_id')
        if resolved.get('conflict_reason') or not canonical:
            raise AccessDenied('RECEIVER_IDENTITY_CONFLICT')
        host = self._endpoint()
        facts = session.transport(max_age=0)
        if (session.device is not device or session.generation != epoch or
                tuple(device.identity.get(k) for k in _FIELDS) != tuple(identity.get(k) for k in _FIELDS) or
                self._endpoint() != host):
            raise AccessDenied('RECEIVER_BINDING_CHANGED')
        if (facts.get('topology_qualified') is not True or facts.get('correlation_basis') != 'container_id' or
                facts.get('serial_com_is_live') is not True or not facts.get('binding')):
            raise AccessDenied('RECEIVER_TRANSPORT_UNQUALIFIED')
        try:
            source, index = facts['binding']
            if type(index) is not int or index <= 0:
                raise ValueError('index')
            source_ip, target_ip = ipaddress.IPv4Address(source), ipaddress.IPv4Address(host)
            prefix = session.policy['host_rndis_prefix']
            if type(prefix) is not int or not 1 <= prefix <= 30:
                raise ValueError('prefix')
            network = ipaddress.IPv4Network((source_ip, prefix), strict=False)
            if target_ip not in network or target_ip in (source_ip, network.network_address, network.broadcast_address):
                raise ValueError('endpoint outside selected receiver subnet')
            if source_ip.is_loopback or source_ip.is_unspecified or target_ip.is_multicast:
                raise ValueError('invalid endpoint')
        except (ValueError, TypeError, KeyError):
            raise AccessDenied('RECEIVER_ENDPOINT_UNQUALIFIED') from None
        scope = [canonical, str(target_ip), str(source_ip), index, facts['serial_com'],
                 *(identity.get(k) for k in _FIELDS)]
        digest = hashlib.sha256(json.dumps(scope, separators=(',', ':')).encode()).hexdigest()
        return ReceiverTarget(ReceiverBinding(epoch, canonical, digest), str(target_ip),
                              str(source_ip), index, facts['serial_com'], identity.get('firmware'),
                              identity['device_name'], identity.get('serial_number'),
                              identity.get('hardware'))

    def check(self, target):
        if not isinstance(target, ReceiverTarget) or self.capture() != target:
            raise AccessDenied('RECEIVER_BINDING_CHANGED')

    def check_selection(self, target):
        """No OS/inventory I/O: for checks inside an already bounded connection.

        capture/check perform fresh topology resolution before/after the network
        step. The connection itself pins source/interface; this fast guard checks
        selection/identity/endpoint invalidation without starting background probes.
        """
        device = self._session.device
        if (not isinstance(target, ReceiverTarget) or device is None or
                self._session.generation != target.binding.selection_epoch or
                device.network_target is not None or self._endpoint() != target.host):
            raise AccessDenied('RECEIVER_BINDING_CHANGED')
        resolved = self._resolve(device.connect_record)
        scope = [resolved.get('canonical_id'), target.host, target.source_ip,
                 target.interface_index, target.serial_port,
                 *(device.identity.get(k) for k in _FIELDS)]
        digest = hashlib.sha256(json.dumps(scope, separators=(',', ':')).encode()).hexdigest()
        if resolved.get('conflict_reason') or digest != target.binding.transport_identity:
            raise AccessDenied('RECEIVER_BINDING_CHANGED')
