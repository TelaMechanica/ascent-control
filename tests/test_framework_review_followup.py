"""Synthetic Service Mode proof and malformed compressed stream regressions."""
import struct
from threading import RLock
import zipfile
import zlib
import pytest
from ascent_core.service_access import AccessDenied, ReceiverBinding, ServiceAccess, ServiceState
from ascent_core.widget_sdk import PackageInvalid, inspect_package


class SyntheticGuardedBackend:
    """Test double only: no real enrollment, cryptography, SSH or network access."""
    def __init__(self, current, *, enrolled=True, pinned='synthetic-key-a', observed='synthetic-key-a'):
        self.current = current
        self.enrolled = enrolled
        self.pinned = pinned
        self.observed = observed
        self.steps = []
        self.closed = 0

    def acquire(self, binding):
        if not self.enrolled:
            raise AccessDenied('ENROLLMENT_REQUIRED')
        if self.pinned != self.observed:
            raise AccessDenied('HOST_KEY_MISMATCH')
        if self.current().binding != binding:
            raise AccessDenied('BACKEND_BINDING_CHANGED')
        return object()

    def step(self, lease, label):
        lease.check()
        # Real backend steps must also be bounded and verify their connection.
        self.steps.append(label)

    def close(self, session):
        self.closed += 1


def setup_backend(**options):
    binding = ReceiverBinding(1, 'synthetic-receiver', 'synthetic-transport')
    state = [ServiceState(True, True, binding)]
    backend = SyntheticGuardedBackend(lambda: state[0], **options)
    access = ServiceAccess(state=lambda: state[0], backend=backend, operation_lock=RLock())
    return access, backend, state, binding


@pytest.mark.parametrize('options,error', [({'enrolled': False}, 'ENROLLMENT_REQUIRED'), ({'observed': 'synthetic-key-b'}, 'HOST_KEY_MISMATCH')])
def test_backend_guard_refuses_before_session(options, error):
    access, backend, _, binding = setup_backend(**options)
    with pytest.raises(AccessDenied, match=error):
        with access.lease(binding):
            pytest.fail('session must not be published')
    assert backend.steps == [] and backend.closed == 0


@pytest.mark.parametrize('change', ['disable', 'provider', 'selection', 'transport'])
def test_mid_lease_change_stops_next_step(change):
    access, backend, state, binding = setup_backend()
    with pytest.raises(AccessDenied):
        with access.lease(binding) as lease:
            backend.step(lease, 'first')
            state[0] = ServiceState(change != 'provider', change != 'disable',
                ReceiverBinding(2 if change == 'selection' else 1, 'synthetic-receiver',
                                'other-transport' if change == 'transport' else 'synthetic-transport'))
            backend.step(lease, 'forbidden-second')
    assert backend.steps == ['first'] and backend.closed == 1


def test_success_and_closed_lease_refusal():
    access, backend, _, binding = setup_backend()
    with access.lease(binding) as lease:
        backend.step(lease, 'first')
        backend.step(lease, 'second')
    assert backend.steps == ['first', 'second'] and backend.closed == 1
    with pytest.raises(AccessDenied, match='CLOSED'):
        lease.check()


def test_backend_independently_revalidates_binding():
    _, backend, state, binding = setup_backend()
    state[0] = ServiceState(True, True, ReceiverBinding(2, 'synthetic-receiver', 'synthetic-transport'))
    with pytest.raises(AccessDenied, match='BACKEND_BINDING_CHANGED'):
        backend.acquire(binding)


def compressed_package(tmp_path):
    path = tmp_path / 'compressed.zip'
    with zipfile.ZipFile(path, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('widget.json', b'{"synthetic":true}')
        archive.writestr('view.json', b'{}')
    with zipfile.ZipFile(path) as archive:
        entry = archive.getinfo('widget.json')
        offset = entry.header_offset
    raw = bytearray(path.read_bytes())
    name_len, extra_len = struct.unpack_from('<HH', raw, offset + 26)
    return path, raw, offset + 30 + name_len + extra_len


def test_corrupt_deflate_is_package_invalid(tmp_path):
    path, raw, start = compressed_package(tmp_path)
    # DEFLATE BTYPE=3 is reserved: preserve a valid ZIP container but break its stream.
    raw[start] = (raw[start] & ~7) | 7
    path.write_bytes(raw)
    with pytest.raises(PackageInvalid, match='Malformed package') as caught:
        inspect_package(path)
    assert isinstance(caught.value.__cause__, zlib.error)


def test_interrupted_zip_is_package_invalid(tmp_path):
    path, raw, start = compressed_package(tmp_path)
    # Keep directory records valid but expose only one compressed stream byte.
    struct.pack_into('<I', raw, 18, 1)
    central = raw.index(b'PK\x01\x02')
    struct.pack_into('<I', raw, central + 20, 1)
    path.write_bytes(raw)
    with zipfile.ZipFile(path) as archive:
        assert archive.namelist() == ['widget.json', 'view.json']
    with pytest.raises(PackageInvalid, match='Malformed package'):
        inspect_package(path)


def test_backend_eof_is_normalized(tmp_path, monkeypatch):
    path, _, _ = compressed_package(tmp_path)
    def interrupted(*args, **kwargs):
        raise EOFError('synthetic interrupted decompression')
    monkeypatch.setattr(zipfile.ZipFile, 'read', interrupted)
    with pytest.raises(PackageInvalid, match='Malformed package') as caught:
        inspect_package(path)
    assert isinstance(caught.value.__cause__, EOFError)
