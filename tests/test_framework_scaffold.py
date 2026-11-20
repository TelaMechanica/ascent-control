"""Offline adversarial checks; no receiver, credential store or host executor."""
import hashlib
import importlib.util
import json
from pathlib import Path
from threading import RLock
import zipfile
import pytest
from ascent_core.service_access import AccessDenied, ReceiverBinding, ServiceAccess, ServiceState
from ascent_core.widget_sdk import PackageInvalid, inspect_package

spec = importlib.util.spec_from_file_location('sdk_cli', Path(__file__).resolve().parents[1] / 'tools/widget_sdk.py')
cli = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cli)


def fixture_access():
    binding = ReceiverBinding(1, 'synthetic-receiver', 'synthetic-transport')
    state = [ServiceState(True, True, binding)]
    events = []
    class Backend:
        def acquire(self, selected):
            events.append(('acquire', selected))
            return object()
        def close(self, session):
            events.append(('close', session))
    backend = Backend()
    access = ServiceAccess(state=lambda: state[0], backend=backend, operation_lock=RLock())
    return access, binding, state, backend, events


def test_service_session_closed_on_operation_failure():
    access, binding, _, _, events = fixture_access()
    with pytest.raises(ValueError):
        with access.lease(binding):
            raise ValueError('synthetic operation failure')
    assert [e[0] for e in events] == ['acquire', 'close']


@pytest.mark.parametrize('loaded,enabled', [(False, True), (True, False), (False, False)])
def test_missing_service_never_acquires(loaded, enabled):
    access, binding, state, _, events = fixture_access()
    state[0] = ServiceState(loaded, enabled, binding)
    with pytest.raises(AccessDenied, match='UNAVAILABLE'):
        with access.lease(binding):
            pytest.fail('must not yield')
    assert events == []


@pytest.mark.parametrize('changed', [ReceiverBinding(2, 'synthetic-receiver', 'synthetic-transport'), ReceiverBinding(1, 'other-receiver', 'synthetic-transport'), ReceiverBinding(1, 'synthetic-receiver', 'other-transport')])
def test_binding_change_prevents_acquisition(changed):
    access, binding, state, _, events = fixture_access()
    state[0] = ServiceState(True, True, changed)
    with pytest.raises(AccessDenied, match='CHANGED'):
        with access.lease(binding):
            pytest.fail('must not yield')
    assert events == []


@pytest.mark.parametrize('revoke', [True, False])
def test_state_change_during_acquisition_retires_session(revoke):
    access, binding, state, backend, events = fixture_access()
    acquire = backend.acquire
    def change(selected):
        session = acquire(selected)
        state[0] = ServiceState(not revoke, True, ReceiverBinding(2, 'synthetic-receiver', 'synthetic-transport'))
        return session
    backend.acquire = change
    with pytest.raises(AccessDenied):
        with access.lease(binding):
            pytest.fail('must not publish stale session')
    assert [e[0] for e in events] == ['acquire', 'close']


def test_example_is_reproducible_and_not_executable(tmp_path):
    a, b = tmp_path / 'a.zip', tmp_path / 'b.zip'
    assert cli.build_example(a)['executable'] is False
    cli.build_example(b)
    assert a.read_bytes() == b.read_bytes()
    assert inspect_package(a)['publisher_verified'] is False
    with pytest.raises(FileExistsError):
        cli.build_example(a)


def mutate(tmp_path, transform):
    original = tmp_path / 'original.zip'
    cli.build_example(original)
    with zipfile.ZipFile(original) as archive:
        entries = [(e.filename, archive.read(e.filename)) for e in archive.infolist()]
    entries = transform(entries)
    candidate = tmp_path / 'candidate.zip'
    with zipfile.ZipFile(candidate, 'w') as archive:
        for name, data in entries:
            archive.writestr(name, data)
    return candidate


@pytest.mark.parametrize('name', ['../outside', '/absolute', 'C:escape', 'folder\\escape', 'NUL.json', 'name.', 'a//b'])
def test_unsafe_archive_paths_denied(tmp_path, name):
    candidate = mutate(tmp_path, lambda entries: entries + [(name, b'bad')])
    with pytest.raises(PackageInvalid):
        inspect_package(candidate)
    assert not (tmp_path.parent / 'outside').exists()


def test_duplicate_zip_names_denied(tmp_path):
    candidate = mutate(tmp_path, lambda entries: entries + [('VIEW.JSON', b'bad')])
    with pytest.raises(PackageInvalid, match='colliding'):
        inspect_package(candidate)


def test_corrupted_payload_denied(tmp_path):
    candidate = mutate(tmp_path, lambda entries: [(n, b'changed' if n == 'view.json' else data) for n, data in entries])
    with pytest.raises(PackageInvalid, match='digest'):
        inspect_package(candidate)


@pytest.mark.parametrize('capability', ['service.credentials.read', 'receiver.shell', 'network.connect'])
def test_privileged_manifest_cannot_grant_access(tmp_path, capability):
    def change(entries):
        result = []
        for name, data in entries:
            if name == 'widget.json':
                manifest = json.loads(data)
                manifest['capabilities'] = [capability]
                data = json.dumps(manifest).encode()
            result.append((name, data))
        return result
    with pytest.raises(PackageInvalid, match='capabilities'):
        inspect_package(mutate(tmp_path, change))


def test_executable_payload_not_admitted_even_with_matching_digest(tmp_path):
    def change(entries):
        result = []
        for name, data in entries:
            if name == 'widget.json':
                manifest = json.loads(data)
                manifest['files']['guest.py'] = hashlib.sha256(b'pass').hexdigest()
                data = json.dumps(manifest).encode()
            result.append((name, data))
        return result + [('guest.py', b'pass')]
    with pytest.raises(PackageInvalid, match='only a declarative view'):
        inspect_package(mutate(tmp_path, change))


def test_duplicate_manifest_keys_denied(tmp_path):
    def change(entries):
        return [(n, b'{"schema":"ascent.widget.v0","schema":"other"}' if n == 'widget.json' else data) for n, data in entries]
    with pytest.raises(PackageInvalid, match='Duplicate JSON'):
        inspect_package(mutate(tmp_path, change))


def test_symlink_entry_denied(tmp_path):
    original = tmp_path / 'original.zip'
    cli.build_example(original)
    candidate = tmp_path / 'candidate.zip'
    with zipfile.ZipFile(original) as source, zipfile.ZipFile(candidate, 'w') as target:
        for entry in source.infolist():
            if entry.filename == 'view.json':
                entry.external_attr = 0o120777 << 16
            target.writestr(entry, source.read(entry.filename))
    with pytest.raises(PackageInvalid, match='ordinary'):
        inspect_package(candidate)


def test_expansion_limit_enforced_before_payload_read(tmp_path):
    candidate = tmp_path / 'candidate.zip'
    with zipfile.ZipFile(candidate, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('widget.json', b'{}')
        archive.writestr('view.json', b'x' * (4 * 1024 * 1024 + 1))
    with pytest.raises(PackageInvalid, match='Expanded'):
        inspect_package(candidate)


def test_invalid_archive_denied(tmp_path):
    candidate = tmp_path / 'candidate.zip'
    candidate.write_bytes(b'not a ZIP')
    with pytest.raises(PackageInvalid, match='Malformed'):
        inspect_package(candidate)


@pytest.mark.parametrize('entry_name', ['widget.json', 'view.json'])
@pytest.mark.parametrize('payload', [b'[' * 2000 + b'0' + b']' * 2000,
                                     b'{"value":' + b'1' * 5000 + b'}'],
                         ids=['deep-nesting', 'oversized-integer'])
def test_adversarial_json_is_normalized_to_package_rejection(tmp_path, entry_name, payload):
    def change(entries):
        result = dict(entries)
        result[entry_name] = payload
        if entry_name == 'view.json':
            manifest = json.loads(result['widget.json'])
            manifest['files']['view.json'] = hashlib.sha256(payload).hexdigest()
            result['widget.json'] = json.dumps(manifest).encode()
        return list(result.items())
    with pytest.raises(PackageInvalid):
        inspect_package(mutate(tmp_path, change))


def test_release_payload_uses_trusted_archive_and_file_digests():
    import hashlib
    import io
    import zipfile
    from ascent_core.widget_sdk import verify_release_payload

    source = io.BytesIO()
    with zipfile.ZipFile(source, 'w') as archive:
        archive.writestr('widget-runtime', b'opaque runtime bytes')
    data = source.getvalue()
    digest = hashlib.sha256(data).hexdigest()
    pins = {'widget-runtime': hashlib.sha256(b'opaque runtime bytes').hexdigest()}
    assert verify_release_payload(data, archive_digest=digest, file_digests=pins) == {
        'widget-runtime': b'opaque runtime bytes'}
    with pytest.raises(PackageInvalid, match='archive digest'):
        verify_release_payload(data, archive_digest='0' * 64, file_digests=pins)
    with pytest.raises(PackageInvalid, match='payload inventory'):
        verify_release_payload(data, archive_digest=digest, file_digests={})
    with pytest.raises(PackageInvalid, match='payload digest'):
        verify_release_payload(data, archive_digest=digest, file_digests={'widget-runtime': '0' * 64})


def test_pinned_release_staging_keeps_default_archive_limits(tmp_path):
    import hashlib
    import zipfile
    import pytest
    from ascent_core.widget_sdk import MAX_EXPANDED_BYTES, PackageInvalid, stage_release_payload

    path = tmp_path / 'receiver.zip'
    blob = b'x' * (MAX_EXPANDED_BYTES + 1)
    with zipfile.ZipFile(path, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('receiver-tool', blob)
    pins = {'archive_digest': hashlib.sha256(path.read_bytes()).hexdigest(),
            'file_digests': {'receiver-tool': hashlib.sha256(blob).hexdigest()}}

    with pytest.raises(PackageInvalid, match='Expanded package exceeds limit'):
        with stage_release_payload(path, **pins):
            pytest.fail('default expansion limit changed')
    with stage_release_payload(path, max_expanded_bytes=len(blob), **pins) as staged:
        assert (staged / 'receiver-tool').read_bytes() == blob
    assert not staged.exists()
