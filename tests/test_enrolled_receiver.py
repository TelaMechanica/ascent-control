"""An operation can reuse only existing protected receiver enrollment."""
from types import SimpleNamespace
import pytest
from ascent_core.service_access import AccessDenied, ReceiverBinding
from ascent_core.service_enrollment import ReceiverEnrollment
from ascent_core.service_receiver import ReceiverService
from ascent_core.service_records import host_key_fingerprint
from test_service_credentials import synthetic


def test_existing_enrollment_is_required_and_scoped_to_the_operation():
    credential = synthetic()
    target = SimpleNamespace(binding=ReceiverBinding(1, 'fixture', 'attached'),
                             device_name='fixture', firmware='fixture')
    record = ReceiverEnrollment('fixture', credential.public_key, host_key_fingerprint(credential.public_key))
    state = {'target': target, 'record': None}

    def selected(current):
        if current != state['target']:
            raise AccessDenied('RECEIVER_BINDING_CHANGED')

    service = ReceiverService(
        selector=SimpleNamespace(check=selected, check_selection=selected),
        enrollments=SimpleNamespace(lookup=lambda identity: state['record']),
        credentials=lambda kind: SimpleNamespace(load=lambda: credential),
        transport=None, enabled=lambda: True,
    )
    with pytest.raises(AccessDenied, match='ENROLLMENT_REQUIRED'):
        with service.enrolled(target, key_type='ed25519'):
            pytest.fail('an untrusted receiver was admitted')

    state['record'] = record
    with service.enrolled(target, key_type='ed25519') as lease:
        assert lease.target == target and lease.host_public_key == record.host_public_key
        lease.check()
        state['target'] = None
        with pytest.raises(AccessDenied, match='BINDING_CHANGED'):
            lease.check()
        state['target'] = target
        state['record'] = None
        with pytest.raises(AccessDenied, match='ENROLLMENT_CHANGED'):
            lease.check()
    with pytest.raises(AccessDenied, match='LEASE_CLOSED'):
        lease.check()


def test_network_inventory_uses_pinned_connection_and_rejects_incomplete_reply(tmp_path):
    from contextlib import contextmanager
    from ascent_core.service_receiver import EnrolledReceiver
    from ascent_core.receiver_ssh import ReadinessSsh

    credential = synthetic()
    target = SimpleNamespace(binding=ReceiverBinding(1, 'fixture', 'attached'))
    identity = tmp_path / 'fixture-key'

    @contextmanager
    def materialize(current):
        assert current == credential
        yield identity, {}, tmp_path

    @contextmanager
    def channel(current, check):
        assert current is target
        check()
        yield '127.0.0.1', 1234

    complete = b'__LINK__\neth0\n__ADDR__\n__LEASE__\n__NETWORK_INVENTORY_END__\n'
    responses = iter([(0, complete), (0, complete.split(b'__NETWORK_INVENTORY_END__')[0])])

    def capture(args, env):
        assert 'StrictHostKeyChecking=yes' in args
        assert 'PreferredAuthentications=publickey' in args
        assert args[-2] == '127.0.0.1' and 'ip -o link show' in args[-1]
        assert (tmp_path / 'known').read_text().endswith(credential.public_key + '\n')
        return next(responses)

    transport = ReadinessSsh(channel=SimpleNamespace(open=channel), materializer=materialize, capture=capture)
    enrollment = EnrolledReceiver(target, credential.public_key, credential, lambda: None)
    assert transport.read_network_inventory(enrollment) == '__LINK__\neth0\n__ADDR__\n__LEASE__\n'
    with pytest.raises(AccessDenied, match='INVENTORY_INCOMPLETE'):
        transport.read_network_inventory(enrollment)


def test_netrunner_transfer_accepts_only_pinned_bytes_and_fixed_staging_names(monkeypatch):
    from contextlib import contextmanager
    import hashlib
    from ascent_core.receiver_ssh import ReadinessSsh

    payload = b'test receiver asset'
    digest = hashlib.sha256(payload).hexdigest()
    calls = []

    @contextmanager
    def authenticated(*args, stdin):
        assert stdin
        yield ['test-openssh'], {}

    def capture(args, env, *, source):
        assert source.read() == payload
        assert 'cat > /usrdata/ascent/netrunner/.wpa_cli.new-0123456789abcdef' in args[-1]
        assert 'mv ' not in args[-1]
        calls.append(args)
        return 0, b'NETRUNNER_STAGE_VERIFIED\n'

    transport = ReadinessSsh(channel=None, capture=capture)
    monkeypatch.setattr(transport, '_authenticated_args', authenticated)
    enrolled = SimpleNamespace(target=None, host_public_key=None, credential=None, check=None)
    arguments = {'filename': 'wpa_cli', 'transaction': '0123456789abcdef',
                 'payload': payload, 'expected_digest': digest}
    for changed, error in (({'filename': '../wpa_cli'}, 'TOOL_NOT_ALLOWED'),
                           ({'payload': b'changed'}, 'TOOL_DIGEST_MISMATCH'),
                           ({'transaction': 'other'}, 'STAGE_ID_INVALID')):
        with pytest.raises(AccessDenied, match=error):
            transport.stage_netrunner_tool(enrolled, **(arguments | changed))
    assert not calls
    transport.stage_netrunner_tool(enrolled, **arguments)
    assert len(calls) == 1


def test_complete_netrunner_package_is_staged_through_one_enrollment(monkeypatch, tmp_path):
    from contextlib import contextmanager
    import hashlib
    import zipfile

    target = object()
    binding = object()
    calls = []

    def stage(enrollment, **data):
        assert enrollment is binding
        calls.append(data)

    def verify(enrollment, **data):
        assert enrollment is binding
        assert {item['filename']: item['expected_digest'] for item in calls} == data['expected_files']
        assert {item['transaction'] for item in calls} == {data['transaction']}

    transport = SimpleNamespace(inspect_netrunner_tools=lambda current: {name: None for name in files},
                                prepare_netrunner_stage=lambda current: None,
                                stage_netrunner_tool=stage, verify_netrunner_stage=verify,
                                activate_netrunner_stage=lambda enrollment, expected_current, **data: verify(enrollment, **data))
    service = ReceiverService(selector=None, credentials=None, enrollments=None,
                              transport=transport, enabled=lambda: True)
    binding = SimpleNamespace(check=lambda: None)

    @contextmanager
    def enrolled(current, *, key_type):
        assert current is target and key_type == 'ed25519'
        yield binding

    monkeypatch.setattr(service, 'enrolled', enrolled)
    files = {name: name.encode() for name in ('wpa_cli', 'wpa_supplicant', 'ascent_wifi_channels')}
    versions = {'2.10.1': {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}}
    archive = tmp_path / 'widget.zip'
    with zipfile.ZipFile(archive, 'w') as package:
        for name, data in files.items():
            package.writestr(name, data)
    with pytest.raises(AccessDenied, match='INVENTORY_INVALID'):
        service.manage_netrunner_release(target, key_type='ed25519', version='2.10.1',
            approved_versions=versions, action='install', verified_files={'wpa_cli': b'partial'})
    assert not calls
    tx = service.apply_netrunner_download(target, key_type='ed25519', archive=archive,
        archive_digest=hashlib.sha256(archive.read_bytes()).hexdigest(), version='2.10.1',
        approved_versions=versions, action='install')
    assert len(calls) == 3
    for step in calls:
        assert step['transaction'] == tx
        assert step['expected_digest'] == hashlib.sha256(step['payload']).hexdigest()


@pytest.mark.parametrize('failure', [None, 'stale', 'interrupted'])
def test_activate_netrunner_bundle_preserves_previous_files_on_failure(tmp_path, monkeypatch, failure):
    from contextlib import contextmanager
    import hashlib
    import subprocess
    from ascent_core import receiver_ssh

    monkeypatch.setattr(receiver_ssh, '_NETRUNNER_ROOT', str(tmp_path))
    names = ('ascent_wifi_channels', 'wpa_cli', 'wpa_supplicant')
    transaction = '0123456789abcdef'
    old = {name: b'previous ' + name.encode() for name in names}
    new = {name: b'next ' + name.encode() for name in names}
    for name in names:
        (tmp_path / name).write_bytes(old[name])
        (tmp_path / f'.{name}.new-{transaction}').write_bytes(new[name])
    if failure == 'stale':
        (tmp_path / 'wpa_cli').write_bytes(b'changed outside install')

    @contextmanager
    def authenticated(*args):
        yield ['local test shell'], {}

    def capture(args, env):
        prefix = ('mv() { case "$2" in *".wpa_cli.new-"*) return 9;; esac; command mv "$@"; }; '
                  if failure == 'interrupted' else '')
        result = subprocess.run(['sh', '-c', prefix + args[-1]], capture_output=True, timeout=5)
        return result.returncode, result.stdout

    ssh = receiver_ssh.ReadinessSsh(channel=None, capture=capture)
    monkeypatch.setattr(ssh, '_authenticated_args', authenticated)
    enrollment = SimpleNamespace(target=None, host_public_key=None, credential=None, check=None)
    hashes = lambda files: {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}
    args = {'transaction': transaction, 'expected_files': hashes(new), 'expected_current': hashes(old)}
    if failure:
        with pytest.raises(AccessDenied, match='ACTIVATION_UNCONFIRMED'):
            ssh.activate_netrunner_stage(enrollment, **args)
        expected = old | ({'wpa_cli': b'changed outside install'} if failure == 'stale' else {})
    else:
        ssh.activate_netrunner_stage(enrollment, **args)
        expected = new
    assert {name: (tmp_path / name).read_bytes() for name in names} == expected
    assert not (tmp_path / '.install-lock').exists()


def test_selected_pro_never_uses_max_download_or_unrelated_board(tmp_path, monkeypatch):
    binding = ReceiverBinding(1, 'fixture', 'attached')
    target = SimpleNamespace(binding=binding, device_name='Ascent_VRX_pro', serial_number='1234',
                             hardware='Ascent-VRX-Pro-V3.0-1.0', firmware='Ascent_VRX_Pro_18_21_10')
    service = ReceiverService(selector=SimpleNamespace(capture=lambda: target), credentials=None,
                              enrollments=None, transport=None, enabled=lambda: True)
    selected = []
    monkeypatch.setattr(service, 'apply_netrunner_download', lambda current, **args: selected.append(args))
    pin = {'widget_id': 'netrunner', 'version': '2.10.1', 'files': {'test': 'digest'}, 'sha256': 'a' * 64}
    pins = {'netrunner-max-2.10.1': pin, 'netrunner-pro-2.10.1': {**pin, 'profile': 'pro-18.21.10'}}
    args = {'expected_binding': binding, 'key_type': 'ed25519', 'library': tmp_path, 'release_id': None,
            'release_pins': pins, 'action': 'install'}
    with pytest.raises(AccessDenied, match='DOWNLOAD_REQUIRED'):
        service.apply_selected_netrunner_download(**args)
    (tmp_path / 'netrunner-pro-2.10.1.zip').write_bytes(b'synthetic archive')
    with pytest.raises(AccessDenied, match='RELEASE_NOT_APPROVED'):
        service.apply_selected_netrunner_download(**{**args, 'release_id': 'netrunner-max-2.10.1'})
    assert not selected
    service.apply_selected_netrunner_download(**args)
    assert selected[0]['archive'].name == 'netrunner-pro-2.10.1.zip'
    target.hardware = 'unqualified board'
    with pytest.raises(AccessDenied, match='PROFILE_UNSUPPORTED'):
        service.apply_selected_netrunner_download(**args)
    assert len(selected) == 1
