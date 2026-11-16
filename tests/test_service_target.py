"""Actual DeviceSession owner with synthetic Windows inventory; no receiver I/O."""
import copy
import sys
from pathlib import Path
import pytest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'runtime'))
from device_session import DeviceSession, InventoryCache
import receiver_identity
import device_capability
from ascent_core.service_access import AccessDenied
from ascent_core.service_target import SelectedReceiver
from test_device_session_integration import FakeWindows, CID


def fixture_target():
    windows = FakeWindows()
    windows.ipv4 = [{'IPAddress': '192.168.3.103', 'PrefixLength': 24, 'AddressState': 'Preferred'}]
    policy = {'ground': '192.168.3.102', 'host_rndis_prefix': 24}
    session = DeviceSession(mirror={}, inventory=InventoryCache(windows.inventory, ttl=0), policy=policy)
    candidate = {'id': 'synthetic-selected-receiver', 'container_id': CID, 'serial_container_id': CID,
                 'network_container_id': CID, 'serial_com': 'COM10', 'vid': '1D77', 'pid': 'A4A2'}
    identity = {'device_name': 'Ascent_VRX_max_WF', 'serial_number': 'synthetic-unit-a',
                'firmware': '19.2.14', 'hardware': 'synthetic-hardware'}
    session.connect(candidate=candidate, identity=identity)
    selector = SelectedReceiver(session=session, resolve_identity=receiver_identity.resolve,
        classify=device_capability.classify, endpoint=lambda: policy['ground'])
    return selector, session, windows, policy, candidate, identity


def test_capture_uses_existing_owner_and_current_transport():
    selector, session, windows, _, _, _ = fixture_target()
    target = selector.capture()
    assert target.binding.selection_epoch == session.generation
    assert target.binding.receiver_identity == CID
    assert target.interface_index == windows.ifindex and target.serial_port == windows.serial_com
    selector.check(target)


@pytest.mark.parametrize('change', ['clear', 'reconnect', 'serial', 'source', 'index', 'firmware', 'endpoint'])
def test_changed_context_refuses_old_target(change):
    selector, session, windows, policy, candidate, identity = fixture_target()
    target = selector.capture()
    if change == 'clear': session.clear()
    elif change == 'reconnect': session.clear(); session.connect(candidate=candidate, identity=identity)
    elif change == 'serial': windows.serial_com = 'COM11'
    elif change == 'source': windows.ipv4[0]['IPAddress'] = '192.168.3.104'
    elif change == 'index': windows.ifindex += 1
    elif change == 'firmware': session.set_identity({**identity, 'firmware': 'synthetic-other'})
    else: policy['ground'] = '192.168.3.101'
    with pytest.raises(AccessDenied): selector.check(target)


def test_identity_a_b_a_still_invalidates_epoch():
    selector, session, _, _, _, identity = fixture_target()
    target = selector.capture()
    session.set_identity({**identity, 'serial_number': 'synthetic-unit-b'})
    session.set_identity(identity)
    assert session.generation > target.binding.selection_epoch
    with pytest.raises(AccessDenied): selector.check(target)


def test_identical_identity_refresh_preserves_epoch():
    selector, session, _, _, _, identity = fixture_target()
    target = selector.capture(); session.set_identity(dict(identity))
    assert session.generation == target.binding.selection_epoch
    selector.check(target)


@pytest.mark.parametrize('condition', ['missing-network', 'duplicate-address', 'conflict', 'aircraft', 'ethernet', 'public-endpoint'])
def test_unqualified_context_not_promoted_to_privileged_identity(condition):
    selector, session, windows, policy, _, identity = fixture_target()
    if condition == 'missing-network': windows.include_network = False
    elif condition == 'duplicate-address': windows.ipv4[0]['AddressState'] = 'Duplicate'
    elif condition == 'conflict': session.device.connect_record['network_container_id'] = 'synthetic-conflicting-container'
    elif condition == 'aircraft': session.set_identity({**identity, 'device_name': 'Ascent_GT_Pro'})
    elif condition == 'ethernet': session.device.network_target = {'connection_token': 'synthetic-eth'}
    else: policy['ground'] = '192.0.2.10'
    with pytest.raises(AccessDenied): selector.capture()


def test_selection_change_during_inventory_discards_context():
    selector, session, _, _, _, _ = fixture_target()
    original = session.transport
    def changed(*args, **kwargs):
        result = original(*args, **kwargs)
        session.clear()
        return result
    session.transport = changed
    with pytest.raises(AccessDenied, match='BINDING_CHANGED'): selector.capture()


def test_fast_selection_guard_does_not_probe_os():
    selector, session, _, _, _, _ = fixture_target(); current = selector.capture()
    session.transport = lambda *args, **kwargs: pytest.fail('fast guard must not probe inventory')
    selector.check_selection(current)
    session.clear()
    with pytest.raises(AccessDenied): selector.check_selection(current)
