"""Hub and RC/MSP configuration: the vendor JSON lane, its schemas, and its limits.

Vendor oracle: PC Tool D2.0.37 (PDB present), cross-checked against D2.0.51.
Citations in runtime/caddx_device_config.py.

The properties that matter most here are the negative ones. This lane looks like the
RF lane and is not: it has no commit opcode, and it has no read at all. A regression
that quietly added either would be invisible in a happy-path test and wrong on
hardware, so both are pinned explicitly.
"""
import json
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'runtime'))

import caddx_device_config as cfg
import caddx_vendor_write as w


# --------------------------------------------------------------------------- #
# The lane
# --------------------------------------------------------------------------- #

def test_remote_paths_are_derived_the_way_the_vendor_derives_them():
    """SetFilePath_Json builds "/factory/" + Path.GetFileName(localPath).

    UpgradeProcessFSM.cs:100-107, over the shipped config values
    HUB_JSON_Path = resource\\param\\mipi_hub.json and
    RCMODE_JSON_Path = resource\\param\\msp_rc_cfg.json.
    """
    assert cfg.HUB_REMOTE_PATH == '/factory/' + cfg.HUB_BASENAME == '/factory/mipi_hub.json'
    assert cfg.RC_REMOTE_PATH == '/factory/' + cfg.RC_BASENAME == '/factory/msp_rc_cfg.json'


def test_the_write_path_allowlist_is_exactly_three_literals():
    """ArFileInfo.filePath is the field the public rooting exploit abuses.

    CLAUDE.md section Authorization (a) names it as the command-injection vector, and
    "Do not" forbids exposing arbitrary filesystem writes. So this must stay a closed
    set of literals -- never a prefix test, a join, or a caller-supplied path.
    """
    assert set(w.ALLOWED_REMOTE_PATHS) == {
        '/factory/fpv_bb_freq.json',
        '/factory/mipi_hub.json',
        '/factory/msp_rc_cfg.json',
    }


@pytest.mark.parametrize('bad', [
    '/factory/passwd', '/etc/passwd', '/factory/user_cfg.json',
    '/factory/mipi_hub.json ', '../factory/mipi_hub.json',
    '/factory/mipi_hub.json;reboot', '/factory/', '',
])
def test_build_file_info_refuses_any_other_remote_path(bad):
    with pytest.raises(w.CaddxWriteError) as e:
        w.build_file_info(b'{}', remote_path=bad)
    assert e.value.code == 'DEVICE_PATH_NOT_ALLOWED'


def test_the_json_lane_has_no_commit_opcode():
    """121 is SET_BB_FREQ_CONFIG and must never be sent on this lane.

    On the 117 ACK, UpgradeProcessFSM.cs:865-878 branches on `_isAutoSendBBFreq`:
    set -> UpgState.SetBBFreq (the empty 121, i.e. the RF lane); clear ->
    UpgState.Completed_Json -> Send_ReopenJson(). So for hub and RC the transfer IS
    the commit. Sending 121 here would issue an unrelated opcode against a device
    that was configured for something else entirely.
    """
    src = (ROOT / 'runtime' / 'caddx_vendor_write.py').read_text()
    start = src.index('def upload_device_json')
    end = src.index('def send_reboot_unacked')
    body = src[start:end]
    assert 'self.exchange(121' not in body
    assert 'self.exchange(115' in body
    assert 'self.exchange(116' in body
    assert 'self.exchange(117' in body
    assert 'send_reboot_unacked' in body


def test_upload_device_json_refuses_the_rf_table():
    """The RF table needs its 121; routing it down this lane would silently skip it."""
    session = w.VendorWriteSession.__new__(w.VendorWriteSession)
    session.receive_max_size = None
    with pytest.raises(w.CaddxWriteError) as e:
        w.VendorWriteSession.upload_device_json(
            session, b'{}', remote_path='/factory/fpv_bb_freq.json')
    assert e.value.code == 'WRONG_LANE_FOR_RF_TABLE'


def test_no_readback_is_claimed_anywhere_on_this_lane():
    """There is no opcode that reads either file back. Nothing may imply otherwise."""
    q = cfg.qualify_device_config_write(
        'hub', candidate={'identity_proven': True, 'serial_com': 'COM10',
                          'serial_container_id': '{X}'},
        identity={'device_name': 'Ascent_CamHub'}, role='camera_hub')
    assert q['eligible'] is True
    # Eligible, but neither of these may ever be True on this lane.
    assert q['readback_supported'] is False
    assert q['capability_proven'] is False
    assert q['commit_opcode'] is None


def test_qualification_fails_closed():
    q = cfg.qualify_device_config_write('hub', candidate=None, identity=None, role=None)
    assert q['eligible'] is False
    for expected in ('NO_ACTIVE_QUALIFIED_DEVICE', 'RAW_IDENTITY_NOT_PROVEN',
                     'SERIAL_TRANSPORT_MISSING', 'PHYSICAL_CONTAINER_ID_MISSING',
                     'DEVICE_ROLE_UNKNOWN'):
        assert expected in q['reasons']


def test_hub_does_not_apply_to_a_plain_receiver():
    """The hub document configures MIPI camera inputs; a VRX has none."""
    q = cfg.qualify_device_config_write(
        'hub', candidate={'identity_proven': True, 'serial_com': 'COM10',
                          'serial_container_id': '{X}'},
        identity={'device_name': 'Ascent_VRX_max_WF'}, role='receiver')
    assert q['eligible'] is False
    assert 'DEVICE_ROLE_NOT_APPLICABLE' in q['reasons']


# --------------------------------------------------------------------------- #
# Hub schema -- the device's file outranks the editor's combo box
# --------------------------------------------------------------------------- #

REAL_DEVICE_HUB = pathlib.Path.home() / 'ascent-corpus' / 'rootfs_19_2_5' / 'fpv' / 'mipi_hub.json'


@pytest.mark.skipif(not REAL_DEVICE_HUB.exists(), reason='extracted Sky rootfs not present')
def test_the_stock_device_document_validates():
    """The regression this guards is a real one that happened during development.

    The stock file carries {"dev_name": "none", "res_info": "1920x1080P60"} on three
    of four nodes. The 2.0.37 editor would never write that -- CamHubCtrl.cs:296-298
    forces res_info to "none" whenever the device goes to "none". A validator built
    from the editor's behaviour rejects the document the device actually ships.
    """
    doc = json.loads(REAL_DEVICE_HUB.read_text())
    result = cfg.validate_hub_document(doc)
    assert result['ok'] is True
    assert any(warn['code'] == 'HUB_NONE_NOT_PAIRED' for warn in result['warnings'])


def test_the_shipped_vendor_template_validates():
    doc = json.loads((ROOT / 'runtime' / 'vendor_templates' / 'mipi_hub.json').read_text())
    assert cfg.validate_hub_document(doc)['ok'] is True


def test_a_camera_the_decompiled_editor_never_heard_of_is_a_warning_not_an_error():
    """`MAX` is on node1 of our own vendor template and in neither build's combo box.

    Refusing unlisted names would mean refusing every camera newer than the build we
    decompiled, and refusing our own shipped template.
    """
    doc = json.loads((ROOT / 'runtime' / 'vendor_templates' / 'mipi_hub.json').read_text())
    doc['node1']['dev_name'] = 'SOME_FUTURE_CAM'
    result = cfg.validate_hub_document(doc)
    assert result['ok'] is True
    assert any(warn['code'] == 'HUB_DEV_NAME_UNLISTED' for warn in result['warnings'])


@pytest.mark.parametrize('mutate,code', [
    (lambda d: d.pop('node2'), 'HUB_NODE_MISSING'),
    (lambda d: d.__setitem__('node0', []), 'HUB_NODE_NOT_OBJECT'),
    (lambda d: d['node0'].__setitem__('selected', 2), 'HUB_FLAG_INVALID'),
    (lambda d: d['node0'].__setitem__('selected', True), 'HUB_FLAG_INVALID'),
    (lambda d: d['node0'].__setitem__('dev_name', ''), 'HUB_DEV_NAME_INVALID'),
    (lambda d: d.__setitem__('fly_ctrl', 3), 'HUB_FLY_CTRL_INVALID'),
])
def test_hub_structural_faults_are_errors(mutate, code):
    doc = json.loads((ROOT / 'runtime' / 'vendor_templates' / 'mipi_hub.json').read_text())
    mutate(doc)
    with pytest.raises(cfg.DeviceConfigError) as e:
        cfg.validate_hub_document(doc)
    assert e.value.code == code


# --------------------------------------------------------------------------- #
# RC schema
# --------------------------------------------------------------------------- #

def test_slot_is_a_channel_index_not_a_boolean():
    """RCModeCtrl.cs:249-254 samples slot0 = 8, slot1 = 10.

    The pre-existing UI rendered `slot0` as an ENABLED yes/no column, which no
    reading of those values survives. Enable/disable is carried by the minimum.
    """
    doc = {'slot0': 8, 'slot0_min': 1000, 'slot0_max': 1300,
           'slot1': 10, 'slot1_min': 1500, 'slot1_max': 2000,
           'slot2': 0, 'slot2_min': 9990, 'slot2_max': 9999,
           'slot3': 0, 'slot3_min': 9990, 'slot3_max': 9999}
    assert cfg.validate_rc_document(doc)['ok'] is True
    assert cfg.rc_slot_disabled(doc, 'slot2') is True
    assert cfg.rc_slot_disabled(doc, 'slot0') is False


def test_the_disable_sentinel_is_the_minimum_above_2100():
    """RCModeCtrl.cs:264/291/318/345 all test `slotN_min > 2100`."""
    assert cfg.RC_DISABLED_MIN_THRESHOLD == 2100
    doc = {'slot0': 0, 'slot0_min': 2101, 'slot0_max': 2200}
    assert cfg.rc_slot_disabled(doc, 'slot0') is True
    doc['slot0_min'] = 2100
    assert cfg.rc_slot_disabled(doc, 'slot0') is False


def test_the_shipped_rc_template_validates():
    doc = json.loads((ROOT / 'runtime' / 'vendor_templates' / 'msp_rc_cfg.json').read_text())
    assert cfg.validate_rc_document(doc)['ok'] is True


def test_the_four_slots_are_the_four_vendor_camera_functions():
    """Handoff section 9's "zoom, reset, camera change, camera reset", in slot order."""
    assert [label for _, label in cfg.RC_SLOTS] == [
        'ZOOM', 'ZOOM RESET', 'CAMERA CHANGE', 'CAMERA RESET']


@pytest.mark.parametrize('doc,code', [
    ({'slot0': 8, 'slot0_min': 1000}, 'RC_FIELD_MISSING'),
    ({'slot0': 'eight', 'slot0_min': 1000, 'slot0_max': 1300}, 'RC_FIELD_NOT_INT'),
    ({'slot0': 99, 'slot0_min': 1000, 'slot0_max': 1300}, 'RC_CHANNEL_OUT_OF_RANGE'),
    ({'slot0': 0, 'slot0_min': 1000, 'slot0_max': 1300}, 'RC_ENABLED_SLOT_UNASSIGNED'),
    ({'slot0': 8, 'slot0_min': 1400, 'slot0_max': 1200}, 'RC_RANGE_INVERTED'),
    ({'slot0': 8, 'slot0_min': 500, 'slot0_max': 1300}, 'RC_PULSE_OUT_OF_RANGE'),
])
def test_rc_faults_are_errors(doc, code):
    with pytest.raises(cfg.DeviceConfigError) as e:
        cfg.validate_rc_document(doc)
    assert e.value.code == code


def test_two_functions_cannot_share_one_rc_channel():
    """One stick movement would fire both. The vendor does not guard this; we do."""
    doc = {'slot0': 8, 'slot0_min': 1000, 'slot0_max': 1300,
           'slot1': 8, 'slot1_min': 1500, 'slot1_max': 2000,
           'slot2': 0, 'slot2_min': 9990, 'slot2_max': 9999,
           'slot3': 0, 'slot3_min': 9990, 'slot3_max': 9999}
    with pytest.raises(cfg.DeviceConfigError) as e:
        cfg.validate_rc_document(doc)
    assert e.value.code == 'RC_CHANNEL_DOUBLE_ASSIGNED'


# --------------------------------------------------------------------------- #
# Merge and serialise
# --------------------------------------------------------------------------- #

def test_merge_preserves_unknown_keys_and_order():
    """Stricter than the vendor, which rebuilds both documents from a typed model.

    RCModeCtrl.cs:640 serialises SlotData (twelve fixed properties) and
    CamHubCtrl.cs:257 serialises CamHubData, so either tool drops anything it does
    not know. Ours must not. This is deliberately not vendor parity.
    """
    baseline = {'a': 1, 'vendor_extra': {'keep': True}, 'node0': {'x': 1, 'y': 2}}
    merged = cfg.merge_document({'node0': {'y': 9}}, baseline)
    assert merged['vendor_extra'] == {'keep': True}
    assert merged['node0'] == {'x': 1, 'y': 9}          # nested merge, not replace
    assert list(merged) == list(baseline)                # order preserved


def test_diff_reports_nested_fields_by_path():
    baseline = {'node0': {'dev_name': 'Z8'}}
    merged = {'node0': {'dev_name': 'IR'}}
    assert cfg.diff_document(baseline, merged) == [
        {'field': 'node0.dev_name', 'from': 'Z8', 'to': 'IR'}]


def test_serialisation_matches_the_vendor_two_space_indent():
    """RCModeCtrl.cs:640 uses Formatting.Indented; Newtonsoft renders that at two."""
    raw = cfg.serialize_document({'a': {'b': 1}})
    assert raw == b'{\n  "a": {\n    "b": 1\n  }\n}'


def test_selftest_passes():
    assert cfg.selftest()['ok'] is True
