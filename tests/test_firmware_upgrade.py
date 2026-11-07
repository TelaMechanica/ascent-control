"""Stock-Caddx firmware upgrade lane: framing, validation, full sequence, failures.

Offline only. No hardware is contacted; the serial transport and the device are both
faked. Every protocol claim asserted here is cited to the decompiled PC Tool in
runtime/caddx_firmware_upgrade.py and docs/FIRMWARE_UPGRADE.md.

The fake device below is deliberately strict: it rejects a frame whose CRC32 does not
recompute, refuses to answer 114/115/116/117/118 before it has been rebooted into
clean mode, and refuses 116 before a 115 has been accepted. A test that passes against
it has exercised ordering, not just opcode presence.
"""
import hashlib
import json
import os
import pathlib
import re
import struct
import sys
import tempfile

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'runtime'))
import caddx_firmware_upgrade as fw
import caddx_read_bundle as rb
import dev_harness as h

# Real bench identity, from fixtures/vrxmax_rf_write_bench_2026-09-06.json.
DEVICE_NAME = 'Ascent_VRX_max_WF'
DEVICE_FW = 'Ascent_VRX_Max_19_2_4'
DEVICE_HW = 'Ascent-VRX-Max-V2.2-10.0'
DEVICE_SN = '9005'


# ======================================================================================
# Fake device
# ======================================================================================
def device_info_payload(*, receive_max_size=fw.OBSERVED_DEVICE_RECEIVE_MAX_SIZE,
                        firmware=DEVICE_FW, device_name=DEVICE_NAME,
                        hardware=DEVICE_HW, serial_number=DEVICE_SN,
                        sdk='19.2.4', cpu_temp=41, detail='OK'):
    p = bytearray(300)
    p[0:4] = int(receive_max_size).to_bytes(4, 'little')
    p[4:4 + len(sdk)] = sdk.encode()
    p[36:36 + len(device_name)] = device_name.encode()
    p[100:104] = int(cpu_temp).to_bytes(4, 'little', signed=True)
    p[104:104 + len(firmware)] = firmware.encode()
    p[168:168 + len(serial_number)] = serial_number.encode()
    p[200:200 + len(hardware)] = hardware.encode()
    p[232:236] = (0).to_bytes(4, 'little', signed=True)
    p[236:236 + len(detail)] = detail.encode()
    return bytes(p)


def ack68(status=0, detail='OK'):
    """ResAckInfo -- the 68-byte payload behind the observed 104-byte 3/114/115 ACKs."""
    return struct.pack('<i', status) + detail.encode('ascii').ljust(64, b'\0')


def filedata80(length, cursize, totalsize, status=0, detail='OK'):
    """ResFileDataInfo -- the 80-byte payload behind the observed 116-byte 117 ACK."""
    return (struct.pack('<iiii', length, cursize, totalsize, status)
            + detail.encode('ascii').ljust(64, b'\0'))


def upgstatus72(percent, status, detail=''):
    return struct.pack('<ii', percent, status) + detail.encode('ascii').ljust(64, b'\0')


class FakeDevice:
    """One Ascent unit speaking the firmware lane."""

    def __init__(self, *, receive_max_size=fw.OBSERVED_DEVICE_RECEIVE_MAX_SIZE,
                 expect_md5=None, expect_total=None,
                 status_sequence=None, firmware_after=None,
                 sendfile_start_status=0, sendfile_end_status=0,
                 sendfile_end_detail='OK', reboot_answers=True,
                 firmware=DEVICE_FW, port='COM10', renumber_to=None):
        self.receive_max_size = receive_max_size
        self.expect_md5 = expect_md5
        self.expect_total = expect_total
        # Each entry is (percent, status). Consumed one per 118 request; the last
        # entry repeats forever.
        self.status_sequence = list(status_sequence or [(50, 2), (100, 3)])
        self.firmware = firmware
        self.firmware_after = firmware_after
        self.sendfile_start_status = sendfile_start_status
        self.sendfile_end_status = sendfile_end_status
        self.sendfile_end_detail = sendfile_end_detail
        self.reboot_answers = reboot_answers
        self.port = port
        self.renumber_to = renumber_to

        self.clean_mode = False
        self.transfer_open = False
        self.upgrade_mode = False
        self.flashed = False
        self.received = bytearray()
        self.declared = None
        self.log: list[dict] = []
        self.chunk_lengths: list[int] = []
        self.status_queries = 0
        self.reboots = 0
        self.bad_crc = 0

    # -- request handling -------------------------------------------------------------
    def request(self, header_bytes, payload):
        hdr = rb.ArHeader.unpack(header_bytes)
        z = bytearray(header_bytes)
        z[32:36] = b'\0\0\0\0'
        if hdr.crc32 != rb.crc32_vendor(bytes(z), payload):
            self.bad_crc += 1
            return None
        assert hdr.magic == fw.MAGIC and hdr.version == fw.VERSION
        assert hdr.type == 1 and hdr.format == 2
        self.log.append({'command': hdr.command, 'seq': hdr.seq, 'retry': hdr.retry,
                         'length': len(payload)})
        return self._dispatch(hdr, payload)

    def _reply(self, hdr, payload):
        h0 = fw.HEADER.pack(fw.MAGIC, fw.VERSION, 2, 0, 0xABCD, hdr.command, 2, 0,
                            len(payload), hdr.seq, hdr.retry, 0)
        crc = rb.crc32_vendor(h0, payload)
        return fw.HEADER.pack(fw.MAGIC, fw.VERSION, 2, 0, 0xABCD, hdr.command, 2, 0,
                              len(payload), hdr.seq, hdr.retry, crc) + payload

    def _unknown(self, hdr):
        h0 = fw.HEADER.pack(fw.MAGIC, fw.VERSION, 2, 0, 0xABCD, 0, 2, 0, 68, hdr.seq, 0, 0)
        p = ack68(-1, 'unkonwn cmd')
        crc = rb.crc32_vendor(h0, p)
        return fw.HEADER.pack(fw.MAGIC, fw.VERSION, 2, 0, 0xABCD, 0, 2, 0, 68,
                              hdr.seq, 0, crc) + p

    def _dispatch(self, hdr, payload):
        c = hdr.command
        if c == fw.CMD_FIND_DEVICE:
            fwstr = self.firmware_after if self.flashed and self.firmware_after else self.firmware
            return self._reply(hdr, device_info_payload(
                receive_max_size=self.receive_max_size, firmware=fwstr))
        if c == fw.CMD_REBOOT:
            assert len(payload) == 32, 'ArDeviceReboot.mode is a 32-byte field'
            self.reboots += 1
            if payload == fw.REBOOT_MODE_CLEAN:
                self.clean_mode = True
            if not self.reboot_answers:
                return None
            return self._reply(hdr, ack68(0, 'OK'))
        if c == fw.CMD_REMOTE_UPGRADE:
            if not self.clean_mode:
                return self._unknown(hdr)
            self.upgrade_mode = True
            return self._reply(hdr, ack68(0, 'OK'))
        if c == fw.CMD_SENDFILE_START:
            if not self.upgrade_mode:
                return self._unknown(hdr)
            assert len(payload) == 328, 'ArFileInfo must be exactly 328 bytes on the wire'
            md5 = payload[:32].decode('ascii')
            length, save_as = struct.unpack_from('<ii', payload, 64)
            remote = payload[72:200].split(b'\0', 1)[0].decode('ascii')
            local = payload[200:328].split(b'\0', 1)[0].decode('ascii')
            self.declared = {'md5': md5, 'length': length, 'save_as_file': save_as,
                             'remote_path': remote, 'file_dir': local}
            if self.sendfile_start_status != 0:
                return self._reply(hdr, ack68(self.sendfile_start_status, 'no space left'))
            self.transfer_open = True
            self.received = bytearray()
            return self._reply(hdr, ack68(0, 'OK'))
        if c == fw.CMD_SENDFILE_DATA:
            if not self.transfer_open:
                return self._unknown(hdr)
            assert len(payload) <= self.receive_max_size, 'chunk exceeded the declared size'
            self.chunk_lengths.append(len(payload))
            self.received.extend(payload)
            return self._reply(hdr, filedata80(len(payload), len(self.received),
                                               self.declared['length']))
        if c == fw.CMD_SENDFILE_END:
            if not self.transfer_open:
                return self._unknown(hdr)
            self.transfer_open = False
            if self.sendfile_end_status != 0:
                return self._reply(hdr, filedata80(0, len(self.received),
                                                   self.declared['length'],
                                                   self.sendfile_end_status,
                                                   self.sendfile_end_detail))
            # The device verifies the whole-file MD5 it was handed at 115 --
            # ar_fpvhs_upgrade "[INFO] MD5 comparison: calculated=... expected=..."
            got = hashlib.md5(bytes(self.received)).hexdigest()
            if self.expect_md5 is not None and got != self.expect_md5:
                return self._reply(hdr, filedata80(0, len(self.received),
                                                   self.declared['length'], -1,
                                                   'CompareMD5 fail!'))
            if self.expect_total is not None and len(self.received) != self.expect_total:
                return self._reply(hdr, filedata80(0, len(self.received),
                                                   self.declared['length'], -1,
                                                   'size mismatch'))
            return self._reply(hdr, filedata80(0, len(self.received),
                                               self.declared['length'], 0,
                                               self.sendfile_end_detail))
        if c == fw.CMD_UPGRADE_STATUS:
            self.status_queries += 1
            idx = min(self.status_queries - 1, len(self.status_sequence) - 1)
            percent, status = self.status_sequence[idx]
            if percent > 99 and status >= 0:
                self.flashed = True
            return self._reply(hdr, upgstatus72(percent, status,
                                                fw.UPGRADE_STATUS_CODES.get(status, ('', ''))[0]))
        return self._unknown(hdr)


class FakePort:
    def __init__(self, device, port):
        self.device = device
        self.port = str(port).upper()
        self.rx = bytearray()
        self.closed = False

    def open(self):
        return self

    def close(self):
        self.closed = True

    def purge_rx(self):
        self.rx.clear()

    def write(self, data):
        data = bytes(data)
        assert len(data) >= fw.HEADER_SIZE
        reply = self.device.request(data[:fw.HEADER_SIZE], data[fw.HEADER_SIZE:])
        if reply:
            self.rx.extend(reply)

    def read(self, n=4096):
        out = bytes(self.rx[:n])
        del self.rx[:n]
        return out


def fake_factory(device):
    def factory(port):
        return FakePort(device, port)
    return factory


def instant_resolver(new_port=None):
    """A reconnect that succeeds immediately, optionally on a different COM name."""
    calls = []

    def resolve(previous_port, *, settle_s, poll_budget_s, phase, progress=None):
        calls.append({'phase': phase, 'previous_port': previous_port,
                      'settle_s': settle_s, 'poll_budget_s': poll_budget_s})
        return (new_port or previous_port), {'strategy': 'test', 'attempts': 1}

    resolve.calls = calls
    return resolve


def make_session(device, *, port='COM10', resolver=None, progress=None):
    return fw.FirmwareUpgradeSession(
        port, serial_factory=fake_factory(device),
        port_resolver=resolver or instant_resolver(),
        progress=progress, sleep=lambda _s: None)


@pytest.fixture()
def image_file():
    """A small image with a valid trailing ASCII MD5, laid out like a real one.

    Real VRX images are RKFW containers whose last 32 bytes are the lowercase ASCII
    MD5 of everything before them -- verified against four vendor images, recorded in
    fixtures/vrx_firmware_images.json.
    """
    with tempfile.TemporaryDirectory() as d:
        body = b'RKFW' + bytes(range(256)) * 40    # 10244 bytes
        digest = hashlib.md5(body).hexdigest().encode('ascii')
        p = pathlib.Path(d) / 'Ascent_VRX_Max_19_2_5.img'
        p.write_bytes(body + digest)
        yield str(p)


# ======================================================================================
# Wire framing and ArFileInfo
# ======================================================================================
def test_module_selftest():
    assert fw.selftest()['ok'] is True


def test_header_and_command_set():
    assert fw.HEADER_SIZE == 36
    assert fw.AR_FILE_INFO.size == 328
    assert sorted(fw.ALLOWED_COMMANDS) == [3, 60, 114, 115, 116, 117, 118]
    # The RF lane's opcodes must never be reachable through this transport.
    for bad in (0, 119, 120, 121, 122, 123, 124):
        with pytest.raises(ValueError):
            fw.build_request(bad)


def test_request_framing_matches_vendor_enqueue_send():
    req = fw.build_request(114, b'', seq=9, retry=3)
    assert len(req) == 36
    hdr = rb.ArHeader.unpack(req)
    assert (hdr.magic, hdr.version, hdr.type, hdr.msgid, hdr.unused) == \
        (fw.MAGIC, fw.VERSION, 1, 0, 0xABCD)
    assert (hdr.command, hdr.format, hdr.userid, hdr.length) == (114, 2, 0, 0)
    assert hdr.seq == 9 and hdr.retry == 3
    z = bytearray(req); z[32:36] = b'\0\0\0\0'
    assert hdr.crc32 == rb.crc32_vendor(bytes(z), b'')


def test_reboot_clean_mode_field():
    # UpgradeProcessFSM.Send_RebootClean: ASCII "clean", Array.Resize(32).
    assert fw.REBOOT_MODE_CLEAN == b'clean' + b'\0' * 27
    assert len(fw.REBOOT_MODE_CLEAN) == 32
    # The RF lane's reboot mode is all zeros; the two must not be confused.
    import caddx_vendor_write as vw
    assert vw.REBOOT_MODE_NORMAL != fw.REBOOT_MODE_CLEAN


def test_file_info_field_layout():
    info = fw.build_file_info(md5_hex='a' * 32, length=179477066,
                              local_path=r'C:\firmware\Ascent_VRX_Max_19_2_5.img')
    assert len(info) == 328
    assert info[:32] == b'a' * 32 and info[32:64] == b'\0' * 32
    assert struct.unpack_from('<i', info, 64)[0] == 179477066
    assert struct.unpack_from('<i', info, 68)[0] == 1               # saveAsFile
    assert info[72:200].split(b'\0', 1)[0] == b'/tmp/pc/Ascent_VRX_Max_19_2_5.img'
    # fileDir is the PC-SIDE path, forward-slash normalised.
    assert info[200:328].split(b'\0', 1)[0] == b'C:/firmware/Ascent_VRX_Max_19_2_5.img'


def test_file_dir_keeps_the_last_128_characters():
    # FileTransferSession.BuildFileInfo, 2.0.51: text.Remove(0, text.Length - 128).
    long_path = 'C:/' + 'x' * 300 + '/a.img'
    assert fw.file_dir_field(long_path) == long_path[-128:]
    info = fw.build_file_info(md5_hex='b' * 32, length=1, local_path=long_path)
    assert info[200:328] == long_path[-128:].encode('ascii')


def test_remote_path_is_tmp_pc_plus_basename():
    assert fw.remote_path_for(r'D:\a\b\Ascent_VRX_Max_19_2_5.img') == \
        '/tmp/pc/Ascent_VRX_Max_19_2_5.img'
    assert fw.remote_path_for('/x/y/z.img') == '/tmp/pc/z.img'


def test_ack_shapes_match_observed_vendor_frame_lengths():
    # Vendor log: cmd 3 / 114 / 115 return 104-byte frames -> 68-byte ResAckInfo.
    assert 36 + 68 == 104
    assert fw.parse_ack68(ack68(0, 'OK')) == {'status': 0, 'detail': 'OK',
                                              'payload_length': 68}
    # Vendor log: cmd 117 returns a 116-byte frame -> 80-byte ResFileDataInfo.
    assert 36 + 80 == 116
    d = fw.parse_file_data80(filedata80(1024, 2048, 4096))
    assert d['length'] == 1024 and d['cursize'] == 2048 and d['totalsize'] == 4096
    assert fw.parse_ack68(b'\0' * 67) is None
    assert fw.parse_file_data80(b'\0' * 79) is None
    assert fw.parse_upgrade_status(b'\0' * 71) is None


# ======================================================================================
# Chunk-size negotiation
# ======================================================================================
def test_chunk_size_comes_from_the_device_and_agrees_with_the_vendor_default():
    r = fw.resolve_chunk_size(fw.OBSERVED_DEVICE_RECEIVE_MAX_SIZE)
    assert r['chunk_size'] == 1048576
    assert r['source'] == 'device_receive_max_size' and r['honoured'] is True
    # The compiled vendor default is the same number, so the two never disagree on
    # real hardware: UpgradeProcessFSM._chunkSize = 1048576.
    assert fw.DEFAULT_CHUNK_SIZE == fw.OBSERVED_DEVICE_RECEIVE_MAX_SIZE


@pytest.mark.parametrize('declared', [None, 0, -1, 512, 1 << 30])
def test_out_of_range_receive_max_size_falls_back_and_is_recorded(declared):
    r = fw.resolve_chunk_size(declared)
    assert r['chunk_size'] == fw.DEFAULT_CHUNK_SIZE
    assert r['source'] == 'vendor_default' and r['honoured'] is False


def test_session_negotiates_the_chunk_size_from_command_60():
    dev = FakeDevice(receive_max_size=4096)
    with make_session(dev) as s:
        s.find_device()
    assert s.chunk['chunk_size'] == 4096
    assert s.chunk['source'] == 'device_receive_max_size'


def test_absurd_declared_receive_size_produces_a_warning():
    dev = FakeDevice(receive_max_size=1 << 30)
    with make_session(dev) as s:
        s.find_device()
    assert s.chunk['chunk_size'] == fw.DEFAULT_CHUNK_SIZE
    assert [w['id'] for w in s.warnings] == ['receive_max_size_out_of_range']


# ======================================================================================
# Version parsing -- transcribed vendor regexes
# ======================================================================================
@pytest.mark.parametrize('name,expected', [
    ('Ascent_VRX_Max_19_2_5.img', '19.2.5'),
    ('Ascent_VRX_Max_18_21_8.img', '18.21.8'),
    ('Ascent_G_Sky_19_2_4.img', '19.2.4'),
    ('Ascent_GT_Max_WF_18_3_4_z8_7.img', '18.3.4.7'),
    ('Ascent_GT_Max_WF_18_3_4_z40_9.img', '18.3.4.9'),
    ('Ascent_GT_Pro_Hub_17_5_3_hub_2.IMG', '17.5.3.2'),
    ('Ascent_VRX_Max_19_2_5.zip', ''),
    ('nothing.img', ''),
])
def test_extract_version(name, expected):
    assert fw.extract_version(name) == expected


def test_current_version_label_falls_back_then_gives_up():
    assert fw.current_version_label('/f/Ascent_VRX_Max_19_2_5.img') == 'V19.2.5'
    # ExtractVersion misses (no _n_n_n before .img) but the path regex hits.
    assert fw.current_version_label('/f/19.2.5.img') == 'V19.2.5'
    assert fw.current_version_label('/f/blob.bin') == 'V_unRecog'


@pytest.mark.parametrize('device_fw,file_label,rc,verdict', [
    ('Ascent_VRX_Max_19_2_4', 'V19.2.5', 0, 'upgrade'),
    ('Ascent_VRX_Max_19_2_4', 'V19.2.4', 0, 'same_version'),
    ('Ascent_VRX_Max_19_2_5', 'V19.2.4', 1, 'downgrade'),
    ('Ascent_VRX_Max_19_2_4', 'V18.21.8', 1, 'downgrade'),
    ('Ascent_VRX_Max_19_2_4', 'V_unRecog', 9, 'version_unparsed'),
    ('no_version_string', 'V19.2.5', 2, 'device_version_unparsed'),
])
def test_judge_versions(device_fw, file_label, rc, verdict):
    r = fw.judge_versions(device_fw, file_label)
    assert (r['rc'], r['verdict']) == (rc, verdict)
    assert (r['res'] < 0) is (rc == 1)


def test_the_two_vendor_family_prefixes_disagree_on_this_hardware():
    """The tip regex and the gate regex are different, and the difference is real.

    UpdateDeviceInfo uses `(\\d+_\\d+_\\d+)$`, which matches "19_2_4" and yields
    "Ascent_VRX_Max". SelectWrongFWFilePrompt uses `(\\d+\\d+\\d+)$`, which needs
    three consecutive digits at end-of-string, misses, and falls through to
    `Remove(12)` -- a truncation mid-word.
    """
    p = fw.family_prefixes(DEVICE_FW)
    assert p['tip'] == 'Ascent_VRX_Max'
    assert p['check'] == 'Ascent_VRX_M'
    assert p['tip_regex_matched'] is True and p['check_regex_matched'] is False
    # A firmware string that DOES end in three consecutive digits takes the other
    # branch, and the vendor then strips the literal "Ascent".
    p2 = fw.family_prefixes('Ascent_VRX_Max_1928')
    assert p2['check_regex_matched'] is True
    assert 'Ascent' not in p2['check']


# ======================================================================================
# Device-reported status, including anti-rollback
# ======================================================================================
def test_status_code_table_matches_the_vendor_enum():
    # 2.0.51 UpgradeStatusErrorCode. -9 is deliberately absent from the vendor enum.
    assert set(fw.UPGRADE_STATUS_CODES) == {-11, -10, -8, -7, -6, -5, -4, -3, -2, -1,
                                            0, 1, 2, 3, 4, 5}
    assert fw.ANTI_ROLLBACK_STATUS == -6
    assert fw.UPGRADE_STATUS_CODES[-6][0] == 'UPGRATE_ERR_APP_VERSION'
    assert fw.UPGRADE_STATUS_CODES[-6][1] == \
        'Upgrade failed, The firmware version number is too low'


@pytest.mark.parametrize('status,ok', [(-11, False), (-6, False), (-1, False),
                                       (0, True), (2, True), (3, True), (5, True)])
def test_judge_upgrade_status(status, ok):
    parsed = fw.parse_upgrade_status(upgstatus72(10, status))
    assert fw.judge_upgrade_status(parsed)[0] is ok


def test_unknown_status_code_is_not_treated_as_a_failure():
    # JudgeUpgradeStatus's `default:` arm returns true.
    parsed = fw.parse_upgrade_status(upgstatus72(10, -9))
    assert parsed['status_code'] == 'UNKNOWN_STATUS'
    assert fw.judge_upgrade_status(parsed)[0] is True


# ======================================================================================
# Selection validation
# ======================================================================================
def test_validation_passes_a_correctly_named_upgrade(image_file):
    v = fw.validate_selection(image_file, {'firmware': DEVICE_FW,
                                           'device_name': DEVICE_NAME})
    assert v['ok'] is True
    assert v['confirmations_required'] == []
    assert v['file_version_label'] == 'V19.2.5'
    assert v['version_verdict']['verdict'] == 'upgrade'
    assert v['remote_path'] == '/tmp/pc/Ascent_VRX_Max_19_2_5.img'
    ids = {c['id'] for c in v['checks']}
    assert ids == {'file_exists', 'path_length', 'file_dir_truncation',
                   'remote_path_fits', 'filename_matches_device', 'not_a_downgrade',
                   'file_extension', 'image_trailing_md5', 'container_recognised'}


def test_missing_file_is_a_blocking_check():
    v = fw.validate_selection('/definitely/not/here.img', {'firmware': DEVICE_FW})
    assert v['ok'] is False and v['blocking'] == ['file_exists']
    assert v['checks'][0]['vendor_message'] == 'firmware path error'


def test_path_longer_than_200_chars_is_blocked_like_2051(tmp_path):
    deep = tmp_path
    while len(str(deep)) < 200:
        deep = deep / 'directory_segment'
    deep.mkdir(parents=True, exist_ok=True)
    p = deep / 'Ascent_VRX_Max_19_2_5.img'
    p.write_bytes(b'RKFW' + b'\0' * 100)
    v = fw.validate_selection(str(p), {'firmware': DEVICE_FW})
    assert 'path_length' in v['blocking'] and v['ok'] is False
    c = next(c for c in v['checks'] if c['id'] == 'path_length')
    assert c['build_specific'] == '2.0.51 only'


def test_filename_device_mismatch_is_a_confirm_not_a_block(tmp_path):
    p = tmp_path / 'Ascent_G_Sky_19_2_5.img'
    p.write_bytes(b'ASW\0' + b'\0' * 100)
    v = fw.validate_selection(str(p), {'firmware': DEVICE_FW})
    assert v['ok'] is True                       # nothing BLOCKS
    assert 'filename_matches_device' in v['confirmations_required']
    c = next(c for c in v['checks'] if c['id'] == 'filename_matches_device')
    assert c['severity'] == 'confirm' and c['vendor'] is True


def test_downgrade_is_a_confirm_with_the_vendor_wording(tmp_path):
    p = tmp_path / 'Ascent_VRX_Max_18_21_8.img'
    p.write_bytes(b'RKFW' + b'\0' * 100)
    v = fw.validate_selection(str(p), {'firmware': DEVICE_FW})
    assert v['ok'] is True
    assert 'not_a_downgrade' in v['confirmations_required']
    c = next(c for c in v['checks'] if c['id'] == 'not_a_downgrade')
    assert c['vendor_message'] == ('Degrade device is not recommended and usually '
                                   'fails. If you want to try degrade?')


def test_a_corrupt_trailing_digest_is_reported_as_ours_not_vendor(tmp_path):
    body = b'RKFW' + b'\x11' * 2000
    p = tmp_path / 'Ascent_VRX_Max_19_2_5.img'
    p.write_bytes(body + (b'0' * 32))            # a wrong but well-formed digest
    v = fw.validate_selection(str(p), {'firmware': DEVICE_FW})
    c = next(c for c in v['checks'] if c['id'] == 'image_trailing_md5')
    assert c['passed'] is False and c['severity'] == 'confirm'
    assert c['vendor'] is False                  # the stock tool never checks this
    assert 'image_trailing_md5' in v['confirmations_required']
    assert v['ok'] is True                       # and it does not block


def test_asw_image_without_a_trailing_digest_is_informational(tmp_path):
    p = tmp_path / 'Ascent_VRX_Max_19_2_5.img'
    p.write_bytes(b'ASW\0' + b'\x00' * 4096)
    v = fw.validate_selection(str(p), {'firmware': DEVICE_FW})
    c = next(c for c in v['checks'] if c['id'] == 'image_trailing_md5')
    assert c['severity'] == 'info' and c['passed'] is True


def test_inspect_image_reports_the_md5_that_goes_on_the_wire(image_file):
    img = fw.inspect_image(image_file)
    raw = pathlib.Path(image_file).read_bytes()
    assert img['md5'] == hashlib.md5(raw).hexdigest()
    assert img['sha256'] == hashlib.sha256(raw).hexdigest()
    assert img['bytes'] == len(raw)
    assert img['container'] == 'RKFW'
    t = img['trailing_md5']
    assert t['carries_trailing_digest'] and t['matches'] is True
    assert t['declared'] == hashlib.md5(raw[:-32]).hexdigest()


def test_real_vendor_image_digests_fixture():
    """The trailing-MD5 layout was verified against four real vendor images."""
    doc = json.loads((ROOT / 'fixtures' / 'vrx_firmware_images.json').read_text())
    assert doc['schema'] == 'ascent.fixture.vrx_firmware_images.v1'
    assert doc['vendor_file_filter'] == fw.VENDOR_FILE_FILTER
    assert len(doc['images']) >= 6
    for row in doc['images']:
        assert row['container'] in ('RKFW', 'ASW'), row['filename']
        assert row['bytes'] > 0
        assert re.fullmatch(r'[0-9a-f]{32}', row['md5_whole_file'])
        assert re.fullmatch(r'[0-9a-f]{64}', row['sha256'])
    # Every VRX image is RKFW and every one of them verifies its trailing digest.
    vrx = [r for r in doc['images'] if r['container'] == 'RKFW']
    assert len(vrx) >= 4
    for row in vrx:
        assert row['carries_trailing_digest'] is True
        assert re.fullmatch(r'[0-9a-f]{32}', row['trailing_md5_declared'])
        assert row['trailing_md5_declared'] == row['md5_of_body']
        assert row['trailing_digest_verified'] is True
    # The Sky container carries no trailing digest, which is why the check is advisory
    # and not a gate.
    sky = [r for r in doc['images'] if r['container'] == 'ASW']
    assert sky and all(r['carries_trailing_digest'] is False for r in sky)
    assert all(r['trailing_md5_declared'] is None for r in sky)
    # The one image that ships inside a zip is recorded as such: the archive is a
    # distribution wrapper, not something the PC Tool ever opens.
    zipped = [r for r in doc['images'] if r['distributed_in_zip']]
    assert zipped and all(r['filename'].endswith('.img') for r in zipped)


# ======================================================================================
# Full sequence
# ======================================================================================
def test_full_upgrade_sequence_order_and_content(image_file):
    raw = pathlib.Path(image_file).read_bytes()
    dev = FakeDevice(expect_md5=hashlib.md5(raw).hexdigest(), expect_total=len(raw),
                     receive_max_size=4096, firmware_after='Ascent_VRX_Max_19_2_5',
                     status_sequence=[(10, 2), (60, 2), (100, 3)])
    resolver = instant_resolver()
    img = fw.inspect_image(image_file)
    with make_session(dev, resolver=resolver) as s:
        result = fw.run_upgrade(s, img)

    # The exact vendor order, with no extra commands.
    assert [e['command'] for e in dev.log] == [
        60, 3, 114, 115, 116, 116, 116, 117, 118, 118, 118, 60]
    assert dev.bad_crc == 0
    # Exactly one reboot is issued by the host: the "clean" one. The post-flash
    # reboot is the device's own -- the vendor does not send command 3 there.
    assert dev.reboots == 1
    assert dev.clean_mode is True
    # Chunking: ceil(10276 / 4096) = 3 chunks, last one short.
    assert dev.chunk_lengths == [4096, 4096, len(raw) - 8192]
    assert bytes(dev.received) == raw
    # ArFileInfo carried the whole-file MD5, the length and saveAsFile = 1.
    assert dev.declared['md5'] == hashlib.md5(raw).hexdigest()
    assert dev.declared['length'] == len(raw)
    assert dev.declared['save_as_file'] == 1
    assert dev.declared['remote_path'] == '/tmp/pc/Ascent_VRX_Max_19_2_5.img'
    assert dev.declared['file_dir'] == image_file.replace('\\', '/')
    # Two reconnects, in order, each with the additive settle + poll budget.
    assert [c['phase'] for c in resolver.calls] == ['reconnect_clean', 'reconnect_final']
    assert resolver.calls[0]['settle_s'] == fw.RECONNECT_SETTLE
    assert resolver.calls[0]['poll_budget_s'] == fw.RECONNECT_POLL_BUDGET
    # Post-flash version reread -- the vendor's own Send_FindDevice after success.
    assert result['firmware_before'] == DEVICE_FW
    assert result['firmware_after'] == 'Ascent_VRX_Max_19_2_5'
    assert result['firmware_changed'] is True
    assert result['status']['queries'] == 3
    assert [st['stage'] for st in result['stages']] == [
        'FIND_DEVICE', 'REBOOT_CLEAN', 'REMOTE_UPGRADE', 'SENDFILE_START',
        'SENDFILE_DATA', 'SENDFILE_END', 'UPGRADE_STATUS', 'FIND_DEVICE_POST']


def test_single_chunk_when_the_image_fits_one_frame(image_file):
    dev = FakeDevice(receive_max_size=fw.DEFAULT_CHUNK_SIZE)
    img = fw.inspect_image(image_file)
    with make_session(dev) as s:
        fw.run_upgrade(s, img)
    assert dev.chunk_lengths == [img['bytes']]
    assert [e['command'] for e in dev.log].count(116) == 1


def test_progress_reports_cover_every_phase(image_file):
    seen = []
    dev = FakeDevice(receive_max_size=4096)
    img = fw.inspect_image(image_file)
    with make_session(dev, progress=seen.append) as s:
        fw.run_upgrade(s, img)
    phases = [p['phase'] for p in seen]
    for expected in ('find_device', 'reboot_clean', 'reconnect_clean', 'remote_upgrade',
                     'sendfile_start', 'sendfile_data', 'sendfile_end',
                     'upgrade_status', 'reconnect_final', 'verify', 'complete'):
        assert expected in phases, expected
    pcts = [p['percent'] for p in seen if 'percent' in p]
    assert pcts == sorted(pcts), 'reported progress must never go backwards'
    assert pcts[-1] == 1.0
    transfer = [p for p in seen if p['phase'] == 'sendfile_data']
    assert transfer[-1]['bytes_sent'] == img['bytes']
    assert transfer[-1]['chunk_index'] == transfer[-1]['chunk_count']


def test_backup_hook_runs_before_the_first_mutating_command(image_file):
    order = []
    dev = FakeDevice()

    def before(ctx):
        order.append(('backup', [e['command'] for e in dev.log]))
        assert ctx['plan']['chunk_size'] == fw.DEFAULT_CHUNK_SIZE
        assert ctx['identity']['firmware'] == DEVICE_FW
        return {'created': True, 'file': 'firmware_preflash_test.json'}

    img = fw.inspect_image(image_file)
    with make_session(dev) as s:
        result = fw.run_upgrade(s, img, on_before_transfer=before)
    # The identity read has happened; nothing mutating has.
    assert order == [('backup', [60])]
    assert result['backup']['file'] == 'firmware_preflash_test.json'


def test_reconnect_may_land_on_a_different_com_port(image_file):
    """A real, observed case: COM13 -> COM6 across the clean reboot (vendor log)."""
    dev = FakeDevice()
    img = fw.inspect_image(image_file)
    with make_session(dev, port='COM13', resolver=instant_resolver('COM6')) as s:
        fw.run_upgrade(s, img)
        assert s.port == 'COM6'


# ======================================================================================
# Failure paths
# ======================================================================================
def test_anti_rollback_refusal_is_reported_as_such(image_file):
    """The device's own verdict: command 118 Status -6, UPGRATE_ERR_APP_VERSION."""
    dev = FakeDevice(status_sequence=[(0, -6)])
    img = fw.inspect_image(image_file)
    with make_session(dev) as s:
        with pytest.raises(fw.FirmwareUpgradeError) as ei:
            fw.run_upgrade(s, img)
    e = ei.value
    assert e.code == 'FIRMWARE_REJECTED_ANTI_ROLLBACK'
    assert str(e) == 'Upgrade failed, The firmware version number is too low'
    assert e.stage == '118'
    assert e.evidence['device_rejected'] is True
    assert e.evidence['status']['status_code'] == 'UPGRATE_ERR_APP_VERSION'
    # The image did reach the device, and that must be said plainly.
    assert e.evidence['image_was_transferred'] is True
    # It stops on the FIRST negative status -- it does not burn 200 queries.
    assert dev.status_queries == 1


@pytest.mark.parametrize('status,code,message', [
    (-5, 'FIRMWARE_UPGRADE_REJECTED',
     'Upgrade failed, the device model does not match the upgraded firmware'),
    (-4, 'FIRMWARE_UPGRADE_REJECTED', 'Upgrade failed, upgrade file is corrupted'),
    (-8, 'FIRMWARE_UPGRADE_REJECTED', 'Upgrade failed, image type error'),
    (-11, 'FIRMWARE_UPGRADE_REJECTED', 'Upgrade failed, flash error'),
])
def test_other_device_refusals_use_the_vendor_wording(image_file, status, code, message):
    dev = FakeDevice(status_sequence=[(0, status)])
    img = fw.inspect_image(image_file)
    with make_session(dev) as s:
        with pytest.raises(fw.FirmwareUpgradeError) as ei:
            fw.run_upgrade(s, img)
    assert ei.value.code == code and str(ei.value) == message


def test_status_query_limit_is_the_vendor_limit(image_file):
    dev = FakeDevice(status_sequence=[(50, 2)])          # never completes
    img = fw.inspect_image(image_file)
    with make_session(dev) as s:
        with pytest.raises(fw.FirmwareUpgradeError) as ei:
            fw.run_upgrade(s, img)
    assert ei.value.code == 'UPGRADE_STATUS_QUERY_LIMIT'
    assert str(ei.value) == 'Upgrade status query limit exceeded'
    assert dev.status_queries == fw.STATUS_POLL_LIMIT == 200
    assert ei.value.evidence['upgrade_may_have_applied'] is True


def test_sendfile_end_status_gate(image_file):
    """117 is the step whose Status the vendor actually reads."""
    dev = FakeDevice(sendfile_end_status=-1, sendfile_end_detail='CompareMD5 fail!')
    img = fw.inspect_image(image_file)
    with make_session(dev) as s:
        with pytest.raises(fw.FirmwareUpgradeError) as ei:
            fw.run_upgrade(s, img)
    assert ei.value.code == 'SENDFILE_END_REJECTED'
    assert str(ei.value) == 'CompareMD5 fail!'
    assert dev.status_queries == 0


def test_sendfile_end_detail_must_be_OK(image_file):
    # `resFileDataInfo.Status != 0 || text != "OK"` -- both halves.
    dev = FakeDevice(sendfile_end_detail='DONE')
    img = fw.inspect_image(image_file)
    with make_session(dev) as s:
        with pytest.raises(fw.FirmwareUpgradeError) as ei:
            fw.run_upgrade(s, img)
    assert ei.value.code == 'SENDFILE_END_REJECTED' and str(ei.value) == 'DONE'


def test_sendfile_start_refusal_stops_before_any_chunk(image_file):
    dev = FakeDevice(sendfile_start_status=-1)
    img = fw.inspect_image(image_file)
    with make_session(dev) as s:
        with pytest.raises(fw.FirmwareUpgradeError) as ei:
            fw.run_upgrade(s, img)
    assert ei.value.code == 'SENDFILE_START_REJECTED'
    assert [e['command'] for e in dev.log].count(116) == 0
    assert dev.chunk_lengths == []


def test_a_device_that_answers_unknown_cmd_fails_immediately(image_file):
    """A firmware without the lane answers a CRC-valid cmd-0 `unkonwn cmd`."""
    dev = FakeDevice()
    dev.clean_mode = False
    img = fw.inspect_image(image_file)

    def no_op_resolver(previous_port, *, settle_s, poll_budget_s, phase, progress=None):
        # Reconnect "succeeds", but the fake device was never put in clean mode
        # because it refuses to record it.
        dev.clean_mode = False
        return previous_port, {}

    dev_reboot_clean = dev._dispatch

    def dispatch(hdr, payload):
        if hdr.command == fw.CMD_REBOOT:
            dev.reboots += 1
            return dev._reply(hdr, ack68(0, 'OK'))       # acknowledged, never applied
        return dev_reboot_clean(hdr, payload)

    dev._dispatch = dispatch
    with make_session(dev, resolver=no_op_resolver) as s:
        with pytest.raises(fw.FirmwareUpgradeError) as ei:
            fw.run_upgrade(s, img)
    assert ei.value.code == 'VENDOR_COMMAND_REJECTED'
    assert 'unkonwn cmd' in str(ei.value)
    assert ei.value.stage == '114'


def test_ack_timeout_when_the_device_says_nothing(image_file):
    dev = FakeDevice()
    dev._dispatch = lambda hdr, payload: None
    s = fw.FirmwareUpgradeSession('COM10', serial_factory=fake_factory(dev),
                                  port_resolver=instant_resolver(),
                                  sleep=lambda _s: None)
    with s:
        with pytest.raises(fw.FirmwareUpgradeError) as ei:
            # A short timeout keeps the test fast; the guard shape is what matters.
            s._exchange(fw.CMD_FIND_DEVICE, timeout=0.4, retry_interval=0.1, stage='60')
    assert ei.value.code == 'VENDOR_ACK_TIMEOUT'
    # Retries allocate a NEW seq and increment `retry` -- docs/PROTOCOL_SPEC.md s6.
    retries = [e['retry'] for e in dev.log]
    seqs = [e['seq'] for e in dev.log]
    assert len(dev.log) >= 2
    assert retries == list(range(len(retries)))
    assert len(set(seqs)) == len(seqs)


def test_a_reply_with_a_foreign_seq_is_not_accepted():
    """2.0.51 matches on command alone. We also require a seq we actually sent."""
    dev = FakeDevice()
    real = dev._dispatch

    def dispatch(hdr, payload):
        reply = real(hdr, payload)
        if reply and hdr.command == fw.CMD_FIND_DEVICE:
            # Rewrite the seq to something never sent, and fix the CRC so the frame
            # is otherwise perfectly valid.
            h = bytearray(reply[:36])
            # `<IHHHHIHHIIII`: seq is at byte 24, retry 28, crc32 32.
            struct.pack_into('<I', h, 24, 0xDEADBEEF)
            struct.pack_into('<I', h, 32, 0)
            payload_out = reply[36:]
            crc = rb.crc32_vendor(bytes(h), payload_out)
            struct.pack_into('<I', h, 32, crc)
            return bytes(h) + payload_out
        return reply

    dev._dispatch = dispatch
    s = fw.FirmwareUpgradeSession('COM10', serial_factory=fake_factory(dev),
                                  port_resolver=instant_resolver(), sleep=lambda _s: None)
    with s:
        with pytest.raises(fw.FirmwareUpgradeError) as ei:
            s._exchange(fw.CMD_FIND_DEVICE, timeout=0.4, retry_interval=0.1, stage='60')
    assert ei.value.code == 'VENDOR_ACK_TIMEOUT'


def test_reconnect_timeout_uses_the_vendor_message():
    dev = FakeDevice()

    def failing(port):
        raise RuntimeError('port does not exist')

    s = fw.FirmwareUpgradeSession('COM10', serial_factory=failing, sleep=lambda _s: None,
                                  monotonic=iter_clock([0.0, 0.0, 0.05, 0.2, 0.4, 9.0, 9.0]))
    with pytest.raises(fw.FirmwareUpgradeError) as ei:
        s._same_port_resolver('COM10', settle_s=0.0, poll_budget_s=0.3, phase='reconnect_clean')
    assert ei.value.code == 'RECONNECT_TIMEOUT'
    assert str(ei.value) == 'Reconnection timeout'


def iter_clock(values):
    seq = list(values)
    state = {'i': 0}

    def now():
        i = min(state['i'], len(seq) - 1)
        state['i'] += 1
        return seq[i]
    return now


def test_short_transfer_is_detected(image_file):
    dev = FakeDevice(receive_max_size=4096)
    img = fw.inspect_image(image_file)
    plan = fw.plan_transfer(img, fw.resolve_chunk_size(4096))

    class TruncatingStream:
        def __init__(self, path):
            self.f = open(path, 'rb')
            self.n = 0

        def read(self, want):
            self.n += 1
            return b'' if self.n > 1 else self.f.read(want)

        def close(self):
            self.f.close()

    with make_session(dev) as s:
        s.find_device()
        s.reboot_clean()
        s._reconnect('reconnect_clean')
        s.remote_upgrade()
        s.send_file_start(plan)
        with pytest.raises(fw.FirmwareUpgradeError) as ei:
            s.send_file_data(plan, TruncatingStream(image_file))
    assert ei.value.code == 'SHORT_TRANSFER'
    assert ei.value.evidence['bytes_sent'] == 4096


# ======================================================================================
# Timing model
# ======================================================================================
def test_timing_constants_match_the_reference_build():
    t = fw.timing_document()
    # 2.0.51 UsbSerialportFSM DefaultAckRetryIntervalMs / DefaultAckTotalTimeoutMs.
    assert (t['ack_retry_interval_s'], t['ack_total_timeout_s']) == (1.5, 10.0)
    # 2.0.37's values are kept for the record, and are different.
    assert (t['ack_retry_interval_s_2037'], t['ack_total_timeout_s_2037']) == (2.0, 8.0)
    # 2.0.51 SendWithRetryGuardDelay(118, ..., 1000).
    assert t['status_poll_delay_s'] == 1.0 and t['status_poll_delay_s_2037'] == 0.5
    assert t['status_poll_limit'] == 200
    # ascent_vrx_max_wf = 11000 in 2.0.51's ReOpenDelayByDevName_Asce.
    assert t['reconnect_settle_s'] == 11.0
    # CLAUDE.md: a commit may not be hard-failed before 110 s.
    assert t['reconnect_total_budget_s'] >= 110.0
    # 2.0.51 ForceSearchMode == 3 / PortRetryTimeLimit.
    assert t['port_retry_limit'] == 8 and t['port_retry_interval_s'] == 1.0


def test_reconnect_budget_is_additive_and_at_least_110_s():
    assert fw.RECONNECT_TOTAL_BUDGET == fw.RECONNECT_SETTLE + fw.RECONNECT_POLL_BUDGET
    assert fw.RECONNECT_TOTAL_BUDGET >= 110.0


def test_every_divergence_from_the_vendor_is_declared():
    ids = {d['id'] for d in fw.VENDOR_DIVERGENCES}
    assert ids == {'pre_transfer_backup', 'sendfile_start_status_gate',
                   'chunk_size_sanity_bound', 'image_trailing_md5_advisory',
                   'reconnect_budget', 'ack_seq_correlation'}
    for d in fw.VENDOR_DIVERGENCES:
        assert d['ours'] and d['vendor'] and d['why']


def test_the_divergence_table_is_not_in_the_interface():
    """"WHERE THIS DIFFERS FROM THE STOCK TOOL" was four columns -- ID, HERE,
    STOCK TOOL, WHY -- cataloguing every deliberate departure from the vendor's
    tool, rendered under ADVANCED on the firmware page.

    It is a design record, and in an interface it reads as a merit badge: this
    project explaining its own choices to somebody who wants to flash firmware.
    The bench put it plainly -- "it's like a list of merit badges, who cares
    for users" -- and asked for everything of that shape to go.

    NOT deleted. It is in the support bundle with the rest of the provenance,
    which is where a reader who needs it already is.
    """
    import re as _re
    app = (ROOT / "runtime" / "www" / "app.js").read_text(encoding="utf-8")
    # Comments stripped: the note explaining the removal necessarily names the
    # thing removed, and a check that cannot tell a rendered string from a
    # comment about it proves nothing.
    code = _re.sub(r"/\*.*?\*/", "", app, flags=_re.S)
    code = _re.sub(r"^\s*//.*$", "", code, flags=_re.M)
    assert "fwDivergencePanel" not in code
    assert "WHERE THIS DIFFERS FROM THE STOCK TOOL" not in code

    import dev_harness
    assert "firmware_divergences" in dev_harness.support_bundle(), \
        "the record must survive the move out of the UI"



# ======================================================================================
# Qualification
# ======================================================================================
GOOD_CANDIDATE = {
    'serial_com': 'COM10',
    'serial_container_id': '{F200001E-BBBB-CCCC-DDDD-EEEEEEEEEEEE}',
    'serial_pnp_device_id': r'USB\VID_1D77&PID_A4A2\6&1234ABCD&0&2',
}
GOOD_IDENTITY = {'device_name': DEVICE_NAME, 'firmware': DEVICE_FW,
                 'hardware': DEVICE_HW, 'serial_number': DEVICE_SN,
                 'receive_max_size': fw.REQUIRED_RECEIVE_MAX_SIZE}


def test_qualification_accepts_the_bench_device():
    q = fw.qualify_firmware_upgrade(candidate=GOOD_CANDIDATE, identity=GOOD_IDENTITY,
                                    selection={'ok': True})
    assert q['eligible'] is True and q['reasons'] == []
    assert q['operation_id'] == 'firmware_image_upgrade'
    assert q['evidence']['vid'] == '1D77' and q['evidence']['pid'] == 'A4A2'
    assert q['evidence']['receive_max_size_qualified'] is True
    assert q['evidence']['required_receive_max_size'] == 1048576


@pytest.mark.parametrize('declared', [None, 0, 4096, 1075165, 8 * 1024 * 1024])
def test_product_qualification_requires_the_exact_observed_receive_size(declared):
    identity = dict(GOOD_IDENTITY)
    identity['receive_max_size'] = declared
    q = fw.qualify_firmware_upgrade(candidate=GOOD_CANDIDATE, identity=identity,
                                    selection={'ok': True})
    assert q['eligible'] is False
    assert any('receive_max_size' in reason and '1048576' in reason
               for reason in q['reasons'])
    assert q['evidence']['receive_max_size'] == declared
    assert q['evidence']['receive_max_size_qualified'] is False


@pytest.mark.parametrize('mutate,reason_fragment', [
    (lambda c, i: c.pop('serial_container_id'), 'ContainerId'),
    (lambda c, i: c.pop('serial_com'), 'serial COM interface'),
    (lambda c, i: c.__setitem__('serial_pnp_device_id', 'USB\\NOPE'), 'VID/PID'),
    (lambda c, i: i.__setitem__('device_name', 'DJI_O3'), 'not an Ascent upgrade target'),
    (lambda c, i: i.__setitem__('device_name', ''), 'no raw command-60 device name'),
    (lambda c, i: i.__setitem__('firmware', ''), 'no firmware string'),
])
def test_qualification_fails_closed(mutate, reason_fragment):
    c = dict(GOOD_CANDIDATE)
    i = dict(GOOD_IDENTITY)
    mutate(c, i)
    q = fw.qualify_firmware_upgrade(candidate=c, identity=i, selection={'ok': True})
    assert q['eligible'] is False
    assert any(reason_fragment in r for r in q['reasons']), q['reasons']


def test_qualification_requires_a_validated_selection():
    assert fw.qualify_firmware_upgrade(candidate=GOOD_CANDIDATE, identity=GOOD_IDENTITY,
                                       selection=None)['eligible'] is False
    q = fw.qualify_firmware_upgrade(candidate=GOOD_CANDIDATE, identity=GOOD_IDENTITY,
                                    selection={'ok': False})
    assert q['eligible'] is False
    assert any('blocking validation' in r for r in q['reasons'])


def test_vendor_gate_is_recorded_verbatim():
    q = fw.qualify_firmware_upgrade(candidate=GOOD_CANDIDATE, identity=GOOD_IDENTITY,
                                    selection={'ok': True})
    assert 'MainFrm.cs:543' in q['vendor_gate']
    # The vendor's own token list, not a narrowed one.
    assert fw.VENDOR_UPGRADE_NAME_TOKENS == ('ascent', 'yohd', 'new device')


# ======================================================================================
# Backend wiring
# ======================================================================================
def test_backend_exports_the_firmware_lane():
    assert h.FIRMWARE_OPERATION_ID == 'firmware_image_upgrade'
    assert h.caddx_firmware_selftest()['ok'] is True
    assert h.VENDOR_FILE_FILTER == 'firmware (*.img)|*.img|All (*.*)|*.*'


def test_firmware_backup_directory_follows_the_save_root(tmp_path):
    original = h.LOCAL_DATA_ROOT
    try:
        h._apply_local_save_root(tmp_path)
        assert h.FIRMWARE_BACKUPS_DIR == tmp_path / 'Backups' / 'Firmware'
        doc = h.local_save_directory_document()
        assert doc['derived']['firmware_backups'] == str(h.FIRMWARE_BACKUPS_DIR)
    finally:
        h._apply_local_save_root(original)


def test_page_document_is_read_only_and_states_the_two_prefixes(monkeypatch):
    monkeypatch.setitem(h.ACTIVE_CONNECTION, 'serial_identity', dict(GOOD_IDENTITY))
    doc = h.firmware_page_document()
    assert doc['ok'] is True
    assert doc['device']['firmware'] == DEVICE_FW
    assert doc['filename_hint']['tip_prefix'] == 'Ascent_VRX_Max'
    assert doc['filename_hint']['gate_prefix'] == 'Ascent_VRX_M'
    assert doc['filename_hint']['prefixes_agree'] is False
    assert doc['vendor_file_filter'] == fw.VENDOR_FILE_FILTER
    assert doc['timing']['status_poll_limit'] == 200
    assert len(doc['divergences']) == len(fw.VENDOR_DIVERGENCES)


def test_select_refuses_without_a_device_identity(monkeypatch, image_file):
    monkeypatch.setitem(h.ACTIVE_CONNECTION, 'serial_identity', {})
    with pytest.raises(h.FirmwareUpgradeError) as ei:
        h.firmware_select({'path': image_file})
    assert ei.value.code == 'NO_DEVICE_IDENTITY'


def test_select_then_clear(monkeypatch, image_file):
    monkeypatch.setitem(h.ACTIVE_CONNECTION, 'serial_identity', dict(GOOD_IDENTITY))
    try:
        r = h.firmware_select({'path': image_file})
        assert r['ok'] is True
        assert r['selection']['validation']['file_version_label'] == 'V19.2.5'
        assert h.firmware_page_document()['selection']['path'] == image_file
        r2 = h.firmware_select({'clear': True})
        assert r2['cleared'] is True
        assert h.firmware_page_document()['selection'] is None
    finally:
        h.SELECTED_FIRMWARE.clear()


def test_select_reports_a_missing_file_with_the_vendor_message(monkeypatch):
    monkeypatch.setitem(h.ACTIVE_CONNECTION, 'serial_identity', dict(GOOD_IDENTITY))
    with pytest.raises(h.FirmwareUpgradeError) as ei:
        h.firmware_select({'path': '/nope/x.img'})
    assert ei.value.code == 'FIRMWARE_PATH_ERROR'
    assert str(ei.value) == 'firmware path error'


def test_upgrade_requires_apply_and_the_selection_digest(monkeypatch, image_file):
    monkeypatch.setitem(h.ACTIVE_CONNECTION, 'serial_identity', dict(GOOD_IDENTITY))
    try:
        with pytest.raises(h.FirmwareUpgradeError) as ei:
            h._upgrade_firmware_locked({})
        assert ei.value.code == 'APPLY_REQUIRED'
        with pytest.raises(h.FirmwareUpgradeError) as ei:
            h._upgrade_firmware_locked({'apply': True})
        assert ei.value.code == 'NO_FIRMWARE_SELECTED'
        h.firmware_select({'path': image_file})
        with pytest.raises(h.FirmwareUpgradeError) as ei:
            h._upgrade_firmware_locked({'apply': True})
        assert ei.value.code == 'EXPECTED_IMAGE_SHA256_REQUIRED'
        sha = h.SELECTED_FIRMWARE['image']['sha256']
        with pytest.raises(h.FirmwareUpgradeError) as ei:
            h._upgrade_firmware_locked({'apply': True, 'expected_image_sha256': sha})
        # No active qualified device in this offline test.
        assert ei.value.code == 'NO_ACTIVE_QUALIFIED_DEVICE'
    finally:
        h.SELECTED_FIRMWARE.clear()


def test_upgrade_refuses_an_image_that_changed_after_validation(monkeypatch, tmp_path):
    monkeypatch.setitem(h.ACTIVE_CONNECTION, 'serial_identity', dict(GOOD_IDENTITY))
    monkeypatch.setitem(h.ACTIVE_CONNECTION, 'candidate', dict(GOOD_CANDIDATE))
    p = tmp_path / 'Ascent_VRX_Max_19_2_5.img'
    body = b'RKFW' + b'\x22' * 1000
    p.write_bytes(body + hashlib.md5(body).hexdigest().encode())
    try:
        h.firmware_select({'path': str(p)})
        stale = h.SELECTED_FIRMWARE['image']['sha256']
        p.write_bytes(b'RKFW' + b'\x33' * 1000 + b'0' * 32)
        with pytest.raises(h.FirmwareUpgradeError) as ei:
            h._upgrade_firmware_locked({'apply': True, 'expected_image_sha256': stale})
        assert ei.value.code == 'IMAGE_CHANGED_SINCE_SELECTION'
    finally:
        h.SELECTED_FIRMWARE.clear()


def test_upgrade_requires_each_vendor_prompt_to_be_acknowledged(monkeypatch, tmp_path):
    """A downgrade must be accepted by name, not merely allowed to proceed."""
    monkeypatch.setitem(h.ACTIVE_CONNECTION, 'serial_identity', dict(GOOD_IDENTITY))
    monkeypatch.setitem(h.ACTIVE_CONNECTION, 'candidate', dict(GOOD_CANDIDATE))
    p = tmp_path / 'Ascent_VRX_Max_18_21_8.img'
    body = b'RKFW' + b'\x44' * 1000
    p.write_bytes(body + hashlib.md5(body).hexdigest().encode())
    try:
        h.firmware_select({'path': str(p)})
        sha = h.SELECTED_FIRMWARE['image']['sha256']
        with pytest.raises(h.FirmwareUpgradeError) as ei:
            h._upgrade_firmware_locked({'apply': True, 'expected_image_sha256': sha})
        assert ei.value.code == 'CONFIRMATION_REQUIRED'
        assert ei.value.evidence['outstanding'] == ['not_a_downgrade']
    finally:
        h.SELECTED_FIRMWARE.clear()


def test_fresh_command_60_receive_size_refuses_before_device_mutation(
        monkeypatch, image_file):
    """The cached page can be qualified, but the final live command 60 is authority."""
    monkeypatch.setitem(h.ACTIVE_CONNECTION, 'serial_identity', dict(GOOD_IDENTITY))
    monkeypatch.setitem(h.ACTIVE_CONNECTION, 'candidate', dict(GOOD_CANDIDATE))
    dev = FakeDevice(receive_max_size=4096)
    monkeypatch.setattr(
        h, 'FirmwareUpgradeSession',
        lambda port, port_resolver, progress: fw.FirmwareUpgradeSession(
            port, serial_factory=fake_factory(dev), port_resolver=instant_resolver(),
            progress=progress, sleep=lambda _s: None))
    try:
        h.firmware_select({'path': image_file})
        sha = h.SELECTED_FIRMWARE['image']['sha256']
        with pytest.raises(h.FirmwareUpgradeError) as ei:
            h._upgrade_firmware_locked({'apply': True,
                                        'expected_image_sha256': sha})
        assert ei.value.code == 'FIRMWARE_RECEIVE_MAX_SIZE_UNSAFE'
        assert ei.value.stage == 'qualification'
        assert ei.value.evidence['fresh_command'] == 60
        assert ei.value.evidence['declared_receive_max_size'] == 4096
        assert [entry['command'] for entry in dev.log] == [60]
        assert dev.reboots == 0 and dev.clean_mode is False
    finally:
        h.SELECTED_FIRMWARE.clear()


def test_preflash_backup_is_a_state_backup_and_says_so(monkeypatch, tmp_path, image_file):
    monkeypatch.setitem(h.ACTIVE_CONNECTION, 'serial_identity', dict(GOOD_IDENTITY))
    monkeypatch.setitem(h.ACTIVE_CONNECTION, 'rf_bands', {
        'available': True, 'state': 'ok',
        'data': {'RFBoardType': 160, 'bandA': [4495000]},
        'integrity': {'verified': True, 'actual_md5': 'f' * 32},
        'captured_at': '2026-09-07T00:00:00Z'})
    original = h.LOCAL_DATA_ROOT
    try:
        h._apply_local_save_root(tmp_path)
        h.firmware_select({'path': image_file})
        sel = dict(h.SELECTED_FIRMWARE)
        plan = fw.plan_transfer(sel['image'], fw.resolve_chunk_size(None)).document()
        b = h._save_firmware_prelight_backup(dict(GOOD_IDENTITY), plan, sel)
        assert b['created'] is True and b['is_image_backup'] is False
        assert b['rf_band_table_included'] is True
        doc = json.loads((h.FIRMWARE_BACKUPS_DIR / b['file']).read_text())
        assert doc['schema'] == 'ascent.firmware_preflash_backup.v1'
        assert doc['is_image_backup'] is False
        assert 'cannot be read back' in doc['note']
        assert doc['identity']['firmware'] == DEVICE_FW
        assert doc['rf_band_table']['data']['RFBoardType'] == 160
        assert doc['selected_image']['md5'] == sel['image']['md5']
        # A second call in the same second must not overwrite the first.
        b2 = h._save_firmware_prelight_backup(dict(GOOD_IDENTITY), plan, sel)
        assert b2['file'] != b['file']
        assert (h.FIRMWARE_BACKUPS_DIR / b['file']).exists()
    finally:
        h.SELECTED_FIRMWARE.clear()
        h._apply_local_save_root(original)
        h.ACTIVE_CONNECTION.pop('rf_bands', None)


def test_preflash_backup_records_a_missing_rf_table_rather_than_faking_one(
        monkeypatch, tmp_path, image_file):
    monkeypatch.setitem(h.ACTIVE_CONNECTION, 'serial_identity', dict(GOOD_IDENTITY))
    monkeypatch.setitem(h.ACTIVE_CONNECTION, 'rf_bands',
                        {'available': False, 'state': 'unsupported_by_device_firmware',
                         'error_code': 'GET_BB_FREQ_UNSUPPORTED'})
    original = h.LOCAL_DATA_ROOT
    try:
        h._apply_local_save_root(tmp_path)
        h.firmware_select({'path': image_file})
        sel = dict(h.SELECTED_FIRMWARE)
        plan = fw.plan_transfer(sel['image'], fw.resolve_chunk_size(None)).document()
        b = h._save_firmware_prelight_backup(dict(GOOD_IDENTITY), plan, sel)
        assert b['rf_band_table_included'] is False
        assert b['rf_band_table_unavailable'] == 'GET_BB_FREQ_UNSUPPORTED'
        doc = json.loads((h.FIRMWARE_BACKUPS_DIR / b['file']).read_text())
        assert doc['rf_band_table'] is None
    finally:
        h.SELECTED_FIRMWARE.clear()
        h._apply_local_save_root(original)
        h.ACTIVE_CONNECTION.pop('rf_bands', None)


def test_browse_is_refused_off_windows(monkeypatch):
    monkeypatch.setattr(h.platform, 'system', lambda: 'Linux')
    with pytest.raises(h.FirmwareUpgradeError) as ei:
        h.firmware_browse()
    assert ei.value.code == 'BROWSE_UNSUPPORTED'


def test_browse_powershell_uses_the_vendor_dialog_settings():
    """The firmware lane is a parity surface and must keep the vendor's exact
    dialog (AscentUpdataFrm.cs:536-542).

    The title and filter are placeholders in the template now, because the variant
    builder reuses the same dialog with its own wording. So this asserts the
    RESOLVED script -- the template with the defaults substituted, which is exactly
    what the firmware lane runs -- rather than the template. That is stricter than
    before: it would catch a default being changed as well as the template being
    changed.
    """
    ps = (h._FIRMWARE_BROWSE_PS
          .replace('__TITLE__', h._VENDOR_BROWSE_TITLE)
          .replace('__FILTER__', h._VENDOR_BROWSE_FILTER))
    assert 'OpenFileDialog' in ps
    assert "$d.Filter = 'firmware (*.img)|*.img|All (*.*)|*.*'" in ps
    assert '$d.FilterIndex = 1' in ps
    assert '$d.Multiselect = $false' in ps
    assert '$d.RestoreDirectory = $true' in ps
    assert "$d.Title = 'Open'" in ps


def test_serial_write_timeout_is_parametrised_without_changing_the_read_path():
    import inspect
    src = inspect.getsource(rb.WinSerial.__init__)
    assert 'write_timeout_ms=3000' in src, 'the read path default must not change'
    # The firmware lane asks for an unbounded write, like 2.0.51's WriteTimeout = -1.
    factory_src = inspect.getsource(fw.default_serial_factory)
    assert 'write_timeout_ms=0' in factory_src


# ======================================================================================
# Locked UI
# ======================================================================================
def test_locked_ui_digests_still_match():
    import locked_ui
    locked_ui.assert_locked(lambda got, want, msg: _assert_equal(got, want, msg))


def _assert_equal(got, want, msg):
    assert got == want, msg


def test_firmware_page_is_no_longer_inspection_only():
    js = (ROOT / 'runtime' / 'www' / 'app.js').read_text(encoding='utf-8')
    assert 'INSPECTION ONLY' not in js
    assert 'FLASHING HARD DISABLED' not in js
    assert 'inspectFirmware' not in js
    for needed in ('/api/firmware/select', '/api/firmware/upgrade',
                   '/api/firmware/browse', 'fwProgressPanel', 'fwResultPanel',
                   'fwErrorPanel', 'FIRMWARE_REJECTED_ANTI_ROLLBACK'):
        assert needed in js, needed


def test_r2_visual_repin_preserves_the_firmware_page_contract():
    """R2 intentionally re-pins the shell while retaining the firmware controls."""
    import locked_ui
    assert locked_ui.digest('index.html') == locked_ui.LOCKED['index.html']
    assert locked_ui.digest('app.css') == locked_ui.LOCKED['app.css']
    # The firmware-lane app.js pin remains recorded and byte-identical.
    assert any(name == 'app.js' and h ==
               '998d5ba99b88c2eb2e3afc1cd4db4172bfaae81b371e06a590ef3250abdc7e97'
               for name, h in locked_ui.PREVIOUS_PINS)
    css = (ROOT / 'runtime' / 'www' / 'app.css').read_text(encoding='utf-8')
    for hook in ('.panel{', '.kv{', '.toolbar{', '.action,', '.secondary',
                 '.text-input{', '.notice{', 'table{'):
        assert hook in css, hook
