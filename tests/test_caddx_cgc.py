"""CGC v0.3.5 control plane, against the real assembly.

Oracle: `CaddxGroundConfiguration.dll` `d42ff30c…` from the 0.3.5 nupkg. NOT the
0.3.3 tree in `Downloads\\CGC\\` -- handoff §6 forbids promoting 0.3.3 to 0.3.5 and
they are different binaries.
"""
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'runtime'))
import caddx_cgc as cgc


def hexs(b):
    return b.hex(' ').upper()


# --------------------------------------------------------------------------- #
# Framing
# --------------------------------------------------------------------------- #

def test_the_pair_frame_reproduces_byte_for_byte():
    """Handoff §8.8's frame, rebuilt from the decompiled BuildFrame/CalcChecksum."""
    assert hexs(cgc.build_key('PAIRING')) == 'FE EF 22 00 04 40 05 00 00 00 45 0D 0A'


def test_checksum_is_an_additive_sum_of_payload_bytes_only():
    """`CalcChecksum` is a `+=` loop over `data`. Not XOR, and it excludes the header."""
    assert cgc.checksum(b'\x40\x05\x00\x00') == 0x45
    assert cgc.checksum(b'') == 0
    assert cgc.checksum(b'\xFF\xFF') == 0x01FE
    # ushort wraparound
    assert cgc.checksum(b'\xFF' * 300) == (255 * 300) & 0xFFFF


def test_frame_layout():
    f = cgc.build_frame(0x22, b'\x01\x02')
    assert f[0:2] == b'\xFE\xEF'
    assert f[2] == 0x22
    assert f[3:5] == b'\x00\x02'          # BE16 length
    assert f[5:7] == b'\x01\x02'
    assert f[7:9] == b'\x00\x03'          # BE16 sum
    assert f[9:11] == b'\x0D\x0A'


@pytest.mark.parametrize('name,expect', [
    ('UP',           'FE EF 22 00 04 40 00 00 00 00 40 0D 0A'),
    ('CONFIRM',      'FE EF 22 00 04 40 04 00 00 00 44 0D 0A'),
    ('UPGRADE',      'FE EF 22 00 04 40 05 01 00 00 46 0D 0A'),
    ('BACK',         'FE EF 22 00 04 40 07 00 00 00 47 0D 0A'),
    ('FORCE_720P60', 'FE EF 22 00 04 40 07 01 00 00 48 0D 0A'),
    ('DEBUG3',       'FE EF 22 00 04 40 09 00 00 00 49 0D 0A'),
])
def test_remote_key_frames(name, expect):
    assert hexs(cgc.build_key(name)) == expect


def test_upgrade_and_force720_are_long_press_variants_not_keys():
    """`BuildKeyUpgrade` is BuildKeyFrame(Pairing, 1); Force720p60 is (Back, 1).

    Treating either as a key of its own would put a wrong byte on the wire.
    """
    assert cgc.REMOTE_KEYS['UPGRADE'] == (cgc.Key.PAIRING, 1)
    assert cgc.REMOTE_KEYS['FORCE_720P60'] == (cgc.Key.BACK, 1)
    assert cgc.REMOTE_KEYS['PAIRING'][1] == 0
    assert cgc.REMOTE_KEYS['BACK'][1] == 0


def test_there_are_exactly_eleven_key_builders():
    assert len(cgc.REMOTE_KEYS) == 11
    assert cgc.Key.INVALID == 8
    assert not any(k == cgc.Key.INVALID for k, _ in cgc.REMOTE_KEYS.values())


def test_four_keys_are_proven_unreachable_in_stock():
    """§8.9's reachability question, answered: none of the four is reachable.

    The only path to a key frame is SendRemoteCommand -> VrxCommandPacketFactory,
    and VrxRemoteCommand has exactly seven members. BuildKeyPairing, BuildKeyUpgrade,
    BuildKeyForce720p60 and BuildKeyDebug3 have zero call sites in the assembly.
    Sending them is therefore beyond stock, not parity with it.
    """
    assert cgc.REMOTE_KEYS_UNREACHABLE_IN_STOCK == {
        'PAIRING', 'UPGRADE', 'FORCE_720P60', 'DEBUG3'}
    assert len(cgc.REMOTE_KEYS_STOCK) == 7
    assert set(cgc.REMOTE_KEYS_STOCK).isdisjoint(cgc.REMOTE_KEYS_UNREACHABLE_IN_STOCK)
    assert set(cgc.REMOTE_KEYS_STOCK) | cgc.REMOTE_KEYS_UNREACHABLE_IN_STOCK == set(cgc.REMOTE_KEYS)


def test_stock_keyboard_bindings_match_RemoteCommandMapper():
    """TryMapKey accepts arrows and WASD, Return, Back and R -- eleven bindings
    onto seven commands."""
    assert cgc.STOCK_KEYBOARD['w'] == 'UP' and cgc.STOCK_KEYBOARD['ArrowUp'] == 'UP'
    assert cgc.STOCK_KEYBOARD['Enter'] == 'CONFIRM'
    assert cgc.STOCK_KEYBOARD['Backspace'] == 'BACK'
    assert cgc.STOCK_KEYBOARD['r'] == 'RECORDING'
    assert set(cgc.STOCK_KEYBOARD.values()) == set(cgc.REMOTE_KEYS_STOCK)


# --------------------------------------------------------------------------- #
# Wireless family
# --------------------------------------------------------------------------- #

def test_the_enum_has_exactly_five_members_and_no_0x55_to_0x57():
    assert [int(w) for w in cgc.Wireless] == [0x50, 0x51, 0x52, 0x53, 0x54]
    assert 0x57 not in {int(w) for w in cgc.Wireless}
    # Known to stock Ground firmware but not to CGC; recognised, never sent.
    assert set(cgc.GROUND_ONLY_OPCODES) == {0x55, 0x56, 0x57}


def test_read_requests_are_direction_a2_with_an_eight_byte_payload():
    f = cgc.build_get(cgc.Wireless.GET_BB_PWR)
    assert hexs(f) == 'FE EF A2 00 08 53 00 00 00 00 00 00 00 00 53 0D 0A'


def test_set_channel_hop_carries_band_channel_and_hop_together():
    """0x50 is SET_CHANNEL_HOP, not a bare frequency -- the payload proves it."""
    f = cgc.build_set_channel_hop(cgc.Band.B, 4, cgc.Hop.HOPPING)
    assert hexs(f) == 'FE EF 22 00 08 50 01 04 01 00 00 00 00 00 56 0D 0A'


@pytest.mark.parametrize('channel', [17, 255, -1])
def test_channel_bound_is_the_vendor_guard(channel):
    """BuildSetFrequency: `if (channel > 16) throw` -- 信道范围 0~16."""
    with pytest.raises(cgc.CgcError) as e:
        cgc.build_set_channel_hop(cgc.Band.A, channel, cgc.Hop.FIXED)
    assert e.value.code == 'CGC_CHANNEL_OUT_OF_RANGE'


def test_channel_16_is_accepted():
    assert cgc.build_set_channel_hop(cgc.Band.A, 16, cgc.Hop.FIXED)


@pytest.mark.parametrize('index', [20, 255, -1])
def test_power_index_bound_is_the_vendor_guard(index):
    """BuildSetPowerIndex: `if (powerIndex > 19) throw` -- 功率索引范围 0~19."""
    with pytest.raises(cgc.CgcError) as e:
        cgc.build_set_power_index(index)
    assert e.value.code == 'CGC_POWER_INDEX_OUT_OF_RANGE'


def test_power_index_19_is_accepted():
    assert hexs(cgc.build_set_power_index(19)).startswith('FE EF 22 00 08 54 13')


# --------------------------------------------------------------------------- #
# Passthrough mode
# --------------------------------------------------------------------------- #

def test_mode_switch_is_0x23_with_subcommand_2():
    """CMD_PASSTHROUGH = 35 (0x23), SUB_CMD_SET_MODE = 2, payload [2, mode, 0,0,0]."""
    assert hexs(cgc.build_set_mode(cgc.Passthrough.CRSF)) == \
        'FE EF 23 00 05 02 02 00 00 00 00 04 0D 0A'
    assert hexs(cgc.build_set_mode(cgc.Passthrough.OSD)) == \
        'FE EF 23 00 05 02 05 00 00 00 00 07 0D 0A'


def test_the_handoff_mode_numbers_are_right_and_the_enum_is_wider():
    """§8.5 gives CRSF=2 and OSD=5. Both correct; SBUS=3 and USER=4 were unrecorded."""
    assert cgc.Passthrough.CRSF == 2 and cgc.Passthrough.OSD == 5
    assert cgc.Passthrough.NONE == 0 and cgc.Passthrough.MAVLINK == 1
    assert cgc.Passthrough.SBUS == 3 and cgc.Passthrough.USER == 4


def test_passthrough_must_not_be_confused_with_the_uart_enum():
    """CGC application mode 2 is CRSF; the MAX physical-UART mode 2 is BYPASS.

    They collide numerically and mean different things (CLAUDE.md, Ground (UDP)).
    Pinned as a documentation property: this module defines only the CGC one.
    """
    src = (ROOT / 'runtime' / 'caddx_cgc.py').read_text()
    assert 'Do not merge this with the MAX' in src
    assert not hasattr(cgc, 'UartMode')


# --------------------------------------------------------------------------- #
# Parsing and decoding
# --------------------------------------------------------------------------- #

def test_round_trip():
    for frame in (cgc.build_key('UP'), cgc.build_get(cgc.Wireless.GET_STATUS),
                  cgc.build_set_mode(cgc.Passthrough.OSD),
                  cgc.build_set_channel_hop(cgc.Band.D, 9, cgc.Hop.FIXED)):
        assert cgc.parse_frame(frame)['payload'] == frame[5:-4]


@pytest.mark.parametrize('mutate,code', [
    # An extra byte before the tail: header and tail both still valid, so this is
    # the case that actually reaches the length check. Truncating cannot reach it --
    # the vendor's order is min-length, header, tail, length, checksum, so a short
    # frame always trips an earlier guard.
    (lambda f: f[:-2] + b'\x00' + f[-2:],          'CGC_LENGTH_MISMATCH'),
    (lambda f: b'\x00\x00' + f[2:],                'CGC_BAD_HEADER'),
    (lambda f: f[:-2] + b'\x00\x00',               'CGC_BAD_TAIL'),
    (lambda f: f[:3] + b'\x00\x7F' + f[5:],        'CGC_LENGTH_MISMATCH'),
    (lambda f: f[:-4] + b'\xFF\xFF' + f[-2:],      'CGC_CHECKSUM_MISMATCH'),
    (lambda f: b'\xFE\xEF',                        'CGC_FRAME_TOO_SHORT'),
])
def test_parse_refuses_malformed_frames_with_a_named_reason(mutate, code):
    """The vendor returns null for all of these and logs one undifferentiated line."""
    good = cgc.build_key('UP')
    with pytest.raises(cgc.CgcError) as e:
        cgc.parse_frame(mutate(good))
    assert e.value.code == code


def test_decode_channel_hop():
    """Updated 2026-10-04: hop_label is the GOGGLES' word now, not our enum
    member name, and 19.2.14 has three states rather than two."""
    reply = cgc.build_frame(cgc.DIR_READ, bytes([0x51, 2, 7, 1]))
    d = cgc.decode_channel_hop(cgc.parse_frame(reply))
    assert d == {'band': 2, 'band_label': 'C', 'channel': 7, 'hop': 1,
                 'hop_label': 'Intra-band', 'hop_label_proven': False}


def test_decode_channel_hop_handles_the_second_hop_mode():
    reply = cgc.build_frame(cgc.DIR_READ, bytes([0x51, 1, 3, 2]))
    d = cgc.decode_channel_hop(cgc.parse_frame(reply))
    assert d['hop'] == 2 and d['hop_label'] == 'Inter-band'


def test_decode_channel_hop_names_nothing_it_does_not_recognise():
    reply = cgc.build_frame(cgc.DIR_READ, bytes([0x51, 1, 3, 9]))
    d = cgc.decode_channel_hop(cgc.parse_frame(reply))
    assert d['hop'] == 9 and d['hop_label'] is None


def test_decode_status_keeps_the_byte_the_vendor_skips():
    """ParseWirelessStatus reads [1],[2],[4],[5],[6] and never [3].

    Rather than guess what [3] is, it is returned raw so a bench capture settles it.
    """
    reply = cgc.build_frame(cgc.DIR_READ, bytes([0x52, 40, 38, 99, 12, 5, 1]))
    d = cgc.decode_status(cgc.parse_frame(reply))
    assert d['rssi1'] == 40 and d['rssi2'] == 38
    assert d['unknown_byte3'] == 99
    assert d['data_rate_mbps'] == 12 and d['delay_ms'] == 5
    assert d['connected'] is True


def test_decode_power_index_expands_the_settable_bitmask():
    """Bytes [2..5] are a little-endian uint32 of acceptable indexes."""
    mask = (1 << 0) | (1 << 8) | (1 << 19)
    reply = cgc.build_frame(cgc.DIR_READ,
                            bytes([0x53, 8]) + mask.to_bytes(4, 'little'))
    d = cgc.decode_power_index(cgc.parse_frame(reply))
    assert d['current_index'] == 8
    assert d['current_label'] == '1000mW'
    assert d['settable_indexes'] == [0, 8, 19]
    assert d['settable_out_of_range'] == []


def test_settable_bits_above_19_are_reported_not_dropped():
    """The vendor loops all 32 bits though only 0..19 are meaningful."""
    mask = (1 << 3) | (1 << 25)
    reply = cgc.build_frame(cgc.DIR_READ,
                            bytes([0x53, 3]) + mask.to_bytes(4, 'little'))
    d = cgc.decode_power_index(cgc.parse_frame(reply))
    assert d['settable_indexes'] == [3]
    assert d['settable_out_of_range'] == [25]


def test_decoders_enforce_the_vendor_minimum_lengths():
    """AssertCmdType requires len(DataContent) >= minDataLen + 1."""
    short = cgc.build_frame(cgc.DIR_READ, bytes([0x52, 1, 2]))
    with pytest.raises(cgc.CgcError) as e:
        cgc.decode_status(cgc.parse_frame(short))
    assert e.value.code == 'CGC_PAYLOAD_TOO_SHORT'


def test_decoder_rejects_a_mismatched_command():
    reply = cgc.build_frame(cgc.DIR_READ, bytes([0x51, 0, 0, 0]))
    with pytest.raises(cgc.CgcError) as e:
        cgc.decode_power_index(cgc.parse_frame(reply))
    assert e.value.code == 'CGC_CMD_TYPE_MISMATCH'


def test_decode_is_forgiving_and_returns_none_for_unknown_commands():
    frame = cgc.parse_frame(cgc.build_frame(cgc.DIR_READ, bytes([0x57, 1, 2, 3])))
    assert cgc.decode(frame) is None          # 0x57 is Ground-only, not in CGC's enum


# --------------------------------------------------------------------------- #
# Power table
# --------------------------------------------------------------------------- #

def test_power_table_is_the_vendor_table_verbatim():
    assert len(cgc.POWER_TABLE) == 20
    assert cgc.POWER_TABLE[0] == '25mW'
    assert cgc.POWER_TABLE[12] == '4000mW'
    assert cgc.POWER_TABLE[18] == '5000mW'
    assert cgc.POWER_TABLE[19] == '5000mW AUTO'


def test_six_entries_are_auto_so_the_index_is_not_just_a_level():
    """13,14,15,16,17,19 repeat a milliwatt figure with adaptive behaviour.

    The map is therefore not injective: index -> mW loses information, which is why
    the index must not be rendered as a power figure.
    """
    assert cgc.POWER_AUTO_INDEXES == {13, 14, 15, 16, 17, 19}
    assert all('AUTO' in cgc.POWER_TABLE[i] for i in cgc.POWER_AUTO_INDEXES)
    # The same declared milliwatts appear under two different indexes.
    assert cgc.power_entry(8)['milliwatts_declared'] == 1000
    assert cgc.power_entry(13)['milliwatts_declared'] == 1000
    assert cgc.power_entry(13)['auto'] is True and cgc.power_entry(8)['auto'] is False


def test_the_index_is_never_presented_as_dbm():
    """Five-concept power discipline: this is a logical power request only."""
    entry = cgc.power_entry(12)
    assert 'dbm' not in {k.lower() for k in entry}
    src = (ROOT / 'runtime' / 'caddx_cgc.py').read_text()
    assert 'Do not map' in src and '0x2649e8' in src


def test_unknown_index_is_labelled_not_guessed():
    assert cgc.power_label(99) == 'Unknown(99)'


# --------------------------------------------------------------------------- #
# Endpoints
# --------------------------------------------------------------------------- #

def test_profile_catalog_matches_the_vendor_catalog():
    """DeviceConnectionProfileCatalog: two profiles, RJ45 index 0 and USB-C index 1."""
    assert cgc.PROFILES['rj45']['device_ip'] == '192.168.1.100'
    assert cgc.PROFILES['usbc']['device_ip'] == '192.168.3.102'
    for p in cgc.PROFILES.values():
        assert (p['ctrl_port'], p['crsf_port'], p['osd_port']) == (9001, 9100, 9200)
    assert cgc.PROFILES['rj45']['rtsp_url'] == 'rtsp://192.168.1.100/live.ch01'
    assert cgc.PROFILES['usbc']['rtsp_url'] == 'rtsp://192.168.3.102/live.ch01'


def test_selftest_passes():
    assert cgc.selftest()['ok'] is True
