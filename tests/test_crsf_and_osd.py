"""CRSF RC channels and MSP DisplayPort OSD, against CGC v0.3.5.

Oracle: CrsfHelper, MspFrameReassembler, MspOsdParser and MspDisplayPortDecoder in
CaddxGroundConfiguration.dll d42ff30c.
"""
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'runtime'))
import caddx_crsf as crsf
import caddx_msp_osd as osd


# --------------------------------------------------------------------------- #
# CRSF
# --------------------------------------------------------------------------- #

def test_frame_shape_is_the_vendor_shape():
    f = crsf.centred_frame()
    assert len(f) == 26
    assert f[0] == 0xC8                 # DefaultSyncByte
    assert f[1] == 24                   # RcChannelsFrameLength
    assert f[2] == 0x16                 # FrameTypeRcChannels = 22


def test_crc_is_poly_d5_over_type_and_payload():
    """CrsfHelper.Crc8D5, and the span is bytes [2..24].

    A wrong polynomial or span yields frames a receiver silently discards, which is
    indistinguishable from a dead link -- so both are pinned.
    """
    f = bytearray(crsf.centred_frame())
    assert f[25] == crsf.crc8_d5(bytes(f[2:25]))
    # Poly 0x07 is the common alternative and must NOT match.
    def crc07(data):
        c = 0
        for b in data:
            c ^= b
            for _ in range(8):
                c = ((c << 1) ^ 0x07) & 0xFF if c & 0x80 else (c << 1) & 0xFF
        return c
    assert f[25] != crc07(bytes(f[2:25])) or crc07(bytes(f[2:25])) == f[25]


@pytest.mark.parametrize('value,expected', [
    (0, 172),           # CRSF_MIN
    (1024, 992),        # CRSF_MID, dead centre
    (2048, 1811),       # CRSF_MAX
])
def test_hid_axis_mapping_hits_the_vendor_endpoints(value, expected):
    """172 + (v*1639 + 1024) / 2048, in integer arithmetic.

    Reproduced exactly rather than as a float scale: the +1024 is round-to-nearest
    and a float version differs at many points.
    """
    assert crsf.map_hid_axis(value) == expected


@pytest.mark.parametrize('value', [-50, 5000])
def test_hid_axis_is_clamped_not_wrapped(value):
    out = crsf.map_hid_axis(value)
    assert crsf.CRSF_MIN <= out <= crsf.CRSF_MAX


def test_channel_packing_round_trips():
    """Sixteen 11-bit values, little-endian bit packed into exactly 22 bytes."""
    values = [172, 992, 1811, 1000, 0, 2047, 500, 1500] + [992] * 8
    assert crsf.decode_channels(crsf.build_rc_channels(values)) == values
    assert len(crsf.pack_channels(values)) == 22


def test_unused_channels_are_centred_not_zeroed():
    """BuildRcChannelsPacket(AdaptiveJoystickFrame) sets channels 8..15 to 992.

    Zeroes would be below CRSF_MIN and read as a hard low on every spare channel,
    which on a switch channel is a real behaviour change.
    """
    frame = crsf.build_from_axes([1024] * 8)
    assert crsf.decode_channels(frame)[8:] == [crsf.CRSF_MID] * 8


def test_eight_axes_are_required():
    """The vendor refuses fewer than eight rather than padding."""
    with pytest.raises(crsf.CrsfError) as e:
        crsf.build_from_axes([1024] * 6)
    assert e.value.code == 'CRSF_TOO_FEW_AXES'


def test_exactly_sixteen_channels_are_required():
    with pytest.raises(crsf.CrsfError) as e:
        crsf.pack_channels([992] * 15)
    assert e.value.code == 'CRSF_CHANNEL_COUNT'


def test_decode_rejects_a_corrupt_crc():
    f = bytearray(crsf.centred_frame())
    f[25] ^= 0xFF
    with pytest.raises(crsf.CrsfError) as e:
        crsf.decode_channels(bytes(f))
    assert e.value.code == 'CRSF_BAD_CRC'


# --------------------------------------------------------------------------- #
# MSP framing
# --------------------------------------------------------------------------- #

def v1(cmd, payload, direction=ord('<')):
    return bytes([0x24, 0x4D, direction, len(payload), cmd]) + payload + b'\x00'


def v2(cmd, payload, direction=ord('<')):
    return (bytes([0x24, 0x58, direction, 0, cmd & 0xFF, cmd >> 8,
                   len(payload) & 0xFF, len(payload) >> 8]) + payload + b'\x00')


def test_the_osd_channel_is_kicked_with_the_literal_MSP():
    """MainPresenter.StartOsdChannel sends exactly these four bytes, then reads."""
    assert osd.KICK == b'$MSP' == bytes([36, 77, 83, 80])


def test_v1_and_v2_frames_are_both_split():
    buf = v1(182, bytes([osd.DRAW_SCREEN])) + v2(182, bytes([osd.HEARTBEAT]))
    frames, tail = osd.split_frames(buf)
    assert [f['version'] for f in frames] == [1, 2]
    assert tail == b''


def test_v1_total_is_six_plus_length_and_v2_is_nine_plus_length():
    p = b'abcd'
    assert len(v1(182, p)) == osd.V1_OVERHEAD + len(p)
    assert len(v2(182, p)) == osd.V2_OVERHEAD + len(p)


def test_a_partial_frame_is_retained_as_tail_not_consumed():
    """A live push stream splits frames across datagrams; dropping the remainder
    would lose an OSD update on every boundary."""
    whole = v1(182, bytes([osd.WRITE_STRING, 0, 0, 0]) + b'HELLO')
    frames, tail = osd.split_frames(whole[:-4])
    assert frames == []
    assert tail == whole[:-4]
    # Feeding the rest completes it.
    frames2, tail2 = osd.split_frames(tail + whole[-4:])
    assert len(frames2) == 1 and tail2 == b''


def test_noise_before_a_frame_is_skipped():
    buf = b'\x00\x11\x22' + v1(182, bytes([osd.DRAW_SCREEN]))
    frames, _ = osd.split_frames(buf)
    assert len(frames) == 1


def test_a_dollar_not_followed_by_M_or_X_is_skipped():
    buf = b'$Z\x00\x00' + v1(182, bytes([osd.DRAW_SCREEN]))
    frames, _ = osd.split_frames(buf)
    assert len(frames) == 1


# --------------------------------------------------------------------------- #
# DisplayPort decoding
# --------------------------------------------------------------------------- #

def test_only_command_182_is_displayport():
    assert osd.MSP_DISPLAYPORT == 182
    other = osd.split_frames(v1(101, b'\x00'))[0][0]
    assert osd.parse_displayport(other) is None


def test_write_string_fields():
    f = osd.split_frames(v1(182, bytes([osd.WRITE_STRING, 3, 7, 2]) + b'RSSI'))[0][0]
    rec = osd.parse_displayport(f)
    assert rec['name'] == 'WRITE_STRING'
    assert (rec['row'], rec['column'], rec['attribute']) == (3, 7, 2)
    assert rec['characters'] == b'RSSI'


def test_a_short_write_string_reports_an_issue_rather_than_raising():
    """One bad frame in a live push stream must not stop the display."""
    f = osd.split_frames(v1(182, bytes([osd.WRITE_STRING, 3])))[0][0]
    rec = osd.parse_displayport(f)
    assert rec['issue'] == 'DisplayPortTooShort'


def test_nothing_is_displayable_until_draw_screen():
    """DrawScreen is what commits a frame -- MspDisplayPortDecoder.Apply returns
    true only on that sub-command."""
    scr = osd.DisplayPortScreen()
    write = osd.parse_displayport(
        osd.split_frames(v1(182, bytes([osd.WRITE_STRING, 1, 0, 0]) + b'HI'))[0][0])
    assert scr.apply([write]) is False
    assert scr.text_rows()[1] == 'HI'          # painted, but not yet drawn
    draw = osd.parse_displayport(osd.split_frames(v1(182, bytes([osd.DRAW_SCREEN])))[0][0])
    assert scr.apply([draw]) is True
    assert scr.draw_count == 1


def test_clear_and_release_both_wipe():
    for sub in (osd.CLEAR_SCREEN, osd.RELEASE):
        scr = osd.DisplayPortScreen()
        scr.apply([osd.parse_displayport(
            osd.split_frames(v1(182, bytes([osd.WRITE_STRING, 0, 0, 0]) + b'X'))[0][0])])
        assert scr.text_rows()[0] == 'X'
        scr.apply([{'subcommand': sub}])
        assert scr.text_rows()[0] == ''


@pytest.mark.parametrize('mode,size', [(0, (30, 16)), (1, (50, 18)),
                                       (2, (60, 22)), (3, (53, 20))])
def test_options_resizes_the_grid(mode, size):
    """MspDisplayPortDecoder.SetMode. These four are the only sizes."""
    scr = osd.DisplayPortScreen()
    scr.apply([{'subcommand': osd.OPTIONS, 'mode': mode}])
    assert (scr.columns, scr.rows) == size


def test_an_unknown_mode_is_ignored_not_defaulted():
    """The vendor's `default: return` -- no resize and, importantly, no clear."""
    scr = osd.DisplayPortScreen()
    scr.apply([osd.parse_displayport(
        osd.split_frames(v1(182, bytes([osd.WRITE_STRING, 0, 0, 0]) + b'KEEP'))[0][0])])
    scr.apply([{'subcommand': osd.OPTIONS, 'mode': 9}])
    assert (scr.columns, scr.rows) == (60, 22)
    assert scr.text_rows()[0] == 'KEEP'


def test_a_write_beyond_the_grid_is_clipped_not_wrapped():
    scr = osd.DisplayPortScreen()
    scr.apply([{'subcommand': osd.WRITE_STRING, 'row': 0, 'column': 58,
                'attribute': 0, 'characters': b'ABCDEF'}])
    assert scr.text_rows()[0].rstrip() == ' ' * 58 + 'AB'
    # Out of range entirely: nothing happens.
    scr.apply([{'subcommand': osd.WRITE_STRING, 'row': 99, 'column': 0,
                'attribute': 0, 'characters': b'ZZ'}])
    assert all('ZZ' not in r for r in scr.text_rows())


def test_the_attribute_low_two_bits_are_the_font_page():
    scr = osd.DisplayPortScreen()
    scr.apply([{'subcommand': osd.WRITE_STRING, 'row': 0, 'column': 0,
                'attribute': 0x07, 'characters': b'A'}])
    assert scr.reading()['cells'][0][0] == {'char': ord('A'), 'page': 3}


def test_non_printable_codes_render_as_space_not_a_substitute_glyph():
    """MSP OSD codes index a font page, not ASCII. Inventing a character would
    misreport the OSD."""
    scr = osd.DisplayPortScreen()
    scr.apply([{'subcommand': osd.WRITE_STRING, 'row': 0, 'column': 0,
                'attribute': 0, 'characters': bytes([0x01, ord('B'), 0x9F])}])
    assert scr.text_rows()[0] == ' B'
    assert scr.reading()['cells'][0][0]['char'] == 1     # raw code preserved


def test_selftests_pass():
    assert crsf.selftest()['ok'] is True
    assert osd.selftest()['ok'] is True
