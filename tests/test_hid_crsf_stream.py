"""HID axes -> CRSF, and the failsafe that CGC does not have.

Oracle for the mapping: CGC v0.3.5 DescriptorDrivenParser and HidAxisNormalizer.
The staleness behaviour is ours and is the most safety-relevant thing in this file,
so it is tested hardest.
"""
import pathlib
import sys
import threading
import time

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'runtime'))
import caddx_crsf as crsf
import caddx_hid as hid


# --------------------------------------------------------------------------- #
# Normalization -- the vendor's formula
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize('value,lo,hi,expected', [
    (0, 0, 255, 0),
    (255, 0, 255, 2048),
    (128, 0, 255, 1028),          # round-to-nearest, not truncation
    (0, 0, 65535, 0),
    (65535, 0, 65535, 2048),
    (32767, 0, 65535, 1024),
    (-32768, -32768, 32767, 0),   # signed descriptor
    (32767, -32768, 32767, 2048),
])
def test_normalize_matches_the_vendor_formula(value, lo, hi, expected):
    """((clamped - min) * 2048 + span/2) / span, integer arithmetic."""
    assert hid.normalize_to_2048(value, lo, hi) == expected


def test_values_outside_the_declared_range_are_clamped():
    assert hid.normalize_to_2048(-50, 0, 255) == 0
    assert hid.normalize_to_2048(9999, 0, 255) == 2048


def test_a_degenerate_range_reads_as_zero_not_centre():
    """The vendor returns 0. An axis whose descriptor makes no sense should read as
    absent, not as a plausible stick position."""
    assert hid.normalize_to_2048(500, 10, 10) == 0
    assert hid.normalize_to_2048(500, 20, 10) == 0


# --------------------------------------------------------------------------- #
# Usage selection
# --------------------------------------------------------------------------- #

def test_axis_usages_are_generic_desktop_0x30_to_0x40():
    assert hid.is_axis_usage(0x010030) and hid.is_axis_usage(0x010040)
    assert not hid.is_axis_usage(0x01002F)
    assert not hid.is_axis_usage(0x010041)
    assert not hid.is_axis_usage(0x020030)      # wrong usage page


def test_button_usages_are_page_nine():
    assert hid.is_button_usage(0x090001)
    assert not hid.is_button_usage(0x010030)


@pytest.mark.parametrize('usage,name', [
    (0x010030, 'X'), (0x010031, 'Y'), (0x010032, 'Z'), (0x010033, 'Rx'),
    (0x010035, 'Rz'), (0x010039, 'Hat Switch'), (0x01003F, '0x3F'),
])
def test_usage_names_match_UsageToName(usage, name):
    assert hid.axis_name(usage) == name


# --------------------------------------------------------------------------- #
# The full chain
# --------------------------------------------------------------------------- #

def test_centre_stick_maps_to_crsf_centre():
    """A mid-travel stick must land exactly on 992, not one either side."""
    normalized = hid.normalize_to_2048(32767, 0, 65535)
    assert crsf.map_hid_axis(normalized) == crsf.CRSF_MID


def test_endpoints_map_to_crsf_endpoints():
    assert crsf.map_hid_axis(hid.normalize_to_2048(0, 0, 255)) == crsf.CRSF_MIN
    assert crsf.map_hid_axis(hid.normalize_to_2048(255, 0, 255)) == crsf.CRSF_MAX


def test_only_the_first_eight_axes_are_sent_and_the_rest_are_centred():
    channels = hid.axes_to_crsf(list(range(0, 2048, 100)))
    assert len(channels) == 16
    assert channels[8:] == [crsf.CRSF_MID] * 8


# --------------------------------------------------------------------------- #
# The stream, and the failsafe
# --------------------------------------------------------------------------- #

class Sink:
    def __init__(self):
        self.frames = []
        self.lock = threading.Lock()

    def __call__(self, frame):
        with self.lock:
            self.frames.append(frame)

    def count(self):
        with self.lock:
            return len(self.frames)


def test_the_stream_refuses_to_start_with_no_stick_positions():
    s = hid.CrsfStream(Sink(), channel_map=hid.vendor_positional_map(8))
    with pytest.raises(hid.HidError) as e:
        s.start()
    assert e.value.code == 'HID_NO_AXES'


def test_a_seven_axis_stick_is_accepted():
    """There is no eight-axis minimum, and there should never have been one.

    A seven-axis gamepad was refused on the bench and the refusal was invisible,
    so USE looked like a dead button. The rule resembled a safety property and was
    not one: frames are not built positionally from axes, they are resolved
    through a CHANNEL MAP whose entries may be an axis, a button or a fixed value.
    Seven axes plus buttons fills sixteen channels perfectly well.
    """
    s = hid.CrsfStream(Sink(), channel_map=hid.vendor_positional_map(7))
    s.update_axes([1024] * 7)          # must not raise
    assert len(s.state()["axes"]) == 7


def test_no_axes_at_all_is_still_refused():
    s = hid.CrsfStream(Sink(), channel_map=hid.vendor_positional_map(7))
    with pytest.raises(hid.HidError) as e:
        s.update_axes([])
    assert e.value.code == 'HID_NO_AXES'


def test_a_channel_mapped_to_an_axis_the_device_lacks_is_refused_by_name():
    """THE PROTECTION THAT REPLACED THE AXIS-COUNT RULE.

    This is what the eight-axis minimum was crudely approximating, and it is
    strictly better: it catches a stale map against a smaller stick per channel,
    names the channel and the axis, and does not punish a device that is simply
    smaller than eight.
    """
    cmap = hid.ChannelMap([{'source': 'axis', 'index': i} for i in range(16)])
    with pytest.raises(hid.HidError) as e:
        cmap.resolve([1024] * 7)
    assert e.value.code == 'MAP_AXIS_MISSING'
    assert 'axis' in str(e.value)


def test_a_seven_axis_stick_can_still_fill_sixteen_channels():
    """Buttons and fixed values cover what the axes do not, which is the whole
    reason the axis-count rule was unnecessary."""
    entries = [{'source': 'axis', 'index': i} for i in range(7)]
    entries += [{'source': 'button', 'index': i, 'low': 172, 'high': 1811} for i in range(4)]
    entries += [{'source': 'fixed', 'value': 992} for _ in range(5)]
    cmap = hid.ChannelMap(entries)
    assert cmap.complete, cmap.unassigned
    out = cmap.resolve([1024] * 7, [False, True, False, True])
    assert len(out) == 16


def test_the_stream_emits_well_formed_crsf_at_a_rate():
    sink = Sink()
    s = hid.CrsfStream(sink, rate_hz=100, stale_after_s=5.0, channel_map=hid.vendor_positional_map(8))
    s.update_axes([1024] * 8)
    s.start()
    try:
        time.sleep(0.25)
        assert sink.count() >= 5, f'only {sink.count()} frames in 250 ms at 100 Hz'
        frame = sink.frames[0]
        assert len(frame) == 26
        assert crsf.decode_channels(frame) == [crsf.CRSF_MID] * 16
    finally:
        s.stop()
    assert s.state()['running'] is False


def test_transmission_STOPS_when_the_sticks_go_stale():
    """The safety property, and the one place we deliberately differ from CGC.

    A CRSF receiver acts on the last frame it got, so a sender that keeps
    transmitting stale positions leaves the aircraft flying the last stick input.
    CGC has no staleness handling -- SendCrsfFrame is called from the input event
    and that is all. Here the stream stops instead.
    """
    sink = Sink()
    s = hid.CrsfStream(sink, rate_hz=100, stale_after_s=0.08, channel_map=hid.vendor_positional_map(8))
    s.update_axes([1500] * 8)
    s.start()
    time.sleep(0.4)                       # long past the cut-off, no further updates
    state = s.state()
    assert state['running'] is False, 'the stream must stop, not keep transmitting'
    assert state['stale_stops'] == 1
    assert 'stale' in (state['halt_reason'] or '')
    settled = sink.count()
    time.sleep(0.15)
    assert sink.count() == settled, 'frames were still being sent after the stop'


def test_it_stops_rather_than_sending_centre():
    """Centre is a real command -- mid-throttle, neutral attitude. Silence lets the
    receiver's own configured failsafe take over, which is the one the operator set
    up for exactly this case."""
    sink = Sink()
    s = hid.CrsfStream(sink, rate_hz=100, stale_after_s=0.05, channel_map=hid.vendor_positional_map(8))
    s.update_axes([1800] * 8)             # sticks well off centre
    s.start()
    time.sleep(0.3)
    assert s.state()['running'] is False
    # Nothing centred was ever emitted as a parting frame.
    centred = crsf.build_rc_channels([crsf.CRSF_MID] * 16)
    assert centred not in sink.frames


def test_fresh_updates_keep_the_stream_alive():
    sink = Sink()
    s = hid.CrsfStream(sink, rate_hz=100, stale_after_s=0.1, channel_map=hid.vendor_positional_map(8))
    s.update_axes([1024] * 8)
    s.start()
    try:
        for _ in range(6):
            time.sleep(0.04)
            s.update_axes([1024] * 8)
        assert s.state()['running'] is True
        assert s.state()['stale_stops'] == 0
    finally:
        s.stop()


def test_a_send_failure_halts_rather_than_spinning():
    def boom(_frame):
        raise OSError('no route to host')
    s = hid.CrsfStream(boom, rate_hz=100, stale_after_s=5.0, channel_map=hid.vendor_positional_map(8))
    s.update_axes([1024] * 8)
    s.start()
    time.sleep(0.2)
    st = s.state()
    assert st['running'] is False
    assert 'no route to host' in (st['last_error'] or '')


@pytest.mark.parametrize('requested,expected', [(1, hid.MIN_RATE_HZ),
                                                (9999, hid.MAX_RATE_HZ),
                                                (None, hid.DEFAULT_RATE_HZ)])
def test_the_rate_is_clamped(requested, expected):
    s = hid.CrsfStream(Sink(), rate_hz=requested if requested is not None else hid.DEFAULT_RATE_HZ, channel_map=hid.vendor_positional_map(8))
    assert s.state()['rate_hz'] == expected


def test_state_always_carries_the_failsafe_statement():
    s = hid.CrsfStream(Sink(), channel_map=hid.vendor_positional_map(8))
    assert 'STOPS' in s.state()['failsafe_note']
    assert 'CGC has no staleness handling' in s.state()['failsafe_note']


def test_selftest_passes():
    assert hid.selftest()['ok'] is True


# --------------------------------------------------------------------------- #
# Channel mapping -- ours. CGC has none.
#
# The operator's layout is ARM on channel 5 and a mix of two-position switches,
# three-position switches and pots across 6-16. CGC's positional mapping (axes
# 0..7 -> channels 1..8, rest centred) would drive ARM from the fifth HID axis and
# park every switch channel on its middle detent. Neither is a safe guess.
# --------------------------------------------------------------------------- #

def test_an_empty_map_is_incomplete_and_names_every_channel():
    m = hid.ChannelMap()
    assert m.complete is False
    assert m.unassigned == list(range(1, 17))


def test_resolving_an_incomplete_map_refuses():
    with pytest.raises(hid.HidError) as e:
        hid.ChannelMap().resolve([1024] * 8)
    assert e.value.code == 'MAP_INCOMPLETE'
    assert 'ARM' in str(e.value)


def test_the_stream_refuses_to_start_without_a_complete_map():
    """The safety property this whole mechanism exists for."""
    s = hid.CrsfStream(Sink())
    s.update_axes([1024] * 8)
    with pytest.raises(hid.HidError) as e:
        s.start()
    assert e.value.code == 'MAP_INCOMPLETE'


def test_an_unassigned_channel_is_never_silently_centred():
    """Centre is a real switch position -- the middle detent of a three-position
    switch -- so it must never stand in for 'nothing assigned'."""
    entries = [{'source': 'axis', 'index': i} for i in range(8)] + [None] * 8
    m = hid.ChannelMap(entries)
    assert m.unassigned == [9, 10, 11, 12, 13, 14, 15, 16]
    with pytest.raises(hid.HidError):
        m.resolve([1024] * 8)


def test_a_realistic_layout_resolves():
    """ARM on 5 from a button, pots and switches across 6-16."""
    entries = [
        {'source': 'axis', 'index': 0},                      # 1 roll
        {'source': 'axis', 'index': 1},                      # 2 pitch
        {'source': 'axis', 'index': 2},                      # 3 throttle
        {'source': 'axis', 'index': 3},                      # 4 yaw
        {'source': 'button', 'index': 0, 'low': 172, 'high': 1811},   # 5 ARM
        {'source': 'axis', 'index': 4},                      # 6 three-pos as an axis
        {'source': 'axis', 'index': 5},                      # 7 pot
        {'source': 'button', 'index': 1, 'low': 172, 'high': 1811},   # 8 two-pos
    ] + [{'source': 'fixed', 'value': 172}] * 8              # 9-16 explicitly low
    m = hid.ChannelMap(entries)
    assert m.complete
    out = m.resolve([0, 1024, 2048, 1024, 512, 1536], buttons=[False, True])
    assert out[0] == crsf.CRSF_MIN and out[2] == crsf.CRSF_MAX
    assert out[4] == 172, 'ARM must read low while the button is released'
    assert out[7] == 1811, 'a pressed two-position switch must read high'
    assert out[8:] == [172] * 8, 'channels the operator set low must stay low'


def test_arm_follows_its_button():
    entries = ([{'source': 'axis', 'index': 0}] * 4
               + [{'source': 'button', 'index': 0, 'low': 172, 'high': 1811}]
               + [{'source': 'fixed', 'value': 992}] * 11)
    m = hid.ChannelMap(entries)
    assert m.resolve([1024], buttons=[False])[4] == 172
    assert m.resolve([1024], buttons=[True])[4] == 1811


def test_a_map_referencing_an_axis_the_device_lacks_is_refused():
    """Refused at start, not one frame into the stream."""
    entries = [{'source': 'axis', 'index': 11}] + [{'source': 'fixed', 'value': 992}] * 15
    s = hid.CrsfStream(Sink(), channel_map=hid.ChannelMap(entries))
    s.update_axes([1024] * 8)
    with pytest.raises(hid.HidError) as e:
        s.start()
    assert e.value.code == 'MAP_AXIS_MISSING'


def test_the_vendor_map_is_available_but_must_be_chosen():
    """CGC's own behaviour, offered explicitly and never defaulted to."""
    v = hid.vendor_positional_map(8)
    assert v.complete
    assert v.resolve([1024] * 8) == [crsf.CRSF_MID] * 16
    # And it is not what a fresh stream has.
    assert hid.CrsfStream(Sink()).channel_map.complete is False


def test_axes_beyond_the_first_eight_are_retained():
    """A three-position switch is often a high axis, and a map may reference it."""
    entries = [{'source': 'axis', 'index': 9}] + [{'source': 'fixed', 'value': 992}] * 15
    s = hid.CrsfStream(Sink(), channel_map=hid.ChannelMap(entries))
    s.update_axes([0] * 9 + [2048])
    s.start()
    try:
        assert s.state()['channels'][0] == crsf.CRSF_MAX
    finally:
        s.stop()


def test_resolved_values_are_clamped_into_the_crsf_range():
    entries = [{'source': 'fixed', 'value': 99999}] + [{'source': 'fixed', 'value': -5}] * 15
    out = hid.ChannelMap(entries).resolve([])
    assert out[0] == crsf.CRSF_MAX and out[1] == crsf.CRSF_MIN


# --------------------------------------------------------------------------- #
# Calibration -- ours. CGC has none.
#
# Its "JoyCalib" button switches to the binding view; its parser hardcodes every
# axis to 0..2048 and trusts the descriptor. A stick that does not reach its own
# declared endpoints therefore never produces full CRSF travel, which on a
# throttle axis can put the arm position out of reach.
# --------------------------------------------------------------------------- #

def test_observed_travel_rescales_to_full_range():
    """A stick reaching only 300..1700 of its declared 0..2048."""
    cal = hid.AxisCalibration(4)
    for v in (300, 1000, 1700):
        cal.observe([v] * 4)
    assert cal.apply([300] * 4)[0] == 0
    assert cal.apply([1700] * 4)[0] == hid.NORMALIZED_MAX
    assert abs(cal.apply([1000] * 4)[0] - 1024) <= 2


def test_full_crsf_travel_is_reached_after_calibration():
    """The property that matters: full stick deflection must reach CRSF_MAX."""
    cal = hid.AxisCalibration(8)
    for v in (300, 1700):
        cal.observe([v] * 8)
    assert crsf.map_hid_axis(cal.apply([1700] * 8)[0]) == crsf.CRSF_MAX
    assert crsf.map_hid_axis(cal.apply([300] * 8)[0]) == crsf.CRSF_MIN
    # Without calibration the same stick falls short, which is the bug.
    assert crsf.map_hid_axis(1700) < crsf.CRSF_MAX


def test_an_axis_without_enough_travel_is_passed_through_uncalibrated():
    """Amplifying a narrow window into full-scale control output is worse than
    leaving the axis alone."""
    cal = hid.AxisCalibration(4)
    cal.observe([1000] * 4)
    cal.observe([1010] * 4)          # 10 counts of travel: noise, not a sweep
    assert cal.usable(0) is False
    assert cal.apply([1005] * 4)[0] == 1005


def test_the_travel_threshold_is_explicit():
    cal = hid.AxisCalibration(1)
    cal.observe([0]); cal.observe([hid.MIN_CALIBRATION_TRAVEL - 1])
    assert cal.usable(0) is False
    cal.observe([hid.MIN_CALIBRATION_TRAVEL])
    assert cal.usable(0) is True


def test_centre_is_marked_on_request_not_inferred():
    """A calibration captured while a stick rested off-centre would bake that in,
    so the resting position is recorded deliberately."""
    cal = hid.AxisCalibration(2)
    cal.observe([0, 0]); cal.observe([2048, 2048])
    assert cal.centre == [None, None]
    cal.mark_centre([1024, 900])
    assert cal.centre == [1024, 900]


def test_calibration_applies_before_the_channel_map():
    """A map assignment must always see a full-travel axis, whatever the stick
    mechanically reaches."""
    sink = Sink()
    s = hid.CrsfStream(sink, rate_hz=100, stale_after_s=5.0,
                       channel_map=hid.vendor_positional_map(8))
    s.start_calibration(8)
    for v in (300, 1700):
        s.update_axes([v] * 8)
    s.finish_calibration()
    s.update_axes([1700] * 8)
    assert s.state()['channels'][0] == crsf.CRSF_MAX


def test_calibration_round_trips_through_a_dict():
    cal = hid.AxisCalibration(3)
    cal.observe([10, 20, 30]); cal.observe([900, 1800, 2000]); cal.mark_centre([500, 900, 1000])
    again = hid.AxisCalibration.from_dict(cal.to_dict())
    assert again.state()['axes'] == cal.state()['axes']


def test_state_says_it_is_observed_not_declared():
    cal = hid.AxisCalibration(1)
    assert 'Observed travel, not the declared descriptor range' in cal.state()['note']
    assert 'CGC does not calibrate at all' in cal.state()['note']


def test_live_values_are_polled_rather_than_read_once():
    """The axis table, the CRSF column and the calibration panel were a single
    frozen reading.

    reloadLive() ran on entering LIVE mode and after a button press, and on no
    timer at all. Sweeping the sticks changed nothing on screen, which makes
    calibration guesswork: the operator is asked to move every axis to its limits
    with no sign that anything is being observed. Reported from the bench as
    "nowhere on the screen can I actually see live values".
    """
    import pathlib
    js = (pathlib.Path(__file__).resolve().parents[1]
          / "runtime" / "www" / "app.js").read_text(encoding="utf-8")
    assert "function startLivePoll(" in js, "nothing polls live stick state"
    body = js[js.index("function startLivePoll("):]
    body = body[:body.index("\nasync function reloadLive")]
    assert "setInterval" in body, "the poll does not repeat"
    assert "/api/cgc/hid" in body, "the poll does not read stick state"
    # It must stop when the operator leaves LIVE, or it runs behind another page.
    # Asserted as a PROPERTY -- that a stop exists and is reached on both paths --
    # rather than by looking for clearInterval at a particular spot. The clear was
    # deliberately moved into one stopLivePoll() so that "every poller is cleared"
    # stays one clearInterval per timer instead of one per exit path.
    assert "function stopLivePoll(" in js, "the poll has no stop"
    assert "clearInterval" in js[js.index("function stopLivePoll("):][:200], (
        "stopLivePoll does not actually clear the timer")
    assert body.count("stopLivePoll()") >= 2, (
        "the poll is not stopped both on a mode change and from inside the tick")
    assert "state.mode!=='live'" in body.replace(" ", ""), (
        "the poll does not stop when the mode changes")
    # And it must be started when the mode changes, not only at load.
    assert "startLivePoll(mode)" in js, "the poll is never started on a mode change"


# --------------------------------------------------------------------------- #
# Momentary vs latching buttons.
#
# A gamepad button is momentary: high only while held. That is unusable for ARM --
# an Xbox controller has no latching switch, so arming would mean holding a button
# for the whole flight. Reported from the bench.
# --------------------------------------------------------------------------- #
def _toggle_stream():
    entries = [{'source': 'button', 'index': 0, 'mode': 'toggle',
                'low': 172, 'high': 1811}] + [{'source': 'fixed', 'value': 992}] * 15
    return hid.CrsfStream(Sink(), channel_map=hid.ChannelMap(entries))


def _press(s, down, axes=6):
    s.update_axes([1024] * axes, buttons=[down])
    return s.state()['channels'][0]


def test_a_toggle_button_latches_on_the_press_and_survives_the_release():
    s = _toggle_stream()
    assert _press(s, False) == 172
    assert _press(s, True) == 1811
    assert _press(s, False) == 1811, "the latch did not survive the release"


def test_a_held_toggle_button_does_not_re_toggle_every_frame():
    """Edge detection, not level. resolve() is called more than once per frame --
    the stream tick and twice from state() -- so a latch computed there would flip
    two or three times per press."""
    s = _toggle_stream()
    _press(s, True)
    for _ in range(10):
        assert _press(s, True) == 1811, "a held button re-toggled"
    assert _press(s, False) == 1811


def test_a_second_press_unlatches():
    s = _toggle_stream()
    _press(s, True); _press(s, False)
    assert _press(s, True) == 172
    assert _press(s, False) == 172


def test_momentary_is_still_the_default_and_is_unchanged():
    entries = [{'source': 'button', 'index': 0, 'low': 172, 'high': 1811}] + \
              [{'source': 'fixed', 'value': 992}] * 15
    s = hid.CrsfStream(Sink(), channel_map=hid.ChannelMap(entries))
    assert _press(s, True) == 1811
    assert _press(s, False) == 172, "a default button latched; it must be momentary"


def test_stopping_the_stream_drops_a_latched_arm():
    """SAFETY. If the latch survived a stop, an operator could stop transmitting
    with ARM latched on, change something, start again, and be armed from the first
    frame without touching a button."""
    s = _toggle_stream()
    _press(s, True); _press(s, False)
    assert s.state()['channels'][0] == 1811
    s.stop()
    assert _press(s, False) == 172, "ARM stayed latched across a stop"


def test_remapping_drops_a_latched_arm():
    s = _toggle_stream()
    _press(s, True); _press(s, False)
    assert s.state()['channels'][0] == 1811
    s.set_channel_map(hid.ChannelMap(
        [{'source': 'button', 'index': 0, 'mode': 'toggle', 'low': 172, 'high': 1811}]
        + [{'source': 'fixed', 'value': 992}] * 15))
    assert _press(s, False) == 172, "ARM stayed latched across a remap"


def test_an_unknown_button_mode_is_refused_not_defaulted():
    """A typo silently becoming momentary would turn a latching ARM into one that
    disarms the moment the operator lets go."""
    cmap = hid.ChannelMap(
        [{'source': 'button', 'index': 0, 'mode': 'latch', 'low': 172, 'high': 1811}]
        + [{'source': 'fixed', 'value': 992}] * 15)
    with pytest.raises(hid.HidError) as e:
        cmap.resolve([1024] * 6, [True], {})
    assert e.value.code == 'MAP_BAD_BUTTON_MODE'


def test_any_button_can_be_either_mode_on_a_per_channel_basis():
    """Asked directly: "I should be able to make any button momentary or latching."

    The mode lives on the CHANNEL ENTRY, not on the button, so it is chosen per
    channel -- and the same physical button can therefore drive one channel
    momentary and another latching at the same time. The latch is kept per button
    index, so two toggle channels on different buttons stay independent.
    """
    entries = [
        {'source': 'button', 'index': 0, 'mode': 'momentary', 'low': 172, 'high': 1811},
        {'source': 'button', 'index': 0, 'mode': 'toggle',    'low': 172, 'high': 1811},
        {'source': 'button', 'index': 5, 'mode': 'toggle',    'low': 172, 'high': 1811},
    ] + [{'source': 'fixed', 'value': 992}] * 13
    s = hid.CrsfStream(Sink(), channel_map=hid.ChannelMap(entries))

    def step(b0, b5):
        btns = [False] * 27
        btns[0], btns[5] = b0, b5
        s.update_axes([1024] * 6, buttons=btns)
        return s.state()['channels'][:3]

    assert step(False, False) == [172, 172, 172]
    assert step(True, False) == [1811, 1811, 172]
    # The same button: the momentary channel follows the release, the toggle does not.
    assert step(False, False) == [172, 1811, 172]
    # A different button latches without disturbing the first.
    assert step(False, True) == [172, 1811, 1811]
    assert step(False, False) == [172, 1811, 1811]
    # Pressing the shared button again unlatches only its toggle channel.
    assert step(True, False) == [1811, 172, 1811]
    assert step(False, False) == [172, 172, 1811]


def test_the_ui_picks_the_control_and_the_mode_separately():
    """Each button appears ONCE in the picker; the mode is a checkbox column.

    Offering every button twice -- once per mode -- made a 27-button controller
    produce 54 options, which is not a list anyone can use. The source picker now
    answers "which control" and the LATCHING column answers "how it behaves".
    """
    import pathlib
    js = (pathlib.Path(__file__).resolve().parents[1]
          / "runtime" / "www" / "app.js").read_text(encoding="utf-8")

    blk = js[js.index("const nbtn="):]
    blk = blk[:blk.index("opts+=opt('fixed:172'")]
    assert blk.count("opts+=opt(") == 1, "a button is still offered more than once"
    assert "— hold" not in blk and "toggle (latching)" not in blk, (
        "the mode is still baked into the picker")

    assert "<th>LATCHING</th>" in js, "there is no LATCHING column"
    assert "data-maplatch=" in js, "there is no per-channel latching control"
    # Only a button can latch. An axis is continuous and a fixed value cannot change.
    assert "isBtn?'':' disabled'" in js.replace(" ", "").replace("isBtn?'':'disabled'",
                                                                "isBtn?'':' disabled'") \
        or "isBtn?'':' disabled'" in js, "the box is not disabled for non-buttons"
    assert "mode: latch ? 'toggle' : 'momentary'" in js, (
        "the checkbox is not what decides the mode that is sent")


def test_the_ui_offers_auto_detect_per_channel():
    import pathlib
    js = (pathlib.Path(__file__).resolve().parents[1]
          / "runtime" / "www" / "app.js").read_text(encoding="utf-8")
    assert "data-mapdetect=" in js, "no per-channel DETECT"
    assert "/api/cgc/hid/detect" in js, "DETECT does not call the endpoint"
    assert "data-mapdetectcancel" in js, "a detection in progress cannot be cancelled"


# --------------------------------------------------------------------------- #
# Auto-detect. Watching happens in update_axes because it sees every HID report;
# the page polls at 5 Hz and would miss a quick button tap between two polls.
# --------------------------------------------------------------------------- #
def _detect_stream():
    return hid.CrsfStream(Sink(), channel_map=hid.ChannelMap([None] * 16))


def _feed(s, axes, pressed=()):
    b = [False] * 27
    for i in pressed:
        b[i] = True
    s.update_axes(axes, buttons=b)


def test_detect_assigns_the_axis_that_was_swept():
    s = _detect_stream()
    _feed(s, [1024] * 6 + [0])
    s.start_detect(5)
    _feed(s, [1024, 1024, 200, 1024, 1024, 1024, 0])
    _feed(s, [1024, 1024, 1900, 1024, 1024, 1024, 0])
    st = s.state()
    assert st['detecting'] is None, "detection did not finish"
    assert st['channel_map'][4] == {'channel': 5, 'assigned': True,
                                    'source': 'axis', 'index': 2}


def test_detect_assigns_a_button_that_was_tapped():
    s = _detect_stream()
    _feed(s, [1024] * 6 + [0])
    s.start_detect(6)
    _feed(s, [1024] * 6 + [0], pressed=(9,))
    row = s.state()['channel_map'][5]
    assert row['source'] == 'button' and row['index'] == 9
    # Momentary by default; the operator ticks LATCHING if they want a switch.
    assert row['mode'] == 'momentary'


def test_a_button_press_beats_a_simultaneous_axis_sweep():
    """Pressing a button is unambiguous -- nobody presses one by accident while
    sweeping a stick -- so it settles detection immediately."""
    s = _detect_stream()
    _feed(s, [1024] * 6 + [0])
    s.start_detect(7)
    _feed(s, [0, 2048, 1024, 1024, 1024, 1024, 0], pressed=(3,))
    assert s.state()['channel_map'][6]['source'] == 'button'


def test_resting_jitter_does_not_win_a_detection():
    """A stick at rest jitters, and a controller on a desk drifts. A deliberate
    sweep has to be clearly separable from that or DETECT assigns the wrong axis."""
    s = _detect_stream()
    _feed(s, [1024] * 6 + [0])
    s.start_detect(8)
    for v in (1024, 1030, 1020, 1035, 1018):
        _feed(s, [v] + [1024] * 5 + [0])
    assert s.state()['detecting'] == 8, "jitter was mistaken for a deliberate move"
    assert s.state()['channel_map'][7]['assigned'] is False


def test_detect_can_be_cancelled_and_assigns_nothing():
    s = _detect_stream()
    _feed(s, [1024] * 6 + [0])
    s.start_detect(9)
    s.cancel_detect()
    _feed(s, [0, 2048, 1024, 1024, 1024, 1024, 0])
    assert s.state()['detecting'] is None
    assert s.state()['channel_map'][8]['assigned'] is False


def test_detect_refuses_a_channel_outside_the_frame():
    s = _detect_stream()
    for bad in (0, 17, -1):
        with pytest.raises(hid.HidError) as e:
            s.start_detect(bad)
        assert e.value.code == 'DETECT_BAD_CHANNEL'
