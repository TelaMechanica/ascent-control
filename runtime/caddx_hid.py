"""HID joystick axes -> CRSF, and the stream that makes it a control link.

Oracle: CGC v0.3.5 `DescriptorDrivenParser`, `HidAxisNormalizer`,
`AdaptiveJoystickFrame` (`CaddxGroundConfiguration.dll` `d42ff30c…`).

The vendor chain, end to end:

    raw HID logical value
      -> HidAxisNormalizer.NormalizeTo2048(value, logicalMin, logicalMax)   0..2048
      -> CrsfHelper.MapHidAxis                                           172..1811
      -> CrsfHelper.BuildRcChannelsPacket                            26-byte frame

`DescriptorDrivenParser` reports every axis as logical 0..2048 regardless of what
the device declares -- `AxisLogicalMin`/`AxisLogicalMax` are hardcoded to
`Repeat(0, n)` and `Repeat(2048, n)`. The device's real range is consumed by the
normalizer and then discarded, so 0..2048 is the contract between the reader and
everything downstream.

Axis selection is by HID usage, not by report order: Generic Desktop page (`0x01`)
usages `0x30`..`0x40`. Buttons are usage page `0x09`. Order is descriptor order,
which is what puts X/Y/Z/Rx on channels 1-4.

--------------------------------------------------------------------------------
THE FAILSAFE IS OURS, AND IT IS THE POINT
--------------------------------------------------------------------------------

CRSF is a *continuous* protocol: a receiver acts on the last frame it got and a
stream that stops simply leaves the last stick positions standing. CGC has no
staleness handling at all -- `SendCrsfFrame` is called from the input event and
that is the whole of it.

That is not safe to reproduce. If the HID reader dies, the USB stick is unplugged,
the host stalls or the page closes, the vendor behaviour is to keep the aircraft on
whatever the sticks last said. So this sender **stops transmitting** once the axes
go stale, and reports why. Stopping is the correct action rather than sending
centred sticks: centre is a real command (mid-throttle, neutral attitude), whereas
silence lets the receiver's own configured failsafe take over, which is the one the
operator set up for exactly this case.
"""

from __future__ import annotations

import threading
import copy
import time

import hid_source

import caddx_crsf as crsf

NORMALIZED_MIN = 0
NORMALIZED_MAX = 2048          # HidAxisNormalizer.NormalizedAxisMax

# DescriptorDrivenParser.IsAxisUsage: page 0x01, usage 0x30..0x40.
AXIS_USAGE_PAGE = 0x01
AXIS_USAGE_MIN = 0x30
AXIS_USAGE_MAX = 0x40
BUTTON_USAGE_PAGE = 0x09

# DescriptorDrivenParser.UsageToName
AXIS_NAMES = {0x30: 'X', 0x31: 'Y', 0x32: 'Z', 0x33: 'Rx', 0x34: 'Ry', 0x35: 'Rz',
              0x36: 'Slider', 0x37: 'Dial', 0x38: 'Wheel', 0x39: 'Hat Switch'}

# Defaults for the stream. 50 Hz is a common CRSF rate and is deliberately
# conservative; the real requirement is bench item C-2.
DEFAULT_RATE_HZ = 50
MIN_RATE_HZ = 10
MAX_RATE_HZ = 250
# How long axes may go unrefreshed before the stream stops. Three frames at the
# default rate, floored so a slow input source is not cut off spuriously.
DEFAULT_STALE_AFTER_S = 0.25


class HidError(RuntimeError):
    def __init__(self, code: str, message: str, evidence=None):
        super().__init__(message)
        self.code = code
        self.evidence = evidence or {}


def axis_name(usage: int) -> str:
    """UsageToName: known usages by name, anything else as 0xNN."""
    low = usage & 0xFFFF
    return AXIS_NAMES.get(low, f'0x{low:02X}')


def is_axis_usage(usage: int) -> bool:
    return (usage >> 16) == AXIS_USAGE_PAGE and AXIS_USAGE_MIN <= (usage & 0xFFFF) <= AXIS_USAGE_MAX


def is_button_usage(usage: int) -> bool:
    return (usage >> 16) == BUTTON_USAGE_PAGE


def normalize_to_2048(value: int, logical_min: int, logical_max: int) -> int:
    """`HidAxisNormalizer.NormalizeTo2048`, integer arithmetic, round-to-nearest.

    A degenerate range returns 0, as the vendor does -- not a centred value, because
    an axis whose descriptor makes no sense should read as absent rather than as a
    plausible stick position.
    """
    if logical_max <= logical_min:
        return 0
    clamped = max(logical_min, min(logical_max, int(value)))
    span = logical_max - logical_min
    return ((clamped - logical_min) * NORMALIZED_MAX + span // 2) // span


# --------------------------------------------------------------------------- #
# Channel mapping
# --------------------------------------------------------------------------- #
#
# CGC maps the first eight HID axes onto channels 1-8 and centres 9-16. That is
# fine for the camera and gimbal work its UI exposes, and it is **not safe as a
# default for flight**, because a real transmitter layout does not look like that:
# a typical setup puts ARM on channel 5 and spreads two-position switches,
# three-position switches and pots across 6-16.
#
# Two things follow, and both are safety properties rather than conveniences.
#
# 1. **A positional default is a guess about arming.** Under the vendor mapping,
#    channel 5 is whatever the fifth HID axis happens to be -- on many sticks a
#    throttle or a pot sitting at an arbitrary position. Channels 9-16 get CRSF
#    centre, which on a three-position switch is the *middle detent*, a real
#    selected position rather than "nothing".
#
# 2. **So there is no safe universal default, and we do not invent one.** An
#    unassigned channel is not centred and not zeroed: the stream refuses to run
#    until every channel is either assigned or explicitly given a value by the
#    operator. Fail closed, because the failure mode is an armed aircraft.
#
# This is ours. CGC has no channel map at all.

SOURCE_AXIS = 'axis'
SOURCE_BUTTON = 'button'
SOURCE_FIXED = 'fixed'

# How a button drives its channel.
#
# MOMENTARY is the default and matches the hardware: high while held. TOGGLE
# latches on the press and holds until the next press, which is what makes a
# gamepad usable for ARM -- an Xbox controller has no latching switch, so without
# it arming would mean holding a button for the entire flight.
BUTTON_MOMENTARY = 'momentary'
BUTTON_TOGGLE = 'toggle'
BUTTON_MODES = (BUTTON_MOMENTARY, BUTTON_TOGGLE)

# How far an axis must travel during auto-detect before it counts as "the one the
# operator moved". A stick at rest jitters by a few counts, and a controller left
# on a desk can drift, so a deliberate sweep has to be clearly separable from
# noise. 400 of 2048 is about a fifth of full travel -- far more than jitter, far
# less than a deliberate move.
DETECT_MIN_TRAVEL = 400

CHANNEL_COUNT = crsf.CHANNEL_COUNT          # 16


class ChannelMap:
    """An explicit input -> CRSF channel assignment.

    Each of the sixteen channels is one of:

      ``{'source': 'axis',   'index': n}``           a HID axis, full range
      ``{'source': 'button', 'index': n,
          'low': 172, 'high': 1811}``                a button, two positions
      ``{'source': 'fixed',  'value': v}``           a constant the operator chose
      ``None``                                       unassigned -- refuses to stream

    A three-position switch usually appears as an *axis* in its HID descriptor, so
    it needs no special case: its detents land wherever the device reports them.
    Where a switch really is a button, `low`/`high` are explicit rather than
    assumed, because which end means "on" is a receiver-side convention.
    """

    def __init__(self, entries=None):
        self.entries: list[dict | None] = list(entries or [None] * CHANNEL_COUNT)
        if len(self.entries) != CHANNEL_COUNT:
            raise HidError('MAP_WRONG_LENGTH',
                           f'a channel map needs exactly {CHANNEL_COUNT} entries, '
                           f'got {len(self.entries)}')

    @property
    def unassigned(self) -> list[int]:
        """1-based channel numbers with no assignment."""
        return [i + 1 for i, e in enumerate(self.entries) if not e]

    @property
    def complete(self) -> bool:
        return not self.unassigned

    def describe(self) -> list[dict]:
        out = []
        for i, e in enumerate(self.entries):
            row = {'channel': i + 1, 'assigned': bool(e)}
            row.update(e or {})
            out.append(row)
        return out

    def resolve(self, axes, buttons=None, latched=None) -> list[int]:
        """Build the sixteen CRSF values. Raises if anything is unassigned."""
        if not self.complete:
            raise HidError('MAP_INCOMPLETE',
                           'channels ' + ', '.join(str(c) for c in self.unassigned) +
                           ' have no assignment. Every channel must be assigned or '
                           'given an explicit value before transmitting -- an '
                           'unassigned channel is not centred, because centre is a '
                           'real switch position and channel 5 is commonly ARM.',
                           {'unassigned': self.unassigned})
        axes = list(axes or [])
        buttons = list(buttons or [])
        out = []
        for i, e in enumerate(self.entries):
            src = e.get('source')
            if src == SOURCE_AXIS:
                idx = int(e['index'])
                if idx >= len(axes):
                    raise HidError('MAP_AXIS_MISSING',
                                   f'channel {i + 1} is mapped to axis {idx}, which '
                                   f'this device does not report ({len(axes)} axes)',
                                   {'channel': i + 1, 'axis': idx})
                out.append(crsf.map_hid_axis(axes[idx]))
            elif src == SOURCE_BUTTON:
                mode = e.get('mode', BUTTON_MOMENTARY)
                if mode not in BUTTON_MODES:
                    # Refused rather than defaulted. A typo silently becoming
                    # momentary would turn a latching ARM into one that disarms the
                    # moment the operator lets go.
                    raise HidError('MAP_BAD_BUTTON_MODE',
                                   f'channel {i + 1} has unknown button mode '
                                   f'{mode!r}; use one of ' + ', '.join(BUTTON_MODES),
                                   {'channel': i + 1, 'mode': mode})
                idx = int(e['index'])
                if idx >= len(buttons):
                    raise HidError('MAP_BUTTON_MISSING',
                                   f'channel {i + 1} is mapped to button {idx}, which '
                                   f'this device does not report ({len(buttons)} '
                                   f'buttons)', {'channel': i + 1, 'button': idx})
                # MOMENTARY IS THE DEFAULT AND TOGGLE IS OPT-IN.
                #
                # A gamepad button is momentary: it reads high only while held. That
                # is unusable for ARM -- an Xbox controller has no latching switch,
                # so arming would mean holding a button for the whole flight. A
                # toggle entry latches on the PRESS and stays until the next press.
                #
                # The latch is NOT computed here. resolve() is called more than once
                # per frame (the stream tick and twice from state()), so flipping a
                # latch inside it would toggle two or three times per press. Edge
                # detection happens once, in update_axes, and this only reads it.
                if e.get('mode') == BUTTON_TOGGLE:
                    on = bool((latched or {}).get(idx, False))
                else:
                    on = bool(buttons[idx])
                out.append(int(e.get('high', crsf.CRSF_MAX)) if on
                           else int(e.get('low', crsf.CRSF_MIN)))
            elif src == SOURCE_FIXED:
                out.append(int(e['value']))
            else:
                raise HidError('MAP_BAD_SOURCE',
                               f'channel {i + 1} has unknown source {src!r}')
        return [max(crsf.CRSF_MIN, min(crsf.CRSF_MAX, v)) for v in out]


def vendor_positional_map(axis_count: int = 8) -> ChannelMap:
    """CGC's own mapping, available explicitly and never used as a default.

    Axes 0..7 onto channels 1..8, channels 9..16 at CRSF centre. Offered so an
    operator doing camera or gimbal work can ask for the vendor behaviour
    deliberately -- but it must be chosen, because on a flight setup channel 5 is
    ARM and this map would drive it from the fifth axis.
    """
    entries = [{'source': SOURCE_AXIS, 'index': i} for i in range(min(8, axis_count))]
    entries += [{'source': SOURCE_FIXED, 'value': crsf.CRSF_MID}
                for _ in range(CHANNEL_COUNT - len(entries))]
    return ChannelMap(entries)


def axes_to_crsf(axes) -> list[int]:
    """CGC's positional mapping. Retained for the vendor-parity tests only.

    Not used by the stream: see ChannelMap and the note above it.
    """
    return [crsf.map_hid_axis(a) for a in list(axes)[:8]] + [crsf.CRSF_MID] * 8


class CrsfStream:
    """Continuous CRSF sender fed by whatever the host reports for the sticks.

    Separating the sender from the input source is deliberate. CRSF wants a steady
    rate regardless of whether a stick moved, and the HID reader produces events
    only when one does. So the reader posts the latest axes and this thread emits at
    a fixed rate -- which is also what makes staleness detectable at all.
    """

    def __init__(self, send, *, rate_hz: int = DEFAULT_RATE_HZ,
                 stale_after_s: float = DEFAULT_STALE_AFTER_S,
                 channel_map: 'ChannelMap | None' = None):
        self._send = send
        self._source_lock = threading.RLock()
        self._hid_source = {}
        self._raw_axes = []
        self._sample_sequence = -1
        self._source_order = -1
        self._output_scope = None
        self._mapping_review = None
        # Calibration is applied BEFORE the channel map, so a map assignment always
        # sees a full-travel axis regardless of what the stick mechanically reaches.
        self._calibration = None
        self._calibrating = False
        # No default map. An unassigned channel is a refusal, not a centred value:
        # channel 5 is commonly ARM and centre is a real switch position.
        self._map = channel_map or ChannelMap()
        self._buttons: list[bool] = []
        self._lock = threading.RLock()
        self._thread = None
        self._stop = threading.Event()
        self._rate_hz = self._clamp_rate(rate_hz)
        self._stale_after = max(0.05, float(stale_after_s))
        self._axes: list[int] | None = None
        self._axes_at = 0.0
        self._source = None
        self._sent = 0
        self._stale_stops = 0
        self._last_error = None
        self._last_frame_hex = None
        self._started_at = None
        self._halt_reason = None
        # Latched button state, and the previous report used to find a rising edge.
        # Both reset on stop and on a remap -- see _reset_latches.
        self._latched: dict[int, bool] = {}
        self._prev_buttons: list[bool] = []
        # Auto-detect: which channel is listening, and what has been seen so far.
        self._detect_channel: int | None = None
        self._detect_lo: list[int] = []
        self._detect_hi: list[int] = []
        self._detect_result: dict | None = None


    def source_event(self, body):
        """Reader epochs serialize with samples; never a second input/control owner."""
        with self._source_lock:
            epoch=body.get('epoch')
            if not isinstance(epoch,str) or not 1<=len(epoch)<=128:
                raise HidError('HID_EPOCH_REQUIRED','Reader epoch required')
            if body.get('action')=='disconnect':
                if self._hid_source.get('epoch')!=epoch:return False
                self.stop('HID reader disconnected')
                with self._lock:
                    self._hid_source['present']=False
                    self._axes=None;self._buttons=[];self._raw_axes=[];self._last_frame_hex=None
                return True
            if body.get('action')!='connect':raise HidError('HID_SOURCE_ACTION','Unknown source action')
            try:layout,fingerprint=hid_source.descriptor(body['descriptor'])
            except (KeyError,ValueError,TypeError) as exc:raise HidError('HID_DESCRIPTOR_INVALID',str(exc)) from exc
            order=body.get('epoch_order')
            if type(order) is not int or order<=self._source_order:
                raise HidError('HID_SOURCE_OLD','Reader registration order is missing or older than current observation')
            device=body.get('device',{})
            if not isinstance(device,dict) or not isinstance(device.get('device_id'),str) or not 1<=len(device['device_id'])<=256:
                raise HidError('HID_IDENTITY_REQUIRED','Host device observation required')
            if any(not isinstance(device.get(k,''),str) or len(device.get(k,''))>256 for k in ('product','manufacturer')):
                raise HidError('HID_IDENTITY_REQUIRED','Invalid controller display name')
            device={key:device[key] for key in ('device_id','product','manufacturer','vendor_id','product_id') if key in device}
            if self._hid_source.get('epoch')==epoch:raise HidError('HID_EPOCH_REUSED','Reconnect needs a new epoch')
            self.stop('HID source changed')
            with self._lock:
                previous=self._hid_source
                compatible=(previous.get('device',{}).get('device_id')==device['device_id'] and previous.get('fingerprint')==fingerprint
                    and all(previous.get('device',{}).get(k)==device.get(k) for k in ('product','manufacturer','vendor_id','product_id')))
                if not compatible:
                    if any(self._map.entries):
                        self._mapping_review=dict(reason='Device or consumed HID layout changed; explicitly revalidate',
                            channels=copy.deepcopy(self._map.describe()),
                            calibration=self._calibration.state() if self._calibration else None,
                            device_id=previous.get('device',{}).get('device_id'),descriptor_id=previous.get('fingerprint'))
                    self._map=ChannelMap();self._calibration=None;self._calibrating=False
                self._axes=None;self._buttons=[];self._raw_axes=[];self._sample_sequence=-1
                self._last_frame_hex=None;self._sent=0;self._last_error=None;self._started_at=None
                self._detect_channel=None;self._detect_result=None
                self._source_order=order
                self._hid_source=dict(epoch=epoch,epoch_order=order,device=dict(device),layout=layout,fingerprint=fingerprint,present=True)
            return True

    def require_source(self, body):
        """Configuration/start requests must name the source shown to the operator."""
        if body.get('action') in ('stop','cancel'):return
        source=self._hid_source
        if source and (body.get('epoch')!=source['epoch'] or body.get('descriptor_id')!=source['fingerprint']):
            raise HidError('HID_SOURCE_CHANGED','Controller observation changed; refresh and review before applying')

    def source_sample(self, body):
        with self._source_lock:
            current=self._hid_source
            if not current.get('present') or body.get('epoch')!=current.get('epoch'):
                raise HidError('HID_SOURCE_CHANGED','Sample belongs to an inactive reader')
            sequence=body.get('sequence')
            if type(sequence) is not int or sequence<=self._sample_sequence:
                raise HidError('HID_SAMPLE_OLD','Late or repeated HID sample')
            axes=body.get('axes');buttons=body.get('buttons');raw=body.get('raw_axes')
            if not isinstance(axes,list) or len(axes)!=len(current['layout']['axes']) or not isinstance(buttons,list) or len(buttons)!=len(current['layout']['buttons']):
                raise HidError('HID_LAYOUT_CHANGED','Sample dimensions differ from current descriptor')
            if not isinstance(raw,list) or len(raw)!=len(axes):raise HidError('HID_RAW_REQUIRED','Raw sample observations required')
            if any(type(v) is not int or not 0<=v<=2048 for v in axes) or any(type(v) is not bool for v in buttons):
                raise HidError('HID_SAMPLE_INVALID','Malformed HID values')
            for value,normal,item in zip(raw,axes,current['layout']['axes']):
                if type(value) is not int or normalize_to_2048(value,item['logical_min'],item['logical_max'])!=normal:
                    raise HidError('HID_SAMPLE_INVALID','Raw and normalized HID observations disagree')
            with self._lock:
                self.update_axes(axes,buttons=buttons,source='hid',_epoch=current['epoch'])
                self._raw_axes=list(raw);self._sample_sequence=sequence

    def rc_source_status(self, assigned_features=()):
        with self._lock:
            observed=self.state()
            features=list(assigned_features)
            if observed['map_complete']:features.insert(0,'CRSF output mapping')
            result=hid_source.status(self._hid_source,observed,features)
            result.update(generated_at_ms=int(time.time()*1000),generated_monotonic_ms=time.monotonic()*1000,input_age_ms=observed['axes_age_ms'],
                          stale_after_ms=observed['stale_after_ms'])
            return result

    @staticmethod
    def _clamp_rate(hz) -> int:
        try:
            hz = int(hz)
        except (TypeError, ValueError):
            hz = DEFAULT_RATE_HZ
        return max(MIN_RATE_HZ, min(MAX_RATE_HZ, hz))

    @property
    def running(self) -> bool:
        t = self._thread
        return bool(t and t.is_alive())

    def set_calibration(self, cal) -> None:
        with self._lock:
            self._calibration = cal

    @property
    def calibration(self):
        return self._calibration

    def start_calibration(self, axis_count: int) -> None:
        with self._lock:
            self._calibration = AxisCalibration(axis_count)
            self._calibrating = True

    def finish_calibration(self) -> None:
        with self._lock:
            self._calibrating = False

    def mark_centre(self) -> None:
        with self._lock:
            if self._calibration and self._axes:
                self._calibration.mark_centre(self._axes)

    def _calibrated(self, axes):
        cal = self._calibration
        return cal.apply(axes) if cal else list(axes)

    def start_detect(self, channel: int) -> None:
        """Listen for whichever control the operator moves next, for one channel.

        DETECTION LIVES HERE AND NOT IN THE PAGE. The UI polls at 5 Hz, which is
        ample for watching a value change but will miss a quick button tap
        entirely. update_axes sees every HID report the device produces, so a press
        and release between two polls is still caught.

        A BUTTON PRESS WINS IMMEDIATELY over any axis movement. Pressing a button
        is unambiguous: nobody presses one by accident while sweeping a stick. An
        axis has to clear DETECT_MIN_TRAVEL, and the largest mover wins, so resting
        jitter on five other axes cannot outvote a deliberate sweep on one.
        """
        if not 1 <= int(channel) <= CHANNEL_COUNT:
            raise HidError('DETECT_BAD_CHANNEL',
                           f'channel must be 1..{CHANNEL_COUNT}, got {channel}',
                           {'channel': channel})
        with self._lock:
            self._detect_channel = int(channel)
            self._detect_lo = []
            self._detect_hi = []
            self._detect_result = None

    def cancel_detect(self) -> None:
        with self._lock:
            self._detect_channel = None
            self._detect_lo = []
            self._detect_hi = []

    def _observe_detect(self, axes, buttons, prev_buttons) -> None:
        """Called from update_axes, under the lock, once per report."""
        ch = self._detect_channel
        if ch is None:
            return
        # A rising edge on any button settles it at once.
        for i, now in enumerate(buttons):
            was = prev_buttons[i] if i < len(prev_buttons) else False
            if now and not was:
                self._finish_detect(ch, {'source': SOURCE_BUTTON, 'index': i,
                                         'mode': BUTTON_MOMENTARY,
                                         'low': crsf.CRSF_MIN, 'high': crsf.CRSF_MAX})
                return
        if len(self._detect_lo) != len(axes):
            self._detect_lo = list(axes)
            self._detect_hi = list(axes)
            return
        best_i, best_travel = None, 0
        for i, v in enumerate(axes):
            if v < self._detect_lo[i]: self._detect_lo[i] = v
            if v > self._detect_hi[i]: self._detect_hi[i] = v
            travel = self._detect_hi[i] - self._detect_lo[i]
            if travel > best_travel:
                best_i, best_travel = i, travel
        if best_i is not None and best_travel >= DETECT_MIN_TRAVEL:
            self._finish_detect(ch, {'source': SOURCE_AXIS, 'index': best_i})

    def _finish_detect(self, channel: int, entry: dict) -> None:
        """Assign the winner and stop listening. Caller holds the lock."""
        entries = list(self._map.entries)
        entries[channel - 1] = entry
        self._map = ChannelMap(entries)
        self._detect_channel = None
        self._detect_lo = []
        self._detect_hi = []
        self._detect_result = {'channel': channel, **entry}
        # A remap drops latches for the usual reason; doing it inline because the
        # lock is already held here.
        self._latched = {}
        self._prev_buttons = []

    def _reset_latches(self) -> None:
        """Drop every latched button to OFF.

        THIS IS A SAFETY PROPERTY, not housekeeping. A latched channel is usually
        ARM. If the latch survived a stop, a remap or a reader change, the operator
        could stop transmitting with ARM latched on, change something, start again,
        and have the aircraft armed from the first frame without touching a button.
        So the latch is dropped whenever the thing that produced it is no longer the
        thing that will consume it.
        """
        self._latched = {}
        self._prev_buttons = []

    def set_channel_map(self, channel_map: 'ChannelMap') -> None:
        with self._lock:
            if self._hid_source:
                layout=self._hid_source['layout']
                for entry in channel_map.entries:
                    if not entry or entry.get('source') not in ('axis','button'):continue
                    items=layout['axes' if entry['source']=='axis' else 'buttons'];index=entry.get('index')
                    if type(index) is not int or not 0<=index<len(items):raise HidError('HID_MAPPING_INPUT_MISSING','Mapped input is absent from descriptor')
                    if entry.get('input_id') not in (None,items[index]['input_id']):raise HidError('HID_MAPPING_IDENTITY_CHANGED','Mapping belongs to another HID input')
                    entry['input_id']=items[index]['input_id']
            self._map = channel_map
            self._mapping_review = None
        self._reset_latches()

    @property
    def channel_map(self) -> 'ChannelMap':
        return self._map

    def update_axes(self, axes, *, buttons=None, source: str | None = None, _epoch=None) -> None:
        """Latest stick positions, already normalized to 0..2048."""
        if self._hid_source and _epoch!=self._hid_source.get('epoch'):
            raise HidError('HID_EPOCH_REQUIRED','Unscoped input cannot replace an identity-bound reader')
        vals = [max(NORMALIZED_MIN, min(NORMALIZED_MAX, int(a))) for a in axes]
        if not vals:
            raise HidError('HID_NO_AXES', 'no axes were supplied', {'axes': 0})
        # THERE IS NO EIGHT-AXIS MINIMUM, and there should never have been one.
        #
        # It was removed after a seven-axis gamepad was refused on the bench. The
        # rule looked like a safety property and was not one: this stream does not
        # build frames positionally from axes, it resolves them through a CHANNEL
        # MAP (`self._map.resolve`), and a map entry may be an axis, a BUTTON or a
        # FIXED value. A seven-axis stick with buttons fills sixteen channels
        # perfectly well.
        #
        # The two real protections are untouched and are what actually matter:
        #   * ChannelMap.resolve raises MAP_AXIS_MISSING if a channel is mapped to
        #     an axis this device does not report -- so a stale map against a
        #     smaller stick is caught per channel, by name;
        #   * the stream refuses to run at all while any channel is unassigned,
        #     because centre is a real switch position and channel 5 is commonly
        #     ARM.
        #
        # `crsf.build_from_axes` still requires eight. That is correct and is left
        # alone: it is the vendor's POSITIONAL helper, which maps eight axes onto
        # the first eight channels and centres the rest, and with fewer than eight
        # it genuinely has nothing to put in a channel.
        with self._lock:
            # Keep every axis, not just the first eight: a channel map may reference
            # axis 8 or beyond, and a three-position switch is often a high axis.
            if self._hid_source and _epoch!=self._hid_source.get('epoch'):
                raise HidError('HID_SOURCE_CHANGED','Reader changed before sample commit')
            self._axes = vals
            if self._calibrating and self._calibration:
                self._calibration.observe(vals)
            new_buttons = [bool(b) for b in (buttons or [])]
            # RISING EDGE ONLY, computed once per report. A held button must not
            # re-toggle on every frame.
            for i, now in enumerate(new_buttons):
                was = self._prev_buttons[i] if i < len(self._prev_buttons) else False
                if now and not was:
                    self._latched[i] = not self._latched.get(i, False)
            self._observe_detect(vals, new_buttons, self._prev_buttons)
            self._prev_buttons = new_buttons
            self._buttons = new_buttons
            self._axes_at = time.monotonic()
            self._source = source
            self._halt_reason = None

    def start(self, *, rate_hz: int | None = None, output_scope=None) -> dict:
        with self._lock:
            if self.running:
                return self.state()
            if self._axes is None:
                raise HidError('HID_NO_AXES',
                               'no stick positions have been reported yet, so there is '
                               'nothing to stream')
            if not self._map.complete:
                raise HidError('MAP_INCOMPLETE',
                               'channels ' +
                               ', '.join(str(c) for c in self._map.unassigned) +
                               ' have no assignment. Assign every channel before '
                               'transmitting -- an unassigned channel is not centred, '
                               'because centre is a real switch position and channel 5 '
                               'is commonly ARM.',
                               {'unassigned': self._map.unassigned})
            # Prove the map resolves against this device before the thread starts,
            # so a missing axis is a refusal rather than a stream that dies one
            # frame in.
            self._map.resolve(self._calibrated(self._axes), self._buttons, self._latched)
            if rate_hz is not None:
                self._rate_hz = self._clamp_rate(rate_hz)
            self._output_scope=output_scope
            self._stop.clear()
            self._sent = 0
            self._last_error = None
            self._halt_reason = None
            self._started_at = time.time()
            self._thread = threading.Thread(target=self._run, name='crsf-stream', daemon=True)
            self._thread.start()
        return self.state()

    def stop(self, reason: str = 'stopped by request') -> dict:
        self._stop.set()
        t = self._thread
        if t and t.is_alive():
            t.join(timeout=2.0)
        with self._lock:
            self._halt_reason = reason
        # A stop must not leave ARM latched for the next start. See _reset_latches.
        self._reset_latches()
        return self.state()

    def _run(self) -> None:
        period = 1.0 / self._rate_hz
        nxt = time.monotonic()
        while not self._stop.is_set():
            with self._lock:
                axes, at = self._axes, self._axes_at
                buttons, cmap = list(self._buttons), self._map
                stale_after = self._stale_after
            age = time.monotonic() - at
            if axes is None or age > stale_after:
                # Stop rather than hold or centre. See the module docstring.
                with self._lock:
                    self._stale_stops += 1
                    self._halt_reason = (
                        f'stick positions went stale ({age * 1000:.0f} ms since the last '
                        f'update, limit {stale_after * 1000:.0f} ms) -- transmission '
                        f'stopped so the receiver\'s own failsafe takes over')
                return
            try:
                frame = crsf.build_rc_channels(
                    cmap.resolve(self._calibrated(axes), buttons, self._latched))
                self._send(frame)
                with self._lock:
                    self._sent += 1
                    self._last_frame_hex = frame.hex(' ').upper()
            except Exception as e:
                with self._lock:
                    self._last_error = f'{type(e).__name__}: {e}'
                    self._halt_reason = 'send failed'
                return
            nxt += period
            delay = nxt - time.monotonic()
            if delay > 0:
                self._stop.wait(delay)
            else:
                nxt = time.monotonic()      # fell behind; do not burst to catch up

    def state(self) -> dict:
        with self._lock:
            age = (time.monotonic() - self._axes_at) if self._axes else None
            profile=hid_source.recognition(self._hid_source.get('device',{}),self._hid_source.get('layout',{}))['profile_kind']
            return {
                'running': self.running, 'rate_hz': self._rate_hz,
                'source_identity': copy.deepcopy(self._hid_source),
                'mapping_revalidation': copy.deepcopy(self._mapping_review),
                'hat_inputs': [dict(item,mapping_supported=False,sample_observed=False) for item in self._hid_source.get('layout',{}).get('hats',[])],
                'button_inputs': [dict(item,pressed=self._buttons[i] if i<len(self._buttons) else None,
                                  logical_channel=f"CH{item['usage']+8}" if profile=='edgetx_classic' else None)
                                  for i,item in enumerate(self._hid_source.get('layout',{}).get('buttons',[]))],
                'inputs': [dict(item,normalized=self._axes[i] if self._axes else None,
                            raw=self._raw_axes[i] if i<len(self._raw_axes) else None,
                            logical_channel=(f"CH{item['usage']-0x30+1}" if profile=='edgetx_classic' and item['usage_page']==1 and 0x30<=item['usage']<=0x37 else None))
                           for i,item in enumerate(self._hid_source.get('layout',{}).get('axes',[]))],
                'stale_after_ms': int(self._stale_after * 1000),
                'axes': list(self._axes) if self._axes else None,
                'axes_age_ms': int(age * 1000) if age is not None else None,
                'axes_stale': bool(age is not None and age > self._stale_after),
                'source': self._source, 'frames_sent': self._sent,
                'stale_stops': self._stale_stops, 'last_error': self._last_error,
                'last_frame_hex': self._last_frame_hex, 'started_at': self._started_at,
                'halt_reason': self._halt_reason,
                'channels': (self._map.resolve(self._calibrated(self._axes), self._buttons, self._latched)
                             if (self._axes and self._map.complete) else None),
                'calibrated_axes': self._calibrated(self._axes) if self._axes else None,
                'calibrating': self._calibrating,
                'calibration': self._calibration.state() if self._calibration else None,
                'channel_map': self._map.describe(),
                'map_complete': self._map.complete,
                'detecting': self._detect_channel,
                'detect_result': self._detect_result,
                'detect_min_travel': DETECT_MIN_TRAVEL,
                'map_unassigned': self._map.unassigned,
                'buttons': list(self._buttons),
                'failsafe_note': (
                    'Transmission STOPS when the stick positions go stale rather than '
                    'holding them or sending centre. Centre is a real command; silence '
                    'lets the receiver\'s own configured failsafe take over. CGC has no '
                    'staleness handling -- this is ours.'),
            }


def selftest() -> dict:
    assert normalize_to_2048(0, 0, 255) == 0
    assert normalize_to_2048(255, 0, 255) == 2048
    assert normalize_to_2048(128, 0, 255) == 1028          # round-to-nearest
    assert normalize_to_2048(5, 10, 20) == 0               # clamped low
    assert normalize_to_2048(1, 5, 5) == 0                 # degenerate range
    assert axis_name(0x010030) == 'X' and axis_name(0x010035) == 'Rz'
    assert is_axis_usage(0x010030) and not is_axis_usage(0x010041)
    assert is_button_usage(0x090001)
    ch = axes_to_crsf([1024] * 8)
    assert ch[:8] == [crsf.CRSF_MID] * 8 and ch[8:] == [crsf.CRSF_MID] * 8
    return {'ok': True}


if __name__ == '__main__':
    print(selftest())


# --------------------------------------------------------------------------- #
# Calibration -- ours. CGC has none.
# --------------------------------------------------------------------------- #
#
# CGC's "JoyCalib" button does not calibrate: it switches to the binding view. Its
# parser hardcodes every axis to 0..2048 and trusts the descriptor's declared
# logical range.
#
# That is fine until a stick does not reach its own declared endpoints, which is
# the normal condition of cheap gimbals and of any stick with mechanical wear. The
# symptom is the one that matters: full deflection does not produce full CRSF
# travel, so the aircraft never sees 100% roll, and on a throttle axis the arm
# position may be unreachable.
#
# So this records what the stick ACTUALLY produces -- observed minimum, maximum and
# resting centre per axis -- and rescales against that instead of the declaration.
#
# It is deliberately not automatic. A calibration captured while a stick happened to
# be held off-centre would bake that in, so the operator starts it, sweeps every
# axis, and the result is only usable once each axis has seen enough travel.

# An axis must show at least this much of the normalized range before its
# calibration is trusted. Below it, the operator did not actually move that axis.
MIN_CALIBRATION_TRAVEL = 400          # of 2048


class AxisCalibration:
    """Observed travel per axis, captured while the operator sweeps the sticks."""

    def __init__(self, axis_count: int):
        self.axis_count = int(axis_count)
        self.lo = [None] * self.axis_count
        self.hi = [None] * self.axis_count
        self.centre = [None] * self.axis_count
        self.samples = 0

    def observe(self, axes) -> None:
        for i, raw in enumerate(list(axes)[:self.axis_count]):
            v = int(raw)
            self.lo[i] = v if self.lo[i] is None else min(self.lo[i], v)
            self.hi[i] = v if self.hi[i] is None else max(self.hi[i], v)
        self.samples += 1

    def mark_centre(self, axes) -> None:
        """Record the resting position. Taken on request, with sticks released."""
        for i, raw in enumerate(list(axes)[:self.axis_count]):
            self.centre[i] = int(raw)

    def travel(self, i: int) -> int:
        if self.lo[i] is None or self.hi[i] is None:
            return 0
        return self.hi[i] - self.lo[i]

    def usable(self, i: int) -> bool:
        return self.travel(i) >= MIN_CALIBRATION_TRAVEL

    def apply(self, axes) -> list[int]:
        """Rescale observed travel back onto the full 0..2048 range.

        An axis without enough observed travel is passed through untouched rather
        than rescaled from a narrow window -- amplifying noise into full-scale
        control output is worse than leaving the axis uncalibrated.
        """
        out = []
        for i, raw in enumerate(list(axes)):
            v = int(raw)
            if i >= self.axis_count or not self.usable(i):
                out.append(max(NORMALIZED_MIN, min(NORMALIZED_MAX, v)))
                continue
            lo, hi = self.lo[i], self.hi[i]
            v = max(lo, min(hi, v))
            out.append(round((v - lo) * NORMALIZED_MAX / (hi - lo)))
        return out

    def state(self) -> dict:
        return {
            'axis_count': self.axis_count, 'samples': self.samples,
            'min_travel_required': MIN_CALIBRATION_TRAVEL,
            'axes': [{'axis': i, 'observed_min': self.lo[i], 'observed_max': self.hi[i],
                      'centre': self.centre[i], 'travel': self.travel(i),
                      'usable': self.usable(i)} for i in range(self.axis_count)],
            'complete': all(self.usable(i) for i in range(self.axis_count)),
            'note': ('Observed travel, not the declared descriptor range. An axis '
                     'that has not moved far enough is passed through uncalibrated '
                     'rather than rescaled from a narrow window, because amplifying '
                     'noise into full-scale control output is worse than no '
                     'calibration. CGC does not calibrate at all -- its parser '
                     'trusts the descriptor.'),
        }

    def to_dict(self) -> dict:
        return {'axis_count': self.axis_count, 'lo': self.lo, 'hi': self.hi,
                'centre': self.centre, 'samples': self.samples}

    @classmethod
    def from_dict(cls, doc: dict) -> 'AxisCalibration':
        c = cls(int(doc.get('axis_count') or 0))
        for field in ('lo', 'hi', 'centre'):
            vals = doc.get(field) or []
            setattr(c, field, [vals[i] if i < len(vals) else None
                               for i in range(c.axis_count)])
        c.samples = int(doc.get('samples') or 0)
        return c
