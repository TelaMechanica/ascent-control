"""Typed read-only vendor diagnostics. No sockets, timers, caches or RF writes.

Layouts independently checked against pinned Gnd485 and MAX-HF reference ELFs.
0x0100000f is NOT the 22-byte record described by the supplied research parser.
Only explicit supported GET contracts below may reach the borrowed RPC transport.
"""
from dataclasses import asdict, dataclass
import struct
import caddx_fw_version as fwver
from typing import Literal

SCHEMA = 'ascent.telemetry.v1'
REFERENCE_GND = '5b745a0c57c8a516c858441f75daab9bb2c8b9c1fe468ffdfa5759549dc19d67'
REFERENCE_MAX = '313102f1bfdf3be77a90e2b6bb17eacd94431aeb40ccf54cdcf8c349038e0bef'
DiagnosticState = Literal['valid_decode', 'partial_decode', 'stale', 'unavailable', 'disconnected', 'unsupported']

@dataclass(frozen=True)
class ReadSpec:
    command: int
    request: bytes
    response_size: int

# Explicit fixed GETs, never generic ioctl/socket-open or caller-selected command.
READS = {
    'status': ReadSpec(0x01000000,b'\0\0',300),
    'debug_rf': ReadSpec(0x0100006b,b'\0\0\0\0',216),
    'work_channels': ReadSpec(0x01000012,b'',129),
}

class TelemetryError(ValueError):
    def __init__(self, code, message, evidence=None):
        self.code=code
        self.evidence=evidence or {}
        super().__init__(message)

@dataclass(frozen=True)
class RfEnd:
    snr_raw: int
    ldpc_tlv_err_raw: int
    ldpc_num_err_raw: int
    agc_a_raw: int
    agc_b_raw: int
    tx_mcs_raw: int
    tx_channel_id_raw: int
    tx_power_raw: int


def _exact(payload, size):
    if not isinstance(payload,bytes) or len(payload)!=size:
        raise TelemetryError('TELEMETRY_SIZE_MISMATCH',f'Expected exactly {size} payload bytes.')


def parse_debug_rf(payload: bytes) -> dict:
    """0x6b,216 bytes; first11 bytes at0/76. The remainder stays uninterpreted.

    Raw widths only: no SNR divisor, calibrated RSSI, dBm or loss percentage.
    Two modulo-u16 fields do not establish counter lifetime/reset semantics.
    """
    _exact(payload,216)
    return {name:asdict(RfEnd(*struct.unpack_from('<HHHBBBBB',payload,offset)))
            for name,offset in [('local_ground',0),('peer',76)]}


def parse_work_channels(payload: bytes) -> dict:
    _exact(payload,129)
    count=payload[0]
    if count>128:
        raise TelemetryError('TELEMETRY_COUNT_INVALID','Work channel count exceeds the128-entry record.')
    # IDs, not MHz. Preserve order/duplicates; no guessed frequency conversion.
    return dict(channel_ids=list(payload[1:1+count]),count=count,units='channel_id',
                frequency_mhz=None,scope='runtime_active_baseband_channels',
                comparison='Separate from firmware-supported channels, RF calibration coverage and UI-selectable frequencies.')


def parse_rf_info(payload: bytes):
    raise TelemetryError('RF_INFO_LAYOUT_CONFLICT','0x0100000f is4 bytes in the reference ioctl tables; the supplied22-byte decoder is blocked.')


def parse_distance(payload: bytes):
    # The reference response is32 bytes, not the supplied four-byte contract.
    raise TelemetryError('DISTANCE_LAYOUT_UNQUALIFIED','Distance selector, full32-byte structure and model correction require qualification.')


def profile(identity):
    name=str((identity or {}).get('device_name') or '').lower()
    firmware=fwver.parse((identity or {}).get('firmware'))
    if name=='ascent_vrx_max_hf' and firmware==(19,2,14):
        return dict(name='MAX-HF19.2.14 reference layout',reference_sha256=REFERENCE_MAX)
    if name in {'ascent_g_gnd','ascent_g_gnd_19_2_4','ascent_gnd485'} and firmware==(19,2,4):
        return dict(name='Gnd48519.2.4 reference layout',reference_sha256=REFERENCE_GND)
    return None


def describe(identity=None, *, connected=False):
    supported=profile(identity)
    return dict(schema=SCHEMA,state='unavailable' if connected and supported else 'unsupported' if connected else 'disconnected',
        eligible=bool(connected and supported),profile=supported,
        operation='manual_read_only',automatic_polling=False,baseband_measurement_interval_ms=None,
        qualification='Static reference layout plus reported model/version and strict wire validation; installed ELF not attested.',
        note='Receipt/decode is not measurement freshness. Raw SNR/AGC and counters have no calibrated dB/dBm/loss conversion.',
        blocked={'rf_info':'Conflicting supplied layout;4-byte reference response.',
                 'snr_db':'Scaling unqualified.','rssi_dbm':'No calibrated RSSI field.',
                 'tx_power_dbm':'Wire-field units not independently qualified.',
                 'temperature_c':'No qualified RPC layout.','latency_ms':'GUI formatting is not a wire schema.',
                 'bitrate_mbps':'No qualified RPC layout.','distance_m':'Full32-byte response/selector and correction unqualified.',
                 'fec_loss_percent':'No denominator or qualified counter lifetime.'})
