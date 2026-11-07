#!/usr/bin/env python3
"""Stock-Caddx persistent BB-frequency write transport.

This module implements only the recovered SET_BB_FREQ transaction.  It is not a
filesystem API and deliberately exposes no caller-controlled device path.

Recovered from Caddx PC Tool 2.0.51 -- the reference build. 2.0.37 has no
FpvSkyRfBoardName entry for RFBoardType 160 and therefore cannot write an RF table
to this project's hardware at all (docs/PROTOCOL_SPEC.md section 9.1). The opcode
set and wire structs are identical across both builds.

    115  SENDFILE_START  ArFileInfo (328 bytes) for /factory/fpv_bb_freq.json
    116  SENDFILE_DATA   raw JSON bytes -- always exactly ONE frame in the RF lane
    117  SENDFILE_END    empty payload
    121  SET_BB_FREQ     empty payload; the commit itself
      3  REBOOT          32-byte zero mode, fire-and-forget, sent by Reopen_Json

The same serial session is used for a fresh command-60 identity and command-120
verified read immediately before the write.

Retries allocate a NEW sequence number and increment the header `retry` field; the
vendor AckGuard re-points at the newest seq. They do NOT reuse the original request
sequence -- docs/PROTOCOL_SPEC.md section 6.

Readback verification after the commit is OURS, not stock: the vendor tool performs
no readback at all. So is preserving key order and unknown vendor fields -- the
vendor rebuilds the document. Both are deliberate improvements per CLAUDE.md, and
neither may be described as vendor parity.
"""
from __future__ import annotations

import hashlib
import json
import re
import struct
import time
from dataclasses import dataclass
from typing import Callable, Iterable

from caddx_read_bundle import (
    ArHeader,
    Decoder,
    WinSerial,
    crc32_vendor,
    parse_bb_freq,
    parse_device_info,
    verify_cmd115_md5,
)

MAGIC = 0x4152544F
VERSION = 3292
HEADER = struct.Struct('<IHHHHIHHIIII')
HEADER_SIZE = HEADER.size
REMOTE_RF_PATH = '/factory/fpv_bb_freq.json'
REMOTE_RF_FILENAME = 'fpv_bb_freq.json'
# ArFileInfo.fileDir carries the PC-SIDE LOCAL PATH, forward-slash normalized -- not
# the remote basename. FileTransferSession.BuildFileInfo does
# `LocalPath.Replace('\\','/')`, and 2.0.51 confirms the semantics by truncating it to
# the LAST 128 chars, which is only meaningful for a path.
# docs/PROTOCOL_SPEC.md section 4. The vendor's own value for this exact transfer is
# `resource/param/fpv_bb_freq.bin` (updateChannel.cs:480, BBFreqTemplatePath).
VENDOR_LOCAL_RF_PATH = 'resource/param/fpv_bb_freq.bin'
FILE_INFO_DIR_MAX = 128
# 3 = AR_COMMAND_REBOOT. Part of the commit path: Reopen_Json sends it with a 32-byte
# zero mode immediately after the 121 ACK (docs/PROTOCOL_SPEC.md section 7).
ALLOWED_COMMANDS = frozenset((3, 60, 115, 116, 117, 120, 121))
REBOOT_MODE_NORMAL = b'\0' * 32     # ArDeviceReboot.mode[32]; "clean" is the firmware lane
MAX_RF_JSON = 64 * 1024

# Reopen_Json timings, docs/PROTOCOL_SPEC.md section 7.
#   send cmd 3 -> sleep 500 ms -> Close() -> sleep settle -> poll Open until budget
# Settle is 11000 ms: 2.0.51's per-model table gives ascent_vrx_max_wf = 11000, which is
# the vendor's own intent for this unit (the shipped flat value is 10000).
# The poll budget is 110 s and is measured FROM AFTER THE SETTLE, because the vendor's
# ReOpenTimeout_Asce window starts after its settle sleep. That is why the observed
# 107 s reconnect is a legal success and 100 s is the wrong deadline.
REBOOT_SEND_SETTLE = 0.5
RECONNECT_SETTLE = 11.0
RECONNECT_POLL_BUDGET = 110.0
RECONNECT_POLL_INTERVAL = 1.0       # vendor ReElectDelay
# RecvLoop discards any frame whose header+payload exceeds this (UsbSerialportFSM.cs:478).
MAX_FRAME_TOTAL = 5120
AR_FILE_INFO = struct.Struct('<64sii128s128s')


class CaddxWriteError(RuntimeError):
    """Fail-closed error for a qualified vendor write transaction."""

    def __init__(self, code: str, message: str, *, stage: str | None = None, evidence: dict | None = None):
        super().__init__(message)
        self.code = code
        self.stage = stage
        self.evidence = evidence or {}


@dataclass(frozen=True)
class WriteProfile:
    operation_id: str
    raw_device_name: str
    firmware: str
    hardware: str
    vid: str
    pid: str
    rf_board_code: int


# First promoted write profile is intentionally exact.  These values are the
# hardware-shaped VRX Max WF identity already represented by the project's real
# command-60/120 bench fixture.  Add another profile only when that exact profile
# has operation-specific evidence; never normalize marketing names into this key.
RF_WRITE_PROFILES = (
    WriteProfile(
        operation_id='persistent_rf_table_write',
        raw_device_name='Ascent_VRX_max_WF',
        firmware='Ascent_VRX_Max_19_2_4',
        hardware='Ascent-VRX-Max-V2.2-10.0',
        vid='1D77',
        pid='A4A2',
        rf_board_code=0xA0,
    ),
)


def _ascii_fixed(value: str | bytes, size: int) -> bytes:
    raw = value if isinstance(value, bytes) else value.encode('ascii', 'strict')
    if len(raw) > size:
        raise CaddxWriteError('FILE_INFO_FIELD_TOO_LONG', f'vendor file-info field exceeds {size} bytes', stage='prepare')
    return raw + b'\0' * (size - len(raw))


# The ONLY remote paths this application will ever name in ArFileInfo.filePath.
#
# ArFileInfo.filePath is the field the public rooting exploit abuses
# (CLAUDE.md section Authorization (a): command injection through
# `ArFileInfo.filePath` on the 114/115/116/117 lane), and CLAUDE.md "Do not" forbids
# exposing arbitrary filesystem writes. So this stays a closed allowlist of literals,
# never a caller-supplied path, never a prefix test, never a join. Widening it is a
# deliberate act that needs its own vendor citation, which is why each entry carries one.
#
#   fpv_bb_freq.json  RF band table      -- empty 121 commit follows the transfer
#   mipi_hub.json     camera hub inputs  -- no commit opcode; transfer IS the commit
#   msp_rc_cfg.json   RC/MSP assignments -- no commit opcode; transfer IS the commit
#
# The two additions are the vendor's own JSON lane: SetFilePath_Json builds the remote
# name as "/factory/" + Path.GetFileName(localPath) (UpgradeProcessFSM.cs:100-107) over
# the shipped config values resource\param\mipi_hub.json and
# resource\param\msp_rc_cfg.json. See runtime/caddx_device_config.py.
ALLOWED_REMOTE_PATHS = {
    REMOTE_RF_PATH: VENDOR_LOCAL_RF_PATH,
    '/factory/mipi_hub.json': 'resource/param/mipi_hub.json',
    '/factory/msp_rc_cfg.json': 'resource/param/msp_rc_cfg.json',
}


def build_file_info(payload: bytes, *, remote_path: str = REMOTE_RF_PATH,
                    file_dir: str = VENDOR_LOCAL_RF_PATH) -> bytes:
    """Build vendor ArFileInfo (328 bytes) for one of the three allowed resources.

    Field semantics per docs/PROTOCOL_SPEC.md section 4:
      MD5[64]     32 lowercase ASCII hex of the payload, NUL-padded
      length      payload length
      saveAsFile  1
      filePath    remote destination; must be a literal from ALLOWED_REMOTE_PATHS
      fileDir     PC-side local path, forward-slash normalized, last 128 chars
    """
    if remote_path not in ALLOWED_REMOTE_PATHS:
        raise CaddxWriteError(
            'DEVICE_PATH_NOT_ALLOWED',
            f'{remote_path!r} is not one of the three writable stock resources',
            stage='prepare',
            evidence={'allowed': sorted(ALLOWED_REMOTE_PATHS)})
    raw = bytes(payload)
    digest = hashlib.md5(raw).hexdigest().encode('ascii')
    # Mirror the 2.0.51 truncation: keep the LAST 128 characters of the local path.
    local = str(file_dir).replace('\\', '/')
    if len(local) > FILE_INFO_DIR_MAX:
        local = local[-FILE_INFO_DIR_MAX:]
    return AR_FILE_INFO.pack(
        _ascii_fixed(digest, 64),
        len(raw),
        1,  # saveAsFile
        _ascii_fixed(remote_path, 128),
        _ascii_fixed(local, 128),
    )


def build_request(command: int, payload: bytes = b'', *, seq: int = 0, retry: int = 0) -> bytes:
    if command not in ALLOWED_COMMANDS:
        raise ValueError(f'command {command} is outside the fixed Caddx parity transport')
    p = bytes(payload)
    if len(p) > MAX_RF_JSON and command == 116:
        raise CaddxWriteError('RF_TABLE_TOO_LARGE', 'RF table exceeds the bounded vendor write size', stage='prepare')
    h0 = HEADER.pack(MAGIC, VERSION, 1, 0, 0xABCD, command, 2, 0, len(p), seq & 0xffffffff, retry & 0xffffffff, 0)
    crc = crc32_vendor(h0, p)
    return HEADER.pack(MAGIC, VERSION, 1, 0, 0xABCD, command, 2, 0, len(p), seq & 0xffffffff, retry & 0xffffffff, crc) + p


def parse_ack68(payload: bytes) -> dict:
    if len(payload) < 68:
        raise CaddxWriteError('SHORT_VENDOR_ACK', f'expected 68-byte vendor ACK, received {len(payload)}', stage='ack')
    status = int.from_bytes(payload[:4], 'little', signed=True)
    detail = payload[4:68].split(b'\0', 1)[0].decode('ascii', 'replace').rstrip(' \r\n\t')
    return {'status': status, 'detail': detail, 'payload_length': len(payload)}


def parse_file_data80(payload: bytes) -> dict | None:
    if len(payload) < 80:
        return None
    length, cursize, totalsize, status = struct.unpack_from('<iiii', payload, 0)
    detail = payload[16:80].split(b'\0', 1)[0].decode('ascii', 'replace').rstrip(' \r\n\t')
    return {'length': length, 'cursize': cursize, 'totalsize': totalsize,
            'status': status, 'detail': detail, 'payload_length': len(payload)}


BAND_TOTAL_MAX = 120        # updateChannel.cs:23 TOTALMAXCOUNT
BAND_SINGLE_MAX = 36        # updateChannel.cs:21 SINGLEMAXCOUNT
FREQ_STEP_KHZ = 1000        # ValidateAllValueKHz: every value % 1000 == 0


def is_band_key(key) -> bool:
    return str(key).lower().startswith('band')


def validate_band_list(key: str, values: list) -> None:
    """Vendor editor rules, recovered in docs/PROTOCOL_SPEC.md section 8.

    `ValidateAllValueKHz` (updateChannel.cs:838-885) drops the LAST element before
    validating: it is a per-band default/fallback frequency, not a channel. After
    the drop, values[0] must be the minimum, values[-1] the maximum, every value a
    multiple of 1000 kHz, and no duplicates.
    """
    if not isinstance(values, list) or len(values) < 2:
        raise CaddxWriteError('RF_BAND_INVALID', f'{key} must be a list of at least two entries', stage='prepare')
    if len(values) > BAND_SINGLE_MAX + 1:
        raise CaddxWriteError('RF_BAND_TOO_LONG',
                              f'{key} has {len(values) - 1} channels; the vendor single-band maximum is {BAND_SINGLE_MAX}',
                              stage='prepare')
    for item in values:
        if isinstance(item, bool) or not isinstance(item, int):
            raise CaddxWriteError('RF_FREQUENCY_NOT_INTEGER', f'{key} contains a non-integer frequency', stage='prepare')
        if item < 1_000_000 or item > 8_000_000:
            raise CaddxWriteError('RF_FREQUENCY_OUT_OF_RANGE',
                                  f'{key} contains a value outside the bounded 1-8 GHz kHz domain', stage='prepare')
        if item % FREQ_STEP_KHZ != 0:
            raise CaddxWriteError('RF_FREQUENCY_NOT_MULTIPLE',
                                  f'{key} value {item} is not a multiple of {FREQ_STEP_KHZ} kHz', stage='prepare')
    channels = values[:-1]          # trailing entry is the per-band default, not a channel
    if len(set(channels)) != len(channels):
        raise CaddxWriteError('RF_FREQUENCY_DUPLICATED', f'{key} contains duplicate channel frequencies', stage='prepare')
    if channels[0] != min(channels):
        raise CaddxWriteError('RF_BAND_MIN_NOT_FIRST', f'{key} first channel must be the band minimum', stage='prepare')
    if channels[-1] != max(channels):
        raise CaddxWriteError('RF_BAND_MAX_NOT_LAST', f'{key} last channel must be the band maximum', stage='prepare')
    if channels[0] >= channels[-1]:
        raise CaddxWriteError('RF_BAND_RANGE_DEGENERATE', f'{key} minimum must be below its maximum', stage='prepare')


def validate_band_collection(table, *, stage: str = 'prepare') -> int:
    """The single authoritative band-set validator. Returns the total channel count.

    Every caller that checks band arrays -- the write path's serializer and the local
    band-plan store -- goes through this one function, so a plan can never be accepted
    under rules the writer would reject, or refused under rules the writer allows.
    It applies `validate_band_list` per band plus the vendor's cross-band total
    (updateChannel.cs:23 TOTALMAXCOUNT), counting the trailing per-band default as a
    default and not as a channel.

    `table` may be a full RF document or a bare {band: [...]} mapping; only band keys
    are considered either way.
    """
    if not isinstance(table, dict):
        raise CaddxWriteError('RF_TABLE_NOT_OBJECT', 'RF table must be a JSON object', stage=stage)
    band_keys = [k for k in table if is_band_key(k)]
    if not band_keys:
        raise CaddxWriteError('RF_NO_BANDS', 'RF table contains no band arrays', stage=stage)
    total = 0
    for key in band_keys:
        validate_band_list(key, table[key])
        total += len(table[key]) - 1               # trailing default is not a channel
    if total > BAND_TOTAL_MAX:
        raise CaddxWriteError('RF_TOTAL_CHANNELS_EXCEEDED',
                              f'total channels across all bands is {total}; the vendor maximum is {BAND_TOTAL_MAX}',
                              stage=stage)
    return total


def merge_rf_table(edits: dict, baseline: dict) -> dict:
    """Apply band edits onto the live table, preserving key order and unknown fields.

    CLAUDE.md requires the write to preserve raw ordering and unknown vendor fields.
    That is deliberately STRICTER than the vendor tool, which rebuilds the document
    from scratch and hoists RFBoardType/is_defalut to the front
    (docs/PROTOCOL_SPEC.md section 8). We therefore start from the *baseline* -- the
    exact live command-116 document -- and overwrite only the band arrays the caller
    edited. Every other key keeps both its value and its original position, whether
    or not we understand it.

    `edits` may name only the bands it changes. A key absent from `baseline` is
    refused: the write path never introduces new top-level fields.
    """
    if not isinstance(edits, dict) or not isinstance(baseline, dict):
        raise CaddxWriteError('RF_TABLE_NOT_OBJECT', 'RF table must be a JSON object', stage='prepare')
    unknown_new = [k for k in edits if k not in baseline]
    if unknown_new:
        raise CaddxWriteError('RF_TABLE_UNKNOWN_KEY',
                              f'refusing to introduce top-level key(s) absent from the live table: {", ".join(map(str, unknown_new))}',
                              stage='prepare')
    merged: dict = {}
    for key, live_value in baseline.items():          # baseline order is authoritative
        if key in edits:
            if is_band_key(key):
                merged[key] = list(edits[key])
            elif edits[key] != live_value:
                raise CaddxWriteError('RF_NON_BAND_FIELD_CHANGE_BLOCKED',
                                      f'{key} is not a band array and cannot be changed by this operation',
                                      stage='prepare')
            else:
                merged[key] = live_value
        else:
            merged[key] = live_value
    return merged


def serialize_rf_table(table: dict, baseline: dict) -> bytes:
    """Serialize an RF table for the wire, preserving baseline key order.

    `table` may be either a full document or a band-edit subset; either way the
    result is ordered by `baseline` and carries every baseline field.
    """
    merged = merge_rf_table(table, baseline)
    if merged.get('RFBoardType') != baseline.get('RFBoardType'):
        raise CaddxWriteError('RF_BOARD_TYPE_CHANGE_BLOCKED', 'RFBoardType cannot be changed by the frequency-table operation', stage='prepare')
    if not isinstance(merged.get('RFBoardType'), int) or isinstance(merged.get('RFBoardType'), bool):
        raise CaddxWriteError('RF_BOARD_TYPE_INVALID', 'RFBoardType must be an integer', stage='prepare')

    validate_band_collection(merged, stage='prepare')

    # The device reads this file with ParseBBFreqConfig (an ASCII decode), so ASCII
    # only. 4-space indent matches the live device document; the vendor tool emits 2,
    # which is one of the reasons byte-parity with the vendor is not claimed.
    raw = json.dumps(merged, ensure_ascii=True, indent=4, separators=(',', ': ')).encode('ascii')
    if len(raw) > MAX_RF_JSON:
        raise CaddxWriteError('RF_TABLE_TOO_LARGE', 'RF table exceeds the bounded vendor write size', stage='prepare')
    # Parse our own output before permitting it onto the wire, order included.
    if not ordered_equal(json.loads(raw.decode('ascii')), merged):
        raise CaddxWriteError('RF_TABLE_SERIALIZATION_FAILED', 'RF table failed serialization round-trip', stage='prepare')
    return raw


def ordered_equal(left, right) -> bool:
    """Deep equality that is sensitive to mapping key order.

    Plain `==` on dicts is order-blind, so it would accept a readback whose keys the
    device had reordered -- a materially different file reported as success. Lists are
    already order-sensitive; this adds the same strictness to objects.
    """
    if isinstance(left, dict) and isinstance(right, dict):
        if list(left.keys()) != list(right.keys()):
            return False
        return all(ordered_equal(left[k], right[k]) for k in left)
    if isinstance(left, dict) or isinstance(right, dict):
        return False
    if isinstance(left, list) and isinstance(right, list):
        if len(left) != len(right):
            return False
        return all(ordered_equal(a, b) for a, b in zip(left, right))
    if isinstance(left, list) or isinstance(right, list):
        return False
    if isinstance(left, bool) != isinstance(right, bool):
        return False
    return left == right


def semantic_equal(left, right) -> bool:
    """Order-aware readback comparison.

    Used to decide "the device now holds what we asked for". It must not be
    order-blind: `{"a":1,"b":2} == {"b":2,"a":1}` is True for dicts, but the two
    serialize to different files with different MD5s, and the RF document's key order
    is something we deliberately preserve. See docs/PROTOCOL_SPEC.md section 8.

    This is the comparison for two documents *we* produced. For a post-write readback
    use `compare_readback()`, which additionally excludes the device-owned fields the
    device rewrites for itself.
    """
    return ordered_equal(left, right)


# ---------------------------------------------------------------------------
# Device-owned fields (bench-established 2026-09-06)
# ---------------------------------------------------------------------------
# Keys inside /factory/fpv_bb_freq.json that the DEVICE owns and rewrites on every
# write. A difference in one of these is never a readback failure.
#
# Bench evidence, Ascent VRX Max WF, first live RF write: the write applied
# correctly and every band array came back exactly as sent, in order -- but the
# verify step raised READBACK_MISMATCH. The only semantic difference in the whole
# document was `is_defalut`: we sent 1 (carried through from the live table, as the
# preservation rule requires) and the device returned 0. The flag means "this file
# is still the untouched factory table", so writing the file necessarily falsifies
# it and the device clears it. See docs/PROTOCOL_SPEC.md section 8.1.
DEVICE_OWNED_KEYS = ('is_defalut',)

# The transition the device is expected to make. Recorded in the write result,
# never gated on -- the band arrays are the proof that a write applied, and no
# field the device owns may be able to fail a write that otherwise verified.
DEVICE_OWNED_EXPECTED = {'is_defalut': 0}


def without_device_owned(table):
    """The document minus device-owned keys, remaining key order untouched."""
    if not isinstance(table, dict):
        return table
    return {k: v for k, v in table.items() if k not in DEVICE_OWNED_KEYS}


def compare_readback(readback, expected) -> dict:
    """Verify a post-write readback against the document we actually serialized.

    Two rules, both learned at the bench and both narrower than they look:

    1. Only the *values* of device-owned keys (`DEVICE_OWNED_KEYS`) are exempt, and
       they are reported separately. Their positions are not: the full key sequence
       still has to line up, so a document normalized vendor-style -- which hoists
       `is_defalut` to the front -- is still a mismatch. A device-owned key the
       device drops entirely is tolerated and recorded. Everything else -- every
       band array, every unknown vendor field, and the order of all of them -- is
       compared with `ordered_equal`. This is deliberately NOT a weakening to
       order-blind `==`; a reordered or altered document still fails.

    2. Nothing here compares payload length or MD5 across the write, and nothing
       may be added that does. The device re-serializes the file itself with no
       indentation -- the bench readback was 1088 bytes against the 2018-byte
       pre-write document -- so the bytes and the digest legitimately differ even
       when the write is perfect. The `115` MD5 is an integrity check *within a
       single read*; it is not a cross-write comparison.

    `expected` must be the merged document that was serialized onto the wire, not
    the caller's request body, which may name only the bands it edits.

    Returns {'match', 'device_owned', 'unexpected_device_owned', 'reason'}.
    """
    if not isinstance(readback, dict) or not isinstance(expected, dict):
        return {'match': False, 'reason': 'RF table readback is not a JSON object',
                'device_owned': [], 'unexpected_device_owned': []}

    device_owned = []
    for key in expected:
        if key not in DEVICE_OWNED_KEYS:
            continue
        present = key in readback
        observed = readback.get(key) if present else None
        anticipated = DEVICE_OWNED_EXPECTED.get(key)
        device_owned.append({
            'key': key,
            'requested': expected[key],
            'observed': observed,
            'present_in_readback': present,
            'device_expected': anticipated,
            'as_documented': present and observed == anticipated,
        })
    unexpected = [d for d in device_owned if not d['as_documented']]

    # Key sequence, device-owned keys included where the device kept them. Only a
    # device-owned key the device dropped outright is forgiven.
    anticipated_keys = [k for k in expected
                        if k in readback or k not in DEVICE_OWNED_KEYS]
    if list(readback.keys()) != anticipated_keys:
        return {'match': False, 'reason': 'readback key order or key set differs from the written table',
                'device_owned': device_owned, 'unexpected_device_owned': unexpected}
    left, right = without_device_owned(readback), without_device_owned(expected)
    if not ordered_equal(left, right):
        return {'match': False, 'reason': 'readback content differs from the written table',
                'device_owned': device_owned, 'unexpected_device_owned': unexpected}
    return {'match': True, 'reason': None,
            'device_owned': device_owned, 'unexpected_device_owned': unexpected}


def diff_rf_table(baseline: dict, merged: dict) -> list[dict]:
    """Per-band changes for operator confirmation. Never used as a gate."""
    out = []
    for key in merged:
        if not is_band_key(key):
            continue
        before = baseline.get(key) or []
        after = merged.get(key) or []
        if list(before) == list(after):
            continue
        changes = []
        for idx in range(max(len(before), len(after))):
            b = before[idx] if idx < len(before) else None
            a = after[idx] if idx < len(after) else None
            if b != a:
                changes.append({'index': idx, 'channel': idx + 1,
                                'is_band_default': idx == len(after) - 1,
                                'before': b, 'after': a})
        out.append({'band': key, 'before_count': len(before), 'after_count': len(after),
                    'changes': changes})
    return out


def stable_identity_matches(expected: dict, actual: dict) -> bool:
    """Do not follow a COM number to a different physical device."""
    keys = ('device_name', 'serial_number', 'hardware', 'firmware')
    return all((expected.get(k) or '') == (actual.get(k) or '') for k in keys)


def qualify_rf_write(*, candidate: dict | None, identity: dict | None, rf_reading: dict | None) -> dict:
    """Operation-specific, fail-closed eligibility result."""
    reasons: list[str] = []
    c = candidate or {}
    i = identity or {}
    r = rf_reading or {}

    if not c or not i:
        reasons.append('NO_ACTIVE_QUALIFIED_DEVICE')
    if not c.get('identity_proven'):
        reasons.append('RAW_IDENTITY_NOT_PROVEN')
    if not c.get('serial_com'):
        reasons.append('SERIAL_TRANSPORT_MISSING')
    serial_pnp = str(c.get('serial_pnp_device_id') or '')
    m = re.search(r'VID_([0-9A-Fa-f]{4})&PID_([0-9A-Fa-f]{4})', serial_pnp)
    vid, pid = ((m.group(1).upper(), m.group(2).upper()) if m else (None, None))
    if not c.get('serial_container_id'):
        reasons.append('PHYSICAL_CONTAINER_ID_MISSING')
    if not r.get('available') or r.get('state') != 'ok':
        reasons.append('FRESH_RF_READ_NOT_AVAILABLE')
    integrity = r.get('integrity') or {}
    if integrity.get('method') != 'vendor_md5_cmd115' or integrity.get('verified') is not True:
        reasons.append('FRESH_RF_MD5_NOT_VERIFIED')

    matched = None
    for profile in RF_WRITE_PROFILES:
        if (i.get('device_name') == profile.raw_device_name and
            i.get('firmware') == profile.firmware and
            i.get('hardware') == profile.hardware and
            vid == profile.vid and pid == profile.pid and
            i.get('rf_board_code') == profile.rf_board_code):
            matched = profile
            break
    if matched is None:
        reasons.append('NO_OPERATION_SPECIFIC_WRITE_PROFILE')

    # RFBoardType is an independent live capability check, not an alias/name check.
    live = r.get('data') if isinstance(r.get('data'), dict) else {}
    if matched and live.get('RFBoardType') != matched.rf_board_code:
        reasons.append('LIVE_RF_BOARD_TYPE_MISMATCH')

    reasons = list(dict.fromkeys(reasons))
    return {
        'operation_id': 'persistent_rf_table_write',
        'eligible': not reasons,
        'profile': matched.raw_device_name + '/' + matched.firmware if matched else None,
        'reasons': reasons,
        'evidence': {
            'raw_device_name': i.get('device_name'),
            'firmware': i.get('firmware'),
            'hardware': i.get('hardware'),
            'rf_board_code': i.get('rf_board_code'),
            'vid': vid,
            'pid': pid,
            'serial_container_id_present': bool(c.get('serial_container_id')),
            'live_rf_md5_verified': integrity.get('verified') is True,
        },
    }


class VendorWriteSession:
    """Single-in-flight vendor serial session with strict seq-correlated replies."""

    def __init__(self, port: str, *, serial_factory: Callable[[str], object] = WinSerial):
        self.port = port.upper()
        self.seq = 0
        self.decoder = Decoder()
        self.sp = None
        self.serial_factory = serial_factory
        self.frames: list[dict] = []
        self.last_payload_by_command: dict[int, bytes] = {}
        # Declared by the device in the cmd-60 payload; bounds the single 116 frame.
        self.receive_max_size: int | None = None

    def __enter__(self):
        self.sp = self.serial_factory(self.port).open()
        return self

    def __exit__(self, *_):
        if self.sp is not None:
            self.sp.close()
        self.sp = None

    def _summary(self, h: ArHeader, payload: bytes, crc_ok) -> dict:
        return {'command': h.command, 'seq': h.seq, 'retry': h.retry, 'length': len(payload),
                'type': h.type, 'format': h.format, 'experimental_local_crc32_match': crc_ok}

    def exchange(self, command: int, payload: bytes = b'', *, expected: Iterable[int] | None = None,
                 timeout: float = 8.0, retry_interval: float = 2.0) -> dict:
        expected_set = set(expected or (command,))
        seq = self.seq
        self.seq = (self.seq + 1) & 0xffffffff
        if hasattr(self.sp, 'purge_rx'):
            self.sp.purge_rx()
        self.decoder = Decoder()
        deadline = time.monotonic() + timeout
        next_send = 0.0
        attempts = 0
        seen = []
        while time.monotonic() < deadline:
            now = time.monotonic()
            if now >= next_send:
                self.sp.write(build_request(command, payload, seq=seq, retry=attempts))
                attempts += 1
                next_send = now + retry_interval
            chunk = self.sp.read(4096)
            if not chunk:
                continue
            for h, p, crc_ok in self.decoder.feed(chunk):
                s = self._summary(h, p, crc_ok)
                seen.append(s)
                self.frames.append(s)
                self.last_payload_by_command[h.command] = p
                # One transaction is in flight; vendor AckGuard requires command AND seq.
                if h.command in expected_set and h.seq == seq:
                    return {'ok': True, 'request_command': command, 'request_seq': seq,
                            'send_attempts': attempts, 'response': s, 'payload': p,
                            'seen_frames': seen[-24:]}
                if h.command == 0 and len(p) >= 4 and int.from_bytes(p[:4], 'little', signed=True) == -1:
                    detail = p[4:68].split(b'\0', 1)[0].decode('ascii', 'replace').strip()
                    raise CaddxWriteError('VENDOR_COMMAND_REJECTED', detail or 'vendor returned command-0 error', stage=str(command), evidence={'seen_frames': seen[-24:]})
                # ...and sometimes the device DOES echo the request command instead.
                # Measured on a factory-fresh VRX Max HF (18.21.7): a command 120
                # request answered with command 120, a 68-byte ResAckInfo, status -1
                # and detail "Config file not found" -- the unit supports the opcode
                # and simply has no file yet. That is a final answer.
                #
                # It only needs handling where the request command is NOT the
                # expected completion, which here is the 120 -> 116 read. Every
                # other call expects its own command back, so an echoing error is
                # seq-correlated into the success branch above and the caller's
                # per-stage ACK check rejects the negative status. Restricting the
                # rule that way keeps it off the correlated path entirely.
                #
                # Seq is deliberately not required, exactly as in the command-0 rule
                # above: whether the error path echoes the request sequence is
                # unproven, and a stale frame is already excluded by the purge and
                # the fresh decoder that open every exchange.
                if h.command == command and h.command not in expected_set and len(p) >= 4:
                    status = int.from_bytes(p[:4], 'little', signed=True)
                    if status < 0:
                        detail = p[4:68].split(b'\0', 1)[0].decode('ascii', 'replace').strip()
                        raise CaddxWriteError('VENDOR_COMMAND_REJECTED',
                                              detail or f'vendor rejected command {command} with status {status}',
                                              stage=str(command),
                                              evidence={'status': status, 'detail': detail,
                                                        'seen_frames': seen[-24:]})
        raise CaddxWriteError('VENDOR_ACK_TIMEOUT', f'no seq-correlated response to command {command}', stage=str(command), evidence={'attempts': attempts, 'seen_frames': seen[-24:]})

    def fresh_identity(self) -> dict:
        """Command 60 only, and record the device's declared receive_max_size.

        The JSON lane needs identity re-proof and the frame bound, but NOT an RF read:
        a camera hub is not required to implement 120 at all (a GT Pro answers it with
        a CRC-valid `cmd 0 unkonwn cmd`), so demanding one here would refuse a device
        the write genuinely applies to.
        """
        d = self.exchange(60, expected=(60,))
        info = parse_device_info(d['payload'])
        rms = info.get('receive_max_size')
        if isinstance(rms, int) and rms > 0:
            self.receive_max_size = rms
        return info

    def fresh_identity_and_rf(self) -> dict:
        d = self.exchange(60, expected=(60,))
        info = parse_device_info(d['payload'])
        rms = info.get('receive_max_size')
        if isinstance(rms, int) and rms > 0:
            self.receive_max_size = rms
        time.sleep(0.10)
        f = self.exchange(120, expected=(116,))
        digest = self.last_payload_by_command.get(115)
        integrity = verify_cmd115_md5(f['payload'], digest)
        if integrity.get('verified') is not True:
            raise CaddxWriteError('LIVE_RF_MD5_NOT_VERIFIED', 'fresh command-120 table failed command-115 MD5 verification', stage='read_before_write', evidence={'integrity': integrity})
        parsed = parse_bb_freq(f['payload'])
        return {
            'identity': info,
            'rf': {'data': parsed['json'], 'text': parsed['text'], 'payload': f['payload'],
                   'integrity': integrity, 'request_seq': f['request_seq'], 'response_seq': f['response']['seq']},
        }

    def upload_and_commit_rf(self, raw_json: bytes, *, receive_max_size: int | None = None) -> dict:
        """115 START / 116 DATA (single frame) / 117 END / empty 121 commit / cmd-3 reboot.

        The RF lane sends the whole document in ONE command-116 frame: the vendor's
        FileTransferSession byte[] constructor sets `_chunkSize = fileLength` and the
        JSON lane never consults the device's RecMaxSize (docs/PROTOCOL_SPEC.md
        section 5). That is a latent vendor overflow, so we bound it here against the
        device's own declared receive size instead of inheriting the bug.
        """
        raw_json = bytes(raw_json)
        if receive_max_size is None:
            receive_max_size = self.receive_max_size
        if receive_max_size:
            budget = int(receive_max_size) - HEADER_SIZE
            if budget > 0 and len(raw_json) > budget:
                raise CaddxWriteError(
                    'RF_TABLE_EXCEEDS_DEVICE_RECEIVE_SIZE',
                    f'RF table is {len(raw_json)} bytes; this device declared a receive_max_size of {receive_max_size}',
                    stage='prepare',
                    evidence={'payload_length': len(raw_json), 'receive_max_size': int(receive_max_size)})
        if len(raw_json) > MAX_FRAME_TOTAL - HEADER_SIZE:
            raise CaddxWriteError(
                'RF_TABLE_EXCEEDS_VENDOR_FRAME_CAP',
                f'RF table is {len(raw_json)} bytes; the vendor receive path discards any frame over {MAX_FRAME_TOTAL} bytes total',
                stage='prepare', evidence={'payload_length': len(raw_json)})
        info = build_file_info(raw_json)
        stages = []

        start = self.exchange(115, info, expected=(115,))
        start_ack = parse_ack68(start['payload'])
        if start_ack['status'] != 0:
            raise CaddxWriteError('SENDFILE_START_REJECTED', start_ack['detail'] or 'SENDFILE_START rejected', stage='115', evidence=start_ack)
        stages.append({'stage': 'SENDFILE_START', 'command': 115, 'seq': start['request_seq'], 'ack': start_ack})

        data = self.exchange(116, raw_json, expected=(116,))
        data_ack = parse_file_data80(data['payload'])
        if data_ack is not None and data_ack['status'] != 0:
            raise CaddxWriteError('SENDFILE_DATA_REJECTED', data_ack['detail'] or 'SENDFILE_DATA rejected', stage='116', evidence=data_ack)
        stages.append({'stage': 'SENDFILE_DATA', 'command': 116, 'seq': data['request_seq'],
                       'ack': data_ack or {'payload_length': len(data['payload']), 'vendor_status': 'not_structured'}})

        end = self.exchange(117, b'', expected=(117,))
        end_ack = parse_file_data80(end['payload'])
        if end_ack is not None and end_ack['status'] != 0:
            raise CaddxWriteError('SENDFILE_END_REJECTED', end_ack['detail'] or 'SENDFILE_END rejected', stage='117', evidence=end_ack)
        stages.append({'stage': 'SENDFILE_END', 'command': 117, 'seq': end['request_seq'],
                       'ack': end_ack or {'payload_length': len(end['payload']), 'vendor_status': 'not_structured'}})

        commit = self.exchange(121, b'', expected=(121,))
        commit_ack = parse_ack68(commit['payload'])
        if commit_ack['status'] != 0:
            raise CaddxWriteError('SET_BB_FREQ_REJECTED', commit_ack['detail'] or 'SET_BB_FREQ rejected', stage='121', evidence=commit_ack)
        stages.append({'stage': 'SET_BB_FREQ', 'command': 121, 'seq': commit['request_seq'], 'ack': commit_ack})

        reboot = self.send_reboot_unacked()
        stages.append({'stage': 'REBOOT', 'command': 3, 'seq': reboot['seq'],
                       'ack': {'vendor_status': 'not_acknowledged_by_design'}})

        return {'ok': True, 'stages': stages, 'payload_md5': hashlib.md5(raw_json).hexdigest(),
                'payload_sha256': hashlib.sha256(raw_json).hexdigest(), 'payload_length': len(raw_json),
                'reboot_requested': True}

    def upload_device_json(self, raw_json: bytes, *, remote_path: str,
                           receive_max_size: int | None = None) -> dict:
        """115 START / 116 DATA / 117 END / cmd-3 reboot. **No commit opcode.**

        The vendor's JSON lane, for /factory/mipi_hub.json and /factory/msp_rc_cfg.json.
        On the 117 ACK `UpgradeProcessFSM.cs:865-878` branches on `_isAutoSendBBFreq`:
        set -> UpgState.SetBBFreq (the empty 121; that is the RF lane), clear ->
        UpgState.Completed_Json -> Send_ReopenJson(). So this lane has no 121 and no
        equivalent -- the transfer itself is the commit, followed by the same reboot and
        reconnect. Sending 121 here would issue SET_BB_FREQ_CONFIG, an unrelated opcode.

        There is no counterpart to the RF lane's readback: no opcode reads either file
        back. The 117 ACK and the reconnect are the whole of the available evidence.
        """
        if remote_path not in ALLOWED_REMOTE_PATHS:
            raise CaddxWriteError(
                'DEVICE_PATH_NOT_ALLOWED',
                f'{remote_path!r} is not one of the three writable stock resources',
                stage='prepare', evidence={'allowed': sorted(ALLOWED_REMOTE_PATHS)})
        if remote_path == REMOTE_RF_PATH:
            raise CaddxWriteError(
                'WRONG_LANE_FOR_RF_TABLE',
                'the RF band table needs the 121 commit; use upload_and_commit_rf',
                stage='prepare')

        raw_json = bytes(raw_json)
        if receive_max_size is None:
            receive_max_size = self.receive_max_size
        if receive_max_size:
            budget = int(receive_max_size) - HEADER_SIZE
            if budget > 0 and len(raw_json) > budget:
                raise CaddxWriteError(
                    'CONFIG_EXCEEDS_DEVICE_RECEIVE_SIZE',
                    f'document is {len(raw_json)} bytes; this device declared a '
                    f'receive_max_size of {receive_max_size}',
                    stage='prepare',
                    evidence={'payload_length': len(raw_json),
                              'receive_max_size': int(receive_max_size)})
        if len(raw_json) > MAX_FRAME_TOTAL - HEADER_SIZE:
            raise CaddxWriteError(
                'CONFIG_EXCEEDS_VENDOR_FRAME_CAP',
                f'document is {len(raw_json)} bytes; the vendor receive path discards '
                f'any frame over {MAX_FRAME_TOTAL} bytes total',
                stage='prepare', evidence={'payload_length': len(raw_json)})

        info = build_file_info(raw_json, remote_path=remote_path,
                               file_dir=ALLOWED_REMOTE_PATHS[remote_path])
        stages = []

        start = self.exchange(115, info, expected=(115,))
        start_ack = parse_ack68(start['payload'])
        if start_ack['status'] != 0:
            raise CaddxWriteError('SENDFILE_START_REJECTED',
                                  start_ack['detail'] or 'SENDFILE_START rejected',
                                  stage='115', evidence=start_ack)
        stages.append({'stage': 'SENDFILE_START', 'command': 115,
                       'seq': start['request_seq'], 'ack': start_ack})

        data = self.exchange(116, raw_json, expected=(116,))
        data_ack = parse_file_data80(data['payload'])
        if data_ack is not None and data_ack['status'] != 0:
            raise CaddxWriteError('SENDFILE_DATA_REJECTED',
                                  data_ack['detail'] or 'SENDFILE_DATA rejected',
                                  stage='116', evidence=data_ack)
        stages.append({'stage': 'SENDFILE_DATA', 'command': 116, 'seq': data['request_seq'],
                       'ack': data_ack or {'payload_length': len(data['payload']),
                                           'vendor_status': 'not_structured'}})

        end = self.exchange(117, b'', expected=(117,))
        end_ack = parse_file_data80(end['payload'])
        if end_ack is not None and end_ack['status'] != 0:
            raise CaddxWriteError('SENDFILE_END_REJECTED',
                                  end_ack['detail'] or 'SENDFILE_END rejected',
                                  stage='117', evidence=end_ack)
        stages.append({'stage': 'SENDFILE_END', 'command': 117, 'seq': end['request_seq'],
                       'ack': end_ack or {'payload_length': len(end['payload']),
                                          'vendor_status': 'not_structured'}})

        reboot = self.send_reboot_unacked()
        stages.append({'stage': 'REBOOT', 'command': 3, 'seq': reboot['seq'],
                       'ack': {'vendor_status': 'not_acknowledged_by_design'}})

        return {'ok': True, 'stages': stages, 'remote_path': remote_path,
                'payload_md5': hashlib.md5(raw_json).hexdigest(),
                'payload_sha256': hashlib.sha256(raw_json).hexdigest(),
                'payload_length': len(raw_json), 'reboot_requested': True,
                'commit_opcode': None,
                'readback_available': False}

    def send_reboot_unacked(self) -> dict:
        """Step 1 of Reopen_Json: cmd 3, 32-byte zero mode, fire-and-forget.

        The vendor sends this through the plain send path -- no ACK guard, no retry --
        then sleeps 500 ms and closes the port, so the reboot ACK is normally never
        observed. Waiting for it here would be wrong: on a healthy unit the port is
        already going away. docs/PROTOCOL_SPEC.md section 7.
        """
        seq = self.seq
        self.seq = (self.seq + 1) & 0xffffffff
        self.sp.write(build_request(3, REBOOT_MODE_NORMAL, seq=seq, retry=0))
        try:
            flush = getattr(self.sp, 'flush', None)
            if callable(flush):
                flush()
        except Exception:
            pass
        # Vendor: Thread.Sleep(500) between the reboot send and Close().
        time.sleep(REBOOT_SEND_SETTLE)
        return {'seq': seq, 'command': 3, 'payload_length': len(REBOOT_MODE_NORMAL)}


def selftest() -> dict:
    assert HEADER_SIZE == 36
    assert AR_FILE_INFO.size == 328
    sample = b'{"RFBoardType":160,"bandA":[4495000,5839000]}'
    fi = build_file_info(sample)
    assert len(fi) == 328
    assert fi[:32] == hashlib.md5(sample).hexdigest().encode('ascii')
    assert int.from_bytes(fi[64:68], 'little', signed=True) == len(sample)
    assert int.from_bytes(fi[68:72], 'little', signed=True) == 1
    assert fi[72:72+128].split(b'\0',1)[0] == REMOTE_RF_PATH.encode('ascii')
    # fileDir is the PC-side local path, not the remote basename (spec section 4).
    assert fi[200:200+128].split(b'\0',1)[0] == VENDOR_LOCAL_RF_PATH.encode('ascii')
    req = build_request(121, b'', seq=5, retry=0)
    h = ArHeader.unpack(req[:36])
    assert h.command == 121 and h.length == 0 and h.seq == 5
    rb = build_request(3, REBOOT_MODE_NORMAL, seq=6, retry=0)
    h3 = ArHeader.unpack(rb[:36])
    assert h3.command == 3 and h3.length == 32 and rb[36:] == b'\0' * 32

    baseline = {'RFBoardType': 160, 'bandC': [6015000, 6045000, 5839000], 'is_defalut': 1,
                'bandA': [4495000, 4525000, 5839000], 'vendor_future_field': [1000, 2000]}
    raw = serialize_rf_table({'bandA': [4495000, 4535000, 5839000]}, baseline)
    out = json.loads(raw)
    # Baseline key order is preserved, and the unknown vendor field survives.
    assert list(out.keys()) == list(baseline.keys()), list(out.keys())
    assert out['vendor_future_field'] == [1000, 2000]
    assert out['bandA'] == [4495000, 4535000, 5839000]
    assert out['bandC'] == baseline['bandC']
    # Order-aware comparison rejects a reordered document that == would accept.
    reordered = {k: out[k] for k in reversed(list(out.keys()))}
    assert reordered == out and not semantic_equal(reordered, out)
    # Readback: the device clears is_defalut and re-serializes compactly. Neither
    # is a mismatch; a reordered or altered band still is (spec section 8.1).
    device_readback = dict(out, is_defalut=0)
    cmp_ok = compare_readback(device_readback, out)
    assert cmp_ok['match'] and cmp_ok['device_owned'][0]['as_documented'], cmp_ok
    assert not compare_readback({k: device_readback[k] for k in reversed(list(out.keys()))}, out)['match']
    bad = dict(device_readback, bandA=[4495000, 4545000, 5839000])
    assert not compare_readback(bad, out)['match']
    return {'ok': True, 'ar_file_info_size': AR_FILE_INFO.size,
            'write_commands': [115, 116, 117, 121, 3], 'commit_payload_length': 0,
            'reconnect_settle_s': RECONNECT_SETTLE, 'reconnect_poll_budget_s': RECONNECT_POLL_BUDGET,
            'file_info_dir': VENDOR_LOCAL_RF_PATH, 'readback_comparison': 'order_aware',
            'device_owned_keys': list(DEVICE_OWNED_KEYS)}


if __name__ == '__main__':
    print(json.dumps(selftest(), indent=2))
