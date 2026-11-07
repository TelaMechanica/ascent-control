#!/usr/bin/env python3
"""Typed PRIMARY/FALLBACK receiver-slot transport for the Ascent Sky (VTX).

Two opcodes, added to the Sky's existing serial file-transfer FSM by
`firmware/sky_user_cfg_provision/`:

    123  GET_USER_CFG   typed read  -- 123 ACK / 115 MD5 sidecar / 116 JSON / 117 terminator
    124  SET_USER_CFG   typed commit -- empty payload, after a 115/116/117 upload

The read is deliberately frame-for-frame identical to the stock command-120 RF table read, so
the host reuses machinery it already has.  The commit is the stock 121 shape with one
difference: **there is no reboot and no reconnect**.  The device only persists a file, so the
serial session survives and the readback happens in the same session.

Three distinct BB identities exist and must never share a field or a label
(docs/GESTURE_V5_PC_TOOL_HANDOFF.md section 7 and section 11):

    Aircraft / VTX BB ID       the unit's own identity, from BB RPC GET_STATUS bytes 6..9
    PRIMARY Receiver BB ID     a VRX identity stored in the VTX at bb_mac_addr_0
    FALLBACK Receiver BB ID    a second VRX identity at bb_mac_addr_1

This module handles only the second and third.  It never reads the live peer, and a caller
must never substitute the live peer for a stored slot: that is a silent placeholder.

A BB ID is four bytes.  It is `BbId` internally and is never called a MAC address outside the
vendor key name `bb_mac_addr`.

Firmware without the two opcodes answers with a CRC-valid command-0 `unkonwn cmd`.  That is
reported as TYPED_USER_CFG_UNSUPPORTED and the caller must display nothing rather than
inventing a value.
"""
from __future__ import annotations

import hashlib
import re
import struct
import time
from typing import Callable, Iterable

from caddx_read_bundle import (
    ArHeader,
    Decoder,
    WinSerial,
    crc32_vendor,
    parse_device_info,
)

MAGIC = 0x4152544F
VERSION = 3292
HEADER = struct.Struct('<IHHHHIHHIIII')
HEADER_SIZE = HEADER.size
AR_FILE_INFO = struct.Struct('<64sii128s128s')
MAX_FRAME_TOTAL = 5120

CMD_FIND_DEVICE = 60
CMD_SENDFILE_START = 115
CMD_SENDFILE_DATA = 116
CMD_SENDFILE_END = 117
CMD_GET_USER_CFG = 123
CMD_SET_USER_CFG = 124

ALLOWED_COMMANDS = frozenset((
    CMD_FIND_DEVICE, CMD_SENDFILE_START, CMD_SENDFILE_DATA, CMD_SENDFILE_END,
    CMD_GET_USER_CFG, CMD_SET_USER_CFG,
))

# The only path this transport will ever name. Matched byte for byte on the device by
# user_cfg_target_is_permitted(); there is no caller-supplied path anywhere in this module.
REMOTE_USER_CFG_PATH = '/factory/user_cfg.json'
REMOTE_USER_CFG_FILENAME = 'user_cfg.json'
# ArFileInfo.fileDir carries the PC-side local path, not the remote name (PROTOCOL_SPEC 4).
LOCAL_STAGING_NAME = 'resource/param/user_cfg.json'
FILE_INFO_DIR_MAX = 128

KEY_PRIMARY = 'bb_mac_addr_0'
KEY_FALLBACK = 'bb_mac_addr_1'
LABEL_PRIMARY = 'PRIMARY Receiver BB ID'
LABEL_FALLBACK = 'FALLBACK Receiver BB ID'

USER_CFG_MAX = 4096          # USER_CFG_MAX in the firmware module
BBID_LEN = 4
OPERATION_ID = 'sky_receiver_slot_provisioning'

_BBID_TEXT_RE = re.compile(r'^(?:0x|0X)?([0-9A-Fa-f]{2})$')


class SkyUserCfgError(RuntimeError):
    """Fail-closed error for a typed user_cfg transaction."""

    def __init__(self, code: str, message: str, *, stage: str | None = None, evidence: dict | None = None):
        super().__init__(message)
        self.code = code
        self.stage = stage
        self.evidence = evidence or {}


# ------------------------------------------------------------------ BB ID handling --------

def parse_bb_id(value) -> bytes:
    """Accept the wire shape (four "0xNN" strings) or a display form, return four bytes.

    Rejects anything that is not exactly four bytes, and rejects the two non-routable
    patterns the firmware also rejects: all-zero and all-0xFF.
    """
    if isinstance(value, (bytes, bytearray)):
        parts = list(value)
    elif isinstance(value, str):
        text = value.strip()
        chunks = [c for c in re.split(r'[:\-\s,]+', text) if c]
        if len(chunks) == 1 and len(chunks[0]) == 8:
            chunks = [chunks[0][i:i + 2] for i in range(0, 8, 2)]
        parts = []
        for c in chunks:
            m = _BBID_TEXT_RE.match(c)
            if not m:
                raise SkyUserCfgError('BB_ID_MALFORMED', f'{value!r} is not a four-byte BB ID', stage='prepare')
            parts.append(int(m.group(1), 16))
    elif isinstance(value, (list, tuple)):
        parts = []
        for c in value:
            if isinstance(c, int):
                if not 0 <= c <= 255:
                    raise SkyUserCfgError('BB_ID_MALFORMED', 'BB ID byte out of range', stage='prepare')
                parts.append(c)
                continue
            m = _BBID_TEXT_RE.match(str(c).strip())
            if not m:
                raise SkyUserCfgError('BB_ID_MALFORMED', f'{c!r} is not a "0xNN" byte', stage='prepare')
            parts.append(int(m.group(1), 16))
    else:
        raise SkyUserCfgError('BB_ID_MALFORMED', f'{type(value).__name__} is not a BB ID', stage='prepare')

    if len(parts) != BBID_LEN:
        raise SkyUserCfgError('BB_ID_MALFORMED',
                              f'a BB ID is {BBID_LEN} bytes; received {len(parts)}', stage='prepare')
    raw = bytes(parts)
    if not bb_id_is_routable(raw):
        raise SkyUserCfgError('BB_ID_NOT_ROUTABLE',
                              'all-zero and all-0xFF are not routable BB IDs', stage='prepare')
    return raw


def bb_id_is_routable(raw: bytes) -> bool:
    """Same rule as the firmware's user_cfg_bbid_is_valid()."""
    if len(raw) != BBID_LEN:
        return False
    if all(b == 0x00 for b in raw):
        return False
    if all(b == 0xFF for b in raw):
        return False
    return True


def format_bb_id(raw: bytes) -> str:
    """Display form. Never labelled as a MAC address."""
    return ':'.join(f'{b:02X}' for b in bytes(raw))


def bb_id_wire_array(raw: bytes) -> list[str]:
    return [f'0x{b:02X}' for b in bytes(raw)]


# ------------------------------------------------------------------ document handling -----

# The canonical document, byte-identical to what the Gesture V5 helper writes and to the
# firmware module's CANONICAL. Only ever uploaded; the device rewrites its own live document
# in place, so this shape is what a never-bound unit ends up with.
_DOC_TEMPLATE = (
    '{{\n'
    '    "{k0}": [\n'
    '        "0x{p0:02X}",\n'
    '        "0x{p1:02X}",\n'
    '        "0x{p2:02X}",\n'
    '        "0x{p3:02X}"\n'
    '    ],\n'
    '    "{k1}": [\n'
    '        "0x{f0:02X}",\n'
    '        "0x{f1:02X}",\n'
    '        "0x{f2:02X}",\n'
    '        "0x{f3:02X}"\n'
    '    ]\n'
    '}}\n'
)


def build_user_cfg_document(primary, fallback) -> bytes:
    """Build the upload document. Both slots are always written explicitly.

    To express "no distinct fallback", pass FALLBACK equal to PRIMARY: the Gesture V5 helper
    already treats that as policy_have_dual = 0 and resyncs to PRIMARY-only. There is no
    "clear the fallback" operation, because there is no firmware behaviour to match for one.
    """
    p = parse_bb_id(primary)
    f = parse_bb_id(fallback)
    text = _DOC_TEMPLATE.format(
        k0=KEY_PRIMARY, k1=KEY_FALLBACK,
        p0=p[0], p1=p[1], p2=p[2], p3=p[3],
        f0=f[0], f1=f[1], f2=f[2], f3=f[3],
    )
    return text.encode('ascii')


_MEMBER_RE_CACHE: dict[str, re.Pattern] = {}


def _slot_regex(key: str) -> re.Pattern:
    rx = _MEMBER_RE_CACHE.get(key)
    if rx is None:
        rx = re.compile(
            r'(?:[{,])\s*"' + re.escape(key) + r'"\s*:\s*\[\s*'
            r'"0[xX]([0-9A-Fa-f]{2})"\s*,\s*'
            r'"0[xX]([0-9A-Fa-f]{2})"\s*,\s*'
            r'"0[xX]([0-9A-Fa-f]{2})"\s*,\s*'
            r'"0[xX]([0-9A-Fa-f]{2})"\s*\]'
        )
        _MEMBER_RE_CACHE[key] = rx
    return rx


def scan_slot(text: str, key: str) -> bytes | None:
    """Mirror of the firmware's strict scanner: the key must be at object-member position and
    its value must be exactly four "0xNN" strings. Anything else reads as absent/malformed."""
    m = _slot_regex(key).search(text)
    if not m:
        return None
    return bytes(int(g, 16) for g in m.groups())


def parse_user_cfg(payload: bytes | str) -> dict:
    """Parse a device-supplied /factory/user_cfg.json into typed slots.

    Reports each slot independently. A missing FALLBACK is the normal state of a unit that has
    only ever been bound with a short press, and is reported as absent -- never as PRIMARY,
    and never filled in from the live peer.
    """
    raw = payload.encode('ascii', 'replace') if isinstance(payload, str) else bytes(payload)
    text = raw.decode('ascii', 'replace')
    primary = scan_slot(text, KEY_PRIMARY)
    fallback = scan_slot(text, KEY_FALLBACK)
    scp = None
    m = re.search(r'(?:[{,])\s*"save_candidate_position"\s*:\s*(-?\d+)', text)
    if m:
        scp = int(m.group(1))
    return {
        'primary_receiver_bb_id': format_bb_id(primary) if primary else None,
        'primary_receiver_bb_id_present': primary is not None,
        'primary_receiver_bb_id_routable': bool(primary and bb_id_is_routable(primary)),
        'fallback_receiver_bb_id': format_bb_id(fallback) if fallback else None,
        'fallback_receiver_bb_id_present': fallback is not None,
        'fallback_receiver_bb_id_routable': bool(fallback and bb_id_is_routable(fallback)),
        'save_candidate_position': scp,
        'labels': {'primary': LABEL_PRIMARY, 'fallback': LABEL_FALLBACK},
        'raw_text': text,
        'payload_length': len(raw),
        'md5': hashlib.md5(raw).hexdigest(),
    }


# ------------------------------------------------------------------ framing ---------------

def build_request(command: int, payload: bytes = b'', *, seq: int = 0, retry: int = 0) -> bytes:
    if command not in ALLOWED_COMMANDS:
        raise ValueError(f'command {command} is outside the typed user_cfg transport')
    p = bytes(payload)
    if len(p) > USER_CFG_MAX and command == CMD_SENDFILE_DATA:
        raise SkyUserCfgError('USER_CFG_TOO_LARGE',
                              f'document is {len(p)} bytes; the device buffer is {USER_CFG_MAX}',
                              stage='prepare')
    h0 = HEADER.pack(MAGIC, VERSION, 1, 0, 0xABCD, command, 2, 0, len(p),
                     seq & 0xffffffff, retry & 0xffffffff, 0)
    crc = crc32_vendor(h0, p)
    return HEADER.pack(MAGIC, VERSION, 1, 0, 0xABCD, command, 2, 0, len(p),
                       seq & 0xffffffff, retry & 0xffffffff, crc) + p


def build_file_info(payload: bytes, *, remote_path: str = REMOTE_USER_CFG_PATH,
                    file_dir: str = LOCAL_STAGING_NAME) -> bytes:
    """ArFileInfo (328 bytes) for the one permitted target.

    The remote path is not a parameter a caller can vary: passing anything else raises. The
    device rejects a mismatch too, but refusing here means a wrong target never reaches the
    wire at all.
    """
    if remote_path != REMOTE_USER_CFG_PATH:
        raise SkyUserCfgError('DEVICE_PATH_NOT_ALLOWED',
                              'only the receiver-slot configuration can be written',
                              stage='prepare')
    raw = bytes(payload)
    digest = hashlib.md5(raw).hexdigest().encode('ascii')
    local = str(file_dir).replace('\\', '/')
    if len(local) > FILE_INFO_DIR_MAX:
        local = local[-FILE_INFO_DIR_MAX:]

    def fixed(v: bytes, size: int) -> bytes:
        if len(v) > size:
            raise SkyUserCfgError('FILE_INFO_FIELD_TOO_LONG',
                                  f'vendor file-info field exceeds {size} bytes', stage='prepare')
        return v + b'\0' * (size - len(v))

    return AR_FILE_INFO.pack(fixed(digest, 64), len(raw), 1,
                             fixed(remote_path.encode('ascii'), 128),
                             fixed(local.encode('ascii'), 128))


def parse_ack68(payload: bytes) -> dict:
    if len(payload) < 68:
        raise SkyUserCfgError('SHORT_VENDOR_ACK',
                              f'expected 68-byte ResAckInfo, received {len(payload)}', stage='ack')
    status = int.from_bytes(payload[:4], 'little', signed=True)
    detail = payload[4:68].split(b'\0', 1)[0].decode('ascii', 'replace').rstrip(' \r\n\t')
    return {'status': status, 'detail': detail, 'payload_length': len(payload)}


_MD5_RE = re.compile(r'^[0-9a-f]{32}$')


def extract_md5_sidecar(payload: bytes | None) -> dict:
    """Pull the digest out of a read-path command-115 payload.

    Offset 0 is the evidenced layout: the Sky's handle_get_bb_freq_config memsets a 68-byte
    buffer and hands that same base pointer to AR_FPV_UPGRADE_CalculateFileMD5
    (ar_fpvhs_upgrade @0x28fbe, @0x28fc6), so there is no status word in front of the digest.
    Offset 4 -- where a ResAckInfo would put it -- is still accepted, and the offset actually
    used is reported, so one bench capture settles it for any firmware that differs.
    """
    if payload is None:
        return {'digest': None, 'offset': None, 'error': 'no_cmd115_sidecar'}
    raw = bytes(payload)
    for off in (0, 4):
        token = raw[off:off + 32]
        try:
            text = token.decode('ascii', 'strict').lower()
        except Exception:
            continue
        if _MD5_RE.match(text):
            return {'digest': text, 'offset': off, 'error': None}
    return {'digest': None, 'offset': None, 'error': 'invalid_cmd115_digest'}


def verify_read_integrity(doc_payload: bytes, sidecar_payload: bytes | None) -> dict:
    """MD5 of the full 116 payload must equal the 115 digest. Missing digest = unverified."""
    actual = hashlib.md5(bytes(doc_payload)).hexdigest()
    side = extract_md5_sidecar(sidecar_payload)
    if side['digest'] is None:
        return {'method': 'vendor_md5_cmd115', 'verified': None if side['error'] == 'no_cmd115_sidecar' else False,
                'expected_md5': None, 'actual_md5': actual, 'digest_offset': None, 'error': side['error']}
    return {'method': 'vendor_md5_cmd115', 'verified': side['digest'] == actual,
            'expected_md5': side['digest'], 'actual_md5': actual,
            'digest_offset': side['offset'], 'error': None}


# ------------------------------------------------------------------ readback --------------

def compare_readback(readback: dict, expected_primary: bytes, expected_fallback: bytes) -> dict:
    """Compare the two slots only.

    Never compare payload length or MD5 across a write: the device re-serialises its own
    document, and on the Sky the commit is an in-place rewrite of an existing file whose
    layout we did not author. Neither figure can be expected to match, however perfect the
    write (CLAUDE.md, RF bench 2026-09-06).
    """
    got_p = readback.get('primary_receiver_bb_id')
    got_f = readback.get('fallback_receiver_bb_id')
    want_p = format_bb_id(expected_primary)
    want_f = format_bb_id(expected_fallback)
    diffs = []
    if got_p != want_p:
        diffs.append({'slot': KEY_PRIMARY, 'label': LABEL_PRIMARY, 'expected': want_p, 'actual': got_p})
    if got_f != want_f:
        diffs.append({'slot': KEY_FALLBACK, 'label': LABEL_FALLBACK, 'expected': want_f, 'actual': got_f})
    return {'match': not diffs, 'differences': diffs,
            'expected': {KEY_PRIMARY: want_p, KEY_FALLBACK: want_f},
            'actual': {KEY_PRIMARY: got_p, KEY_FALLBACK: got_f}}


# ------------------------------------------------------------------ qualification ---------

def qualify_user_cfg_write(*, candidate: dict | None, identity: dict | None,
                           user_cfg_reading: dict | None, candidate_count: int | None = None) -> dict:
    """Per-operation, fail-closed eligibility for a receiver-slot commit.

    There is no model profile here on purpose. Sky units are indistinguishable by USB
    descriptor -- CDC VID:PID, gadget serial, RNDIS MAC and RNDIS IP are all identical across
    every unit (config_serial.sh:65,68,72; config_ether.sh:3,4,7; usb_ip.sh:6,7). So the
    capability proof is the device's own answer: a typed read that came back MD5-verified with
    a parseable PRIMARY slot proves both that this firmware carries the opcodes and that this
    device has receiver slots at all. A raw command-60 identity is still required for
    freshness and for the session model, and it is recorded, but it is not the gate.

    Because the units are indistinguishable, provisioning is one unit at a time: more than one
    Ascent serial interface present is ambiguity, and ambiguity fails closed
    (docs/GESTURE_V5_PC_TOOL_HANDOFF.md section 7).
    """
    reasons: list[str] = []
    c = candidate or {}
    i = identity or {}
    s = user_cfg_reading or {}

    if not c or not i:
        reasons.append('NO_ACTIVE_QUALIFIED_DEVICE')
    if not c.get('identity_proven'):
        reasons.append('RAW_IDENTITY_NOT_PROVEN')
    if not c.get('serial_com'):
        reasons.append('SERIAL_TRANSPORT_MISSING')
    if not c.get('serial_container_id'):
        reasons.append('PHYSICAL_CONTAINER_ID_MISSING')
    if candidate_count is not None and int(candidate_count) > 1:
        reasons.append('AMBIGUOUS_MULTIPLE_ASCENT_INTERFACES')

    if not s.get('available'):
        reasons.append('TYPED_USER_CFG_READ_NOT_AVAILABLE')
    elif s.get('supported') is False:
        reasons.append('TYPED_USER_CFG_UNSUPPORTED')
    else:
        integrity = s.get('integrity') or {}
        if integrity.get('verified') is not True:
            reasons.append('TYPED_USER_CFG_MD5_NOT_VERIFIED')
        slots = s.get('slots') or {}
        if not slots.get('primary_receiver_bb_id_present'):
            reasons.append('PRIMARY_SLOT_NOT_READABLE')

    reasons = list(dict.fromkeys(reasons))
    return {
        'operation_id': OPERATION_ID,
        'eligible': not reasons,
        'reasons': reasons,
        'evidence': {
            'raw_device_name': i.get('device_name'),
            'firmware': i.get('firmware'),
            'hardware': i.get('hardware'),
            'serial_number': i.get('serial_number'),
            'serial_container_id_present': bool(c.get('serial_container_id')),
            'ascent_interfaces_present': candidate_count,
            'typed_read_md5_verified': ((s.get('integrity') or {}).get('verified') is True),
            'typed_read_digest_offset': (s.get('integrity') or {}).get('digest_offset'),
        },
    }


# ------------------------------------------------------------------ session ----------------

class SkyUserCfgSession:
    """Single-in-flight typed session for the Sky receiver slots."""

    def __init__(self, port: str, *, serial_factory: Callable[[str], object] = WinSerial):
        self.port = port.upper()
        self.seq = 0
        self.decoder = Decoder()
        self.sp = None
        self.serial_factory = serial_factory
        self.frames: list[dict] = []
        self.last_payload_by_command: dict[int, bytes] = {}
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
        """One transaction. Retries allocate a new seq and increment `retry`, matching the
        vendor AckGuard, which re-points at the newest sequence (PROTOCOL_SPEC 6)."""
        expected_set = set(expected or (command,))
        seq = self.seq
        self.seq = (self.seq + 1) & 0xffffffff
        if hasattr(self.sp, 'purge_rx'):
            self.sp.purge_rx()
        self.decoder = Decoder()
        deadline = time.monotonic() + timeout
        next_send = 0.0
        attempts = 0
        seen: list[dict] = []
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
                if h.command in expected_set and h.seq == seq:
                    return {'ok': True, 'request_command': command, 'request_seq': seq,
                            'send_attempts': attempts, 'response': s, 'payload': p,
                            'seen_frames': seen[-24:]}
                if h.command == 0 and len(p) >= 4 and int.from_bytes(p[:4], 'little', signed=True) == -1:
                    detail = p[4:68].split(b'\0', 1)[0].decode('ascii', 'replace').strip()
                    # Firmware without the opcode answers exactly this way. It is a capability
                    # answer, not a transport fault: do not retry and do not fabricate a value.
                    raise SkyUserCfgError(
                        'TYPED_USER_CFG_UNSUPPORTED',
                        detail or f'this firmware does not implement command {command}',
                        stage=str(command), evidence={'seen_frames': seen[-24:]})
                # ...and sometimes the device DOES echo the request command instead.
                # Measured on a factory-fresh VRX Max HF (18.21.7): a command 120
                # request answered with command 120, a 68-byte ResAckInfo, status -1
                # and detail "Config file not found" -- the unit supports the opcode
                # and simply has no file yet. That is a final answer.
                #
                # It only needs handling where the request command is NOT the
                # expected completion, which here is the 123 -> 116 read. Every
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
                        # Firmware that DOES implement the opcode and simply has no
                        # document to return answers here. That is a different answer
                        # from the command-0 one above -- the opcode exists -- so it
                        # gets its own code and must not be reported as unsupported.
                        raise SkyUserCfgError(
                            'TYPED_USER_CFG_REJECTED',
                            detail or f'the device rejected command {command} with status {status}',
                            stage=str(command),
                            evidence={'status': status, 'detail': detail,
                                      'seen_frames': seen[-24:]})
        raise SkyUserCfgError('VENDOR_ACK_TIMEOUT',
                              f'no seq-correlated response to command {command}',
                              stage=str(command),
                              evidence={'attempts': attempts, 'seen_frames': seen[-24:]})

    def fresh_identity(self) -> dict:
        d = self.exchange(CMD_FIND_DEVICE, expected=(CMD_FIND_DEVICE,))
        info = parse_device_info(d['payload'])
        rms = info.get('receive_max_size')
        if isinstance(rms, int) and rms > 0:
            self.receive_max_size = rms
        return info

    def read_user_cfg(self) -> dict:
        """Typed read. The command-116 frame is the document; the 123 ACK is not.

        Mirrors the command-120 guard: the read completes on 116, and the 115 sidecar arrives
        before it, so it is collected from the frame log rather than waited on separately.
        """
        r = self.exchange(CMD_GET_USER_CFG, expected=(CMD_SENDFILE_DATA,))
        doc = r['payload']
        sidecar = self.last_payload_by_command.get(CMD_SENDFILE_START)
        integrity = verify_read_integrity(doc, sidecar)
        ack = self.last_payload_by_command.get(CMD_GET_USER_CFG)
        ack_parsed = None
        if ack is not None and len(ack) >= 68:
            ack_parsed = parse_ack68(ack)
            if ack_parsed['status'] != 0:
                raise SkyUserCfgError('GET_USER_CFG_REJECTED',
                                      ack_parsed['detail'] or 'GET_USER_CFG rejected',
                                      stage='123', evidence=ack_parsed)
        if integrity.get('verified') is not True:
            raise SkyUserCfgError('USER_CFG_MD5_NOT_VERIFIED',
                                  'typed receiver-slot read failed command-115 MD5 verification',
                                  stage='read', evidence={'integrity': integrity})
        slots = parse_user_cfg(doc)
        return {'slots': slots, 'integrity': integrity, 'ack': ack_parsed,
                'request_seq': r['request_seq'], 'response_seq': r['response']['seq'],
                'payload_length': len(doc)}

    def upload_and_commit(self, document: bytes) -> dict:
        """115 START / 116 DATA (single frame) / 117 END / empty 124 commit.

        No reboot and no reconnect: the firmware commit only persists a file. That is the one
        deliberate difference from the RF write's 121 commit, which ends in Reopen_Json().
        """
        raw = bytes(document)
        if self.receive_max_size:
            budget = int(self.receive_max_size) - HEADER_SIZE
            if budget > 0 and len(raw) > budget:
                raise SkyUserCfgError(
                    'USER_CFG_EXCEEDS_DEVICE_RECEIVE_SIZE',
                    f'document is {len(raw)} bytes; this device declared a receive_max_size of {self.receive_max_size}',
                    stage='prepare',
                    evidence={'payload_length': len(raw), 'receive_max_size': int(self.receive_max_size)})
        if len(raw) > MAX_FRAME_TOTAL - HEADER_SIZE:
            raise SkyUserCfgError('USER_CFG_EXCEEDS_VENDOR_FRAME_CAP',
                                  f'document is {len(raw)} bytes; the receive path discards any frame '
                                  f'over {MAX_FRAME_TOTAL} bytes total',
                                  stage='prepare', evidence={'payload_length': len(raw)})

        stages = []
        start = self.exchange(CMD_SENDFILE_START, build_file_info(raw), expected=(CMD_SENDFILE_START,))
        start_ack = parse_ack68(start['payload'])
        if start_ack['status'] != 0:
            raise SkyUserCfgError('SENDFILE_START_REJECTED',
                                  start_ack['detail'] or 'SENDFILE_START rejected',
                                  stage='115', evidence=start_ack)
        stages.append({'stage': 'SENDFILE_START', 'command': CMD_SENDFILE_START,
                       'seq': start['request_seq'], 'ack': start_ack})

        data = self.exchange(CMD_SENDFILE_DATA, raw, expected=(CMD_SENDFILE_DATA,))
        stages.append({'stage': 'SENDFILE_DATA', 'command': CMD_SENDFILE_DATA,
                       'seq': data['request_seq'], 'ack': {'payload_length': len(data['payload'])}})

        end = self.exchange(CMD_SENDFILE_END, b'', expected=(CMD_SENDFILE_END,))
        stages.append({'stage': 'SENDFILE_END', 'command': CMD_SENDFILE_END,
                       'seq': end['request_seq'], 'ack': {'payload_length': len(end['payload'])}})

        commit = self.exchange(CMD_SET_USER_CFG, b'', expected=(CMD_SET_USER_CFG,))
        commit_ack = parse_ack68(commit['payload'])
        if commit_ack['status'] != 0:
            raise SkyUserCfgError('SET_USER_CFG_REJECTED',
                                  commit_ack['detail'] or 'SET_USER_CFG rejected',
                                  stage='124', evidence=commit_ack)
        stages.append({'stage': 'SET_USER_CFG', 'command': CMD_SET_USER_CFG,
                       'seq': commit['request_seq'], 'ack': commit_ack})

        return {'ok': True, 'stages': stages, 'reboot_requested': False,
                'payload_md5': hashlib.md5(raw).hexdigest(),
                'payload_length': len(raw)}

    def provision_receiver_slots(self, primary, fallback) -> dict:
        """Full transaction: prepare, upload, commit, reread, verify.

        The readback compares only the two slots, against the values actually serialised onto
        the wire. It never compares payload length or MD5 across the write.
        """
        p = parse_bb_id(primary)
        f = parse_bb_id(fallback)
        before = self.read_user_cfg()
        document = build_user_cfg_document(p, f)
        commit = self.upload_and_commit(document)
        # No reconnect window to wait out; the session is still up.
        after = self.read_user_cfg()
        verdict = compare_readback(after['slots'], p, f)
        return {
            'ok': verdict['match'],
            'operation_id': OPERATION_ID,
            'before': before['slots'],
            'after': after['slots'],
            'commit': commit,
            'readback': verdict,
            'readback_integrity': after['integrity'],
            'document_md5': commit['payload_md5'],
            'document_length': commit['payload_length'],
            'reboot_required_for_effect': True,
        }


def selftest() -> dict:
    """Static self-checks. No device, no filesystem."""
    assert HEADER_SIZE == 36
    assert AR_FILE_INFO.size == 328

    doc = build_user_cfg_document((':'.join(('F2', '00', '00', '14'))), ['0xF2', '0x00', '0x00', '0x30'])
    parsed = parse_user_cfg(doc)
    assert parsed['primary_receiver_bb_id'] == (':'.join(('F2', '00', '00', '14'))), parsed
    assert parsed['fallback_receiver_bb_id'] == (':'.join(('F2', '00', '00', '30'))), parsed
    assert parsed['labels']['primary'] == LABEL_PRIMARY

    fi = build_file_info(doc)
    assert len(fi) == 328
    assert fi[:32] == hashlib.md5(doc).hexdigest().encode('ascii')
    assert int.from_bytes(fi[64:68], 'little', signed=True) == len(doc)
    assert int.from_bytes(fi[68:72], 'little', signed=True) == 1
    assert fi[72:200].split(b'\0', 1)[0] == REMOTE_USER_CFG_PATH.encode('ascii')
    assert fi[200:328].split(b'\0', 1)[0] == LOCAL_STAGING_NAME.encode('ascii')

    req = build_request(CMD_SET_USER_CFG, b'', seq=9)
    h = ArHeader.unpack(req[:36])
    assert (h.command, h.length, h.format, h.seq) == (124, 0, 2, 9)

    side = b'' .join([hashlib.md5(doc).hexdigest().encode('ascii'), b'\0' * 36])
    integ = verify_read_integrity(doc, side)
    assert integ['verified'] is True and integ['digest_offset'] == 0, integ

    return {'ok': True, 'module': 'caddx_sky_user_cfg'}


if __name__ == '__main__':
    import json as _json
    print(_json.dumps(selftest(), indent=2))
