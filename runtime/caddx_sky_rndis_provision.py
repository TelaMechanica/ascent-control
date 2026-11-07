#!/usr/bin/env python3
"""USB-C (RNDIS) PRIMARY/FALLBACK receiver-slot transport for the Ascent Sky (VTX).

This is a **second, local route** to the same operation the serial 123/124 opcodes provide
(`caddx_sky_user_cfg.py`).  It is not a replacement.  The serial route stays exactly as it
is: it is the upstream Caddx contribution, it is the FSM the authorization names, and it is
the one shaped for the 19.2.5 collaborative line.  This route exists because that one cannot
be flashed from the corpus we hold - its handlers belong inside `ar_fpvhs_upgrade`, which we
have only as a stripped ELF - whereas a Gesture V5-style helper is a program *added* to the
rootfs and is buildable from source we do hold.

    firmware/sky_rndis_provision/    the helper-side service and the flashable image
    docs/SKY_RNDIS_PROVISIONING.md   the assessment, the design and the flash procedure

How the device is reached
-------------------------
The Sky's USB gadget is exclusive: `config_serial.sh` builds a CDC-ACM gadget and
`config_ether.sh` builds an RNDIS gadget, and only one can own the single UDC.  So the CDC
COM port and the RNDIS interface never exist at the same time, and reaching this service
means giving up the serial port until the unit is switched back or rebooted.

The switch itself is stock: `ar_fpvhs_upgrade` answers the OTAR command 0x3A by running
`disable_config_serial.sh` then `config_ether.sh` (strings at 0x298b0-0x2994d), with no
reboot.  `usb_ip.sh:7` then hardcodes the device at **192.168.3.104/24** on `usb0`.  That
path is not theoretical: it was exercised on this bench on 2026-08-29
(`sky_persistence_diag_20260829_214753.json` - switch over COM21, ACK valid, BB RPC on
192.168.3.104:50000 answering at 1 Hz for minutes).

Identity, and why it is better here than on the serial route
------------------------------------------------------------
Every Ascent Sky is identical over USB - same CDC VID:PID, same RNDIS VID:PID, same gadget
serial (a board-type code), same MAC, same IPv4 - so the serial route can only say "exactly
one Ascent interface is present, therefore this is the unit".  Over RNDIS the baseband RPC
answers GET_STATUS with the unit's **own BB ID at payload bytes 6..9**, which is the only
per-unit identifier that exists on a Sky.  This module reads it and records it with every
operation.  Destination IP is still not identity - every Ascent RNDIS device answers on
192.168.3.104 - so the socket is always bound to the correlated adapter's own host address
and pinned with IP_UNICAST_IF, and more than one Ascent adapter fails closed.

Three distinct BB identities exist and must never share a field or a label
(docs/GESTURE_V5_PC_TOOL_HANDOFF.md sections 7 and 11):

    Aircraft / VTX BB ID       the unit's own identity, GET_STATUS bytes 6..9
    PRIMARY Receiver BB ID     a VRX identity stored in the VTX at bb_mac_addr_0
    FALLBACK Receiver BB ID    a second VRX identity at bb_mac_addr_1

This module handles the second and third.  It never substitutes the live peer for a stored
slot: the live peer says who the VTX is linked to right now, which is not what is stored in
either slot, and showing it under a role label is a silent placeholder.
"""
from __future__ import annotations

import hashlib
import platform
import socket
import struct
import zlib

from caddx_sky_user_cfg import (
    KEY_FALLBACK,
    KEY_PRIMARY,
    LABEL_FALLBACK,
    LABEL_PRIMARY,
    bb_id_is_routable,
    format_bb_id,
    parse_user_cfg,
)

# --------------------------------------------------------------------------- wire format
# Mirror of firmware/sky_rndis_provision/sky_prov_wire.h.  Kept constant-for-constant, and
# tests/test_sky_rndis_provision.py::WireFormatParityTests reads that header and fails if
# the two ever drift.
MAGIC = 0x56505341            # "ASPV" little-endian
VERSION = 1
SERVICE_REV = 1

PORT = 50124
DEVICE_ADDR = '192.168.3.104'   # usb_ip.sh:7, hardcoded on every Sky
BIND_IFACE = 'usb0'             # config_ether.sh:42-45

OP_GET_SLOTS = 1
OP_SET_SLOTS = 2

REQ_LEN = 32
RESP_HDR_LEN = 64
DOC_MAX = 4096

REQ_OFF_MAGIC = 0
REQ_OFF_VERSION = 4
REQ_OFF_OP = 5
REQ_OFF_PRIMARY = 8
REQ_OFF_FALLBACK = 12
REQ_OFF_CRC = 28

RESP_OFF_MAGIC = 0
RESP_OFF_VERSION = 4
RESP_OFF_OP = 5
RESP_OFF_STATUS = 6
RESP_OFF_FLAGS = 7
RESP_OFF_DOCLEN = 8
RESP_OFF_DOCCRC = 12
RESP_OFF_PRIMARY = 16
RESP_OFF_FALLBACK = 20
RESP_OFF_SERVICE = 24
RESP_OFF_DETAIL = 28
RESP_DETAIL_LEN = 32
RESP_OFF_CRC = 60

FLAG_PRIMARY = 0x01
FLAG_FALLBACK = 0x02

# user_cfg_store.h result codes, plus the transport-level rejections from sky_prov_wire.h.
UCFG_STATUS = {
    0: ('OK', 'ok'),
    -1: ('TARGET_NOT_PERMITTED', 'target not permitted'),
    -2: ('USER_CFG_OPEN_FAILED', 'cannot open config'),
    -3: ('USER_CFG_TOO_LARGE', 'config too large'),
    -4: ('USER_CFG_READ_FAILED', 'config read failed'),
    -5: ('PRIMARY_SLOT_MISSING', 'bb_mac_addr_0 missing'),
    -6: ('FALLBACK_SLOT_MISSING', 'bb_mac_addr_1 missing'),
    -7: ('PRIMARY_SLOT_MALFORMED', 'bb_mac_addr_0 must be four 0xNN strings'),
    -8: ('FALLBACK_SLOT_MALFORMED', 'bb_mac_addr_1 must be four 0xNN strings'),
    -9: ('BB_ID_NOT_ROUTABLE', 'bb_mac_addr_0 is not a routable BB ID'),
    -10: ('BB_ID_NOT_ROUTABLE', 'bb_mac_addr_1 is not a routable BB ID'),
    -11: ('USER_CFG_CAPACITY', 'config would exceed capacity'),
    -12: ('USER_CFG_WRITE_FAILED', 'config write failed'),
    -13: ('USER_CFG_RENAME_FAILED', 'config rename failed'),
    -14: ('DEVICE_VERIFY_FAILED', 'readback verify failed'),
    -40: ('SERVICE_REJECTED_FRAME', 'bad magic'),
    -41: ('SERVICE_REJECTED_FRAME', 'unsupported protocol version'),
    -42: ('SERVICE_REJECTED_FRAME', 'unsupported operation'),
    -43: ('SERVICE_REJECTED_FRAME', 'request CRC mismatch'),
    -44: ('SERVICE_REJECTED_FRAME', 'reserved field was not zero'),
}

OPERATION_ID = 'sky_receiver_slot_provisioning_rndis'
TRANSPORT_ID = 'usb_c_rndis'

BB_RPC_PORT = 50000
IP_UNICAST_IF = 31


class SkyRndisProvisionError(RuntimeError):
    """Fail-closed error for a USB-C provisioning transaction."""

    def __init__(self, code: str, message: str, *, stage: str | None = None,
                 evidence: dict | None = None):
        super().__init__(message)
        self.code = code
        self.stage = stage
        self.evidence = evidence or {}


def crc32(data: bytes) -> int:
    return zlib.crc32(bytes(data)) & 0xFFFFFFFF


# --------------------------------------------------------------------------- framing ----

def build_request(op: int, primary: bytes = b'\0' * 4, fallback: bytes = b'\0' * 4) -> bytes:
    """Build the fixed 32-byte request.

    A commit carries eight bytes of BB ID and nothing else: no path, no filename, no
    document, no length that drives a file operation on the device.  That is the whole reason
    this transport is narrow, and it is why there is no parameter here for a target.
    """
    if op not in (OP_GET_SLOTS, OP_SET_SLOTS):
        raise SkyRndisProvisionError('UNSUPPORTED_OPERATION',
                                     f'operation {op} is not part of this transport', stage='prepare')
    if op == OP_GET_SLOTS and (primary != b'\0' * 4 or fallback != b'\0' * 4):
        raise SkyRndisProvisionError('READ_CARRIES_NO_DATA',
                                     'a typed read must carry no slot data', stage='prepare')
    if op == OP_SET_SLOTS:
        for raw, label in ((primary, LABEL_PRIMARY), (fallback, LABEL_FALLBACK)):
            if len(raw) != 4:
                raise SkyRndisProvisionError('BB_ID_MALFORMED', f'{label} must be four bytes',
                                             stage='prepare')
            if not bb_id_is_routable(raw):
                raise SkyRndisProvisionError('BB_ID_NOT_ROUTABLE',
                                             f'{label} is not a routable BB ID', stage='prepare')
    buf = bytearray(REQ_LEN)
    struct.pack_into('<I', buf, REQ_OFF_MAGIC, MAGIC)
    buf[REQ_OFF_VERSION] = VERSION
    buf[REQ_OFF_OP] = op
    buf[REQ_OFF_PRIMARY:REQ_OFF_PRIMARY + 4] = bytes(primary)
    buf[REQ_OFF_FALLBACK:REQ_OFF_FALLBACK + 4] = bytes(fallback)
    struct.pack_into('<I', buf, REQ_OFF_CRC, crc32(bytes(buf[:REQ_OFF_CRC])))
    return bytes(buf)


def status_code(status: int) -> tuple[str, str]:
    return UCFG_STATUS.get(status, ('DEVICE_ERROR', f'device status {status}'))


def parse_response(raw: bytes) -> dict:
    """Parse and fully validate a service response.  Fails closed on anything unexpected."""
    if len(raw) < RESP_HDR_LEN:
        raise SkyRndisProvisionError('SHORT_RESPONSE',
                                     f'response header is {len(raw)} bytes, expected {RESP_HDR_LEN}',
                                     stage='response')
    hdr = raw[:RESP_HDR_LEN]
    if struct.unpack_from('<I', hdr, RESP_OFF_MAGIC)[0] != MAGIC:
        raise SkyRndisProvisionError('BAD_RESPONSE_MAGIC',
                                     'the peer on this port is not the provisioning service',
                                     stage='response')
    if struct.unpack_from('<I', hdr, RESP_OFF_CRC)[0] != crc32(hdr[:RESP_OFF_CRC]):
        raise SkyRndisProvisionError('RESPONSE_CRC_MISMATCH',
                                     'response header CRC does not match', stage='response')
    version = hdr[RESP_OFF_VERSION]
    if version != VERSION:
        raise SkyRndisProvisionError('PROTOCOL_VERSION_MISMATCH',
                                     f'device speaks provisioning protocol {version}, host speaks {VERSION}',
                                     stage='response', evidence={'device_version': version})
    doc_len = struct.unpack_from('<I', hdr, RESP_OFF_DOCLEN)[0]
    if doc_len > DOC_MAX:
        raise SkyRndisProvisionError('DOCUMENT_TOO_LARGE',
                                     f'device declared a {doc_len}-byte document', stage='response')
    body = raw[RESP_HDR_LEN:]
    if len(body) != doc_len:
        raise SkyRndisProvisionError('DOCUMENT_LENGTH_MISMATCH',
                                     f'device declared {doc_len} document bytes and sent {len(body)}',
                                     stage='response')
    doc_crc = struct.unpack_from('<I', hdr, RESP_OFF_DOCCRC)[0]
    integrity = {
        'method': 'service_crc32',
        'verified': (crc32(body) == doc_crc) if doc_len else None,
        'expected_crc32': f'{doc_crc:08x}',
        'actual_crc32': f'{crc32(body):08x}' if doc_len else None,
        'error': None if doc_len else 'no_document_returned',
    }
    status = struct.unpack_from('<b', hdr, RESP_OFF_STATUS)[0]
    code, text = status_code(status)
    detail = hdr[RESP_OFF_DETAIL:RESP_OFF_DETAIL + RESP_DETAIL_LEN].split(b'\0', 1)[0]
    flags = hdr[RESP_OFF_FLAGS]
    return {
        'op': hdr[RESP_OFF_OP],
        'status': status,
        'status_code': code,
        'status_text': text,
        'detail': detail.decode('ascii', 'replace'),
        'service_revision': struct.unpack_from('<I', hdr, RESP_OFF_SERVICE)[0],
        'device_reported': {
            'primary_present': bool(flags & FLAG_PRIMARY),
            'fallback_present': bool(flags & FLAG_FALLBACK),
            'primary_receiver_bb_id': (format_bb_id(hdr[RESP_OFF_PRIMARY:RESP_OFF_PRIMARY + 4])
                                       if flags & FLAG_PRIMARY else None),
            'fallback_receiver_bb_id': (format_bb_id(hdr[RESP_OFF_FALLBACK:RESP_OFF_FALLBACK + 4])
                                        if flags & FLAG_FALLBACK else None),
        },
        'document': bytes(body),
        'document_length': doc_len,
        'integrity': integrity,
    }


# --------------------------------------------------------------------------- transport --

def _pin_windows_ipv4_interface(sock: socket.socket, if_index: int | None) -> None:
    """Steer egress to one specific adapter.

    Multiple Ascent RNDIS devices expose the same device-side IP, so the destination address
    proves nothing about which unit answers. Binding the source address is not enough on
    Windows either; IP_UNICAST_IF is what actually pins the outbound interface.
    """
    if platform.system().lower() != 'windows':
        return
    if not if_index or int(if_index) <= 0:
        raise SkyRndisProvisionError('IFINDEX_REQUIRED',
                                     'a correlated Windows interface index is required before '
                                     'talking to a device-side RNDIS address', stage='transport')
    sock.setsockopt(socket.IPPROTO_IP, IP_UNICAST_IF, struct.pack('!I', int(if_index)))


def _exchange(request: bytes, *, host: str, port: int, source_ip: str | None,
              if_index: int | None, timeout: float) -> bytes:
    """One request, one response, one connection.

    The service serves a single connection at a time and closes it once the response is
    written, so a connection is never reused. Reading to EOF is therefore the framing.
    """
    raw = bytearray()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            _pin_windows_ipv4_interface(s, if_index)
            if source_ip:
                s.bind((source_ip, 0))
            s.settimeout(timeout)
            s.connect((host, port))
            s.sendall(request)
            while len(raw) < RESP_HDR_LEN + DOC_MAX:
                chunk = s.recv(4096)
                if not chunk:
                    break
                raw.extend(chunk)
    except ConnectionRefusedError as exc:
        raise SkyRndisProvisionError(
            'PROVISIONING_SERVICE_UNAVAILABLE',
            'nothing is listening on the receiver-slot provisioning port. Either this firmware '
            'does not carry the service, or the unit is not currently in RNDIS mode.',
            stage='transport', evidence={'host': host, 'port': port}) from exc
    except socket.timeout as exc:
        raise SkyRndisProvisionError('PROVISIONING_SERVICE_TIMEOUT',
                                     'the receiver-slot provisioning service did not answer',
                                     stage='transport',
                                     evidence={'host': host, 'port': port, 'timeout_s': timeout}) from exc
    except OSError as exc:
        raise SkyRndisProvisionError('PROVISIONING_TRANSPORT_ERROR',
                                     f'{type(exc).__name__}: {exc}', stage='transport',
                                     evidence={'host': host, 'port': port}) from exc
    if not raw:
        raise SkyRndisProvisionError('EMPTY_RESPONSE',
                                     'the provisioning service closed the connection without answering',
                                     stage='transport')
    return bytes(raw)


class SkyRndisSession:
    """A bound, interface-pinned conversation with one physical Sky over USB-C.

    ``source_ip`` and ``if_index`` are not optional in production: they are what tie this
    conversation to one physical device rather than to whichever RNDIS adapter Windows
    happened to route to.
    """

    def __init__(self, *, host: str = DEVICE_ADDR, port: int = PORT,
                 source_ip: str | None = None, if_index: int | None = None,
                 timeout: float = 4.0):
        self.host = host
        self.port = port
        self.source_ip = source_ip
        self.if_index = if_index
        self.timeout = timeout

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def _call(self, op: int, primary: bytes = b'\0' * 4, fallback: bytes = b'\0' * 4) -> dict:
        req = build_request(op, primary, fallback)
        return parse_response(_exchange(req, host=self.host, port=self.port,
                                        source_ip=self.source_ip, if_index=self.if_index,
                                        timeout=self.timeout))

    # ------------------------------------------------------------------ operations ----

    def read_slots(self) -> dict:
        """Typed read of /factory/user_cfg.json.

        The document is parsed **here**, with the same parser the serial route uses, rather
        than trusting the device's own parse. The device's parse is kept alongside so a
        disagreement is visible instead of silent.
        """
        r = self._call(OP_GET_SLOTS)
        if r['status'] != 0:
            raise SkyRndisProvisionError(r['status_code'], r['detail'] or r['status_text'],
                                         stage='read',
                                         evidence={'device_status': r['status'],
                                                   'service_revision': r['service_revision']})
        if r['integrity']['verified'] is not True:
            raise SkyRndisProvisionError('READ_INTEGRITY_UNVERIFIED',
                                         'the returned document did not match its CRC-32',
                                         stage='read', evidence={'integrity': r['integrity']})
        slots = parse_user_cfg(r['document'])
        disagreement = []
        for field in ('primary_receiver_bb_id', 'fallback_receiver_bb_id'):
            if slots.get(field) != r['device_reported'].get(field):
                disagreement.append({'field': field, 'host_parse': slots.get(field),
                                     'device_parse': r['device_reported'].get(field)})
        return {
            'slots': slots,
            'integrity': r['integrity'],
            'device_reported': r['device_reported'],
            'parse_disagreement': disagreement,
            'service_revision': r['service_revision'],
            'payload_length': r['document_length'],
            'transport': TRANSPORT_ID,
        }

    def commit_slots(self, primary: bytes, fallback: bytes) -> dict:
        """Commit both slots.  No reboot, no reconnect, no candidate SET.

        The device rewrites its own live document in place, two hex digits at a time, and
        verifies from the persisted file before it answers. The new PRIMARY becomes the boot
        candidate at the next power cycle.
        """
        r = self._call(OP_SET_SLOTS, primary, fallback)
        return {
            'accepted': r['status'] == 0,
            'status': r['status'],
            'status_code': r['status_code'],
            'detail': r['detail'] or r['status_text'],
            'device_reported': r['device_reported'],
            'service_revision': r['service_revision'],
            'rebooted': False,
            'transport': TRANSPORT_ID,
        }


def compare_readback(readback_slots: dict, expected_primary: bytes, expected_fallback: bytes) -> dict:
    """Compare the two slots only.

    Never compare document length or a digest across a write. The device re-serialises
    nothing here - it rewrites in place - but the rule stands regardless: it is the exact
    error that produced a false READBACK_MISMATCH on the RF bench on 2026-09-06, and a
    concurrent bind gesture could legitimately change bytes we did not write.
    """
    want_p, want_f = format_bb_id(expected_primary), format_bb_id(expected_fallback)
    got_p = readback_slots.get('primary_receiver_bb_id')
    got_f = readback_slots.get('fallback_receiver_bb_id')
    diffs = []
    if got_p != want_p:
        diffs.append({'slot': KEY_PRIMARY, 'label': LABEL_PRIMARY, 'expected': want_p, 'actual': got_p})
    if got_f != want_f:
        diffs.append({'slot': KEY_FALLBACK, 'label': LABEL_FALLBACK, 'expected': want_f, 'actual': got_f})
    return {'match': not diffs, 'differences': diffs,
            'expected': {KEY_PRIMARY: want_p, KEY_FALLBACK: want_f},
            'actual': {KEY_PRIMARY: got_p, KEY_FALLBACK: got_f}}


# --------------------------------------------------------------------------- identity ---

def bb_status_identity(*, host: str = DEVICE_ADDR, source_ip: str | None = None,
                       if_index: int | None = None, timeout: float = 1.5) -> dict:
    """Read the unit's own BB ID from the stock baseband RPC GET_STATUS.

    Payload bytes 6..9 are the local BB ID and 254..257 are the **live peer**, which is not a
    stored slot and must never be shown as one. Only the local BB ID is returned here, plus
    the raw link state for diagnostics.
    """
    hdr = bytearray(18)
    hdr[0] = 0xAA
    hdr[1:5] = (2).to_bytes(4, 'little')
    hdr[5:9] = (0x01000000).to_bytes(4, 'big')
    x = 0
    for b in hdr[:17]:
        x ^= b
    hdr[17] = (~x) & 0xFF
    req = bytes(hdr) + b'\x00\x00' + b'\xBB'
    try:
        raw = bytearray()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            _pin_windows_ipv4_interface(s, if_index)
            if source_ip:
                s.bind((source_ip, 0))
            s.settimeout(timeout)
            s.connect((host, BB_RPC_PORT))
            s.sendall(req)
            while len(raw) < 319:
                chunk = s.recv(4096)
                if not chunk:
                    break
                raw.extend(chunk)
    except OSError as exc:
        return {'ok': False, 'reason': type(exc).__name__, 'host': host}
    pos = raw.find(b'\xAA')
    if pos < 0 or len(raw) < pos + 19:
        return {'ok': False, 'reason': 'no valid RPC frame', 'host': host}
    n = int.from_bytes(raw[pos + 1:pos + 5], 'little')
    payload = bytes(raw[pos + 18:pos + 18 + n])
    if len(payload) < 258:
        return {'ok': False, 'reason': f'short STATUS payload {len(payload)}', 'host': host}
    return {'ok': True, 'host': host,
            'aircraft_bb_id': format_bb_id(payload[6:10]),
            'link_state_raw': payload[252],
            'payload_length': len(payload)}


# --------------------------------------------------------------------------- qualification

def qualify_rndis_provisioning(*, adapters: list | None, serial_interfaces: int | None,
                               binding: tuple | None, identity: dict | None,
                               reading: dict | None) -> dict:
    """Per-operation, fail-closed eligibility for a USB-C receiver-slot commit.

    There is no model profile and no VID/PID gate, for the same reason the serial route has
    none: every Ascent Sky presents identical USB identity, so a profile keyed on those would
    be keyed on nothing. What is gated instead:

    * **Exactly one** Ascent RNDIS adapter is present. Never the first of several - two
      present is ambiguity, and every Ascent RNDIS device answers on the same device-side
      address, so nothing downstream could tell them apart.
    * **No Ascent serial interface is present at the same time.** A Sky in RNDIS mode has
      given up its CDC port; a serial interface still present means a second Ascent device is
      attached, and provisioning is one unit at a time.
    * A usable host address and interface index on that adapter, so the socket can be bound
      and pinned rather than routed.
    * The unit answered the stock baseband RPC with its **own BB ID** - the only per-unit
      identifier a Sky has.
    * The device's own answer is the capability proof: a typed read that came back
      CRC-verified with a parseable PRIMARY slot proves both that this firmware carries the
      service and that this unit has receiver slots at all.
    """
    reasons: list[str] = []
    rows = adapters if isinstance(adapters, list) else None
    if rows is None:
        reasons.append('RNDIS_INVENTORY_UNAVAILABLE')
    elif len(rows) == 0:
        reasons.append('NO_ASCENT_RNDIS_ADAPTER')
    elif len(rows) > 1:
        reasons.append('AMBIGUOUS_MULTIPLE_RNDIS_ADAPTERS')

    if serial_interfaces is None:
        reasons.append('USB_INVENTORY_UNAVAILABLE')
    elif int(serial_interfaces) > 0:
        reasons.append('AMBIGUOUS_ASCENT_SERIAL_INTERFACE_PRESENT')

    if not binding or not binding[0] or not binding[1]:
        reasons.append('RNDIS_BINDING_UNRESOLVED')

    i = identity or {}
    if not i.get('ok') or not i.get('aircraft_bb_id'):
        reasons.append('AIRCRAFT_BB_ID_NOT_PROVEN')

    s = reading or {}
    if not s.get('available'):
        reasons.append('TYPED_USER_CFG_READ_NOT_AVAILABLE')
    elif s.get('supported') is False:
        reasons.append('PROVISIONING_SERVICE_UNAVAILABLE')
    else:
        if ((s.get('integrity') or {}).get('verified')) is not True:
            reasons.append('TYPED_USER_CFG_CRC_NOT_VERIFIED')
        if not (s.get('slots') or {}).get('primary_receiver_bb_id_present'):
            reasons.append('PRIMARY_SLOT_NOT_READABLE')
        if s.get('parse_disagreement'):
            reasons.append('HOST_DEVICE_PARSE_DISAGREEMENT')

    reasons = list(dict.fromkeys(reasons))
    return {
        'operation_id': OPERATION_ID,
        'transport': TRANSPORT_ID,
        'eligible': not reasons,
        'reasons': reasons,
        'evidence': {
            'ascent_rndis_adapters': (len(rows) if rows is not None else None),
            'ascent_serial_interfaces': serial_interfaces,
            'bound_source_ip': binding[0] if binding else None,
            'bound_ifindex': binding[1] if binding else None,
            'aircraft_bb_id': i.get('aircraft_bb_id'),
            'link_state_raw': i.get('link_state_raw'),
            'typed_read_crc_verified': ((s.get('integrity') or {}).get('verified') is True),
            'service_revision': s.get('service_revision'),
        },
    }


def selftest() -> dict:
    """Offline self-check of the framing, with no device and no socket."""
    req = build_request(OP_GET_SLOTS)
    assert len(req) == REQ_LEN
    assert crc32(req[:REQ_OFF_CRC]) == struct.unpack_from('<I', req, REQ_OFF_CRC)[0]
    doc = b'{\n    "bb_mac_addr_0": [\n        "0xF2",\n        "0x00",\n        "0x00",\n        "0x14"\n    ]\n}\n'
    hdr = bytearray(RESP_HDR_LEN)
    struct.pack_into('<I', hdr, RESP_OFF_MAGIC, MAGIC)
    hdr[RESP_OFF_VERSION] = VERSION
    hdr[RESP_OFF_OP] = OP_GET_SLOTS
    hdr[RESP_OFF_FLAGS] = FLAG_PRIMARY
    struct.pack_into('<I', hdr, RESP_OFF_DOCLEN, len(doc))
    struct.pack_into('<I', hdr, RESP_OFF_DOCCRC, crc32(doc))
    hdr[RESP_OFF_PRIMARY:RESP_OFF_PRIMARY + 4] = bytes.fromhex('f2000014')
    struct.pack_into('<I', hdr, RESP_OFF_SERVICE, SERVICE_REV)
    hdr[RESP_OFF_DETAIL:RESP_OFF_DETAIL + 2] = b'ok'
    struct.pack_into('<I', hdr, RESP_OFF_CRC, crc32(bytes(hdr[:RESP_OFF_CRC])))
    r = parse_response(bytes(hdr) + doc)
    assert r['integrity']['verified'] is True
    assert r['device_reported']['primary_receiver_bb_id'] == (':'.join(('F2', '00', '00', '14')))
    assert parse_user_cfg(r['document'])['primary_receiver_bb_id'] == (':'.join(('F2', '00', '00', '14')))
    return {'ok': True, 'operation_id': OPERATION_ID, 'transport': TRANSPORT_ID,
            'port': PORT, 'device_addr': DEVICE_ADDR,
            'request_bytes': REQ_LEN, 'response_header_bytes': RESP_HDR_LEN,
            'document_max': DOC_MAX, 'md5_of_selftest_doc': hashlib.md5(doc).hexdigest()}


if __name__ == '__main__':
    import json
    print(json.dumps(selftest(), indent=2))
