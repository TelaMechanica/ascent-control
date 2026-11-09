"""Bounded MAX Ethernet observations and short vendor keys. No privileged access.

Endpoint selection is not USB identity. The caller owns selection/route checks,
serialization and operator confirmation; this module owns the fixed wire formats.
"""
from __future__ import annotations
import ipaddress
import re
import socket
import struct
import time
from datetime import datetime, timezone

import caddx_cgc as cgc
import caddx_relay_qos as framing
import vendor_rf_telemetry as telemetry

KEYS = ('UP', 'DOWN', 'LEFT', 'RIGHT', 'CONFIRM', 'BACK', 'PAIRING')
READS = {
    'status': (0x01000000, b'\0\0', 300),
    'mcs': (0x01000006, b'\0\0', 8),
    'power': (0x01000008, b'\x08', 2),
    'channels': (0x01000012, b'', 129),
    'rf_raw': (0x0100006b, b'\0\0\0\0', 216),
}


class EthernetError(ValueError):
    def __init__(self, code, message):
        self.code = code
        super().__init__(message)


def fast_route(host):
    """Read the Windows route/source without a PowerShell process or packets."""
    import ctypes
    if not hasattr(ctypes, 'WinDLL'):
        return None
    try:
        address = socket.inet_aton(str(ipaddress.IPv4Address(host)))
        class Address(ctypes.Structure):
            _fields_ = [('family', ctypes.c_ushort), ('port', ctypes.c_ushort),
                        ('address', ctypes.c_ubyte * 4), ('padding', ctypes.c_ubyte * 8)]
        destination = Address()
        destination.family = socket.AF_INET
        destination.address[:] = address
        index = ctypes.c_ulong()
        get_best = ctypes.WinDLL('iphlpapi', use_last_error=True).GetBestInterfaceEx
        get_best.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]
        get_best.restype = ctypes.c_ulong
        if get_best(ctypes.byref(destination), ctypes.byref(index)) or not index.value:
            return None
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect((str(host), 9))  # Route selection only: no datagram is sent.
            source = sock.getsockname()[0]
        return {'source_ip': source, 'if_index': index.value}
    except (OSError, ValueError, AttributeError):
        return None


def validate_target(target):
    if target.get('id') != 'network:max_eth' or target.get('kind') != 'vrx':
        raise EthernetError('MAX_ETH_NOT_SELECTED', 'Select MAX ETH and connect first.')
    for key in ('device_ip', 'source_ip'):
        try:
            addr = ipaddress.IPv4Address(target.get(key))
        except (ValueError, TypeError):
            raise EthernetError('MAX_ETH_ROUTE_UNKNOWN', 'The selected Ethernet route is unavailable.') from None
        if addr.is_unspecified or addr.is_multicast or addr.is_loopback or str(addr) == '255.255.255.255':
            raise EthernetError('MAX_ETH_ROUTE_UNKNOWN', 'A unicast receiver interface is required.')
    if target['device_ip'] == target['source_ip'] or type(target.get('if_index')) is not int or not 0 < target['if_index'] < 2**31:
        raise EthernetError('MAX_ETH_ROUTE_UNKNOWN', 'The selected Ethernet interface is unavailable.')


def _receive(sock, count, deadline):
    data = bytearray()
    while len(data) < count:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('Ethernet read deadline elapsed.')
        sock.settimeout(remaining)
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise EthernetError('MAX_ETH_REPLY_INCOMPLETE', 'The receiver reply ended early.')
        data.extend(chunk)
    return bytes(data)


def read_rpc(target, name, *, timeout=1.2):
    validate_target(target)
    if name not in READS:
        raise EthernetError('MAX_ETH_READ_UNKNOWN', 'This receiver read is not offered.')
    command, request, size = READS[name]
    deadline = time.monotonic() + timeout
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        framing._pin_interface(sock, target['if_index'])
        sock.bind((target['source_ip'], 0))
        sock.settimeout(timeout)
        sock.connect((target['device_ip'], 50000))
        sock.sendall(framing.build_frame(command, request))
        header = _receive(sock, 18, deadline)
        if (header[0] != 0xaa or header[17] != framing._checksum17(header[:17]) or
                int.from_bytes(header[5:9], 'big') != command or
                int.from_bytes(header[13:17], 'big') != 0):
            raise EthernetError('MAX_ETH_REPLY_MISMATCH', 'The RPC reply did not match the requested read.')
        # Live MAX replies assign an opaque tag in meta1; meta2 is the result.
        # One fresh TCP connection per read binds the reply to this request.
        if int.from_bytes(header[1:5], 'little') != size:
            raise EthernetError('MAX_ETH_REPLY_SIZE', 'This receiver returned a different record layout.')
        try:
            return framing.parse_frame(header + _receive(sock, size + 1, deadline))
        except framing.RelayQosError as exc:
            raise EthernetError('MAX_ETH_REPLY_INVALID', str(exc)) from exc


def decode(name, payload):
    if len(payload) != READS[name][2]:
        raise EthernetError('MAX_ETH_REPLY_SIZE', 'Unexpected receiver record length.')
    if name == 'status':
        link = payload[252]
        return {'local_bb_id': ':'.join(f'{b:02X}' for b in payload[6:10]),
                'link': {0: 'UNLINKED', 1: 'SEARCHING', 2: 'LINKED'}.get(link, 'Unknown'),
                'link_raw': link, 'rx_mcs_raw': payload[253] if link == 2 else None}
    if name == 'mcs':
        return {'mcs_encoded_raw': payload[0], 'throughput_raw': struct.unpack_from('<I', payload, 4)[0]}
    if name == 'power':
        return {'selector_raw': payload[0], 'power_raw': payload[1]}
    if name == 'channels':
        return telemetry.parse_work_channels(payload)
    return telemetry.parse_debug_rf(payload)


def require_same_receiver(target, status):
    expected = ((target.get('observed') or {}).get('status') or {}).get('decoded') or {}
    before, after = expected.get('local_mac4'), status.get('local_bb_id')
    if not isinstance(before, str) or not re.fullmatch(r'(?:[0-9A-Fa-f]{2}:){3}[0-9A-Fa-f]{2}', before):
        raise EthernetError('MAX_ETH_IDENTITY_UNKNOWN', 'Reconnect to establish the receiver baseband identity.')
    raw = bytes.fromhex(before.replace(':', ''))
    if raw in (bytes(4), b'\xff' * 4, bytes((0x66, 0, 0, 0))) or before.upper() != str(after).upper():
        raise EthernetError('MAX_ETH_IDENTITY_CHANGED', 'Receiver identity changed. Reconnect before using remote keys.')


def key_request(body):
    allowed = {'key', 'connection_token', 'confirm_pairing', 'acknowledge_non_stock'}
    if not isinstance(body, dict) or set(body) - allowed or body.get('key') not in KEYS:
        raise EthernetError('MAX_ETH_KEY_UNKNOWN', 'Choose a short menu key or pairing.')
    if body['key'] == 'PAIRING' and (body.get('confirm_pairing') is not True or body.get('acknowledge_non_stock') is not True):
        raise EthernetError('MAX_ETH_PAIR_CONFIRM', 'Confirm pairing; it can interrupt the existing link.')
    return body['key']


def send_key(target, key):
    validate_target(target)
    if key not in KEYS:
        raise EthernetError('MAX_ETH_KEY_UNKNOWN', 'This remote key is not offered.')
    frame = cgc.build_key(key)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        framing._pin_interface(sock, target['if_index'])
        sock.bind((target['source_ip'], 0))
        sock.settimeout(0.9)
        sock.connect((target['device_ip'], 9001))
        if sock.send(frame) != len(frame):
            raise EthernetError('MAX_ETH_SEND_UNKNOWN', 'The complete key request was not confirmed sent. Outcome is unknown.')
    return {'ok': True, 'key': key, 'state': 'SENT', 'execution_verified': False,
            'pairing_verified': False, 'retry': False,
            'message': 'Key request sent. Receiver action has not been verified.'}


def rtsp_status(target, *, timeout=0.9):
    validate_target(target)
    deadline = time.monotonic() + timeout
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        framing._pin_interface(sock, target['if_index'])
        sock.bind((target['source_ip'], 0))
        sock.settimeout(timeout)
        sock.connect((target['device_ip'], 554))
        sock.sendall(('OPTIONS rtsp://' + target['device_ip'] + '/live.ch01 RTSP/1.0\r\nCSeq: 1\r\n\r\n').encode('ascii'))
        data = bytearray()
        while b'\r\n\r\n' not in data and len(data) < 4096:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('RTSP read deadline elapsed.')
            sock.settimeout(remaining)
            chunk = sock.recv(min(1024, 4096 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
    line = bytes(data).split(b'\r\n', 1)[0].decode('ascii', errors='replace')
    if not re.fullmatch(r'RTSP/1\.0 [0-9]{3}[^\r\n]*', line):
        raise EthernetError('MAX_ETH_RTSP_REPLY', 'The endpoint did not return an RTSP status line.')
    return {'responding': True, 'status': line, 'playback_verified': False}


def document(target, *, check=lambda: None, reader=None, rtsp=None):
    validate_target(target)
    reader, rtsp = reader or read_rpc, rtsp or rtsp_status
    result = {'ok': True, 'captured_at': datetime.now(timezone.utc).isoformat(),
              'identity_proven': False, 'identity_scope': 'selected Ethernet endpoint; USB identity unavailable',
              'layout_scope': 'MAX reference layouts; physical units for raw RF fields remain unqualified',
              'reads': {}, 'controls': {'eligible': False, 'keys': list(KEYS)}}
    for name in READS:
        check()
        try:
            payload = reader(target, name)
            check()
            values = decode(name, payload)
            result['reads'][name] = {'ok': True, 'bytes': len(payload), 'values': values}
            if name == 'status':
                try:
                    require_same_receiver(target, values)
                    result['controls']['eligible'] = True
                except EthernetError as exc:
                    if exc.code == 'MAX_ETH_IDENTITY_CHANGED':
                        raise
                    result['controls']['reason'] = str(exc)
        except (OSError, ValueError) as exc:
            if isinstance(exc, EthernetError) and exc.code in ('MAX_ETH_IDENTITY_CHANGED', 'MAX_ETH_TARGET_CHANGED', 'MAX_ETH_ROUTE_CHANGED'):
                raise
            result['reads'][name] = {'ok': False, 'error': str(exc)}
    check()
    try:
        result['rtsp'] = rtsp(target)
    except (OSError, ValueError) as exc:
        result['rtsp'] = {'responding': False, 'error': str(exc), 'playback_verified': False}
    check()
    return result
