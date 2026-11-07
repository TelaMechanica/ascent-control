"""Read-only Relay factory TCP queries, traced in the exact 19.2.14 archive.

ar_fpvhs_mp_service (5751d7ca...): main binds TCP/6835; worker 0x184b4
dispatches system messages. IDs 3 and 22 read factory SN and saved cur_mode.
No write, reboot, security, shell or button commands are exposed here.
Live Ethernet replies are retained in phase4.75-relay-dual-side-deep-dive-2026-10-31.
Factory SN is raw (0150); updater USB identity adds a type prefix (4_0150).
That relationship alone is not a unique physical-device correlation.
"""
from __future__ import annotations

import ipaddress
import socket
import struct
import time

from caddx_relay_qos import _pin_interface

PORT = 6835


class FactoryReadError(ValueError):
    pass


def _read(sock, count, deadline):
    data = b""
    while len(data) < count:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Relay factory read timed out")
        sock.settimeout(remaining)
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise FactoryReadError("Incomplete factory reply")
        data += chunk
    return data


def _query(sock, message, deadline):
    if message not in (3, 22):
        raise FactoryReadError("Only serial-number and saved-role reads are offered")
    payload = bytes([message])
    header = bytearray(16)
    struct.pack_into("<HHHH", header, 0, 0xFAFA, 1, 0, len(payload))
    struct.pack_into("<HH", header, 12, sum(header[:12]) & 65535, sum(payload))
    sock.sendall(header + payload)
    reply = _read(sock, 16, deadline)
    magic, sequence, kind, length = struct.unpack_from("<HHHH", reply)
    if magic != 0xFAFA or kind != 0 or not 1 <= length <= 128:
        raise FactoryReadError("Unexpected factory reply header")
    data = _read(sock, length, deadline)
    if sum(data) & 65535 != struct.unpack_from("<H", reply, 14)[0]:
        raise FactoryReadError("Factory payload checksum mismatch")
    if data[0] != 1:
        raise FactoryReadError("Factory service did not accept this read")
    return data[1:]


def read_identity_role(host, *, source_ip, if_index, timeout=1.2):
    """One bounded connection, two reads, no retries; explicit source required."""
    host = str(ipaddress.IPv4Address(host))
    source_ip = str(ipaddress.IPv4Address(source_ip))
    timeout = max(0.2, min(float(timeout), 5.0))
    deadline = time.monotonic() + timeout
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        _pin_interface(sock, if_index)
        sock.bind((source_ip, 0))
        sock.settimeout(timeout)
        sock.connect((host, PORT))
        serial = _query(sock, 3, deadline).rstrip(b"\0").decode("ascii")
        if not serial or not serial.isprintable():
            raise FactoryReadError("Factory serial is missing or invalid")
        role = _query(sock, 22, deadline)
        if len(role) != 1:
            raise FactoryReadError("Unexpected saved-role reply length")
    return {"factory_serial": serial, "cur_mode": role[0],
            "source": "factory_tcp_6835", "correlation": "operator_asserted_ip"}
