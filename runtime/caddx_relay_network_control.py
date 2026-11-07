"""Bounded Relay Ethernet buttons and role reversal; no general command API.

Bench: Relay4_0150 /19.2.14, 2026-10-31. HF GPIO0 and MF GPIO48 five-second
presses were physically confirmed. Factory role23 + reboot9 was confirmed by
physical observation and network readback. The current one-second bind hold is operator-requested and awaits physical verification.
No files or services are installed.
The platform's empty reply acknowledges dispatch, not GPIO execution or pairing.
"""
from __future__ import annotations
import ipaddress
import socket
import struct
import time
import caddx_relay_factory as factory
import caddx_relay_qos as qos
from caddx_relay_press import PIN_HF, PIN_MF


class NetworkControlError(ValueError):
    pass


def validate_target(target):
    observed = target.get('observed') or {}
    identity = observed.get('factory') or {}
    radios = (observed.get('qos') or {}).get('radios') or {}
    if target.get('id') != 'network:repeater_eth':
        raise NetworkControlError('Select REPEATER ETH and connect first.')
    if not identity.get('factory_serial') or identity.get('cur_mode') not in (2, 3):
        raise NetworkControlError('Read the Relay identity and role before using network controls.')
    ids = []
    for key in ('0', '1'):
        radio = radios.get(key) or {}
        if not radio.get('status_ok') or not radio.get('local_mac') or radio.get('role_raw') not in (0, 1):
            raise NetworkControlError('Read both Relay radios before using network controls.')
        ids.append(radio['local_mac'])
    if len(set(ids)) != 2 or {radios[k]['role_raw'] for k in ('0', '1')} != {0, 1}:
        raise NetworkControlError('The two radio identities or roles are not established.')
    ipaddress.IPv4Address(target['device_ip'])
    ipaddress.IPv4Address(target['source_ip'])
    if not isinstance(target.get('if_index'), int) or target['if_index'] <= 0:
        raise NetworkControlError('The PC network interface is not established.')


def _press_script(action):
    pin = {'hf': PIN_HF, 'mf': PIN_MF}[action]
    return (f'G=/sys/class/gpio/gpio{pin}; test "$(cat "$G/direction")" = in || exit 1; '
            'trap \'echo in >"$G/direction"\' EXIT HUP INT TERM; '
            'echo out >"$G/direction" && echo 0 >"$G/value" && sleep 1')


def _factory_control_frame(payload):
    if payload not in (b'\x17\0\x02', b'\x17\0\x03', b'\x09'):
        raise NetworkControlError('This control message is not offered.')
    h = bytearray(16)
    struct.pack_into('<HHHH', h, 0, 0xfafa, 1, 0, len(payload))
    struct.pack_into('<HH', h, 12, sum(h[:12]) & 65535, sum(payload) & 65535)
    return bytes(h) + payload


def _factory_ack(sock):
    deadline = time.monotonic() + 2
    h = factory._read(sock, 16, deadline)
    magic, seq, kind, length = struct.unpack_from('<HHHH', h)
    if magic != 0xfafa or kind != 0 or not 1 <= length <= 128:
        raise NetworkControlError('Unexpected role-write reply.')
    body = factory._read(sock, length, deadline)
    if sum(body) & 65535 != struct.unpack_from('<H', h, 14)[0] or body[0] != 1:
        raise NetworkControlError('The role write was not acknowledged.')


def perform(target, action):
    """Caller owns device/serial gates; a single request, never automatic retry."""
    if action not in ('hf', 'mf', 'swap'):
        raise NetworkControlError('Choose HF bind, MF bind or reverse roles.')
    validate_target(target)
    host, source, index = target['device_ip'], target['source_ip'], target['if_index']
    expected = target['observed']
    fresh = factory.read_identity_role(host, source_ip=source, if_index=index, timeout=2)
    if fresh['factory_serial'] != expected['factory']['factory_serial'] or fresh['cur_mode'] != expected['factory']['cur_mode']:
        raise NetworkControlError('The Relay identity or saved role changed. Read Ethernet status again.')
    for key in ('0', '1'):
        read = qos.read_qos(host, int(key), 'status', source_ip=source, if_index=index)
        actual = read.get('decoded') or {}
        before = expected['qos']['radios'][key]
        if (read.get('error') or not read.get('length_match')
                or actual.get('local_mac4') != before['local_mac']
                or actual.get('role_raw') != before['role_raw']):
            raise NetworkControlError('A radio identity or role changed. Read Ethernet status again.')
        if actual.get('slot0_link_state') != 0:
            raise NetworkControlError('Network button control is currently qualified only with both radio links idle.')
    result = {'ok': True, 'action': action, 'device_ip': host,
              'factory_serial': fresh['factory_serial'], 'transport': 'ethernet',
              'execution_verified': False, 'pairing_verified': False, 'retry': False}
    port = factory.PORT if action == 'swap' else qos.RELAY_RPC_PORT
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        qos._pin_interface(sock, index)
        sock.bind((source, 0))
        sock.settimeout(8)
        sock.connect((host, port))
        if action == 'swap':
            # Re-prove factory identity on the same connection that will write.
            serial = factory._query(sock, 3, time.monotonic()+2).rstrip(b'\0').decode('ascii')
            mode = factory._query(sock, 22, time.monotonic()+2)
            if serial != fresh['factory_serial'] or mode != bytes([fresh['cur_mode']]):
                raise NetworkControlError('The target changed before the role write.')
            new_mode = 3 if fresh['cur_mode'] == 2 else 2
            sock.sendall(_factory_control_frame(bytes([23, 0, new_mode])))
            _factory_ack(sock)
            if factory._query(sock, 22, time.monotonic()+2) != bytes([new_mode]):
                raise NetworkControlError('Saved role did not read back. Reboot was withheld.')
            sock.sendall(_factory_control_frame(b'\x09'))
            result.update(state='REBOOT_REQUESTED', saved_mode=new_mode, requires_reconnect=True)
        else:
            command = 0x0c000004
            sock.sendall(qos.build_frame(command, _press_script(action).encode('ascii')))
            deadline = time.monotonic() + 8
            header = factory._read(sock, 18, deadline)
            length = int.from_bytes(header[1:5], 'little')
            if header[0] != 0xaa or int.from_bytes(header[5:9], 'big') != command or length > 2048:
                raise NetworkControlError('Unexpected button reply. Outcome is unknown; do not retry automatically.')
            qos.parse_frame(header + factory._read(sock, length+1, deadline))
            # Keep the host gates through the fixed hold/release window.
            time.sleep(1.2)
            result.update(state='REQUEST_ACKNOWLEDGED', hold_seconds=1,
                          message='Request acknowledged. Check the receiver LED; pairing is not verified.')
    return result
