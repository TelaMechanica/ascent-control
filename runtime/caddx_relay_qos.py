"""Ascent Relay QoS reader over the AR8030 usbpack RPC (TCP/50000).

Per-radio live link quality for a Relay reached at its OWN IP: MCS, throughput,
RX-MCS, baseband power and the current hopping frequency, read straight from the
baseband through the stock read-only GET ioctls.

Evidence / provenance
---------------------
The wire framing is NOT invented here. It is the AR8030 `usbpack` RPC that this
project already drives for the Ground STATUS read, re-confirmed byte-for-byte:

  * 18-byte header, `0xAA` start / `0xBB` trailer, uint32-LE payload length,
    uint32-BE command, uint32-BE meta1 (= work_id), uint32-BE meta2, and a
    complement-XOR checksum over header bytes 0..16 -- identical to
    `caddx_read_bundle.bb_rpc_status` and `dev_harness.bb_frame`.
  * The STATUS ioctl is command `0x01000000` and its 300-byte reply places the
    local BbId at offset 6, link state at 252 and RX-MCS at 253 -- the SAME
    offsets the proven Ground STATUS reader uses, which cross-validates the
    layout of the frame this module parses.

The ioctl command table and the per-field QoS decodes (mcs/throughput/power/
channel) come from the stock 19.2.4 `ar_fpvhs_relay` / `libar_bb` prior art.

Confidence
----------
  * TRANSPORT: CONFIRMED -- byte-identical to the proven Ground STATUS path.
  * `current_mcs = raw - 2` and power dBm at `payload[1]` remain
    INFERRED from vendor code; linked-RF accuracy is not qualified.
  * Work IDs do not establish aircraft/ground sides: a 2026-10-31 Ethernet
    before/after swap observed role codes reverse with stable BBIDs.
    Return neutral labels and observed role codes, never a fixed side guess.

Read-only: only GET ioctls are issued. There is no SET path in this module.

Transport note: a Relay reached at an operator-asserted LAN/eth IP has no USB
ContainerId, so the socket MUST be bound to an explicitly resolved source IP /
interface (via the host's `resolve_nic_for_ip`). This module never opens an
unbound socket; "destination IP is not identity" still holds.
"""
from __future__ import annotations

import platform
import socket
import struct
import time
from typing import Optional

SCHEMA = "ascent.relay_qos.v1"
RELAY_RPC_PORT = 50000
IP_UNICAST_IF = 31  # Windows socket option; pins egress interface by ifIndex.

# Read-only BB ioctls: (command, input bytes, expected output length) from the
# 19.2.4 libar_bb table. ONLY GET ioctls appear here by design.
BB_GET_STATUS = 0x01000000
BB_GET_MCS = 0x01000006
BB_GET_CURRENT_POWER = 0x01000008
BB_GET_CHANNEL_INFO = 0x0100000A

#: name -> (command, input_payload, expected_output_length)
QOS_SPECS = {
    "mcs-throughput": (BB_GET_MCS, b"\x00\x00", 8),
    "status": (BB_GET_STATUS, b"\x00\x00", 300),
    "current-power": (BB_GET_CURRENT_POWER, b"\x08", 2),  # 0x08 is a slot selector
    "channel-info": (BB_GET_CHANNEL_INFO, b"", 964),
}

# Work IDs survive a role swap; roles do not. Ethernet before/after evidence on
# 2026-10-31 observed 0/1 -> 1/0 role codes with the same BBIDs. Do not fix a
# physical radio's aircraft/ground role from its work ID.
SIDE_HINT = {
    0: {"label": "Work ID 0", "radio": None, "role": None, "device": None},
    1: {"label": "Work ID 1", "radio": None, "role": None, "device": None},
}


class RelayQosError(RuntimeError):
    """Typed relay-QoS failure. The dev_harness endpoint translates it to a
    JSON error body; the polling helpers below catch it into an error dict so a
    single bad read never aborts a sweep."""

    def __init__(self, code: str, message: str, evidence: Optional[dict] = None):
        super().__init__(message)
        self.code = code
        self.evidence = evidence or {}


# --------------------------------------------------------------------------- #
# Wire framing (the AR8030 usbpack RPC) -- self-contained, no dev_harness import
# --------------------------------------------------------------------------- #

def _checksum17(b) -> int:
    x = 0
    for v in b[:17]:
        x ^= v
    return (~x) & 0xFF


def build_frame(cmd: int, payload: bytes = b"", meta1: int = 0, meta2: int = 0) -> bytes:
    h = bytearray(18)
    h[0] = 0xAA
    h[1:5] = len(payload).to_bytes(4, "little")
    h[5:9] = (cmd & 0xFFFFFFFF).to_bytes(4, "big")
    h[9:13] = (meta1 & 0xFFFFFFFF).to_bytes(4, "big")
    h[13:17] = (meta2 & 0xFFFFFFFF).to_bytes(4, "big")
    h[17] = _checksum17(h)
    return bytes(h) + payload + b"\xBB"


def parse_frame(raw: bytes) -> bytes:
    """Return the payload of the first valid frame in `raw`, or raise."""
    pos = raw.find(b"\xAA")
    if pos < 0 or len(raw) < pos + 19:
        raise RelayQosError("NO_FRAME", "no valid RPC frame in reply")
    n = int.from_bytes(raw[pos + 1:pos + 5], "little")
    if n > (1 << 20):
        raise RelayQosError("FRAME_TOO_LONG", f"implausible payload length {n}")
    if _checksum17(raw[pos:pos + 17]) != raw[pos + 17]:
        raise RelayQosError("BAD_CHECKSUM", "frame checksum mismatch")
    if len(raw) < pos + 18 + n + 1 or raw[pos + 18 + n] != 0xBB:
        raise RelayQosError("INCOMPLETE_FRAME", "RPC frame is incomplete or has an invalid trailer")
    return raw[pos + 18:pos + 18 + n]


def _pin_interface(sock: socket.socket, if_index) -> None:
    if platform.system().lower() != "windows":
        return
    if not if_index or int(if_index) <= 0:
        raise RelayQosError(
            "NO_INTERFACE",
            "Relay RPC reads require the resolved Windows interface index")
    sock.setsockopt(socket.IPPROTO_IP, IP_UNICAST_IF, struct.pack("!I", int(if_index)))


# --------------------------------------------------------------------------- #
# Decoders -- one per QoS read. Short payloads set `decode_error`, never raise.
# --------------------------------------------------------------------------- #

def _mac4(b) -> str:
    return ":".join(f"{x:02x}" for x in b)


def decode_qos(name: str, payload: bytes) -> dict:
    d = {"payload_length": len(payload)}
    if name == "mcs-throughput":
        if len(payload) < 8:
            d["decode_error"] = f"short payload ({len(payload)}<8)"
            return d
        d["mcs_encoded_raw"] = payload[0]
        d["current_mcs"] = int(payload[0]) - 2  # INFERRED: raw-2
        d["throughput_kbps"] = struct.unpack_from("<I", payload, 4)[0]
    elif name == "current-power":
        if len(payload) < 2:
            d["decode_error"] = f"short payload ({len(payload)}<2)"
            return d
        d["byte0_raw"] = payload[0]
        d["current_power_dbm"] = payload[1]  # INFERRED: dBm at byte 1
    elif name == "status":
        if len(payload) < 258:
            d["decode_error"] = f"short payload ({len(payload)}<258)"
            return d
        d["role_raw"] = payload[0]
        d["mode_raw"] = payload[1]
        d["configured_slot_bitmap"] = payload[4]
        d["runtime_slot_bitmap"] = payload[5]
        d["local_mac4"] = _mac4(payload[6:10])
        d["slot0_link_state"] = payload[0xFC]
        d["slot0_rx_mcs_raw"] = payload[0xFD]
        d["slot0_peer_mac4"] = _mac4(payload[0xFE:0x102])
    elif name == "channel-info":
        if len(payload) < 8:
            d["decode_error"] = f"short payload ({len(payload)}<8)"
            return d
        count = payload[0]
        index = payload[3]
        max_entries = (len(payload) - 4) // 4
        n = min(count, max_entries, 240)
        d["frequency_count_raw"] = count
        d["current_index_raw"] = index
        d["frequency_list_raw"] = [
            struct.unpack_from("<I", payload, 4 + i * 4)[0] for i in range(n)]
        if index < max_entries:
            cur = struct.unpack_from("<I", payload, 4 + index * 4)[0]
            d["current_frequency_raw"] = cur
            if 1_000_000 <= cur <= 10_000_000:
                d["current_frequency_mhz"] = cur / 1000.0
    else:
        d["decode_error"] = f"unknown read {name!r}"
    return d


# --------------------------------------------------------------------------- #
# One QoS read. Never raises -- returns an error dict so a sweep tolerates a
# single failed read (monitor-style polling).
# --------------------------------------------------------------------------- #

def read_qos(host: str, work_id: int, name: str, *,
             source_ip: Optional[str] = None, if_index: Optional[int] = None,
             timeout: float = 1.2) -> dict:
    out = {
        "name": name, "work_id": work_id,
        "command_hex": None, "expected_output_length": None,
        "error": None, "decoded": None, "length_match": None,
    }
    if name not in QOS_SPECS:
        out["error"] = f"unknown QoS read {name!r}"
        return out
    cmd, payload_in, expected = QOS_SPECS[name]
    out["command_hex"] = f"0x{cmd:08x}"
    out["expected_output_length"] = expected
    if not source_ip:
        out["error"] = ("Relay RPC requires an exact source IP; resolve the NIC "
                        "for the relay's IP first")
        return out
    req = build_frame(cmd, payload_in, meta1=work_id)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            _pin_interface(s, if_index)
            s.bind((source_ip, 0))  # bind before connect: destination IP alone is not identity
            s.settimeout(timeout)
            s.connect((host, RELAY_RPC_PORT))
            s.sendall(req)
            raw = b""
            deadline = time.monotonic() + timeout
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                s.settimeout(max(0.05, remaining))
                try:
                    chunk = s.recv(4096)
                except socket.timeout:
                    break
                if not chunk:
                    break
                raw += chunk
                # Stop as soon as a complete declared frame is in hand.
                pos = raw.find(b"\xAA")
                if pos >= 0 and len(raw) >= pos + 19:
                    n = int.from_bytes(raw[pos + 1:pos + 5], "little")
                    if len(raw) >= pos + 19 + n:
                        break
        payload = parse_frame(raw)
        out["length_match"] = (len(payload) == expected)
        pos = raw.find(b"\xAA")
        if int.from_bytes(raw[pos + 5:pos + 9], "big") != cmd:
            raise RelayQosError("WRONG_COMMAND", "RPC reply does not match the requested read")
        if not out["length_match"]:
            raise RelayQosError("WRONG_LENGTH", "RPC reply has an unexpected payload length")
        out["decoded"] = decode_qos(name, payload)
    except RelayQosError as e:
        out["error"] = f"{e.code}: {e}"
    except OSError as e:
        out["error"] = f"{type(e).__name__}: {e}"
    return out


# --------------------------------------------------------------------------- #
# Per-radio and whole-relay aggregation
# --------------------------------------------------------------------------- #

def read_radio(host: str, work_id: int, *,
               source_ip: Optional[str] = None, if_index: Optional[int] = None,
               timeout: float = 1.2) -> dict:
    """Bundle the QoS reads for one radio into a stable per-radio dict."""
    hint = SIDE_HINT.get(
        work_id, {"label": None, "radio": None, "role": None, "device": None})
    radio = {
        "work_id": work_id, **hint,
        "mcs": None, "throughput_kbps": None, "rx_mcs_raw": None,
        "link_state": None, "power_dbm": None, "frequency_mhz": None,
        "channel_count": None, "channel_index": None,
        "local_mac": None, "peer_mac": None,
        "slot_bitmap_config": None, "slot_bitmap_runtime": None,
        "errors": {},
    }

    def pull(read_name):
        r = read_qos(host, work_id, read_name,
                     source_ip=source_ip, if_index=if_index, timeout=timeout)
        if r.get("error"):
            radio["errors"][read_name] = r["error"]
            return None
        dec = r.get("decoded") or {}
        if dec.get("decode_error"):
            radio["errors"][read_name] = dec["decode_error"]
        return dec

    m = pull("mcs-throughput")
    if m:
        radio["mcs_encoded_raw"] = m.get("mcs_encoded_raw")
        radio["mcs"] = m.get("current_mcs")
        radio["throughput_kbps"] = m.get("throughput_kbps")
    st = pull("status")
    if st:
        radio["role_raw"] = st.get("role_raw")
        radio["rx_mcs_raw"] = st.get("slot0_rx_mcs_raw")
        radio["link_state"] = st.get("slot0_link_state")
        radio["local_mac"] = st.get("local_mac4")
        radio["peer_mac"] = st.get("slot0_peer_mac4")
        radio["slot_bitmap_config"] = st.get("configured_slot_bitmap")
        radio["slot_bitmap_runtime"] = st.get("runtime_slot_bitmap")
    p = pull("current-power")
    if p:
        radio["power_dbm"] = p.get("current_power_dbm")
    c = pull("channel-info")
    if c:
        radio["frequency_mhz"] = c.get("current_frequency_mhz")
        radio["channel_count"] = c.get("frequency_count_raw")
        radio["channel_index"] = c.get("current_index_raw")

    # The STATUS read is the liveness anchor: it is the same 0x01000000 the proven
    # Ground STATUS path uses, so "did status answer" is the honest link signal.
    radio["status_ok"] = "status" not in radio["errors"]
    return radio


def read_all_radios(host: str, *,
                    source_ip: Optional[str] = None, if_index: Optional[int] = None,
                    work_ids=(0, 1), timeout: float = 1.2) -> dict:
    radios = {}
    for wid in work_ids:
        radios[str(wid)] = read_radio(
            host, wid, source_ip=source_ip, if_index=if_index, timeout=timeout)
    connected = any(r.get("status_ok") for r in radios.values())
    return {"schema": SCHEMA, "host": host, "radios": radios, "connected": connected}


# --------------------------------------------------------------------------- #
# UI-facing capability description and a device-free self-test
# --------------------------------------------------------------------------- #

def describe() -> dict:
    return {
        "schema": SCHEMA,
        "feature": "Relay QoS (per-radio MCS / throughput / power / frequency)",
        "transport": (f"AR8030 usbpack RPC, TCP/{RELAY_RPC_PORT}, read-only GET "
                      "ioctls"),
        "reads": list(QOS_SPECS),
        "radios": SIDE_HINT,
        "hardware_verified": False,
        "confidence": {
            "transport": ("CONFIRMED -- byte-identical framing to the proven "
                          "Ground STATUS read"),
            "current_mcs_minus_2": "INFERRED from vendor binary; bench-unconfirmed",
            "power_dbm_byte1": "INFERRED from vendor binary; bench-unconfirmed",
            "work_id_side_map": "UNRESOLVED; role codes change after a role swap",
            "external_50000_reachability": ("CONFIRMED for operator-selected Ethernet endpoint "
                                            "192.168.1.105 on 2026-10-31; not universal qualification"),
        },
    }


def selftest() -> dict:
    # Decode paths against synthetic payloads (no device).
    mcs = decode_qos("mcs-throughput", bytes([7, 0, 0, 0]) + struct.pack("<I", 12345))
    assert mcs["current_mcs"] == 5 and mcs["throughput_kbps"] == 12345, mcs
    pw = decode_qos("current-power", bytes([0x00, 24]))
    assert pw["current_power_dbm"] == 24, pw
    st_pay = bytearray(300)
    st_pay[6:10] = bytes([0xF2, 0x00, 0x00, 0x22])
    st_pay[0xFC] = 2
    st_pay[0xFD] = 9
    st_pay[0xFE:0x102] = bytes([0xF2, 0x00, 0x00, 0x04])
    st = decode_qos("status", bytes(st_pay))
    assert st["slot0_link_state"] == 2 and st["slot0_rx_mcs_raw"] == 9, st
    assert st["local_mac4"] == (':'.join(('f2', '00', '00', '22'))), st
    assert st["slot0_peer_mac4"] == (':'.join(('f2', '00', '00', '04'))), st
    ch_pay = bytearray(4 + 4 * 3)
    ch_pay[0] = 3
    ch_pay[3] = 1
    struct.pack_into("<I", ch_pay, 4 + 1 * 4, 4915000)
    ch = decode_qos("channel-info", bytes(ch_pay))
    assert ch["current_frequency_mhz"] == 4915.0, ch
    # Frame round-trips.
    f = build_frame(BB_GET_MCS, b"\x00\x00", meta1=1)
    assert f[0] == 0xAA and f[-1] == 0xBB and _checksum17(f[:17]) == f[17]
    assert parse_frame(f) == b"\x00\x00"
    empty = build_frame(BB_GET_STATUS, b"")
    assert parse_frame(empty) == b""
    return {"ok": True}


if __name__ == "__main__":
    import json
    print(json.dumps(selftest()))
    print(json.dumps(describe(), indent=2))
