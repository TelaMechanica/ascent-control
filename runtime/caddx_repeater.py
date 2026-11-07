#!/usr/bin/env python3
"""Repeater (Relay) control, built strictly on what the research established.

### Where this comes from

`docs/REPEATER_CONTROL_STATIC_ANALYSIS_2026-10-08.md`, a disassembly of
`/ar8030soc/ar_ldy_gnd` from Ascent VRX Max 19.2.14. Every opcode here carries
the confidence that document assigned it, and **the confidence decides what this
module is willing to do**:

| Operation | Opcode | Confidence | What this module does |
|---|---|---|---|
| Get Relay BB power | `0xA3` rd | HIGH, observed literal | reads it |
| Set Relay BB power | `0xA4` wr | HIGH | writes it, then reads back with `0xA3` |
| Set channel + hop | `0xA0` wr | HIGH | **withheld** -- see below |
| Get channel/hop | `0xA1` rd | INFERRED | offered as an unverified probe only |
| Get Relay BB status | `0xA5` rd | INFERRED | unverified probe only |
| Get Relay distance | `0xA6` rd | INFERRED | unverified probe only |

### Why the channel/hop WRITE is withheld although it is HIGH confidence

Its readback is `0xA1`, which is INFERRED -- derived from a rule, not observed as
a literal, and the source document says in as many words: "Verify before sending
one." A write whose result cannot be confirmed is exactly the shape this project
refuses for Hub and RC: a page that can only write and never read back is not
ready to be offered. The write is implemented and tested; it is gated behind
`allow_unconfirmed=True`, which nothing in the application passes.

Set BB power is different and is offered, because its readback `0xA3` is HIGH on
an observed literal. That is the one pair where both halves are established.

### Relay mode is a precondition, not something to switch on

`is_relay_mode()` returns `cur_mode == 2 || cur_mode == 3` from a global with
exactly one store, inside a function whose only caller parses a config section.
No host command reaches it. Status `11` therefore means the receiver is not in a
relay mode, it is not retryable, and the honest report is that the unit must be
provisioned out of band -- not that the operation failed.

Note the guard also accepts mode **3**, which is undocumented. So status 11
strictly means "cur_mode is neither 2 nor 3", and this module says that rather
than asserting a specific provisioning state it cannot see.

### What has NOT happened

Nothing in this module has been sent to hardware. The source document says so of
itself, and nothing since has changed that. Every response parser here is
exercised against recorded fixtures, and the live path is marked UNVERIFIED
wherever it is surfaced.
"""
from __future__ import annotations

import struct

from caddx_cgc import DIR_READ, DIR_WRITE, build_frame, parse_frame, CgcError

SCHEMA = "ascent.repeater.v1"

# -- opcodes, with the confidence the research assigned them ------------------ #
OP_SET_CHANNEL_HOP = 0xA0
OP_GET_CHANNEL_HOP = 0xA1
OP_GET_BB_POWER = 0xA3
OP_SET_BB_POWER = 0xA4
OP_GET_BB_STATUS = 0xA5
OP_GET_DISTANCE = 0xA6

HIGH = "HIGH"
INFERRED = "INFERRED"

OPCODES = {
    OP_SET_CHANNEL_HOP: {"name": "SET_RELAY_CHANNEL_HOP", "dir": DIR_WRITE,
                         "confidence": HIGH, "readback": OP_GET_CHANNEL_HOP},
    OP_GET_CHANNEL_HOP: {"name": "GET_RELAY_CHANNEL_HOP", "dir": DIR_READ,
                         "confidence": INFERRED, "readback": None},
    OP_GET_BB_POWER: {"name": "GET_RELAY_BB_PWR", "dir": DIR_READ,
                      "confidence": HIGH, "readback": None},
    OP_SET_BB_POWER: {"name": "SET_RELAY_BB_PWR", "dir": DIR_WRITE,
                      "confidence": HIGH, "readback": OP_GET_BB_POWER},
    OP_GET_BB_STATUS: {"name": "GET_RELAY_BB_STATUS", "dir": DIR_READ,
                       "confidence": INFERRED, "readback": None},
    OP_GET_DISTANCE: {"name": "GET_RELAY_DISTANCE", "dir": DIR_READ,
                      "confidence": INFERRED, "readback": None},
}

#: An operation is OFFERED by the application only when it is HIGH confidence AND,
#: if it writes, its readback is HIGH too. Everything else is a probe the operator
#: may run deliberately, labelled unverified.
def offered(op: int) -> bool:
    spec = OPCODES.get(op)
    if not spec or spec["confidence"] != HIGH:
        return False
    rb = spec.get("readback")
    if spec["dir"] == DIR_WRITE:
        return bool(rb) and OPCODES.get(rb, {}).get("confidence") == HIGH
    return True


# -- status codes ------------------------------------------------------------- #
STATUS_OK = 0
STATUS_TEXT = {
    0: "accepted",
    3: "the receiver returned its default case, which is not a success",
    4: "the request was empty",
    7: "the hop value was rejected",
    9: "returned by the 0x59 handler, whose meaning is not established",
    11: ("the receiver is not in a relay mode. Its cur_mode is neither 2 nor 3. "
         "No host command can change that -- relay mode is provisioned out of band "
         "by `ar_ldy_gnd --precfg_relay`, which then exits -- so this is not "
         "retryable and is not a fault in the request."),
}
STATUS_NOT_RELAY = 11

#: Deliberately NOT a complete enumeration. The research lists 3, 4, 7, 9 and 11
#: from different handlers and never states they come from one enum, so an
#: unrecognised code is reported as unrecognised rather than guessed at.
CHANNEL_MAX = 36          # cmp w0,#0x24 at 0xc7868
HOP_MAX = 1


class RepeaterError(RuntimeError):
    def __init__(self, code: str, message: str, evidence=None):
        super().__init__(message)
        self.code = code
        self.evidence = evidence or {}


def status_text(code: int) -> str:
    return STATUS_TEXT.get(code, f"status {code}, which this build does not recognise")


# -- requests ----------------------------------------------------------------- #
def build_read(op: int) -> bytes:
    """A read request: direction 0xA2, 8-byte payload, opcode then seven zeros."""
    spec = OPCODES.get(op)
    if not spec or spec["dir"] != DIR_READ:
        raise RepeaterError("NOT_A_READ", f"opcode 0x{op:02X} is not a Repeater read")
    return build_frame(DIR_READ, bytes([op]) + b"\x00" * 7)


def build_set_bb_power(value: int) -> bytes:
    """Set Relay baseband power. Body carried from `packet+5`, per the research."""
    v = int(value)
    if not 0 <= v <= 0xFF:
        raise RepeaterError("POWER_OUT_OF_RANGE",
                            "the baseband power byte is 0..255", {"value": value})
    return build_frame(DIR_WRITE, bytes([OP_SET_BB_POWER, v]) + b"\x00" * 6)


def build_set_channel_hop(band: int, channel: int, hop: int, *,
                          allow_unconfirmed: bool = False) -> bytes:
    """`[op][band][chan<=36][hop<=1]`, padded to the 8-byte body.

    Refused unless the caller states it accepts an unconfirmable write. The
    readback for this is 0xA1, which the research marks INFERRED and tells the
    reader to verify before sending. Nothing in the application passes the flag.
    """
    if not allow_unconfirmed:
        raise RepeaterError(
            "READBACK_NOT_ESTABLISHED",
            "Setting the Relay channel is withheld. The opcode is high confidence "
            "but its readback (0xA1) is inferred, not observed, so the change "
            "could not be confirmed. A write that cannot be read back is not "
            "offered.",
            {"write": "0xA0", "readback": "0xA1", "readback_confidence": INFERRED})
    if not 0 <= int(channel) <= CHANNEL_MAX:
        raise RepeaterError("CHANNEL_OUT_OF_RANGE",
                            f"channel must be 0..{CHANNEL_MAX}", {"channel": channel})
    if not 0 <= int(hop) <= HOP_MAX:
        raise RepeaterError("HOP_OUT_OF_RANGE", f"hop must be 0..{HOP_MAX}", {"hop": hop})
    return build_frame(DIR_WRITE,
                       bytes([OP_SET_CHANNEL_HOP, int(band) & 0xFF,
                              int(channel) & 0xFF, int(hop) & 0xFF]) + b"\x00" * 4)


# -- responses ---------------------------------------------------------------- #
def parse_response(raw: bytes, *, expect: int | None = None) -> dict:
    """Decode one reply. The envelope check is the CGC one, unchanged."""
    try:
        frame = parse_frame(raw)
    except CgcError as e:
        raise RepeaterError(e.code, str(e), e.evidence) from None
    payload = frame["payload"]
    if not payload:
        raise RepeaterError("EMPTY_PAYLOAD", "the reply carried no payload")
    op = payload[0]
    if expect is not None and op != expect:
        raise RepeaterError("OPCODE_MISMATCH",
                            f"asked for 0x{expect:02X} and the reply carries "
                            f"0x{op:02X}", {"expected": expect, "got": op})
    status = payload[1] if len(payload) > 1 else None
    out = {"opcode": op, "name": (OPCODES.get(op) or {}).get("name"),
           "direction": frame["direction"], "payload": payload,
           "status": status, "status_text": status_text(status) if status is not None else None,
           "ok": status == STATUS_OK,
           "not_relay_mode": status == STATUS_NOT_RELAY}
    if op == OP_GET_BB_POWER and len(payload) > 2:
        out["bb_power"] = payload[2]
    if op == OP_GET_CHANNEL_HOP and len(payload) > 4:
        out["band"], out["channel"], out["hop"] = payload[2], payload[3], payload[4]
        out["unverified"] = True
    if op == OP_GET_DISTANCE and len(payload) > 5:
        out["distance"] = struct.unpack("<H", bytes(payload[2:4]))[0]
        out["unverified"] = True
    if op == OP_GET_BB_STATUS:
        out["unverified"] = True
    return out


def describe() -> dict:
    """What this build is willing to do, and on what evidence. For the UI."""
    rows = []
    for op, spec in sorted(OPCODES.items()):
        rb = spec.get("readback")
        rows.append({
            "opcode": f"0x{op:02X}", "name": spec["name"],
            "writes": spec["dir"] == DIR_WRITE,
            "confidence": spec["confidence"],
            "readback": f"0x{rb:02X}" if rb else None,
            "readback_confidence": OPCODES[rb]["confidence"] if rb else None,
            "offered": offered(op),
            "why_not": None if offered(op) else (
                "the opcode is inferred from a rule rather than observed, and the "
                "research says to verify it before sending one"
                if spec["confidence"] != HIGH else
                "the write is high confidence but its readback is inferred, so the "
                "change could not be confirmed"),
        })
    return {"schema": SCHEMA, "operations": rows,
            "hardware_verified": False,
            "note": ("No Repeater operation in this build has been exercised on "
                     "hardware. The decode comes from a disassembly of ar_ldy_gnd "
                     "on VRX Max 19.2.14, and every parser here is tested against "
                     "recorded fixtures only.")}


def selftest() -> dict:
    f = build_read(OP_GET_BB_POWER)
    assert parse_frame(f)["payload"][0] == OP_GET_BB_POWER
    r = parse_response(build_frame(DIR_READ, bytes([OP_GET_BB_POWER, 0, 22]) + b"\x00" * 5),
                       expect=OP_GET_BB_POWER)
    assert r["bb_power"] == 22 and r["ok"] is True
    n = parse_response(build_frame(DIR_WRITE, bytes([OP_SET_BB_POWER, 11]) + b"\x00" * 6))
    assert n["not_relay_mode"] is True and not n["ok"]
    assert offered(OP_GET_BB_POWER) and offered(OP_SET_BB_POWER)
    assert not offered(OP_SET_CHANNEL_HOP) and not offered(OP_GET_CHANNEL_HOP)
    try:
        build_set_channel_hop(0, 1, 0)
        raise AssertionError("the unconfirmable write was not refused")
    except RepeaterError as e:
        assert e.code == "READBACK_NOT_ESTABLISHED"
    return {"ok": True}


if __name__ == "__main__":
    import json
    print(json.dumps(selftest(), indent=2))
