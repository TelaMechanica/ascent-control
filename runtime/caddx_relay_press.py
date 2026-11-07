"""Relay / Repeater binding-button control.

Presses the Relay's MF and HF binding buttons, and the dual-press gesture that
swaps the radios, from the host. Confirmed on hardware 2026-10-11; evidence and
the full trace are in `docs/RELAY_BINDING_CONTROL_2026-10-11.md`.

HOW A PRESS WORKS
-----------------
The buttons are sysfs GPIOs the unit exports itself at boot
(`fpv_run_cx489_relay.sh:102-107`). `ar_fpvhs_relay`'s key thread polls them --
lseek+read every iteration, no caching -- and on a change calls
`press_action(role)`, which runs the full nine-ioctl bb-match sequence and drives
the unit's own LED. So driving a pin is a real press, performed by the Relay's
own code. Nothing is written to storage and restoring the pin direction, or any
power cycle, undoes it.

The pin is driven by a shell command delivered through the updater's file-transfer
lane, which formats a caller-supplied path straight into `popen`
(`AR_FPV_UPGRADE_CalculateFileMD5` at 0x21000). That is a pre-existing, publicly
disclosed vendor flaw, recorded in CLAUDE.md section 7(a); it is not
project-original and is not being generalised here.

SCOPE -- READ BEFORE EXTENDING
------------------------------
This module presses buttons and must not grow past that. The shell text is built
HERE from a pin number and a duration; no caller supplies it, and there is no
parameter that admits arbitrary text. There is no shell, no fifo, no callback and
no session. CLAUDE.md section 7 prohibits a general exploit framework and that
prohibition is intact. If a future need looks like "just let the caller pass a
command", it is out of scope -- say so rather than adding a parameter.

THE FOUR THINGS THAT MUST BE RIGHT
----------------------------------
Each of these cost a bench session to find, and each is silent when wrong:

1. **Active low.** The button idles pulled high and is driven to ground when
   pressed, so the asserted level is 0. Writing 1 asserts "not pressed" and is
   indistinguishable from doing nothing.
2. **`${P}0`, never `$P0`.** In `sh`, `$P0` is the variable `P0` -- undefined --
   not `$P` followed by `0`. This regression silently broke a press that had
   already been confirmed working.
3. **The reply waits out the hold.** `popen` runs the script synchronously, so a
   15-second hold delays the final reply by 15 seconds. A short timeout reads
   that as silence and resends, RE-RUNNING the press.
4. **Do not send 0x72.** `REMOTE_UPGRADE` is not needed for the transfer and puts
   the unit in upgrade mode, which changes the LEDs and makes the result
   unreadable.
"""
from __future__ import annotations

import hashlib
import json
import struct
import time
import zlib

MAGIC, VERSION = 0x4152544F, 3292
HEADER = struct.Struct("<IHHHHIHHIIII")

CMD_START, CMD_DATA, CMD_END = 0x73, 0x74, 0x75

#: gpio0 is HF and gpio48 is MF. BOTH CONFIRMED on hardware 2026-10-11, each
#: pressed individually and each binding its own radio.
#:
#: Do NOT infer this from the firmware's role names. The binary knows the pins
#: only as role 0 (AP, `fpv_relay_ap_bb_match`) and role 1 (DEV,
#: `fpv_relay_dev_bb_match`), never by the label on the case, and
#: `fpv_relay_ap_is_rf3700()` swaps which path reads which pin. The mapping here
#: is from observation, not from the names.
PIN_HF, PIN_MF = 0, 48

#: A single press binds. The swap needs a LONG simultaneous hold -- 4 s does
#: nothing, 15 s works. The hold is what distinguishes the gesture, not the fact
#: that both pins are down.
HOLD_BIND, HOLD_SWAP = 5.0, 15.0

BUTTONS = {
    "hf":   {"pins": [PIN_HF], "hold": HOLD_BIND, "reboots": False,
             "label": "HF bind"},
    "mf":   {"pins": [PIN_MF], "hold": HOLD_BIND, "reboots": False,
             "label": "MF bind"},
    "swap": {"pins": [PIN_HF, PIN_MF], "hold": HOLD_SWAP, "reboots": True,
             "label": "swap radio sides"},
}

SLASH = "$(pwd|cut -c1)"              # a '/' that does not exist until sh runs
STAGE = SLASH + "tmp" + SLASH + "ap"  # absolute: a relative path writes nowhere
DEVICE_CMD_BUDGET = 128 - len("md5sum ") - 1   # snprintf(buf, 128, "%s %s", ...)

#: Reached only after CompareMD5 fails, which is reached only after
#: CalculateFileMD5 has run popen. So this text is POSITIVE CONFIRMATION the
#: injected command executed -- it is the only honest signal on this lane.
EXECUTED_MARKER = "filedata length error"


class RelayPressError(RuntimeError):
    def __init__(self, code: str, message: str, detail: dict | None = None):
        super().__init__(message)
        self.code, self.message, self.detail = code, message, detail or {}


# --------------------------------------------------------------------------- wire
def frame(cmd: int, seq: int, payload: bytes = b"", retry: int = 0) -> bytes:
    h0 = HEADER.pack(MAGIC, VERSION, 1, 0, 0xABCD, cmd, 2, 0, len(payload), seq, retry, 0)
    crc = zlib.crc32(h0 + payload) & 0xFFFFFFFF
    return HEADER.pack(MAGIC, VERSION, 1, 0, 0xABCD, cmd, 2, 0,
                       len(payload), seq, retry, crc) + payload


def file_info(path: str, size: int, md5: str) -> bytes:
    """The 328-byte ArFileInfo, layout confirmed against the vendor tool's own
    0x73 payload byte for byte."""
    b = bytearray(328)
    b[0:32] = md5.encode("ascii")
    b[64:68] = size.to_bytes(4, "little")
    b[68:72] = (1).to_bytes(4, "little")
    p = path.encode("ascii")
    if len(p) > 250:
        raise RelayPressError("PATH_TOO_LONG", f"path is {len(p)} bytes, max 250")
    b[72:72 + len(p)] = p
    return bytes(b)


# --------------------------------------------------------------------------- script
def press_script(pins, hold: float, level: int = 0) -> str:
    """The shell the device runs. Built here; never caller-supplied.

    The staged script may not contain a literal '/' -- it is delivered as a
    filename -- but it runs as ONE shell, so a slash goes in a variable once and
    is reused. `$(pwd|cut -c1)` is 14 characters and `${S}` is 4, which is the
    difference between 33 staged writes and three.

    For the swap the pins are driven TOGETHER and released together. Pressing one
    then the other would bind both radios, which is the documented wrong outcome.
    """
    parts = [f"S={SLASH}", f"P=${{S}}sys${{S}}class${{S}}gpio${{S}}gpio"]
    for i, pin in enumerate(pins):
        parts.append(f"G{i}=${{P}}{pin}")            # ${P}N -- NOT $PN
    for i in range(len(pins)):
        parts.append(f"echo out >$G{i}${{S}}direction")
    for i in range(len(pins)):
        parts.append(f"echo {level} >$G{i}${{S}}value")
    parts.append(f"sleep {hold:g}")
    for i in range(len(pins)):
        # Restoring the pin to an input is NOT optional: until it runs the
        # physical button on the case cannot be read.
        parts.append(f"echo in >$G{i}${{S}}direction")
    return ";".join(parts)


def stage_writes(script: str) -> list[str]:
    """Split the script into per-write chunks sized against the real device
    buffer rather than a guess. A fixed guess of 10 produced 33 writes -- more
    exposure to the device's payload race than it needed."""
    wrapper = len(f"/tmp/;echo -n ''>>{STAGE}")
    chunk = max(8, DEVICE_CMD_BUDGET - wrapper - 4)      # 4 spare for ' escaping
    return [script[i:i + chunk] for i in range(0, len(script), chunk)]


# --------------------------------------------------------------------------- transport
class Transport:
    """Byte pipe to the Relay's updater.

    Deliberately abstract. Tonight's path is the CDC serial lane, but
    `ar_fpvhs_upgrade` also imports socket/bind/listen/accept and binds TCP 6444
    and 6333, so the same frames may be deliverable over Ethernet. The press does
    not care which; keeping this seam means Ethernet is a transport, not a
    rewrite. 6444 was NOT observed open over RNDIS on 2026-10-11 -- verify before
    assuming it.
    """

    def write(self, data: bytes) -> None: raise NotImplementedError
    def read(self, size: int) -> bytes: raise NotImplementedError
    def reset(self) -> None: pass
    def close(self) -> None: pass


class SerialTransport(Transport):
    """Windows CDC serial. The port is the Relay's COM port."""

    def __init__(self, port: str, timeout: float = 1.5):
        import serial                                   # the project's own shim
        self._s = serial.Serial(port=port, baudrate=115200, timeout=timeout)

    def write(self, data): self._s.write(data)
    def read(self, size): return self._s.read(size)

    def reset(self):
        try:
            self._s.reset_input_buffer()
            self._s.reset_output_buffer()
        except Exception:                               # noqa: BLE001
            pass

    def close(self):
        try:
            self._s.close()
        except Exception:                               # noqa: BLE001
            pass


# --------------------------------------------------------------------------- session
class RelayLink:
    """One updater session: seq-matched reads, flush-then-resend on silence."""

    def __init__(self, transport: Transport, resends: int = 3):
        self._t = transport
        self._seq = 0
        self._resends = resends
        self.trail: list[dict] = []

    def _read_exact(self, n: int, deadline: float) -> bytes | None:
        buf = bytearray()
        while len(buf) < n and time.monotonic() < deadline:
            chunk = self._t.read(n - len(buf))
            if chunk:
                buf += chunk
        return bytes(buf) if len(buf) == n else None

    def _read_reply(self, want_seq: int, timeout: float):
        """Return (cmd, detail) for OUR seq; stale replies are discarded.

        This is what makes a resend safe. A reply carrying another seq is the
        late answer to an earlier frame; raising on it turns one lost payload
        into a dead run. Retrying WITHOUT this check duplicates replies and
        desyncs the stream -- measured, on 2026-10-11.
        """
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            hdr = self._read_exact(36, deadline)
            if hdr is None:
                return None
            *_, cmd, _, _, length, seq, _, _ = HEADER.unpack(hdr)
            body = self._read_exact(length, deadline) if length else b""
            if seq != want_seq:
                continue
            text = "".join(chr(c) if 32 <= c < 127 else " " for c in body)
            return cmd, " ".join(text.split())
        return None

    def send(self, cmd: int, payload: bytes = b"", timeout: float = 3.0):
        self._seq += 1
        seq = self._seq
        f = frame(cmd, seq, payload)
        for attempt in range(self._resends + 1):
            self._t.write(f)
            r = self._read_reply(seq, timeout)
            if r is not None:
                self.trail.append({"cmd": f"0x{cmd:02x}", "seq": seq,
                                   "detail": r[1][:80], "attempts": attempt + 1})
                return r
            # Silence: the device abandoned the frame and left its payload in
            # the stream, so the next header would be misaligned. Clear both
            # sides and resend the IDENTICAL frame -- same seq, so a late reply
            # to it is still accepted.
            self._t.reset()
            time.sleep(0.05)
        raise RelayPressError("NO_REPLY",
                              f"the Relay did not answer 0x{cmd:02x} after "
                              f"{self._resends + 1} attempts",
                              {"seq": seq, "trail": self.trail})

    def run_remote(self, shell_text: str, reply_timeout: float = 3.0) -> str:
        """Make the device execute `shell_text` once, and return what it said."""
        content = b"x\n"
        md5 = hashlib.md5(content).hexdigest()
        path = "/tmp/;" + shell_text
        self.send(CMD_START, file_info(path, len(content), md5))
        self.send(CMD_DATA, content)
        _, detail = self.send(CMD_END, timeout=reply_timeout)
        return detail


# --------------------------------------------------------------------------- operation
def press(transport: Transport, button: str, *, resends: int = 3) -> dict:
    """Press one of BUTTONS. Returns a result dict; raises RelayPressError."""
    spec = BUTTONS.get(button)
    if spec is None:
        raise RelayPressError("UNKNOWN_BUTTON",
                              f"no such button {button!r}; expected one of "
                              + ", ".join(sorted(BUTTONS)))
    script = press_script(spec["pins"], spec["hold"])
    writes = stage_writes(script)
    link = RelayLink(transport, resends=resends)
    executed = 0
    try:
        for i, part in enumerate(writes, 1):
            redirect = ">" if i == 1 else ">>"
            safe = part.replace("'", "'\\''")
            detail = link.run_remote(f"echo -n '{safe}'{redirect}{STAGE}")
            if EXECUTED_MARKER in detail:
                executed += 1
        try:
            detail = link.run_remote(f"sh {STAGE}",
                                     reply_timeout=spec["hold"] + 10.0)
            if EXECUTED_MARKER in detail:
                executed += 1
            rebooted = False
        except RelayPressError:
            # LOSING THE DEVICE HERE IS THE SUCCESS CASE FOR THE SWAP: the
            # gesture makes the unit fpv_config_save then fpv_sys_reboot, so it
            # leaves the bus mid-command. For a plain bind it is a real failure.
            if not spec["reboots"]:
                raise
            rebooted = True
        return {
            "ok": True,
            "button": button,
            "label": spec["label"],
            "pins": list(spec["pins"]),
            "hold_seconds": spec["hold"],
            "staged_writes": len(writes),
            "commands_confirmed_executed": executed,
            "rebooted": rebooted,
            "expect_reboot": spec["reboots"],
            "trail": link.trail,
        }
    finally:
        transport.close()


def selftest() -> dict:
    """Offline checks of the things that are silent when wrong."""
    hf = press_script(BUTTONS["hf"]["pins"], HOLD_BIND)
    swap = press_script(BUTTONS["swap"]["pins"], HOLD_SWAP)
    return {
        "active_low": ">$G0${S}value" in hf and "echo 0 >" in hf,
        "brace_expansion": "${P}0" in hf and "$P0;" not in hf,
        "restores_direction": hf.count("echo in >") == 1 and swap.count("echo in >") == 2,
        "swap_drives_both": "G0=${P}0" in swap and "G1=${P}48" in swap,
        "stage_path_absolute": STAGE.startswith(SLASH),
        "hf_writes": len(stage_writes(hf)),
        "swap_writes": len(stage_writes(swap)),
    }


# --------------------------------------------------------------------------- side map
#: Which physical Relay side faces the VTX vs the VRX, and which is HF vs MF.
#: DETERMINISTIC from the persisted `cur_mode` (in /factory/fact_env.json at
#: stSetDev.cur_mode). Physical sides are fixed: MF = 3700 MHz, HF = 5800 MHz.
#: cur_mode 2 = normal, 3 = reversed. Link roles on a P2P link are Sky/VTX = AP,
#: Ground/VRX = DEV, and the Relay uses the COMPLEMENTARY role on each side, so:
#:   cur_mode 2: MF(3700)=AP->VRX-facing, HF(5800)=DEV->VTX-facing
#:   cur_mode 3: MF(3700)=DEV->VTX-facing, HF(5800)=AP->VRX-facing
#: Source: ASCENT_Relay_Role_Mapping_2026-10-12 (user-provided) + the memory
#: note relay-role-cur-mode-mapping. Non-relay units carry cur_mode = 0,
#: which means something else -- this map returns None for anything but 2 or 3.
#:
#: NOTE (do not change here): that mapping doc says the dual-bind-button SWAP
#: toggles cur_mode 2<->3 with an ~8 s hold; our swap gesture above uses
#: HOLD_SWAP = 15 s. That is a firmware-rev discrepancy to reconcile on the
#: bench; the hold is left as-is deliberately.
MF_FREQ_MHZ, HF_FREQ_MHZ = 3700, 5800


def parse_fact_env_cur_mode(json_text):
    """`stSetDev.cur_mode` from fact_env.json text, or None if absent/malformed.

    Pure. Missing file, non-JSON, non-dict, missing section, or a non-integer
    value all read as None -- "unknown", never a guessed 0.
    """
    try:
        doc = json.loads(json_text)
    except (TypeError, ValueError):
        return None
    if not isinstance(doc, dict):
        return None
    dev = doc.get("stSetDev")
    if not isinstance(dev, dict):
        return None
    v = dev.get("cur_mode")
    if isinstance(v, bool) or not isinstance(v, int):
        return None
    return v


def cur_mode_side_map(cur_mode):
    """{"mf":{freq_mhz,side}, "hf":{freq_mhz,side}} for cur_mode 2|3, else None.

    `side` is "VTX" or "VRX" -- which endpoint that physical radio faces. None
    for any cur_mode other than 2 or 3 (do not guess a side).
    """
    if isinstance(cur_mode, bool) or not isinstance(cur_mode, int):
        return None          # 2.0, "2", True etc. are not a valid orientation
    if cur_mode == 2:        # normal
        mf_side, hf_side = "VRX", "VTX"
    elif cur_mode == 3:      # reversed
        mf_side, hf_side = "VTX", "VRX"
    else:
        return None
    return {"mf": {"freq_mhz": MF_FREQ_MHZ, "side": mf_side},
            "hf": {"freq_mhz": HF_FREQ_MHZ, "side": hf_side}}
