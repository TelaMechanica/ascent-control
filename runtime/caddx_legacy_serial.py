"""Read-only Caddx PC Tool legacy serial protocol implementation.

This module is intentionally limited to vendor GET/query commands that have been
statically recovered from Caddx PC Tool 2.2.8:
  * command 60  - FIND_DEVICE / device information
  * command 120 - GET_BB_FREQ / persistent BB frequency table

It mirrors the legacy UsbSerialportFSM framing used by PC Tool discovery:
  magic 0x4152544F, version 3292, type 1, format 2, 36-byte LE header,
  CRC32 over header-with-zero-crc + payload.

No device mutation command exists in this module.
"""
from __future__ import annotations

import ctypes
import hashlib
import json
import platform
import struct
import time
import zlib
from dataclasses import dataclass

MAGIC = 0x4152544F
MAGIC_BYTES = struct.pack("<I", MAGIC)  # 4F 54 52 41 = 'OTRA'
VERSION = 3292
HEADER = struct.Struct("<IHHHHIHHIIII")
HEADER_SIZE = HEADER.size
MAX_VENDOR_FRAME = 5120

READ_ONLY_COMMANDS = frozenset((60, 120))


class CaddxSerialError(RuntimeError):
    """A serial transaction did not produce the response the caller asked for.

    ``status`` and ``detail`` are populated when the device answered with a typed
    vendor error (spec 9.2 ``ResAckInfo``) rather than falling silent. A silent
    port and an explicit refusal are both failures, but only one of them has
    anything to tell the operator, so they must not arrive looking identical.
    """

    def __init__(self, message: str, *, status: int | None = None,
                 detail: str | None = None, terminal: bool = False):
        super().__init__(message)
        self.status = status
        self.detail = detail
        self.terminal = terminal


@dataclass(frozen=True)
class ArHeader:
    magic: int
    version: int
    type: int
    msgid: int
    unused: int
    command: int
    format: int
    userid: int
    length: int
    seq: int
    retry: int
    crc32: int

    @classmethod
    def unpack(cls, raw: bytes) -> "ArHeader":
        if len(raw) != HEADER_SIZE:
            raise CaddxSerialError(f"header size {len(raw)} != {HEADER_SIZE}")
        return cls(*HEADER.unpack(raw))


def crc32_vendor(header_zero_crc: bytes, payload: bytes = b"") -> int:
    # PC Tool's CrcCalc is the standard reflected CRC-32 (poly 0xEDB88320,
    # init/final XOR 0xffffffff), which is equivalent to zlib.crc32 here.
    return zlib.crc32(header_zero_crc + payload) & 0xFFFFFFFF


def build_request(command: int, payload: bytes = b"", seq: int = 0, retry: int = 0) -> bytes:
    if command not in READ_ONLY_COMMANDS:
        raise ValueError("only recovered read-only commands 60 and 120 are permitted")
    payload = bytes(payload)
    h0 = HEADER.pack(
        MAGIC, VERSION, 1, 0, 0xABCD,
        command, 2, 0,
        len(payload), seq & 0xFFFFFFFF, retry & 0xFFFFFFFF, 0,
    )
    crc = crc32_vendor(h0, payload)
    h = HEADER.pack(
        MAGIC, VERSION, 1, 0, 0xABCD,
        command, 2, 0,
        len(payload), seq & 0xFFFFFFFF, retry & 0xFFFFFFFF, crc,
    )
    return h + payload


def parse_device_info(payload: bytes) -> dict:
    # ResDeviceInfo layout recovered directly from PC Tool ParseDeviceInfo.
    if len(payload) < 300:
        raise CaddxSerialError(f"device-info payload too short ({len(payload)}; expected 300)")
    p = payload[:300]

    def asc(a: int, b: int) -> str:
        raw = p[a:b]
        # Vendor uses Encoding.ASCII.GetString(...).TrimEnd('\\0'). Also strip
        # trailing spaces/CRLF for presentation, without changing the raw payload.
        return raw.split(b"\x00", 1)[0].decode("ascii", "replace").rstrip(" \r\n\t")

    return {
        "receive_max_size": int.from_bytes(p[0:4], "little", signed=False),
        "sdk_version": asc(4, 36),
        "device_name": asc(36, 100),
        "cpu_temp": int.from_bytes(p[100:104], "little", signed=True),
        "firmware": asc(104, 168),
        "serial_number": asc(168, 200),
        "hardware": asc(200, 232),
        "status": int.from_bytes(p[232:236], "little", signed=True),
        "detail": asc(236, 300),
        "payload_length": len(payload),
    }


def parse_bb_frequency(payload: bytes) -> dict:
    text = payload.decode("ascii", "replace").rstrip("\x00 \r\n\t")
    try:
        data = json.loads(text)
    except Exception as exc:
        raise CaddxSerialError(f"BB frequency response was not valid JSON ({type(exc).__name__})") from exc
    return {"text": text, "data": data, "payload_length": len(payload)}


# --- Windows synchronous COM transport ------------------------------------
if platform.system().lower() == "windows":
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value
    GENERIC_READ = 0x80000000
    GENERIC_WRITE = 0x40000000
    OPEN_EXISTING = 3
    PURGE_TXABORT = 0x0001
    PURGE_RXABORT = 0x0002
    PURGE_TXCLEAR = 0x0004
    PURGE_RXCLEAR = 0x0008

    class DCB(ctypes.Structure):
        _fields_ = [
            ("DCBlength", wintypes.DWORD),
            ("BaudRate", wintypes.DWORD),
            ("flags", wintypes.DWORD),
            ("wReserved", wintypes.WORD),
            ("XonLim", wintypes.WORD),
            ("XoffLim", wintypes.WORD),
            ("ByteSize", ctypes.c_ubyte),
            ("Parity", ctypes.c_ubyte),
            ("StopBits", ctypes.c_ubyte),
            ("XonChar", ctypes.c_char),
            ("XoffChar", ctypes.c_char),
            ("ErrorChar", ctypes.c_char),
            ("EofChar", ctypes.c_char),
            ("EvtChar", ctypes.c_char),
            ("wReserved1", wintypes.WORD),
        ]

    class COMMTIMEOUTS(ctypes.Structure):
        _fields_ = [
            ("ReadIntervalTimeout", wintypes.DWORD),
            ("ReadTotalTimeoutMultiplier", wintypes.DWORD),
            ("ReadTotalTimeoutConstant", wintypes.DWORD),
            ("WriteTotalTimeoutMultiplier", wintypes.DWORD),
            ("WriteTotalTimeoutConstant", wintypes.DWORD),
        ]

    kernel32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                     wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.GetCommState.argtypes = [wintypes.HANDLE, ctypes.POINTER(DCB)]
    kernel32.SetCommState.argtypes = [wintypes.HANDLE, ctypes.POINTER(DCB)]
    kernel32.SetCommTimeouts.argtypes = [wintypes.HANDLE, ctypes.POINTER(COMMTIMEOUTS)]
    kernel32.SetupComm.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD]
    kernel32.PurgeComm.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.ReadFile.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD,
                                  ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID]
    kernel32.WriteFile.argtypes = [wintypes.HANDLE, wintypes.LPCVOID, wintypes.DWORD,
                                   ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID]


class WindowsSerialPort:
    """Minimal 115200 8N1 synchronous COM transport, no external pyserial dependency."""

    def __init__(self, port: str, baud: int = 115200):
        if platform.system().lower() != "windows":
            raise CaddxSerialError("Windows COM probing is available only on Windows")
        self.port = port.upper()
        self.baud = int(baud)
        self.handle = None

    def open(self):
        path = "\\\\.\\" + self.port
        h = kernel32.CreateFileW(path, GENERIC_READ | GENERIC_WRITE, 0, None,
                                 OPEN_EXISTING, 0, None)
        if h == INVALID_HANDLE_VALUE:
            err = ctypes.get_last_error()
            raise CaddxSerialError(f"could not open {self.port} (Win32 {err})")
        self.handle = h
        try:
            dcb = DCB()
            dcb.DCBlength = ctypes.sizeof(DCB)
            if not kernel32.GetCommState(h, ctypes.byref(dcb)):
                raise CaddxSerialError(f"GetCommState failed (Win32 {ctypes.get_last_error()})")
            dcb.BaudRate = self.baud
            # SerialPort defaults used by Caddx: 8 data, no parity, one stop, no handshake.
            dcb.flags = 0x00000001  # fBinary only
            dcb.ByteSize = 8
            dcb.Parity = 0
            dcb.StopBits = 0
            if not kernel32.SetCommState(h, ctypes.byref(dcb)):
                raise CaddxSerialError(f"SetCommState failed (Win32 {ctypes.get_last_error()})")
            timeouts = COMMTIMEOUTS(25, 0, 75, 0, 3000)
            if not kernel32.SetCommTimeouts(h, ctypes.byref(timeouts)):
                raise CaddxSerialError(f"SetCommTimeouts failed (Win32 {ctypes.get_last_error()})")
            # Vendor asks for ~1 MiB buffers; SetupComm is advisory and some drivers reject
            # very large sizes, so fall back quietly if it does.
            kernel32.SetupComm(h, 1075200, 1075200)
            kernel32.PurgeComm(h, PURGE_RXABORT | PURGE_TXABORT | PURGE_RXCLEAR | PURGE_TXCLEAR)
            return self
        except Exception:
            self.close()
            raise

    def close(self):
        if self.handle not in (None, INVALID_HANDLE_VALUE):
            kernel32.CloseHandle(self.handle)
        self.handle = None

    def __enter__(self):
        return self.open()

    def __exit__(self, *_):
        self.close()

    def write(self, data: bytes):
        if self.handle is None:
            raise CaddxSerialError("serial port is not open")
        data = bytes(data)
        buf = ctypes.create_string_buffer(data)
        written = wintypes.DWORD(0)
        ok = kernel32.WriteFile(self.handle, buf, len(data), ctypes.byref(written), None)
        if not ok or written.value != len(data):
            raise CaddxSerialError(f"serial write failed (Win32 {ctypes.get_last_error()})")

    def read_some(self, max_bytes: int = 4096) -> bytes:
        if self.handle is None:
            raise CaddxSerialError("serial port is not open")
        buf = ctypes.create_string_buffer(max_bytes)
        got = wintypes.DWORD(0)
        ok = kernel32.ReadFile(self.handle, buf, max_bytes, ctypes.byref(got), None)
        if not ok:
            err = ctypes.get_last_error()
            raise CaddxSerialError(f"serial read failed (Win32 {err})")
        return bytes(buf.raw[: got.value])


class FrameDecoder:
    def __init__(self):
        self.buf = bytearray()

    def feed(self, data: bytes) -> list[tuple[ArHeader, bytes, bool | None]]:
        self.buf.extend(data)
        out: list[tuple[ArHeader, bytes, bool | None]] = []
        while True:
            pos = self.buf.find(MAGIC_BYTES)
            if pos < 0:
                # Keep at most the last 3 bytes, in case they prefix the magic.
                if len(self.buf) > 3:
                    del self.buf[:-3]
                break
            if pos:
                del self.buf[:pos]
            if len(self.buf) < HEADER_SIZE:
                break
            raw_h = bytes(self.buf[:HEADER_SIZE])
            try:
                h = ArHeader.unpack(raw_h)
            except Exception:
                del self.buf[0]
                continue
            if h.magic != MAGIC or h.length > (MAX_VENDOR_FRAME - HEADER_SIZE):
                del self.buf[0]
                continue
            total = HEADER_SIZE + h.length
            if len(self.buf) < total:
                break
            payload = bytes(self.buf[HEADER_SIZE:total])
            del self.buf[:total]
            # Vendor legacy RecvLoop does not reject normal frames on CRC mismatch. We
            # therefore report CRC state rather than dropping the response.
            zeroed = bytearray(raw_h)
            zeroed[32:36] = b"\x00\x00\x00\x00"
            calc = crc32_vendor(bytes(zeroed), payload)
            crc_ok = (calc == h.crc32) if h.crc32 != 0 else None
            out.append((h, payload, crc_ok))
        return out


def query(port: str, command: int, *, total_timeout: float | None = None,
          retry_interval: float = 2.0) -> dict:
    if command not in READ_ONLY_COMMANDS:
        raise ValueError("read-only transport only allows 60 and 120")
    # Caddx Send_FindDevice uses 2s retry / 8s total. BB freq uses the same legacy
    # command transport with response ACK target 116; 8s is conservative and bounded.
    if total_timeout is None:
        total_timeout = 8.0
    expected = {60} if command == 60 else {116}
    frame = build_request(command, b"", seq=0, retry=0)
    decoder = FrameDecoder()
    deadline = time.monotonic() + total_timeout
    next_send = 0.0
    sends = 0
    seen: list[dict] = []
    digest115: str | None = None

    with WindowsSerialPort(port, 115200) as sp:
        while time.monotonic() < deadline:
            now = time.monotonic()
            if now >= next_send:
                sp.write(frame)
                sends += 1
                next_send = now + retry_interval
            chunk = sp.read_some(4096)
            if chunk:
                for h, payload, crc_ok in decoder.feed(chunk):
                    seen.append({"command": h.command, "length": h.length, "seq": h.seq, "crc_ok": crc_ok})
                    if h.command == 115:
                        raw_digest = payload.split(b"\x00", 1)[0].strip()
                        try:
                            text_digest = raw_digest.decode("ascii", "strict").lower()
                            digest115 = text_digest if len(text_digest) == 32 and all(c in "0123456789abcdef" for c in text_digest) else None
                        except Exception:
                            digest115 = None
                    if h.command not in expected and len(payload) >= 4:
                        # A typed vendor error is a FINAL answer to the one request
                        # in flight, and retrying it just spends the whole budget
                        # before reporting "no answer" -- which is what a dead port
                        # reports too. Measured in the other transport on a
                        # factory-fresh VRX Max HF (18.21.7): command 120 answered
                        # with command 120, a 68-byte ResAckInfo, status -1 and
                        # detail "Config file not found". Six sends, twelve seconds,
                        # and the operator was told nothing.
                        #
                        # Two shapes, because the device uses both. Error frames
                        # usually come back as command 0 with status -1 and do not
                        # echo the request; sometimes they echo it instead.
                        #
                        # Only a NEGATIVE status terminates, and only on a frame the
                        # caller is not already waiting for. The 120 ACK is status 0
                        # on command 120 and is NOT the completion of a read -- the
                        # 116 table is -- so terminating on a success ACK would
                        # break the very path this protects.
                        #
                        # The command test is a fail-safe rather than a measured
                        # need: no frame we model reads negative here (an ASCII MD5
                        # digest cannot, every byte being under 0x80). It is there
                        # so an UNMODELLED frame -- binary telemetry, a future
                        # opcode, a resynchronised fragment -- cannot refuse a
                        # request it was never answering.
                        status = int.from_bytes(payload[:4], "little", signed=True)
                        if status < 0 and (h.command == 0 or h.command == command):
                            detail = payload[4:].split(b"\x00", 1)[0].decode("utf-8", "replace").strip()
                            raise CaddxSerialError(
                                f"device refused command {command}: status {status}"
                                + (f" ({detail})" if detail else ""),
                                status=status, detail=detail or None, terminal=True)
                    if h.command in expected:
                        result = {
                            "ok": True,
                            "port": port.upper(),
                            "request_command": command,
                            "response_command": h.command,
                            "response_type": h.type,
                            "response_format": h.format,
                            "seq": h.seq,
                            "payload_length": len(payload),
                            "crc_ok": crc_ok,
                            "send_attempts": sends,
                            "seen_frames": seen[-12:],
                        }
                        if command == 60:
                            result["device_info"] = parse_device_info(payload)
                        else:
                            actual = hashlib.md5(payload).hexdigest()
                            result["integrity"] = {"method": "vendor_md5_cmd115", "expected_md5": digest115, "actual_md5": actual, "verified": digest115 == actual if digest115 else None}
                            if digest115 is None:
                                raise CaddxSerialError("BB frequency response was not accompanied by a valid command-115 MD5 digest")
                            if digest115 != actual:
                                raise CaddxSerialError("BB frequency command-115 MD5 digest mismatch")
                            result["bb_frequency"] = parse_bb_frequency(payload)
                        return result
            # ReadFile returns periodically due to COMMTIMEOUTS, so no busy loop.
    commands = ", ".join(str(x["command"]) for x in seen[-8:]) or "none"
    raise CaddxSerialError(f"no matching response to command {command}; received commands: {commands}")


def self_test() -> dict:
    # Codec + parser deterministic tests; safe on all platforms and no device required.
    req60 = build_request(60)
    assert len(req60) == 36
    h = ArHeader.unpack(req60[:36])
    assert h.magic == MAGIC and h.version == VERSION and h.command == 60 and h.length == 0
    z = bytearray(req60[:36]); z[32:36] = b"\0\0\0\0"
    assert h.crc32 == crc32_vendor(bytes(z), b"")

    p = bytearray(300)
    p[0:4] = (4096).to_bytes(4, "little")
    p[4:4+3] = b"SDK"
    p[36:36+14] = b"Ascent VRX Max"
    p[100:104] = (41).to_bytes(4, "little", signed=True)
    p[104:104+15] = b"Ascent_G_Gnd_19"
    p[168:168+4] = b"1234"
    p[200:200+14] = b"FPV-Ascent-Gnd"
    info = parse_device_info(bytes(p))
    assert info["device_name"] == "Ascent VRX Max"
    assert info["receive_max_size"] == 4096

    payload = b'{"BandA":[4900,4920]}\x00'
    f = parse_bb_frequency(payload)
    assert f["data"]["BandA"][0] == 4900

    # Decoder resynchronization and CRC reporting.
    hdr0 = HEADER.pack(MAGIC, VERSION, 2, 0, 0xABCD, 60, 2, 0, len(p), 7, 0, 0)
    crc = crc32_vendor(hdr0, bytes(p))
    resp = HEADER.pack(MAGIC, VERSION, 2, 0, 0xABCD, 60, 2, 0, len(p), 7, 0, crc) + bytes(p)
    d = FrameDecoder(); frames = d.feed(b"junk" + resp[:71]) + d.feed(resp[71:])
    assert len(frames) == 1 and frames[0][0].command == 60 and frames[0][2] is True
    return {"ok": True, "header_size": HEADER_SIZE, "request60_hex": req60.hex(" ").upper()}


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--port")
    ap.add_argument("--command", type=int, choices=sorted(READ_ONLY_COMMANDS))
    a = ap.parse_args()
    if a.self_test:
        print(json.dumps(self_test(), indent=2))
    elif a.port and a.command:
        print(json.dumps(query(a.port, a.command), indent=2))
    else:
        ap.error("use --self-test or --port COMx --command 60|120")
