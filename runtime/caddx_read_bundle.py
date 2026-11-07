#!/usr/bin/env python3
"""Ascent / Caddx read-only device probe v0.2.

Purpose: prove vendor PC Tool read parity *before* wiring anything into the GUI.
No device write/config/flash commands are implemented.

Recovered from Caddx PC Tool 2.0.51 (the reference build; 2.0.37 lacks RFBoardType
160 and cannot address this project's hardware -- docs/PROTOCOL_SPEC.md section 9.1):
  command 60  FIND_DEVICE     -> command 60, 300-byte device info
  command 120 GET_BB_FREQ     -> 120 ACK, 115 MD5 sidecar, 116 ASCII JSON table,
                                 then a bare 36-byte 117 terminator

Critical behavior mirrored here: Caddx keeps ONE UsbSerialportFSM session open;
sequence numbers advance across requests. FIND_DEVICE is normally seq 0 and the
next GET_BB_FREQ is seq 1.

Retries allocate a NEW sequence number and increment the header `retry` field;
the vendor AckGuard re-points at the new seq (`_pendingAck.ExpectedSeq = resend.Seq`).
They do NOT reuse the original request sequence -- see docs/PROTOCOL_SPEC.md section 6.
"""
from __future__ import annotations

import argparse
import hashlib
import ctypes
import json
import os
import platform
import re
import socket
import struct
import subprocess
import time
import zlib
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

MAGIC = 0x4152544F
MAGIC_BYTES = struct.pack('<I', MAGIC)
VERSION = 3292
HEADER = struct.Struct('<IHHHHIHHIIII')
HEADER_SIZE = HEADER.size
MAX_FRAME = 5120
# Ascent USB VID block, from decompiled vendor `VIDConst` (docs/PROTOCOL_SPEC.md section 10).
# 0x1D6B..0x1D84 covers the Lite/GND/SKY family, VRX, GT Pro, VRX Pro, VRX Max, Cine, EX/EX2,
# RC and the OPV2 units.  0x1D7C..0x1D7F are unassigned in `VIDConst` but kept inside the
# contiguous block: recognizing an unassigned in-block VID is harmless because QUALIFY gates
# every operation independently.
#
# Deliberately EXCLUDED from discovery:
#   0x1A86  VIDConst.GM_V2 -- the GM-series gimbal's USB-serial bridge.  A Caddx device, but
#           not a configurable target for this tool.  Never add it here.
#   0x2207  Ascent_VRX_Proold -- superseded VRX Pro ID, dropped from 2.0.51's VIDConst.
#   0x0525  VIDConst.SimDevice -- simulator, not hardware.
VID_MIN, VID_MAX = 0x1D6B, 0x1D84
VID_EXCLUDED = {0x1A86, 0x2207, 0x0525}
# Windows PnP-instance regex for the same block.  PowerShell `-match` is case-insensitive.
VID_PNP_RE = r'VID_1D(6[B-F]|7[0-9A-F]|8[0-4])'

# VID:PID pairs that RECOGNITION may match but that carry no evidentiary weight.
#
# 0x1D6B is a genuine Ascent VID -- `VIDConst.ASCENT_L_GND401` = 7531 -- so the block cannot
# simply be narrowed.  But `1D6B:0002` specifically is the stock Linux Foundation USB gadget
# ID, which the Ascent Sky's own RNDIS personality uses verbatim
# (fpv/config_ether.sh:3-4: idVendor 0x1D6B, idProduct 0x0002), alongside a hardcoded gadget
# serial `123456789012`, a hardcoded ethernet MAC and a hardcoded IPv4
# (fpv/usb_ip.sh:6-7).  Every unrelated Linux USB gadget and root hub on the host presents the
# same pair.
#
# So the row must still be returned -- an Ascent Sky in RNDIS mode IS `1D6B:0002`, and its
# adapter is needed for topology correlation -- but matching it is not proof that an Ascent
# device is present.  Only a raw command-60 identity is.  See
# docs/GESTURE_V5_PROVISIONING_FEASIBILITY.md section 8.1.
NON_EVIDENTIARY_VID_PIDS = frozenset({(0x1D6B, 0x0002)})


def _as_hex_int(value):
    if isinstance(value, str):
        s = value.strip().upper()
        for prefix in ('VID_', 'PID_', '0X'):
            if s.startswith(prefix):
                s = s[len(prefix):]
        try:
            return int(s, 16)
        except ValueError:
            return None
    return value if isinstance(value, int) else None


def vid_pid_is_ascent_evidence(vid, pid) -> bool:
    """True only if this VID:PID is *evidence* of an Ascent device.

    Narrower than `vid_in_ascent_block`, which answers the recognition question.  A False
    result never means "drop the interface" -- it means "do not count this as proof".  A
    device is still proven only by its raw command-60 identity, and every operation is still
    gated independently by QUALIFY.
    """
    v = _as_hex_int(vid)
    p = _as_hex_int(pid)
    if v is None:
        return False
    if not vid_in_ascent_block(v):
        return False
    if p is not None and (v, p) in NON_EVIDENTIARY_VID_PIDS:
        return False
    return True


def pnp_vid_pid(pnp_device_id):
    """Extract (vid, pid) as ints from a Windows PnP instance path, or (None, None)."""
    m = re.search(r'VID_([0-9A-Fa-f]{4})&PID_([0-9A-Fa-f]{4})', str(pnp_device_id or ''))
    if not m:
        return (None, None)
    return (int(m.group(1), 16), int(m.group(2), 16))


def pnp_is_ascent_evidence(pnp_device_id) -> bool:
    v, p = pnp_vid_pid(pnp_device_id)
    return vid_pid_is_ascent_evidence(v, p)

RF_BOARD_ENUM = {0x10:'FPV_SKY_RF_486',0x20:'FPV_SKY_RF_420_5500',0x30:'FPV_SKY_RF_420_6500',0x50:'FPV_SKY_RF_422',0x60:'FPV_SKY_RF_420_3600',0x70:'FPV_SKY_RF_426',0x80:'FPV_SKY_RF_424',0x90:'FPV_SKY_RF_428',0xA0:'FPV_SKY_RF_424_v11'}
READ_ONLY_COMMANDS = {60, 120}


def vid_in_ascent_block(vid) -> bool:
    """True if `vid` is inside the recognized Ascent VID block.

    Recognition only.  A True result does NOT imply the device is eligible for any
    operation -- eligibility is decided per-operation by QUALIFY against raw cmd-60
    identity.  See docs/PROTOCOL_SPEC.md section 10.
    """
    if isinstance(vid, str):
        s = vid.strip().upper()
        if s.startswith('0X'): s = s[2:]
        if s.startswith('VID_'): s = s[4:]
        try: vid = int(s, 16)
        except ValueError: return False
    if not isinstance(vid, int): return False
    if vid in VID_EXCLUDED: return False
    return VID_MIN <= vid <= VID_MAX

class ProbeError(RuntimeError): pass

@dataclass(frozen=True)
class ArHeader:
    magic:int; version:int; type:int; msgid:int; unused:int; command:int
    format:int; userid:int; length:int; seq:int; retry:int; crc32:int
    @classmethod
    def unpack(cls,b:bytes): return cls(*HEADER.unpack(b))

def crc32_vendor(h:bytes,p:bytes=b'')->int:
    return zlib.crc32(h+p) & 0xffffffff

def build_request(cmd:int,payload:bytes=b'',seq:int=0,retry:int=0)->bytes:
    if cmd not in READ_ONLY_COMMANDS: raise ValueError('read-only probe permits only commands 60 and 120')
    p=bytes(payload)
    h0=HEADER.pack(MAGIC,VERSION,1,0,0xABCD,cmd,2,0,len(p),seq & 0xffffffff,retry & 0xffffffff,0)
    c=crc32_vendor(h0,p)
    return HEADER.pack(MAGIC,VERSION,1,0,0xABCD,cmd,2,0,len(p),seq & 0xffffffff,retry & 0xffffffff,c)+p

def ascii_z(b:bytes)->str:
    return b.split(b'\0',1)[0].decode('ascii','replace').rstrip(' \r\n\t')

def parse_device_info(payload:bytes)->dict:
    if len(payload)<300: raise ProbeError(f'device-info payload too short: {len(payload)} (expected at least 300)')
    p=payload[:300]
    info={
      'receive_max_size': int.from_bytes(p[0:4],'little'),
      'sdk_version': ascii_z(p[4:36]),
      'device_name': ascii_z(p[36:100]),
      'cpu_temp': int.from_bytes(p[100:104],'little',signed=True),
      'firmware': ascii_z(p[104:168]),
      'serial_number': ascii_z(p[168:200]),
      'hardware': ascii_z(p[200:232]),
      'status': int.from_bytes(p[232:236],'little',signed=True),
      'detail': ascii_z(p[236:300]),
      'payload_length': len(payload),
    }
    # Mirrors updateChannel::OnAsceDevRecInfo. It derives an RF-board enum byte
    # from the major component after the trailing '-'. We report the recovered
    # numeric candidate only; we do not invent an enum-name mapping.
    m=re.search(r'V(\d+\.\d+)-(\d+\.\d+)$', info['hardware'] or '')
    if m:
        try:
            major=int(m.group(2).split('.')[0])
            code=(major*16)&0xff
            info['pc_tool_rf_board_code_candidate']=code
            info['pc_tool_rf_board_name']=RF_BOARD_ENUM.get(code)
            info['pc_tool_rf_board_enum_defined']=code in RF_BOARD_ENUM
            info['pc_tool_rf_version_match']=m.group(0)
        except Exception:
            pass
    return info

def parse_bb_freq(payload:bytes)->dict:
    text=payload.decode('ascii','replace').rstrip('\0 \r\n\t')
    try: obj=json.loads(text)
    except Exception as e: raise ProbeError(f'command 116 payload is not JSON ({type(e).__name__})') from e
    return {'json':obj,'text':text,'payload_length':len(payload)}

class Decoder:
    def __init__(self): self.buf=bytearray()
    def feed(self,data:bytes):
        self.buf.extend(data); out=[]
        while True:
            pos=self.buf.find(MAGIC_BYTES)
            if pos<0:
                if len(self.buf)>3: del self.buf[:-3]
                break
            if pos: del self.buf[:pos]
            if len(self.buf)<HEADER_SIZE: break
            raw=bytes(self.buf[:HEADER_SIZE]); h=ArHeader.unpack(raw)
            if h.magic!=MAGIC or h.length>MAX_FRAME-HEADER_SIZE:
                del self.buf[0]; continue
            n=HEADER_SIZE+h.length
            if len(self.buf)<n: break
            payload=bytes(self.buf[HEADER_SIZE:n]); del self.buf[:n]
            z=bytearray(raw); z[32:36]=b'\0'*4
            calc=crc32_vendor(bytes(z),payload)
            crc_ok=None if h.crc32==0 else calc==h.crc32
            out.append((h,payload,crc_ok))
        return out

# Windows serial implementation intentionally has no pyserial dependency.
if platform.system().lower()=='windows':
    from ctypes import wintypes
    k=ctypes.WinDLL('kernel32',use_last_error=True)
    INVALID=wintypes.HANDLE(-1).value; GENERIC_READ=0x80000000; GENERIC_WRITE=0x40000000; OPEN_EXISTING=3
    PURGE=0x0001|0x0002|0x0004|0x0008
    PURGE_RX=0x0002|0x0008
    class DCB(ctypes.Structure):
        _fields_=[('DCBlength',wintypes.DWORD),('BaudRate',wintypes.DWORD),('flags',wintypes.DWORD),('wReserved',wintypes.WORD),('XonLim',wintypes.WORD),('XoffLim',wintypes.WORD),('ByteSize',ctypes.c_ubyte),('Parity',ctypes.c_ubyte),('StopBits',ctypes.c_ubyte),('XonChar',ctypes.c_char),('XoffChar',ctypes.c_char),('ErrorChar',ctypes.c_char),('EofChar',ctypes.c_char),('EvtChar',ctypes.c_char),('wReserved1',wintypes.WORD)]
    class CTO(ctypes.Structure):
        _fields_=[('ReadIntervalTimeout',wintypes.DWORD),('ReadTotalTimeoutMultiplier',wintypes.DWORD),('ReadTotalTimeoutConstant',wintypes.DWORD),('WriteTotalTimeoutMultiplier',wintypes.DWORD),('WriteTotalTimeoutConstant',wintypes.DWORD)]
    k.CreateFileW.argtypes=[wintypes.LPCWSTR,wintypes.DWORD,wintypes.DWORD,wintypes.LPVOID,wintypes.DWORD,wintypes.DWORD,wintypes.HANDLE]; k.CreateFileW.restype=wintypes.HANDLE
    k.CloseHandle.argtypes=[wintypes.HANDLE]; k.GetCommState.argtypes=[wintypes.HANDLE,ctypes.POINTER(DCB)]; k.SetCommState.argtypes=[wintypes.HANDLE,ctypes.POINTER(DCB)]; k.SetCommTimeouts.argtypes=[wintypes.HANDLE,ctypes.POINTER(CTO)]
    k.SetupComm.argtypes=[wintypes.HANDLE,wintypes.DWORD,wintypes.DWORD]; k.PurgeComm.argtypes=[wintypes.HANDLE,wintypes.DWORD]
    k.ReadFile.argtypes=[wintypes.HANDLE,wintypes.LPVOID,wintypes.DWORD,ctypes.POINTER(wintypes.DWORD),wintypes.LPVOID]
    k.WriteFile.argtypes=[wintypes.HANDLE,wintypes.LPCVOID,wintypes.DWORD,ctypes.POINTER(wintypes.DWORD),wintypes.LPVOID]

class WinSerial:
    # write_timeout_ms exists for the firmware lane only. Its 116 frame is a whole
    # 1 MiB chunk, and PC Tool 2.0.51 sets SerialPort.WriteTimeout = -1 (infinite)
    # for exactly that reason (UsbSerialportFSM.cs Open, 2.0.51). The default keeps
    # the read-path behaviour byte-for-byte unchanged.
    def __init__(self,port,*,write_timeout_ms=3000): self.port=port.upper(); self.h=None; self.write_timeout_ms=int(write_timeout_ms)
    def open(self):
        if platform.system().lower()!='windows': raise ProbeError('live COM probing requires Windows')
        h=k.CreateFileW('\\\\.\\'+self.port,GENERIC_READ|GENERIC_WRITE,0,None,OPEN_EXISTING,0,None)
        if h==INVALID: raise ProbeError(f'could not open {self.port} (Win32 {ctypes.get_last_error()})')
        self.h=h
        d=DCB(); d.DCBlength=ctypes.sizeof(DCB)
        if not k.GetCommState(h,ctypes.byref(d)): raise ProbeError(f'GetCommState failed (Win32 {ctypes.get_last_error()})')
        d.BaudRate=115200; d.flags=1; d.ByteSize=8; d.Parity=0; d.StopBits=0
        if not k.SetCommState(h,ctypes.byref(d)): raise ProbeError(f'SetCommState failed (Win32 {ctypes.get_last_error()})')
        # Native tool sets 25 second SerialPort timeouts, while its ack guard has
        # shorter logical deadlines. Short OS-level reads let us implement those
        # logical deadlines without hanging the probe.
        if not k.SetCommTimeouts(h,ctypes.byref(CTO(25,0,75,0,self.write_timeout_ms))): raise ProbeError(f'SetCommTimeouts failed (Win32 {ctypes.get_last_error()})')
        k.SetupComm(h,1075200,1075200); k.PurgeComm(h,PURGE); return self
    def close(self):
        if self.h not in (None,INVALID): k.CloseHandle(self.h)
        self.h=None
    def __enter__(self): return self.open()
    def __exit__(self,*_): self.close()
    def write(self,b):
        buf=ctypes.create_string_buffer(bytes(b)); n=wintypes.DWORD(0)
        if not k.WriteFile(self.h,buf,len(b),ctypes.byref(n),None) or n.value!=len(b): raise ProbeError(f'write failed (Win32 {ctypes.get_last_error()})')
    def read(self,n=4096):
        buf=ctypes.create_string_buffer(n); got=wintypes.DWORD(0)
        if not k.ReadFile(self.h,buf,n,ctypes.byref(got),None): raise ProbeError(f'read failed (Win32 {ctypes.get_last_error()})')
        return bytes(buf.raw[:got.value])
    def purge_rx(self):
        if not k.PurgeComm(self.h,PURGE_RX): raise ProbeError(f'PurgeComm RX failed (Win32 {ctypes.get_last_error()})')

def frame_summary(h,p,crc_ok):
    # IMPORTANT: static analysis of Caddx PC Tool 2.2.8 UsbSerialportFSM::RecvLoop
    # shows that ordinary command frames are NOT rejected on CRC mismatch. Only the
    # text-ACK command 119 goes through TryValidateAckFrame. Keep our local CRC result
    # as a diagnostic, but never present it as vendor-enforced integrity.
    d={'command':h.command,'type':h.type,'format':h.format,'msgid':h.msgid,'userid':h.userid,
       'length':h.length,'seq':h.seq,'retry':h.retry,
       # Local reconstruction only. This is deliberately NOT an acceptance gate:
       # the device supplies command 115 as the integrity sidecar for the 116 table.
       'experimental_local_crc32_match':crc_ok,
       'header_crc32':f'{h.crc32:08X}' if h.crc32 else None}
    # Capture enough payload evidence to diagnose framing without dumping arbitrary
    # binary data or local paths into a screenshot.
    d['payload_prefix_hex']=p[:48].hex(' ').upper()
    if p and all((32<=x<127) or x in (9,10,13,0) for x in p[:min(len(p),256)]):
        d['payload_ascii_prefix']=p[:256].decode('ascii','replace').replace('\x00','\\0')
    return d

class VendorSession:
    def __init__(self,port):
        self.port=port.upper(); self.seq=0; self.decoder=Decoder(); self.sp=None; self.frames=[]
        # Raw payloads are retained only in-process for transaction validation.
        # They are not automatically exported to diagnostics.
        self._last_payload_by_command={}
    def __enter__(self): self.sp=WinSerial(self.port).open(); return self
    def __exit__(self,*_): self.sp.close()
    def exchange(self,cmd,expected,total=8.0,retry_interval=2.0):
        seq=self.seq; self.seq=(self.seq+1)&0xffffffff
        # Only one request is ever in flight. Drain stale serial bytes and decoder
        # fragments from the preceding completed transaction before a new command.
        if hasattr(self.sp,'purge_rx'): self.sp.purge_rx()
        self.decoder=Decoder()
        deadline=time.monotonic()+total; next_send=0; attempts=0; local=[]
        while time.monotonic()<deadline:
            now=time.monotonic()
            if now>=next_send:
                # Native AckGuard retries preserve the original sequence but set
                # header.retry to 0,1,2,...
                request=build_request(cmd,seq=seq,retry=attempts)
                self.sp.write(request); attempts+=1; next_send=now+retry_interval
            chunk=self.sp.read(4096)
            if not chunk: continue
            for h,p,c in self.decoder.feed(chunk):
                s=frame_summary(h,p,c); local.append(s); self.frames.append(s)
                self._last_payload_by_command[h.command]=p
                if h.command in expected:
                    return {'ok':True,'request_command':cmd,'request_seq':seq,'send_attempts':attempts,'response':s,'payload':p}
                # Vendor error frames do not echo the request command/sequence. The
                # first int32 is -1 and command is 0. Treat that as a terminal answer
                # to the single in-flight request instead of retrying four times.
                if h.command == 0 and len(p) >= 4 and int.from_bytes(p[:4],'little',signed=True) == -1:
                    return {'ok':False,'terminal_error':True,'error_status':-1,
                            'request_command':cmd,'request_seq':seq,'send_attempts':attempts,
                            'seen_frames':local[-24:]}
                # ...but they SOMETIMES DO echo it, which the comment above assumed
                # away. Measured on a factory-fresh VRX Max HF (18.21.7): a command
                # 120 request answers with command 120, a 68-byte ResAckInfo, status
                # -1 and detail "Config file not found" -- the unit supports the
                # opcode and simply has no /factory/fpv_bb_freq.json yet. That is a
                # final answer, but it matched neither the expected set nor the
                # command==0 rule, so it was retried six times over twelve seconds
                # and then reported as an indistinguishable "no answer".
                #
                # Status is the ResAckInfo int32 at offset 0 and the detail is the
                # NUL-terminated string at offset 4 (spec 9.2). Only a NEGATIVE
                # status terminates: a success ACK on the requested command is also
                # command==cmd -- the 120 ACK is status 0 and is NOT the completion,
                # the 116 table is -- so terminating on it would break the read.
                if (h.command == cmd and h.command not in expected and len(p) >= 4):
                    status = int.from_bytes(p[:4],'little',signed=True)
                    if status < 0:
                        detail = p[4:].split(b'\x00',1)[0].decode('utf-8','replace')
                        return {'ok':False,'terminal_error':True,'error_status':status,
                                'error_detail':detail,
                                'request_command':cmd,'request_seq':seq,'send_attempts':attempts,
                                'seen_frames':local[-24:]}
        return {'ok':False,'request_command':cmd,'request_seq':seq,'send_attempts':attempts,'seen_frames':local[-24:]}
    def last_payload(self,command:int):
        return self._last_payload_by_command.get(command)

def _hidden_kwargs()->dict:
    """Keep PowerShell's console off the screen.

    THIS IS NOT COSMETIC. Discovery runs this repeatedly -- every connection
    attempt and every activation -- and without it each call flashes a console
    window on top of whatever the operator is doing. Reported from the bench as
    "a series of powershell windows keep firing", which for someone who does not
    use a command line looks like a bug at best and like being attacked at
    worst. This tool is built for exactly those operators.

    Every other PowerShell call in this application already hides its window;
    this one was missed, which is why it was the one being seen.
    """
    if platform.system().lower()!='windows': return {}
    si=subprocess.STARTUPINFO()
    si.dwFlags|=subprocess.STARTF_USESHOWWINDOW
    si.wShowWindow=0                      # SW_HIDE
    return {'startupinfo':si,'creationflags':subprocess.CREATE_NO_WINDOW}


def ps_json(script:str):
    cp=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',script],capture_output=True,text=True,timeout=8,**_hidden_kwargs())
    if cp.returncode: raise ProbeError((cp.stderr or cp.stdout or 'PowerShell query failed').strip().splitlines()[-1])
    raw=cp.stdout.strip()
    if not raw: return []
    d=json.loads(raw); return d if isinstance(d,list) else [d]

def discover_ports():
    if platform.system().lower()!='windows': return []
    script=r'''Get-CimInstance Win32_PnPEntity -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '\(COM\d+\)' -and $_.PNPDeviceID -match '<VIDRE>&PID_' } | ForEach-Object { $m=[regex]::Match($_.Name,'\((COM\d+)\)'); if($m.Success){ [pscustomobject]@{Port=$m.Groups[1].Value;Name=$_.Name;PnPDeviceID=$_.PNPDeviceID} } } | ConvertTo-Json -Compress'''.replace('<VIDRE>',VID_PNP_RE)
    return ps_json(script)

def discover_nics():
    if platform.system().lower()!='windows': return []
    script=r'''Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | Where-Object { $_.PnPDeviceID -match '<VIDRE>' -or $_.InterfaceDescription -match '(?i)Remote NDIS|RNDIS' } | ForEach-Object { $ips=@(Get-NetIPAddress -InterfaceIndex $_.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object IPAddress,PrefixLength); [pscustomobject]@{Name=$_.Name;Description=$_.InterfaceDescription;ifIndex=$_.ifIndex;Status=$_.Status;PnPDeviceID=$_.PnPDeviceID;IPv4=$ips} } | ConvertTo-Json -Depth 4 -Compress'''.replace('<VIDRE>',VID_PNP_RE)
    return ps_json(script)

def discover_problem_devices():
    """Ascent USB interfaces Windows could not bring up.

    `Get-NetAdapter` only ever sees an adapter that HAS a driver, so a device
    whose driver failed to install is invisible to `discover_nics` -- and the
    application then reports "no correlated RNDIS interface", which is true and
    sends the operator looking at networking when the answer is in Device
    Manager. Measured on this bench: an industrial Gnd485 enumerated as

        Error  CM_PROB_FAILED_INSTALL  "RNDIS"
        USB\\VID_1D75&PID_0101&MI_00\\7&2F882527&1&0000

    with no class at all, while a phantom record of the SAME unit on a different
    hub path still showed "Remote NDIS Compatible Device" in class Net -- so the
    inbox driver binds to this hardware and simply had not bound here.

    Phantoms are excluded: a remembered device that is not present is not a
    problem to report.
    """
    if platform.system().lower()!='windows': return []
    script=r'''Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue | Where-Object { $_.InstanceId -match '<VIDRE>' -and $_.Problem -ne 'CM_PROB_NONE' } | ForEach-Object { [pscustomobject]@{Name=$_.FriendlyName;Class=$_.Class;Status=$_.Status;Problem=[string]$_.Problem;InstanceId=$_.InstanceId} } | ConvertTo-Json -Depth 3 -Compress'''.replace('<VIDRE>',VID_PNP_RE)
    try:
        return ps_json(script)
    except Exception:
        return []


IP_UNICAST_IF=31

def _pin_windows_ipv4_interface(sock:socket.socket,if_index:int|None):
    if platform.system().lower()!='windows':
        return
    if not if_index or int(if_index)<=0:
        raise ProbeError('Ground network reads require the correlated Windows interface index')
    sock.setsockopt(socket.IPPROTO_IP,IP_UNICAST_IF,struct.pack('!I',int(if_index)))

def bb_rpc_status(host='192.168.3.102',port=50000,timeout=.8,source_ip=None,if_index=None):
    # Confirmed Ground STATUS read. No SET commands exist here.
    hdr=bytearray(18); hdr[0]=0xAA; hdr[1:5]=(2).to_bytes(4,'little'); hdr[5:9]=(0x01000000).to_bytes(4,'big'); hdr[9:13]=(0).to_bytes(4,'big'); hdr[13:17]=(0).to_bytes(4,'big'); hdr[17]=(~(sum([]) if False else 0))&0xff
    # Actual checksum is complement XOR bytes 0..16.
    x=0
    for b in hdr[:17]: x^=b
    hdr[17]=(~x)&0xff
    req=bytes(hdr)+b'\x00\x00'+b'\xBB'
    try:
      if not source_ip: raise ProbeError('Ground RPC requires an exact source IP')
      with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:
        _pin_windows_ipv4_interface(s,if_index)
        s.bind((source_ip,0)); s.settimeout(timeout); s.connect((host,port)); s.sendall(req); raw=b''
        while len(raw)<319:
            b=s.recv(4096)
            if not b: break
            raw+=b
      # Find AA and parse payload length conservatively.
      pos=raw.find(b'\xAA')
      if pos<0 or len(raw)<pos+19: return {'ok':False,'reason':'no valid RPC frame'}
      n=int.from_bytes(raw[pos+1:pos+5],'little'); payload=raw[pos+18:pos+18+n]
      if len(payload)<258: return {'ok':False,'reason':f'short STATUS payload {len(payload)}'}
      fmt=lambda b: ':'.join(f'{x:02X}' for x in b)
      return {'ok':True,'host':host,'local_bb_id':fmt(payload[6:10]),'link_state_raw':payload[252],'rx_mcs_raw':payload[253],'peer_field':fmt(payload[254:258]),'payload_length':len(payload)}
    except Exception as e: return {'ok':False,'reason':type(e).__name__}


def verify_cmd115_md5(cmd116_payload:bytes, cmd115_payload:bytes|None)->dict:
    """Verify the device-supplied command-115 MD5 sidecar for command-116."""
    actual=hashlib.md5(bytes(cmd116_payload)).hexdigest()
    if cmd115_payload is None:
        return {'method':'vendor_md5_cmd115','verified':None,'expected_md5':None,'actual_md5':actual}
    raw=bytes(cmd115_payload).split(b'\0',1)[0].strip()
    try:
        expected=raw.decode('ascii','strict').lower()
    except Exception:
        expected=''
    if not re.fullmatch(r'[0-9a-f]{32}',expected):
        return {'method':'vendor_md5_cmd115','verified':False,'expected_md5':expected or None,'actual_md5':actual,
                'error':'invalid_cmd115_digest'}
    return {'method':'vendor_md5_cmd115','verified':expected==actual,'expected_md5':expected,'actual_md5':actual}

def classify_unknown_cmd(frames):
    # Hardware on GT Pro 17.5.14 sends command=0, status=-1 and the misspelled
    # ASCII text "unkonwn cmd". Status is the primary discriminator; accept both
    # spellings only as secondary evidence in case later vendor firmware fixes it.
    for fr in frames or []:
        hx=(fr.get('payload_prefix_hex') or '').replace(' ','').upper()
        if not hx.startswith('FFFFFFFF'):
            continue
        if fr.get('command') == 0:
            return True
        if ('756E6B6F6E776E20636D64'.upper() in hx or  # "unkonwn cmd"
            '756E6B6E6F776E20636D64'.upper() in hx):   # "unknown cmd"
            return True
    return False

def sanitize_obj(o):
    # This probe intentionally doesn't collect cwd/home. Still scrub path-like strings.
    home=os.path.expanduser('~')
    def one(x):
      if isinstance(x,str):
        if home and home!='~': x=x.replace(home,'%USERPROFILE%')
        x=re.sub(r'(?i)[A-Z]:\\Users\\[^\\\s]+',r'%USERPROFILE%',x)
        return x
      if isinstance(x,list): return [one(v) for v in x]
      if isinstance(x,dict): return {k:one(v) for k,v in x.items()}
      return x
    return one(o)

def run(port:str,do_freq=True,ground_host=None,ground_source_ip=None,ground_ifindex=None,include_nics=True):
    report={'schema':'ascent.device.read.probe.v2','captured_at':datetime.now(timezone.utc).isoformat(),'mode':'READ_ONLY','port':port.upper(),'device_info':None,'bb_frequency':None,'serial_frames':[],'windows_nics':discover_nics() if include_nics else []}
    with VendorSession(port) as sess:
        d=sess.exchange(60,{60})
        if not d['ok']:
            report['device_info']={'state':'no_response','request_seq':d['request_seq'],'seen_frames':d.get('seen_frames',[])}
            report['serial_frames']=sess.frames; return sanitize_obj(report)
        try:
            info=parse_device_info(d['payload']); report['device_info']={'state':'ok',**info,'request_seq':d['request_seq'],'response_seq':d['response']['seq']}
        except Exception as e:
            report['device_info']={'state':'parse_error','error_code':type(e).__name__}
        if do_freq:
            # Native Caddx keeps the same serial FSM alive after command 60. The
            # next EnqueueSend therefore uses the incremented sequence number.
            time.sleep(.15)
            f=sess.exchange(120,{116})
            if f['ok']:
                try:
                    integrity=verify_cmd115_md5(f['payload'],sess.last_payload(115))
                    if integrity['verified'] is False:
                        report['bb_frequency']={'state':'digest_mismatch',
                            'request_seq':f['request_seq'],'response_seq':f['response']['seq'],
                            'payload_length':len(f['payload']),'integrity':integrity}
                    elif integrity['verified'] is None:
                        # Never call an unverified RF table "ok". Keep parsed data available
                        # for engineering diagnostics, but mark its integrity state explicitly.
                        report['bb_frequency']={'state':'unverified',**parse_bb_freq(f['payload']),
                            'request_seq':f['request_seq'],'response_seq':f['response']['seq'],
                            'integrity':integrity}
                    else:
                        report['bb_frequency']={'state':'ok',**parse_bb_freq(f['payload']),
                            'request_seq':f['request_seq'],'response_seq':f['response']['seq'],
                            'integrity':integrity}
                except Exception as e: report['bb_frequency']={'state':'response_parse_error','error_code':type(e).__name__,'request_seq':f['request_seq'],'response':f['response']}
            else:
                cmds=[x.get('command') for x in f.get('seen_frames',[])]
                report['bb_frequency']={'state':('unsupported_by_device_firmware' if classify_unknown_cmd(f.get('seen_frames',[])) else 'no_matching_frequency_response'),'request_seq':f['request_seq'],'send_attempts':f['send_attempts'],'received_commands':cmds,'seen_frames':f.get('seen_frames',[])}
        report['serial_frames']=sess.frames
    if ground_host:
        if not ground_source_ip: raise ProbeError('Ground RPC requires --ground-source-ip to prevent wrong-target routing')
        report['ground_status']=bb_rpc_status(ground_host,source_ip=ground_source_ip,if_index=ground_ifindex)
    return sanitize_obj(report)

def selftest():
    assert HEADER_SIZE==36
    r0=build_request(60,seq=0); h0=ArHeader.unpack(r0[:36]); assert h0.command==60 and h0.seq==0
    r1=build_request(120,seq=1); h1=ArHeader.unpack(r1[:36]); assert h1.command==120 and h1.seq==1
    p=bytearray(300); p[0:4]=(4096).to_bytes(4,'little'); p[36:50]=b'Ascent_GT_pro\0'; p[104:110]=b'19.2.4'; p[168:172]=b'0098'; p[200:222]=b'FPV-Ascent-Gnd V2.1-2.4'
    i=parse_device_info(p); assert i['device_name']=='Ascent_GT_pro' and i['firmware']=='19.2.4'
    assert i['pc_tool_rf_board_code_candidate']==32
    f=parse_bb_freq(b'{"RFBoardType":32,"BandA":[4900,4920]}\0'); assert f['json']['BandA'][1]==4920
    # Fragmented command116 decode
    payload=b'{"BandA":[4900]}'; hh0=HEADER.pack(MAGIC,VERSION,2,0,0xABCD,116,2,0,len(payload),1,0,0); c=crc32_vendor(hh0,payload); frame=HEADER.pack(MAGIC,VERSION,2,0,0xABCD,116,2,0,len(payload),1,0,c)+payload
    dec=Decoder(); z=dec.feed(b'junk'+frame[:17])+dec.feed(frame[17:]); assert len(z)==1 and z[0][0].command==116
    assert classify_unknown_cmd([{'command':0,'payload_prefix_hex':'FF FF FF FF 75 6E 6B 6F 6E 77 6E 20 63 6D 64'}])
    assert classify_unknown_cmd([{'command':0,'payload_prefix_hex':'FF FF FF FF 75 6E 6B 6E 6F 77 6E 20 63 6D 64'}])
    sample=b'{"RFBoardType":160,"bandA":[4495000]}'
    digest=hashlib.md5(sample).hexdigest().encode('ascii')+b'\0'*4
    assert verify_cmd115_md5(sample,digest)['verified'] is True
    assert verify_cmd115_md5(sample,b'0'*32)['verified'] is False
    return {'ok':True,'header_size':36,'find_device_seq':0,'get_bb_freq_seq_after_find':1,
            'bb_frequency_integrity':'vendor_md5_cmd115',
            'request60_hex':r0.hex(' ').upper(),'request120_seq1_hex':r1.hex(' ').upper()}

def main():
    ap=argparse.ArgumentParser(description='Read-only Ascent/Caddx protocol probe. No write commands are implemented.')
    ap.add_argument('--port',help='COM port, e.g. COM21. If omitted and one Ascent COM is present, auto-select it.')
    ap.add_argument('--identity-only',action='store_true',help='Do command 60 only; skip GET_BB_FREQ.')
    ap.add_argument('--ground-host',help='Also perform confirmed read-only Ground STATUS RPC, e.g. 192.168.3.102')
    ap.add_argument('--ground-source-ip',help='Required with --ground-host: exact PC-side RNDIS IPv4 for the intended device')
    ap.add_argument('--ground-ifindex',type=int,help='Required with --ground-host on Windows: correlated RNDIS interface index')
    ap.add_argument('--out',default='ascent_probe.json',help='sanitized JSON output path')
    ap.add_argument('--list',action='store_true',help='list detected Ascent COM ports/NICs and exit')
    ap.add_argument('--self-test',action='store_true')
    a=ap.parse_args()
    if a.self_test:
        print(json.dumps(selftest(),indent=2)); return 0
    if a.list:
        print(json.dumps({'ports':discover_ports(),'nics':discover_nics()},indent=2)); return 0
    port=a.port
    if not port:
        ports=discover_ports()
        if len(ports)!=1:
            print(json.dumps({'error':'PORT_SELECTION_REQUIRED','detected_ports':ports},indent=2)); return 2
        port=ports[0]['Port']
    print(f'Ascent protocol probe — READ ONLY — {port}')
    print('  [1/2] FIND_DEVICE command 60...')
    report=run(port,not a.identity_only,a.ground_host,a.ground_source_ip,a.ground_ifindex)
    di=report.get('device_info') or {}
    if di.get('state')=='ok':
        print(f"        device   : {di.get('device_name')}")
        print(f"        firmware : {di.get('firmware') or '-'}")
        print(f"        hardware : {di.get('hardware') or '-'}")
        print(f"        serial   : {di.get('serial_number') or '-'}")
        print(f"        SDK      : {di.get('sdk_version') or '-'}")
    else: print(f"        identity : {di.get('state')}")
    if not a.identity_only:
        print('  [2/2] GET_BB_FREQ command 120 on SAME serial session...')
        bf=report.get('bb_frequency') or {}
        print(f"        result   : {bf.get('state','not run')}")
        if bf.get('state')=='unsupported_by_device_firmware': print('        meaning  : device returned a valid \"unknown cmd\" reply to GET_BB_FREQ')
        if bf.get('state')=='ok':
            obj=bf.get('json') or {}; print(f"        keys     : {', '.join(str(k) for k in obj.keys())}")
        elif bf.get('received_commands') is not None: print(f"        received : {bf.get('received_commands')}")
    out=Path(a.out); out.write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(f'  Saved sanitized report: {out.name}')
    return 0

if __name__=='__main__': raise SystemExit(main())
