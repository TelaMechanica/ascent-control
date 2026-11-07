#!/usr/bin/env python3
"""Stock-Caddx firmware upgrade lane -- the PC Tool's own sequence, reproduced.

Source of truth is the decompiled vendor tool. Reference build is **2.0.51**
(CLAUDE.md, "Reference build"); 2.0.37 is cited wherever the two differ, and every
difference this module resolves is named in `VENDOR_DIVERGENCES` below.

Live vendor call chain, traced end to end
-----------------------------------------
    FindDeviceFrm card "Connect"
      -> MainFrm.OnFindDeviceFrm                      (MainFrm.cs:714-736)
      -> FunctionSelectFrm.DispFunCard(FuntionType.upgrade)
      -> MainFrm.OnFunctionSelectFrm                  (MainFrm.cs:538-561)
      -> MainFrm.AscentUpgradeCtrlOpend               (MainFrm.cs:738-754)
      -> new AscentUpdataFrm(e.AscentInfo)            -- the firmware page
           AscentUpdataFrm_Load -> ConnectDevice()    (AscentUpdataFrm.cs:174-184, 370-398)
           uploadDragger1_MouseClick -> OpenFileDialog(*.img)  (AscentUpdataFrm.cs:532-582)
           btnstartUpg_Click -> StartUpgAscentModalFrm -> UpgFSM.Start()
                                                       (AscentUpdataFrm.cs:638-676 / 2.0.51 663-711)
      -> UpgradeProcessFSM.Start()                    (UpgradeProcessFSM.cs:274-292)

`GD.IsUseNewAscentUpg` is `false` in 2.0.51 (GD.cs:21), and `FirmwareUpgradeFlowV2`
is never constructed anywhere in either build -- so `UpgradeProcessFSM` is the live
path in BOTH builds. V2 is dead code, quoted here only where it linearises the same
sequence unambiguously.

Wire sequence (UpgradeProcessFSM.NextState / OnAck)
---------------------------------------------------
    60   FIND_DEVICE      identity + receiveMaxSize -> chunk size
     3   REBOOT "clean"   32-byte mode, ASCII "clean" + NUL padding
    ..   reconnect        settle, then reopen (COM number may change)
   114   REMOTE_UPGRADE   empty
   115   SENDFILE_START   328-byte ArFileInfo
   116   SENDFILE_DATA    one frame per chunk, repeated
   117   SENDFILE_END     empty; THIS is the status-gated step
   118   UPGRADE_STATUS   polled, 1000 ms apart, <= 200 times
    ..   reconnect        device reboots itself; the tool does NOT send cmd 3 here
    60   FIND_DEVICE      post-flash version reread (AscentUpdataFrm.cs:281)

What this module deliberately does NOT do
-----------------------------------------
The vendor performs **no** content validation on the .img before sending: no
signature, no header parse, no version check against the image, no size check. Its
only pre-send gates are on the *file name* and the *path*, and both are soft prompts
the operator can accept. The whole-file MD5 is computed only to fill
`ArFileInfo.MD5`, and the DEVICE is what verifies it. See `validate_selection`.
"""
from __future__ import annotations

import hashlib
import os
import re
import struct
import time
from dataclasses import dataclass
from typing import Callable, Iterable

from caddx_read_bundle import (
    ArHeader,
    Decoder,
    WinSerial,
    crc32_vendor,
    parse_device_info,
)

# --------------------------------------------------------------------------------------
# Wire constants -- AR_COMMAND.cs, ArConstants.cs, ArFileInfo.cs (identical in both builds)
# --------------------------------------------------------------------------------------
MAGIC = 0x4152544F
VERSION = 3292
HEADER = struct.Struct('<IHHHHIHHIIII')
HEADER_SIZE = HEADER.size                       # 36, ArConstants.FRAMELENGTH
AR_FILE_INFO = struct.Struct('<64sii128s128s')  # ArFileInfo, Pack = 1 -> 328 bytes

CMD_REBOOT = 3
CMD_FIND_DEVICE = 60
CMD_REMOTE_UPGRADE = 114
CMD_SENDFILE_START = 115
CMD_SENDFILE_DATA = 116
CMD_SENDFILE_END = 117
CMD_UPGRADE_STATUS = 118
# The firmware lane's complete opcode set. 120/121/122 belong to the RF lane and are
# refused here so this transport can never be repurposed into a config writer.
ALLOWED_COMMANDS = frozenset((CMD_REBOOT, CMD_FIND_DEVICE, CMD_REMOTE_UPGRADE,
                              CMD_SENDFILE_START, CMD_SENDFILE_DATA,
                              CMD_SENDFILE_END, CMD_UPGRADE_STATUS))

# UpgradeProcessFSM.Send_RebootClean: Encoding.ASCII.GetBytes("clean") then
# Array.Resize(32). "clean" is the firmware lane's reboot mode; the RF lane's
# Reopen_Json sends 32 zero bytes instead (CLAUDE.md, RF table write step 5).
REBOOT_MODE_CLEAN = b'clean' + b'\0' * 27
assert len(REBOOT_MODE_CLEAN) == 32

# UpgradeProcessFSM.Start(): remote path is "/tmp/pc/" + Path.GetFileName(FilePath).
# Corroborated device-side: ar_fpvhs_upgrade contains the literals "/tmp/pc/%s",
# "/tmp/pc", "mount -t vfat /tmp/msc.vfat.img /tmp/pc/" and
# "[APP INFO] ... upgrade file dir is /tmp/pc/".
REMOTE_UPGRADE_DIR = '/tmp/pc/'
SAVE_AS_FILE = 1                    # ArFileInfo.saveAsFile, FileTransferSession.cs:67
FILE_PATH_MAX = 128                 # ArFileInfo.filePath[128]
FILE_DIR_MAX = 128                  # ArFileInfo.fileDir[128]
MD5_FIELD_MAX = 64                  # ArFileInfo.MD5[64]; 32 ASCII hex chars are used

# UpgradeProcessFSM._chunkSize field initialiser. Also FirmwareUpgradeFlowV2:17.
DEFAULT_CHUNK_SIZE = 1048576
# Real devices declare exactly this in the cmd-60 payload. Vendor log lines, four
# separate units: "最大接收1048576kb" for Ascent_G_Sky_18_3_1/18_3_2 (486 board),
# Ascent_G_Gnd_16_1_1 (Ascent_VRX, 485 board) and Ascent_VRX_Max_18_3_4.
OBSERVED_DEVICE_RECEIVE_MAX_SIZE = 1048576
# Product qualification is intentionally stricter than the protocol helper below.
# The transfer machinery remains able to model other values for reverse-engineering
# and tests, but Ascent Control has hardware evidence only for this exact declaration.
REQUIRED_RECEIVE_MAX_SIZE = OBSERVED_DEVICE_RECEIVE_MAX_SIZE
# A declared receive size outside this range is not honoured; the vendor default is
# used instead and the fact is recorded. This bound is OURS -- the vendor assigns
# `_chunkSize = resAscentInfo.RecMaxSize` unconditionally (UpgradeProcessFSM.cs:696).
CHUNK_SIZE_MIN = 1024
CHUNK_SIZE_MAX = 8 * 1024 * 1024

# ACK guard. 2.0.51 UsbSerialportFSM DefaultAckRetryIntervalMs / DefaultAckTotalTimeoutMs.
# 2.0.37 used 2000 / 8000 (UpgradeProcessFSM.cs:47,49). Reference build wins.
ACK_RETRY_INTERVAL = 1.5
ACK_TOTAL_TIMEOUT = 10.0
ACK_RETRY_INTERVAL_2037 = 2.0
ACK_TOTAL_TIMEOUT_2037 = 8.0
# The 116 chunk ACK gets its own budget. A 1 MiB frame is ~70 ms of wire time on the
# real bench (12.07 s of 116 traffic for one Ascent VRX Max image, vendor log
# 2026-04-25 14:53:05.801 -> 14:53:17.871), so 10 s is already ~140x headroom; this
# is here so a slow flash-write ACK is not mistaken for a dead link.
CHUNK_ACK_TIMEOUT = 30.0
# UpgradeProcessFSM.Send_UpgradeStatus. 2.0.51 enqueues 118 with a 1000 ms send delay
# (SendWithRetryGuardDelay(..., 1000)); 2.0.37 did Thread.Sleep(500) instead.
STATUS_POLL_DELAY = 1.0
STATUS_POLL_DELAY_2037 = 0.5
STATUS_POLL_LIMIT = 200             # QueryUpgradeStatustimesLimit
# UpgradeProcessFSM.OnAck, UpgState.UpgradeStatus: Thread.Sleep(500) between the
# Percent > 99 report and NextState(Completed).
POST_STATUS_SETTLE = 0.5

# Reconnect model. Two ADDITIVE numbers, because Reopen(int) sleeps the settle and
# only then starts its ReOpenTimeout_Asce poll window (UsbSerialportFSM.cs:245-294).
#   settle  11000 ms -- 2.0.51 GD.ResolveReOpenDelay_Asce, ReOpenDelayByDevName_Asce
#                       ["ascent_vrx_max_wf"] = 11000
#   budget 100000 ms -- 2.0.37's shipped SysParam.data ReOpenTimeout_Asce. 2.0.51's
#                       shipped file says 60000 and its compiled default is 60000.
#                       The larger value is kept deliberately: CLAUDE.md records a
#                       107.0 s reconnect as a legal success and forbids hard-failing
#                       before 110 s. Taking 2.0.51's 60 s here would fail that run.
RECONNECT_SETTLE = 11.0
RECONNECT_POLL_BUDGET = 100.0
RECONNECT_TOTAL_BUDGET = RECONNECT_SETTLE + RECONNECT_POLL_BUDGET   # 111 s
# 2.0.51 ForceSearchMode == 3 (shipped SysParam.data): retry the OLD port name
# PortRetryTimeLimit times, 1000 ms apart, and only then search USB for a matching
# VID+PID. 2.0.37 had IsPortnameChanged = true and searched by VID immediately.
PORT_RETRY_LIMIT = 8                # GD.PortRetryTimeLimit
PORT_RETRY_INTERVAL = 1.0           # the literal Thread.Sleep(1000) in that branch
RECONNECT_POLL_INTERVAL = 1.0       # GD.ReElectDelay, used by the 2.0.37 branch

# UsbSerialportFSM.RecvLoop discards any frame whose header+payload exceeds this.
# It bounds REPLIES only; the send path is bounded by SerialPort.WriteBufferSize
# = 1075200 (UsbSerialportFSM.Open), which is what makes a 1 MiB 116 frame legal.
MAX_REPLY_FRAME_TOTAL = 5120
SERIAL_WRITE_BUFFER = 1075200

OPERATION_ID = 'firmware_image_upgrade'
# What the operator calls it. OPERATION_ID is ours -- it keys the write gate and
# appears in logs -- and it was being shown on screen as a value, which tells a
# tester nothing about what the action does.
OPERATION_LABEL = 'Upgrade the firmware on this unit'

# The vendor's own OpenFileDialog filter, AscentUpdataFrm.cs:536-540. The dragger's
# AntdUI filter is the localised twin, AscentUpdataFrm.cs:183.
VENDOR_FILE_FILTER = 'firmware (*.img)|*.img|All (*.*)|*.*'
VENDOR_FILE_EXTENSION = '.img'
# 2.0.51 SelectWrongFWFilePrompt hard-refuses a selected path longer than this.
# 2.0.37 has no such check at all and would throw inside BuildFileInfo instead.
VENDOR_PATH_LENGTH_LIMIT = 200


# --------------------------------------------------------------------------------------
# Device-reported upgrade status -- 2.0.51 UpgradeStatusErrorCode + JudgeUpgradeStatus.
# The strings are the vendor's, verbatim, so a failure reads the same as the stock tool.
# 2.0.37 has NEITHER the enum nor the mapping: it ignores Status entirely and lets the
# 200-query limit expire, which is why a device-side rejection there reports only
# "查询升级状态次数超限".
# --------------------------------------------------------------------------------------
UPGRADE_STATUS_CODES = {
    -11: ('UPGRATE_ERR_FLASH_ERR', 'Upgrade failed, flash error'),
    -10: ('UPGRATE_ERR_MAX', 'Upgrade failed, unknown error'),
    -8: ('UPGRATE_ERR_IMG_TYPE', 'Upgrade failed, image type error'),
    -7: ('UPGRATE_ERR_UPGRADE_MODE', 'Upgrade failed, invalid upgrade mode'),
    -6: ('UPGRATE_ERR_APP_VERSION', 'Upgrade failed, The firmware version number is too low'),
    -5: ('UPGRATE_ERR_BOARD_TYPE', 'Upgrade failed, the device model does not match the upgraded firmware'),
    -4: ('UPGRATE_ERR_BAD_FILE', 'Upgrade failed, upgrade file is corrupted'),
    -3: ('UPGRATE_ERR_NO_FILE', 'Upgrade failed, no upgrade file found'),
    -2: ('UPGRATE_ERR_NO_PC', 'Upgrade failed, no computer connected'),
    -1: ('UPGRATE_ERR_NO_SD', 'Upgrade failed, no SD card detected'),
    0: ('STAT_VERIFY_IMAGE', 'Verifying image'),
    1: ('STAT_START', 'Upgrade started'),
    2: ('STAT_IN_PROGRESS', 'Upgrade in progress'),
    3: ('STAT_DONE', 'Upgrade done'),
    4: ('STAT_ENTER_CLEAN_SYSTEM', 'Entering clean system'),
    5: ('STAT_ENTER_CLEAN_SYSTEM_FAILED', 'Failed to enter clean system'),
}
# The one code that IS the device's anti-rollback verdict. `AR_FPV_UPGRADE_-
# VerifyImgFileVersionInfo` in the Sky's ar_fpvhs_upgrade compares the image header's
# u32AppVersion against /etc/app.version and logs "VerifyImgFileVersionInfo err %d".
ANTI_ROLLBACK_STATUS = -6


# --------------------------------------------------------------------------------------
# Divergences from a literal transcription of the vendor, each one deliberate.
# Anything not listed here is vendor behaviour reproduced as-is.
# --------------------------------------------------------------------------------------
VENDOR_DIVERGENCES = (
    {'id': 'pre_transfer_backup',
     'ours': 'A timestamped identity + RF-table backup is written before the first '
             'mutating command.',
     'vendor': 'The PC Tool backs up nothing before a flash.',
     'why': 'CLAUDE.md standing rule: timestamped backup before every write. The '
            'firmware image itself cannot be read back out of the device, so this is '
            'a state backup, not an image backup, and says so.'},
    {'id': 'sendfile_start_status_gate',
     'ours': 'A non-zero Status in the 115 ACK aborts before any 116 chunk is sent.',
     'vendor': 'UpgradeProcessFSM.OnAck UpgState.SendFileStart checks only that a 115 '
               'ACK arrived; Status is never read. It fails a moment later when the '
               'first 116 ACK never comes and the 10 s guard expires.',
     'why': 'Same outcome, reached before pushing ~171 MiB at a device that already '
            'refused the transfer.'},
    {'id': 'chunk_size_sanity_bound',
     'ours': f'The product hard-stops unless a fresh command-60 identity declares '
             f'receiveMaxSize exactly {REQUIRED_RECEIVE_MAX_SIZE}.',
     'vendor': 'UpgradeProcessFSM.cs:696 assigns `_chunkSize = RecMaxSize` with no bound.',
     'why': 'Every observed device declares exactly 1048576. Other values are not '
            'bench-qualified and can exceed the host write queue or make a fallback '
            'larger than the device declaration.'},
    {'id': 'image_trailing_md5_advisory',
     'ours': 'The .img trailing 32-byte ASCII MD5 is verified and REPORTED as an '
             'advisory check the operator may accept or decline, exactly like the '
             "vendor's own filename prompt.",
     'vendor': 'FileHashHelper.ReadLast32Bytes / ComputeMd5WithoutLast32Bytes exist in '
               'BOTH builds but are called only from the developer menu item '
               '读img中的md5ToolStripMenuItem_Click, against a hard-coded path. The '
               'production upgrade path never validates image content.',
     'why': 'Vendor code, vendor semantics, surfaced without becoming a new gate.'},
    {'id': 'reconnect_budget',
     'ours': f'{RECONNECT_SETTLE:.0f} s settle + {RECONNECT_POLL_BUDGET:.0f} s poll.',
     'vendor': "2.0.51's shipped SysParam.data says ReOpenTimeout_Asce = 60000; "
               "2.0.37's says 100000.",
     'why': 'CLAUDE.md records a 107.0 s reconnect as a legal success and forbids '
            'hard-failing before 110 s. 60 s would fail that observed run.'},
    {'id': 'ack_seq_correlation',
     'ours': 'An ACK must carry the matching command AND a sequence number this '
             'transaction actually sent (the original or one of its retries).',
     'vendor': '2.0.51 matches on command alone (TryConsumeMatchedAck(uint cmd)); '
               '2.0.37 matched command AND seq but re-pointed at each retry seq.',
     'why': "2.0.51 dropped seq matching to fix retry re-pointing. Tracking the "
            'transaction seq set fixes the same bug without accepting a stale reply '
            'from an earlier command.'},
)


class FirmwareUpgradeError(RuntimeError):
    """Fail-closed error for the qualified firmware upgrade transaction."""

    def __init__(self, code: str, message: str, *, stage: str | None = None,
                 evidence: dict | None = None):
        super().__init__(message)
        self.code = code
        self.stage = stage
        self.evidence = evidence or {}


# --------------------------------------------------------------------------------------
# Version parsing -- transcribed from AscentUpdataFrm.
#
# Python `re` and .NET Regex agree on every pattern used here (no backreferences, no
# balancing groups, no .NET-only constructs), so these are literal translations.
# --------------------------------------------------------------------------------------

# AscentUpdataFrm.ExtractVersion, applied to OpenFileDialog.SafeFileName (the BASENAME).
_EXTRACT_VERSION_RE = re.compile(
    r'.*?(\d+)_(\d+)_(\d+)(?:(?:_z8_|_z40_|_hub_)(\d+)|)\.img$', re.IGNORECASE)
# AscentUpdataFrm.uploadDragger1_MouseClick fallback, applied to the FULL path.
_PATH_VERSION_RE = re.compile(r'(\d+[\._]\d+[\._]\d+\.img)')
# AscentUpdataFrm.JudgePerVersAndCurrVers, applied to FWVers.ToLower().
_DEVICE_VERSION_RE = re.compile(r'(\d+)_(\d+)_(\d+)$')
# AscentUpdataFrm.UpdateDeviceInfo, for the lab_FWTips prefix.
_TIP_PREFIX_RE = re.compile(r'(\d+_\d+_\d+)$')
# AscentUpdataFrm.SelectWrongFWFilePrompt, for the filename-match prefix. Note this is
# NOT the same pattern as the tip's: `\d+\d+\d+` needs three or more CONSECUTIVE
# digits at end-of-string, which "Ascent_VRX_Max_19_2_4" does not have. The two
# prefixes therefore disagree on this project's own hardware -- see family_prefixes().
_NAME_CHECK_RE = re.compile(r'(\d+\d+\d+)$')
_UNRECOGNISED_VERSION = 'V_unRecog'


def extract_version(safe_file_name: str) -> str:
    """AscentUpdataFrm.ExtractVersion(string fileName) -- dotted version or ''."""
    m = _EXTRACT_VERSION_RE.match(str(safe_file_name or ''))
    if not m:
        return ''
    a, b, c, d = m.group(1), m.group(2), m.group(3), m.group(4)
    return f'{a}.{b}.{c}.{d}' if d else f'{a}.{b}.{c}'


def current_version_label(path: str) -> str:
    """`_currVer` exactly as AscentUpdataFrm computes it on file selection.

    ExtractVersion(SafeFileName) first; on a miss, the full-path regex; on a miss of
    that, the literal "V_unRecog" (AscentUpdataFrm.cs:559-576).
    """
    path = str(path or '')
    base = os.path.basename(path.replace('\\', '/'))
    v = extract_version(base)
    if v:
        return 'V' + v
    m = _PATH_VERSION_RE.search(path)
    if not m:
        return _UNRECOGNISED_VERSION
    token = m.group(1)
    if '_' in token:
        return ('V' + token).replace('_', '.').replace('.img', '')
    if '.' in token:
        return ('V' + token).replace('.img', '')
    return _UNRECOGNISED_VERSION


def device_version_label(firmware_info: str) -> str:
    """`_perVer` -- AscentUpdataFrm.UpdateDeviceInfo:446-454."""
    fw = str(firmware_info or '')
    m = re.search(r'(\d+_\d+_\d+)', fw)
    if not m:
        return fw
    return ('V' + m.group(1)).replace('_', '.')


def _parse_dotnet_version(text: str) -> tuple[int, ...] | None:
    """`new System.Version(text)` -- 2 to 4 non-negative components, else it throws.

    AscentUpdataFrm wraps the whole comparison in try/catch and returns 9 on a throw,
    which is why "V_unRecog" produces no downgrade prompt at all.
    """
    parts = str(text).split('.')
    if not 2 <= len(parts) <= 4:
        return None
    out = []
    for p in parts:
        if not p.isdigit():
            return None
        out.append(int(p))
    while len(out) < 4:
        out.append(-1)      # .NET leaves unspecified components as -1
    return tuple(out)


def judge_versions(firmware_info: str, current_version_label_text: str) -> dict:
    """AscentUpdataFrm.JudgePerVersAndCurrVers(out int res) -> (return value, res).

    Returns the vendor's own two numbers plus a plain reading of them:
        rc 1 with res < 0  -> the downgrade warning dialog is shown
        rc 0               -> proceed silently
        rc 2               -> device firmware string has no trailing n_n_n
        rc 9               -> a version failed to parse; NO dialog is shown
    """
    fw = str(firmware_info or '').lower()
    m = _DEVICE_VERSION_RE.search(fw)
    if not m:
        return {'rc': 2, 'res': 0, 'verdict': 'device_version_unparsed',
                'device_version': None, 'file_version': None}
    device_text = m.group(0).replace('_', '.')
    file_text = str(current_version_label_text or '').replace('V', '', 1).replace('_', '.')
    dev = _parse_dotnet_version(device_text)
    fil = _parse_dotnet_version(file_text)
    if dev is None or fil is None:
        return {'rc': 9, 'res': 0, 'verdict': 'version_unparsed',
                'device_version': device_text if dev else None,
                'file_version': file_text if fil else None}
    if fil < dev:
        return {'rc': 1, 'res': -1, 'verdict': 'downgrade',
                'device_version': device_text, 'file_version': file_text}
    if fil > dev:
        return {'rc': 0, 'res': 0, 'verdict': 'upgrade',
                'device_version': device_text, 'file_version': file_text}
    return {'rc': 0, 'res': 0, 'verdict': 'same_version',
            'device_version': device_text, 'file_version': file_text}


def versions_equal(label_a: str, label_b: str) -> bool:
    """Compare two `_currVer`/`_perVer`-shaped labels under System.Version semantics.

    Used only for OUR post-flash check. The vendor never compares these two values --
    it re-reads command 60 after a completed upgrade and repaints the label.
    """
    a = _parse_dotnet_version(str(label_a or '').replace('V', '', 1).replace('_', '.'))
    b = _parse_dotnet_version(str(label_b or '').replace('V', '', 1).replace('_', '.'))
    return a is not None and b is not None and a == b


def device_version_label_strict(firmware_info: str) -> str:
    """Like device_version_label, but the version can't start inside a model token.

    The vendor regex is unanchored and takes the first match, which is fine for
    `Ascent_VRX_Max_19_2_4` and wrong for any name whose model token ends in a
    digit: `..._z40_19_2_14` yields `40_19_2`. Here the first number must start
    the string or follow an underscore, so `z40` cannot donate its `40`.
    device_version_label keeps the vendor's behaviour because it feeds the
    vendor-parity prompts; OUR post-flash check uses this one.
    """
    m = re.search(r'(?:^|(?<=_))(\d+_\d+_\d+)', str(firmware_info or ''))
    if not m:
        return device_version_label(firmware_info)
    return ('V' + m.group(1)).replace('_', '.')


def flashed_version_matches(file_label: str, device_label: str) -> bool:
    """Post-flash check: does the device now run the version the file declared?

    A Z8 / Z40 / Hub filename carries a FOURTH component -- the variant build
    number after `_z8_`/`_z40_`/`_hub_` (`..._19_2_14_z40_2.img` -> V19.2.14.2) --
    while command 60 only ever reports three (`..._19_2_14` -> V19.2.14). Under
    versions_equal those can never be equal, so every successful variant flash
    was reported NOT FULLY VERIFIED. The device has no field that carries the
    variant number, so the honest comparison is the three it does report.
    """
    a = _parse_dotnet_version(str(file_label or '').replace('V', '', 1).replace('_', '.'))
    b = _parse_dotnet_version(str(device_label or '').replace('V', '', 1).replace('_', '.'))
    if a is None or b is None:
        return False
    if a[3] >= 0 and b[3] < 0:
        return a[:3] == b[:3]
    return versions_equal(file_label, device_label)


def identity_matches_across_firmware(expected: dict, actual: dict) -> bool:
    """Same physical unit, when the firmware string is legitimately allowed to change.

    `caddx_vendor_write.stable_identity_matches` also compares `firmware`, which is
    right for the RF lane and wrong twice over here: clean mode may report a different
    firmware string, and after a successful flash it certainly does. device_name,
    serial_number and hardware are the fields that must not move.
    """
    keys = ('serial_number', 'hardware')
    if not all((str((expected or {}).get(k) or '') == str((actual or {}).get(k) or ''))
               for k in keys):
        return False
    return _same_model_name(str((expected or {}).get('device_name') or ''),
                            str((actual or {}).get('device_name') or ''))


def _same_model_name(a: str, b: str) -> bool:
    """Equal, or equal once a camera-variant suffix is removed from either.

    17.5.8 Z40 builds its command-60 name as `Ascent_GT_pro_z40`; 19.2.14 runs the
    stock identity code and reports `Ascent_GT_pro`
    (docs/Z40_17_5_8_GOLDEN_BASELINE_2026-10-07.md S4). That change is the flash
    working, not a different unit -- serial and hardware still have to match.
    """
    if a == b:
        return True
    strip = lambda n: re.sub(r'_(z40|z8|hub)$', '', n, flags=re.IGNORECASE)
    return bool(a) and bool(b) and strip(a) == strip(b)


def family_prefixes(firmware_info: str) -> dict:
    """The two DIFFERENT prefixes the vendor derives from the same firmware string.

    `tip` drives the on-screen hint  (UpdateDeviceInfo, regex `(\\d+_\\d+_\\d+)$`)
    `check` drives the actual guard  (SelectWrongFWFilePrompt, regex `(\\d+\\d+\\d+)$`)

    They are not the same pattern and do not agree. For `Ascent_VRX_Max_19_2_4` the
    tip yields "Ascent_VRX_Max" while the check falls through to `Remove(12)` and
    yields "Ascent_VRX_M" -- a 12-character truncation mid-word. Both are reproduced,
    because the check is what gates and the tip is what the operator is told.
    """
    fw = str(firmware_info or '')
    tip = fw[:12] if len(fw) >= 12 else fw
    m_tip = _TIP_PREFIX_RE.search(fw)
    if m_tip:
        tip = fw[:max(m_tip.start() - 1, 0)]
    check = fw[:12] if len(fw) >= 12 else fw
    m_check = _NAME_CHECK_RE.search(fw)
    if m_check:
        check = fw[:max(m_check.start() - 1, 0)].replace('Ascent', '')
    return {'tip': tip, 'check': check,
            'tip_regex_matched': bool(m_tip), 'check_regex_matched': bool(m_check)}


# --------------------------------------------------------------------------------------
# Image inspection. None of this gates the vendor path; see VENDOR_DIVERGENCES.
# --------------------------------------------------------------------------------------
IMAGE_CONTAINERS = {
    b'RKFW': 'RKFW',    # Rockchip firmware image -- every Ascent VRX .img observed
    b'ASW\0': 'ASW',    # Ascent Sky container -- every Ascent_G_Sky_*.img observed
}
IMAGE_TRAILING_MD5_BYTES = 32


def identify_container(head: bytes) -> str | None:
    for magic, name in IMAGE_CONTAINERS.items():
        if head.startswith(magic):
            return name
    return None


def inspect_image(path: str, *, hash_limit: int | None = None) -> dict:
    """Local, read-only description of the selected image.

    `md5` is the field the vendor actually puts on the wire: MD5 of the WHOLE file
    (FileTransferSession.ComputeMD5 opens its own stream at position 0). The trailing
    digest check reproduces FileHashHelper -- vendor code, developer-menu-only.
    """
    p = str(path)
    size = os.path.getsize(p)
    md5 = hashlib.md5()
    sha = hashlib.sha256()
    trailing = hashlib.md5()
    head = b''
    remaining_body = size - IMAGE_TRAILING_MD5_BYTES
    consumed = 0
    tail = b''
    with open(p, 'rb') as f:
        while True:
            block = f.read(1 << 20)
            if not block:
                break
            if not head:
                head = block[:16]
            md5.update(block)
            sha.update(block)
            if remaining_body > 0 and consumed < remaining_body:
                take = min(len(block), remaining_body - consumed)
                trailing.update(block[:take])
            consumed += len(block)
    if size >= IMAGE_TRAILING_MD5_BYTES:
        with open(p, 'rb') as f:
            f.seek(-IMAGE_TRAILING_MD5_BYTES, os.SEEK_END)
            tail = f.read(IMAGE_TRAILING_MD5_BYTES)
    declared = tail.decode('ascii', 'replace').strip('\x00').strip()
    computed = trailing.hexdigest() if remaining_body > 0 else None
    if re.fullmatch(r'[0-9a-fA-F]{32}', declared or ''):
        carries = True
        matches = declared.lower() == (computed or '')
    else:
        carries = False
        matches = None
        declared = ''
    return {
        'path': p,
        'basename': os.path.basename(p.replace('\\', '/')),
        'bytes': size,
        'md5': md5.hexdigest(),
        'sha256': sha.hexdigest(),
        'container': identify_container(head),
        'container_magic_hex': head[:4].hex().upper(),
        'trailing_md5': {
            'carries_trailing_digest': carries,
            'declared': declared or None,
            'computed_over_body': computed,
            'matches': matches,
            'body_bytes': max(remaining_body, 0),
        },
    }


# --------------------------------------------------------------------------------------
# Selection validation -- the complete set of pre-send checks the PC Tool performs.
#
# severity:
#   'block'   the vendor refuses outright, no operator override
#   'confirm' the vendor shows a modal the operator can accept ("proceed anyway")
#   'info'    recorded, never gates
# `vendor` says whether the check exists in the stock tool at all.
# --------------------------------------------------------------------------------------

#: Camera-variant Sky units (Z8 / Z40 / Hub). Their OWN updater parses the
#: filename on the device and refuses a name it cannot parse with -5
#: UPGRATE_ERR_BOARD_TYPE -- after the whole image has been transferred.
#: Evidence differs per variant and travels with the check:
#:   z40  PROVEN statically from the 17.5.8 Z40 ar_fpvhs_upgrade
#:        (docs/Z40_FLASH_PATH_17_5_8_UPDATER_2026-10-07.md section 3): the last
#:        five `_` tokens must each be digits or the literal, case-sensitive `z40`.
#:   hub  INFERRED: the vendor's own image is `..._18_21_4_Hub_6.img`, so the Hub
#:        updater must accept `Hub`; accepted case-insensitively here.
#:   z8   INFERRED by analogy with z40.
VARIANT_TOKENS = {'z40': ('z40',), 'z8': ('z8',), 'hub': ('hub', 'Hub', 'HUB')}
VARIANT_EVIDENCE = {'z40': 'PROVEN', 'z8': 'INFERRED', 'hub': 'INFERRED'}
_VARIANT_IN_IDENTITY_RE = re.compile(r'(?:^|_)(z40|z8|hub)(?:_|$)', re.IGNORECASE)


def device_variant(identity: dict | None) -> str | None:
    """'z40' / 'z8' / 'hub' when command 60 names a camera variant, else None.

    Read from the device name first (`Ascent_GT_pro_z40` on 17.5.8 Z40), then the
    firmware string (`..._17_5_8_z40_2`). Recognition only -- never a gate.
    """
    i = identity or {}
    for field in ('device_name', 'firmware'):
        m = _VARIANT_IN_IDENTITY_RE.search(str(i.get(field) or ''))
        if m:
            return m.group(1).lower()
    return None


def variant_filename_ok(basename: str, variant: str) -> bool:
    """Would that variant's on-device updater parse this filename?"""
    stem = re.sub(r'\.img$', '', str(basename or ''), flags=re.IGNORECASE)
    tokens = stem.split('_')
    if len(tokens) < 6:
        return False
    allowed = VARIANT_TOKENS.get(variant, ())
    return all(t.isdigit() or t in allowed for t in tokens[-5:])


def variant_filename_suggestion(basename: str, identity: dict | None,
                                variant: str) -> str | None:
    """A name the updater accepts, built from the version the file declares."""
    v = extract_version(basename) or ''
    parts = v.split('.')
    if len(parts) < 3:
        m = re.search(r'(\d+)_(\d+)_(\d+)', str(basename or ''))
        if not m:
            return None
        parts = list(m.groups())
    sub = parts[3] if len(parts) > 3 else None
    if sub is None:
        m = re.search(r'_' + variant + r'_(\d+)', str((identity or {}).get('firmware') or ''),
                      re.IGNORECASE)
        sub = m.group(1) if m else '1'
    return f'Ascent_G_Sky_{parts[0]}_{parts[1]}_{parts[2]}_{VARIANT_TOKENS[variant][0]}_{sub}.img'


def validate_selection(path: str, identity: dict, *, image: dict | None = None) -> dict:
    """Every gate between "operator picked a file" and "first byte on the wire"."""
    checks: list[dict] = []
    p = str(path or '')
    fw = str((identity or {}).get('firmware') or '')
    prefixes = family_prefixes(fw)

    # 1. UpgradeProcessFSM.Start(): string.IsNullOrEmpty(FilePath) || !File.Exists(FilePath)
    exists = bool(p) and os.path.isfile(p)
    checks.append({
        'id': 'file_exists', 'severity': 'block', 'vendor': True,
        'passed': exists,
        'citation': 'UpgradeProcessFSM.cs:276-285',
        'vendor_message': 'firmware path error',
        'detail': p or '(no path)',
    })
    if not exists:
        return _selection_result(p, checks, prefixes, None, None, None)

    # 2. 2.0.51 SelectWrongFWFilePrompt: path.Length > 200 -> hard refuse.
    #    2.0.37 has no such check; it would throw inside BuildFileInfo instead.
    checks.append({
        'id': 'path_length', 'severity': 'block', 'vendor': True,
        'passed': len(p) <= VENDOR_PATH_LENGTH_LIMIT,
        'citation': 'AscentUpdataFrm.cs (2.0.51) SelectWrongFWFilePrompt',
        'vendor_message': 'The file path of the selected firmware is too long, '
                          'please move the file to a shorter path!',
        'detail': f'{len(p)} characters, vendor limit {VENDOR_PATH_LENGTH_LIMIT}',
        'build_specific': '2.0.51 only',
    })

    # 2b. ArFileInfo.fileDir is 128 bytes. 2.0.51 keeps the LAST 128 characters rather
    #     than refusing (FileTransferSession.BuildFileInfo, 2.0.51). 2.0.37 does not
    #     truncate and Array.Copy throws. Recorded, never a gate -- truncation is the
    #     reference build's behaviour and we reproduce it.
    local_forward = p.replace('\\', '/')
    checks.append({
        'id': 'file_dir_truncation', 'severity': 'info', 'vendor': True,
        'passed': True,
        'citation': 'FileTransferSession.cs BuildFileInfo (2.0.51)',
        'detail': (f'ArFileInfo.fileDir will carry the last {FILE_DIR_MAX} characters'
                   if len(local_forward) > FILE_DIR_MAX else
                   'local path fits ArFileInfo.fileDir[128] without truncation'),
        'truncated': len(local_forward) > FILE_DIR_MAX,
    })

    # 3. ArFileInfo.filePath[128] must hold "/tmp/pc/" + basename.
    remote = remote_path_for(p)
    checks.append({
        'id': 'remote_path_fits', 'severity': 'block', 'vendor': False,
        'passed': len(remote.encode('ascii', 'replace')) <= FILE_PATH_MAX,
        'citation': 'ArFileInfo.filePath[128]; UpgradeProcessFSM.cs:288',
        'detail': remote,
        'note': 'The vendor never checks this; Array.Copy would throw on overflow.',
    })

    # 4. AscentUpdataFrm.SelectWrongFWFilePrompt filename-vs-device check.
    stem = p.replace(VENDOR_FILE_EXTENSION, '')     # .NET Replace: ALL occurrences
    name_ok = bool(prefixes['check']) and prefixes['check'] in stem
    checks.append({
        'id': 'filename_matches_device', 'severity': 'confirm', 'vendor': True,
        'passed': name_ok,
        'citation': 'AscentUpdataFrm.cs:916-957 (2.0.37) / SelectWrongFWFilePrompt (2.0.51)',
        'vendor_message': 'The filename of the selected firmware does not match the '
                          'device. Whether the firmware file is selected incorrectly?',
        'detail': f"device prefix {prefixes['check']!r} not found in {stem!r}"
                  if not name_ok else f"device prefix {prefixes['check']!r} found",
        'note': 'A substring test on the FILE NAME. It is not a compatibility key and '
                'the device re-checks board type itself (UPGRATE_ERR_BOARD_TYPE).',
    })

    # 4b. Ours, not the PC Tool's: a camera-variant unit's own updater parses the
    #     filename and refuses what it cannot parse -- but only after the full
    #     transfer, as 118 Status -5. Saying so before the transfer is the point.
    variant = device_variant(identity)
    if variant:
        base = os.path.basename(p.replace('\\', '/'))
        v_ok = variant_filename_ok(base, variant)
        suggestion = None if v_ok else variant_filename_suggestion(base, identity, variant)
        checks.append({
            'id': 'variant_updater_filename', 'severity': 'confirm', 'vendor': False,
            'passed': v_ok,
            'evidence': VARIANT_EVIDENCE[variant],
            'variant': variant,
            'citation': 'docs/Z40_FLASH_PATH_17_5_8_UPDATER_2026-10-07.md section 3',
            'detail': (f'the {variant.upper()} updater on the unit should accept {base!r}'
                       if v_ok else
                       f'the {variant.upper()} updater on the unit parses the last five '
                       f'parts of the name and is expected to refuse {base!r} with -5 '
                       f'(board type) after the transfer'
                       + (f'; rename the file to {suggestion!r}' if suggestion else '')),
            'suggested_filename': suggestion,
            'note': ('The device decides, not this check. z40 is proven from the 17.5.8 '
                     'updater; z8 and hub are inferred.'),
        })

    # 5. AscentUpdataFrm.btnstartUpg_Click downgrade prompt.
    cur = current_version_label(p)
    verdict = judge_versions(fw, cur)
    is_downgrade = verdict['rc'] == 1 and verdict['res'] < 0
    checks.append({
        'id': 'not_a_downgrade', 'severity': 'confirm', 'vendor': True,
        'passed': not is_downgrade,
        'citation': 'AscentUpdataFrm.cs:638-663 (2.0.37) / btnstartUpg_Click (2.0.51)',
        'vendor_message': 'Degrade device is not recommended and usually fails. '
                          'If you want to try degrade?',
        'vendor_message_2037': 'It is not recommended to device。',
        'detail': f"device {verdict.get('device_version')} -> file {verdict.get('file_version')} "
                  f"({verdict['verdict']}, rc={verdict['rc']}, res={verdict['res']})",
        'note': 'A prompt, not a gate. The real anti-rollback decision belongs to the '
                'device and arrives as command-118 Status -6 UPGRATE_ERR_APP_VERSION.',
    })

    # 6. Extension. The vendor filter defaults to *.img but the dialog offers All (*.*)
    #    and the dragger accepts anything, so this can only ever be advisory.
    checks.append({
        'id': 'file_extension', 'severity': 'info', 'vendor': True,
        'passed': p.lower().endswith(VENDOR_FILE_EXTENSION),
        'citation': 'AscentUpdataFrm.cs:536-540',
        'detail': VENDOR_FILE_FILTER,
    })

    img = image if image is not None else inspect_image(p)
    # 7. Trailing image MD5 -- vendor code, developer menu only. See VENDOR_DIVERGENCES.
    t = img['trailing_md5']
    if t['carries_trailing_digest']:
        checks.append({
            'id': 'image_trailing_md5', 'severity': 'confirm', 'vendor': False,
            'passed': bool(t['matches']),
            'citation': 'FileHashHelper.cs:10-33; MainFrm.cs:1796-1821 (developer menu)',
            'detail': f"declared {t['declared']} vs computed {t['computed_over_body']}",
            'note': 'The stock upgrade path performs no image-content validation at all.',
        })
    else:
        checks.append({
            'id': 'image_trailing_md5', 'severity': 'info', 'vendor': False,
            'passed': True,
            'citation': 'FileHashHelper.cs:10-33',
            'detail': 'this image carries no trailing ASCII MD5 (ASW containers do not)',
        })
    # 8. Container recognition -- pure information. Never a gate: identifying a base by
    #    filename or container is explicitly forbidden (CLAUDE.md).
    checks.append({
        'id': 'container_recognised', 'severity': 'info', 'vendor': False,
        'passed': img['container'] is not None,
        'citation': 'observed: every Ascent VRX .img is RKFW, every Sky .img is ASW',
        'detail': img['container'] or f"unrecognised magic {img['container_magic_hex']}",
    })
    return _selection_result(p, checks, prefixes, cur, verdict, img)


def _selection_result(path, checks, prefixes, cur, verdict, img) -> dict:
    blocking = [c for c in checks if c['severity'] == 'block' and not c['passed']]
    # Operator wording for anything the UI will ask the operator to accept. Attached
    # here rather than in the UI so there is one source for it.
    for _c in checks:
        if _c.get('severity') == 'confirm':
            _c['plain_label'] = CONFIRM_PLAIN.get(_c['id'], _c.get('vendor_message') or _c['id'])

    confirms = [c for c in checks if c['severity'] == 'confirm' and not c['passed']]
    return {
        'ok': not blocking,
        'path': path,
        'checks': checks,
        'blocking': [c['id'] for c in blocking],
        'confirmations_required': [c['id'] for c in confirms],
        'family_prefixes': prefixes,
        'file_version_label': cur,
        'version_verdict': verdict,
        'image': img,
        'remote_path': remote_path_for(path) if path else None,
        'vendor_file_filter': VENDOR_FILE_FILTER,
    }


def remote_path_for(local_path: str) -> str:
    """UpgradeProcessFSM.Start(): "/tmp/pc/" + Path.GetFileName(FilePath)."""
    return REMOTE_UPGRADE_DIR + os.path.basename(str(local_path).replace('\\', '/'))


def file_dir_field(local_path: str) -> str:
    """ArFileInfo.fileDir -- the PC-SIDE path, '/'-normalised, last 128 chars (2.0.51)."""
    text = str(local_path).replace('\\', '/')
    if len(text) > FILE_DIR_MAX:
        text = text[len(text) - FILE_DIR_MAX:]
    return text


def _ascii_fixed(value: str | bytes, size: int, *, field_name: str) -> bytes:
    raw = value if isinstance(value, bytes) else value.encode('ascii', 'strict')
    if len(raw) > size:
        raise FirmwareUpgradeError('FILE_INFO_FIELD_TOO_LONG',
                                   f'ArFileInfo.{field_name} exceeds {size} bytes',
                                   stage='prepare')
    return raw + b'\0' * (size - len(raw))


def build_file_info(*, md5_hex: str, length: int, local_path: str,
                    remote_path: str | None = None) -> bytes:
    """FileTransferSession.BuildFileInfo -- 328 bytes, Pack = 1.

        MD5[64]     32 lowercase ASCII hex of the WHOLE file, NUL-padded
        length      file length in bytes
        saveAsFile  1
        filePath    remote destination, "/tmp/pc/<basename>"
        fileDir     PC-side local path, '/'-normalised, last 128 chars
    """
    remote = remote_path if remote_path is not None else remote_path_for(local_path)
    return AR_FILE_INFO.pack(
        _ascii_fixed(md5_hex.lower().encode('ascii'), MD5_FIELD_MAX, field_name='MD5'),
        int(length),
        SAVE_AS_FILE,
        _ascii_fixed(remote, FILE_PATH_MAX, field_name='filePath'),
        _ascii_fixed(file_dir_field(local_path), FILE_DIR_MAX, field_name='fileDir'),
    )


def build_request(command: int, payload: bytes = b'', *, seq: int = 0, retry: int = 0) -> bytes:
    """UsbSerialportFSM.EnqueueSend -- header then payload, CRC over both with crc32=0."""
    if command not in ALLOWED_COMMANDS:
        raise ValueError(f'command {command} is outside the firmware upgrade lane')
    p = bytes(payload)
    h0 = HEADER.pack(MAGIC, VERSION, 1, 0, 0xABCD, command, 2, 0,
                     len(p), seq & 0xffffffff, retry & 0xffffffff, 0)
    crc = crc32_vendor(h0, p)
    return HEADER.pack(MAGIC, VERSION, 1, 0, 0xABCD, command, 2, 0,
                       len(p), seq & 0xffffffff, retry & 0xffffffff, crc) + p


def parse_ack68(payload: bytes) -> dict | None:
    """ResAckInfo -- int Status; byte Detail[64]. Shape of the 3/114/115 ACKs."""
    if len(payload) < 68:
        return None
    status = int.from_bytes(payload[:4], 'little', signed=True)
    detail = payload[4:68].split(b'\0', 1)[0].decode('ascii', 'replace').rstrip(' \r\n\t')
    return {'status': status, 'detail': detail, 'payload_length': len(payload)}


def parse_file_data80(payload: bytes) -> dict | None:
    """ResFileDataInfo -- Length, Cursize, Totalsize, Status, Detail[64]. 116/117 ACKs."""
    if len(payload) < 80:
        return None
    length, cursize, totalsize, status = struct.unpack_from('<iiii', payload, 0)
    detail = payload[16:80].split(b'\0', 1)[0].decode('ascii', 'replace').rstrip(' \r\n\t')
    return {'length': length, 'cursize': cursize, 'totalsize': totalsize,
            'status': status, 'detail': detail, 'payload_length': len(payload)}


def parse_upgrade_status(payload: bytes) -> dict | None:
    """ResUpgradeStatus -- int Percent; int Status; byte Detail[64]."""
    if len(payload) < 72:
        return None
    percent, status = struct.unpack_from('<ii', payload, 0)
    detail = payload[8:72].split(b'\0', 1)[0].decode('ascii', 'replace').rstrip(' \r\n\t')
    code, text = UPGRADE_STATUS_CODES.get(status, ('UNKNOWN_STATUS', f'status {status}'))
    return {'percent': percent, 'status': status, 'detail': detail,
            'status_code': code, 'status_text': text,
            'is_error': status < 0, 'is_anti_rollback': status == ANTI_ROLLBACK_STATUS,
            'payload_length': len(payload)}


def judge_upgrade_status(parsed: dict) -> tuple[bool, str]:
    """2.0.51 UpgradeProcessFSM.JudgeUpgradeStatus(ResUpgradeStatus, out string)."""
    if parsed is None:
        return True, 'upgrade success'
    code, text = UPGRADE_STATUS_CODES.get(parsed['status'], (None, None))
    if code is None:
        return True, 'upgrade success'
    if parsed['status'] >= 0:
        return True, 'upgrade success'
    return False, text


def resolve_chunk_size(receive_max_size) -> dict:
    """UpgradeProcessFSM.cs:696 `_chunkSize = RecMaxSize`, with a sanity bound.

    Every real device observed declares 1048576, which is also the vendor's compiled
    default -- so on real hardware the negotiated and default values coincide.
    """
    if isinstance(receive_max_size, int) and CHUNK_SIZE_MIN <= receive_max_size <= CHUNK_SIZE_MAX:
        return {'chunk_size': receive_max_size, 'source': 'device_receive_max_size',
                'declared': receive_max_size, 'honoured': True}
    return {'chunk_size': DEFAULT_CHUNK_SIZE, 'source': 'vendor_default',
            'declared': receive_max_size if isinstance(receive_max_size, int) else None,
            'honoured': False}


# --------------------------------------------------------------------------------------
# Qualification. Per-operation, fail closed -- CLAUDE.md "Write qualification".
# --------------------------------------------------------------------------------------
# Raw command-60 device names this project has evidence of the firmware lane on. The
# vendor's own gate is looser (`DeviceName.Contains("Ascent")`, MainFrm.cs:543); ours
# is the vendor gate PLUS the requirement that the device answered command 60 in this
# session with a name and firmware string we can read.
VENDOR_UPGRADE_NAME_TOKENS = ('ascent', 'yohd', 'new device')


# code -> what it means to the person holding the unit. The technical reason stays
# beside it for the diagnostics view; this is what the page shows by default.
# What each confirmable prompt MEANS, in operator words.
#
# The confirmation table used to print the check's internal id -- `not_a_downgrade`,
# `filename_matches_device` -- in its first column, in a normal (non-diagnostic)
# state. That is an internal enum value on screen, which this project's own rule
# forbids, and it told the operator nothing the vendor message beside it did not
# already say better. The id is still available behind ADVANCED for a bug report.
#
# These are deliberately phrased as THE QUESTION BEING ASKED, because the operator is
# being asked to accept something, not shown a status.
CONFIRM_PLAIN = {
    'filename_matches_device':
        'The file name does not look like it belongs to this unit',
    'not_a_downgrade':
        'This would move the unit to an older firmware version',
    'image_trailing_md5':
        'This image does not carry the trailing checksum we can verify',
    'variant_updater_filename':
        'This unit will probably refuse this file name after the transfer',
}


REFUSAL_PLAIN = {
    'NO_DEVICE_NAME': 'This unit has not reported enough identity information yet. '
                      'Reconnect it and wait for identification to finish.',
    'NOT_UPGRADE_TARGET': 'This unit does not identify as one this tool can upgrade.',
    'NO_FIRMWARE_STRING': 'This unit did not report its firmware version, so the tool '
                          'cannot compare it with the file you chose.',
    'NO_RECEIVE_SIZE': 'This unit did not report how large a transfer it accepts.',
    'RECEIVE_SIZE_UNEXPECTED': 'This unit reports a transfer size the upgrade does not '
                               'support.',
    'NO_SERIAL_PORT': 'No serial port is open to this unit. Reconnect it over USB-C.',
    'NO_CONTAINER_ID': 'Windows has not linked the serial port to a physical USB device '
                       'yet, so the unit could not be found again after a restart. '
                       'Reconnect it and wait for identification to finish.',
    'NO_VID_PID': 'Windows has not reported enough about the USB device to confirm it '
                  'is an Ascent unit.',
    'NO_FILE': 'No firmware file has been chosen and checked yet.',
    'FILE_FAILED_VALIDATION': 'The firmware file you chose did not pass its checks.',
}


def qualify_firmware_upgrade(*, candidate: dict | None, identity: dict | None,
                             selection: dict | None) -> dict:
    reasons: list[str] = []
    codes: list[str] = []
    c = candidate or {}
    i = identity or {}
    raw_name = str(i.get('device_name') or '')
    firmware = str(i.get('firmware') or '')
    receive_max_size = i.get('receive_max_size')
    port = c.get('serial_com')
    container = str(c.get('serial_container_id') or '').strip().upper()
    pnp = c.get('serial_pnp_device_id')
    m = re.search(r'VID_([0-9A-Fa-f]{4})&PID_([0-9A-Fa-f]{4})', str(pnp or ''))
    vid, pid = (m.group(1).upper(), m.group(2).upper()) if m else (None, None)

    if not raw_name:
        reasons.append('no raw command-60 device name for the connected device')
        codes.append('NO_DEVICE_NAME')
    elif not any(t in raw_name.lower() for t in VENDOR_UPGRADE_NAME_TOKENS):
        reasons.append(f'raw command-60 name {raw_name!r} is not an Ascent upgrade target '
                       f'(vendor gate: MainFrm.cs:543)')
        codes.append('NOT_UPGRADE_TARGET')
    if not firmware:
        reasons.append('device reported no firmware string, so no version comparison is possible')
        codes.append('NO_FIRMWARE_STRING')
    if receive_max_size != REQUIRED_RECEIVE_MAX_SIZE:
        if receive_max_size is None:
            reasons.append('device reported no receive_max_size; firmware upgrade requires '
                           f'exactly {REQUIRED_RECEIVE_MAX_SIZE}')
            codes.append('NO_RECEIVE_SIZE')
        else:
            reasons.append(f'device declared receive_max_size {receive_max_size}; firmware '
                           f'upgrade requires exactly {REQUIRED_RECEIVE_MAX_SIZE}')
            codes.append('RECEIVE_SIZE_UNEXPECTED')
    if not port:
        reasons.append('no serial COM interface is bound to the connected device')
        codes.append('NO_SERIAL_PORT')
    if not container:
        reasons.append('no Windows USB ContainerId; the device could not be re-found after reboot')
        codes.append('NO_CONTAINER_ID')
    if not vid or not pid:
        reasons.append('no VID/PID evidence for the serial interface')
        codes.append('NO_VID_PID')
    if selection is None:
        reasons.append('no firmware file has been selected and validated')
        codes.append('NO_FILE')
    elif not selection.get('ok'):
        reasons.append('the selected firmware file failed a blocking validation')
        codes.append('FILE_FAILED_VALIDATION')

    return {
        'operation_id': OPERATION_ID,
        'operation_label': OPERATION_LABEL,
        'eligible': not reasons,
        # `reasons` stays exactly as it was -- it is the diagnostic text and the
        # tests pin it. `reason_codes` and `plain_reasons` are additive: the page
        # shows the plain sentences and keeps the technical ones behind ADVANCED.
        'reasons': reasons,
        'reason_codes': codes,
        'plain_reasons': [REFUSAL_PLAIN.get(c) for c in codes if REFUSAL_PLAIN.get(c)],
        'evidence': {
            'raw_device_name': raw_name or None,
            'firmware': firmware or None,
            'receive_max_size': receive_max_size,
            'required_receive_max_size': REQUIRED_RECEIVE_MAX_SIZE,
            'receive_max_size_qualified': receive_max_size == REQUIRED_RECEIVE_MAX_SIZE,
            'serial_com': port,
            'container_id_present': bool(container),
            'vid': vid, 'pid': pid,
            'selection_ok': None if selection is None else bool(selection.get('ok')),
        },
        'vendor_gate': 'DeviceName.Contains("Ascent") || Contains("YoHD") || '
                       'Contains("new device")  -- MainFrm.cs:543, OnFunctionSelectFrm',
    }


# --------------------------------------------------------------------------------------
# The transaction.
# --------------------------------------------------------------------------------------
@dataclass
class UpgradePlan:
    local_path: str
    remote_path: str
    file_bytes: int
    md5_hex: str
    chunk_size: int
    chunk_count: int
    chunk_size_source: str

    def document(self) -> dict:
        return {'local_path': self.local_path, 'remote_path': self.remote_path,
                'file_bytes': self.file_bytes, 'md5': self.md5_hex,
                'chunk_size': self.chunk_size, 'chunk_count': self.chunk_count,
                'chunk_size_source': self.chunk_size_source}


def plan_transfer(image: dict, chunk: dict) -> UpgradePlan:
    size = int(image['bytes'])
    cs = int(chunk['chunk_size'])
    count = (size + cs - 1) // cs if size else 0
    return UpgradePlan(local_path=image['path'], remote_path=remote_path_for(image['path']),
                       file_bytes=size, md5_hex=image['md5'], chunk_size=cs,
                       chunk_count=count, chunk_size_source=chunk['source'])


def default_serial_factory(port: str):
    # 2.0.51 sets SerialPort.WriteTimeout = -1 because a 116 frame is a whole chunk.
    return WinSerial(port, write_timeout_ms=0)


class FirmwareUpgradeSession:
    """One serial session running the PC Tool's firmware lane.

    Windows-specific device re-enumeration is NOT done here: `port_resolver` is
    supplied by the caller so this module stays testable offline and so USB topology
    correlation keeps living in one place (CLAUDE.md, Multi-device correlation).
    """

    def __init__(self, port: str, *,
                 serial_factory: Callable[[str], object] = default_serial_factory,
                 port_resolver: Callable[..., tuple] | None = None,
                 progress: Callable[[dict], None] | None = None,
                 sleep: Callable[[float], None] = time.sleep,
                 monotonic: Callable[[], float] = time.monotonic):
        self.port = str(port).upper()
        self.seq = 0
        self.sp = None
        self.serial_factory = serial_factory
        self.port_resolver = port_resolver or self._same_port_resolver
        self.progress = progress
        self._sleep = sleep
        self._now = monotonic
        self.decoder = Decoder()
        self.stages: list[dict] = []
        self.warnings: list[dict] = []
        self.identity: dict | None = None
        self.chunk: dict | None = None

    # -- transport -------------------------------------------------------------------
    def open(self):
        self.sp = self.serial_factory(self.port).open()
        self.decoder = Decoder()
        return self

    def close(self):
        if self.sp is not None:
            try:
                self.sp.close()
            except Exception:
                pass
        self.sp = None

    def __enter__(self):
        return self.open()

    def __exit__(self, *_):
        self.close()

    def _report(self, **fields):
        if self.progress:
            self.progress(dict(fields))

    def _exchange(self, command: int, payload: bytes = b'', *,
                  expected: Iterable[int] | None = None,
                  timeout: float = ACK_TOTAL_TIMEOUT,
                  retry_interval: float = ACK_RETRY_INTERVAL,
                  stage: str | None = None) -> dict:
        """Send, then honour the vendor's ACK guard.

        Retries allocate a NEW sequence number and increment the header `retry` field
        (docs/PROTOCOL_SPEC.md section 6). A reply is accepted when its command matches
        and its seq is one this transaction sent -- see VENDOR_DIVERGENCES
        `ack_seq_correlation`.
        """
        expected_set = set(expected or (command,))
        if hasattr(self.sp, 'purge_rx'):
            try:
                self.sp.purge_rx()
            except Exception:
                pass
        self.decoder = Decoder()
        sent_seqs: set[int] = set()
        started = self._now()
        deadline = started + timeout
        next_send = 0.0
        attempts = 0
        seen: list[dict] = []
        while self._now() < deadline:
            now = self._now()
            if now >= next_send:
                seq = self.seq
                self.seq = (self.seq + 1) & 0xffffffff
                sent_seqs.add(seq)
                self.sp.write(build_request(command, payload, seq=seq, retry=attempts))
                attempts += 1
                next_send = now + retry_interval
            chunk = self.sp.read(4096)
            if not chunk:
                continue
            for h, p, crc_ok in self.decoder.feed(chunk):
                summary = {'command': h.command, 'seq': h.seq, 'retry': h.retry,
                           'length': len(p), 'local_crc32_match': crc_ok}
                seen.append(summary)
                if h.command in expected_set and h.seq in sent_seqs:
                    return {'ok': True, 'request_command': command,
                            'send_attempts': attempts, 'response': summary, 'payload': p,
                            'seen_frames': seen[-16:]}
                if h.command == 0:
                    ack = parse_ack68(p) or {}
                    raise FirmwareUpgradeError(
                        'VENDOR_COMMAND_REJECTED',
                        ack.get('detail') or 'device returned the vendor "unkonwn cmd" reply',
                        stage=stage or str(command),
                        evidence={'seen_frames': seen[-16:], 'ack': ack})
        raise FirmwareUpgradeError(
            'VENDOR_ACK_TIMEOUT',
            f'no correlated response to command {command} within {timeout:.0f} s',
            stage=stage or str(command),
            evidence={'attempts': attempts, 'seen_frames': seen[-16:]})

    def _send_unacked(self, command: int, payload: bytes = b'') -> dict:
        seq = self.seq
        self.seq = (self.seq + 1) & 0xffffffff
        self.sp.write(build_request(command, payload, seq=seq, retry=0))
        flush = getattr(self.sp, 'flush', None)
        if callable(flush):
            try:
                flush()
            except Exception:
                pass
        return {'seq': seq, 'command': command, 'payload_length': len(payload)}

    # -- default reconnect ------------------------------------------------------------
    def _same_port_resolver(self, previous_port, *, settle_s, poll_budget_s, phase,
                            progress=None):
        """2.0.51 ForceSearchMode == 3 without the USB search half.

        The search half needs Windows PnP and belongs to dev_harness; this default
        keeps the timing model identical so offline tests exercise the same shape.
        """
        self._sleep(settle_s)
        started = self._now()
        deadline = started + poll_budget_s
        attempts = 0
        last_error = None
        while self._now() < deadline:
            attempts += 1
            try:
                probe = self.serial_factory(previous_port).open()
                probe.close()
                return previous_port, {'attempts': attempts, 'strategy': 'same_port',
                                       'elapsed_s': round(self._now() - started, 2)}
            except Exception as exc:
                last_error = f'{type(exc).__name__}: {exc}'
            if progress:
                progress({'phase': phase, 'settle_s': settle_s,
                          'poll_budget_s': poll_budget_s,
                          'elapsed_s': round(self._now() - started, 1),
                          'attempts': attempts, 'last_error': last_error})
            self._sleep(PORT_RETRY_INTERVAL)
        raise FirmwareUpgradeError(
            'RECONNECT_TIMEOUT', 'Reconnection timeout', stage=phase,
            evidence={'attempts': attempts, 'last_error': last_error,
                      'settle_s': settle_s, 'poll_budget_s': poll_budget_s})

    def _reconnect(self, phase: str) -> dict:
        self.close()
        self._report(phase=phase, settle_s=RECONNECT_SETTLE,
                     poll_budget_s=RECONNECT_POLL_BUDGET, elapsed_s=0.0)
        port, evidence = self.port_resolver(
            self.port, settle_s=RECONNECT_SETTLE, poll_budget_s=RECONNECT_POLL_BUDGET,
            phase=phase, progress=self.progress)
        if port and port.upper() != self.port:
            evidence = dict(evidence or {})
            evidence['port_changed_from'] = self.port
            self.port = port.upper()
        self.open()
        return dict(evidence or {}, port=self.port)

    # -- stages ------------------------------------------------------------------------
    def find_device(self) -> dict:
        """Command 60. Also negotiates the chunk size (UpgradeProcessFSM.cs:684-698)."""
        self._report(phase='find_device', percent=0.02, desc='Query device info')
        d = self._exchange(CMD_FIND_DEVICE, expected=(CMD_FIND_DEVICE,), stage='60')
        info = parse_device_info(d['payload'])
        self.identity = info
        self.chunk = resolve_chunk_size(info.get('receive_max_size'))
        if not self.chunk['honoured'] and self.chunk['declared'] is not None:
            self.warnings.append({
                'id': 'receive_max_size_out_of_range',
                'message': f"device declared receive_max_size {self.chunk['declared']}; "
                           f'using the vendor default {DEFAULT_CHUNK_SIZE}'})
        self.stages.append({'stage': 'FIND_DEVICE', 'command': 60,
                            'receive_max_size': info.get('receive_max_size'),
                            'chunk': dict(self.chunk)})
        return info

    def reboot_clean(self) -> dict:
        """Command 3, mode ASCII "clean" padded to 32 bytes.

        2.0.51 sends this WITHOUT an ACK guard and transitions straight to
        WaitCleanOnline; 2.0.37 guarded it and waited for the cmd-3 ACK. The reference
        build's behaviour is reproduced: the reply is collected opportunistically as
        evidence and never gates. Real devices do answer it -- vendor log
        "返回帧长度=104,cmd=3" immediately before every observed reconnect.
        """
        self._report(phase='reboot_clean', percent=0.08, desc='Reconnecting device')
        sent = self._send_unacked(CMD_REBOOT, REBOOT_MODE_CLEAN)
        ack = None
        deadline = self._now() + 1.0
        while self._now() < deadline:
            try:
                data = self.sp.read(4096)
            except Exception:
                break
            if not data:
                continue
            for h, p, _ in self.decoder.feed(data):
                if h.command == CMD_REBOOT and h.seq == sent['seq']:
                    ack = parse_ack68(p)
                    deadline = 0.0
                    break
        stage = {'stage': 'REBOOT_CLEAN', 'command': 3, 'seq': sent['seq'],
                 'mode': 'clean', 'ack': ack,
                 'ack_is_gating': False}
        self.stages.append(stage)
        return stage

    def remote_upgrade(self) -> dict:
        """Command 114. The vendor's readiness proof after the clean-mode reconnect."""
        self._report(phase='remote_upgrade', percent=0.13,
                     desc='Device ready, entering upgrade mode')
        d = self._exchange(CMD_REMOTE_UPGRADE, expected=(CMD_REMOTE_UPGRADE,), stage='114')
        ack = parse_ack68(d['payload'])
        self.stages.append({'stage': 'REMOTE_UPGRADE', 'command': 114, 'ack': ack})
        self._report(phase='remote_upgrade', percent=0.15,
                     desc='Upgrade mode entered, starting file transfer')
        return {'ack': ack}

    def send_file_start(self, plan: UpgradePlan) -> dict:
        self._report(phase='sendfile_start', percent=0.17, desc='Start transferring files')
        info = build_file_info(md5_hex=plan.md5_hex, length=plan.file_bytes,
                               local_path=plan.local_path, remote_path=plan.remote_path)
        d = self._exchange(CMD_SENDFILE_START, info, expected=(CMD_SENDFILE_START,),
                           stage='115')
        ack = parse_ack68(d['payload'])
        # See VENDOR_DIVERGENCES sendfile_start_status_gate.
        if ack is not None and ack['status'] != 0:
            raise FirmwareUpgradeError('SENDFILE_START_REJECTED',
                                       ack['detail'] or 'SENDFILE_START rejected',
                                       stage='115', evidence=ack)
        self.stages.append({'stage': 'SENDFILE_START', 'command': 115,
                            'file_info_bytes': len(info), 'ack': ack,
                            'plan': plan.document()})
        return {'ack': ack, 'file_info': info}

    def send_file_data(self, plan: UpgradePlan, stream) -> dict:
        """Command 116 per chunk, ACKed one at a time (UpgradeProcessFSM.cs:560-590)."""
        sent = 0
        index = 0
        acks: list[dict] = []
        while sent < plan.file_bytes:
            want = min(plan.chunk_size, plan.file_bytes - sent)
            block = stream.read(want)
            if not block:
                break
            d = self._exchange(CMD_SENDFILE_DATA, block, expected=(CMD_SENDFILE_DATA,),
                               timeout=CHUNK_ACK_TIMEOUT, stage='116')
            ack = parse_file_data80(d['payload'])
            if ack is not None and ack['status'] != 0:
                raise FirmwareUpgradeError('SENDFILE_DATA_REJECTED',
                                           ack['detail'] or 'SENDFILE_DATA rejected',
                                           stage='116',
                                           evidence=dict(ack, chunk_index=index))
            sent += len(block)
            index += 1
            if len(acks) < 4 or index >= plan.chunk_count - 1:
                acks.append(dict(ack or {}, chunk_index=index - 1))
            # Vendor UI maps the transfer to 0.17 -> 0.60 (FirmwareUpgradeFlowV2:162).
            fraction = (sent / plan.file_bytes) if plan.file_bytes else 1.0
            self._report(phase='sendfile_data', percent=0.17 + 0.43 * fraction,
                         desc='File transfer in progress...',
                         bytes_sent=sent, bytes_total=plan.file_bytes,
                         chunk_index=index, chunk_count=plan.chunk_count)
        if sent != plan.file_bytes:
            raise FirmwareUpgradeError('SHORT_TRANSFER',
                                       f'sent {sent} of {plan.file_bytes} bytes',
                                       stage='116',
                                       evidence={'bytes_sent': sent,
                                                 'bytes_total': plan.file_bytes})
        self.stages.append({'stage': 'SENDFILE_DATA', 'command': 116,
                            'chunks_sent': index, 'bytes_sent': sent,
                            'chunk_size': plan.chunk_size, 'sample_acks': acks})
        return {'chunks_sent': index, 'bytes_sent': sent}

    def send_file_end(self) -> dict:
        """Command 117. The only transfer step whose Status the vendor actually reads.

        UpgradeProcessFSM.OnAck, UpgState.SendFileEnd:
            if (resFileDataInfo.Status != 0 || text != "OK") { Fail(desc); return; }
        The device-side MD5 comparison is what this reports -- ar_fpvhs_upgrade logs
        "[INFO] MD5 comparison: calculated=%.32s, expected=%.32s, result=%d".
        """
        self._report(phase='sendfile_end', percent=0.62, desc='Finish transferring firmware')
        d = self._exchange(CMD_SENDFILE_END, b'', expected=(CMD_SENDFILE_END,), stage='117')
        ack = parse_file_data80(d['payload'])
        if ack is None:
            raise FirmwareUpgradeError('SENDFILE_END_MALFORMED',
                                       'SENDFILE_END reply was not an 80-byte ResFileDataInfo',
                                       stage='117',
                                       evidence={'payload_length': len(d['payload'])})
        if ack['status'] != 0 or ack['detail'] != 'OK':
            raise FirmwareUpgradeError('SENDFILE_END_REJECTED',
                                       ack['detail'] or 'SENDFILE_END rejected',
                                       stage='117', evidence=ack)
        self.stages.append({'stage': 'SENDFILE_END', 'command': 117, 'ack': ack})
        self._report(phase='upgrade_status', percent=0.65, desc='Check upgrade status')
        return {'ack': ack}

    def poll_upgrade_status(self) -> dict:
        """Command 118, <= 200 queries, 1000 ms apart.

        Status < 0 is the device's own verdict and ends the operation immediately
        (2.0.51 JudgeUpgradeStatus). Status -6 UPGRATE_ERR_APP_VERSION is the
        anti-rollback refusal; it is reported as such rather than as a generic failure.
        """
        history: list[dict] = []
        for query in range(1, STATUS_POLL_LIMIT + 1):
            self._sleep(STATUS_POLL_DELAY)
            d = self._exchange(CMD_UPGRADE_STATUS, expected=(CMD_UPGRADE_STATUS,), stage='118')
            parsed = parse_upgrade_status(d['payload'])
            if parsed is None:
                raise FirmwareUpgradeError('UPGRADE_STATUS_MALFORMED',
                                           'UPGRADE_STATUS reply was not a 72-byte ResUpgradeStatus',
                                           stage='118',
                                           evidence={'payload_length': len(d['payload'])})
            if len(history) < 3 or parsed['status'] < 0 or parsed['percent'] > 99:
                history.append(dict(parsed, query=query))
            ok, text = judge_upgrade_status(parsed)
            if not ok:
                code = ('FIRMWARE_REJECTED_ANTI_ROLLBACK' if parsed['is_anti_rollback']
                        else 'FIRMWARE_UPGRADE_REJECTED')
                self.stages.append({'stage': 'UPGRADE_STATUS', 'command': 118,
                                    'queries': query, 'history': history,
                                    'outcome': parsed['status_code']})
                raise FirmwareUpgradeError(code, text, stage='118',
                                           evidence={'status': parsed, 'queries': query,
                                                     'history': history,
                                                     'device_rejected': True})
            if parsed['percent'] > 99:
                # Vendor wording, ours is the fraction. AscentUpdataFrm sets Percent=1f
                # here and then spends the whole final reconnect at 100%; the bar would
                # finish twice. The reported fraction stays monotonic instead and only
                # reaches 1.0 at `complete`.
                self._report(phase='upgrade_status', percent=0.96,
                             desc='Upgrade successful, device is auto restarting')
                self._sleep(POST_STATUS_SETTLE)
                self.stages.append({'stage': 'UPGRADE_STATUS', 'command': 118,
                                    'queries': query, 'history': history,
                                    'outcome': 'COMPLETE'})
                return {'queries': query, 'history': history, 'final': parsed}
            pct = max(0, min(99, parsed['percent']))
            self._report(phase='upgrade_status', percent=0.65 + pct * 0.0034,
                         desc='Loading firmware', device_percent=parsed['percent'],
                         device_status=parsed['status_code'], query=query)
        raise FirmwareUpgradeError('UPGRADE_STATUS_QUERY_LIMIT',
                                   'Upgrade status query limit exceeded', stage='118',
                                   evidence={'queries': STATUS_POLL_LIMIT,
                                             'history': history,
                                             'upgrade_may_have_applied': True})

    def reread_identity(self) -> dict:
        """Post-flash version reread.

        This IS a vendor step: on a completed upgrade AscentUpdataFrm's progress
        handler calls `GD.Inst.UpgFSM.Send_FindDevice()` (AscentUpdataFrm.cs:280-281),
        whose command-60 ACK repaints the firmware/hardware/SN labels through
        UpgFSM_OnAsceDevRecInfo.
        """
        # Deliberately no `percent`: the vendor already reported 1.0 when command 118
        # completed and reports 1.0 again on "upgrade is complete", so anything lower
        # in between would make a progress bar run backwards.
        self._report(phase='verify', desc='Rereading device firmware version')
        d = self._exchange(CMD_FIND_DEVICE, expected=(CMD_FIND_DEVICE,), stage='60-post')
        info = parse_device_info(d['payload'])
        self.stages.append({'stage': 'FIND_DEVICE_POST', 'command': 60,
                            'firmware': info.get('firmware'),
                            'device_name': info.get('device_name')})
        return info


def run_upgrade(session: FirmwareUpgradeSession, image: dict, *,
                open_image: Callable[[str], object] | None = None,
                on_before_transfer: Callable[[dict], dict] | None = None) -> dict:
    """The complete vendor firmware lane, in vendor order.

    `on_before_transfer` runs after command 60 and BEFORE the first mutating command
    (the "clean" reboot). That is where the timestamped pre-flash backup is taken --
    see VENDOR_DIVERGENCES `pre_transfer_backup`.
    """
    opener = open_image or (lambda p: open(p, 'rb'))
    started = time.time()
    identity = session.find_device()
    plan = plan_transfer(image, session.chunk or resolve_chunk_size(None))
    backup = None
    if on_before_transfer is not None:
        backup = on_before_transfer({'identity': identity, 'plan': plan.document()})

    committed = False
    session.reboot_clean()
    clean_reconnect = session._reconnect('reconnect_clean')
    session.remote_upgrade()
    session.send_file_start(plan)
    committed = True
    stream = opener(plan.local_path)
    try:
        session.send_file_data(plan, stream)
    finally:
        try:
            stream.close()
        except Exception:
            pass
    session.send_file_end()
    try:
        status = session.poll_upgrade_status()
    except FirmwareUpgradeError as exc:
        ev = dict(exc.evidence or {})
        ev.setdefault('image_was_transferred', committed)
        ev.setdefault('backup', backup)
        ev.setdefault('clean_reconnect', clean_reconnect)
        raise FirmwareUpgradeError(exc.code, str(exc), stage=exc.stage, evidence=ev) from exc

    # UpgState.Completed -> Send_ReopenCOM(). The vendor does NOT send command 3 here:
    # the device reboots itself ("Upgrade successful, device is auto restarting").
    # Only the dead FirmwareUpgradeFlowV2.FinalRebootAsync sends an explicit reboot.
    final_reconnect = session._reconnect('reconnect_final')
    post = session.reread_identity()
    session._report(phase='complete', percent=1.0, desc='upgrade is complete')
    return {
        'ok': True,
        'operation_id': OPERATION_ID,
        'plan': plan.document(),
        'identity_before': identity,
        'identity_after': post,
        'firmware_before': identity.get('firmware'),
        'firmware_after': post.get('firmware'),
        'firmware_changed': (identity.get('firmware') or None) != (post.get('firmware') or None),
        'status': status,
        'stages': session.stages,
        'warnings': session.warnings,
        'backup': backup,
        'clean_reconnect': clean_reconnect,
        'final_reconnect': final_reconnect,
        'elapsed_s': round(time.time() - started, 2),
    }


def timing_document() -> dict:
    """Every timing constant, with the build each value comes from."""
    return {
        'ack_retry_interval_s': ACK_RETRY_INTERVAL,
        'ack_total_timeout_s': ACK_TOTAL_TIMEOUT,
        'ack_retry_interval_s_2037': ACK_RETRY_INTERVAL_2037,
        'ack_total_timeout_s_2037': ACK_TOTAL_TIMEOUT_2037,
        'chunk_ack_timeout_s': CHUNK_ACK_TIMEOUT,
        'status_poll_delay_s': STATUS_POLL_DELAY,
        'status_poll_delay_s_2037': STATUS_POLL_DELAY_2037,
        'status_poll_limit': STATUS_POLL_LIMIT,
        'reconnect_settle_s': RECONNECT_SETTLE,
        'reconnect_poll_budget_s': RECONNECT_POLL_BUDGET,
        'reconnect_total_budget_s': RECONNECT_TOTAL_BUDGET,
        'port_retry_limit': PORT_RETRY_LIMIT,
        'port_retry_interval_s': PORT_RETRY_INTERVAL,
        'default_chunk_size': DEFAULT_CHUNK_SIZE,
        'observed_device_receive_max_size': OBSERVED_DEVICE_RECEIVE_MAX_SIZE,
    }


def selftest() -> dict:
    assert HEADER_SIZE == 36
    assert AR_FILE_INFO.size == 328
    assert REBOOT_MODE_CLEAN == b'clean' + b'\0' * 27

    # ArFileInfo layout, field by field.
    fi = build_file_info(md5_hex='0123456789abcdef' * 2, length=179477066,
                         local_path=r'D:\fw\Ascent_VRX_Max_19_2_5.img')
    assert len(fi) == 328
    assert fi[:32] == b'0123456789abcdef' * 2
    assert fi[32:64] == b'\0' * 32
    assert int.from_bytes(fi[64:68], 'little', signed=True) == 179477066
    assert int.from_bytes(fi[68:72], 'little', signed=True) == 1
    assert fi[72:200].split(b'\0', 1)[0] == b'/tmp/pc/Ascent_VRX_Max_19_2_5.img'
    assert fi[200:328].split(b'\0', 1)[0] == b'D:/fw/Ascent_VRX_Max_19_2_5.img'

    # fileDir keeps the LAST 128 characters (2.0.51 BuildFileInfo).
    long_local = 'C:/' + 'd' * 200 + '/x.img'
    assert file_dir_field(long_local) == long_local[-128:]
    assert len(file_dir_field(long_local)) == 128

    # Header framing.
    req = build_request(115, fi, seq=7, retry=2)
    h = ArHeader.unpack(req[:36])
    assert h.magic == MAGIC and h.version == VERSION and h.command == 115
    assert h.type == 1 and h.format == 2 and h.length == 328 and h.seq == 7 and h.retry == 2
    z = bytearray(req[:36]); z[32:36] = b'\0\0\0\0'
    assert h.crc32 == crc32_vendor(bytes(z), fi)
    for bad in (0, 120, 121, 122, 123):
        try:
            build_request(bad)
        except ValueError:
            pass
        else:
            raise AssertionError(f'command {bad} must be refused by the firmware lane')

    # ExtractVersion, the vendor regex, including the z8/z40/hub 4th component.
    assert extract_version('Ascent_VRX_Max_19_2_5.img') == '19.2.5'
    assert extract_version('Ascent_G_Sky_18_21_8.img') == '18.21.8'
    assert extract_version('Ascent_GT_Max_WF_18_3_4_z8_7.img') == '18.3.4.7'
    assert extract_version('Ascent_GT_Pro_Hub_17_5_3_hub_2.IMG') == '17.5.3.2'
    assert extract_version('firmware.bin') == ''
    assert current_version_label('/x/Ascent_VRX_Max_19_2_5.img') == 'V19.2.5'
    assert current_version_label('/x/no_version_here.bin') == 'V_unRecog'
    assert current_version_label('/x/18_21_8.img') == 'V18.21.8'

    # _perVer, and the downgrade verdict the button click acts on.
    assert device_version_label('Ascent_VRX_Max_19_2_4') == 'V19.2.4'
    up = judge_versions('Ascent_VRX_Max_19_2_4', 'V19.2.5')
    assert up['rc'] == 0 and up['verdict'] == 'upgrade'
    down = judge_versions('Ascent_VRX_Max_19_2_5', 'V19.2.4')
    assert down['rc'] == 1 and down['res'] < 0 and down['verdict'] == 'downgrade'
    same = judge_versions('Ascent_VRX_Max_19_2_4', 'V19.2.4')
    assert same['rc'] == 0 and same['verdict'] == 'same_version'
    # "V_unRecog" makes new Version(...) throw, so the vendor shows NO prompt.
    assert judge_versions('Ascent_VRX_Max_19_2_4', _UNRECOGNISED_VERSION)['rc'] == 9

    # The two prefixes really do disagree on this project's own firmware string.
    pf = family_prefixes('Ascent_VRX_Max_19_2_4')
    assert pf['tip'] == 'Ascent_VRX_Max', pf
    assert pf['check'] == 'Ascent_VRX_M', pf
    assert pf['tip_regex_matched'] and not pf['check_regex_matched']

    # Status decoding, including the anti-rollback verdict.
    payload = struct.pack('<ii', 42, -6) + b'app version err!'.ljust(64, b'\0')
    st = parse_upgrade_status(payload)
    assert st['status_code'] == 'UPGRATE_ERR_APP_VERSION' and st['is_anti_rollback']
    ok, text = judge_upgrade_status(st)
    assert not ok and text == 'Upgrade failed, The firmware version number is too low'
    done = parse_upgrade_status(struct.pack('<ii', 100, 3) + b'\0' * 64)
    assert judge_upgrade_status(done)[0] and done['percent'] == 100

    # Chunk size negotiation.
    assert resolve_chunk_size(OBSERVED_DEVICE_RECEIVE_MAX_SIZE)['chunk_size'] == DEFAULT_CHUNK_SIZE
    assert resolve_chunk_size(OBSERVED_DEVICE_RECEIVE_MAX_SIZE)['source'] == 'device_receive_max_size'
    assert resolve_chunk_size(None)['chunk_size'] == DEFAULT_CHUNK_SIZE
    assert resolve_chunk_size(0)['honoured'] is False
    assert resolve_chunk_size(1 << 30)['honoured'] is False

    # ACK shapes match the observed vendor frame lengths: 104 = 36 + 68 for 3/114/115,
    # 116 = 36 + 80 for 117.
    assert parse_ack68(b'\0' * 68)['status'] == 0
    assert parse_ack68(b'\0' * 67) is None
    fd = parse_file_data80(struct.pack('<iiii', 1024, 1024, 2048, 0) + b'OK'.ljust(64, b'\0'))
    assert fd['detail'] == 'OK' and fd['totalsize'] == 2048

    return {'ok': True, 'operation_id': OPERATION_ID,
            'commands': sorted(ALLOWED_COMMANDS),
            'ar_file_info_size': AR_FILE_INFO.size,
            'remote_dir': REMOTE_UPGRADE_DIR,
            'reboot_mode': 'clean',
            'timing': timing_document(),
            'divergence_count': len(VENDOR_DIVERGENCES)}


if __name__ == '__main__':
    import json
    print(json.dumps(selftest(), indent=2))
