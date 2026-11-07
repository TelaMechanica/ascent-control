#!/usr/bin/env python3
"""Repair a Windows driver that failed to install on an Ascent USB interface.

### What this does, and the one thing it refuses to do

Windows sometimes fails to bind a driver to a receiver's USB network interface,
and the application then cannot correlate to the unit at all. Where a compatible
inbox driver exists, this installs it: targeted at the exact device instance,
elevated, and verified afterwards by asking Windows rather than by assuming.

**Where no compatible driver exists, it says so and stops.** That is not a
limitation worked around later -- it is the point. Forcing a driver that does
not claim the device's IDs is how a network interface half-works, and it is
indistinguishable afterwards from a device that was simply broken.

### The case this was built for, measured

An industrial Gnd485 reported:

    Problem 28 (0x1C) CM_PROB_FAILED_INSTALL, status 0xC0000490
    Description "RNDIS", class Unknown

and the description is where the trap is. The STRING says RNDIS; the compatible
IDs say otherwise:

    USB\\Class_02&SubClass_06&Prot_00      <- CDC ECM
    USB\\Class_02&SubClass_06
    USB\\Class_02

Microsoft's `rndiscmp.inf` claims `USB\\Class_EF&SubClass_04&Prot_01` and
`USB\\MS_COMP_RNDIS&MS_SUBCOMP_5162001`. Those sets do not intersect, and no
inbox INF on the machine claims `Class_02&SubClass_06` at all -- Windows ships no
CDC ECM class driver. So for that device the honest verdict is UNSUPPORTED
DRIVER, and the fix is device-side: the unit must present RNDIS rather than ECM.

Which is also why the driver is never chosen by name here. The INF is found by
asking Windows which packages claim the IDs THIS device presents.
"""
from __future__ import annotations

import base64
import json
import os
import platform
import re
import subprocess
import time

SCHEMA = "ascent.driver_repair.v1"

#: Outcomes. Each is a different thing to do next, which is why they are not
#: collapsed into ok/failed.
REPAIRED = "REPAIRED"                    # bound, verified, usable now
REBOOT_REQUIRED = "REBOOT_REQUIRED"      # installed, needs a restart to bind
UNSUPPORTED_DRIVER = "UNSUPPORTED_DRIVER"  # nothing on this machine claims it
NOT_NEEDED = "NOT_NEEDED"                # nothing is in a failed state
DECLINED = "DECLINED"                    # the operator dismissed elevation
FAILED = "FAILED"                        # it was attempted and did not work

#: Only these problem codes are a driver that failed to attach. A disabled device
#: or one the operator unplugged is not something to install a driver over.
REPAIRABLE_PROBLEMS = ("CM_PROB_FAILED_INSTALL", "CM_PROB_DRIVER_FAILED_LOAD",
                       "CM_PROB_DRIVER_NOT_INSTALLED")

_PS = ("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass")


class DriverRepairError(RuntimeError):
    def __init__(self, code: str, message: str, evidence=None):
        super().__init__(message)
        self.code = code
        self.evidence = evidence or {}


def _windows() -> bool:
    return platform.system().lower() == "windows"


def _hide() -> dict:
    """Keep PowerShell's console off the screen. See service_mode._no_window."""
    if platform.system().lower() != "windows":
        return {}
    si = subprocess.STARTUPINFO()
    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    si.wShowWindow = 0
    return {"startupinfo": si, "creationflags": subprocess.CREATE_NO_WINDOW}


def _ps(script: str, timeout: float = 60.0) -> str:
    try:
        r = subprocess.run([*_PS, "-Command", script], capture_output=True,
                           text=True, timeout=timeout, **_hide())
    except (OSError, subprocess.TimeoutExpired) as e:
        raise DriverRepairError("POWERSHELL_UNAVAILABLE",
                                f"{type(e).__name__} running PowerShell") from None
    return r.stdout or ""


def _ps_json(script: str, timeout: float = 60.0):
    raw = _ps(script, timeout).strip()
    if not raw:
        return []
    try:
        doc = json.loads(raw)
    except ValueError:
        return []
    return doc if isinstance(doc, list) else [doc]


def device_ids(instance_id: str) -> dict:
    """The hardware and compatible IDs this device actually presents.

    The DESCRIPTION is deliberately not trusted for anything but display: the
    device that prompted this module calls itself "RNDIS" and presents CDC ECM.
    """
    if not _windows():
        return {"hardware_ids": [], "compatible_ids": []}
    q = ("$i='%s';"
         "$h=(Get-PnpDeviceProperty -InstanceId $i -KeyName DEVPKEY_Device_HardwareIds"
         " -EA SilentlyContinue).Data;"
         "$c=(Get-PnpDeviceProperty -InstanceId $i -KeyName DEVPKEY_Device_CompatibleIds"
         " -EA SilentlyContinue).Data;"
         "[pscustomobject]@{hardware_ids=@($h);compatible_ids=@($c)}|ConvertTo-Json -Depth 3"
         ) % instance_id.replace("'", "''")
    rows = _ps_json(q)
    if not rows:
        return {"hardware_ids": [], "compatible_ids": []}
    d = rows[0]
    return {"hardware_ids": [str(x) for x in (d.get("hardware_ids") or [])],
            "compatible_ids": [str(x) for x in (d.get("compatible_ids") or [])]}


def claiming_drivers(ids: list) -> list:
    """INF packages on this machine that claim any of these IDs.

    Windows decides, not this module. `pnputil /enum-drivers /ids` prints the
    hardware and compatible IDs each package claims, so the match is made
    against what the system actually holds rather than against an INF name
    someone wrote down once.
    """
    if not _windows() or not ids:
        return []
    wanted = {i.strip().upper() for i in ids if i and i.strip()}
    out, current = [], None
    text = _ps("pnputil /enum-drivers /ids 2>&1", timeout=180.0)
    for line in text.splitlines():
        line = line.strip()
        m = re.match(r"^Published Name:\s*(\S+)", line, re.I)
        if m:
            current = {"inf": m.group(1), "original": None, "provider": None,
                       "class": None, "matched": []}
            out.append(current)
            continue
        if current is None:
            continue
        for key, field in (("Original Name", "original"), ("Provider Name", "provider"),
                           ("Class Name", "class")):
            m = re.match(rf"^{key}:\s*(.+)$", line, re.I)
            if m:
                current[field] = m.group(1).strip()
        up = line.upper()
        for w in wanted:
            if w and w in up:
                current["matched"].append(w)
    return [p for p in out if p["matched"]]


def find_repairable(problem_devices: list, instance_id: str | None = None) -> dict | None:
    """The one failed interface this repair would act on, or None.

    Exactly one device, named explicitly or selected unambiguously. A repair that
    guesses which of several devices the operator meant is a repair that modifies
    an unrelated adapter.
    """
    cands = [d for d in (problem_devices or [])
             if str(d.get("Problem") or "") in REPAIRABLE_PROBLEMS]
    if instance_id:
        cands = [d for d in cands
                 if str(d.get("InstanceId") or "").upper() == instance_id.upper()]
    if len(cands) == 1:
        return cands[0]
    return None


def plan(problem_devices: list, instance_id: str | None = None) -> dict:
    """What would be done, and whether it can be. Changes nothing.

    This is the whole decision, made before any elevation prompt, so an operator
    is never asked to approve an administrative action that cannot succeed.
    """
    dev = find_repairable(problem_devices, instance_id)
    if dev is None:
        return {"schema": SCHEMA, "state": NOT_NEEDED, "device": None,
                "message": "No Ascent USB interface is in a repairable driver state."}

    iid = str(dev.get("InstanceId") or "")
    ids = device_ids(iid)
    all_ids = list(ids["hardware_ids"]) + list(ids["compatible_ids"])
    packages = claiming_drivers(all_ids)

    if not packages:
        return {
            "schema": SCHEMA, "state": UNSUPPORTED_DRIVER, "device": dev,
            "ids": ids, "packages": [],
            "message": (
                "No driver on this computer claims the IDs this interface "
                "presents, so there is nothing to install. The device describes "
                f"itself as {dev.get('Name') or 'unknown'}, but the IDs are what "
                "Windows matches on: "
                + (", ".join(ids["compatible_ids"][:3]) or "none reported")
                + ". A driver that does not claim them would not be a repair."),
            "manual": _manual_text()}

    return {"schema": SCHEMA, "state": "READY", "device": dev, "ids": ids,
            "packages": packages,
            "message": (f"{len(packages)} driver package(s) on this computer claim "
                        f"this interface. The repair installs the best match and "
                        f"then asks Windows whether it bound."),
            "manual": _manual_text()}


def _manual_text() -> str:
    return ("Device Manager does the same thing by hand: find the device, Update "
            "driver, Browse my computer, Let me pick from a list, then choose a "
            "driver that lists this device's hardware ID.")


def verify(instance_id: str, problem_lookup) -> dict:
    """Did it actually bind? Asked of Windows, three ways.

    A repair that reports success because a command exited zero is the same
    defect as a revoke that reports success because it did not raise.
    """
    if not _windows():
        return {"bound": False, "reason": "not Windows"}
    q = ("$d=Get-PnpDevice -InstanceId '%s' -EA SilentlyContinue;"
         "if($d){[pscustomobject]@{Status=[string]$d.Status;Problem=[string]$d.Problem;"
         "Class=[string]$d.Class}|ConvertTo-Json}"
         ) % instance_id.replace("'", "''")
    rows = _ps_json(q)
    if not rows:
        return {"bound": False, "reason": "the device is no longer present"}
    d = rows[0]
    no_problem = str(d.get("Problem") or "") in ("", "CM_PROB_NONE")
    is_net = str(d.get("Class") or "").lower() == "net"
    adapter = _adapter_present(instance_id)
    return {"bound": bool(no_problem and is_net and adapter),
            "status": d.get("Status"), "problem": d.get("Problem"),
            "class": d.get("Class"), "adapter_present": adapter,
            "reason": None if (no_problem and is_net and adapter) else
                      ("the device still reports a problem" if not no_problem else
                       "the device did not join the Net class" if not is_net else
                       "no network adapter appeared for it")}


def _adapter_present(instance_id: str) -> bool:
    """A Net class alone is not a working adapter; ask for the adapter itself."""
    q = ("$a=Get-NetAdapter -IncludeHidden -EA SilentlyContinue | "
         "Where-Object { $_.PnPDeviceID -eq '%s' };"
         "if($a){'yes'}else{'no'}") % instance_id.replace("'", "''").upper()
    return _ps(q).strip().lower().startswith("yes")


# --------------------------------------------------------------------------- #
# MICROSOFT OS DESCRIPTOR CACHE
#
# The repair that actually applies to this hardware, and it is not a driver
# install.
#
# Windows caches, per VID+PID+REVISION, whether a device answered the Microsoft
# OS String Descriptor at index 0xEE:
#
#     HKLM\SYSTEM\CurrentControlSet\Control\usbflags\<VID><PID><REV>    osvc
#
# `osvc` is two bytes: byte 0 is the supported flag, byte 1 the vendor code.
# **00 00 means "asked once, got nothing, never ask again."** From then on
# Windows does not synthesise the MS_COMP_RNDIS compatible ID, so rndiscmp.inf
# no longer ranks and the interface fails to install.
#
# Measured here. An industrial Gnd485 bound Remote NDIS legitimately --
#
#     MatchingDeviceId: usb\ms_comp_rndis&ms_subcomp_5162001
#     ConfigFlags: 0              (no CONFIGFLAG_MANUAL_INSTALL)
#
# -- and a 2026-09-08 inspection of that platform recorded MI_00 as Remote NDIS
# with host 192.168.3.103/24 and device 192.168.3.102. So RNDIS works on this
# hardware and was never forced. A second unit of the SAME revision now reports
# CM_PROB_FAILED_INSTALL while presenting identical compatible IDs, and the
# cache reads 00 00.
#
# THE KEY IS SHARED. It is keyed on VID+PID+REV, not on a unit, so a negative
# written while one receiver was slow to answer poisons every receiver of that
# revision. That is why this is scoped to the revision of the device actually
# connected and never to a product family.
# --------------------------------------------------------------------------- #

USBFLAGS_PATH = r"HKLM:\SYSTEM\CurrentControlSet\Control\usbflags"

#: Cached NEGATIVE: byte 0 clear means "this device does not support MS OS
#: descriptors". That is the value worth clearing, and the only one.
OSVC_NEGATIVE = (0, )


def usbflags_key_for(hardware_ids: list) -> str | None:
    """`<VID><PID><REV>` for the device, from its own hardware IDs.

    Taken from the REV-bearing hardware ID rather than assembled from a product
    table, so the repair can only ever touch the revision actually connected.
    """
    for hid in hardware_ids or []:
        # IGNORECASE deliberately: Windows returns these in either case and a
        # lowercase hardware ID previously produced no key at all, which the
        # caller could not distinguish from a device that genuinely has no
        # revision.
        m = re.search(r"VID_([0-9A-Fa-f]{4})&PID_([0-9A-Fa-f]{4})&REV_([0-9A-Fa-f]{4})",
                      str(hid), re.IGNORECASE)
        if m:
            return (m.group(1) + m.group(2) + m.group(3)).upper()
    return None


def read_usbflags(key: str) -> dict:
    """The current cache entry, byte for byte. Read-only."""
    if not _windows() or not key:
        return {"present": False, "key": key, "values": {}}
    q = ("$p='%s\\%s';"
         "if(Test-Path $p){$k=Get-ItemProperty $p;"
         "$o=@{};$k.PSObject.Properties|Where-Object{$_.Name -notlike 'PS*'}|"
         "ForEach-Object{$o[$_.Name]= if($_.Value -is [byte[]]){($_.Value|ForEach-Object{'{0:X2}' -f $_}) -join '-'}else{[string]$_.Value}};"
         "[pscustomobject]@{present=$true;values=$o}|ConvertTo-Json -Depth 3}"
         "else{[pscustomobject]@{present=$false;values=@{}}|ConvertTo-Json}"
         ) % (USBFLAGS_PATH, key)
    rows = _ps_json(q)
    if not rows:
        return {"present": False, "key": key, "values": {}}
    d = rows[0]
    return {"present": bool(d.get("present")), "key": key,
            "values": dict(d.get("values") or {})}


def diagnose_descriptor_cache(hardware_ids: list, compatible_ids: list) -> dict:
    """Is a cached negative the reason RNDIS is not being offered?

    Two conditions, both required, and neither inferred from the other:
      * the device does NOT currently present an MS_COMP_RNDIS compatible ID;
      * the cache for its revision records a negative answer.

    If the device already presents MS_COMP_RNDIS, the cache is not the problem
    and clearing it would be a change made for no stated reason.
    """
    key = usbflags_key_for(hardware_ids)
    has_mscomp = any("MS_COMP_RNDIS" in str(c).upper() for c in (compatible_ids or []))
    flags = read_usbflags(key) if key else {"present": False, "key": None, "values": {}}
    osvc = str(flags.get("values", {}).get("osvc") or "")
    negative = bool(osvc) and osvc.split("-")[0] == "00"

    if has_mscomp:
        return {"applies": False, "key": key, "osvc": osvc or None,
                "reason": ("This interface already presents an MS_COMP_RNDIS "
                           "compatible ID, so the descriptor cache is not what is "
                           "stopping it.")}
    if not key:
        return {"applies": False, "key": None, "osvc": None,
                "reason": "This device reports no revision, so no cache entry can be identified."}
    if not flags["present"]:
        return {"applies": False, "key": key, "osvc": None,
                "reason": ("Windows holds no descriptor cache for this revision, so "
                           "there is nothing stale to clear.")}
    if not negative:
        return {"applies": False, "key": key, "osvc": osvc,
                "reason": (f"The cache for this revision reads {osvc}, which is not a "
                           f"cached negative. Clearing it would change nothing.")}
    return {"applies": True, "key": key, "osvc": osvc,
            "reason": ("Windows has cached that this revision does not answer the "
                       "Microsoft OS descriptor, so it no longer asks -- and without "
                       "that answer the MS_COMP_RNDIS compatible ID is never "
                       "produced and the RNDIS driver cannot rank. Clearing the one "
                       "cached value makes Windows ask again.")}


#: Descriptor-cache outcomes. Distinct from the driver-install outcomes above
#: because the next step differs in every case.
CACHE_CLEARED = "CACHE_CLEARED"              # cleared, descriptor returned, adapter up
CACHE_NOT_APPLICABLE = "NOT_APPLICABLE"      # no cached negative; nothing to do
DESCRIPTOR_STILL_ABSENT = "DESCRIPTOR_STILL_ABSENT"  # cleared, device still silent
REPLUG_REQUIRED = "REPLUG_REQUIRED"          # cleared, re-enumeration needs the operator
ROLLED_BACK = "ROLLED_BACK"                  # restored from the backup


def backup_dir() -> str:
    """Where backups live. Beside the rest of this application's own state."""
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    d = os.path.join(base, "Ascent Control", "driver_repair")
    os.makedirs(d, exist_ok=True)
    return d


def backup_usbflags(key: str, dest: str | None = None) -> dict:
    """Export the whole usbflags subkey to a .reg file BEFORE touching it.

    `reg export` rather than a hand-written file: the restore is then `reg
    import`, a supported round trip, instead of our reconstruction of what we
    believe we saw. The recorded values are kept alongside it so the report can
    name the exact bytes that were removed.
    """
    if not key:
        raise DriverRepairError("NO_KEY", "no cache key to back up")
    before = read_usbflags(key)
    if not before["present"]:
        raise DriverRepairError("NO_KEY", f"usbflags\\{key} does not exist")
    dest = dest or backup_dir()
    os.makedirs(dest, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    path = os.path.join(dest, f"usbflags-{key}-{stamp}.reg")
    native = USBFLAGS_PATH.replace("HKLM:", "HKEY_LOCAL_MACHINE") + "\\" + key
    out = _ps("reg.exe export '%s' '%s' /y 2>&1; $LASTEXITCODE"
              % (native, path.replace("'", "''")))
    if not os.path.exists(path):
        raise DriverRepairError("BACKUP_FAILED",
                                "the registry key could not be exported, so nothing "
                                "was changed: " + out.strip()[:200])
    return {"path": path, "key": key, "values": before["values"],
            "exported_at": stamp}


def _elevated(script: str, timeout: float = 120.0) -> dict:
    """Run one PowerShell script elevated, and find out whether it ran.

    Start-Process -Verb RunAs raises the UAC prompt. A dismissed prompt throws
    rather than exiting non-zero, so the cancel is caught by name and reported as
    DECLINED -- the operator refusing is not a failure and must not read like one.
    """
    enc = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    outer = ("try{$p=Start-Process powershell.exe -Verb RunAs -Wait -PassThru "
             "-WindowStyle Hidden -ArgumentList "
             "'-NoProfile','-ExecutionPolicy','Bypass','-EncodedCommand','%s';"
             "\"rc=$($p.ExitCode)\"}"
             "catch{if($_.Exception.Message -match 'cancell?ed'){'rc=DECLINED'}"
             "else{\"rc=ERR $($_.Exception.Message)\"}}") % enc
    out = _ps(outer, timeout=timeout).strip()
    tail = out.splitlines()[-1].strip() if out else ""
    if tail == "rc=DECLINED":
        return {"ran": False, "declined": True, "detail": "elevation was dismissed"}
    m = re.search(r"rc=(-?\d+)", tail)
    if m:
        return {"ran": m.group(1) == "0", "declined": False,
                "exit_code": int(m.group(1)), "detail": out}
    return {"ran": False, "declined": False, "detail": out or "no result"}


def clear_osvc(key: str, confirmed: bool = False, dest: str | None = None) -> dict:
    """Remove the single cached `osvc` value. Nothing else, ever.

    `Remove-ItemProperty -Name osvc` deletes one value and leaves the subkey and
    any sibling values (`SkipBOSDescriptorQuery`, `IgnoreHWSerNum`, ...) exactly
    as they were. Deleting the key wholesale would be easier and would discard
    settings this repair has no opinion about.

    The backup happens first and a failure to back up aborts before any change.
    """
    if not confirmed:
        raise DriverRepairError("NOT_CONFIRMED",
                                "the operator has not confirmed this change")
    if not _windows():
        raise DriverRepairError("NOT_WINDOWS", "this repair only applies on Windows")
    backup = backup_usbflags(key, dest)
    if "osvc" not in {k.lower(): k for k in backup["values"]}:
        return {"changed": False, "backup": backup,
                "reason": "the cached value is already absent"}

    script = ("$ErrorActionPreference='Stop';"
              "$p='%s\\%s';"
              "if(-not (Test-Path $p)){exit 2};"
              "$v=Get-ItemProperty $p;"
              "if($null -eq $v.osvc){exit 3};"
              "Remove-ItemProperty -Path $p -Name osvc -Force;"
              "$after=Get-ItemProperty $p;"
              "if($null -ne $after.osvc){exit 4};"
              "exit 0") % (USBFLAGS_PATH, key)
    res = _elevated(script)
    if res.get("declined"):
        return {"changed": False, "declined": True, "backup": backup,
                "reason": "the elevation prompt was dismissed, so nothing was changed"}
    after = read_usbflags(key)
    gone = "osvc" not in {k.lower() for k in after["values"]}
    if not gone:
        return {"changed": False, "backup": backup,
                "reason": "the value is still present after the attempt: "
                          + str(res.get("detail", ""))[:200]}
    return {"changed": True, "backup": backup, "key": key,
            "removed": backup["values"].get("osvc"),
            "remaining": after["values"]}


def rollback_usbflags(backup: dict) -> dict:
    """Put back exactly what was exported, by importing the saved file."""
    path = (backup or {}).get("path")
    if not path or not os.path.exists(path):
        return {"restored": False,
                "reason": "the backup file is missing",
                "manual": _cache_manual_text(backup)}
    res = _elevated("$ErrorActionPreference='Stop';"
                    "reg.exe import '%s';exit $LASTEXITCODE"
                    % path.replace("'", "''"))
    if res.get("declined"):
        return {"restored": False, "declined": True,
                "reason": "the elevation prompt was dismissed",
                "manual": _cache_manual_text(backup)}
    return {"restored": bool(res.get("ran")), "path": path,
            "reason": None if res.get("ran") else str(res.get("detail", ""))[:200],
            "manual": None if res.get("ran") else _cache_manual_text(backup)}


def _cache_manual_text(backup: dict | None) -> str:
    key = (backup or {}).get("key") or "<VID><PID><REV>"
    path = (backup or {}).get("path")
    saved = (backup or {}).get("values", {}).get("osvc")
    lines = [f"Registry Editor, HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\"
             f"Control\\usbflags\\{key}."]
    if path:
        lines.append(f"Double-clicking {path} restores the saved values.")
    if saved:
        lines.append(f"The value removed was a Binary named osvc = {saved}.")
    lines.append("Unplugging and reconnecting the receiver makes Windows read the "
                 "device again either way.")
    return " ".join(lines)


def reenumerate(instance_id: str) -> dict:
    """Make Windows read the device's descriptors again.

    `pnputil /restart-device` is the supported mechanism and is tried first. It
    is not available on every build and does not always force a fresh descriptor
    read, so a failure here is reported as REPLUG_REQUIRED rather than as a
    failed repair -- a physical reconnect always works and costs the operator
    one action.
    """
    if not _windows():
        return {"restarted": False, "reason": "not Windows"}
    res = _elevated("$ErrorActionPreference='Continue';"
                    "pnputil.exe /restart-device '%s';exit $LASTEXITCODE"
                    % instance_id.replace("'", "''"))
    if res.get("declined"):
        return {"restarted": False, "declined": True,
                "reason": "the elevation prompt was dismissed"}
    return {"restarted": bool(res.get("ran")),
            "reason": None if res.get("ran") else
                      "Windows did not restart the device from software"}


def verify_descriptor_cache(instance_id: str) -> dict:
    """Requirement 7, asked of Windows rather than assumed from an exit code.

    Three independent questions, reported separately so a partial result is
    legible:
      * does the interface now present MS_COMP_RNDIS at all;
      * does a driver that claims it actually rank for it;
      * is there a network adapter.

    The first is the one that says whether clearing the cache worked. The other
    two say whether that was sufficient.
    """
    ids = device_ids(instance_id)
    compat = [str(c).upper() for c in ids.get("compatible_ids", [])]
    descriptor = any("MS_COMP_RNDIS" in c for c in compat)
    claimers = claiming_drivers(ids.get("hardware_ids", []) +
                               ids.get("compatible_ids", [])) if descriptor else []
    rndis = [d for d in claimers
             if "rndis" in str(d.get("inf", "")).lower()
             or "rndis" in str(d.get("matching_id", "")).lower()]
    adapter = _adapter_present(instance_id)
    return {"descriptor_present": descriptor,
            "compatible_ids": ids.get("compatible_ids", []),
            "rndis_driver_applicable": bool(rndis),
            "rndis_drivers": rndis,
            "adapter_present": adapter,
            # Asked of Windows. This used to read `ids.get("problem")`, a key
            # `device_ids` has never set, so a device sitting in
            # CM_PROB_FAILED_INSTALL reported `"problem": null` -- a null that
            # reads as "no problem" and is exactly the silent placeholder this
            # product does not ship.
            "problem": device_problem(instance_id),
            "repaired": bool(descriptor and adapter)}


def device_problem(instance_id: str) -> str | None:
    """The device's current problem code, or None when it genuinely has none."""
    if not _windows() or not instance_id:
        return None
    q = ("$d=Get-PnpDevice -InstanceId '%s' -EA SilentlyContinue;"
         "if($d){[string]$d.Problem}") % instance_id.replace("'", "''")
    text = _ps(q).strip()
    return None if text in ("", "CM_PROB_NONE") else text


def repair_descriptor_cache(instance_id: str, hardware_ids: list,
                            compatible_ids: list, confirmed: bool = False,
                            dest: str | None = None) -> dict:
    """The whole targeted repair, in order, with the result Windows actually gives.

    Order is the point. Diagnose, back up, change one value, re-enumerate, ask
    Windows what happened, and roll back if the change did not produce the
    descriptor -- so a machine that does not respond to this is left exactly as
    it was found rather than carrying an unexplained registry edit.
    """
    started = time.strftime("%Y-%m-%dT%H:%M:%S")
    diag = diagnose_descriptor_cache(hardware_ids, compatible_ids)
    if not diag["applies"]:
        return {"schema": SCHEMA, "operation": "descriptor_cache",
                "outcome": CACHE_NOT_APPLICABLE, "started": started,
                "diagnosis": diag, "changed": False}

    if not confirmed:
        return {"schema": SCHEMA, "operation": "descriptor_cache",
                "outcome": DECLINED, "started": started, "diagnosis": diag,
                "changed": False,
                "reason": "this change has not been confirmed by the operator"}

    cleared = clear_osvc(diag["key"], confirmed=True, dest=dest)
    if not cleared.get("changed"):
        return {"schema": SCHEMA, "operation": "descriptor_cache",
                "outcome": DECLINED if cleared.get("declined") else FAILED,
                "started": started, "diagnosis": diag, "changed": False,
                "backup": cleared.get("backup"),
                "reason": cleared.get("reason"),
                "manual": _cache_manual_text(cleared.get("backup"))}

    backup = cleared["backup"]
    restarted = reenumerate(instance_id)
    check = verify_descriptor_cache(instance_id)

    if check["descriptor_present"]:
        outcome = CACHE_CLEARED if check["adapter_present"] else REBOOT_REQUIRED
        return {"schema": SCHEMA, "operation": "descriptor_cache",
                "outcome": outcome, "started": started, "diagnosis": diag,
                "changed": True, "removed": cleared.get("removed"),
                "backup": backup, "reenumerate": restarted, "verification": check,
                "reason": None if outcome == CACHE_CLEARED else
                          ("Windows is reading the descriptor again, but no network "
                           "adapter has appeared yet. Reconnect the receiver, or "
                           "restart, and check again.")}

    if not restarted.get("restarted"):
        # Nothing has been proven either way: the device was never re-read. The
        # change stays in place because a replug is what completes it.
        return {"schema": SCHEMA, "operation": "descriptor_cache",
                "outcome": REPLUG_REQUIRED, "started": started, "diagnosis": diag,
                "changed": True, "removed": cleared.get("removed"),
                "backup": backup, "reenumerate": restarted, "verification": check,
                "reason": ("The cached value was cleared, but Windows could not "
                           "re-read the device from software. Unplug the receiver, "
                           "reconnect it, and check again."),
                "manual": _cache_manual_text(backup)}

    rolled = rollback_usbflags(backup)
    return {"schema": SCHEMA, "operation": "descriptor_cache",
            "outcome": ROLLED_BACK if rolled.get("restored") else DESCRIPTOR_STILL_ABSENT,
            "started": started, "diagnosis": diag, "changed": not rolled.get("restored"),
            "backup": backup, "reenumerate": restarted, "verification": check,
            "rollback": rolled,
            "reason": ("The cached value was cleared and the device was re-read, "
                       "and it still did not report Microsoft OS descriptor "
                       "support. The cache was not what was stopping it, so the "
                       "original value has been restored."
                       if rolled.get("restored") else
                       "The cached value was cleared, the device still did not "
                       "report Microsoft OS descriptor support, and the original "
                       "value could not be restored automatically."),
            "manual": None if rolled.get("restored") else _cache_manual_text(backup)}


def selftest() -> dict:
    ids = ["USB\\Class_02&SubClass_06&Prot_00"]
    assert claiming_drivers([]) == []
    assert find_repairable([], None) is None
    assert find_repairable([{"Problem": "CM_PROB_DISABLED"}]) is None
    one = [{"Problem": "CM_PROB_FAILED_INSTALL", "InstanceId": "USB\\X"}]
    assert find_repairable(one)["InstanceId"] == "USB\\X"
    two = one + [{"Problem": "CM_PROB_FAILED_INSTALL", "InstanceId": "USB\\Y"}]
    assert find_repairable(two) is None, "ambiguity must not be resolved by guessing"
    assert find_repairable(two, "usb\\y")["InstanceId"] == "USB\\Y"
    return {"ok": True, "ids_probe": ids}


if __name__ == "__main__":
    print(json.dumps(selftest(), indent=2))
