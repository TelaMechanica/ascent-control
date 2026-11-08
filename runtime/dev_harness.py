"""Public AC backend: stock protocol and host-only operation roots."""
from __future__ import annotations

import argparse

import base64

import hashlib

import ipaddress

import json

import os

import re

import secrets

import pathlib

import platform

import socket

import struct

import subprocess

import tempfile

import threading

import time

import webbrowser

from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler

from pathlib import Path

from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parent

import sys

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

WWW = ROOT / "www"

TEMPLATES = ROOT / "vendor_templates"

RNDIS_HELPER = ROOT / "Configure-AscentRNDIS.ps1"

APP_VERSION = '0.43.57'

def _resolve_edition() -> str:
    return 'consumer'

APP_EDITION = _resolve_edition()

SERVICE_MODE_AVAILABLE = False

ACTIVE_CONNECTION = {"candidate_id": None, "candidate": None, "serial_identity": None,
                     "rf_bands": None, "serial_bundle": None, "ground_status": None,
                     "ground_local_bb_id": None, "network_binding": None,
                     "sky_user_cfg": None}

DISCOVERY_LOCK = threading.RLock()

DISCOVERY_IDENTITY = {}  # PNPDeviceID -> {identity/error/probing/last_seen}

DISCOVERY_LAST = {"captured_at": None, "inventory": None,
                  # What the 1 Hz discovery poll last reported, reduced to the two
                  # facts that tell NO DEVICE, SCANNING and DETECTED apart. Recorded
                  # so /api/device-capabilities can name the connection state without
                  # re-running discovery: it must stay a cheap, side-effect-free read.
                  "candidate_summary": None, "candidate_summary_at": None}

DISCOVERY_SUMMARY_MAX_AGE = 5.0

DEVICE_MUTATION_LOCK = threading.Lock()

NETWORK_SESSION_LOCK = threading.Lock()

DEVICE_OPERATION_STATE = {"active": False, "operation_id": None, "started_at": None}

DEVICE_OPERATION_PROGRESS: dict = {}

_DEVICE_PROGRESS_LOCK = threading.RLock()

def _set_write_progress(**fields) -> None:
    with _DEVICE_PROGRESS_LOCK:
        DEVICE_OPERATION_PROGRESS.clear()
        DEVICE_OPERATION_PROGRESS.update(fields)
        DEVICE_OPERATION_PROGRESS["at"] = utc_now()

def _device_operation_progress() -> dict:
    with _DEVICE_PROGRESS_LOCK:
        return dict(DEVICE_OPERATION_PROGRESS)

HOST_STATE = {"shutting_down": False}

import operation_audit as smaudit

import firmware_builder
import wallpaper_image

import caddx_repeater as rep

import windows_driver_repair as drvrepair

from caddx_legacy_serial import query as caddx_legacy_query

import caddx_read_bundle as readbundle

from caddx_read_bundle import run as caddx_read_bundle, VID_PNP_RE, pnp_is_ascent_evidence

from device_session import CachedRead, DeviceSession, InventoryCache, SerialBusyError, SerialGate, extract_com as device_session_extract_com, resolve_transport, _ipv4_rows as device_session_ipv4_rows, _UNUSABLE_ADDRESS_STATES as UNUSABLE_ADDRESS_STATES

from caddx_vendor_write import CaddxWriteError, VendorWriteSession, qualify_rf_write, serialize_rf_table, semantic_equal, compare_readback, stable_identity_matches, DEVICE_OWNED_KEYS, DEVICE_OWNED_EXPECTED, merge_rf_table, diff_rf_table, RECONNECT_SETTLE as VW_RECONNECT_SETTLE, RECONNECT_POLL_BUDGET as VW_RECONNECT_POLL_BUDGET

from caddx_sky_user_cfg import SkyUserCfgError, SkyUserCfgSession, LABEL_PRIMARY as SKY_LABEL_PRIMARY, LABEL_FALLBACK as SKY_LABEL_FALLBACK, OPERATION_ID as SKY_USER_CFG_OPERATION_ID, build_user_cfg_document, compare_readback as sky_compare_readback, format_bb_id as sky_format_bb_id, parse_bb_id as sky_parse_bb_id, qualify_user_cfg_write

import caddx_cgc as cgc

import caddx_crsf as crsf

import caddx_relay_qos as relayqos

import caddx_relay_factory as relayfactory

import caddx_relay_network_control as relaynetwork

import caddx_hid as hidaxes

import caddx_msp

import vendor_rf_telemetry as vendor_rf

import receiver_capabilities as receiver_caps

import caddx_fw_version as fwver

import max_19_2_14 as max19214

import known_receivers as knownrx

import first_run as firstrun

import caddx_msp_osd as mspsd

import caddx_device_config as devcfg

import device_capability

import device_config_store as cfgstore

import device_naming

import local_settings

import rf_band_plans

import rf_plan_api

import vtx_nicknames

from caddx_sky_rndis_provision import SkyRndisProvisionError, SkyRndisSession, DEVICE_ADDR as SKY_RNDIS_DEVICE_ADDR, PORT as SKY_RNDIS_PORT, OPERATION_ID as SKY_RNDIS_OPERATION_ID, TRANSPORT_ID as SKY_RNDIS_TRANSPORT, bb_status_identity as sky_rndis_identity, compare_readback as sky_rndis_compare_readback, qualify_rndis_provisioning

import caddx_firmware_upgrade as fwupg

import caddx_firmware_variant

import experimental

from caddx_firmware_upgrade import (
    FirmwareUpgradeError, FirmwareUpgradeSession,
    OPERATION_ID as FIRMWARE_OPERATION_ID,
    VENDOR_FILE_FILTER, VENDOR_DIVERGENCES as FIRMWARE_DIVERGENCES,
    inspect_image as firmware_inspect_image,
    qualify_firmware_upgrade, run_upgrade as firmware_run_upgrade,
    selftest as caddx_firmware_selftest, timing_document as firmware_timing_document,
    validate_selection as firmware_validate_selection,
)

DEVICE_IMAGE_ASSETS = {
    "ascent_camhub": "Ascent_CamHub.png",
    "ascent_gt": "Ascent_GT.png",
    "ascent_gtpro": "Ascent_GTPro.png",
    "ascent_gt_pro": "Ascent_GTPro.png",
    "ascent_gtproz40": "Ascent_GTProZ40.png",
    "ascent_gt_pro_z40": "Ascent_GTProZ40.png",
    "ascent_gtproz8": "Ascent_GTProZ8.png",
    "ascent_gt_pro_z8": "Ascent_GTProZ8.png",
    "ascent_gt_pro_hub": "Ascent_CamHub.png",
    # Exact alias, by product decision 2026-09-23: the bare GT Max HF identity uses
    # the existing GT Pro render. It previously resolved to no image at all.
    #
    # This is not the guess the rule below forbids. That rule bans deriving artwork
    # from a FAMILY SUBSTRING -- matching "gt_max" and picking something plausible --
    # because the Z8 and Z40 builds are visually different units and the identity
    # cannot tell them apart. This is a single exact key, chosen deliberately, and it
    # cannot capture the Z8 or Z40 identities: those normalize to
    # `ascent_gt_max_hf_z8` and `ascent_gt_max_hf_z40`, which have their own entries
    # immediately below and are unchanged.
    #
    # The DISPLAYED NAME is unaffected -- device_naming renders "Ascent GT Max HF"
    # from its own table, and artwork selection never feeds it.
    "ascent_gt_max_hf": "Ascent_GTPro.png",
    "ascent_gt_max_hf_z40": "Ascent_GT_Max_HF_Z40.png",
    "ascent_gt_max_hf_z8": "Ascent_GT_Max_HF_Z8.png",
    "ascent_gt_max_hub": "Ascent_GT_Max_Hub.png",
    "ascent_gt_max_wf": "Ascent_GT_Max_WF.png",
    "ascent_gt_max_wf_z40": "Ascent_GT_Max_WF_Z40.png",
    "ascent_gt_max_wf_hub": "Ascent_GT_Max_Hub.png",
    "ascent_gt_max_hf_hub": "Ascent_GT_Max_Hub.png",
    "ascent_gt_max_wf_z8": "Ascent_GT_Max_WF_Z8.png",
    "ascent_goggles": "Ascent_Goggles.png",
    "ascent_goggles_l": "Ascent_Goggles.png",
    "ascent_liteplus": "Ascent_LitePlus.png",
    "ascent_lite_vtx": "Ascent_Lite_VTX.png",
    "ascent_rc": "Ascent_RC.png",
    "ascent_relay": "Ascent_Relay.png",
    "ascent_repeater": "ascent_repeater.png",
    "ascent_vrx": "Ascent_VRX.png",
    "ascent_vrxmax": "Ascent_VRXMAX.png",
    "ascent_vrx_max": "Ascent_VRXMAX.png",
    "ascent_vrxpro": "Ascent_VRXPro.png",
    "ascent_vrx_pro": "Ascent_VRXPro.png",
    "ascent_vrx_cine": "Ascent_VRX_Cine.png",
    "ascent_vrx_max_wf": "Ascent_VRX_MAX_WF.png",
}

def _norm_device_name(value: str | None) -> str:
    # One normalizer, shared with the device-class capability model so artwork
    # selection and page visibility can never disagree about what a name is.
    return device_capability.norm_device_name(value)

DEVICE_IMAGE_STAND_INS = {
    "ascent_vrx_max_hf": "ascent_vrx_max_wf",
}

def device_image_for_name(value: str | None) -> str | None:
    key = _norm_device_name(value)
    if not key:
        return None
    if key in DEVICE_IMAGE_ASSETS:
        return "/assets/devices/" + DEVICE_IMAGE_ASSETS[key]
    stand_in = DEVICE_IMAGE_STAND_INS.get(key)
    if stand_in and stand_in in DEVICE_IMAGE_ASSETS:
        return "/assets/devices/" + DEVICE_IMAGE_ASSETS[stand_in]
    # Do not guess product artwork from family substrings. The factory render is
    # selected only after command-60 returns an exact vendor device name, or the
    # owner has explicitly approved a stand-in above.
    return None

def device_image_provenance(value: str | None) -> dict:
    """Whether the render is this model's own, and if not, whose it is.

    Returned alongside the image so the UI can say so. A borrowed render that
    does not announce itself is exactly the silent substitution the artwork rule
    forbids, and the rule is kept by declaring the borrow, not by hiding it.
    """
    key = _norm_device_name(value)
    if not key:
        return {"image": None, "exact": None, "depicts": None}
    if key in DEVICE_IMAGE_ASSETS:
        return {"image": "/assets/devices/" + DEVICE_IMAGE_ASSETS[key],
                "exact": True, "depicts": None}
    stand_in = DEVICE_IMAGE_STAND_INS.get(key)
    if stand_in and stand_in in DEVICE_IMAGE_ASSETS:
        return {"image": "/assets/devices/" + DEVICE_IMAGE_ASSETS[stand_in],
                "exact": False, "depicts": _display_for_key(stand_in),
                "note": ("No factory render exists for this model, so a sibling's "
                         "render is shown. It is not a picture of this unit.")}
    return {"image": None, "exact": None, "depicts": None}

def _display_for_key(key: str) -> str:
    """A human label for a normalized artwork key, for the stand-in note."""
    return key.replace("_", " ").title().replace("Vrx", "VRX").replace("Hf", "HF").replace("Wf", "WF")

def sanitize_error(value: object) -> str:
    import re
    s = str(value or "")
    # User-visible diagnostics must never leak local usernames, tenant/share names,
    # project directories, or container paths. Preserve the error text after a
    # conventional ``: message`` separator while replacing the path itself.
    s = re.sub(r"(?i)\b[A-Z]:\\[^:\r\n]+", "<local-path>", s)
    s = re.sub(r"\\\\[^:\r\n]+", "<network-path>", s)
    s = re.sub(r"/(?:home|Users|mnt/data)/[^:\r\n]+", "<local-path>", s)
    return s[:360]

HOST_CFG = {
    "ground": "192.168.3.102",
    "rpc_port": 50000,
    "mgmt_port": 50100,
    "ctrl_udp_port": 9001,
    "crsf_udp_port": 9100,
    "osd_udp_port": 9200,
    "host_rndis_ip": "192.168.3.103",
    "host_rndis_prefix": 24,
}

INVENTORY_TTL = 1.5

TRANSPORT_MAX_AGE = 2.0

RF_SUCCESS_TTL = 45.0

RF_FAILURE_BACKOFF = 3.0

SERIAL_GATE_TIMEOUT = 20.0

HOST_IP_WAIT_SECONDS = 8.0

INVENTORY_CACHE = InventoryCache(lambda: windows_usb_inventory(), ttl=INVENTORY_TTL)

SERIAL_GATE = SerialGate()

SESSION = DeviceSession(mirror=ACTIVE_CONNECTION, inventory=INVENTORY_CACHE, policy=HOST_CFG, transport_max_age=TRANSPORT_MAX_AGE)

MAX_HTTP_BODY = 256 * 1024

LOCAL_DATA_ROOT = local_settings.save_root()

RF_BACKUPS_DIR = LOCAL_DATA_ROOT / "Backups" / "RF"

USER_CFG_BACKUPS_DIR = LOCAL_DATA_ROOT / "Backups" / "ReceiverSlots"

FIRMWARE_BACKUPS_DIR = LOCAL_DATA_ROOT / "Backups" / "Firmware"

def _apply_local_save_root(root: Path) -> None:
    """Point every local-save directory at ``root``.

    Directories are not created here: a save creates its own parent when it runs, so a
    settings change never leaves empty folders behind for a path the operator may
    correct a moment later.
    """
    global LOCAL_DATA_ROOT, RF_BACKUPS_DIR, USER_CFG_BACKUPS_DIR
    global FIRMWARE_BACKUPS_DIR
    LOCAL_DATA_ROOT = Path(root)
    RF_BACKUPS_DIR = LOCAL_DATA_ROOT / "Backups" / "RF"
    USER_CFG_BACKUPS_DIR = LOCAL_DATA_ROOT / "Backups" / "ReceiverSlots"
    FIRMWARE_BACKUPS_DIR = LOCAL_DATA_ROOT / "Backups" / "Firmware"

def local_save_directory_document() -> dict:
    """The save-directory setting, plus the directories actually in force.

    These are two different facts and are reported as two different fields. The
    persisted setting is re-read on every call, while the derived directories are set
    at import and on an accepted change -- so an edit to the settings file by another
    process would leave them disagreeing. ``in_effect`` says whether they agree, rather
    than showing a path saves are not going to.
    """
    doc = local_settings.save_directory_document()
    doc["derived_root"] = str(LOCAL_DATA_ROOT)
    doc["in_effect"] = str(LOCAL_DATA_ROOT) == doc["path"]
    doc["derived"] = {"rf_backups": str(RF_BACKUPS_DIR),
                      "receiver_slot_backups": str(USER_CFG_BACKUPS_DIR),
                      "firmware_backups": str(FIRMWARE_BACKUPS_DIR)}
    return doc

def set_local_save_directory(body: dict) -> dict:
    """Validate, persist, then re-point the derived directories.

    A rejected path changes nothing: ``set_save_directory`` raises before it writes,
    and ``_apply_local_save_root`` is only reached on success.
    """
    if body.get("reset") is True:
        result = local_settings.reset_save_directory()
    else:
        result = local_settings.set_save_directory(body.get("directory"))
    _apply_local_save_root(local_settings.save_root())
    return {**result, "state": local_save_directory_document()}

def discovery_summary() -> dict:
    """The last discovery report, or an explicit "not known".

    A cheap read of what ``connection_inventory`` already recorded. It never refreshes
    the inventory and never schedules an identity probe, because
    ``/api/device-capabilities`` is fetched on the connection path and must not spawn a
    PowerShell pair or contend for a COM port to answer.

    ``reported`` is false when the poll has never run or its result has aged out. That
    is deliberately not the same as "no candidates": not knowing resolves to SCANNING.
    """
    with DISCOVERY_LOCK:
        summary = DISCOVERY_LAST.get("candidate_summary")
        at = DISCOVERY_LAST.get("candidate_summary_at")
    age = None if at is None else max(0.0, time.monotonic() - at)
    reported = bool(summary) and age is not None and age <= DISCOVERY_SUMMARY_MAX_AGE
    return {"reported": reported,
            "candidates": int((summary or {}).get("candidates") or 0),
            "identified": int((summary or {}).get("identified") or 0),
            "age_s": None if age is None else round(age, 3),
            "max_age_s": DISCOVERY_SUMMARY_MAX_AGE}

def device_capabilities() -> dict:
    """Which pages apply, for the connection state the host is actually in.

    Two inputs, and the state is decided before the class. The raw command-60 name comes
    from the **active session only** -- a detected-but-unconnected candidate's name is
    still deliberately not used to select a device class. What that candidate does
    supply is the discovery half of the state: whether anything is present at all, and
    whether discovery has proven an identity for it.

    That split is the fix for the hardware finding of 2026-09-08: every not-connected
    case used to arrive at ``page_visibility`` as the single fact "no raw name", which
    failed open, so the sidebar showed all six primary pages while the connection bar
    read SCANNING…. NO DEVICE, SCANNING and DETECTED are now distinct states and all
    three show the host-local pages only.
    """
    dev = SESSION.device
    raw = (dev.identity or {}).get("device_name") if dev else None
    disc = discovery_summary()
    state = device_capability.derive_connection_state(
        connected=bool(dev), raw_device_name=raw,
        discovery_reported=disc["reported"],
        candidate_count=disc["candidates"],
        identified_candidate=disc["identified"] > 0)
    doc = device_capability.page_visibility(raw, state)
    doc["connected"] = bool(dev)
    doc["discovery"] = disc
    # Display-only rendering of the same raw name, carried beside it and never in
    # place of it.  Handoff 2026-09-16 §3 wants a human-readable name; CLAUDE.md
    # "Device identity" requires the raw command-60 string to stay authoritative.
    # Both hold: `product.raw` is the key, `product.display` is the label, and
    # page visibility above is still derived from `raw` alone.
    doc["product"] = device_naming.humanize(raw)
    target = getattr(dev, "network_target", None)
    if target is not None:
        allowed = set(device_capability.NO_DEVICE_VISIBLE)
        if target.get("kind") == "repeater":
            allowed.add("repeater")
        for page, entry in doc["pages"].items():
            entry["visible"] = page in allowed
            entry["reason"] = ("Host-local page or explicit Ethernet provider."
                               if page in allowed else "This operation is not available over the selected Ethernet connection.")
        doc.update(source="selected_network_target", name_consulted=False,
                   identity_proven=False, transport="ethernet",
                   visible=[p for p in doc["pages"] if doc["pages"][p]["visible"]],
                   hidden=[p for p in doc["pages"] if not doc["pages"][p]["visible"]])
    return doc

def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

def checksum17(b: bytes) -> int:
    x = 0
    for v in b:
        x ^= v
    return (~x) & 0xFF

def bb_frame(cmd: int, payload: bytes = b"", meta1: int = 0, meta2: int = 0) -> bytes:
    h = bytearray(18)
    h[0] = 0xAA
    h[1:5] = len(payload).to_bytes(4, "little")
    h[5:9] = cmd.to_bytes(4, "big")
    h[9:13] = meta1.to_bytes(4, "big")
    h[13:17] = meta2.to_bytes(4, "big")
    h[17] = checksum17(h[:17])
    return bytes(h) + payload + b"\xBB"

def recv_exact(s: socket.socket, n: int) -> bytes:
    out = bytearray()
    while len(out) < n:
        d = s.recv(n - len(out))
        if not d:
            raise EOFError("stream ended early")
        out.extend(d)
    return bytes(out)

def _candidate_network_binding(candidate: dict | None,
                               inventory: dict | None = None) -> tuple[str, int] | None:
    """Source address + ifIndex for one candidate.

    With ``inventory``, the answer is resolved by ContainerId against that (current)
    Windows state -- the row positions and IPv4 leases in ``candidate`` are ignored.
    This is the path every active consumer takes, via ``_active_network_binding()``.

    Without ``inventory`` this parses the candidate row itself. That form is only the
    discovery-list preview for a device nobody has connected to yet, where no ownership
    has been established and there is nothing to re-resolve against.
    """
    if not isinstance(candidate, dict):
        return None
    if inventory is not None:
        cid = candidate.get("serial_container_id") or candidate.get("container_id")
        facts = resolve_transport(inventory, cid, ground_ip=HOST_CFG["ground"],
                                  host_prefix=HOST_CFG["host_rndis_prefix"])
        return facts.get("binding")
    # Qualification is the gate. Missing ifIndex is not a reason to fall through.
    if candidate.get("topology_qualified") is not True:
        return None
    try:
        if_index = int(candidate.get("ifindex"))
    except Exception:
        return None
    if if_index <= 0:
        return None
    ips = candidate.get("ipv4") or []
    if isinstance(ips, dict):
        ips = [ips]
    for row in ips:
        if not isinstance(row, dict):
            continue
        ip = str(row.get("IPAddress") or "")
        try:
            prefix = int(row.get("PrefixLength") or -1)
        except Exception:
            prefix = -1
        if ip.startswith("192.168.3.") and ip != HOST_CFG["ground"] and prefix == HOST_CFG["host_rndis_prefix"]:
            return ip, if_index
    return None

def _active_network_binding() -> tuple[str, int] | None:
    """The selected device's live source address + ifIndex.

    Resolved by ContainerId against current Windows state on every call. Alpha14
    re-parsed the inventory row frozen into ACTIVE_CONNECTION["candidate"] at connect
    time, so a device whose RNDIS address arrived after the 8 s connect window stayed
    unreachable to Ground/RF for the rest of the session while Device Info still
    showed it (BACKEND_INVENTORY.md 3.2).
    """
    return SESSION.network_binding()

def _active_binding_detail() -> dict:
    """Live binding plus the named reason it is absent, for actionable errors."""
    return SESSION.network_binding_detail()

def _no_binding_error(purpose: str) -> RuntimeError:
    detail = _active_binding_detail()
    reason = detail.get("error") or "the selected device has no topology-qualified RNDIS interface"
    return RuntimeError(
        f"No topology-qualified RNDIS source address/interface is selected for {purpose}: {reason}"
    )

IP_UNICAST_IF = 31

def _pin_windows_ipv4_interface(sock: socket.socket, if_index: int) -> None:
    """Pin IPv4 egress to the ContainerId-correlated Windows interface.

    Windows IP_UNICAST_IF expects the interface index in network byte order.
    """
    if platform.system().lower() != "windows":
        return
    if not isinstance(if_index, int) or if_index <= 0:
        raise RuntimeError("A valid correlated RNDIS interface index is required")
    sock.setsockopt(socket.IPPROTO_IP, IP_UNICAST_IF, struct.pack("!I", if_index))

def _require_binding(source_ip: str | None, if_index: int | None,
                     purpose: str) -> tuple[str, int]:
    """The one place a Ground transport resolves its source address and interface.

    An explicit binding is honoured as given; otherwise it is resolved live from the
    selected device by ContainerId. Absence is a named failure, never a fallback to
    the default route or the first RNDIS adapter.
    """
    if source_ip is None or if_index is None:
        binding = _active_network_binding()
        if binding:
            source_ip, if_index = binding
    if not source_ip or not if_index:
        raise _no_binding_error(purpose)
    return source_ip, int(if_index)

def _bb_read(name: str, source_ip: str | None = None, if_index: int | None = None, *, strict=False) -> bytes:
    """Existing bound RPC exchange, closed named GET contracts only."""
    spec = vendor_rf.READS[name]
    host = HOST_CFG["ground"]
    port = HOST_CFG["rpc_port"]
    source_ip, if_index = _require_binding(source_ip, if_index, "Ground RPC")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        _pin_windows_ipv4_interface(s, int(if_index))
        s.bind((source_ip, 0))
        s.settimeout(1.25)
        s.connect((host, port))
        s.sendall(bb_frame(spec.command, spec.request))
        hdr = recv_exact(s, 18)
        if hdr[0] != 0xAA or hdr[17] != checksum17(hdr[:17]):
            raise ValueError("invalid RPC header")
        if strict or name != 'status':
            if (int.from_bytes(hdr[5:9], 'big') != spec.command or
                    int.from_bytes(hdr[9:13], 'big') != 0 or
                    int.from_bytes(hdr[13:17], 'big') != 0):
                raise vendor_rf.TelemetryError('RPC_CORRELATION_FAILED', 'RPC command/work ID/result did not match this named read.')
        n = int.from_bytes(hdr[1:5], "little")
        if (strict or name != 'status') and n != spec.response_size:
            raise vendor_rf.TelemetryError('TELEMETRY_SIZE_MISMATCH', 'RPC payload size differs from the independently verified layout.', {'received_length':n,'expected_length':spec.response_size})
        if n > 1024 * 1024:
            raise ValueError("response too large")
        tail = recv_exact(s, n + 1)
        if tail[-1] != 0xBB:
            raise ValueError("invalid RPC trailer")
        p = tail[:-1]
        if len(p) != spec.response_size:
            raise ValueError(f"{name} length {len(p)} != {spec.response_size}")
    return p

def bb_status(source_ip: str | None = None, if_index: int | None = None, *, _strict=False) -> dict:
    host, port = HOST_CFG['ground'], HOST_CFG['rpc_port']
    source_ip, if_index = _require_binding(source_ip, if_index, 'Ground RPC')
    p = _bb_read('status', source_ip, if_index, strict=_strict)

    def bbid(o: int) -> str:
        return ":".join(f"{x:02X}" for x in p[o:o + 4])

    link_raw = p[252]
    link = {0: "UNLINKED", 1: "SEARCHING", 2: "LINKED"}.get(link_raw, f"0x{link_raw:02X}")
    # STATUS peer bytes and RX-MCS are diagnostics only when a link exists. In
    # particular <synthetic address> is observed in unlinked state and must never become
    # identity/fleet data.
    linked = link_raw == 2
    return {
        "connected": True,
        "host": host,
        "port": port,
        "source_ip": source_ip,
        "ifindex": if_index,
        "local_bb_id": bbid(6),
        "link": link,
        "link_raw": link_raw,
        "rx_mcs": p[253] if linked else None,
        "peer_diagnostic": bbid(254) if linked else None,
        "peer_raw_when_unlinked": bbid(254) if not linked else None,
        "peer_is_authoritative": False,
        "captured_at": utc_now(),
    }

def vendor_rf_metadata() -> dict:
    dev=SESSION.device
    identity=getattr(dev,'identity',{}) if dev else {}
    doc=vendor_rf.describe(identity,connected=dev is not None)
    doc['video']=receiver_caps.video_document(identity)
    return doc

def vendor_rf_read() -> dict:
    """One manual reading, no cache/timer/retry or second receiver session."""
    dev=SESSION.device
    identity=dict(getattr(dev,'identity',{}) or {}) if dev else {}
    doc=vendor_rf.describe(identity,connected=dev is not None)
    if not doc['eligible']:
        return doc
    binding=_active_network_binding()
    if not binding:
        return dict(doc,state='unavailable',error='NO_CORRELATED_NETWORK_BINDING')
    endpoint=(HOST_CFG['ground'],HOST_CFG['rpc_port'])
    target=dict(endpoint=endpoint,candidate_id=getattr(dev,'candidate_id',None),container_id=getattr(dev,'container_id',None),
                connected_at=getattr(dev,'connected_at',None),identity=identity,source_ip=binding[0],ifindex=binding[1])
    doc.update(target=target,captured_at=utc_now(),reads={})
    def check():
        if (SESSION.device is not dev or dict(getattr(dev,'identity',{}) or {})!=identity or _active_network_binding()!=binding
                or (HOST_CFG['ground'],HOST_CFG['rpc_port'])!=endpoint):
            raise vendor_rf.TelemetryError('RF_DIAGNOSTIC_TARGET_CHANGED','Selected receiver/interface changed; discard this reading.')
    def read(name):
        check()
        started=time.monotonic()
        payload=bb_status(*binding,_strict=True) if name=='status' else _bb_read(name,*binding)
        check()
        doc['reads'][name]=dict(state='valid_decode',received_at=utc_now(),
            elapsed_ms=round((time.monotonic()-started)*1000),measurement_age_ms=None)
        return payload
    try:
        doc['status']=read('status')
        for name,parser in [('debug_rf',vendor_rf.parse_debug_rf),('work_channels',vendor_rf.parse_work_channels)]:
            try:
                doc[name]=parser(read(name))
            except Exception as exc:
                if getattr(exc,'code',None)=='RF_DIAGNOSTIC_TARGET_CHANGED':raise
                doc['reads'][name]={**doc['reads'].get(name,{}),'state':'unavailable','code':getattr(exc,'code',type(exc).__name__),'message':sanitize_error(str(exc)),'evidence':getattr(exc,'evidence',{})}
        check()
        doc.update(state='valid_decode' if all(r['state']=='valid_decode' for r in doc['reads'].values()) else 'partial_decode',peer_usable=doc['status'].get('link_raw')==2,
            measurement_age_ms=None,baseband_measurement_interval_ms=None)
        return doc
    except Exception as exc:
        return dict(doc,state='unavailable',error=getattr(exc,'code',type(exc).__name__),message=sanitize_error(str(exc)))

MP_CMD_UDP_PORT = 4208                            # 0x1070

MP_CMD_GET_BATTERY = bytes([0x0B, 0x01, 0x0D])    # family 0x0B, non-zero, sub-cmd 0x0D

_BATTERY_MV_MIN, _BATTERY_MV_MAX = 3000, 60000

def parse_battery_reply(reply: bytes) -> dict:
    """Decode the 5-byte MP battery reply. Pure and total.

    Any short, wrong-status or out-of-range reply reads as unavailable rather than
    raising, so a garbled datagram can never take down the header that polls this.
    """
    if not reply or len(reply) < 5 or reply[0] != 0x01:
        return {"ok": False, "error": "BATTERY_REPLY_INVALID",
                "message": "the device did not return a battery reading"}
    mv = int.from_bytes(reply[1:5], "little")
    if not (_BATTERY_MV_MIN <= mv <= _BATTERY_MV_MAX):
        return {"ok": False, "error": "BATTERY_OUT_OF_RANGE",
                "message": f"battery reading {mv} mV is outside the plausible range"}
    return {"ok": True, "battery_mv": mv, "battery_v": round(mv / 1000.0, 2),
            "source": "mp_udp_4208"}

def vrx_battery(source_ip: str | None = None, if_index: int | None = None) -> dict:
    """Read device battery mV over the MP UDP server. One datagram; never raises.

    Bound to the ContainerId-correlated RNDIS interface, exactly like bb_status --
    destination IP is not identity when several units share 192.168.3.102.
    """
    try:
        source_ip, if_index = _require_binding(source_ip, if_index, "VRX battery")
    except Exception as e:                                        # noqa: BLE001
        return {"ok": False, "error": "NO_BINDING",
                "message": sanitize_error(f"{type(e).__name__}: {e}")}
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            _pin_windows_ipv4_interface(s, int(if_index))
            s.bind((source_ip, 0))
            s.settimeout(1.5)
            s.sendto(MP_CMD_GET_BATTERY, (HOST_CFG["ground"], MP_CMD_UDP_PORT))
            reply, _ = s.recvfrom(64)
    except Exception as e:                                        # noqa: BLE001
        return {"ok": False, "error": "BATTERY_UNREACHABLE",
                "message": sanitize_error(f"{type(e).__name__}: {e}")}
    doc = parse_battery_reply(reply)
    doc["captured_at"] = utc_now()
    return doc

def gc_checksum(payload: bytes) -> int:
    return sum(payload) & 0xFFFF

def gc_frame(direction: int, payload: bytes) -> bytes:
    return (
        b"\xFE\xEF"
        + bytes([direction & 0xFF])
        + len(payload).to_bytes(2, "big")
        + payload
        + gc_checksum(payload).to_bytes(2, "big")
        + b"\x0D\x0A"
    )

def gc_parse_frame(data: bytes) -> dict:
    if len(data) < 9:
        raise ValueError(f"VRX UDP frame too short ({len(data)} bytes)")
    if data[:2] != b"\xFE\xEF" or data[-2:] != b"\x0D\x0A":
        raise ValueError("VRX UDP header/tail mismatch")
    direction = data[2]
    n = int.from_bytes(data[3:5], "big")
    if len(data) != 9 + n:
        raise ValueError(f"VRX UDP length mismatch: header={n}, datagram={len(data)}")
    payload = data[5:5 + n]
    expected = int.from_bytes(data[5 + n:7 + n], "big")
    actual = gc_checksum(payload)
    if expected != actual:
        raise ValueError(f"VRX UDP checksum mismatch: got 0x{expected:04X}, expected 0x{actual:04X}")
    return {
        "direction": direction,
        "payload_length": n,
        "command": payload[0] if payload else None,
        "payload_hex": payload.hex(" ").upper(),
        "frame_hex": data.hex(" ").upper(),
    }

def gc_query(command: int, timeout: float = 0.75, source_ip: str | None = None, if_index: int | None = None) -> dict:
    host = HOST_CFG["ground"]
    port = HOST_CFG["ctrl_udp_port"]
    source_ip, if_index = _require_binding(source_ip, if_index, "Ground UDP")
    tx = gc_frame(0xA2, bytes([command]))
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        _pin_windows_ipv4_interface(s, int(if_index))
        s.bind((source_ip, 0))
        s.settimeout(timeout)
        # Connected UDP rejects datagrams from any source other than the selected device.
        s.connect((host, port))
        s.send(tx)
        data = s.recv(64 * 1024)
        peer = (host, port)
    parsed = gc_parse_frame(data)
    parsed.update({
        "host": host,
        "port": port,
        "source_ip": source_ip,
        "ifindex": if_index,
        "peer": f"{peer[0]}:{peer[1]}",
        "tx_hex": tx.hex(" ").upper(),
        "captured_at": utc_now(),
        "decode_status": "RAW_VALIDATED_ONLY",
    })
    return parsed

CGC_OPERATION_ID = "cgc_live_control"

CGC_REPLY_TIMEOUT = 0.75

def _cgc_exchange(frame: bytes, *, expect_reply: bool, timeout: float = CGC_REPLY_TIMEOUT,
                  source_ip: str | None = None, if_index: int | None = None) -> dict:
    """Send one FE/EF frame on 9001 from the correlated interface.

    Connected UDP, so a datagram from any source other than the selected device is
    refused by the kernel rather than parsed. Same discipline as gc_query.
    """
    host = HOST_CFG["ground"]
    port = HOST_CFG["ctrl_udp_port"]
    source_ip, if_index = _require_binding(source_ip, if_index, "CGC control")
    out = {"tx_hex": frame.hex(" ").upper(), "host": host, "port": port,
           "source_ip": source_ip, "ifindex": if_index, "sent_at": utc_now()}
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sk:
        _pin_windows_ipv4_interface(sk, int(if_index))
        sk.bind((source_ip, 0))
        sk.settimeout(timeout)
        sk.connect((host, port))
        sk.send(frame)
        if not expect_reply:
            out["reply"] = None
            return out
        data = sk.recv(64 * 1024)
    out["rx_hex"] = data.hex(" ").upper()
    try:
        parsed = cgc.parse_frame(data)
    except cgc.CgcError as e:
        out["reply"] = {"ok": False, "error": e.code, "message": str(e)}
        return out
    decoded = cgc.decode(parsed)
    out["reply"] = {"ok": True, "direction": parsed["direction"],
                    "wireless_cmd": parsed["wireless_cmd"],
                    "payload_hex": parsed["payload_hex"], "decoded": decoded,
                    # These decoders have never executed anywhere -- CGC ships them
                    # and calls none of them. An offset one byte out returns a
                    # number, and a number looks like an answer, so every decoded
                    # field is range-checked and the verdict travels with it.
                    "plausibility": cgc.plausibility(parsed["wireless_cmd"], decoded),
                    "beyond_stock": decoded is not None}
    return out

def cgc_eligibility() -> dict:
    """Live control needs a correlated network binding, not a serial session."""
    reasons = []
    binding = _active_network_binding()
    if not binding:
        reasons.append("NO_CORRELATED_NETWORK_BINDING")
    if SESSION.device is None:
        reasons.append("NO_ACTIVE_QUALIFIED_DEVICE")
    return {"operation_id": CGC_OPERATION_ID, "eligible": not reasons, "reasons": reasons,
            "binding": ({"source_ip": binding[0], "ifindex": binding[1]} if binding else None),
            "endpoint": {"host": HOST_CFG["ground"], "ctrl_port": HOST_CFG["ctrl_udp_port"]},
            "profiles": cgc.PROFILES,
            "oracle": "CGC v0.3.5 CaddxGroundConfiguration.dll d42ff30c"}

def cgc_live_state() -> dict:
    """Read all three wireless queries and decode them. Read-only."""
    doc = {"ok": True, "captured_at": utc_now(), "eligibility": cgc_eligibility(),
           "queries": {},
           "beyond_stock_note": (
               "CGC v0.3.5 validates these replies and logs the hex without decoding "
               "them; its three response parsers have no caller. The decoded fields "
               "below are ours, transcribed from that dead vendor code.")}
    for name, cmd in (("channel_hop", cgc.Wireless.GET_CHANNEL_HOP),
                      ("status", cgc.Wireless.GET_STATUS),
                      ("power_index", cgc.Wireless.GET_BB_PWR)):
        try:
            doc["queries"][name] = {"ok": True, "command": int(cmd),
                                    **_cgc_exchange(cgc.build_get(cmd), expect_reply=True)}
        except Exception as e:
            doc["queries"][name] = {"ok": False, "command": int(cmd),
                                    "error": sanitize_error(f"{type(e).__name__}: {e}")}
    # A single verdict over the whole read, so the first bench session answers
    # "did the decoders work" without anyone reading three tables.
    verdicts, suspects = [], []
    for name, q in doc["queries"].items():
        pl = (q.get("reply") or {}).get("plausibility") or {}
        if pl.get("applies"):
            verdicts.append(pl["verdict"])
            suspects += [f"{name}.{f}" for f in pl.get("suspect", [])]
    replied = [n for n, q in doc["queries"].items() if (q.get("reply") or {}).get("ok")]
    doc["self_test"] = {
        "queries_sent": len(doc["queries"]),
        "replies": replied,
        "no_reply": [n for n in doc["queries"] if n not in replied],
        "decoded": len(verdicts),
        "suspect_fields": suspects,
        "verdict": ("no_reply" if not replied
                    else "suspect" if suspects
                    else "consistent" if verdicts else "undecoded"),
        "note": ("Consistent means every decoded field is within what it can physically "
                 "be. It does NOT mean the transcribed offsets are proven -- an offset "
                 "one byte out still returns a number. Suspect means at least one field "
                 "cannot be what it claims, and the most likely cause is the decoder, "
                 "not the device."),
        "still_open": cgc.OPEN_OBSERVATIONS,
    }
    doc["power_table"] = [cgc.power_entry(i) for i in range(cgc.POWER_INDEX_MAX + 1)]
    doc["stock_keys"] = list(cgc.REMOTE_KEYS_STOCK)
    doc["non_stock_keys"] = sorted(cgc.REMOTE_KEYS_UNREACHABLE_IN_STOCK)
    doc["passthrough_modes"] = {m.name: int(m) for m in cgc.Passthrough}
    # Both names per index, from the device's own binary and from the PC Tool.
    doc["passthrough_labels"] = cgc.mode_labels()
    doc["hop_labels"] = cgc.hop_labels()
    doc["hop_name_source"] = cgc.HOP_NAME_SOURCE
    doc["hop_assignment_proven"] = cgc.HOP_ASSIGNMENT_PROVEN
    doc["hop_assignment_note"] = cgc.HOP_ASSIGNMENT_NOTE
    # The goggles' own VRX UART menu, recorded for comparison only. Whether
    # this frame drives it is NOT established, so the two are kept apart.
    doc["device_uart_menu"] = list(cgc.DEVICE_UART_MENU)
    doc["device_uart_menu_source"] = cgc.DEVICE_UART_MENU_SOURCE
    doc["device_uart_correspondence_proven"] = cgc.DEVICE_UART_CORRESPONDENCE_PROVEN
    # There is no read. build_set_mode is the only mode call in the protocol,
    # so the current setting cannot be retrieved and must not be implied.
    doc["passthrough_readable"] = False
    doc["channel_max"] = cgc.CHANNEL_MAX
    doc["power_index_max"] = cgc.POWER_INDEX_MAX
    return doc

def _cgc_guard() -> None:
    e = cgc_eligibility()
    if not e["eligible"]:
        raise cgc.CgcError("CGC_NOT_ELIGIBLE",
                           "live control is not available for the selected device", e)

def cgc_send_key(body: dict) -> dict:
    name = str(body.get("key") or "").upper()
    if name not in cgc.REMOTE_KEYS:
        raise cgc.CgcError("CGC_UNKNOWN_KEY", f"{name!r} is not a vendor key",
                           {"stock": list(cgc.REMOTE_KEYS_STOCK)})
    non_stock = name in cgc.REMOTE_KEYS_UNREACHABLE_IN_STOCK
    if non_stock and body.get("acknowledge_non_stock") is not True:
        raise cgc.CgcError(
            "CGC_KEY_NOT_REACHABLE_IN_STOCK",
            f"{name} has no caller in CGC v0.3.5, so the stock tool cannot send it. "
            f"Sending it is beyond parity and must be acknowledged explicitly.",
            {"key": name, "stock_keys": list(cgc.REMOTE_KEYS_STOCK)})
    _cgc_guard()
    # Fire and forget, as the vendor does: SendRemoteCommand awaits no reply.
    res = _cgc_exchange(cgc.build_key(name), expect_reply=False)
    return {"ok": True, "key": name, "beyond_stock": non_stock, "transport": res}

def cgc_set_mode(body: dict) -> dict:
    raw = body.get("mode")
    try:
        mode = (cgc.Passthrough[str(raw).upper()] if isinstance(raw, str)
                else cgc.Passthrough(int(raw)))
    except (KeyError, ValueError):
        raise cgc.CgcError("CGC_MODE_INVALID", f"unknown passthrough mode {raw!r}",
                           {"modes": {m.name: int(m) for m in cgc.Passthrough}}) from None
    if body.get("apply") is not True:
        raise cgc.CgcError("APPLY_REQUIRED", "the request must set apply=true")
    _cgc_guard()
    res = _cgc_exchange(cgc.build_set_mode(mode), expect_reply=False)
    return {"ok": True, "mode": mode.name, "mode_value": int(mode), "transport": res,
            "note": ("Switches the device's serial passthrough. It changes what the UART "
                     "carries; it does not reboot the unit, and the stock tool sends the "
                     "same frame and waits for nothing.")}

def cgc_set_power(body: dict) -> dict:
    index = body.get("index")
    if not isinstance(index, int) or isinstance(index, bool):
        raise cgc.CgcError("CGC_POWER_INDEX_INVALID", "index must be an integer")
    if body.get("apply") is not True:
        raise cgc.CgcError("APPLY_REQUIRED", "the request must set apply=true")
    _cgc_guard()
    res = _cgc_exchange(cgc.build_set_power_index(index), expect_reply=False)
    return {"ok": True, "index": index, "entry": cgc.power_entry(index), "transport": res}

def cgc_set_channel(body: dict) -> dict:
    if body.get("apply") is not True:
        raise cgc.CgcError("APPLY_REQUIRED", "the request must set apply=true")
    band, channel, hop = body.get("band"), body.get("channel"), body.get("hop")
    for label, value in (("band", band), ("channel", channel), ("hop", hop)):
        if not isinstance(value, int) or isinstance(value, bool):
            raise cgc.CgcError("CGC_FIELD_INVALID", f"{label} must be an integer")
    _cgc_guard()
    res = _cgc_exchange(cgc.build_set_channel_hop(band, channel, hop), expect_reply=False)
    return {"ok": True, "band": band, "channel": channel, "hop": hop, "transport": res,
            "note": ("0x50 sets the channel AND the hop state together; the device-side "
                     "name is SET_CHANNEL_HOP. Changing either can drop the video link.")}

OSD_OPERATION_ID = "cgc_osd_channel"

CRSF_OPERATION_ID = "cgc_crsf_send"

class OsdChannel:
    """Background reader for the MSP DisplayPort stream on UDP 9200.

    One thread, one socket, bound to the ContainerId-correlated source address with
    IP_UNICAST_IF pinned -- the same rule as every other Ground transport here.

    The reassembler tail is kept across datagrams on purpose: a live push stream
    splits MSP frames across UDP boundaries, and discarding the remainder would lose
    an OSD update at every split.
    """

    def __init__(self):
        self._lock = threading.RLock()
        self._thread = None
        self._stop = threading.Event()
        # Observed RC channels, if a flight controller ever pushes MSP_RC on this
        # stream. Recorded and reported; never assumed to exist.
        self._rc_channels = None
        self._rc_at = 0.0
        self._rc_frames = 0
        self._screen = mspsd.DisplayPortScreen()
        self._tail = b""
        self._stats = {"datagrams": 0, "frames": 0, "displayport": 0, "draws": 0,
                       "issues": 0, "bytes": 0}
        self._started_at = None
        self._last_rx = None
        self._error = None
        self._binding = None

    @property
    def running(self) -> bool:
        t = self._thread
        return bool(t and t.is_alive())

    def start(self) -> dict:
        with self._lock:
            if self.running:
                return self.state()
            source_ip, if_index = _require_binding(None, None, "OSD channel")
            self._stop.clear()
            self._error = None
            self._tail = b""
            self._screen = mspsd.DisplayPortScreen()
            self._stats = {k: 0 for k in self._stats}
            self._binding = {"source_ip": source_ip, "ifindex": int(if_index)}
            self._started_at = utc_now()
            self._thread = threading.Thread(target=self._run, args=(source_ip, int(if_index)),
                                            name="osd-9200", daemon=True)
            self._thread.start()
        time.sleep(0.15)          # let the kick go out before the first poll reads state
        return self.state()

    def stop(self) -> dict:
        self._stop.set()
        t = self._thread
        if t and t.is_alive():
            t.join(timeout=2.0)
        return self.state()

    def _run(self, source_ip: str, if_index: int) -> None:
        host = HOST_CFG["ground"]
        port = HOST_CFG.get("osd_udp_port", 9200)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sk:
                _pin_windows_ipv4_interface(sk, if_index)
                sk.bind((source_ip, 0))
                sk.settimeout(0.5)
                sk.connect((host, port))
                # MainPresenter.StartOsdChannel:193 -- the whole handshake.
                sk.send(mspsd.KICK)
                while not self._stop.is_set():
                    try:
                        data = sk.recv(65535)
                    except socket.timeout:
                        continue
                    except OSError as e:
                        self._error = sanitize_error(f"{type(e).__name__}: {e}")
                        return
                    self._ingest(data)
        except Exception as e:
            self._error = sanitize_error(f"{type(e).__name__}: {e}")

    def _ingest(self, data: bytes) -> None:
        with self._lock:
            self._stats["datagrams"] += 1
            self._stats["bytes"] += len(data)
            self._last_rx = utc_now()
            frames, self._tail = mspsd.split_frames(self._tail + data)
            self._stats["frames"] += len(frames)
            records = []
            for f in frames:
                # Every frame is decoded here and only DisplayPort is kept, so a
                # controller pushing MSP_RC was already arriving and being thrown
                # away. Recording it costs one branch and settles on the bench
                # whether that source exists at all.
                if f.get('command') == caddx_msp.MSP_RC:
                    vals = caddx_msp.decode_rc(f.get('payload') or b'')
                    if vals:
                        self._rc_channels = vals
                        self._rc_at = time.monotonic()
                        self._rc_frames += 1
                rec = mspsd.parse_displayport(f)
                if rec is None:
                    continue
                self._stats["displayport"] += 1
                if rec.get("issue"):
                    self._stats["issues"] += 1
                records.append(rec)
            if self._screen.apply(records):
                self._stats["draws"] += 1

    def state(self, include_cells: bool = False) -> dict:
        with self._lock:
            snap = self._screen.reading()
            if not include_cells:
                snap.pop("cells", None)
            rc_age_ms = (int((time.monotonic() - self._rc_at) * 1000)
                         if self._rc_at else None)
            return {"ok": True, "operation_id": OSD_OPERATION_ID,
                    # For the record rather than for use: nothing in this project
                    # has yet seen a flight controller push MSP_RC.
                    "observed_rc": list(self._rc_channels) if self._rc_channels else None,
                    "observed_rc_age_ms": rc_age_ms,
                    "observed_rc_frames": self._rc_frames,
                    "running": self.running, "started_at": self._started_at,
                    "last_rx": self._last_rx, "error": self._error,
                    "binding": self._binding, "stats": dict(self._stats),
                    "screen": snap, "tail_bytes": len(self._tail),
                    "endpoint": {"host": HOST_CFG["ground"],
                                 "port": HOST_CFG.get("osd_udp_port", 9200)},
                    "note": ("UDP 9200 is native MSP. The channel is opened with the "
                             "literal bytes $MSP and then only read -- the flight "
                             "controller pushes and nothing is acknowledged. The grid "
                             "shows what the last DRAW_SCREEN committed."),
                    "rendering_note": ("CGC composites this grid over the video through "
                                       "GStreamer. We have no video surface, so it is "
                                       "shown as a character display: more readable in a "
                                       "window, and strictly less than stock over video.")}

OSD_CHANNEL = OsdChannel()

def osd_state(include_cells: bool = False) -> dict:
    doc = OSD_CHANNEL.state(include_cells)
    doc["eligibility"] = cgc_eligibility()
    return doc

def osd_action(body: dict) -> dict:
    action = str(body.get("action") or "").lower()
    if action == "start":
        _cgc_guard()
        return osd_state()
    if action == "stop":
        return OSD_CHANNEL.stop() | {"eligibility": cgc_eligibility()}
    raise cgc.CgcError("OSD_UNKNOWN_ACTION", f"unknown action {action!r}",
                       {"actions": ["start", "stop"]})

def crsf_send(body: dict) -> dict:
    """Send one CRSF RC_CHANNELS frame on 9100. Send-only; nothing acknowledges it."""
    if body.get("apply") is not True:
        raise cgc.CgcError("APPLY_REQUIRED", "the request must set apply=true")
    _cgc_guard()
    channels = body.get("channels")
    axes = body.get("axes")
    if isinstance(channels, list):
        frame = crsf.build_rc_channels(channels)
        basis = "explicit CRSF channel values"
    elif isinstance(axes, list):
        frame = crsf.build_from_axes(axes)
        basis = "HID axes mapped through the vendor curve"
    else:
        frame = crsf.centred_frame()
        basis = "all sixteen channels centred (CRSF 992)"
    host = HOST_CFG["ground"]
    port = HOST_CFG.get("crsf_udp_port", 9100)
    source_ip, if_index = _require_binding(None, None, "CRSF")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sk:
        _pin_windows_ipv4_interface(sk, int(if_index))
        sk.bind((source_ip, 0))
        sk.connect((host, port))
        sk.send(frame)
    return {"ok": True, "operation_id": CRSF_OPERATION_ID, "basis": basis,
            "frame_hex": frame.hex(" ").upper(),
            "decoded_channels": crsf.decode_channels(frame),
            "endpoint": {"host": host, "port": port},
            "source_ip": source_ip, "ifindex": int(if_index),
            "note": ("Send-only: nothing acknowledges a CRSF frame, and one frame is "
                     "not a control link. A real link needs a continuous stream from an "
                     "input source -- see docs/CGC_LIVE_MODE.md.")}

HID_OPERATION_ID = "cgc_hid_crsf_stream"

def _hid_receiver_identity_token():
    # Cache-only preflight correlation, never USB/network probing or physical trust.
    if not ACTIVE_CONNECTION.get('candidate_id') and not ACTIVE_CONNECTION.get('serial_identity'):
        return None
    observed={'candidate_id':ACTIVE_CONNECTION.get('candidate_id'),
              'serial_identity':ACTIVE_CONNECTION.get('serial_identity'),
              'ground':HOST_CFG['ground'],'port':HOST_CFG.get('crsf_udp_port',9100)}
    return hashlib.sha256(json.dumps(observed,sort_keys=True,default=str).encode()).hexdigest()

def _hid_receiver_scope():
    # Existing selected-connection observation only; never probe/enroll a receiver.
    return json.dumps({'candidate_id':ACTIVE_CONNECTION.get('candidate_id'),
                       'serial_identity':ACTIVE_CONNECTION.get('serial_identity'),
                       'binding':_require_binding(None,None,'CRSF stream'),
                       'ground':HOST_CFG['ground'],'port':HOST_CFG.get('crsf_udp_port',9100)},sort_keys=True,default=str)

def _crsf_socket_send(frame: bytes) -> None:
    """One datagram to 9100 from the correlated interface.

    The explicit stream-start scope must still match the selected connection.
    A changed target refuses this stream; it never automatically redirects output.
    A socket per frame retains the existing source-interface binding behavior.
    """
    if CRSF_STREAM._output_scope is not None and CRSF_STREAM._output_scope!=_hid_receiver_scope():
        raise hidaxes.HidError('HID_RECEIVER_CHANGED','Selected receiver changed; explicitly restart output')
    host = HOST_CFG["ground"]
    port = HOST_CFG.get("crsf_udp_port", 9100)
    source_ip, if_index = _require_binding(None, None, "CRSF stream")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sk:
        _pin_windows_ipv4_interface(sk, int(if_index))
        sk.bind((source_ip, 0))
        sk.connect((host, port))
        if CRSF_STREAM._output_scope is not None and CRSF_STREAM._output_scope!=_hid_receiver_scope():
            raise hidaxes.HidError('HID_RECEIVER_CHANGED','Selected receiver changed before send')
        sk.send(frame)

CRSF_STREAM = hidaxes.CrsfStream(_crsf_socket_send)

def rc_source_document():
    doc = CRSF_STREAM.rc_source_status([])
    doc.update(receiver_token=_hid_receiver_identity_token())
    return doc

def hid_source(body):
    CRSF_STREAM.source_event(body)
    return hid_state()

def hid_state() -> dict:
    with CRSF_STREAM._source_lock:
        doc = {"ok": True, "operation_id": HID_OPERATION_ID,
               "stream": CRSF_STREAM.state(),
               "rc_source": rc_source_document(),
               "eligibility": cgc_eligibility(),
               "normalized_range": [hidaxes.NORMALIZED_MIN, hidaxes.NORMALIZED_MAX],
               "rate_bounds_hz": [hidaxes.MIN_RATE_HZ, hidaxes.MAX_RATE_HZ],
               "axis_usages": {f"0x{u:02X}": n for u, n in hidaxes.AXIS_NAMES.items()},
               "note": ("Axes arrive from the desktop host already normalized to 0..2048, "
                        "which is the contract CGC's own DescriptorDrivenParser uses: it "
                        "reports every axis as 0..2048 regardless of what the device "
                        "declares.")}
        return doc

def hid_axes(body: dict) -> dict:
    """Latest stick positions from the host reader. Host-local; no device command."""
    axes = body.get("axes")
    if not isinstance(axes, list):
        raise hidaxes.HidError("HID_AXES_REQUIRED", "axes must be a list of integers")
    if body.get('epoch') is not None or CRSF_STREAM._hid_source:
        CRSF_STREAM.source_sample(body)
    else:
        CRSF_STREAM.update_axes(axes, buttons=body.get("buttons"), source=body.get("source"))
    return hid_state()

def hid_channel_map(body: dict) -> dict:
    """Set the channel map. Host-local; no device command.

    There is deliberately no default map. The operator's layout -- ARM on channel 5,
    switches and pots across 6-16 -- cannot be inferred from a HID descriptor, and
    the vendor's positional mapping would drive ARM from the fifth axis. So every
    channel is assigned explicitly or the stream refuses to run.
    """
    with CRSF_STREAM._source_lock:
        CRSF_STREAM.require_source(body)
        entries = body.get("channels")
        if not isinstance(entries, list):
            raise hidaxes.HidError("MAP_REQUIRED", "channels must be a list of 16 entries")
        CRSF_STREAM.set_channel_map(hidaxes.ChannelMap(entries))
        return hid_state()

def hid_detect(body: dict) -> dict:
    """Listen for whichever control the operator moves next. Host-local.

    The watching happens in CrsfStream.update_axes, which sees every HID report.
    Doing it in the page would miss a quick button tap between two 5 Hz polls.
    """
    with CRSF_STREAM._source_lock:
        CRSF_STREAM.require_source(body)
        action = str(body.get("action") or "start").lower()
        if action == "cancel":
            CRSF_STREAM.cancel_detect()
            return hid_state()
        if action != "start":
            raise hidaxes.HidError("DETECT_BAD_ACTION",
                                   f"unknown detect action {action!r}; use start or cancel")
        ch = body.get("channel")
        if ch is None:
            raise hidaxes.HidError("DETECT_BAD_CHANNEL", "a channel is required")
        if not (CRSF_STREAM.state().get("axes") or []):
            raise hidaxes.HidError(
                "HID_NO_AXES",
                "no stick has reported anything yet, so there is nothing to detect. "
                "Start the reader first.")
        CRSF_STREAM.start_detect(int(ch))
        return hid_state()

def hid_vendor_map(body: dict) -> dict:
    """Fill the map positionally: each axis in order, then centred channels.

    THE AXIS COUNT COMES FROM THE DEVICE, not from a constant. It used to default
    to 8, so on a stick with fewer axes this built a map referencing an axis that
    does not exist and the whole request failed with MAP_AXIS_MISSING -- the
    operator pressed the button and nothing loaded, with no indication why. A
    7-axis controller reproduced it exactly: "channel 8 is mapped to axis 7, which
    this device does not report".

    An explicit axis_count is still honoured so the caller can ask for fewer.
    """
    with CRSF_STREAM._source_lock:
        CRSF_STREAM.require_source(body)
        if body.get("apply") is not True:
            raise hidaxes.HidError("APPLY_REQUIRED", "the request must set apply=true")
        asked = body.get("axis_count")
        if asked is None:
            asked = len((CRSF_STREAM.state().get("axes") or []))
        n = int(asked)
        if n <= 0:
            raise hidaxes.HidError(
                "HID_NO_AXES",
                "no stick has reported any axes yet, so there is nothing to fill from. "
                "Start the reader and move a stick first.")
        CRSF_STREAM.set_channel_map(hidaxes.vendor_positional_map(n))
        return hid_state()

def hid_calibrate(body: dict) -> dict:
    """Start, finish, centre or clear a calibration. Host-local; no device command.

    Deliberately operator-driven rather than automatic: a calibration captured while
    a stick happened to rest off-centre would bake that in.
    """
    with CRSF_STREAM._source_lock:
        CRSF_STREAM.require_source(body)
        action = str(body.get("action") or "").lower()
        if action == "start":
            st = CRSF_STREAM.state()
            n = len(st.get("axes") or [])
            if not n:
                raise hidaxes.HidError("HID_NO_AXES",
                                       "no stick positions have been reported yet")
            CRSF_STREAM.start_calibration(int(body.get("axis_count") or n))
        elif action == "finish":
            CRSF_STREAM.finish_calibration()
        elif action == "centre":
            CRSF_STREAM.mark_centre()
        elif action == "clear":
            CRSF_STREAM.set_calibration(None)
        else:
            raise hidaxes.HidError("HID_UNKNOWN_ACTION", f"unknown action {action!r}",
                                   {"actions": ["start", "finish", "centre", "clear"]})
        return hid_state()

def hid_stream(body: dict) -> dict:
    with CRSF_STREAM._source_lock:
        CRSF_STREAM.require_source(body)
        action = str(body.get("action") or "").lower()
        if action == "start":
            if body.get("apply") is not True:
                raise hidaxes.HidError("APPLY_REQUIRED", "the request must set apply=true")
            _cgc_guard()
            if CRSF_STREAM._hid_source and (body.get('receiver_token') is None or body.get('receiver_token')!=_hid_receiver_identity_token()):
                raise hidaxes.HidError('HID_RECEIVER_CHANGED','Receiver observation changed; refresh and explicitly restart output')
            output_scope=_hid_receiver_scope()
            if CRSF_STREAM._hid_source and body.get('receiver_token')!=_hid_receiver_identity_token():
                raise hidaxes.HidError('HID_RECEIVER_CHANGED','Receiver changed during output preparation')
            CRSF_STREAM.start(rate_hz=body.get("rate_hz"),output_scope=output_scope)
            return hid_state()
        if action == "stop":
            CRSF_STREAM.stop()
            return hid_state()
        raise hidaxes.HidError("HID_UNKNOWN_ACTION", f"unknown action {action!r}",
                               {"actions": ["start", "stop"]})

def device_compatibility_document() -> dict:
    """What this build knows about the connected unit's firmware, and what it does not.

    The honest shape matters more than the content: a unit this build has no evidence
    for gets `applies: null` and an explicit statement that nothing was inferred from
    a sibling product line.
    """
    ident = ACTIVE_CONNECTION.get("serial_identity") or {}
    device_name, firmware = ident.get("device_name"), ident.get("firmware")
    doc = max19214.capability_document(device_name, firmware)
    rf_elig = rf_write_eligibility()
    return {
        "ok": True, "schema": "ascent.device_compatibility.v1",
        "identity": {"device_name": device_name, "firmware": firmware,
                     "hardware": ident.get("hardware"),
                     "sdk_version": ident.get("sdk_version")},
        "version": fwver.describe(firmware),
        "compatibility": doc,
        "rf_table_write": {"eligible": rf_elig.get("eligible"),
                           "reasons": rf_elig.get("reasons"),
                           "note": max19214.RF_TABLE_WRITE_ON_19_2_14["detail"]},
        "captured_at": utc_now(),
    }

def _blocking_operation_active() -> bool:
    return bool(DEVICE_OPERATION_STATE.get('active'))

def usb_driver_document() -> dict:
    """What is wrong with the receiver's USB network interface, if anything.

    Read-only. It never changes anything and is safe to poll.
    """
    out = {"schema": drvrepair.SCHEMA, "supported": platform.system() == "Windows",
           "devices": [], "offered": False}
    if not out["supported"]:
        out["reason"] = "Driver repair is a Windows-only operation."
        return out
    try:
        problems = readbundle.discover_problem_devices() or []
    except Exception as e:
        out["error"] = "PROBLEM_SCAN_FAILED"
        out["message"] = sanitize_error(f"{type(e).__name__}: {e}")
        return out
    if not problems:
        out["reason"] = ("Windows reports no Ascent USB device in an error state. "
                         "If a receiver is connected and still has no network "
                         "interface, it is in serial mode rather than network mode.")
        return out

    for dev in problems:
        iid = str(dev.get("InstanceId") or "")
        ids = drvrepair.device_ids(iid) if iid else {}
        diag = drvrepair.diagnose_descriptor_cache(ids.get("hardware_ids", []),
                                                   ids.get("compatible_ids", []))
        claimers = drvrepair.claiming_drivers(
            list(ids.get("hardware_ids", [])) + list(ids.get("compatible_ids", [])))
        entry = {
            "instance_id": iid,
            "name": dev.get("Name") or dev.get("FriendlyName"),
            "problem": dev.get("Problem"),
            "status": dev.get("Status"),
            "hardware_ids": ids.get("hardware_ids", []),
            "compatible_ids": ids.get("compatible_ids", []),
            "descriptor_cache": diag,
            "claiming_drivers": claimers,
        }
        if diag.get("applies"):
            entry["remedy"] = "DESCRIPTOR_CACHE"
            entry["headline"] = ("Windows has cached that this receiver does not "
                                 "support Microsoft OS descriptors, so it no longer "
                                 "asks and no network driver can match it.")
            entry["action"] = "CLEAR CACHED DESCRIPTOR"
            entry["changes"] = [
                f"Exports HKLM\\SYSTEM\\CurrentControlSet\\Control\\usbflags\\"
                f"{diag['key']} to a backup file first.",
                "Deletes one value, osvc, from that key. Nothing else is touched.",
                "Asks Windows to re-read the receiver.",
                "Restores the backup automatically if the receiver still does not "
                "answer.",
            ]
            entry["scope"] = (f"Scoped to revision {diag['key'][-4:]}, read from this "
                              f"receiver's own hardware ID. No other device revision "
                              f"is affected.")
        elif claimers:
            entry["remedy"] = "DRIVER_INSTALL"
            entry["headline"] = ("A driver on this machine claims this device but it "
                                 "has not attached.")
            entry["action"] = "REINSTALL DRIVER"
        else:
            entry["remedy"] = "NONE_AVAILABLE"
            entry["headline"] = ("No driver on this machine claims this device, and "
                                 "its descriptor cache is not the reason.")
            entry["manual"] = drvrepair._manual_text()
        out["devices"].append(entry)

    out["offered"] = any(d.get("remedy") in ("DESCRIPTOR_CACHE", "DRIVER_INSTALL")
                         for d in out["devices"])
    return out

def usb_driver_repair(body: dict) -> dict:
    """Perform the repair the diagnosis named, for ONE named device.

    `instance_id` is required and `confirm` must be true: a repair that can run
    without the operator naming the device is a repair that can run against the
    wrong one.
    """
    body = body or {}
    iid = str(body.get("instance_id") or "").strip()
    if not iid:
        raise ValueError("instance_id is required")
    if not body.get("confirm"):
        raise ValueError("confirm must be true")
    if platform.system() != "Windows":
        raise ValueError("driver repair is a Windows-only operation")

    ids = drvrepair.device_ids(iid)
    if not ids.get("hardware_ids") and not ids.get("compatible_ids"):
        raise ValueError("that device is no longer present")

    result = drvrepair.repair_descriptor_cache(
        iid, ids.get("hardware_ids", []), ids.get("compatible_ids", []),
        confirmed=True)

    # Re-read afterwards either way, so the panel shows the state Windows is in
    # now rather than the state it was in when the operator pressed the button.
    try:
        result["now"] = usb_driver_document()
    except Exception:
        pass
    return result

REPEATER_IDENTITIES = ("ascent_relay", "ascent_repeater")

def _is_repeater(device_name: str | None) -> bool:
    return _norm_device_name(device_name) in REPEATER_IDENTITIES

def repeater_document() -> dict:
    """What this build knows about the connected device, as a Repeater.

    Detection is by raw command-60 identity, never by VID/PID and never by the
    stored record -- the same rule everything else here follows, and the one the
    stale-record defect was about.
    """
    ident = (ACTIVE_CONNECTION.get("serial_identity") or {})
    name = ident.get("device_name")
    present = bool(name)
    is_rep = _is_repeater(name)
    caps = rep.describe()

    doc = {"ok": True, "schema": rep.SCHEMA, "operation_id": "repeater_control",
           "device": {"device_name": name, "serial_number": ident.get("serial_number"),
                      "firmware": ident.get("firmware"),
                      "hardware": ident.get("hardware")} if present else None,
           "is_repeater": is_rep,
           "operations": caps["operations"],
           "hardware_verified": caps["hardware_verified"],
           "note": caps["note"],
           "captured_at": utc_now()}

    if not present:
        doc["state"] = "NO_DEVICE"
        doc["message"] = ("No device is connected. Repeater controls need a live "
                          "command-60 identity, which is the only thing that says "
                          "what a unit is.")
    elif not is_rep:
        doc["state"] = "NOT_A_REPEATER"
        doc["message"] = (f"The connected device identifies as {name}. These controls "
                          f"are for the Relay/Repeater and are not offered for it -- "
                          f"a page that presents capabilities a device does not have "
                          f"is worse than one that is absent.")
    else:
        doc["state"] = "READY"
        doc["message"] = ("Repeater identified. The operations below are built from a "
                          "disassembly of the Ground application and have NOT been "
                          "exercised on hardware.")
    return doc

def repeater_read(body: dict | None = None) -> dict:
    """Issue one established read and report what came back.

    Refuses an opcode this build does not offer rather than sending it. The
    research says of the inferred ones, in as many words, "Verify before sending
    one", and a tool that sends them anyway has ignored its own evidence.
    """
    want = int((body or {}).get("opcode") or rep.OP_GET_BB_POWER)
    if not rep.offered(want):
        raise rep.RepeaterError(
            "OPERATION_NOT_OFFERED",
            f"0x{want:02X} is not offered by this build. Its opcode or its readback "
            f"is inferred rather than observed, and the research says to verify it "
            f"before sending one.",
            {"opcode": f"0x{want:02X}"})
    ident = ACTIVE_CONNECTION.get("serial_identity") or {}
    if not _is_repeater(ident.get("device_name")):
        raise rep.RepeaterError("NOT_A_REPEATER",
                                "the connected device does not identify as a Repeater")
    binding = _active_network_binding()
    if not binding:
        raise rep.RepeaterError(
            "NO_CORRELATED_NETWORK_BINDING",
            "This unit has no correlated local interface, so a datagram to it could "
            "reach a different receiver. Several Ascent units answer on one "
            "device-side address; the interface is chosen by USB ContainerId.")
    frame = rep.build_read(want)
    raw = _cgc_exchange(frame, expect_reply=True)
    return {"ok": True, "request": frame.hex(), "response": rep.parse_response(raw, expect=want),
            "hardware_verified": False}

SERVER_REF: dict = {}

def device_history_document(_body: dict | None = None) -> dict:
    """What is remembered, for the Advanced surface.

    Reads the registry directly rather than through the receivers document,
    because the operator is asking about STORED history, not about what is
    connected right now.
    """
    doc = knownrx.load_document()
    devices = doc.get("devices") or []
    rows = []
    for d in devices:
        rows.append({
            "device_id": d.get("device_id"),
            "product": d.get("product") or d.get("command_60_identity"),
            "firmware": d.get("firmware"),
            "first_seen": d.get("first_seen"),
            "last_seen": d.get("last_seen"),
            "address_count": len(d.get("observed_macs") or []),
            "service_mode": (d.get("service_mode") or {}).get("state"),
            # The identity an operator recognises, and the one the RF layer
            # addresses by. Both, because a nickname is not an identity and a
            # BB ID is not a name.
            "serial_number": d.get("serial_number"),
            "bb_id": d.get("bb_id") or d.get("nickname_bb_id"),
            # WHEN THE FIRMWARE LAST CHANGED, and what it was before. null is
            # NO CHANGE OBSERVED -- not "never updated", which is a different
            # thing and is not knowable for a unit first seen after its update.
            "firmware_changed_at": d.get("firmware_changed_at"),
            "firmware_previous": ((d.get("firmware_history") or [{}])[-1]
                                  .get("firmware") if d.get("firmware_history")
                                  else None),
            "addresses": [m.get("address") for m in (d.get("observed_macs") or [])],
        })
    return {"ok": True, "policy": firstrun.policies().get("device_history"),
            "count": len(rows), "devices": rows,
            "store": str(knownrx.store_path()),
            "note": ("Addresses are discovery evidence only. They never "
                     "authorise an operation and are never used as an identity.")}

def device_history_forget(body: dict) -> dict:
    """Forget one remembered device.

    Deliberately does NOT revoke a key or touch the receiver -- forgetting is a
    host-local act, and conflating it with revocation would mean an operator
    tidying a list silently lost access to hardware.
    """
    device_id = str((body or {}).get("device_id") or "")
    if not device_id:
        raise knownrx.RegistryError("DEVICE_ID_REQUIRED", "name the device to forget")
    doc = knownrx.load_document()
    before = len(doc.get("devices") or [])
    doc["devices"] = [d for d in (doc.get("devices") or [])
                      if d.get("device_id") != device_id]
    if len(doc["devices"]) == before:
        raise knownrx.RegistryError("DEVICE_NOT_FOUND", "no such remembered device")
    knownrx.save_document(doc)
    return {"ok": True, "forgotten": device_id, "remaining": len(doc["devices"]),
            "note": ("Removed from this computer only. Nothing was changed on "
                     "the receiver, and any key it holds is still installed.")}

def device_history_clear(body: dict) -> dict:
    confirmed = bool((body or {}).get("confirmed"))
    if not confirmed:
        raise knownrx.RegistryError("CONFIRMATION_REQUIRED",
                                    "clearing all device history needs confirmation")
    doc = knownrx.load_document()
    n = len(doc.get("devices") or [])
    doc["devices"] = []
    knownrx.save_document(doc)
    return {"ok": True, "cleared": n,
            "note": "Removed from this computer only. No receiver was changed."}

HISTORY_CSV_COLUMNS = ("device_id", "product", "serial_number", "bb_id",
                       "firmware", "firmware_changed_at", "firmware_previous",
                       "first_seen", "last_seen", "service_mode",
                       "address_count", "addresses")

def device_history_export(body: dict | None = None) -> dict:
    """Explicit export. Returns the content rather than writing a file.

    CSV as well as JSON, because the operator asked for "a persistent json or
    csv file" and a spreadsheet is what a fleet list actually gets read in.
    Returned as text for the caller to save, so nothing is written anywhere
    the operator did not choose.
    """
    body = body or {}
    doc = device_history_document()
    out = {"ok": True, "exported_at": utc_now(),
           "document": knownrx.load_document(),
           "columns": list(HISTORY_CSV_COLUMNS)}
    if str(body.get("format") or "").lower() == "csv" or body.get("csv"):
        import csv as _csv
        import io as _io
        buf = _io.StringIO()
        w = _csv.writer(buf, lineterminator="\n")
        w.writerow(HISTORY_CSV_COLUMNS)
        for r in out["document"].get("devices") or []:
            row = {d["device_id"]: d for d in doc["devices"]}.get(r.get("device_id"), {})
            w.writerow([
                ";".join(row.get(c) or []) if c == "addresses"
                else ("" if row.get(c) is None else row.get(c))
                for c in HISTORY_CSV_COLUMNS])
        out["csv"] = buf.getvalue()
    return out

NETWORK_OPERATION_ID = "rndis_host_address"

RNDIS_HOST_ADDRESS = "192.168.3.103"

RNDIS_PREFIX = 24

def _adapter_ipv4(row: dict) -> list[dict]:
    ips = row.get("IPv4") or []
    if isinstance(ips, dict):
        ips = [ips]
    return [x for x in ips if isinstance(x, dict)]

def resolve_nic_for_ip(target_ip: str) -> dict | None:
    """Which laptop NIC + local source IPv4 routes to target_ip.

    Windows-only (Find-NetRoute); None on other platforms, on a bad IP, or when the
    route cannot be resolved. WINDOWS-VALIDATED-LATER: the PowerShell shape is
    host-tested through a mocked _run_powershell_json, but the live Find-NetRoute
    output is only verifiable on Windows. PowerShell runs hidden (the windowless
    host must not flash a console).
    """
    if platform.system().lower() != "windows":
        return None
    try:
        socket.inet_aton(str(target_ip))
    except OSError:
        return None
    script = (
        "$ErrorActionPreference='Stop';"
        f"$r=Find-NetRoute -RemoteIPAddress '{target_ip}' -ErrorAction Stop|Select-Object -First 1;"
        "$ifx=$r.InterfaceIndex;$src=$r.IPAddress;"
        "if(-not $src){$src=(Get-NetIPAddress -InterfaceIndex $ifx -AddressFamily IPv4 "
        "-ErrorAction SilentlyContinue|Select-Object -First 1).IPAddress};"
        "[pscustomobject]@{if_index=$ifx;source_ip=$src}|ConvertTo-Json -Compress"
    )
    try:
        rows = _run_powershell_json(script)  # runs hidden; mockable in tests
    except Exception:
        return None
    row = rows[0] if rows else None
    if not isinstance(row, dict):
        return None
    ifx, src = row.get("if_index"), row.get("source_ip")
    if not isinstance(ifx, int) or ifx <= 0 or not isinstance(src, str) or not src.strip():
        return None
    return {"source_ip": src.strip(), "if_index": ifx}

def _tcp_reachable(host: str, port: int, binding: dict | None, timeout: float = 1.0) -> bool:
    """One bound TCP connect test. Bound to the resolved NIC when we have one, the
    same way bb_status binds; best-effort (unbound) otherwise. Never raises."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        if binding:
            try:
                _pin_windows_ipv4_interface(s, binding["if_index"])
            except Exception:
                pass
            try:
                s.bind((binding["source_ip"], 0))
            except OSError:
                pass
        s.settimeout(timeout)
        s.connect((host, int(port)))
        return True
    except OSError:
        return False
    finally:
        try:
            s.close()
        except OSError:
            pass

_NETWORK_PROBE_PORTS = {"map_bridge": 50140, "rpc_qos": 50000, "video": 554, "service_mode": 22}

def network_probe(device_ip: str) -> dict:
    """Operator-asserted-IP reachability probe. Resolves the NIC, port-tests, and
    gates features by what answered (unreachable = UNKNOWN/null, not unsupported).
    Never raises."""
    try:
        socket.inet_aton(str(device_ip))
    except (OSError, TypeError):
        return {"ok": False, "error": "BAD_IP",
                "message": "device_ip must be a valid IPv4 address",
                "device_ip": device_ip}
    binding = resolve_nic_for_ip(device_ip)
    ports = {name: _tcp_reachable(device_ip, port, binding)
             for name, port in _NETWORK_PROBE_PORTS.items()}
    # Feature gating: an open port == available (True); a closed one == UNKNOWN
    # (None) rather than "unsupported" -- a filtered port is not proof of absence.
    features = {name: (True if ports[name] else None) for name in _NETWORK_PROBE_PORTS}
    return {
        "ok": True,
        "device_ip": device_ip,
        "correlation": "operator_asserted_ip",
        "source_ip": (binding or {}).get("source_ip"),
        "if_index": (binding or {}).get("if_index"),
        "nic_resolved": binding is not None,
        "reachable": any(ports.values()),
        "ports": ports,
        "features": features,
        "captured_at": utc_now(),
        "note": ("Operator-asserted IP, not ContainerId-correlated. Closed ports read "
                 "as UNKNOWN, not unsupported."),
    }

def repeater_network_read(body: dict) -> dict:
    """Explicit Ethernet target; never borrows a USB session or credentials."""
    import ipaddress
    request_device, request_generation = SESSION.device, SESSION.generation
    try:
        device_ip = str(ipaddress.IPv4Address(str((body or {}).get("device_ip") or "")))
    except ValueError:
        return {"ok": False, "error": "BAD_IP", "message": "Enter the Relay IPv4 address."}
    binding = resolve_nic_for_ip(device_ip) or {}
    source_ip, if_index = binding.get("source_ip"), binding.get("if_index")
    if not source_ip:
        return {"ok": False, "error": "NO_NIC_ROUTE", "device_ip": device_ip,
                "message": "No PC network interface reaches this subnet."}
    result = {"ok": True, "device_ip": device_ip, "source_ip": source_ip,
              "if_index": if_index, "transport": "ethernet_ip",
              "correlation": "operator_asserted_ip", "captured_at": utc_now(),
              "factory": None, "factory_error": None}
    try:
        result["factory"] = relayfactory.read_identity_role(
            device_ip, source_ip=source_ip, if_index=if_index)
    except (OSError, ValueError) as exc:
        result["factory_error"] = sanitize_error(str(exc))
    result["qos"] = relayqos.read_all_radios(
        device_ip, source_ip=source_ip, if_index=if_index)
    result["reachable"] = bool(result["factory"] or result["qos"].get("connected"))
    dev = SESSION.device
    if (dev is request_device and SESSION.generation == request_generation
            and dev and dev.network_target and dev.network_target.get("kind") == "repeater"
            and dev.network_target.get("device_ip") == device_ip
            and NETWORK_SESSION_LOCK.acquire(blocking=False)):
        try:
            if SESSION.device is dev and SESSION.generation == request_generation:
                target = dev.network_target
                before = target.get("observed") or {}
                old_serial = (before.get("factory") or {}).get("factory_serial")
                new_serial = (result.get("factory") or {}).get("factory_serial")
                changed = bool(old_serial and new_serial and old_serial != new_serial)
                for key in ("0", "1"):
                    old = ((before.get("qos") or {}).get("radios") or {}).get(key) or {}
                    new = (result["qos"].get("radios") or {}).get(key) or {}
                    changed |= bool(old.get("local_mac") and new.get("local_mac") and old["local_mac"] != new["local_mac"])
                changed |= target.get("source_ip") != source_ip or target.get("if_index") != if_index
                if changed:
                    target["requires_reconnect"] = True
                    result["requires_reconnect"] = True
                target.update(observed=result, captured_at=result["captured_at"],
                              source_ip=source_ip, if_index=if_index)
        finally:
            NETWORK_SESSION_LOCK.release()
    return result

def repeater_network_control(body: dict) -> dict:
    """Fixed actions on the selected, freshly re-proved Ethernet target only."""
    import copy
    import uuid
    if not isinstance(body, dict) or body.get("action") not in ("hf", "mf", "swap"):
        return {"ok": False, "error": "UNKNOWN_ACTION", "message": "Choose HF bind, MF bind or reverse roles."}
    if not NETWORK_SESSION_LOCK.acquire(blocking=False):
        return {"ok": False, "error": "DEVICE_BUSY", "message": "A connection or network action is in progress."}
    try:
        dev = SESSION.device
        target = dev.network_target if dev else None
        if not target or not body.get("connection_token") or body.get("connection_token") != target.get("connection_token"):
            return {"ok": False, "error": "TARGET_CHANGED", "message": "Connect to REPEATER ETH and read its status before using these controls."}
        if target.get("requires_reconnect"):
            return {"ok": False, "error": "RECONNECT_REQUIRED", "message": "Reconnect after the role-change reboot before using another control."}
        if time.monotonic() < target.get("next_control_at", 0):
            return {"ok": False, "error": "DEVICE_BUSY", "message": "Wait for the current bind window to finish before another control."}
        action = body.get("action")
        if action == "swap" and body.get("confirm_reboot") is not True:
            return {"ok": False, "error": "CONFIRM_REBOOT", "message": "Confirm the role reversal and reboot."}
        binding = resolve_nic_for_ip(target["device_ip"]) or {}
        if binding.get("source_ip") != target.get("source_ip") or binding.get("if_index") != target.get("if_index"):
            return {"ok": False, "error": "NETWORK_ROUTE_CHANGED", "message": "The PC network route changed. Reconnect before using these controls."}
        with SERIAL_GATE.hold("relay_network_control", timeout=1):
            if DEVICE_OPERATION_STATE.get("active") or not DEVICE_MUTATION_LOCK.acquire(blocking=False):
                return {"ok": False, "error": "DEVICE_BUSY", "message": "A device operation is in progress."}
            try:
                transaction = uuid.uuid4().hex
                evidence = {"device_ip": target["device_ip"], "source_ip": target["source_ip"],
                            "if_index": target["if_index"],
                            "factory_serial": ((target.get("observed") or {}).get("factory") or {}).get("factory_serial")}
                smaudit.append(smaudit.record("relay_network_" + action, "BEGIN",
                               transaction_id=transaction, network_target=evidence))
                try:
                    result = relaynetwork.perform(copy.deepcopy(target), action)
                except Exception:
                    if action in ("hf", "mf"):
                        target["next_control_at"] = time.monotonic() + 30
                    smaudit.append(smaudit.record("relay_network_" + action, "OUTCOME_UNKNOWN",
                                   transaction_id=transaction, network_target=evidence))
                    raise
                smaudit.append(smaudit.record("relay_network_" + action, result.get("state") or "REQUEST_ACKNOWLEDGED",
                               transaction_id=transaction, network_target=evidence,
                               execution_verified=False, pairing_verified=False))
                if result.get("requires_reconnect"):
                    target["requires_reconnect"] = True
                else:
                    target["next_control_at"] = time.monotonic() + 30
                    result["wait_seconds"] = 30
                target["last_action"] = result
                return result
            finally:
                DEVICE_MUTATION_LOCK.release()
    except SerialBusyError:
        return {"ok": False, "error": "DEVICE_BUSY", "message": "A device operation is in progress."}
    except (OSError, ValueError, relayqos.RelayQosError) as exc:
        return {"ok": False, "error": "NETWORK_CONTROL_NOT_COMPLETED",
                "message": sanitize_error(str(exc)), "execution_verified": False,
                "outcome": "unknown", "retry": False,
                "wait_seconds": int(max(0, (target or {}).get("next_control_at", 0) - time.monotonic()) + 0.99)}
    finally:
        NETWORK_SESSION_LOCK.release()

def network_relay_qos(body: dict) -> dict:
    """Per-radio Relay QoS at an operator-asserted Relay IP (read-only).

    Resolves the NIC for the given IP exactly as network_probe does, binds the
    bb-ioctl RPC socket to it (destination IP alone is not identity), and reads
    both radios. Never raises. Unreachable radios report their error per-field
    rather than being presented as unsupported."""
    device_ip = str((body or {}).get("device_ip") or "")
    try:
        socket.inet_aton(device_ip)
    except (OSError, TypeError):
        return {"ok": False, "error": "BAD_IP",
                "message": "device_ip must be a valid IPv4 address",
                "device_ip": device_ip}
    work_ids = (body or {}).get("work_ids") or [0, 1]
    try:
        work_ids = [int(w) for w in work_ids]
    except (TypeError, ValueError):
        work_ids = [0, 1]
    try:
        timeout = float((body or {}).get("timeout") or 1.2)
    except (TypeError, ValueError):
        timeout = 1.2
    timeout = max(0.2, min(timeout, 5.0))

    binding = resolve_nic_for_ip(device_ip)
    source_ip = (binding or {}).get("source_ip")
    if_index = (binding or {}).get("if_index")
    # Fail closed on NIC resolution: without a bound source IP a read could leave
    # from the wrong adapter and reach a different unit. Return the honest reason.
    if not source_ip:
        return {"ok": False, "error": "NO_NIC_ROUTE",
                "message": ("No local NIC route to the relay IP; configure the host "
                            "adapter for this subnet first"),
                "device_ip": device_ip,
                "correlation": "operator_asserted_ip",
                "nic_resolved": False,
                "captured_at": utc_now()}
    qos = relayqos.read_all_radios(device_ip, source_ip=source_ip,
                                   if_index=if_index, work_ids=work_ids,
                                   timeout=timeout)
    # Honest registry note: did the operator mark this IP as a relay? We do NOT
    # gate on it (the IP is operator-asserted either way), we just report it.
    registry_kind = None
    try:
        for d in (local_settings.known_devices() or []):
            if str(d.get("device_ip")) == device_ip:
                registry_kind = d.get("kind")
                break
    except Exception:
        registry_kind = None
    return {
        "ok": True,
        "device_ip": device_ip,
        "correlation": "operator_asserted_ip",
        "source_ip": source_ip,
        "if_index": if_index,
        "nic_resolved": True,
        "registry_kind": registry_kind,
        "connected": qos.get("connected"),
        "radios": qos.get("radios"),
        "schema": qos.get("schema"),
        "captured_at": utc_now(),
        "note": ("Operator-asserted IP, not ContainerId-correlated. Per-radio "
                 "MCS/power/frequency decodes are vendor-derived and bench-"
                 "unconfirmed; treat radio/role labels as hints, not identity."),
    }

def network_adapters() -> dict:
    """Every RNDIS-ish adapter, with a diagnosis and the repair that would apply.

    The diagnosis is deliberately per-adapter and names the reason: "no address on
    the device subnet" and "not correlated to a serial device" are different
    problems with different fixes, and collapsing them is what leaves an operator
    guessing.
    """
    try:
        inv = INVENTORY_CACHE.get(max_age=2.0)
    except Exception as e:
        return {"ok": False, "supported": False,
                "error": sanitize_error(f"{type(e).__name__}: {e}")}
    inventory = inv.inventory or {}
    nets = inventory.get("network") or []
    usb = inventory.get("usb") or []

    # ContainerIds that carry a recognised Ascent serial interface. An adapter
    # sharing one is the RNDIS half of a real device.
    serial_cids = {
        str(r.get("ContainerId") or "").strip().upper()
        for r in usb
        if pnp_is_ascent_evidence(str(r.get("PNPDeviceID") or ""))
    } - {""}

    rows = []
    for n in nets:
        desc = str(n.get("InterfaceDescription") or "")
        pnp = str(n.get("PnPDeviceID") or "")
        if not re.search(r"(?i)rndis|remote ndis|usb ethernet", desc) and \
           not VID_PNP_RE.search(pnp):
            continue
        ips = _adapter_ipv4(n)
        cid = str(n.get("ContainerId") or "").strip().upper()
        on_subnet = [x for x in ips
                     if str(x.get("IPAddress") or "").startswith("192.168.3.")
                     and str(x.get("IPAddress")) != HOST_CFG["ground"]
                     and int(x.get("PrefixLength") or -1) == RNDIS_PREFIX]
        correlated = bool(cid and cid in serial_cids)

        problems = []
        if not correlated:
            problems.append("NOT_CORRELATED")
        if not on_subnet:
            problems.append("NO_DEVICE_SUBNET_ADDRESS")
        if str(n.get("Status") or "").lower() not in ("up", ""):
            problems.append("ADAPTER_DOWN")

        rows.append({
            "name": n.get("Name"), "description": desc,
            "ifindex": int(n["ifIndex"]) if n.get("ifIndex") is not None else None,
            "status": n.get("Status"), "mac": n.get("MacAddress"),
            "container_id": cid or None,
            "correlated_to_serial": correlated,
            "addresses": [{"ip": x.get("IPAddress"), "prefix": x.get("PrefixLength"),
                           "state": x.get("AddressState")} for x in ips],
            "ready": bool(on_subnet) and correlated,
            "problems": problems,
            "repair": None if on_subnet else {
                "action": "set_static_ipv4",
                "address": RNDIS_HOST_ADDRESS, "prefix": RNDIS_PREFIX,
                "also": "disables DHCP on this interface",
                "reversible": ("Undo it from here: POST the same ifindex with "
                               "rollback=true. Only an address this application "
                               "recorded adding is removed, and DHCP is restored if "
                               "this application disabled it."),
            },
        })

    return {
        "ok": True, "supported": platform.system().lower() == "windows",
        "operation_id": NETWORK_OPERATION_ID,
        "adapters": rows,
        "device_address": HOST_CFG["ground"],
        "host_address": RNDIS_HOST_ADDRESS, "prefix": RNDIS_PREFIX,
        "note": ("The host address is configured automatically during CONNECT, but "
                 "only once a device is identified AND its RNDIS sibling is "
                 "ContainerId-correlated. When the correlation is what is broken the "
                 "automatic path never runs, which is when this page is useful."),
        "elevation": ("Changing an adapter address needs Administrator. Windows will "
                      "prompt; the application itself does not run elevated."),
    }

def network_configure(body: dict) -> dict:
    """Apply -- or roll back -- the static host address on one adapter.

    Explicit, never implicit, in both directions. Rollback removes only an address
    this application recorded adding, so it can never delete operator configuration.
    """
    rollback = body.get("rollback") is True
    if not rollback and body.get("apply") is not True:
        raise ValueError("the request must set apply=true (or rollback=true)")
    ifindex = body.get("ifindex")
    if not isinstance(ifindex, int):
        raise ValueError("ifindex must be an integer")

    doc = network_adapters()
    match = next((a for a in doc.get("adapters", []) if a["ifindex"] == ifindex), None)
    if match is None:
        raise ValueError(f"interface {ifindex} is not a recognised Ascent RNDIS adapter")
    # The helper script refuses a non-Ascent adapter itself; this is the second gate,
    # so a typo in a request body cannot reach an unrelated NIC.
    if not match["correlated_to_serial"] and body.get("force") is not True:
        raise ValueError(
            f"interface {ifindex} ({match['name']}) is not ContainerId-correlated to "
            f"any Ascent serial device. Set force=true only if you are certain this is "
            f"the right adapter -- multiple Ascent units expose the same device-side "
            f"IP, so configuring the wrong one points the host at a different aircraft.")

    before = list(match["addresses"])
    result = _configure_rndis_elevated(ifindex, rollback=rollback)
    INVENTORY_CACHE.invalidate()
    after = network_adapters()
    now = next((a for a in after.get("adapters", []) if a["ifindex"] == ifindex), None)
    return {"ok": True, "ifindex": ifindex, "helper": result,
            "rolled_back": rollback,
            "before": before, "after": (now or {}).get("addresses", []),
            "ready": bool((now or {}).get("ready")),
            "state": after}

def rf_reading() -> dict:
    # 0x51 frequency, 0x52 wireless status, 0x53 power index.
    result = {
        "available": False,
        "transport": f"udp://{HOST_CFG['ground']}:{HOST_CFG['ctrl_udp_port']}",
        "queries": {},
        "captured_at": utc_now(),
        "note": "Response framing is validated; payload fields remain raw until cross-product qualification.",
    }
    for name, cmd in (("frequency", 0x51), ("wireless_status", 0x52), ("power_index", 0x53)):
        try:
            result["queries"][name] = {"ok": True, **gc_query(cmd)}
            result["available"] = True
        except Exception as e:
            result["queries"][name] = {"ok": False, "error": sanitize_error(f"{type(e).__name__}: {e}"), "command": cmd}
    return result

def _hidden_subprocess_kwargs() -> dict:
    """Hide helper-process consoles when launched from the windowless WPF host."""
    if platform.system().lower() != "windows":
        return {}
    si = subprocess.STARTUPINFO()
    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    si.wShowWindow = 0  # SW_HIDE
    return {"startupinfo": si, "creationflags": subprocess.CREATE_NO_WINDOW}

POWERSHELL_TIMEOUT = 20

def _run_powershell_json(script: str) -> list:
    cp = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        timeout=POWERSHELL_TIMEOUT,
        **_hidden_subprocess_kwargs(),
    )
    if cp.returncode != 0:
        raise RuntimeError((cp.stderr or cp.stdout or "PowerShell query failed").strip())
    raw = cp.stdout.strip()
    if not raw:
        return []
    obj = json.loads(raw)
    return obj if isinstance(obj, list) else [obj]

def _pnp_root_key(pnp_id: str | None) -> str | None:
    """Best-effort grouping key for sibling MI_00/MI_02 interfaces."""
    if not pnp_id or "\\" not in pnp_id:
        return None
    tail = pnp_id.rsplit("\\", 1)[-1]
    parts = tail.split("&")
    if len(parts) >= 3:
        return "&".join(parts[:3]).upper()
    return tail.upper()

def _vid_pid(pnp_id: str | None) -> tuple[str | None, str | None]:
    import re
    m = re.search(r"VID_([0-9A-Fa-f]{4})&PID_([0-9A-Fa-f]{4})", pnp_id or "")
    return (m.group(1).upper(), m.group(2).upper()) if m else (None, None)

_INVENTORY_TTL = 2.0

_INVENTORY_LOCK = threading.Lock()

_INVENTORY_CACHE: dict = {"at": 0.0, "value": None}

def windows_usb_inventory() -> dict:
    with _INVENTORY_LOCK:
        cached = _INVENTORY_CACHE["value"]
        if cached is not None and (time.monotonic() - _INVENTORY_CACHE["at"]) < _INVENTORY_TTL:
            return dict(cached, cached=True)
        value = _windows_usb_inventory_uncached()
        _INVENTORY_CACHE["at"] = time.monotonic()
        _INVENTORY_CACHE["value"] = value
        return dict(value, cached=False)

def _windows_usb_inventory_uncached() -> dict:
    out = {
        "platform": platform.system(),
        "supported": platform.system().lower() == "windows",
        "usb": [],
        "network": [],
        "captured_at": utc_now(),
    }
    if not out["supported"]:
        return out

    if os.name=='nt':
        # Keep the same live PnP/ContainerId/IP evidence, without CIM calls
        # that can stall while a Wi-Fi adapter associates or disconnects.
        helper=Path(__file__).parent/'windows_device_inventory.py'
        python=Path(sys.executable).with_name('python.exe')
        if not python.is_file():python=Path(sys.executable)
        result=subprocess.run([str(python),str(helper),VID_PNP_RE],
            capture_output=True,text=True,timeout=5,**_hidden_subprocess_kwargs())
        if result.returncode==0:
            value=json.loads(result.stdout)
            if not isinstance(value,dict)or value.get('platform')!='Windows' or value.get('supported')is not True or not all(isinstance(value.get(k),list)for k in ('usb','network')):
                raise ValueError('Native device inventory returned an invalid document')
            return value
        if result.returncode!=3:
            raise RuntimeError((result.stderr or 'Native device inventory failed').strip())
        # API unavailable is the only legacy fallback; malformed/failed native
        # observations remain failures, never an apparently valid old binding.

    # ContainerId is the Windows-supported correlation primitive for sibling
    # interfaces of one physical USB composite device. PnP instance tails are
    # retained only as diagnostics/fallback and never qualify a network write/read.
    # The WQL pre-filter is a pure speed-up and is deliberately WIDER than
    # VID_PNP_RE: it keeps every USB device and drops ACPI/PCI/display/software
    # nodes, which on this bench is 268 entities down to 6 and halves the query.
    # The authoritative match is still the shared VID_PNP_RE below, so widening
    # recognition there cannot be silently undone here.
    #
    # `[_]` is not decoration. In WQL `_` is a single-character wildcard, so a bare
    # 'VID_' would also match 'VIDx'; the bracket makes it a literal underscore.
    usb_script = r"""
$items = Get-CimInstance -Query "SELECT Name,Status,PNPClass,DeviceID,PNPDeviceID FROM Win32_PnPEntity WHERE PNPDeviceID LIKE '%VID[_]%'" -ErrorAction SilentlyContinue |
  Where-Object { $_.PNPDeviceID -match '<VIDRE>' } |
  ForEach-Object {
    $cid = $null
    try { $cid = (Get-PnpDeviceProperty -InstanceId $_.PNPDeviceID -KeyName 'DEVPKEY_Device_ContainerId' -ErrorAction Stop).Data } catch {}
    [pscustomobject]@{
      Name=$_.Name; Status=$_.Status; PNPClass=$_.PNPClass; DeviceID=$_.DeviceID;
      PNPDeviceID=$_.PNPDeviceID; ContainerId=if($cid){$cid.ToString()}else{$null}
    }
  }
$items | ConvertTo-Json -Compress -Depth 4
"""
    net_script = r"""
$items = Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue |
  Where-Object {
    $_.Status -ne 'Not Present' -and (
      $_.PnPDeviceID -match '<VIDRE>' -or
      $_.InterfaceDescription -match '(?i)RNDIS|Remote NDIS|USB Ethernet'
    )
  } | ForEach-Object {
    $a = $_
    $cid = $null
    try { $cid = (Get-PnpDeviceProperty -InstanceId $a.PnPDeviceID -KeyName 'DEVPKEY_Device_ContainerId' -ErrorAction Stop).Data } catch {}
    $ips = @(Get-NetIPAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
      Select-Object IPAddress,PrefixLength,PrefixOrigin,SuffixOrigin,AddressState)
    [pscustomobject]@{
      Name=$a.Name; InterfaceDescription=$a.InterfaceDescription; ifIndex=$a.ifIndex; Status=$a.Status;
      PnPDeviceID=$a.PnPDeviceID; ContainerId=if($cid){$cid.ToString()}else{$null};
      MacAddress=$a.MacAddress; LinkSpeed=$a.LinkSpeed; IPv4=$ips
    }
  }
$items | ConvertTo-Json -Compress -Depth 6
"""
    out["usb"] = _run_powershell_json(usb_script.replace("<VIDRE>", VID_PNP_RE))
    out["network"] = _run_powershell_json(net_script.replace("<VIDRE>", VID_PNP_RE))
    return out

def _probe_serial_cache(pnp_id: str, port: str) -> None:
    """Probe one newly seen Ascent COM interface with the vendor FIND_DEVICE GET."""
    # Never contend for a COM port that another serial session already owns. This is
    # opportunistic background work: if the gate is held by a connect, an RF read or a
    # qualified write, the probe simply skips its turn and the next poll retries.
    if DEVICE_OPERATION_STATE.get("active") or SERIAL_GATE.busy:
        return
    with DISCOVERY_LOCK:
        row = DISCOVERY_IDENTITY.setdefault(pnp_id, {})
        if row.get("probing"):
            return
        row.update({"probing": True, "port": port, "last_seen": time.monotonic()})
    try:
        with SERIAL_GATE.hold(f"discovery:{port}", timeout=0):
            ident = serial_identity(port)
        result = {"probing": False, "identity": ident, "error": None, "port": port, "last_seen": time.monotonic()}
    except SerialBusyError:
        # Not a device failure. Clear the in-progress marker and leave whatever the
        # previous probe established untouched so the UI does not flicker.
        with DISCOVERY_LOCK:
            row = DISCOVERY_IDENTITY.get(pnp_id)
            if row is not None:
                row.update({"probing": False, "last_seen": time.monotonic()})
        return
    except Exception as exc:
        result = {"probing": False, "identity": None, "error": sanitize_error(f"{type(exc).__name__}: {exc}"), "port": port, "last_seen": time.monotonic()}
    with DISCOVERY_LOCK:
        DISCOVERY_IDENTITY[pnp_id] = result

def _schedule_identity_probes(inv: dict) -> None:
    seen = set()
    for u in inv.get("usb") or []:
        name = str(u.get("Name") or "")
        cls = str(u.get("PNPClass") or "").lower()
        if cls != "ports" and "(COM" not in name:
            continue
        port = _extract_com(name)
        pnp = str(u.get("PNPDeviceID") or "")
        if not port or not pnp:
            continue
        seen.add(pnp)
        with DISCOVERY_LOCK:
            cached = DISCOVERY_IDENTITY.get(pnp)
            should = cached is None or (cached.get("identity") is None and not cached.get("probing") and time.monotonic() - cached.get("last_seen", 0) > 3.0)
            if cached:
                cached["last_seen"] = time.monotonic()
        if should:
            threading.Thread(target=_probe_serial_cache, args=(pnp, port), daemon=True, name=f"AscentProbe-{port}").start()
    # Remove stale identities after the interface has actually disappeared.
    with DISCOVERY_LOCK:
        now = time.monotonic()
        for key in list(DISCOVERY_IDENTITY):
            if key not in seen and now - DISCOVERY_IDENTITY[key].get("last_seen", 0) > 3.0:
                DISCOVERY_IDENTITY.pop(key, None)

def _build_connection_candidates(inv: dict) -> list[dict]:
    groups = {}
    host_ip = HOST_CFG["host_rndis_ip"]
    prefix = HOST_CFG["host_rndis_prefix"]

    def group_for(root: str, fallback: str):
        return groups.setdefault(root or fallback, {"root": root or fallback, "serial": None, "network": None, "usb": []})

    for u in inv.get("usb") or []:
        pnp = str(u.get("PNPDeviceID") or "")
        cid = str(u.get("ContainerId") or "").strip().upper() or None
        root = "CID:" + cid if cid else _pnp_root_key(pnp)
        g = group_for(root, "usb:" + pnp)
        if cid: g["container_id"] = cid
        g["usb"].append(u)
        name = str(u.get("Name") or "")
        cls = str(u.get("PNPClass") or "").lower()
        if cls == "ports" or "(COM" in name:
            g["serial"] = u

    for n in inv.get("network") or []:
        pnp = str(n.get("PnPDeviceID") or "")
        cid = str(n.get("ContainerId") or "").strip().upper() or None
        root = "CID:" + cid if cid else _pnp_root_key(pnp)
        g = group_for(root, "net:" + pnp)
        if cid: g["container_id"] = cid
        g["network"] = n

    candidates = []
    for root, g in groups.items():
        serial = g.get("serial")
        network = g.get("network")
        if serial is None and network is None:
            continue
        serial_pnp = str(serial.get("PNPDeviceID") or "") if serial else None
        com = _extract_com(serial.get("Name")) if serial else None
        with DISCOVERY_LOCK:
            probe = dict(DISCOVERY_IDENTITY.get(serial_pnp, {})) if serial_pnp else {}
        ident = probe.get("identity")
        device_name = ident.get("device_name") if ident else None
        image = ident.get("device_image") if ident else None
        pnp = str((network or {}).get("PnPDeviceID") or serial_pnp or "")
        vid, pid = _vid_pid(pnp)
        # Recognition is deliberately wide, but not every match is evidence.  1D6B:0002 is the
        # stock Linux Foundation gadget ID -- the Sky's own RNDIS personality uses it verbatim
        # (config_ether.sh:3-4) and so does every unrelated Linux USB gadget on the host.  A
        # group whose only in-block interface is that pair has not been shown to be an Ascent
        # device by USB descriptors alone; only a raw command-60 identity shows that.  Keep the
        # row -- the RNDIS sibling is needed for topology correlation -- but do not claim it.
        vid_pid_evidence = any(
            pnp_is_ascent_evidence(str(row.get("PNPDeviceID") or row.get("PnPDeviceID") or ""))
            for row in (list(g.get("usb") or []) + ([network] if network else []))
        )
        ips = (network or {}).get("IPv4") or []
        if isinstance(ips, dict): ips = [ips]
        configured = any(isinstance(x, dict) and str(x.get("IPAddress") or "").startswith("192.168.3.") and x.get("IPAddress") != HOST_CFG["ground"] and int(x.get("PrefixLength") or -1) == prefix for x in ips)
        ifindex = int(network.get("ifIndex")) if network and network.get("ifIndex") is not None else None
        container_id = g.get("container_id")
        serial_cid = str((serial or {}).get("ContainerId") or "").strip().upper() or None
        network_cid = str((network or {}).get("ContainerId") or "").strip().upper() or None
        topology_qualified = bool(serial and network and serial_cid and network_cid and serial_cid == network_cid)
        correlation_basis = "container_id" if topology_qualified else ("serial_only" if serial and not network else "unqualified")
        transports=[]
        if com: transports.append(f"SERIAL {com}")
        if network: transports.append("USB-C / RNDIS")
        if device_name:
            # The dropdown showed the raw command-60 string here, which is the
            # handoff §5 "raw internal identifiers as the primary product name"
            # defect.  The rendered name is the label; `device_name` on the row
            # below is untouched and is what every gate still reads.
            label = f"{device_naming.display_name(device_name) or device_name} — " + " + ".join(transports)
        elif probe.get("probing"):
            label = "IDENTIFYING ASCENT DEVICE… — " + " + ".join(transports)
        elif not vid_pid_evidence:
            # Say what is actually known: a USB gadget matched the recognition pattern and
            # nothing has proven it is an Ascent unit.
            label = "UNPROVEN USB GADGET — " + " + ".join(transports)
        else:
            label = "UNIDENTIFIED ASCENT DEVICE — " + " + ".join(transports)
        candidates.append({
            "id": f"device:{root}", "physical_root": root, "label": label,
            "device_name": device_name, "device_image": image,
            "device_product": device_naming.humanize(device_name),
            "identity_proven": bool(ident and device_name), "identity": ident,
            "identity_probe_in_progress": bool(probe.get("probing")),
            "identity_error": probe.get("error"),
            "transport": " + ".join(transports), "serial_com": com,
            "serial_port": serial.get("Name") if serial else None,
            "serial_pnp_device_id": serial_pnp,
            "container_id": container_id, "serial_container_id": serial_cid, "network_container_id": network_cid,
            "topology_qualified": topology_qualified, "correlation_basis": correlation_basis,
            "ifindex": ifindex, "adapter_name": network.get("Name") if network else None,
            "adapter_description": network.get("InterfaceDescription") if network else None,
            "adapter_status": network.get("Status") if network else None,
            "pnp_device_id": pnp, "vid": vid, "pid": pid, "ipv4": ips,
            "vid_pid_evidentiary": vid_pid_evidence,
            "ascent_evidence": "cmd60_identity" if (ident and device_name)
                               else ("vid_pid" if vid_pid_evidence else "none"),
            "host_ip_ready": configured, "target_host_ip": host_ip, "target_prefix": prefix,
        })
    # Proven identity first, then anything with real VID:PID evidence, then the rest.  Auto
    # selection reads candidates[0], so an unproven Linux gadget must never sort ahead of a
    # real unit.
    candidates.sort(key=lambda c: (not c["identity_proven"], not c.get("vid_pid_evidentiary", True),
                                   not bool(c.get("serial_com")), not c["host_ip_ready"], c["label"]))
    return candidates

NETWORK_CONNECTION_PROFILES = {
    "network:repeater_eth": {"id": "network:repeater_eth", "label": "REPEATER ETH",
                             "device_ip": "192.168.1.105", "kind": "repeater"},
    "network:max_eth": {"id": "network:max_eth", "label": "MAX ETH",
                        "device_ip": "192.168.1.100", "kind": "vrx"},
}

def connect_network_profile(profile_id: str) -> dict:
    """Select an explicit IP target in the shared session, without USB identity."""
    profile = dict(NETWORK_CONNECTION_PROFILES[profile_id])
    SESSION.clear()
    if profile['kind'] == 'repeater':
        observed = repeater_network_read({'device_ip': profile['device_ip']})
        reachable = observed.get('reachable') is True
    else:
        binding = resolve_nic_for_ip(profile['device_ip']) or {}
        source, index = (binding.get('source_ip'), binding.get('if_index'))
        status = relayqos.read_qos(profile['device_ip'], 0, 'status', source_ip=source, if_index=index) if source else None
        reachable = bool(status and (not status.get('error')) and status.get('length_match'))
        observed = {'source_ip': source, 'if_index': index, 'status': status, 'captured_at': utc_now(), 'reachable': reachable}
    target = {**profile, 'source_ip': observed.get('source_ip'), 'if_index': observed.get('if_index'), 'observed': observed, 'captured_at': observed.get('captured_at'), 'correlation': 'operator_selected_ip'}
    if not reachable:
        return {'connected': False, 'error': 'NETWORK_UNREACHABLE', 'message': 'The selected Ethernet address did not return a valid status. Check the cable and PC network settings.', 'network_target': target, 'serial_identity': None}
    candidate = {**profile, 'network_target': target, 'transport': 'ETHERNET', 'identity_proven': False, 'serial_com': None}
    import secrets
    target['connection_token'] = secrets.token_urlsafe(24)
    SESSION.connect(candidate=candidate, identity={}, diagnostics={'network_target': target})
    return {**SESSION.state_document()['active'], 'identity_proven': False, 'rpc_connected': bool((observed.get('qos') or {}).get('connected') or observed.get('status')), 'captured_at': utc_now()}

def connection_inventory() -> dict:
    # One shared short-TTL refresh feeds the 1 Hz discovery poll and every live
    # transport resolution, instead of each paying for its own PowerShell pair.
    snap = INVENTORY_CACHE.get()
    if not snap.ok:
        if SESSION.device and SESSION.device.network_target is not None:
            return {"candidates": [], "network_profiles": list(NETWORK_CONNECTION_PROFILES.values()),
                    "active_candidate_id": SESSION.device.candidate_id,
                    "inventory": snap.meta(), "usb_inventory_error": snap.error,
                    "captured_at": utc_now()}
        raise RuntimeError(snap.error or "Windows USB/RNDIS inventory is unavailable")
    inv = snap.inventory
    # Session liveness (connection ownership): a valid inventory that no longer contains
    # the active device's ContainerId means the device was physically removed (USB pulled)
    # -- not a transient failure, since snap.ok proves the inventory spoke. Drop the
    # session so active_candidate_id goes null below and EVERY UI surface (Device Info,
    # header, product image, service-mode target) clears and auto-detect re-acquires.
    if SESSION.connected and not SESSION.still_present(inv):
        SESSION.clear()
    _schedule_identity_probes(inv)
    candidates = _build_connection_candidates(inv)
    with DISCOVERY_LOCK:
        DISCOVERY_LAST.update({
            "captured_at": snap.captured_at, "inventory": inv,
            "candidate_summary": {
                "candidates": len(candidates),
                "identified": sum(1 for c in candidates if c.get("identity_proven")),
            },
            "candidate_summary_at": time.monotonic(),
        })
    return {"platform": inv.get("platform"), "supported": inv.get("supported", False), "mode": "auto",
            "ground": HOST_CFG["ground"], "target_host_ip": HOST_CFG["host_rndis_ip"],
            "target_prefix": HOST_CFG["host_rndis_prefix"], "candidates": candidates,
            "network_profiles": list(NETWORK_CONNECTION_PROFILES.values()),
            "detected": bool(candidates), "active_candidate_id": SESSION.device.candidate_id if SESSION.connected else None,
            "inventory": snap.meta(),
            "serial_gate": SERIAL_GATE.status(),
            "captured_at": utc_now()}

def _select_connection_candidate(candidate_id: str | None) -> dict:
    doc = connection_inventory()
    candidates = doc["candidates"]
    if not candidates:
        raise RuntimeError("No Ascent USB interface is currently detected")
    if not candidate_id or candidate_id == "auto":
        # Product identity first; never prefer an RNDIS interface merely because BB RPC answers.
        best = candidates[0]
        if not best.get("identity_proven") and not best.get("vid_pid_evidentiary", True):
            # Nothing present has been shown to be an Ascent device.  Ambiguous or unproven
            # targets fail closed rather than being auto-selected.
            raise RuntimeError(
                "No Ascent device is proven present: the only USB interface detected is "
                f"{best.get('pnp_device_id') or 'an unproven gadget'}, which matches the "
                "recognition pattern but carries no evidentiary weight. Select it explicitly "
                "if that is genuinely the target.")
        return best
    for c in candidates:
        if c["id"] == candidate_id:
            return c
    raise ValueError("Selected Ascent device is no longer present")

def _configure_rndis_elevated(ifindex: int, *, rollback: bool = False) -> dict:
    """Configure -- or undo -- the host address on one RNDIS adapter, elevated.

    `rollback` removes ONLY an address this application recorded having added. The
    helper keeps an ownership marker precisely so that undoing our own change cannot
    destroy an address the operator configured themselves.
    """
    if platform.system().lower() != "windows":
        raise RuntimeError("Automatic RNDIS configuration is Windows-only")
    helper = RNDIS_HELPER.resolve()
    if not helper.is_file():
        raise RuntimeError(f"the RNDIS configuration helper is missing: {helper.name}")

    # -EncodedCommand, NOT an -ArgumentList array.
    #
    # TWO BUGS LIVED IN THE OLD FORM AND BOTH BIT ON THE BENCH.
    #
    # 1. `Start-Process -ArgumentList @(...)` joins the array with spaces and
    #    does NOT quote the elements. The installed helper lives at
    #    "C:\Program Files\Ascent Control\runtime\...", so PowerShell received
    #    `-File C:\Program` and never found the script. The development tree has
    #    no spaces in its path, which is why this only appeared once installed.
    #    `json.dumps` made it worse by doubling the backslashes -- PowerShell
    #    does not treat \\ as an escape, so the path was literally doubled.
    #
    # 2. Exit code -196608 (0xFFFD0000) is what powershell.exe returns for an
    #    unhandled terminating error in a -File script. It says the script threw
    #    and nothing about what it threw, which is not something an operator can
    #    act on.
    #
    # Base64 UTF-16LE sidesteps shell quoting entirely -- there is no command
    # line to get wrong -- and the wrapper captures the helper's own output to a
    # file this process can read back, so the REASON survives elevation.
    # -Verb RunAs and -RedirectStandardError are in different parameter sets in
    # Windows PowerShell 5.1, so redirecting from the inside is not a style
    # choice; it is the only way to get the text out.
    log = pathlib.Path(tempfile.gettempdir()) / f"ascent_rndis_{os.getpid()}_{int(time.time())}.log"
    inner_ps = (
        "$ErrorActionPreference='Stop';"
        f"$log={_ps_literal(str(log))};"
        "try{"
        f"  & {_ps_literal(str(helper))} -InterfaceIndex {int(ifindex)}"
        f"{' -Rollback' if rollback else ''} *>&1 | Out-File -FilePath $log -Encoding utf8;"
        "  exit 0"
        "}catch{"
        "  $_.ToString() | Out-File -FilePath $log -Encoding utf8;"
        "  exit 1"
        "}")
    enc = base64.b64encode(inner_ps.encode("utf-16-le")).decode("ascii")

    outer = ("try{$p=Start-Process -FilePath 'powershell.exe' -Verb RunAs -Wait "
             "-PassThru -WindowStyle Hidden -ArgumentList "
             "'-NoProfile','-ExecutionPolicy','Bypass','-EncodedCommand','" + enc + "';"
             "\"rc=$($p.ExitCode)\"}"
             "catch{if($_.Exception.Message -match 'cancell?ed'){'rc=DECLINED'}"
             "else{\"rc=ERR $($_.Exception.Message)\"}}")
    try:
        cp = subprocess.run(["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
                             "-Command", outer],
                            capture_output=True, text=True, timeout=180,
                            **_hidden_subprocess_kwargs())
        detail = ""
        try:
            if log.exists():
                # utf-8-SIG: PowerShell 5.1's `Out-File -Encoding utf8` writes a
                # BOM, and str.strip() does not remove \ufeff -- it would have
                # ridden along at the front of the message shown to the operator.
                detail = log.read_text(encoding="utf-8-sig", errors="replace").strip()
        except OSError:
            detail = ""
    finally:
        try:
            log.unlink()
        except OSError:
            pass

    tail = (cp.stdout or "").strip().splitlines()
    tail = tail[-1].strip() if tail else ""

    if tail == "rc=DECLINED":
        raise RuntimeError(
            "Windows needs Administrator to set an adapter address, and the "
            "elevation prompt was dismissed. Press ACTIVATE SERVICE MODE again "
            "and choose Yes.")
    m = re.search(r"rc=(-?\d+)", tail)
    if m is None:
        raise RuntimeError(
            "the elevated helper did not report a result"
            + (f": {sanitize_error(tail)}" if tail else ""))
    code = int(m.group(1))
    if code != 0:
        # The helper's OWN message, when there is one. An exit code alone is
        # the thing that made this take three attempts to diagnose.
        reason = sanitize_error(_first_error_line(detail)) if detail else ""
        raise RuntimeError(
            (f"Windows refused to configure the adapter: {reason}" if reason else
             f"the RNDIS configuration helper failed (exit {code})")
            + ". The address can also be set from NETWORK ADAPTERS."
            if not rollback else
            (f"the host address could not be rolled back: {reason}" if reason else
             f"RNDIS host configuration could not be rolled back (exit {code})"))
    return {"ok": True, "ifindex": int(ifindex), "rollback": bool(rollback),
            "exit_code": code, "helper_output": detail[:800] or None}

def _ps_literal(text: str) -> str:
    """A PowerShell single-quoted literal. Doubling ' is the only escape it has.

    Used instead of json.dumps, which emits C-style backslash escapes that
    PowerShell does not interpret -- turning every Windows path into a
    doubled-separator path that does not exist.
    """
    return "'" + str(text).replace("'", "''") + "'"

def _first_error_line(text: str) -> str:
    """The helper's message, without the PowerShell error decoration.

    A CategoryInfo block and a stack position are noise to an operator; the
    first non-empty line is the sentence that says what went wrong.
    """
    for line in (text or "").splitlines():
        line = line.strip()
        if line and not line.startswith(("+", "At ", "CategoryInfo",
                                         "FullyQualifiedErrorId")):
            return line[:300]
    return ""

def connect_host(candidate_id: str | None) -> dict:
    if candidate_id in NETWORK_CONNECTION_PROFILES:
        return connect_network_profile(candidate_id)
    if isinstance(candidate_id, str) and candidate_id.startswith("network:"):
        raise ValueError("Unknown Ethernet connection preset")
    c = _select_connection_candidate(candidate_id)
    ident = None
    bands = None
    bundle_report = None
    serial_error = None

    # Connection qualification is based on the exact vendor identity transaction.
    # When a serial interface exists, do identity + frequency in ONE PC-Tool-style
    # session so the frequency request advances to sequence 1.
    if c.get("serial_com"):
        try:
            bundle = serial_read_bundle(c["serial_com"], True, gate_owner="connect")
            ident = bundle["identity"]
            bands = bundle["rf_bands"]
            bundle_report = bundle["report"]
            serial_error = None
            with DISCOVERY_LOCK:
                DISCOVERY_IDENTITY[c["serial_pnp_device_id"]] = {
                    "probing": False, "identity": ident, "error": None,
                    "port": c["serial_com"], "last_seen": time.monotonic()
                }
            c["identity"] = ident
            c["identity_proven"] = True
            c["device_name"] = ident.get("device_name")
            c["device_image"] = ident.get("device_image")
        except Exception as exc:
            serial_error = sanitize_error(f"{type(exc).__name__}: {exc}")
    else:
        # A device without a serial configuration interface is not guessed from BB
        # RPC. It remains unqualified/read-only until another exact identity surface
        # is proven.
        serial_error = "No vendor serial identity interface is associated with this physical device."

    changed = False
    network_present = c.get("ifindex") is not None
    network_qualified = bool(ident and network_present and c.get("topology_qualified"))
    if ident and network_present and not network_qualified:
        c["network_qualification_error"] = "RNDIS interface is not ContainerId-correlated to the selected serial device."

    if network_qualified and not c.get("host_ip_ready"):
        try:
            _configure_rndis_elevated(c["ifindex"])
            changed = True
            # Waiting here only shortens time-to-first-Ground-read. It is no longer
            # load-bearing: the binding is re-resolved by ContainerId on every request,
            # so an address that lands after this window is picked up on its own
            # instead of leaving the session permanently unbound.
            deadline = time.time() + HOST_IP_WAIT_SECONDS
            while time.time() < deadline:
                time.sleep(0.4)
                current = _select_connection_candidate(c["id"])
                if current.get("host_ip_ready") and current.get("topology_qualified"):
                    current["identity"] = ident
                    current["identity_proven"] = True
                    current["device_name"] = ident.get("device_name")
                    current["device_image"] = ident.get("device_image")
                    c = current
                    break
            else:
                c["host_ip_pending"] = True
        except Exception as exc:
            c["network_config_error"] = sanitize_error(f"{type(exc).__name__}: {exc}")

    # Resolve the binding by ContainerId against current Windows state, not against
    # the candidate row captured before _configure_rndis_elevated ran.
    inventory_result = INVENTORY_CACHE.get(max_age=0.0)
    network_binding = _candidate_network_binding(c, inventory_result.inventory) if network_qualified else None
    source_ip = network_binding[0] if network_binding else None
    source_ifindex = network_binding[1] if network_binding else None
    # Ground RPC is an independent capability, but it is attempted only through the
    # RNDIS interface proven to share the selected serial device's ContainerId.
    if network_qualified and network_binding:
        try:
            status = bb_status(source_ip, source_ifindex)
            rpc_ok = True
            rpc_error = None
        except Exception as exc:
            status = None
            rpc_ok = False
            rpc_error = sanitize_error(f"{type(exc).__name__}: {exc}")
    else:
        status = None
        rpc_ok = False
        rpc_error = None if not network_present else "NETWORK_TOPOLOGY_UNQUALIFIED"

    identity_ok = bool(ident and ident.get("device_name"))
    if identity_ok:
        SESSION.connect(
            candidate=c, identity=ident, serial_bundle=bundle_report,
            ground_status=status if rpc_ok else None,
            diagnostics={"serial_error": serial_error,
                         "rpc_error": rpc_error,
                         "network_qualification_error": c.get("network_qualification_error"),
                         "network_config_error": c.get("network_config_error"),
                         "host_network_changed": changed},
        )
        # A read is only cached as a value when it produced one. A failed command-120
        # is recorded as an absent table with a reason and an age, so /api/rf-bands
        # retries it instead of pinning the failure for the session.
        if isinstance(bands, dict) and bands.get("available") and bands.get("state") == "ok":
            SESSION.record_rf_success(bands)
        elif isinstance(bands, dict):
            SESSION.record_rf_failure(bands)
        c = SESSION.live_candidate() or c
    else:
        SESSION.clear()
    return {
        "connected": identity_ok,
        "identity_proven": identity_ok,
        "error": None if identity_ok else "DEVICE_IDENTITY_FAILED",
        "message": None if identity_ok else "The Ascent USB interface was detected, but the vendor device identity query did not complete.",
        "host_network_configured": bool(network_qualified and network_binding),
        "host_network_changed": changed,
        "candidate": c,
        "ground": HOST_CFG["ground"],
        "rpc_status": status,
        "network_binding": ACTIVE_CONNECTION.get("network_binding"),
        "transport": SESSION.network_binding_detail() if identity_ok else None,
        "rpc_connected": rpc_ok,
        "rpc_error": rpc_error,
        "serial_identity": ident,
        "rf_bands": bands,
        "serial_error": serial_error,
        "captured_at": utc_now(),
    }

def _extract_com(name: str | None) -> str | None:
    return device_session_extract_com(name)

def caddx_serial_get(port: str, command: int) -> dict:
    """Compatibility helper. Command 120 is never sent as a fresh seq-0 session.

    Command 60 may be queried alone for background discovery. A frequency read must
    use serial_read_bundle(), which mirrors Caddx: FIND_DEVICE seq0 then GET_BB_FREQ
    seq1 in the same COM session.
    """
    if command != 60:
        raise ValueError("command 120 requires the same-session identity+frequency reader")
    return caddx_legacy_query(port, 60)

def _identity_from_bundle(report: dict, port: str) -> dict:
    info = report.get("device_info") or {}
    if info.get("state") != "ok":
        raise RuntimeError("vendor device identity query did not complete")
    dev = (info.get("device_name") or "").strip()
    if not dev:
        raise RuntimeError("vendor device-info response did not contain a device name")
    return {
        "available": True,
        "port": port.upper(),
        "device_name": dev,
        "firmware": info.get("firmware"),
        "hardware": info.get("hardware"),
        "serial_number": info.get("serial_number"),
        "sdk_version": info.get("sdk_version"),
        "cpu_temp": info.get("cpu_temp"),
        "status": info.get("status"),
        "detail": info.get("detail"),
        "receive_max_size": info.get("receive_max_size"),
        "rf_board_code": info.get("pc_tool_rf_board_code_candidate"),
        "rf_board_name": info.get("pc_tool_rf_board_name"),
        "rf_board_enum_defined": info.get("pc_tool_rf_board_enum_defined"),
        "device_image": device_image_for_name(dev),
        "device_image_provenance": device_image_provenance(dev),
        "protocol": {
            "request_seq": info.get("request_seq"),
            "response_seq": info.get("response_seq"),
            "payload_length": info.get("payload_length"),
        },
        "captured_at": report.get("captured_at") or utc_now(),
    }

def _frequency_from_bundle(report: dict, port: str) -> dict:
    bf = report.get("bb_frequency") or {}
    state = bf.get("state") or "not_run"
    if state == "ok":
        integrity = bf.get("integrity") or {}
        if integrity.get("method") != "vendor_md5_cmd115" or integrity.get("verified") is not True:
            return {"available": False, "state": "integrity_unverified", "port": port.upper(),
                    "source": "Caddx PC Tool serial GET_BB_FREQ", "command": 120,
                    "error_code": "BB_FREQ_INTEGRITY_UNVERIFIED"}
        data = bf.get("json")
        if not isinstance(data, dict):
            return {"available": False, "state": "response_parse_error", "port": port.upper(),
                    "source": "Caddx PC Tool serial GET_BB_FREQ", "command": 120,
                    "error_code": "BB_FREQ_JSON_MISSING"}
        return {
            "available": True,
            "state": "ok",
            "port": port.upper(),
            "command": 120,
            "source": "Caddx PC Tool serial GET_BB_FREQ",
            "data": data,
            "integrity": integrity,
            "captured_at": report.get("captured_at") or utc_now(),
            "protocol": {
                "request_seq": bf.get("request_seq"),
                "response_seq": bf.get("response_seq"),
                "payload_length": bf.get("payload_length"),
            },
        }
    if state == "unsupported_by_device_firmware":
        return {
            "available": False,
            "state": state,
            "port": port.upper(),
            "command": 120,
            "source": "Caddx PC Tool serial GET_BB_FREQ",
            "error_code": "GET_BB_FREQ_UNSUPPORTED",
            "message": "The connected firmware returned the vendor 'unknown cmd' response to GET_BB_FREQ.",
            "received_commands": bf.get("received_commands") or [],
        }
    return {
        "available": False,
        "state": state,
        "port": port.upper(),
        "command": 120,
        "source": "Caddx PC Tool serial GET_BB_FREQ",
        "error_code": "GET_BB_FREQ_NO_RESPONSE",
        "message": "The device did not return a usable persistent BB frequency table.",
        "received_commands": bf.get("received_commands") or [],
    }

def serial_read_bundle(port: str, include_frequency: bool = True,
                       gate_owner: str = "serial_read_bundle") -> dict:
    # Every COM session in this process passes through the one serial gate. It is
    # reentrant, so a caller that already holds it (connect, an RF read, the qualified
    # write's verified readback) is not blocked by its own hold.
    with SERIAL_GATE.hold(gate_owner, timeout=SERIAL_GATE_TIMEOUT):
        report = caddx_read_bundle(port, include_frequency, include_nics=False)
    ident = _identity_from_bundle(report, port)
    bands = _frequency_from_bundle(report, port) if include_frequency else None
    return {"identity": ident, "rf_bands": bands, "report": report}

def serial_identity(port: str) -> dict:
    # Background discovery only needs command 60 and therefore may use a one-command
    # session. Connect uses serial_read_bundle() so command 120 gets seq1 on the same
    # session as the identity request.
    with SERIAL_GATE.hold(f"serial_identity:{port}", timeout=SERIAL_GATE_TIMEOUT):
        d = caddx_serial_get(port, 60)
    info = d.get("device_info") or {}
    dev = (info.get("device_name") or "").strip()
    if not dev:
        raise RuntimeError("vendor device-info response did not contain a device name")
    return {"available": True, "port": port.upper(), "device_name": dev,
            "firmware": info.get("firmware"), "hardware": info.get("hardware"),
            "serial_number": info.get("serial_number"), "sdk_version": info.get("sdk_version"),
            "cpu_temp": info.get("cpu_temp"), "status": info.get("status"), "detail": info.get("detail"),
            "receive_max_size": info.get("receive_max_size"),
            "device_image": device_image_for_name(dev),
        "device_image_provenance": device_image_provenance(dev),
            "protocol": {k: d.get(k) for k in ("response_command","response_type","response_format","seq","payload_length","crc_ok","send_attempts","seen_frames")},
            "captured_at": utc_now()}

def active_serial_port() -> str | None:
    """The selected device's COM number, re-resolved by ContainerId when possible.

    A vendor restart can move the device to a different COM number, so the stored
    value is a fallback rather than the answer.
    """
    return SESSION.serial_port()

def _rf_response(entry: CachedRead, cache_state: str) -> dict:
    """Serve an RF read with its freshness attached.

    Response shape is unchanged for the UI; the freshness fields are additive.
    """
    doc = dict(entry.value if entry.ok else (entry.failure or {}))
    doc["cache_state"] = cache_state
    doc["freshness"] = entry.freshness()
    return doc

def rf_band_table(force_refresh: bool = False) -> dict:
    if not SESSION.connected:
        return {"available": False, "state": "no_connected_serial_device",
                "source": "Caddx PC Tool serial GET_BB_FREQ", "command": 120,
                "error_code": "NO_CONNECTED_SERIAL_DEVICE"}
    port = active_serial_port()
    if not port:
        return {"available": False, "state": "no_connected_serial_device",
                "source": "Caddx PC Tool serial GET_BB_FREQ", "command": 120,
                "error_code": "NO_CONNECTED_SERIAL_DEVICE"}
    entry = SESSION.rf_read
    if entry is not None and not SESSION.rf_needs_read(RF_SUCCESS_TTL, RF_FAILURE_BACKOFF, force_refresh):
        # Only a success is ever served from cache. A failure inside its backoff is
        # served as the failure it is -- an absent table with a reason and an age.
        return _rf_response(entry, "cached" if entry.ok else "failed_backoff")
    try:
        bundle = serial_read_bundle(port, True, gate_owner="rf_band_table")
    except SerialBusyError as e:
        return {"available": False, "state": "serial_busy",
                "source": "Caddx PC Tool serial GET_BB_FREQ", "port": port,
                "command": 120, "error_code": "SERIAL_BUSY",
                "message": sanitize_error(str(e)), "holder": e.holder}
    except Exception as e:
        failure = {"available": False, "state": "serial_read_failed",
                   "source": "Caddx PC Tool serial GET_BB_FREQ", "port": port,
                   "command": 120, "error_code": "SERIAL_READ_FAILED",
                   "message": sanitize_error(f"{type(e).__name__}: {e}")}
        return _rf_response(SESSION.record_rf_failure(failure), "fresh")
    # Exact identity is refreshed together with the table. If the USB device was
    # swapped on the same COM number, update the active identity rather than using
    # stale product metadata.
    SESSION.set_identity(bundle["identity"])
    SESSION.set_serial_bundle(bundle["report"])
    bands = bundle["rf_bands"] or {}
    if bands.get("available") and bands.get("state") == "ok":
        return _rf_response(SESSION.record_rf_success(bands), "fresh")
    return _rf_response(SESSION.record_rf_failure(bands), "fresh")

def _enrich_fresh_identity(info: dict, port: str) -> dict:
    """Convert a fresh command-60 payload into the active identity shape."""
    dev = (info.get("device_name") or "").strip()
    if not dev:
        raise CaddxWriteError("FRESH_IDENTITY_MISSING", "fresh command-60 identity did not contain a device name", stage="qualification")
    return {
        "available": True,
        "port": port.upper(),
        "device_name": dev,
        "firmware": info.get("firmware"),
        "hardware": info.get("hardware"),
        "serial_number": info.get("serial_number"),
        "sdk_version": info.get("sdk_version"),
        "cpu_temp": info.get("cpu_temp"),
        "status": info.get("status"),
        "detail": info.get("detail"),
        "receive_max_size": info.get("receive_max_size"),
        "rf_board_code": info.get("pc_tool_rf_board_code_candidate"),
        "rf_board_name": info.get("pc_tool_rf_board_name"),
        "rf_board_enum_defined": info.get("pc_tool_rf_board_enum_defined"),
        "device_image": device_image_for_name(dev),
        "device_image_provenance": device_image_provenance(dev),
        "captured_at": utc_now(),
    }

def _fresh_rf_reading(fresh: dict, port: str) -> dict:
    rf = fresh.get("rf") or {}
    return {
        "available": True,
        "state": "ok",
        "port": port.upper(),
        "command": 120,
        "source": "Caddx PC Tool serial GET_BB_FREQ",
        "data": rf.get("data"),
        "integrity": rf.get("integrity"),
        "captured_at": utc_now(),
        "protocol": {"request_seq": rf.get("request_seq"), "response_seq": rf.get("response_seq"),
                     "payload_length": len(rf.get("payload") or b"")},
    }

def rf_write_eligibility() -> dict:
    """Current cached eligibility is advisory; the write re-proves it fresh."""
    return qualify_rf_write(candidate=SESSION.live_candidate(),
                            identity=ACTIVE_CONNECTION.get("serial_identity"),
                            rf_reading=ACTIVE_CONNECTION.get("rf_bands"))

def rf_write_preview(body: dict) -> dict:
    """Validate proposed band edits and describe exactly what would change.

    Read-only: touches no device command. Its purpose is to let the confirmation
    dialog state the change precisely, and to reject invalid edits before the
    operator is asked to authorize a write. The write path re-validates everything
    from a fresh read regardless -- this is a convenience, never a gate.
    """
    import hashlib
    table = body.get("table")
    if not isinstance(table, dict):
        raise CaddxWriteError("RF_TABLE_REQUIRED", "table must be a JSON object", stage="request")
    reading = ACTIVE_CONNECTION.get("rf_bands") or {}
    baseline = reading.get("data")
    if not reading.get("available") or reading.get("state") != "ok" or not isinstance(baseline, dict):
        raise CaddxWriteError("FRESH_RF_READ_NOT_AVAILABLE",
                              "a verified live RF table is required before previewing a write",
                              stage="freshness")
    integrity = reading.get("integrity") or {}
    if integrity.get("verified") is not True:
        raise CaddxWriteError("FRESH_RF_MD5_NOT_VERIFIED",
                              "the live RF table is not MD5-verified; refresh before previewing",
                              stage="freshness")
    merged = merge_rf_table(table, baseline)
    raw = serialize_rf_table(merged, baseline)
    changes = diff_rf_table(baseline, merged)
    eligibility = rf_write_eligibility()
    return {
        "ok": True,
        "changed": not semantic_equal(merged, baseline),
        "changes": changes,
        "change_count": sum(len(c["changes"]) for c in changes),
        "expected_current_md5": (integrity.get("actual_md5") or "").lower(),
        "proposed_md5": hashlib.md5(raw).hexdigest(),
        "proposed_length": len(raw),
        "key_order_preserved": list(merged.keys()) == list(baseline.keys()),
        "preserved_keys": [k for k in baseline if not str(k).lower().startswith("band")],
        # Fields the device rewrites for itself on any write. Stated up front so the
        # confirmation dialog does not present the 1 -> 0 clear as an anomaly later.
        "device_owned_fields": [
            {"key": k, "current": baseline.get(k), "device_will_set": DEVICE_OWNED_EXPECTED.get(k)}
            for k in DEVICE_OWNED_KEYS if k in baseline
        ],
        "eligibility": eligibility,
        "reconnect": {"settle_s": RECONNECT_SETTLE, "poll_budget_s": RECONNECT_POLL_BUDGET,
                      "total_budget_s": RECONNECT_VERIFY_TIMEOUT},
        "captured_at": utc_now(),
    }

def _save_rf_backup(raw_payload: bytes, identity: dict) -> dict:
    import hashlib
    import re
    RF_BACKUPS_DIR.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    stable = "|".join(str(identity.get(k) or "") for k in ("device_name", "serial_number", "hardware"))
    key = hashlib.sha256(stable.encode("utf-8")).hexdigest()[:12]
    name = f"fpv_bb_freq_{stamp}_{key}.json"
    target = RF_BACKUPS_DIR / name
    # Exclusive create keeps backups immutable. A same-second collision gets a
    # monotonic suffix without replacing the first pre-write image.
    for n in range(100):
        t = target if n == 0 else RF_BACKUPS_DIR / f"fpv_bb_freq_{stamp}_{key}_{n:02d}.json"
        try:
            with t.open("xb") as f:
                f.write(bytes(raw_payload))
            target = t
            break
        except FileExistsError:
            continue
    else:
        raise CaddxWriteError("BACKUP_CREATE_FAILED", "could not allocate an immutable RF backup", stage="backup")
    return {"created": True, "file": target.name, "sha256": hashlib.sha256(raw_payload).hexdigest(),
            "md5": hashlib.md5(raw_payload).hexdigest(), "bytes": len(raw_payload)}

def _serial_vid_pid(candidate: dict) -> tuple[str | None, str | None]:
    return _vid_pid(candidate.get("serial_pnp_device_id"))

RECONNECT_SETTLE = VW_RECONNECT_SETTLE

RECONNECT_POLL_BUDGET = VW_RECONNECT_POLL_BUDGET

RECONNECT_VERIFY_TIMEOUT = RECONNECT_SETTLE + RECONNECT_POLL_BUDGET

_RECONNECT_FAST_WINDOW = 20.0

_RECONNECT_FAST_INTERVAL = 1.0

_RECONNECT_SLOW_INTERVAL = 2.5

def _find_reconnected_serial(container_id: str, expected_vid: str, expected_pid: str,
                             expected_identity: dict,
                             settle: float = RECONNECT_SETTLE,
                             timeout: float = RECONNECT_POLL_BUDGET,
                             progress: "Callable[[dict], None] | None" = None) -> tuple[str, dict]:
    """Follow only the same Windows USB ContainerId after the vendor restart.

    `timeout` is the poll budget measured from AFTER `settle`, matching Reopen_Json.
    """
    if progress:
        progress({"phase": "settling", "settle_s": settle,
                  "poll_budget_s": timeout, "elapsed_s": 0.0})
    if settle > 0:
        time.sleep(settle)
    started = time.monotonic()
    deadline = started + timeout
    last_error = None
    cid = str(container_id or "").strip().upper()
    while time.monotonic() < deadline:
        try:
            # The device is expected to disappear and return, so this must observe
            # current state rather than any cached inventory.
            inv = INVENTORY_CACHE.get(max_age=0.0).inventory
            if inv is None:
                raise RuntimeError("Windows USB/RNDIS inventory is unavailable")
            ports = []
            for u in inv.get("usb") or []:
                ucid = str(u.get("ContainerId") or "").strip().upper()
                if not cid or ucid != cid:
                    continue
                name = str(u.get("Name") or "")
                cls = str(u.get("PNPClass") or "").lower()
                port = _extract_com(name) if (cls == "ports" or "(COM" in name) else None
                if not port:
                    continue
                vid, pid = _vid_pid(str(u.get("PNPDeviceID") or ""))
                if vid == expected_vid and pid == expected_pid:
                    ports.append(port)
            # An exact ContainerId should expose at most one configuration serial
            # endpoint. Ambiguity fails closed rather than selecting the first port.
            ports = sorted(set(ports))
            if len(ports) > 1:
                raise CaddxWriteError("RECONNECT_SERIAL_AMBIGUOUS", "multiple serial interfaces match the committed device ContainerId", stage="verify")
            if ports:
                port = ports[0]
                try:
                    bundle = serial_read_bundle(port, True)
                    if not stable_identity_matches(expected_identity, bundle.get("identity") or {}):
                        raise CaddxWriteError("RECONNECT_IDENTITY_MISMATCH", "the reconnected serial interface did not match the pre-write device identity", stage="verify")
                    return port, bundle
                except CaddxWriteError:
                    raise
                except Exception as exc:
                    last_error = sanitize_error(f"{type(exc).__name__}: {exc}")
        except CaddxWriteError:
            raise
        except Exception as exc:
            last_error = sanitize_error(f"{type(exc).__name__}: {exc}")
        elapsed = time.monotonic() - started
        if progress:
            progress({"phase": "waiting", "settle_s": settle, "poll_budget_s": timeout,
                      "elapsed_s": round(elapsed, 1), "last_error": last_error})
        time.sleep(_RECONNECT_FAST_INTERVAL if elapsed < _RECONNECT_FAST_WINDOW
                   else _RECONNECT_SLOW_INTERVAL)
    raise CaddxWriteError("RECONNECT_VERIFY_TIMEOUT",
                          f"SET_BB_FREQ was acknowledged, but the exact physical device did not return with a verified RF table within {settle:.0f} s settle + {timeout:.0f} s poll budget",
                          stage="verify",
                          evidence={"last_error": last_error, "write_may_have_applied": True,
                                    "settle_s": settle, "poll_budget_s": timeout})

def _write_rf_band_table_locked(body: dict) -> dict:
    """Qualified stock-Caddx RF-table write + restart + verified readback."""
    import hashlib
    import re
    if body.get("apply") is not True:
        raise CaddxWriteError("APPLY_REQUIRED", "RF write requires apply=true", stage="request")
    expected_md5 = str(body.get("expected_current_md5") or "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{32}", expected_md5):
        raise CaddxWriteError("EXPECTED_MD5_REQUIRED", "expected_current_md5 must be the verified MD5 from the live command-120 table", stage="request")
    table = body.get("table")
    if not isinstance(table, dict):
        raise CaddxWriteError("RF_TABLE_REQUIRED", "table must be a JSON object", stage="request")

    candidate = dict(ACTIVE_CONNECTION.get("candidate") or {})
    expected_identity = dict(ACTIVE_CONNECTION.get("serial_identity") or {})
    port = candidate.get("serial_com")
    if not candidate or not expected_identity or not port:
        raise CaddxWriteError("NO_ACTIVE_QUALIFIED_DEVICE", "connect and identify the target device before writing", stage="qualification")
    container_id = str(candidate.get("serial_container_id") or "").strip().upper()
    vid, pid = _serial_vid_pid(candidate)
    if not container_id or not vid or not pid:
        raise CaddxWriteError("PHYSICAL_IDENTITY_INCOMPLETE", "serial ContainerId/VID/PID evidence is required before writing", stage="qualification")

    backup = None
    committed = False
    with VendorWriteSession(port) as sess:
        fresh = sess.fresh_identity_and_rf()
        fresh_identity = _enrich_fresh_identity(fresh["identity"], port)
        fresh_rf = _fresh_rf_reading(fresh, port)
        if not stable_identity_matches(expected_identity, fresh_identity):
            raise CaddxWriteError("FRESH_IDENTITY_MISMATCH", "the COM interface no longer belongs to the connected device identity", stage="qualification")
        eligibility = qualify_rf_write(candidate=candidate, identity=fresh_identity, rf_reading=fresh_rf)
        if not eligibility.get("eligible"):
            raise CaddxWriteError("OPERATION_NOT_QUALIFIED", "this exact device/firmware/hardware tuple is not qualified for persistent RF-table writes", stage="qualification", evidence=eligibility)
        actual_md5 = ((fresh_rf.get("integrity") or {}).get("actual_md5") or "").lower()
        if actual_md5 != expected_md5:
            raise CaddxWriteError("STALE_RF_TABLE", "the live RF table changed since it was presented to the editor; refresh before writing", stage="freshness",
                                  evidence={"expected_md5": expected_md5, "actual_md5": actual_md5})
        baseline = fresh_rf.get("data") or {}
        # merge_rf_table starts from the live document, so baseline key order and any
        # unknown vendor field survive; only band arrays the caller edited change.
        merged = merge_rf_table(table, baseline)
        raw_new = serialize_rf_table(merged, baseline)
        changes = diff_rf_table(baseline, merged)
        if semantic_equal(merged, baseline):
            return {"ok": True, "changed": False, "verified": True, "message": "Requested RF table already matches the live device table.",
                    "eligibility": eligibility, "integrity": fresh_rf.get("integrity"),
                    "changes": changes}
        # Backup exact command-116 bytes before the first mutating command.
        backup = _save_rf_backup(fresh["rf"]["payload"], fresh_identity)
        transaction = sess.upload_and_commit_rf(raw_new)
        committed = True

    _set_write_progress(phase="rebooting", settle_s=RECONNECT_SETTLE,
                        poll_budget_s=RECONNECT_POLL_BUDGET, elapsed_s=0.0)
    try:
        new_port, verify_bundle = _find_reconnected_serial(
            container_id, vid, pid, fresh_identity,
            progress=lambda p: _set_write_progress(**p))
        verify_identity = verify_bundle.get("identity") or {}
        verify_rf = verify_bundle.get("rf_bands") or {}
        if not stable_identity_matches(fresh_identity, verify_identity):
            raise CaddxWriteError("READBACK_IDENTITY_MISMATCH", "readback came from a different physical identity", stage="verify",
                                  evidence={"write_may_have_applied": True})
        if not verify_rf.get("available") or verify_rf.get("state") != "ok" or (verify_rf.get("integrity") or {}).get("verified") is not True:
            raise CaddxWriteError("READBACK_NOT_VERIFIED", "device returned after commit, but the persistent RF readback was not MD5-verified", stage="verify",
                                  evidence={"write_may_have_applied": True})
        readback = verify_rf.get("data")
        # Compare against `merged` -- the exact document serialized onto the wire --
        # not the request body, which may name only the bands it edits.
        #
        # compare_readback excludes device-owned fields: the device clears
        # is_defalut 1 -> 0 on any write to /factory/fpv_bb_freq.json (bench
        # 2026-09-06, docs/PROTOCOL_SPEC.md section 8.1). It stays order-aware on
        # everything else. Byte length and MD5 are deliberately NOT compared across
        # the write -- the device re-serializes the file without indentation, so
        # they can never match even on a perfect write.
        comparison = compare_readback(readback, merged)
        if not comparison["match"]:
            raise CaddxWriteError("READBACK_MISMATCH", "persistent RF readback does not match the requested semantic table", stage="verify",
                                  evidence={"write_may_have_applied": True,
                                            "reason": comparison.get("reason"),
                                            "device_owned_fields": comparison.get("device_owned"),
                                            "requested_sha256": hashlib.sha256(json.dumps(merged, sort_keys=True).encode()).hexdigest(),
                                            "readback_sha256": hashlib.sha256(json.dumps(readback, sort_keys=True).encode()).hexdigest()})

        # Promote only the verified post-restart state into the session. The COM
        # number may have moved across the restart; it is re-resolved by ContainerId
        # from here on, so the stored fallback is updated to the observed port.
        SESSION.set_identity(verify_identity)
        SESSION.set_serial_bundle(verify_bundle.get("report"))
        SESSION.record_rf_success(verify_rf)
        if SESSION.device is not None:
            SESSION.device.last_known_serial_com = new_port
        INVENTORY_CACHE.invalidate()
        SESSION.live_candidate()
        return {"ok": True, "changed": True, "verified": True,
                "operation_id": "persistent_rf_table_write", "eligibility": eligibility,
                "backup": backup, "transaction": transaction,
                "readback": {"port": new_port, "integrity": verify_rf.get("integrity"),
                              "semantic_match": True,
                              "device_owned_fields": comparison.get("device_owned"),
                              "device_owned_unexpected": comparison.get("unexpected_device_owned"),
                              "data": readback},
                "captured_at": utc_now()}
    except CaddxWriteError as exc:
        ev = dict(exc.evidence or {})
        ev.setdefault("write_may_have_applied", committed)
        ev.setdefault("backup", backup)
        raise CaddxWriteError(exc.code, str(exc), stage=exc.stage, evidence=ev) from exc

def _sky_user_cfg_read(port: str, gate_owner: str = "sky_user_cfg_read") -> dict:
    with SERIAL_GATE.hold(gate_owner, timeout=SERIAL_GATE_TIMEOUT):
        with SkyUserCfgSession(port) as sess:
            sess.fresh_identity()
            return sess.read_user_cfg()

def sky_user_cfg_reading(refresh: bool = False) -> dict:
    """Typed read of the stored receiver slots for the connected device.

    Read-only.  Cached on ACTIVE_CONNECTION so eligibility and the page share one answer,
    and re-read on demand.
    """
    cached = ACTIVE_CONNECTION.get("sky_user_cfg")
    if cached and not refresh:
        return cached
    candidate = dict(ACTIVE_CONNECTION.get("candidate") or {})
    port = candidate.get("serial_com")
    if not port:
        doc = {"available": False, "supported": None, "state": "no_serial_transport",
               "labels": {"primary": SKY_LABEL_PRIMARY, "fallback": SKY_LABEL_FALLBACK},
               "message": "Connect to an Ascent device over its USB-C serial interface first.",
               "captured_at": utc_now()}
        return doc
    if DEVICE_OPERATION_STATE.get("active"):
        return {"available": False, "supported": None, "state": "device_busy",
                "labels": {"primary": SKY_LABEL_PRIMARY, "fallback": SKY_LABEL_FALLBACK},
                "message": "A device operation is in progress.", "captured_at": utc_now()}
    try:
        r = _sky_user_cfg_read(port)
        doc = {"available": True, "supported": True, "state": "ok", "port": port.upper(),
               "slots": r["slots"], "integrity": r["integrity"],
               "labels": {"primary": SKY_LABEL_PRIMARY, "fallback": SKY_LABEL_FALLBACK},
               "protocol": {"request_seq": r["request_seq"], "response_seq": r["response_seq"],
                            "payload_length": r["payload_length"],
                            "commands": {"read": 123, "commit": 124}},
               "captured_at": utc_now()}
    except SkyUserCfgError as exc:
        supported = False if exc.code == "TYPED_USER_CFG_UNSUPPORTED" else None
        message = ("This firmware does not implement the typed receiver-slot commands. "
                   "Stored PRIMARY and FALLBACK values cannot be read, and nothing may be "
                   "shown in their place."
                   if supported is False else sanitize_error(str(exc)))
        doc = {"available": False, "supported": supported, "state": "unsupported" if supported is False else "error",
               "port": port.upper(), "error": exc.code, "stage": exc.stage, "message": message,
               "labels": {"primary": SKY_LABEL_PRIMARY, "fallback": SKY_LABEL_FALLBACK},
               "evidence": exc.evidence, "captured_at": utc_now()}
    except Exception as exc:
        doc = {"available": False, "supported": None, "state": "error", "port": port.upper(),
               "error": "USER_CFG_READ_FAILED",
               "labels": {"primary": SKY_LABEL_PRIMARY, "fallback": SKY_LABEL_FALLBACK},
               "message": sanitize_error(f"{type(exc).__name__}: {exc}"), "captured_at": utc_now()}
    ACTIVE_CONNECTION["sky_user_cfg"] = doc
    return doc

def _sky_candidate_count() -> int | None:
    """How many Ascent serial interfaces are present.  Provisioning is one unit at a time:
    Sky units are indistinguishable by USB descriptor, so two present is ambiguity."""
    try:
        doc = connection_inventory()
    except Exception:
        return None
    return sum(1 for c in doc.get("candidates") or [] if c.get("serial_com"))

def sky_user_cfg_eligibility() -> dict:
    """Cached eligibility is advisory; the commit re-proves it from a fresh read."""
    return qualify_user_cfg_write(candidate=SESSION.live_candidate(),
                                  identity=ACTIVE_CONNECTION.get("serial_identity"),
                                  user_cfg_reading=ACTIVE_CONNECTION.get("sky_user_cfg"),
                                  candidate_count=_sky_candidate_count())

def _sky_slots_from_body(body: dict) -> tuple[bytes, bytes]:
    primary = body.get("primary_receiver_bb_id")
    fallback = body.get("fallback_receiver_bb_id")
    if primary is None:
        raise SkyUserCfgError("PRIMARY_REQUIRED",
                              f"{SKY_LABEL_PRIMARY} is required", stage="request")
    if fallback is None:
        raise SkyUserCfgError("FALLBACK_REQUIRED",
                              f"{SKY_LABEL_FALLBACK} is required. To provision a unit with no "
                              f"distinct fallback, set it equal to the {SKY_LABEL_PRIMARY}.",
                              stage="request")
    return sky_parse_bb_id(primary), sky_parse_bb_id(fallback)

def sky_user_cfg_write_preview(body: dict) -> dict:
    """Describe exactly what a commit would change.  Touches no device command."""
    p, f = _sky_slots_from_body(body)
    reading = ACTIVE_CONNECTION.get("sky_user_cfg") or {}
    if not reading.get("available") or reading.get("state") != "ok":
        raise SkyUserCfgError("TYPED_USER_CFG_READ_NOT_AVAILABLE",
                              "a verified typed read of the stored slots is required before "
                              "previewing a commit", stage="preview")
    slots = reading.get("slots") or {}
    document = build_user_cfg_document(p, f)
    changes = []
    for label, key, current, proposed in (
        (SKY_LABEL_PRIMARY, "primary_receiver_bb_id", slots.get("primary_receiver_bb_id"), sky_format_bb_id(p)),
        (SKY_LABEL_FALLBACK, "fallback_receiver_bb_id", slots.get("fallback_receiver_bb_id"), sky_format_bb_id(f)),
    ):
        changes.append({"label": label, "field": key, "current": current, "proposed": proposed,
                        "changes": current != proposed,
                        "creates_slot": current is None})
    return {
        "operation_id": SKY_USER_CFG_OPERATION_ID,
        "target": "/factory/user_cfg.json",
        "changes": changes,
        "any_change": any(c["changes"] for c in changes),
        "fallback_equals_primary": p == f,
        "document_length": len(document),
        "document_md5": hashlib.md5(document).hexdigest(),
        "eligibility": sky_user_cfg_eligibility(),
        "effect": ("The commit persists both slots immediately and does not reboot the device. "
                   "The new PRIMARY becomes the boot candidate at the next power cycle."),
        "captured_at": utc_now(),
    }

def _write_sky_user_cfg_locked(body: dict) -> dict:
    if body.get("apply") is not True:
        raise SkyUserCfgError("APPLY_REQUIRED", "a receiver-slot commit requires apply=true", stage="request")
    p, f = _sky_slots_from_body(body)

    candidate = dict(ACTIVE_CONNECTION.get("candidate") or {})
    expected_identity = dict(ACTIVE_CONNECTION.get("serial_identity") or {})
    port = candidate.get("serial_com")
    if not candidate or not expected_identity or not port:
        raise SkyUserCfgError("NO_ACTIVE_QUALIFIED_DEVICE",
                              "connect and identify the target device before provisioning",
                              stage="qualification")
    if not str(candidate.get("serial_container_id") or "").strip():
        raise SkyUserCfgError("PHYSICAL_IDENTITY_INCOMPLETE",
                              "serial ContainerId evidence is required before provisioning",
                              stage="qualification")

    count = _sky_candidate_count()
    with SkyUserCfgSession(port) as sess:
        fresh_identity = sess.fresh_identity()
        if not stable_identity_matches(expected_identity, fresh_identity):
            raise SkyUserCfgError("FRESH_IDENTITY_MISMATCH",
                                  "the COM interface no longer belongs to the connected device identity",
                                  stage="qualification")
        before = sess.read_user_cfg()
        fresh_reading = {"available": True, "supported": True, "state": "ok",
                          "slots": before["slots"], "integrity": before["integrity"]}
        eligibility = qualify_user_cfg_write(candidate=candidate, identity=fresh_identity,
                                             user_cfg_reading=fresh_reading,
                                             candidate_count=count)
        if not eligibility.get("eligible"):
            raise SkyUserCfgError("OPERATION_NOT_QUALIFIED",
                                  "this device is not qualified for receiver-slot provisioning",
                                  stage="qualification", evidence=eligibility)

        backup = _save_sky_user_cfg_backup(before["slots"], fresh_identity)
        _set_write_progress(phase="committing")
        document = build_user_cfg_document(p, f)
        try:
            commit = sess.upload_and_commit(document)
        finally:
            # Stale from the moment the transfer starts, not from the moment it succeeds: a
            # failed commit may still have applied. Only a fresh MD5-verified read may clear
            # this. Same rule as the RF panel (CLAUDE.md, RF bench 2026-09-06).
            ACTIVE_CONNECTION["sky_user_cfg"] = {
                "available": False, "supported": True, "state": "stale_after_write",
                "port": port.upper(),
                "labels": {"primary": SKY_LABEL_PRIMARY, "fallback": SKY_LABEL_FALLBACK},
                "message": ("A receiver-slot write was attempted. The stored values shown before "
                            "it are no longer known to be current; a fresh verified read is "
                            "required, and a failed write may still have applied."),
                "captured_at": utc_now(),
            }
        # No reboot, no reconnect: the commit only persists a file, so the same session
        # reads it straight back.
        _set_write_progress(phase="verifying")
        after = sess.read_user_cfg()
        verdict = sky_compare_readback(after["slots"], p, f)

    ACTIVE_CONNECTION["sky_user_cfg"] = {
        "available": True, "supported": True, "state": "ok", "port": port.upper(),
        "slots": after["slots"], "integrity": after["integrity"],
        "labels": {"primary": SKY_LABEL_PRIMARY, "fallback": SKY_LABEL_FALLBACK},
        "captured_at": utc_now(),
    }
    if not verdict["match"]:
        raise SkyUserCfgError("READBACK_MISMATCH",
                              "the commit was acknowledged but the readback does not match",
                              stage="verify",
                              evidence={"readback": verdict, "backup": backup,
                                        "integrity": after["integrity"]})
    return {
        "ok": True,
        "operation_id": SKY_USER_CFG_OPERATION_ID,
        "target": "/factory/user_cfg.json",
        "before": before["slots"],
        "after": after["slots"],
        "readback": verdict,
        "readback_integrity": after["integrity"],
        "commit": commit,
        "backup": backup,
        "rebooted": False,
        "reboot_required_for_effect": True,
        "message": ("Receiver slots written and verified. Power-cycle the aircraft for the new "
                    "PRIMARY to become the boot candidate."),
        "captured_at": utc_now(),
    }

def _save_sky_user_cfg_backup(slots: dict, identity: dict, *,
                              transport: str = "usb_c_serial",
                              stable_key: str | None = None,
                              identity_fields: tuple = ("device_name", "firmware", "hardware", "serial_number")) -> dict:
    """Timestamped, immutable pre-commit image of the two stored slots.

    `stable_key` lets the USB-C/RNDIS route key its backups on the unit's own BB ID, which is
    the only per-unit identifier a Sky has; the serial route has no access to it and falls
    back to the raw command-60 identity fields.
    """
    USER_CFG_BACKUPS_DIR.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    stable = stable_key or "|".join(str(identity.get(k) or "")
                                    for k in ("device_name", "serial_number", "hardware"))
    key = hashlib.sha256(stable.encode("utf-8")).hexdigest()[:12]
    payload = json.dumps({
        "captured_at": utc_now(),
        "transport": transport,
        "identity": {k: identity.get(k) for k in identity_fields},
        "labels": {"primary": SKY_LABEL_PRIMARY, "fallback": SKY_LABEL_FALLBACK},
        "primary_receiver_bb_id": slots.get("primary_receiver_bb_id"),
        "fallback_receiver_bb_id": slots.get("fallback_receiver_bb_id"),
        "save_candidate_position": slots.get("save_candidate_position"),
        "raw_text": slots.get("raw_text"),
        "md5": slots.get("md5"),
    }, indent=2).encode("utf-8")
    for n in range(100):
        name = f"user_cfg_{stamp}_{key}.json" if n == 0 else f"user_cfg_{stamp}_{key}_{n:02d}.json"
        t = USER_CFG_BACKUPS_DIR / name
        try:
            with t.open("xb") as fh:
                fh.write(payload)
            return {"created": True, "file": t.name, "bytes": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest()}
        except FileExistsError:
            continue
    raise SkyUserCfgError("BACKUP_CREATE_FAILED",
                          "could not allocate an immutable receiver-slot backup", stage="backup")

def _sky_rndis_adapters() -> list | None:
    """Ascent-recognised RNDIS adapters currently present, or None if unknowable.

    Recognition is by the shared VID pattern.  That is recognition only: the Sky's RNDIS
    personality is literally 1D6B:0002, the stock Linux Foundation gadget ID, which carries no
    evidentiary weight (CLAUDE.md).  What proves the peer is an Ascent Sky is its answer -
    the baseband RPC BB ID and the provisioning service's own CRC-valid reply - never the VID.
    """
    try:
        inv = windows_usb_inventory()
    except Exception:
        return None
    if not inv.get("supported"):
        return None
    out = []
    for row in inv.get("network") or []:
        if not isinstance(row, dict):
            continue
        pnp = str(row.get("PnPDeviceID") or "")
        if pnp and re.search(VID_PNP_RE, pnp, re.IGNORECASE):
            out.append(row)
    return out

def _sky_rndis_binding(row: dict) -> tuple:
    """(binding, rejections) for one adapter: the host-side IPv4 and ifIndex to bind."""
    rejections = []
    try:
        ifindex = int(row.get("ifIndex"))
    except Exception:
        return None, [{"reason": "ifindex_unavailable"}]
    if ifindex <= 0:
        return None, [{"reason": "ifindex_unavailable"}]
    for r in device_session_ipv4_rows(row.get("IPv4")):
        ip = str(r.get("IPAddress") or "")
        try:
            prefix = int(r.get("PrefixLength") or -1)
        except Exception:
            prefix = -1
        state = str(r.get("AddressState") or "").strip().lower()
        if not ip.startswith("192.168.3.") or ip == SKY_RNDIS_DEVICE_ADDR or prefix != 24:
            continue
        if state in UNUSABLE_ADDRESS_STATES:
            rejections.append({"ip": ip, "address_state": r.get("AddressState")})
            continue
        return (ip, ifindex), rejections
    return None, rejections or [{"reason": "no_host_address_on_device_subnet"}]

def _sky_rndis_transport() -> dict:
    """Resolve the one adapter this operation may use, or say exactly why it cannot."""
    adapters = _sky_rndis_adapters()
    doc = {"transport": SKY_RNDIS_TRANSPORT, "adapters": None, "binding": None,
           "rejections": [], "device_addr": SKY_RNDIS_DEVICE_ADDR, "port": SKY_RNDIS_PORT,
           "state": "unresolved", "message": None}
    if adapters is None:
        doc["state"] = "inventory_unavailable"
        doc["message"] = ("Windows USB/RNDIS inventory is unavailable. USB-C provisioning is "
                          "Windows-only; WSL2 is NAT'd and cannot reach the device subnet.")
        return doc
    doc["adapters"] = len(adapters)
    if not adapters:
        doc["state"] = "no_adapter"
        doc["message"] = ("No Ascent RNDIS interface is present. Switch the unit's USB gadget "
                          "to RNDIS first; its CDC COM port disappears when you do.")
        return doc
    if len(adapters) > 1:
        doc["state"] = "ambiguous"
        doc["message"] = ("More than one Ascent RNDIS interface is present. Every Ascent RNDIS "
                          "device answers on the same device-side address, so this is ambiguous "
                          "and provisioning is one unit at a time.")
        return doc
    binding, rejections = _sky_rndis_binding(adapters[0])
    doc["rejections"] = rejections
    doc["adapter"] = {k: adapters[0].get(k) for k in ("Name", "InterfaceDescription", "ifIndex", "Status")}
    if not binding:
        doc["state"] = "host_address_pending"
        doc["message"] = ("The Ascent RNDIS adapter has no usable host address on 192.168.3.0/24 "
                          "yet.")
        return doc
    doc["binding"] = {"source_ip": binding[0], "ifindex": binding[1]}
    doc["state"] = "resolved"
    return doc

def _sky_rndis_session(transport: dict) -> SkyRndisSession:
    b = (transport or {}).get("binding") or {}
    if not b.get("source_ip") or not b.get("ifindex"):
        raise SkyRndisProvisionError("RNDIS_BINDING_UNRESOLVED",
                                     (transport or {}).get("message")
                                     or "no correlated Ascent RNDIS adapter is available",
                                     stage="transport", evidence={"transport": transport})
    return SkyRndisSession(host=SKY_RNDIS_DEVICE_ADDR, port=SKY_RNDIS_PORT,
                           source_ip=b["source_ip"], if_index=b["ifindex"])

def sky_rndis_probe() -> dict:
    """Read-only: what is reachable over USB-C right now, and which unit is it.

    This is the endpoint that answers "is the service present" honestly on stock firmware:
    a stock Sky refuses the connection, which reports as unsupported rather than as an error.
    """
    transport = _sky_rndis_transport()
    doc = {"transport": transport, "identity": None, "service": None, "captured_at": utc_now()}
    if transport["state"] != "resolved":
        doc["available"] = False
        return doc
    b = transport["binding"]
    doc["identity"] = sky_rndis_identity(host=SKY_RNDIS_DEVICE_ADDR,
                                         source_ip=b["source_ip"], if_index=b["ifindex"])
    try:
        with _sky_rndis_session(transport) as sess:
            r = sess.read_slots()
        doc["service"] = {"present": True, "revision": r["service_revision"],
                          "integrity": r["integrity"]}
        doc["available"] = True
    except SkyRndisProvisionError as exc:
        doc["service"] = {"present": False, "error": exc.code, "message": sanitize_error(str(exc))}
        doc["available"] = False
    return doc

def sky_rndis_reading(refresh: bool = False) -> dict:
    """Typed read of the stored receiver slots over USB-C.

    Firmware without the service refuses the connection.  That surfaces as
    PROVISIONING_SERVICE_UNAVAILABLE, `supported` is false, and the page must show **nothing**
    in the PRIMARY and FALLBACK fields.  It must never fall back to the live peer.
    """
    cached = ACTIVE_CONNECTION.get("sky_rndis_user_cfg")
    if cached and not refresh:
        return cached
    labels = {"primary": SKY_LABEL_PRIMARY, "fallback": SKY_LABEL_FALLBACK}
    if DEVICE_OPERATION_STATE.get("active"):
        return {"available": False, "supported": None, "state": "device_busy", "labels": labels,
                "transport": SKY_RNDIS_TRANSPORT,
                "message": "A device operation is in progress.", "captured_at": utc_now()}
    transport = _sky_rndis_transport()
    if transport["state"] != "resolved":
        return {"available": False, "supported": None, "state": transport["state"],
                "labels": labels, "transport": SKY_RNDIS_TRANSPORT,
                "message": transport["message"], "evidence": transport,
                "captured_at": utc_now()}
    try:
        with _sky_rndis_session(transport) as sess:
            r = sess.read_slots()
        doc = {"available": True, "supported": True, "state": "ok",
               "transport": SKY_RNDIS_TRANSPORT, "labels": labels,
               "slots": r["slots"], "integrity": r["integrity"],
               "device_reported": r["device_reported"],
               "parse_disagreement": r["parse_disagreement"],
               "service_revision": r["service_revision"],
               "protocol": {"payload_length": r["payload_length"],
                            "operations": {"read": "GET_SLOTS", "commit": "SET_SLOTS"},
                            "endpoint": f"{SKY_RNDIS_DEVICE_ADDR}:{SKY_RNDIS_PORT}"},
               "captured_at": utc_now()}
    except SkyRndisProvisionError as exc:
        unsupported = exc.code == "PROVISIONING_SERVICE_UNAVAILABLE"
        doc = {"available": False, "supported": False if unsupported else None,
               "state": "unsupported" if unsupported else "error",
               "transport": SKY_RNDIS_TRANSPORT, "labels": labels,
               "error": exc.code, "stage": exc.stage,
               "message": ("This firmware does not carry the USB-C receiver-slot provisioning "
                           "service. Stored PRIMARY and FALLBACK values cannot be read, and "
                           "nothing may be shown in their place."
                           if unsupported else sanitize_error(str(exc))),
               "evidence": exc.evidence, "captured_at": utc_now()}
    except Exception as exc:
        doc = {"available": False, "supported": None, "state": "error",
               "transport": SKY_RNDIS_TRANSPORT, "labels": labels,
               "error": "USER_CFG_READ_FAILED",
               "message": sanitize_error(f"{type(exc).__name__}: {exc}"), "captured_at": utc_now()}
    ACTIVE_CONNECTION["sky_rndis_user_cfg"] = doc
    return doc

def sky_rndis_eligibility() -> dict:
    """Cached eligibility is advisory; the commit re-proves all of it from a fresh read."""
    transport = _sky_rndis_transport()
    binding = None
    if transport.get("binding"):
        binding = (transport["binding"]["source_ip"], transport["binding"]["ifindex"])
    identity = None
    if binding:
        identity = sky_rndis_identity(host=SKY_RNDIS_DEVICE_ADDR,
                                      source_ip=binding[0], if_index=binding[1])
    doc = qualify_rndis_provisioning(
        adapters=([None] * transport["adapters"]) if transport.get("adapters") is not None else None,
        serial_interfaces=_sky_candidate_count(),
        binding=binding, identity=identity,
        reading=ACTIVE_CONNECTION.get("sky_rndis_user_cfg"))
    doc["transport_state"] = transport
    return doc

def sky_rndis_write_preview(body: dict) -> dict:
    """Describe exactly what a commit would change.  Touches no device command."""
    p, f = _sky_slots_from_body(body)
    reading = ACTIVE_CONNECTION.get("sky_rndis_user_cfg") or {}
    if not reading.get("available") or reading.get("state") != "ok":
        raise SkyRndisProvisionError("TYPED_USER_CFG_READ_NOT_AVAILABLE",
                                     "a verified typed read of the stored slots is required "
                                     "before previewing a commit", stage="preview")
    slots = reading.get("slots") or {}
    changes = []
    for label, key, current, proposed in (
        (SKY_LABEL_PRIMARY, "primary_receiver_bb_id", slots.get("primary_receiver_bb_id"), sky_format_bb_id(p)),
        (SKY_LABEL_FALLBACK, "fallback_receiver_bb_id", slots.get("fallback_receiver_bb_id"), sky_format_bb_id(f)),
    ):
        changes.append({"label": label, "field": key, "current": current, "proposed": proposed,
                        "changes": current != proposed, "creates_slot": current is None})
    return {
        "operation_id": SKY_RNDIS_OPERATION_ID,
        "transport": SKY_RNDIS_TRANSPORT,
        "target": "/factory/user_cfg.json",
        "changes": changes,
        "any_change": any(c["changes"] for c in changes),
        "fallback_equals_primary": p == f,
        "request_bytes": 32,
        "eligibility": sky_rndis_eligibility(),
        "effect": ("The commit sends only the two four-byte BB IDs; no document, path or "
                   "filename crosses the wire. The device rewrites its own live "
                   "/factory/user_cfg.json in place and verifies it before answering. It does "
                   "not reboot and does not disturb the link. The new PRIMARY becomes the boot "
                   "candidate at the next power cycle."),
        "captured_at": utc_now(),
    }

def _write_sky_rndis_locked(body: dict) -> dict:
    if body.get("apply") is not True:
        raise SkyRndisProvisionError("APPLY_REQUIRED", "a receiver-slot commit requires apply=true",
                                     stage="request")
    p, f = _sky_slots_from_body(body)

    transport = _sky_rndis_transport()
    if transport["state"] != "resolved":
        raise SkyRndisProvisionError("RNDIS_BINDING_UNRESOLVED",
                                     transport["message"] or "no usable Ascent RNDIS adapter",
                                     stage="qualification", evidence={"transport": transport})
    binding = (transport["binding"]["source_ip"], transport["binding"]["ifindex"])
    identity = sky_rndis_identity(host=SKY_RNDIS_DEVICE_ADDR,
                                  source_ip=binding[0], if_index=binding[1])
    expected_bb = str((body.get("expect_aircraft_bb_id") or "")).strip().upper() or None
    if expected_bb and identity.get("aircraft_bb_id") != expected_bb:
        raise SkyRndisProvisionError("AIRCRAFT_IDENTITY_MISMATCH",
                                     "the unit answering on this interface is not the one the "
                                     "request names", stage="qualification",
                                     evidence={"expected": expected_bb,
                                               "actual": identity.get("aircraft_bb_id")})

    with _sky_rndis_session(transport) as sess:
        before = sess.read_slots()
        fresh = {"available": True, "supported": True, "state": "ok",
                 "slots": before["slots"], "integrity": before["integrity"],
                 "parse_disagreement": before["parse_disagreement"],
                 "service_revision": before["service_revision"]}
        eligibility = qualify_rndis_provisioning(
            adapters=[None] * transport["adapters"], serial_interfaces=_sky_candidate_count(),
            binding=binding, identity=identity, reading=fresh)
        if not eligibility.get("eligible"):
            raise SkyRndisProvisionError("OPERATION_NOT_QUALIFIED",
                                         "this device is not qualified for receiver-slot "
                                         "provisioning over USB-C",
                                         stage="qualification", evidence=eligibility)

        backup = _save_sky_user_cfg_backup(
            before["slots"], identity, transport=SKY_RNDIS_TRANSPORT,
            stable_key=str(identity.get("aircraft_bb_id") or ""),
            identity_fields=("aircraft_bb_id", "host", "link_state_raw"))
        _set_write_progress(phase="committing")
        try:
            commit = sess.commit_slots(p, f)
        finally:
            # Stale from the moment the commit is sent, not from the moment it succeeds: a
            # failed commit may still have applied. Only a fresh CRC-verified read clears it.
            ACTIVE_CONNECTION["sky_rndis_user_cfg"] = {
                "available": False, "supported": True, "state": "stale_after_write",
                "transport": SKY_RNDIS_TRANSPORT,
                "labels": {"primary": SKY_LABEL_PRIMARY, "fallback": SKY_LABEL_FALLBACK},
                "message": ("A receiver-slot write was attempted. The stored values shown "
                            "before it are no longer known to be current; a fresh verified "
                            "read is required, and a failed write may still have applied."),
                "captured_at": utc_now(),
            }
        _set_write_progress(phase="verifying")
        after = sess.read_slots()

    verdict = sky_rndis_compare_readback(after["slots"], p, f)
    ACTIVE_CONNECTION["sky_rndis_user_cfg"] = {
        "available": True, "supported": True, "state": "ok",
        "transport": SKY_RNDIS_TRANSPORT,
        "labels": {"primary": SKY_LABEL_PRIMARY, "fallback": SKY_LABEL_FALLBACK},
        "slots": after["slots"], "integrity": after["integrity"],
        "device_reported": after["device_reported"],
        "parse_disagreement": after["parse_disagreement"],
        "service_revision": after["service_revision"],
        "captured_at": utc_now(),
    }
    if not commit["accepted"]:
        raise SkyRndisProvisionError(commit["status_code"], commit["detail"], stage="commit",
                                     evidence={"readback": verdict, "backup": backup,
                                               "device_status": commit["status"]})
    if not verdict["match"]:
        raise SkyRndisProvisionError("READBACK_MISMATCH",
                                     "the commit was acknowledged but the readback does not match",
                                     stage="verify",
                                     evidence={"readback": verdict, "backup": backup,
                                               "integrity": after["integrity"]})
    return {
        "ok": True,
        "operation_id": SKY_RNDIS_OPERATION_ID,
        "transport": SKY_RNDIS_TRANSPORT,
        "target": "/factory/user_cfg.json",
        "aircraft_bb_id": identity.get("aircraft_bb_id"),
        "before": before["slots"],
        "after": after["slots"],
        "readback": verdict,
        "readback_integrity": after["integrity"],
        "commit": commit,
        "backup": backup,
        "rebooted": False,
        "reboot_required_for_effect": True,
        "message": ("Receiver slots written and verified over USB-C. Power-cycle the aircraft "
                    "for the new PRIMARY to become the boot candidate."),
        "captured_at": utc_now(),
    }

def write_sky_rndis_slots(body: dict) -> dict:
    """Serialize the commit against every other device mutation.

    The serial gate is deliberately not held: in RNDIS mode the unit has no COM port, so
    there is no serial session to protect. The mutation lock is shared with every other
    write so an RF commit and a provisioning commit can never overlap.
    """
    if HOST_STATE.get("shutting_down"):
        raise SkyRndisProvisionError("HOST_SHUTTING_DOWN",
                                     "application shutdown is already in progress", stage="lifecycle")
    if not DEVICE_MUTATION_LOCK.acquire(blocking=False):
        raise SkyRndisProvisionError("DEVICE_BUSY", "another device mutation is already in progress",
                                     stage="lifecycle",
                                     evidence={"operation_state": dict(DEVICE_OPERATION_STATE)})
    DEVICE_OPERATION_STATE.update({"active": True, "operation_id": SKY_RNDIS_OPERATION_ID,
                                   "started_at": utc_now()})
    _set_write_progress(phase="starting")
    try:
        return _write_sky_rndis_locked(body)
    finally:
        DEVICE_OPERATION_STATE.update({"active": False, "operation_id": None, "started_at": None})
        _set_write_progress(phase="idle")
        DEVICE_MUTATION_LOCK.release()

def write_sky_user_cfg(body: dict) -> dict:
    """Serialize the commit against every other device mutation."""
    if HOST_STATE.get("shutting_down"):
        raise SkyUserCfgError("HOST_SHUTTING_DOWN", "application shutdown is already in progress",
                              stage="lifecycle")
    if not DEVICE_MUTATION_LOCK.acquire(blocking=False):
        raise SkyUserCfgError("DEVICE_BUSY", "another device mutation is already in progress",
                              stage="lifecycle",
                              evidence={"operation_state": dict(DEVICE_OPERATION_STATE)})
    DEVICE_OPERATION_STATE.update({"active": True, "operation_id": SKY_USER_CFG_OPERATION_ID,
                                   "started_at": utc_now()})
    _set_write_progress(phase="starting")
    try:
        SESSION.live_candidate()
        with SERIAL_GATE.hold("sky_user_cfg_write", timeout=SERIAL_GATE_TIMEOUT):
            return _write_sky_user_cfg_locked(body)
    finally:
        DEVICE_OPERATION_STATE.update({"active": False, "operation_id": None, "started_at": None})
        _set_write_progress(phase="idle")
        DEVICE_MUTATION_LOCK.release()

def _plan_target() -> dict:
    """The connected unit's hardware identity, for compatibility assessment only."""
    ident = ACTIVE_CONNECTION.get("serial_identity") or {}
    reading = ACTIVE_CONNECTION.get("rf_bands") or {}
    live = reading.get("data") if isinstance(reading.get("data"), dict) else None
    verified = (reading.get("available") is True and reading.get("state") == "ok"
                and (reading.get("integrity") or {}).get("verified") is True)
    return {
        "connected": bool(ident.get("device_name")),
        "device_name": ident.get("device_name"),
        "hardware": ident.get("hardware"),
        "rf_board_code": ident.get("rf_board_code"),
        "live_table_verified": verified,
        "live_bands": {k: v for k, v in (live or {}).items() if rf_band_plans.is_band_key(k)} if verified else None,
    }

def _rf_plan_api():
    return rf_plan_api.RfPlanApi(target=_plan_target, now=utc_now, store=rf_band_plans)

def rf_band_plans_document() -> dict:
    return _rf_plan_api().document()

def rf_band_plan_save(body: dict) -> dict:
    return _rf_plan_api().save(body)

def rf_band_plan_delete(body: dict) -> dict:
    return _rf_plan_api().delete(body)

def rf_band_plan_export(body: dict) -> dict:
    return _rf_plan_api().export(body)

def rf_band_plan_import(body: dict) -> dict:
    return _rf_plan_api().import_csv(body)

def write_rf_band_table(body: dict) -> dict:
    """Serialize all device mutations and expose explicit in-flight state."""
    if HOST_STATE.get("shutting_down"):
        raise CaddxWriteError("HOST_SHUTTING_DOWN", "application shutdown is already in progress", stage="lifecycle")
    if not DEVICE_MUTATION_LOCK.acquire(blocking=False):
        raise CaddxWriteError("DEVICE_BUSY", "another device mutation is already in progress", stage="lifecycle",
                              evidence={"operation_state": dict(DEVICE_OPERATION_STATE)})
    DEVICE_OPERATION_STATE.update({"active": True, "operation_id": "persistent_rf_table_write", "started_at": utc_now()})
    _set_write_progress(phase="starting")
    try:
        # Re-resolve the selected device's transport facts before the transaction
        # reads them, so the write starts from current Windows state rather than
        # whichever request last refreshed the mirror.
        SESSION.live_candidate()
        # The serial gate is the single mutual exclusion for COM access; the write
        # holds it across the commit and the reconnect/readback that follows.
        with SERIAL_GATE.hold("rf_table_write", timeout=SERIAL_GATE_TIMEOUT):
            return _write_rf_band_table_locked(body)
    finally:
        DEVICE_OPERATION_STATE.update({"active": False, "operation_id": None, "started_at": None})
        _set_write_progress(phase="idle")
        DEVICE_MUTATION_LOCK.release()

def _config_bb_id() -> str | None:
    """The connected unit's own BB ID, used to key its documents.

    Command 60 carries no BB ID; the only one a connected unit exposes is
    ground_local_bb_id from Ground RPC STATUS bytes 6..9, a RECEIVER identity
    (CLAUDE.md, Device identity). When there is none we fall back to the default
    profile and the document says which it used.
    """
    return (ACTIVE_CONNECTION.get("ground_status") or {}).get("local_bb_id")

def _config_role() -> str | None:
    dev = SESSION.device
    raw = (dev.identity or {}).get("device_name") if dev else None
    if not raw:
        return None
    return device_capability.classify(raw).get("role")

def _device_config_target() -> dict:
    candidate = SESSION.live_candidate() or {}
    identity = ACTIVE_CONNECTION.get("serial_identity") or {}
    return {"generation": SESSION.generation,
            "container_id": candidate.get("serial_container_id"),
            "port": candidate.get("serial_com"),
            "identity": {k: identity.get(k) for k in
                         ("device_name", "serial_number", "hardware", "firmware")}}

def _device_config_review_token(kind: str, document: dict, baseline: dict) -> str:
    material = {"kind": kind, "target": _device_config_target(),
                "profile": cfgstore.profile_key(_config_bb_id()),
                "document": hashlib.sha256(devcfg.serialize_document(document)).hexdigest(),
                "baseline": hashlib.sha256(devcfg.serialize_document(baseline)).hexdigest()}
    return hashlib.sha256(json.dumps(material, sort_keys=True).encode()).hexdigest()

def device_config_document(kind: str) -> dict:
    doc = cfgstore.get(kind, _config_bb_id())
    doc["eligibility"] = device_config_eligibility(kind)
    doc["target"] = _device_config_target()
    doc["vendor_oracle"] = "PC Tool D2.0.37 (PDB present); cross-checked against D2.0.51"
    return doc

def device_config_eligibility(kind: str) -> dict:
    return devcfg.qualify_device_config_write(
        kind,
        candidate=SESSION.live_candidate(),
        identity=ACTIVE_CONNECTION.get("serial_identity"),
        role=_config_role())

def device_config_write_preview(kind: str, body: dict) -> dict:
    """Validate a proposed edit and state exactly what would change. No device command."""
    edits = body.get("document")
    if not isinstance(edits, dict):
        raise devcfg.DeviceConfigError("DOCUMENT_REQUIRED",
                                       "document must be a JSON object", stage="request")
    bb = _config_bb_id()
    baseline = cfgstore.get(kind, bb)["document"]
    merged = devcfg.merge_document(edits, baseline)
    validation = cfgstore.KINDS[kind]["validate"](merged)   # raises on structure
    if kind == "rc" and (devcfg.rc_slot_disabled(merged, "slot0") or not merged.get("slot0")):
        raise devcfg.DeviceConfigError("ZOOM_CHANNEL_REQUIRED",
                                       "The vendor RC upload requires an assigned zoom control channel.", stage="review")
    raw = devcfg.serialize_document(merged)
    return {
        "ok": True,
        "kind": kind,
        "profile": cfgstore.profile_key(bb),
        "baseline": baseline,
        "merged": merged,
        "target": _device_config_target(),
        "review_token": _device_config_review_token(kind, merged, baseline),
        "diff": devcfg.diff_document(baseline, merged),
        "warnings": validation.get("warnings", []),
        "payload_length": len(raw),
        "payload_md5": hashlib.md5(raw).hexdigest(),
        "remote_path": cfgstore.KINDS[kind]["remote_path"],
        "eligibility": device_config_eligibility(kind),
        "lane": {
            "commands": [115, 116, 117, 3],
            "commit_opcode": None,
            "note": "The file transfer is the commit -- this lane has no 121. A cmd-3 "
                    "reboot and the standard reconnect follow the 117 ACK.",
        },
        "readback_supported": False,
        "readback_reason": cfgstore.get(kind, bb)["readback_reason"],
    }

def save_device_config(kind: str, body: dict) -> dict:
    """Store an edit locally. Host-local only -- no device command, no device lock.

    This is the vendor's own shape: CamHubCtrl writes its JSON to disk and a separate
    action sends it. Saving is therefore always available, including with no device
    attached, and never implies anything reached hardware.
    """
    edits = body.get("document")
    if not isinstance(edits, dict):
        raise devcfg.DeviceConfigError("DOCUMENT_REQUIRED",
                                       "document must be a JSON object", stage="request")
    bb = _config_bb_id()
    baseline = cfgstore.get(kind, bb)["document"]
    merged = devcfg.merge_document(edits, baseline)
    cfgstore.put(kind, merged, bb_id=bb)
    return device_config_document(kind)

def reset_device_config(kind: str) -> dict:
    cfgstore.reset_to_template(kind, bb_id=_config_bb_id())
    return device_config_document(kind)

def _write_device_config_locked(kind: str, body: dict) -> dict:
    meta = cfgstore.KINDS[kind]
    bb = _config_bb_id()
    stored = cfgstore.get(kind, bb)

    if body.get("apply") is not True:
        raise devcfg.DeviceConfigError("APPLY_REQUIRED",
                                       "the request must set apply=true", stage="request")

    edits = body.get("document")
    document = devcfg.merge_document(edits, stored["document"]) if isinstance(edits, dict) \
        else stored["document"]
    meta["validate"](document)
    raw = devcfg.serialize_document(document)
    review_token = _device_config_review_token(kind, document, stored["document"])
    if body.get("review_token") != review_token:
        raise devcfg.DeviceConfigError("CONFIG_REVIEW_STALE",
                                       "Review this configuration again: the target, draft or saved baseline changed.",
                                       stage="review")
    generation = SESSION.generation
    if kind == "rc" and (devcfg.rc_slot_disabled(document, "slot0") or not document.get("slot0")):
        raise devcfg.DeviceConfigError("ZOOM_CHANNEL_REQUIRED",
                                       "The vendor RC upload requires an assigned zoom control channel.",
                                       stage="review")

    # Re-prove eligibility against current state; the cached answer is advisory.
    elig = device_config_eligibility(kind)
    if not elig["eligible"]:
        raise devcfg.DeviceConfigError("OPERATION_NOT_QUALIFIED",
                                       "this device is not qualified for " + meta["label"]
                                       + " configuration",
                                       stage="qualify", evidence=elig)

    candidate = SESSION.live_candidate() or {}
    port = candidate.get("serial_com")
    if not port:
        raise devcfg.DeviceConfigError("SERIAL_TRANSPORT_MISSING",
                                       "no serial port for the selected device",
                                       stage="qualify")

    expected_identity = dict(ACTIVE_CONNECTION.get("serial_identity") or {})
    container_id = candidate.get("serial_container_id")
    vid, pid = _vid_pid(str(candidate.get("serial_pnp_device_id") or ""))

    _set_write_progress(phase="connecting", port=port)
    with VendorWriteSession(port) as session:
        # Do not follow a COM number onto a different physical unit. Identity only --
        # this lane must not require an RF read (see fresh_identity).
        actual = session.fresh_identity()
        if not stable_identity_matches(expected_identity, actual):
            raise devcfg.DeviceConfigError(
                "FRESH_IDENTITY_MISMATCH",
                "the device on this port is not the one this session identified",
                stage="qualify",
                evidence={"expected": expected_identity, "actual": actual})
        if SESSION.generation != generation or _device_config_review_token(kind, document, cfgstore.get(kind, bb)["document"]) != review_token:
            raise devcfg.DeviceConfigError("CONFIG_REVIEW_STALE", "Selected device changed before upload.", stage="qualify")
        _set_write_progress(phase="transferring", bytes=len(raw))
        result = session.upload_device_json(raw, remote_path=meta["remote_path"])

    # Same additive settle + poll budget as the RF lane; Send_ReopenJson is the same
    # Reopen_Json call (UpgradeProcessFSM.cs:340-341).
    _set_write_progress(phase="rebooting", settle_s=RECONNECT_SETTLE,
                        poll_budget_s=RECONNECT_POLL_BUDGET, elapsed_s=0.0)
    new_port, verify_bundle = _find_reconnected_serial(
        container_id, vid, pid, expected_identity,
        progress=lambda p: _set_write_progress(**p))
    verify_identity = verify_bundle.get("identity") or {}
    if not stable_identity_matches(expected_identity, verify_identity):
        raise devcfg.DeviceConfigError(
            "RECONNECT_IDENTITY_MISMATCH",
            "a device returned on this ContainerId but it is not the same physical unit",
            stage="verify",
            evidence={"write_may_have_applied": True,
                      "expected": expected_identity, "actual": verify_identity})
    reconnect = {"port": new_port, "identity": verify_identity,
                 "settle_s": RECONNECT_SETTLE, "poll_budget_s": RECONNECT_POLL_BUDGET}
    _set_write_progress(phase="idle")

    stored_after = cfgstore.record_write(kind, document, bb_id=bb,
                                        reviewed_baseline=stored["document"],
                                        reviewed_revision=stored["revision"],
                                        result={**result, "target": {"identity": expected_identity,
                                                                  "container_id": container_id, "port": port}})
    return {
        "ok": True,
        "kind": kind,
        "operation_id": meta["operation_id"],
        "remote_path": meta["remote_path"],
        "transfer": result,
        "reconnect": reconnect,
        "stored": stored_after,
        # The honest verification statement. There is nothing stronger available.
        "verification": {
            "readback_performed": False,
            "readback_supported": False,
            "basis": "the SENDFILE_END (117) acknowledgement and a successful reconnect",
            "reason": stored_after["readback_reason"],
        },
    }

def write_device_config(kind: str, body: dict) -> dict:
    if HOST_STATE.get("shutting_down"):
        raise devcfg.DeviceConfigError("HOST_SHUTTING_DOWN",
                                       "application shutdown is already in progress",
                                       stage="lifecycle")
    if not DEVICE_MUTATION_LOCK.acquire(blocking=False):
        raise devcfg.DeviceConfigError("DEVICE_BUSY",
                                       "another device mutation is already in progress",
                                       stage="lifecycle",
                                       evidence={"operation_state": dict(DEVICE_OPERATION_STATE)})
    op = cfgstore.KINDS[kind]["operation_id"]
    DEVICE_OPERATION_STATE.update({"active": True, "operation_id": op, "started_at": utc_now()})
    _set_write_progress(phase="starting")
    try:
        SESSION.live_candidate()
        with SERIAL_GATE.hold(op, timeout=SERIAL_GATE_TIMEOUT):
            return _write_device_config_locked(kind, body)
    finally:
        DEVICE_OPERATION_STATE.update({"active": False, "operation_id": None, "started_at": None})
        _set_write_progress(phase="idle")
        DEVICE_MUTATION_LOCK.release()

SELECTED_FIRMWARE: dict = {}

_FIRMWARE_LOCK = threading.Lock()

def firmware_page_document() -> dict:
    """Everything the FIRMWARE UPGRADE page needs, with no device command issued."""
    identity = ACTIVE_CONNECTION.get("serial_identity") or {}
    with _FIRMWARE_LOCK:
        selection = dict(SELECTED_FIRMWARE) or None
    prefixes = fwupg.family_prefixes(str(identity.get("firmware") or ""))
    doc = {
        "ok": True,
        "operation_id": FIRMWARE_OPERATION_ID,
        "platform": platform.system(),
        "browse_supported": platform.system().lower() == "windows",
        "vendor_file_filter": VENDOR_FILE_FILTER,
        "device": {
            "device_name": identity.get("device_name"),
            "firmware": identity.get("firmware"),
            "hardware": identity.get("hardware"),
            "serial_number": identity.get("serial_number"),
            "sdk_version": identity.get("sdk_version"),
            "cpu_temp_c": identity.get("cpu_temp"),
            "receive_max_size": identity.get("receive_max_size"),
            "device_version_label": fwupg.device_version_label(str(identity.get("firmware") or "")),
        },
        # The vendor prints the tip prefix on screen and gates on a DIFFERENT prefix.
        # Both are shown, because a mismatch prompt the operator cannot predict from
        # the on-screen hint is exactly the confusion this page has to avoid.
        "filename_hint": {
            "tip_prefix": prefixes["tip"],
            "tip_text": (f'Please select "{prefixes["tip"]}_xxx" filename firmware'
                         if prefixes["tip"] else None),
            "gate_prefix": prefixes["check"],
            "prefixes_agree": bool(prefixes["tip"]) and prefixes["tip"] == prefixes["check"],
        },
        "selection": selection,
        "timing": firmware_timing_document(),
        "divergences": list(FIRMWARE_DIVERGENCES),
        "backup_directory": str(FIRMWARE_BACKUPS_DIR),
        "eligibility": firmware_eligibility(),
        "captured_at": utc_now(),
    }
    return doc

_BUILDER_LOCK = threading.Lock()

_BUILDER_STATE: dict = {"running": False, "target": None, "started": None,
                        "result": None}

def firmware_builder_document(_body: dict | None = None) -> dict:
    """Can this machine build an image, and what would it build?

    HOST-LOCAL AND DEVICE-FREE. Nothing here talks to a receiver, nothing here
    flashes, and the page is safe to open with no unit attached -- which is the
    normal case, because building an image and flashing one are different jobs
    done at different times.
    """
    doc = {"schema": "ascent.firmware_builder.v1",
           "targets": [{"id": k, **{kk: vv for kk, vv in v.items()
                                    if kk != "script"}}
                       for k, v in firmware_builder.TARGETS.items()],
           "planning_targets": [{"id": k, "label": v["label"], "buildable": False,
                                 "blocker": dict(v)}
                                for k, v in firmware_builder.CAMERA_PORTS.items()],
           "state": dict(_BUILDER_STATE)}
    try:
        doc["preflight"] = firmware_builder.preflight()
    except Exception as e:                       # noqa: BLE001 - reported, not raised
        doc["preflight"] = {"can_build": False, "blockers": [
            {"name": "preflight", "detail": sanitize_error(str(e)), "fix": None}]}
    return doc

def firmware_builder_build(body: dict | None = None) -> dict:
    """Run the real builder and hand back ITS report, unaltered.

    gate1 is one command and runs here, synchronously. z8, z40 and hub are a
    pipeline (gate 1 -> stage 1 -> verify -> staging -> gate 2) and are started
    as ONE background job, polled through /api/firmware/builder; see
    _start_variant_job. They used to be run here as a single command, which
    could not work for any of the three.

    The verdict in the response is the one the builder's own gates reached.
    This function does not form a second opinion about whether an image is
    good, and an unreadable report is reported as UNKNOWN rather than being
    rounded to either answer.
    """
    body = body or {}
    target = str(body.get("target") or "").strip()
    pre = firmware_builder.preflight(target=target)
    if not pre.get("can_build"):
        return {"ok": False, "error": pre.get("error") or "BUILD_UNAVAILABLE",
                "message": (pre.get("camera_port") or {}).get("what") or "This machine cannot build an image yet.",
                "preflight": pre}
    if target in firmware_builder.PIPELINE or target == "hdpro":
        return _start_variant_job(target, body, pre)

    out_dir = body.get("out_dir") or os.path.join(
        tempfile.gettempdir(), "ascent-firmware-build")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, (body.get("out_name") or "gate1_rebuilt") + ".img")
    report_path = out_path + ".report.json"

    inputs = dict(body.get("inputs") or {})
    # On Windows the builder runs inside WSL, where a C:\ path does not exist.
    # EVERY path goes through the translator -- the inputs, the outputs AND the
    # builder directory, whose verifier and script paths are derived from it.
    # Only the inputs used to be translated, so the scripts themselves were
    # handed to WSL as Windows paths.
    try:
        tr = firmware_builder.make_translator(backend=pre)
        for k, v in list(inputs.items()):
            if v and os.path.isabs(str(v)):
                inputs[k] = tr(str(v))
        argv = firmware_builder.build_argv(
            target, builder_dir=tr(pre["builder_dir"]), mkfs=pre["mkfs_path"],
            inputs=inputs, out_path=tr(out_path), report_path=tr(report_path))
        argv[0] = pre.get("python_path") or "python3"
    except firmware_builder.BuilderError as e:
        return {"ok": False, "error": e.code, "message": e.message,
                "evidence": e.evidence}

    if not _BUILDER_LOCK.acquire(blocking=False):
        return {"ok": False, "error": "BUILD_IN_PROGRESS",
                "message": "A build is already running. One at a time.",
                "state": dict(_BUILDER_STATE)}
    try:
        _BUILDER_STATE.update({"running": True, "target": target, "stage": "gate1",
                               "stages": [], "started": time.time(), "result": None})
        try:
            r = subprocess.run(firmware_builder.wrap_for_host(argv, backend=pre),
                               capture_output=True, text=True, timeout=3600)
        except subprocess.TimeoutExpired:
            return {"ok": False, "error": "BUILD_TIMEOUT",
                    "message": "The build did not finish within an hour."}
        except OSError as e:
            return {"ok": False, "error": "BUILD_NOT_RUN",
                    "message": sanitize_error(str(e))}

        text = ""
        try:
            with open(report_path, "r", encoding="utf-8") as fh:
                text = fh.read()
        except OSError:
            pass
        summary = firmware_builder.summarise_report(text)
        built = os.path.isfile(out_path)
        result = {
            # ok means THE BUILDER RAN AND ITS GATE PASSED. A zero exit with a
            # failed gate is not a success and must not read as one.
            "ok": r.returncode == 0 and summary.get("pass") is True,
            "target": target,
            "exit_code": r.returncode,
            "gate_pass": summary.get("pass"),
            "report": summary.get("report"),
            "report_parse_error": summary.get("parse_error"),
            # A gate-1 rebuild is the donor regenerated to prove the method.
            # It is evidence, not a product, so it is never offered as one.
            "rebuilt": ({"path": out_path, "bytes": os.path.getsize(out_path)}
                        if built else None),
            "image": None,
            "stdout": (r.stdout or "")[-4000:],
            "stderr": (r.stderr or "")[-4000:],
            "mkfs_version": pre.get("mkfs_version"),
            "mkfs_version_note": pre.get("mkfs_version_note"),
        }
        if summary.get("pass") is None:
            result["message"] = ("The gate report could not be read, so whether it "
                                 "PASSED is unknown.")
        _BUILDER_STATE["result"] = {k: result[k] for k in
                                    ("ok", "target", "gate_pass", "exit_code")}
        return result
    finally:
        _BUILDER_STATE["running"] = False
        _BUILDER_LOCK.release()

def _start_variant_job(target: str, body: dict, pre: dict) -> dict:
    """Start the z8/z40/hub pipeline as one background job and return at once.

    A build takes minutes. The page polls /api/firmware/builder, whose `state`
    carries the stage in progress, every finished stage, and -- at the end --
    the result. The result's `image` is present ONLY when gate 2's own report
    says PASS (firmware_builder.run_variant_build); a stage-1 ELF is `app`.
    """
    donor = body.get("donor") or (body.get("inputs") or {}).get("donor")
    sources = dict(body.get("sources") or {})
    for k, v in (body.get("inputs") or {}).items():
        if k != "donor" and v and k not in sources:
            sources[k] = v
    if not donor:
        return {"ok": False, "error": "INPUT_MISSING", "message": "A donor image is required."}
    try:
        rep = caddx_firmware_variant.analyse(str(donor))
        av = rep.get("app_version") or {}
        sub = None
        # The Hub's sub-version (Hub_6) travels with it; Z8/Z40 sources carry
        # none, and the updater then wants _1.
        if target == "hub" and sources.get("hub"):
            try:
                hav = caddx_firmware_variant.analyse(str(sources["hub"])).get("app_version") or {}
                sub = hav.get("APP_SUB_VERSION")
            except Exception:                                   # noqa: BLE001
                sub = None
        if target == "hub" and not any(sources.values()):
            support = firmware_builder.inspect_camera_support(pre["builder_dir"], target)
            if support:
                sub = support["source_versions"]["hub"]["sub_version"]
        out_name = (firmware_builder.check_output_name(body["out_name"], target)
                    if body.get("out_name") else
                    firmware_builder.output_name(target, av.get("APP_VERSION"), sub))
    except firmware_builder.BuilderError as e:
        return {"ok": False, "error": e.code, "message": e.message, "evidence": e.evidence}
    except Exception as e:                                      # noqa: BLE001
        return {"ok": False, "error": "DONOR_UNREADABLE", "message": sanitize_error(str(e))}

    work_dir = body.get("out_dir") or str(
        LOCAL_DATA_ROOT / "Builds" / f"{target}-{time.strftime('%Y%m%d-%H%M%S')}")

    if not _BUILDER_LOCK.acquire(blocking=False):
        return {"ok": False, "error": "BUILD_IN_PROGRESS",
                "message": "A build is already running. One at a time.",
                "state": dict(_BUILDER_STATE)}
    _BUILDER_STATE.update({"running": True, "target": target, "stage": None,
                           "stages": [], "started": time.time(), "result": None,
                           "out_name": out_name, "work_dir": work_dir})

    def on_stage(name, status, detail):
        _BUILDER_STATE["stage"] = name
        label = name + (f" ({detail})" if detail else "")
        rows = _BUILDER_STATE.setdefault("stages", [])
        if status == "running":
            rows.append({"stage": label, "status": "running"})
        elif rows and rows[-1]["stage"] == label:
            rows[-1]["status"] = status

    def job():
        try:
            res = firmware_builder.run_variant_build(
                target, donor=str(donor), sources=sources, work_dir=work_dir,
                out_name=out_name, builder_dir=pre["builder_dir"], mkfs=pre["mkfs_path"],
                translate=firmware_builder.make_translator(backend=pre), on_stage=on_stage,
                python_path=pre.get("python_path") or "python3", backend=pre)
            res["mkfs_version"] = pre.get("mkfs_version")
            res["mkfs_version_note"] = pre.get("mkfs_version_note")
        except firmware_builder.BuilderError as e:
            res = {"ok": False, "error": e.code, "message": e.message,
                   "evidence": e.evidence, "image": None}
        except Exception as e:                                  # noqa: BLE001
            res = {"ok": False, "error": "BUILD_FAILED",
                   "message": sanitize_error(f"{type(e).__name__}: {e}"), "image": None}
        _BUILDER_STATE["result"] = res
        _BUILDER_STATE["running"] = False
        _BUILDER_LOCK.release()

    try:
        threading.Thread(target=job, name=f"variant-build-{target}", daemon=True).start()
    except RuntimeError as e:
        _BUILDER_STATE["running"] = False
        _BUILDER_LOCK.release()
        return {"ok": False, "error": "BUILD_NOT_RUN", "message": sanitize_error(str(e))}
    return {"ok": True, "started": True, "target": target, "out_name": out_name,
            "work_dir": work_dir, "state": dict(_BUILDER_STATE)}

def firmware_eligibility() -> dict:
    with _FIRMWARE_LOCK:
        selection = dict(SELECTED_FIRMWARE) or None
    return qualify_firmware_upgrade(candidate=SESSION.live_candidate(),
                                    identity=ACTIVE_CONNECTION.get("serial_identity"),
                                    selection=(selection or {}).get("validation"))

_FIRMWARE_BROWSE_PS = r"""
Add-Type -AssemblyName System.Windows.Forms | Out-Null
$d = New-Object System.Windows.Forms.OpenFileDialog
$d.Title = '__TITLE__'
$d.Filter = '__FILTER__'
$d.FilterIndex = 1
$d.RestoreDirectory = $true
$d.Multiselect = $false
if ($d.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
  [pscustomobject]@{ ok = $true; path = $d.FileName } | ConvertTo-Json -Compress
} else {
  [pscustomobject]@{ ok = $false; path = '' } | ConvertTo-Json -Compress
}
"""

_VENDOR_BROWSE_TITLE = "Open"

_VENDOR_BROWSE_FILTER = "firmware (*.img)|*.img|All (*.*)|*.*"

def firmware_browse(title: str = _VENDOR_BROWSE_TITLE,
                    file_filter: str = _VENDOR_BROWSE_FILTER) -> dict:
    """A real native OpenFileDialog.

    The vendor uses System.Windows.Forms.OpenFileDialog with exactly the default
    Title, Filter, FilterIndex, RestoreDirectory and Multiselect
    (AscentUpdataFrm.cs:536-542), so the firmware lane passes no arguments and stays
    at parity. The variant builder passes its own wording: it is our feature, not the
    vendor's, and "Open" with a firmware filter would misdescribe what it selects.

    A WebView `<input type=file>` cannot be used here: it hands the page file CONTENT
    and never a path, and the backend needs a path it can stream a 170 MB image from.

    TITLE AND FILTER ARE INTERPOLATED INTO POWERSHELL, so they are refused unless
    they are plain. They are internal constants today and never operator input; this
    check exists so that stays true if a caller is ever added carelessly.
    """
    for part in (title, file_filter):
        if "'" in part or "\n" in part or "\r" in part or "`" in part or "$" in part:
            raise FirmwareUpgradeError("BROWSE_FAILED",
                                       "the file dialog wording must be plain text",
                                       stage="select")
    if platform.system().lower() != "windows":
        raise FirmwareUpgradeError("BROWSE_UNSUPPORTED",
                                   "the native firmware file dialog requires Windows; "
                                   "type or paste a path instead",
                                   stage="select")
    # STA is required for a Windows Forms dialog, and the dialog is modal for as long
    # as the operator leaves it open -- so this call gets no timeout of its own.
    cp = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-STA", "-Command",
         _FIRMWARE_BROWSE_PS.replace("__TITLE__", title)
                            .replace("__FILTER__", file_filter)],
        capture_output=True, text=True, **_hidden_subprocess_kwargs())
    if cp.returncode != 0:
        raise FirmwareUpgradeError("BROWSE_FAILED",
                                   sanitize_error((cp.stderr or cp.stdout or
                                                   "the file dialog could not be opened").strip()),
                                   stage="select")
    raw = (cp.stdout or "").strip()
    if not raw:
        return {"ok": True, "cancelled": True}
    try:
        obj = json.loads(raw)
    except ValueError:
        raise FirmwareUpgradeError("BROWSE_FAILED", "the file dialog returned no usable result",
                                   stage="select")
    if not obj.get("ok") or not obj.get("path"):
        return {"ok": True, "cancelled": True}
    return {"ok": True, "cancelled": False, "path": str(obj["path"])}

def wallpaper_prepare(body: dict) -> dict:
    """Prepare a local JPEG; temporary pixels are removed before returning."""
    path = Path(str((body or {}).get('path') or '').strip().strip('"'))
    try:
        if not path.is_file():
            return {'ok': False, 'error': 'IMAGE_PATH_REQUIRED', 'message': 'Choose a PNG or JPEG image.'}
        if path.stat().st_size > 32 * 1024 * 1024:
            return {'ok': False, 'error': 'IMAGE_TOO_LARGE', 'message': 'Choose an image smaller than 32 MB.'}
        source = wallpaper_image.measure(path.read_bytes())
        if source['width'] * source['height'] > 80000000:
            return {'ok': False, 'error': 'IMAGE_TOO_LARGE', 'message': 'Choose an image smaller than 80 megapixels.'}
        plan = wallpaper_image.plan_fit(source['width'], source['height'])
        if os.name != 'nt':
            return {'ok': True, 'prepared': False, 'source': source, 'plan': plan,
                    'message': 'Image preparation requires Windows.'}
        with tempfile.TemporaryDirectory(prefix='ascent-wallpaper-') as work:
            output = Path(work) / wallpaper_image.REMOTE_NAME
            script = wallpaper_image.resize_powershell(str(path), str(output), plan)
            result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', script],
                                    capture_output=True, text=True, timeout=60, **_hidden_subprocess_kwargs())
            if result.returncode or not output.is_file():
                return {'ok': False, 'error': 'IMAGE_PREPARATION_FAILED',
                        'message': 'The image could not be prepared. Choose another PNG or JPEG.'}
            data = output.read_bytes()
            measured = wallpaper_image.measure(data)
            if measured['format'] != wallpaper_image.tile.JPEG or (measured['width'], measured['height']) != (1920, 1080):
                return {'ok': False, 'error': 'IMAGE_OUTPUT_INVALID', 'message': 'The prepared image did not match the required format.'}
        return {'ok': True, 'prepared': True, 'source': source, 'plan': plan,
                'filename': wallpaper_image.REMOTE_NAME, 'jpeg_base64': base64.b64encode(data).decode('ascii'),
                'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
    except wallpaper_image.WallpaperError as exc:
        return {'ok': False, 'error': exc.code, 'message': exc.message}
    except (OSError, subprocess.SubprocessError) as exc:
        return {'ok': False, 'error': 'IMAGE_PREPARATION_FAILED', 'message': sanitize_error(str(exc))}


def firmware_variant_plan(body: dict) -> dict:
    """What building a product variant from this donor would take, and what stops it.

    Deliberately UNGATED. Knowing whether something is possible should never require
    accepting the risk of doing it, and this answers from the donor's own bytes.
    """
    path = body.get("path")
    if not isinstance(path, str) or not path.strip():
        raise caddx_firmware_variant.FirmwareVariantError(
            "PATH_REQUIRED", "a donor firmware image path is required")
    plan = caddx_firmware_variant.plan_variant_build(path.strip(),
                                                     str(body.get("target") or ""))
    plan["stage1"] = _variant_stage1_slots(path.strip(), plan, body.get("folder"))
    return plan

def _variant_stage1_slots(donor: str, plan: dict, folder=None) -> dict:
    """Which images fill the build's source slots, identified from their bytes.

    The donor fills n19. The rest are looked for in `folder`, or the donor's
    own folder. Ambiguous slots come back with their candidates so the page
    can ask, never pick.
    """
    target = plan.get("target")
    if target == 'hdpro':
        return {'mode': 'bundled_support', 'complete': True, 'needed': [], 'found': {}, 'missing': [], 'ambiguous': {}, 'candidates': {}}
    if target not in firmware_builder.STAGE1_INPUTS:
        return {"complete": False, "needed": [], "found": {}, "missing": [],
                "ambiguous": {}, "candidates": {}}
    try:
        support = firmware_builder.inspect_camera_support(firmware_builder.default_builder_dir(), target)
    except firmware_builder.BuilderError as exc:
        return {"mode": "support_unavailable", "complete": False, "needed": [], "found": {},
                "missing": [], "ambiguous": {}, "candidates": {}, "error": exc.code, "message": exc.message}
    if support:
        return {"mode": "bundled_support", "complete": True,
                "needed": [{"slot": "n19", "product": "normal", "version": plan.get("donor_version")}],
                "found": {"n19": {"path": donor, "name": os.path.basename(donor), "from_donor": True}},
                "missing": [], "ambiguous": {}, "candidates": {},
                "support_pack": {"id": support["pack_id"], "file_count": support["file_count"],
                                 "source_versions": support["source_versions"]}}
    folder = str(folder or os.path.dirname(os.path.abspath(donor)))
    try:
        rows = firmware_builder.discover_images(folder)
    except firmware_builder.BuilderError as e:
        return {"complete": False, "folder": folder, "error": e.code, "message": e.message,
                "needed": [], "found": {}, "missing": [], "ambiguous": {}, "candidates": {}}
    donor_abs = os.path.abspath(donor)
    drow = next((r for r in rows if os.path.abspath(r["path"]) == donor_abs and r.get("ok")),
                None)
    if drow is None:
        drow = {"path": donor, "name": os.path.basename(donor), "ok": True,
                "product": plan.get("donor_product"), "version": plan.get("donor_version"),
                "sha256": (plan.get("verdict") or {}).get("sha256")}
    res = firmware_builder.resolve_stage1_inputs(target, rows, donor=drow)
    res["folder"] = folder
    return res

def firmware_variant_build(body: dict) -> dict:
    """Construct the image, with the real Mode A builder.

    THIS USED TO REFUSE, AND THE REFUSAL WAS CORRECT AT THE TIME. It read
    "no image writer exists", because nothing in this project had ever written
    a UBIFS image and a button that produced one anyway would have been the
    exact failure the brief forbids.

    That is no longer true. firmware/mode_a/ regenerates a donor's UBIFS
    volumes and transplants an application into them, and it carries its own
    gates: gate 1 rebuilds the donor and proves the rebuild, and gate 2 refuses
    to run until gate 1 has passed on that same donor hash. So the refusal is
    replaced by a call to that builder -- not by a reimplementation of it, and
    not by a second opinion about its output.

    WHAT IS UNCHANGED. The experimental gate still applies and is still checked
    first. The verdict reported is the builder's own; an unreadable gate report
    is reported as UNKNOWN rather than rounded to a pass. Nothing here flashes
    anything: this produces a file on this computer.
    """
    experimental.require("firmware_variant_build")
    target = str(body.get("target") or "").strip()
    donor = body.get("path") or body.get("donor")

    port = firmware_builder.camera_port_blocker(target)
    if port:
        return {"ok": False, "error": port["id"], "message": port["what"],
                "image": None, "camera_port": port}

    # The page's target names are the builder's target names. Refused unless
    # they are one of the three pipelines, so a new page option cannot
    # silently select a builder that was never meant to be reachable from here.
    if target not in firmware_builder.PIPELINE and target != "hdpro":
        return {"ok": False, "error": "TARGET_UNKNOWN",
                "message": f"{target!r} is not a product this builds"}
    sources = dict(body.get("sources") or {})
    return firmware_builder_build({
        "target": target,
        "donor": donor,
        "sources": sources,
        "out_dir": body.get("out_dir"),
        "out_name": body.get("out_name"),
    })

def firmware_variant(body: dict) -> dict:
    """Identify a local firmware image: which product it is, and on what evidence.

    Separate from firmware_select() on purpose. select() asks "may this image be
    sent to the device in front of me", which is a question about the device.
    This asks "what IS this file", which is a question about the file alone -- it
    needs no device, no connection and no qualification, and it is the only way to
    tell a normal G_Sky image from a Z8, Z40 or Hub build. Four files in this
    project's corpus share one filename and two of them are a Hub donor, so the
    name cannot answer it and the version string cannot either.
    """
    path = body.get("path")
    if not isinstance(path, str) or not path.strip():
        raise caddx_firmware_variant.FirmwareVariantError(
            "PATH_REQUIRED", "a firmware image path is required")
    return caddx_firmware_variant.analyse(path.strip())

def firmware_select(body: dict) -> dict:
    """Validate a chosen path and remember it. Read-only: no device command runs.

    Reproduces every pre-send gate the PC Tool applies, each labelled with whether it
    is a vendor check and whether the vendor lets the operator override it.
    """
    path = body.get("path")
    if body.get("clear") is True:
        with _FIRMWARE_LOCK:
            SELECTED_FIRMWARE.clear()
        return {"ok": True, "cleared": True, "state": firmware_page_document()}
    if not isinstance(path, str) or not path.strip():
        raise FirmwareUpgradeError("PATH_REQUIRED", "a firmware file path is required",
                                   stage="select")
    path = path.strip().strip('"')
    identity = ACTIVE_CONNECTION.get("serial_identity") or {}
    if not identity.get("firmware"):
        # The vendor cannot reach this page without a command-60 identity: the page is
        # constructed from `e.AscentInfo` (MainFrm.cs:747). Neither can we.
        raise FirmwareUpgradeError("NO_DEVICE_IDENTITY",
                                   "connect and identify a device before selecting firmware; "
                                   "the filename and version checks compare against its "
                                   "command-60 firmware string",
                                   stage="select")
    if not os.path.isfile(path):
        raise FirmwareUpgradeError("FIRMWARE_PATH_ERROR", "firmware path error", stage="select",
                                   evidence={"path": path})
    image = firmware_inspect_image(path)
    validation = firmware_validate_selection(path, identity, image=image)
    record = {
        "path": path,
        "selected_at": utc_now(),
        "image": image,
        "validation": validation,
        "compared_against": {"device_name": identity.get("device_name"),
                             "firmware": identity.get("firmware")},
    }
    with _FIRMWARE_LOCK:
        SELECTED_FIRMWARE.clear()
        SELECTED_FIRMWARE.update(record)
    return {"ok": validation["ok"], "selection": record, "state": firmware_page_document()}

def _save_firmware_prelight_backup(identity: dict, plan: dict, selection: dict) -> dict:
    """Timestamped pre-flash backup. OURS -- the PC Tool backs up nothing.

    A firmware image cannot be read back out of the device over this protocol, so this
    is honestly a *state* backup, not an image backup, and the document says so. What
    it does capture is everything a reflash can plausibly reset and that we can read:
    the full command-60 identity, and the MD5-verified persistent RF band table.
    """
    FIRMWARE_BACKUPS_DIR.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    stable = "|".join(str(identity.get(k) or "")
                      for k in ("device_name", "serial_number", "hardware"))
    key = hashlib.sha256(stable.encode("utf-8")).hexdigest()[:12]
    rf = None
    rf_error = None
    reading = ACTIVE_CONNECTION.get("rf_bands") or {}
    if reading.get("available") and reading.get("state") == "ok":
        rf = {"data": reading.get("data"), "integrity": reading.get("integrity"),
              "captured_at": reading.get("captured_at"),
              "source": "session RF reading (command 120, command-115 MD5 verified)"}
    else:
        rf_error = (reading.get("error_code") or reading.get("state")
                    or "no verified RF table was available in this session")
    doc = {
        "schema": "ascent.firmware_preflash_backup.v1",
        "created_at": utc_now(),
        "operation_id": FIRMWARE_OPERATION_ID,
        "is_image_backup": False,
        "note": "The device firmware image cannot be read back over the Caddx serial "
                "protocol, so this captures recoverable device STATE only. It does not "
                "make the flash reversible.",
        "identity": identity,
        "planned_transfer": plan,
        "selected_image": {k: selection.get("image", {}).get(k)
                           for k in ("basename", "bytes", "md5", "sha256", "container")},
        "validation": selection.get("validation"),
        "rf_band_table": rf,
        "rf_band_table_unavailable": rf_error,
    }
    payload = json.dumps(doc, indent=2, sort_keys=False).encode("utf-8")
    target = FIRMWARE_BACKUPS_DIR / f"firmware_preflash_{stamp}_{key}.json"
    for n in range(100):
        t = target if n == 0 else FIRMWARE_BACKUPS_DIR / f"firmware_preflash_{stamp}_{key}_{n:02d}.json"
        try:
            with t.open("xb") as f:
                f.write(payload)
            target = t
            break
        except FileExistsError:
            continue
    else:
        raise FirmwareUpgradeError("BACKUP_CREATE_FAILED",
                                   "could not allocate an immutable pre-flash backup",
                                   stage="backup")
    return {"created": True, "file": target.name, "directory": str(FIRMWARE_BACKUPS_DIR),
            "bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest(),
            "is_image_backup": False,
            "rf_band_table_included": rf is not None,
            "rf_band_table_unavailable": rf_error}

def _firmware_port_resolver(container_id: str, expected_vid: str, expected_pid: str):
    """2.0.51 ForceSearchMode == 3, with our own device-identity discipline.

    The vendor retries the OLD COM name PortRetryTimeLimit times 1000 ms apart and only
    then searches USB for a matching VID+PID (UsbSerialportFSM.Reopen, 2.0.51). It
    searches globally, so on a bench with two Ascent units it can reopen the wrong one.
    We keep the same two-phase shape and the same timings, but the search half is
    restricted to the SAME Windows USB ContainerId -- CLAUDE.md, Multi-device
    correlation: destination identity is never "the first matching device".

    This is a real, observed requirement, not a hypothetical: the vendor log shows one
    Ascent VRX Max moving COM13 -> COM6 across the clean-mode reboot and COM6 -> COM13
    coming back (2026-04-25 14:53:04 and 14:55:00).
    """
    cid = str(container_id or "").strip().upper()

    def resolve(previous_port, *, settle_s, poll_budget_s, phase, progress=None):
        if settle_s > 0:
            if progress:
                progress({"phase": phase, "settle_s": settle_s,
                          "poll_budget_s": poll_budget_s, "elapsed_s": 0.0,
                          "strategy": "settling"})
            time.sleep(settle_s)
        started = time.monotonic()
        deadline = started + poll_budget_s
        same_port_attempts = 0
        last_error = None
        while time.monotonic() < deadline:
            elapsed = round(time.monotonic() - started, 1)
            if same_port_attempts < fwupg.PORT_RETRY_LIMIT:
                same_port_attempts += 1
                strategy = "same_port"
                try:
                    probe = fwupg.default_serial_factory(previous_port).open()
                    probe.close()
                    return previous_port, {"strategy": strategy,
                                           "same_port_attempts": same_port_attempts,
                                           "elapsed_s": elapsed}
                except Exception as exc:
                    last_error = sanitize_error(f"{type(exc).__name__}: {exc}")
            else:
                strategy = "usb_search_same_container"
                try:
                    port = _firmware_search_port(cid, expected_vid, expected_pid)
                    if port:
                        probe = fwupg.default_serial_factory(port).open()
                        probe.close()
                        return port, {"strategy": strategy,
                                      "same_port_attempts": same_port_attempts,
                                      "elapsed_s": elapsed}
                    last_error = "no serial interface on the committed ContainerId yet"
                except CaddxWriteError:
                    raise
                except FirmwareUpgradeError:
                    raise
                except Exception as exc:
                    last_error = sanitize_error(f"{type(exc).__name__}: {exc}")
            if progress:
                progress({"phase": phase, "settle_s": settle_s,
                          "poll_budget_s": poll_budget_s, "elapsed_s": elapsed,
                          "strategy": strategy, "last_error": last_error})
            time.sleep(fwupg.PORT_RETRY_INTERVAL)
        raise FirmwareUpgradeError("RECONNECT_TIMEOUT", "Reconnection timeout", stage=phase,
                                   evidence={"last_error": last_error,
                                             "settle_s": settle_s,
                                             "poll_budget_s": poll_budget_s,
                                             "same_port_attempts": same_port_attempts})

    return resolve

def _firmware_search_port(container_id: str, expected_vid: str, expected_pid: str) -> str | None:
    """The COM interface on exactly this physical device, or None.

    Ambiguity fails closed rather than choosing the first port -- the vendor's own
    GetDevicePortname returns the first VID+PID match it finds anywhere.
    """
    inv = INVENTORY_CACHE.get(max_age=0.0).inventory
    if inv is None:
        raise FirmwareUpgradeError("INVENTORY_UNAVAILABLE",
                                   "Windows USB inventory is unavailable during reconnect",
                                   stage="reconnect")
    ports = []
    for u in inv.get("usb") or []:
        ucid = str(u.get("ContainerId") or "").strip().upper()
        if not container_id or ucid != container_id:
            continue
        name = str(u.get("Name") or "")
        cls = str(u.get("PNPClass") or "").lower()
        port = _extract_com(name) if (cls == "ports" or "(COM" in name) else None
        if not port:
            continue
        vid, pid = _vid_pid(str(u.get("PNPDeviceID") or ""))
        if vid == expected_vid and pid == expected_pid:
            ports.append(port)
    ports = sorted(set(ports))
    if len(ports) > 1:
        raise FirmwareUpgradeError("RECONNECT_SERIAL_AMBIGUOUS",
                                   "multiple serial interfaces match the device ContainerId",
                                   stage="reconnect", evidence={"ports": ports})
    return ports[0] if ports else None

def _upgrade_firmware_locked(body: dict) -> dict:
    """The qualified flash. Every gate is re-proven here from fresh state."""
    if body.get('apply') is not True:
        raise FirmwareUpgradeError('APPLY_REQUIRED', 'firmware upgrade requires apply=true', stage='request')
    with _FIRMWARE_LOCK:
        selection = dict(SELECTED_FIRMWARE)
    if not selection:
        raise FirmwareUpgradeError('NO_FIRMWARE_SELECTED', 'select and validate a firmware file first', stage='request')
    expected_sha = str(body.get('expected_image_sha256') or '').strip().lower()
    if not re.fullmatch('[0-9a-f]{64}', expected_sha):
        raise FirmwareUpgradeError('EXPECTED_IMAGE_SHA256_REQUIRED', 'expected_image_sha256 must be the SHA-256 reported when the file was selected', stage='request')
    candidate = dict(ACTIVE_CONNECTION.get('candidate') or {})
    expected_identity = dict(ACTIVE_CONNECTION.get('serial_identity') or {})
    port = candidate.get('serial_com')
    if not candidate or not expected_identity or (not port):
        raise FirmwareUpgradeError('NO_ACTIVE_QUALIFIED_DEVICE', 'connect and identify the target device before flashing', stage='qualification')
    container_id = str(candidate.get('serial_container_id') or '').strip().upper()
    vid, pid = _serial_vid_pid(candidate)
    if not container_id or not vid or (not pid):
        raise FirmwareUpgradeError('PHYSICAL_IDENTITY_INCOMPLETE', 'serial ContainerId/VID/PID evidence is required before flashing; without it the device cannot be re-found across the two reboots', stage='qualification')
    path = selection['path']
    if not os.path.isfile(path):
        raise FirmwareUpgradeError('FIRMWARE_PATH_ERROR', 'firmware path error', stage='prepare', evidence={'path': path})
    image = firmware_inspect_image(path)
    if image['sha256'] != expected_sha:
        raise FirmwareUpgradeError('IMAGE_CHANGED_SINCE_SELECTION', 'the selected firmware file changed on disk after it was validated; select it again', stage='prepare', evidence={'expected_sha256': expected_sha, 'actual_sha256': image['sha256']})
    validation = firmware_validate_selection(path, expected_identity, image=image)
    if not validation['ok']:
        raise FirmwareUpgradeError('FIRMWARE_VALIDATION_FAILED', 'the selected firmware file failed a blocking validation', stage='prepare', evidence={'blocking': validation['blocking'], 'checks': validation['checks']})
    acknowledged = body.get('acknowledge')
    acknowledged = [str(a) for a in acknowledged] if isinstance(acknowledged, list) else []
    outstanding = [c for c in validation['confirmations_required'] if c not in acknowledged]
    if outstanding:
        raise FirmwareUpgradeError('CONFIRMATION_REQUIRED', 'this firmware selection needs explicit acknowledgement', stage='prepare', evidence={'outstanding': outstanding, 'checks': [c for c in validation['checks'] if c['id'] in outstanding]})
    eligibility = qualify_firmware_upgrade(candidate=candidate, identity=expected_identity, selection=validation)
    if not eligibility.get('eligible'):
        raise FirmwareUpgradeError('OPERATION_NOT_QUALIFIED', 'this device is not qualified for a firmware upgrade', stage='qualification', evidence=eligibility)
    resolver = _firmware_port_resolver(container_id, vid, pid)
    backup_holder: dict = {}

    def before_transfer(ctx: dict) -> dict:
        fresh = _enrich_fresh_identity(ctx['identity'], port)
        if not stable_identity_matches(expected_identity, fresh):
            raise FirmwareUpgradeError('FRESH_IDENTITY_MISMATCH', 'the COM interface no longer belongs to the connected device identity', stage='qualification')
        fresh_eligibility = qualify_firmware_upgrade(candidate=candidate, identity=fresh, selection=validation)
        if not fresh_eligibility.get('eligible'):
            if fresh.get('receive_max_size') != fwupg.REQUIRED_RECEIVE_MAX_SIZE:
                raise FirmwareUpgradeError('FIRMWARE_RECEIVE_MAX_SIZE_UNSAFE', 'fresh command-60 receive_max_size is not exactly 1048576; firmware upgrade refused before any device mutation', stage='qualification', evidence={'eligibility': fresh_eligibility, 'fresh_command': 60, 'declared_receive_max_size': fresh.get('receive_max_size'), 'required_receive_max_size': fwupg.REQUIRED_RECEIVE_MAX_SIZE})
            raise FirmwareUpgradeError('OPERATION_NOT_QUALIFIED', 'fresh device state is not qualified for a firmware upgrade', stage='qualification', evidence=fresh_eligibility)
        b = _save_firmware_prelight_backup(fresh, ctx['plan'], selection)
        backup_holder.update(b)
        _set_write_progress(phase='backed_up', backup=b.get('file'))
        return b
    session = FirmwareUpgradeSession(port, port_resolver=resolver, progress=lambda p: _set_write_progress(**p))
    try:
        with session:
            result = firmware_run_upgrade(session, image, on_before_transfer=before_transfer)
    except FirmwareUpgradeError as exc:
        ev = dict(exc.evidence or {})
        ev.setdefault('backup', backup_holder or None)
        ev.setdefault('stages', session.stages)
        raise FirmwareUpgradeError(exc.code, str(exc), stage=exc.stage, evidence=ev) from exc
    after = result['identity_after']
    verify = _enrich_fresh_identity(after, session.port)
    identity_stable = fwupg.identity_matches_across_firmware(expected_identity, verify)
    expected_label = validation.get('file_version_label')
    observed_label = fwupg.device_version_label_strict(str(verify.get('firmware') or ''))
    version_check = {'method': 'command-60 firmware string vs the version the selected filename declares', 'expected_from_filename': expected_label, 'observed_device_version': observed_label, 'comparable': bool(expected_label and observed_label and (expected_label != fwupg._UNRECOGNISED_VERSION)), 'match': None, 'parity_note': "Ours, not the PC Tool's. AscentUpdataFrm re-reads command 60 on completion and repaints the firmware label without comparing it."}
    if version_check['comparable']:
        version_check['match'] = fwupg.flashed_version_matches(expected_label, observed_label)
    try:
        bundle = serial_read_bundle(session.port, True)
        SESSION.set_identity(bundle.get('identity') or verify)
        SESSION.set_serial_bundle(bundle.get('report'))
        rb = bundle.get('rf_bands') or {}
        if rb.get('available') and rb.get('state') == 'ok':
            SESSION.record_rf_success(rb)
        if SESSION.device is not None:
            SESSION.device.last_known_serial_com = session.port
    except Exception as exc:
        bundle = {'error': sanitize_error(f'{type(exc).__name__}: {exc}')}
    INVENTORY_CACHE.invalidate()
    SESSION.live_candidate()
    return {'ok': True, 'operation_id': FIRMWARE_OPERATION_ID, 'eligibility': eligibility, 'backup': result.get('backup') or (backup_holder or None), 'plan': result['plan'], 'stages': result['stages'], 'warnings': result['warnings'], 'status': result['status'], 'firmware_before': result['firmware_before'], 'firmware_after': result['firmware_after'], 'firmware_changed': result['firmware_changed'], 'verified': bool(result['firmware_changed']) and identity_stable and (version_check['match'] is True), 'post_flash_identity_stable': identity_stable, 'version_check': version_check, 'port': session.port, 'port_changed': session.port != str(port).upper(), 'clean_reconnect': result['clean_reconnect'], 'final_reconnect': result['final_reconnect'], 'elapsed_s': result['elapsed_s'], 'post_read': {'error': bundle.get('error')} if bundle.get('error') else {'ok': True}, 'captured_at': utc_now()}

def upgrade_firmware(body: dict) -> dict:
    """Serialize the flash against every other device mutation."""
    if HOST_STATE.get("shutting_down"):
        raise FirmwareUpgradeError("HOST_SHUTTING_DOWN",
                                   "application shutdown is already in progress",
                                   stage="lifecycle")
    if not DEVICE_MUTATION_LOCK.acquire(blocking=False):
        raise FirmwareUpgradeError("DEVICE_BUSY",
                                   "another device mutation is already in progress",
                                   stage="lifecycle",
                                   evidence={"operation_state": dict(DEVICE_OPERATION_STATE)})
    DEVICE_OPERATION_STATE.update({"active": True, "operation_id": FIRMWARE_OPERATION_ID,
                                   "started_at": utc_now()})
    _set_write_progress(phase="starting")
    try:
        SESSION.live_candidate()
        # The flash holds the serial gate across both reboots. Its budget is far longer
        # than a config write, so the gate wait is longer too rather than reporting a
        # spurious busy holder while a background read finishes.
        with SERIAL_GATE.hold("firmware_upgrade", timeout=SERIAL_GATE_TIMEOUT):
            return _upgrade_firmware_locked(body)
    finally:
        DEVICE_OPERATION_STATE.update({"active": False, "operation_id": None, "started_at": None})
        _set_write_progress(phase="idle")
        DEVICE_MUTATION_LOCK.release()

def load_template(name: str) -> dict:
    mapping = {
        "rf": TEMPLATES / "fpv_bb_freq.json",
        "hub": TEMPLATES / "mipi_hub.json",
        "rc": TEMPLATES / "msp_rc_cfg.json",
    }
    if name not in mapping:
        raise KeyError(name)
    p = mapping[name]
    with p.open("r", encoding="utf-8-sig") as f:
        obj = json.load(f)
    return {
        "template": name,
        "source": "Caddx PC Tool 2.2.8 local resource",
        "read_only": True,
        "data": obj,
    }

class Handler(SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        super().end_headers()

    def translate_path(self, path: str) -> str:
        rel = urlparse(path).path.lstrip("/") or "index.html"
        candidate = (WWW / rel).resolve()
        try:
            candidate.relative_to(WWW.resolve())
        except ValueError:
            return str(WWW / "__blocked__")
        return str(candidate)

    def log_message(self, *_args):
        pass

    def json_response(self, obj, status: int = 200):
        data = json.dumps(obj, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if not self._allow_local_request(write=False):
            return
        p = urlparse(self.path).path
        if p == "/api/app":
            self.json_response({
                "name": "Ascent Control",
                "version": APP_VERSION,
                "edition": APP_EDITION,
                "service_mode_available": SERVICE_MODE_AVAILABLE,
                "mode": "operation-qualified",
                "ground": HOST_CFG["ground"],
                "night_default": True,
            })
            return
        if p == "/api/rf-diagnostics":
            self.json_response(vendor_rf_metadata())
            return
        if p == "/api/rf-diagnostics/read":
            self.json_response(vendor_rf_read())
            return
        if p == "/api/status":
            try:
                self.json_response(bb_status())
            except Exception as e:
                self.json_response({"connected": False, "error": sanitize_error(f"{type(e).__name__}: {e}"), "host": HOST_CFG["ground"], "port": HOST_CFG["rpc_port"]}, 503)
            return
        if p == "/api/vrx/battery":
            # One small UDP round-trip; fail-soft so the header poll never errors.
            self.json_response(vrx_battery())
            return
        if p == "/api/connection-state":
            # The authoritative device/session document. Stable identity is stored;
            # ifIndex, IPv4, adapter status and the COM number in `candidate` are
            # re-resolved by ContainerId against current Windows state on this request.
            self.json_response(SESSION.state_document())
            return
        if p == "/api/rf-bands":
            self.json_response(rf_band_table())
            return
        if p == "/api/operation-state":
            self.json_response({"device": dict(DEVICE_OPERATION_STATE), "host": dict(HOST_STATE),
                                "progress": _device_operation_progress(),
                                "serial_gate": SERIAL_GATE.status(),
                                "inventory": INVENTORY_CACHE.peek().meta()})
            return
        if p == "/api/rf-bands/write-eligibility":
            self.json_response(rf_write_eligibility())
            return
        if p == "/api/sky/receiver-slots":
            q = parse_qs(urlparse(self.path).query)
            refresh = str((q.get("refresh") or ["0"])[0]).lower() in ("1", "true", "yes")
            doc = sky_user_cfg_reading(refresh=refresh)
            self.json_response(doc, 200 if doc.get("available") else 503)
            return
        if p == "/api/sky/receiver-slots/write-eligibility":
            self.json_response(sky_user_cfg_eligibility())
            return
        if p == "/api/sky/rndis/probe":
            doc = sky_rndis_probe()
            self.json_response(doc, 200 if doc.get("available") else 503)
            return
        if p == "/api/sky/rndis/receiver-slots":
            q = parse_qs(urlparse(self.path).query)
            refresh = str((q.get("refresh") or ["0"])[0]).lower() in ("1", "true", "yes")
            doc = sky_rndis_reading(refresh=refresh)
            self.json_response(doc, 200 if doc.get("available") else 503)
            return
        if p == "/api/sky/rndis/receiver-slots/write-eligibility":
            self.json_response(sky_rndis_eligibility())
            return
        if p == "/api/experimental/features":
            self.json_response(experimental.features())
            return
        if p == "/api/firmware":
            # Host-local page document. Issues no device command, so it is safe to
            # poll and safe to call while a mutation is in flight.
            try:
                self.json_response(firmware_page_document())
            except Exception as e:
                self.json_response({"ok": False, "error": "FIRMWARE_STATE_FAILED",
                                    "message": sanitize_error(f"{type(e).__name__}: {e}")}, 500)
            return
        if p == "/api/firmware/eligibility":
            self.json_response(firmware_eligibility())
            return
        if p == "/api/firmware/builder":
            self.json_response(firmware_builder_document())
            return
        if p == "/api/cgc/live":
            try:
                self.json_response(cgc_live_state())
            except Exception as e:
                self.json_response({"ok": False, "error": "CGC_LIVE_FAILED",
                                    "message": sanitize_error(f"{type(e).__name__}: {e}")}, 503)
            return
        if p == "/api/network/adapters":
            self.json_response(network_adapters())
            return
        if p == "/api/network/known-devices":
            self.json_response(local_settings.known_devices_document())
            return
        if p == "/api/usb-driver":
            self.json_response(usb_driver_document())
            return
        if p == "/api/device-history":
            self.json_response(device_history_document())
            return
        if p == "/api/repeater":
            self.json_response(repeater_document())
            return
        if p == "/api/settings/auto-connect":
            self.json_response({"ok": True,
                                "auto_connect": local_settings.auto_connect()})
            return
        if p == "/api/settings/battery-warnings":
            self.json_response({"ok": True,
                                "battery_warnings": local_settings.battery_warnings(),
                                "presets": local_settings.BATTERY_CHEMISTRIES})
            return
        if p == "/api/device-compatibility":
            self.json_response(device_compatibility_document())
            return
        if p == "/api/cgc/hid":
            self.json_response(hid_state())
            return
        if p == "/api/cgc/osd":
            q = parse_qs(urlparse(self.path).query)
            cells = str((q.get("cells") or ["0"])[0]).lower() in ("1", "true", "yes")
            self.json_response(osd_state(include_cells=cells))
            return
        if p == "/api/cgc/eligibility":
            self.json_response(cgc_eligibility())
            return
        if p == "/api/device-capabilities":
            self.json_response(device_capabilities())
            return
        if p == "/api/vtx-nicknames":
            self.json_response(vtx_nicknames.document())
            return
        if p == "/api/rf-band-plans":
            self.json_response(rf_band_plans_document())
            return
        if p == "/api/settings/save-directory":
            self.json_response(local_save_directory_document())
            return
        if p == "/api/rf":
            doc = rf_reading()
            self.json_response(doc, 200 if doc["available"] else 503)
            return
        if p == "/api/windows-devices":
            try:
                self.json_response(windows_usb_inventory())
            except Exception as e:
                self.json_response({"platform": platform.system(), "supported": False, "error": sanitize_error(f"{type(e).__name__}: {e}")}, 503)
            return
        if p == "/api/connections":
            try:
                self.json_response(connection_inventory())
            except Exception as e:
                self.json_response({"supported": False, "detected": False, "candidates": [],
                                    "network_profiles": list(NETWORK_CONNECTION_PROFILES.values()),
                                    "error": sanitize_error(f"{type(e).__name__}: {e}")}, 503)
            return
        if p.startswith("/api/template/"):
            name = p.rsplit("/", 1)[-1]
            try:
                self.json_response(load_template(name))
            except Exception as e:
                self.json_response({"error": sanitize_error(f"{type(e).__name__}: {e}")}, 404)
            return
        if p.startswith("/api/device-config/"):
            rest = p[len("/api/device-config/"):]
            kind, _, tail = rest.partition("/")
            if kind not in cfgstore.KINDS:
                self.json_response({"ok": False, "error": "UNKNOWN_CONFIG_KIND",
                                    "message": f"unknown configuration kind {kind!r}"}, 404)
                return
            try:
                if tail == "":
                    self.json_response(device_config_document(kind))
                elif tail == "write-eligibility":
                    self.json_response(device_config_eligibility(kind))
                else:
                    self.json_response({"ok": False, "error": "UNKNOWN_CONFIG_ROUTE"}, 404)
            except Exception as e:
                self.json_response({"ok": False, "error": "CONFIG_STATE_FAILED",
                                    "message": sanitize_error(f"{type(e).__name__}: {e}")}, 500)
            return
        if p.startswith('/api/'):
            self.json_response({'ok': False, 'error': 'UNKNOWN_API_ROUTE'}, 404)
            return
        super().do_GET()

    def _read_json_body(self) -> dict:
        try:
            n = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            raise ValueError("invalid Content-Length")
        if n < 0 or n > MAX_HTTP_BODY:
            raise ValueError("request body too large")
        if n == 0:
            return {}
        obj = json.loads(self.rfile.read(n).decode("utf-8"))
        if not isinstance(obj, dict):
            raise ValueError("JSON body must be an object")
        return obj

    def do_POST(self):
        if not self._allow_local_request(write=True):
            return
        p = urlparse(self.path).path
        if p == "/api/usb-driver/repair":
            try:
                self.json_response(usb_driver_repair(self._read_json_body()))
            except ValueError as e:
                self.json_response({"ok": False, "error": "USB_DRIVER_REPAIR_REFUSED",
                                    "message": sanitize_error(str(e))}, 400)
            except Exception as e:
                self.json_response({"ok": False, "error": "USB_DRIVER_REPAIR_FAILED",
                                    "message": sanitize_error(f"{type(e).__name__}: {e}")}, 502)
            return
        if p == "/api/network/known-devices":
            # Host-local registry edit (operator-asserted IPs). No device touched.
            try:
                self.json_response(local_settings.set_known_devices(self._read_json_body()))
            except local_settings.LocalSettingsError as e:
                self.json_response({"ok": False, "error": e.code,
                                    "message": str(e), "evidence": e.evidence}, 400)
            return
        if p == "/api/network/probe":
            # Read-only reachability probe of an operator-asserted IP. Never raises.
            body = self._read_json_body()
            self.json_response(network_probe(str(body.get("device_ip") or "")))
            return
        if p == "/api/network/relay-qos":
            # Read-only per-radio Relay QoS (bb-ioctl RPC, bound to the resolved
            # NIC). Operator-asserted IP; never raises.
            self.json_response(network_relay_qos(self._read_json_body()))
            return
        if p == "/api/repeater/network-read":
            self.json_response(repeater_network_read(self._read_json_body()))
            return
        if p == "/api/repeater/network-control":
            self.json_response(repeater_network_control(self._read_json_body()))
            return
        if p == "/api/network/configure":
            # A mutation: it reconfigures a host network adapter. It read a JSON
            # body from do_GET, which is both the wrong verb and the same
            # misplacement that killed the maps and CGC routes.
            try:
                self.json_response(network_configure(self._read_json_body()))
            except ValueError as e:
                self.json_response({"ok": False, "error": "NETWORK_CONFIGURE_REFUSED",
                                    "message": sanitize_error(str(e))}, 400)
            except Exception as e:
                self.json_response({"ok": False, "error": "NETWORK_CONFIGURE_FAILED",
                                    "message": sanitize_error(f"{type(e).__name__}: {e}")}, 502)
            return
        if p.startswith("/api/cgc/"):
            # Same fault the maps routes had: these read a JSON body, so they are POST
            # routes, but the block sat in do_GET where it both never ran as intended
            # AND shadowed the Live-mode reads behind it -- /api/cgc/live and
            # /api/cgc/eligibility answered 404 UNKNOWN_CGC_ROUTE, and /api/cgc/osd
            # reached the OSD *action* handler instead of the OSD read. Live mode
            # therefore showed nothing, silently, for the same reason MAPS did.
            verb = p[len("/api/cgc/"):]
            handlers = {"key": cgc_send_key, "mode": cgc_set_mode,
                        "power": cgc_set_power, "channel": cgc_set_channel,
                        "osd": osd_action, "crsf": crsf_send,
                        "hid/axes": hid_axes, "hid/stream": hid_stream, "hid/source": hid_source,
                        "hid/map": hid_channel_map,
                        "hid/calibrate": hid_calibrate,
                        "hid/vendor-map": hid_vendor_map,
                        "hid/detect": hid_detect}
            fn = handlers.get(verb)
            if fn is None:
                self.json_response({"ok": False, "error": "UNKNOWN_CGC_ROUTE"}, 404)
                return
            try:
                self.json_response(fn(self._read_json_body()))
            except hidaxes.HidError as e:
                self.json_response({"ok": False, "error": e.code,
                                    "message": sanitize_error(str(e)),
                                    "evidence": e.evidence}, 400)
            except cgc.CgcError as e:
                if e.code in {"APPLY_REQUIRED", "CGC_UNKNOWN_KEY", "CGC_MODE_INVALID",
                              "CGC_FIELD_INVALID", "CGC_POWER_INDEX_INVALID",
                              "CGC_CHANNEL_OUT_OF_RANGE", "CGC_POWER_INDEX_OUT_OF_RANGE",
                              "CGC_BAND_INVALID", "CGC_HOP_INVALID"}:
                    status = 400
                elif e.code == "CGC_KEY_NOT_REACHABLE_IN_STOCK":
                    status = 409          # needs an acknowledgement, not a rejection
                elif e.code == "CGC_NOT_ELIGIBLE":
                    status = 403
                else:
                    status = 502
                self.json_response({"ok": False, "error": e.code,
                                    "message": sanitize_error(str(e)),
                                    "evidence": e.evidence}, status)
            except Exception as e:
                self.json_response({"ok": False, "error": "CGC_SEND_FAILED",
                                    "message": sanitize_error(f"{type(e).__name__}: {e}")}, 502)
            return
        if p == "/api/settings/auto-connect":
            body = self._read_json_body()
            self.json_response(local_settings.set_auto_connect(body.get("enabled")))
            return
        if p == "/api/settings/battery-warnings":
            body = self._read_json_body()
            try:
                self.json_response(local_settings.set_battery_warnings(body))
            except local_settings.LocalSettingsError as e:
                self.json_response({"ok": False, "error": e.code,
                                    "message": str(e), "evidence": e.evidence}, 400)
            return
        if p == "/api/connect":
            # Connection orchestration must not race an in-flight device
            # mutation -- but a BACKGROUND re-verify is not one. It runs
            # unprompted, it writes nothing, and refusing CONNECT because of
            # it tells an operator that an operation they did not start and
            # cannot see is in progress. Every real mutation still refuses.
            if _blocking_operation_active() or HOST_STATE.get("shutting_down"):
                self.json_response({"connected": False, "error": "DEVICE_BUSY",
                                    "message": "A device operation or application shutdown is in progress."}, 409)
                return
            if not NETWORK_SESSION_LOCK.acquire(blocking=False):
                self.json_response({"connected": False, "error": "DEVICE_BUSY", "message": "A connection or network action is in progress."}, 409)
                return
            response_status = 200
            try:
                body = self._read_json_body()
                cid = body.get("candidate_id")
                if cid is not None and not isinstance(cid, str):
                    raise ValueError("candidate_id must be a string")
                response = connect_host(cid)
            except Exception as e:
                detail = sanitize_error(f"{type(e).__name__}: {e}")
                code = "NO_ASCENT_DEVICE" if "No Ascent USB interface" in str(e) else "CONNECT_FAILED"
                message = "No Ascent USB device is currently detected." if code == "NO_ASCENT_DEVICE" else "Unable to identify the selected Ascent device using the vendor serial session."
                if isinstance(cid, str) and cid.startswith("network:"):
                    code, message = "NETWORK_CONNECT_FAILED", "Unable to establish the selected Ethernet connection."
                response = {"connected": False, "error": code, "message": message, "diagnostic": detail}
                response_status = 503
            finally:
                NETWORK_SESSION_LOCK.release()
            self.json_response(response, response_status)
            return
        if p == "/api/vtx-nicknames":
            # Local metadata only. This never reaches a device, so it takes no device
            # lock and is not blocked by an in-flight write.
            try:
                body = self._read_json_body()
                self.json_response({**vtx_nicknames.set_nickname(body.get("bb_id"),
                                                                 body.get("nickname"),
                                                                 body.get("identity")),
                                    "store": vtx_nicknames.document()})
            except vtx_nicknames.NicknameInUse as e:
                # Its own code, because the UI shows this one inline against the
                # nickname field rather than as a generic rejection. The BB ID that
                # holds the name is returned so the operator can see which unit it is.
                self.json_response({"ok": False, "error": "NICKNAME_IN_USE",
                                    "message": sanitize_error(str(e)),
                                    "conflict": {"bb_id": e.bb_id,
                                                 "nickname": e.nickname}}, 409)
            except ValueError as e:
                self.json_response({"ok": False, "error": "NICKNAME_REJECTED",
                                    "message": sanitize_error(str(e))}, 400)
            except OSError as e:
                self.json_response({"ok": False, "error": "NICKNAME_STORE_UNWRITABLE",
                                    "message": sanitize_error(f"{type(e).__name__}: {e}")}, 500)
            return
        if p == "/api/settings/save-directory":
            try:
                body = self._read_json_body()
                self.json_response(set_local_save_directory(body))
            except local_settings.LocalSettingsError as e:
                self.json_response({"ok": False, "error": e.code,
                                    "message": sanitize_error(str(e)),
                                    "evidence": e.evidence,
                                    "state": local_save_directory_document()}, 400)
            except Exception as e:
                self.json_response({"ok": False, "error": "SAVE_DIR_FAILED",
                                    "message": sanitize_error(f"{type(e).__name__}: {e}")}, 500)
            return
        if p.startswith("/api/device-config/"):
            rest = p[len("/api/device-config/"):]
            kind, _, tail = rest.partition("/")
            if kind not in cfgstore.KINDS:
                self.json_response({"ok": False, "error": "UNKNOWN_CONFIG_KIND",
                                    "message": f"unknown configuration kind {kind!r}"}, 404)
                return
            try:
                body = self._read_json_body()
                if tail == "save":
                    # Host-local only: no device command, so it is not blocked by an
                    # in-flight write and works with nothing attached.
                    self.json_response(save_device_config(kind, body))
                elif tail == "reset":
                    self.json_response(reset_device_config(kind))
                elif tail == "write-preview":
                    self.json_response(device_config_write_preview(kind, body))
                elif tail == "write":
                    self.json_response(write_device_config(kind, body))
                else:
                    self.json_response({"ok": False, "error": "UNKNOWN_CONFIG_ROUTE"}, 404)
            except devcfg.DeviceConfigError as e:
                if e.code in {"APPLY_REQUIRED", "DOCUMENT_REQUIRED", "EDITS_NOT_OBJECT",
                              "CONFIG_TOO_LARGE"} or e.code.startswith(("HUB_", "RC_")):
                    status = 400
                elif e.code in {"OPERATION_NOT_QUALIFIED", "SERIAL_TRANSPORT_MISSING",
                                "DEVICE_PATH_NOT_ALLOWED"}:
                    status = 403
                elif e.code in {"DEVICE_BUSY", "HOST_SHUTTING_DOWN",
                                "FRESH_IDENTITY_MISMATCH", "RECONNECT_IDENTITY_MISMATCH"}:
                    status = 409
                else:
                    status = 502
                self.json_response({"ok": False, "error": e.code, "stage": e.stage,
                                    "message": sanitize_error(str(e)),
                                    "evidence": e.evidence}, status)
            except CaddxWriteError as e:
                self.json_response({"ok": False, "error": e.code, "stage": e.stage,
                                    "message": sanitize_error(str(e)),
                                    "evidence": e.evidence}, 502)
            except Exception as e:
                self.json_response({"ok": False, "error": "CONFIG_WRITE_FAILED",
                                    "message": sanitize_error(f"{type(e).__name__}: {e}")}, 502)
            return
        if p == '/api/wallpaper/browse':
            self.json_response(firmware_browse(title='Choose a background image',
                file_filter='Images (*.png;*.jpg;*.jpeg)|*.png;*.jpg;*.jpeg|All files (*.*)|*.*'))
            return
        if p == '/api/wallpaper/prepare':
            self.json_response(wallpaper_prepare(self._read_json_body()))
            return
        if p.startswith("/api/device-history/"):
            action = p[len("/api/device-history/"):]
            handler = {"forget": device_history_forget,
                       "clear": device_history_clear,
                       "export": device_history_export}.get(action)
            if handler is None:
                self.json_response({"ok": False, "error": "UNKNOWN_HISTORY_ACTION"}, 404)
                return
            try:
                self.json_response(handler(self._read_json_body()))
            except knownrx.RegistryError as e:
                self.json_response({"ok": False, "error": e.code,
                                    "message": sanitize_error(str(e))}, 400)
            return
        if p == "/api/repeater/read":
            try:
                self.json_response(repeater_read(self._read_json_body()))
            except rep.RepeaterError as e:
                self.json_response({"ok": False, "error": e.code, "message": str(e),
                                    "evidence": e.evidence}, 400)
            except Exception as e:                               # noqa: BLE001
                self.json_response({"ok": False, "error": "REPEATER_READ_FAILED",
                                    "message": sanitize_error(f"{type(e).__name__}: {e}")}, 502)
            return
        if p.startswith("/api/rf-band-plans/"):
            # Host-local store. No device command, no serial gate, no mutation lock.
            action = p[len("/api/rf-band-plans/"):]
            handler = {"save": rf_band_plan_save, "delete": rf_band_plan_delete,
                       "export": rf_band_plan_export, "import": rf_band_plan_import}.get(action)
            if handler is None:
                self.json_response({"ok": False, "error": "UNKNOWN_PLAN_ACTION",
                                    "message": "No such band-plan action."}, 404)
                return
            try:
                self.json_response(handler(self._read_json_body()))
            except rf_band_plans.RfPlanError as e:
                status = 409 if e.code in {"PLAN_NAME_IN_USE", "PLAN_NOT_FOUND",
                                           "PLAN_LIMIT_REACHED",
                                           "FRESH_RF_READ_NOT_AVAILABLE"} else 400
                self.json_response({"ok": False, "error": e.code,
                                    "message": sanitize_error(str(e)),
                                    "evidence": e.evidence}, status)
            except OSError as e:
                self.json_response({"ok": False, "error": "PLAN_STORE_UNWRITABLE",
                                    "message": sanitize_error(f"{type(e).__name__}: {e}")}, 500)
            except Exception as e:
                self.json_response({"ok": False, "error": "PLAN_OPERATION_FAILED",
                                    "message": sanitize_error(f"{type(e).__name__}: {e}")}, 400)
            return
        if p == "/api/rf-bands/write-preview":
            try:
                body = self._read_json_body()
                self.json_response(rf_write_preview(body))
            except CaddxWriteError as e:
                self.json_response({"ok": False, "error": e.code, "stage": e.stage,
                                    "message": sanitize_error(str(e)), "evidence": e.evidence}, 409)
            except Exception as e:
                self.json_response({"ok": False, "error": "PREVIEW_FAILED",
                                    "message": sanitize_error(f"{type(e).__name__}: {e}")}, 400)
            return
        if p == "/api/rf-bands/write":
            try:
                body = self._read_json_body()
                self.json_response(write_rf_band_table(body))
            except CaddxWriteError as e:
                if e.code in {"APPLY_REQUIRED", "EXPECTED_MD5_REQUIRED", "RF_TABLE_REQUIRED",
                              "RF_TABLE_NOT_OBJECT", "RF_BOARD_TYPE_CHANGE_BLOCKED",
                              "RF_BOARD_TYPE_INVALID", "RF_BAND_INVALID", "RF_FREQUENCY_OUT_OF_RANGE",
                              "RF_TABLE_TOO_LARGE", "RF_TABLE_SERIALIZATION_FAILED"}:
                    status = 400
                elif e.code in {"OPERATION_NOT_QUALIFIED", "PHYSICAL_IDENTITY_INCOMPLETE"}:
                    status = 403
                elif e.code in {"STALE_RF_TABLE", "NO_ACTIVE_QUALIFIED_DEVICE", "FRESH_IDENTITY_MISMATCH",
                                    "DEVICE_BUSY", "HOST_SHUTTING_DOWN"}:
                    status = 409
                else:
                    status = 502
                self.json_response({"ok": False, "error": e.code, "message": str(e),
                                    "stage": e.stage, "evidence": e.evidence}, status)
            except Exception as e:
                self.json_response({"ok": False, "error": "RF_WRITE_FAILED",
                                    "message": "Persistent RF-table write failed.",
                                    "diagnostic": sanitize_error(f"{type(e).__name__}: {e}")}, 502)
            return
        if p == "/api/sky/receiver-slots/write-preview":
            try:
                body = self._read_json_body()
                self.json_response(sky_user_cfg_write_preview(body))
            except SkyUserCfgError as e:
                self.json_response({"ok": False, "error": e.code, "stage": e.stage,
                                    "message": sanitize_error(str(e)), "evidence": e.evidence}, 409)
            except Exception as e:
                self.json_response({"ok": False, "error": "PREVIEW_FAILED",
                                    "message": sanitize_error(f"{type(e).__name__}: {e}")}, 400)
            return
        if p == "/api/sky/receiver-slots/write":
            try:
                body = self._read_json_body()
                self.json_response(write_sky_user_cfg(body))
            except SkyUserCfgError as e:
                if e.code in {"APPLY_REQUIRED", "PRIMARY_REQUIRED", "FALLBACK_REQUIRED",
                              "BB_ID_MALFORMED", "BB_ID_NOT_ROUTABLE", "DEVICE_PATH_NOT_ALLOWED",
                              "USER_CFG_TOO_LARGE"}:
                    status = 400
                elif e.code in {"OPERATION_NOT_QUALIFIED", "PHYSICAL_IDENTITY_INCOMPLETE",
                                "TYPED_USER_CFG_UNSUPPORTED"}:
                    status = 403
                elif e.code in {"NO_ACTIVE_QUALIFIED_DEVICE", "FRESH_IDENTITY_MISMATCH",
                                "DEVICE_BUSY", "HOST_SHUTTING_DOWN",
                                "TYPED_USER_CFG_READ_NOT_AVAILABLE"}:
                    status = 409
                else:
                    status = 502
                self.json_response({"ok": False, "error": e.code, "message": str(e),
                                    "stage": e.stage, "evidence": e.evidence}, status)
            except Exception as e:
                self.json_response({"ok": False, "error": "USER_CFG_WRITE_FAILED",
                                    "message": "Receiver-slot provisioning failed.",
                                    "diagnostic": sanitize_error(f"{type(e).__name__}: {e}")}, 502)
            return
        if p == "/api/sky/rndis/receiver-slots/write-preview":
            try:
                body = self._read_json_body()
                self.json_response(sky_rndis_write_preview(body))
            except (SkyRndisProvisionError, SkyUserCfgError) as e:
                self.json_response({"ok": False, "error": e.code, "stage": e.stage,
                                    "message": sanitize_error(str(e)), "evidence": e.evidence}, 409)
            except Exception as e:
                self.json_response({"ok": False, "error": "PREVIEW_FAILED",
                                    "message": sanitize_error(f"{type(e).__name__}: {e}")}, 400)
            return
        if p == "/api/sky/rndis/receiver-slots/write":
            try:
                body = self._read_json_body()
                self.json_response(write_sky_rndis_slots(body))
            except (SkyRndisProvisionError, SkyUserCfgError) as e:
                if e.code in {"APPLY_REQUIRED", "PRIMARY_REQUIRED", "FALLBACK_REQUIRED",
                              "BB_ID_MALFORMED", "BB_ID_NOT_ROUTABLE", "READ_CARRIES_NO_DATA",
                              "UNSUPPORTED_OPERATION"}:
                    status = 400
                elif e.code in {"OPERATION_NOT_QUALIFIED", "PROVISIONING_SERVICE_UNAVAILABLE",
                                "AIRCRAFT_IDENTITY_MISMATCH"}:
                    status = 403
                elif e.code in {"RNDIS_BINDING_UNRESOLVED", "IFINDEX_REQUIRED", "DEVICE_BUSY",
                                "HOST_SHUTTING_DOWN", "TYPED_USER_CFG_READ_NOT_AVAILABLE"}:
                    status = 409
                else:
                    status = 502
                self.json_response({"ok": False, "error": e.code, "message": str(e),
                                    "stage": e.stage, "evidence": e.evidence}, status)
            except Exception as e:
                self.json_response({"ok": False, "error": "USER_CFG_WRITE_FAILED",
                                    "message": "Receiver-slot provisioning over USB-C failed.",
                                    "diagnostic": sanitize_error(f"{type(e).__name__}: {e}")}, 502)
            return
        if p == "/api/firmware/variant/browse":
            # Same native dialog as the firmware lane, different wording: this picks
            # a DONOR image to build from, not an image to flash, and calling it
            # "Open" with a firmware filter would misdescribe it. Host-local; it
            # opens a dialog and returns a path, nothing more.
            if _blocking_operation_active() or HOST_STATE.get("shutting_down"):
                self.json_response({"ok": False, "error": "DEVICE_BUSY",
                                    "message": "A device operation or application shutdown "
                                               "is in progress."}, 409)
                return
            try:
                self.json_response(firmware_browse(
                    title="Choose a donor image",
                    file_filter="Ascent Sky image (*.img)|*.img|All (*.*)|*.*"))
            except FirmwareUpgradeError as e:
                self.json_response({"ok": False, "error": e.code, "stage": e.stage,
                                    "message": sanitize_error(str(e)),
                                    "evidence": e.evidence}, 400)
            except Exception as e:
                self.json_response({"ok": False, "error": "BROWSE_FAILED",
                                    "message": sanitize_error(f"{type(e).__name__}: {e}")}, 500)
            return
        if p == "/api/firmware/browse":
            # Host-local: opens a native dialog. Refused while a mutation is in flight
            # only because a modal dialog would sit on top of an in-progress flash.
            if DEVICE_OPERATION_STATE.get("active") or HOST_STATE.get("shutting_down"):
                self.json_response({"ok": False, "error": "DEVICE_BUSY",
                                    "message": "A device operation or application shutdown "
                                               "is in progress."}, 409)
                return
            try:
                self.json_response(firmware_browse())
            except FirmwareUpgradeError as e:
                self.json_response({"ok": False, "error": e.code, "stage": e.stage,
                                    "message": sanitize_error(str(e)),
                                    "evidence": e.evidence}, 400)
            except Exception as e:
                self.json_response({"ok": False, "error": "BROWSE_FAILED",
                                    "message": sanitize_error(f"{type(e).__name__}: {e}")}, 500)
            return
        if p == "/api/firmware/select":
            # Host-local validation. Reads the file, contacts no device.
            try:
                body = self._read_json_body()
                self.json_response(firmware_select(body))
            except FirmwareUpgradeError as e:
                status = 409 if e.code == "NO_DEVICE_IDENTITY" else 400
                self.json_response({"ok": False, "error": e.code, "stage": e.stage,
                                    "message": sanitize_error(str(e)),
                                    "evidence": e.evidence,
                                    "state": firmware_page_document()}, status)
            except Exception as e:
                self.json_response({"ok": False, "error": "FIRMWARE_SELECT_FAILED",
                                    "message": sanitize_error(f"{type(e).__name__}: {e}")}, 500)
            return
        if p in ("/api/experimental/acknowledge", "/api/experimental/withdraw",
                 "/api/firmware/variant/plan", "/api/firmware/variant/build"):
            try:
                body = self._read_json_body()
                fn = {"/api/experimental/acknowledge": experimental.acknowledge,
                      "/api/experimental/withdraw": experimental.withdraw,
                      "/api/firmware/variant/plan": firmware_variant_plan,
                      "/api/firmware/variant/build": firmware_variant_build}[p]
                self.json_response(fn(body))
            except (experimental.ExperimentalFeatureError,
                    caddx_firmware_variant.FirmwareVariantError) as e:
                self.json_response(e.as_dict(), 400)
            except Exception as e:
                self.json_response({"ok": False, "error": "EXPERIMENTAL_FAILED",
                                    "message": sanitize_error(f"{type(e).__name__}: {e}")}, 500)
            return
        if p == "/api/firmware/variant":
            # Identify a local image: which product it is, and on what evidence.
            # Reads a file the operator chose and nothing else -- no device I/O, no
            # network and no write -- which is why it needs no write qualification.
            try:
                body = self._read_json_body()
                self.json_response(firmware_variant(body))
            except caddx_firmware_variant.FirmwareVariantError as e:
                self.json_response(e.as_dict(), 400)
            except Exception as e:
                self.json_response({"ok": False, "error": "FIRMWARE_VARIANT_FAILED",
                                    "message": sanitize_error(f"{type(e).__name__}: {e}")}, 500)
            return
        if p == "/api/firmware/builder/build":
            # HOST-LOCAL. Produces a file and a report; touches no receiver and
            # flashes nothing. Long-running by nature -- the caller waits.
            try:
                self.json_response(firmware_builder_build(self._read_json_body()))
            except Exception as e:
                self.json_response({"ok": False, "error": "BUILD_FAILED",
                                    "message": sanitize_error(
                                        f"{type(e).__name__}: {e}")}, 500)
            return
        if p == "/api/firmware/upgrade":
            try:
                body = self._read_json_body()
                self.json_response(upgrade_firmware(body))
            except FirmwareUpgradeError as e:
                if e.code in {"APPLY_REQUIRED", "NO_FIRMWARE_SELECTED",
                              "EXPECTED_IMAGE_SHA256_REQUIRED", "FIRMWARE_PATH_ERROR",
                              "IMAGE_CHANGED_SINCE_SELECTION", "FIRMWARE_VALIDATION_FAILED",
                              "CONFIRMATION_REQUIRED"}:
                    status = 400
                elif e.code in {"OPERATION_NOT_QUALIFIED", "PHYSICAL_IDENTITY_INCOMPLETE",
                                "FRESH_IDENTITY_MISMATCH",
                                "FIRMWARE_RECEIVE_MAX_SIZE_UNSAFE"}:
                    status = 403
                elif e.code in {"DEVICE_BUSY", "HOST_SHUTTING_DOWN",
                                "NO_ACTIVE_QUALIFIED_DEVICE", "INVENTORY_UNAVAILABLE"}:
                    status = 409
                else:
                    status = 502
                self.json_response({"ok": False, "error": e.code, "message": str(e),
                                    "stage": e.stage, "evidence": e.evidence}, status)
            except SerialBusyError as e:
                self.json_response({"ok": False, "error": "SERIAL_BUSY",
                                    "message": sanitize_error(str(e))}, 409)
            except Exception as e:
                self.json_response({"ok": False, "error": "FIRMWARE_UPGRADE_FAILED",
                                    "message": "Firmware upgrade failed.",
                                    "diagnostic": sanitize_error(f"{type(e).__name__}: {e}")}, 502)
            return
        if p == "/api/host/shutdown":
            # Block until any qualified write has completed, then prevent new mutations
            # before asking serve_forever() to stop. This makes window-close safe once
            # the WPF host uses this endpoint instead of immediately killing Python.
            DEVICE_MUTATION_LOCK.acquire()
            try:
                HOST_STATE["shutting_down"] = True
            finally:
                DEVICE_MUTATION_LOCK.release()
            self.json_response({"ok": True, "shutting_down": True})
            threading.Thread(target=self.server.shutdown, daemon=True, name="AscentBackendShutdown").start()
            return
        if p == '/api/disconnect':
            if DEVICE_OPERATION_STATE.get('active') or HOST_STATE.get('shutting_down'):
                self.json_response({'ok': False, 'error': 'DEVICE_BUSY', 'message': 'A device operation is in progress.'}, 409)
                return
            if not NETWORK_SESSION_LOCK.acquire(blocking=False):
                self.json_response({'ok': False, 'error': 'DEVICE_BUSY', 'message': 'A connection operation is in progress.'}, 409)
                return
            try:
                SESSION.clear()
            finally:
                NETWORK_SESSION_LOCK.release()
            self.json_response({'connected': False, 'ok': True, 'message': 'Application session disconnected.'})
            return
        self._method_not_allowed()

    def _method_not_allowed(self):
        self.json_response({"error": "method not implemented for this resource"}, 405)

    do_PUT = _method_not_allowed

    do_DELETE = _method_not_allowed

    do_PATCH = _method_not_allowed

    def _allow_local_request(self, write=False):
        port = self.server.server_address[1]
        try:
            host = urlparse('http://' + str(self.headers.get('Host', '')))
            if host.hostname not in ('127.0.0.1', 'localhost', '::1') or host.port != port or host.username or host.password:
                raise ValueError('host')
            origin = self.headers.get('Origin')
            if write and origin is not None:
                peer = urlparse(origin)
                if peer.scheme != 'http' or peer.hostname != host.hostname or peer.port != port or peer.username or peer.password or peer.path or peer.query or peer.fragment:
                    raise ValueError('origin')
        except (ValueError, TypeError):
            self.json_response({'ok': False, 'error': 'LOCAL_ORIGIN_REQUIRED', 'message': 'This request must come from the local application.'}, 403)
            return False
        return True

class AscentHTTPServer(ThreadingHTTPServer):
    """
    The API server, with one behaviour changed: a client that hangs up mid-response
    is not a stack trace.

    WebView2 drops in-flight fetches routinely -- navigate away from a page with a
    request outstanding and the socket closes under the handler. socketserver's
    default handle_error prints a full traceback for each one. Measured on the
    shipped host.log: 26 such aborts, 18 full tracebacks, and they were the bulk of a
    108 KB log. Log volume is not harmless; it is what hides the failures that matter.

    The suppression is deliberately narrow. Only the three exceptions that mean "the
    peer went away" are quietened, they are COUNTED rather than discarded so the
    support bundle can still say how often it happens, and everything else falls
    through to the default handler with its traceback intact. A quiet log that also
    swallows real faults would be worse than a noisy one.
    """

    disconnect_errors = (ConnectionAbortedError, ConnectionResetError, BrokenPipeError)

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.client_disconnects = 0
        self.last_disconnect = None

    def handle_error(self, request, client_address):
        exc = sys.exc_info()[1]
        if isinstance(exc, self.disconnect_errors):
            self.client_disconnects += 1
            self.last_disconnect = utc_now()
            return
        super().handle_error(request, client_address)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ground", default="192.168.3.102")
    ap.add_argument("--listen", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--no-browser", action="store_true")
    a = ap.parse_args()
    HOST_CFG["ground"] = a.ground

    server = AscentHTTPServer((a.listen, a.port), Handler)
    SERVER_REF["server"] = server
    actual_port = server.server_address[1]
    url = f"http://{a.listen}:{actual_port}/"
    print(f"Ascent Control {APP_VERSION}: {url}")
    print(f"Ground RPC: {a.ground}:50000")
    print(f"Ground Control UDP: {a.ground}:9001")
    print(f"Picker Fleet GET: {a.ground}:50100")
    print("OPERATION-QUALIFIED DEVICE BOUNDARY: persistent RF-table write is enabled only for exact qualified profiles; other device mutations remain unavailable.")
    if not a.no_browser:
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass

def support_bundle(*, audience='public'):
    return {'schema': 'ascent.public.support.v1', 'app': {'name': 'Ascent Control', 'version': APP_VERSION}, 'firmware_divergences': FIRMWARE_DIVERGENCES, 'audience': 'public', 'identities_included': False, 'hardware_qualified': False}

if __name__ == '__main__':
    main()
