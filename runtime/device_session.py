#!/usr/bin/env python3
"""Authoritative selected-device / session model.

CLAUDE.md implementation-order item 1: *one selected-physical-device object owning
COM identity, raw cmd-60 identity, serial, hw/fw info, USB topology, RNDIS sibling,
local IPv4, ifIndex, capabilities, freshness, session state. Every page consumes it.*

The distinction this module exists to enforce:

  STABLE keys are stored on the object -- ContainerId, serial PnP instance id,
  VID/PID, and the raw command-60 identity. They name the physical unit and do not
  change while it stays plugged into the same port.

  VOLATILE facts are never stored -- ifIndex, local IPv4, adapter status, and the
  COM number itself. They are re-resolved on demand, keyed by ContainerId, against
  *current* Windows state served from a short-TTL inventory cache.

Alpha14 froze one PowerShell inventory row at connect time and re-parsed it for the
rest of the session (BACKEND_INVENTORY.md 3.2). A device that finished its RNDIS
address assignment after the 8 s connect window, or that lost one ContainerId lookup
to a swallowed PowerShell exception, stayed permanently unreachable to RF/Ground while
Device Info kept happily showing it. Re-resolving by ContainerId deletes both failure
modes: a later refresh simply observes the address that is now live.

Correlation policy is unchanged and still fails closed per CLAUDE.md. ContainerId is
the correlation primitive; more than one serial or network interface under one
ContainerId is ambiguity, not a menu; and a device-side IP is never identity.

Nothing here opens a serial port, a socket, or a subprocess. The Windows inventory
arrives through an injected provider, which is what makes the whole model testable
off-bench.
"""
from __future__ import annotations

import re
import threading
import time
from contextlib import contextmanager

__all__ = [
    "SerialBusyError",
    "SerialGate",
    "InventoryRecord",
    "InventoryCache",
    "CachedRead",
    "SelectedDevice",
    "DeviceSession",
    "norm_container_id",
    "extract_com",
    "vid_pid",
    "resolve_transport",
    "utc_now",
]

_COM_RE = re.compile(r"\((COM\d+)\)", re.I)
_VIDPID_RE = re.compile(r"VID_([0-9A-Fa-f]{4})&PID_([0-9A-Fa-f]{4})")

# IPv4 addresses that Windows has not settled are not usable source addresses. Two
# Ascent RNDIS adapters currently receive the same host address (Configure-AscentRNDIS
# hardcodes one), and the second lands in Duplicate/Tentative -- binding to it would
# be ambiguous at the OS level even though IP_UNICAST_IF steers egress correctly.
_UNUSABLE_ADDRESS_STATES = {"duplicate", "tentative", "invalid", "deprecated"}


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def norm_container_id(value: object) -> str | None:
    """ContainerId as a comparison key. Empty and whitespace are absence, not a match.

    The all-zeros GUID is treated as absence too. Windows reports
    {00000000-0000-0000-0000-000000000000} for a device that is NOT part of a
    container -- USB CDC-ACM serial gadgets (what the bench connects over) do exactly
    this. It is a sentinel, not an identity: two different units both reporting it must
    never be judged the same device, so it can neither match nor key liveness.
    """
    text = str(value or "").strip().upper()
    if not text:
        return None
    if not text.strip("{}-0"):      # only braces, hyphens and zeros -> the null GUID
        return None
    return text


def extract_com(name: str | None) -> str | None:
    m = _COM_RE.search(name or "")
    return m.group(1).upper() if m else None


def vid_pid(pnp_id: str | None) -> tuple[str | None, str | None]:
    m = _VIDPID_RE.search(pnp_id or "")
    return (m.group(1).upper(), m.group(2).upper()) if m else (None, None)


def _ipv4_rows(value: object) -> list[dict]:
    if isinstance(value, dict):
        return [value]
    if isinstance(value, list):
        return [x for x in value if isinstance(x, dict)]
    return []


def _is_serial_row(row: dict) -> bool:
    name = str(row.get("Name") or "")
    cls = str(row.get("PNPClass") or "").lower()
    return cls == "ports" or "(COM" in name


# --------------------------------------------------------------------------- #
# Serial mutual exclusion
# --------------------------------------------------------------------------- #

class SerialBusyError(RuntimeError):
    """Raised when a COM session is requested while another one holds the gate."""

    def __init__(self, message: str, *, holder: dict | None = None):
        super().__init__(message)
        self.holder = holder or {}


class SerialGate:
    """The single mutual-exclusion flag for *every* COM session in this process.

    Alpha14 guarded only device mutations (``DEVICE_OPERATION_STATE["active"]``, set
    exclusively by the RF write). Background discovery therefore reopened the selected
    COM port every ~3 s and raced any user-initiated connect or RF read for the same
    handle (BACKEND_INVENTORY.md 2.4 defect 2).

    Reentrant on purpose: the write transaction holds the gate across its own verified
    readback, and that readback goes through the ordinary bundle reader.

    Waiters state their patience. Background discovery passes ``timeout=0`` and skips
    its turn; operator-initiated work waits a bounded interval and then reports a
    named busy holder rather than blocking a request thread forever.
    """

    def __init__(self):
        self._lock = threading.RLock()
        self._meta_lock = threading.Lock()
        self._depth = 0
        self._owner: str | None = None
        self._owner_thread: str | None = None
        self._started_at: str | None = None
        self._started_monotonic: float | None = None

    @contextmanager
    def hold(self, owner: str, timeout: float | None = 20.0):
        if timeout is not None and timeout <= 0:
            acquired = self._lock.acquire(blocking=False)
        elif timeout is None:
            acquired = self._lock.acquire()
        else:
            acquired = self._lock.acquire(timeout=timeout)
        if not acquired:
            raise SerialBusyError(
                "another serial session is already using the selected COM interface",
                holder=self.status(),
            )
        with self._meta_lock:
            self._depth += 1
            if self._depth == 1:
                self._owner = owner
                self._owner_thread = threading.current_thread().name
                self._started_at = utc_now()
                self._started_monotonic = time.monotonic()
        try:
            yield self
        finally:
            with self._meta_lock:
                self._depth -= 1
                if self._depth <= 0:
                    self._depth = 0
                    self._owner = None
                    self._owner_thread = None
                    self._started_at = None
                    self._started_monotonic = None
            self._lock.release()

    @property
    def busy(self) -> bool:
        with self._meta_lock:
            return self._depth > 0

    def status(self) -> dict:
        with self._meta_lock:
            held_for = (
                round(time.monotonic() - self._started_monotonic, 3)
                if self._started_monotonic is not None else None
            )
            return {
                "busy": self._depth > 0,
                "owner": self._owner,
                "owner_thread": self._owner_thread,
                "started_at": self._started_at,
                "held_for_seconds": held_for,
                "depth": self._depth,
            }


# --------------------------------------------------------------------------- #
# Short-TTL Windows inventory cache
# --------------------------------------------------------------------------- #

class InventoryRecord:
    """One Windows USB/RNDIS inventory result, with its own age and failure reason."""

    __slots__ = ("inventory", "captured_at", "error", "_monotonic")

    def __init__(self, inventory: dict | None, captured_at: str | None,
                 monotonic: float | None, error: str | None):
        self.inventory = inventory
        self.captured_at = captured_at
        self.error = error
        self._monotonic = monotonic

    @property
    def ok(self) -> bool:
        return self.inventory is not None

    def age(self) -> float | None:
        if self._monotonic is None:
            return None
        return time.monotonic() - self._monotonic

    def meta(self) -> dict:
        age = self.age()
        return {
            "available": self.ok,
            "captured_at": self.captured_at,
            "age_seconds": round(age, 3) if age is not None else None,
            "error": self.error,
        }


class InventoryCache:
    """Short-TTL cache over the Windows USB/RNDIS inventory.

    Each refresh spawns two PowerShell processes, and the UI polls ``/api/connections``
    at 1 Hz, so every transport resolution reading the inventory directly would
    multiply that cost. The cache exists to share one refresh between the discovery
    poll and every on-demand resolution.

    It is explicitly *not* a place to keep a stale record alive: every consumer
    states the maximum age it will accept, and a failed refresh is reported as a
    failure rather than silently serving the previous result.
    """

    def __init__(self, provider, ttl: float = 1.5):
        self._provider = provider
        self._ttl = float(ttl)
        self._lock = threading.RLock()
        self._record = InventoryRecord(None, None, None, None)

    @property
    def ttl(self) -> float:
        return self._ttl

    def invalidate(self) -> None:
        with self._lock:
            self._record = InventoryRecord(None, None, None, None)

    def peek(self) -> InventoryRecord:
        with self._lock:
            return self._record

    def get(self, max_age: float | None = None, force: bool = False) -> InventoryRecord:
        limit = self._ttl if max_age is None else float(max_age)
        with self._lock:
            snap = self._record
            age = snap.age()
            if not force and age is not None and age <= limit:
                # Share a fresh failure as a failure, never as stale topology.
                # Otherwise each field immediately launches another expensive
                # Windows refresh after the same timeout.
                return snap
            try:
                inv = self._provider()
                snap = InventoryRecord(inv, utc_now(), time.monotonic(), None)
            except Exception as exc:
                snap = InventoryRecord(None, utc_now(), time.monotonic(),
                                         f"{type(exc).__name__}: {exc}")
            self._record = snap
            return snap


# --------------------------------------------------------------------------- #
# Freshness-stamped reads
# --------------------------------------------------------------------------- #

class CachedRead:
    """A read result that carries its own freshness and, on failure, its reason.

    A failed read is **not** a cached value. It is an absent value with a recorded
    reason and an age. Alpha14 stored failure dicts in the same slot as success dicts
    and gated re-reads on plain truthiness, so a single failed command-120 at connect
    time pinned "RF table unavailable" for the whole session and ``force_refresh`` had
    no caller (BACKEND_INVENTORY.md 3.2).
    """

    __slots__ = ("ok", "value", "failure", "captured_at", "attempts", "_monotonic")

    def __init__(self, ok: bool, value: dict | None, failure: dict | None,
                 attempts: int = 1):
        self.ok = bool(ok)
        self.value = value
        self.failure = failure
        self.attempts = int(attempts)
        self.captured_at = utc_now()
        self._monotonic = time.monotonic()

    @classmethod
    def success(cls, value: dict, attempts: int = 1) -> "CachedRead":
        return cls(True, value, None, attempts)

    @classmethod
    def failure_of(cls, payload: dict, attempts: int = 1) -> "CachedRead":
        return cls(False, None, payload, attempts)

    def age(self) -> float:
        return time.monotonic() - self._monotonic

    def is_fresh(self, ttl: float) -> bool:
        return self.age() <= float(ttl)

    def freshness(self) -> dict:
        return {
            "captured_at": self.captured_at,
            "age_seconds": round(self.age(), 3),
            "attempts": self.attempts,
            "read_state": "value" if self.ok else "absent",
        }


# --------------------------------------------------------------------------- #
# ContainerId -> live transport facts
# --------------------------------------------------------------------------- #

def resolve_transport(inventory: dict | None, container_id: str | None, *,
                      ground_ip: str, host_prefix: int,
                      expected_vid: str | None = None,
                      expected_pid: str | None = None) -> dict:
    """Re-derive one physical device's volatile transport facts from current state.

    Keyed by ContainerId, never by position in the inventory and never by device-side
    IP. Fails closed: an unknown ContainerId, a missing sibling, or two interfaces of
    one kind under a single ContainerId all yield ``topology_qualified: False`` and a
    named state, rather than a best guess.
    """
    out = {
        "state": "unresolved",
        "error": None,
        "container_id": norm_container_id(container_id),
        "serial_com": None,
        "serial_pnp_device_id": None,
        "serial_status": None,
        "ifindex": None,
        "adapter_name": None,
        "adapter_description": None,
        "adapter_status": None,
        "ipv4": [],
        "host_ip_ready": False,
        "topology_qualified": False,
        "correlation_basis": "unqualified",
        "binding": None,
        "binding_rejections": [],
        "vid": None,
        "pid": None,
    }
    cid = out["container_id"]
    if not cid:
        out["state"] = "container_id_absent"
        out["error"] = "The selected device has no Windows ContainerId; RNDIS correlation cannot be proven."
        return out
    if not isinstance(inventory, dict):
        out["state"] = "inventory_unavailable"
        out["error"] = "Current Windows USB/RNDIS inventory is unavailable."
        return out

    serial_rows = [u for u in (inventory.get("usb") or [])
                   if isinstance(u, dict) and norm_container_id(u.get("ContainerId")) == cid
                   and _is_serial_row(u) and extract_com(u.get("Name"))]
    net_rows = [n for n in (inventory.get("network") or [])
                if isinstance(n, dict) and norm_container_id(n.get("ContainerId")) == cid]

    if len(serial_rows) > 1:
        out["state"] = "serial_ambiguous"
        out["error"] = "More than one serial interface reports the selected device ContainerId."
        return out
    if len(net_rows) > 1:
        out["state"] = "network_ambiguous"
        out["error"] = "More than one network interface reports the selected device ContainerId."
        return out

    if serial_rows:
        srow = serial_rows[0]
        out["serial_com"] = extract_com(srow.get("Name"))
        out["serial_pnp_device_id"] = str(srow.get("PNPDeviceID") or "") or None
        out["serial_status"] = srow.get("Status")
        out["vid"], out["pid"] = vid_pid(out["serial_pnp_device_id"])

    if (expected_vid or expected_pid) and out["serial_pnp_device_id"]:
        if (expected_vid and out["vid"] != expected_vid) or (expected_pid and out["pid"] != expected_pid):
            out["state"] = "vid_pid_mismatch"
            out["error"] = "The interface now holding this ContainerId does not match the connected device VID/PID."
            return out

    if not net_rows:
        out["state"] = "network_absent" if serial_rows else "container_id_absent_from_inventory"
        out["error"] = ("No RNDIS sibling currently reports the selected device ContainerId."
                        if serial_rows else
                        "The selected device ContainerId is not present in current Windows state.")
        return out

    nrow = net_rows[0]
    out["adapter_name"] = nrow.get("Name")
    out["adapter_description"] = nrow.get("InterfaceDescription")
    out["adapter_status"] = nrow.get("Status")
    try:
        out["ifindex"] = int(nrow.get("ifIndex"))
    except Exception:
        out["ifindex"] = None
    rows = _ipv4_rows(nrow.get("IPv4"))
    out["ipv4"] = rows

    if not serial_rows:
        out["state"] = "serial_absent"
        out["error"] = "No serial configuration interface currently reports the selected device ContainerId."
        return out

    # Both siblings present under one ContainerId: correlation is proven for this
    # refresh. This is the same policy as the connect-time gate, evaluated against
    # live state instead of a record.
    out["topology_qualified"] = True
    out["correlation_basis"] = "container_id"

    if not isinstance(out["ifindex"], int) or out["ifindex"] <= 0:
        out["state"] = "ifindex_unavailable"
        out["error"] = "The correlated RNDIS adapter did not report a usable interface index."
        return out

    for row in rows:
        ip = str(row.get("IPAddress") or "")
        try:
            prefix = int(row.get("PrefixLength") or -1)
        except Exception:
            prefix = -1
        addr_state = str(row.get("AddressState") or "").strip().lower()
        if not ip.startswith("192.168.3.") or ip == ground_ip or prefix != int(host_prefix):
            continue
        out["host_ip_ready"] = True
        if addr_state in _UNUSABLE_ADDRESS_STATES:
            out["binding_rejections"].append({"ip": ip, "address_state": row.get("AddressState")})
            continue
        out["binding"] = (ip, out["ifindex"])
        out["state"] = "resolved"
        return out

    if out["binding_rejections"]:
        out["state"] = "address_not_usable"
        out["error"] = ("The correlated RNDIS host address is not in a usable Windows address state "
                        "(duplicate or tentative).")
    else:
        out["state"] = "host_address_pending"
        out["error"] = "The correlated RNDIS adapter has no configured host address on the device subnet yet."
    return out


# --------------------------------------------------------------------------- #
# The selected device
# --------------------------------------------------------------------------- #

class SelectedDevice:
    """One selected physical device: stable keys stored, volatile facts resolved."""

    def __init__(self, *, candidate: dict, identity: dict):
        c = dict(candidate or {})
        self.candidate_id: str | None = c.get("id")
        self.physical_root: str | None = c.get("physical_root")
        self.container_id = norm_container_id(c.get("container_id"))
        self.serial_container_id = norm_container_id(c.get("serial_container_id"))
        self.network_container_id = norm_container_id(c.get("network_container_id"))
        self.serial_pnp_device_id: str | None = c.get("serial_pnp_device_id")
        self.vid, self.pid = vid_pid(self.serial_pnp_device_id)
        if not self.vid:
            self.vid, self.pid = c.get("vid"), c.get("pid")
        # Raw command-60 identity, kept exactly as the vendor returned it. Display
        # humanization happens at render time and never keys anything here.
        self.identity = dict(identity or {})
        # The COM number is only a starting point: it can change across a vendor
        # restart, so it is re-resolved by ContainerId whenever inventory allows.
        self.last_known_serial_com: str | None = c.get("serial_com")
        self.connected_at = utc_now()
        self._connected_monotonic = time.monotonic()
        # Retained strictly as a diagnostic record of what connect observed. Nothing
        # derives live transport facts from it.
        self.connect_record = c
        # Explicit IP selections have their own observed services, never a
        # fabricated command-60 identity or a borrowed USB/COM binding.
        self.network_target = c.get("network_target") if isinstance(c.get("network_target"), dict) else None
        # Most recent live-resolved candidate row for this device.
        self.live_row: dict | None = None

    @property
    def correlation_container_id(self) -> str | None:
        return self.serial_container_id or self.container_id

    def session_age(self) -> float:
        return time.monotonic() - self._connected_monotonic

    def stable_keys(self) -> dict:
        return {
            "candidate_id": self.candidate_id,
            "physical_root": self.physical_root,
            "container_id": self.container_id,
            "serial_container_id": self.serial_container_id,
            "network_container_id": self.network_container_id,
            "serial_pnp_device_id": self.serial_pnp_device_id,
            "vid": self.vid,
            "pid": self.pid,
            "raw_device_name": self.identity.get("device_name"),
            "serial_number": self.identity.get("serial_number"),
            "firmware": self.identity.get("firmware"),
            "hardware": self.identity.get("hardware"),
            "connected_at": self.connected_at,
            "session_age_seconds": round(self.session_age(), 3),
        }


class DeviceSession:
    """The one object every page consumes.

    Holds the selected device, resolves its volatile transport facts live, and owns
    the freshness-stamped cached reads. ``mirror`` is the legacy ``ACTIVE_CONNECTION``
    dict, kept in sync so the qualified write path and the fleet-record key continue
    to read exactly the values they read before this model existed.
    """

    def __init__(self, *, mirror: dict, inventory: InventoryCache, policy: dict,
                 transport_max_age: float = 2.0, identity_changed=None):
        self._lock = threading.RLock()
        self._mirror = mirror
        self.inventory = inventory
        self.policy = policy
        self.transport_max_age = float(transport_max_age)
        self._identity_changed = identity_changed
        self._device: SelectedDevice | None = None
        self._rf: CachedRead | None = None
        self._ground_status: dict | None = None
        self._ground_local_bb_id: str | None = None
        self._serial_bundle: dict | None = None
        self._connect_diagnostics: dict = {}
        # Monotonic token bumped on every connect and every clear-of-a-device. An async
        # device query captures it before the call and discards its result if the token
        # has moved (the session was cleared or switched to another device meanwhile), so
        # a slow read for device A can never overwrite state now belonging to device B.
        self._generation = 0

    # -- lifecycle ---------------------------------------------------------- #

    @property
    def device(self) -> SelectedDevice | None:
        return self._device

    @property
    def connected(self) -> bool:
        return self._device is not None

    @property
    def generation(self) -> int:
        """Current session generation (see _generation). Capture before an async read."""
        return self._generation

    def still_present(self, inventory: dict | None) -> bool:
        """Is the selected device still in this inventory?

        True when there is no selected device, the inventory cannot be evaluated, or no
        usable identity key exists (never false-clear on a transient failure). False ONLY
        when a valid inventory definitively lacks the device -- the real "USB pulled"
        signal. Callers must pass an inventory they know is fresh/authoritative (snap.ok).

        The device is matched by, in order of strength:
          1. ContainerId (authoritative -- but many bench units connect over a serial
             CDC-ACM gadget that has NO real ContainerId, see norm_container_id);
          2. the serial PnP instance path (uniquely identifies a serial-only device);
          3. the COM number (last resort; weak, because Windows can renumber it).
        A real ContainerId or serial PnP id is DECISIVE: if present on the device and a
        valid inventory does not contain it, the device is gone. COM matching is used only
        when neither stronger key exists. This is what makes a cold USB pull on a
        serial-only session self-heal instead of waiting for a manual refresh.
        """
        dev = self._device
        if dev is None:
            return True
        if dev.network_target is not None:
            return True  # USB inventory cannot establish Ethernet liveness.
        if not isinstance(inventory, dict):
            return True
        usb = [u for u in (inventory.get("usb") or []) if isinstance(u, dict)]
        net = [n for n in (inventory.get("network") or []) if isinstance(n, dict)]

        strong_key = False
        cid = norm_container_id(dev.correlation_container_id)
        if cid:
            strong_key = True
            if any(norm_container_id(r.get("ContainerId")) == cid for r in usb + net):
                return True
        spnp = (dev.serial_pnp_device_id or "").strip().upper()
        if spnp:
            strong_key = True
            if any(str(u.get("PNPDeviceID") or "").strip().upper() == spnp for u in usb):
                return True
        if strong_key:
            return False        # had a decisive key, a valid inventory lacks it -> gone

        com = (dev.last_known_serial_com or "").strip().upper()
        if com:                 # no ContainerId and no serial PnP id -- fall back to COM
            return any(extract_com(u.get("Name")) == com for u in usb)
        return True             # nothing to go on -> cannot evaluate, do not clear

    def connect(self, *, candidate: dict, identity: dict, serial_bundle: dict | None = None,
                ground_status: dict | None = None, diagnostics: dict | None = None) -> SelectedDevice:
        with self._lock:
            self._device = SelectedDevice(candidate=candidate, identity=identity)
            self._serial_bundle = serial_bundle
            self._ground_status = ground_status
            self._ground_local_bb_id = (ground_status or {}).get("local_bb_id")
            self._connect_diagnostics = dict(diagnostics or {})
            self._rf = None
            self._generation += 1
            self._sync_mirror()
            return self._device

    def clear(self) -> None:
        with self._lock:
            had_device = self._device is not None
            self._device = None
            self._rf = None
            self._ground_status = None
            self._ground_local_bb_id = None
            self._serial_bundle = None
            self._connect_diagnostics = {}
            if had_device:
                self._generation += 1
            self._sync_mirror()

    def set_ground_status(self, status: dict | None, *, generation: int | None = None) -> None:
        with self._lock:
            if self._device is None:
                # Ground state without a selected device has nothing to belong to.
                return
            if self._device.network_target is not None:
                return  # Legacy Ground polling is bound to the USB policy address.
            if generation is not None and generation != self._generation:
                # Stale async result: captured for an earlier session/device. Discard it
                # rather than overwrite state that now belongs to a different device.
                return
            self._ground_status = status
            if status and status.get("local_bb_id"):
                self._ground_local_bb_id = status["local_bb_id"]
            self._sync_mirror()

    # -- live transport ----------------------------------------------------- #

    def transport(self, max_age: float | None = None, force: bool = False) -> dict:
        """Volatile transport facts for the selected device, resolved right now."""
        dev = self._device
        if dev is not None and dev.network_target is not None:
            target = dev.network_target
            return {"state": "ethernet_selected", "error": None,
                    "binding": None, "serial_com": None, "serial_com_is_live": False,
                    "ifindex": target.get("if_index"), "source_ip": target.get("source_ip"),
                    "host_ip_ready": True, "ipv4": [], "topology_qualified": False,
                    "correlation_basis": "operator_selected_ip",
                    "network_target": target, "inventory": {"available": False, "reason": "Ethernet selection is independent of USB inventory"}}
        if dev is None:
            return {"state": "no_selected_device", "error": "No device is selected.",
                    "topology_qualified": False, "correlation_basis": "unqualified",
                    "binding": None, "serial_com": None, "ifindex": None,
                    "host_ip_ready": False, "ipv4": [], "inventory": {"available": False}}
        snap = self.inventory.get(self.transport_max_age if max_age is None else max_age, force=force)
        facts = resolve_transport(
            snap.inventory, dev.correlation_container_id,
            ground_ip=self.policy.get("ground"),
            host_prefix=self.policy.get("host_rndis_prefix", 24),
            expected_vid=dev.vid, expected_pid=dev.pid,
        )
        facts["inventory"] = snap.meta()
        if facts.get("serial_com") is None:
            # Inventory could not name the port this refresh. Keep serving the last
            # known COM so a transient PowerShell failure does not look like an
            # unplug, but say plainly that the value is not live.
            facts["serial_com"] = dev.last_known_serial_com
            facts["serial_com_is_live"] = False
        else:
            facts["serial_com_is_live"] = True
            with self._lock:
                dev.last_known_serial_com = facts["serial_com"]
        return facts

    def network_binding(self, max_age: float | None = None) -> tuple[str, int] | None:
        return self.transport(max_age).get("binding")

    def network_binding_detail(self, max_age: float | None = None) -> dict:
        facts = self.transport(max_age)
        return {
            "binding": facts.get("binding"),
            "state": facts.get("state"),
            "error": facts.get("error"),
            "topology_qualified": facts.get("topology_qualified"),
            "correlation_basis": facts.get("correlation_basis"),
            "ifindex": facts.get("ifindex"),
            "host_ip_ready": facts.get("host_ip_ready"),
            "adapter_status": facts.get("adapter_status"),
            "inventory": facts.get("inventory"),
        }

    def serial_port(self, max_age: float | None = None) -> str | None:
        dev = self._device
        if dev is None:
            return None
        return self.transport(max_age).get("serial_com") or dev.last_known_serial_com

    def live_candidate(self, max_age: float | None = None) -> dict | None:
        """The candidate shape every page already reads, rebuilt from live state.

        Stable identity comes from the device object; ifIndex, IPv4, adapter status,
        COM number and qualification come from this refresh. The connect-time record
        supplies only presentation leftovers that are not transport facts.
        """
        dev = self._device
        if dev is not None and dev.network_target is not None:
            return {**dev.connect_record, "identity_proven": False, "identity": None,
                    "serial_com": None, "transport": "ETHERNET", "topology_qualified": False}
        if dev is None:
            return None
        facts = self.transport(max_age)
        record = dev.connect_record
        transports = []
        if facts.get("serial_com"):
            transports.append(f"SERIAL {facts['serial_com']}")
        if facts.get("ifindex"):
            transports.append("USB-C / RNDIS")
        ident = dev.identity
        candidate = {
            "id": dev.candidate_id,
            "physical_root": dev.physical_root,
            "label": ((f"{ident.get('device_name')} — " + " + ".join(transports))
                      if ident.get("device_name") else record.get("label")),
            "device_name": ident.get("device_name"),
            "device_image": ident.get("device_image"),
            "identity_proven": bool(ident.get("device_name")),
            "identity": ident,
            "identity_probe_in_progress": False,
            "identity_error": None,
            "transport": " + ".join(transports),
            "serial_com": facts.get("serial_com"),
            "serial_port": record.get("serial_port"),
            "serial_pnp_device_id": facts.get("serial_pnp_device_id") or dev.serial_pnp_device_id,
            "container_id": dev.container_id,
            "serial_container_id": dev.serial_container_id,
            "network_container_id": dev.network_container_id,
            "topology_qualified": bool(facts.get("topology_qualified")),
            "correlation_basis": facts.get("correlation_basis"),
            "ifindex": facts.get("ifindex"),
            "adapter_name": facts.get("adapter_name"),
            "adapter_description": facts.get("adapter_description"),
            "adapter_status": facts.get("adapter_status"),
            "pnp_device_id": record.get("pnp_device_id"),
            "vid": dev.vid,
            "pid": dev.pid,
            "ipv4": facts.get("ipv4") or [],
            "host_ip_ready": bool(facts.get("host_ip_ready")),
            "target_host_ip": self.policy.get("host_rndis_ip"),
            "target_prefix": self.policy.get("host_rndis_prefix"),
            # Live-resolution diagnostics. These are the fields BACKEND_INVENTORY 3.5
            # item 4 asks to surface; they are produced here so the operator has a
            # named reason rather than a bare UNAVAILABLE.
            "transport_state": facts.get("state"),
            "transport_resolved_at": (facts.get("inventory") or {}).get("captured_at"),
            "transport_age_seconds": (facts.get("inventory") or {}).get("age_seconds"),
            "network_qualification_error": facts.get("error") if not facts.get("topology_qualified") else None,
            "network_binding_error": facts.get("error") if facts.get("topology_qualified") and not facts.get("binding") else None,
        }
        for key in ("network_config_error",):
            if record.get(key):
                candidate[key] = record[key]
        with self._lock:
            if self._device is dev:
                dev.live_row = candidate
                self._mirror["candidate"] = candidate
        return candidate

    # -- freshness-stamped reads ------------------------------------------- #

    @property
    def rf_read(self) -> CachedRead | None:
        return self._rf

    def record_rf_success(self, value: dict) -> CachedRead:
        with self._lock:
            attempts = (self._rf.attempts + 1) if self._rf else 1
            self._rf = CachedRead.success(value, attempts)
            self._sync_mirror()
            return self._rf

    def record_rf_failure(self, payload: dict) -> CachedRead:
        with self._lock:
            attempts = (self._rf.attempts + 1) if self._rf else 1
            self._rf = CachedRead.failure_of(payload, attempts)
            self._sync_mirror()
            return self._rf

    def rf_needs_read(self, success_ttl: float, failure_backoff: float,
                      force: bool = False) -> bool:
        entry = self._rf
        if force or entry is None:
            return True
        if not entry.ok:
            # A failure is an absent table with an age, never a cached table. It is
            # retried once the backoff elapses instead of being pinned for the session.
            return entry.age() >= failure_backoff
        return not entry.is_fresh(success_ttl)

    def set_serial_bundle(self, report: dict | None) -> None:
        with self._lock:
            self._serial_bundle = report
            self._sync_mirror()

    def set_identity(self, identity: dict) -> None:
        """Refresh the raw command-60 identity of the already-selected device."""
        changed = False
        with self._lock:
            if self._device is not None and identity:
                fields=('device_name','serial_number','hardware','hardware_version','firmware')
                changed=any(self._device.identity.get(k)!=identity.get(k)for k in fields)
                self._device.identity = dict(identity)
            self._sync_mirror()
        # Never call another owner while holding the selected-device lock.
        if changed and self._identity_changed is not None:
            self._identity_changed()

    # -- documents ---------------------------------------------------------- #

    def state_document(self) -> dict:
        dev = self._device
        if dev is None:
            return {"active": {
                "candidate_id": None, "candidate": None, "serial_identity": None,
                "rf_bands": None, "ground_local_bb_id": None, "network_binding": None,
                "connected": False, "stable_keys": None, "transport": None, "reads": None,
            }}
        candidate = self.live_candidate()
        facts = self.transport()
        binding = facts.get("binding")
        rf = self._rf
        return {"active": {
            # Contract keys, unchanged shape.
            "candidate_id": dev.candidate_id,
            "candidate": candidate,
            "serial_identity": None if dev.network_target is not None else dev.identity,
            "network_target": dev.network_target,
            "rf_bands": rf.value if (rf and rf.ok) else None,
            "ground_local_bb_id": self._ground_local_bb_id,
            "network_binding": ({"container_id": dev.correlation_container_id,
                                 "source_ip": binding[0], "ifindex": binding[1]}
                                if binding else None),
            # Additive: the authoritative model itself.
            "connected": True,
            "stable_keys": dev.stable_keys(),
            "transport": {k: v for k, v in facts.items() if k != "ipv4"},
            "reads": {
                "rf_bands": (rf.freshness() if rf else {"read_state": "never_attempted"}),
            },
            "connect_diagnostics": self._connect_diagnostics,
        }}

    # -- legacy mirror ------------------------------------------------------ #

    def _sync_mirror(self) -> None:
        """Keep ACTIVE_CONNECTION in step for consumers not yet ported to this model.

        The qualified RF write path and the local device-record key still read that
        dict directly. Mirroring is deliberate and temporary; the session object is
        the authority, and only successful reads ever reach the mirror -- a failed RF
        read leaves ``rf_bands`` absent so write qualification fails closed on it.
        """
        dev = self._device
        rf = self._rf
        if dev is None:
            self._mirror.update({
                "candidate_id": None, "candidate": None, "serial_identity": None,
                "rf_bands": None, "serial_bundle": None, "ground_status": None,
                "ground_local_bb_id": None, "network_binding": None,
                "network_target": None,
            })
            return
        if dev.network_target is not None:
            self._mirror.update({"candidate_id": dev.candidate_id,
                "candidate": dev.connect_record, "serial_identity": None,
                "rf_bands": None, "serial_bundle": None, "ground_status": None,
                "ground_local_bb_id": None, "network_binding": None,
                "network_target": dev.network_target})
            return
        # peek(), never get(): the mirror must not stall other session callers behind a
        # PowerShell refresh while this lock is held. The live binding is computed
        # separately by state_document() and by _active_network_binding().
        binding = resolve_transport(
            self.inventory.peek().inventory, dev.correlation_container_id,
            ground_ip=self.policy.get("ground"),
            host_prefix=self.policy.get("host_rndis_prefix", 24),
        ).get("binding")
        self._mirror.update({
            "candidate_id": dev.candidate_id,
            "network_target": None,
            "candidate": dev.live_row or dev.connect_record,
            "serial_identity": dev.identity,
            "rf_bands": rf.value if (rf and rf.ok) else None,
            "serial_bundle": self._serial_bundle,
            "ground_status": self._ground_status,
            "ground_local_bb_id": self._ground_local_bb_id,
            "network_binding": ({"container_id": dev.correlation_container_id,
                                 "source_ip": binding[0], "ifindex": binding[1]}
                                if binding else None),
        })


def selftest() -> None:
    """Import-safe checks. No Windows, no device, no subprocess."""
    cid = "{11111111-2222-3333-4444-555555555555}"
    other = "{F200001E-BBBB-CCCC-DDDD-EEEEEEEEEEEE}"
    serial_pnp = r"USB\VID_1D77&PID_A4A2&MI_02\7&AAA&0&0002"
    net_pnp = r"USB\VID_1D77&PID_A4A2&MI_00\7&AAA&0&0000"

    def inv(ipv4, ncid=cid):
        return {"platform": "Windows", "supported": True,
                "usb": [{"Name": "USB Serial Device (COM10)", "PNPClass": "Ports",
                         "Status": "OK", "PNPDeviceID": serial_pnp, "ContainerId": cid}],
                "network": [{"Name": "Ethernet 4", "InterfaceDescription": "Remote NDIS",
                             "ifIndex": 29, "Status": "Up", "PnPDeviceID": net_pnp,
                             "ContainerId": ncid, "IPv4": ipv4}]}

    policy = {"ground_ip": "192.168.3.102", "host_prefix": 24}
    ready = resolve_transport(inv([{"IPAddress": "192.168.3.103", "PrefixLength": 24}]), cid, **policy)
    assert ready["binding"] == ("192.168.3.103", 29), ready
    assert ready["topology_qualified"] is True

    # The failure Alpha14 could not recover from: no address at connect time.
    pending = resolve_transport(inv([]), cid, **policy)
    assert pending["binding"] is None and pending["state"] == "host_address_pending"
    # ...and the same device once Windows finishes assigning it.
    assert resolve_transport(inv([{"IPAddress": "192.168.3.103", "PrefixLength": 24}]),
                             cid, **policy)["binding"] == ("192.168.3.103", 29)

    # Fail closed: sibling under a different ContainerId is never usable.
    mismatched = resolve_transport(inv([{"IPAddress": "192.168.3.103", "PrefixLength": 24}], other), cid, **policy)
    assert mismatched["binding"] is None and mismatched["topology_qualified"] is False

    # Fail closed: a duplicate/tentative host address is not a source address.
    dup = resolve_transport(inv([{"IPAddress": "192.168.3.103", "PrefixLength": 24,
                                  "AddressState": "Duplicate"}]), cid, **policy)
    assert dup["binding"] is None and dup["state"] == "address_not_usable"
    assert dup["host_ip_ready"] is True

    # Fail closed: two serial interfaces under one ContainerId is ambiguity.
    amb = inv([{"IPAddress": "192.168.3.103", "PrefixLength": 24}])
    amb["usb"].append({"Name": "USB Serial Device (COM11)", "PNPClass": "Ports",
                       "Status": "OK", "PNPDeviceID": serial_pnp + "X", "ContainerId": cid})
    assert resolve_transport(amb, cid, **policy)["state"] == "serial_ambiguous"

    # A failed read is an absent value with an age, not a cached value.
    fail = CachedRead.failure_of({"available": False, "error_code": "X"})
    assert fail.ok is False and fail.value is None and fail.age() >= 0

    gate = SerialGate()
    with gate.hold("a"):
        assert gate.busy is True
        with gate.hold("a-nested"):   # reentrant for the holding thread
            pass
        blocked = []
        t = threading.Thread(target=lambda: blocked.append(_try_hold(gate)))
        t.start(); t.join()
        assert blocked == [False], blocked
    assert gate.busy is False
    print("device_session selftest: PASS")


def _try_hold(gate: SerialGate) -> bool:
    try:
        with gate.hold("other-thread", timeout=0):
            return True
    except SerialBusyError:
        return False


if __name__ == "__main__":
    selftest()
