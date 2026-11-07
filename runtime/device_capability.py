"""Which pages apply to the connected device class.

Derived from the **raw command-60 device name only**. Never from VID/PID: this bench's
own unit reports VID 0x1D77 (`VIDConst.Ascent_VRX_Pro`) while command 60 returns
`Ascent_VRX_max_WF`, so a VID-derived class would be wrong twice over -- wrong product
line and wrong variant (CLAUDE.md, Multi-device correlation).

Two axes, both explicit. Visibility is decided first by the **connection state** --
one of the five in ``CONNECTION_STATES`` -- and only then, in the one state that says
a live identified device exists, by the device class derived from that name.

Fail closed before a device, fail open after one. With no live identified device
(NO DEVICE, SCANNING, DETECTED-but-not-connected) only ``NO_DEVICE_VISIBLE`` appears: a
page that needs a live device to say anything true must not be reachable when there is
none. Once a session is open, an unrecognized name or a recognized class we hold no
capability evidence for generally shows pages, because hiding a page the device really
supports is then the worse error. Hub/RC are explicit exceptions: only a connected,
applicable reported camera profile may expose them.

Corrected 2026-09-08, on hardware: the sidebar showed all six primary pages while the
connection bar read ``SCANNING…``. Every not-connected case arrived here as the single
fact "no raw name", and that one case failed open. NO DEVICE, SCANNING and DETECTED are
now separate states with an entry each, so no state can inherit another's policy.

-------------------------------------------------------------------------------
This is NOT vendor parity. It is an Ascent Control behaviour.
-------------------------------------------------------------------------------

PC Tool 2.0.37's sidebar is static. `Caddx_PCTool.SidebarCtrl` declares fixed panels
-- pan_firmware, pan_Channel, pan_RCMode, pan_CamHub, pan_setting, pan_HelpCenter,
pan_prodSer, pan_customerService -- and neither it nor `MainFrm` ever assigns
`.Visible` on one from a device name. The vendor's only device-class gate is the
function-card list in `MainFrm.OnFindDeviceFrm`:

    if (e.DeviceName.Contains("Ascent") || ... ) DispFunCard(1, { FuntionType.upgrade })
    else if (e.DeviceName.Contains("GM") || e.DeviceName == "SimGM")
                                          DispFunCard(1, { FuntionType.gmSet })

So the vendor shows Hub and RC Mode for every connected device, and gates a gimbal to
gimbal settings alone. Only that second half is parity; hiding Hub/RC for a receiver is
ours. Do not describe it as matching the stock tool.

-------------------------------------------------------------------------------
Evidence for the two surfaces that are hidden
-------------------------------------------------------------------------------

HUB MANAGEMENT and RC CHANNEL MANAGEMENT are air-side surfaces:

  * Both configuration files live on the **Sky (air-unit) filesystem**:
    `rootfs_19_2_5/fpv/mipi_hub.json` and `rootfs_19_2_5/fpv/msp_rc_cfg.json`,
    extracted from vendor `Ascent_G_Sky_19_2_5.img`, alongside `mipi_hub.ini`
    (`[hub_link] selected_sensor=hdmi`) and `user_cfg.json`.
  * `mipi_hub.json` enumerates camera inputs and a flight controller: `node0..node3`
    with `dev_name` in {Z8, MAX, Z40, HDMI, none} plus `"fly_ctrl": "betaFlight"`.
    The vendor editor `Caddx_PCTool.CamHubCtrl` exposes exactly those as
    `sel_vtx`, `sel_cam1`, `sel_cam2`, `sel_cam3`, `sel_hdmi`.
  * `msp_rc_cfg.json` is MSP RC channel mapping (`slot0..slot3` with min/max), MSP
    being the flight-controller protocol.

A VRX receiver or goggle has no MIPI camera inputs and no flight controller, so
neither surface exists on it. That is the whole of the hiding policy.

DEVICE NICKNAMES stays visible for every baseband device: it is where
PRIMARY/FALLBACK receiver provisioning lands and is host-local besides.

RF BAND CHANNEL MANAGEMENT is now gated to the ground receiver (VRX), by the
user on 2026-10-13. This REVERSES the earlier stance recorded here -- that a
GT Pro answering command 120 with `unkonwn cmd` is "a firmware capability result
the RF page reports itself, not a device class." On the bench that produced a
page that can only ever fail on an air unit: the BB table read is unsupported
there, and the LIVE RF STATE queries (0x51/0x52/0x53) run over Ground
configuration UDP, which an air unit has no path for. A page that cannot succeed
reads as broken, so it is withheld rather than shown failing. NOTE the Sky does
carry the 120 handler, so Sky-side RF editing is technically possible; it is
withheld too under the plain VRX-only directive -- drop "rf" from the ROLE_AIR
entry in `_HIDDEN_BY_ROLE` to bring Sky back. An unrecognized class still fails
open (RF shown), per the standing rule.
"""
from __future__ import annotations

import re

# Route IDs, matching the nav `data-view` values. Display labels are fixed by
# docs/NAVIGATION_CONTRACT.md and are not this module's business.
# Order matches the sidebar markup. DEVICE INFO leads: it is the page that answers
# "what am I connected to", it is reachable in every connection state, and it is the
# one an operator opens first. DEVICE NICKNAMES is host-local bookkeeping and moved
# below the device pages on 2026-09-23, by the user.
# In DOCUMENT ORDER: the navigation contract is asserted element-wise against
# index.html's data-view attributes, so this list is the sidebar read top to
# bottom -- primary buttons first, then the WIDGETS menu, then ADVANCED.
PAGES = ("device", "widgetmanager", "rf", "hub", "rc", "fleet", "firmware",
         # MANAGE REPEATER. Device-class page, withheld for every role except
         # link infrastructure: a page that offers capabilities a device does not
         # have is worse than one that is absent.
         "repeater",
         "maps",
         # NETRUNNER. The receiver's own network: which interfaces exist, which
         # are up, and -- on a MAX -- the Wi-Fi radio. It needs a DEVICE, which
         # is why it is absent from NO_DEVICE_VISIBLE: there is no host-local
         # half of "what interfaces does that unit have". It also needs
         # maintenance access, but that is the WIDGETS menu's gate rather than
         # this one, because it is a property of the receiver's state and not
         # of its device class.
         "netrunner",
         # PICKER. The standalone RC4/RC5 target picker, peer to MAPSTER and
         # NETRUNNER in the WIDGETS menu. It needs a live receiver: the switch
         # acts on the receiver's real link state, and the on-unit picker is
         # read from discovery. With no device it is hidden, like NETRUNNER.
         "picker",
         # WIDGET LAYOUT. The organizer for all overlay widgets. It arranges the
         # widgets that render on the connected receiver's overlay and deploys
         # the layout to it, so it needs a live device and is hidden without one.
         "widgetlayout",
         "recovery",
         "settings", "diagnostics")

# Device-class applicability only: Widget Manager additionally requires verified
# receiver Service Mode in the UI; inclusion here never grants maintenance access.
# Host-local or universal pages. No device class ever removes these: DEVICE INFO must
# stay reachable precisely when a device is unrecognized, and SETTINGS/DIAGNOSTICS/
# FIRMWARE UPGRADE describe the host, not the peer.
ALWAYS_VISIBLE = ("device", "firmware", "maps", "recovery",
                  "settings", "diagnostics")

# What stays reachable when there is no live, identified device: the host-local four,
# plus DEVICE NICKNAMES. Decided by the user, 2026-09-08. The fleet table on that
# page does need a live device and says so itself, but the LOCAL NICKNAMES panel on
# it is a host-local store -- no fleet read, no device lock, no device command
# (docs/HARDWARE_BUGS_2026-09-07.md bug 1, deliberately made device-free) -- and it is
# reachable from nowhere else in the navigation contract. Hiding the page would undo
# that. Hub/RC require a connected, explicitly applicable device.
NO_DEVICE_VISIBLE = ("device", "fleet", "firmware", "maps", "recovery",
                     "settings", "diagnostics")

# Why a page that is in NO_DEVICE_VISIBLE but not in ALWAYS_VISIBLE stays visible with
# no device. It must not read as a claim that the whole page works.
_PARTLY_HOST_LOCAL = {
    "fleet": ("Reachable with no device only for its LOCAL NICKNAMES panel, which "
              "is a host-local store: no fleet read, no device lock, no device command. "
              "The fleet list itself needs a live, identified device and says so."),
}

assert set(ALWAYS_VISIBLE) <= set(NO_DEVICE_VISIBLE)
assert set(NO_DEVICE_VISIBLE) - set(ALWAYS_VISIBLE) == set(_PARTLY_HOST_LOCAL)

# --------------------------------------------------------------------------- #
# Connection states -- the five distinct states the frontend can be in.
#
# Total and explicitly enumerated. Every member of CONNECTION_STATES has its own entry
# in _STATE_POLICY, `page_visibility` refuses a state that is not a member, and a test
# asserts the two agree -- so a sixth state cannot quietly inherit a fifth one's
# policy, which is exactly how SCANNING ended up showing every page.
# --------------------------------------------------------------------------- #

STATE_NO_DEVICE = "no_device"
STATE_SCANNING = "scanning"
STATE_DETECTED = "detected"
STATE_CONNECTED_RECOGNIZED = "connected_recognized"
STATE_CONNECTED_UNRECOGNIZED = "connected_unrecognized"

#: Every connection state, in the order an operator meets them.
CONNECTION_STATES = (
    STATE_NO_DEVICE,
    STATE_SCANNING,
    STATE_DETECTED,
    STATE_CONNECTED_RECOGNIZED,
    STATE_CONNECTED_UNRECOGNIZED,
)

# What a state does to the page set:
#   minimal -- ALWAYS_VISIBLE only; there is no live identified device to read.
#   by_role -- the device-class table further down.
#   open    -- every page; a live device whose class we cannot name.
POLICY_MINIMAL = "minimal"
POLICY_BY_ROLE = "by_role"
POLICY_OPEN = "open"

_STATE_POLICY: dict[str, dict] = {
    STATE_NO_DEVICE: {
        "policy": POLICY_MINIMAL,
        "label": "NO DEVICE DETECTED",
        "live_device": False,
        "reason": ("No Ascent USB interface is detected. This page needs a live, "
                   "identified device, so it is hidden rather than shown empty."),
    },
    STATE_SCANNING: {
        "policy": POLICY_MINIMAL,
        "label": "SCANNING FOR A DEVICE",
        "live_device": False,
        # Deliberately the same page set as NO DEVICE. Probing is not evidence of a
        # peer, and nothing is known about one either way.
        "reason": ("Discovery is still probing and no device identity has been "
                   "established yet. This page needs a live, identified device, so it "
                   "is hidden rather than shown empty -- the same page set as NO "
                   "DEVICE, because neither state knows anything about a peer."),
    },
    STATE_DETECTED: {
        "policy": POLICY_MINIMAL,
        "label": "DEVICE DETECTED — NOT CONNECTED",
        "live_device": False,
        # Discovery has a command-60 name, but no session is open, so no page can read
        # anything. A detected name must not unhide a page it cannot fill.
        "reason": ("A device is detected and identified by discovery, but no session "
                   "is open, so there is nothing live to read. CONNECT to enable this "
                   "page."),
    },
    STATE_CONNECTED_RECOGNIZED: {
        "policy": POLICY_BY_ROLE,
        "label": "CONNECTED — RECOGNIZED DEVICE CLASS",
        "live_device": True,
        "reason": "",  # per-role reasons come from _HIDDEN_BY_ROLE
    },
    STATE_CONNECTED_UNRECOGNIZED: {
        "policy": POLICY_OPEN,
        "label": "CONNECTED — UNRECOGNIZED DEVICE CLASS",
        "live_device": True,
        "reason": ("A session is open but this device class is not in the capability "
                   "table. Every page stays visible rather than risk hiding a real "
                   "capability."),
    },
}

ROLE_UNKNOWN = "unknown"
ROLE_UNIDENTIFIED = "unidentified"
ROLE_RECEIVER = "receiver"
ROLE_AIR = "air"
ROLE_CAMERA_HUB = "camera_hub"
ROLE_LINK = "link"
ROLE_GIMBAL = "gimbal"

# Ordered: the first pattern that matches a normalized raw name wins. `_hub` is tested
# before the air-unit patterns because `ascent_gt_max_wf_hub` is a camera hub, not a
# plain GT Max WF.
_ROLE_PATTERNS: tuple[tuple[str, str, str], ...] = (
    (ROLE_GIMBAL, r"(^|_)gm\d*(_|$)|gimbal|^simgm$",
     "GM-series gimbal. Vendor gates a GM device to gimbal settings alone "
     "(MainFrm.OnFindDeviceFrm), and it does not speak the Ascent baseband protocol."),
    (ROLE_CAMERA_HUB, r"cam_?hub|(^|_)hub(_|$)",
     "Camera hub. Carries the MIPI camera inputs that mipi_hub.json describes."),
    (ROLE_RECEIVER, r"(^|_)vrx|goggles",
     "Ground-side receiver or goggle. No MIPI camera inputs and no flight controller, "
     "so mipi_hub.json and msp_rc_cfg.json have no counterpart on it."),
    (ROLE_AIR, r"(^|_)sky\d*(_|$)|vtx|(^|_)gt|lite",
     "Air unit. rootfs_19_2_5/fpv carries both mipi_hub.json and msp_rc_cfg.json."),
    (ROLE_LINK, r"relay|repeater",
     "Link infrastructure. Camera-hub and RC capability are not established for this "
     "class, so every page stays visible."),
)

_ROLE_LABELS = {
    ROLE_UNKNOWN: "UNRECOGNIZED DEVICE CLASS",
    ROLE_UNIDENTIFIED: "NO IDENTIFIED DEVICE",
    ROLE_RECEIVER: "GROUND RECEIVER",
    ROLE_AIR: "AIR UNIT",
    ROLE_CAMERA_HUB: "CAMERA HUB",
    ROLE_LINK: "LINK INFRASTRUCTURE",
    ROLE_GIMBAL: "GIMBAL",
}

# Positive evidence only. A page absent from a role's entry here is visible for that
# role; a role absent from this table hides nothing at all.
# ---------------------------------------------------------------------------
# Operator 2026-10-18 supersedes the historical global withholding decision.
# These are host-local editors with an explicit, separately gated device upload.
# Raw command-60 subtype is applicability evidence, never readback/capability proof.
NO_DEVICE_IO_YET: dict[str, str] = {}

# Pages this build offers at all. PAGES minus the ones withheld pending device I/O.
# Callers asserting on a complete page set should use this rather than PAGES, so a
# future page joining or leaving NO_DEVICE_IO_YET moves both together.
OFFERED_PAGES = [p for p in PAGES if p not in NO_DEVICE_IO_YET]

HUB_PROFILE_TOKENS = ("hub",)
RC_PROFILE_TOKENS = ("hub", "z8", "z40")

# Identities whose firmware string is known NOT to distinguish the camera variant.
# Matching one of these makes the RC answer unknown rather than false.
_VARIANT_AMBIGUOUS = (r"gt_?max_?hf",)


def firmware_profile_gate(page: str, firmware_profile: str | None,
                          raw_device_name: str | None = None) -> bool | None:
    """Would this page apply, given the active firmware profile?

    Returns True, False, or **None for "cannot be determined"**. None is not a
    failure mode to paper over: on a GT Max HF the identity does not say whether the
    image is a Z8 or a Z40 build, and guessing would either hide a page the operator
    needs or show one that writes a document the unit has no hardware for.

    Used by visibility and operation eligibility. Unknown qualification grants neither page visibility nor device-upload permission.
    """
    if page not in ("hub", "rc"):
        raise ValueError(f"no firmware-profile gate is defined for {page!r}")
    profile = (firmware_profile or "").lower()
    if not profile:
        return None
    tokens = HUB_PROFILE_TOKENS if page == "hub" else RC_PROFILE_TOKENS
    if any(t in profile for t in tokens):
        return True
    # No token matched. For most units that is a definite no -- normal VTX firmware
    # carries neither -- but not for a unit whose identity cannot express the
    # difference.
    if page == "rc":
        name = norm_device_name(raw_device_name)
        if name and any(re.search(pat, name) for pat in _VARIANT_AMBIGUOUS):
            return None
    return False


_HIDDEN_BY_ROLE: dict[str, dict[str, str]] = {
    # MANAGE REPEATER is listed for every role that is NOT link
    # infrastructure. An unrecognized class still sees it, which is the
    # deliberate fail-open for a live device -- and is harmless here because
    # the page itself reports NOT_A_REPEATER and offers nothing when the
    # command-60 identity is not a Relay or Repeater.
    # RF BAND CHANNEL MANAGEMENT edits the persistent BB frequency table (opcodes
    # 120/121). It is bench-proven on the VRX; a GT Pro answers 120 with
    # "unkonwn cmd" (unsupported), and the LIVE RF STATE queries (0x51/0x52/0x53)
    # run over Ground configuration UDP, which an air unit has no path for. So the
    # page can only fail on an air unit -- it is gated to the ground receiver.
    # (Sky firmware does carry the 120 handler; if Sky-side RF editing is wanted
    # later, drop "rf" from this ROLE_AIR entry. Gated to VRX per product decision
    # 2026-10-13.)
    ROLE_AIR: {
        "repeater": ("MANAGE REPEATER carries Relay/Repeater controls. This device does not identify as link infrastructure, so the page is withheld rather than offering operations it cannot perform."),
        "rf": ("RF BAND CHANNEL MANAGEMENT edits the persistent BB frequency table "
               "(opcodes 120/121). A GT Pro answers 120 with 'unkonwn cmd' and the "
               "live RF queries run over Ground configuration UDP, so the page can "
               "only fail on an air unit. It is gated to the ground receiver."),
    },
    ROLE_CAMERA_HUB: {
        "repeater": ("MANAGE REPEATER carries Relay/Repeater controls. This device does not identify as link infrastructure, so the page is withheld rather than offering operations it cannot perform."),
        "rf": ("RF BAND CHANNEL MANAGEMENT edits the ground receiver's BB frequency "
               "table. A camera hub is not on that configuration path."),
    },
    ROLE_LINK: {
        "rf": ("RF BAND CHANNEL MANAGEMENT edits the ground receiver's persistent BB "
               "frequency table (opcodes 120/121); a Relay/Repeater is not that "
               "device. Gated to the ground receiver."),
    },
    ROLE_RECEIVER: {
        "repeater": ("MANAGE REPEATER carries Relay/Repeater controls. This device does not identify as one, so the page is withheld rather than offering operations it cannot perform."),
        "hub": ("HUB MANAGEMENT configures MIPI camera inputs and a flight controller "
                "(mipi_hub.json node0..3 / fly_ctrl), which exist on the air unit's "
                "filesystem. A ground receiver has neither."),
        "rc": ("RC CHANNEL MANAGEMENT maps MSP RC channels (msp_rc_cfg.json), an "
               "air-side flight-controller surface. A ground receiver has no flight "
               "controller."),
    },
    ROLE_GIMBAL: {
        "widgetmanager": "Widget Manager requires receiver maintenance access.",
        "repeater": ("MANAGE REPEATER carries Relay/Repeater controls. This device does not identify as one, so the page is withheld rather than offering operations it cannot perform."),
        "fleet": "A gimbal is not on the Ascent baseband link and has no VRX fleet.",
        "rf": "A gimbal has no baseband RF table.",
        "hub": "A gimbal has no MIPI camera hub.",
        "rc": "A gimbal has no MSP RC configuration.",
        "netrunner": ("NETRUNNER reads a receiver's network interfaces over "
                      "maintenance access. A gimbal is a USB-serial bridge with "
                      "no network stack to read."),
        "picker": ("PICKER switches an Ascent receiver's RF target. A gimbal is "
                   "not on the Ascent baseband link and has no picker."),
        "widgetlayout": ("WIDGET LAYOUT arranges a receiver's overlay widgets. A "
                         "gimbal has no overlay to lay out."),
    },
}


def norm_device_name(value: str | None) -> str:
    """Lowercase underscore-separated form of a raw command-60 device name.

    Vendor names arrive with inconsistent separators and case -- `Ascent_VRX_max_WF`
    from command 60, `Ascent GT Max HF` in the shipped `SysParam.data`. Normalizing is
    for matching only; the raw name is what gets stored and displayed.
    """
    return re.sub(r"[^a-z0-9]+", "_", (value or "").strip().lower()).strip("_")


def classify(raw_device_name: str | None) -> dict:
    """Classify a raw command-60 device name into a device role.

    Returns ``{"role", "role_label", "normalized", "raw_device_name", "identified",
    "evidence"}``. An empty name is ``unidentified``; a non-empty unmatched name is
    ``unknown``. Both show every page, but they are different states and the UI says
    which.
    """
    key = norm_device_name(raw_device_name)
    if not key:
        return {"role": ROLE_UNIDENTIFIED, "role_label": _ROLE_LABELS[ROLE_UNIDENTIFIED],
                "normalized": "", "raw_device_name": raw_device_name, "identified": False,
                "evidence": "No command-60 identity for the selected device."}
    for role, pattern, evidence in _ROLE_PATTERNS:
        if re.search(pattern, key):
            return {"role": role, "role_label": _ROLE_LABELS[role], "normalized": key,
                    "raw_device_name": raw_device_name, "identified": True,
                    "evidence": evidence}
    return {"role": ROLE_UNKNOWN, "role_label": _ROLE_LABELS[ROLE_UNKNOWN],
            "normalized": key, "raw_device_name": raw_device_name, "identified": True,
            "evidence": ("This device class is not in the capability table. Every page "
                         "stays visible rather than risk hiding a real capability.")}


def derive_connection_state(*, connected: bool, raw_device_name: str | None,
                            discovery_reported: bool = False,
                            candidate_count: int = 0,
                            identified_candidate: bool = False) -> str:
    """Map observable facts onto exactly one member of ``CONNECTION_STATES``.

    Only an open session can produce a connected state. *Which* connected state comes
    from ``classify`` on the session's raw command-60 name, so "recognized" is decided
    in one place and cannot disagree with the role the same document reports.

    Not connected, the three states are told apart by discovery alone:

      * ``discovery_reported`` false -- the discovery poll has not reported yet, or its
        last result is too stale to use. We are probing and know nothing: **SCANNING**.
      * no candidates -- **NO DEVICE**.
      * a candidate with a proven command-60 identity -- **DETECTED**.
      * candidates but none identified yet -- **SCANNING**.

    ``discovery_reported`` defaults to false so a caller that omits it lands on
    SCANNING, the fail-closed state, rather than on NO DEVICE by accident.
    """
    if connected:
        role = classify(raw_device_name)["role"]
        if role in (ROLE_UNIDENTIFIED, ROLE_UNKNOWN):
            return STATE_CONNECTED_UNRECOGNIZED
        return STATE_CONNECTED_RECOGNIZED
    if not discovery_reported:
        return STATE_SCANNING
    if int(candidate_count or 0) <= 0:
        return STATE_NO_DEVICE
    if identified_candidate:
        return STATE_DETECTED
    return STATE_SCANNING


def page_visibility(raw_device_name: str | None, connection_state: str) -> dict:
    """Per-page visibility for one connection state and one raw command-60 name.

    ``connection_state`` is required and must be a member of ``CONNECTION_STATES``.
    There is deliberately no default: a state falling through to another state's
    policy is the bug this signature replaces. An unrecognized state raises rather
    than guessing.

    The state decides first. The raw name is consulted **only** where the state says a
    live device is present -- in the three not-connected states it is not looked at at
    all, so a detected candidate's name, or a name left over from a closed session,
    cannot select a class or unhide a page.

    Every page appears in ``pages`` with a ``visible`` flag and a ``reason``. Nothing
    is silently omitted: a hidden page carries the evidence that hid it.
    """
    policy = _STATE_POLICY.get(connection_state)
    if policy is None:
        raise ValueError(
            f"unknown connection state {connection_state!r}; expected one of "
            + ", ".join(CONNECTION_STATES))
    kind = policy["policy"]
    info = classify(raw_device_name if policy["live_device"] else None)
    hidden_by_role = _HIDDEN_BY_ROLE.get(info["role"], {}) if kind == POLICY_BY_ROLE else {}
    pages: dict[str, dict] = {}
    for page in PAGES:
        # Checked first, and before ALWAYS_VISIBLE, so neither a role nor an
        # unrecognized device class nor a host-local exemption can reinstate a page
        # that has no way to read the device.
        if page in NO_DEVICE_IO_YET:
            pages[page] = {"visible": False, "reason": NO_DEVICE_IO_YET[page],
                           "withheld_pending_device_io": True}
        elif page in ("hub", "rc"):
            applicable_role = info["role"] in (ROLE_AIR, ROLE_CAMERA_HUB)
            qualified = (firmware_profile_gate(page, raw_device_name, raw_device_name)
                         if policy["live_device"] and applicable_role else None)
            pages[page] = {"visible": bool(policy["live_device"] and applicable_role and qualified is True),
                           "profile_applicable": qualified,
                           "reason": ("Reported camera subtype applies to this configuration."
                                      if qualified is True else
                                      policy["reason"] if not policy["live_device"] else
                                      "A connected device with an applicable reported camera subtype is required.")}
        elif page in ALWAYS_VISIBLE:
            pages[page] = {"visible": True, "reason": "Host-local page; always available."}
        elif kind == POLICY_MINIMAL:
            pages[page] = ({"visible": True, "reason": _PARTLY_HOST_LOCAL[page]}
                           if page in NO_DEVICE_VISIBLE
                           else {"visible": False, "reason": policy["reason"]})
        elif kind == POLICY_OPEN:
            pages[page] = {"visible": True, "reason": policy["reason"]}
        elif page in hidden_by_role:
            pages[page] = {"visible": False, "reason": hidden_by_role[page]}
        else:
            pages[page] = {"visible": True,
                           "reason": (f"Applies to {info['role_label'].lower()}, or "
                                      "capability not established for this class.")}
    return {
        "available": True,
        "source": "raw_command_60_device_name",
        "connection_state": connection_state,
        "connection_state_label": policy["label"],
        "connection_states": list(CONNECTION_STATES),
        "visibility_policy": kind,
        "live_device": policy["live_device"],
        # False in every not-connected state: the name was not read.
        "name_consulted": policy["live_device"],
        **info,
        "pages": pages,
        "visible": [p for p in PAGES if pages[p]["visible"]],
        "hidden": [p for p in PAGES if not pages[p]["visible"]],
        "parity": ("Ascent Control behaviour, not stock PC Tool parity. PC Tool 2.0.37's "
                   "SidebarCtrl is static and shows Hub and RC Mode for every device."),
    }


def selftest() -> None:
    """Import-safe checks. No device, no subprocess, no Windows."""
    # A connected, recognized device is the only state that consults the name, so it is
    # the state every device-class check below runs in.
    live = STATE_CONNECTED_RECOGNIZED

    # The bench unit: a receiver, so no Hub and no RC.
    doc = page_visibility("Ascent_VRX_max_WF", live)
    assert doc["role"] == ROLE_RECEIVER, doc
    assert doc["hidden"] == ["hub", "rc", "repeater"], doc["hidden"]
    assert doc["pages"]["rf"]["visible"] and doc["pages"]["fleet"]["visible"]

    # Separator and case variance must not change the class.
    for name in ("Ascent VRX Max WF", "ascent-vrx-max-wf", "ASCENT_VRX_MAX_WF"):
        assert classify(name)["role"] == ROLE_RECEIVER, name

    # A bare VRX shows no Hub tab -- the stated example.
    assert page_visibility("Ascent_VRX", live)["pages"]["hub"]["visible"] is False

    # Air units: rf, hub, rc and repeater all go.
    for name in ("Ascent_G_Sky", "Ascent_Lite_VTX", "Ascent_GT_pro", "Ascent GT Max HF",
                 "ASCENT_L_SKY402", "ASCENT_H_SKY482", "ASCENT_SKY_EX1"):
        d = page_visibility(name, live)
        assert d["role"] == ROLE_AIR, (name, d["role"])
        # RF remains receiver-only and Repeater remains link infrastructure.
        # Hub/RC now follow the reported camera subtype, with unknown kept explicit.
        assert "rf" in d["hidden"] and "repeater" in d["hidden"], (name, d["hidden"])

    # A hub variant of an air unit is a camera hub, and keeps the Hub page.
    for name in ("Ascent_CamHub", "Ascent_GT_Max_WF_Hub", "Ascent_GT_pro_Hub"):
        d = page_visibility(name, live)
        assert d["role"] == ROLE_CAMERA_HUB, (name, d["role"])
        assert d["pages"]["hub"]["visible"] is True, name
        assert d["pages"]["rc"]["visible"] is True, name

    # Gimbal: vendor-evidenced, gated to the host-local pages only.
    d = page_visibility("CADDX_GM3", live)
    assert d["role"] == ROLE_GIMBAL, d
    assert d["visible"] == list(ALWAYS_VISIBLE), d["visible"]

    # ---- the five connection states, one assertion block each -------------- #
    # Every state is named here. _STATE_POLICY and CONNECTION_STATES must agree, so a
    # sixth state added to one and not the other fails immediately.
    assert set(_STATE_POLICY) == set(CONNECTION_STATES), set(_STATE_POLICY) ^ set(CONNECTION_STATES)

    minimal = list(NO_DEVICE_VISIBLE)
    # 1. NO DEVICE -- nothing detected at all.
    d = page_visibility(None, STATE_NO_DEVICE)
    assert d["visible"] == minimal, d["visible"]
    assert d["live_device"] is False and d["name_consulted"] is False, d
    # 2. SCANNING -- actively probing, no identity yet. Same page set as NO DEVICE.
    d = page_visibility(None, STATE_SCANNING)
    assert d["visible"] == minimal, d["visible"]
    assert d["visible"] == page_visibility(None, STATE_NO_DEVICE)["visible"]
    # A name reaching this state -- a stale one, or a detected candidate's -- must not
    # unhide anything.
    assert page_visibility("Ascent_G_Sky", STATE_SCANNING)["visible"] == minimal
    # 3. DETECTED but not connected -- discovery has a name, no session is open.
    d = page_visibility("Ascent_VRX_max_WF", STATE_DETECTED)
    assert d["visible"] == minimal, d["visible"]
    assert d["role"] == ROLE_UNIDENTIFIED, d["role"]
    # The device-only pages, and only those, are the ones that go. NETRUNNER
    # joined them: reading a receiver's interfaces needs the receiver, and
    # there is no host-local half of that question. PICKER and WIDGET LAYOUT
    # likewise act on a live receiver.
    assert d["hidden"] == ["widgetmanager", "rf", "hub", "rc", "repeater", "netrunner",
                           "picker", "widgetlayout"], d["hidden"]
    # A page kept for a host-local surface says so rather than implying it works.
    assert "LOCAL NICKNAMES" in d["pages"]["fleet"]["reason"], d["pages"]["fleet"]
    # 4. CONNECTED, recognized -- the device-class table applies.
    d = page_visibility("Ascent_VRX_max_WF", STATE_CONNECTED_RECOGNIZED)
    assert d["hidden"] == ["hub", "rc", "repeater"] and d["live_device"] is True, d
    # Receiver role excludes these air-side configuration operations.
    assert all(not d["pages"][p]["visible"] for p in ("hub", "rc")), d
    # 5. CONNECTED, unrecognized -- a live device we cannot classify: every page.
    d = page_visibility("Totally_New_Product_9000", STATE_CONNECTED_UNRECOGNIZED)
    # An unrecognized class still fails OPEN, so MANAGE REPEATER is among the pages
    # it keeps -- harmless, because the page itself reports NOT_A_REPEATER and
    # offers nothing when the command-60 identity is not a Relay or Repeater.
    assert d["hidden"] == ["hub", "rc"] and d["visible"] == [p for p in OFFERED_PAGES if p not in ("hub", "rc")], d
    assert d["live_device"] is True, d

    # An unknown state raises rather than inheriting a policy.
    try:
        page_visibility(None, "half_connected")
    except ValueError:
        pass
    else:
        raise AssertionError("an unknown connection state must raise")

    # ---- derive_connection_state is total and lands on all five ------------ #
    assert derive_connection_state(connected=False, raw_device_name=None,
                                   discovery_reported=True, candidate_count=0) == STATE_NO_DEVICE
    assert derive_connection_state(connected=False, raw_device_name=None,
                                   discovery_reported=True, candidate_count=2,
                                   identified_candidate=False) == STATE_SCANNING
    # No discovery report yet is SCANNING, not NO DEVICE: we are probing and know nothing.
    assert derive_connection_state(connected=False, raw_device_name=None,
                                   discovery_reported=False) == STATE_SCANNING
    assert derive_connection_state(connected=False, raw_device_name=None,
                                   discovery_reported=True, candidate_count=1,
                                   identified_candidate=True) == STATE_DETECTED
    assert derive_connection_state(connected=True,
                                   raw_device_name="Ascent_VRX_max_WF") == STATE_CONNECTED_RECOGNIZED
    for name in (None, "", "Totally_New_Product_9000"):
        assert derive_connection_state(connected=True,
                                       raw_device_name=name) == STATE_CONNECTED_UNRECOGNIZED, name
    # A detected candidate never yields a connected state without a session.
    assert derive_connection_state(connected=False, raw_device_name="Ascent_VRX_max_WF",
                                   discovery_reported=True, candidate_count=1,
                                   identified_candidate=True) == STATE_DETECTED

    # Fail-open, but only with a live device, and with exactly one exception: a
    # recognized class we hold no capability evidence for, and an unrecognized name,
    # both keep every page that is OFFERED. The two withheld for lack of device I/O
    # are never offered, on any class -- fail-open cannot reinstate a page that has
    # no way to read the device.
    # Link infrastructure: rf is gated to the ground receiver too, on top of the
    # two withheld for lack of device I/O.
    for name in ("Ascent_Relay", "Ascent_Repeater"):
        assert page_visibility(name, live)["hidden"] == ["rf", "hub", "rc"], name
    d = page_visibility("Totally_New_Product_9000", live)
    assert (d["role"] == ROLE_UNKNOWN and d["hidden"] == ["hub", "rc"]
            and d["identified"] is True), d

    # Contract: every page is always reported with a reason, in every state, and the
    # host-local four never hide.
    for state in CONNECTION_STATES:
        for name in (None, "Ascent_VRX", "CADDX_GM3", "Ascent_G_Sky", "nonsense"):
            d = page_visibility(name, state)
            assert set(d["pages"]) == set(PAGES), (state, name)
            assert d["connection_state"] == state and d["connection_state_label"], d
            for page in ALWAYS_VISIBLE:
                assert d["pages"][page]["visible"] is True, (state, name, page)
            for page in d["pages"]:
                assert d["pages"][page]["reason"], (state, name, page)


if __name__ == "__main__":
    selftest()
    print("device_capability selftest OK")
