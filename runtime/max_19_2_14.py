"""
What an Ascent MAX VRX running 19.2.14 can actually do, and how we know.

### Scope, stated first because it is the thing most easily got wrong

Everything here describes **MAX 19.2.14 only**. It must not be projected onto
Pro 19.2.14, generic Ground 19.2.14, or MAX 19.2.4. No Pro 19.2.14 target has been
established at all, and the Relay-endpoint finding below explicitly *withdraws* an
older 19.2.4 conclusion rather than carrying it forward. `applies_to()` is the gate
and it matches exactly; an unrecognised unit gets `None` -- unknown -- never a
borrowed answer.

### Evidence classes

Every capability carries one, and they are not interchangeable:

* `FW_PROVEN`      - read out of the exact shipping firmware or its own release note.
* `PROVEN_LIVE`    - observed on the bench unit.
* `STRONG_INFERENCE` - follows from proven facts but has not been observed directly.
* `OPEN`           - named so it is not mistaken for settled. Never gates a feature open.

A capability is offered to the operator only on `FW_PROVEN` or `PROVEN_LIVE`.
`STRONG_INFERENCE` and `OPEN` may be *described*; they may not be *relied on*.

### The corrections this module carries

Three older models are withdrawn here, and the UI and docs must not reinstate them:

1. **UVC does not replace RNDIS.** The Type-C connector is a Linux composite gadget.
   RNDIS and CDC ACM are always present; UVC is *added* when enabled. "Video or
   networking" was never the choice.
2. **The Relay RJ45 pseudowire terminates on the MAX's physical `eth0`, not on
   `usb0`/RNDIS.** `usb0` is a separate MAX-local IP interface. Stock boot creates no
   bridge between them.
3. **Type-C DP / Alt-DP video is disabled in shipped firmware.** HDMI and UVC are the
   video outputs. The current printed manual is stale on this point.
"""
from __future__ import annotations

import caddx_fw_version as fwver

FW_PROVEN = "FW-PROVEN"
PROVEN_LIVE = "PROVEN-LIVE"
STRONG_INFERENCE = "STRONG-INFERENCE"
OPEN = "OPEN"

OFFERABLE = (FW_PROVEN, PROVEN_LIVE)

# The exact target. Board type and product line are matched exactly; the version is
# compared numerically, never lexically (19.2.14 sorts below 19.2.4 as a string).
TARGET_RELEASE = "19.2.14"
TARGET_BOARD_TYPE = "VRX_MAX"
MAX_DEVICE_NAMES = frozenset({"Ascent_VRX_max_WF", "Ascent_VRX_max_HF", "Ascent_VRX_Max"})


def applies_to(device_name, firmware) -> bool | None:
    """Does this model describe the given unit?

    True only for a MAX product line at exactly 19.2.14. False for a MAX on another
    release. **None for anything else**, including Pro and generic Ground, because
    this module holds no evidence about them and a False would read as "we checked".
    """
    if not isinstance(device_name, str) or device_name not in MAX_DEVICE_NAMES:
        return None
    same = fwver.same_release(firmware, TARGET_RELEASE)
    return None if same is None else same


# --------------------------------------------------------------------------- #
# USB-C: one composite gadget, not a mode switch
# --------------------------------------------------------------------------- #

USB_FUNCTIONS = {
    "rndis": {"always": True, "evidence": FW_PROVEN,
              "detail": "USB Ethernet. The MAX-local IP interface, address 192.168.3.102."},
    "acm": {"always": True, "evidence": FW_PROVEN,
            "detail": "CDC ACM serial. The gadget serial endpoint carrying the "
                      "MAVLink / CRSF / transparent serial paths."},
    "uvc": {"always": False, "evidence": FW_PROVEN,
            "detail": "UVC camera, present only when UVC is enabled. Enabling it ADDS "
                      "a function to the same composite device; it does not remove "
                      "RNDIS or ACM."},
}

# Advertised by the shipping gadget script when UVC is on.
UVC_FORMATS = ({"width": 1280, "height": 720, "nominal_fps": 60, "encoding": "MJPEG"},
               {"width": 1920, "height": 1080, "nominal_fps": 30, "encoding": "MJPEG"})


def usb_composite_model(uvc_enabled: bool) -> dict:
    """The set of USB functions the host should expect to enumerate.

    Enabling or disabling UVC rewrites the descriptor set, so the host sees a USB
    re-enumeration. That is a transition to expect, not a fault.
    """
    present = [name for name, f in USB_FUNCTIONS.items() if f["always"] or (name == "uvc" and uvc_enabled)]
    return {
        "functions": present,
        "uvc_enabled": bool(uvc_enabled),
        "mutually_exclusive": False,
        "re_enumerates_on_uvc_change": True,
        "formats": list(UVC_FORMATS) if uvc_enabled else [],
        "evidence": FW_PROVEN,
        "note": ("RNDIS and CDC ACM are always present. UVC is added when enabled; it "
                 "never replaces them, so video and networking are not an either/or."),
    }


# --------------------------------------------------------------------------- #
# Video
# --------------------------------------------------------------------------- #

RTSP_PORT = 554
RTSP_PATH = "live.ch01"


def rtsp_url(device_ip: str, port: int = RTSP_PORT) -> str:
    """The receiver's own RTSP endpoint.

    Ascent Control connects to this directly. It does not proxy, transcode or
    re-serve the stream, and no document or UI string may imply that it does.
    """
    if not isinstance(device_ip, str) or not device_ip.strip():
        raise ValueError("an device address is required to build an RTSP URL")
    return f"rtsp://{device_ip.strip()}:{int(port)}/{RTSP_PATH}"


VIDEO_PATHS = {
    "hdmi": {"available": True, "evidence": FW_PROVEN, "host_consumable": False,
             "detail": "A receiver output to a display. Not a stream this PC can consume."},
    "uvc": {"available": True, "evidence": FW_PROVEN, "host_consumable": True,
            "requires": "UVC enabled in device configuration",
            "detail": "Appears as a standard USB camera when enabled."},
    "rtsp": {"available": True, "evidence": FW_PROVEN, "host_consumable": True,
             "requires": "RNDIS reachable",
             "detail": "Served by the receiver over its own IP interface."},
    "typec_dp": {"available": False, "evidence": FW_PROVEN, "host_consumable": False,
                 "detail": "Type-C DP / Alt-DP video is DISABLED in shipped firmware — "
                           "the eDP controller and PHY are disabled in the device tree. "
                           "The printed manual still describes it and is stale."},
}


# --------------------------------------------------------------------------- #
# Serial routing: MAVLink, CRSF, pass-through
# --------------------------------------------------------------------------- #

# Recovered from the pass-through selector. The NUMBERS are proven; what the vendor
# release note's "option1"/"option2" shorthand binds to is NOT.
PASSTHROUGH_CHOICES = (
    {"value": 0, "label": "Command", "target": None, "evidence": FW_PROVEN},
    {"value": 1, "label": "MAVLink", "target": "vtx", "evidence": FW_PROVEN},
    {"value": 2, "label": "CRSF", "target": "vtx", "evidence": FW_PROVEN},
    {"value": 3, "label": "MAVLink (Relay)", "target": "relay", "evidence": FW_PROVEN},
    {"value": 4, "label": "CRSF (Relay)", "target": "relay", "evidence": FW_PROVEN},
    {"value": 100, "label": "None", "target": None, "evidence": FW_PROVEN},
)

# Stated as unresolved on purpose. The binary proves both destination families and the
# separately persisted Relay state; the release note never binds its shorthand numbers
# to a destination. Do not write option1 = VTX (or the reverse) as fact.
OPTION_MAPPING = {
    "resolved": False, "evidence": OPEN,
    "detail": ("The vendor release note says Relay-mode pass-through supports only "
               "'option1' and 'option2'. Which destination each shorthand names is "
               "not established. The selector values above are proven; the shorthand "
               "mapping is not."),
}

MAVLINK_UDP_PORT = 14550

SERIAL_TRANSPORTS = {
    "mavlink_uart": {"evidence": FW_PROVEN,
                     "detail": "Transparent MAVLink over UART. Protocol verification "
                               "was removed in 19.2.14, so the path is byte-transparent."},
    "mavlink_udp": {"evidence": FW_PROVEN, "port": MAVLINK_UDP_PORT,
                    "detail": f"Transparent MAVLink over UDP port {MAVLINK_UDP_PORT}."},
    "crsf": {"evidence": FW_PROVEN, "detail": "CRSF routing, VTX- or Relay-targeted."},
}

# Normal-mode and Relay-mode pass-through selections persist separately on the device.
PASSTHROUGH_STATE_IS_PER_MODE = {"value": True, "evidence": FW_PROVEN}


# --------------------------------------------------------------------------- #
# Relay topology -- the withdrawn model and the correct one
# --------------------------------------------------------------------------- #

RELAY_TOPOLOGY = {
    "pseudowire_endpoint": "eth0",
    "pseudowire_endpoint_detail": (
        "The Relay RJ45 Ethernet/GDTT pseudowire terminates on the MAX's PHYSICAL "
        "RJ45 (eth0). Whole Ethernet frames are carried, so ARP, DHCP and broadcast "
        "traffic traverse it end to end."),
    "eth0_stock_address": "192.168.1.100",
    "usb0_address": "192.168.3.102",
    "usb0_role": ("A separate MAX-local IP interface for RTSP, control and UDP "
                  "services. It is NOT the far endpoint of the Relay pseudowire."),
    "stock_bridge_between_them": False,
    "stock_bridge_detail": ("Stock boot configures the two interfaces independently "
                            "and creates no bridge, no forwarding and no NAT between "
                            "them. Any such arrangement is a Service Mode "
                            "configuration, not stock behaviour."),
    "gated_on_relay_mode": True,
    "evidence": FW_PROVEN,
    "live_corroboration": ("A laptop on the MAX RJ45 received a DHCP lease from a "
                           "server on the Relay-side LAN, which is Layer-2 behaviour "
                           "and matches the traced model."),
    "withdrawn_model": ("Relay RJ45 <-> RF/GDTT <-> MAX usb0/RNDIS. Withdrawn for "
                        "19.2.14. The earlier 19.2.4 usb0 conclusion is unverified, "
                        "not evidence of a change between releases."),
}

# Role reversal is a device-side physical gesture. Ascent Control reports it; it has
# no control over it and must not imply otherwise.
RELAY_ROLE_REVERSAL = {
    "user_accessible": True, "evidence": PROVEN_LIVE,
    "gesture": "Hold both Relay bind buttons for about 8 seconds. The Relay reboots.",
    "detail": ("Reverses which physical Relay radio is AP and which is DEV. The bands "
               "themselves are fixed in hardware. Ground 'Relay Mode' is a "
               "control-plane state, not a band selector."),
    "host_controllable": False,
}


# --------------------------------------------------------------------------- #
# RF
# --------------------------------------------------------------------------- #

RF_FEATURES = {
    "i_auto_full_band": {"evidence": FW_PROVEN,
                         "detail": "Full-band hopping is displayed as I-AUTO. Do not "
                                   "equate it with classic time-sequenced FHSS without "
                                   "evidence."},
    "rf426_rf429_frequency_edit": {"evidence": FW_PROVEN,
                                   "detail": "Frequency modification for RF modules 426 and 429."},
    "one_ghz_list_updated": {"evidence": FW_PROVEN, "detail": "The 1 GHz frequency list was updated."},
    "ten_watt_auto_fix": {"evidence": FW_PROVEN, "detail": "Abnormal 10 W Auto operation was fixed."},
    "ground_relay_power_cli": {"evidence": FW_PROVEN,
                               "detail": "Ground and Relay-Ground power are settable from the host."},
    "sky_ground_mac_count_cli": {"evidence": FW_PROVEN,
                                 "detail": "The number of Ground MAC addresses a Sky stores "
                                           "is settable from the host."},
    "two_ap_pairing_records": {"evidence": FW_PROVEN,
                               "detail": "Two AP/Ground pairing records are supported."},
    "bb_firmware_updated": {"evidence": FW_PROVEN,
                            "detail": "Baseband firmware updated: Sky B-path RF control "
                                      "repaired, full-band tuning optimised."},
}

# The persistent RF band table is a separate, older capability with its own evidence.
# It was bench-proven on this unit at 19.2.4 and has NOT been re-proven at 19.2.14,
# and 19.2.14 changed the frequency lists and the power table. Re-earn it.
RF_TABLE_WRITE_ON_19_2_14 = {
    "proven": False, "evidence": OPEN,
    "detail": ("The persistent RF table write was bench-proven on this unit at 19.2.4. "
               "19.2.14 updated the 1 GHz list and the RF426 power table and removed "
               "device-side protocol length validation, so the earlier result does not "
               "carry over. A read and a write must be re-run on 19.2.14 before this "
               "is offered."),
}


# --------------------------------------------------------------------------- #
# Wi-Fi -- present in firmware, not running
# --------------------------------------------------------------------------- #

WIFI_MODEL = {
    "stack_present": {"value": True, "evidence": FW_PROVEN,
                      "detail": "A Linux AIC8800 AP stack with hostapd and udhcpd."},
    "auto_starts_at_boot": {"value": False, "evidence": FW_PROVEN,
                            "detail": "The start script is commented out of normal boot."},
    "service_enable_path_exists": {"value": True, "evidence": FW_PROVEN,
                                   "detail": "A host/service control path can bring it up."},
    "device_reports_state_to_front_panel": {"value": True, "evidence": FW_PROVEN},
    "front_panel_can_enable": {"value": None, "evidence": OPEN,
                               "detail": "No set/enable path has been found. Unproven, "
                                         "and not to be described as working."},
}


def wifi_status(wlan0_up=None, ssid=None) -> dict:
    """Report the ACTUAL interface state, never firmware capability.

    `wlan0_up=None` means not observed. The one thing this must never do is report
    Wi-Fi as active because the firmware contains support for it.
    """
    if wlan0_up is None:
        state, detail = "UNKNOWN", ("The interface state has not been read from the unit. "
                                    "Firmware support is not evidence that Wi-Fi is running.")
    elif wlan0_up:
        state, detail = "UP", "wlan0 is up on the unit."
    else:
        state, detail = "DOWN", ("wlan0 is not up. This is the stock state: the Wi-Fi "
                                 "start script is not run at normal boot.")
    return {"state": state, "detail": detail, "ssid": ssid if wlan0_up else None,
            "observed": wlan0_up is not None,
            "activation_requires_service_mode": True, "evidence": PROVEN_LIVE if wlan0_up is not None else OPEN}


# --------------------------------------------------------------------------- #
# Audio
# --------------------------------------------------------------------------- #

AUDIO = {
    "hdmi_live": {"value": True, "evidence": FW_PROVEN},
    "local_playback": {"value": True, "evidence": FW_PROVEN},
    "scope_note": ("MAX 19.2.14 only. Not established for generic Ground 19.2.14 or "
                   "for 19.2.4."),
}


def capability_document(device_name=None, firmware=None, *, uvc_enabled=False,
                        wlan0_up=None) -> dict:
    """Everything above, scoped to whether it actually applies to this unit."""
    applies = applies_to(device_name, firmware)
    return {
        "target": {"release": TARGET_RELEASE, "board_type": TARGET_BOARD_TYPE},
        "device_name": device_name,
        "firmware": firmware,
        "firmware_parsed": fwver.describe(firmware),
        "applies": applies,
        "applies_detail": (
            "This unit is a MAX at 19.2.14." if applies is True else
            "This unit is a MAX on a different release; 19.2.14 facts do not apply."
            if applies is False else
            "Not a recognised MAX. No 19.2.14 evidence is claimed for it, and none is "
            "inferred from other product lines."),
        "usb": usb_composite_model(uvc_enabled) if applies else None,
        "video": VIDEO_PATHS if applies else None,
        "serial": {"transports": SERIAL_TRANSPORTS, "choices": list(PASSTHROUGH_CHOICES),
                   "option_mapping": OPTION_MAPPING,
                   "per_mode_state": PASSTHROUGH_STATE_IS_PER_MODE} if applies else None,
        "relay": {"topology": RELAY_TOPOLOGY, "role_reversal": RELAY_ROLE_REVERSAL} if applies else None,
        "rf": {"features": RF_FEATURES, "table_write": RF_TABLE_WRITE_ON_19_2_14} if applies else None,
        "wifi": {"model": WIFI_MODEL, "status": wifi_status(wlan0_up)} if applies else None,
        "audio": AUDIO if applies else None,
    }


def selftest() -> None:
    assert applies_to("Ascent_VRX_max_WF", "Ascent_VRX_Max_19_2_14") is True
    assert applies_to("Ascent_VRX_max_WF", "Ascent_VRX_Max_19_2_4") is False
    assert applies_to("Ascent_GT_pro", "19.2.14") is None          # never inferred
    assert applies_to("Ascent_VRX_Pro", "19.2.14") is None
    m = usb_composite_model(True)
    assert set(m["functions"]) == {"rndis", "acm", "uvc"} and m["mutually_exclusive"] is False
    assert set(usb_composite_model(False)["functions"]) == {"rndis", "acm"}
    assert RELAY_TOPOLOGY["pseudowire_endpoint"] == "eth0"
    assert RELAY_TOPOLOGY["stock_bridge_between_them"] is False
    assert VIDEO_PATHS["typec_dp"]["available"] is False
    assert rtsp_url("192.168.3.102") == "rtsp://192.168.3.102:554/live.ch01"
    assert wifi_status(None)["state"] == "UNKNOWN"
    assert wifi_status(False)["state"] == "DOWN"
    assert OPTION_MAPPING["resolved"] is False
