"""Hub (`mipi_hub.json`) and RC/MSP (`msp_rc_cfg.json`) device configuration.

Vendor oracle: **PC Tool D2.0.37** (`/mnt/c/ascent-corpus/decomp/Caddx_PCTool/`,
provenance in `docs/evidence/PROVENANCE.txt`; the 2.0.37 build ships its PDB so the
member names below are original, not inferred). Cross-checked against 2.0.51 where the
excerpt exists. Every rule here cites the file and line it came from.

--------------------------------------------------------------------------------
THE LANE, AND HOW IT DIFFERS FROM THE RF LANE
--------------------------------------------------------------------------------

Both pages use the *same* vendor call pair (`RCModeCtrl.cs:649-650` for RC,
`RCModeCtrl.cs:700-701` for Hub -- note both live in RCModeCtrl, the Hub button
included):

    GD.Inst.UpgFSM.SetFilePath_Json(ConstVal.<HUB|RCMODE>_JSON_Path);
    GD.Inst.UpgFSM.Send_FileStart_Json();

`SetFilePath_Json` (`UpgradeProcessFSM.cs:100-107`) builds

    new FileTransferSession(path, "/factory/" + Path.GetFileName(path))

so **the remote path is `/factory/` plus the local basename** -- it is not a constant
anywhere in the vendor source. With the shipped config values
(`Caddx PC Tool.exe.config`: `HUB_JSON_Path = resource\\param\\mipi_hub.json`,
`RCMODE_JSON_Path = resource\\param\\msp_rc_cfg.json`) that resolves to
`/factory/mipi_hub.json` and `/factory/msp_rc_cfg.json`.

The FSM then runs `115` -> `116` -> `117` and, on the `117` ACK
(`UpgradeProcessFSM.cs:865-878`), branches on `_isAutoSendBBFreq`:

* BBFreq set  -> `UpgState.SetBBFreq`, i.e. the empty `121` commit. This is the RF lane.
* BBFreq clear -> `UpgState.Completed_Json`, which calls `Send_ReopenJson()`
  (`UpgradeProcessFSM.cs:340-341`), which is `Reopen_Json(ReOpenTimeout_Asce)`.

**So the Hub/RC lane has no commit opcode.** There is no `121` and no equivalent: the
file transfer *is* the commit, and it is followed by the same cmd-3 reboot and reconnect
the RF lane uses. Do not send `121` on this lane -- that opcode is
`SET_BB_FREQ_CONFIG` and means something else entirely.

Chunking: the two-argument `FileTransferSession(localPath, remotePath)` constructor sets
`_chunkSize = (int)_fileLength` (`FileTransferSession.cs:48-58`), so like the RF lane the
whole document goes in **one** `116` frame. Both documents are well under a kilobyte, but
the frame is still bounded against the device's declared `receive_max_size` rather than
inheriting the vendor's unchecked behaviour.

--------------------------------------------------------------------------------
THERE IS NO READ PATH. THIS IS NOT AN OMISSION.
--------------------------------------------------------------------------------

The complete opcode set (`AR_COMMAND`, identical in 2.0.37 and 2.0.51) is
`0 3 60 114 115 116 117 118 120 121 122`. `120`/`121`/`122` are BB-frequency specific.
**Nothing reads `/factory/mipi_hub.json` or `/factory/msp_rc_cfg.json` back off the
device**, and the vendor tool never attempts it: `CamHubCtrl` loads its state from the
*local* file (`ConstVal.HUB_JSON_Path`) and `RCModeCtrl` from
`ConstVal.RCMODE_JSON_Path`.

Two consequences, and both are load-bearing:

1. **The host-local document is the source of truth**, exactly as it is in the vendor
   tool. `CamHubCtrl.cs:258` is `File.WriteAllText(ConstVal.HUB_JSON_Path, contents)` --
   the editor writes the file locally, and a separate action sends it.
2. **No post-write readback is possible on stock firmware.** The RF lane's
   read-verify-compare cycle has no counterpart here. A write is confirmed by the `117`
   ACK and the reconnect, and that is *all* the evidence the protocol affords. Callers
   must report that honestly rather than implying verification.

--------------------------------------------------------------------------------
PRESERVATION -- STRICTER THAN STOCK, DELIBERATELY
--------------------------------------------------------------------------------

The vendor rebuilds both documents from a typed model and drops anything it does not
know: `RCModeCtrl.cs:640` serialises `SlotData` (twelve fixed properties) and
`CamHubCtrl.cs:257` serialises `CamHubData`. Any unknown key in either file is silently
lost on save. We do the opposite and merge onto the caller's baseline, preserving key
order and unknown keys -- the same rule `caddx_vendor_write.merge_rf_table` applies, and
for the same reason. Never describe this as vendor parity.
"""

from __future__ import annotations

import copy
import json
import re

# --------------------------------------------------------------------------- #
# Identity of the two documents
# --------------------------------------------------------------------------- #

HUB_BASENAME = 'mipi_hub.json'
RC_BASENAME = 'msp_rc_cfg.json'
HUB_REMOTE_PATH = '/factory/' + HUB_BASENAME
RC_REMOTE_PATH = '/factory/' + RC_BASENAME

# Vendor local paths, from the shipped Caddx PC Tool.exe.config. Recorded because
# ArFileInfo.fileDir carries the PC-side path and the remote name is derived from
# this basename -- not because we read or write these locations.
VENDOR_LOCAL_HUB_PATH = 'resource/param/mipi_hub.json'
VENDOR_LOCAL_RC_PATH = 'resource/param/msp_rc_cfg.json'

HUB_OPERATION_ID = 'hub_config_write'
RC_OPERATION_ID = 'rc_config_write'

MAX_CONFIG_JSON = 64 * 1024


class DeviceConfigError(RuntimeError):
    def __init__(self, code: str, message: str, *, stage: str = 'validate', evidence=None):
        super().__init__(message)
        self.code = code
        self.stage = stage
        self.evidence = evidence or {}


# --------------------------------------------------------------------------- #
# Hub -- mipi_hub.json
# --------------------------------------------------------------------------- #

HUB_NODE_KEYS = ('node0', 'node1', 'node2', 'node3')

# --------------------------------------------------------------------------------
# WHAT IS AN ERROR HERE, AND WHAT IS ONLY A WARNING
#
# Two sources disagree about this format and the evidence order settles it:
# **the device's own file outranks the PC Tool's editor.**
#
# The stock document extracted from the Sky rootfs
# (`~/ascent-corpus/rootfs_19_2_5/fpv/mipi_hub.json`) carries
# `{"dev_name": "none", "res_info": "1920x1080P60"}` on three of its four nodes. The
# 2.0.37/2.0.51 editor would never produce that -- `CamHubCtrl.cs:296-298` forces
# `res_info = "none"` whenever the device goes to `none`. So pairing the two is a
# behaviour of the *editor*, not an invariant of the *format*, and a validator that
# enforced it would refuse the document the device actually ships.
#
# Likewise the shipped `runtime/vendor_templates/mipi_hub.json` names `MAX` on node1,
# which neither decompiled build offers in `sel_cam2` -- it came off a device image, not
# out of the tool. Refusing unknown camera names would mean refusing every camera newer
# than the build we decompiled.
#
# Therefore:
#   ERROR   -- structure and types: a missing node, a non-object node, a non-string
#              name, a flag that is not the integer 0 or 1, an oversize document.
#              These are things that could make the device misparse the file.
#   WARNING -- vocabulary and editor conventions: an unlisted device name, an
#              unexpected resolution, an unpaired none, a non-exclusive radio flag.
#              Reported with the oracle named, and passed through unchanged.
# --------------------------------------------------------------------------------

# Per-node device vocabulary as the vendor EDITOR offers it, from the combo boxes in
# CamHubCtrl's designer region. Identical in 2.0.37 and 2.0.51.
#   CamHubCtrl.cs:756/760  sel_cam1.Items = none, GT_PRO, IR, Z8
#   CamHubCtrl.cs:736/740  sel_cam2.Items = none, GT_PRO, IR, Z8
#   CamHubCtrl.cs:716/720  sel_cam3.Items = none, Z40
#   CamHubCtrl.cs:695/699  sel_hdmi.Items = none + four HDMI modes
# This is a UI hint and a warning source. It is NOT a validation gate -- see above.
HUB_EDITOR_NODE_DEVICES = {
    'node0': ('none', 'GT_PRO', 'IR', 'Z8'),
    'node1': ('none', 'GT_PRO', 'IR', 'Z8'),
    'node2': ('none', 'Z40'),
    'node3': ('none', 'HDMI'),
}

# Additionally observed in real device documents, so known-good despite postdating the
# decompiled editor. `MAX` appears on node1 of runtime/vendor_templates/mipi_hub.json,
# which was extracted from a Sky rootfs.
HUB_OBSERVED_NODE_DEVICES = {
    'node1': ('MAX',),
}

HUB_HDMI_RESOLUTIONS = ('none', '1920x1080P60', '1920x1080P50', '1280x720P60', '1280x720P50')
HUB_FLY_CTRL_KNOWN = ('betaFlight',)

_RES_RE = re.compile(r'^\d{3,4}x\d{3,4}P\d{2,3}$')


def hub_known_devices(node_key: str) -> tuple[str, ...]:
    return tuple(HUB_EDITOR_NODE_DEVICES.get(node_key, ())
                 + HUB_OBSERVED_NODE_DEVICES.get(node_key, ()))


def hub_resolution_for(node_key: str, dev_name: str) -> str:
    """The resolution the vendor EDITOR's change handler would set for this device.

    CamHubCtrl.cs:295-338. Used to explain a warning, never to rewrite a document.
    """
    if dev_name == 'none':
        return 'none'
    if node_key in ('node0', 'node1'):
        return '960x540P60' if dev_name == 'Z8' else '1920x1080P60'
    if node_key == 'node2':
        return '2000x1500P50'
    return '1920x1080P60'


def validate_hub_node(key: str, node, warnings: list) -> None:
    if not isinstance(node, dict):
        raise DeviceConfigError('HUB_NODE_NOT_OBJECT', f'{key} must be an object',
                                evidence={'node': key})
    dev = node.get('dev_name')
    if not isinstance(dev, str) or not dev:
        raise DeviceConfigError('HUB_DEV_NAME_INVALID',
                                f'{key}.dev_name must be a non-empty string',
                                evidence={'node': key, 'dev_name': dev})
    res = node.get('res_info')
    if not isinstance(res, str) or not res:
        raise DeviceConfigError('HUB_RES_INFO_INVALID',
                                f'{key}.res_info must be a non-empty string',
                                evidence={'node': key, 'res_info': res})
    for flag in ('selected', 'high_priority'):
        val = node.get(flag)
        if not isinstance(val, int) or isinstance(val, bool) or val not in (0, 1):
            raise DeviceConfigError('HUB_FLAG_INVALID',
                                    f'{key}.{flag} must be the integer 0 or 1',
                                    evidence={'node': key, 'field': flag, 'value': val})

    known = hub_known_devices(key)
    if dev not in known:
        warnings.append({
            'code': 'HUB_DEV_NAME_UNLISTED',
            'message': f'{key}.dev_name {dev!r} is not offered by the decompiled 2.0.37 / '
                       f'2.0.51 editor for this input (offers: {", ".join(known)}). A '
                       f'camera newer than that build would look like this. Passed '
                       f'through unchanged.',
        })
    if res != 'none' and not _RES_RE.match(res):
        warnings.append({
            'code': 'HUB_RES_INFO_MALFORMED',
            'message': f'{key}.res_info {res!r} is not a WIDTHxHEIGHTPFPS string. Passed '
                       f'through unchanged.',
        })
    if key == 'node3' and res not in HUB_HDMI_RESOLUTIONS:
        warnings.append({
            'code': 'HUB_RES_INFO_UNLISTED',
            'message': f'node3.res_info {res!r} is not one of the HDMI modes the editor '
                       f'offers ({", ".join(HUB_HDMI_RESOLUTIONS)}). Passed through.',
        })
    if (dev == 'none') != (res == 'none'):
        warnings.append({
            'code': 'HUB_NONE_NOT_PAIRED',
            'message': f'{key} has dev_name={dev!r} with res_info={res!r}. The editor moves '
                       f'both to "none" together, but the stock device document does not '
                       f'(three of its four nodes are exactly this shape), so this is '
                       f'normal and is preserved.',
        })


def validate_hub_document(doc) -> dict:
    """Validate mipi_hub.json. Raises on structure; returns warnings for convention."""
    if not isinstance(doc, dict):
        raise DeviceConfigError('HUB_NOT_OBJECT', 'mipi_hub.json must be a JSON object')
    warnings: list = []
    for key in HUB_NODE_KEYS:
        if key not in doc:
            raise DeviceConfigError('HUB_NODE_MISSING', f'{key} is missing',
                                    evidence={'node': key})
        validate_hub_node(key, doc[key], warnings)

    fly = doc.get('fly_ctrl')
    if not isinstance(fly, str) or not fly:
        raise DeviceConfigError('HUB_FLY_CTRL_INVALID',
                                'fly_ctrl must be a non-empty string',
                                evidence={'fly_ctrl': fly})
    if fly not in HUB_FLY_CTRL_KNOWN:
        warnings.append({
            'code': 'HUB_FLY_CTRL_UNKNOWN',
            'message': f'fly_ctrl {fly!r} is not a value the decompiled editor offers '
                       f'(known: {", ".join(HUB_FLY_CTRL_KNOWN)}). Passed through.',
        })

    # CamHubCtrl.cs:166,170 -- "Selected" and "High Priority" are each a single-select
    # radio group over CAM1/CAM2/CAM3/HDMI, so more than one holder is a state the
    # editor cannot produce. A warning, not an error: it is the editor's constraint.
    for flag in ('selected', 'high_priority'):
        holders = [k for k in HUB_NODE_KEYS if doc[k].get(flag) == 1]
        if len(holders) > 1:
            warnings.append({
                'code': 'HUB_FLAG_NOT_EXCLUSIVE',
                'message': f'{len(holders)} inputs set {flag}=1 ({", ".join(holders)}). '
                           f'The editor is a single-select radio group over the four '
                           f'inputs, so it would show only one.',
            })
        elif not holders:
            warnings.append({'code': f'HUB_NO_{flag.upper()}',
                             'message': f'No input sets {flag}=1.'})
        elif doc[holders[0]].get('dev_name') == 'none':
            warnings.append({
                'code': 'HUB_DISABLED_NODE_FLAGGED',
                'message': f'{holders[0]} is set to "none" but carries {flag}=1.',
            })

    for key in HUB_NODE_KEYS:
        node = doc[key]
        expected = hub_resolution_for(key, node['dev_name'])
        if key != 'node3' and node['res_info'] != expected and node['dev_name'] != 'none':
            warnings.append({
                'code': 'HUB_RES_INFO_UNEXPECTED',
                'message': f'{key}.res_info is {node["res_info"]!r}; the editor would set '
                           f'{expected!r} for dev_name {node["dev_name"]!r}. Preserved.',
            })
    return {'ok': True, 'warnings': warnings}


# --------------------------------------------------------------------------- #
# RC / MSP -- msp_rc_cfg.json
# --------------------------------------------------------------------------- #

# The four slots are the four functions handoff section 9 names, in this order. From
# the control each slot drives in RCModeCtrl.ApplySlotData:
#   slot0 -> lab_Inp_zoom  / sliRan_zoom    (RCModeCtrl.cs:283-287)   zoom
#   slot1 -> lab_Inp_reset / sliRan_reset   (RCModeCtrl.cs:310-314)   zoom reset
#   slot2 -> lab_Inp_cam1  / sliRan_cam1    (RCModeCtrl.cs:337-341)   camera change
#   slot3 -> lab_Inp_cam2  / sliRan_cam2    (RCModeCtrl.cs:364-367)   camera reset
RC_SLOTS = (
    ('slot0', 'ZOOM'),
    ('slot1', 'ZOOM RESET'),
    ('slot2', 'CAMERA CHANGE'),
    ('slot3', 'CAMERA RESET'),
)

# `slotN` is an RC CHANNEL INDEX assigned to that function -- it is `Sel_Idx` on a
# channel selector, not a boolean. The vendor's own sample data is
# `slot0 = 8, slot1 = 10` (RCModeCtrl.cs:249-254), which no boolean reading survives.
# Index 0 is the selector's "unassigned" position: it is what ApplySlotData sets when a
# slot is disabled (`lab_Inp_zoom.Sel_Idx = 0`, RCModeCtrl.cs:266).
RC_CHANNEL_MIN = 0
RC_CHANNEL_MAX = 18
RC_CHANNEL_UNASSIGNED = 0

# **The disable sentinel.** RCModeCtrl.cs:264, 291, 318, 345 all test
# `slotN_min > 2100` and, when true, hide the range controls entirely and force the
# channel selector to 0. So a slot is disabled by putting its minimum above 2100 --
# which is exactly what the shipped template's 9990/9999 pairs are doing.
RC_DISABLED_MIN_THRESHOLD = 2100

# The displayed fallback range for a disabled slot, RCModeCtrl.cs:276-279.
RC_DISABLED_DISPLAY = (1200, 1500)

# Ordinary RC pulse bounds. The vendor clamps nothing below 2100 itself; these are the
# range-slider's own limits and are applied as a validation floor/ceiling so an
# out-of-band value cannot be sent as if it were a real range.
RC_PULSE_MIN = 800
RC_PULSE_MAX = 2100


def rc_slot_disabled(doc: dict, slot: str) -> bool:
    """A slot is disabled iff its minimum exceeds the vendor's 2100 threshold."""
    return int(doc.get(f'{slot}_min', 0)) > RC_DISABLED_MIN_THRESHOLD


def validate_rc_document(doc) -> dict:
    if not isinstance(doc, dict):
        raise DeviceConfigError('RC_NOT_OBJECT', 'msp_rc_cfg.json must be a JSON object')

    warnings = []
    assigned: dict[int, str] = {}
    for slot, label in RC_SLOTS:
        for field in (slot, f'{slot}_min', f'{slot}_max'):
            if field not in doc:
                raise DeviceConfigError('RC_FIELD_MISSING', f'{field} is missing',
                                        evidence={'field': field})
            val = doc[field]
            if not isinstance(val, int) or isinstance(val, bool):
                raise DeviceConfigError('RC_FIELD_NOT_INT',
                                        f'{field} must be an integer, got {type(val).__name__}',
                                        evidence={'field': field, 'value': val})

        chan = doc[slot]
        lo = doc[f'{slot}_min']
        hi = doc[f'{slot}_max']

        if rc_slot_disabled(doc, slot):
            # Disabled. The vendor forces the selector to 0 when it loads such a
            # document, so a non-zero channel here is a state its UI cannot show.
            if chan != RC_CHANNEL_UNASSIGNED:
                warnings.append({
                    'code': 'RC_DISABLED_SLOT_HAS_CHANNEL',
                    'message': f'{label} ({slot}) is disabled by {slot}_min={lo} (>'
                               f'{RC_DISABLED_MIN_THRESHOLD}) but still names channel '
                               f'{chan}. The vendor editor would display channel 0. '
                               f'Preserved as given.',
                })
            if hi < lo:
                raise DeviceConfigError('RC_RANGE_INVERTED',
                                        f'{slot}_max ({hi}) is below {slot}_min ({lo})',
                                        evidence={'slot': slot, 'min': lo, 'max': hi})
            continue

        if not (RC_CHANNEL_MIN <= chan <= RC_CHANNEL_MAX):
            raise DeviceConfigError(
                'RC_CHANNEL_OUT_OF_RANGE',
                f'{label} ({slot}) names channel {chan}; expected '
                f'{RC_CHANNEL_MIN}..{RC_CHANNEL_MAX}',
                evidence={'slot': slot, 'channel': chan})
        if chan == RC_CHANNEL_UNASSIGNED:
            raise DeviceConfigError(
                'RC_ENABLED_SLOT_UNASSIGNED',
                f'{label} ({slot}) is enabled ({slot}_min={lo}) but names channel 0, '
                f'which is the unassigned position. Disable it by setting {slot}_min '
                f'above {RC_DISABLED_MIN_THRESHOLD} instead.',
                evidence={'slot': slot, 'channel': chan, 'min': lo})

        for field, val in ((f'{slot}_min', lo), (f'{slot}_max', hi)):
            if not (RC_PULSE_MIN <= val <= RC_PULSE_MAX):
                raise DeviceConfigError(
                    'RC_PULSE_OUT_OF_RANGE',
                    f'{field} is {val}; an enabled slot must lie in '
                    f'{RC_PULSE_MIN}..{RC_PULSE_MAX} microseconds',
                    evidence={'slot': slot, 'field': field, 'value': val})
        if hi <= lo:
            raise DeviceConfigError('RC_RANGE_INVERTED',
                                    f'{slot}_max ({hi}) must be above {slot}_min ({lo})',
                                    evidence={'slot': slot, 'min': lo, 'max': hi})

        if chan in assigned:
            # Two functions on one channel fire together. The vendor does not guard
            # this; we refuse it, and say so.
            raise DeviceConfigError(
                'RC_CHANNEL_DOUBLE_ASSIGNED',
                f'channel {chan} is assigned to both {assigned[chan]} and {label}; one '
                f'stick movement would trigger both',
                evidence={'channel': chan, 'slots': [assigned[chan], label]})
        assigned[chan] = label

    if not assigned:
        warnings.append({'code': 'RC_ALL_SLOTS_DISABLED',
                         'message': 'Every slot is disabled; no RC channel controls the '
                                    'camera.'})
    if not rc_slot_disabled(doc, 'slot0') and (rc_slot_disabled(doc, 'slot1') or doc['slot0_max'] - doc['slot0_min'] < 500):
        warnings.append({'code': 'INAV_ZOOM_PRECONDITIONS',
                         'message': 'The traced INAV zoom path needs zoom and zoom-reset channels plus a zoom range of at least 500. DisplayPort slot control is a separate path.'})
    if any(doc[slot] == 18 for slot, _label in RC_SLOTS):
        warnings.append({'code': 'RC_EXTENDED_CHANNEL',
                         'message': 'CH18 is outside the PC Tool CH1–CH17 selector; preserved, not hardware-qualified.'})
    return {'ok': True, 'warnings': warnings}


# --------------------------------------------------------------------------- #
# Merge, serialise, diff -- shared
# --------------------------------------------------------------------------- #

def merge_document(edits: dict, baseline: dict) -> dict:
    """Apply edits onto the baseline, preserving key order and unknown keys.

    Stricter than the vendor, which rebuilds both documents from a typed model and
    drops what it does not recognise (`RCModeCtrl.cs:640`, `CamHubCtrl.cs:257`).
    """
    if not isinstance(edits, dict):
        raise DeviceConfigError('EDITS_NOT_OBJECT', 'edits must be a JSON object')
    merged = copy.deepcopy(baseline)
    for key, value in edits.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            nested = copy.deepcopy(merged[key])
            nested.update(copy.deepcopy(value))
            merged[key] = nested
        else:
            merged[key] = copy.deepcopy(value)
    return merged


def serialize_document(doc: dict) -> bytes:
    """Serialise for the wire.

    The vendor writes `Formatting.Indented` (`RCModeCtrl.cs:640`), which Newtonsoft
    renders at two spaces, and `CamHubCtrl.cs:252-257` uses the same settings object.
    We match that because unlike the RF lane there is no readback to normalise
    against, so the bytes we send are the only artefact either side can point at.
    """
    raw = json.dumps(doc, indent=2, ensure_ascii=False).encode('utf-8')
    if len(raw) > MAX_CONFIG_JSON:
        raise DeviceConfigError('CONFIG_TOO_LARGE',
                                f'document serialises to {len(raw)} bytes, over the '
                                f'{MAX_CONFIG_JSON}-byte guard',
                                stage='prepare', evidence={'length': len(raw)})
    return raw


def _flatten(doc, prefix=''):
    out = {}
    for key, value in (doc or {}).items():
        path = f'{prefix}{key}'
        if isinstance(value, dict):
            out.update(_flatten(value, f'{path}.'))
        else:
            out[path] = value
    return out


def diff_document(baseline: dict, merged: dict) -> list[dict]:
    before, after = _flatten(baseline), _flatten(merged)
    rows = []
    for key in sorted(set(before) | set(after)):
        if before.get(key) != after.get(key):
            rows.append({'field': key,
                         'from': before.get(key, None),
                         'to': after.get(key, None)})
    return rows


def selftest() -> dict:
    hub = {
        'node0': {'dev_name': 'Z8', 'res_info': '960x540P60', 'selected': 1, 'high_priority': 1},
        'node1': {'dev_name': 'none', 'res_info': 'none', 'selected': 0, 'high_priority': 0},
        'node2': {'dev_name': 'Z40', 'res_info': '2000x1500P50', 'selected': 0, 'high_priority': 0},
        'node3': {'dev_name': 'HDMI', 'res_info': '1920x1080P60', 'selected': 0, 'high_priority': 0},
        'fly_ctrl': 'betaFlight',
    }
    assert validate_hub_document(hub)['ok']
    rc = {'slot0': 8, 'slot0_min': 1000, 'slot0_max': 1300,
          'slot1': 10, 'slot1_min': 1500, 'slot1_max': 2000,
          'slot2': 0, 'slot2_min': 9990, 'slot2_max': 9999,
          'slot3': 0, 'slot3_min': 9990, 'slot3_max': 9999}
    assert validate_rc_document(rc)['ok']
    assert rc_slot_disabled(rc, 'slot2') and not rc_slot_disabled(rc, 'slot0')
    assert HUB_REMOTE_PATH == '/factory/mipi_hub.json'
    assert RC_REMOTE_PATH == '/factory/msp_rc_cfg.json'
    return {'ok': True}


if __name__ == '__main__':
    print(selftest())


# --------------------------------------------------------------------------- #
# Per-operation qualification
# --------------------------------------------------------------------------- #

# Which device roles each document applies to. Roles come from
# `device_capability`, which derives them from the raw command-60 name and nothing
# else -- never from VID/PID.
#
# The hub document configures MIPI camera inputs, so it belongs to a unit that has
# them: the camera-hub role. The user's own account of the workflow matches the
# vendor's -- the hub JSON is edited locally and then sent to a VTX running a hub
# image -- so an ordinary VRX receiver is not a target for it.
#
# RC/MSP assigns RC channels to camera functions and is carried by the air-side unit
# that owns the camera, so it applies to the same hub-capable units and to air units.
HUB_APPLICABLE_ROLES = ('camera_hub',)
RC_APPLICABLE_ROLES = ('camera_hub', 'air')


def qualify_device_config_write(kind: str, *, candidate: dict | None,
                                identity: dict | None, role: str | None) -> dict:
    """Fail-closed, per-operation eligibility for a hub or RC write.

    **This cannot be a capability proof, and says so.** For the RF table the vendor
    gives us a read (`120`) whose success proves the device implements the resource
    before anything is written. There is no such read here, so the strongest
    available evidence is the raw command-60 role. An eligible result therefore means
    "this unit's raw identity says the document applies to it", not "the device
    answered that it supports this". `capability_proven` is False on every path and
    callers must surface that rather than rounding it up.
    """
    applicable = HUB_APPLICABLE_ROLES if kind == 'hub' else RC_APPLICABLE_ROLES
    operation_id = HUB_OPERATION_ID if kind == 'hub' else RC_OPERATION_ID
    remote_path = HUB_REMOTE_PATH if kind == 'hub' else RC_REMOTE_PATH

    reasons: list[str] = []
    c = candidate or {}
    i = identity or {}

    if not c or not i:
        reasons.append('NO_ACTIVE_QUALIFIED_DEVICE')
    if not c.get('identity_proven'):
        reasons.append('RAW_IDENTITY_NOT_PROVEN')
    if not c.get('serial_com'):
        reasons.append('SERIAL_TRANSPORT_MISSING')
    if not c.get('serial_container_id'):
        reasons.append('PHYSICAL_CONTAINER_ID_MISSING')
    if role is None:
        reasons.append('DEVICE_ROLE_UNKNOWN')
    elif role not in applicable:
        # Not an error in the device; the document simply is not for this unit.
        reasons.append('DEVICE_ROLE_NOT_APPLICABLE')

    from device_capability import firmware_profile_gate
    profile = firmware_profile_gate(kind, i.get('device_name'), i.get('device_name'))
    if profile is not True:
        reasons.append('CAMERA_PROFILE_UNKNOWN' if profile is None else 'CAMERA_PROFILE_NOT_APPLICABLE')

    return {
        'operation_id': operation_id,
        'eligible': not reasons,
        'reasons': reasons,
        'remote_path': remote_path,
        'role': role,
        'applicable_roles': list(applicable),
        'device_name': i.get('device_name'),
        'serial_com': c.get('serial_com'),
        # The two honesty flags. Neither is ever True on this lane.
        'capability_proven': False,
        'profile_applicable': profile,
        'capability_basis': (
            'raw command-60 role and camera subtype only. No vendor opcode reads this resource, so the '
            'device cannot be asked whether it supports the write before one is made.'),
        'readback_supported': False,
        'commit_opcode': None,
        'lane': '115/116/117 then cmd-3 reboot and reconnect; no commit opcode',
    }
