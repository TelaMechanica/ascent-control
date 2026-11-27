"""Which firmware can carry Service Mode -- and which can carry FIRST ACCESS.

These are two different questions and conflating them is why 18.21.7 looked
unsupported when it is not.

**Stage 2 -- persistent key-based SSH.** Needs an SSH daemon that reads
~/.ssh/authorized_keys and a writable, persistent /root. Nothing version-specific:
the mechanism is one appended line. Every sampled image carries Dropbear, an
S50dropbear init script, and an inittab that remounts the rootfs rw before rcS, and
on 18.21.7 the daemon was observed LIVE answering tcp/22.

**Stage 1 -- first privileged access.** Needs the transfer-lane injection to reach
popen at runtime on that exact firmware. MAX 18.21.7 has historical bench
evidence; MAX 19.2.14 has the operator's end-to-end Service Mode confirmation
recorded on 2026-10-27. See the exact-version rows below.

The Gnd485 industrial Ground has its own independent evidence; its aarch64/glibc,
cx485 result cannot qualify an RK3568 MAX receiver. Evidence is recorded
separately for each platform/version and identifies operator-provided results.

Stage 2 and Stage 1 remain separate checks. An unlisted firmware does not inherit
first-access qualification from another version.
"""
from __future__ import annotations

import caddx_fw_version as fwver

# Evidence grades, strongest first.
VERIFIED = "VERIFIED"      # observed on hardware, this firmware
INFERRED = "INFERRED"      # read out of that firmware's image
UNKNOWN = "UNKNOWN"        # no evidence either way

MAX_DEVICE_NAMES = frozenset({
    "Ascent_VRX_max_HF", "Ascent_VRX_max_WF", "Ascent_VRX_Max",
})

#: The industrial Ground. A SEPARATE PLATFORM, not a MAX variant: aarch64/glibc
#: against the MAX's RK3568, running `daemon_sdio` / `ar_ldy_gnd` from a parallel
#: build tree. Nothing measured on one transfers to the other.
#:
#: It needed naming because the gate previously returned None for every device
#: name outside MAX_DEVICE_NAMES, so an industrial Ground was indistinguishable
#: from a MAX on firmware nobody had looked at. Those are different situations
#: and only one of them is answered by evidence we could go and collect.
GND485_DEVICE_PREFIXES = ("Ascent_G_Gnd", "Ascent_G_GND")

#: The Relay / Repeater. A THIRD platform, and not a receiver at all: 32-bit ARM
#: Thumb against musl, running `ar_fpvhs_relay` / `ar_fpvhs_upgrade`, where the
#: MAX is aarch64 RK3568 and the Gnd485 is aarch64 glibc. Nothing measured on
#: either of those transfers here, in either direction.
#:
#: It also differs in a way that matters for Service Mode as a whole: THERE IS NO
#: SSH DAEMON ON THIS PLATFORM. No dropbear, no sshd anywhere in the image --
#: only a stock BusyBox login daemon on tcp/23. So Stage 2 as designed (one
#: appended `authorized_keys` line, verified over the device's own sshd) has
#: nothing to land on, and this platform deliberately carries NO STAGE2_EVIDENCE
#: entry. `stage2_supported` returning None here is correct and is not an
#: oversight to be "fixed" by adding a row.
RELAY_DEVICE_PREFIXES = ("Ascent_Relay",)

PLATFORM_MAX = "max"
PLATFORM_GND485 = "gnd485"
PLATFORM_RELAY = "relay"

# --------------------------------------------------------------------------- #
# WHICH SSH KEY TYPE A PLATFORM CAN ACTUALLY VERIFY
#
# A MEASURED PROPERTY OF THE PLATFORM, not a probe result, because the probe
# can fail and a failed probe must not silently reintroduce the fault.
#
# The Gnd485 ships dropbear 2019.78. Read out of the vendor's own aarch64
# binary: it contains `ssh-rsa`, `ssh-dss` and `ecdsa-sha2-nistp{256,384,521}`,
# and not one occurrence of `ed25519`, which dropbear did not gain until
# 2020.79. An ed25519 key installed there is correct in every observable
# respect -- right file, right modes, right path, present when counted -- and
# can never authenticate. There is no symptom that distinguishes it from a
# missing key.
#
# That is why this is keyed on the platform rather than taken from the SSH
# banner alone. If the banner read fails, falling back to the default would put
# an unusable key on exactly the unit this entry exists for, and the enrollment
# would verify it as a success.
#
# `None` means "no measured constraint" -- ask the daemon. It does NOT mean
# ed25519 is known to work.
# --------------------------------------------------------------------------- #

KEY_TYPES_BY_PLATFORM = {
    PLATFORM_GND485: ("ecdsa",),
}


def key_types_for_platform(platform):
    """The key types this platform is KNOWN to verify, or None if unmeasured."""
    return KEY_TYPES_BY_PLATFORM.get(platform)


def platform_of(device_name, firmware=None) -> str | None:
    """Which platform this unit is, from BOTH identity fields.

    THE DEVICE NAME IS NOT ALWAYS THE PLATFORM. Measured 2026-10-09 on the
    industrial Ground after its upgrade: command 60 returns

        device_name = "Ascent_VRX"
        firmware    = "Ascent_G_Gnd_19_2_14"
        hardware    = "FPV-Ascent-Gnd-485-V1.1-1.0"

    -- the generic product word in the name field and the platform in the
    firmware field. A gate reading only `device_name` called that unit
    unrecognised and reported "no Service Mode evidence" for a receiver whose
    SSH daemon had just been observed answering.

    Both fields are consulted, most specific first. This does not widen what
    qualifies: STAGE2_EVIDENCE still has to hold an entry for the resulting
    (platform, version) pair.
    """
    for field in (device_name, firmware):
        if not isinstance(field, str) or not field:
            continue
        # Gnd485 first: "Ascent_G_Gnd_19_2_14" must not be read as a MAX just
        # because some other field says VRX.
        if field.startswith(GND485_DEVICE_PREFIXES):
            return PLATFORM_GND485
        # Relay next, and for the same reason. A Relay reports device_name
        # "Ascent_Relay" and firmware "Ascent_Relay_19_2_14" (measured on the
        # bench unit, 2026-10-11, COM41). Neither form reaches the MAX branches
        # below -- "Ascent_Relay" is not in MAX_DEVICE_NAMES and the firmware
        # does not start with "Ascent_VRX_" -- so this is additive, not a
        # reordering, and no existing unit changes platform because of it.
        if field.startswith(RELAY_DEVICE_PREFIXES):
            return PLATFORM_RELAY
    if isinstance(device_name, str) and device_name in MAX_DEVICE_NAMES:
        return PLATFORM_MAX
    if isinstance(firmware, str) and firmware.startswith("Ascent_VRX_"):
        return PLATFORM_MAX
    return None

#: Stage-2 evidence, keyed on the PARSED version.
#:
#: Command 60 reports the firmware two different ways depending on the unit -- the
#: live Max HF says "Ascent_VRX_Max_18_21_7" while other paths carry a bare
#: "18.21.7". Keying on the raw string silently refused one of those forms, so the
#: project's existing parser normalises both to a version tuple. One parser, reused.
#: Keyed (platform, version). It used to be keyed on version alone, which only
#: worked while one platform was in play -- two platforms can share a version
#: number and mean entirely different software.
STAGE2_EVIDENCE: dict[tuple, dict] = {
    (PLATFORM_GND485, (16, 5, 3)): {
        "grade": VERIFIED,
        "detail": ("Dropbear observed live on this receiver over USB-C/RNDIS, "
                   "2026-10-09: 192.168.3.102 tcp/22 open from host "
                   "192.168.3.103, banner SSH-2.0-dropbear_2019.78. The unit "
                   "offers an ssh-rsa host key ONLY -- ed25519 and ecdsa scans "
                   "return nothing -- so the host-key pin and the client's "
                   "accepted algorithms both have to allow for that."),
    },
    # MEASURED NEGATIVE, 2026-10-09, on the receiver itself. Not an absence of
    # evidence -- evidence of absence, which is why it is False and not None.
    #
    #   root mount     squashfs ro,relatime
    #   root writable  touch: /root/.ascent_wtest: Read-only file system
    #   ssh dir        /root/.ssh: No such file or directory
    #
    # Stage 2 asks whether the unit can hold a PERSISTENT authorized_keys entry.
    # This one has a live Dropbear answering on 22 and a read-only root
    # filesystem, so the daemon is present and the key has nowhere to live. The
    # MAX remounts its rootfs rw in /etc/inittab before rcS; that is a MAX fact
    # and it does not transfer, which is exactly the assumption this platform
    # was never supposed to inherit.
    #
    # SCOPED TO THE PATH THE ENROLLMENT TARGETS, and the scope is the point.
    # It does NOT say this platform cannot hold a persistent credential:
    # /usrdata is writable and is where Dropbear was started from, and nothing
    # has established which keys file that daemon actually reads. Persistent
    # access on this platform is an UNRESOLVED ARCHITECTURE QUESTION, not a
    # closed one, and must not be recorded as the latter because one path was
    # measured shut.
    (PLATFORM_GND485, (19, 2, 14)): {
        # VERIFIED describes the MEASUREMENT; `supported: None` describes what
        # it settles, which is no longer the same thing. See stage2_supported.
        "grade": VERIFIED,
        "supported": None,
        "detail": ("Measured on hardware: / is squashfs read-only, /root is not "
                   "writable and /root/.ssh does not exist. Enrollment no longer "
                   "targets /root on this platform -- the key is stored on "
                   "/usrdata, which is writable persistent storage, and linked "
                   "into place at start-up through the vendor's own boot hook. "
                   "That route is implemented and has NOT yet been demonstrated "
                   "on hardware. Dropbear is live (SSH-2.0-dropbear_2019.78) and "
                   "cannot verify an ed25519 key, so this receiver is given an "
                   "ECDSA one."),
    },
    (PLATFORM_MAX, (18, 21, 7)): {
        "grade": VERIFIED,
        "detail": ("Dropbear observed live on this receiver: tcp/22 open, banner "
                   "SSH-2.0-dropbear_2022.82, offering ssh-ed25519."),
    },
    # Pro 18.21.10, 2026-10-30: the managed key authenticated over the device's
    # own SSH (independent pinned-key check), which demonstrates a readable
    # persistent authorized_keys entry for that session. Cold-cycle (reboot)
    # persistence was not part of that report and is gated separately by the
    # orchestrator's persistence check. Pairs with the Stage-1 row below.
    (PLATFORM_MAX, (18, 21, 10)): {
        "grade": VERIFIED,
        "detail": ("Pro 18.21.10 reached VERIFIED on 2026-10-30 with an "
                   "independent pinned-key SSH check, demonstrating a readable "
                   "authorized_keys entry over the device's own Dropbear. Reboot "
                   "persistence was not in that report and is gated separately."),
    },
    (PLATFORM_MAX, (18, 21, 3)): {"grade": INFERRED, "detail": "dropbear + S50dropbear in image"},
    (PLATFORM_MAX, (18, 21, 4)): {"grade": INFERRED, "detail": "dropbear + S50dropbear in image"},
    (PLATFORM_MAX, (18, 21, 8)): {"grade": INFERRED, "detail": "dropbear + S50dropbear in image"},
    (PLATFORM_MAX, (19, 2, 14)): {
        "grade": VERIFIED,
        "detail": ("Operator confirmed MAX Service Mode working end to end on "
                   "19.2.14, recorded 2026-10-27. Serial, timings and raw logs "
                   "were not supplied; no new agent bench execution."),
    },
}


def _evidence(device_name, firmware):
    plat = platform_of(device_name, firmware)
    v = fwver.parse(firmware) if firmware is not None else None
    return STAGE2_EVIDENCE.get((plat, v)) if (plat and v) else None

#: Stage-1 (first access) evidence, keyed by exact platform and firmware.
#:
#: Binary presence of the md5sum->popen primitive is NOT entry here. It is measured
#: in every sampled image and proves only that the construction exists, never that a
#: live guard still routes an attacker-controlled path into it. Filling this needs a
#: device-side result, which is Gate 2.
STAGE1_EVIDENCE: dict[tuple, dict] = {
    (PLATFORM_MAX, (19, 2, 14)): {
        "grade": VERIFIED,
        "device": "MAX on 19.2.14; serial not supplied",
        "source": "operator_confirmation_2026-10-27",
        "detail": (
            "Operator confirms MAX Service Mode worked end to end on 19.2.14 "
            "and corrects the stale unproven-first-access warning in 0.43.29. "
            "Test scope is MAX/VRX 19.2.14, with Pro separately on 18.21.10 "
            "(its own row below). This is operator-provided evidence; no fresh "
            "agent hardware test, raw capture, serial or timing was supplied. It "
            "does not qualify other firmware, cold-cycle persistence or CoT."),
    },
    # Operator-DESIGNATED validated, 2026-11-27. The 2026-10-30 Pro bench reached
    # VERIFIED, repeat managed access succeeded, and an INDEPENDENT pinned-key SSH
    # check confirmed access -- but the first-access TOOL timed out on that run, so
    # the checkpoint graded first access PARTIAL overall. The operator has elevated
    # it to validated for distribution. Recorded honestly: this is weaker evidence
    # than the MAX 19.2.14 end-to-end confirmation, and it is a per-PLATFORM key
    # (platform_of maps the RK3568 Pro to 'max'), so it qualifies the MAX software
    # at 18.21.10, observed on a Pro.
    (PLATFORM_MAX, (18, 21, 10)): {
        "grade": VERIFIED,
        "device": "Ascent_VRX_Pro on 18.21.10 (AC 0.43.34), serial not supplied",
        "source": "bench_2026-10-30_partial_operator_designated_2026-11-27",
        "detail": (
            "2026-10-30 VRX Pro bench: activation reached VERIFIED, repeat managed "
            "access succeeded, and an independent pinned-key SSH check confirmed "
            "access. The initial first-access tool timed out, so the checkpoint "
            "graded first access PARTIAL overall. Operator-designated as validated "
            "for distribution on 2026-11-27. No fresh agent hardware test, raw "
            "capture, serial or timing was supplied beyond the checkpoint."),
    },
    (PLATFORM_GND485, (19, 2, 14)): {
        "grade": VERIFIED,
        "device": "Ascent_G_Gnd_19_2_14, serial 1004, COM9",
        "detail": (
            "2026-10-09: first access obtained on THIS platform at THIS version, "
            "twice. The receiver opened a connection back to "
            "192.168.3.103:4444 and the session answered as uid=0 at an "
            "interactive prompt rooted at /usrdata/fpv/boot_ar8030. "
            "Device-originated execution AND administrative identity, both "
            "observed."),
    },
    (PLATFORM_MAX, (18, 21, 7)): {
        "grade": VERIFIED,
        "device": "Ascent_VRX_max_HF, hw Ascent-VRX-Max-V2.2-3.0, serial 1001",
        "detail": (
            "Gate 2, 2026-10-08: ACCESS / CONCLUSIVE. The receiver opened a "
            "connection back to 192.168.3.103:4444 and the session answered the "
            "identity probe with uid=0(root) gid=0(root) at an interactive sh-5.1 "
            "prompt. Device-originated execution AND administrative identity, both "
            "observed -- not inferred from the callback alone."),
    },
}


#: Stage-1 evidence held at PLATFORM level, which is a weaker claim than a row in
#: STAGE1_EVIDENCE and is deliberately kept apart from it.
#:
#: A row above says "first access was observed working on this platform AT THIS
#: VERSION". An entry here says only "the mechanism has been observed working on
#: this platform at SOME version". That is enough to make an attempt reasonable
#: and is NOT enough to call a firmware qualified, so it never satisfies
#: `stage1_supported` and never silently enables anything.
#:
#: The Gnd485 entry is the platform's OWN result. It is not inherited from the
#: MAX, and nothing here assumes the MAX mechanism transfers -- the two
#: platforms have separate entries because they are separate software.
STAGE1_PLATFORM_EVIDENCE: dict[str, dict] = {
    PLATFORM_GND485: {
        # This is the fallback for Gnd485 versions with no row of their own.
        # 19.2.14 HAS one now (STAGE1_EVIDENCE above), so it no longer reaches
        # here -- which matters, because the text below said 19.2.14 was
        # unproven and that forced an "acknowledge this is unproven" tick on
        # every activation of a unit where first access had in fact succeeded
        # twice. A stale sentence became a ceremony.
        "grade": INFERRED,
        "observed_on": "an earlier firmware of this platform",
        "detail": (
            "A root session was obtained on a Gnd485 on 2026-09-08 through the "
            "same access path, and two binaries were retrieved by hash-verified "
            "read. The unit's firmware version was never recorded, so that "
            "result qualifies the PLATFORM and cannot qualify any version."),
        "unproven": (
            "Nothing establishes that the path reaches the same point on a "
            "version with no result of its own. The updater is a different "
            "build per release, and a live guard can change between releases "
            "without the construction disappearing."),
    },
    PLATFORM_MAX: {
        "grade": VERIFIED,
        "observed_on": ("19.2.14 (operator confirmation); 18.21.10 (Pro, partial); "
                        "18.21.7 (historical)"),
        "detail": ("Operator confirmed 19.2.14 end to end on 2026-10-27; Pro "
                   "18.21.10 reached VERIFIED with independent SSH on 2026-10-30 "
                   "(tool timed out, graded partial); historical Gate 2, "
                   "2026-10-08, serial 1001 on 18.21.7."),
        "unproven": ("Unlisted MAX firmware has not been shown to behave "
                     "the same way."),
    },
    # STATIC ONLY. This is the weakest entry in the table and must stay that
    # way until a session is actually observed: no first access has EVER been
    # obtained on a Relay, at any version, by anyone on this project. What is
    # held is a read of the platform's own updater, not a result.
    PLATFORM_RELAY: {
        "grade": INFERRED,
        "observed_on": "no Relay, at any version -- static analysis only",
        "detail": (
            "Exact archived Ascent_Relay_19_2_14 updater: sha256 61ddd37b..., "
            "236,732 bytes. AR_FPV_UPGRADE_CalculateFileMD5 at 0x21b04 builds "
            "snprintf(buf, 128, \"%s %s\", \"md5sum\", filePath) at 0x21b76 "
            "and calls popen at 0x21b80. This is static evidence only; no Relay "
            "first-access session has been established. The historical 7349fdaf... "
            "hash/offset attribution is not the exact updater in this archive. "
            "Relay USB selects exclusive CDC serial or RNDIS, and its archived "
            "USB network address is 192.168.3.105. The stock OTAR 0x3A switch "
            "exists in this updater, but identity-preserving handoff and live "
            "access remain unqualified. The image has no stock SSH daemon, so "
            "ordinary receiver-key enrollment is not established. See "
            "corpus/PHASE4_75_RELAY_USB_IDENTITY_AND_TRANSPORT_2026-10-30.md."),
        "unproven": (
            "NO SESSION HAS EVER BEEN OBSERVED ON THIS PLATFORM. Everything "
            "above is a static read of one binary; nothing establishes that the "
            "path actually reaches a shell on a Relay, that the callback "
            "survives this platform's networking, or that the tool's on-device "
            "fragment assembly behaves the same against a 32-bit musl busybox "
            "as against the aarch64 glibc platforms it was exercised on. "
            "Treat a failure here as unexplained rather than as evidence the "
            "primitive is patched."),
    },
}


def stage1_attemptable(device_name, firmware) -> dict | None:
    """May first access reasonably be ATTEMPTED here, though unqualified?

    Returns the platform evidence, or None when there is none. This is the
    answer to a different question from `stage1_supported`, and the two must not
    be collapsed:

        stage1_supported   -- proven at this version. Proceeds on its own.
        stage1_attemptable -- plausible on this platform, unproven at this
                              version. Proceeds ONLY with an explicit, per-request
                              operator acknowledgement, and the attempt's real
                              result is what gets recorded.

    Returning something here is never permission by itself. The caller must still
    carry the acknowledgement, which is why this returns the evidence rather than
    a bare boolean -- a caller that wants to proceed has to show the operator
    what is and is not known first.
    """
    if stage1_supported(device_name, firmware):
        return None                      # already qualified; this does not apply
    plat = platform_of(device_name, firmware)
    if plat is None:
        return None
    ev = STAGE1_PLATFORM_EVIDENCE.get(plat)
    if ev is None:
        return None
    return dict(ev, platform=plat, firmware=firmware, qualified=False)


def stage2_supported(device_name, firmware) -> bool | None:
    """Can this unit hold a persistent authorized_keys entry?

    True when we hold evidence for that exact firmware. None -- never False -- for a
    firmware we simply have not looked at, because "we did not check" must not read
    as "we checked and it cannot".
    """
    if platform_of(device_name, firmware) is None:
        return None
    ev = _evidence(device_name, firmware)
    if ev is None:
        return None
    # `supported` IS AN EXPLICIT TRI-STATE when present, and all three values
    # mean different things:
    #
    #   True  -- measured, and it works.
    #   False -- measured, and it does not. Evidence of absence, not absence of
    #            evidence, and no live probe may overturn it.
    #   None  -- we looked, we learned something, and the question is STILL
    #            OPEN. This is not the same as having no row at all: the row
    #            carries what was measured, while refusing to turn that
    #            measurement into a verdict it does not support.
    #
    # The third value exists because a measurement can outlive its conclusion.
    # The Gnd485 row recorded that /root is unwritable and concluded the
    # platform could not hold a credential. The first half is still true; the
    # second stopped being true the moment enrollment stopped targeting /root.
    # Left as False it refused to attempt the route built to get around it.
    if "supported" in ev:
        return ev["supported"]
    # No explicit value: the grade decides, so every row predating the tri-state
    # keeps exactly the meaning it had.
    return ev["grade"] in (VERIFIED, INFERRED)


def stage2_grade(device_name, firmware) -> str:
    ev = _evidence(device_name, firmware)
    return ev["grade"] if ev else UNKNOWN


def stage2_detail_text(device_name, firmware) -> str:
    """The evidence sentence for this unit, or empty when there is none."""
    return (_evidence(device_name, firmware) or {}).get("detail", "")


def stage1_supported(device_name, firmware) -> bool:
    """Is automated FIRST access hardware-proven here? Fails closed.

    Keyed on platform AND version. The Gnd485 root inspection of 2026-09-08 is
    real, and it is NOT entered here: that session was obtained by hand on a
    unit whose firmware version this project did not record, and an
    unversioned result cannot qualify a version. Recording it as evidence for
    16.5.3 would be inventing the part that matters.
    """
    plat = platform_of(device_name, firmware)
    v = fwver.parse(firmware) if firmware is not None else None
    return bool(plat and v) and (plat, v) in STAGE1_EVIDENCE


def qualification(device_name, firmware) -> dict:
    """Everything the UI needs to explain what will and will not happen.

    TWO ANSWERS, NEVER ONE. "Service Mode is not qualified for this firmware"
    was printed for a receiver whose SSH daemon was live and reachable, because
    one unqualified stage blocked the whole feature. Routine SSH management and
    exploit-based first access are different operations with different
    evidence, and an operator who already holds a trusted key needs only the
    first.
    """
    plat = platform_of(device_name, firmware)
    s2 = stage2_supported(device_name, firmware)
    s1 = stage1_supported(device_name, firmware)
    ev = _evidence(device_name, firmware)
    return {
        "firmware": firmware,
        "device_name": device_name,
        "platform": plat,
        "platform_recognised": plat is not None,

        # Stage 2 -- routine SSH management against a device that already
        # trusts our key. No vendor service touched, no injection, no popen.
        "stage2_supported": s2,
        "stage2_grade": stage2_grade(device_name, firmware),
        "stage2_detail": (ev or {}).get("detail"),

        # Stage 1 -- obtaining first access on a device that trusts nothing yet.
        "stage1_supported": s1,
        "stage1_detail": _stage1_detail(plat, firmware),

        "needs_operator_first_access": bool(s2) and not s1,
        "summary": _summary(plat, s2, s1),
    }


def _stage1_detail(plat, firmware) -> str:
    if plat == PLATFORM_GND485:
        return ("A root session WAS obtained on a Gnd485 by hand on 2026-09-08, "
                "so the technique is not theoretical on this platform. It is not "
                "recorded as evidence for a firmware version because the version "
                "of that unit was never written down, and an unversioned result "
                "cannot qualify a version.")
    if plat == PLATFORM_MAX:
        ev = STAGE1_EVIDENCE.get((plat, fwver.parse(firmware)))
        if ev:
            return ev["detail"]
        return ("MAX first access has evidence on 19.2.14 (operator confirmation, "
                "2026-10-27) and historically 18.21.7. This firmware is unproven.")
    return ("This device name is not one this build has evidence for, so nothing "
            "can be said about first access on it either way.")


def _summary(plat, s2, s1) -> str:
    """One sentence an operator can act on, naming WHICH half is missing."""
    if plat is None:
        return ("This build holds no Service Mode evidence for this device, so "
                "neither SSH management nor first access can be offered.")
    if s2 and s1:
        return "Both SSH management and automatic first access are qualified here."
    if s2 and not s1:
        return ("SSH management is qualified on this receiver -- its SSH daemon "
                "is established. Automatic first access is not, so enrolling a "
                "new key needs an operator-supplied route; a key this receiver "
                "already trusts works without one.")
    if not s2 and s1:
        return ("First access is qualified but the persistent SSH path is not "
                "established on this firmware.")
    return ("Neither stage is qualified on this firmware yet. That is an absence "
            "of evidence, not a measurement that it cannot work.")
