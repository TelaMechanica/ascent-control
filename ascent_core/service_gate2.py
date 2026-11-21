"""Gate 2 harness: authorization, preflight, and evidence classification.

SEPARATE IMPLEMENTATION BOUNDARY, and right now an EMPTY one. This module holds
everything around first privileged access -- deciding whether it may be attempted,
proving the preconditions, and classifying what the attempt means -- and holds no
access mechanism at all.

That split is deliberate and load-bearing. The classification problem is the hard
part of Gate 2 and is worth solving on its own: an attempt that produces nothing
means completely different things depending on whether the return path was sound,
and getting that wrong sends the next engineer after the wrong fault for days.

`attempt()` requires BOTH an explicit operator authorization token and an injected
mechanism. Neither has a default. With no mechanism supplied it reports
NOT_IMPLEMENTED rather than improvising one.
"""
from __future__ import annotations

import socket
from typing import Callable

# --------------------------------------------------------------------------- #
# Outcomes. Telling these apart IS Gate 2.
# --------------------------------------------------------------------------- #

RESULT_ACCESS = "ACCESS"                        # first privileged session obtained
RESULT_MECHANISM_REJECTED = "MECHANISM_REJECTED"  # device refused the attempt
RESULT_NO_RESPONSE = "NO_RESPONSE"              # accepted, nothing came back
RESULT_NO_ROUTE = "NO_ROUTE"                    # host could not reach the device
RESULT_UNAUTHORIZED = "UNAUTHORIZED"            # refused locally; nothing sent
RESULT_NOT_IMPLEMENTED = "NOT_IMPLEMENTED"      # no mechanism supplied
RESULT_PREFLIGHT_FAILED = "PREFLIGHT_FAILED"    # a precondition failed

RESULTS = (RESULT_ACCESS, RESULT_MECHANISM_REJECTED, RESULT_NO_RESPONSE,
           RESULT_NO_ROUTE, RESULT_UNAUTHORIZED, RESULT_NOT_IMPLEMENTED,
           RESULT_PREFLIGHT_FAILED)

#: What each outcome entitles you to conclude -- and NO_RESPONSE is conditional on
#: purpose. It is a privilege result only when the return path was independently
#: proven first; otherwise it is indistinguishable from a network fault and settles
#: nothing. That is why the listener is proven BEFORE the attempt, never after.
RESULT_MEANING = {
    RESULT_ACCESS:
        "First privileged access succeeded on this firmware. Evidence for stage 1.",
    RESULT_MECHANISM_REJECTED:
        "Compatibility result: the device refused the attempt. On this firmware the "
        "path is guarded or absent.",
    RESULT_NO_RESPONSE:
        "Conditional. If the return path was proven before the attempt this is a "
        "PRIVILEGE result -- accepted and nothing executed. If it was not, this is "
        "ambiguous with a network fault and establishes nothing.",
    RESULT_NO_ROUTE:
        "Network result. Nothing was learned about the device.",
    RESULT_UNAUTHORIZED:
        "Refused locally. Nothing was sent to the device.",
    RESULT_NOT_IMPLEMENTED:
        "No access mechanism is supplied. Nothing was sent to the device.",
    RESULT_PREFLIGHT_FAILED:
        "A precondition failed. Nothing was sent to the device.",
}

# --------------------------------------------------------------------------- #
# Transport evidence, and why binding is not it.
#
# A host socket that binds and accepts proves the HOST path. It says nothing about
# whether the device can open a connection back, which is a different direction
# across different hardware. Treating the two as equivalent is what would turn
# silence into a false privilege finding.
# --------------------------------------------------------------------------- #

TRANSPORT_NONE = "NONE"                    # nothing established
TRANSPORT_HOST_ONLY = "HOST_ONLY"          # we can bind and accept locally
TRANSPORT_DEVICE_TO_HOST = "DEVICE_TO_HOST"  # a device-originated connection was seen

TRANSPORT_GRADES = (TRANSPORT_NONE, TRANSPORT_HOST_ONLY, TRANSPORT_DEVICE_TO_HOST)

TRANSPORT_MEANING = {
    TRANSPORT_NONE:
        "No transport evidence.",
    TRANSPORT_HOST_ONLY:
        "The host can bind and accept on this address. This is NOT evidence that "
        "the device can reach it; the directions are independent.",
    TRANSPORT_DEVICE_TO_HOST:
        "A connection originated BY THE DEVICE was observed reaching this host. "
        "Only this grade makes silence interpretable.",
}

# --------------------------------------------------------------------------- #
# Confidence. Three levels, because two were not enough.
# --------------------------------------------------------------------------- #

CONFIDENCE_CONCLUSIVE = "CONCLUSIVE"       # may be recorded as stage-1 evidence
CONFIDENCE_SUGGESTIVE = "SUGGESTIVE"       # leans one way; never recorded as proof
CONFIDENCE_INCONCLUSIVE = "INCONCLUSIVE"   # establishes nothing

#: Outcomes that stand on their own. The device either acted or refused; neither
#: reading depends on the return path.
CONCLUSIVE = frozenset({RESULT_ACCESS, RESULT_MECHANISM_REJECTED})


def classify_confidence(result: str, transport_grade: str) -> str:
    """How much a given outcome is allowed to establish.

    Silence is the whole problem. With only host-side binding, NO_RESPONSE is
    INCONCLUSIVE -- it is equally explained by a device that never executed and by a
    device that executed and could not reach us. With a device-originated connection
    independently observed, that second explanation is retired and silence becomes
    SUGGESTIVE of a privilege failure.

    It never becomes CONCLUSIVE. A payload can fail for reasons that are neither
    privilege nor transport -- a missing binary being the obvious one, since `nc` is
    absent from every sampled image -- so silence alone is not proof that the
    mechanism was refused.
    """
    if result in CONCLUSIVE:
        return CONFIDENCE_CONCLUSIVE
    if result == RESULT_NO_RESPONSE:
        return (CONFIDENCE_SUGGESTIVE if transport_grade == TRANSPORT_DEVICE_TO_HOST
                else CONFIDENCE_INCONCLUSIVE)
    return CONFIDENCE_INCONCLUSIVE


class Preflight:
    """Everything establishable before anything is sent.

    The listener check is the one that earns its place: proving the host can bind
    and accept on the address the device would answer to is what later makes a
    NO_RESPONSE attributable to privilege rather than plumbing.
    """

    def __init__(self, *, device_host: str | None, listen_addr: str,
                 listen_port: int, firmware: str | None,
                 reachable: Callable[[str], bool] | None = None,
                 device_to_host_proven: bool = False):
        self._device_to_host_proven = bool(device_to_host_proven)
        self.device_host = device_host
        self.listen_addr = listen_addr
        self.listen_port = listen_port
        self.firmware = firmware
        self._reachable = reachable

    def run(self) -> dict:
        checks: list[dict] = []

        def chk(name, ok, detail=""):
            checks.append({"check": name, "ok": bool(ok), "detail": str(detail)})

        chk("device address known", bool(self.device_host), self.device_host or "none")
        chk("firmware known", bool(self.firmware), self.firmware or "unknown")

        bindable = False
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self.listen_addr, self.listen_port))
            s.close()
            bindable = True
            chk("host can bind the return address", True,
                f"{self.listen_addr}:{self.listen_port}")
        except OSError as exc:
            chk("host can bind the return address", False,
                f"{self.listen_addr}:{self.listen_port} {exc}")

        if self._reachable is not None:
            chk("host can reach the device", self._reachable(self.device_host),
                self.device_host)

        # The grade is deliberately capped at HOST_ONLY here. Host-to-device
        # reachability does not imply device-to-host: the directions are
        # independent, and only an observed device-originated connection lifts it.
        grade = TRANSPORT_HOST_ONLY if bindable else TRANSPORT_NONE
        if self._device_to_host_proven:
            grade = TRANSPORT_DEVICE_TO_HOST

        return {
            "ok": all(c["ok"] for c in checks),
            "checks": checks,
            "transport_grade": grade,
            "transport_meaning": TRANSPORT_MEANING[grade],
            "residual_gap": (
                "Binding proves the HOST socket path only. It does not prove the "
                "device can reach this address; nothing short of a device-originated "
                "connection does, which is what the attempt itself tests."),
        }


class Gate2:
    """Decides whether an attempt may run, and what its result means."""

    #: A caller must pass exactly this. Nothing derives or defaults it.
    AUTHORIZATION = "GATE2-AUTHORIZED-BY-OPERATOR"

    def __init__(self, *, authorization: str | None = None,
                 listen_addr: str = "192.168.3.103", listen_port: int = 4444,
                 mechanism: Callable[[dict], dict] | None = None,
                 reachable: Callable[[str], bool] | None = None,
                 device_to_host_proven: bool = False,
                 audit_sink: Callable[[dict], None] | None = None):
        # Must be supplied from an OBSERVATION, never inferred from our own binding.
        self.device_to_host_proven = bool(device_to_host_proven)
        self.authorization = authorization
        self.listen_addr = listen_addr
        self.listen_port = listen_port
        self._mechanism = mechanism
        self._reachable = reachable
        self._audit_sink = audit_sink

    def authorized(self) -> bool:
        return self.authorization == self.AUTHORIZATION

    def _emit(self, record: dict) -> dict:
        if self._audit_sink is not None:
            self._audit_sink(record)
        return record

    #: Evidence a mechanism may attach to its result and have carried through.
    #: Everything else it returns is dropped, so a mechanism cannot invent an
    #: outcome field or overwrite one this class owns.
    MECHANISM_EVIDENCE = ("uid0", "identity_raw")

    def _outcome(self, result, *, preflight=None, sent=False, detail=None,
                 firmware=None, evidence=None):
        grade = (preflight or {}).get("transport_grade", TRANSPORT_NONE)
        confidence = classify_confidence(result, grade)
        # The outcome used to be rebuilt from scratch, which silently discarded
        # whatever the mechanism had established -- a run confirmed uid=0 and
        # reported it only inside the detail STRING, with the structured fields
        # empty. Recording administrative identity from prose would be exactly the
        # overstatement the grading exists to prevent.
        extra = {k: v for k, v in (evidence or {}).items()
                 if k in self.MECHANISM_EVIDENCE}
        return self._emit({
            **extra,
            "result": result,
            "ok": result == RESULT_ACCESS,
            "meaning": RESULT_MEANING[result],
            "detail": detail,
            "sent_to_device": bool(sent),
            "preflight": preflight,
            "firmware": firmware,
            "transport_grade": grade,
            "confidence": confidence,
            # Only a CONCLUSIVE outcome may be recorded as stage-1 evidence. A
            # SUGGESTIVE one is reported and deliberately not recorded: silence,
            # however well explained, is not proof the mechanism was refused.
            "record_as_evidence": (confidence == CONFIDENCE_CONCLUSIVE
                                   and bool((preflight or {}).get("ok", False))),
        })

    def attempt(self, target: dict) -> dict:
        firmware = (target or {}).get("firmware")

        if not self.authorized():
            return self._outcome(RESULT_UNAUTHORIZED, firmware=firmware)

        pre = Preflight(device_host=(target or {}).get("host"),
                        listen_addr=self.listen_addr,
                        listen_port=self.listen_port,
                        firmware=firmware,
                        reachable=self._reachable,
                        device_to_host_proven=self.device_to_host_proven).run()
        if not pre["ok"]:
            return self._outcome(RESULT_PREFLIGHT_FAILED, preflight=pre,
                                 firmware=firmware)

        if self._mechanism is None:
            # The boundary is empty by design. It will not be improvised.
            return self._outcome(RESULT_NOT_IMPLEMENTED, preflight=pre,
                                 firmware=firmware)

        try:
            res = self._mechanism(target) or {}
        except Exception as exc:
            return self._outcome(RESULT_NO_RESPONSE, preflight=pre, sent=True,
                                 detail=f"{type(exc).__name__}: {exc}",
                                 firmware=firmware)

        result = res.get("result")
        if result not in RESULTS:
            return self._outcome(RESULT_NO_RESPONSE, preflight=pre,
                                 sent=bool(res.get("sent")),
                                 detail="mechanism returned no recognised result",
                                 firmware=firmware)
        return self._outcome(result, preflight=pre, sent=bool(res.get("sent")),
                             evidence=res,
                             detail=res.get("detail"), firmware=firmware)
