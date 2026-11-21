"""First access: obtain the initial administrative session and install the managed
public key on a receiver that does not yet trust this host.

This is the one step the enroll/verify SDK cannot perform on its own, because
verify() authenticates a key that must already be present. First access runs the
operator's serial first-access tool (physical/USB access to the receiver), receives
the administrative callback, and installs the public key using the *validated*,
platform-aware enrollment commands (squashfs bind-mount / root-home probe / dropbear
key-type), ported from the proven implementation.

Trust boundary (deliberate): this module installs the key and nothing else. It does
**not** write any enrollment/trust record. The caller runs the SDK's authenticated
verify() afterward, which proves the key against the confirmed host key and is the
only path that records trust. A first access that installs a key but fails
verification therefore leaves no trust record.
"""
from __future__ import annotations

from . import first_access_session as _session
from . import service_firmware as _fw
from . import enrollment_commands as _ec
from . import service_gate2 as _g2


class FirstAccessError(RuntimeError):
    def __init__(self, code: str, detail: str = ""):
        super().__init__(detail or code)
        self.code = code
        self.detail = detail


class _Session:
    """Thin command wrapper over the live reverse-shell callback."""

    def __init__(self, listener):
        self._l = listener

    def run(self, command: str) -> str:
        return self._l.converse((command + "\n").encode()).decode("utf-8", "replace")

    def stop(self) -> None:
        try:
            self._l.stop()
        except Exception:  # noqa: BLE001 — teardown is best-effort
            pass


def install_key(*, target: dict, public_key, tool_path, serial_port: str,
                listen_addr: str, listen_port: int = 4444, timeout: float = 45.0,
                on_line=None) -> dict:
    """Run first access and install `public_key` on the selected receiver.

    `target` carries at least `device_name` and `firmware`. Returns a dict with
    `ok` and the install facts. Raises FirstAccessError on an unusable call shape.
    Never creates a trust record.
    """
    if not serial_port:
        raise FirstAccessError("SERIAL_PORT_REQUIRED",
                               "No serial port was supplied for the selected receiver.")
    if not listen_addr:
        raise FirstAccessError("CALLBACK_ADDR_REQUIRED",
                               "No local callback address faces the selected receiver.")
    keys = _ec.as_key_list(public_key)
    if not keys:
        raise FirstAccessError("NO_PUBLIC_KEY", "No public key was supplied to install.")

    mechanism = _session.make_mechanism(
        tool_path, serial_port=serial_port, listen_addr=listen_addr,
        listen_port=listen_port, timeout=timeout, keep_session=True,
        identity_probe=True, on_line=on_line)

    outcome = mechanism(dict(target))
    if outcome.get("result") != _g2.RESULT_ACCESS:
        return {"ok": False, "stage": "first_access", "result": outcome.get("result"),
                "detail": outcome.get("detail", "first access did not obtain a session")}
    if not outcome.get("uid0"):
        return {"ok": False, "stage": "privilege",
                "detail": "a callback was received but administrative identity (uid=0) "
                          "was not confirmed; the key was not installed.",
                "identity_raw": outcome.get("identity_raw")}

    listener = getattr(mechanism, "session", None)
    if listener is None:
        return {"ok": False, "stage": "session",
                "detail": "no administrative session was retained to install the key."}

    sess = _Session(listener)
    try:
        name, firmware = target.get("device_name"), target.get("firmware")
        platform = _fw.platform_of(name, firmware)
        keys_path = _ec.enrollment_target(platform)

        device_home = None
        verification = None
        if platform == _fw.PLATFORM_GND485:
            # squashfs root: key goes to writable persistent storage, /root is
            # bind-mounted over it. Ask the receiver where root's home really is.
            device_home = _ec.parse_root_home(sess.run(_ec.root_home_probe_command()))
            if not device_home:
                return {"ok": False, "stage": "root_home",
                        "detail": "the receiver did not report its administrator home "
                                  "directory; the key was not placed."}
            commands = _ec.squashfs_enrollment_commands(keys, home=device_home)
        else:
            commands = [_ec.authorized_keys_append_command(k, keys_path) for k in keys]

        transcript = [sess.run(c) for c in commands]

        # Read back rather than trust the writes.
        if platform == _fw.PLATFORM_GND485:
            verification = _ec.parse_enrollment_verification(
                sess.run(_ec.squashfs_verify_command(keys, home=device_home)),
                expected_keys=len(keys))
            per_key = int((verification.get("facts") or {}).get("key") or 0)
            installed = per_key // max(len(keys), 1)
            if not verification.get("ok"):
                return {"ok": False, "stage": "verify_install", "platform": platform,
                        "detail": "setup did not complete on the receiver: "
                                  + " ".join(verification.get("problems") or []),
                        "verification": verification,
                        "transcript": [t[-200:] for t in transcript][-3:]}
        else:
            import re
            counts = []
            for k in keys:
                seen = sess.run(f"grep -c -x -F {_ec._q(k)} {_ec._q(keys_path)} "
                                f"2>/dev/null || echo 0")
                digits = [int(t) for t in re.findall(r"^\s*(\d+)\s*$", seen, re.M)]
                counts.append(digits[-1] if digits else 0)
            installed = min(counts) if counts else 0

        if installed != 1:
            return {"ok": False, "stage": "verify_install", "platform": platform,
                    "installed": installed, "keys_path": keys_path, "root_home": device_home,
                    "detail": f"the key is present {installed} time(s) in authorized_keys "
                              f"after first access; exactly one was expected.",
                    "transcript": [t[-200:] for t in transcript][-3:]}

        return {"ok": True, "installed": installed, "platform": platform,
                "keys_path": keys_path, "root_home": device_home,
                "detail": "the managed public key was installed over first access; "
                          "run verify() to authenticate and record trust."}
    finally:
        sess.stop()
