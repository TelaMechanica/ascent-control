"""Gate 2 mechanism: drive the operator's EXISTING first-access tool.

This module contains no payload, no protocol framing and no injection mechanics. It
is process orchestration: it binds a listener, runs a tool the operator supplies by
path, waits for the callback that tool is expected to produce, and reports which of
Gate 2's outcomes occurred.

That split is deliberate. The access tool is a pre-existing, independently disclosed
asset; reproducing any part of it here would create a second copy of something that
should stay single. What was missing was never the mechanism -- it was the wiring
between that mechanism and Service Mode.

Nothing runs unless the operator passes an explicit tool path AND Gate 2 holds its
authorization token. There is no default path and no search: Service Mode never goes
looking for a way into a receiver.
"""
from __future__ import annotations

import os
import hashlib
import secrets
import socket
import platform
import re
import subprocess
import threading
import time
from pathlib import Path

from . import service_gate2 as g2


class AccessDiagnostics:
    """Retain protocol metadata, never arbitrary tool text or session contents.

    Unknown lines are counted but not stored. In particular, payload dumps and
    traceback source lines must not become an alternative copy of the tool.
    """

    def __init__(self):
        self.started = time.monotonic()
        self.lines = 0
        self.events = []
        self.first_events = []
        self.event_count = 0
        self.last_request = None
        self.last_reply = None
        self.reply_status_pending = False
        self.last_exception = None

    def line(self, number, text):
        self.lines += 1
        event = {"line": number,
                 "elapsed_seconds": round(time.monotonic() - self.started, 3)}
        for field, pattern in (
            ("cmd", r"\bcmd\s*[=:]\s*(0x[0-9a-fA-F]{1,8}|[0-9]{1,10})\b"),
            ("seq", r"\bseq\s*[=:]\s*([0-9]{1,10})\b"),
            ("arg", r"\barg\s*[=:]\s*([0-9]{1,10})\b"),
            ("payload_length", r"\bpayload_len\s*[=:]\s*([0-9]{1,10})\b"),
            ("status", r"^\s*status\s*:\s*(-?[0-9]{1,10})\s*$"),
        ):
            match = re.search(pattern, text)
            if match:
                token = match.group(1)
                event[field] = int(token, 16 if token.startswith("0x") else 10)
        # Only exception type is retained; its arbitrary message may contain
        # credentials, commands or a payload. Numeric cmd/seq above is enough
        # to correlate the timeout with the preceding exchange.
        match = re.match(r"^(TimeoutError|OSError|PermissionError|ConnectionError|"
                         r"UnicodeEncodeError|ValueError|RuntimeError):", text.strip())
        if match:
            event["exception_type"] = match.group(1)
        match = re.search(r"\bWin32\s+([0-9]{1,10})\b", text)
        if match:
            event["win32_error"] = int(match.group(1))
        match = re.search(r"\[write #([0-9]{1,10})\]", text)
        if match:
            event["write_index"] = int(match.group(1))
        direction = re.match(r"^\s*\[?(TX|RX)\b", text)
        if direction:
            event["direction"] = direction.group(1)
        prefix = re.match(r"^\[(send|recv|recv-unexpected)\]", text)
        if prefix:
            event["direction"] = "TX" if prefix.group(1) == "send" else "RX"
        mismatch = re.match(r"^\[warn\] seq mismatch: expected=([0-9]{1,10}), "
                            r"got=([0-9]{1,10})\s*$", text)
        if mismatch:
            event.update(warning="sequence_mismatch",
                         expected_seq=int(mismatch.group(1)),
                         received_seq=int(mismatch.group(2)))
        for prefix, code in (("[warn] CRC fail:", "crc_failure"),
                             ("[warn] bad header:", "invalid_header"),
                             ("[warn] bad proto:", "invalid_protocol"),
                             ("[warn] bad magic2:", "invalid_secondary_magic")):
            if text.startswith(prefix):
                event["warning"] = code
        if event.get("direction") == "TX" and "cmd" in event and "seq" in event:
            self.last_request = dict(event)
            self.reply_status_pending = False
        elif event.get("direction") == "RX" and "cmd" in event and "seq" in event:
            request = self.last_request or {}
            if (event["cmd"], event["seq"]) == (request.get("cmd"), request.get("seq")):
                self.last_reply = dict(event)
                self.reply_status_pending = True
        elif "status" in event and self.reply_status_pending:
            self.last_reply["status"] = event["status"]
            self.reply_status_pending = False
        else:
            self.reply_status_pending = False
        if "exception_type" in event:
            self.last_exception = dict(event)
        if len(event) > 2:
            self.event_count += 1
            if len(self.first_events) < 16:
                self.first_events.append(dict(event))
            self.events.append(event)
            del self.events[:-40]

    def summary(self):
        """Describe observations only; a missing reply does not identify its cause."""
        request = self.last_request
        reply = self.last_reply
        matched = bool(request and reply and reply["line"] > request["line"] and
                       (request["cmd"], request["seq"]) == (reply["cmd"], reply["seq"]))
        summary = {"stage": "initial_access", "last_request": request,
                   "last_matching_reply": reply,
                   "reply_observed_for_last_request": matched,
                   "last_exception": self.last_exception,
                   "underlying_cause": "not_established"}
        if (request and not matched and self.last_exception and
                self.last_exception["line"] > request["line"]):
            exc = self.last_exception
            # Only correlate an exception that names this exact transaction.
            if ((exc.get("cmd"), exc.get("seq")) ==
                    (request["cmd"], request["seq"]) and
                    exc["exception_type"] == "TimeoutError"):
                elapsed = max(0, exc["elapsed_seconds"] - request["elapsed_seconds"])
                summary["signature"] = "initial_access_reply_timeout"
                summary["wait_seconds"] = round(elapsed, 3)
                arg = f" argument {request['arg']}" if "arg" in request else ""
                previous = (f" Previous matching reply: command 0x{reply['cmd']:02X}, "
                            f"sequence {reply['seq']}"
                            + (f", status {reply['status']}" if "status" in reply else "")
                            + "." if reply else "")
                summary["detail"] = (
                    f"Initial access timed out: no matching reply was observed for "
                    f"command 0x{request['cmd']:02X}{arg}, sequence {request['seq']}, "
                    f"within {elapsed:.1f}s.{previous} The underlying cause is not established. "
                    "Export the operator support bundle for support review.")
        return summary

    def document(self):
        return {"summary": self.summary(), "output_lines": self.lines, "events": list(self.events),
                "first_events": list(self.first_events),
                "event_count": self.event_count,
                "tail_events_omitted": max(0, self.event_count - len(self.events)),
                "elapsed_seconds": round(time.monotonic() - self.started, 3),
                "capture_policy": "numeric_protocol_metadata_only"}


def _run_streaming(argv, *, timeout, cwd, env, on_line):
    """Run `argv`, reporting each stdout line as it arrives.

    Returns an object with the same `returncode` / `stdout` / `stderr` shape the
    blocking path produces, so everything downstream is unchanged.

    stderr is merged into stdout deliberately: the tool reports progress on both
    and interleaving them preserves the order things actually happened, which is
    what makes the trail readable when something fails midway.
    """
    collected = []
    # Hidden like every other child. This one is MINE -- added with the progress
    # bar -- and it runs the access tool, so without this it opens a console
    # window for the whole seventy seconds of first access.
    hide = {}
    if platform.system().lower() == "windows":
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        si.wShowWindow = 0
        hide = {"startupinfo": si, "creationflags": subprocess.CREATE_NO_WINDOW}
    proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            cwd=cwd, env=env, text=True, errors="replace",
                            bufsize=1, **hide)
    deadline = time.monotonic() + timeout
    try:
        for line in proc.stdout:                      # iterates as lines arrive
            line = line.rstrip("\r\n")
            collected.append(line)
            try:
                on_line(len(collected), line)
            except Exception:
                # A reporting failure must never fail the operation it reports on.
                pass
            if time.monotonic() > deadline:
                proc.kill()
                raise subprocess.TimeoutExpired(argv, timeout)
        proc.wait(timeout=max(1.0, deadline - time.monotonic()))
    finally:
        if proc.stdout is not None:
            proc.stdout.close()
    return subprocess.CompletedProcess(argv, proc.returncode,
                                       "\n".join(collected), "")


class CallbackListener:
    """Accepts one connection the device is expected to originate.

    Bound BEFORE the tool runs. If the listener was never bound, a silent outcome is
    indistinguishable between "the device never executed anything" and "the device
    executed and could not reach us" -- two findings with different remedies.
    """

    def __init__(self, addr: str, port: int):
        self.addr = addr
        self.port = port
        self._sock: socket.socket | None = None
        self._conn: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    def start(self) -> None:
        """Bind and begin accepting. Raises OSError if the address is unusable."""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.addr, self.port))
        s.listen(1)
        s.settimeout(0.25)
        self._sock = s
        self._stop.clear()

        def accept():
            while not self._stop.is_set():
                try:
                    conn, _ = s.accept()
                except socket.timeout:
                    continue
                except OSError:
                    return
                self._conn = conn
                return

        self._thread = threading.Thread(target=accept, daemon=True)
        self._thread.start()

    def wait(self, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self._conn is not None:
                return True
            time.sleep(0.05)
        return self._conn is not None

    def converse(self, send: bytes, *, read_timeout: float = 6.0,
                 limit: int = 65536, until: bytes | None = None) -> bytes:
        """Send one line to the accepted session and read what comes back.

        READING UNTIL A MARKER, NOT UNTIL A PAUSE. This originally stopped at the
        first half-second gap after any data arrived. That was adequate for the
        one job it was written for -- asking `id` and seeing whether the answer
        says uid=0 -- and it is wrong for anything whose output can pause.

        It cost a bench run. Enrollment runs multi-part commands through an
        interactive `sh -i`, which echoes what it is sent; output arrives in
        pieces, a pause lands in the middle, and the read returns truncated. The
        count of installed keys then parsed as zero and a successful enrollment
        was reported as having installed nothing -- on a receiver where first
        access had just been confirmed at uid=0.

        With `until`, the caller appends a marker to its own command and the read
        ends when that marker arrives. A pause is then just a pause. The timeout
        still bounds it, so a session that dies mid-command cannot hang anyone,
        and a read that ends WITHOUT the marker is incomplete by definition --
        which the caller can now tell, where before it could not.
        """
        if self._conn is None:
            return b""
        data = bytearray()
        try:
            self._conn.sendall(send)
            self._conn.settimeout(0.5)
            deadline = time.monotonic() + read_timeout
            while time.monotonic() < deadline and len(data) < limit:
                try:
                    chunk = self._conn.recv(min(4096, limit - len(data)))
                except socket.timeout:
                    # No marker expected: fall back to the old behaviour, which
                    # is still right for a single short answer.
                    if until is None and data:
                        break
                    continue
                except OSError:
                    break
                if not chunk:
                    break
                data.extend(chunk)
                if until is not None and until in data:
                    break
        except OSError:
            pass
        return bytes(data)

    def stop(self) -> None:
        """Release the port, and do not return until it is actually released.

        The accept thread holds the listening socket, so closing it here while that
        thread is still in accept() leaves the port bound. A leaked listener makes
        the NEXT attempt report NO_ROUTE, which then reads as a network fault that
        is really our own. Signal the thread, join it, then close.
        """
        self._stop.set()
        thread, self._thread = self._thread, None
        if thread is not None and thread.is_alive():
            thread.join(timeout=2.0)
        sock, self._sock = self._sock, None
        for h in (self._conn, sock):
            try:
                if h is not None:
                    h.close()
            except OSError:
                pass
        self._conn = None


def make_mechanism(tool_path, *, serial_port: str, listen_addr: str,
                   listen_port: int = 4444, timeout: float = 45.0,
                   callback_grace: float = 5.0, argv_prefix=(),
                   identity_probe: bool = False, keep_session: bool = False,
                   runner=subprocess.run, on_line=None, on_diagnostics=None):
    """Build the callable Gate 2 invokes as its mechanism.

    `tool_path` is the operator's own first-access tool. Required, no default, never
    searched for. `runner` is injectable so tests never execute the real tool.

    `argv_prefix` is prepended to the command, for a tool that is not directly
    executable -- a .py on Windows needs its interpreter named explicitly, since
    there is no shebang honoured there. It is a sequence, never a shell string, so
    nothing is word-split or interpreted on the way to the process.
    """
    tool = Path(tool_path).expanduser() if tool_path else None
    prefix = [str(a) for a in (argv_prefix or ())]

    # Pin the child's stdio encoding. We capture its output as text, and on Windows
    # the inherited console codepage is cp1252, which cannot encode characters a
    # tool may legitimately print -- a tick mark was enough to kill one outright
    # with UnicodeEncodeError before it finished its work. That presents as the tool
    # exiting non-zero with no callback, i.e. indistinguishable from the device
    # having refused it, which is the wrong conclusion to hand anyone. Forcing UTF-8
    # here changes nothing about the tool itself.
    child_env = dict(os.environ)
    child_env.setdefault("PYTHONIOENCODING", "utf-8")
    child_env.setdefault("PYTHONUTF8", "1")

    # TELL THE TOOL WHICH RECEIVER AND WHICH WAY BACK.
    #
    # The tool was invoked with no arguments and no environment, so it had to
    # carry a hardcoded serial port and callback address. That is wrong on a
    # bench with more than one receiver: the Industrial Gnd485 enumerates on
    # COM9 and the VRX MAX on COM10 on the same PC, so a fixed port could only
    # ever serve one of them.
    #
    # The failure mode is the bad one. Driving the wrong port makes the tool
    # exit without a callback, which is INDISTINGUISHABLE from the receiver
    # refusing first access -- a false negative on the one question a
    # qualification run exists to answer.
    #
    # The caller already knows both facts: which receiver the operator selected
    # and which local address faces it. Passing them beats the tool guessing.
    #
    # ENVIRONMENT RATHER THAN ARGV, for two reasons. It does not change the
    # tool's command-line contract, so a tool that ignores these still runs
    # exactly as before; and a tool run by hand keeps whatever defaults it
    # carries. `set` rather than `setdefault`: an inherited ASCENT_SERIAL_PORT
    # from some unrelated shell must not outrank the receiver actually selected.
    if serial_port:
        child_env["ASCENT_SERIAL_PORT"] = str(serial_port)
    child_env["ASCENT_CALLBACK_HOST"] = str(listen_addr)
    child_env["ASCENT_CALLBACK_PORT"] = str(listen_port)

    def mechanism(target: dict) -> dict:
        diagnostics = AccessDiagnostics()
        process_status = {"callback_received": False}

        def progress(number, line):
            diagnostics.line(number, line)
            if on_line is not None:
                on_line(number, line)

        if tool is None or not tool.is_file():
            return {"result": g2.RESULT_NOT_IMPLEMENTED, "sent": False,
                    "detail": f"no first-access tool at {tool!s}"}

        listener = CallbackListener(listen_addr, listen_port)
        try:
            listener.start()
        except OSError as exc:
            # The return path does not exist, so nothing that followed would be
            # interpretable. Do not run the tool.
            return {"result": g2.RESULT_NO_ROUTE, "sent": False,
                    "detail": f"listener could not bind {listen_addr}:{listen_port}: {exc}"}

        try:
            process_status["tool_sha256"] = hashlib.sha256(tool.read_bytes()).hexdigest()
            try:
                if on_line is None:
                    proc = runner(prefix + [str(tool)], capture_output=True, text=True,
                                  timeout=timeout, cwd=str(tool.parent),
                                  env=child_env, errors="replace")
                    for number, line in enumerate(
                            ((proc.stdout or "") + "\n" + (proc.stderr or "")).splitlines(), 1):
                        diagnostics.line(number, line)
                else:
                    # STREAMED, so a 70-second operation can say what it is doing.
                    #
                    # `capture_output=True` returns nothing until the tool exits,
                    # which is why the panel showed a bare "WORKING..." for over
                    # a minute with no way to tell progress from a hang.
                    #
                    # The blocking path is kept for callers that pass no callback,
                    # because `runner` is injectable and every existing test
                    # supplies a `subprocess.run` stand-in. Streaming replaces the
                    # transport, not the contract.
                    proc = _run_streaming(prefix + [str(tool)], timeout=timeout,
                                          cwd=str(tool.parent), env=child_env,
                                          on_line=progress)
                process_status["exit_code"] = proc.returncode
            except subprocess.TimeoutExpired:
                process_status["timed_out"] = True
                return {"result": g2.RESULT_NO_RESPONSE, "sent": True,
                        "detail": f"the tool did not finish within {timeout:.0f}s"}
            except OSError as exc:
                return {"result": g2.RESULT_MECHANISM_REJECTED, "sent": False,
                        "detail": f"could not run the tool: {exc}"}

            if listener.wait(timeout=callback_grace):
                process_status["callback_received"] = True
                out = {"result": g2.RESULT_ACCESS, "sent": True,
                       "detail": "the device opened a connection back to this host"}
                if keep_session:
                    # Hand the live session upward instead of tearing it down.
                    # Enrollment has to RUN the three commands somewhere, and this
                    # session is the administrative access that was just proven --
                    # requiring the operator to open a second one by hand is exactly
                    # the manual step the product exists to remove.
                    mechanism.session = listener
                if identity_probe:
                    # A callback is execution, not privilege. Ask the session who it
                    # is rather than assuming, and report the answer verbatim so a
                    # non-root session is visible instead of being read as success.
                    raw = listener.converse(b"id\n")
                    text = raw.decode("utf-8", "replace").strip()
                    out["identity_raw"] = text[:400]
                    out["uid0"] = ("uid=0(" in text) or text.startswith("uid=0 ")
                    out["detail"] = ("privileged session confirmed (uid=0)" if out["uid0"]
                                     else "callback received; administrative identity "
                                          "NOT confirmed")
                return out

            # The tool ran and nothing connected back. A zero exit means the tool
            # finished, NOT that access was obtained -- the only evidence of success
            # is an accepted inbound connection. Gate 2 decides what silence is
            # allowed to mean; it is never conclusive here.
            tail = ((getattr(proc, "stderr", "") or getattr(proc, "stdout", "") or "")
                    .strip().splitlines() or [""])[-1]
            return {"result": g2.RESULT_NO_RESPONSE, "sent": True,
                    "detail": (f"tool exited {getattr(proc, 'returncode', '?')}; "
                               f"no callback. {diagnostics.summary().get('detail') or tail[:160]}")}
        finally:
            if on_diagnostics is not None:
                try:
                    on_diagnostics(dict(diagnostics.document(), **process_status))
                except Exception:
                    # Diagnostics must not alter access or enrollment outcomes.
                    pass
            # Only release it when it was not handed upward; otherwise the caller
            # owns it and is responsible for close_session().
            if getattr(mechanism, "session", None) is not listener:
                listener.stop()

    #: Set to the live CallbackListener when keep_session is on and access
    #: succeeded. None otherwise, so a caller cannot mistake a torn-down
    #: session for a usable one.
    mechanism.session = None
    mechanism.tool_path = str(tool) if tool else None
    mechanism.serial_port = serial_port
    mechanism.listen_addr = listen_addr
    mechanism.listen_port = listen_port
    #: Exposed for the same reason as the fields above: so a caller and a test
    #: can see what was actually composed rather than inferring it. An empty
    #: prefix against a .py tool is a real defect on Windows -- CreateProcess
    #: honours no shebang -- and it presents as the tool failing rather than as
    #: a configuration mistake, so it needs to be inspectable.
    mechanism.argv_prefix = tuple(prefix)
    return mechanism


class Gate2InitialAccess:
    """Adapts Gate 2 to the shape `Orchestrator` expects for `initial_access`.

    The orchestrator asks for `{"ok": bool, "detail": str}`; Gate 2 speaks a richer
    outcome vocabulary. Only ACCESS is success -- every other outcome, including an
    inconclusive silence, is a failure to obtain first access.
    """

    def __init__(self, gate: "g2.Gate2", mechanism=None):
        self._gate = gate
        self._mechanism = mechanism
        self.last_outcome: dict | None = None

    def establish(self, target: dict) -> dict:
        out = self._gate.attempt(target)
        self.last_outcome = out
        return {"ok": out.get("result") == g2.RESULT_ACCESS,
                "detail": out.get("detail") or out.get("meaning")}

    # -- the live session, for the steps that follow ------------------------- #

    @property
    def session(self):
        """The administrative session, or None. Only ever set after ACCESS."""
        return getattr(self._mechanism, "session", None)

    def privileged(self) -> bool:
        """Did the probe actually confirm uid=0?

        Enrollment writes to /root, so running it on a session whose privilege was
        never established would produce a failure that looks like the device
        refusing a correct key.
        """
        return bool((self.last_outcome or {}).get("uid0"))

    def run_command(self, command: str, *, read_timeout: float = 8.0) -> str:
        """Run one command in the established session and return what it printed.

        Raises if there is no session, rather than silently reporting success for
        work that never happened.
        """
        sess = self.session
        if sess is None:
            raise RuntimeError("no administrative session is open")
        # A MARKER PER CALL, so one command's trailing output cannot be read as
        # the next one's answer. The nonce makes that impossible even if an
        # earlier read returned late.
        # BOTH ENDS, NOT JUST THE FAR ONE.
        #
        # This emitted a unique END marker and returned everything read before
        # it. The nonce made the marker unique; it never said where the ANSWER
        # BEGINS. So anything still in the buffer -- the tail of the previous
        # command, the shell's prompt, its echo of our own line -- was returned
        # as this command's output.
        #
        # Observed on hardware: a diagnosis whose answers were all off by one.
        # `root_dir` showed a command, `root_writable` showed root_dir's answer,
        # `dropbear_args` showed root_home's. The same desync reaches the
        # enrolment read-back, which parses a `grep -c` result, so a count could
        # be taken from the wrong command entirely.
        #
        # A start marker bounds it. The shell echoes the whole line, so the
        # start text appears twice -- once in the echo, once when the shell
        # actually runs `echo` -- and the real one is the LAST, which is why
        # this splits from the right.
        nonce = secrets.token_hex(6)
        start = "__ASCENT_B_%s__" % nonce
        marker = "__ASCENT_E_%s__" % nonce
        line = "echo %s; %s; echo %s\n" % (
            start, command.rstrip("\n").rstrip(";"), marker)
        raw = sess.converse(line.encode("utf-8"), read_timeout=read_timeout,
                            until=marker.encode("ascii"))
        text = raw.decode("utf-8", "replace")
        if start in text:
            text = text.rsplit(start, 1)[-1]
        if marker not in text:
            # Incomplete by definition. Saying so beats handing back a partial
            # answer that a caller will parse as a result -- which is exactly
            # how a successful enrollment was read as having installed nothing.
            raise RuntimeError(
                "the session did not finish the command within "
                f"{read_timeout:g}s; its reply was incomplete")
        # Between the two markers. The echo of our own line now sits BEFORE the
        # start marker and is gone already; what remains is the command's own
        # output and nothing else.
        body = text.split(marker, 1)[0]
        return "\n".join(l for l in body.splitlines()
                          if start not in l and marker not in l
                          and l.strip() != line.strip()).strip("\n")

    def close_session(self) -> None:
        sess = self.session
        if sess is not None:
            sess.stop()
            try:
                self._mechanism.session = None
            except AttributeError:
                pass
