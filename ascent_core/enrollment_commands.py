"""Validated receiver enrollment command builders (ported from the proven
service_mode implementation; pure string/parse helpers, no I/O, no exploit payload)."""
from __future__ import annotations
import re


KEY_TYPES = ("ed25519", "ecdsa")
DROPBEAR_ED25519_FROM = (2020, 79)
def parse_dropbear_version(banner: str):
    """(year, release) from an SSH identification string, or None."""
    # Both forms: the SSH banner `dropbear_2019.78` and what `dropbear -V`
    # prints, `Dropbear v2019.78`.
    m = re.search(r"dropbear[\s_v-]*(\d{4})\.(\d+)", banner or "", re.I)
    return (int(m.group(1)), int(m.group(2))) if m else None
def daemon_version_command() -> str:
    """Ask the receiver's own daemon what it is.

    More reliable than the network banner at the moment it matters: enrollment
    already holds a privileged session, so this needs no second connection and
    cannot fail because a probe timed out. `-V` is in the binary's own usage
    text and prints `Dropbear v2019.78`.
    """
    return "dropbear -V 2>&1 | head -1"
def daemon_key_types(banner: str) -> tuple:
    """Which of our key types this daemon can verify, best first.

    An unrecognised daemon gets the full list rather than a guess: OpenSSH and
    every current dropbear handle both, and narrowing on no evidence would
    install a weaker key than the receiver deserves. Narrowing happens only for
    a daemon that has been IDENTIFIED as too old, which is a fact, not a
    default.
    """
    v = parse_dropbear_version(banner)
    if v is not None and v < DROPBEAR_ED25519_FROM:
        return ("ecdsa",)
    return KEY_TYPES
REMOTE_AUTHORIZED_KEYS = "/root/.ssh/authorized_keys"
class ServiceModeError(RuntimeError):
    def __init__(self, code: str, message: str, evidence: dict | None = None):
        super().__init__(message)
        self.code = code
        self.evidence = evidence or {}
_PUBKEY = re.compile(r"^(ssh-ed25519|ssh-rsa|ecdsa-sha2-[a-z0-9-]+)\s+[A-Za-z0-9+/]+=*(\s+[^\n\r']{0,128})?$")
def validate_public_key(key) -> str:
    """One well-formed public key line, with nothing that could escape a shell quote."""
    if not isinstance(key, str):
        raise ServiceModeError("PUBLIC_KEY_INVALID", "a public key line is required")
    line = key.strip()
    if "\n" in line or "\r" in line or "'" in line or not _PUBKEY.match(line):
        raise ServiceModeError("PUBLIC_KEY_INVALID",
                               "that is not a well-formed single-line public key")
    return line
def _q(path: str) -> str:
    """Single-quote one already-validated literal for the remote shell.

    Every value reaching this has been through a validator above, so this is defence
    in depth rather than the primary control. The primary control is that no caller
    can introduce a value the validators did not accept.
    """
    return "'" + path.replace("'", "'\\''") + "'"
USRDATA_ROOT = "/usrdata/ascent"
USRDATA_HOME = USRDATA_ROOT + "/root"
USRDATA_AUTHORIZED_KEYS = USRDATA_HOME + "/.ssh/authorized_keys"
VENDOR_RUN_HOOK = "/usrdata/run.sh"
HOOK_MARKER = "# ascent-service-mode"
DEFAULT_ROOT_HOME = "/root"
UNSAFE_MOUNT_TARGETS = frozenset({"", "/", "/usr", "/etc", "/bin", "/sbin",
                                  "/lib", "/dev", "/proc", "/sys", "/tmp",
                                  "/var", "/usrdata"})
def root_home_probe_command() -> str:
    """Ask the receiver where root's home actually is.

    THIS WAS AN ASSUMPTION AND IT SHOULD NOT HAVE BEEN. The whole bind-mount
    design rests on dropbear resolving root's home to /root, and the only
    evidence for that was /etc/passwd from an **18.x** rootfs dump. The unit is
    19.2.14. Carrying a fact across firmware bases without re-deriving it is
    precisely the error this project has a standing rule against, and the
    failure mode is silent: dropbear looks somewhere we never wrote, finds no
    authorized_keys, and refuses the key with nothing the client can see.

    Read-only, and it costs one command.
    """
    return ("awk -F: '$1==\"root\"{print \"home=\" $6}' /etc/passwd 2>/dev/null "
            "| head -1")
def parse_root_home(output: str) -> str | None:
    """The home directory the receiver reported, or None if it did not say.

    None is returned rather than the default, deliberately: a caller that
    cannot tell "the device said /root" from "the device said nothing" would
    reintroduce the assumption this probe exists to remove.
    """
    for line in (output or "").splitlines():
        line = line.strip()
        if line.startswith("home=") and len(line) > 5:
            home = line[5:].strip().rstrip("/") or "/"
            return home if home.startswith("/") else None
    return None
def mount_target_is_safe(home: str | None) -> bool:
    return bool(home) and home.rstrip("/") not in UNSAFE_MOUNT_TARGETS \
        and home.startswith("/")
def hook_line(home: str = DEFAULT_ROOT_HOME) -> str:
    return f"mount -o bind {USRDATA_HOME} {home} 2>/dev/null  {HOOK_MARKER}"
def as_key_list(public_key) -> list:
    """One key or several, always returned as a validated list.

    Several is not a luxury. When a receiver's SSH daemon cannot be identified,
    picking one algorithm is a guess, and the wrong guess is INVISIBLE: the key
    installs correctly, reads back correctly, sits at the path the daemon opens,
    and is refused because the daemon has no code for that algorithm. Installing
    every type this host holds removes the guess entirely.
    """
    if isinstance(public_key, str):
        keys = [public_key]
    elif isinstance(public_key, (list, tuple)):
        keys = list(public_key)
    else:
        # None, an int, anything else. `list(None)` raises TypeError, which
        # escapes the typed-error contract every caller relies on and turns a
        # rejected input into a crash.
        raise ServiceModeError("PUBLIC_KEY_INVALID",
                               "a public key line is required")
    if not keys:
        raise ServiceModeError("PUBLIC_KEY_INVALID", "at least one public key is required")
    return [validate_public_key(k) for k in keys]
def squashfs_enrollment_commands(public_key: str,
                                 home: str = DEFAULT_ROOT_HOME) -> list:
    """Install a key on a unit whose / is read-only.

    THE HOOK IS APPENDED, NEVER WRITTEN. /usrdata/run.sh is a vendor extension
    point and may already carry an operator's own startup, so `>` would destroy
    work this application did not put there -- the same mistake as truncating
    authorized_keys, with a larger blast radius. It is created only if absent,
    appended to otherwise, and the append is guarded so a second activation
    changes nothing.
    """
    keys = as_key_list(public_key)
    if not mount_target_is_safe(home):
        # Refused rather than defaulted. Mounting over "/" would shadow the
        # running system, and quietly substituting /root for an unexpected
        # answer would put the key somewhere dropbear is not looking while
        # reporting success.
        raise ServiceModeError(
            "UNSAFE_HOME_DIRECTORY",
            f"The receiver reports its administrator home as {home!r}, which "
            f"this application will not mount over.")
    ak = _q(USRDATA_AUTHORIZED_KEYS)
    home_dir = _q(USRDATA_HOME)
    ssh_dir = _q(USRDATA_HOME + "/.ssh")
    return [
        # 1. The key, on storage that survives a reboot.
        #
        #    EVERY PATH dropbear INSPECTS GETS AN EXPLICIT MODE. Its
        #    checkpubkeyperms() stats three of them -- the home directory, its
        #    .ssh, and authorized_keys -- and refuses the key if ANY is group-
        #    or other-writable. `mkdir -p` applies the ambient umask, and this
        #    runs in a shell spawned by a vendor daemon whose umask we do not
        #    control: a umask of 0 yields a 0777 home directory, dropbear then
        #    rejects every key, and the only thing the client can see is a bare
        #    "permission denied". The home directory is chmod'd for exactly
        #    that reason -- it was the omission that cost the first attempt.
        f"mkdir -p {ssh_dir} && touch {ak} "
        f"&& chmod 755 {_q(USRDATA_ROOT)} && chmod 700 {home_dir} {ssh_dir} "
        f"&& chmod 600 {ak}",
        # 2. Append our line only if it is not already there, and only after a
        #    newline guard -- a file not ending in one would otherwise have our
        #    key concatenated onto its last entry, destroying both.
        *[f"grep -qxF {_q(k)} {ak} || "
          f"{{ if [ -s {ak} ] && [ -n \"$(tail -c 1 {ak})\" ]; then echo >> {ak}; fi; "
          f"echo {_q(k)} >> {ak}; }}" for k in keys],
        # 3. Make /root resolve to it for this boot. Already-mounted is not an
        #    error, so a second activation is a no-op.
        f"mountpoint -q {_q(home)} 2>/dev/null || "
        f"mount -o bind {_q(USRDATA_HOME)} {_q(home)} 2>/dev/null || true",
        # 4. And for every boot after it, through the vendor's hook.
        f"touch {_q(VENDOR_RUN_HOOK)}; "
        f"grep -qF {_q(HOOK_MARKER)} {_q(VENDOR_RUN_HOOK)} || "
        f"{{ if [ -s {_q(VENDOR_RUN_HOOK)} ] && "
        f"[ -n \"$(tail -c 1 {_q(VENDOR_RUN_HOOK)})\" ]; then "
        f"echo >> {_q(VENDOR_RUN_HOOK)}; fi; "
        f"echo {_q(hook_line(home))} >> {_q(VENDOR_RUN_HOOK)}; }}; "
        f"chmod +x {_q(VENDOR_RUN_HOOK)} 2>/dev/null || true",
    ]
VERIFY_BEGIN = "ASCENT_ENROLL_BEGIN"
VERIFY_END = "ASCENT_ENROLL_END"
def squashfs_verify_command(public_key: str,
                            home: str = DEFAULT_ROOT_HOME) -> str:
    """Report every condition dropbear will evaluate, on the device.

    Enrolling blind and learning the outcome at the next SSH attempt converts a
    precise and fixable fault -- a mode, an absent mount, a key that did not
    land -- into one opaque "the device refused this computer's key", at a
    moment when the shell that could have answered the question is already
    gone. This asks while the shell is still open.

    It is READ-ONLY: grep, awk and ls. It changes nothing, so it is safe to run
    after a failure as well as after a success, which is when it is most useful.
    """
    keys = as_key_list(public_key)
    ak = _q(USRDATA_AUTHORIZED_KEYS)

    # SUMMED IN SHELL VARIABLES, not inline in the arithmetic. `grep -c` prints
    # "0" and exits 1 when a file has no match, so the familiar
    # `$(grep -c ... || echo 0)` emits TWO lines -- harmless in a plain echo,
    # a syntax error inside $(( )). A missing file prints nothing, which is why
    # each is defaulted before it is added.
    def _sum(var, path):
        parts = []
        for i, k in enumerate(keys):
            parts.append(f"{var}{i}=$(grep -cxF {_q(k)} {path} 2>/dev/null); "
                         f"{var}{i}=${{{var}{i}:-0}}; ")
        total = "+".join(f"${var}{i}" for i in range(len(keys)))
        return "".join(parts) + f"{var}=$(({total})); "

    return (
        f"echo {VERIFY_BEGIN}; "
        # Counted, not just tested: "how many times" distinguishes a missing key
        # from a key appended twice by a repeated activation.
        + _sum("k", ak) +
        f"echo \"key=$k\"; "
        f"echo \"mount=$(awk -v h={_q(home)} "
        f"'$2==h{{n=1}} END{{print n+0}}' /proc/mounts)\"; "
        f"echo \"hook=$(grep -cF {_q(HOOK_MARKER)} {_q(VENDOR_RUN_HOOK)} 2>/dev/null || echo 0)\"; "
        # THROUGH THE HOME PATH, which is what dropbear actually opens.
        #
        # Checking only the storage path proves our files are right and proves
        # nothing about what the SSH service will read: it resolves
        # <home>/.ssh/authorized_keys, and between that and our directory sits
        # a bind mount that may not have been applied. A key that is perfect on
        # one side of a missing mount is still refused, with no visible
        # difference from a key that was never written. So the effective path
        # is asked about by name.
        + _sum("e", _q(home.rstrip("/") + "/.ssh/authorized_keys")) +
        f"echo \"effective=$e\"; "
        # ls -ld, not stat: stat is absent from minimal busybox builds, and the
        # permission string answers the only question that matters here.
        f"ls -ld {_q(USRDATA_HOME)} {_q(USRDATA_HOME + '/.ssh')} {ak} 2>&1; "
        f"ls -ld {_q(home)} {_q(home.rstrip('/') + '/.ssh')} "
        f"{_q(home.rstrip('/') + '/.ssh/authorized_keys')} 2>&1; "
        f"echo {VERIFY_END}"
    )
def parse_enrollment_verification(output: str, *, strict_mount: bool = True,
                                  expected_keys: int = 1) -> dict:
    """Turn that report into a verdict and, when it fails, into the reason.

    Returns ``{"ok": bool, "problems": [str, ...], "facts": {...}}``. Each
    problem names the thing to fix in the operator's terms, because the point of
    asking was to be able to say something better than "refused".
    """
    text = output or ""
    facts: dict = {}
    problems: list = []

    if VERIFY_END not in text:
        return {"ok": False, "facts": facts,
                "problems": ["The receiver did not finish reporting its state, so the "
                             "enrollment could not be confirmed."]}

    body = text.split(VERIFY_BEGIN, 1)[-1].split(VERIFY_END, 1)[0]
    for line in body.splitlines():
        line = line.strip()
        for name in ("key", "mount", "hook", "effective"):
            if line.startswith(name + "="):
                try:
                    facts[name] = int(line.split("=", 1)[1].strip() or 0)
                except ValueError:
                    facts[name] = 0
        # `ls -ld` output: mode string first, path last.
        if line[:1] in ("d", "-") and len(line.split()) >= 4:
            parts = line.split()
            mode, path = parts[0], parts[-1]
            facts.setdefault("modes", {})[path] = mode

    found = facts.get("key", 0)
    if not found:
        problems.append("The access key is not present in the receiver's key file.")
    elif found < expected_keys:
        problems.append(f"Only {found} of {expected_keys} access keys reached the "
                        "receiver's key file.")
    elif found > expected_keys:
        problems.append(f"The key file holds {found} copies of this computer's access "
                        f"keys; {expected_keys} was expected.")

    for path, mode in (facts.get("modes") or {}).items():
        if len(mode) < 10:
            continue
        if mode[_GROUP_W] == "w" or mode[_OTHER_W] == "w":
            problems.append(f"{path} can be written by other users ({mode}); the SSH "
                            "service refuses keys stored anywhere that permissive.")

    missing = [p for p in (USRDATA_HOME, USRDATA_HOME + "/.ssh", USRDATA_AUTHORIZED_KEYS)
               if p not in (facts.get("modes") or {})]
    if missing:
        problems.append("The receiver is missing " + ", ".join(missing) + ".")

    # THE DECISIVE FACT. Everything else is a reason; this is the outcome.
    if "effective" in facts and facts["effective"] < expected_keys:
        problems.append("The receiver's SSH service cannot see the access key at the "
                        "location it reads, so a login would be refused.")

    if strict_mount and not facts.get("mount"):
        problems.append("The key directory is not yet in place as the administrator's "
                        "home directory on this boot.")
    if not facts.get("hook"):
        problems.append("Nothing was added to make the access survive a restart.")

    return {"ok": not problems, "problems": problems, "facts": facts}
def enrollment_target(platform: str | None) -> str:
    """Where authorized_keys lives for this platform.

    Not a guess from the device: the caller passes the platform the firmware
    evidence already identified, so one place decides and the rest follows.
    """
    return (USRDATA_AUTHORIZED_KEYS if platform == "gnd485"
            else REMOTE_AUTHORIZED_KEYS)
def authorized_keys_append_command(public_key: str,
                                   keys_path: str = REMOTE_AUTHORIZED_KEYS) -> str:
    """One idempotent shell command that appends `public_key` to `keys_path`.

    The SAME guard enrollment_instructions() uses: `grep -qxF` makes a re-run a
    no-op, and the trailing-newline test prevents concatenation onto a file that
    does not end in a newline -- which would destroy both the last existing key
    and this one. Self-sufficient (creates the dir/file if missing) so it can run
    stand-alone during enrollment to deploy the session-access public key.
    """
    k = as_key_list(public_key)[0]
    return (
        f"mkdir -p \"$(dirname {_q(keys_path)})\" && touch {_q(keys_path)} && "
        f"grep -qxF {_q(k)} {_q(keys_path)} || "
        f"{{ if [ -s {_q(keys_path)} ] && "
        f"[ -n \"$(tail -c 1 {_q(keys_path)})\" ]; then "
        f"echo >> {_q(keys_path)}; fi; "
        f"echo {_q(k)} >> {_q(keys_path)}; }}")
