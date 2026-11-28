"""parse_enrollment_verification: the squashfs/GND485 enrollment readback parser.

Regression guard for the `ls -ld` permission check. It indexes the mode string at
the group-write and other-write bits; those indices were once undefined module
names, so the parser raised NameError on ALL real output and a possibly-successful
GND485 key install was reported as a generic first-access failure. These tests run
the parser on realistic transcripts and pin that a group- or other-writable key
directory is what gets flagged (Dropbear refuses keys under a world-writable path).
"""
from ascent_core import enrollment_commands as ec

HOME = ec.USRDATA_HOME
SSH = HOME + "/.ssh"
KEYS = ec.USRDATA_AUTHORIZED_KEYS


def _transcript(*, modes, key=1, mount=1, hook=1, effective=1):
    """Build the BEGIN..END report the device emits, with one ls -ld line per path."""
    lines = [ec.VERIFY_BEGIN,
             f"key={key}", f"mount={mount}", f"hook={hook}", f"effective={effective}"]
    for path, mode in modes.items():
        lines.append(f"{mode} 2 root root 4096 Jan 1 00:00 {path}")
    lines.append(ec.VERIFY_END)
    return "\n".join(lines)


SAFE_MODES = {HOME: "drwx------", SSH: "drwx------", KEYS: "-rw-------"}


def test_clean_enrollment_parses_without_error_and_passes():
    # The regression: this used to raise NameError on the first ls -ld line.
    result = ec.parse_enrollment_verification(_transcript(modes=SAFE_MODES))
    assert result["ok"] is True
    assert result["problems"] == []
    assert result["facts"]["key"] == 1


def test_group_writable_key_directory_is_flagged():
    # drwxrwxr-x: group-write bit (index 5) set, other-write (index 8) clear.
    modes = dict(SAFE_MODES, **{SSH: "drwxrwxr-x"})
    result = ec.parse_enrollment_verification(_transcript(modes=modes))
    assert result["ok"] is False
    assert any("written by other users" in p for p in result["problems"])


def test_other_writable_key_directory_is_flagged():
    # drwxr-x-wx: other-write bit (index 8) set, group-write (index 5) clear.
    # Proves the other-write index is correct, not just the group one.
    modes = dict(SAFE_MODES, **{SSH: "drwxr-x-wx"})
    result = ec.parse_enrollment_verification(_transcript(modes=modes))
    assert result["ok"] is False
    assert any("written by other users" in p for p in result["problems"])


def test_truncated_report_is_reported_not_crashed():
    result = ec.parse_enrollment_verification("ASCENT_ENROLL_BEGIN\nkey=1\n")  # no END
    assert result["ok"] is False
    assert result["problems"]
