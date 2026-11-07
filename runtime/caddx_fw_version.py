"""
One authoritative firmware-version parser and comparator.

### Why this module exists

`19.2.14` sorts *below* `19.2.4` as a string. That is not hypothetical here: the bench
MAX was re-flashed from 19.2.4 to 19.2.14, and anything that ordered firmware
lexically would have called the newer build older, offered a downgrade as an upgrade,
or silently failed an exact-equality gate while reporting a version mismatch it could
not explain.

`caddx_firmware_upgrade.judge_versions` already compares correctly, because it
reproduces the vendor's `System.Version` numeric-tuple semantics. That function is the
*vendor parity* path and must keep behaving exactly as the PC Tool does, including its
return codes and its `V_unRecog` quirk. This module is the *project's own* comparator
for everything that is not vendor parity -- capability gating, profile matching,
support matrices -- so those callers never hand-roll a comparison and never reach for
`>` on a string.

Both agree on ordering. They are kept separate because they answer different
questions: one asks "what would the vendor tool do", the other asks "is this unit at
or past the build we have evidence for".

### What a version is here

A firmware version is a tuple of non-negative integers, compared element by element,
shorter-is-smaller only when all shared elements are equal (`19.2 < 19.2.1`). It is
parsed out of the shapes this project actually sees:

```
Ascent_VRX_Max_19_2_14   -> (19, 2, 14)    command-60 firmware field
19.2.14                  -> (19, 2, 14)    command-60 sdk_version field
V19.2.14                 -> (19, 2, 14)    vendor label form
Ascent_VRX_Max_19_2_14.img -> (19, 2, 14)  image filename
```

Anything else parses to `None`, which every comparison treats as *unknown* and never
as *old*. An unknown version must fail a gate closed, not sort to the bottom.
"""
from __future__ import annotations

import re

# Three or two dotted components, or the underscore form, anywhere in the string. The
# underscore form is anchored to the tail because `Ascent_VRX_Max_19_2_14` puts the
# version last and a product name may itself contain digits.
_DOTTED = re.compile(r"(?<![\d.])(\d{1,4}(?:\.\d{1,4}){1,3})(?![\d.])")
_UNDERSCORE = re.compile(r"(?:^|_)(\d{1,4}(?:_\d{1,4}){1,3})(?:$|\.img$)", re.IGNORECASE)

MAX_COMPONENTS = 4


def parse(text) -> tuple | None:
    """A version tuple, or None when the text carries no parsable version.

    None means *unknown*, never *zero*. Callers must not substitute a default.
    """
    if not isinstance(text, str):
        return None
    s = text.strip()
    if not s:
        return None
    # Strip a leading vendor "V" label marker, but only when a digit follows, so a
    # product name beginning with V is not mangled.
    if len(s) > 1 and s[0] in "Vv" and s[1].isdigit():
        s = s[1:]
    for pattern, sep in ((_DOTTED, "."), (_UNDERSCORE, "_")):
        m = pattern.search(s)
        if m:
            parts = m.group(1).split(sep)
            if len(parts) > MAX_COMPONENTS:
                return None
            try:
                return tuple(int(p) for p in parts)
            except ValueError:
                return None
    return None


def _pad(a: tuple, b: tuple) -> tuple:
    n = max(len(a), len(b))
    return a + (0,) * (n - len(a)), b + (0,) * (n - len(b))


def compare(left, right) -> int | None:
    """-1, 0 or 1 -- or None when either side is unknown.

    A None result is the honest answer to "which is newer" when one version could not
    be parsed, and callers must branch on it rather than coercing it to an ordering.
    """
    a, b = (left if isinstance(left, tuple) else parse(left),
            right if isinstance(right, tuple) else parse(right))
    if a is None or b is None:
        return None
    a, b = _pad(a, b)
    return (a > b) - (a < b)


def is_at_least(candidate, floor) -> bool | None:
    """Is `candidate` the same as or newer than `floor`? None when unknown.

    This is the shape a capability gate wants, and it returns None rather than False
    for an unparsable version so the caller can fail closed with a reason instead of
    silently treating an unknown build as too old.
    """
    c = compare(candidate, floor)
    return None if c is None else c >= 0


def same_release(left, right) -> bool | None:
    c = compare(left, right)
    return None if c is None else c == 0


def label(version) -> str:
    """`(19, 2, 14)` -> `19.2.14`. An unknown version renders as a dash, not a zero."""
    v = version if isinstance(version, tuple) else parse(version)
    return "—" if v is None else ".".join(str(n) for n in v)


def describe(text) -> dict:
    """Everything a UI or document needs about one version string, including the
    honest `known: False` case."""
    v = parse(text)
    return {"raw": text if isinstance(text, str) else None,
            "components": list(v) if v else None,
            "label": label(v), "known": v is not None}


def selftest() -> None:
    # The exact hazard this module exists for.
    assert parse("Ascent_VRX_Max_19_2_14") == (19, 2, 14)
    assert parse("Ascent_VRX_Max_19_2_4") == (19, 2, 4)
    assert compare("19.2.14", "19.2.4") == 1
    assert "19.2.14" < "19.2.4"            # the lexical trap, stated so it is visible
    assert is_at_least("19.2.14", "19.2.4") is True
    assert is_at_least("19.2.4", "19.2.14") is False
    assert compare("nonsense", "19.2.4") is None
    assert is_at_least("nonsense", "19.2.4") is None
    assert label(parse("V19.2.14")) == "19.2.14"
