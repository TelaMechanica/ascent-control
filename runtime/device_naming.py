"""Human-readable product naming for raw command-60 device identities.

CLAUDE.md, "Device identity": *keep the exact raw command-60 identity internally,
humanize only for display*, and *never use display names as compatibility or
security keys*.  This module is display-only and is deliberately unreachable from
any qualification path: `QUALIFY`, the RF write gate and the firmware gate all
read ``identity["device_name"]``, never ``display``.  Every return value carries
the untouched ``raw`` string beside the rendered one so a caller cannot
accidentally lose it.

Handoff ASCENT_CONTROL_CURRENT_HANDOFF_FOR_CLAUDE_OPUS_2026-09-16.md §5 lists
"displaying raw internal identifiers such as ``Ascent_VRX_max_WF`` as the primary
product name" as a defect of the Alpha14-class build.  That was accurate: before
this module the candidate dropdown label and the DEVICE INFO name row both
rendered the raw string.  §3 then requires "a human-readable user alias without
replacing the immutable hardware identity" -- so both are shown, always, and the
raw one is never dropped from the page.

Resolution has exactly three outcomes and each is reported in ``source``:

``mapped``    the identity matched a known product in TABLE.  This is the only
              case that yields a vendor product name.
``derived``   no table entry matched.  The tokens are rendered readably
              (acronyms upper-cased, everything else title-cased) and the result
              is explicitly *not* claimed to be a vendor product name.  An
              unreleased or unmodelled unit lands here rather than being coerced
              into a sibling's name -- the same rule as the device-artwork lock
              ("exact render or no render").
``absent``    there is no identity to render.

Version suffixes are handled by longest-prefix match rather than by pattern
stripping, because vendor identity strings carry version material in several
shapes (``Ascent_VRX_Max_19_2_4``, ``Ascent_VRX_Max_1928``,
``Ascent_GT_Max_WF_18_3_4_z40_9``). Known Z8/Z40 product variants remain in the
display even when embedded in that suffix. Whatever is left over after the
matched prefix is returned in ``trailing`` and is *never* presented as a
firmware version: the firmware version has its own command-60 field.
"""

from __future__ import annotations

# Tokens rendered in full upper case.  These are the vendor's own casing for the
# product lines in CLAUDE.md "Families to support" plus the transport/telemetry
# acronyms that appear inside identity strings.
_ACRONYMS = frozenset({
    "vrx", "vtx", "gt", "wf", "hf", "rc", "hd", "fpv", "osd", "gnd", "av", "z40", "z8",
})

# Camera/product variants that remain part of the marketing name even when vendor
# identities place them after a firmware run (for example
# ``Ascent_GT_Max_WF_18_3_4_z40_9``). They are not version material.
_PRODUCT_VARIANTS = {"z40": "Z40", "z8": "Z8"}

# Known raw command-60 identities, normalised to lower-case underscore tokens.
# Keys are token tuples so lookup is exact and order-sensitive; a substring match
# would let `Ascent_VRX_Max_HF` answer to the `Ascent_VRX_Max` entry.
#
# Display strings are the vendor's product names as written in CLAUDE.md
# "Families to support" and in vendor `SysParam.data`.  Nothing here is invented:
# an identity with no known product name must fall through to `derived`.
TABLE: dict[tuple[str, ...], str] = {
    ("ascent", "vrx"): "Ascent VRX",
    ("ascent", "vrx", "m"): "Ascent VRX",
    ("ascent", "vrxpro"): "Ascent VRX Pro",
    ("ascent", "vrx", "pro"): "Ascent VRX Pro",
    ("ascent", "vrxmax"): "Ascent VRX Max",
    ("ascent", "vrx", "max"): "Ascent VRX Max",
    ("ascent", "vrx", "max", "wf"): "Ascent VRX Max WF",
    ("ascent", "vrx", "max", "hf"): "Ascent VRX Max HF",
    ("ascent", "vrx", "cine"): "Ascent VRX Cine",
    ("ascent", "goggles"): "Ascent Goggles",
    ("ascent", "gtpro"): "Ascent GT Pro",
    ("ascent", "gt", "pro"): "Ascent GT Pro",
    ("ascent", "gtproz40"): "Ascent GT Pro Z40",
    ("ascent", "gtproz8"): "Ascent GT Pro Z8",
    ("ascent", "gt", "pro", "z40"): "Ascent GT Pro Z40",
    ("ascent", "gt", "pro", "z8"): "Ascent GT Pro Z8",
    ("ascent", "gt", "max", "wf"): "Ascent GT Max WF",
    ("ascent", "gt", "max", "wf", "z40"): "Ascent GT Max WF Z40",
    ("ascent", "gt", "max", "wf", "z8"): "Ascent GT Max WF Z8",
    ("ascent", "gt", "max", "hf"): "Ascent GT Max HF",
    ("ascent", "gt", "max", "hf", "z40"): "Ascent GT Max HF Z40",
    ("ascent", "gt", "max", "hf", "z8"): "Ascent GT Max HF Z8",
    ("ascent", "relay"): "Ascent Relay",
    ("ascent", "repeater"): "Ascent Repeater",
    ("ascent", "sky"): "Ascent Sky",
    ("ascent", "g", "sky"): "Ascent Sky",
    ("ascent", "g", "gnd"): "Ascent Ground",
    ("ascent", "camhub"): "Ascent Camera Hub",
    ("ascent", "cam", "hub"): "Ascent Camera Hub",
    ("ascent", "lite", "vtx"): "Ascent Lite VTX",
    ("ascent", "liteplus"): "Ascent Lite Plus",
}


def _tokens(raw: str) -> list[str]:
    out: list[str] = []
    for chunk in str(raw).replace("-", "_").replace(" ", "_").split("_"):
        chunk = chunk.strip()
        if chunk:
            out.append(chunk.lower())
    return out


def _is_version_token(tok: str) -> bool:
    """Is this token version/build material rather than part of the product name?

    Vendor identity strings append version material in several shapes:
    ``Ascent_VRX_Max_19_2_4`` (dotted, split on underscores), ``..._1928``
    (joined). A literal ``v`` prefix is accepted, but Z8/Z40 are handled as
    product variants rather than being discarded as version material.

    A token that is a *word* is not version material, and that distinction is
    what stops an unmodelled variant borrowing its base product's name.
    """
    if tok.isdigit():
        return True
    return tok.startswith("v") and tok[1:].isdigit()


def _render_token(tok: str) -> str:
    if tok in _ACRONYMS:
        return tok.upper()
    if tok.isdigit():
        return tok
    return tok[:1].upper() + tok[1:]


def humanize(raw: object) -> dict:
    """Render a raw command-60 device name for display.

    Returns a dict that always carries ``raw`` unchanged.  ``display`` is never
    used as a key for anything -- see the module docstring.
    """
    if raw is None or not str(raw).strip():
        return {"raw": None, "display": None, "source": "absent",
                "is_product_name": False, "hub": False, "trailing": None}

    raw_str = str(raw)
    toks = _tokens(raw_str)

    # A camera-hub variant is a suffix on another product line, not a line of its
    # own -- `Ascent_GT_Max_WF_Hub` is a GT Max WF.  Lift it out before matching
    # so one table entry serves both, then put it back on the rendered name.
    hub = "hub" in toks
    base = [t for t in toks if t != "hub"]

    # Longest-prefix match: the identity string carries version material in
    # several different shapes, and a prefix walk handles all of them without
    # guessing which trailing tokens are a version.
    for end in range(len(base), 0, -1):
        key = tuple(base[:end])
        name = TABLE.get(key)
        if name is None:
            continue
        trailing = base[end:]
        variants = [t for t in trailing if t in _PRODUCT_VARIANTS]
        version_material = [t for t in trailing if t not in _PRODUCT_VARIANTS]
        # A shortened prefix may only match when everything it dropped is version
        # material.  `Ascent_VRX_Max_19_2_4` is a VRX Max; `Ascent_VRX_Max_Quantum`
        # is an unmodelled variant and must NOT present as "Ascent VRX Max".  This
        # is the device-artwork rule applied to names: exact render or no render.
        if (len(set(variants)) > 1 or
                (version_material and not all(_is_version_token(t)
                                              for t in version_material))):
            break
        display = name
        if variants:
            variant = _PRODUCT_VARIANTS[variants[0]]
            if not display.endswith(f" {variant}"):
                display = f"{display} {variant}"
        return {
            "raw": raw_str,
            "display": f"{display} Hub" if hub else display,
            "source": "mapped",
            "is_product_name": True,
            "hub": hub,
            "trailing": "_".join(trailing) or None,
        }

    # Unknown line.  Render it legibly but do not claim it is a product name, and
    # do not let it borrow a sibling's name.
    rendered = " ".join(_render_token(t) for t in toks) if toks else raw_str
    return {
        "raw": raw_str,
        "display": rendered,
        "source": "derived",
        "is_product_name": False,
        "hub": hub,
        "trailing": None,
    }


def display_name(raw: object) -> str | None:
    """Convenience accessor. Returns None when there is nothing to render."""
    return humanize(raw)["display"]
