"""Client-key compatibility decisions, independent of enrollment or authority.

A known receiver restriction cannot be widened by an unavailable daemon probe.
Unknown compatibility is not evidence that any candidate will authenticate.
Explicit archival exports are outside this policy: preserving a key must remain
possible even when it is unsuitable for the currently selected receiver.
"""
from .service_access import AccessDenied

CLIENT_KEY_TYPES = ('ed25519', 'ecdsa')
_GND_PREFIXES = ('Ascent_G_Gnd', 'Ascent_G_GND')


def compatible_key_types(device_name, firmware=None):
    for field in (device_name, firmware):
        if isinstance(field, str) and field.startswith(_GND_PREFIXES):
            return ('ecdsa',)
    return None


def require_compatible_key_type(key_type, device_name, firmware=None):
    """Call before publishing a conversion or preparing/invoking first access."""
    if key_type not in CLIENT_KEY_TYPES:
        raise AccessDenied('CLIENT_KEY_TYPE_UNSUPPORTED')
    supported = compatible_key_types(device_name, firmware)
    if supported is not None and key_type not in supported:
        raise AccessDenied('CLIENT_KEY_ALGORITHM_INCOMPATIBLE')
    return key_type


def recommend_key_type(available, device_name=None, firmware=None):
    """Recommend a retained compatible key; never generate or replace a key."""
    supported = compatible_key_types(device_name, firmware)
    candidates = [kind for kind in CLIENT_KEY_TYPES if kind in available and
                  (supported is None or kind in supported)]
    if 'ecdsa' in candidates:
        return 'ecdsa'
    return next(iter(candidates), None)
