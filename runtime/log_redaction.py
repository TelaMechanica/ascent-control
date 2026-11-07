"""Shared log key-material redaction; no receiver access."""
import re
_PRIVATE_BLOCK = re.compile('-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----', re.DOTALL)
_PUBLIC_BODY = re.compile('(ssh-ed25519|ssh-rsa|ecdsa-sha2-\\S+)\\s+([A-Za-z0-9+/=]{20,})')

def redact(text) -> str:
    """Strip key material from anything heading for a log or an API response.

    Private blocks vanish entirely. Public keys keep their type and a short tail so a
    human can tell two keys apart without the full material being written down.
    """
    if not isinstance(text, str):
        return ''
    out = _PRIVATE_BLOCK.sub('[private key redacted]', text)
    out = _PUBLIC_BODY.sub(lambda m: f'{m.group(1)} …{m.group(2)[-8:]}', out)
    return out
