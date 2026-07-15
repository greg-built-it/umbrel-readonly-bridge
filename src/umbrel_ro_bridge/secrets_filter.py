"""
Secret-Erkennung und -Maskierung fuer read_text und grep.
"""

import re

SECRET_KEY_RE = re.compile(
    r"(?i)(api[_-]?key|token|secret|password|passwd|credential|authorization|auth_json|client_secret|private_key|macaroon|seed|mnemonic)"
)

# Heuristik: Base64/Hex-String, der wie ein Key aussieht.
KEY_LIKE_RE = re.compile(r"(?:[A-Za-z0-9+/]{40,}={0,3}|[a-f0-9]{40,})")


def mask_secret_line(line: str) -> str:
    """Maskiert den Wert in einer Zeile, falls ein Secret-artiger Schlüssel erkannt wird."""
    match = SECRET_KEY_RE.search(line)
    if not match:
        return line
    # Ersetze alles nach dem ersten =, : oder Leerzeichen hinter dem Key.
    key_end = match.end()
    rest = line[key_end:]
    # Finde Trennzeichen am Anfang des Rests
    delim_match = re.match(r'([\t ]*[:=][\t ]*|[\t ]+)', rest)
    if delim_match:
        return line[:key_end] + delim_match.group(0) + "[REDACTED]"
    return line[:key_end] + " [REDACTED]"


def mask_key_like_strings(text: str) -> str:
    """Ersetzt sehr lange Base64/Hex-Blöcke, die wie Schlüssel aussehen."""
    return KEY_LIKE_RE.sub("[KEY_LIKE_REDACTED]", text)


def sanitize_text(text: str) -> str:
    """Wendet beide Maskierungen an."""
    lines = text.splitlines(keepends=True)
    masked = [mask_secret_line(line) for line in lines]
    joined = "".join(masked)
    return mask_key_like_strings(joined)


def mask_secrets(text: str) -> str:
    """Alias fuer sanitize_text; wird von fs.read_text und fs.grep verwendet."""
    return sanitize_text(text)


def is_likely_secret_file(filename: str) -> bool:
    lowered = filename.lower()
    secret_names = {
        "auth.json", "secrets.json", "credentials.json", ".env",
        "wallet.dat", "id_rsa", "id_ed25519", "id_ecdsa", "authorized_keys",
    }
    if lowered in secret_names:
        return True
    if any(lowered.endswith(ext) for ext in (".pem", ".key", ".macaroon")):
        return True
    return False
