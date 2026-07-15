"""
Zugriffsrichtlinien fuer die Umbrel Read-Only MCP Bridge.

Pfadnormalisierung, Root-Sandbox, Symlink-Enforcement, Denylist fuer Secrets
und Allowlist-Root-Konfiguration.
"""

import os
import re
import stat
from pathlib import Path

# ---------------------------------------------------------------------------
# Konstanten: zu schützende Token-Pfade
# ---------------------------------------------------------------------------
# Der eigene App-Token kann unter verschiedenen Pfaden auftauchen:
#   - als Secret-Mount im Container: /run/secrets/bridge-token
#   - im App-Data-Store auf dem Host: /host/umbrel/app-data/.../bridge-token
#   - als Symlink-Ziel oder versteckte Datei .bridge-token
# Diese Pfade werden explizit blockiert, auch wenn sie unterhalb der
# erlaubten Datenwurzel liegen.

TOKEN_FILE_NAME = "bridge-token"
TOKEN_HIDDEN_NAME = ".bridge-token"
TOKEN_SECRET_PATH = Path("/run/secrets/bridge-token").resolve()
TOKEN_APP_DATA_PATH = Path("/host/umbrel/app-data/greg-umbrel-readonly-bridge/data/bridge-token").resolve()

TOKEN_REALPATHS = {TOKEN_SECRET_PATH, TOKEN_APP_DATA_PATH}
TOKEN_BASENAMES = {TOKEN_FILE_NAME, TOKEN_HIDDEN_NAME}


# ---------------------------------------------------------------------------
# Konfigurierbare Datenwurzeln
# ---------------------------------------------------------------------------
#
# Diese Pfade definieren, auf welche Bereiche von /home/umbrel/umbrel die
# Bridge zugreifen darf. Die Denylist ist eine zusaetzliche Schutzschicht.
#
# Standardmodus: Medien, Benutzerdateien, Backups, ausgewaehlte App-Daten.
# Extended-Read: zusaetzlich alle App-Daten, selbst wenn sie root gehoeren.

DATA_ROOTS_STANDARD = (
    "/host/umbrel",
)

DATA_ROOTS_EXTENDED = (
    "/host/umbrel",
)

DATA_ROOTS_ALL = DATA_ROOTS_STANDARD

# ---------------------------------------------------------------------------
# Denylist
# ---------------------------------------------------------------------------
#
# Diese Pfade/Muster werden blockiert, auch wenn sie innerhalb der Allowlist
# liegen. Die Erkennung ist heuristisch und nicht zuverlaessig fuer alle
# Secrets in JSON, YAML, Datenbanken, Backups oder Logs.

DENIED_PATH_PATTERNS = [
    re.compile(r"(^|/|\.)\.env$"),
    re.compile(r"(^|/|\.)[a-zA-Z0-9_-]*\.env$"),
    re.compile(r"(^|/)auth\.json$"),
    re.compile(r"(^|/)secrets\.json$"),
    re.compile(r"(^|/)credentials\.json$"),
    re.compile(r"(^|/)\.ssh(/|$)"),
    re.compile(r"(^|/)(id_[^/]+|authorized_keys|known_hosts)$"),
    re.compile(r"\.pem$"),
    re.compile(r"\.key$"),
    re.compile(r"\.macaroon$"),
    re.compile(r"(^|/)wallet\.dat$"),
    re.compile(r"(^|/)secrets(/|$)"),
    re.compile(r"(^|/)credentials(/|$)"),
    re.compile(r"(^|/)wallet(/|$)"),
    re.compile(r"(^|/)macaroons(/|$)"),
    re.compile(r"(^|/)docker\.sock$"),
    re.compile(r"(^|/)\.docker(/|$)"),
    re.compile(r"(^|/)proc(/|$)"),
    re.compile(r"(^|/)sys(/|$)"),
    re.compile(r"(^|/)dev(/|$)"),
    re.compile(r"(^|/)run/secrets(/|$)"),
    re.compile(r"(^|/)\.bridge-token$"),
    re.compile(r"(^|/)bridge-token$"),
]

SHELL_META_PATH_RE = re.compile(r"[;|&$`\"'\\<>{}[\]\n\x00]")
SHELL_META_NAME_RE = re.compile(r"[;|&$`\"'\\<>{}\n\x00]")

MAX_PATH_LEN = 4096


class PolicyError(Exception):
    """Verletzung einer Sicherheitsrichtlinie."""
    pass


def _contains_shell_meta(path: str) -> bool:
    return bool(SHELL_META_PATH_RE.search(path))


def _contains_shell_meta_name(name: str) -> bool:
    return bool(SHELL_META_NAME_RE.search(name))


def _get_allowed_roots() -> tuple[str, ...]:
    """Liest den Modus aus der Umgebungsvariable BRIDGE_MODE."""
    mode = os.environ.get("BRIDGE_MODE", "standard").lower()
    if mode == "extended-read":
        return DATA_ROOTS_EXTENDED
    return DATA_ROOTS_STANDARD


def _is_under_allowed_root(resolved: Path) -> bool:
    """Prueft, ob resolved unter einem der erlaubten Roots liegt."""
    try:
        for root in _get_allowed_roots():
            root_resolved = Path(root).resolve()
            resolved.relative_to(root_resolved)
            return True
    except ValueError:
        pass
    return False


def _is_token_path(resolved: Path) -> bool:
    """
    Prueft, ob der kanonisch aufgeloeste Pfad ein eigener App-Token-Pfad
    ist.  Erfasst den Secret-Mount, den persistenten App-Datenpfad sowie
    Symlinks, die darauf zeigen, auch wenn die Datei nicht existiert.
    """
    try:
        real = Path(os.path.realpath(resolved))
    except (OSError, RuntimeError):
        real = resolved

    # Exakte Realpath-Treffer (auch Symlinks werden aufgeloest).
    if real in TOKEN_REALPATHS:
        return True

    # Aufgeloester Pfad-Treffer (funktioniert auch ohne existierende Datei).
    try:
        if resolved in TOKEN_REALPATHS:
            return True
    except (OSError, RuntimeError):
        pass

    # Basisnamen-Sperre fuer bridge-token / .bridge-token.
    if real.name in TOKEN_BASENAMES:
        return True
    if resolved.name in TOKEN_BASENAMES:
        return True

    return False


def resolve_host_path(request_path: str, require_exists: bool = True) -> Path:  # noqa: D401
    """
    Normalisiert einen Request-Pfad und prueft:
      - Laenge
      - keine Shell-Metazeichen
      - liegt unter einem der konfigurierten Daten-Roots
      - Symlinks bleiben innerhalb der Roots
      - Token-Pfade (inkl. Symlinks auf Token) blockiert
    """
    if not isinstance(request_path, str):
        raise PolicyError("Pfad muss ein String sein.")
    if len(request_path) > MAX_PATH_LEN:
        raise PolicyError("Pfad zu lang.")
    if _contains_shell_meta(request_path):
        raise PolicyError("Pfad enthaelt unerlaubte Zeichen.")

    p = Path(request_path)
    if not p.is_absolute():
        p = Path("/host/umbrel") / p

    try:
        resolved = p.resolve(strict=False)
    except (OSError, RuntimeError) as e:
        raise PolicyError(f"Pfadaufloesung fehlgeschlagen: {e}")

    # Eigene App-Token-Pfade blockieren, BEVOR die Root-Pruefung sie
    # ausschliessen koennte (z. B. /run/secrets/bridge-token).
    if _is_token_path(resolved):
        raise PolicyError("Zugriff auf Token-Quelle verweigert.")

    if not _is_under_allowed_root(resolved):
        raise PolicyError("Pfad liegt ausserhalb der erlaubten Datenwurzeln.")

    if require_exists:
        if not resolved.exists():
            raise PolicyError("Pfad existiert nicht.")
        real = Path(os.path.realpath(resolved))
        if not _is_under_allowed_root(real):
            raise PolicyError("Symlink zeigt ausserhalb der erlaubten Datenwurzeln.")
        if _is_token_path(real):
            raise PolicyError("Zugriff auf Token-Quelle verweigert.")

    return resolved


def enforce_host_path(request_path: str) -> Path:
    """Alias fuer resolve_host_path; prueft Existenz."""
    return resolve_host_path(request_path)


def is_denied_path(path: Path) -> tuple[bool, str | None]:
    """Prueft, ob ein Pfad aufgrund der Denylist blockiert werden soll."""
    if _is_token_path(path):
        return True, "Token-Quelle"
    s = str(path)
    for pat in DENIED_PATH_PATTERNS:
        if pat.search(s):
            return True, f"Denylist trifft zu: {pat.pattern}"
    return False, None


def assert_allowed_for_read(path: Path) -> None:
    """Wirft PolicyError, wenn der Pfad nicht gelesen werden darf."""
    denied, reason = is_denied_path(path)
    if denied:
        raise PolicyError(f"Zugriff auf Pfad verweigert: {reason}")


def validate_find_args(name: str | None,
                       size: str | None,
                       mtime_days: int | None,
                       maxdepth: int | None) -> None:
    """Validiert Argumente fuer find-Operationen."""
    if maxdepth is not None and (not isinstance(maxdepth, int) or maxdepth < 0 or maxdepth > 5):
        raise PolicyError("maxdepth muss zwischen 0 und 5 liegen.")
    if size is not None and not re.fullmatch(r"[+-]?\d+[cwkMGTP]?", size):
        raise PolicyError("size hat ungueltiges Format.")
    if mtime_days is not None and not isinstance(mtime_days, int):
        raise PolicyError("mtime_days muss eine Ganzzahl sein.")
    if name is not None and _contains_shell_meta_name(name):
        raise PolicyError("name enthaelt unerlaubte Zeichen.")


def validate_grep_args(pattern: str,
                       path: Path,
                       max_matches: int | None) -> None:
    if _contains_shell_meta(pattern):
        raise PolicyError("pattern enthaelt unerlaubte Zeichen.")
    if max_matches is not None and (not isinstance(max_matches, int) or max_matches < 1 or max_matches > 1000):
        raise PolicyError("max_matches muss zwischen 1 und 1000 liegen.")
    assert_allowed_for_read(path)


def validate_command_name(name: str) -> None:
    if not re.fullmatch(r"[a-z_][a-z0-9_-]*", name):
        raise PolicyError("Ungueltiger Befehlsname.")


def validate_sqlite_query(query: str) -> None:
    """Prueft, ob die SQLite-Abfrage read-only ist."""
    normalized = query.strip()
    lowered = normalized.lower()
    if not lowered:
        raise PolicyError("Leere Abfrage.")
    # Erlaubt nur SELECT-Statements und harmlose read-only PRAGMAs.
    if not re.match(r"^\s*select\b", normalized, re.IGNORECASE) and \
            not re.match(r"^\s*pragma\s+(table_info|index_list|index_info|foreign_key_list)\s*\(", normalized, re.IGNORECASE):
        raise PolicyError("Nur SELECT oder read-only PRAGMA erlaubt.")
    forbidden = (";", "attach", "detach", "load_extension", "pragma write", "journal_mode",
                 "wal_checkpoint", "synchronous", "locking_mode", "schema_version",
                 "secure_delete", "user_version", "application_id", "auto_vacuum",
                 "page_size", "max_page_count")
    for tok in forbidden:
        if tok in lowered:
            raise PolicyError(f"Verbotenes SQL-Element erkannt: {tok}")
    # Nur ein Statement erlaubt.
    if normalized.count(";") > 1 or (normalized.count(";") == 1 and not normalized.endswith(";")):
        raise PolicyError("Nur ein SQL-Statement erlaubt.")


def validate_pdf_path(p: Path) -> None:
    """Prueft Groessenlimit fuer PDFs."""
    max_size = 100 * 1024 * 1024  # 100 MiB
    try:
        if p.stat().st_size > max_size:
            raise PolicyError("PDF ueberschreitet 100 MiB Limit.")
    except OSError as e:
        raise PolicyError(f"PDF-Statistik fehlgeschlagen: {e}")
