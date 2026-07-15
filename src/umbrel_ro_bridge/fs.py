"""
Read-only Dateisystem-Operationen fuer die Umbrel MCP Bridge.

Alle Funktionen gehen von einem in policy.py definierten Root-Verzeichnis aus
und wenden eine Denylist an. Es gibt KEINE Schreiboperationen.
"""

import hashlib
import io
import json
import mimetypes
import os
import re
import sqlite3
import stat
import struct
import tarfile
import zipfile
from pathlib import Path
from typing import Any

from . import policy, secrets_filter


def _magic_from_buffer(data: bytes, mime: bool = False) -> str | None:
    try:
        import magic
        if mime:
            return magic.from_buffer(data, mime=True)
        return magic.from_buffer(data)
    except Exception:
        return None


class FilesystemError(Exception):
    pass


# ---------------------------------------------------------------------------
# Hilfsfunktionen
# ---------------------------------------------------------------------------

MAX_TEXT_BYTES = 5 * 1024 * 1024        # 5 MiB
MAX_TEXT_LIMIT_INPUT = 20 * 1024 * 1024  # 20 MiB
MAX_CHUNK_SIZE = 64 * 1024              # 64 KiB
MAX_ARCHIVE_ENTRIES = 1000
MAX_SQLITE_ROWS = 1000
MAX_PDF_PAGES = 50
MAX_PDF_SIZE = 100 * 1024 * 1024        # 100 MiB
MAX_GREP_FILE_BYTES = 20 * 1024 * 1024  # 20 MiB
MAX_GREP_MATCHES = 1000
MAX_FIND_RESULTS = 1000


def _resolve(path: str) -> Path:
    try:
        return policy.resolve_host_path(path)
    except policy.PolicyError as e:
        raise FilesystemError(str(e))


def _is_allowed(path: Path) -> bool:
    denied, _reason = policy.is_denied_path(path)
    return not denied


def _stat_dict(p: Path) -> dict[str, Any]:
    try:
        st = p.stat(follow_symlinks=False)
    except OSError as e:
        return {"path": str(p), "error": str(e)}
    return {
        "path": str(p),
        "type": _file_type(p, st),
        "size": st.st_size,
        "mode": stat.S_IMODE(st.st_mode),
        "uid": st.st_uid,
        "gid": st.st_gid,
        "mtime": st.st_mtime,
        "is_symlink": stat.S_ISLNK(st.st_mode),
    }


def _file_type(p: Path, st: os.stat_result) -> str:
    if stat.S_ISDIR(st.st_mode):
        return "directory"
    if stat.S_ISLNK(st.st_mode):
        return "symlink"
    if stat.S_ISREG(st.st_mode):
        return "file"
    if stat.S_ISBLK(st.st_mode) or stat.S_ISCHR(st.st_mode):
        return "device"
    return "other"


# ---------------------------------------------------------------------------
# Werkzeuge
# ---------------------------------------------------------------------------

def list_directory(path: str) -> dict[str, Any]:
    root = _resolve(path)
    if not root.exists():
        raise FilesystemError(f"Pfad nicht gefunden: {path}")
    if not root.is_dir():
        raise FilesystemError(f"Kein Verzeichnis: {path}")

    entries: list[dict[str, Any]] = []
    try:
        for child in sorted(root.iterdir()):
            try:
                if not _is_allowed(child):
                    entries.append({
                        "name": child.name,
                        "allowed": False,
                        "reason": "denylist",
                    })
                    continue
                st = child.stat(follow_symlinks=False)
                entries.append({
                    "name": child.name,
                    "type": _file_type(child, st),
                    "size": st.st_size,
                    "mode": stat.S_IMODE(st.st_mode),
                    "allowed": True,
                })
            except OSError as e:
                entries.append({"name": child.name, "error": str(e), "allowed": False})
    except PermissionError as e:
        raise FilesystemError(f"Keine Berechtigung: {e}")
    return {"path": str(root), "entries": entries}


def stat_path(path: str) -> dict[str, Any]:
    p = _resolve(path)
    return _stat_dict(p)


def read_text(path: str, limit: int | None = None) -> dict[str, Any]:
    p = _resolve(path)
    if not p.is_file():
        raise FilesystemError(f"Keine reguläre Datei: {path}")
    if limit is None:
        limit = MAX_TEXT_BYTES
    if not isinstance(limit, int) or limit < 0 or limit > MAX_TEXT_LIMIT_INPUT:
        raise FilesystemError("limit muss zwischen 0 und 20 MiB liegen")
    policy.assert_allowed_for_read(p)
    try:
        raw = p.read_bytes()[:limit]
    except PermissionError as e:
        raise FilesystemError(f"Keine Berechtigung: {e}")
    except OSError as e:
        raise FilesystemError(f"Lesefehler: {e}")

    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise FilesystemError("Datei ist keine reine UTF-8-Textdatei; verwende read_binary_metadata/read_binary_chunk.")

    text = secrets_filter.mask_secrets(text)
    return {
        "path": str(p),
        "size": len(raw),
        "truncated": p.stat().st_size > limit,
        "encoding": "utf-8",
        "content": text,
    }


def read_binary_metadata(path: str) -> dict[str, Any]:
    """Liest maximal 512 Bytes Header + MIME-Typ + einfache Medienmetadaten."""
    p = _resolve(path)
    if not p.is_file():
        raise FilesystemError(f"Keine reguläre Datei: {path}")
    policy.assert_allowed_for_read(p)
    try:
        with p.open("rb") as f:
            header = f.read(512)
    except PermissionError as e:
        raise FilesystemError(f"Keine Berechtigung: {e}")
    mime = mimetypes.guess_type(str(p))[0]
    if not mime:
        mime = _magic_from_buffer(header, mime=True)
    description = _magic_from_buffer(header, mime=False) or ""

    meta: dict[str, Any] = {
        "path": str(p),
        "size": p.stat().st_size,
        "mime_type": mime or "application/octet-stream",
        "description": description,
        "header_length": len(header),
    }

    # Einfache Medienmetadaten
    if mime and mime.startswith("image/"):
        if header[:2] == b"\xff\xd8" and len(header) >= 32:
            try:
                import mmap
                from io import BytesIO
                buf = BytesIO(header + p.open("rb").read(524288))
                data = buf.read()
                m = re.search(rb"\xff\xc0.{3}(.{2})(.{2})", data, re.DOTALL)
                if m:
                    meta["width"] = struct.unpack(">H", m.group(2))[0]
                    meta["height"] = struct.unpack(">H", m.group(1))[0]
            except Exception:
                pass
        elif header[:8] == b"\x89PNG\r\n\x1a\n" and len(header) >= 24:
            meta["width"] = struct.unpack(">I", header[16:20])[0]
            meta["height"] = struct.unpack(">I", header[20:24])[0]

    return meta


def read_binary_chunk(path: str, offset: int = 0, length: int = 4096) -> dict[str, Any]:
    """Liest ein festes Binärstück. Maximale Chunk-Größe 64 KiB."""
    p = _resolve(path)
    if not p.is_file():
        raise FilesystemError(f"Keine reguläre Datei: {path}")
    policy.assert_allowed_for_read(p)
    if not isinstance(offset, int) or offset < 0:
        raise FilesystemError("offset muss eine nicht-negative Ganzzahl sein")
    if not isinstance(length, int) or length < 1 or length > MAX_CHUNK_SIZE:
        raise FilesystemError(f"length muss zwischen 1 und {MAX_CHUNK_SIZE} liegen")
    try:
        total = p.stat().st_size
    except OSError as e:
        raise FilesystemError(f"Statistik fehlgeschlagen: {e}")
    if offset > total:
        return {"path": str(p), "offset": offset, "length": 0, "total_size": total, "base64": ""}
    try:
        with p.open("rb") as f:
            f.seek(offset)
            data = f.read(length)
    except PermissionError as e:
        raise FilesystemError(f"Keine Berechtigung: {e}")
    except OSError as e:
        raise FilesystemError(f"Lesefehler: {e}")
    return {
        "path": str(p),
        "offset": offset,
        "length": len(data),
        "total_size": total,
        "base64": data.hex(),
        "eof": (offset + len(data)) >= total,
    }


def archive_list(path: str, max_entries: int = MAX_ARCHIVE_ENTRIES) -> dict[str, Any]:
    """Listet Inhalte von .zip oder .tar.* ohne Extraktion."""
    p = _resolve(path)
    if not p.is_file():
        raise FilesystemError(f"Keine reguläre Datei: {path}")
    policy.assert_allowed_for_read(p)
    if not isinstance(max_entries, int) or max_entries < 1 or max_entries > MAX_ARCHIVE_ENTRIES:
        raise FilesystemError(f"max_entries muss zwischen 1 und {MAX_ARCHIVE_ENTRIES} liegen")
    name = p.name.lower()
    entries: list[dict[str, Any]] = []
    try:
        if name.endswith(".zip"):
            with zipfile.ZipFile(p, "r") as zf:
                for i, info in enumerate(zf.infolist()):
                    if i >= max_entries:
                        break
                    entries.append({
                        "name": info.filename,
                        "size": info.file_size,
                        "compressed": info.compress_size,
                        "is_dir": info.is_dir(),
                    })
            fmt = "zip"
        elif name.endswith(".tar") or name.endswith((".tar.gz", ".tar.bz2", ".tar.xz")):
            with tarfile.open(p, "r:*") as tf:
                for i, member in enumerate(tf.getmembers()):
                    if i >= max_entries:
                        break
                    entries.append({
                        "name": member.name,
                        "size": member.size,
                        "mode": stat.S_IMODE(member.mode),
                        "is_dir": member.isdir(),
                    })
            fmt = "tar"
        else:
            raise FilesystemError("Nur .zip und .tar.* unterstützt.")
    except (zipfile.BadZipFile, tarfile.TarError) as e:
        raise FilesystemError(f"Archivfehler: {e}")
    except PermissionError as e:
        raise FilesystemError(f"Keine Berechtigung: {e}")
    return {"path": str(p), "format": fmt, "count": len(entries), "entries": entries}


def sqlite_query(path: str, query: str, max_rows: int = MAX_SQLITE_ROWS) -> dict[str, Any]:
    """Read-only SQLite-Abfrage mit uri=mode=ro."""
    p = _resolve(path)
    if not p.is_file():
        raise FilesystemError(f"Keine reguläre Datei: {path}")
    policy.assert_allowed_for_read(p)
    policy.validate_sqlite_query(query)
    if not isinstance(max_rows, int) or max_rows < 1 or max_rows > MAX_SQLITE_ROWS:
        raise FilesystemError(f"max_rows muss zwischen 1 und {MAX_SQLITE_ROWS} liegen")
    try:
        # URI-Modus + immutable verhindern Schreibzugriff auf Dateiebene.
        uri = f"file:{p}?mode=ro&immutable=1"
        conn = sqlite3.connect(uri, uri=True, timeout=5.0)
        # Zusaetzliche Schreibschutz-Massnahmen
        conn.execute("PRAGMA query_only = ON")
        conn.execute("PRAGMA journal_mode = OFF")
        conn.execute("PRAGMA locking_mode = NORMAL")
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute(query)
        rows = cur.fetchall()
        columns = [d[0] for d in cur.description] if cur.description else []
        conn.close()
    except sqlite3.Error as e:
        raise FilesystemError(f"SQLite-Fehler: {e}")
    except PermissionError as e:
        raise FilesystemError(f"Keine Berechtigung: {e}")
    return {
        "path": str(p),
        "query": query,
        "columns": columns,
        "row_count": len(rows),
        "truncated": len(rows) > max_rows,
        "rows": [dict(r) for r in rows[:max_rows]],
    }


def extract_pdf_text(path: str, max_pages: int = 10) -> dict[str, Any]:
    """Extrahiert Text aus PDF-Seiten ohne externe Shell."""
    p = _resolve(path)
    if not p.is_file():
        raise FilesystemError(f"Keine reguläre Datei: {path}")
    policy.assert_allowed_for_read(p)
    policy.validate_pdf_path(p)
    if not isinstance(max_pages, int) or max_pages < 1 or max_pages > MAX_PDF_PAGES:
        raise FilesystemError(f"max_pages muss zwischen 1 und {MAX_PDF_PAGES} liegen")
    try:
        import PyPDF2
    except ImportError:
        raise FilesystemError("PyPDF2 nicht verfuegbar.")
    try:
        reader = PyPDF2.PdfReader(str(p))
        total = len(reader.pages)
        pages: list[dict[str, Any]] = []
        for i in range(min(max_pages, total)):
            try:
                text = reader.pages[i].extract_text() or ""
            except Exception as e:
                text = f"[Extraktionsfehler: {e}]"
            pages.append({"page": i + 1, "text": text[:5000]})
        return {"path": str(p), "total_pages": total, "extracted_pages": len(pages), "pages": pages}
    except PermissionError as e:
        raise FilesystemError(f"Keine Berechtigung: {e}")
    except Exception as e:
        raise FilesystemError(f"PDF-Fehler: {type(e).__name__}: {e}")


def file_type(path: str) -> dict[str, Any]:
    return stat_path(path)


def find_files(
    path: str,
    name: str | None = None,
    size: str | None = None,
    mtime_days: int | None = None,
    maxdepth: int | None = None,
) -> dict[str, Any]:
    root = _resolve(path)
    if not root.exists():
        raise FilesystemError(f"Pfad nicht gefunden: {path}")
    policy.validate_find_args(name, size, mtime_days, maxdepth)
    maxdepth = min(maxdepth if maxdepth is not None else 3, 5)
    results: list[str] = []
    count = 0
    name_re = None
    if name:
        if "*" in name:
            name_re = re.compile(name.replace("*", ".*"), re.IGNORECASE)
        elif "?" in name or "[" in name:
            raise FilesystemError("Nur *-Wildcards unterstützt")
    now = os.time() if mtime_days is not None else 0

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        current_depth = len(Path(dirpath).relative_to(root).parts)
        if current_depth >= maxdepth:
            del dirnames[:]
            continue
        for name_ in list(dirnames) + list(filenames):
            candidate = Path(dirpath) / name_
            if not _is_allowed(candidate):
                continue
            if name_re:
                if not name_re.fullmatch(name_):
                    continue
            elif name:
                if name.lower() not in name_.lower():
                    continue
            try:
                st = candidate.stat(follow_symlinks=False)
            except OSError:
                continue
            if size and not _matches_size(st.st_size, size):
                continue
            if mtime_days is not None:
                if (now - st.st_mtime) / 86400 > mtime_days:
                    continue
            results.append(str(candidate))
            count += 1
            if count >= MAX_FIND_RESULTS:
                break
        if count >= MAX_FIND_RESULTS:
            break
    return {"root": str(root), "count": len(results), "matches": results}


def _matches_size(size: int, spec: str) -> bool:
    """Einfache Groessenpruefung: z.B. +100M, -1G, 50k"""
    m = re.match(r'^([+-]?)(\d+)([kmgt]?)\$', spec, re.IGNORECASE)
    if not m:
        return True
    sign = m.group(1)
    num = m.group(2)
    unit = m.group(3)
    multiplier = {"": 1, "k": 1024, "m": 1024**2, "g": 1024**3, "t": 1024**4}
    target = int(num) * multiplier.get(unit.lower(), 1)
    if sign == "+":
        return size >= target
    if sign == "-":
        return size <= target
    return size == target


def grep_text(path: str, pattern: str, max_matches: int | None = None) -> dict[str, Any]:
    root = _resolve(path)
    if not root.exists():
        raise FilesystemError(f"Pfad nicht gefunden: {path}")
    policy.validate_grep_args(pattern, root, max_matches)
    max_matches = min(max_matches if max_matches is not None else MAX_GREP_MATCHES, MAX_GREP_MATCHES)
    try:
        compiled = re.compile(pattern, re.IGNORECASE)
    except re.error as e:
        raise FilesystemError(f"Ungueltiges Regex-Muster: {e}")
    matches: list[dict[str, Any]] = []
    count = 0

    def _grep_file(candidate: Path) -> None:
        nonlocal count
        if not _is_allowed(candidate):
            return
        try:
            st = candidate.stat(follow_symlinks=False)
        except OSError:
            return
        if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_GREP_FILE_BYTES:
            return
        try:
            text = candidate.read_text(encoding="utf-8", errors="replace")
        except (OSError, UnicodeError):
            return
        for line_no, line in enumerate(text.splitlines(), start=1):
            if compiled.search(line):
                matches.append({
                    "path": str(candidate),
                    "line": line_no,
                    "match": secrets_filter.mask_secrets(line[:500]),
                })
                count += 1
                if count >= max_matches:
                    return

    if root.is_file():
        _grep_file(root)
        return {"root": str(root), "count": count, "matches": matches}

    for dirpath, _dirnames, filenames in os.walk(root, followlinks=False):
        for filename in filenames:
            _grep_file(Path(dirpath) / filename)
            if count >= max_matches:
                return {"root": str(root), "count": count, "matches": matches}
    return {"root": str(root), "count": count, "matches": matches}


def du(path: str, maxdepth: int = 2) -> dict[str, Any]:
    root = _resolve(path)
    if not root.exists():
        raise FilesystemError(f"Pfad nicht gefunden: {path}")
    maxdepth = max(0, min(maxdepth, 5))
    results: list[dict[str, Any]] = []
    total = 0

    def _du(p: Path, depth: int) -> int:
        nonlocal total
        try:
            st = p.stat(follow_symlinks=False)
        except OSError:
            return 0
        if stat.S_ISREG(st.st_mode):
            total += st.st_size
            return st.st_size
        if stat.S_ISDIR(st.st_mode):
            size = 0
            try:
                for child in p.iterdir():
                    if not _is_allowed(child):
                        continue
                    size += _du(child, depth + 1)
            except PermissionError:
                pass
            total += size
            if depth <= maxdepth:
                results.append({"path": str(p), "size": size})
            return size
        return 0

    _du(root, 0)
    return {"root": str(root), "total": total, "entries": results}


def sha256(path: str) -> dict[str, Any]:
    p = _resolve(path)
    if not p.is_file():
        raise FilesystemError(f"Keine reguläre Datei: {path}")
    policy.assert_allowed_for_read(p)
    h = hashlib.sha256()
    try:
        with p.open("rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                h.update(chunk)
    except PermissionError as e:
        raise FilesystemError(f"Keine Berechtigung: {e}")
    return {"path": str(p), "sha256": h.hexdigest()}


def mount_inventory() -> dict[str, Any]:
    mounts: list[dict[str, Any]] = []
    try:
        with Path("/proc/self/mountinfo").open("r") as f:
            for line in f:
                parts = line.split()
                if len(parts) < 5:
                    continue
                mount_id, parent_id, major_minor, root, mountpoint = parts[:5]
                options = parts[5] if len(parts) > 5 else ""
                if mountpoint.startswith("/host/umbrel"):
                    mounts.append({
                        "mountpoint": mountpoint,
                        "options": options,
                    })
    except Exception:
        pass
    return {"mounts": mounts}
