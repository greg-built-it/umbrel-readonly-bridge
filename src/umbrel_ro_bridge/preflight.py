"""Bounded, read-only filesystem and archive preflight operations."""

from __future__ import annotations

import hashlib
import heapq
import os
import posixpath
import re
import stat
import tarfile
import time
import zipfile
from pathlib import Path
from typing import Any

from . import policy

MAX_TREE_FILES = 100_000
MAX_TREE_TOP_N = 100
MAX_TREE_TIMEOUT_SECONDS = 120
MAX_ARCHIVE_ENTRIES = 10_000
MAX_ARCHIVE_TOP_N = 100
MAX_ARCHIVE_UNCOMPRESSED_BYTES = 4 * 1024 * 1024 * 1024
MAX_ARCHIVE_COMPRESSED_BYTES = 1 * 1024 * 1024 * 1024
MAX_ARCHIVE_TIMEOUT_SECONDS = 120
MAX_ARCHIVE_ENTRY_PATH_LENGTH = 4096
MAX_ARCHIVE_WARN_LIST_LENGTH = 1000


class PreflightError(Exception):
    """Safe, user-facing preflight failure."""


def _resolve(path: str, require_exists: bool = True) -> Path:
    try:
        resolved = policy.resolve_host_path(path, require_exists=require_exists)
        policy.assert_allowed_for_read(resolved)
        return resolved
    except policy.PolicyError as error:
        raise PreflightError(str(error)) from error


def _validate_int(name: str, value: Any, minimum: int, maximum: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= maximum:
        raise PreflightError(f"{name} muss eine Ganzzahl zwischen {minimum} und {maximum} sein")
    return value


def _decode_mountinfo_path(value: str) -> str:
    return re.sub(r"\\([0-7]{3})", lambda match: chr(int(match.group(1), 8)), value)


def _read_mountinfo() -> list[dict[str, str]]:
    mounts: list[dict[str, str]] = []
    try:
        with Path("/proc/self/mountinfo").open("r", encoding="utf-8") as handle:
            for line in handle:
                fields = line.rstrip("\n").split()
                try:
                    separator = fields.index("-")
                except ValueError:
                    continue
                if separator < 6 or len(fields) <= separator + 2:
                    continue
                mounts.append({
                    "mountpoint": _decode_mountinfo_path(fields[4]),
                    "major_minor": fields[2],
                    "filesystem_type": fields[separator + 1],
                })
    except OSError:
        pass
    return mounts


def _mount_for_path(path: Path) -> dict[str, str] | None:
    best = None
    best_depth = -1
    for mount in _read_mountinfo():
        mountpoint = Path(mount["mountpoint"])
        try:
            path.relative_to(mountpoint)
        except ValueError:
            continue
        if len(mountpoint.parts) > best_depth:
            best = mount
            best_depth = len(mountpoint.parts)
    return best


def filesystem_capacity(path: str) -> dict[str, Any]:
    resolved = _resolve(path)
    try:
        values = os.statvfs(resolved)
    except OSError as error:
        raise PreflightError(f"Dateisystemstatistik fehlgeschlagen: {error}") from error
    fragment_size = values.f_frsize or values.f_bsize
    mount = _mount_for_path(resolved)
    return {
        "path": str(resolved),
        "filesystem_type": mount.get("filesystem_type") if mount else None,
        "device": mount.get("major_minor") if mount else None,
        "block_size": values.f_bsize,
        "fragment_size": fragment_size,
        "blocks_total": values.f_blocks,
        "blocks_free": values.f_bfree,
        "blocks_avail": values.f_bavail,
        "bytes_total": values.f_blocks * fragment_size,
        "bytes_used": (values.f_blocks - values.f_bfree) * fragment_size,
        "bytes_free": values.f_bfree * fragment_size,
        "bytes_avail": values.f_bavail * fragment_size,
        "inodes_total": values.f_files,
        "inodes_free": values.f_ffree,
        "inodes_avail": values.f_favail,
    }


def tree_inventory(path: str, max_files: int = MAX_TREE_FILES, top_n: int = 20,
                   timeout_seconds: int = MAX_TREE_TIMEOUT_SECONDS) -> dict[str, Any]:
    root = _resolve(path)
    if not root.is_dir():
        raise PreflightError(f"Kein Verzeichnis: {path}")
    max_files = _validate_int("max_files", max_files, 1, MAX_TREE_FILES)
    top_n = _validate_int("top_n", top_n, 1, MAX_TREE_TOP_N)
    timeout_seconds = _validate_int("timeout_seconds", timeout_seconds, 1, MAX_TREE_TIMEOUT_SECONDS)

    started = time.monotonic()
    result: dict[str, Any] = {
        "root": str(root), "logical_size": 0, "allocated_size": 0,
        "file_count": 0, "directory_count": 1, "symlink_count": 0,
        "special_count": 0, "visited_count": 0, "sparse_files": [],
        "largest_files": [], "truncated": False, "truncation_reasons": [],
    }
    reasons: set[str] = set()
    stack = [root]
    while stack:
        if time.monotonic() - started >= timeout_seconds:
            reasons.add("timeout")
            break
        directory = stack.pop()
        try:
            children = sorted(directory.iterdir(), key=lambda item: item.name, reverse=True)
        except OSError:
            reasons.add("unreadable")
            continue
        for child in children:
            if time.monotonic() - started >= timeout_seconds:
                reasons.add("timeout")
                stack.clear()
                break
            if result["visited_count"] >= max_files:
                reasons.add("max_files")
                stack.clear()
                break
            denied, _ = policy.is_denied_path(child)
            if denied:
                reasons.add("denied_entries")
                continue
            try:
                entry_stat = child.stat(follow_symlinks=False)
            except OSError:
                reasons.add("stat_errors")
                continue
            result["visited_count"] += 1
            relative = child.relative_to(root).as_posix()
            mode = entry_stat.st_mode
            if stat.S_ISDIR(mode):
                result["directory_count"] += 1
                stack.append(child)
            elif stat.S_ISLNK(mode):
                result["symlink_count"] += 1
            elif stat.S_ISREG(mode):
                result["file_count"] += 1
                allocated = getattr(entry_stat, "st_blocks", 0) * 512
                result["logical_size"] += entry_stat.st_size
                result["allocated_size"] += allocated
                item = {"path": relative, "logical_size": entry_stat.st_size, "allocated_size": allocated}
                result["largest_files"].append(item)
                result["largest_files"].sort(key=lambda value: (-value["logical_size"], value["path"]))
                del result["largest_files"][top_n:]
                if entry_stat.st_size > allocated:
                    result["sparse_files"].append(item.copy())
                    result["sparse_files"].sort(key=lambda value: (-value["logical_size"], value["path"]))
                    del result["sparse_files"][top_n:]
            else:
                result["special_count"] += 1
    result["truncated"] = bool(reasons)
    result["truncation_reasons"] = sorted(reasons)
    return result


def _path_flags(name: str) -> tuple[bool, bool]:
    portable = name.replace("\\", "/")
    absolute = portable.startswith("/") or bool(re.match(r"^[A-Za-z]:/", portable))
    return absolute, ".." in portable.split("/")


def _link_outside(member_name: str, link_name: str, hardlink: bool) -> bool:
    link = link_name.replace("\\", "/")
    if link.startswith("/") or re.match(r"^[A-Za-z]:/", link):
        return True
    base = "" if hardlink else posixpath.dirname(member_name.replace("\\", "/"))
    normalized = posixpath.normpath(posixpath.join(base, link))
    return normalized == ".." or normalized.startswith("../")


def _tar_type(member: tarfile.TarInfo) -> str:
    if member.isreg(): return "regular"
    if member.isdir(): return "directory"
    if member.issym(): return "symlink"
    if member.islnk(): return "hardlink"
    if member.isblk(): return "block_device"
    if member.ischr(): return "char_device"
    if member.isfifo(): return "fifo"
    if member.type == b"s": return "socket"
    return "other"


def _sha256(path: Path, max_bytes: int = MAX_ARCHIVE_COMPRESSED_BYTES) -> str:
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            total += len(chunk)
            if total > max_bytes:
                raise PreflightError("Archiv überschreitet maximale komprimierte Größe")
            digest.update(chunk)
    return digest.hexdigest()


def _archive_result(path: Path, archive_format: str) -> dict[str, Any]:
    kinds = ("regular", "directory", "symlink", "hardlink", "block_device",
             "char_device", "fifo", "socket", "other")
    return {
        "path": str(path), "format": archive_format, "size": path.stat().st_size,
        "sha256": _sha256(path), "valid": None, "gzip_valid": None,
        "tar_valid": None, "entry_count": 0, "uncompressed_total": 0,
        "compressed_total": None, "type_counts": {kind: 0 for kind in kinds},
        "absolute_paths": [], "dotdot_paths": [], "outside_symlinks": [],
        "outside_hardlinks": [], "setuid_setgid": [], "largest_members": [],
        "truncated": False, "truncation_reasons": [], "error": None,
    }


def _bounded_archive_text(result: dict[str, Any], value: str) -> str:
    if len(value) <= MAX_ARCHIVE_ENTRY_PATH_LENGTH:
        return value
    result["truncated"] = True
    if "entry_path_too_long" not in result["truncation_reasons"]:
        result["truncation_reasons"].append("entry_path_too_long")
    return value[:MAX_ARCHIVE_ENTRY_PATH_LENGTH - 3] + "..."


def _append_archive_warning(result: dict[str, Any], collection: list[Any], value: Any) -> None:
    if len(collection) < MAX_ARCHIVE_WARN_LIST_LENGTH:
        collection.append(value)
        return
    result["truncated"] = True
    if "warning_list_limit" not in result["truncation_reasons"]:
        result["truncation_reasons"].append("warning_list_limit")


def _record_name(result: dict[str, Any], name: str) -> None:
    absolute, dotdot = _path_flags(name)
    display_name = _bounded_archive_text(result, name)
    if absolute:
        _append_archive_warning(result, result["absolute_paths"], display_name)
    if dotdot:
        _append_archive_warning(result, result["dotdot_paths"], display_name)


def _record_largest(result: dict[str, Any], name: str, size: int, top_n: int) -> None:
    name = _bounded_archive_text(result, name)
    result["largest_members"].append({"name": name, "size": size})
    result["largest_members"].sort(key=lambda item: (-item["size"], item["name"]))
    del result["largest_members"][top_n:]


def _record_setuid(result: dict[str, Any], name: str) -> None:
    name = _bounded_archive_text(result, name)
    _append_archive_warning(result, result["setuid_setgid"], name)


def _record_outside_link(result: dict[str, Any], kind: str, name: str, target: str) -> None:
    collection = result["outside_symlinks"] if kind == "symlink" else result["outside_hardlinks"]
    value = {
        "name": _bounded_archive_text(result, name),
        "target": _bounded_archive_text(result, target),
    }
    _append_archive_warning(result, collection, value)


def archive_inspect(path: str, max_entries: int = MAX_ARCHIVE_ENTRIES, top_n: int = 20,
                    validate: bool = True,
                    timeout_seconds: int = MAX_ARCHIVE_TIMEOUT_SECONDS) -> dict[str, Any]:
    archive_path = _resolve(path)
    if not archive_path.is_file():
        raise PreflightError(f"Keine reguläre Datei: {path}")
    max_entries = _validate_int("max_entries", max_entries, 1, MAX_ARCHIVE_ENTRIES)
    top_n = _validate_int("top_n", top_n, 1, MAX_ARCHIVE_TOP_N)
    timeout_seconds = _validate_int(
        "timeout_seconds", timeout_seconds, 1, MAX_ARCHIVE_TIMEOUT_SECONDS
    )
    if not isinstance(validate, bool):
        raise PreflightError("validate muss ein Boolean sein")
    started = time.monotonic()
    lower = archive_path.name.lower()
    is_zip = lower.endswith(".zip")
    is_gzip_tar = lower.endswith((".tar.gz", ".tgz"))
    is_tar = lower.endswith((".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz"))
    if not is_zip and not is_tar:
        raise PreflightError("Nur ZIP- und TAR-Archive werden unterstützt")
    result = _archive_result(archive_path, "zip" if is_zip else "tar")

    def timed_out() -> bool:
        if time.monotonic() - started < timeout_seconds:
            return False
        result["truncated"] = True
        if "timeout" not in result["truncation_reasons"]:
            result["truncation_reasons"].append("timeout")
        return True

    try:
        if is_zip:
            if archive_path.stat().st_size > MAX_ARCHIVE_COMPRESSED_BYTES:
                raise PreflightError("ZIP-Archiv überschreitet maximale komprimierte Größe")
            compressed_total = 0
            with zipfile.ZipFile(archive_path, "r") as archive:
                infolist = archive.infolist()
                if len(infolist) > max_entries:
                    result["truncated"] = True
                    result["truncation_reasons"].append("max_entries")
                for index, member in enumerate(infolist):
                    if timed_out():
                        break
                    if index >= max_entries:
                        break
                    result["entry_count"] += 1
                    result["uncompressed_total"] += member.file_size
                    compressed_total += member.compress_size
                    mode = (member.external_attr >> 16) & 0xFFFF
                    is_symlink = stat.S_IFMT(mode) == stat.S_IFLNK
                    if member.is_dir():
                        member_kind = "directory"
                    elif is_symlink:
                        member_kind = "symlink"
                    else:
                        member_kind = "regular"
                    result["type_counts"][member_kind] += 1
                    _record_name(result, member.filename)
                    _record_largest(result, member.filename, member.file_size, top_n)
                    if mode & (stat.S_ISUID | stat.S_ISGID):
                        _record_setuid(result, member.filename)
                    if is_symlink:
                        with archive.open(member, "r") as stream:
                            target_bytes = stream.read(MAX_ARCHIVE_ENTRY_PATH_LENGTH + 1)
                        target = target_bytes.decode("utf-8", "replace")
                        if len(target_bytes) > MAX_ARCHIVE_ENTRY_PATH_LENGTH:
                            target = target[:MAX_ARCHIVE_ENTRY_PATH_LENGTH] + "..."
                            result["truncated"] = True
                            if "entry_path_too_long" not in result["truncation_reasons"]:
                                result["truncation_reasons"].append("entry_path_too_long")
                        if _link_outside(member.filename, target, False):
                            _record_outside_link(
                                result, "symlink", member.filename, target
                            )
                    if result["uncompressed_total"] > MAX_ARCHIVE_UNCOMPRESSED_BYTES:
                        result["truncated"] = True
                        result["truncation_reasons"].append("max_uncompressed_total")
                        break
                    if validate and not member.is_dir() and not is_symlink:
                        with archive.open(member, "r") as stream:
                            while True:
                                if timed_out():
                                    break
                                if not stream.read(1024 * 1024):
                                    break
                        if result["truncated"]:
                            break
            result["compressed_total"] = compressed_total
            if validate and not result["truncated"]: result["valid"] = True
        else:
            if archive_path.stat().st_size > MAX_ARCHIVE_COMPRESSED_BYTES:
                raise PreflightError("TAR-Archiv überschreitet maximale komprimierte Größe")
            with tarfile.open(archive_path, "r:*") as archive:
                for index, member in enumerate(archive):
                    if timed_out():
                        break
                    if index >= max_entries:
                        result["truncated"] = True
                        result["truncation_reasons"].append("max_entries")
                        break
                    result["entry_count"] += 1
                    result["uncompressed_total"] += member.size
                    kind = _tar_type(member)
                    result["type_counts"][kind] += 1
                    _record_name(result, member.name)
                    _record_largest(result, member.name, member.size, top_n)
                    if member.mode & (stat.S_ISUID | stat.S_ISGID): _record_setuid(result, member.name)
                    if member.issym() and _link_outside(member.name, member.linkname, False):
                        _record_outside_link(result, "symlink", member.name, member.linkname)
                    if member.islnk() and _link_outside(member.name, member.linkname, True):
                        _record_outside_link(result, "hardlink", member.name, member.linkname)
                    if result["uncompressed_total"] > MAX_ARCHIVE_UNCOMPRESSED_BYTES:
                        result["truncated"] = True
                        result["truncation_reasons"].append("max_uncompressed_total")
                        break
                    if validate and member.isreg() and member.size:
                        archive.fileobj.seek(member.offset_data)
                        remaining = member.size
                        while remaining:
                            if timed_out():
                                break
                            chunk = archive.fileobj.read(min(1024 * 1024, remaining))
                            if not chunk: raise tarfile.ReadError(f"Verkürztes Mitglied: {member.name}")
                            remaining -= len(chunk)
                        if result["truncated"]:
                            break
                if is_gzip_tar and validate and not result["truncated"]:
                    while True:
                        if timed_out():
                            break
                        chunk = archive.fileobj.read(1024 * 1024)
                        if not chunk:
                            break
                        if archive.fileobj.tell() > MAX_ARCHIVE_UNCOMPRESSED_BYTES:
                            result["truncated"] = True
                            result["truncation_reasons"].append("max_uncompressed_total")
                            break
            if validate and not result["truncated"]:
                result["tar_valid"] = True
                if is_gzip_tar:
                    result["gzip_valid"] = True
                result["valid"] = True
    except (OSError, EOFError, zipfile.BadZipFile, tarfile.TarError) as error:
        if is_tar: result["tar_valid"] = False
        result["valid"] = False
        result["error"] = f"Archivfehler: {error}"
    return result


def _requested_absolute(path: str) -> Path:
    policy.resolve_host_path(path, require_exists=False)
    requested = Path(path)
    if not requested.is_absolute(): requested = Path("/host/umbrel") / requested
    return Path(os.path.abspath(requested))


def resolve_path_info(path: str) -> dict[str, Any]:
    canonical = _resolve(path, require_exists=False)
    requested = _requested_absolute(path)
    try:
        policy.assert_allowed_for_read(requested)
    except policy.PolicyError as error:
        raise PreflightError(str(error)) from error
    exists = requested.exists() or requested.is_symlink()
    is_symlink = requested.is_symlink()
    symlink_target = None
    kind = None
    mount = None
    stat_value = None
    is_mountpoint = False
    if exists:
        canonical = _resolve(path, require_exists=True)
        try:
            lstat_value = requested.lstat()
            stat_value = canonical.stat()
        except OSError as error:
            raise PreflightError(f"Pfadstatistik fehlgeschlagen: {error}") from error
        if stat.S_ISDIR(lstat_value.st_mode): kind = "directory"
        elif stat.S_ISLNK(lstat_value.st_mode): kind = "symlink"
        elif stat.S_ISREG(lstat_value.st_mode): kind = "file"
        elif stat.S_ISBLK(lstat_value.st_mode) or stat.S_ISCHR(lstat_value.st_mode): kind = "device"
        else: kind = "other"
        if is_symlink:
            target_text = os.readlink(requested)
            _resolve(str(requested.parent / target_text), require_exists=True)
            symlink_target = target_text
        mount = _mount_for_path(canonical)
        is_mountpoint = bool(mount and Path(mount["mountpoint"]) == canonical)
        if not is_mountpoint and canonical.parent != canonical:
            try: is_mountpoint = canonical.stat().st_dev != canonical.parent.stat().st_dev
            except OSError: pass
    return {
        "requested": str(requested), "canonical": str(canonical), "exists": exists,
        "type": kind, "is_symlink": is_symlink, "symlink_target": symlink_target,
        "is_mountpoint": is_mountpoint,
        "filesystem_type": mount.get("filesystem_type") if mount else None,
        "device": mount.get("major_minor") if mount else None,
        "st_dev": stat_value.st_dev if stat_value else None,
        "st_ino": stat_value.st_ino if stat_value else None, "allowed": True,
    }


def check_path_overlap(path_a: str, path_b: str) -> dict[str, Any]:
    a, b = _resolve(path_a), _resolve(path_b)
    try: a_stat, b_stat = a.stat(), b.stat()
    except OSError as error: raise PreflightError(f"Pfadstatistik fehlgeschlagen: {error}") from error
    if a == b: overlap, reason = True, "same_canonical_path"
    elif a_stat.st_dev == b_stat.st_dev and a_stat.st_ino == b_stat.st_ino:
        overlap, reason = True, "same_inode"
    else:
        try: b.relative_to(a); overlap, reason = True, "path_a_contains_path_b"
        except ValueError:
            try: a.relative_to(b); overlap, reason = True, "path_b_contains_path_a"
            except ValueError: overlap, reason = False, "disjoint_paths"
    mount_a, mount_b = _mount_for_path(a), _mount_for_path(b)
    common_mount = None
    if mount_a and mount_b and mount_a.get("mountpoint") == mount_b.get("mountpoint"):
        common_mount = mount_a.get("mountpoint")
    return {
        "path_a": str(a), "path_b": str(b), "overlap": overlap, "reason": reason,
        "common_filesystem": a_stat.st_dev == b_stat.st_dev,
        "device_a": mount_a.get("major_minor") if mount_a else str(a_stat.st_dev),
        "device_b": mount_b.get("major_minor") if mount_b else str(b_stat.st_dev),
        "common_mount": common_mount,
    }
