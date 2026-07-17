import io
import json
import stat
import tarfile
import zipfile
from pathlib import Path
from unittest.mock import patch

import pytest

from umbrel_ro_bridge import preflight, server


def _allow_tmp(monkeypatch, path: Path) -> None:
    monkeypatch.setattr(preflight, "_resolve", lambda value, require_exists=True: Path(value))


def test_tree_inventory_counts_sparse_and_does_not_follow_symlink(tmp_path, monkeypatch):
    _allow_tmp(monkeypatch, tmp_path)
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "regular").write_bytes(b"abc")
    sparse = tmp_path / "sparse"
    with sparse.open("wb") as handle:
        handle.seek(1024 * 1024)
        handle.write(b"x")
    (tmp_path / "link").symlink_to(tmp_path / "sub")

    result = preflight.tree_inventory(str(tmp_path), max_files=20, top_n=10)

    assert result["file_count"] == 2
    assert result["directory_count"] == 2
    assert result["symlink_count"] == 1
    assert result["logical_size"] >= 1024 * 1024 + 1
    assert any(item["path"] == "sparse" for item in result["sparse_files"])


def test_tree_inventory_reports_max_files_truncation(tmp_path, monkeypatch):
    _allow_tmp(monkeypatch, tmp_path)
    for index in range(3):
        (tmp_path / f"f{index}").write_text("x")

    result = preflight.tree_inventory(str(tmp_path), max_files=2)

    assert result["truncated"] is True
    assert "max_files" in result["truncation_reasons"]
    assert result["visited_count"] == 2


def test_archive_inspect_flags_tar_traversal_links_and_setuid(tmp_path, monkeypatch):
    archive_path = tmp_path / "danger.tar"
    with tarfile.open(archive_path, "w") as archive:
        traversal = tarfile.TarInfo("../escape")
        traversal.size = 1
        archive.addfile(traversal, io.BytesIO(b"x"))
        symlink = tarfile.TarInfo("safe/link")
        symlink.type = tarfile.SYMTYPE
        symlink.linkname = "../../outside"
        archive.addfile(symlink)
        hardlink = tarfile.TarInfo("hard")
        hardlink.type = tarfile.LNKTYPE
        hardlink.linkname = "../outside"
        archive.addfile(hardlink)
        privileged = tarfile.TarInfo("setuid")
        privileged.mode = 0o4755
        privileged.size = 0
        archive.addfile(privileged, io.BytesIO())
    _allow_tmp(monkeypatch, archive_path)

    result = preflight.archive_inspect(str(archive_path))

    assert "../escape" in result["dotdot_paths"]
    assert result["outside_symlinks"] == [
        {"name": "safe/link", "target": "../../outside"}
    ]
    assert result["outside_hardlinks"] == [
        {"name": "hard", "target": "../outside"}
    ]
    assert "setuid" in result["setuid_setgid"]
    assert result["valid"] is True


def test_archive_inspect_detects_zip_symlink_outside(tmp_path, monkeypatch):
    archive_path = tmp_path / "danger.zip"
    member = zipfile.ZipInfo("safe/link")
    member.create_system = 3
    member.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr(member, "../../outside")
    _allow_tmp(monkeypatch, archive_path)

    result = preflight.archive_inspect(str(archive_path))

    assert result["type_counts"]["symlink"] == 1
    assert result["type_counts"]["regular"] == 0
    assert result["outside_symlinks"] == [
        {"name": "safe/link", "target": "../../outside"}
    ]


def test_archive_inspect_never_uses_extraction(tmp_path, monkeypatch):
    archive_path = tmp_path / "safe.tar"
    with tarfile.open(archive_path, "w") as archive:
        member = tarfile.TarInfo("file")
        member.size = 1
        archive.addfile(member, io.BytesIO(b"x"))
    _allow_tmp(monkeypatch, archive_path)

    with patch.object(tarfile.TarFile, "extract", side_effect=AssertionError), patch.object(
        tarfile.TarFile, "extractall", side_effect=AssertionError
    ), patch.object(zipfile.ZipFile, "extract", side_effect=AssertionError), patch.object(
        zipfile.ZipFile, "extractall", side_effect=AssertionError
    ):
        assert preflight.archive_inspect(str(archive_path))["valid"] is True


def test_archive_rejects_oversized_compressed_input(tmp_path, monkeypatch):
    archive_path = tmp_path / "oversized.zip"
    archive_path.write_bytes(b"PK")
    _allow_tmp(monkeypatch, archive_path)
    monkeypatch.setattr(preflight, "MAX_ARCHIVE_COMPRESSED_BYTES", 1)

    with pytest.raises(preflight.PreflightError, match="komprimierte Größe"):
        preflight.archive_inspect(str(archive_path))


def test_archive_warning_lists_are_bounded(tmp_path, monkeypatch):
    archive_path = tmp_path / "warnings.tar"
    with tarfile.open(archive_path, "w") as archive:
        for name in ("../one", "../two"):
            member = tarfile.TarInfo(name)
            archive.addfile(member)
    _allow_tmp(monkeypatch, archive_path)
    monkeypatch.setattr(preflight, "MAX_ARCHIVE_WARN_LIST_LENGTH", 1)

    result = preflight.archive_inspect(str(archive_path), validate=False)

    assert len(result["dotdot_paths"]) == 1
    assert result["truncated"] is True
    assert "warning_list_limit" in result["truncation_reasons"]


def test_serializer_preserves_sha256_and_structured_env_keys():
    digest = "a" * 64
    payload = {"sha256": digest, "env_keys": ["TOKEN", "OPENAI_API_KEY", "PATH"]}

    masked = json.loads(server._serialize_tool_result(payload))
    trusted = json.loads(server._serialize_tool_result(payload, trusted_structured=True))

    assert masked["sha256"] == digest
    assert trusted == payload


def test_tool_contract_has_25_unique_read_only_tools():
    names = [tool.name for tool in server.TOOLS]

    assert len(names) == 25
    assert len(set(names)) == 25
    assert {
        "filesystem_capacity",
        "tree_inventory",
        "archive_inspect",
        "resolve_path_info",
        "check_path_overlap",
        "openclaw_docker_info",
        "openclaw_local_images",
        "openclaw_image_config",
        "openclaw_container_inspect",
    }.issubset(names)
    assert not any(word in name for name in names for word in ("write", "exec", "delete", "start", "stop"))
