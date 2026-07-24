"""M3-B1 + M3-SEC1: safe source-archive extraction. CI-safe (pure filesystem).

Covers format detection, happy-path zip/tar extraction, and fail-closed rejection
of the TM-7 vectors: zip-slip, absolute paths, entry-count cap, extracted-size
cap, non-regular members, and (M3-SEC1) compression-ratio bombs — both the
pre-store declared-size check and the authoritative real-streamed-ratio check —
plus the no-exec guarantee on extracted files. The release-blocking pins for the
same vectors live in test_safety_negatives.py.
"""

import io
import tarfile
import zipfile
from pathlib import Path

import pytest

import app.services.source_archive as archive_mod
from app.services.source_archive import (
    ArchiveError,
    detect_format,
    extract_archive,
    validate_archive,
)


def _zip(entries: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return buf.getvalue()


def _tar(entries: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, data in entries.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


# ── format detection ─────────────────────────────────────────────────────────
def test_detect_zip() -> None:
    assert detect_format(_zip({"a.py": b"x = 1\n"})) == "zip"


def test_detect_tar() -> None:
    assert detect_format(_tar({"a.py": b"x = 1\n"})) == "tar"


def test_detect_unrecognized_raises() -> None:
    with pytest.raises(ArchiveError):
        detect_format(b"not an archive")


# ── happy path ───────────────────────────────────────────────────────────────
def test_extract_zip_writes_files(tmp_path: Path) -> None:
    data = _zip({"pkg/a.py": b"import os\n", "pkg/b.py": b"y = 2\n"})
    summary = extract_archive(data, tmp_path / "out")
    assert summary.archive_format == "zip"
    assert summary.entries == 2
    assert (tmp_path / "out" / "pkg" / "a.py").read_bytes() == b"import os\n"
    assert (tmp_path / "out" / "pkg" / "b.py").read_bytes() == b"y = 2\n"


def test_extract_tar_writes_files(tmp_path: Path) -> None:
    data = _tar({"src/main.py": b"eval('1')\n"})
    summary = extract_archive(data, tmp_path / "out")
    assert summary.archive_format == "tar"
    assert summary.entries == 1
    assert (tmp_path / "out" / "src" / "main.py").read_bytes() == b"eval('1')\n"


# ── fail-closed: zip-slip / absolute paths (TM-7 baseline) ───────────────────
def test_zip_slip_traversal_rejected(tmp_path: Path) -> None:
    data = _zip({"../escape.py": b"pwned\n"})
    with pytest.raises(ArchiveError):
        extract_archive(data, tmp_path / "out")
    assert not (tmp_path / "escape.py").exists()


def test_absolute_path_entry_rejected(tmp_path: Path) -> None:
    # zipfile.writestr sanitizes a leading "/", so craft the entry name directly.
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        info = zipfile.ZipInfo(filename="/etc/pwned.py")
        zf.writestr(info, b"x\n")
    with pytest.raises(ArchiveError):
        extract_archive(buf.getvalue(), tmp_path / "out")


def test_tar_traversal_rejected(tmp_path: Path) -> None:
    data = _tar({"../../etc/pwned": b"x\n"})
    with pytest.raises(ArchiveError):
        extract_archive(data, tmp_path / "out")


# ── fail-closed: resource caps ───────────────────────────────────────────────
def test_entry_count_cap(tmp_path: Path) -> None:
    data = _zip({f"f{i}.py": b"x\n" for i in range(5)})
    with pytest.raises(ArchiveError):
        extract_archive(data, tmp_path / "out", max_entries=3)


def test_extracted_size_cap(tmp_path: Path) -> None:
    data = _zip({"big.py": b"A" * 4096})
    with pytest.raises(ArchiveError):
        extract_archive(data, tmp_path / "out", max_total_bytes=1024)


# ── fail-closed: non-regular tar members are skipped, never materialized ──────
def test_tar_symlink_not_materialized(tmp_path: Path) -> None:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        link = tarfile.TarInfo(name="evil-link")
        link.type = tarfile.SYMTYPE
        link.linkname = "/etc/passwd"
        tf.addfile(link)
        reg = tarfile.TarInfo(name="ok.py")
        reg.size = 3
        tf.addfile(reg, io.BytesIO(b"x\n\n"))
    summary = extract_archive(buf.getvalue(), tmp_path / "out")
    # Only the regular file is written; the symlink is skipped.
    assert summary.entries == 1
    assert (tmp_path / "out" / "ok.py").is_file()
    assert not (tmp_path / "out" / "evil-link").exists()


# ── validate_archive (pre-store gate) ────────────────────────────────────────
def test_validate_accepts_good_zip() -> None:
    assert validate_archive(_zip({"a.py": b"x\n"})) == "zip"


def test_validate_rejects_non_archive() -> None:
    with pytest.raises(ArchiveError):
        validate_archive(b"\x00\x01 garbage")


def test_validate_rejects_zip_slip_name() -> None:
    with pytest.raises(ArchiveError):
        validate_archive(_zip({"../escape.py": b"x\n"}))


# ── M3-SEC1: compression-ratio bomb detection ────────────────────────────────
def test_streamed_ratio_bomb_rejected(tmp_path: Path) -> None:
    # A highly compressible file: ~200KB of one byte deflates to a few hundred
    # bytes → a huge real ratio. Small floor + ratio so the tiny archive trips it.
    data = _zip({"bomb.txt": b"A" * 200_000})
    with pytest.raises(ArchiveError, match="ratio"):
        extract_archive(data, tmp_path / "out", ratio_floor_bytes=1024, max_compression_ratio=10)


def test_declared_size_bomb_rejected_pre_store(monkeypatch: pytest.MonkeyPatch) -> None:
    # validate_archive uses module constants; shrink them so a small compressible
    # archive's *declared* uncompressed total trips the honest-bomb pre-check.
    monkeypatch.setattr(archive_mod, "RATIO_CHECK_FLOOR_BYTES", 1024)
    monkeypatch.setattr(archive_mod, "MAX_COMPRESSION_RATIO", 10)
    data = _zip({"bomb.txt": b"A" * 200_000})  # declares 200KB, compresses tiny
    with pytest.raises(ArchiveError, match="expansion"):
        validate_archive(data)


def test_small_compressible_archive_not_ratio_flagged(tmp_path: Path) -> None:
    # Under the default floor (10MiB), a small high-ratio archive is harmless and
    # must extract cleanly — no false positive.
    data = _zip({"a.txt": b"A" * 50_000})
    summary = extract_archive(data, tmp_path / "out")
    assert summary.entries == 1
    assert (tmp_path / "out" / "a.txt").read_bytes() == b"A" * 50_000


# ── M3-SEC1: no-exec on extracted files ──────────────────────────────────────
def test_extracted_files_are_not_executable(tmp_path: Path) -> None:
    data = _zip({"pkg/run.sh": b"#!/bin/sh\necho hi\n"})
    extract_archive(data, tmp_path / "out")
    mode = (tmp_path / "out" / "pkg" / "run.sh").stat().st_mode
    assert mode & 0o111 == 0  # no execute bit for owner/group/other
