"""Safe source-archive handling (M3-B1) — accept an uploaded code archive and
extract it for the SAST scanners.

An uploaded archive is untrusted input from a (possibly malicious) client, so
extraction is the classic zip-slip / zip-bomb / symlink-escape surface (TM-7).
This module fails closed: an unrecognized, malformed, or unsafe archive raises
`ArchiveError` and nothing is materialized.

Scope of the guards HERE (M3-B1 baseline — the cheap, dangerous-to-omit ones):
  - reject entries with absolute paths or `..` traversal that escape the
    extraction root (zip-slip), for both zip and tar;
  - hard caps on entry count and total *streamed* (real, not header-declared)
    extracted bytes — a first-line bound on decompression bombs;
  - only regular files are materialized; symlinks / hardlinks / devices / fifos
    are skipped, never written.

Deferred to M3-SEC1 (the full TM-7 hardening + release-blocking negative matrix):
  compression-ratio bomb detection, symlink-escape reproduction tests, an
  isolated no-exec quota'd extraction mount, and fuzzing. The caps here are a
  floor, not the finished defense.
"""

import io
import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

# Baseline safety caps. Module constants (not Settings) — they are safety floors,
# not per-deployment tuning, and keeping them out of Settings avoids widening the
# config surface every test double must mirror.
MAX_UPLOAD_BYTES = 100 * 1024 * 1024  # reject an upload larger than this (pre-store)
MAX_EXTRACTED_BYTES = 500 * 1024 * 1024  # cap total bytes written during extraction
MAX_ENTRIES = 20_000  # cap archive member count
_COPY_CHUNK = 1024 * 1024

_CONTENT_TYPES = {"zip": "application/zip", "tar": "application/x-tar"}


class ArchiveError(Exception):
    """The archive is unrecognized, malformed, or unsafe. Always fail closed —
    we never partially trust a hostile archive."""


@dataclass(frozen=True)
class ExtractionSummary:
    archive_format: str
    entries: int
    total_bytes: int


def detect_format(data: bytes) -> str:
    """Return "zip" or "tar" for a recognized archive, else raise ArchiveError.
    zip is probed first (its magic is unambiguous); tar has no header magic so it
    is confirmed by a successful open."""
    if zipfile.is_zipfile(io.BytesIO(data)):
        return "zip"
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*"):
            return "tar"
    except tarfile.TarError:
        raise ArchiveError("unrecognized archive format (expected zip or tar)") from None


def content_type_for(archive_format: str) -> str:
    return _CONTENT_TYPES.get(archive_format, "application/octet-stream")


def _safe_dest(base: Path, name: str) -> Path:
    """Resolve an archive member name under `base`, rejecting absolute paths and
    any `..` traversal that would escape the extraction root (zip-slip)."""
    if name.startswith(("/", "\\")):
        raise ArchiveError(f"unsafe absolute path entry: {name!r}")
    candidate = (base / name).resolve()
    base_r = base.resolve()
    if candidate != base_r and base_r not in candidate.parents:
        raise ArchiveError(f"entry escapes extraction root: {name!r}")
    return candidate


def _stream_copy(src: BinaryIO, dest_path: Path, total: int, cap: int) -> int:
    """Copy `src` to `dest_path` in bounded chunks, enforcing the cumulative
    extracted-bytes cap on the REAL streamed size (header-declared sizes can
    lie). Returns the new running total."""
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    with open(dest_path, "wb") as out:
        while True:
            chunk = src.read(_COPY_CHUNK)
            if not chunk:
                break
            total += len(chunk)
            if total > cap:
                raise ArchiveError(
                    f"extracted content exceeds {cap}-byte cap (decompression bomb?)"
                )
            out.write(chunk)
    return total


def _extract_zip(
    data: bytes, dest: Path, *, max_entries: int, max_total_bytes: int
) -> tuple[int, int]:
    total = 0
    count = 0
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        infos = zf.infolist()
        if len(infos) > max_entries:
            raise ArchiveError(f"archive has {len(infos)} entries, over the {max_entries} cap")
        for info in infos:
            target = _safe_dest(dest, info.filename)
            if info.is_dir():
                continue
            with zf.open(info) as src:
                total = _stream_copy(src, target, total, max_total_bytes)
            count += 1
    return count, total


def _extract_tar(
    data: bytes, dest: Path, *, max_entries: int, max_total_bytes: int
) -> tuple[int, int]:
    total = 0
    count = 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
        members = tf.getmembers()
        if len(members) > max_entries:
            raise ArchiveError(f"archive has {len(members)} entries, over the {max_entries} cap")
        for member in members:
            target = _safe_dest(dest, member.name)
            if member.isdir():
                continue
            # Only regular files are materialized. Symlinks / hardlinks / devices /
            # fifos are skipped — never written — so a symlink can't be used to
            # escape the root or plant a special file (baseline TM-7).
            if not member.isreg():
                continue
            src = tf.extractfile(member)
            if src is None:
                continue
            with src:
                total = _stream_copy(src, target, total, max_total_bytes)
            count += 1
    return count, total


def validate_archive(data: bytes) -> str:
    """Cheap pre-store gate for an uploaded archive: confirm it is a recognized
    zip/tar, within the entry cap, with only safe member paths — WITHOUT
    extracting. Returns the detected format or raises ArchiveError. The
    authoritative streamed-size enforcement happens in `extract_archive`."""
    fmt = detect_format(data)
    if fmt == "zip":
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = zf.namelist()
    else:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
            names = tf.getnames()
    if len(names) > MAX_ENTRIES:
        raise ArchiveError(f"archive has {len(names)} entries, over the {MAX_ENTRIES} cap")
    # Lexical path-safety dry run against a sentinel root (no filesystem touch).
    sentinel = Path("/__das_archive_validate__")
    for name in names:
        _safe_dest(sentinel, name)
    return fmt


def extract_archive(
    data: bytes,
    dest: Path,
    *,
    max_entries: int = MAX_ENTRIES,
    max_total_bytes: int = MAX_EXTRACTED_BYTES,
) -> ExtractionSummary:
    """Safely extract a zip/tar archive into `dest` (created if absent). Enforces
    entry-count and total-extracted-bytes caps, rejects path-escaping entries,
    and materializes only regular files. Raises ArchiveError on anything unsafe
    or unusable — the caller must treat that as a hard failure (TM-14)."""
    fmt = detect_format(data)
    dest.mkdir(parents=True, exist_ok=True)
    if fmt == "zip":
        count, total = _extract_zip(
            data, dest, max_entries=max_entries, max_total_bytes=max_total_bytes
        )
    else:
        count, total = _extract_tar(
            data, dest, max_entries=max_entries, max_total_bytes=max_total_bytes
        )
    return ExtractionSummary(archive_format=fmt, entries=count, total_bytes=total)
