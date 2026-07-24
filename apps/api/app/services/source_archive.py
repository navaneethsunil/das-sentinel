"""Safe source-archive handling (M3-B1) — accept an uploaded code archive and
extract it for the SAST scanners.

An uploaded archive is untrusted input from a (possibly malicious) client, so
extraction is the classic zip-slip / zip-bomb / symlink-escape surface (TM-7).
This module fails closed: an unrecognized, malformed, or unsafe archive raises
`ArchiveError` and nothing is materialized.

The full TM-7 defense (M3-SEC1, completing the M3-B1 baseline):
  - reject entries with absolute paths or `..` traversal that escape the
    extraction root (zip-slip), for both zip and tar;
  - hard caps on entry count and total *streamed* (real, not header-declared)
    extracted bytes — the absolute bound on decompression bombs;
  - **compression-ratio bomb detection** — a two-layer guard: a cheap pre-store
    check on the archive's *declared* uncompressed total (catches an honest
    bomb before it is even stored), plus an authoritative check on the *real*
    streamed decompressed:compressed ratio during extraction (catches a bomb
    that lies about its sizes). Both fail closed above a floor, so tiny/harmless
    archives are never false-flagged;
  - only regular files are materialized; symlinks / hardlinks / devices / fifos
    are skipped, never written;
  - extracted files are written **non-executable** (mode 0o600, archive mode
    bits never propagated) — no-exec at the file level. The worker extracts into
    a per-run isolated temp dir it wipes afterward, and the caps above bound the
    disk it can consume (the quota). A mount-level `noexec`/quota on that dir is
    the documented infra hardening seam on top of these app-level guarantees.

Fuzzing the archive/SARIF parsers against malformed input is M3-SEC2.
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
# Decompression-bomb ratio: reject once real extracted bytes exceed this multiple
# of the archive's compressed size. Enforced only past the floor, so a small,
# legitimately-compressible archive (source compresses ~3-5:1) is never flagged;
# 200:1 leaves wide headroom while catching classic bombs (42.zip ≈ 10^11:1).
MAX_COMPRESSION_RATIO = 200
RATIO_CHECK_FLOOR_BYTES = 10 * 1024 * 1024  # below this expansion is harmless — skip ratio check
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


def _stream_copy(
    src: BinaryIO,
    dest_path: Path,
    total: int,
    cap: int,
    *,
    compressed_ref: int,
    max_ratio: int,
    ratio_floor: int,
) -> int:
    """Copy `src` to `dest_path` in bounded chunks, enforcing on the REAL streamed
    size (header-declared sizes can lie): the cumulative extracted-bytes cap and
    the decompressed:compressed ratio cap (past the floor). The extracted file is
    written non-executable. Returns the new running total."""
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
            if total > ratio_floor and compressed_ref > 0 and total > compressed_ref * max_ratio:
                raise ArchiveError(
                    f"decompressed:compressed ratio exceeds {max_ratio}:1 cap (zip-bomb?)"
                )
            out.write(chunk)
    # No-exec: extracted files are data for the SAST scanner, never run. We never
    # propagate the archive's mode bits, and pin owner-only read/write here.
    dest_path.chmod(0o600)
    return total


def _extract_zip(
    data: bytes,
    dest: Path,
    *,
    max_entries: int,
    max_total_bytes: int,
    max_ratio: int,
    ratio_floor: int,
) -> tuple[int, int]:
    total = 0
    count = 0
    compressed_ref = len(data)
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        infos = zf.infolist()
        if len(infos) > max_entries:
            raise ArchiveError(f"archive has {len(infos)} entries, over the {max_entries} cap")
        for info in infos:
            target = _safe_dest(dest, info.filename)
            if info.is_dir():
                continue
            with zf.open(info) as src:
                total = _stream_copy(
                    src,
                    target,
                    total,
                    max_total_bytes,
                    compressed_ref=compressed_ref,
                    max_ratio=max_ratio,
                    ratio_floor=ratio_floor,
                )
            count += 1
    return count, total


def _extract_tar(
    data: bytes,
    dest: Path,
    *,
    max_entries: int,
    max_total_bytes: int,
    max_ratio: int,
    ratio_floor: int,
) -> tuple[int, int]:
    total = 0
    count = 0
    compressed_ref = len(data)
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
                total = _stream_copy(
                    src,
                    target,
                    total,
                    max_total_bytes,
                    compressed_ref=compressed_ref,
                    max_ratio=max_ratio,
                    ratio_floor=ratio_floor,
                )
            count += 1
    return count, total


def validate_archive(data: bytes) -> str:
    """Cheap pre-store gate for an uploaded archive: confirm it is a recognized
    zip/tar, within the entry cap, with only safe member paths, and without a
    grossly bomb-like *declared* uncompressed total — all WITHOUT extracting.
    Returns the detected format or raises ArchiveError. The authoritative
    streamed-size + real-ratio enforcement happens in `extract_archive` (a bomb
    that lies about its declared sizes is caught there)."""
    fmt = detect_format(data)
    declared_total = 0
    if fmt == "zip":
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            infos = zf.infolist()
            names = [i.filename for i in infos]
            declared_total = sum(max(i.file_size, 0) for i in infos)
    else:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
            members = tf.getmembers()
            names = [m.name for m in members]
            declared_total = sum(max(m.size, 0) for m in members)
    if len(names) > MAX_ENTRIES:
        raise ArchiveError(f"archive has {len(names)} entries, over the {MAX_ENTRIES} cap")
    # Honest-bomb pre-check: reject before storing if the declared expansion is
    # absurd. A lying bomb slips this but is caught by the streamed check.
    if (
        declared_total > RATIO_CHECK_FLOOR_BYTES
        and len(data) > 0
        and declared_total > len(data) * MAX_COMPRESSION_RATIO
    ):
        raise ArchiveError(
            f"declared expansion {declared_total}B over {MAX_COMPRESSION_RATIO}:1 cap (zip-bomb?)"
        )
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
    max_compression_ratio: int = MAX_COMPRESSION_RATIO,
    ratio_floor_bytes: int = RATIO_CHECK_FLOOR_BYTES,
) -> ExtractionSummary:
    """Safely extract a zip/tar archive into `dest` (created if absent). Enforces
    entry-count, total-extracted-bytes, and decompressed:compressed ratio caps on
    the real streamed bytes, rejects path-escaping entries, and materializes only
    regular files (non-executable). Raises ArchiveError on anything unsafe or
    unusable — the caller must treat that as a hard failure (TM-14)."""
    fmt = detect_format(data)
    dest.mkdir(parents=True, exist_ok=True)
    extractor = _extract_zip if fmt == "zip" else _extract_tar
    count, total = extractor(
        data,
        dest,
        max_entries=max_entries,
        max_total_bytes=max_total_bytes,
        max_ratio=max_compression_ratio,
        ratio_floor=ratio_floor_bytes,
    )
    return ExtractionSummary(archive_format=fmt, entries=count, total_bytes=total)
