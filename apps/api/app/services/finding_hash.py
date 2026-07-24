"""Canonical finding dedup identity (M3-B2).

`hash_code` is SHA-256 over a DEFINED field set (DATABASE_SCHEMA §7 / TR-20): the
target + the finding's source tool + its stable per-finding fingerprint (which
encodes rule_id + location). A SINGLE definition is shared by every producer — the
native scanner and LLM-suite paths AND SARIF (re)import — so a finding created by a
scan and the same finding re-imported from an exported SARIF resolve to the SAME
hash_code and dedup correctly into `duplicate_of` (TR-20).

`partial_fingerprints` always carries the source + fingerprint under stable keys
(`PF_SOURCE`/`PF_FINGERPRINT`) so both survive a SARIF export/import round-trip.
"""

import hashlib
import uuid
from typing import Any

# Stable partial_fingerprints keys every producer writes.
PF_SOURCE = "source"
PF_FINGERPRINT = "fingerprint"


def compute_hash_code(
    engagement_id: uuid.UUID, target_id: uuid.UUID, source: str, fingerprint: str
) -> bytes:
    """Stable dedup identity: the same fingerprinted finding from the same source
    against the same target (in the same engagement) is one finding across runs and
    across a SARIF round-trip."""
    return hashlib.sha256(f"{engagement_id}|{target_id}|{source}|{fingerprint}".encode()).digest()


def location_fingerprint(rule_id: str | None, location: dict[str, Any] | None) -> str:
    """Derive a stable fingerprint from rule_id + location for a finding with no
    tool-provided one (e.g. a foreign SARIF result). Mirrors the SAST
    'rule:file:line' / DAST 'rule:method:url' shape the native adapters emit."""
    loc = location if isinstance(location, dict) else {}
    parts = [rule_id or "unknown"]
    for key in ("file", "start_line", "method", "url", "endpoint", "param"):
        value = loc.get(key)
        if value is not None:
            parts.append(str(value))
    return ":".join(parts)
