"""CVSS scoring service (M3-B3) — DATABASE_SCHEMA §8, CLAUDE.md §1/§7.

Scores are computed and parsed with the maintained `cvss` PyPI package
(RedHatProductSecurity/cvss): **v4.0 is the default, v3.1 is retained for
historical CVEs** (dual-scoring). The version is taken from the vector string's
own prefix — the vector *is* the version — so a stored score can never disagree
with its vector. We never hand-roll v4.0's MacroVector scoring; the package is
the single source of the base score and its severity band. The package is pure
Python (no network), so this works air-gapped.

The LLM never sets a final CVSS (CLAUDE.md §7); scoring is a human action, guarded
by VALIDATE_FINDINGS, or a value derived programmatically from a supplied vector.

History is insert-only: `set_cvss_score` clears the prior `is_current` row and
inserts a fresh one, so the table itself is the audit trail — a historical row's
score/vector/version is never rewritten and rows are never soft-deleted (only the
`is_current` flag on the superseded row is flipped, which is the schema-sanctioned
mutation). The `ux_cvss_current` partial unique index enforces *at most one*
current row per finding; this service guarantees *exactly one* after any set.
"""

from dataclasses import dataclass

from cvss import CVSS3, CVSS4
from cvss.exceptions import CVSSError
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.cvss import CvssScore, CvssVersion
from app.models.finding import Finding, Severity

# Only the two supported vector families (CLAUDE.md §1 dual-scoring). A 3.0 or v2
# vector is refused rather than silently mislabeled — the enum has no member for it.
_VERSION_PREFIX: dict[str, CvssVersion] = {
    "CVSS:4.0/": CvssVersion.V4_0,
    "CVSS:3.1/": CvssVersion.V3_1,
}

# The `cvss` package's qualitative labels → our working severity band.
_SEVERITY_BAND: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "none": Severity.INFORMATIONAL,
}


class CvssComputeError(Exception):
    """A vector string is malformed, an unsupported version, or a manual override
    is missing its required justification. Fail-closed — no score is written."""


@dataclass(frozen=True)
class ComputedScore:
    version: CvssVersion
    vector_string: str  # canonical/normalized form from the package
    base_score: float
    severity_band: Severity


def detect_version(vector_string: str) -> CvssVersion:
    """Resolve the CVSS version from the vector's own prefix (fail-closed)."""
    vector = vector_string.strip()
    for prefix, version in _VERSION_PREFIX.items():
        if vector.startswith(prefix):
            return version
    raise CvssComputeError(
        "unsupported or missing CVSS version prefix (expected 'CVSS:4.0/' or 'CVSS:3.1/')"
    )


def compute(vector_string: str) -> ComputedScore:
    """Parse and score a CVSS vector with the `cvss` package. Raises
    CvssComputeError on anything malformed — the package never invents a score."""
    vector = vector_string.strip()
    version = detect_version(vector)
    try:
        if version is CvssVersion.V4_0:
            metric = CVSS4(vector)
            base_score = float(metric.base_score)
            label = metric.severity
        else:
            metric = CVSS3(vector)
            base_score = float(metric.base_score)
            label = metric.severities()[0]
        clean_vector = metric.clean_vector()
    except CVSSError as exc:
        raise CvssComputeError(f"invalid CVSS vector: {exc}") from exc
    band = _SEVERITY_BAND.get(label.lower())
    if band is None:  # defensive — the package's label set is closed
        raise CvssComputeError(f"unrecognized CVSS severity label: {label!r}")
    return ComputedScore(
        version=version, vector_string=clean_vector, base_score=base_score, severity_band=band
    )


async def set_cvss_score(
    session: AsyncSession,
    *,
    finding: Finding,
    vector_string: str,
    is_manual_override: bool = False,
    override_justification: str | None = None,
    scored_by=None,
    now=None,  # accepted for call-site symmetry; created_at is a server default
) -> CvssScore:
    """Record a new current CVSS score for a finding (insert-only history).

    The base score and severity band always come from parsing `vector_string` with
    the `cvss` package — never hand-entered. A manual override requires a non-empty
    justification (fail-closed). The prior current row (if any) is superseded by
    clearing its `is_current` flag before the new current row is inserted, so the
    `ux_cvss_current` invariant holds. Returns the flushed-not-committed row so the
    write is atomic with the caller's transaction (the caller commits)."""
    computed = compute(vector_string)  # raises CvssComputeError

    justification: str | None = None
    if is_manual_override:
        if not (override_justification and override_justification.strip()):
            raise CvssComputeError("manual override requires a justification")
        justification = override_justification.strip()

    # Supersede the prior current score (the only sanctioned mutation of history).
    await session.execute(
        update(CvssScore)
        .where(CvssScore.finding_id == finding.id, CvssScore.is_current.is_(True))
        .values(is_current=False)
    )
    score = CvssScore(
        finding_id=finding.id,
        version=computed.version,
        vector_string=computed.vector_string,
        base_score=computed.base_score,
        severity_band=computed.severity_band,
        is_current=True,
        is_manual_override=is_manual_override,
        override_justification=justification,
        scored_by=scored_by,
    )
    session.add(score)
    await session.flush()
    return score


async def get_current_score(session: AsyncSession, finding_id) -> CvssScore | None:
    """The one current CVSS score for a finding, or None if never scored."""
    return (
        await session.execute(
            select(CvssScore).where(
                CvssScore.finding_id == finding_id, CvssScore.is_current.is_(True)
            )
        )
    ).scalar_one_or_none()


async def list_score_history(session: AsyncSession, finding_id) -> list[CvssScore]:
    """Every CVSS score ever recorded for a finding, newest first (the full audit
    trail — the current row plus all superseded rows)."""
    return list(
        (
            await session.execute(
                select(CvssScore)
                .where(CvssScore.finding_id == finding_id)
                .order_by(CvssScore.created_at.desc())
            )
        ).scalars()
    )
