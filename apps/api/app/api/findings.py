"""Finding read endpoints (M2-F3) — nested under an engagement, read-only.

There is no mutation surface here: findings are produced by the suite path
(services/findings.py) and their status history is append-only (DB trigger). The
UI reads a list, a detail (finding + linked evidence + status history), and a
single evidence blob's content. Every route is VIEW-guarded and org/engagement-
scoped through `get_org_engagement`/`get_org_finding` (cross-org → 404).

Evidence content is served through this endpoint — the browser never reaches
object storage. The blob is loaded via the storage abstraction, which re-verifies
its SHA-256; a tampered blob fails loud (500) rather than being served silently.
"""

import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import Capability, Principal, get_db, get_evidence_store, require
from app.schemas.findings import EvidenceContentOut, FindingDetailOut, FindingOut
from app.services.engagements import get_org_engagement
from app.services.findings_read import (
    get_finding_evidence_rows,
    get_finding_status_history,
    get_org_finding,
    list_engagement_findings,
    load_linked_evidence,
)
from app.storage.evidence import EvidenceIntegrityError, EvidenceNotFoundError, StorageError

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/engagements/{engagement_id}/findings", tags=["findings"])


@router.get("", response_model=list[FindingOut])
async def list_findings(
    engagement_id: uuid.UUID,
    scan_id: uuid.UUID | None = Query(default=None),
    principal: Principal = Depends(require(Capability.VIEW)),
    db: AsyncSession = Depends(get_db),
) -> list[FindingOut]:
    if await get_org_engagement(db, engagement_id, principal.organization_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="engagement not found")
    findings = await list_engagement_findings(db, engagement_id, scan_id=scan_id)
    return [FindingOut.from_model(f) for f in findings]


@router.get("/{finding_id}", response_model=FindingDetailOut)
async def get_finding(
    engagement_id: uuid.UUID,
    finding_id: uuid.UUID,
    principal: Principal = Depends(require(Capability.VIEW)),
    db: AsyncSession = Depends(get_db),
) -> FindingDetailOut:
    finding = await get_org_finding(db, engagement_id, finding_id, principal.organization_id)
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="finding not found")
    evidence = await get_finding_evidence_rows(db, finding.id)
    history = await get_finding_status_history(db, finding.id)
    return FindingDetailOut.from_model(finding, evidence, history)


@router.get("/{finding_id}/evidence/{evidence_id}", response_model=EvidenceContentOut)
async def get_finding_evidence_content(
    engagement_id: uuid.UUID,
    finding_id: uuid.UUID,
    evidence_id: uuid.UUID,
    principal: Principal = Depends(require(Capability.VIEW)),
    db: AsyncSession = Depends(get_db),
    store=Depends(get_evidence_store),
) -> EvidenceContentOut:
    # Scope the finding to the caller's org/engagement first, then only serve
    # evidence that is actually linked to it.
    finding = await get_org_finding(db, engagement_id, finding_id, principal.organization_id)
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="finding not found")
    try:
        loaded = await load_linked_evidence(db, store, finding.id, evidence_id)
    except EvidenceNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="evidence not found"
        ) from exc
    except (EvidenceIntegrityError, StorageError) as exc:
        # Integrity/backend failure is a loud server-side error — never serve a
        # blob whose hash does not verify (chain of custody).
        logger.error("evidence load failed for %s: %s", evidence_id, exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="evidence could not be verified",
        ) from exc
    if loaded is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="evidence not found")
    evidence, data = loaded
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = data.decode("utf-8", errors="replace")
    return EvidenceContentOut(
        evidence_id=evidence.id,
        kind=evidence.kind,
        content_type=evidence.content_type,
        size_bytes=evidence.size_bytes,
        content_sha256=evidence.content_sha256.hex(),
        content=text,
    )
