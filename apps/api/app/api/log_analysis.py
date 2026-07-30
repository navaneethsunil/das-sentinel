"""LLM log-analysis endpoint — a new AI discovery source over a raw log blob.

Running analysis drives our LLM and creates findings, so it is a VALIDATE_FINDINGS
action; the created findings are ai_generated / INFORMATIONAL / OPEN and NEVER
presented as verified (CLAUDE.md §2.6/§2.9). Org/engagement/target-scoped via the
get_org_* helpers (cross-org → 404, no IDOR/BOLA); the run is audited. A guardrail
violation (an unanchored/invented candidate) is refused 422 with nothing written.
"""

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import AuditService
from app.core.deps import (
    Capability,
    Principal,
    get_audit_service,
    get_db,
    get_evidence_store,
    get_llm_service,
    require,
)
from app.llm import LLMService
from app.llm.base import HostedModelNotAllowedError, LLMBudgetExceededError, LLMError
from app.models.evidence import Evidence, EvidenceKind
from app.schemas.log_analysis import LogAnalysisRequest, LogAnalysisResultOut
from app.services.engagements import get_org_engagement
from app.services.log_analysis import LogAnalysisError, LogAnalysisRejected, analyze_log
from app.services.targets import get_org_target
from app.storage.evidence import BlobStore

router = APIRouter(
    prefix="/engagements/{engagement_id}/targets/{target_id}/log-analysis", tags=["log-analysis"]
)


def _client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


@router.post("", response_model=LogAnalysisResultOut, status_code=status.HTTP_201_CREATED)
async def run_log_analysis(
    engagement_id: uuid.UUID,
    target_id: uuid.UUID,
    body: LogAnalysisRequest,
    request: Request,
    principal: Principal = Depends(require(Capability.VALIDATE_FINDINGS)),
    db: AsyncSession = Depends(get_db),
    audit: AuditService = Depends(get_audit_service),
    llm: LLMService = Depends(get_llm_service),
    store: BlobStore = Depends(get_evidence_store),
) -> LogAnalysisResultOut:
    engagement = await get_org_engagement(db, engagement_id, principal.organization_id)
    target = await get_org_target(db, engagement_id, target_id, principal.organization_id)
    if engagement is None or target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="target not found")

    evidence = await db.get(Evidence, body.evidence_id)
    # Org-scope the blob (no cross-org read) and require it be raw tool output.
    if evidence is None or evidence.organization_id != principal.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="evidence not found")
    if evidence.kind is not EvidenceKind.RAW_SCANNER_OUTPUT:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="log analysis only accepts raw_scanner_output evidence",
        )

    try:
        findings, _interaction, _candidates = await analyze_log(
            db,
            llm,
            store,
            engagement=engagement,
            target=target,
            evidence=evidence,
            now=datetime.now(UTC),
            created_by=principal.user_id,
        )
    except LogAnalysisRejected as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    except HostedModelNotAllowedError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except LLMBudgetExceededError as exc:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=str(exc)) from exc
    except LogAnalysisError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    except LLMError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="LLM error") from exc

    await audit.log(
        organization_id=principal.organization_id,
        actor_user_id=principal.user_id,
        action="finding.log_analysis_run",
        object_type="evidence",
        object_id=evidence.id,
        engagement_id=engagement_id,
        detail={
            "target_id": str(target.id),
            "candidate_count": len(findings),
            "finding_ids": [str(f.id) for f in findings],
        },
        ip_address=_client_ip(request),
    )
    await db.commit()
    for f in findings:
        await db.refresh(f)
    return LogAnalysisResultOut.from_findings(findings)
