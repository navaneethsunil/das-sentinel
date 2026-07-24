"""Automated remediation guidance endpoints (M4-B1) — nested under a finding.

Generating guidance is a VALIDATE_FINDINGS action (it drives our LLM); reading it
is VIEW. Every route is org/engagement-scoped via get_org_finding (cross-org →
404, no IDOR/BOLA). Generation produces an is_ai_generated DRAFT for human review
and NEVER mutates the finding (CLAUDE.md §2.9/§7); the event is audited.
"""

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
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
from app.llm.base import (
    HostedModelNotAllowedError,
    LLMBudgetExceededError,
    LLMError,
)
from app.models.remediation import Remediation
from app.schemas.remediation import RemediationOut
from app.services.engagements import get_org_engagement
from app.services.findings_read import get_org_finding
from app.services.remediation import RemediationError, generate_remediation
from app.storage.evidence import BlobStore

router = APIRouter(
    prefix="/engagements/{engagement_id}/findings/{finding_id}/remediation", tags=["remediation"]
)


def _client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


@router.post("/generate", response_model=RemediationOut, status_code=status.HTTP_201_CREATED)
async def generate(
    engagement_id: uuid.UUID,
    finding_id: uuid.UUID,
    request: Request,
    principal: Principal = Depends(require(Capability.VALIDATE_FINDINGS)),
    db: AsyncSession = Depends(get_db),
    audit: AuditService = Depends(get_audit_service),
    llm: LLMService = Depends(get_llm_service),
    store: BlobStore = Depends(get_evidence_store),
) -> RemediationOut:
    """Generate DRAFT remediation guidance for a finding via our LLM (guardrailed).
    A guardrail violation (e.g. an invented evidence pointer) is refused 422 with
    nothing written; the finding is never mutated."""
    engagement = await get_org_engagement(db, engagement_id, principal.organization_id)
    finding = await get_org_finding(db, engagement_id, finding_id, principal.organization_id)
    if engagement is None or finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="finding not found")
    try:
        row, _interaction, _draft = await generate_remediation(
            db,
            llm,
            store,
            engagement=engagement,
            finding=finding,
            created_by=principal.user_id,
        )
    except RemediationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    except HostedModelNotAllowedError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except LLMBudgetExceededError as exc:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=str(exc)) from exc
    except LLMError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="LLM error") from exc
    await audit.log(
        organization_id=principal.organization_id,
        actor_user_id=principal.user_id,
        action="finding.remediation_generated",
        object_type="finding",
        object_id=finding.id,
        engagement_id=engagement_id,
        detail={
            "remediation_id": str(row.id),
            "is_ai_generated": row.is_ai_generated,
            "has_code_example": row.secure_code_example is not None,
            "has_patch_suggestion": row.patch_suggestion is not None,
        },
        ip_address=_client_ip(request),
    )
    await db.commit()
    await db.refresh(row)
    return RemediationOut.from_model(row)


@router.get("", response_model=list[RemediationOut])
async def list_remediations(
    engagement_id: uuid.UUID,
    finding_id: uuid.UUID,
    principal: Principal = Depends(require(Capability.VIEW)),
    db: AsyncSession = Depends(get_db),
) -> list[RemediationOut]:
    finding = await get_org_finding(db, engagement_id, finding_id, principal.organization_id)
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="finding not found")
    rows = (
        (
            await db.execute(
                select(Remediation)
                .where(Remediation.finding_id == finding.id)
                .order_by(Remediation.created_at.desc())
            )
        )
        .scalars()
        .all()
    )
    return [RemediationOut.from_model(r) for r in rows]
