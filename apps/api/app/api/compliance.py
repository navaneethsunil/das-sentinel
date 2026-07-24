"""Compliance mapping endpoints (M3-B4).

Reference catalog (frameworks + controls) is global read-only data (VIEW). A
finding's mappings are read (VIEW) and edited (VALIDATE_FINDINGS) nested under the
engagement, org/engagement-scoped via get_org_finding (cross-org → 404). Auto-map
creates AUTOMATED mappings from a finding's own structured references; manual add
records a human-VALIDATED mapping. Every mutation is audited.
"""

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import AuditService
from app.core.deps import (
    Capability,
    Principal,
    get_audit_service,
    get_db,
    require,
)
from app.schemas.compliance import (
    AutoMapOut,
    FrameworkOut,
    MappingCreateIn,
    MappingOut,
)
from app.services.compliance import (
    ComplianceMappingError,
    add_mapping,
    auto_map_finding,
    get_finding_mappings,
    list_frameworks,
    remove_mapping,
)
from app.services.engagements import get_org_engagement
from app.services.findings_read import get_org_finding, list_engagement_findings

router = APIRouter(tags=["compliance"])


def _client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def _mapping_rows_to_out(rows) -> list[MappingOut]:  # noqa: ANN001
    return [
        MappingOut(
            control_id=control.id,
            framework_key=framework.key,
            framework_name=framework.name,
            code=control.code,
            title=control.title,
            mapped_by=mapping.mapped_by,
            confidence=float(mapping.confidence) if mapping.confidence is not None else None,
        )
        for mapping, control, framework in rows
    ]


@router.get("/compliance/frameworks", response_model=list[FrameworkOut])
async def get_frameworks(
    principal: Principal = Depends(require(Capability.VIEW)),  # noqa: ARG001
    db: AsyncSession = Depends(get_db),
) -> list[FrameworkOut]:
    """The seeded compliance catalog — every framework with its controls."""
    return [FrameworkOut.from_model(f, controls) for f, controls in await list_frameworks(db)]


@router.get(
    "/engagements/{engagement_id}/findings/{finding_id}/compliance",
    response_model=list[MappingOut],
)
async def get_mappings(
    engagement_id: uuid.UUID,
    finding_id: uuid.UUID,
    principal: Principal = Depends(require(Capability.VIEW)),
    db: AsyncSession = Depends(get_db),
) -> list[MappingOut]:
    finding = await get_org_finding(db, engagement_id, finding_id, principal.organization_id)
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="finding not found")
    return _mapping_rows_to_out(await get_finding_mappings(db, finding.id))


@router.post(
    "/engagements/{engagement_id}/findings/{finding_id}/compliance/auto-map",
    response_model=AutoMapOut,
)
async def auto_map_one(
    engagement_id: uuid.UUID,
    finding_id: uuid.UUID,
    request: Request,
    principal: Principal = Depends(require(Capability.VALIDATE_FINDINGS)),
    db: AsyncSession = Depends(get_db),
    audit: AuditService = Depends(get_audit_service),
) -> AutoMapOut:
    finding = await get_org_finding(db, engagement_id, finding_id, principal.organization_id)
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="finding not found")
    created = await auto_map_finding(db, finding)
    await audit.log(
        organization_id=principal.organization_id,
        actor_user_id=principal.user_id,
        action="finding.compliance_auto_mapped",
        object_type="finding",
        object_id=finding.id,
        engagement_id=engagement_id,
        detail={"created": len(created)},
        ip_address=_client_ip(request),
    )
    await db.commit()
    return AutoMapOut(created=len(created), control_ids=created)


@router.post(
    "/engagements/{engagement_id}/findings/{finding_id}/compliance",
    response_model=list[MappingOut],
    status_code=status.HTTP_201_CREATED,
)
async def add_manual_mapping(
    engagement_id: uuid.UUID,
    finding_id: uuid.UUID,
    body: MappingCreateIn,
    request: Request,
    principal: Principal = Depends(require(Capability.VALIDATE_FINDINGS)),
    db: AsyncSession = Depends(get_db),
    audit: AuditService = Depends(get_audit_service),
) -> list[MappingOut]:
    finding = await get_org_finding(db, engagement_id, finding_id, principal.organization_id)
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="finding not found")
    try:
        await add_mapping(db, finding, body.control_id)
    except ComplianceMappingError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    await audit.log(
        organization_id=principal.organization_id,
        actor_user_id=principal.user_id,
        action="finding.compliance_mapped",
        object_type="finding",
        object_id=finding.id,
        engagement_id=engagement_id,
        detail={"control_id": str(body.control_id)},
        ip_address=_client_ip(request),
    )
    await db.commit()
    return _mapping_rows_to_out(await get_finding_mappings(db, finding.id))


@router.delete(
    "/engagements/{engagement_id}/findings/{finding_id}/compliance/{control_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def delete_mapping(
    engagement_id: uuid.UUID,
    finding_id: uuid.UUID,
    control_id: uuid.UUID,
    request: Request,
    principal: Principal = Depends(require(Capability.VALIDATE_FINDINGS)),
    db: AsyncSession = Depends(get_db),
    audit: AuditService = Depends(get_audit_service),
) -> None:
    finding = await get_org_finding(db, engagement_id, finding_id, principal.organization_id)
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="finding not found")
    removed = await remove_mapping(db, finding.id, control_id)
    if not removed:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="mapping not found")
    await audit.log(
        organization_id=principal.organization_id,
        actor_user_id=principal.user_id,
        action="finding.compliance_unmapped",
        object_type="finding",
        object_id=finding.id,
        engagement_id=engagement_id,
        detail={"control_id": str(control_id)},
        ip_address=_client_ip(request),
    )
    await db.commit()


@router.post("/engagements/{engagement_id}/compliance/auto-map", response_model=AutoMapOut)
async def auto_map_engagement(
    engagement_id: uuid.UUID,
    request: Request,
    principal: Principal = Depends(require(Capability.VALIDATE_FINDINGS)),
    db: AsyncSession = Depends(get_db),
    audit: AuditService = Depends(get_audit_service),
) -> AutoMapOut:
    """Auto-map every canonical finding in the engagement in one pass."""
    if await get_org_engagement(db, engagement_id, principal.organization_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="engagement not found")
    created: list[uuid.UUID] = []
    for finding in await list_engagement_findings(db, engagement_id):
        created.extend(await auto_map_finding(db, finding))
    await audit.log(
        organization_id=principal.organization_id,
        actor_user_id=principal.user_id,
        action="engagement.compliance_auto_mapped",
        object_type="engagement",
        object_id=engagement_id,
        engagement_id=engagement_id,
        detail={"created": len(created)},
        ip_address=_client_ip(request),
    )
    await db.commit()
    return AutoMapOut(created=len(created), control_ids=created)
