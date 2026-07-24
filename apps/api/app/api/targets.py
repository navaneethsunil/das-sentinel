"""Target inventory CRUD (M1-B10) — nested under an engagement.

Mutations require MANAGE_ENGAGEMENTS; reads require VIEW. Engagement- and
org-scoped (cross-org/engagement → 404, no IDOR leak). auth_config is validated
to hold credential references only (TR-23). target_type is immutable after
create (it fixes how primary_value is validated and matched). Mutations are
audited; findings_by_severity is a computed rollup, empty at M1.
"""

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import AuditService
from app.core.deps import (
    Capability,
    Principal,
    get_audit_service,
    get_db,
    get_evidence_store,
    require,
)
from app.models.engagement import ScopeMatcher
from app.models.evidence import EvidenceKind
from app.models.target import Target, TargetType
from app.schemas.targets import (
    SourceArchiveUploadOut,
    TargetCreate,
    TargetOut,
    TargetUpdate,
)
from app.services.engagements import get_org_engagement
from app.services.scope_matchers import validate_matcher
from app.services.source_archive import (
    MAX_UPLOAD_BYTES,
    ArchiveError,
    content_type_for,
    validate_archive,
)
from app.services.targets import get_org_target
from app.storage import BlobStore, store_evidence

router = APIRouter(prefix="/engagements/{engagement_id}/targets", tags=["targets"])

_URL_TYPES = {
    TargetType.WEB_APP,
    TargetType.REST_API,
    TargetType.GRAPHQL_API,
    TargetType.AI_CHATBOT,
    TargetType.LLM_API_WRAPPER,
    TargetType.AI_AGENT,
}


def _client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def _revalidate_primary_value(target_type: TargetType, value: str) -> str:
    if target_type in _URL_TYPES:
        return validate_matcher(ScopeMatcher.URL, value)
    if target_type == TargetType.SOURCE_REPO:
        return validate_matcher(ScopeMatcher.REPO, value)
    return value


async def _require_engagement(
    db: AsyncSession, engagement_id: uuid.UUID, org_id: uuid.UUID
) -> None:
    if await get_org_engagement(db, engagement_id, org_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="engagement not found")


async def _require_target(
    db: AsyncSession, engagement_id: uuid.UUID, target_id: uuid.UUID, org_id: uuid.UUID
) -> Target:
    target = await get_org_target(db, engagement_id, target_id, org_id)
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="target not found")
    return target


@router.post("", response_model=TargetOut, status_code=status.HTTP_201_CREATED)
async def create_target(
    engagement_id: uuid.UUID,
    body: TargetCreate,
    request: Request,
    principal: Principal = Depends(require(Capability.MANAGE_ENGAGEMENTS)),
    db: AsyncSession = Depends(get_db),
    audit: AuditService = Depends(get_audit_service),
) -> TargetOut:
    await _require_engagement(db, engagement_id, principal.organization_id)
    target = Target(
        engagement_id=engagement_id,
        name=body.name,
        target_type=body.target_type,
        environment=body.environment,
        primary_value=body.primary_value,
        auth_status=body.auth_status,
        auth_config=body.auth_config,
        connector_config=body.connector_config,
    )
    db.add(target)
    await db.flush()
    await audit.log(
        organization_id=principal.organization_id,
        actor_user_id=principal.user_id,
        action="target.created",
        object_type="target",
        object_id=target.id,
        engagement_id=engagement_id,
        detail={"target_type": target.target_type.value, "name": target.name},
        ip_address=_client_ip(request),
    )
    await db.refresh(target)
    return TargetOut.from_model(target)


@router.post("/{target_id}/source-archive", response_model=SourceArchiveUploadOut)
async def upload_source_archive(
    engagement_id: uuid.UUID,
    target_id: uuid.UUID,
    request: Request,
    file: UploadFile = File(...),
    principal: Principal = Depends(require(Capability.MANAGE_ENGAGEMENTS)),
    db: AsyncSession = Depends(get_db),
    store: BlobStore = Depends(get_evidence_store),
    audit: AuditService = Depends(get_audit_service),
) -> SourceArchiveUploadOut:
    """Attach an uploaded code archive to a source_archive target (M3-B1, TRD §API).

    The archive is stored as content-addressed, immutable evidence (kind
    source_archive); the target's primary_value is set to its object key so the
    SAST scanner materializes it at scan time. The upload is size-capped and
    validated as a safe zip/tar before it is stored — a hostile or unrecognized
    archive is rejected (422/413) and nothing is persisted (TM-7, fail-closed)."""
    target = await _require_target(db, engagement_id, target_id, principal.organization_id)
    if target.target_type is not TargetType.SOURCE_ARCHIVE:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="target is not a source_archive target",
        )
    # Bounded read: request at most one byte past the cap so an oversized upload is
    # detected without buffering an unbounded body (TM-12).
    data = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"archive exceeds the {MAX_UPLOAD_BYTES}-byte upload cap",
        )
    if not data:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="empty upload")
    try:
        archive_format = validate_archive(data)
    except ArchiveError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc

    engagement = await get_org_engagement(db, engagement_id, principal.organization_id)
    evidence = await store_evidence(
        db,
        store,
        organization_id=engagement.organization_id,
        content=data,
        kind=EvidenceKind.SOURCE_ARCHIVE,
        content_type=content_type_for(archive_format),
    )
    target.primary_value = evidence.object_key
    target.updated_at = datetime.now(target.created_at.tzinfo)
    await db.flush()
    await audit.log(
        organization_id=principal.organization_id,
        actor_user_id=principal.user_id,
        action="target.source_archive_uploaded",
        object_type="target",
        object_id=target.id,
        engagement_id=engagement_id,
        detail={
            "evidence_id": str(evidence.id),
            "archive_format": archive_format,
            "size_bytes": evidence.size_bytes,
        },
        ip_address=_client_ip(request),
    )
    return SourceArchiveUploadOut(
        target_id=target.id,
        evidence_id=evidence.id,
        object_key=evidence.object_key,
        size_bytes=evidence.size_bytes,
        content_sha256=evidence.content_sha256.hex(),
        archive_format=archive_format,
    )


@router.get("", response_model=list[TargetOut])
async def list_targets(
    engagement_id: uuid.UUID,
    principal: Principal = Depends(require(Capability.VIEW)),
    db: AsyncSession = Depends(get_db),
) -> list[TargetOut]:
    await _require_engagement(db, engagement_id, principal.organization_id)
    result = await db.execute(
        select(Target)
        .where(Target.engagement_id == engagement_id, Target.deleted_at.is_(None))
        .order_by(Target.created_at)
    )
    return [TargetOut.from_model(t) for t in result.scalars().all()]


@router.get("/{target_id}", response_model=TargetOut)
async def get_target(
    engagement_id: uuid.UUID,
    target_id: uuid.UUID,
    principal: Principal = Depends(require(Capability.VIEW)),
    db: AsyncSession = Depends(get_db),
) -> TargetOut:
    target = await _require_target(db, engagement_id, target_id, principal.organization_id)
    return TargetOut.from_model(target)


@router.patch("/{target_id}", response_model=TargetOut)
async def update_target(
    engagement_id: uuid.UUID,
    target_id: uuid.UUID,
    body: TargetUpdate,
    request: Request,
    principal: Principal = Depends(require(Capability.MANAGE_ENGAGEMENTS)),
    db: AsyncSession = Depends(get_db),
    audit: AuditService = Depends(get_audit_service),
) -> TargetOut:
    target = await _require_target(db, engagement_id, target_id, principal.organization_id)
    changes = body.model_dump(exclude_unset=True)
    if "primary_value" in changes:
        changes["primary_value"] = _revalidate_primary_value(
            target.target_type, changes["primary_value"]
        )
    for field, value in changes.items():
        setattr(target, field, value)
    target.updated_at = datetime.now(target.created_at.tzinfo)
    await db.flush()
    await audit.log(
        organization_id=principal.organization_id,
        actor_user_id=principal.user_id,
        action="target.updated",
        object_type="target",
        object_id=target.id,
        engagement_id=engagement_id,
        detail={"fields": sorted(changes)},
        ip_address=_client_ip(request),
    )
    await db.refresh(target)
    return TargetOut.from_model(target)


@router.delete("/{target_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_target(
    engagement_id: uuid.UUID,
    target_id: uuid.UUID,
    request: Request,
    principal: Principal = Depends(require(Capability.MANAGE_ENGAGEMENTS)),
    db: AsyncSession = Depends(get_db),
    audit: AuditService = Depends(get_audit_service),
) -> None:
    target = await _require_target(db, engagement_id, target_id, principal.organization_id)
    target.deleted_at = datetime.now(target.created_at.tzinfo)
    await db.flush()
    await audit.log(
        organization_id=principal.organization_id,
        actor_user_id=principal.user_id,
        action="target.deleted",
        object_type="target",
        object_id=target.id,
        engagement_id=engagement_id,
        ip_address=_client_ip(request),
    )
