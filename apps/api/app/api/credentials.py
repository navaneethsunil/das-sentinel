"""Managed credential endpoints — the in-app secret vault (org-scoped).

Every route is MANAGE_CREDENTIALS-guarded (Admin/Tester) and scoped to the caller's
organization: a credential in another org is 404, never 403-with-data. The secret is
WRITE-ONLY — create accepts it, no route ever returns it. Create/delete are audited.
"""

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import AuditService
from app.core.deps import (
    Capability,
    Principal,
    get_audit_service,
    get_credential_cipher,
    get_db,
    require,
)
from app.core.sessions import utcnow
from app.models.credential import Credential
from app.schemas.credentials import CredentialCreate, CredentialOut
from app.services.credentials import (
    CredentialCipher,
    create_credential,
    get_org_credential,
    list_credentials,
)

router = APIRouter(prefix="/credentials", tags=["credentials"])


def _client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


@router.post("", response_model=CredentialOut, status_code=status.HTTP_201_CREATED)
async def create(
    body: CredentialCreate,
    request: Request,
    principal: Principal = Depends(require(Capability.MANAGE_CREDENTIALS)),
    db: AsyncSession = Depends(get_db),
    audit: AuditService = Depends(get_audit_service),
    cipher: CredentialCipher = Depends(get_credential_cipher),
) -> CredentialOut:
    try:
        row = await create_credential(
            db,
            cipher,
            organization_id=principal.organization_id,
            name=body.name,
            description=body.description,
            secret=body.secret.get_secret_value(),
            created_by=principal.user_id,
        )
        await db.flush()
    except IntegrityError as exc:
        # The partial unique index (org, name) where not deleted.
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="a credential with this name already exists",
        ) from exc
    await audit.log(
        organization_id=principal.organization_id,
        actor_user_id=principal.user_id,
        action="credential.created",
        object_type="credential",
        object_id=row.id,
        detail={"name": row.name},  # never the secret
        ip_address=_client_ip(request),
    )
    await db.commit()
    await db.refresh(row)
    return CredentialOut.from_model(row)


@router.get("", response_model=list[CredentialOut])
async def list_all(
    principal: Principal = Depends(require(Capability.MANAGE_CREDENTIALS)),
    db: AsyncSession = Depends(get_db),
) -> list[CredentialOut]:
    rows = await list_credentials(db, principal.organization_id)
    return [CredentialOut.from_model(r) for r in rows]


@router.delete("/{credential_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete(
    credential_id: uuid.UUID,
    request: Request,
    principal: Principal = Depends(require(Capability.MANAGE_CREDENTIALS)),
    db: AsyncSession = Depends(get_db),
    audit: AuditService = Depends(get_audit_service),
) -> None:
    row = await get_org_credential(db, principal.organization_id, credential_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="credential not found")
    await db.execute(update(Credential).where(Credential.id == row.id).values(deleted_at=utcnow()))
    await audit.log(
        organization_id=principal.organization_id,
        actor_user_id=principal.user_id,
        action="credential.deleted",
        object_type="credential",
        object_id=row.id,
        detail={"name": row.name},
        ip_address=_client_ip(request),
    )
    await db.commit()
