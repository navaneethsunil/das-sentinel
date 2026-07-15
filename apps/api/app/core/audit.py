"""Audit writer + coverage middleware (M1-B5) — ARCHITECTURE §5.1, TM-9.

Two complementary paths:
  1. AuditService.log(...) — the explicit writer. Services call it for
     domain-meaningful events (scope.blocked, roe.accepted, ...) on the
     REQUEST's own DB session, so the event commits atomically with the action
     it records (or rolls back with it).
  2. audit_state_changes middleware — a coverage net. After every
     state-changing HTTP method it writes a baseline event on its OWN session,
     so no authenticated state change goes unrecorded even if a handler forgot
     the explicit call. Independent session ⇒ a rolled-back/failed request is
     still audited as an attempt.

Immutability is enforced in the DB (audit_events UPDATE/DELETE trigger, M1-D4);
this module only ever inserts.
"""

import logging
import uuid
from collections.abc import Awaitable, Callable
from typing import Any

from fastapi import Request, Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AuditEvent, AuditOutcome

logger = logging.getLogger(__name__)

STATE_CHANGING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def outcome_for_status(status_code: int) -> AuditOutcome:
    """Map an HTTP status to an audit outcome. 403 is an authorization *block*
    (a security-relevant denial), distinct from other failures."""
    if status_code < 400:
        return AuditOutcome.SUCCESS
    if status_code == 403:
        return AuditOutcome.BLOCKED
    return AuditOutcome.FAILURE


class AuditService:
    def __init__(self, db: AsyncSession) -> None:
        self._db = db

    async def log(
        self,
        *,
        organization_id: uuid.UUID,
        action: str,
        object_type: str,
        actor_user_id: uuid.UUID | None = None,
        object_id: uuid.UUID | None = None,
        engagement_id: uuid.UUID | None = None,
        outcome: AuditOutcome = AuditOutcome.SUCCESS,
        detail: dict[str, Any] | None = None,
        ip_address: str | None = None,
    ) -> AuditEvent:
        event = AuditEvent(
            organization_id=organization_id,
            actor_user_id=actor_user_id,
            action=action,
            object_type=object_type,
            object_id=object_id,
            engagement_id=engagement_id,
            outcome=outcome,
            detail=detail,
            ip_address=ip_address,
        )
        self._db.add(event)
        await self._db.flush()
        return event


def register_audit_middleware(app: Any) -> None:
    @app.middleware("http")
    async def audit_state_changes(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        response = await call_next(request)
        if request.method not in STATE_CHANGING_METHODS:
            return response

        # Only authenticated actions carry an org (audit_events.organization_id
        # is NOT NULL). get_principal stamps request.state.principal; anonymous
        # attempts (401) are captured in the access log, not the audit table.
        principal = getattr(request.state, "principal", None)
        if principal is None:
            return response

        try:
            sessionmaker = request.app.state.db_sessionmaker
            async with sessionmaker() as db:
                await AuditService(db).log(
                    organization_id=principal.organization_id,
                    actor_user_id=principal.user_id,
                    action=f"{request.method} {request.url.path}",
                    object_type="http_request",
                    outcome=outcome_for_status(response.status_code),
                    detail={
                        "method": request.method,
                        "path": request.url.path,
                        "status_code": response.status_code,
                    },
                    ip_address=request.client.host if request.client else None,
                )
                await db.commit()
        except Exception:
            # The action already completed; a failed audit write must not mask
            # the response. Surface it loudly — a persistent failure here is an
            # operational alarm. Domain-critical events use the transactional
            # AuditService.log path instead (atomic with the action).
            logger.exception(
                "audit middleware failed to record %s %s",
                request.method,
                request.url.path,
            )
        return response
