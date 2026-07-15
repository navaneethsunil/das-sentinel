"""Approval-gate schemas (M1-B11)."""

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.core.scope import OperationKind
from app.models.engagement import ApprovalGate, ApprovalStatus

MAX_EXPIRY_HOURS = 168  # 7 days


class ApprovalRequest(BaseModel):
    target_id: uuid.UUID
    operation_kind: OperationKind  # must derive HIGH_RISK (validated in the service)
    justification: str = Field(min_length=1, max_length=2000)
    expires_in_hours: int = Field(default=24, ge=1, le=MAX_EXPIRY_HOURS)


class ApprovalDecision(BaseModel):
    approve: bool
    reason: str | None = Field(default=None, max_length=2000)


class ApprovalRevoke(BaseModel):
    reason: str | None = Field(default=None, max_length=2000)


class ApprovalOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    engagement_id: uuid.UUID
    target_id: uuid.UUID
    requested_by: uuid.UUID
    action_type: str
    justification: str
    operation_digest: str  # hex
    roe_ack_id: uuid.UUID
    policy_version: str
    status: ApprovalStatus
    decided_by: uuid.UUID | None
    decided_at: datetime | None
    decision_reason: str | None
    expires_at: datetime
    revoked_at: datetime | None
    consumed_at: datetime | None
    created_at: datetime

    @classmethod
    def from_model(cls, gate: ApprovalGate) -> "ApprovalOut":
        return cls(
            id=gate.id,
            engagement_id=gate.engagement_id,
            target_id=gate.target_id,
            requested_by=gate.requested_by,
            action_type=gate.action_type,
            justification=gate.justification,
            operation_digest=gate.operation_digest.hex(),
            roe_ack_id=gate.roe_ack_id,
            policy_version=gate.policy_version,
            status=gate.status,
            decided_by=gate.decided_by,
            decided_at=gate.decided_at,
            decision_reason=gate.decision_reason,
            expires_at=gate.expires_at,
            revoked_at=gate.revoked_at,
            consumed_at=gate.consumed_at,
            created_at=gate.created_at,
        )
