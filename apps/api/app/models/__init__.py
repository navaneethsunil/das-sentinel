"""SQLAlchemy models. Importing this package registers every table on
Base.metadata (which Alembic autogenerate/check runs against)."""

from app.models.base import Base
from app.models.engagement import (
    ApprovalGate,
    ApprovalStatus,
    Engagement,
    EngagementStatus,
    ROEAcknowledgement,
    ScanIntensity,
    ScopeItem,
    ScopeKind,
    ScopeMatcher,
)
from app.models.identity import Organization, Session, User, UserRole
from app.models.target import AuthStatus, EnvironmentLabel, Target, TargetType

__all__ = [
    "ApprovalGate",
    "ApprovalStatus",
    "AuthStatus",
    "Base",
    "Engagement",
    "EngagementStatus",
    "EnvironmentLabel",
    "Organization",
    "ROEAcknowledgement",
    "ScanIntensity",
    "ScopeItem",
    "ScopeKind",
    "ScopeMatcher",
    "Session",
    "Target",
    "TargetType",
    "User",
    "UserRole",
]
