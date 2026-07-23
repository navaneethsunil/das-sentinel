"""SQLAlchemy models. Importing this package registers every table on
Base.metadata (which Alembic autogenerate/check runs against)."""

from app.models.audit import AuditEvent, AuditOutcome
from app.models.base import Base
from app.models.compliance import (
    ComplianceControl,
    ComplianceFramework,
    FindingComplianceMapping,
)
from app.models.cvss import CvssScore, CvssVersion
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
from app.models.evidence import Evidence, EvidenceKind
from app.models.finding import (
    Finding,
    FindingEvidence,
    FindingProvenance,
    FindingStatus,
    FindingStatusHistory,
    SarifLevel,
    Severity,
)
from app.models.identity import Organization, Session, User, UserRole
from app.models.llm import LLMInteraction, LLMPurpose
from app.models.scan import (
    ExecutionAuthorization,
    Scan,
    ScanStatus,
    TestRun,
    TestSuite,
)
from app.models.scanner import ScannerRun
from app.models.target import AuthStatus, EnvironmentLabel, Target, TargetType

__all__ = [
    "ApprovalGate",
    "ApprovalStatus",
    "AuditEvent",
    "AuditOutcome",
    "AuthStatus",
    "Base",
    "ComplianceControl",
    "ComplianceFramework",
    "CvssScore",
    "CvssVersion",
    "Engagement",
    "EngagementStatus",
    "EnvironmentLabel",
    "Evidence",
    "EvidenceKind",
    "ExecutionAuthorization",
    "Finding",
    "FindingComplianceMapping",
    "FindingEvidence",
    "FindingProvenance",
    "FindingStatus",
    "FindingStatusHistory",
    "LLMInteraction",
    "LLMPurpose",
    "Organization",
    "ROEAcknowledgement",
    "SarifLevel",
    "Scan",
    "ScanIntensity",
    "ScannerRun",
    "ScanStatus",
    "ScopeItem",
    "ScopeKind",
    "ScopeMatcher",
    "Session",
    "Severity",
    "Target",
    "TargetType",
    "TestRun",
    "TestSuite",
    "User",
    "UserRole",
]
