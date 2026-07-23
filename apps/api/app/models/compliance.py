"""Compliance-mapping models (M3-D2) — DATABASE_SCHEMA §10.

Frameworks and controls are lookup TABLES, not enums: the sets extend often
(OWASP LLM 2025, OWASP Agentic 2026, WSTG v4.2, NIST AI RMF + 600-1, 800-53
Rev 5.2.0, 800-115) so a native enum would be the wrong tool (§general-conventions).
Seeded from the versioned KB in packages/compliance/ at M3-B4.

finding_compliance_mappings records HOW a mapping was produced via mapped_by
(reusing finding_provenance — an auto/AI/human distinction, same as findings)
with an optional confidence when LLM-assisted; the LLM never sets a finding's
severity/status, only proposes a draft mapping a human can accept (§2.6/§2.9).

finding_provenance is reused (from the M2-D1 finding migration).
"""

import uuid

from sqlalchemy import ForeignKey, Numeric, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base
from app.models.finding import FINDING_PROVENANCE_ENUM, FindingProvenance
from app.models.identity import GEN_UUID, UUID_PK


class ComplianceFramework(Base):
    __tablename__ = "compliance_frameworks"

    id: Mapped[uuid.UUID] = mapped_column(UUID_PK, primary_key=True, server_default=GEN_UUID)
    # e.g. 'owasp_llm_2025','nist_800_53_r5','nist_800_115'
    key: Mapped[str] = mapped_column(Text, unique=True)
    name: Mapped[str] = mapped_column(Text)
    version: Mapped[str] = mapped_column(Text)
    source_url: Mapped[str | None] = mapped_column(Text)


class ComplianceControl(Base):
    __tablename__ = "compliance_controls"
    __table_args__ = (
        UniqueConstraint("framework_id", "code", name="uq_compliance_controls_framework_id_code"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID_PK, primary_key=True, server_default=GEN_UUID)
    framework_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("compliance_frameworks.id", ondelete="CASCADE")
    )
    code: Mapped[str] = mapped_column(Text)  # 'LLM01','AC-6','WSTG-ATHZ-02',…
    title: Mapped[str] = mapped_column(Text)
    description: Mapped[str | None] = mapped_column(Text)


class FindingComplianceMapping(Base):
    """Many-to-many finding↔control with provenance of the mapping itself."""

    __tablename__ = "finding_compliance_mappings"

    finding_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), primary_key=True
    )
    control_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("compliance_controls.id", ondelete="RESTRICT"), primary_key=True
    )
    mapped_by: Mapped[FindingProvenance] = mapped_column(
        FINDING_PROVENANCE_ENUM, server_default=FindingProvenance.AUTOMATED.value
    )
    # 0–1 when LLM-assisted.
    confidence: Mapped[float | None] = mapped_column(Numeric(3, 2))
