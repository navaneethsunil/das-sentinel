"""Compliance mapping schemas (M3-B4)."""

import uuid

from pydantic import BaseModel

from app.models.compliance import ComplianceControl, ComplianceFramework
from app.models.finding import FindingProvenance


class ControlOut(BaseModel):
    id: uuid.UUID
    code: str
    title: str
    description: str | None

    @classmethod
    def from_model(cls, c: ComplianceControl) -> "ControlOut":
        return cls(id=c.id, code=c.code, title=c.title, description=c.description)


class FrameworkOut(BaseModel):
    id: uuid.UUID
    key: str
    name: str
    version: str
    source_url: str | None
    controls: list[ControlOut]

    @classmethod
    def from_model(
        cls, f: ComplianceFramework, controls: list[ComplianceControl]
    ) -> "FrameworkOut":
        return cls(
            id=f.id,
            key=f.key,
            name=f.name,
            version=f.version,
            source_url=f.source_url,
            controls=[ControlOut.from_model(c) for c in controls],
        )


class MappingOut(BaseModel):
    """A finding↔control mapping with the control + framework it points at."""

    control_id: uuid.UUID
    framework_key: str
    framework_name: str
    code: str
    title: str
    mapped_by: FindingProvenance
    confidence: float | None


class MappingCreateIn(BaseModel):
    control_id: uuid.UUID


class AutoMapOut(BaseModel):
    """Result of an auto-map run: how many mappings were newly created."""

    created: int
    control_ids: list[uuid.UUID]
