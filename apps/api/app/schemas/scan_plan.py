"""Scan-plan API schemas (M4) — deterministic next-scan recommendations."""

import uuid

from pydantic import BaseModel

from app.services.scan_plan import ScanPlan, ScanRecommendation


class ScanRecommendationOut(BaseModel):
    scanner: str
    category: str
    reason: str
    already_run: bool

    @classmethod
    def from_obj(cls, r: ScanRecommendation) -> "ScanRecommendationOut":
        return cls(
            scanner=r.scanner, category=r.category, reason=r.reason, already_run=r.already_run
        )


class ScanPlanOut(BaseModel):
    target_id: uuid.UUID
    target_type: str
    detected_technologies: list[str]
    endpoints_discovered: int
    recommendations: list[ScanRecommendationOut]

    @classmethod
    def from_obj(cls, p: ScanPlan) -> "ScanPlanOut":
        return cls(
            target_id=p.target_id,
            target_type=p.target_type,
            detected_technologies=p.detected_technologies,
            endpoints_discovered=p.endpoints_discovered,
            recommendations=[ScanRecommendationOut.from_obj(r) for r in p.recommendations],
        )
