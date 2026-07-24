"""Automated remediation guidance (M4-B1) — DRAFT, human-reviewed.

Produces per-finding remediation guidance with our own LLM, under the exact
M2-SEC2 triage guardrails (TM-4): the finding + its captured (attacker-
influenceable) evidence travel as clearly-delimited UNTRUSTED DATA; the only
instructions are the platform system prompt; output is structured-only with NO
status/severity/fixed channel; every cited evidence pointer must resolve to a
real linked record (invented pointer ⇒ reject fail-closed).

The result is persisted as an `is_ai_generated` `remediations` row for human
review (CLAUDE.md §2.9/§7) — generating it NEVER mutates the finding or marks it
fixed. A `patch_suggestion`, if present, is always surfaced with a
`PATCH_REVIEW_NOTICE` ("requires developer review") and is never auto-applied.
"""

import uuid
from dataclasses import dataclass

from sqlalchemy.ext.asyncio import AsyncSession

from app.llm import LLMService
from app.llm.base import LLMMessage
from app.models.engagement import Engagement
from app.models.finding import Finding
from app.models.llm import LLMInteraction, LLMPurpose
from app.models.remediation import Remediation
from app.services.triage import (
    DEFAULT_MAX_EVIDENCE_CHARS,
    build_triage_input,
    gather_finding_evidence,
)
from app.storage.evidence import BlobStore

_REMEDIATION_PROMPT_TEMPLATE = "remediation_system@v1"
_CONFIDENCE_VALUES = ("low", "medium", "high")

# Every patch suggestion is developer-reviewed, never auto-applied (schema §9).
PATCH_REVIEW_NOTICE = "requires developer review"

# Structured-output contract. Like triage, it has NO status/severity/fixed field
# — the model has no channel to declare a platform decision (TM-4).
REMEDIATION_OUTPUT_SCHEMA: dict = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        # Plain-English: root cause + fix + verification + standards refs (schema §9).
        "guidance_text": {"type": "string", "maxLength": 12000},
        "secure_code_example": {"type": "string", "maxLength": 8000},
        "patch_suggestion": {"type": "string", "maxLength": 8000},
        "confidence": {"type": "string", "enum": list(_CONFIDENCE_VALUES)},
        "cited_evidence": {"type": "array", "items": {"type": "string"}, "maxItems": 64},
    },
    "required": ["guidance_text", "cited_evidence"],
}


class RemediationError(Exception):
    """Base for remediation-generation failures."""


class RemediationRejected(RemediationError):
    """The model's output failed a guardrail and is discarded fail-closed: not
    structured output, missing guidance, or an invented evidence pointer. The
    finding is never touched."""


@dataclass(frozen=True)
class RemediationDraft:
    """Validated DRAFT guidance (no status/severity/action channel, TM-4)."""

    finding_id: uuid.UUID
    guidance_text: str
    secure_code_example: str | None
    patch_suggestion: str | None
    confidence: str | None
    cited_evidence_ids: list[uuid.UUID]


def _opt_str(value: object) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


def evaluate_remediation_output(
    structured: object,
    *,
    allowed_labels: dict[str, uuid.UUID],
    finding_id: uuid.UUID,
) -> RemediationDraft:
    """Pure guardrail: validate the model's structured output into a draft, or
    reject fail-closed. Status/severity/fixed are never read; every cited evidence
    label must be one we provided (else it is invented and the draft is rejected)."""
    if not isinstance(structured, dict):
        raise RemediationRejected("model returned no structured output (structured-output-only)")

    guidance = structured.get("guidance_text")
    if not isinstance(guidance, str) or not guidance.strip():
        raise RemediationRejected("remediation output is missing guidance_text")

    cited = structured.get("cited_evidence", [])
    if not isinstance(cited, list):
        raise RemediationRejected("cited_evidence must be a list")
    resolved: list[uuid.UUID] = []
    for label in cited:
        if not isinstance(label, str) or label not in allowed_labels:
            raise RemediationRejected(
                f"cited evidence pointer {label!r} does not resolve to a linked "
                "evidence record (invented pointer)"
            )
        resolved.append(allowed_labels[label])

    confidence = structured.get("confidence")
    return RemediationDraft(
        finding_id=finding_id,
        guidance_text=guidance.strip(),
        secure_code_example=_opt_str(structured.get("secure_code_example")),
        patch_suggestion=_opt_str(structured.get("patch_suggestion")),
        confidence=confidence if confidence in _CONFIDENCE_VALUES else None,
        cited_evidence_ids=resolved,
    )


async def generate_remediation(
    session: AsyncSession,
    llm: LLMService,
    store: BlobStore,
    *,
    engagement: Engagement,
    finding: Finding,
    created_by: uuid.UUID | None = None,
    max_evidence_chars: int = DEFAULT_MAX_EVIDENCE_CHARS,
    load_evidence_items=gather_finding_evidence,
) -> tuple[Remediation, LLMInteraction, RemediationDraft]:
    """Generate DRAFT remediation guidance for `finding` and persist it as an
    `is_ai_generated` `remediations` row (flushed into the caller's transaction).
    Raises `RemediationRejected` fail-closed on any guardrail violation — the
    finding is never mutated. `load_evidence_items` is injectable for testing."""
    loaded = await load_evidence_items(session, store, finding.id)
    labelled = [(f"E{i}", item) for i, item in enumerate(loaded, start=1)]
    allowed_labels = {label: item.evidence_id for label, item in labelled}

    from app.llm.prompts import load_prompt

    system = load_prompt("remediation_system").body
    user = build_triage_input(finding, labelled, max_evidence_chars=max_evidence_chars)

    result, interaction = await llm.complete(
        session,
        organization_id=engagement.organization_id,
        engagement=engagement,
        purpose=LLMPurpose.REMEDIATION,
        system=system,
        messages=[LLMMessage(role="user", content=user)],
        output_schema=REMEDIATION_OUTPUT_SCHEMA,
        prompt_template=_REMEDIATION_PROMPT_TEMPLATE,
        ref_object_type="finding",
        ref_object_id=finding.id,
    )

    draft = evaluate_remediation_output(
        result.structured, allowed_labels=allowed_labels, finding_id=finding.id
    )
    row = Remediation(
        finding_id=finding.id,
        guidance_text=draft.guidance_text,
        secure_code_example=draft.secure_code_example,
        patch_suggestion=draft.patch_suggestion,
        is_ai_generated=True,
        created_by=created_by,
    )
    session.add(row)
    await session.flush()
    return row, interaction, draft
