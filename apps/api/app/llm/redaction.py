"""Redaction-before-egress (M2-B2, TRD TR-16.2, TM-5).

Before any *hosted* model call, sensitive data is scrubbed from the prompt. This
is defense-in-depth, not the sole control — the `hosted_models_allowed` gate is
what authorizes hosted egress at all; redaction reduces the blast radius of what
leaves the box when it is authorized.

The `Redactor` Protocol keeps the detector swappable. The MVP `RegexRedactor`
does a secret/high-entropy scan plus high-confidence identifier patterns
(emails, IPs, private keys, cloud/API tokens, JWTs, auth headers). A
Presidio-class NER detector can replace it behind the same interface without
touching the facade — recorded as the upgrade path in SECURITY_DEVELOPMENT_PLAN.

Fail-closed contract: if `redact_text` raises, the facade blocks egress
(RedactionFailedError). A redactor must therefore raise rather than return
partially-scrubbed text when it cannot complete.
"""

import math
import re
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from app.llm.base import LLMMessage


@runtime_checkable
class Redactor(Protocol):
    def redact_text(self, text: str) -> tuple[str, list[str]]:
        """Return (scrubbed_text, labels_redacted). Raise if it cannot complete
        — the caller treats any exception as "block egress"."""
        ...


# High-confidence structural patterns. Order matters: the most specific /
# longest matches (PEM blocks, JWTs) run before the broad token scan so a key is
# labelled by what it is, not swallowed as a generic secret.
_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "private_key",
        re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----.*?"
            r"-----END (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----",
            re.DOTALL,
        ),
    ),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")),
    (
        "auth_header",
        re.compile(r"(?i)\b(?:authorization|proxy-authorization)\s*[:=]\s*\S+"),
    ),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[0-9A-Z]{12,}\b")),
    # Provider-style prefixed secrets (sk-..., ghp_..., xoxb-...): a known prefix
    # followed by a long token body.
    (
        "prefixed_token",
        re.compile(r"\b(?:sk|pk|rk|ghp|gho|ghs|ghr|xox[baprs]|glpat)[-_][A-Za-z0-9_-]{16,}\b"),
    ),
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("ipv4", re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")),
)

# Candidate tokens for the entropy scan: long unbroken runs of secret-ish
# characters. A candidate is redacted only if its Shannon entropy clears the
# threshold, so ordinary long words (all lowercase, low entropy) are left alone.
_TOKEN_CANDIDATE = re.compile(r"\b[A-Za-z0-9+/=_-]{24,}\b")
_ENTROPY_BITS_PER_CHAR = 3.5


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    length = len(value)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


@dataclass(frozen=True)
class RegexRedactor:
    """MVP redactor. Deterministic, dependency-light, air-gap-safe."""

    entropy_threshold: float = _ENTROPY_BITS_PER_CHAR

    def redact_text(self, text: str) -> tuple[str, list[str]]:
        labels: list[str] = []
        redacted = text
        for label, pattern in _PATTERNS:
            if pattern.search(redacted):
                redacted = pattern.sub(f"[REDACTED:{label}]", redacted)
                labels.append(label)

        def _entropy_sub(match: re.Match[str]) -> str:
            token = match.group(0)
            if _shannon_entropy(token) >= self.entropy_threshold:
                labels.append("high_entropy")
                return "[REDACTED:secret]"
            return token

        redacted = _TOKEN_CANDIDATE.sub(_entropy_sub, redacted)
        # De-dup while preserving first-seen order (for the audit trail).
        seen: dict[str, None] = {}
        for label in labels:
            seen.setdefault(label, None)
        return redacted, list(seen)


def redact_messages(
    redactor: Redactor, system: str | None, messages: list[LLMMessage]
) -> tuple[str | None, list[LLMMessage], list[str]]:
    """Scrub the system prompt and every message. Returns the scrubbed pair plus
    the union of labels redacted. Any exception from the redactor propagates —
    the facade turns it into a blocked egress."""
    all_labels: list[str] = []
    new_system = system
    if system is not None:
        new_system, labels = redactor.redact_text(system)
        all_labels.extend(labels)
    new_messages: list[LLMMessage] = []
    for message in messages:
        scrubbed, labels = redactor.redact_text(message.content)
        all_labels.extend(labels)
        new_messages.append(LLMMessage(role=message.role, content=scrubbed))
    return new_system, new_messages, all_labels
