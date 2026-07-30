"""Target helpers (M1-B10).

auth_config must hold *references* to credentials (a secrets-manager key id, a
vault path), never plaintext secrets (TR-23, CLAUDE.md §11). We enforce this by
rejecting keys whose names indicate raw secret material unless they are clearly
reference handles (…_ref/_id/_uri/_arn/_name). Fail closed: a suspicious key is
rejected even if it might be benign — rename it to a reference form.
"""

import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.target import Target

# Substrings that indicate raw secret material in a key name.
_SECRET_MARKERS = (
    "password",
    "passwd",
    "secret",
    "token",
    "credential",
    "api_key",
    "apikey",
    "private_key",
    "privatekey",
)
_SECRET_EXACT = frozenset({"key", "pass", "pwd"})
# A key ending in one of these is a reference, not the secret itself.
_REFERENCE_SUFFIXES = ("_ref", "_id", "_uri", "_arn", "_name", "_url")
# Recognized reference schemes a `*_ref` value must use — the credential store
# (cred:), an environment variable (env:), or a future external manager (vault:).
# This is what makes "references only" enforceable on VALUES, not just key names:
# a plaintext secret under an innocuous `*_ref` key is now rejected too.
_REFERENCE_SCHEMES = ("cred:", "env:", "vault:")


def _key_is_plaintext_secret(key: str) -> bool:
    lowered = key.lower()
    if lowered.endswith(_REFERENCE_SUFFIXES):
        return False
    if lowered in _SECRET_EXACT:
        return True
    return any(marker in lowered for marker in _SECRET_MARKERS)


def validate_auth_config_references(auth_config: dict[str, Any] | None) -> None:
    """Raise ValueError if auth_config appears to embed a plaintext secret.

    Two gates: (1) a key whose NAME indicates raw secret material is rejected, and
    (2) a string VALUE under a `*_ref` key must be one of the recognized reference
    schemes — so `{"api_key_ref": "hunter2"}` (a plaintext secret hiding under a
    reference-shaped key) no longer slips into the DB in the clear."""
    if auth_config is None:
        return

    def _walk(node: Any, path: str) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                key_str = str(key)
                if _key_is_plaintext_secret(key_str):
                    raise ValueError(
                        f"auth_config.{path}{key} looks like a plaintext secret; "
                        "store a reference instead (e.g. '<name>_ref')"
                    )
                if (
                    key_str.lower().endswith("_ref")
                    and isinstance(value, str)
                    and not value.startswith(_REFERENCE_SCHEMES)
                ):
                    raise ValueError(
                        f"auth_config.{path}{key} must be a credential reference "
                        f"({', '.join(_REFERENCE_SCHEMES)}<…>), not a plaintext value"
                    )
                _walk(value, f"{path}{key}.")
        elif isinstance(node, list):
            for i, item in enumerate(node):
                _walk(item, f"{path}{i}.")

    _walk(auth_config, "")


async def get_org_target(
    db: AsyncSession, engagement_id: uuid.UUID, target_id: uuid.UUID, org_id: uuid.UUID
) -> Target | None:
    """Fetch a live target within an engagement that belongs to the caller's org,
    or None (router maps to 404 — no cross-org/cross-engagement leak)."""
    return (
        await db.execute(
            select(Target)
            .join(Target.engagement)
            .where(
                Target.id == target_id,
                Target.engagement_id == engagement_id,
                Target.deleted_at.is_(None),
                Target.engagement.has(organization_id=org_id),
            )
        )
    ).scalar_one_or_none()
