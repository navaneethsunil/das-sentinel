"""least-privilege runtime DB role (SEC-DEBT-4) — SECURITY_DEVELOPMENT_PLAN, TM-9.

Provisions a restricted `postgres_app_user` role that the app/worker connect as
in production (postgres_use_app_role=true). It gets full DML on mutable tables
but only SELECT/INSERT on the append-only chain-of-custody tables — a
privilege-level floor beneath the immutability triggers: even a SQL-injection
that reached DDL could not DROP a trigger (no ownership) nor UPDATE/DELETE these
rows (no privilege). Migrations still run as the owner (get_settings runs this
against owner_database_url), which owns the tables and can always maintain them.

No-op when no app password is configured (dev single-role), so it never breaks
the trigger-only setup. The role is cluster-scoped; grants are per-database.

Revision ID: a2b4c6d8e0f2
Revises: f1a2c3d4e5f6
Create Date: 2026-07-28
"""

import sqlalchemy as sa
from alembic import op

from app.core.config import get_settings

revision = "a2b4c6d8e0f2"
down_revision = "f1a2c3d4e5f6"
branch_labels = None
depends_on = None

# The chain-of-custody / audit tables carrying a raising UPDATE/DELETE trigger
# (grep: BEFORE UPDATE OR DELETE ON …). The app role gets SELECT/INSERT only.
APPEND_ONLY = (
    "audit_events",
    "evidence",
    "execution_authorizations",
    "finding_status_history",
    "llm_interactions",
    "retests",
    "roe_acknowledgements",
)


def _ident(name: str) -> str:
    # Config-derived identifier (never user input); quote defensively anyway.
    return '"' + name.replace('"', '""') + '"'


def upgrade() -> None:
    settings = get_settings()
    if settings.postgres_app_password is None:
        return  # dev single-role: the triggers remain the role-independent floor
    conn = op.get_bind()
    role = _ident(settings.postgres_app_user)
    db = _ident(settings.postgres_db)
    pw_literal = "'" + settings.postgres_app_password.get_secret_value().replace("'", "''") + "'"

    exists = conn.execute(
        sa.text("SELECT 1 FROM pg_roles WHERE rolname = :r"),
        {"r": settings.postgres_app_user},
    ).scalar()
    verb = "ALTER" if exists else "CREATE"
    # DDL cannot bind identifiers/passwords; values are config-derived + escaped.
    conn.execute(sa.text(f"{verb} ROLE {role} WITH LOGIN PASSWORD {pw_literal}"))  # noqa: S608

    conn.execute(sa.text(f"GRANT CONNECT ON DATABASE {db} TO {role}"))
    conn.execute(sa.text(f"GRANT USAGE ON SCHEMA public TO {role}"))
    conn.execute(
        sa.text(f"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {role}")
    )
    conn.execute(sa.text(f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {role}"))
    for table in APPEND_ONLY:
        conn.execute(sa.text(f"REVOKE UPDATE, DELETE ON {_ident(table)} FROM {role}"))
    # Future owner-created tables default to full DML for the app role; a new
    # append-only table must REVOKE UPDATE/DELETE in its own migration.
    conn.execute(
        sa.text(
            f"ALTER DEFAULT PRIVILEGES IN SCHEMA public "
            f"GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {role}"
        )
    )
    conn.execute(
        sa.text(
            f"ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO {role}"
        )
    )


def downgrade() -> None:
    settings = get_settings()
    if settings.postgres_app_password is None:
        return
    conn = op.get_bind()
    role = _ident(settings.postgres_app_user)
    db = _ident(settings.postgres_db)
    if not conn.execute(
        sa.text("SELECT 1 FROM pg_roles WHERE rolname = :r"),
        {"r": settings.postgres_app_user},
    ).scalar():
        return
    # Reverse in dependency order so DROP ROLE has no lingering grants/defaults.
    conn.execute(
        sa.text("ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM " + role)
    )
    conn.execute(
        sa.text("ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON SEQUENCES FROM " + role)
    )
    conn.execute(sa.text(f"REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM {role}"))
    conn.execute(sa.text(f"REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM {role}"))
    conn.execute(sa.text(f"REVOKE USAGE ON SCHEMA public FROM {role}"))
    conn.execute(sa.text(f"REVOKE ALL PRIVILEGES ON DATABASE {db} FROM {role}"))
    conn.execute(sa.text(f"DROP ROLE IF EXISTS {role}"))
