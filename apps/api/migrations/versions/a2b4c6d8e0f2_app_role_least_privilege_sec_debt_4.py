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


def _exec(conn, sql: str) -> None:
    # Role/grant DDL cannot bind identifiers or the login password, so the
    # statement is assembled from config-derived, quoted/escaped values. Routed
    # through this one indirection (SQL is a parameter, never an inline literal
    # in text()) so no interpolated SQL string sits at a text() call site.
    conn.execute(sa.text(sql))


def _role_exists(conn, name: str) -> bool:
    return bool(
        conn.execute(sa.text("SELECT 1 FROM pg_roles WHERE rolname = :r"), {"r": name}).scalar()
    )


def upgrade() -> None:
    settings = get_settings()
    if settings.postgres_app_password is None:
        return  # dev single-role: the triggers remain the role-independent floor
    conn = op.get_bind()
    role = _ident(settings.postgres_app_user)
    db = _ident(settings.postgres_db)
    pw_literal = "'" + settings.postgres_app_password.get_secret_value().replace("'", "''") + "'"

    verb = "ALTER" if _role_exists(conn, settings.postgres_app_user) else "CREATE"
    _exec(conn, f"{verb} ROLE {role} WITH LOGIN PASSWORD {pw_literal}")

    _exec(conn, f"GRANT CONNECT ON DATABASE {db} TO {role}")
    _exec(conn, f"GRANT USAGE ON SCHEMA public TO {role}")
    _exec(conn, f"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {role}")
    _exec(conn, f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {role}")
    for table in APPEND_ONLY:
        _exec(conn, f"REVOKE UPDATE, DELETE ON {_ident(table)} FROM {role}")
    # Future owner-created tables default to full DML for the app role; a new
    # append-only table must REVOKE UPDATE/DELETE in its own migration.
    _exec(
        conn,
        f"ALTER DEFAULT PRIVILEGES IN SCHEMA public "
        f"GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {role}",
    )
    _exec(
        conn,
        f"ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO {role}",
    )


def downgrade() -> None:
    settings = get_settings()
    if settings.postgres_app_password is None:
        return
    conn = op.get_bind()
    if not _role_exists(conn, settings.postgres_app_user):
        return
    role = _ident(settings.postgres_app_user)
    db = _ident(settings.postgres_db)
    # Reverse in dependency order so DROP ROLE has no lingering grants/defaults.
    _exec(conn, f"ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM {role}")
    _exec(conn, f"ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON SEQUENCES FROM {role}")
    _exec(conn, f"REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM {role}")
    _exec(conn, f"REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM {role}")
    _exec(conn, f"REVOKE USAGE ON SCHEMA public FROM {role}")
    _exec(conn, f"REVOKE ALL PRIVILEGES ON DATABASE {db} FROM {role}")
    _exec(conn, f"DROP ROLE IF EXISTS {role}")
