"""Identity & access models (M1-D1) — DATABASE_SCHEMA.md §3.

Multi-tenancy: users hang off organizations from day one so row-level scoping
can be enabled later without reshaping (single-org enforcement for now).
Sessions are opaque and server-side (NOT JWT): only the SHA-256 of the cookie
token is stored, never the token itself.
"""

import enum
import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    LargeBinary,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import CITEXT, INET, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base

# App supplies UUIDv7 where possible (time-ordered, smaller indexes);
# gen_random_uuid() (v4) is the DB-side fallback (DATABASE_SCHEMA.md §1).
UUID_PK = UUID(as_uuid=True)
GEN_UUID = text("gen_random_uuid()")
NOW = text("now()")


class UserRole(enum.Enum):
    ADMIN = "admin"
    TESTER = "tester"
    REVIEWER = "reviewer"
    READ_ONLY = "read_only"


USER_ROLE_ENUM = Enum(
    UserRole,
    name="user_role",
    values_callable=lambda e: [member.value for member in e],
)


class Organization(Base):
    __tablename__ = "organizations"

    id: Mapped[uuid.UUID] = mapped_column(UUID_PK, primary_key=True, server_default=GEN_UUID)
    name: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=NOW)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=NOW)

    users: Mapped[list["User"]] = relationship(back_populates="organization")


class User(Base):
    __tablename__ = "users"
    __table_args__ = (UniqueConstraint("organization_id", "email"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID_PK, primary_key=True, server_default=GEN_UUID)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="RESTRICT")
    )
    # citext: case-insensitive uniqueness in the DB itself, not app-side folding.
    email: Mapped[str] = mapped_column(CITEXT)
    # Argon2id (or PBKDF2 if the FIPS gate flips — CLAUDE.md §3); hashing lands in M1-B1.
    password_hash: Mapped[str] = mapped_column(Text)
    display_name: Mapped[str] = mapped_column(Text)
    role: Mapped[UserRole] = mapped_column(USER_ROLE_ENUM, server_default=UserRole.READ_ONLY.value)
    is_active: Mapped[bool] = mapped_column(Boolean, server_default=text("true"))
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=NOW)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=NOW)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    organization: Mapped[Organization] = relationship(back_populates="users")
    sessions: Mapped[list["Session"]] = relationship(back_populates="user")


class Session(Base):
    __tablename__ = "sessions"
    __table_args__ = (
        # Hot path: validate-per-request looks up live sessions for a user.
        Index(
            "ix_sessions_user_active",
            "user_id",
            postgresql_where=text("revoked_at IS NULL"),
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID_PK, primary_key=True, server_default=GEN_UUID)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    # SHA-256 (32 raw bytes) of the high-entropy cookie value; plain fast hash is
    # correct here — the token is unguessable, a KDF would be over-engineering.
    token_hash: Mapped[bytes] = mapped_column(LargeBinary, unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=NOW)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=NOW)
    idle_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    absolute_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ip_address: Mapped[str | None] = mapped_column(INET)
    user_agent: Mapped[str | None] = mapped_column(Text)

    user: Mapped[User] = relationship(back_populates="sessions")
