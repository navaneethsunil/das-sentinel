"""Opaque server-side session lifecycle (M1-B2) — ARCHITECTURE §5.1, §13.

Not JWT: the raw token is a 256-bit random value returned to the client in a
`__Host-` cookie; only its SHA-256 is ever stored. Every request re-validates
against the store (Valkey cache → Postgres), so revocation, forced logout, and
kill-all are instant — a stateless token can't offer that.

Instant revocation depends on write-through cache invalidation: revoke deletes
the Valkey entry AND stamps `revoked_at`, so a revoked session can't outlive
its cache TTL. The short cache TTL is only a backstop. Every validation path
fails closed — any error, miss, expiry, or revocation returns None.
"""

import hashlib
import json
import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from fastapi import Response
from redis.asyncio import Redis
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.models.identity import Session, User, UserRole

TOKEN_BYTES = 32  # 256-bit opaque token
CACHE_PREFIX = "session:"


def generate_token() -> str:
    """URL-safe high-entropy session token (never stored; only its hash is)."""
    return secrets.token_urlsafe(TOKEN_BYTES)


def hash_token(token: str) -> bytes:
    """SHA-256 of the token. Plain fast hash is correct — the token is already
    high-entropy and unguessable, so a KDF would be over-engineering."""
    return hashlib.sha256(token.encode()).digest()


@dataclass(frozen=True)
class ValidatedSession:
    session_id: uuid.UUID
    user_id: uuid.UUID
    role: UserRole


class SessionService:
    def __init__(self, db: AsyncSession, cache: Redis, settings: Settings) -> None:
        self._db = db
        self._cache = cache
        self._settings = settings

    def _cache_key(self, token_hash: bytes) -> str:
        return f"{CACHE_PREFIX}{token_hash.hex()}"

    async def _cache_write(
        self, token_hash: bytes, session_id: uuid.UUID, user: "SessionUser"
    ) -> None:
        snapshot = {
            "session_id": str(session_id),
            "user_id": str(user.user_id),
            "role": user.role.value,
            "idle_expires_at": user.idle_expires_at.isoformat(),
            "absolute_expires_at": user.absolute_expires_at.isoformat(),
        }
        await self._cache.set(
            self._cache_key(token_hash),
            json.dumps(snapshot),
            ex=self._settings.session_cache_ttl_seconds,
        )

    async def _cache_drop(self, token_hash: bytes) -> None:
        await self._cache.delete(self._cache_key(token_hash))

    async def create_session(
        self,
        user_id: uuid.UUID,
        role: UserRole,
        *,
        now: datetime,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> str:
        """Issue a new session; return the raw token to set in the cookie."""
        token = generate_token()
        token_hash = hash_token(token)
        idle = now + timedelta(seconds=self._settings.session_idle_ttl_seconds)
        absolute = now + timedelta(seconds=self._settings.session_absolute_ttl_seconds)

        session = Session(
            user_id=user_id,
            token_hash=token_hash,
            created_at=now,
            last_seen_at=now,
            idle_expires_at=idle,
            absolute_expires_at=absolute,
            ip_address=ip_address,
            user_agent=user_agent,
        )
        self._db.add(session)
        await self._db.flush()

        await self._cache_write(
            token_hash,
            session.id,
            SessionUser(user_id, role, idle, absolute),
        )
        return token

    async def regenerate_on_login(
        self,
        old_token: str | None,
        user_id: uuid.UUID,
        role: UserRole,
        *,
        now: datetime,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> str:
        """Session-fixation defense: revoke any pre-login session and mint a
        fresh id (ARCHITECTURE §13 — the most common auth gap)."""
        if old_token:
            await self.revoke_session(old_token, now=now)
        return await self.create_session(
            user_id, role, now=now, ip_address=ip_address, user_agent=user_agent
        )

    async def validate_session(self, token: str, *, now: datetime) -> ValidatedSession | None:
        token_hash = hash_token(token)

        cached = await self._cache.get(self._cache_key(token_hash))
        if cached is not None:
            snapshot = json.loads(cached)
            absolute = datetime.fromisoformat(snapshot["absolute_expires_at"])
            idle = datetime.fromisoformat(snapshot["idle_expires_at"])
            if now < absolute and now < idle:
                await self._slide(token_hash, now)
                return ValidatedSession(
                    uuid.UUID(snapshot["session_id"]),
                    uuid.UUID(snapshot["user_id"]),
                    UserRole(snapshot["role"]),
                )
            # Cache says expired — fall through to DB (which is authoritative).

        row = (
            await self._db.execute(
                select(Session, User.role)
                .join(User, Session.user_id == User.id)
                .where(Session.token_hash == token_hash)
            )
        ).one_or_none()
        if row is None:
            return None
        session, role = row

        if (
            session.revoked_at is not None
            or now >= session.absolute_expires_at
            or now >= session.idle_expires_at
            or not await self._user_is_active(session.user_id)
        ):
            # Revoked/expired in DB — ensure any stale cache entry is gone.
            await self._cache_drop(token_hash)
            return None

        session.idle_expires_at = now + timedelta(seconds=self._settings.session_idle_ttl_seconds)
        session.last_seen_at = now
        await self._db.flush()
        await self._cache_write(
            token_hash,
            session.id,
            SessionUser(
                session.user_id, role, session.idle_expires_at, session.absolute_expires_at
            ),
        )
        return ValidatedSession(session.id, session.user_id, role)

    async def _slide(self, token_hash: bytes, now: datetime) -> None:
        idle = now + timedelta(seconds=self._settings.session_idle_ttl_seconds)
        await self._db.execute(
            update(Session)
            .where(Session.token_hash == token_hash, Session.revoked_at.is_(None))
            .values(idle_expires_at=idle, last_seen_at=now)
        )
        await self._db.flush()
        # Refresh the cached idle window so the slide is visible on cache hits.
        cached = await self._cache.get(self._cache_key(token_hash))
        if cached is not None:
            snapshot = json.loads(cached)
            snapshot["idle_expires_at"] = idle.isoformat()
            await self._cache.set(
                self._cache_key(token_hash),
                json.dumps(snapshot),
                ex=self._settings.session_cache_ttl_seconds,
            )

    async def _user_is_active(self, user_id: uuid.UUID) -> bool:
        active = (
            await self._db.execute(select(User.is_active).where(User.id == user_id))
        ).scalar_one_or_none()
        return bool(active)

    async def revoke_session(self, token: str, *, now: datetime) -> None:
        """Logout: revoke a single session by its raw token (write-through)."""
        token_hash = hash_token(token)
        await self._db.execute(
            update(Session)
            .where(Session.token_hash == token_hash, Session.revoked_at.is_(None))
            .values(revoked_at=now)
        )
        await self._db.flush()
        await self._cache_drop(token_hash)

    async def revoke_all_for_user(
        self, user_id: uuid.UUID, *, now: datetime, except_session_id: uuid.UUID | None = None
    ) -> int:
        """Kill-all-sessions (also used on password/role change). Returns the
        count revoked. Write-through: every affected cache entry is dropped."""
        stmt = select(Session.id, Session.token_hash).where(
            Session.user_id == user_id, Session.revoked_at.is_(None)
        )
        if except_session_id is not None:
            stmt = stmt.where(Session.id != except_session_id)
        rows = (await self._db.execute(stmt)).all()

        revoke = (
            update(Session)
            .where(Session.user_id == user_id, Session.revoked_at.is_(None))
            .values(revoked_at=now)
        )
        if except_session_id is not None:
            revoke = revoke.where(Session.id != except_session_id)
        await self._db.execute(revoke)
        await self._db.flush()

        for _session_id, token_hash in rows:
            await self._cache_drop(token_hash)
        return len(rows)


@dataclass(frozen=True)
class SessionUser:
    """Fields needed to write a cache snapshot for a session."""

    user_id: uuid.UUID
    role: UserRole
    idle_expires_at: datetime
    absolute_expires_at: datetime


def utcnow() -> datetime:
    return datetime.now(UTC)


def set_session_cookie(response: Response, token: str, settings: Settings) -> None:
    """Attach the opaque token to the response as a `__Host-` cookie.

    __Host- requires Secure, Path=/, and no Domain — set explicitly so the
    prefix stays valid. SameSite=Strict is the CSRF baseline (a synchronizer
    token is added on state-changing routes in M1-SEC2). No Max-Age: it is a
    session cookie; server-side idle/absolute expiry is authoritative.
    """
    response.set_cookie(
        settings.session_cookie_name,
        token,
        httponly=True,
        secure=True,
        samesite="strict",
        path="/",
    )


def clear_session_cookie(response: Response, settings: Settings) -> None:
    response.delete_cookie(
        settings.session_cookie_name,
        httponly=True,
        secure=True,
        samesite="strict",
        path="/",
    )
