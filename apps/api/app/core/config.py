"""Single Settings object — the only place configuration enters the app (CLAUDE.md §5).

Every host, key, and model name comes from the environment (see `.env.example` at the
repo root); nothing here embeds a deployment-specific value. Import `get_settings()`
everywhere — never instantiate `Settings` directly outside tests.
"""

from functools import lru_cache
from typing import Literal
from urllib.parse import quote_plus

from pydantic import AliasChoices, Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Known dev/placeholder secret values that must never reach production (the compose
# `:-devpassword` fallbacks + the `.env.example` templates). Compared case-folded.
_WEAK_SECRETS = frozenset(
    {
        "",
        "devpassword",
        "change-me",
        "changeme",
        "password",
        "dassentinel",
        "minioadmin",
        "secret",
    }
)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # ── App ──────────────────────────────────────────────────────────────
    das_env: Literal["dev", "test", "prod"] = "dev"
    log_level: str = "INFO"
    api_root_path: str = "/api"
    # Interactive API docs (Swagger/ReDoc/openapi.json) leak the full route map +
    # schemas. Fail-safe OFF: exposed only when explicitly enabled (dev sets it in
    # .env), never on by a forgotten prod env var (ASVS V4 — SEC-DEBT-7).
    expose_api_docs: bool = False

    # ── Auth (M1-B1) ─────────────────────────────────────────────────────
    # argon2id (OWASP default) | pbkdf2_sha256 (FIPS fallback — ROADMAP gate).
    # S105 suppressed: value is a scheme *name*, not a credential — owner: core config.
    password_hash_scheme: Literal["argon2id", "pbkdf2_sha256"] = "argon2id"  # noqa: S105

    # ── Sessions (M1-B2) ─────────────────────────────────────────────────
    # __Host- prefix implies Secure + Path=/ + no Domain (ARCHITECTURE §13).
    session_cookie_name: str = "__Host-das_session"
    # Server-enforced timeouts for a high-value tool (ARCHITECTURE §13).
    session_idle_ttl_seconds: int = 900  # 15 min sliding
    session_absolute_ttl_seconds: int = 28_800  # 8 h hard cap
    # Valkey cache TTL — short backstop; revoke is write-through, not TTL-driven.
    session_cache_ttl_seconds: int = 300

    # ── CSRF double-submit (M1-SEC2, TM-10) ──────────────────────────────
    # Non-HttpOnly on purpose: the SPA reads the cookie and echoes it in the
    # header; the match is what proves same-origin (core/csrf.py).
    csrf_cookie_name: str = "__Host-das_csrf"
    csrf_header_name: str = "X-CSRF-Token"

    # ── Login rate limiting (M1-SEC5 / SEC-DEBT-1, TM-10) ─────────────────
    # Anti-brute-force on /auth/login: Valkey sliding-window counters, keyed
    # per-IP (primary gate) and per-account (temporary, auto-expiring — never
    # an indefinite lockout, which would itself be a targeted-DoS vector,
    # CLAUDE.md §2.5). Failures increment; a correct login clears the account
    # counter. Tunable per deployment.
    login_rate_limit_window_seconds: int = 900  # 15 min rolling window
    login_rate_limit_max_per_ip: int = 30
    login_rate_limit_max_per_email: int = 5

    # ── Scan orchestration (M2-W1/W2) ────────────────────────────────────
    # How often the worker re-reads scans.cancel_requested and heartbeats while
    # a run is in flight (emergency stop, §2.10 / TM-12). Smaller = faster stop,
    # more DB polls; this is the cancellation budget's coarse bound.
    scan_cancel_poll_seconds: float = 2.0

    # ── PostgreSQL ───────────────────────────────────────────────────────
    postgres_host: str
    postgres_port: int = 5432
    # Owner/DDL role: runs migrations and owns every table. Also the admin role
    # for verify-script cleanup (needs superuser session_replication_role).
    postgres_user: str
    postgres_password: SecretStr
    postgres_db: str
    # Least-privilege runtime role (SEC-DEBT-4). When postgres_app_password is set,
    # the role migration provisions `postgres_app_user` with full DML on mutable
    # tables but only SELECT/INSERT on the append-only ones — a privilege floor
    # beneath the immutability triggers. The app/worker connect as it only when
    # postgres_use_app_role is true; migrations always run as the owner above.
    postgres_app_user: str = "das_app"
    postgres_app_password: SecretStr | None = None
    postgres_use_app_role: bool = False

    # ── Valkey (separate logical DBs per M0-W1) ──────────────────────────
    valkey_host: str
    valkey_port: int = 6379
    valkey_db_broker: int = 0
    valkey_db_results: int = 1
    valkey_db_cache: int = 2
    valkey_db_sessions: int = 3

    # ── Evidence store (dev MinIO behind the storage/ abstraction) ───────
    minio_endpoint: str
    minio_secure: bool = False
    evidence_bucket: str
    # Scoped client credentials, falling back to server root creds (dev only).
    minio_access_key: str = Field(
        validation_alias=AliasChoices("MINIO_ACCESS_KEY", "MINIO_ROOT_USER")
    )
    minio_secret_key: SecretStr = Field(
        validation_alias=AliasChoices("MINIO_SECRET_KEY", "MINIO_ROOT_PASSWORD")
    )
    # WORM chain-of-custody: every stored blob gets a COMPLIANCE object-lock
    # retention of this many days. 0 = OFF (dev default) so blobs stay deletable;
    # a positive value makes evidence undeletable until it expires (prod go-live,
    # proven via scripts/verify_worm.py against the deployed backend).
    evidence_worm_retention_days: int = 0

    # ── LLM (provider abstraction — CLAUDE.md §7) ────────────────────────
    llm_provider: Literal["anthropic", "ollama", "vllm"]
    anthropic_api_key: SecretStr | None = None
    llm_model_default: str
    llm_model_triage: str
    llm_model_classifier: str
    ollama_base_url: str | None = None
    vllm_base_url: str | None = None

    # ── Per-engagement LLM budget ceiling (M2-SEC4, TM-12) ───────────────
    # Fail-closed ceilings bounding runaway LLM work/cost per engagement,
    # summed from that engagement's `llm_interactions`. A value <= 0 disables
    # that ceiling. Tokens bound total work for any provider (local + hosted);
    # cost bounds hosted spend (local calls have no per-token charge).
    llm_max_tokens_per_engagement: int = 2_000_000
    llm_max_cost_usd_per_engagement: float = 0.0

    # ── Egress shaper (M2-SEC1, TM-1) ────────────────────────────────────
    # Comma-separated host / host:port of operator-trusted model provider
    # endpoints run traffic may reach even though they are not engagement
    # targets. Everything else is default-deny (scope + SSRF). Empty = only
    # in-scope target IPs are reachable.
    egress_provider_allowlist: str = ""

    # ── ZAP DAST scanner (M3-W3) ─────────────────────────────────────────
    # The ZAP daemon runs as a separate digest-pinned container on the internal
    # network; the adapter drives it over its API. The API key is a runtime
    # secret injected into both the daemon and the adapter — it is NEVER
    # persisted into scanner_runs.config, evidence, logs, or exports (CLAUDE.md
    # §3 scanner-secret rule, TR-23). image_digest is recorded on scanner_runs
    # for reproducibility (the exact pinned image the daemon runs).
    zap_api_url: str = "http://zap:8090"
    zap_api_key: SecretStr = SecretStr("")
    zap_image_digest: str = ""

    # ── MFA / TOTP (SEC-DEBT-2) ──────────────────────────────────────────
    # Fernet key encrypting each user's TOTP secret at rest (reversible
    # authenticator secret → must not sit in the clear on an L3 auth surface).
    # Optional: unset falls back to a fixed dev key outside prod; in prod a
    # user enrolling MFA with no key set fails closed (validated where used,
    # like the ZAP/LLM secrets — a deployment that never enables MFA still boots).
    mfa_secret_encryption_key: SecretStr | None = None
    mfa_issuer: str = "DAS Sentinel"

    # ── Compliance KB (M3-B4) ────────────────────────────────────────────
    # Versioned OWASP/NIST knowledge base (packages/compliance/*.json), seeded
    # into compliance_frameworks/controls by scripts/seed_compliance.py. Reading
    # it is a deploy/operational step (a mounted or baked KB dir), not a per-
    # request path — the API serves mappings from the DB, never the files.
    compliance_kb_dir: str = "/app/packages/compliance"

    @model_validator(mode="after")
    def _reject_weak_prod_secrets(self) -> "Settings":
        """Fail startup fast if production is running on a dev/placeholder secret
        (SEC-DEBT-11). Only the ALWAYS-required secrets are checked here — the DB
        and evidence store; on-demand secrets (ZAP, LLM) are validated where they
        are used so a deployment that doesn't run them still boots. No-op outside
        prod so dev/test keep their convenient defaults."""
        if self.das_env != "prod":
            return self
        required = [
            ("POSTGRES_PASSWORD", self.postgres_password),
            ("MINIO_SECRET_KEY", self.minio_secret_key),
        ]
        # The app-role password is only required when the app actually uses it.
        if self.postgres_use_app_role:
            required.append(("POSTGRES_APP_PASSWORD", self.postgres_app_password))
        weak = [
            name
            for name, secret in required
            if secret is None or secret.get_secret_value().strip().casefold() in _WEAK_SECRETS
        ]
        if weak:
            raise ValueError(
                f"DAS_ENV=prod but {', '.join(weak)} is unset or a known-weak default; "
                "set a strong secret before production."
            )
        return self

    def require_llm_backend(self) -> None:
        """Fail loud when the selected provider has no backend configured.

        Called by the LLM layer (`app/llm`, M2) before any client is built — not at
        startup, so an M0/M1 deployment that never touches an LLM still boots with
        an empty ANTHROPIC_API_KEY.
        """
        required = {
            "anthropic": ("ANTHROPIC_API_KEY", self.anthropic_api_key),
            "ollama": ("OLLAMA_BASE_URL", self.ollama_base_url),
            "vllm": ("VLLM_BASE_URL", self.vllm_base_url),
        }
        var, value = required[self.llm_provider]
        if value is None or (isinstance(value, SecretStr) and not value.get_secret_value()):
            raise ValueError(f"LLM_PROVIDER={self.llm_provider!r} requires {var} to be set")

    # ── Derived URLs (computed, never configured directly) ───────────────
    def _pg_url(self, user: str, password: str) -> str:
        return (
            f"postgresql+asyncpg://{quote_plus(user)}:{quote_plus(password)}@"
            f"{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @property
    def owner_database_url(self) -> str:
        """Owner/DDL role — migrations and admin/cleanup. Always postgres_user."""
        return self._pg_url(self.postgres_user, self.postgres_password.get_secret_value())

    @property
    def database_url(self) -> str:
        """Runtime connection. The restricted app role when enabled and configured
        (SEC-DEBT-4), else the owner — dev stays single-role by default."""
        if self.postgres_use_app_role and self.postgres_app_password is not None:
            return self._pg_url(
                self.postgres_app_user, self.postgres_app_password.get_secret_value()
            )
        return self.owner_database_url

    @property
    def app_role_database_url(self) -> str | None:
        """Explicit restricted-role URL for verification, ignoring the use flag;
        None when no app password is configured (role not provisioned)."""
        if self.postgres_app_password is None:
            return None
        return self._pg_url(self.postgres_app_user, self.postgres_app_password.get_secret_value())

    def _valkey_url(self, db: int) -> str:
        # redis:// scheme — Valkey is protocol-compatible and Celery/clients
        # do not recognize valkey:// (M0-W1).
        return f"redis://{self.valkey_host}:{self.valkey_port}/{db}"

    @property
    def celery_broker_url(self) -> str:
        return self._valkey_url(self.valkey_db_broker)

    @property
    def celery_result_backend_url(self) -> str:
        return self._valkey_url(self.valkey_db_results)

    @property
    def cache_url(self) -> str:
        return self._valkey_url(self.valkey_db_cache)

    @property
    def session_store_url(self) -> str:
        return self._valkey_url(self.valkey_db_sessions)


@lru_cache
def get_settings() -> Settings:
    return Settings()
