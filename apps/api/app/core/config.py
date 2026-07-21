"""Single Settings object — the only place configuration enters the app (CLAUDE.md §5).

Every host, key, and model name comes from the environment (see `.env.example` at the
repo root); nothing here embeds a deployment-specific value. Import `get_settings()`
everywhere — never instantiate `Settings` directly outside tests.
"""

from functools import lru_cache
from typing import Literal
from urllib.parse import quote_plus

from pydantic import AliasChoices, Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


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
    postgres_user: str
    postgres_password: SecretStr
    postgres_db: str

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

    # ── LLM (provider abstraction — CLAUDE.md §7) ────────────────────────
    llm_provider: Literal["anthropic", "ollama", "vllm"]
    anthropic_api_key: SecretStr | None = None
    llm_model_default: str
    llm_model_triage: str
    llm_model_classifier: str
    ollama_base_url: str | None = None
    vllm_base_url: str | None = None

    # ── Egress shaper (M2-SEC1, TM-1) ────────────────────────────────────
    # Comma-separated host / host:port of operator-trusted model provider
    # endpoints run traffic may reach even though they are not engagement
    # targets. Everything else is default-deny (scope + SSRF). Empty = only
    # in-scope target IPs are reachable.
    egress_provider_allowlist: str = ""

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
    @property
    def database_url(self) -> str:
        return (
            f"postgresql+asyncpg://{quote_plus(self.postgres_user)}:"
            f"{quote_plus(self.postgres_password.get_secret_value())}@"
            f"{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

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
