# BACKEND_SCHEMA.md — DAS Sentinel

> The **backend application schema**: the typed contracts of the API and service layer — Pydantic request/response models, internal service interfaces, adapter protocols, Celery job payloads, and module boundaries. This is the code-facing companion to `DATABASE_SCHEMA.md` (persistence) and `TRD.md` (requirements). Where a field maps to a stored column, `DATABASE_SCHEMA.md` is authoritative; this document defines the **wire and interface shapes**, which are intentionally *not* 1:1 with tables (no hashes, no internal flags leak to the client).

Notation: Pydantic v2 / Python 3.12 type hints. `= None` denotes optional; `Literal[...]` mirrors the DB enums in `DATABASE_SCHEMA.md §14`.

---

## 1. Layering & module boundaries (normative)

```
apps/api/app/
├── api/         routers — parse request model, call ONE service, shape response model. No ORM, no business logic.
├── schemas/     Pydantic request/response models (this doc §3–§9). The API contract.
├── services/    business logic. The ONLY layer that mutates domain state. Returns domain objects/DTOs.
├── core/        cross-cutting: config, security (hash/session/csrf), scope, audit, deps, errors.
├── models/      SQLAlchemy ORM (maps to DATABASE_SCHEMA.md). Never imported by routers.
├── scanners/    ScannerAdapter implementations (§10).
├── llm/         provider abstraction + adapters + prompt templates (§11).
├── workers/     Celery tasks — thin wrappers that load state and call services/adapters (§12).
├── storage/     object-store (S3) client for evidence (§8).
└── reports/     exporters (csv, markdown; later pdf/docx/json).
```

**Boundary rules (enforced by review + import-lint):**
- Routers depend on `schemas` + `services` only. Routers never import `models` or `sqlalchemy`.
- `services` never build HTTP responses or import `fastapi.Response`; they raise typed domain errors (§2).
- `core/scope.py` and `core/audit.py` are importable by services and workers alike — the same safety path serves every entry point.
- DTOs cross the service→router boundary as Pydantic models; ORM objects never leave `services`.

---

## 2. Error model (typed domain errors → HTTP)

Services raise domain errors; a single FastAPI exception handler maps them to RFC 9457 `application/problem+json` with the status codes fixed in `TRD.md §3` / `APPFLOW.md §5`.

```python
class DomainError(Exception):
    type_uri: str          # RFC 9457 "type" (e.g. "/errors/scope-violation")
    title: str
    status: int
    detail: str | None = None

# Scope / authorization family
class EngagementInactive(DomainError):     status = 409
class ROENotAccepted(DomainError):         status = 403
class ScopeViolation(DomainError):         status = 403   # allow-miss or deny-hit
class IntensityNotAuthorized(DomainError): status = 422
class HighRiskNotApproved(DomainError):    status = 403
class RBACDenied(DomainError):             status = 403
class NotAuthenticated(DomainError):       status = 401
class StateConflict(DomainError):          status = 409
class ValidationProblem(DomainError):      status = 422
class RateLimited(DomainError):            status = 429
```

Response body (all errors):
```python
class ProblemDetail(BaseModel):
    type: str            # type_uri
    title: str
    status: int
    detail: str | None = None
    instance: str | None = None   # request path
```
The handler also emits the `audit_event` (`outcome='blocked'|'failure'`) for the scope/authorization family.

---

## 3. Shared / primitive models

```python
Uuid = Annotated[str, "uuid"]

class Page(BaseModel, Generic[T]):        # keyset pagination envelope
    items: list[T]
    next_cursor: str | None = None

Severity   = Literal["critical","high","medium","low","informational"]
Intensity  = Literal["passive","safe_active","authenticated_active","high_risk"]
Provenance = Literal["automated","ai_generated","validated","manually_overridden"]
FindingStatus = Literal["open","in_triage","confirmed","mitigated","fixed",
                        "accepted_risk","false_positive","out_of_scope"]
TargetType = Literal["web_app","rest_api","graphql_api","source_repo","source_archive",
                     "ai_chatbot","llm_api_wrapper","ai_agent"]
Role       = Literal["admin","tester","reviewer","read_only"]
```

---

## 4. Auth & session

```python
class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class MeResponse(BaseModel):
    id: Uuid
    email: EmailStr
    display_name: str
    role: Role
    organization_id: Uuid
# Login sets the __Host- session cookie + returns a CSRF token header; body = MeResponse.
# No token/password is ever returned in a body.
```

`core/security.py` interface:
```python
def hash_password(pw: str) -> str: ...            # Argon2id | PBKDF2 per config (TR-21)
def verify_password(pw: str, hash: str) -> bool: ...
def new_session(user_id: Uuid, ip, ua) -> tuple[str, Session]: ...   # returns (raw_token, row); stores SHA-256
def validate_session(raw_token: str) -> SessionContext | None: ...   # cache→db; checks revoked/expiry
def revoke_session(session_id: Uuid) -> None: ...                    # + cache purge
def issue_csrf(session_id: Uuid) -> str: ...
def check_csrf(session_id: Uuid, token: str) -> bool: ...
```

---

## 5. Engagement, scope, ROE, approvals

```python
class EngagementCreate(BaseModel):
    name: str
    client_system_name: str
    test_window_start: datetime | None = None
    test_window_end: datetime | None = None
    rate_limit_rps: int = Field(5, ge=1, le=100)
    max_intensity: Intensity = "safe_active"
    hosted_models_allowed: bool = False
    coordination_contact: str | None = None
    emergency_stop_contact: str | None = None

class EngagementResponse(EngagementCreate):
    id: Uuid
    status: Literal["draft","active","paused","closed"]
    roe_accepted: bool
    roe_reacceptance_required: bool          # true if scope edited after acceptance
    created_at: datetime

class ScopeItemCreate(BaseModel):
    kind: Literal["allow","deny"]
    matcher_type: Literal["url","domain","ip_cidr","api_base","repo"]
    value: str
    notes: str | None = None

class ScopeItemResponse(ScopeItemCreate):
    id: Uuid

class ROEAcceptRequest(BaseModel):
    acknowledged: Literal[True]              # must be explicit true

class ROEStatusResponse(BaseModel):
    accepted: bool
    accepted_by: Uuid | None = None
    accepted_at: datetime | None = None
    content_hash: str | None = None          # hex of the stored bytea, display only
    reacceptance_required: bool

class ApprovalRequest(BaseModel):
    action_type: str
    justification: str = Field(min_length=10)

class ApprovalResponse(BaseModel):
    id: Uuid
    action_type: str
    status: Literal["pending","approved","denied","expired"]
    requested_by: Uuid
    decided_by: Uuid | None = None
    decided_at: datetime | None = None
```

---

## 6. Targets

```python
class TargetCreate(BaseModel):
    name: str
    target_type: TargetType
    environment: Literal["dev","staging","production"] = "dev"
    primary_value: str                       # URL / base / repo / object key
    auth_config_ref: str | None = None       # secrets-manager reference ONLY, never a secret

class TargetResponse(BaseModel):
    id: Uuid
    name: str
    target_type: TargetType
    environment: str
    primary_value: str
    auth_status: Literal["none","configured","verified"]
    last_scan_at: datetime | None = None
    findings_by_severity: dict[Severity, int]   # computed rollup, not stored
```

---

## 7. Scans, findings, CVSS, reports

```python
class ScanCreate(BaseModel):
    engagement_id: Uuid
    target_id: Uuid
    scanner: Literal["semgrep","zap"] | None = None       # exactly one of scanner|suite
    suite: Literal["prompt_injection","data_leakage","agent_permission"] | None = None
    intensity: Intensity
    config: dict = {}                                      # adapter-specific, validated per adapter
    approval_gate_id: Uuid | None = None                  # required iff intensity == high_risk

class ScanResponse(BaseModel):
    id: Uuid
    status: Literal["queued","running","completed","failed","cancelled"]
    engagement_id: Uuid
    target_id: Uuid
    intensity: Intensity
    runs: list["RunSummary"]
    progress: float | None = None            # 0..1 heartbeat
    error_summary: str | None = None
    queued_at: datetime
    finished_at: datetime | None = None

class RunSummary(BaseModel):
    id: Uuid
    kind: Literal["scanner","test"]
    name: str                                # 'semgrep' | 'zap' | 'pyrit' ...
    version: str
    status: str

class EvidenceRef(BaseModel):
    id: Uuid
    kind: Literal["raw_scanner_output","http_transcript","llm_transcript","source_archive"]
    content_type: str
    size_bytes: int
    sha256: str                              # hex, display/verify only
    # NB: bytes are fetched via a separate streaming endpoint, not inlined

class FindingResponse(BaseModel):
    id: Uuid
    title: str
    message: str
    severity: Severity
    provenance: Provenance
    status: FindingStatus
    is_false_positive: bool
    rule_id: str | None = None
    sarif_level: Literal["none","note","warning","error"] | None = None
    location: dict                           # SAST(file/line) | DAST(endpoint/method) | LLM(prompt ref)
    cvss: "CVSSResponse | None" = None       # current score
    mappings: list["MappingRef"] = []
    evidence: list[EvidenceRef] = []
    duplicate_of: Uuid | None = None
    created_at: datetime

class FindingStatusPatch(BaseModel):
    status: FindingStatus | None = None
    is_false_positive: bool | None = None
    reason: str | None = None
    # service enforces the provenance rule: ai_generated → confirmed/fixed requires human actor

class CVSSRequest(BaseModel):
    version: Literal["v4_0","v3_1"] = "v4_0"
    vector_string: str
    manual_override: bool = False
    justification: str | None = None         # required when manual_override

class CVSSResponse(BaseModel):
    version: Literal["v4_0","v3_1"]
    vector_string: str
    base_score: float = Field(ge=0, le=10)
    severity_band: Severity
    is_manual_override: bool
    created_at: datetime

class MappingRef(BaseModel):
    framework: str                           # 'owasp_llm_2025','nist_800_53_r5',...
    code: str                                # 'LLM01','AC-4',...
    title: str

class ReportCreate(BaseModel):
    report_type: Literal["executive","technical","poam"]
    title: str

class ReportResponse(ReportCreate):
    id: Uuid
    status: Literal["draft","final"]
    finding_ids: list[Uuid]
    created_at: datetime
# export → streaming response (text/csv | text/markdown), not a JSON body
```

---

## 8. Object storage interface (`storage/`)

```python
class StoredEvidence(BaseModel):
    id: Uuid
    object_key: str
    sha256: bytes                # 32 bytes
    size_bytes: int
    content_type: str

class EvidenceStore(Protocol):
    def put(self, data: bytes | IO, kind: str, content_type: str,
            retain_until: datetime | None) -> StoredEvidence: ...   # blob first (hashed, object-lock), then caller commits row
    def open(self, object_key: str) -> IO: ...                      # streaming read; caller re-verifies hash
    def exists(self, object_key: str) -> bool: ...
```
Two-phase write (TR-18): `put()` writes + locks the blob and returns the descriptor; the **service** commits the `evidence` row in the same transaction as the finding. An orphan-sweep task reconciles blobs whose row commit failed.

---

## 9. Service interfaces (selected)

Services are the only mutation layer; each method audits and enforces safety.

```python
class ScopeService(Protocol):
    def authorize_operation(self, engagement, target, op: NormalizedOperation,
                            roe_ack, now) -> ExecutionAuthorization: ...
        # op carries typed/canonical config + SERVER-derived effective intensity (not caller-declared);
        # checks ROE-terms equality + test window against `now`; raises the §2 scope family + ROETermsMismatch
        # / OutsideTestWindow; deterministic (now, roe_ack injected); negative matrix (TR-31)

class ScanService(Protocol):
    def create_scan(self, ctx: SessionContext, req: ScanCreate) -> ScanResponse: ...
        # RBAC → authorize_operation → persist queued + immutable execution_authorization envelope
        # (same txn) → enqueue job(scan_id) → 202
    def cancel_scan(self, ctx, scan_id: Uuid) -> None: ...           # emergency stop
    def get_scan(self, ctx, scan_id: Uuid) -> ScanResponse: ...

class FindingService(Protocol):
    def normalize_and_store(self, run, drafts: list[FindingDraft]) -> list[Uuid]: ...
        # compute hash_code; dedup → duplicate_of; write findings + finding_evidence
    def transition(self, ctx, finding_id, patch: FindingStatusPatch) -> FindingResponse: ...
        # enforces provenance rule; writes finding_status_history
    def set_cvss(self, ctx, finding_id, req: CVSSRequest) -> CVSSResponse: ...
        # computes via the `cvss` library; insert-only; flips prior is_current

class AuditService(Protocol):
    def record(self, *, actor, action, object_type, object_id,
               engagement_id, outcome, detail: dict | None) -> None: ...   # append-only
```

---

## 10. Scanner adapter protocol (`scanners/`)

```python
class Command(BaseModel):
    argv: list[str]
    cwd: str | None = None
    env: dict[str,str] = {}
    timeout_s: int

class RawResult(BaseModel):
    exit_code: int
    stdout_key: str          # object-store key of captured raw output (evidence)
    stderr: str              # captured; surfaced on failure, never swallowed
    started_at: datetime
    finished_at: datetime

class FindingDraft(BaseModel):        # pre-normalization output of an adapter
    rule_id: str | None
    title: str
    message: str
    severity: Severity
    sarif_level: str | None
    location: dict
    raw_ref: str              # evidence object key

class ScannerAdapter(Protocol):
    name: str
    def version(self) -> str: ...
    def validate_prerequisites(self) -> None: ...
    def build_command(self, target: TargetResponse, config: dict) -> Command: ...
    def run(self, cmd: Command, on_progress: Callable[[float], None]) -> RawResult: ...
        # launched with start_new_session=True; PGID recorded; timeout + rate-limit ceiling
    def normalize(self, raw: RawResult) -> list[FindingDraft]: ...

# The AI/LLM Runner mirrors this shape:
class Runner(Protocol):
    suite: str
    def run(self, target: TargetResponse, config: dict) -> list[FindingDraft]: ...   # PyRIT (MVP)
```

---

## 11. LLM provider interface (`llm/`)

```python
class LLMRequest(BaseModel):
    purpose: Literal["test_gen","triage","remediation","mapping","report","summarization"]
    prompt_template: str          # template id + version
    inputs: dict                  # evidence-grounded inputs
    engagement_id: Uuid
    prefer_local: bool = False

class LLMResponse(BaseModel):
    text: str
    provider: str                 # 'anthropic' | 'ollama' | 'vllm'
    model: str
    input_tokens: int
    output_tokens: int
    cost_usd: Decimal
    was_redacted: bool
    hosted: bool

class LLMProvider(Protocol):
    def complete(self, req: LLMRequest, engagement) -> LLMResponse: ...
        # 1) hosted requested + engagement.hosted_models_allowed==False  -> local-only
        # 2) redaction pass before ANY hosted egress; error/timeout -> fail closed (block)
        # 3) current Claude params only (adaptive thinking, strict tool use)
        # 4) result stored ai_generated; logs llm_interactions row
```

---

## 12. Celery job payloads (`workers/`)

Jobs carry **IDs only** — never scope, credentials, or domain objects. Authorization state lives in the immutable `execution_authorization` envelope, which the worker re-reads and re-derives (defense in depth, TR-2). The worker never trusts the envelope as a payload — it recomputes it from live DB state.

```python
class ScanJob(BaseModel):
    scan_id: Uuid
    # worker: load scan + execution_authorization envelope + engagement/target/ROE/approval →
    #         re-derive & recompute operation_digest → authorize_operation() AGAIN (test window,
    #         ROE-terms equality, approval digest) → atomically consume approval if high-risk →
    #         ExecutionOwner launches adapter.run()/PyRIT in rootless sandbox (egress via shaper) →
    #         evidence → normalize → findings → verify teardown → status

class OrphanSweepJob(BaseModel):
    older_than: datetime          # reconcile evidence blobs whose row commit failed
```

Task registry (names stable for monitoring): `scan.execute`, `scan.cancel`, `evidence.orphan_sweep`, `llm.call` (async variants). Cancellation signals the recorded process group `SIGTERM → SIGKILL`.

---

## 13. Config schema (`core/config.py`)

Single `Settings` (pydantic-settings), env-loaded, no hardcoded values.

```python
class Settings(BaseSettings):
    database_url: str
    valkey_url: str                       # redis:// scheme; separate DBs via path
    object_store_endpoint: str
    object_store_bucket: str
    password_hash: Literal["argon2id","pbkdf2"] = "argon2id"   # FIPS → pbkdf2 (TR-21)
    session_idle_minutes: int = 15
    session_absolute_hours: int = 8
    llm_default_model: str = "claude-opus-4-8"
    llm_triage_model: str = "claude-sonnet-5"
    anthropic_api_key: SecretStr | None = None
    ollama_base_url: str | None = None
    model_config = SettingsConfigDict(env_file=".env", env_prefix="SENTINEL_")
```

---

## 14. Contract invariants (must hold)

- **No secret or hash in any response model** — sessions/passwords/API keys never serialize outward; `sha256`/`content_hash` are display-only hex, evidence bytes stream via a dedicated endpoint.
- **Request models validate at the edge** (Pydantic) before any service call; services assume validated input but still enforce authorization/scope.
- **Enums mirror the DB** (`§3` ↔ `DATABASE_SCHEMA.md §14`); adding a value is a coordinated migration + schema change.
- **`config` dicts are adapter-validated** — each scanner/runner validates its own `config` shape; unknown keys are rejected.
- **Job payloads are ID-only** — re-hydration + re-authorization happen in the worker.
- **Every mutating service method audits** and, for the scope family, emits a `blocked` event on refusal.

### Framework dependency & serialization notes (verified against Pydantic v2 docs)
- **`EmailStr` requires the `email-validator` dependency** — declare `pydantic[email]` in requirements, or importing/using `EmailStr` raises `ImportError` at startup.
- **`SecretStr` never serializes plaintext by default** — `repr()`, `model_dump_json()`, and `model_dump(mode="json")` emit the masked value; plain `model_dump()` returns the `SecretStr` *object* (still masked in repr). Retrieve the real value only via `.get_secret_value()`, and never log it. (Used for `anthropic_api_key` in §13.)
- Constraint placement: `Field(5, ge=1, le=100)` is valid; the most idiomatic v2 form is `Annotated[int, Field(ge=1, le=100)] = 5` — either is acceptable.
