// Response shapes of the FastAPI backend (apps/api/app/main.py).
// Scaffold (M0-F1): kept in lockstep by hand for now; generation from the
// OpenAPI schema replaces this file once the API surface grows (M1).

export type CheckState = "ok" | "unavailable";

export interface HealthResponse {
  status: "ok";
}

// apps/api/app/schemas/users.py UserOut
export type UserRole = "admin" | "tester" | "reviewer" | "read_only";

export interface User {
  id: string;
  organization_id: string;
  email: string;
  display_name: string;
  role: UserRole;
  is_active: boolean;
  last_login_at: string | null;
  created_at: string;
}

// apps/api/app/schemas/auth.py
export interface LoginResponse {
  user: User;
  csrf_token: string;
}

export interface LogoutAllResponse {
  revoked_sessions: number;
}

// apps/api/app/schemas/engagements.py
export type EngagementStatus = "draft" | "active" | "paused" | "closed";
export type ScanIntensity = "passive" | "safe_active" | "authenticated_active" | "high_risk";

export interface Engagement {
  id: string;
  organization_id: string;
  name: string;
  client_system_name: string;
  status: EngagementStatus;
  test_window_start: string | null;
  test_window_end: string | null;
  rate_limit_rps: number;
  max_intensity: ScanIntensity;
  hosted_models_allowed: boolean;
  coordination_contact: string | null;
  emergency_stop_contact: string | null;
  created_by: string;
  created_at: string;
  updated_at: string;
}

export interface EngagementInput {
  name: string;
  client_system_name: string;
  test_window_start: string | null;
  test_window_end: string | null;
  rate_limit_rps: number;
  max_intensity: ScanIntensity;
  hosted_models_allowed: boolean;
  coordination_contact: string | null;
  emergency_stop_contact: string | null;
}

// apps/api/app/schemas/scope.py
export type ScopeKind = "allow" | "deny";
export type ScopeMatcherType = "url" | "domain" | "ip_cidr" | "api_base" | "repo";

export interface ScopeItem {
  id: string;
  engagement_id: string;
  kind: ScopeKind;
  matcher_type: ScopeMatcherType;
  value: string;
  notes: string | null;
  created_at: string;
}

export interface ScopeItemInput {
  kind: ScopeKind;
  matcher_type: ScopeMatcherType;
  value: string;
  notes: string | null;
}

// apps/api/app/schemas/roe.py
export interface ScopeSnapshotRow {
  kind: string;
  matcher_type: string;
  value: string;
}

export interface ROEView {
  roe_text: string;
  scope_snapshot: ScopeSnapshotRow[];
  terms_snapshot: Record<string, unknown>;
  content_hash: string;
  is_accepted: boolean;
  requires_reacceptance: boolean;
  latest_acknowledgement_id: string | null;
  accepted_at: string | null;
}

export interface ROEAcknowledgement {
  id: string;
  engagement_id: string;
  accepted_by: string;
  accepted_at: string;
  roe_text: string;
  scope_snapshot: ScopeSnapshotRow[];
  terms_snapshot: Record<string, unknown>;
  content_hash: string;
}

// apps/api/app/schemas/targets.py
export type TargetType =
  | "web_app"
  | "rest_api"
  | "graphql_api"
  | "source_repo"
  | "source_archive"
  | "ai_chatbot"
  | "llm_api_wrapper"
  | "ai_agent";
export type EnvironmentLabel = "dev" | "staging" | "production";
export type AuthStatus = "none" | "configured" | "verified";

export interface Target {
  id: string;
  engagement_id: string;
  name: string;
  target_type: TargetType;
  environment: EnvironmentLabel;
  primary_value: string;
  auth_status: AuthStatus;
  auth_config: Record<string, unknown> | null;
  connector_config: Record<string, unknown> | null;
  last_scan_at: string | null;
  risk_summary: string | null;
  findings_by_severity: Record<string, number>;
  created_at: string;
  updated_at: string;
}

export interface TargetInput {
  name: string;
  target_type: TargetType;
  environment: EnvironmentLabel;
  primary_value: string;
  auth_status: AuthStatus;
  auth_config: Record<string, unknown> | null;
  connector_config: Record<string, unknown> | null;
}

// target_type is immutable after create — it fixes primary_value validation.
export type TargetUpdateInput = Partial<Omit<TargetInput, "target_type">>;

// LLM target types the suite launcher can drive (mirrors _LLM_TARGET_TYPES /
// schemas ScanLaunchIn on the API).
export const LLM_TARGET_TYPES: readonly TargetType[] = ["ai_chatbot", "llm_api_wrapper"];

// apps/api/app/models/scan.py + schemas/scans.py
export type TestSuite = "prompt_injection" | "data_leakage";
export type ScanStatus = "queued" | "running" | "completed" | "failed" | "cancelled";
export type LaunchIntensity = "safe_active" | "authenticated_active";

export interface Scan {
  id: string;
  engagement_id: string;
  target_id: string;
  intensity: ScanIntensity;
  status: ScanStatus;
  cancel_requested: boolean;
  runner_ref: string | null;
  queued_at: string;
  started_at: string | null;
  finished_at: string | null;
  last_heartbeat_at: string | null;
  error_summary: string | null;
}

export interface ScanLaunchInput {
  target_id: string;
  suites: TestSuite[];
  intensity: LaunchIntensity;
}

// apps/api/app/schemas/audit.py
export type AuditOutcome = "success" | "blocked" | "failure";

export interface AuditEvent {
  id: string;
  actor_user_id: string | null;
  actor_email: string | null;
  action: string;
  object_type: string;
  object_id: string | null;
  engagement_id: string | null;
  engagement_name: string | null;
  outcome: AuditOutcome;
  detail: Record<string, unknown> | null;
  ip_address: string | null;
  created_at: string;
}

export interface ReadinessResponse {
  status: CheckState;
  checks: {
    database: CheckState;
    valkey: CheckState;
  };
}
