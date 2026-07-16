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

export interface ReadinessResponse {
  status: CheckState;
  checks: {
    database: CheckState;
    valkey: CheckState;
  };
}
