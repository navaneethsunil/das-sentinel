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

export interface ReadinessResponse {
  status: CheckState;
  checks: {
    database: CheckState;
    valkey: CheckState;
  };
}
