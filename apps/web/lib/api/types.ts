// Response shapes of the FastAPI backend (apps/api/app/main.py).
// Scaffold (M0-F1): kept in lockstep by hand for now; generation from the
// OpenAPI schema replaces this file once the API surface grows (M1).

export type CheckState = "ok" | "unavailable";

export interface HealthResponse {
  status: "ok";
}

export interface ReadinessResponse {
  status: CheckState;
  checks: {
    database: CheckState;
    valkey: CheckState;
  };
}
