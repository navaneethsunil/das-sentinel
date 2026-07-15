// Typed API client scaffold (M0-F1).
//
// Base URL resolution:
//   - server (RSC/route handlers): API_INTERNAL_URL — the compose-internal service
//     address; never exposed to the browser (no NEXT_PUBLIC_ prefix).
//   - browser: same-origin "/api", routed by the proxy (M0-I4). CORS stays off.

import type {
  HealthResponse,
  LoginResponse,
  LogoutAllResponse,
  ReadinessResponse,
  User,
} from "./types";

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly path: string,
  ) {
    super(`API request failed: ${path} -> HTTP ${status}`);
    this.name = "ApiError";
  }
}

// Double-submit CSRF protocol constants (M1-SEC2) — pinned to the API defaults
// (apps/api Settings.csrf_cookie_name / csrf_header_name). The cookie is
// deliberately not HttpOnly: reading it here and echoing it in the header is
// what proves same-origin to the CSRF middleware.
const CSRF_COOKIE = "__Host-das_csrf";
const CSRF_HEADER = "X-CSRF-Token";

function readCsrfToken(): string | null {
  if (typeof document === "undefined") {
    return null;
  }
  for (const pair of document.cookie.split("; ")) {
    const [name, ...rest] = pair.split("=");
    if (name === CSRF_COOKIE) {
      return decodeURIComponent(rest.join("="));
    }
  }
  return null;
}

/** Hard-navigate to the login page when the server says the session is gone.
 * Full navigation (not router.push) so all client state is dropped with it. */
function expireToLogin(path: string): never {
  if (typeof window !== "undefined") {
    window.location.assign("/login?expired=1");
  }
  throw new ApiError(401, path);
}

function baseUrl(): string {
  if (typeof window !== "undefined") {
    return "/api";
  }
  const internal = process.env.API_INTERNAL_URL;
  if (!internal) {
    throw new Error("API_INTERNAL_URL is not set (required for server-side API calls)");
  }
  return internal;
}

async function apiFetch<T>(
  path: string,
  init?: RequestInit,
  acceptStatuses: readonly number[] = [200],
): Promise<T> {
  const response = await fetch(`${baseUrl()}${path}`, {
    cache: "no-store",
    ...init,
  });
  if (!acceptStatuses.includes(response.status)) {
    throw new ApiError(response.status, path);
  }
  return (await response.json()) as T;
}

async function apiMutate<T>(
  path: string,
  body?: unknown,
  acceptStatuses: readonly number[] = [200],
): Promise<T> {
  const headers: Record<string, string> = {};
  const csrf = readCsrfToken();
  if (csrf) {
    headers[CSRF_HEADER] = csrf;
  }
  if (body !== undefined) {
    headers["Content-Type"] = "application/json";
  }
  const response = await fetch(`${baseUrl()}${path}`, {
    method: "POST",
    cache: "no-store",
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  if (!acceptStatuses.includes(response.status)) {
    throw new ApiError(response.status, path);
  }
  // 204 has no body by definition.
  return (response.status === 204 ? undefined : await response.json()) as T;
}

export function getHealth(): Promise<HealthResponse> {
  return apiFetch<HealthResponse>("/healthz");
}

export function getReadiness(): Promise<ReadinessResponse> {
  // 503 is a well-formed "not ready" payload, not a transport failure.
  return apiFetch<ReadinessResponse>("/readyz", undefined, [200, 503]);
}

/** Throws ApiError(401) on bad credentials — the caller renders the error,
 * never a redirect (this IS the login page's call). */
export function login(email: string, password: string): Promise<LoginResponse> {
  return apiMutate<LoginResponse>("/auth/login", { email, password });
}

/** Signed-in user, or null when there is no valid session (no redirect —
 * callers like the user menu render the signed-out state instead). */
export async function getMe(): Promise<User | null> {
  const response = await fetch(`${baseUrl()}/auth/me`, { cache: "no-store" });
  if (response.status === 401) {
    return null;
  }
  if (response.status !== 200) {
    throw new ApiError(response.status, "/auth/me");
  }
  return (await response.json()) as User;
}

export async function logout(): Promise<void> {
  try {
    await apiMutate<void>("/auth/logout", undefined, [204]);
  } catch (error) {
    if (error instanceof ApiError && error.status === 401) {
      // Session already dead (expired or revoked elsewhere) — same end state.
      expireToLogin("/auth/logout");
    }
    throw error;
  }
}

export async function logoutAll(): Promise<LogoutAllResponse> {
  try {
    return await apiMutate<LogoutAllResponse>("/auth/logout-all");
  } catch (error) {
    if (error instanceof ApiError && error.status === 401) {
      expireToLogin("/auth/logout-all");
    }
    throw error;
  }
}
