// Typed API client scaffold (M0-F1).
//
// Base URL resolution:
//   - server (RSC/route handlers): API_INTERNAL_URL — the compose-internal service
//     address; never exposed to the browser (no NEXT_PUBLIC_ prefix).
//   - browser: same-origin "/api", routed by the proxy (M0-I4). CORS stays off.

import type {
  Engagement,
  EngagementInput,
  EngagementStatus,
  EvidenceContent,
  HealthResponse,
  LoginResponse,
  LogoutAllResponse,
  ReadinessResponse,
  ROEAcknowledgement,
  Scan,
  ScanLaunchInput,
  ScopeItem,
  ScopeItemInput,
  SourceArchiveUploadResult,
  Target,
  TargetInput,
  TargetUpdateInput,
  User,
} from "./types";

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly path: string,
    /** FastAPI's `detail` field when the error body carried one (e.g. the scope
     * keystone's machine reason on a 403). Undefined for non-JSON error bodies. */
    public readonly detail?: string,
  ) {
    super(`API request failed: ${path} -> HTTP ${status}`);
    this.name = "ApiError";
  }
}

/** Best-effort read of FastAPI's `{ "detail": ... }` from an error response.
 * Returns undefined when the body is absent or not the expected shape. */
async function errorDetail(response: Response): Promise<string | undefined> {
  try {
    const body: unknown = await response.clone().json();
    if (body && typeof body === "object" && "detail" in body) {
      const detail = (body as { detail: unknown }).detail;
      if (typeof detail === "string") {
        return detail;
      }
    }
  } catch {
    // Non-JSON body (HTML error page, empty) — no detail to surface.
  }
  return undefined;
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
  method: "POST" | "PATCH" | "DELETE" = "POST",
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
    method,
    cache: "no-store",
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  if (!acceptStatuses.includes(response.status)) {
    throw new ApiError(response.status, path, await errorDetail(response));
  }
  // 204 has no body by definition.
  return (response.status === 204 ? undefined : await response.json()) as T;
}

/** apiMutate for signed-in flows: a 401 means the session died mid-use, so
 * hard-navigate to the expired-session login instead of surfacing an error. */
async function authMutate<T>(
  path: string,
  body?: unknown,
  acceptStatuses: readonly number[] = [200],
  method: "POST" | "PATCH" | "DELETE" = "POST",
): Promise<T> {
  try {
    return await apiMutate<T>(path, body, acceptStatuses, method);
  } catch (error) {
    if (error instanceof ApiError && error.status === 401) {
      expireToLogin(path);
    }
    throw error;
  }
}

/** apiFetch for signed-in reads (e.g. live status polling): a 401 → the
 * expired-session login, same as authMutate. */
async function authFetch<T>(path: string, acceptStatuses: readonly number[] = [200]): Promise<T> {
  try {
    return await apiFetch<T>(path, undefined, acceptStatuses);
  } catch (error) {
    if (error instanceof ApiError && error.status === 401) {
      expireToLogin(path);
    }
    throw error;
  }
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

export function logout(): Promise<void> {
  // A 401 here means the session was already dead — same end state, handled
  // by authMutate's expired-session redirect.
  return authMutate<void>("/auth/logout", undefined, [204]);
}

export function logoutAll(): Promise<LogoutAllResponse> {
  return authMutate<LogoutAllResponse>("/auth/logout-all");
}

export function createEngagement(input: EngagementInput): Promise<Engagement> {
  return authMutate<Engagement>("/engagements", input, [201]);
}

export function updateEngagement(id: string, patch: Partial<EngagementInput>): Promise<Engagement> {
  return authMutate<Engagement>(`/engagements/${id}`, patch, [200], "PATCH");
}

/** 409 (ApiError) when the state machine refuses the transition. */
export function changeEngagementStatus(id: string, status: EngagementStatus): Promise<Engagement> {
  return authMutate<Engagement>(`/engagements/${id}/status`, { status });
}

export function deleteEngagement(id: string): Promise<void> {
  return authMutate<void>(`/engagements/${id}`, undefined, [204], "DELETE");
}

/** 422 (ApiError) when the value is malformed for its matcher type — the
 * server validates + normalizes; the stored value may differ from the input. */
export function addScopeItem(engagementId: string, input: ScopeItemInput): Promise<ScopeItem> {
  return authMutate<ScopeItem>(`/engagements/${engagementId}/scope-items`, input, [201]);
}

export function removeScopeItem(engagementId: string, itemId: string): Promise<void> {
  return authMutate<void>(
    `/engagements/${engagementId}/scope-items/${itemId}`,
    undefined,
    [204],
    "DELETE",
  );
}

/** 422 (ApiError) when primary_value is malformed for the target type or
 * auth_config holds anything but credential references (TR-23). */
export function createTarget(engagementId: string, input: TargetInput): Promise<Target> {
  return authMutate<Target>(`/engagements/${engagementId}/targets`, input, [201]);
}

export function updateTarget(
  engagementId: string,
  targetId: string,
  patch: TargetUpdateInput,
): Promise<Target> {
  return authMutate<Target>(
    `/engagements/${engagementId}/targets/${targetId}`,
    patch,
    [200],
    "PATCH",
  );
}

export function deleteTarget(engagementId: string, targetId: string): Promise<void> {
  return authMutate<void>(
    `/engagements/${engagementId}/targets/${targetId}`,
    undefined,
    [204],
    "DELETE",
  );
}

/** Upload a source archive (zip/tar) to a source_archive target (M3-B1). Sent as
 * multipart/form-data — the browser sets the Content-Type + boundary, so we do
 * not set it here. 413 when over the size cap; 422 when it is not a valid archive
 * or the target is the wrong type (ApiError.detail carries the reason). */
export async function uploadSourceArchive(
  engagementId: string,
  targetId: string,
  file: File,
): Promise<SourceArchiveUploadResult> {
  const path = `/engagements/${engagementId}/targets/${targetId}/source-archive`;
  const form = new FormData();
  form.append("file", file);
  const headers: Record<string, string> = {};
  const csrf = readCsrfToken();
  if (csrf) {
    headers[CSRF_HEADER] = csrf;
  }
  const response = await fetch(`${baseUrl()}${path}`, {
    method: "POST",
    cache: "no-store",
    headers,
    body: form,
  });
  if (response.status === 401) {
    expireToLogin(path);
  }
  if (response.status !== 200) {
    throw new ApiError(response.status, path, await errorDetail(response));
  }
  return (await response.json()) as SourceArchiveUploadResult;
}

/** Launch a scan — an LLM test suite (`suites`) or an external scanner
 * (`scanners`), exactly one. 403 (ApiError) when the scope keystone blocks it
 * (out of scope / ROE / over-intensity / high-risk needs approval — detail carries
 * the machine reason); 422 when the target is the wrong type for the chosen kind. */
export function launchScan(engagementId: string, input: ScanLaunchInput): Promise<Scan> {
  return authMutate<Scan>(`/engagements/${engagementId}/scans`, input, [201]);
}

/** Live scan list for an engagement (status polling). */
export function listScans(engagementId: string): Promise<Scan[]> {
  return authFetch<Scan[]>(`/engagements/${engagementId}/scans`);
}

/** Request emergency stop for a running/queued scan (M2-W2 signal path). The
 * worker effects the kill and marks it cancelled; this only sets the flag.
 * 409 (ApiError) when the scan already finished — caller refreshes to reconcile. */
export function cancelScan(engagementId: string, scanId: string): Promise<Scan> {
  return authMutate<Scan>(`/engagements/${engagementId}/scans/${scanId}/cancel`, undefined, [200]);
}

/** Fetch a single evidence blob's content (the transcript viewer). Served
 * through the API — the browser never reaches object storage — and the API
 * re-verifies the SHA-256 before returning (500 on an integrity failure). */
export function getFindingEvidence(
  engagementId: string,
  findingId: string,
  evidenceId: string,
): Promise<EvidenceContent> {
  return authFetch<EvidenceContent>(
    `/engagements/${engagementId}/findings/${findingId}/evidence/${evidenceId}`,
  );
}

/** Acceptance is bound to the hash the user was shown — 409 (ApiError) when
 * the ROE changed since it was rendered (accept only what you actually saw). */
export function acceptRoe(
  engagementId: string,
  acknowledgedContentHash: string,
): Promise<ROEAcknowledgement> {
  return authMutate<ROEAcknowledgement>(
    `/engagements/${engagementId}/roe/accept`,
    { acknowledged_content_hash: acknowledgedContentHash },
    [201],
  );
}
