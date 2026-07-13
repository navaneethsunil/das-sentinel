// Typed API client scaffold (M0-F1).
//
// Base URL resolution:
//   - server (RSC/route handlers): API_INTERNAL_URL — the compose-internal service
//     address; never exposed to the browser (no NEXT_PUBLIC_ prefix).
//   - browser: same-origin "/api", routed by the proxy (M0-I4). CORS stays off.

import type { HealthResponse, ReadinessResponse } from "./types";

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly path: string,
  ) {
    super(`API request failed: ${path} -> HTTP ${status}`);
    this.name = "ApiError";
  }
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

export function getHealth(): Promise<HealthResponse> {
  return apiFetch<HealthResponse>("/healthz");
}

export function getReadiness(): Promise<ReadinessResponse> {
  // 503 is a well-formed "not ready" payload, not a transport failure.
  return apiFetch<ReadinessResponse>("/readyz", undefined, [200, 503]);
}
