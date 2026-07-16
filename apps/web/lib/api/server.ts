// Server-side (RSC) API reads. The browser's session cookie is forwarded to
// the compose-internal API explicitly — RSC fetches don't carry the incoming
// request's cookies on their own. Server code only READS; every mutation goes
// through the browser client (lib/api/client.ts) so it carries the CSRF pair.

import { cookies } from "next/headers";
import { redirect } from "next/navigation";

import { ApiError } from "./client";
import type { User } from "./types";

function internalBaseUrl(): string {
  const internal = process.env.API_INTERNAL_URL;
  if (!internal) {
    throw new Error("API_INTERNAL_URL is not set (required for server-side API calls)");
  }
  return internal;
}

async function forwardedCookieHeader(): Promise<string> {
  return (await cookies())
    .getAll()
    .map(({ name, value }) => `${name}=${value}`)
    .join("; ");
}

/** GET an authenticated resource for the current request's session.
 * 401 → login redirect; 404 → null (page renders notFound). */
export async function serverGet<T>(path: string): Promise<T | null> {
  // cookies() FIRST: it marks the render dynamic, so build-time prerendering
  // bails out here instead of dying on the missing API_INTERNAL_URL.
  const cookie = await forwardedCookieHeader();
  const response = await fetch(`${internalBaseUrl()}${path}`, {
    cache: "no-store",
    headers: { cookie },
  });
  if (response.status === 401) {
    redirect("/login");
  }
  if (response.status === 404) {
    return null;
  }
  if (response.status !== 200) {
    throw new ApiError(response.status, path);
  }
  return (await response.json()) as T;
}

/** The signed-in user, or null — NEVER a redirect. Safe in layouts (which
 * also render for signed-out pages like /login); pages that require auth
 * keep using serverGet's 401 → login behavior. */
export async function serverMe(): Promise<User | null> {
  const cookie = await forwardedCookieHeader();
  const response = await fetch(`${internalBaseUrl()}/auth/me`, {
    cache: "no-store",
    headers: { cookie },
  });
  if (response.status !== 200) {
    return null;
  }
  return (await response.json()) as User;
}
