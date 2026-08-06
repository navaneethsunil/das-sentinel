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

/** Send an unauthenticated request to the login page. A caller that still has
 * a session cookie had one that expired or was revoked, so it gets the amber
 * banner; a caller with no cookie at all was simply never signed in. */
async function redirectToLogin(): Promise<never> {
  const hadSession = (await cookies()).has("__Host-das_session");
  redirect(hadSession ? "/login?expired=1" : "/login");
}

/** The signed-in user, or a redirect to login. Use in every page that must not
 * render for an anonymous visitor. */
export async function requireUser(): Promise<User> {
  const me = await serverMe();
  return me ?? redirectToLogin();
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
    return redirectToLogin();
  }
  if (response.status === 404) {
    return null;
  }
  if (response.status !== 200) {
    throw new ApiError(response.status, path);
  }
  return (await response.json()) as T;
}

/** serverGet for a SUPPLEMENTARY resource the caller's role may legitimately
 * not be allowed to read: 403 → null instead of throwing.
 *
 * Only for data a page renders fine without (e.g. the credential picker's
 * options — a Reviewer sees the target form with an empty picker). `serverGet`
 * deliberately still throws on 403: mapping every forbidden response to null
 * would make "you may not see this" indistinguishable from "this does not
 * exist", which hides access-control bugs and can render a page as though
 * forbidden data were simply absent. Do NOT use this for a page's PRIMARY
 * resource — a page whose whole subject is forbidden should say so, not render
 * an empty version of itself. */
export async function serverGetOptional<T>(path: string): Promise<T | null> {
  try {
    return await serverGet<T>(path);
  } catch (error) {
    if (error instanceof ApiError && error.status === 403) {
      return null;
    }
    throw error;
  }
}

/** serverGet for a page's PRIMARY resource that some roles are legitimately not
 * allowed to read (the credential vault, the user directory, the audit log).
 * 403 → the "forbidden" sentinel so the page can render a role-appropriate
 * access-denied screen instead of throwing into the error boundary, which shows
 * the generic "A server error occurred" and reads as a broken app.
 *
 * Deliberately NOT null (that means "does not exist", per serverGet) and
 * deliberately not folded into serverGet: a caller has to opt in per page, so an
 * unexpected 403 anywhere else still surfaces as the bug it is. */
export const FORBIDDEN = "forbidden" as const;

export async function serverGetOrForbidden<T>(path: string): Promise<T | null | typeof FORBIDDEN> {
  try {
    return await serverGet<T>(path);
  } catch (error) {
    if (error instanceof ApiError && error.status === 403) {
      return FORBIDDEN;
    }
    throw error;
  }
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
