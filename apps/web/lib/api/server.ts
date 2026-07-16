// Server-side (RSC) API reads. The browser's session cookie is forwarded to
// the compose-internal API explicitly — RSC fetches don't carry the incoming
// request's cookies on their own. Server code only READS; every mutation goes
// through the browser client (lib/api/client.ts) so it carries the CSRF pair.

import { cookies } from "next/headers";
import { redirect } from "next/navigation";

import { ApiError } from "./client";

function internalBaseUrl(): string {
  const internal = process.env.API_INTERNAL_URL;
  if (!internal) {
    throw new Error("API_INTERNAL_URL is not set (required for server-side API calls)");
  }
  return internal;
}

/** GET an authenticated resource for the current request's session.
 * 401 → login redirect; 404 → null (page renders notFound). */
export async function serverGet<T>(path: string): Promise<T | null> {
  const cookieHeader = (await cookies())
    .getAll()
    .map(({ name, value }) => `${name}=${value}`)
    .join("; ");
  const response = await fetch(`${internalBaseUrl()}${path}`, {
    cache: "no-store",
    headers: { cookie: cookieHeader },
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
