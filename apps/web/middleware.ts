import { NextResponse, type NextRequest } from "next/server";

// Nonce-based CSP for the web app (hardening: removes script-src 'unsafe-inline').
// Next.js App Router emits inline bootstrap/RSC scripts; a per-request nonce lets
// us drop 'unsafe-inline' for scripts. Next reads the nonce from the CSP on the
// *request* headers and stamps it onto every script it generates; the same policy
// on the *response* is what the browser enforces. 'strict-dynamic' lets those
// nonce'd scripts load the chunk graph without host allowlisting.
//
// style-src keeps 'unsafe-inline' on purpose: nonces don't cover style attributes,
// and React/Tailwind inject inline styles. script-src is the XSS-relevant surface.
//
// The /api path is proxied to FastAPI and never reaches Next — Caddy sets its CSP.
export function middleware(request: NextRequest) {
  const nonce = btoa(crypto.randomUUID());
  const csp = [
    `default-src 'self'`,
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'`,
    `style-src 'self' 'unsafe-inline'`,
    `img-src 'self' data: blob:`,
    `font-src 'self' data:`,
    `connect-src 'self'`,
    `object-src 'none'`,
    `base-uri 'self'`,
    `form-action 'self'`,
    `frame-ancestors 'none'`,
  ].join("; ");

  const requestHeaders = new Headers(request.headers);
  requestHeaders.set("x-nonce", nonce);
  // The root layout has no other way to know the current path, and it needs it
  // to render /set-password without app chrome (no escape hatch out of a
  // forced password change).
  requestHeaders.set("x-pathname", request.nextUrl.pathname);
  requestHeaders.set("Content-Security-Policy", csp);

  const response = NextResponse.next({ request: { headers: requestHeaders } });
  response.headers.set("Content-Security-Policy", csp);
  return response;
}

export const config = {
  // Every document route; static assets carry no inline scripts and can't be
  // nonce'd (their chunks are authorized via strict-dynamic from the page).
  matcher: "/((?!_next/static|_next/image|favicon.ico).*)",
};
