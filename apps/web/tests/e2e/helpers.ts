import type { Page } from "@playwright/test";

// Fixture user from apps/api/scripts/seed_e2e_user.py (run before the specs,
// locally and in CI).
export const E2E_EMAIL = "e2e-admin@dassentinel.example.com";
export const E2E_PASSWORD = "e2e horse battery staple";

// Transient transport resets seen on the CI runner (h3/QUIC buffer starvation,
// socket migration) — the nav fails before the page loads. These are safe to
// retry; a real 4xx/5xx surfaces as page content, not a goto rejection.
const TRANSIENT_NAV =
  /ERR_NETWORK_CHANGED|ERR_CONNECTION_(RESET|CLOSED|REFUSED|ABORTED)|ERR_ABORTED|ERR_EMPTY_RESPONSE/;

/** page.goto that retries a handful of times on transient transport resets.
 * Anything else (or exhausting the retries) rethrows unchanged. */
export async function gotoStable(page: Page, url: string, attempts = 3): Promise<void> {
  for (let attempt = 1; ; attempt++) {
    try {
      await page.goto(url);
      return;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (attempt >= attempts || !TRANSIENT_NAV.test(message)) {
        throw error;
      }
    }
  }
}

export async function signIn(page: Page) {
  await gotoStable(page, "/login");
  await page.getByLabel("Email").fill(E2E_EMAIL);
  await page.getByLabel("Password").fill(E2E_PASSWORD);
  await page.getByRole("button", { name: "Sign in" }).click();
  // Post-login redirect to the dashboard. Bound the wait so a stuck/reset
  // redirect under CI load fails fast enough for the configured retry to re-run,
  // instead of consuming the whole test timeout on one attempt.
  await page.waitForURL((url) => url.pathname === "/", { timeout: 30_000 });
}
