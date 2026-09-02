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

/** Drive the custom DateTimeField popup: open it, navigate to the target
 * month, click the day, set the time, and Apply (all inside the popup). */
export async function pickDateTime(page: Page, label: string, date: Date): Promise<void> {
  const pad = (n: number) => String(n).padStart(2, "0");
  const dayIso = `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}`;
  await page.getByLabel(label, { exact: true }).click();
  const dialog = page.getByRole("dialog", { name: `${label} picker` });
  const shown = (await dialog.getAttribute("data-month")) ?? dayIso.slice(0, 7);
  const [shownYear, shownMonth] = shown.split("-").map(Number);
  const diff = (date.getFullYear() - shownYear) * 12 + (date.getMonth() + 1 - shownMonth);
  for (let i = 0; i < Math.abs(diff); i++) {
    await dialog.getByRole("button", { name: diff > 0 ? "Next month" : "Previous month" }).click();
  }
  await dialog.getByRole("button", { name: dayIso }).click();
  await dialog.getByLabel("Time").fill(`${pad(date.getHours())}:${pad(date.getMinutes())}`);
  await dialog.getByRole("button", { name: "Apply" }).click();
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
