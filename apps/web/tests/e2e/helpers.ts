import type { Page } from "@playwright/test";

// Fixture user from apps/api/scripts/seed_e2e_user.py (run before the specs,
// locally and in CI).
export const E2E_EMAIL = "e2e-admin@dassentinel.example.com";
export const E2E_PASSWORD = "e2e horse battery staple";

export async function signIn(page: Page) {
  await page.goto("/login");
  await page.getByLabel("Email").fill(E2E_EMAIL);
  await page.getByLabel("Password").fill(E2E_PASSWORD);
  await page.getByRole("button", { name: "Sign in" }).click();
  await page.waitForURL((url) => url.pathname === "/");
}
