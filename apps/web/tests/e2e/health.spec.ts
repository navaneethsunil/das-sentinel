import { expect, test } from "@playwright/test";

// M0-T1 round-trip: browser → proxy (:443) → web (RSC render) → api → db/valkey.
// /health is a force-dynamic Server Component, so every badge below is proof the
// whole chain answered during THIS request — nothing is prerendered or cached.
test("health page renders an all-ok stack through the single ingress", async ({ page }) => {
  await page.goto("/health");

  await expect(page.getByRole("heading", { name: "System health" })).toBeVisible();

  for (const probe of ["API (liveness)", "Database", "Valkey"]) {
    const row = page.locator("li", { hasText: probe });
    await expect(row.getByText("ok", { exact: true })).toBeVisible();
  }

  // Local watchable runs only (PW_PAUSE_MS=3000); 0 in CI.
  await page.waitForTimeout(Number(process.env.PW_PAUSE_MS ?? 0));
});

// Hardening: web pages carry a nonce-based CSP (no script-src 'unsafe-inline').
// The page above rendering + hydrating is the functional proof the nonce works;
// this asserts the policy shape so a regression to 'unsafe-inline' is caught.
test("web CSP is nonce-based with no script-src unsafe-inline", async ({ page }) => {
  const response = await page.goto("/health");
  const csp = response?.headers()["content-security-policy"] ?? "";
  expect(csp).toMatch(/script-src[^;]*'nonce-[^']+'/);
  expect(csp).toMatch(/script-src[^;]*'strict-dynamic'/);
  expect(csp).not.toMatch(/script-src[^;]*'unsafe-inline'/);
  expect(csp).toContain("frame-ancestors 'none'");
});
