import { defineConfig } from "@playwright/test";

// E2E smoke config (M0-T1). The stack must already be running (docker compose
// up) — the tests drive the real single ingress, never a dev server.
export default defineConfig({
  testDir: "./tests/e2e",
  // Serial: all specs share one fixture user on one stack, and the auth spec's
  // "sign out everywhere" revokes ALL of that user's sessions — a parallel
  // worker signed in as the same user gets its session killed mid-test.
  workers: 1,
  // Absorb CI-load timing flakes (transport resets, slow RSC re-render after a
  // router.refresh under a loaded runner) — the router.refresh-heavy scope-roe
  // and the sign-out-everywhere flows are timing-marginal on the GH runner but
  // pass locally every time. A retry that succeeds is reported "flaky" (visible,
  // not hidden); a real deterministic failure still fails BOTH attempts and the
  // job. No retries locally so a genuine break surfaces immediately.
  retries: process.env.CI ? 1 : 0,
  // Chromium only: the smoke test proves the stack path, not a browser matrix.
  projects: [{ name: "chromium", use: { browserName: "chromium" } }],
  use: {
    baseURL: process.env.BASE_URL ?? "https://localhost",
    // Caddy mints certs from its internal CA (air-gap — no public ACME), so
    // the browser must accept the locally-trusted-only chain.
    ignoreHTTPSErrors: true,
    launchOptions: {
      // Local watchable runs: PW_SLOWMO=500 npx playwright test --headed
      slowMo: Number(process.env.PW_SLOWMO ?? 0),
    },
  },
});
