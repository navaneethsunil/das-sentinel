import { defineConfig } from "@playwright/test";

// E2E smoke config (M0-T1). The stack must already be running (docker compose
// up) — the tests drive the real single ingress, never a dev server.
export default defineConfig({
  testDir: "./tests/e2e",
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
