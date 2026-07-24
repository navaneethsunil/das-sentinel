import { execFileSync } from "node:child_process";
import path from "node:path";

import { expect, test } from "@playwright/test";

import { signIn } from "./helpers";

// The stack lives at the repo root (two levels up from apps/web, where
// Playwright runs). We seed real findings + transcript evidence for the e2e org
// through the API's own suite path, then read them back through the UI.
const REPO_ROOT = path.resolve(process.cwd(), "..", "..");
const SCRIPTS_MOUNT = `${REPO_ROOT}/apps/api/scripts:/app/scripts:ro`;
const KB_MOUNT = `${REPO_ROOT}/packages/compliance:/app/packages/compliance:ro`;

/** Run a seed script inside a one-off api container (fixed argv — no shell).
 * `extraMounts` adds read-only volumes (e.g. the compliance KB for seeding). */
function seed(script: string, extraMounts: string[] = []): string {
  const mountArgs = [SCRIPTS_MOUNT, ...extraMounts].flatMap((m) => ["-v", m]);
  return execFileSync(
    "docker",
    [
      "compose",
      "run",
      "--rm",
      "--no-deps",
      ...mountArgs,
      "--entrypoint",
      "sh",
      "api",
      "-c",
      `cd /app && PYTHONPATH=/app uv run --no-sync python scripts/${script}`,
    ],
    { cwd: REPO_ROOT, encoding: "utf8" },
  );
}

// The findings fixture engagement id, captured from the seed output.
let engagementId: string;

test.beforeAll(() => {
  seed("seed_e2e_user.py"); // ensure the e2e org + admin exist first
  seed("seed_compliance.py", [KB_MOUNT]); // KB so compliance auto-map has controls
  const out = seed("seed_e2e_findings.py");
  const match = out.match(/ENGAGEMENT_ID=([0-9a-f-]{36})/);
  if (!match) {
    throw new Error(`seed did not print an engagement id:\n${out}`);
  }
  engagementId = match[1];
});

// M2-F3: the detail page links to the findings list, which surfaces severity,
// OWASP LLM tag, and provenance; automated findings are clearly NOT validated.
test("findings list shows severity, OWASP tag, and an automated (not validated) label", async ({
  page,
}) => {
  await signIn(page);
  await page.goto(`/engagements/${engagementId}`);
  await page.getByTestId("view-findings").click();
  await page.waitForURL((url) => url.pathname.endsWith("/findings"));

  const table = page.getByTestId("findings-table");
  await expect(table).toBeVisible();
  // Two findings seeded: LLM01 (high) + LLM07 (medium), severity-first.
  await expect(table.getByTestId("finding-row")).toHaveCount(2);
  await expect(table.getByTestId("finding-owasp").first()).toHaveText("LLM01");
  // Provenance is Automated — the truthfulness control (CLAUDE.md §2.9).
  await expect(table.getByTestId("finding-provenance").first()).toHaveText("Automated");
});

// M2-F3: the finding detail shows provenance + status, the "not human-validated"
// notice for an automated finding, and an evidence transcript that loads through
// the API (never the browser hitting object storage).
test("finding detail shows provenance/status, the unvalidated notice, and a transcript", async ({
  page,
}) => {
  await signIn(page);
  await page.goto(`/engagements/${engagementId}/findings`);

  await page
    .getByTestId("findings-table")
    .getByRole("link", { name: "Direct system-prompt override" })
    .click();
  await page.waitForURL((url) => /\/findings\/[0-9a-f-]{36}$/.test(url.pathname));

  await expect(page.getByTestId("finding-provenance")).toHaveText("Automated");
  await expect(page.getByTestId("finding-status").first()).toHaveText("Open");
  await expect(page.getByTestId("finding-owasp")).toHaveText("LLM01");
  await expect(page.getByTestId("unvalidated-notice")).toBeVisible();

  // The transcript viewer fetches the evidence blob on demand through the API.
  await page.getByTestId("evidence-toggle").first().click();
  const content = page.getByTestId("evidence-content");
  await expect(content).toBeVisible();
  await expect(content.getByText("canary-canary-direct-aaa").first()).toBeVisible();
});

// M2-F3: the dedicated findings list page lists all findings for the engagement.
test("engagement findings page lists all findings", async ({ page }) => {
  await signIn(page);
  await page.goto(`/engagements/${engagementId}/findings`);

  const table = page.getByTestId("findings-table");
  await expect(table).toBeVisible();
  await expect(table.getByTestId("finding-row")).toHaveCount(2);
});

/** Open the most-severe finding's detail (LLM01, high) from the findings list. */
async function openTopFinding(page: import("@playwright/test").Page): Promise<void> {
  await page.goto(`/engagements/${engagementId}/findings`);
  await page
    .getByTestId("findings-table")
    .getByTestId("finding-row")
    .first()
    .getByRole("link")
    .click();
  await page.waitForURL((url) => /\/findings\/[0-9a-f-]{36}$/.test(url.pathname));
}

// M3-F2: the CVSS editor scores a finding from a vector; the base score + band
// are derived server-side (B3) and shown.
test("finding detail: CVSS editor scores from a vector", async ({ page }) => {
  await signIn(page);
  await openTopFinding(page);

  const cvss = page.getByTestId("cvss-editor");
  await expect(cvss).toBeVisible();
  await page
    .locator("#cvss_vector")
    .fill("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H");
  await cvss.getByRole("button", { name: "Save score" }).click();
  // 10.0 / Critical, derived by the cvss package (latest score wins, re-run safe).
  await expect(cvss.getByTestId("cvss-score")).toHaveText("10.0");
  await expect(cvss.getByTestId("finding-severity")).toHaveText("Critical");
});

// M3-F2: compliance mappings — auto-map (exact/identity → LLM01), remove, and
// manual add via the framework→control picker (deterministic: remove before add).
test("finding detail: compliance auto-map, remove, and manual add", async ({ page }) => {
  await signIn(page);
  await openTopFinding(page);

  const comp = page.getByTestId("compliance-mappings");
  await expect(comp).toBeVisible();
  const llm01 = comp.getByTestId("mapping-tag").filter({ hasText: "LLM01" });

  // auto-map derives the owasp_llm_2025/LLM01 control (idempotent)
  await comp.getByTestId("auto-map").click();
  await expect(llm01).toBeVisible();
  await expect(llm01).toContainText("auto");

  // remove it → gone, then manually add it back via the picker (now VALIDATED)
  await llm01.getByRole("button", { name: "Remove LLM01" }).click();
  await expect(llm01).toHaveCount(0);

  await comp.getByLabel("Framework").selectOption({
    label: "OWASP Top 10 for Large Language Model Applications",
  });
  await comp.getByLabel("Control").selectOption({ label: "LLM01 — Prompt Injection" });
  await comp.getByRole("button", { name: "Add mapping" }).click();
  await expect(llm01).toBeVisible();
  await expect(llm01).not.toContainText("auto"); // human-added = validated

  // clean up so the run is repeatable
  await llm01.getByRole("button", { name: "Remove LLM01" }).click();
  await expect(llm01).toHaveCount(0);
});
