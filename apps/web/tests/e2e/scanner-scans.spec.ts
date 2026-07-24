import { execFileSync } from "node:child_process";
import path from "node:path";

import { expect, test, type Page } from "@playwright/test";

import { signIn } from "./helpers";

const REPO_ROOT = path.resolve(process.cwd(), "..", "..");

// The source-archive upload stores evidence in MinIO; bucket creation is not in
// the API startup path (M2-B1), so bootstrap it here (idempotent) rather than
// depend on another spec's seed having run first.
test.beforeAll(() => {
  execFileSync(
    "docker",
    [
      "compose",
      "run",
      "--rm",
      "--no-deps",
      "-v",
      `${REPO_ROOT}/apps/api/scripts:/app/scripts:ro`,
      "--entrypoint",
      "sh",
      "api",
      "-c",
      "cd /app && PYTHONPATH=/app uv run --no-sync python scripts/ensure_bucket.py",
    ],
    { cwd: REPO_ROOT, stdio: "pipe" },
  );
});

const pad = (n: number) => String(n).padStart(2, "0");
const asLocalInput = (d: Date) =>
  `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;

const FIXTURE_ZIP = path.join(process.cwd(), "tests", "e2e", "fixtures", "sample-src.zip");

/** Build an active engagement with a source_archive target, leaving the page on
 * the engagement detail view. Returns the engagement URL. */
async function setupCodeEngagement(page: Page, name: string): Promise<string> {
  await signIn(page);

  const now = Date.now();
  await page.goto("/engagements/new");
  await page.getByLabel("Name").fill(name);
  await page.getByLabel("Client / system under test").fill("Code Lab");
  await page.getByLabel("Test window start").fill(asLocalInput(new Date(now - 864e5)));
  await page.getByLabel("Test window end").fill(asLocalInput(new Date(now + 864e5)));
  await page.getByRole("button", { name: "Create engagement" }).click();
  await page.waitForURL((url) => /\/engagements\/[0-9a-f-]{36}$/.test(url.pathname));
  const engagementUrl = page.url();

  // A scope item keeps the ROE meaningful; a source_archive target is authorized
  // regardless (it is engagement-local material, scanned in place).
  await page.getByLabel("Matcher type").selectOption("domain");
  await page.getByLabel("Value").fill("code.example.com");
  await page.getByRole("button", { name: "Add scope item" }).click();
  await expect(page.getByTestId("scope-allow-list").getByText("code.example.com")).toBeVisible();

  await page.getByLabel(/I have read the Rules of Engagement/).check();
  await page.getByRole("button", { name: "Accept Rules of Engagement" }).click();
  await expect(page.getByTestId("roe-status")).toHaveText("Accepted");

  await page.goto(`${engagementUrl}/targets/new`);
  await page.getByLabel("Name").fill("App source");
  await page.getByLabel("Type").selectOption("source_archive");
  await page.getByLabel("Archive reference").fill("uploads/app-src.zip");
  await page.getByRole("button", { name: "Add target" }).click();
  await page.waitForURL((url) => /\/engagements\/[0-9a-f-]{36}$/.test(url.pathname));
  await expect(page.getByTestId("targets-table").getByText("App source")).toBeVisible();

  await page.getByRole("button", { name: "Activate" }).click();
  await expect(page.getByTestId("engagement-status")).toHaveText("Active");
  return engagementUrl;
}

// M3-F1: launch a SAST (Semgrep) scanner scan against a source_archive target.
test("scanner launcher: launch a Semgrep scan against a code target", async ({ page }) => {
  await setupCodeEngagement(page, `e2e-scanner-${Date.now()}`);

  const launcher = page.getByTestId("scanner-launcher");
  await expect(launcher).toBeVisible();
  // The code target auto-derives the Semgrep scanner; the high-risk gate notice
  // is shown (approval-gate requirement).
  await expect(launcher.getByText(/Semgrep/)).toBeVisible();
  await expect(page.getByTestId("high-risk-note")).toBeVisible();

  await launcher.getByRole("button", { name: "Launch scanner" }).click();
  const scansTable = page.getByTestId("scans-table");
  await expect(scansTable).toBeVisible();
  await expect(scansTable.getByTestId("scan-status").first()).toHaveText(
    /Queued|Running|Completed/,
  );
});

// M3-F1: upload a source archive to a source_archive target (B1 upload UI).
test("source-archive upload: attach a code archive to a source_archive target", async ({
  page,
}) => {
  const engagementUrl = await setupCodeEngagement(page, `e2e-upload-${Date.now()}`);

  // Open the target's edit page via the targets table link.
  await page.goto(engagementUrl);
  await page.getByTestId("targets-table").getByRole("link", { name: "App source" }).click();
  await page.waitForURL((url) => /\/targets\/[0-9a-f-]{36}\/edit$/.test(url.pathname));

  const upload = page.getByTestId("source-archive-upload");
  await expect(upload).toBeVisible();
  await upload.locator('input[type="file"]').setInputFiles(FIXTURE_ZIP);
  await upload.getByRole("button", { name: "Upload archive" }).click();

  await expect(page.getByTestId("upload-result")).toContainText("Uploaded zip archive");
});
