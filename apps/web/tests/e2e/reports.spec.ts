import { execFileSync } from "node:child_process";
import path from "node:path";

import { expect, test } from "@playwright/test";

import { signIn } from "./helpers";

const REPO_ROOT = path.resolve(process.cwd(), "..", "..");
const SCRIPTS_MOUNT = `${REPO_ROOT}/apps/api/scripts:/app/scripts:ro`;

function seed(script: string): string {
  return execFileSync(
    "docker",
    [
      "compose",
      "run",
      "--rm",
      "--no-deps",
      "-v",
      SCRIPTS_MOUNT,
      "--entrypoint",
      "sh",
      "api",
      "-c",
      `cd /app && PYTHONPATH=/app uv run --no-sync python scripts/${script}`,
    ],
    { cwd: REPO_ROOT, encoding: "utf8" },
  );
}

let engagementId: string;

test.beforeAll(() => {
  seed("seed_e2e_user.py");
  const out = seed("seed_e2e_findings.py"); // engagement with 2 findings + evidence
  const match = out.match(/ENGAGEMENT_ID=([0-9a-f-]{36})/);
  if (!match) {
    throw new Error(`seed did not print an engagement id:\n${out}`);
  }
  engagementId = match[1];
});

// M3-F3: generate a report, edit it, export CSV + Markdown, finalize (locks it),
// and delete it. Exercises the full B5 lifecycle through the UI.
test("report builder: generate, edit, export, finalize, delete", async ({ page }) => {
  await signIn(page);

  // reach the reports surface from the engagement page
  await page.goto(`/engagements/${engagementId}`);
  await page.getByTestId("view-reports").click();
  await page.waitForURL((url) => url.pathname.endsWith("/reports"));

  // generate a POA&M report → lands on the builder
  await page.getByLabel("Type").selectOption("poam");
  await page.getByLabel("Title").fill(`e2e POA&M ${Date.now()}`);
  await page.getByRole("button", { name: "Generate report" }).click();
  await page.waitForURL((url) => /\/reports\/[0-9a-f-]{36}$/.test(url.pathname));

  const builder = page.getByTestId("report-builder");
  await expect(builder).toBeVisible();
  await expect(builder.getByTestId("report-status")).toHaveText("Draft");
  // the snapshot carried the engagement's two findings
  await expect(builder.getByTestId("report-finding")).toHaveCount(2);

  // edit the summary + a POA&M field, then save
  await page.locator("#report_summary").fill("Overall posture is fair; two LLM findings.");
  await builder
    .getByTestId("report-finding")
    .first()
    .getByLabel("Responsible owner")
    .fill("Team Blue");
  await page.getByRole("button", { name: "Save changes" }).click();
  await expect(page.getByText("Saved.")).toBeVisible();

  // export POA&M CSV — a real browser download
  const csvDownload = page.waitForEvent("download");
  await builder.getByTestId("download-csv").click();
  expect((await csvDownload).suggestedFilename()).toMatch(/^poam-.*\.csv$/);

  // export Markdown
  const mdDownload = page.waitForEvent("download");
  await builder.getByTestId("download-md").click();
  expect((await mdDownload).suggestedFilename()).toMatch(/^report-.*\.md$/);

  // finalize → read-only; the summary field is disabled
  await builder.getByTestId("finalize").click();
  await expect(builder.getByTestId("report-status")).toHaveText("Final");
  await expect(page.locator("#report_summary")).toBeDisabled();
  // export still works after finalize
  const finalCsv = page.waitForEvent("download");
  await builder.getByTestId("download-csv").click();
  expect((await finalCsv).suggestedFilename()).toMatch(/^poam-.*\.csv$/);

  // delete (confirm dialog) → back to the reports list
  page.once("dialog", (dialog) => void dialog.accept());
  await page.getByRole("button", { name: "Delete" }).click();
  await page.waitForURL((url) => url.pathname.endsWith("/reports"));
});
