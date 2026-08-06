import { execFileSync } from "node:child_process";
import path from "node:path";

import { expect, test, type Page } from "@playwright/test";

import { signIn } from "./helpers";

// The stack lives at the repo root (two levels up from apps/web, where
// Playwright runs). The cancel test controls the worker there so a launched
// scan stays active long enough to exercise the emergency-stop button.
const REPO_ROOT = path.resolve(process.cwd(), "..", "..");

// Fixed argv (no shell, no interpolation) — flip one compose service on/off.
// redteam-worker sits behind a profile and may not exist in this stack at all, so
// failures are ignored: holding a queue that has no consumer is already the state
// the caller wants.
function composeService(action: "stop" | "start", service: "worker" | "redteam-worker"): void {
  const argv =
    service === "redteam-worker"
      ? ["compose", "--profile", "redteam", action, service]
      : ["compose", action, service];
  try {
    execFileSync("docker", argv, { cwd: REPO_ROOT, stdio: "pipe" });
  } catch {
    if (service === "worker") {
      throw new Error(`docker compose ${action} ${service} failed`);
    }
  }
}

const pad = (n: number) => String(n).padStart(2, "0");
const asLocalInput = (d: Date) =>
  `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;

/** Build a launchable engagement end to end (scope → ROE → active LLM target)
 * and leave the page on its detail view, ready to launch a scan. */
async function setupLaunchableEngagement(page: Page, name: string): Promise<void> {
  await signIn(page);

  // a test window bracketing "now" — the keystone refuses a launch without one
  const now = Date.now();
  const windowStart = asLocalInput(new Date(now - 864e5));
  const windowEnd = asLocalInput(new Date(now + 864e5));

  await page.goto("/engagements/new");
  await page.getByLabel("Name").fill(name);
  await page.getByLabel("Client / system under test").fill("Scan Lab");
  await page.getByLabel("Test window start").fill(windowStart);
  await page.getByLabel("Test window end").fill(windowEnd);
  await page.getByRole("button", { name: "Create engagement" }).click();
  await page.waitForURL((url) => /\/engagements\/[0-9a-f-]{36}$/.test(url.pathname));

  await page.getByLabel("Matcher type").selectOption("domain");
  await page.getByLabel("Value").fill("mock-llm.example.com");
  await page.getByRole("button", { name: "Add scope item" }).click();
  await expect(
    page.getByTestId("scope-allow-list").getByText("mock-llm.example.com"),
  ).toBeVisible();

  await page.getByLabel(/I have read the Rules of Engagement/).check();
  await page.getByRole("button", { name: "Accept Rules of Engagement" }).click();
  await expect(page.getByTestId("roe-status")).toHaveText("Accepted");

  await page.getByRole("link", { name: "Add LLM target" }).click();
  await page.waitForURL((url) => url.pathname.endsWith("/targets/new"));
  await page.getByLabel("Name").fill("Mock chatbot");
  await page.getByLabel("Type").selectOption("ai_chatbot");
  await page.getByLabel("URL").fill("https://mock-llm.example.com/v1/chat/completions");
  await page
    .getByLabel("Connector config (transport shape, JSON)")
    .fill('{"mode": "chat_messages"}');
  await page.getByRole("button", { name: "Add target" }).click();
  await page.waitForURL((url) => /\/engagements\/[0-9a-f-]{36}$/.test(url.pathname));
  await expect(page.getByTestId("targets-table").getByText("Mock chatbot")).toBeVisible();

  await page.getByRole("button", { name: "Activate" }).click();
  await expect(page.getByTestId("engagement-status")).toHaveText("Active");
  await expect(page.getByLabel("Target")).toHaveValue(/[0-9a-f-]{36}/);
}

// M2-F1: LLM target connector config + suite launcher — configure an LLM
// target and launch an in-scope suite scan; the scope keystone gates the launch
// from the UI (over-intensity is blocked with the reason surfaced).
test("suite launcher: configure LLM target, launch a scan, and see the intensity gate block", async ({
  page,
}) => {
  await setupLaunchableEngagement(page, `e2e-scans-${Date.now()}`);

  await page.getByRole("button", { name: "Launch scan" }).click();
  const scansTable = page.getByTestId("scans-table");
  await expect(scansTable).toBeVisible();
  await expect(scansTable.getByTestId("scan-status").first()).toHaveText(
    /Queued|Running|Completed/,
  );

  await page.getByLabel("Intensity").selectOption("authenticated_active");
  await page.getByRole("button", { name: "Launch scan" }).click();
  await expect(
    page.getByRole("alert").filter({ hasText: "exceeds the engagement's maximum intensity" }),
  ).toBeVisible();
});

// M2-F2 + T1 (live status): a launched suite scan is enqueued, its status renders
// and polls in place, and it routes to the `redteam` queue (PyRIT image). The
// base worker must NEVER pick one up — it consumes only the default queue and
// lacks the tools, so it could only run the no-op placeholder and report a scan
// "completed" that executed nothing. That is asserted on runner_ref rather than
// on the scan staying Queued, so the test holds whether or not this stack runs a
// redteam worker. Real suite completion is proven by verify_e2e_llm_scan.py.
test("live status: a launched suite scan is enqueued and routed to the suite runner", async ({
  page,
}) => {
  await setupLaunchableEngagement(page, `e2e-scan-live-${Date.now()}`);
  const engagementId = new URL(page.url()).pathname.split("/")[2];

  await page.getByRole("button", { name: "Launch scan" }).click();
  const status = page.getByTestId("scans-table").getByTestId("scan-status").first();
  await expect(status).toBeVisible();
  // Give the polling panel a couple of cycles before reading the record.
  await page.waitForTimeout(6000);

  const scans = await (await page.request.get(`/api/engagements/${engagementId}/scans`)).json();
  const scan = scans[0];
  expect(["queued", "running", "completed", "failed", "cancelled"]).toContain(scan.status);
  // null = still queued (no redteam worker here); "inproc:…" = the in-process
  // suite owner ran it. A subprocess pid would mean the placeholder path ran.
  expect(scan.runner_ref === null || String(scan.runner_ref).startsWith("inproc:")).toBe(true);
});

// M2-F2 (emergency stop): with the worker stopped, a launched scan stays queued
// so the cancel button is exercised — clicking it requests the stop (the row
// shows "Stopping…"). The worker-side kill itself is proven in
// scripts/verify_emergency_stop.py; here we prove the UI is wired to the route.
test.describe("emergency stop button (worker held so the scan stays active)", () => {
  // Hold BOTH consumers: suite scans route to `redteam`, so a running redteam
  // worker would finish this scan before the cancel button could be exercised.
  test.beforeAll(() => {
    composeService("stop", "worker");
    composeService("stop", "redteam-worker");
  });
  test.afterAll(() => {
    composeService("start", "worker");
    composeService("start", "redteam-worker");
  });

  test("cancel button requests emergency stop on a queued scan", async ({ page }) => {
    await setupLaunchableEngagement(page, `e2e-scan-cancel-${Date.now()}`);

    await page.getByRole("button", { name: "Launch scan" }).click();
    const row = page.getByTestId("scan-row").first();
    await expect(row.getByTestId("scan-status")).toHaveText("Queued");

    const cancel = row.getByRole("button", { name: "Cancel" });
    await expect(cancel).toBeVisible();
    await cancel.click();

    // The stop was requested (cancel_requested); with the worker held, the scan
    // stays queued and the row surfaces the pending stop.
    await expect(row.getByTestId("scan-stopping")).toBeVisible();
  });
});
