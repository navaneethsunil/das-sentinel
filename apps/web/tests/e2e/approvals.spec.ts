import { expect, test, type Page } from "@playwright/test";

import { gotoStable, signIn } from "./helpers";

const pad = (n: number) => String(n).padStart(2, "0");
const asLocalInput = (d: Date) =>
  `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;

/** An active engagement whose ceiling permits high risk, with an in-scope target
 * and an accepted ROE — the preconditions for requesting an approval gate. */
async function setupHighRiskEngagement(page: Page, name: string): Promise<string> {
  await signIn(page);
  const now = Date.now();

  await page.goto("/engagements/new");
  await page.getByLabel("Name").fill(name);
  await page.getByLabel("Client / system under test").fill("Approval Lab");
  await page.getByLabel("Test window start").fill(asLocalInput(new Date(now - 864e5)));
  await page.getByLabel("Test window end").fill(asLocalInput(new Date(now + 864e5)));
  await page.getByLabel("Maximum intensity").selectOption("high_risk");
  await page.getByRole("button", { name: "Create engagement" }).click();
  await page.waitForURL((url) => /\/engagements\/[0-9a-f-]{36}$/.test(url.pathname));
  const engagementPath = new URL(page.url()).pathname;

  await page.getByLabel("Matcher type").selectOption("domain");
  await page.getByLabel("Value").fill("approval-lab.example.com");
  await page.getByRole("button", { name: "Add scope item" }).click();
  await expect(
    page.getByTestId("scope-allow-list").getByText("approval-lab.example.com"),
  ).toBeVisible();

  await page.getByRole("link", { name: "Add target" }).click();
  await page.waitForURL((url) => url.pathname.endsWith("/targets/new"));
  await page.getByLabel("Name").fill("Approval target");
  await page.getByLabel("URL").fill("https://approval-lab.example.com/");
  await page.getByRole("button", { name: "Add target" }).click();
  await page.waitForURL((url) => /\/engagements\/[0-9a-f-]{36}$/.test(url.pathname));

  await page.getByLabel(/I have read the Rules of Engagement/).check();
  await page.getByRole("button", { name: "Accept Rules of Engagement" }).click();
  await expect(page.getByTestId("roe-status")).toHaveText("Accepted");

  await page.getByRole("button", { name: "Activate" }).click();
  await expect(page.getByTestId("engagement-status")).toHaveText("Active");
  return engagementPath;
}

// M1-B11 UI: the approvals surface exists, is reachable from the scanner
// launcher's high-risk note and the sidebar, and requesting a gate works.
test("approvals: request a high-risk gate from the UI, reachable from the launcher note", async ({
  page,
}) => {
  const engagementPath = await setupHighRiskEngagement(page, `e2e-approvals-${Date.now()}`);

  // The high-risk note now links to the real page, not back to the overview.
  await page.getByTestId("high-risk-note").getByRole("link", { name: "Approvals" }).click();
  await page.waitForURL((url) => url.pathname === `${engagementPath}/approvals`);
  await expect(page.getByRole("heading", { name: "Approvals", exact: true })).toBeVisible();
  await expect(page.getByTestId("approvals-manager")).toBeVisible();

  // Sidebar entry for the current engagement.
  await expect(page.locator("nav").getByRole("link", { name: "Approvals" })).toBeVisible();

  await page.getByLabel("High-risk action").selectOption("exploit_validation");
  await page.getByLabel("Justification").fill("e2e: client authorized exploit validation");
  await page.getByRole("button", { name: "Request approval" }).click();

  const row = page.getByTestId("approval-row").first();
  await expect(row).toBeVisible();
  await expect(row.getByTestId("approval-status")).toHaveText("pending");
  await expect(page.getByTestId("approval-notice")).toContainText("second person");
});

// Four-eyes (Settings.approval_require_separate_approver, default on): an admin
// holds both capabilities, so the UI must refuse its own decision — and say why.
test("approvals: four-eyes blocks the requester from deciding their own gate", async ({ page }) => {
  const engagementPath = await setupHighRiskEngagement(page, `e2e-four-eyes-${Date.now()}`);
  await gotoStable(page, `${engagementPath}/approvals`);

  await page.getByLabel("Justification").fill("e2e: four-eyes probe");
  await page.getByRole("button", { name: "Request approval" }).click();
  const row = page.getByTestId("approval-row").first();
  await expect(row.getByTestId("approval-status")).toHaveText("pending");

  // Same signed-in admin requested it, so Approve must be refused, not silently
  // accepted, and the gate must stay pending.
  await row.getByRole("button", { name: "Approve" }).click();
  await expect(page.getByTestId("approvals-manager").getByRole("alert")).toContainText(
    "someone other than the requester",
  );
  await expect(row.getByTestId("approval-status")).toHaveText("pending");
});
