import { expect, test } from "@playwright/test";

import { E2E_EMAIL, signIn } from "./helpers";

// M1-F5: role-aware nav, current-engagement context bar, and the read-only
// audit viewer (Admin/Reviewer) with per-engagement filtering.
test("audit viewer: role-aware nav, engagement context bar, filtered event log", async ({
  page,
}) => {
  const stamp = Date.now();
  const nameA = `e2e-audit-a-${stamp}`;
  const nameB = `e2e-audit-b-${stamp}`;

  // signed out: no audit-log nav entry (role-gated; nothing is signed in)
  await page.goto("/login");
  await expect(page.getByRole("link", { name: "Audit log" })).toHaveCount(0);

  // the fixture user is an admin — the nav entry appears
  await signIn(page);
  await expect(page.getByRole("link", { name: "Audit log" })).toBeVisible();

  async function createEngagement(name: string) {
    await page.goto("/engagements/new");
    await page.getByLabel("Name").fill(name);
    await page.getByLabel("Client / system under test").fill("Audit Lab");
    await page.getByRole("button", { name: "Create engagement" }).click();
    await page.waitForURL((url) => /\/engagements\/[0-9a-f-]{36}$/.test(url.pathname));
  }

  // two engagements, so the filter has something to exclude
  await createEngagement(nameB);
  await createEngagement(nameA);

  // context bar: breadcrumb + status, on the detail page and its subpages
  const contextBar = page.getByTestId("engagement-context");
  await expect(contextBar.getByRole("link", { name: nameA })).toBeVisible();
  await expect(page.getByTestId("engagement-status")).toHaveText("Draft");
  await page.getByRole("link", { name: "Add target" }).click();
  await page.waitForURL((url) => url.pathname.endsWith("/targets/new"));
  await expect(contextBar.getByRole("link", { name: nameA })).toBeVisible();
  await contextBar.getByRole("link", { name: nameA }).click();
  await page.waitForURL((url) => /\/engagements\/[0-9a-f-]{36}$/.test(url.pathname));

  // one more audited action on A so the filtered view has two event kinds
  await page.getByRole("button", { name: "Activate" }).click();
  await expect(page.getByTestId("engagement-status")).toHaveText("Active");

  // per-engagement audit view via the context bar
  await page.getByRole("link", { name: "View audit log" }).click();
  await page.waitForURL((url) => url.pathname === "/audit");
  await expect(page.getByText("Filtered to engagement")).toBeVisible();
  const table = page.getByTestId("audit-table");
  await expect(table.getByText("engagement.created")).toBeVisible();
  await expect(table.getByText("engagement.status_changed")).toBeVisible();
  await expect(table.getByText(E2E_EMAIL).first()).toBeVisible();
  // filter really filters: only A's rows, B never appears
  await expect(table.getByRole("link", { name: nameA }).first()).toBeVisible();
  await expect(table.getByRole("link", { name: nameB })).toHaveCount(0);

  // clearing the filter shows the org-wide stream (B's creation included)
  await page.getByRole("link", { name: "show all" }).click();
  await expect(page.getByText("Filtered to engagement")).toHaveCount(0);
  await expect(table.getByRole("link", { name: nameB }).first()).toBeVisible();
});
