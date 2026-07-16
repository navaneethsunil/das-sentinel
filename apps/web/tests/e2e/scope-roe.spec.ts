import { expect, test } from "@playwright/test";

import { signIn } from "./helpers";

// M1-F3: scope editor + ROE acceptance flow — add/normalize/reject scope
// items, signed-acknowledgement acceptance bound to the rendered hash (a
// stale page gets 409, never a silent accept), and scope edits after
// acceptance forcing re-acceptance.
test("scope editor + ROE acceptance: normalize, reject, accept-what-you-saw, drift re-acceptance", async ({
  page,
  context,
}) => {
  const name = `e2e-scope-roe-${Date.now()}`;
  await signIn(page);

  // minimal engagement to hang scope + ROE off
  await page.goto("/engagements/new");
  await page.getByLabel("Name").fill(name);
  await page.getByLabel("Client / system under test").fill("Scope Lab");
  await page.getByRole("button", { name: "Create engagement" }).click();
  await page.waitForURL((url) => /\/engagements\/[0-9a-f-]{36}$/.test(url.pathname));
  const detailUrl = page.url();

  // fresh engagement: no scope, ROE not accepted
  const allowList = page.getByTestId("scope-allow-list");
  const denyList = page.getByTestId("scope-deny-list");
  await expect(page.getByTestId("roe-status")).toHaveText("Acceptance required");
  await expect(allowList.getByText("nothing is in scope yet")).toBeVisible();

  // malformed value for the matcher type → 422 surfaced, nothing stored
  await page.getByLabel("Matcher type").selectOption("domain");
  await page.getByLabel("Value").fill("not a domain!");
  await page.getByRole("button", { name: "Add scope item" }).click();
  await expect(page.getByRole("alert").filter({ hasText: "not a valid Domain" })).toBeVisible();

  // allow rule: domain
  await page.getByLabel("Value").fill("app.acme.example.com");
  await page.getByRole("button", { name: "Add scope item" }).click();
  await expect(allowList.getByText("app.acme.example.com")).toBeVisible();

  // deny rule: bare IP is normalized server-side to a /32
  await page.getByLabel("List").selectOption("deny");
  await page.getByLabel("Matcher type").selectOption("ip_cidr");
  await page.getByLabel("Value").fill("10.9.8.7");
  await page.getByRole("button", { name: "Add scope item" }).click();
  await expect(denyList.getByText("10.9.8.7/32")).toBeVisible();

  // the rendered ROE text reflects both rules
  const roeText = page.getByTestId("roe-text");
  await expect(roeText).toContainText("domain: app.acme.example.com");
  await expect(roeText).toContainText("ip_cidr: 10.9.8.7/32");

  // accept is armed only by the signed acknowledgement
  const acceptButton = page.getByRole("button", { name: "Accept Rules of Engagement" });
  const acknowledgement = page.getByLabel(/I have read the Rules of Engagement/);
  await expect(acceptButton).toBeDisabled();
  await acknowledgement.check();
  await expect(acceptButton).toBeEnabled();

  // scope changes elsewhere AFTER this page rendered → this page's hash is
  // stale and acceptance must be refused (accept only what you actually saw)
  const page2 = await context.newPage();
  await page2.goto(detailUrl);
  await page2.getByLabel("Value").fill("https://api.acme.example.com/v1");
  await page2.getByRole("button", { name: "Add scope item" }).click();
  await expect(
    page2.getByTestId("scope-allow-list").getByText("https://api.acme.example.com/v1"),
  ).toBeVisible();
  await page2.close();

  await acceptButton.click();
  await expect(page.getByRole("alert").filter({ hasText: "ROE changed" })).toBeVisible();

  // the 409 handler refreshed the panel to the current version — re-read,
  // re-acknowledge, accept
  await expect(roeText).toContainText("url: https://api.acme.example.com/v1");
  await acknowledgement.check();
  await acceptButton.click();
  await expect(page.getByTestId("roe-status")).toHaveText("Accepted");

  // any scope edit after acceptance forces re-acceptance
  await page.getByLabel("List").selectOption("allow");
  await page.getByLabel("Matcher type").selectOption("domain");
  await page.getByLabel("Value").fill("staging.acme.example.com");
  await page.getByRole("button", { name: "Add scope item" }).click();
  await expect(allowList.getByText("staging.acme.example.com")).toBeVisible();
  await expect(page.getByTestId("roe-status")).toHaveText("Acceptance required");

  // removing the item reverts scope to exactly the accepted state — the
  // recomputed hash matches the acknowledgement again, so acceptance is
  // validly restored (hash-based, not edit-count-based)
  await page.getByRole("button", { name: "Remove staging.acme.example.com" }).click();
  await expect(allowList.getByText("staging.acme.example.com")).toHaveCount(0);
  await expect(page.getByTestId("roe-status")).toHaveText("Accepted");
});
