import { expect, test, type Page } from "@playwright/test";

import { gotoStable, signIn } from "./helpers";

// M1-F3: scope editor + ROE acceptance. Split into three independent flows so a
// transient hiccup in one doesn't cascade, and each stays well under the test
// timeout. Every mutation here goes through a client `router.refresh()` that
// re-runs the engagement detail page's multi-fetch RSC — under CI load that
// re-render can take several seconds, so refresh-dependent assertions use a
// generous timeout (SETTLE) rather than the 5s default that used to flake.
const SETTLE = { timeout: 15_000 };

// Each flow re-runs router.refresh several times; give the whole test headroom.
test.describe.configure({ timeout: 90_000 });

async function newEngagement(page: Page, name: string): Promise<string> {
  await gotoStable(page, "/engagements/new");
  await page.getByLabel("Name").fill(name);
  await page.getByLabel("Client / system under test").fill("Scope Lab");
  await page.getByRole("button", { name: "Create engagement" }).click();
  await page.waitForURL((url) => /\/engagements\/[0-9a-f-]{36}$/.test(url.pathname));
  return page.url();
}

async function addScopeItem(
  page: Page,
  opts: { list: "allow" | "deny"; type: string; value: string },
): Promise<void> {
  await page.getByLabel("List").selectOption(opts.list);
  await page.getByLabel("Matcher type").selectOption(opts.type);
  await page.getByLabel("Value").fill(opts.value);
  await page.getByRole("button", { name: "Add scope item" }).click();
}

// M1-F3: malformed values are rejected (422 surfaced, nothing stored); valid
// rules are added, a bare IP is normalized to /32, and the ROE text reflects them.
test("scope editor: reject malformed, add allow + normalized deny, reflect in ROE", async ({
  page,
}) => {
  await signIn(page);
  await newEngagement(page, `e2e-scope-${Date.now()}`);

  const allowList = page.getByTestId("scope-allow-list");
  const denyList = page.getByTestId("scope-deny-list");
  await expect(page.getByTestId("roe-status")).toHaveText("Acceptance required", SETTLE);
  await expect(allowList.getByText("nothing is in scope yet")).toBeVisible(SETTLE);

  // malformed value for the matcher type → 422 surfaced, nothing stored
  await addScopeItem(page, { list: "allow", type: "domain", value: "not a domain!" });
  await expect(page.getByRole("alert").filter({ hasText: "not a valid Domain" })).toBeVisible(
    SETTLE,
  );

  // allow rule: domain
  await page.getByLabel("Value").fill("app.acme.example.com");
  await page.getByRole("button", { name: "Add scope item" }).click();
  await expect(allowList.getByText("app.acme.example.com")).toBeVisible(SETTLE);

  // deny rule: bare IP normalized server-side to a /32
  await addScopeItem(page, { list: "deny", type: "ip_cidr", value: "10.9.8.7" });
  await expect(denyList.getByText("10.9.8.7/32")).toBeVisible(SETTLE);

  // the rendered ROE text reflects both rules
  const roeText = page.getByTestId("roe-text");
  await expect(roeText).toContainText("domain: app.acme.example.com", SETTLE);
  await expect(roeText).toContainText("ip_cidr: 10.9.8.7/32", SETTLE);
});

// M1-F3: acceptance is bound to the hash the user was shown — scope changing
// elsewhere after the page rendered makes this page's hash stale, so acceptance
// is refused (409) and forces a re-read + re-acknowledge.
test("ROE acceptance is bound to the shown hash: scope drift → 409 → re-accept", async ({
  page,
  context,
}) => {
  await signIn(page);
  const detailUrl = await newEngagement(page, `e2e-roe-drift-${Date.now()}`);

  await addScopeItem(page, { list: "allow", type: "domain", value: "app.acme.example.com" });
  await expect(page.getByTestId("scope-allow-list").getByText("app.acme.example.com")).toBeVisible(
    SETTLE,
  );

  // accept is armed only by the signed acknowledgement
  const acceptButton = page.getByRole("button", { name: "Accept Rules of Engagement" });
  const acknowledgement = page.getByLabel(/I have read the Rules of Engagement/);
  await expect(acceptButton).toBeDisabled();
  await acknowledgement.check();
  await expect(acceptButton).toBeEnabled();

  // scope changes on a second page AFTER this one rendered → stale hash here
  const page2 = await context.newPage();
  await gotoStable(page2, detailUrl);
  await page2.getByLabel("Value").fill("https://api.acme.example.com/v1");
  await page2.getByRole("button", { name: "Add scope item" }).click();
  await expect(
    page2.getByTestId("scope-allow-list").getByText("https://api.acme.example.com/v1"),
  ).toBeVisible(SETTLE);
  await page2.close();

  await acceptButton.click();
  await expect(page.getByRole("alert").filter({ hasText: "ROE changed" })).toBeVisible(SETTLE);

  // the 409 handler refreshed the panel to the current version — re-read,
  // re-acknowledge, accept
  await expect(page.getByTestId("roe-text")).toContainText(
    "url: https://api.acme.example.com/v1",
    SETTLE,
  );
  await acknowledgement.check();
  await acceptButton.click();
  await expect(page.getByTestId("roe-status")).toHaveText("Accepted", SETTLE);
});

// M1-F3: any scope edit after acceptance forces re-acceptance; reverting to the
// exact accepted state restores it (hash-based, not edit-count-based).
test("scope edit after acceptance forces re-acceptance; reverting restores it", async ({
  page,
}) => {
  await signIn(page);
  await newEngagement(page, `e2e-roe-revert-${Date.now()}`);

  const allowList = page.getByTestId("scope-allow-list");
  await addScopeItem(page, { list: "allow", type: "domain", value: "app.acme.example.com" });
  await expect(allowList.getByText("app.acme.example.com")).toBeVisible(SETTLE);

  await page.getByLabel(/I have read the Rules of Engagement/).check();
  await page.getByRole("button", { name: "Accept Rules of Engagement" }).click();
  await expect(page.getByTestId("roe-status")).toHaveText("Accepted", SETTLE);

  // edit after acceptance → re-acceptance required
  await addScopeItem(page, { list: "allow", type: "domain", value: "staging.acme.example.com" });
  await expect(allowList.getByText("staging.acme.example.com")).toBeVisible(SETTLE);
  await expect(page.getByTestId("roe-status")).toHaveText("Acceptance required", SETTLE);

  // remove it → scope reverts to exactly the accepted state → Accepted restored
  await page.getByRole("button", { name: "Remove staging.acme.example.com" }).click();
  await expect(allowList.getByText("staging.acme.example.com")).toHaveCount(0, SETTLE);
  await expect(page.getByTestId("roe-status")).toHaveText("Accepted", SETTLE);
});
