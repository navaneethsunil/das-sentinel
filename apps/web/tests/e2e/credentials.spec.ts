import { expect, test } from "@playwright/test";

import { signIn } from "./helpers";

// Managed credential vault: create a credential (secret encrypted, write-only),
// see it listed with its cred:<id> reference (never the secret), reference it
// from a target via the picker, then delete it.
test("credentials: create, reference from a target, delete", async ({ page }) => {
  const credName = `e2e-cred-${Date.now()}`;
  const secretValue = "sk-live-DO-NOT-SHOW-1234567890";
  await signIn(page);

  // Reach the vault the way a user would — the left-menu entry.
  await page.getByRole("link", { name: "Credentials" }).click();
  await page.waitForURL((url) => url.pathname === "/credentials");
  await expect(page.getByRole("heading", { name: "Credentials" })).toBeVisible();

  // Create a credential.
  await page.getByLabel("Name").fill(credName);
  await page.getByLabel("Description (optional)").fill("E2E test bearer token");
  await page.getByLabel("Secret").fill(secretValue);
  await page.getByRole("button", { name: "Create credential" }).click();

  // It appears in the list with a cred:<id> reference — and the secret is NOWHERE
  // on the page (write-only).
  const row = page.getByTestId("credential-row").filter({ hasText: credName });
  await expect(row).toBeVisible();
  await expect(row.getByText(/^cred:[0-9a-f-]{36}$/)).toBeVisible();
  await expect(page.getByText(secretValue)).toHaveCount(0);

  const reference = (await row.getByText(/^cred:/).textContent())?.trim() ?? "";
  expect(reference).toMatch(/^cred:[0-9a-f-]{36}$/);

  // Set up an engagement + target, and reference the credential via the picker.
  const engName = `e2e-cred-eng-${Date.now()}`;
  await page.goto("/engagements/new");
  await page.getByLabel("Name").fill(engName);
  await page.getByLabel("Client / system under test").fill("Cred Lab");
  await page.getByRole("button", { name: "Create engagement" }).click();
  await page.waitForURL((url) => /\/engagements\/[0-9a-f-]{36}$/.test(url.pathname));

  await page.getByRole("link", { name: "Add target" }).click();
  await page.waitForURL((url) => url.pathname.endsWith("/targets/new"));
  await page.getByLabel("Name").fill("Portal with credential");
  await page.getByLabel("URL").fill("https://portal.cred.example.com");
  await page.getByLabel("Auth status").selectOption("configured");

  // Pick the credential from the vault — it inserts the reference, not the secret.
  await page.getByLabel("Credential", { exact: true }).selectOption(reference);
  const authConfig = page.getByLabel("Auth config (credential references only, JSON)");
  await expect(authConfig).toHaveValue(new RegExp(reference.replace(/[-]/g, "\\$&")));
  await expect(authConfig).not.toHaveValue(new RegExp(secretValue));

  await page.getByRole("button", { name: "Add target" }).click();
  await page.waitForURL((url) => /\/engagements\/[0-9a-f-]{36}$/.test(url.pathname));
  await expect(
    page.getByTestId("targets-table").getByRole("link", { name: "Portal with credential" }),
  ).toBeVisible();

  // Delete the credential.
  await page.getByRole("link", { name: "Credentials" }).click();
  await page.waitForURL((url) => url.pathname === "/credentials");
  await page
    .getByTestId("credential-row")
    .filter({ hasText: credName })
    .getByRole("button", { name: `Delete ${credName}` })
    .click();
  await expect(page.getByTestId("credential-row").filter({ hasText: credName })).toHaveCount(0);
});
