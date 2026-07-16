import { expect, test } from "@playwright/test";

import { signIn } from "./helpers";

// M1-F4: target inventory — add (per-type primary-value validation,
// refs-only auth_config), list on the engagement detail page, edit
// (immutable type), delete.
test("target inventory: add with validation, list, edit, delete", async ({ page }) => {
  const name = `e2e-targets-${Date.now()}`;
  await signIn(page);

  await page.goto("/engagements/new");
  await page.getByLabel("Name").fill(name);
  await page.getByLabel("Client / system under test").fill("Target Lab");
  await page.getByRole("button", { name: "Create engagement" }).click();
  await page.waitForURL((url) => /\/engagements\/[0-9a-f-]{36}$/.test(url.pathname));
  await expect(page.getByText("No targets yet", { exact: false })).toBeVisible();

  // add a web target: malformed URL is rejected (422), then a valid one lands
  await page.getByRole("link", { name: "Add target" }).click();
  await page.waitForURL((url) => url.pathname.endsWith("/targets/new"));
  await page.getByLabel("Name").fill("Portal web app");
  await page.getByLabel("Environment").selectOption("staging");
  await page.getByLabel("URL").fill("not-a-url");
  await page.getByRole("button", { name: "Add target" }).click();
  await expect(page.getByRole("alert").filter({ hasText: "must be well-formed" })).toBeVisible();
  await page.getByLabel("URL").fill("https://portal.acme.example.com");
  await page.getByRole("button", { name: "Add target" }).click();
  await page.waitForURL((url) => /\/engagements\/[0-9a-f-]{36}$/.test(url.pathname));

  const table = page.getByTestId("targets-table");
  await expect(table.getByRole("link", { name: "Portal web app" })).toBeVisible();
  await expect(table.getByText("Web application")).toBeVisible();
  await expect(table.getByText("Staging")).toBeVisible();
  await expect(table.getByText("No auth")).toBeVisible();

  // add a repo target: the value field follows the type, and auth_config with
  // a plaintext-looking secret is rejected (refs only, TR-23)
  await page.getByRole("link", { name: "Add target" }).click();
  await page.waitForURL((url) => url.pathname.endsWith("/targets/new"));
  await page.getByLabel("Name").fill("Portal source");
  await page.getByLabel("Type").selectOption("source_repo");
  await page.getByLabel("Repository").fill("git@github.com:acme/portal.git");
  await page.getByLabel("Auth status").selectOption("configured");
  const authConfig = page.getByLabel("Auth config (credential references only, JSON)");
  await authConfig.fill('{"password": "hunter2"}');
  await page.getByRole("button", { name: "Add target" }).click();
  await expect(page.getByRole("alert").filter({ hasText: "credential references" })).toBeVisible();
  await authConfig.fill('{"deploy_key_ref": "vault://acme/portal-deploy"}');
  await page.getByRole("button", { name: "Add target" }).click();
  await page.waitForURL((url) => /\/engagements\/[0-9a-f-]{36}$/.test(url.pathname));
  await expect(table.getByRole("link", { name: "Portal source" })).toBeVisible();
  await expect(table.getByText("Source repository")).toBeVisible();
  await expect(table.getByText("Configured")).toBeVisible();

  // edit: type is immutable (disabled), other fields save
  await table.getByRole("link", { name: "Portal web app" }).click();
  await page.waitForURL((url) => url.pathname.endsWith("/edit"));
  await expect(page.getByLabel("Type")).toBeDisabled();
  await expect(page.getByLabel("Type")).toHaveValue("web_app");
  await page.getByLabel("Environment").selectOption("production");
  await page.getByLabel("Auth status").selectOption("verified");
  await page.getByRole("button", { name: "Save changes" }).click();
  await page.waitForURL((url) => /\/engagements\/[0-9a-f-]{36}$/.test(url.pathname));
  await expect(table.getByText("Production")).toBeVisible();
  await expect(table.getByText("Verified")).toBeVisible();

  // delete the repo target; the web target stays
  page.on("dialog", (dialog) => dialog.accept());
  await table.getByRole("link", { name: "Portal source" }).click();
  await page.waitForURL((url) => url.pathname.endsWith("/edit"));
  await page.getByRole("button", { name: "Delete target" }).click();
  await page.waitForURL((url) => /\/engagements\/[0-9a-f-]{36}$/.test(url.pathname));
  await expect(table.getByRole("link", { name: "Portal source" })).toHaveCount(0);
  await expect(table.getByRole("link", { name: "Portal web app" })).toBeVisible();
});
