import { expect, test } from "@playwright/test";

import { gotoStable, signIn } from "./helpers";

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
  // The API's own validation message is surfaced verbatim, not a generic
  // catch-all (errorDetail reads Pydantic's array-shaped 422 `detail`).
  await expect(
    page.getByRole("alert").filter({ hasText: "must be an absolute http(s) URL" }),
  ).toBeVisible();
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
  await expect(
    page.getByRole("alert").filter({ hasText: "looks like a plaintext secret" }),
  ).toBeVisible();
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

// UAT DEF-011 regression: a role WITHOUT manage_credentials (Reviewer /
// Read only) must still be able to OPEN the target form. The credential picker
// is supplementary data — /credentials answers 403 for these roles — and
// serverGet throws on 403, which crashed the Server Component and served a
// "server error occurred" page instead of the form. serverGetOptional maps that
// one status to null so the page renders with an empty picker; the API is still
// the enforcement when the form is submitted.
test("viewer roles can open the target form; the credential picker is just empty", async ({
  page,
}) => {
  const email = `e2e-viewer-targets-${Date.now()}@example.com`;
  const password = "Harbor-Willow-Basalt-41";

  await signIn(page);
  await page.goto("/users");
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Display name").fill("Viewer Targets");
  await page.getByLabel("Role", { exact: true }).selectOption("reviewer");
  await page.getByRole("button", { name: "Create user" }).click();
  const tempPassword = (
    await page.getByTestId("temp-password-panel").locator("code").innerText()
  ).trim();

  // An engagement for the viewer to open a target form against.
  await page.goto("/engagements/new");
  await page.getByLabel("Name").fill(`e2e-viewer-targets-${Date.now()}`);
  await page.getByLabel("Client / system under test").fill("Viewer Lab");
  await page.getByRole("button", { name: "Create engagement" }).click();
  await page.waitForURL((url) => /\/engagements\/[0-9a-f-]{36}$/.test(url.pathname));
  const engagementPath = new URL(page.url()).pathname;

  await page.getByRole("button", { name: "Account menu" }).click();
  await page
    .getByTestId("account-menu")
    .getByRole("button", { name: "Sign out", exact: true })
    .click();
  await page.waitForURL((url) => url.pathname === "/login");

  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Password").fill(tempPassword);
  await page.getByRole("button", { name: "Sign in" }).click();
  await page.waitForURL((url) => url.pathname === "/set-password");
  await page.getByLabel("New password").fill(password);
  await page.getByLabel("Confirm password").fill(password);
  await page.getByRole("button", { name: /set password/i }).click();
  await page.waitForURL((url) => url.pathname === "/");

  await page.goto(`${engagementPath}/targets/new`);
  await expect(page.getByLabel("Name")).toBeVisible();
  await expect(page.getByText("A server error occurred")).toHaveCount(0);
  await expect(page.getByLabel("Credential", { exact: true })).toHaveValue("");
  await expect(
    page
      .getByLabel("Credential", { exact: true })
      .getByRole("option", { name: "No credentials yet" }),
  ).toHaveCount(1);

  // The refusal is the API's, on submit — not a crashed page.
  await page.getByLabel("Name").fill("Viewer attempt");
  await page.getByLabel("URL").fill("https://viewer.example.com");
  await page.getByRole("button", { name: "Add target" }).click();
  await expect(
    page.getByRole("alert").filter({ hasText: "can view targets but not change them" }),
  ).toBeVisible();

  // A page whose PRIMARY resource is forbidden must say which roles may see it,
  // not fall into the error boundary ("A server error occurred").
  for (const [path, heading] of [
    ["/credentials", "Credentials"],
    ["/users", "Users"],
  ] as const) {
    await gotoStable(page, path);
    await expect(page.getByTestId("access-denied")).toBeVisible();
    await expect(page.getByRole("heading", { name: heading })).toBeVisible();
    await expect(page.getByText("A server error occurred")).toHaveCount(0);
  }
  // Reviewer DOES hold view_audit, so the audit log still renders its own data.
  await gotoStable(page, "/audit");
  await expect(page.getByTestId("access-denied")).toHaveCount(0);
});
