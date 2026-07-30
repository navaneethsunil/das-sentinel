import { expect, test, type Page } from "@playwright/test";

import { gotoStable, signIn } from "./helpers";

// User management (admin-only): an admin creates a read-only user and a second
// admin, assigns roles, and the role separation actually holds — the read-only
// user has no Users menu, the new admin does. Then the admin changes the
// read-only user's role from the list.

async function loginAs(page: Page, email: string, password: string) {
  await gotoStable(page, "/login");
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Password").fill(password);
  await page.getByRole("button", { name: "Sign in" }).click();
  await page.waitForURL((url) => url.pathname === "/", { timeout: 30_000 });
}

test("users: admin creates users, assigns roles, and role separation holds", async ({ page }) => {
  const ts = Date.now();
  const viewer = { email: `e2e-viewer-${ts}@dassentinel.example.com`, password: `viewer-pass-${ts}-alpha` };
  const admin2 = { email: `e2e-admin2-${ts}@dassentinel.example.com`, password: `admin-pass-${ts}-bravo` };

  await signIn(page);

  // Reach the admin-only Users page from the left menu.
  await page.getByRole("link", { name: "Users" }).click();
  await page.waitForURL((url) => url.pathname === "/users");
  await expect(page.getByRole("heading", { name: "Users" })).toBeVisible();

  // Create a read-only user.
  await page.getByLabel("Email").fill(viewer.email);
  await page.getByLabel("Display name").fill("Vera Viewer");
  await page.getByLabel("Role", { exact: true }).selectOption("read_only");
  await page.getByLabel("Temporary password").fill(viewer.password);
  await page.getByRole("button", { name: "Create user" }).click();

  const viewerRow = page.getByTestId("user-row").filter({ hasText: viewer.email });
  await expect(viewerRow).toBeVisible();
  await expect(viewerRow.getByLabel(`Role for ${viewer.email}`)).toHaveValue("read_only");

  // Create a second admin.
  await page.getByLabel("Email").fill(admin2.email);
  await page.getByLabel("Display name").fill("Adam Admin");
  await page.getByLabel("Role", { exact: true }).selectOption("admin");
  await page.getByLabel("Temporary password").fill(admin2.password);
  await page.getByRole("button", { name: "Create user" }).click();

  const admin2Row = page.getByTestId("user-row").filter({ hasText: admin2.email });
  await expect(admin2Row).toBeVisible();
  await expect(admin2Row.getByLabel(`Role for ${admin2.email}`)).toHaveValue("admin");

  // Sign out, then sign in as the read-only user — they must NOT see the admin
  // Users menu (role separation, enforced by the API's MANAGE_USERS guard).
  await page.getByRole("button", { name: "Sign out", exact: true }).click();
  await page.waitForURL((url) => url.pathname === "/login");
  await loginAs(page, viewer.email, viewer.password);
  await expect(page.getByRole("link", { name: "Users" })).toHaveCount(0);
  await expect(page.getByRole("link", { name: "Credentials" })).toHaveCount(0);

  // The new admin, by contrast, sees Users and can open it.
  await page.getByRole("button", { name: "Sign out", exact: true }).click();
  await page.waitForURL((url) => url.pathname === "/login");
  await loginAs(page, admin2.email, admin2.password);
  await page.getByRole("link", { name: "Users" }).click();
  await page.waitForURL((url) => url.pathname === "/users");
  await expect(page.getByRole("heading", { name: "Users" })).toBeVisible();

  // The admin changes the read-only user's role to reviewer from the list.
  const viewerRow2 = page.getByTestId("user-row").filter({ hasText: viewer.email });
  await viewerRow2.getByLabel(`Role for ${viewer.email}`).selectOption("reviewer");
  await expect(viewerRow2.getByLabel(`Role for ${viewer.email}`)).toHaveValue("reviewer");
});
