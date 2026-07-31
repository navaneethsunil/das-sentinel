import { type Page, expect, test } from "@playwright/test";

import { gotoStable, signIn } from "./helpers";

// Role administration from the Users list — the half user-management.spec.ts does
// not cover: an admin re-assigns an existing user's role from the row dropdown,
// and a user created as Admin really gets admin powers (Users nav + page).
// Creating a user hands back a generated one-time password (no password field),
// so a new account's first login must set a permanent one before it can be used.

const ts = Date.now();
const VIEWER_EMAIL = `e2e-viewer-${ts}@dassentinel.example.com`;
const ADMIN2_EMAIL = `e2e-admin2-${ts}@dassentinel.example.com`;
const ADMIN2_PW = "Harbor-Willow-Basalt-41";

async function signInAs(page: Page, email: string, password: string) {
  await gotoStable(page, "/login");
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Password").fill(password);
  await page.getByRole("button", { name: "Sign in" }).click();
}

async function signOut(page: Page) {
  await page.getByRole("button", { name: "Account menu" }).click();
  await page
    .getByTestId("account-menu")
    .getByRole("button", { name: "Sign out", exact: true })
    .click();
  await page.waitForURL((url) => url.pathname === "/login");
}

/** Create a user and return the one-time temporary password shown once. */
async function createUser(page: Page, email: string, name: string, role: string) {
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Display name").fill(name);
  await page.getByLabel("Role", { exact: true }).selectOption(role);
  await page.getByRole("button", { name: "Create user" }).click();
  const panel = page.getByTestId("temp-password-panel");
  await expect(panel).toBeVisible();
  const tempPassword = (await panel.locator("code").innerText()).trim();
  await panel.getByRole("button", { name: "Done" }).click();
  return tempPassword;
}

test("users: admin assigns roles from the list and a new admin gets admin powers", async ({
  page,
}) => {
  await signIn(page);

  // Reach the admin-only Users page from the left menu.
  await page.getByRole("link", { name: "Users" }).click();
  await page.waitForURL((url) => url.pathname === "/users");
  await expect(page.getByRole("heading", { name: "Users" })).toBeVisible();

  // Create a read-only user, then promote it to reviewer from the row dropdown.
  await createUser(page, VIEWER_EMAIL, "Vera Viewer", "read_only");
  const viewerRow = page.getByTestId("user-row").filter({ hasText: VIEWER_EMAIL });
  await expect(viewerRow).toBeVisible();
  const viewerRole = viewerRow.getByLabel(`Role for ${VIEWER_EMAIL}`);
  await expect(viewerRole).toHaveValue("read_only");
  await viewerRole.selectOption("reviewer");
  await expect(viewerRole).toHaveValue("reviewer");

  // Create a second admin and take its temporary password.
  const admin2TempPw = await createUser(page, ADMIN2_EMAIL, "Adam Admin", "admin");
  const admin2Row = page.getByTestId("user-row").filter({ hasText: ADMIN2_EMAIL });
  await expect(admin2Row.getByLabel(`Role for ${ADMIN2_EMAIL}`)).toHaveValue("admin");

  // The new admin sets a permanent password on first login, then has real admin
  // powers: the Administration nav and the Users page itself.
  await signOut(page);
  await signInAs(page, ADMIN2_EMAIL, admin2TempPw);
  await page.waitForURL((url) => url.pathname === "/set-password");
  await page.getByLabel("New password").fill(ADMIN2_PW);
  await page.getByLabel("Confirm password").fill(ADMIN2_PW);
  await page.getByRole("button", { name: "Set password" }).click();
  await page.waitForURL((url) => url.pathname === "/");

  await page.getByRole("link", { name: "Users" }).click();
  await page.waitForURL((url) => url.pathname === "/users");
  await expect(page.getByRole("heading", { name: "Users" })).toBeVisible();
  // The promotion the first admin made is visible to this one too.
  await expect(
    page
      .getByTestId("user-row")
      .filter({ hasText: VIEWER_EMAIL })
      .getByLabel(`Role for ${VIEWER_EMAIL}`),
  ).toHaveValue("reviewer");
});
