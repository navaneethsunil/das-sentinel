import { type Page, expect, test } from "@playwright/test";

import { E2E_EMAIL as ADMIN_EMAIL, E2E_PASSWORD as ADMIN_PASSWORD, gotoStable } from "./helpers";

// Full manual-style walkthrough of the user-management + self-service features:
// admin creates a user (auto temp password, copy, regenerate), the new user is
// forced to set a permanent password on first login, admin-only nav is hidden
// for the read-only user, and self-service profile/password edits work.

// Clipboard permissions so the "Copy" button can be verified for real.
test.use({ permissions: ["clipboard-read", "clipboard-write"] });

const NEW_USER_EMAIL = `newuser-${Date.now()}@example.com`;
const NEW_USER_NAME = "New Test User";
const PERMANENT_PW = "Zephyr-Meadow-Quartz-73";
const CHANGED_PW = "Lantern-River-Cobalt-58";

async function signInAs(page: Page, email: string, password: string) {
  await gotoStable(page, "/login");
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Password").fill(password);
  await page.getByRole("button", { name: "Sign in" }).click();
}

async function signOut(page: Page) {
  await page.getByRole("button", { name: "Account menu" }).click();
  await page.getByTestId("account-menu").getByRole("button", { name: "Sign out", exact: true }).click();
  await page.waitForURL((url) => url.pathname === "/login");
}

test("login page is chrome-free, then the full user lifecycle", async ({ page }) => {
  // 1) Login page: only the form — no sidebar nav, no account menu.
  await gotoStable(page, "/login");
  await expect(page.getByRole("button", { name: "Sign in" })).toBeVisible();
  await expect(page.getByRole("link", { name: "Engagements" })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Account menu" })).toHaveCount(0);

  // 2) Sign in as admin → dashboard, admin sees the Administration nav.
  await signInAs(page, ADMIN_EMAIL, ADMIN_PASSWORD);
  await page.waitForURL((url) => url.pathname === "/");
  await expect(page.getByRole("link", { name: "Users" })).toBeVisible();

  // 3) Create a user — no password field; a temp password is generated.
  await page.getByRole("link", { name: "Users" }).click();
  await page.waitForURL((url) => url.pathname === "/users");
  await page.getByLabel("Email").fill(NEW_USER_EMAIL);
  await page.getByLabel("Display name").fill(NEW_USER_NAME);
  await page.getByRole("button", { name: "Create user" }).click();

  const panel = page.getByTestId("temp-password-panel");
  await expect(panel).toBeVisible();
  const firstPw = (await panel.locator("code").innerText()).trim();
  expect(firstPw.length).toBeGreaterThanOrEqual(12);

  // 3a) Copy button actually copies to the clipboard.
  await panel.getByRole("button", { name: "Copy" }).click();
  await expect(panel.getByRole("button", { name: "Copied" })).toBeVisible();
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(firstPw);

  // 3b) "Generate new" mints a different password (this is the one we'll use).
  await panel.getByRole("button", { name: "Generate new" }).click();
  await expect(panel.locator("code")).not.toHaveText(firstPw);
  const tempPw = (await panel.locator("code").innerText()).trim();

  await signOut(page);

  // 4) New user logs in with the temp password → forced to set a permanent one.
  await signInAs(page, NEW_USER_EMAIL, tempPw);
  await page.waitForURL((url) => url.pathname === "/set-password");
  await page.getByLabel("New password").fill(PERMANENT_PW);
  await page.getByLabel("Confirm password").fill(PERMANENT_PW);
  await page.getByRole("button", { name: "Set password" }).click();
  await page.waitForURL((url) => url.pathname === "/");

  // 5) Read-only user must NOT see the admin-only Administration nav.
  await expect(page.getByRole("link", { name: "Users" })).toHaveCount(0);
  await expect(page.getByText("Administration", { exact: true })).toHaveCount(0);

  // 6) Account menu → profile settings; edit name + phone.
  await page.getByRole("button", { name: "Account menu" }).click();
  await page.getByRole("menuitem", { name: "Account settings" }).click();
  await page.waitForURL((url) => url.pathname === "/profile");
  await page.getByLabel("Name").fill(`${NEW_USER_NAME} Updated`);
  await page.getByLabel("Phone number").fill("+1 555 0100");
  await page.getByRole("button", { name: "Save profile" }).click();
  await expect(page.getByText("Profile saved.")).toBeVisible();

  // 7) Self-service password change (needs the current password).
  await page.getByLabel("Current password").fill(PERMANENT_PW);
  await page.getByLabel("New password", { exact: true }).fill(CHANGED_PW);
  await page.getByLabel("Confirm new password").fill(CHANGED_PW);
  await page.getByRole("button", { name: "Change password" }).click();
  await expect(page.getByText("Password changed.")).toBeVisible();

  // 8) The changed password works and no longer forces a reset.
  await signOut(page);
  await signInAs(page, NEW_USER_EMAIL, CHANGED_PW);
  await page.waitForURL((url) => url.pathname === "/");
});
