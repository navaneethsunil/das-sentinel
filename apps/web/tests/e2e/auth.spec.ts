import { expect, test, type Page } from "@playwright/test";

// M1-F1 auth flow against the real stack. Fixture user comes from
// apps/api/scripts/seed_e2e_user.py (run before this spec, locally and in CI).
const EMAIL = "e2e-admin@dassentinel.example.com";
const PASSWORD = "e2e horse battery staple";

async function signIn(page: Page) {
  await page.goto("/login");
  await page.getByLabel("Email").fill(EMAIL);
  await page.getByLabel("Password").fill(PASSWORD);
  await page.getByRole("button", { name: "Sign in" }).click();
  await page.waitForURL((url) => url.pathname === "/");
}

test("signed-out shell offers sign-in, not a user menu", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("link", { name: "Sign in" })).toBeVisible();
  await expect(page.getByTestId("user-menu")).toHaveCount(0);
});

test("wrong password shows the generic error and stays signed out", async ({ page }) => {
  await page.goto("/login");
  await page.getByLabel("Email").fill(EMAIL);
  await page.getByLabel("Password").fill("wrong-password-entirely");
  await page.getByRole("button", { name: "Sign in" }).click();
  // .filter: Next's route announcer is also role="alert" (strict mode).
  await expect(page.getByRole("alert").filter({ hasText: "Invalid" })).toHaveText(
    "Invalid email or password.",
  );
  expect(new URL(page.url()).pathname).toBe("/login");
});

test("login shows the user in the shell; logout returns to login", async ({ page }) => {
  await signIn(page);
  const menu = page.getByTestId("user-menu");
  await expect(menu).toContainText(EMAIL);
  await expect(menu).toContainText("Admin");

  await menu.getByRole("button", { name: "Sign out", exact: true }).click();
  await page.waitForURL((url) => url.pathname === "/login");
  await expect(page.getByRole("link", { name: "Sign in" })).toBeVisible();
});

test("sign out everywhere kills the other session; it lands on the expired banner", async ({
  page,
  browser,
  baseURL,
}) => {
  await signIn(page);

  // Second session for the same user, isolated cookie jar.
  const contextB = await browser.newContext({ baseURL, ignoreHTTPSErrors: true });
  const pageB = await contextB.newPage();
  await signIn(pageB);

  page.on("dialog", (dialog) => dialog.accept());
  await page.getByTestId("user-menu").getByRole("button", { name: "Sign out everywhere" }).click();
  await page.waitForURL((url) => url.pathname === "/login");

  // Session B is revoked server-side; its next state-changing call is a 401,
  // which the client turns into the expired-session redirect (M1-F1 expiry UX).
  await pageB
    .getByTestId("user-menu")
    .getByRole("button", { name: "Sign out", exact: true })
    .click();
  await pageB.waitForURL((url) => url.searchParams.get("expired") === "1");
  await expect(pageB.getByRole("status")).toContainText("session has expired");
  await contextB.close();
});
