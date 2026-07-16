import { expect, test } from "@playwright/test";

import { signIn } from "./helpers";

// M1-F2: full engagement lifecycle through the UI — create with all fields,
// list, edit, walk the status machine to its terminal state, delete.
test("engagement lifecycle: create → edit → status machine → delete", async ({ page }) => {
  const name = `e2e-engagement-${Date.now()}`;
  await signIn(page);

  // create
  await page.goto("/engagements/new");
  await page.getByLabel("Name").fill(name);
  await page.getByLabel("Client / system under test").fill("Acme Portal");
  await page.getByLabel("Rate limit (requests/s)").fill("7");
  await page.getByLabel("Maximum intensity").selectOption("passive");
  await page.getByLabel("Coordination contact").fill("secops@acme.example.com");
  await page.getByLabel("Emergency-stop contact").fill("+1 555 0100 (24/7)");
  await page.getByRole("button", { name: "Create engagement" }).click();
  await page.waitForURL((url) => /\/engagements\/[0-9a-f-]{36}$/.test(url.pathname));

  await expect(page.getByRole("heading", { name })).toBeVisible();
  await expect(page.getByTestId("engagement-status")).toHaveText("Draft");
  await expect(page.getByText("Acme Portal")).toBeVisible();
  await expect(page.getByText("7 rps")).toBeVisible();
  await expect(page.getByText("Local models only")).toBeVisible();

  // list shows it
  await page.goto("/engagements");
  await expect(page.getByRole("link", { name })).toBeVisible();
  await page.getByRole("link", { name }).click();
  await page.waitForURL((url) => /\/engagements\/[0-9a-f-]{36}$/.test(url.pathname));

  // edit
  await page.getByRole("link", { name: "Edit" }).click();
  await page.waitForURL((url) => url.pathname.endsWith("/edit"));
  await page.getByLabel("Rate limit (requests/s)").fill("9");
  await page.getByLabel("Hosted LLMs allowed (otherwise local models only)").check();
  await page.getByRole("button", { name: "Save changes" }).click();
  await page.waitForURL((url) => /\/engagements\/[0-9a-f-]{36}$/.test(url.pathname));
  await expect(page.getByText("9 rps")).toBeVisible();
  await expect(page.getByText("Allowed", { exact: true })).toBeVisible();

  // status machine: draft → active → paused → active → closed (terminal)
  page.on("dialog", (dialog) => dialog.accept());
  await page.getByRole("button", { name: "Activate" }).click();
  await expect(page.getByTestId("engagement-status")).toHaveText("Active");
  await page.getByRole("button", { name: "Pause" }).click();
  await expect(page.getByTestId("engagement-status")).toHaveText("Paused");
  await page.getByRole("button", { name: "Activate" }).click();
  await expect(page.getByTestId("engagement-status")).toHaveText("Active");
  await page.getByRole("button", { name: "Close" }).click();
  await expect(page.getByTestId("engagement-status")).toHaveText("Closed");
  await expect(page.getByText("Closed is terminal")).toBeVisible();

  // delete → back to the list, no longer present
  await page.getByRole("button", { name: "Delete engagement" }).click();
  await page.waitForURL((url) => url.pathname === "/engagements");
  await expect(page.getByRole("link", { name })).toHaveCount(0);
});
