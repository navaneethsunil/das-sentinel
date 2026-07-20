import { expect, test } from "@playwright/test";

import { signIn } from "./helpers";

// M2-F1: LLM target connector config + suite launcher. Builds a launchable
// engagement end to end (scope → ROE → LLM target → active), launches an
// in-scope suite scan (queued, visible in the recent-scans table), and proves
// the scope keystone gates the launch from the UI (over-intensity is blocked
// with the reason surfaced).
test("suite launcher: configure LLM target, launch a scan, and see the intensity gate block", async ({
  page,
}) => {
  const name = `e2e-scans-${Date.now()}`;
  await signIn(page);

  // A test window that brackets "now" — the scope keystone refuses a launch
  // outside (or without) the authorized window.
  const pad = (n: number) => String(n).padStart(2, "0");
  const asLocalInput = (d: Date) =>
    `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
  const now = Date.now();
  const windowStart = asLocalInput(new Date(now - 864e5));
  const windowEnd = asLocalInput(new Date(now + 864e5));

  // minimal engagement (default max intensity = safe active)
  await page.goto("/engagements/new");
  await page.getByLabel("Name").fill(name);
  await page.getByLabel("Client / system under test").fill("Scan Lab");
  await page.getByLabel("Test window start").fill(windowStart);
  await page.getByLabel("Test window end").fill(windowEnd);
  await page.getByRole("button", { name: "Create engagement" }).click();
  await page.waitForURL((url) => /\/engagements\/[0-9a-f-]{36}$/.test(url.pathname));

  // scope: allow the LLM host
  await page.getByLabel("Matcher type").selectOption("domain");
  await page.getByLabel("Value").fill("mock-llm.example.com");
  await page.getByRole("button", { name: "Add scope item" }).click();
  await expect(
    page.getByTestId("scope-allow-list").getByText("mock-llm.example.com"),
  ).toBeVisible();

  // accept the ROE for that scope
  await page.getByLabel(/I have read the Rules of Engagement/).check();
  await page.getByRole("button", { name: "Accept Rules of Engagement" }).click();
  await expect(page.getByTestId("roe-status")).toHaveText("Accepted");

  // before any LLM target, the launcher points the user at adding one
  await expect(page.getByText("No LLM targets yet", { exact: false })).toBeVisible();

  // add an AI-chatbot target — the connector-config field appears only for LLM
  // types, and it is where the transport shape (non-secret) lives
  await page.getByRole("link", { name: "Add LLM target" }).click();
  await page.waitForURL((url) => url.pathname.endsWith("/targets/new"));
  await page.getByLabel("Name").fill("Mock chatbot");
  await page.getByLabel("Type").selectOption("ai_chatbot");
  await page.getByLabel("URL").fill("https://mock-llm.example.com/v1/chat/completions");
  const connector = page.getByLabel("Connector config (transport shape, JSON)");
  await expect(connector).toBeVisible();
  await connector.fill('{"mode": "chat_messages"}');
  await page.getByRole("button", { name: "Add target" }).click();
  await page.waitForURL((url) => /\/engagements\/[0-9a-f-]{36}$/.test(url.pathname));
  await expect(page.getByTestId("targets-table").getByText("Mock chatbot")).toBeVisible();

  // activate the engagement (scans need an active engagement)
  await page.getByRole("button", { name: "Activate" }).click();
  await expect(page.getByTestId("engagement-status")).toHaveText("Active");

  // launch a prompt-injection scan at safe-active → queued, shown in the table
  await expect(page.getByLabel("Target")).toHaveValue(/[0-9a-f-]{36}/);
  await page.getByRole("button", { name: "Launch scan" }).click();
  const scansTable = page.getByTestId("scans-table");
  await expect(scansTable).toBeVisible();
  await expect(scansTable.getByTestId("scan-status").first()).toHaveText(
    /Queued|Running|Completed/,
  );

  // the scope keystone gates from the UI: authenticated-active exceeds the
  // engagement's safe-active ceiling and is blocked with the reason surfaced
  await page.getByLabel("Intensity").selectOption("authenticated_active");
  await page.getByRole("button", { name: "Launch scan" }).click();
  await expect(
    page.getByRole("alert").filter({ hasText: "exceeds the engagement's maximum intensity" }),
  ).toBeVisible();
});
