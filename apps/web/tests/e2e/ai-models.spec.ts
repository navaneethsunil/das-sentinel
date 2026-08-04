import { expect, test } from "@playwright/test";

import { gotoStable, signIn } from "./helpers";

// AI model registry: an admin registers a provider once under System → AI models
// and engagements then pick it. Registration is verified against the provider
// before it saves, so the CI-safe path here is the refusal; set E2E_OLLAMA_URL to
// a reachable Ollama (as seen FROM the api container, e.g.
// http://host.docker.internal:11434) plus E2E_OLLAMA_MODEL to also exercise the
// happy path locally. `http://localhost:11434` is what an operator types — the API
// resolves loopback to the Docker host itself.
const OLLAMA_URL = process.env.E2E_OLLAMA_URL;
const OLLAMA_MODEL = process.env.E2E_OLLAMA_MODEL ?? "llama3.1:8b";

test("ai models: an unreachable provider is refused, not saved", async ({ page }) => {
  await signIn(page);

  await page.getByRole("link", { name: "AI models" }).click();
  await page.waitForURL((url) => url.pathname === "/ai-models");
  await expect(page.getByRole("heading", { name: "AI models" })).toBeVisible();

  await page.getByLabel("Provider").selectOption("ollama");
  await page.getByLabel("Name").fill(`e2e-bad-${Date.now()}`);
  await page.getByLabel("Model").fill("nothing-here");
  await page.getByLabel("Ollama endpoint").fill("http://127.0.0.1:1");
  await page.getByRole("button", { name: "Add model" }).click();

  // The provider check failed, so the model was never stored. A loopback endpoint
  // is also retried against the Docker host, and the error names both addresses.
  await expect(page.getByText(/could not reach Ollama at/i)).toBeVisible();
  await expect(page.getByText(/host\.docker\.internal/i)).toBeVisible();
  await expect(page.getByTestId("ai-model-row")).toHaveCount(0);
});

test("ai models: the engagement form offers the registry", async ({ page }) => {
  await signIn(page);
  await gotoStable(page, "/engagements/new");
  // Present whether or not a model is registered; the empty state points at the
  // System → AI models page rather than silently offering nothing.
  await expect(page.getByLabel("AI model")).toBeVisible();
});

test(
  OLLAMA_URL
    ? "ai models: register a local model and use it"
    : "ai models: register a local model and use it (skipped — set E2E_OLLAMA_URL)",
  async ({ page }) => {
    test.skip(!OLLAMA_URL, "no reachable Ollama configured");
    const name = `e2e-ollama-${Date.now()}`;
    await signIn(page);
    await gotoStable(page, "/ai-models");

    await page.getByLabel("Provider").selectOption("ollama");
    await page.getByLabel("Name").fill(name);
    await page.getByLabel("Model").fill(OLLAMA_MODEL);
    await page.getByLabel("Ollama endpoint").fill(OLLAMA_URL!);
    await page.getByRole("button", { name: "Add model" }).click();

    const row = page.getByTestId("ai-model-row").filter({ hasText: name });
    await expect(row).toBeVisible();
    await expect(row).toContainText(OLLAMA_MODEL);
    await expect(row).toContainText("local · on-box");
    // No key was involved, but nothing key-shaped may ever appear here either.
    await expect(page.getByText(/api_key/i)).toHaveCount(0);

    // An engagement can now pick it — that is the whole point of registering once.
    await gotoStable(page, "/engagements/new");
    await expect(page.getByLabel("AI model")).toContainText(name);

    await gotoStable(page, "/ai-models");
    await page
      .getByTestId("ai-model-row")
      .filter({ hasText: name })
      .getByRole("button", { name: "Remove" })
      .click();
    await expect(page.getByTestId("ai-model-row").filter({ hasText: name })).toHaveCount(0);
  },
);
