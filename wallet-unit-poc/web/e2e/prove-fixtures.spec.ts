import { test, expect } from "@playwright/test";
import { installMockServices } from "./mock-services";

test("landing screen renders and Start is interactive", async ({ page }) => {
  await installMockServices(page);
  await page.goto("/");
  await expect(page.getByTestId("start-button")).toBeVisible();
  await expect(page.getByTestId("start-button")).toBeEnabled();
});

test("Start → setup screen polls HiPKI and detects card (mocked)", async ({ page }) => {
  await installMockServices(page);
  await page.goto("/");
  await page.getByTestId("start-button").click();
  await expect(page.getByTestId("setup-assets")).toBeVisible();
  await expect(page.getByTestId("setup-hipki")).toBeVisible();
  await expect(page.getByTestId("setup-pin")).toBeVisible();
  // Poller ticks every ~2s; the card fixture resolves to `card_ready` soon
  // after the withcert=true pull completes.
  await expect(page.getByTestId("hipki-body")).toContainText(
    /Test User|Card/,
    { timeout: 15_000 },
  );
});

test("full flow with mocks reaches terminal state", async ({ page }) => {
  await installMockServices(page);
  await page.goto("/");
  await page.getByTestId("start-button").click();

  // Wait for the poller to reach card_ready.
  await expect(page.getByTestId("hipki-body")).toContainText(
    /Test User|Card/,
    { timeout: 15_000 },
  );
  // Enter PIN + verify.
  await page.getByTestId("pin-input").fill("123456");
  await page.getByTestId("pin-verify").click();
  await expect(page.getByTestId("pin-body")).toContainText(
    /Ready to prove/,
    { timeout: 10_000 },
  );
  // Asset download may still be in flight; wait for Continue to enable.
  await expect(page.getByTestId("continue-button")).toBeEnabled({
    timeout: 60_000,
  });
  await page.getByTestId("continue-button").click();
  // Terminal state: either `done` or `error` row surfaces and the Retry row
  // appears.
  await Promise.race([
    page.getByTestId("step-done").waitFor({ timeout: 120_000 }).then(() => "done"),
    page.getByTestId("step-error").waitFor({ timeout: 120_000 }).then(() => "error"),
  ]);
  const done = await page.getByTestId("step-done").count();
  const error = await page.getByTestId("step-error").count();
  expect(done + error).toBeGreaterThan(0);
  await expect(page.getByTestId("retry-button")).toBeVisible();
});
