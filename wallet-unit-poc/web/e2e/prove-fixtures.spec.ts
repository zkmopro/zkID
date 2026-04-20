import { test, expect } from "@playwright/test";
import { installMockVerifier } from "./mock-verifier";

test("landing screen renders and Start is interactive", async ({ page }) => {
  await installMockVerifier(page);
  await page.goto("/");
  await expect(page.getByTestId("start-button")).toBeVisible();
  await expect(page.getByTestId("start-button")).toBeEnabled();
});

test("Start → Continue → proving advances UI past idle", async ({ page }) => {
  await installMockVerifier(page);
  await page.goto("/");
  await page.getByTestId("start-button").click();
  await expect(page.getByTestId("setup-assets")).toBeVisible();
  await page.getByTestId("continue-button").click();
  await expect(page.getByTestId("step-list")).toBeVisible();
  // Either reach done (fixtures + mock complete the pipeline) or surface an
  // error row. Either outcome proves: FSM advanced, Worker ran, message pump
  // wired the UI through the new screen container.
  await Promise.race([
    page
      .getByTestId("step-done")
      .waitFor({ timeout: 90_000 })
      .then(() => "done"),
    page
      .getByTestId("step-error")
      .waitFor({ timeout: 90_000 })
      .then(() => "error"),
  ]);
  const done = await page.getByTestId("step-done").count();
  const error = await page.getByTestId("step-error").count();
  expect(done + error).toBeGreaterThan(0);
  // Retry row appears after the pipeline reaches a terminal state.
  await expect(page.getByTestId("retry-button")).toBeVisible();
});
