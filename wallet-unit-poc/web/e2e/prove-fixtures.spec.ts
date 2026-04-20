import { test, expect } from "@playwright/test";
import { installMockVerifier } from "./mock-verifier";

test("app renders and prove button is interactive", async ({ page }) => {
  await installMockVerifier(page);
  await page.goto("/");
  await expect(page.getByTestId("prove-button")).toBeVisible();
  await expect(page.getByTestId("prove-button")).toBeEnabled();
});

test("clicking prove transitions UI past idle", async ({ page }) => {
  await installMockVerifier(page);
  await page.goto("/");
  await page.getByTestId("prove-button").click();
  // Either reach done (if fixtures + mock complete the pipeline) or surface an
  // error row. Either outcome proves: button-click reached the Worker, the
  // Worker ran, and the message pump wired the UI.
  await Promise.race([
    page.getByTestId("step-done").waitFor({ timeout: 90_000 }).then(() => "done"),
    page.getByTestId("step-error").waitFor({ timeout: 90_000 }).then(() => "error"),
  ]);
  const done = await page.getByTestId("step-done").count();
  const error = await page.getByTestId("step-error").count();
  expect(done + error).toBeGreaterThan(0);
});
