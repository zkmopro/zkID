import { test, expect } from "@playwright/test";

test("@real pipeline verifies against live go-zkid-verifier", async ({ page }) => {
  // Only run under E2E_MODE=real. Grepped via playwright --grep @real.
  await page.goto("/");
  await page.getByTestId("prove-button").click();
  await expect(page.getByTestId("step-done")).toBeVisible({ timeout: 20 * 60_000 });
  await expect(page.getByTestId("server-result")).toContainText(/verified/i);
});
