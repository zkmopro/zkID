import { test, expect } from "@playwright/test";

// Runs under E2E_MODE=real only, gated via `--grep @real`. Requires a live
// HiPKI LocalSignServer, moica-revocation-smt, and go-zkid-verifier, plus a
// real MOICA card inserted. PIN must be supplied via the `E2E_PIN` env var.
test("@real pipeline verifies against live services", async ({ page }) => {
  const pin = process.env.E2E_PIN;
  if (!pin) {
    test.skip(true, "E2E_PIN env var required for real-mode run");
    return;
  }
  await page.goto("/");
  await page.getByTestId("start-button").click();
  await page.getByTestId("hipki-detect").click();
  await expect(page.getByTestId("hipki-read")).toBeEnabled({ timeout: 30_000 });
  await page.getByTestId("hipki-read").click();
  await expect(page.getByTestId("hipki-body")).toContainText(/Card/, {
    timeout: 30_000,
  });
  await page.getByTestId("pin-input").fill(pin);
  await page.getByTestId("pin-verify").click();
  await expect(page.getByTestId("pin-body")).toContainText(/Locked/, {
    timeout: 30_000,
  });
  await expect(page.getByTestId("continue-button")).toBeEnabled({
    timeout: 5 * 60_000,
  });
  await page.getByTestId("continue-button").click();
  await page.getByTestId("start-proving").click();
  await expect(page.getByTestId("review-send")).toBeVisible({
    timeout: 20 * 60_000,
  });
  await page.getByTestId("review-send").click();
  await expect(page.getByTestId("result-verified")).toBeVisible({
    timeout: 60_000,
  });
});
