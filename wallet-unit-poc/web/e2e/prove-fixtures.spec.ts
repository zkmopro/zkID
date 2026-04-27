import { test, expect } from "@playwright/test";
import { installMockServices } from "./mock-services";

async function breakKeysManifest(
  page: import("@playwright/test").Page,
  body: { status: number; contentType: string; body: string },
): Promise<void> {
  await page.route("**/keys/manifest.json**", async (route) => {
    await route.fulfill(body);
  });
}

test("landing screen renders and Start is interactive", async ({ page }) => {
  await installMockServices(page);
  await page.goto("/");
  await expect(page.getByTestId("start-button")).toBeVisible();
  await expect(page.getByTestId("start-button")).toBeEnabled();
});

test("Start → setup screen exposes the click-driven HiPKI flow", async ({ page }) => {
  await installMockServices(page);
  await page.goto("/");
  await page.getByTestId("start-button").click();
  await expect(page.getByTestId("setup-assets")).toBeVisible();
  await expect(page.getByTestId("setup-hipki")).toBeVisible();
  await expect(page.getByTestId("setup-pin")).toBeVisible();
  await expect(page.getByTestId("hipki-detect")).toBeVisible();

  await page.getByTestId("hipki-detect").click();
  // Mock HiPKI fixture has at least one card-bearing slot, so Read card unlocks.
  await expect(page.getByTestId("hipki-read")).toBeEnabled({ timeout: 10_000 });
  await page.getByTestId("hipki-read").click();
  await expect(page.getByTestId("hipki-body")).toContainText(/Card/, {
    timeout: 10_000,
  });
});

test("full flow reaches result and holds proof on review gate", async ({ page }) => {
  await installMockServices(page);
  await page.goto("/");
  await page.getByTestId("start-button").click();

  await page.getByTestId("hipki-detect").click();
  await expect(page.getByTestId("hipki-read")).toBeEnabled({ timeout: 10_000 });
  await page.getByTestId("hipki-read").click();
  await expect(page.getByTestId("hipki-body")).toContainText(/Card/, {
    timeout: 10_000,
  });

  await page.getByTestId("pin-input").fill("123456");
  await page.getByTestId("pin-verify").click();
  await expect(page.getByTestId("pin-body")).toContainText(/Locked/, {
    timeout: 10_000,
  });
  await expect(page.getByTestId("pin-lock-badge")).toBeVisible();

  // Continue enables once warmup finishes.
  await expect(page.getByTestId("continue-button")).toBeEnabled({
    timeout: 120_000,
  });
  await page.getByTestId("continue-button").click();

  // Ready gate — user must explicitly click Start proving.
  await expect(page.getByTestId("start-proving")).toBeVisible();
  await expect(page.getByTestId("ready-card")).toBeVisible();
  await page.getByTestId("start-proving").click();

  // Review gate — proofs are held in memory; user must explicitly Send.
  await expect(page.getByTestId("review-send")).toBeVisible({
    timeout: 10 * 60_000,
  });
  await expect(page.getByTestId("review-challenge")).toBeVisible();
  await expect(page.getByTestId("review-cert-size")).toContainText(/B/);

  await page.getByTestId("review-send").click();

  // Result — the mock verifier accepts when the body shape is well-formed.
  await expect(page.getByTestId("result-verified")).toBeVisible({
    timeout: 60_000,
  });
  await expect(page.getByTestId("result-prove-again")).toBeVisible();
});

test("manifest 500 leaves Assets panel in an unreachable error state", async ({
  page,
}) => {
  await installMockServices(page);
  await breakKeysManifest(page, {
    status: 500,
    contentType: "text/plain",
    body: "simulated manifest outage",
  });
  await page.goto("/");
  await page.getByTestId("start-button").click();
  await expect(page.getByTestId("assets-body")).toContainText(
    /Cannot reach server manifest/i,
    { timeout: 30_000 },
  );
  await expect(page.getByTestId("assets-retry")).toBeVisible();
});

test("malformed manifest surfaces a malformed error and blocks proving", async ({
  page,
}) => {
  await installMockServices(page);
  await breakKeysManifest(page, {
    status: 200,
    contentType: "application/json",
    body: "this is not json",
  });
  await page.goto("/");
  await page.getByTestId("start-button").click();
  await expect(page.getByTestId("assets-body")).toContainText(
    /manifest malformed/i,
    { timeout: 30_000 },
  );
  await expect(page.getByTestId("continue-button")).toBeDisabled();
});

test("manifest missing a required asset entry surfaces missing_asset error", async ({
  page,
}) => {
  await installMockServices(page);
  await breakKeysManifest(page, {
    status: 200,
    contentType: "application/json",
    body: JSON.stringify({ assets: {} }),
  });
  await page.goto("/");
  await page.getByTestId("start-button").click();
  await expect(page.getByTestId("assets-body")).toContainText(
    /missing a required entry/i,
    { timeout: 30_000 },
  );
});

test("retry from review routes through setup for PIN re-verify (no submit)", async ({ page }) => {
  await installMockServices(page);
  await page.goto("/");
  await page.getByTestId("start-button").click();
  await page.getByTestId("hipki-detect").click();
  await expect(page.getByTestId("hipki-read")).toBeEnabled({ timeout: 10_000 });
  await page.getByTestId("hipki-read").click();
  await page.getByTestId("pin-input").fill("123456");
  await page.getByTestId("pin-verify").click();
  await expect(page.getByTestId("continue-button")).toBeEnabled({
    timeout: 120_000,
  });
  await page.getByTestId("continue-button").click();
  await page.getByTestId("start-proving").click();
  await expect(page.getByTestId("review-send")).toBeVisible({
    timeout: 10 * 60_000,
  });

  // Retry from review → back to setup with the PIN panel reset. Strict
  // single-use: session Pin was consumed during proving, user must
  // re-enter to run another proving attempt.
  await page.getByTestId("review-retry").click();
  await expect(page.getByTestId("setup-pin")).toBeVisible();
  await expect(page.getByTestId("pin-input")).toBeEnabled();
  await expect(page.getByTestId("pin-lock-badge")).toBeHidden();
});
