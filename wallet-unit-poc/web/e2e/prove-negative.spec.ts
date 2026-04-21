// Negative-path coverage for the proving flow. Each test installs a mock
// shape that breaks one specific stage and asserts the UI surfaces the
// failure cleanly (no infinite spinner, no swallowed error, Retry visible).

import { test, expect } from "@playwright/test";
import { installMockServices } from "./mock-services";

test("wrong PIN decrements the attempt counter and locks at zero", async ({
  page,
}) => {
  await installMockServices(page, { signRejectsPin: true });
  await page.goto("/");
  await page.getByTestId("start-button").click();
  await page.getByTestId("hipki-detect").click();
  await expect(page.getByTestId("hipki-read")).toBeEnabled({ timeout: 10_000 });
  await page.getByTestId("hipki-read").click();
  await expect(page.getByTestId("hipki-body")).toContainText(/Card/, {
    timeout: 10_000,
  });

  await page.getByTestId("pin-input").fill("000000");
  await page.getByTestId("pin-verify").click();
  await expect(page.getByTestId("pin-body")).toContainText(/2 attempts left/, {
    timeout: 10_000,
  });

  await page.getByTestId("pin-input").fill("000001");
  await page.getByTestId("pin-verify").click();
  await expect(page.getByTestId("pin-body")).toContainText(/1 attempts left/, {
    timeout: 10_000,
  });

  await page.getByTestId("pin-input").fill("000002");
  await page.getByTestId("pin-verify").click();
  await expect(page.getByTestId("pin-body")).toContainText(/Card is locked/, {
    timeout: 10_000,
  });
  await expect(page.getByTestId("pin-input")).toBeDisabled();
  await expect(page.getByTestId("pin-verify")).toBeDisabled();
});

test("verifier 500 surfaces the error and Retry stays available", async ({
  page,
}) => {
  await installMockServices(page, { linkVerifyStatus: 500 });
  await page.goto("/");
  await page.getByTestId("start-button").click();
  await page.getByTestId("hipki-detect").click();
  await expect(page.getByTestId("hipki-read")).toBeEnabled({ timeout: 10_000 });
  await page.getByTestId("hipki-read").click();

  await page.getByTestId("pin-input").fill("123456");
  await page.getByTestId("pin-verify").click();
  await expect(page.getByTestId("pin-body")).toContainText(/Ready to prove/, {
    timeout: 10_000,
  });
  await expect(page.getByTestId("continue-button")).toBeEnabled({
    timeout: 60_000,
  });
  await page.getByTestId("continue-button").click();

  // Verifier 500 surfaces in either a step-error row or the result banner.
  await page.getByTestId("step-error").waitFor({ timeout: 120_000 });
  await expect(page.getByTestId("retry-button")).toBeVisible();
});
