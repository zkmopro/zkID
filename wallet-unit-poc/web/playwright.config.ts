import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "e2e",
  timeout: process.env.E2E_MODE === "real" ? 20 * 60_000 : 2 * 60_000,
  fullyParallel: false,
  retries: process.env.CI ? 1 : 0,
  // In default (mock) mode, skip specs tagged @real. The real spec needs a
  // live go-zkid-verifier + Release keys and runs nightly, not on PRs.
  grepInvert: process.env.E2E_MODE === "real" ? undefined : /@real/,
  use: {
    baseURL: "http://localhost:4173",
    trace: "retain-on-failure",
    viewport: { width: 1280, height: 720 },
  },
  webServer: {
    command: "pnpm preview",
    url: "http://localhost:4173",
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
  projects: [
    { name: "chromium", use: { browserName: "chromium" } },
  ],
});
