// Playwright mocks for every external service the Phase 4 pipeline hits:
// verifier (challenge + link-verify), HiPKI (pkcs11info + sign), and the
// SMT revocation server.
//
// The cert fixtures re-use `ecdsa-spartan2/tests/testdata/*.json` so schema
// drift between the Rust and TS sides surfaces in e2e too.

import type { Page } from "@playwright/test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const TESTDATA = resolve(__dirname, "../../ecdsa-spartan2/tests/testdata");
const PKCS11_FIXTURE = readFileSync(
  resolve(TESTDATA, "pkcs11info_test.json"),
  "utf8",
);
const SIGN_FIXTURE_RAW = readFileSync(
  resolve(TESTDATA, "response_sign_test.json"),
  "utf8",
);
const SIGN_FIXTURE = JSON.parse(SIGN_FIXTURE_RAW) as Record<string, unknown>;

export async function installMockServices(page: Page): Promise<void> {
  // Verifier -----------------------------------------------------------
  await page.route("**/challenge", async (route, req) => {
    if (req.method() !== "POST") return route.fallback();
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        id: "e2e-challenge-0001",
        bytes: "deadbeef",
        expires_at: new Date(Date.now() + 10 * 60_000).toISOString(),
      }),
    });
  });

  await page.route("**/link-verify", async (route, req) => {
    if (req.method() !== "POST") return route.fallback();
    const body = req.postDataJSON();
    const shapeOk =
      typeof body?.cert_chain_proof === "string" &&
      typeof body?.device_sig_proof === "string" &&
      body.cert_chain_proof.length > 0 &&
      body.device_sig_proof.length > 0 &&
      ["rs2048", "rs4096"].includes(body?.cert_chain_type);
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        verified: shapeOk,
        nullifier: body?.nullifier ?? "mock",
      }),
    });
  });

  // HiPKI --------------------------------------------------------------
  await page.route("**/pkcs11info*", async (route, req) => {
    if (req.method() !== "GET") return route.fallback();
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: PKCS11_FIXTURE,
    });
  });

  await page.route("**/sign", async (route, req) => {
    if (req.method() !== "POST") return route.fallback();
    // Always return the bundled test fixture. Real HiPKI would re-sign
    // with a different TBS each call, but for e2e the same signature is
    // enough to exercise the wire path.
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(SIGN_FIXTURE),
    });
  });

  // SMT ----------------------------------------------------------------
  await page.route("**/proof/**", async (route, req) => {
    if (req.method() !== "GET") return route.fallback();
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        root: "0x2a",
        entry: ["0x270f"],
        matchingEntry: ["0x7", "0xb"],
        siblings: [],
      }),
    });
  });
}
