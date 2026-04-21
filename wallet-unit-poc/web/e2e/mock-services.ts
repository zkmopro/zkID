// Playwright mocks for every external service the pipeline hits.
//
// HiPKI XHRs come from the popupForm postMessage bridge popup window, out
// of reach of `page.route()`. The popup module exposes a test override via
// `globalThis.__HIPKI_TEST_HANDLER__`; we inject it through `addInitScript`
// before any app code runs. Verifier and SMT mocks stay on `page.route()`
// since those calls are issued from the app origin.
//
// Cert fixtures re-use `ecdsa-spartan2/tests/testdata/*.json` so Rust/TS
// schema drift surfaces in e2e too.

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

export interface InstallMockOptions {
  /** Set to a non-2xx status to simulate verifier downtime. */
  linkVerifyStatus?: number;
  /** Override the response body the verifier returns. */
  linkVerifyBody?: unknown;
  /** Force `signTbs` to fail with a non-zero ret_code (wrong PIN). */
  signRejectsPin?: boolean;
  /** Replace the SMT response shape (e.g. for "no proof" paths). */
  smtBody?: unknown;
}

export async function installMockServices(
  page: Page,
  opts: InstallMockOptions = {},
): Promise<void> {
  await installHipkiPopupHandler(page, {
    pkcs11Fixture: PKCS11_FIXTURE,
    signFixture: SIGN_FIXTURE_RAW,
    signRejectsPin: opts.signRejectsPin ?? false,
  });

  // Verifier -----------------------------------------------------------
  await page.route("**/challenge", async (route, req) => {
    if (req.method() !== "POST") return route.fallback();
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        challenge_id: "e2e-challenge-0001",
        challenge_bytes: "deadbeef",
        expires_at: new Date(Date.now() + 10 * 60_000).toISOString(),
      }),
    });
  });

  await page.route("**/link-verify", async (route, req) => {
    if (req.method() !== "POST") return route.fallback();
    if (opts.linkVerifyStatus && opts.linkVerifyStatus >= 400) {
      await route.fulfill({
        status: opts.linkVerifyStatus,
        contentType: "text/plain",
        body: "verifier down",
      });
      return;
    }
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
      body: JSON.stringify(
        opts.linkVerifyBody ?? {
          verified: shapeOk,
          nullifier: body?.nullifier ?? "mock",
        },
      ),
    });
  });

  // SMT ----------------------------------------------------------------
  await page.route("**/proof/**", async (route, req) => {
    if (req.method() !== "GET") return route.fallback();
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(
        opts.smtBody ?? {
          root: "0x2a",
          entry: ["0x270f"],
          matchingEntry: ["0x7", "0xb"],
          siblings: [],
        },
      ),
    });
  });
}

interface PopupHandlerOpts {
  pkcs11Fixture: string;
  signFixture: string;
  signRejectsPin: boolean;
}

/** Install the popup test handler before app boot. The handler runs in
 *  page context and must be self-contained — pass fixture text as
 *  JSON-serialisable args rather than closing over Node state. */
async function installHipkiPopupHandler(
  page: Page,
  opts: PopupHandlerOpts,
): Promise<void> {
  await page.addInitScript((injected) => {
    const { pkcs11Fixture, signFixture, signRejectsPin } = injected;
    interface HandlerGlobal {
      __HIPKI_TEST_HANDLER__?: (
        payload: Record<string, unknown>,
      ) => Promise<string>;
    }
    const g = globalThis as HandlerGlobal;
    g.__HIPKI_TEST_HANDLER__ = async (payload) => {
      const func = payload.func;
      if (func === "CheckEnvir" || func === "GetUserCert") {
        return pkcs11Fixture;
      }
      if (func === "MakeSignature") {
        if (signRejectsPin) {
          const fixture = JSON.parse(signFixture) as Record<string, unknown>;
          return JSON.stringify({
            ...fixture,
            ret_code: 1,
            last_error: 0x6982,
          });
        }
        return signFixture;
      }
      throw new Error(`mock popup handler: unknown func ${String(func)}`);
    };
  }, opts);
}
