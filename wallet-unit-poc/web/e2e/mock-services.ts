// Playwright mocks for every external service the pipeline hits.
//
// HiPKI XHRs come from the popupForm postMessage bridge popup window, out
// of reach of `page.route()`. The popup module exposes a test override via
// `globalThis.__HIPKI_TEST_HANDLER__`; we inject it through `addInitScript`
// before any app code runs. Verifier mocks stay on `page.route()` since
// those calls are issued from the app origin.
//
// SMT is different: instead of mocking a network endpoint, we inject a
// fake SMT engine via `globalThis.__SMT_TEST_ENGINE__` so the app skips
// the real Go WASM bootstrap entirely. That hook runs inside the proving
// Worker, which is why the init script uses `page.addInitScript` AND we
// forward the same escape hatch via the module loader setup below.
//
// Cert fixtures re-use `ecdsa-spartan2/tests/testdata/*.json` so Rust/TS
// schema drift surfaces in e2e too.

import type { Page } from "@playwright/test";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

// `__dirname` is not defined in ESM (`package.json` has `"type": "module"`);
// derive it from `import.meta.url` so Playwright's ESM loader can run this
// file without crashing at module init.
const HERE = dirname(fileURLToPath(import.meta.url));

const TESTDATA = resolve(HERE, "../../ecdsa-spartan2/tests/testdata");
const SIGN_FIXTURE_RAW = readFileSync(
  resolve(TESTDATA, "response_sign_test.json"),
  "utf8",
);

/** `pkcs11info_test.json` is authored for the Rust CLI and predates the
 *  slot-picker UI. Gap 1: slots have no `slotDescription`, so the setup
 *  screen stores `"(unnamed reader)"` as the selected slot and then
 *  `buildCardContext` fails to find it in the re-queried fixture. Gap 2:
 *  user certs carry no `sn` and tokens carry no `serialNumber`, so
 *  `deriveSerialHex` throws with "no serial number on user cert or token".
 *  Inject both here so the mock is self-contained without having to mutate
 *  a fixture that the Rust tests also read. */
const PKCS11_FIXTURE = (() => {
  const raw = readFileSync(
    resolve(TESTDATA, "pkcs11info_test.json"),
    "utf8",
  );
  interface Cert {
    label?: string;
    sn?: string;
    [k: string]: unknown;
  }
  interface Token {
    serialNumber?: string;
    certs?: Cert[];
    [k: string]: unknown;
  }
  interface Slot {
    slotDescription?: string;
    token?: Token;
    [k: string]: unknown;
  }
  const parsed = JSON.parse(raw) as { slots?: Slot[] };
  parsed.slots?.forEach((slot, i) => {
    if (!slot.slotDescription) slot.slotDescription = `Mock Reader ${i}`;
    if (slot.token && !slot.token.serialNumber) {
      slot.token.serialNumber = `MOCKSN${String(i).padStart(6, "0")}`;
    }
    slot.token?.certs?.forEach((cert) => {
      if (cert.label !== "CA Cert" && !cert.sn) {
        cert.sn = "0xDEADBEEF";
      }
    });
  });
  return JSON.stringify(parsed);
})();

export interface InstallMockOptions {
  /** Set to a non-2xx status to simulate verifier downtime. */
  linkVerifyStatus?: number;
  /** Override the response body the verifier returns. */
  linkVerifyBody?: unknown;
  /** Force `signTbs` to fail with a non-zero ret_code (wrong PIN). */
  signRejectsPin?: boolean;
  /** Replace the SMT proof the fake engine emits (e.g. for "no proof" paths).
   *  Fields are hex strings, matching what smt.wasm's `smtCreateProof` returns. */
  smtBody?: {
    root: string;
    entry: string[];
    matchingEntry?: string[];
    siblings: string[];
  };
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

  await installSmtTestEngine(page, {
    smtBody: opts.smtBody ?? {
      root: "2a",
      entry: ["270f"],
      matchingEntry: ["7", "b"],
      siblings: ["64"],
    },
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

  // Dead-end any stray request to the old SMT server path so regressions
  // that forget to delete the remote-fetch code surface as loud test
  // failures instead of silently passing.
  await page.route("**/smt-snapshot/**", async (route) => {
    await route.fulfill({
      status: 410,
      contentType: "text/plain",
      body: "snapshot download should be stubbed by __SMT_TEST_ENGINE__ in e2e",
    });
  });
  await page.route("**/proof/**", async (route) => {
    await route.fulfill({
      status: 410,
      contentType: "text/plain",
      body: "remote SMT proof endpoint is gone — browser uses __SMT_TEST_ENGINE__",
    });
  });
}

interface SmtEngineOpts {
  smtBody: {
    root: string;
    entry: string[];
    matchingEntry?: string[];
    siblings: string[];
  };
}

/** Seed `globalThis.__SMT_TEST_PROOF__` on the main thread so the app's
 *  main-thread SMT client short-circuits the Worker round-trip and returns
 *  the fixture inputs directly. Worker globals are isolated from
 *  `page.addInitScript`, which is why the hook lives on the main thread.
 *  `main.ts` checks the same hook to flip `$smt` to ready synchronously. */
async function installSmtTestEngine(
  page: Page,
  opts: SmtEngineOpts,
): Promise<void> {
  await page.addInitScript((injected) => {
    const body = injected.smtBody;
    interface ProofGlobal {
      __SMT_TEST_PROOF__?: {
        root: string;
        entry: string[];
        matchingEntry?: string[];
        siblings: string[];
      };
    }
    (globalThis as ProofGlobal).__SMT_TEST_PROOF__ = body;
  }, opts);
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
