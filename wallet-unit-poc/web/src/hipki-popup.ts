// HiPKI popup bridge (`/popupForm`) used because LocalSignServer has no CORS.
// The flow is one request per popup: open -> wait for ready message -> send
// payload -> receive response text -> popup closes.

import { stripTrailingSlash } from "./url-utils";

const HIPKI_BASE =
  import.meta.env.VITE_HIPKI_BASE_URL ?? "http://localhost:61161";

/** Test-mode override: when `globalThis.__HIPKI_TEST_HANDLER__` is set, every
 *  `popupRequest` is routed through it instead of opening a real popup.
 *  Playwright cannot intercept a popup's same-origin XHRs to LocalSignServer,
 *  so e2e mocks bypass the bridge entirely by installing this handler. */
type HipkiTestHandler = (
  payload: Record<string, unknown>,
) => Promise<string>;

interface HipkiTestGlobal {
  __HIPKI_TEST_HANDLER__?: HipkiTestHandler;
}

function getTestHandler(): HipkiTestHandler | undefined {
  return (globalThis as HipkiTestGlobal).__HIPKI_TEST_HANDLER__;
}

const POPUP_PATH = "/popupForm";
const POPUP_WINDOW_FEATURES = "width=480,height=320,resizable=yes,scrollbars=yes";
const READY_TIMEOUT_MS = 10_000;
const RESPONSE_TIMEOUT_MS = 30_000;

function originOf(url: string): string {
  // Fail fast on invalid URLs so misconfiguration is explicit.
  return new URL(url).origin;
}

/** Shape check for the popup's ready signal (`{func:"getTbs"}`). */
function isReadySignal(data: unknown): boolean {
  if (typeof data !== "string") return false;
  try {
    const parsed = JSON.parse(data) as { func?: unknown };
    return parsed?.func === "getTbs";
  } catch {
    return false;
  }
}

/**
 * Open one popup, send one request, await one response, then let the
 * popup self-close. Must be called from a user-gesture handler
 * (button click) so the browser doesn't pop-block.
 */
function popupRequest(
  payload: Record<string, unknown>,
  baseUrl: string = HIPKI_BASE,
): Promise<string> {
  const testHandler = getTestHandler();
  if (testHandler) return testHandler(payload);
  return new Promise<string>((resolve, reject) => {
    const target = `${stripTrailingSlash(baseUrl)}${POPUP_PATH}`;
    let expectedOrigin: string;
    try {
      expectedOrigin = originOf(target);
    } catch {
      reject(new Error(`HiPKI: invalid baseUrl ${baseUrl}`));
      return;
    }
    const popup = window.open(target, "hipkiPopup", POPUP_WINDOW_FEATURES);
    if (!popup) {
      reject(new Error("HiPKI popup blocked - allow popups for this site"));
      return;
    }

    let ready = false;
    let settled = false;
    const cleanup = (): void => {
      window.removeEventListener("message", onMessage);
      clearTimeout(readyTimer);
      clearTimeout(responseTimer);
    };

    const finish = (
      kind: "ok" | "err",
      value: string | Error,
    ): void => {
      if (settled) return;
      settled = true;
      cleanup();
      if (kind === "ok") resolve(value as string);
      else reject(value as Error);
    };

    const onMessage = (ev: MessageEvent): void => {
      // Browser extensions postMessage objects into every window; reject
      // anything that isn't from the popup's origin or isn't a string.
      if (ev.origin !== expectedOrigin) return;
      const data = ev.data;
      if (typeof data !== "string") return;
      if (!ready) {
        if (isReadySignal(data)) {
          ready = true;
          clearTimeout(readyTimer);
          // Send the request payload now that the popup is listening.
          popup.postMessage(JSON.stringify(payload), expectedOrigin);
        }
        return;
      }
      // Any subsequent string from the popup is the responseText.
      finish("ok", data);
    };

    window.addEventListener("message", onMessage);

    const readyTimer = setTimeout(() => {
      if (!ready) {
        if (!popup.closed) popup.close();
        finish("err", new Error("HiPKI popup did not signal ready"));
      }
    }, READY_TIMEOUT_MS);

    const responseTimer = setTimeout(() => {
      if (!popup.closed) popup.close();
      finish("err", new Error("HiPKI popup timeout"));
    }, RESPONSE_TIMEOUT_MS);
  });
}

/** Generic /pkcs11info bridge wrapper. */
export async function popupPkcs11Info<T = Record<string, unknown>>(
  withCert: boolean,
  slotDescription?: string,
): Promise<T> {
  const payload: Record<string, unknown> = {
    func: withCert ? "GetUserCert" : "CheckEnvir",
  };
  if (slotDescription) payload.slotDescription = slotDescription;
  const body = await popupRequest(payload);
  return JSON.parse(body) as T;
}

/** Generic /sign bridge wrapper. */
export async function popupSign<T = Record<string, unknown>>(
  tbs: string,
  pin: string,
  slotDescription?: string,
): Promise<T> {
  const payload: Record<string, unknown> = {
    func: "MakeSignature",
    tbs,
    pin,
    hashAlgorithm: "SHA256",
    signatureType: "PKCS1",
  };
  if (slotDescription) payload.slotDescription = slotDescription;
  const body = await popupRequest(payload);
  return JSON.parse(body) as T;
}
