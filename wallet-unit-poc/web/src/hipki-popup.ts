// HiPKI bridge using LocalSignServer's `popupForm` postMessage protocol.
//
// HiPKI's LocalSignServer at http://localhost:61161 doesn't send CORS
// headers, so direct `fetch()` from any other origin is blocked even
// though the server returns 200. The workaround is `popupForm`: the
// LocalSignServer hosts a tiny HTML page at /popupForm. Because that
// page IS hosted at http://localhost:61161, its own XHRs to the local
// API are same-origin and unblocked. Our app talks to the popup via
// window.postMessage, which works across origins by design.
//
// Protocol the popupForm actually implements (verified against the
// HiPKI sample at https://medium.com/chouhsiang/...-popupform-...):
//   1. window.open("http://localhost:61161/popupForm")
//   2. popup posts `JSON.stringify({func:"getTbs"})` to window.opener
//      once it's ready to accept commands.
//   3. our app posts `JSON.stringify(payload)` — `payload.func` selects
//      the action ("pkcs11info", "MakeSignature", ...).
//   4. popup runs the operation, posts back the raw responseText, and
//      then calls `window.close()` on itself.
//
// **Single-shot per popup.** The popup self-closes after one response.
// Each request needs its own `window.open()`, which requires a user
// gesture. Polling through this bridge is not possible — every probe
// would need a click. Setup UI is structured around that.

import { stripTrailingSlash } from "./url-utils";

const HIPKI_BASE =
  import.meta.env.VITE_HIPKI_BASE_URL ?? "http://localhost:61161";

const POPUP_PATH = "/popupForm";
const POPUP_WINDOW_FEATURES = "width=480,height=320,resizable=yes,scrollbars=yes";
const READY_TIMEOUT_MS = 10_000;
const RESPONSE_TIMEOUT_MS = 30_000;

function originOf(url: string): string {
  try {
    return new URL(url).origin;
  } catch {
    return url;
  }
}

/** Look-alike check for the popup's ready signal (`{func:"getTbs"}`). */
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
export function popupRequest(
  payload: Record<string, unknown>,
  baseUrl: string = HIPKI_BASE,
): Promise<string> {
  return new Promise<string>((resolve, reject) => {
    const target = `${stripTrailingSlash(baseUrl)}${POPUP_PATH}`;
    const expectedOrigin = originOf(target);
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
      payload: string | Error,
    ): void => {
      if (settled) return;
      settled = true;
      cleanup();
      if (kind === "ok") resolve(payload as string);
      else reject(payload as Error);
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

/** Convenience wrapper for /pkcs11info via the bridge. Generic so callers
 *  can pin the response type at the call site without a secondary cast. */
export async function popupPkcs11Info<T = Record<string, unknown>>(
  withCert: boolean,
): Promise<T> {
  const body = await popupRequest({
    func: "pkcs11info",
    withcert: withCert,
  });
  return JSON.parse(body) as T;
}

/** Convenience wrapper for /sign via the bridge. PIN is passed straight
 *  through; caller is responsible for redaction (use the `Pin` wrapper). */
export async function popupSign<T = Record<string, unknown>>(
  tbs: string,
  pin: string,
): Promise<T> {
  const body = await popupRequest({
    func: "MakeSignature",
    tbs,
    pin,
    hashAlgorithm: "SHA256",
    signatureType: "PKCS1",
  });
  return JSON.parse(body) as T;
}
