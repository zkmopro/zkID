// HiPKI bridge using LocalSignServer's `popupForm` postMessage protocol.
//
// HiPKI's LocalSignServer at http://localhost:61161 doesn't send CORS
// headers, so direct `fetch()` from any other origin is blocked even
// though the server returns 200. The official workaround (HiPKI Citizen
// Card series, blog 7) is `popupForm`: the LocalSignServer hosts a tiny
// HTML page at /popupForm. Because that page IS hosted at
// http://localhost:61161, its own XHRs to /pkcs11info, /sign, etc. are
// same-origin and unblocked. Our app communicates with the popup via
// window.postMessage, which works across origins by design.
//
// Protocol the popupForm expects (reverse-engineered from the blog post
// at https://medium.com/chouhsiang/...-popupform-...):
//   1. window.open("http://localhost:61161/popupForm")
//   2. popup posts the literal string "getTbs" to window.opener once it's
//      ready to accept commands.
//   3. our app posts JSON.stringify(payload) — payload is the request as
//      the underlying HiPKI endpoint would expect it (e.g. {tbs, pin,
//      hashAlgorithm, signatureType} for /sign). The popup decides which
//      endpoint to hit based on payload shape.
//   4. popup runs the operation and posts back the raw responseText
//      (a JSON string) via window.opener.postMessage(...).
//
// Limitations:
//  * `popupForm` uses `window.opener`, so the bridge only works from a
//    popup window — not an iframe.
//  * Browsers gate `window.open` to user-gesture handlers. Each session
//    needs at least one click on a button that opens the popup.
//  * `Cross-Origin-Opener-Policy: same-origin` severs `window.opener`
//    for cross-origin popups; we must use `same-origin-allow-popups`.
//
// Single-flight: at most one HiPKI request is in flight through the
// bridge. The popupForm doesn't carry a request id, so we serialise.

import { stripTrailingSlash } from "./url-utils";

const HIPKI_BASE =
  import.meta.env.VITE_HIPKI_BASE_URL ?? "http://localhost:61161";

const POPUP_PATH = "/popupForm";
const POPUP_WINDOW_FEATURES = "width=480,height=320,resizable=yes,scrollbars=yes";

let popup: Window | null = null;
let popupOrigin: string | null = null;
let pendingReady: { resolve: () => void; reject: (e: Error) => void } | null = null;
let pendingResponse: { resolve: (text: string) => void; reject: (e: Error) => void; timeoutId: ReturnType<typeof setTimeout> } | null = null;
let messageListener: ((ev: MessageEvent) => void) | null = null;
let inflight: Promise<string> | null = null;

function originOf(url: string): string {
  try {
    return new URL(url).origin;
  } catch {
    return url;
  }
}

export function isPopupReady(): boolean {
  return popup !== null && !popup.closed && popupOrigin !== null;
}

/**
 * Open the LocalSignServer popup and wait for its `getTbs` ready signal.
 * Must be called from a user-gesture handler (button click) so the browser
 * doesn't pop-block. Idempotent: returns immediately if a live popup
 * already exists.
 */
export function openHipkiPopup(baseUrl: string = HIPKI_BASE): Promise<void> {
  if (isPopupReady()) return Promise.resolve();

  const target = `${stripTrailingSlash(baseUrl)}${POPUP_PATH}`;
  popupOrigin = originOf(target);
  popup = window.open(target, "hipkiPopup", POPUP_WINDOW_FEATURES);
  if (!popup) {
    popupOrigin = null;
    return Promise.reject(
      new Error("HiPKI popup blocked - allow popups for this site"),
    );
  }

  if (!messageListener) {
    messageListener = (ev: MessageEvent) => {
      if (ev.origin !== popupOrigin) return;
      const data = ev.data;
      if (data === "getTbs") {
        pendingReady?.resolve();
        pendingReady = null;
        return;
      }
      if (typeof data === "string" && pendingResponse) {
        clearTimeout(pendingResponse.timeoutId);
        pendingResponse.resolve(data);
        pendingResponse = null;
      }
    };
    window.addEventListener("message", messageListener);
  }

  return new Promise<void>((resolve, reject) => {
    pendingReady = { resolve, reject };
    setTimeout(() => {
      if (pendingReady) {
        // On timeout we must also tear down the popup state. Otherwise
        // `popup` / `popupOrigin` stay set, `isPopupReady()` returns true,
        // and the next `openHipkiPopup` short-circuits without arming a
        // fresh readiness handshake — the bridge would be half-alive.
        pendingReady.reject(new Error("HiPKI popup did not respond"));
        pendingReady = null;
        closeHipkiPopup();
      }
    }, 10_000);
  });
}

export function closeHipkiPopup(): void {
  if (popup && !popup.closed) popup.close();
  popup = null;
  popupOrigin = null;
  pendingReady = null;
  if (pendingResponse) {
    clearTimeout(pendingResponse.timeoutId);
    pendingResponse.reject(new Error("HiPKI popup closed"));
    pendingResponse = null;
  }
  inflight = null;
  if (messageListener) {
    window.removeEventListener("message", messageListener);
    messageListener = null;
  }
}

/**
 * Post a payload to the popup and resolve with the raw response body.
 * Serialised: a second call queues until the first resolves. The popup's
 * id-less protocol can't correlate concurrent requests, so we wait.
 */
export function postToHipkiPopup(
  payload: Record<string, unknown>,
  timeoutMs = 30_000,
): Promise<string> {
  const run = async (): Promise<string> => {
    if (!popup || popup.closed || !popupOrigin) {
      throw new Error("HiPKI popup not open");
    }
    return new Promise<string>((resolve, reject) => {
      const timeoutId = setTimeout(() => {
        pendingResponse = null;
        reject(new Error("HiPKI popup timeout"));
      }, timeoutMs);
      pendingResponse = { resolve, reject, timeoutId };
      popup!.postMessage(JSON.stringify(payload), popupOrigin!);
    });
  };

  // Run after any in-flight request settles (success OR failure — we don't
  // want one bad call to deadlock the chain). The caller sees `next`'s real
  // outcome; `inflight` is a separate pointer that never rejects, so the
  // chain keeps advancing.
  const prev = inflight ?? Promise.resolve("");
  const next = prev.then(run, run);
  inflight = next.then(
    () => "",
    () => "",
  );
  return next;
}

/** Convenience wrapper for /pkcs11info via the bridge. Generic so callers
 *  can pin the response type at the call site without a secondary cast. */
export async function popupPkcs11Info<T = Record<string, unknown>>(
  withCert: boolean,
): Promise<T> {
  const body = await postToHipkiPopup({
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
  const body = await postToHipkiPopup({
    func: "MakeSignature",
    tbs,
    pin,
    hashAlgorithm: "SHA256",
    signatureType: "PKCS1",
  });
  return JSON.parse(body) as T;
}
