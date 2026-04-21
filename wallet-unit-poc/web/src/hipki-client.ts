// Typed surface for HiPKI LocalSignServer responses.
//
// All requests route through the popupForm bridge (see `hipki-popup.ts`)
// because LocalSignServer ships no CORS headers — direct fetch is blocked
// by the browser. The popup is same-origin with localhost:61161 and talks
// to the main app via window.postMessage.
//
// Field names mirror `ecdsa-spartan2/src/hipki_client.rs` so responses
// deserialize without renames (`subjectDN`, `issuerDN`, `cardSN`).

import { popupPkcs11Info, popupSign } from "./hipki-popup";

export interface Pkcs11CertEntry {
  certb64: string;
  label: string;
  usage?: string;
  sn?: string;
  subjectDN?: string;
  issuerDN?: string;
}

export interface Pkcs11TokenInfo {
  certs: Pkcs11CertEntry[];
  serialNumber?: string;
}

export interface Pkcs11Slot {
  slotDescription?: string;
  token?: Pkcs11TokenInfo;
}

export interface Pkcs11InfoResponse {
  /** LocalSignServer version, e.g. `"1.0.11"`. Present on both GET + POST. */
  serverVersion?: string;
  libraryDescription?: string;
  libraryVersion?: string;
  slots: Pkcs11Slot[];
}

export interface CardSignResponse {
  cardSN: string;
  certb64: string;
  /** Non-zero = PIN / card error. Inspect before trusting `signature`. */
  last_error: number;
  /** `0` on success. */
  ret_code: number;
  signature: string;
}

export interface SignTbsParams {
  tbs: string;
  /** 6-8 digit card PIN. Caller is responsible for lifetime + redaction. */
  pin: string;
  /** Pick a specific reader by `slotDescription` from a prior
   *  `probePkcs11Info()` call. Omit to default to the first reader. */
  slotDescription?: string;
}

/** Full cert-chain lookup, optionally scoped to a specific reader. */
export async function fetchPkcs11Info(
  slotDescription?: string,
): Promise<Pkcs11InfoResponse> {
  return requestPkcs11Info(true, slotDescription);
}

/** Cheap probe — enumerates every connected reader without touching certs.
 *  Use this first to populate a reader picker, then call `fetchPkcs11Info`
 *  with the chosen `slotDescription`. */
export async function probePkcs11Info(): Promise<Pkcs11InfoResponse> {
  return requestPkcs11Info(false);
}

async function requestPkcs11Info(
  withCert: boolean,
  slotDescription?: string,
): Promise<Pkcs11InfoResponse> {
  const body = await popupPkcs11Info<Pkcs11InfoResponse>(
    withCert,
    slotDescription,
  );
  if (!Array.isArray(body?.slots)) {
    throw new Error("HiPKI /pkcs11info response missing slots array");
  }
  return body;
}

/**
 * Sign TBS data via HiPKI `/sign` with `signatureType: "PKCS1"` (raw RSA
 * PKCS#1 v1.5 signature the circuit expects, not CMS-wrapped).
 *
 * The caller MUST inspect `ret_code` / `last_error` — wrong PINs return a
 * 200 with non-zero codes. The Taiwan Citizen Card locks after three wrong
 * PIN attempts; count retries at the UI layer.
 */
export async function signTbs(
  params: SignTbsParams,
): Promise<CardSignResponse> {
  return popupSign<CardSignResponse>(params.tbs, params.pin, params.slotDescription);
}
