// Client for the HiPKI LocalSignServer running on the user's machine.
//
// Mirrors `ecdsa-spartan2/src/hipki_client.rs` — types preserve the server's
// camelCase JSON keys (`subjectDN`, `issuerDN`, `cardSN`) so responses
// deserialize without renames. The browser hits HiPKI directly; we assume
// the user has installed a CORS-enabled LocalSignServer. Over HTTPS the
// browser's mixed-content rules apply — see README.

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
}

/** Full cert-chain lookup. Used once per proving run; the polling detector
 *  uses `probePkcs11Info` (no `withcert=true`) which is cheap enough to hit
 *  on an interval. Both go through the popup bridge. */
export async function fetchPkcs11Info(): Promise<Pkcs11InfoResponse> {
  return requestPkcs11Info(true);
}

/** Cheap probe used by the polling detector. Matches the HiPKI "IC card
 *  function check" reference page's `POST /pkcs11info` call. */
export async function probePkcs11Info(): Promise<Pkcs11InfoResponse> {
  return requestPkcs11Info(false);
}

async function requestPkcs11Info(
  withCert: boolean,
): Promise<Pkcs11InfoResponse> {
  const body = await popupPkcs11Info<Pkcs11InfoResponse>(withCert);
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
  return popupSign<CardSignResponse>(params.tbs, params.pin);
}
