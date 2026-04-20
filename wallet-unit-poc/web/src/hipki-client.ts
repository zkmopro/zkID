// Client for the HiPKI LocalSignServer running on the user's machine.
//
// Mirrors `ecdsa-spartan2/src/hipki_client.rs` — types preserve the server's
// camelCase JSON keys (`subjectDN`, `issuerDN`, `cardSN`) so responses
// deserialize without renames. The browser hits HiPKI directly; we assume
// the user has installed a CORS-enabled LocalSignServer. Over HTTPS the
// browser's mixed-content rules apply — see README.

import { stripTrailingSlash } from "./url-utils";

const HIPKI_BASE =
  import.meta.env.VITE_HIPKI_BASE_URL ?? "http://localhost:61161";

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
  token?: Pkcs11TokenInfo;
}

export interface Pkcs11InfoResponse {
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
  baseUrl?: string;
}

export async function fetchPkcs11Info(
  baseUrl: string = HIPKI_BASE,
): Promise<Pkcs11InfoResponse> {
  const url = `${stripTrailingSlash(baseUrl)}/pkcs11info?withcert=true`;
  const r = await fetch(url, { method: "GET" });
  if (!r.ok) {
    throw new Error(`GET /pkcs11info returned ${r.status} ${r.statusText}`);
  }
  const body = (await r.json()) as Pkcs11InfoResponse;
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
  const base = stripTrailingSlash(params.baseUrl ?? HIPKI_BASE);
  const tbsPackage = JSON.stringify({
    tbs: params.tbs,
    pin: params.pin,
    hashAlgorithm: "SHA256",
    signatureType: "PKCS1",
  });

  // application/x-www-form-urlencoded with a single `tbsPackage` field
  // mirrors Rust's `send_form(&[("tbsPackage", ...)])` exactly.
  const body = new URLSearchParams();
  body.append("tbsPackage", tbsPackage);

  const r = await fetch(`${base}/sign`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: body.toString(),
  });
  if (!r.ok) {
    // Deliberately opaque — server could echo request fields and leak the
    // PIN into the error message / logs.
    throw new Error(`POST /sign returned ${r.status} ${r.statusText}`);
  }
  return (await r.json()) as CardSignResponse;
}
