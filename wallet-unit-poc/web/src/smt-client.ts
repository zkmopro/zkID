// Client for the moica-revocation-smt server.
//
// Mirrors `ecdsa-spartan2/src/smt_client.rs`. The wire response uses
// camelCase (`matchingEntry`); the circuit-input shape uses snake_case
// (`smt_root`, `smt_siblings`, ...) so the object deserializes directly
// into `zkid_input_builder::types::SmtCircuitInputs` via the wasm entry.

import { stripTrailingSlash } from "./url-utils";

const SMT_BASE =
  import.meta.env.VITE_SMT_BASE_URL ?? "http://localhost:3000";
const SMT_ISSUER_DEFAULT: SmtIssuer =
  (import.meta.env.VITE_SMT_ISSUER as SmtIssuer | undefined) ?? "g2";

/** SMT tree depth. Must match the circuit parameter (`smtDepth = 128`). */
export const SMT_DEPTH = 128;

/** `g2` = RSA-2048 CA; `g3` = RSA-4096. Typed to catch issuer typos at API boundaries. */
export type SmtIssuer = "g2" | "g3";

export interface SmtProofResponse {
  root: string;
  entry: string[];
  matchingEntry?: string[];
  siblings: string[];
}

/** Circuit-ready SMT inputs. Field names match the Rust `SmtCircuitInputs` struct. */
export interface SmtCircuitInputs {
  smt_root: string;
  serial_number: string;
  smt_siblings: string[];
  smt_old_key: string;
  smt_old_value: string;
  smt_is_old0: string;
}

export interface FetchSmtProofParams {
  issuer?: SmtIssuer;
  /** Certificate serial number in hex (with or without `0x` prefix). */
  serialHex: string;
  baseUrl?: string;
  depth?: number;
}

export async function fetchSmtProof(
  params: FetchSmtProofParams,
): Promise<SmtCircuitInputs> {
  const base = stripTrailingSlash(params.baseUrl ?? SMT_BASE);
  const issuer = params.issuer ?? SMT_ISSUER_DEFAULT;
  const depth = params.depth ?? SMT_DEPTH;
  const url = `${base}/proof/${encodeURIComponent(issuer)}/${encodeURIComponent(
    params.serialHex,
  )}`;

  const r = await fetch(url, { method: "GET" });
  if (!r.ok) {
    throw new Error(
      `GET /proof/${issuer}/${params.serialHex} returned ${r.status} ${r.statusText}`,
    );
  }
  return convertSmtProofToCircuitInputs(
    (await r.json()) as SmtProofResponse,
    depth,
  );
}

/** Exported for unit tests; also usable by callers that have a cached response. */
export function convertSmtProofToCircuitInputs(
  resp: SmtProofResponse,
  depth: number = SMT_DEPTH,
): SmtCircuitInputs {
  if (!Array.isArray(resp?.entry) || resp.entry.length === 0) {
    throw new Error("SMT response has empty entry array");
  }
  if (!Array.isArray(resp.siblings)) {
    throw new Error("SMT response missing siblings array");
  }

  const siblings = resp.siblings.map(hexToDecimal);
  // Pad to depth with "0"; truncate if server returned more than depth.
  while (siblings.length < depth) siblings.push("0");
  if (siblings.length > depth) siblings.length = depth;

  const matching = resp.matchingEntry;
  const hasMatching = Array.isArray(matching) && matching.length >= 2;
  const [smt_old_key, smt_old_value, smt_is_old0] = hasMatching
    ? [hexToDecimal(matching![0]), hexToDecimal(matching![1]), "0"]
    : ["0", "0", "1"];

  return {
    smt_root: hexToDecimal(resp.root),
    serial_number: hexToDecimal(resp.entry[0]),
    smt_siblings: siblings,
    smt_old_key,
    smt_old_value,
    smt_is_old0,
  };
}

/**
 * Convert `0x`-prefixed hex to decimal. Values without the prefix pass through
 * unchanged — the server sometimes emits already-decimal entries. Matches
 * `hex_to_decimal` in `ecdsa-spartan2/src/smt_client.rs`.
 */
function hexToDecimal(val: string): string {
  if (val.startsWith("0x") || val.startsWith("0X")) {
    return BigInt(val).toString(10);
  }
  return val;
}
