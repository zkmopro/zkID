// Client for the go-zkid-verifier REST API.
//
// Wire shape (snake_case, byte-for-byte with the native Rust client):
//   POST /challenge    → { challenge_id, challenge_bytes, expires_at }
//   POST /link-verify  → { verified, nullifier, id_verified?, persisted? }
//
// Keeping the server's exact field names on the interface avoids a remap
// layer where a TS-side rename would silently cast to `undefined` at
// runtime — the `createChallenge` shape guard enforces this invariant.
//
// The verifier has a 2 MB body limit; base64 inflates ~33%, so we cap
// each raw proof at 700 KB to surface a clean error before the server 413s.

import { composeSignal, parsePositiveInt } from "./abort-utils";

const VERIFIER_BASE =
  import.meta.env.VITE_VERIFIER_BASE_URL ?? "http://localhost:8080";

const MAX_RAW_PROOF_BYTES = 700 * 1024;

export interface Challenge {
  challenge_id: string;
  challenge_bytes: string;
  expires_at: string;
}

export interface LinkVerifyResult {
  verified: boolean;
  nullifier: string;
  id_verified?: boolean;
  persisted?: boolean;
}

export interface LinkVerifyParams {
  challengeId: string;
  certChainType: "rs2048" | "rs4096";
  certChainProofBytes: Uint8Array;
  deviceSigProofBytes: Uint8Array;
  nullifier: string;
}

/** Default per-request timeout. Overridable via VITE_VERIFIER_TIMEOUT_MS. */
const VERIFIER_TIMEOUT_MS = parsePositiveInt(
  import.meta.env.VITE_VERIFIER_TIMEOUT_MS,
  15_000,
);

export interface CreateChallengeOptions {
  signal?: AbortSignal;
}

export interface SubmitLinkVerifyOptions {
  signal?: AbortSignal;
}

export async function createChallenge(
  opts: CreateChallengeOptions = {},
): Promise<Challenge> {
  const r = await fetch(`${VERIFIER_BASE}/challenge`, {
    method: "POST",
    signal: composeSignal(opts.signal, VERIFIER_TIMEOUT_MS),
  });
  if (!r.ok) {
    throw new Error(`POST /challenge returned ${r.status} ${r.statusText}`);
  }
  const body = (await r.json()) as Partial<Challenge>;
  // Runtime shape guard. The `as Challenge` cast alone is unsound — if the
  // server ever changes field names, downstream code would read `undefined`
  // and break silently. Fail fast here instead.
  if (
    typeof body?.challenge_id !== "string" ||
    typeof body?.challenge_bytes !== "string"
  ) {
    throw new Error(
      `POST /challenge: unexpected response shape (got keys: ${Object.keys(body ?? {}).join(", ") || "none"})`,
    );
  }
  return body as Challenge;
}

export async function submitLinkVerify(
  params: LinkVerifyParams,
  opts: SubmitLinkVerifyOptions = {},
): Promise<LinkVerifyResult> {
  assertProofSize("cert_chain_proof", params.certChainProofBytes);
  assertProofSize("device_sig_proof", params.deviceSigProofBytes);

  const body = {
    challenge_id: params.challengeId,
    cert_chain_type: params.certChainType,
    // Go's json.Unmarshal decodes base64 into []byte automatically.
    cert_chain_proof: bytesToBase64(params.certChainProofBytes),
    device_sig_proof: bytesToBase64(params.deviceSigProofBytes),
    nullifier: params.nullifier,
  };

  const r = await fetch(`${VERIFIER_BASE}/link-verify`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
    signal: composeSignal(opts.signal, VERIFIER_TIMEOUT_MS),
  });
  if (!r.ok) {
    const text = await r.text().catch(() => "");
    throw new Error(
      `POST /link-verify returned ${r.status} ${r.statusText}${text ? ` — ${text}` : ""}`,
    );
  }
  return (await r.json()) as LinkVerifyResult;
}

function assertProofSize(field: string, bytes: Uint8Array): void {
  if (bytes.byteLength > MAX_RAW_PROOF_BYTES) {
    throw new Error(
      `${field} is ${bytes.byteLength} bytes, exceeds ${MAX_RAW_PROOF_BYTES}-byte raw cap (server limit is 2 MB for the whole JSON body, base64 inflates ~33%)`,
    );
  }
}

function bytesToBase64(b: Uint8Array): string {
  // TextEncoder-free; works in Worker context without globalThis.atob polyfills.
  let s = "";
  // Chunk to avoid hitting String.fromCharCode arg-count limits on large inputs.
  const CHUNK = 0x8000;
  for (let i = 0; i < b.length; i += CHUNK) {
    s += String.fromCharCode(...b.subarray(i, Math.min(i + CHUNK, b.length)));
  }
  return btoa(s);
}
