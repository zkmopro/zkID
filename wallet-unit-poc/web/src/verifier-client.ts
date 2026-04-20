// Client for github.com/zkmopro/go-zkid-verifier REST API.
// API shape sourced from go-zkid-verifier PR #8 (challenge/handler.go):
//   POST /challenge                           → { id, bytes, expires_at }
//   POST /link-verify  (2 MB body limit)      → { verified, nullifier, id_verified?, persisted? }
//   POST /verify-tbs   (legacy, not used here)
//
// The 2 MB body limit matters: base64 inflates payloads ~33%, so the raw proof
// cap before encoding is ~1.5 MB. We set a conservative per-proof raw cap of
// 700 KB that surfaces a clean error instead of letting the server 413.

const VERIFIER_BASE =
  import.meta.env.VITE_VERIFIER_BASE_URL ?? "http://localhost:8080";

const MAX_RAW_PROOF_BYTES = 700 * 1024;

export interface Challenge {
  id: string;
  bytes: string;
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

export async function createChallenge(): Promise<Challenge> {
  const r = await fetch(`${VERIFIER_BASE}/challenge`, { method: "POST" });
  if (!r.ok) {
    throw new Error(`POST /challenge returned ${r.status} ${r.statusText}`);
  }
  return (await r.json()) as Challenge;
}

export async function submitLinkVerify(
  params: LinkVerifyParams,
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
