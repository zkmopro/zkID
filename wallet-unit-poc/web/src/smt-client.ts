// Request/response wrapper around the proving Worker's SMT engine.
//
// The engine itself (`smt-local.ts`) runs inside the Worker to isolate the
// Go runtime and large snapshot buffer from the main-thread event loop.
// This module is the main-thread entry point: `fetchSmtProof` postMessages
// a `smt_proof` request and awaits the matching `smt_proof_done` reply.
//
// Types + `convertSmtProofToCircuitInputs` live here because the Worker
// imports them too — the conversion runs inside the Worker so the wire
// format between Worker and main thread is the already-decimalised
// `SmtCircuitInputs`, not the raw hex proof.

/** SMT tree depth. Must match the circuit parameter (`smtDepth = 128`) and
 *  the binary snapshot header's `depth` field. */
export const SMT_DEPTH = 128;

/** `g2` = RSA-2048 CA (MOICA-G2); `g3` = RSA-4096 (MOICA-G3). */
export type SmtIssuer = "g2" | "g3";

/** Shape emitted by `smt.wasm::smtCreateProof`. Hex strings have no `0x`
 *  prefix (Go `big.Int.Text(16)` convention); `hexToDecimal` below accepts
 *  both prefixed and bare forms so older fixtures still work. */
export interface SmtProofResponse {
  root: string;
  entry: string[];
  matchingEntry?: string[];
  siblings: string[];
  /** Present on the wasm output; ignored here. */
  membership?: boolean;
}

/** Circuit-ready SMT inputs. Field names match the Rust `SmtCircuitInputs`
 *  struct (`zkid-input-builder/src/types.rs`) so the wasm bridge can
 *  deserialise directly. */
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
  depth?: number;
  signal?: AbortSignal;
}

interface SmtProofDone {
  step: "smt_proof_done";
  requestId: string;
  inputs: SmtCircuitInputs;
}
interface SmtProofError {
  step: "smt_proof_error";
  requestId: string;
  message: string;
}

/** Page-global test escape hatch. When present, `fetchSmtProof` skips the
 *  Worker entirely and returns fake inputs derived from the fixture proof.
 *  Playwright injects this through `page.addInitScript` — Worker globals are
 *  isolated so the equivalent Worker-side hook would never fire.
 *  `sign-main.ts` checks the same hook to short-circuit `load_smt` and flip
 *  `$smt` to ready synchronously. */
interface SmtTestHookGlobal {
  __SMT_TEST_PROOF__?: SmtProofResponse;
}

export function getSmtTestProof(): SmtProofResponse | undefined {
  return (globalThis as SmtTestHookGlobal).__SMT_TEST_PROOF__;
}

let requestCounter = 0;

/** Post `{type:"smt_proof"}` to the Worker and resolve with the matching
 *  `smt_proof_done` reply. The Worker must already have an SMT engine
 *  loaded for the card's issuer (sign-main.ts sends `{type:"load_smt"}` once
 *  HiPKI reaches `card_ready`). */
export function fetchSmtProof(
  worker: Worker,
  params: FetchSmtProofParams,
): Promise<SmtCircuitInputs> {
  const testProof = getSmtTestProof();
  if (testProof) {
    if (params.signal?.aborted) {
      return Promise.reject(new DOMException("aborted", "AbortError"));
    }
    return Promise.resolve(
      convertSmtProofToCircuitInputs(testProof, params.depth ?? SMT_DEPTH),
    );
  }
  return new Promise<SmtCircuitInputs>((resolve, reject) => {
    const requestId = `smt-${Date.now()}-${requestCounter++}`;
    let settled = false;

    const onAbort = () => {
      if (settled) return;
      settled = true;
      worker.removeEventListener("message", onMessage);
      params.signal?.removeEventListener("abort", onAbort);
      reject(new DOMException("aborted", "AbortError"));
    };

    const onMessage = (ev: MessageEvent<SmtProofDone | SmtProofError | unknown>) => {
      const d = ev.data as SmtProofDone | SmtProofError | undefined;
      if (!d || typeof d !== "object" || !("step" in d) || !("requestId" in d))
        return;
      if (d.requestId !== requestId) return;
      if (d.step !== "smt_proof_done" && d.step !== "smt_proof_error") return;
      if (settled) return;
      settled = true;
      worker.removeEventListener("message", onMessage);
      params.signal?.removeEventListener("abort", onAbort);
      if (d.step === "smt_proof_done") {
        resolve(d.inputs);
      } else {
        reject(new Error(d.message));
      }
    };

    if (params.signal?.aborted) {
      reject(new DOMException("aborted", "AbortError"));
      return;
    }
    params.signal?.addEventListener("abort", onAbort, { once: true });
    worker.addEventListener("message", onMessage);
    worker.postMessage({
      type: "smt_proof",
      requestId,
      serialHex: params.serialHex,
    });
  });
}

/** Exported for the Worker (which calls it after `smtCreateProof`) and for
 *  unit tests that want to check the hex→decimal padding logic without
 *  instantiating the wasm engine. */
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
  // Pad to depth with "0"; truncate if the engine returned more than depth.
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

/** Convert a hex string to a decimal string. Accepts both `0x`-prefixed and
 *  bare forms — the wasm engine emits bare hex (Go `big.Int.Text(16)`) while
 *  REST-era fixtures used `0x`-prefixed strings. Pure-decimal inputs are
 *  NOT supported on this path: every field on `SmtProofResponse` is a hex
 *  serialisation of a big integer. */
function hexToDecimal(val: string): string {
  const stripped =
    val.startsWith("0x") || val.startsWith("0X") ? val.slice(2) : val;
  if (stripped === "") return "0";
  return BigInt("0x" + stripped).toString(10);
}
