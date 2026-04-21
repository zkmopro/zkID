// Main-thread proving orchestrator. Lives between the setup screen (which
// gathers HiPKI cert + PIN) and the Worker (which runs CPU/wasm-bound steps).
//
// No fixture path, no default-JSON fallback. If any step throws, the step
// row + result banner show the error and the FSM transitions to `error`.

import { base64ToBytes, bytesToHex, hexToBytes } from "./bytes";
import { fetchPkcs11Info, signTbs } from "./hipki-client";
import { buildInputs } from "./inputs";
import type { CircuitKind } from "./manifest";
import type { Pin } from "./pin";
import { dispatch } from "./store";
import { fetchSmtProof, type SmtIssuer } from "./smt-client";
import { result, steps, type Step } from "./ui";
import { createChallenge } from "./verifier-client";
import type { RunInput, WorkerInMsg } from "./worker";

export interface CardContext {
  userCertDer: Uint8Array;
  issuerCertDer: Uint8Array;
  serialHex: string;
  kIssuer: 17 | 34;
  issuer: SmtIssuer;
  certKind: CircuitKind;
  /** Reader the cert was read from. Threaded through to /sign so the
   *  proving signature uses the same physical card. */
  slotDescription?: string;
}

/** What `buildCardContext` returns — the pipeline context plus the humanised
 *  fields the setup screen needs for the panel display. Folding both into one
 *  call keeps the HiPKI round-trip count at one. */
export interface DetectedCard {
  card: CardContext;
  subjectDN?: string;
  cardSN?: string;
}

export interface ProvingContext {
  card: CardContext;
  pin: Pin;
  nullifier: string;
  /** Aborts in-flight network calls when the user navigates away from the
   *  proving phase. The CPU/wasm work in the Worker is cancelled separately
   *  by the caller (Worker terminate or `cancel` message). */
  signal?: AbortSignal;
}

/** Sentinel thrown when `runProvingPipeline` notices its `AbortSignal`
 *  has fired. Callers swallow it without emitting a duplicate FSM error. */
export class PipelineAborted extends Error {
  constructor() {
    super("pipeline aborted");
    this.name = "PipelineAborted";
  }
}

function setStep(step: Step, label?: string): void {
  steps[step].set({ status: "in_progress", label });
}

function stepDone(step: Step, label?: string): void {
  steps[step].set({ status: "done", label });
}

function fail(where: string, err: unknown): never {
  const message = err instanceof Error ? err.message : String(err);
  result.set({ kind: "error", message: `${where}: ${message}` });
  dispatch({ type: "pipeline_error", where, message });
  throw err;
}

function isAbortError(err: unknown): boolean {
  if (err instanceof PipelineAborted) return true;
  return err instanceof DOMException && err.name === "AbortError";
}

function checkAborted(signal: AbortSignal | undefined): void {
  if (signal?.aborted) throw new PipelineAborted();
}

/** Step runner: set spinner → run body → mark done → surface errors through
 *  `fail`. Returning the body's value lets callers chain without the
 *  `let x: T; try { x = ... }; x!.foo` dance. AbortError / PipelineAborted
 *  bypass `fail` so cancellation doesn't paint a fake error in the UI. */
async function stage<T>(
  step: Step,
  run: () => Promise<T>,
  labelFrom?: (value: T) => string,
): Promise<T> {
  setStep(step);
  try {
    const value = await run();
    stepDone(step, labelFrom?.(value));
    return value;
  } catch (err) {
    if (isAbortError(err)) throw new PipelineAborted();
    fail(step, err);
  }
}

export async function runProvingPipeline(
  worker: Worker,
  ctx: ProvingContext,
): Promise<void> {
  const { signal } = ctx;

  const challenge = await stage(
    "challenge",
    () => createChallenge({ signal }),
    (ch) => `id=${ch.id}`,
  );
  checkAborted(signal);
  const tbs = hexToBytes(challenge.bytes);

  // The HiPKI popup is user-driven and can't be cancelled mid-flight.
  // We let the popup complete naturally and bail on the next abort check.
  const userSignatureB64 = await stage("sign", async () => {
    const sig = await signTbs({
      tbs: bytesToHex(tbs),
      pin: ctx.pin.consume(),
      slotDescription: ctx.card.slotDescription,
    });
    if (sig.ret_code !== 0 || sig.last_error !== 0) {
      throw new Error(
        `HiPKI sign failed: ret_code=${sig.ret_code} last_error=${sig.last_error}`,
      );
    }
    return sig.signature;
  });
  checkAborted(signal);

  const smtInputs = await stage("smt", () =>
    fetchSmtProof({
      issuer: ctx.card.issuer,
      serialHex: ctx.card.serialHex,
      signal,
    }),
  );
  checkAborted(signal);

  const { certJson, deviceJson } = await stage("build", () =>
    buildInputs({
      card: ctx.card,
      userSignatureB64,
      tbs,
      smtInputs,
    }),
  );
  checkAborted(signal);

  // Hand off to Worker. Its Progress events drive the remaining steps
  // (download/load/witness/prove/submit) via `progress.ts::applyProgress`.
  // Worker cancellation is handled by the caller — terminating the worker
  // or sending `{type: "cancel"}` is what stops the CPU/wasm work.
  const input: RunInput = {
    certJson,
    deviceJson,
    certKind: ctx.card.certKind,
    challengeId: challenge.id,
    nullifier: ctx.nullifier,
  };
  const msg: WorkerInMsg = { type: "run", input };
  await waitForWorkerTerminal(worker, signal, () => worker.postMessage(msg));
}

/** Resolves on the next `done` or `error` Progress event the Worker posts.
 *  If the AbortSignal fires first, throws `PipelineAborted` so the caller
 *  swallows it without painting a duplicate FSM error. */
function waitForWorkerTerminal(
  worker: Worker,
  signal: AbortSignal | undefined,
  kickoff: () => void,
): Promise<void> {
  return new Promise((resolve, reject) => {
    const onMessage = (ev: MessageEvent) => {
      const p = ev.data as { step: string };
      if (p.step === "done" || p.step === "error") {
        cleanup();
        resolve();
      }
    };
    const onAbort = () => {
      cleanup();
      reject(new PipelineAborted());
    };
    function cleanup(): void {
      worker.removeEventListener("message", onMessage);
      signal?.removeEventListener("abort", onAbort);
    }
    if (signal?.aborted) {
      reject(new PipelineAborted());
      return;
    }
    worker.addEventListener("message", onMessage);
    signal?.addEventListener("abort", onAbort);
    kickoff();
  });
}

/** Issuer DN → `g2` / `g3`. MOICA-G2 issues RSA-2048 certs, MOICA-G3 RSA-4096. */
function deriveIssuer(issuerDn: string | undefined): SmtIssuer {
  if (!issuerDn) return "g2";
  return /g3|4096|root\s*ca\s*g3/i.test(issuerDn) ? "g3" : "g2";
}

/** Fetch + parse the HiPKI pkcs11info response into a `CardContext` plus the
 *  humanised fields the setup panel shows. When `slotDescription` is
 *  supplied we require the response to contain that exact slot — anything
 *  else (silent scoping failure on an older LocalSignServer, race with a
 *  card pull) throws so the user doesn't end up signing with a different
 *  physical reader than the one they picked. */
export async function buildCardContext(
  slotDescription?: string,
): Promise<DetectedCard> {
  const info = await fetchPkcs11Info(slotDescription);
  const slot = slotDescription
    ? info.slots.find((s) => s.slotDescription === slotDescription)
    : info.slots.find((s) => s.token) ?? info.slots[0];
  if (slotDescription && !slot) {
    throw new Error(
      `HiPKI: requested reader '${slotDescription}' not in response`,
    );
  }
  const token = slot?.token;
  if (!token) throw new Error("HiPKI: no token in /pkcs11info response");
  const userEntry = token.certs.find((c) => c.label !== "CA Cert");
  const caEntry = token.certs.find((c) => c.label === "CA Cert");
  if (!userEntry) throw new Error("HiPKI: no user cert in token");
  if (!caEntry) throw new Error("HiPKI: no 'CA Cert' entry in token");

  const issuer = deriveIssuer(userEntry.issuerDN);
  const kIssuer: 17 | 34 = issuer === "g3" ? 34 : 17;
  const certKind: CircuitKind =
    issuer === "g3" ? "cert_chain_rs4096" : "cert_chain_rs2048";

  return {
    card: {
      userCertDer: base64ToBytes(userEntry.certb64),
      issuerCertDer: base64ToBytes(caEntry.certb64),
      serialHex: deriveSerialHex(userEntry.sn, token.serialNumber),
      kIssuer,
      issuer,
      certKind,
      slotDescription: slotDescription ?? slot?.slotDescription,
    },
    subjectDN: userEntry.subjectDN,
    cardSN: token.serialNumber,
  };
}

/** Prefer the cert's own serial number field; fall back to the token serial. */
function deriveSerialHex(
  entrySn: string | undefined,
  tokenSerial: string | undefined,
): string {
  const candidate = entrySn ?? tokenSerial;
  if (!candidate) {
    throw new Error("HiPKI: no serial number on user cert or token");
  }
  return candidate.startsWith("0x") || candidate.startsWith("0X")
    ? candidate
    : `0x${candidate}`;
}
