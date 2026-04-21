// Main-thread proving orchestrator. Lives between the setup screen and the
// Worker, running the network/IO pipeline (challenge → sign → smt → build)
// and handing the inputs off to the already-warm Worker for the CPU/wasm
// proving steps. Submission is owned by the Review screen via main.ts.

import { base64ToBytes, challengeBytesToTbs } from "./bytes";
import { fetchPkcs11Info, signTbs } from "./hipki-client";
import { buildInputs } from "./inputs";
import type { CircuitKind } from "./manifest";
import type { Pin } from "./pin";
import { dispatch } from "./store";
import { fetchSmtProof, type SmtIssuer } from "./smt-client";
import { result, steps, type Step } from "./ui";
import type { Challenge } from "./verifier-client";
import type { ProveInput, WorkerInMsg } from "./worker";

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

/** Pipeline context plus the humanised fields the setup panel displays.
 *  Folded into one return so HiPKI is hit just once. */
export interface DetectedCard {
  card: CardContext;
  subjectDN?: string;
  cardSN?: string;
}

export interface ProvingContext {
  card: CardContext;
  pin: Pin;
  nullifier: string;
  /** Pre-fetched by the Ready screen so the Start-proving click reaches
   *  window.open with user-activation still live. An awaited fetch here
   *  would consume activation and get the HiPKI popup blocked. */
  challenge: Challenge;
  /** Aborts in-flight network calls on phase exit. CPU/wasm work in the
   *  Worker is cancelled separately by the caller. */
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
 *  `fail`. AbortError / PipelineAborted bypass `fail` so cancellation doesn't
 *  paint a fake error in the UI. */
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

/** Run the main-thread portion of the proving pipeline (challenge → sign →
 *  smt → build) and hand off to the warm Worker. Returns once the `prove`
 *  message is posted; per-step progress + terminal events flow back through
 *  `progress.ts`. Caller owns Worker lifecycle. */
export async function runProvingPipeline(
  worker: Worker,
  ctx: ProvingContext,
): Promise<void> {
  const { signal, challenge } = ctx;

  // Pre-fetched by the Ready screen — paint the row as done immediately.
  // There must be NO awaited work between here and the `signTbs` call
  // below so the user-activation window from the Start-proving click is
  // still live when `window.open` fires inside the popup bridge.
  stepDone("challenge", `id=${challenge.challenge_id}`);
  // Byte-for-byte parity with the native prover: `challenge_bytes` is an
  // opaque string. HiPKI signs it as-is; the circuit consumes its UTF-8
  // bytes. Do NOT hex-decode — the server can emit odd-length strings,
  // and hex-decoding would diverge from the Rust CLI even on even-length
  // inputs.
  const tbs = challengeBytesToTbs(challenge.challenge_bytes);

  // The HiPKI popup is user-driven and can't be cancelled mid-flight; we
  // let it complete naturally and bail on the next abort check.
  const userSignatureB64 = await stage("sign", async () => {
    const sig = await signTbs({
      tbs: challenge.challenge_bytes,
      // `read()` — NOT `consume()` — because the session-locked Pin is
      // reused across "Retry proving" / "Prove again". `setup-state.ts::
      // resetSetup` calls `destroy()` on FSM reset → landing.
      pin: ctx.pin.read(),
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

  const input: ProveInput = {
    certJson,
    deviceJson,
    certKind: ctx.card.certKind,
    challengeId: challenge.challenge_id,
    nullifier: ctx.nullifier,
  };
  const msg: WorkerInMsg = { type: "prove", input };
  worker.postMessage(msg);
}

/** Issuer DN → `g2` / `g3`. MOICA-G2 issues RSA-2048 certs, MOICA-G3 RSA-4096. */
function deriveIssuer(issuerDn: string | undefined): SmtIssuer {
  if (!issuerDn) return "g2";
  return /g3|4096|root\s*ca\s*g3/i.test(issuerDn) ? "g3" : "g2";
}

/** Fetch + parse the HiPKI pkcs11info response into a `CardContext`.
 *  When `slotDescription` is supplied, require the response to contain
 *  that exact slot so a silent scoping failure can't route the signature
 *  to a different physical reader than the one the user picked. */
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
