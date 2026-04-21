// Main-thread sign-phase pipeline. Runs the network/IO portion (challenge →
// sign → smt → build) on the sign route (/) and returns a `ProveInput` that
// the caller hands off (via sessionStorage) to the proving route (/prove),
// where a fresh, cross-origin-isolated Worker owns the CPU/wasm proving
// steps. Submission is owned by the Review screen via prove-main.ts.

import { cert_modulus_bits, cert_serial_hex } from "./wasm/spartan2_wasm.js";

import { base64ToBytes, challengeBytesToTbs } from "./bytes";
import { fetchPkcs11Info, signTbs } from "./hipki-client";
import { buildInputs, ensureWasm } from "./inputs";
import type { CircuitKind } from "./manifest";
import type { Pin } from "./pin";
import { dispatch } from "./store";
import { fetchSmtProof, type SmtIssuer } from "./smt-client";
import { result, steps, type Step } from "./ui";
import type { Challenge } from "./verifier-client";
import type { ProveInput } from "./worker";

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
 *  smt → build) and return the built `ProveInput`. Per-step progress flows
 *  through `progress.ts`. The SMT Worker is only used for the smt_proof RPC;
 *  the heavy prove Worker lives on /prove. Caller owns Worker lifecycle. */
export async function runSignPhasePipeline(
  worker: Worker,
  ctx: ProvingContext,
): Promise<ProveInput> {
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

  // The HiPKI popup is user-driven and can't be cancelled mid-flight; we let
  // it complete naturally and bail on the next abort check. `/sign` returns
  // the cert whose private key produced the signature — MOICA tokens carry
  // multiple user certs, and `/pkcs11info` may hand back a different one.
  // Key the proving inputs off this cert, not the one cached during setup.
  const { signatureB64: userSignatureB64, userCertDer: signedUserCertDer } =
    await stage("sign", async () => {
      const sig = await signTbs({
        tbs: challenge.challenge_bytes,
        pin: ctx.pin.consume(),
        slotDescription: ctx.card.slotDescription,
      });
      if (sig.ret_code !== 0 || sig.last_error !== 0) {
        throw new Error(
          `HiPKI sign failed: ret_code=${sig.ret_code} last_error=${sig.last_error}`,
        );
      }
      if (!sig.certb64) {
        throw new Error("HiPKI sign response missing certb64 (needed to proof-match the signing key)");
      }
      return {
        signatureB64: sig.signature,
        userCertDer: base64ToBytes(sig.certb64),
      };
    });
  checkAborted(signal);

  await ensureWasm();
  const signedSerialHex = cert_serial_hex(signedUserCertDer);
  const signedNullifier = `zkid-${signedSerialHex}`;

  const smtInputs = await stage(
    "smt",
    async () => {
      const t0 = performance.now();
      const inputs = await fetchSmtProof(worker, {
        issuer: ctx.card.issuer,
        serialHex: signedSerialHex,
        signal,
      });
      return { inputs, ms: Math.round(performance.now() - t0) };
    },
    ({ ms }) => `MerkleProof in ${ms}ms`,
  ).then((x) => x.inputs);
  checkAborted(signal);

  const { certJson, deviceJson } = await stage("build", () =>
    buildInputs({
      card: {
        ...ctx.card,
        userCertDer: signedUserCertDer,
        serialHex: signedSerialHex,
      },
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
    nullifier: signedNullifier,
  };
  return input;
}

/** Route to rs2048 / rs4096 by the issuer cert's actual modulus width, not
 *  by guessing from the issuer DN — MOICA-G3 issuer DNs don't always carry
 *  "G3" or "4096", and picking rs2048 for a 4096-bit key would truncate the
 *  modulus into 17*121=2057 bits and fail the cert-chain RSA verify. */
async function deriveIssuerFromCert(
  issuerCertDer: Uint8Array,
): Promise<{ issuer: SmtIssuer; kIssuer: 17 | 34; certKind: CircuitKind }> {
  await ensureWasm();
  const bits = cert_modulus_bits(issuerCertDer);
  return bits > 2048
    ? { issuer: "g3", kIssuer: 34, certKind: "cert_chain_rs4096" }
    : { issuer: "g2", kIssuer: 17, certKind: "cert_chain_rs2048" };
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

  const issuerCertDer = base64ToBytes(caEntry.certb64);
  const { issuer, kIssuer, certKind } = await deriveIssuerFromCert(issuerCertDer);

  return {
    card: {
      userCertDer: base64ToBytes(userEntry.certb64),
      issuerCertDer,
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
