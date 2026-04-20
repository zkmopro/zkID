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

/** Step runner: set spinner → run body → mark done → surface errors through
 *  `fail`. Returning the body's value lets callers chain without the
 *  `let x: T; try { x = ... }; x!.foo` dance. */
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
    fail(step, err);
  }
}

export async function runProvingPipeline(
  worker: Worker,
  ctx: ProvingContext,
): Promise<void> {
  const challenge = await stage(
    "challenge",
    () => createChallenge(),
    (ch) => `id=${ch.id}`,
  );
  const tbs = hexToBytes(challenge.bytes);

  const userSignatureB64 = await stage("sign", async () => {
    const sig = await signTbs({
      tbs: bytesToHex(tbs),
      pin: ctx.pin.consume(),
    });
    if (sig.ret_code !== 0 || sig.last_error !== 0) {
      throw new Error(
        `HiPKI sign failed: ret_code=${sig.ret_code} last_error=${sig.last_error}`,
      );
    }
    return sig.signature;
  });

  const smtInputs = await stage("smt", () =>
    fetchSmtProof({
      issuer: ctx.card.issuer,
      serialHex: ctx.card.serialHex,
    }),
  );

  const { certJson, deviceJson } = await stage("build", () =>
    buildInputs({
      card: ctx.card,
      userSignatureB64,
      tbs,
      smtInputs,
    }),
  );

  // Hand off to Worker. Its Progress events drive the remaining steps
  // (download/load/witness/prove/submit) via `progress.ts::applyProgress`.
  const input: RunInput = {
    certJson,
    deviceJson,
    certKind: ctx.card.certKind,
    challengeId: challenge.id,
    nullifier: ctx.nullifier,
  };
  const msg: WorkerInMsg = { type: "run", input };
  await waitForWorkerTerminal(worker, () => worker.postMessage(msg));
}

/** Resolves on the next `done` or `error` Progress event the Worker posts. */
function waitForWorkerTerminal(
  worker: Worker,
  kickoff: () => void,
): Promise<void> {
  return new Promise((resolve) => {
    const onMessage = (ev: MessageEvent) => {
      const p = ev.data as { step: string };
      if (p.step === "done" || p.step === "error") {
        worker.removeEventListener("message", onMessage);
        resolve();
      }
    };
    worker.addEventListener("message", onMessage);
    kickoff();
  });
}

/** Issuer DN → `g2` / `g3`. MOICA-G2 issues RSA-2048 certs, MOICA-G3 RSA-4096. */
export function deriveIssuer(issuerDn: string | undefined): SmtIssuer {
  if (!issuerDn) return "g2";
  return /g3|4096|root\s*ca\s*g3/i.test(issuerDn) ? "g3" : "g2";
}

/** Fetch + parse the HiPKI pkcs11info response into a `CardContext` plus the
 *  humanised fields the setup panel shows. Single HiPKI round-trip. */
export async function buildCardContext(): Promise<DetectedCard> {
  const info = await fetchPkcs11Info();
  const token = info.slots[0]?.token;
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
