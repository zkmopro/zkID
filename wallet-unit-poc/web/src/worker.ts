// Dedicated Worker: runs the cert-chain + device-sig prove pipeline off the
// main thread. See src/main.ts for the message contract. The Worker posts
// Progress events describing each pipeline step; the main thread translates
// those into UI atom updates via src/ui.ts.

import init, {
  CircuitKind,
  initThreadPool,
  load_pk,
  prove,
} from "./wasm/spartan2_wasm.js";

import { ensureAsset } from "./asset-download";
import { assetStore } from "./asset-store";
import {
  CIRCUITS,
  hydrateManifest,
  type CircuitKind as Kind,
} from "./manifest";
import { createChallenge, submitLinkVerify } from "./verifier-client";
import { calculateWitness } from "./witness";

// Worker message contract -------------------------------------------------

export interface RunInput {
  cert: Record<string, unknown>;
  device: Record<string, unknown>;
  nullifier: string;
}

export type WorkerInMsg =
  | { type: "run"; input: RunInput }
  | { type: "cancel" };

export type Progress =
  | { step: "preflight"; status: "in_progress" | "done" }
  | { step: "challenge"; status: "in_progress" | "done"; challengeId?: string }
  | {
      step: "download";
      status: "in_progress" | "done";
      asset?: string;
      bytesDone?: number;
      bytesTotal?: number;
    }
  | { step: "load"; status: "in_progress" | "done"; kind?: Kind }
  | { step: "witness"; status: "in_progress" | "done"; kind?: Kind }
  | {
      step: "prove";
      status: "in_progress" | "done";
      kind?: Kind;
      phase?: "prep" | "prove";
    }
  | { step: "submit"; status: "in_progress" | "done" }
  | { step: "done"; durationMs: number; verified: boolean }
  | { step: "error"; where: string; message: string; retryable: boolean };

// Kind → wasm CircuitKind enum. Matches CircuitKind in wasm/spartan2_wasm.d.ts.
const KIND_ENUM: Record<Kind, CircuitKind> = {
  cert_chain_rs2048: CircuitKind.CertChainRs2048,
  cert_chain_rs4096: CircuitKind.CertChainRs4096,
  device_sig_rs2048: CircuitKind.DeviceSigRs2048,
};

// Kind → human label used in progress events.
const KIND_LABEL: Record<Kind, string> = {
  cert_chain_rs2048: "cert_chain_rs2048",
  cert_chain_rs4096: "cert_chain_rs4096",
  device_sig_rs2048: "device_sig_rs2048",
};

let cancelled = false;
let running = false;

// The project's tsconfig lib list is ES2023 + DOM (no WebWorker lib, so adding
// it would fight DOM's global `self`). Cast once to a narrow shape describing
// the three Worker APIs we actually use.
interface WorkerGlobal {
  onmessage: ((this: WorkerGlobal, ev: MessageEvent<WorkerInMsg>) => unknown) | null;
  postMessage(msg: Progress): void;
  navigator: { hardwareConcurrency?: number };
  location: { search?: string };
}

const workerSelf: WorkerGlobal = self as unknown as WorkerGlobal;

workerSelf.onmessage = (ev: MessageEvent<WorkerInMsg>) => {
  const data = ev.data;
  if (!data || typeof data !== "object") return;
  if (data.type === "cancel") {
    cancelled = true;
    return;
  }
  if (data.type === "run") {
    if (running) return;
    running = true;
    cancelled = false;
    runPipeline(data.input).finally(() => {
      running = false;
    });
  }
};

function post(p: Progress): void {
  workerSelf.postMessage(p);
}

function detectCertKind(cert: unknown): Kind {
  if (
    cert &&
    typeof cert === "object" &&
    Array.isArray((cert as { issuerN?: unknown }).issuerN) &&
    (cert as { issuerN: unknown[] }).issuerN.length === 34
  ) {
    return "cert_chain_rs4096";
  }
  return "cert_chain_rs2048";
}

function clampThreads(): number {
  const override = parseThreadOverride();
  if (override != null) return override;
  const hc = (workerSelf.navigator as Navigator | undefined)?.hardwareConcurrency;
  const raw = typeof hc === "number" && hc > 0 ? hc - 1 : 2;
  return Math.max(2, Math.min(8, raw));
}

function parseThreadOverride(): number | null {
  try {
    const loc = workerSelf.location;
    if (!loc || !loc.search) return null;
    const params = new URLSearchParams(loc.search);
    const t = params.get("threads");
    if (!t) return null;
    const n = Number.parseInt(t, 10);
    if (!Number.isFinite(n) || n < 1) return null;
    return Math.max(1, Math.min(32, n));
  } catch {
    return null;
  }
}

function errorMessage(err: unknown): string {
  if (err instanceof Error) return err.message;
  try {
    return String(err);
  } catch {
    return "unknown error";
  }
}

function postError(where: string, err: unknown): void {
  post({
    step: "error",
    where,
    message: errorMessage(err),
    retryable: true,
  });
}

async function runPipeline(inputs: RunInput): Promise<void> {
  const t0 = performance.now();
  try {
    // 0. Preflight: bring up wasm module + thread pool + manifest.
    post({ step: "preflight", status: "in_progress" });
    await init();
    await initThreadPool(clampThreads());
    await hydrateManifest();
    post({ step: "preflight", status: "done" });
    if (cancelled) return;

    // 1. Fetch a challenge up front. device-sig TBS is assumed to embed it.
    post({ step: "challenge", status: "in_progress" });
    const challenge = await createChallenge();
    post({ step: "challenge", status: "done", challengeId: challenge.id });
    if (cancelled) return;

    const certKind = detectCertKind(inputs.cert);
    const kinds: Kind[] = [certKind, "device_sig_rs2048"];

    // 2. Download PK + witness-wasm for each circuit.
    post({ step: "download", status: "in_progress" });
    for (const kind of kinds) {
      const m = CIRCUITS[kind];
      await ensureAsset(m.pkUrl, `${kind}_pk`, m.expected.pk, (p) =>
        post({
          step: "download",
          status: "in_progress",
          asset: `${KIND_LABEL[kind]} pk`,
          bytesDone: p.bytesDone,
          bytesTotal: p.bytesTotal,
        }),
      );
      if (cancelled) return;
      await ensureAsset(
        m.witnessWasmUrl,
        `${kind}_wgen`,
        m.expected.witnessWasm,
        (p) =>
          post({
            step: "download",
            status: "in_progress",
            asset: `${KIND_LABEL[kind]} witness-wasm`,
            bytesDone: p.bytesDone,
            bytesTotal: p.bytesTotal,
          }),
      );
      if (cancelled) return;
    }
    post({ step: "download", status: "done" });

    // 3. Load PKs into the wasm crate.
    post({ step: "load", status: "in_progress" });
    for (const kind of kinds) {
      const pk = await assetStore.get(`${kind}_pk`);
      if (!pk) throw new Error(`missing cached PK for ${kind}`);
      load_pk(KIND_ENUM[kind], pk);
      post({ step: "load", status: "in_progress", kind });
      if (cancelled) return;
    }
    post({ step: "load", status: "done" });

    // 4. Witness + prove, per circuit.
    post({ step: "witness", status: "in_progress" });
    const certWgen = await assetStore.get(`${certKind}_wgen`);
    if (!certWgen) throw new Error(`missing witness-wasm for ${certKind}`);
    const certWtns = await calculateWitness(certKind, inputs.cert, certWgen);
    post({ step: "witness", status: "in_progress", kind: certKind });
    if (cancelled) return;

    const deviceWgen = await assetStore.get("device_sig_rs2048_wgen");
    if (!deviceWgen) throw new Error("missing witness-wasm for device_sig_rs2048");
    const deviceWtns = await calculateWitness(
      "device_sig_rs2048",
      inputs.device,
      deviceWgen,
    );
    post({ step: "witness", status: "done", kind: "device_sig_rs2048" });
    if (cancelled) return;

    post({ step: "prove", status: "in_progress", kind: certKind, phase: "prep" });
    const certProofOut = prove(KIND_ENUM[certKind], certWtns) as {
      proof: ArrayLike<number>;
    };
    post({ step: "prove", status: "in_progress", kind: certKind, phase: "prove" });
    if (cancelled) return;

    post({
      step: "prove",
      status: "in_progress",
      kind: "device_sig_rs2048",
      phase: "prep",
    });
    const deviceProofOut = prove(
      KIND_ENUM["device_sig_rs2048"],
      deviceWtns,
    ) as { proof: ArrayLike<number> };
    post({ step: "prove", status: "done", kind: "device_sig_rs2048", phase: "prove" });
    if (cancelled) return;

    // 5. Submit both proofs to go-zkid-verifier.
    post({ step: "submit", status: "in_progress" });
    const verifyRes = await submitLinkVerify({
      challengeId: challenge.id,
      certChainType: certKind === "cert_chain_rs4096" ? "rs4096" : "rs2048",
      certChainProofBytes: new Uint8Array(certProofOut.proof),
      deviceSigProofBytes: new Uint8Array(deviceProofOut.proof),
      nullifier: inputs.nullifier,
    });
    post({ step: "submit", status: "done" });

    post({
      step: "done",
      durationMs: performance.now() - t0,
      verified: verifyRes.verified,
    });
  } catch (err) {
    postError("pipeline", err);
  }
}
