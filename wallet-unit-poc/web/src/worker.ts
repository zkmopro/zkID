// Dedicated Worker: runs the cert-chain + device-sig prove pipeline off the
// main thread. The main thread does network + HiPKI + SMT + input-building
// and hands this Worker a pair of pre-built JSON input strings plus the
// cert-chain circuit kind. The Worker owns only the CPU/wasm-bound steps:
// preflight, download PK + witness-wasm, load PK, witness-calc, prove, and
// submit. See src/main.ts for the orchestrator that feeds it.

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
import { submitLinkVerify } from "./verifier-client";
import { calculateWitness } from "./witness";

// Worker message contract -------------------------------------------------

export interface RunInput {
  certJson: string;
  deviceJson: string;
  certKind: Kind;
  challengeId: string;
  nullifier: string;
}

export type WorkerInMsg =
  | { type: "run"; input: RunInput }
  | { type: "cancel" };

export type Progress =
  | { step: "preflight"; status: "in_progress" | "done" }
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

const KIND_ENUM: Record<Kind, CircuitKind> = {
  cert_chain_rs2048: CircuitKind.CertChainRs2048,
  cert_chain_rs4096: CircuitKind.CertChainRs4096,
  device_sig_rs2048: CircuitKind.DeviceSigRs2048,
};

const KIND_LABEL: Record<Kind, string> = {
  cert_chain_rs2048: "cert_chain_rs2048",
  cert_chain_rs4096: "cert_chain_rs4096",
  device_sig_rs2048: "device_sig_rs2048",
};

let cancelled = false;
let running = false;

// The project's tsconfig lib list is ES2023 + DOM (no WebWorker lib), so cast
// once to a narrow shape describing the APIs we actually use.
interface WorkerGlobal {
  onmessage: ((this: WorkerGlobal, ev: MessageEvent<WorkerInMsg>) => unknown) | null;
  postMessage(msg: Progress): void;
  navigator: { hardwareConcurrency?: number };
  location: { search?: string };
  crossOriginIsolated?: boolean;
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

function clampThreads(): number {
  // `wasm-bindgen-rayon` needs SharedArrayBuffer, which requires
  // `crossOriginIsolated`. The popup bridge requires COOP
  // `same-origin-allow-popups`, which disables isolation. Fall back to
  // single-threaded proving so the pipeline still works, just slower.
  if (workerSelf.crossOriginIsolated !== true) return 1;
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
    // 0. Preflight: wasm module + thread pool + manifest. When
    // `crossOriginIsolated === false` (popup-bridge mode, see vite.config.ts
    // COOP notes), we fall back to single-threaded proving — rayon needs
    // SharedArrayBuffer which the browser disables without isolation.
    post({ step: "preflight", status: "in_progress" });
    await init();
    const threads = clampThreads();
    if (threads > 1) await initThreadPool(threads);
    await hydrateManifest();
    post({ step: "preflight", status: "done" });
    if (cancelled) return;

    const { certKind } = inputs;
    const kinds: Kind[] = [certKind, "device_sig_rs2048"];

    // 1. Download PK + witness-wasm for each circuit.
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

    // 2. Load PKs into the wasm crate.
    post({ step: "load", status: "in_progress" });
    for (const kind of kinds) {
      const pk = await assetStore.get(`${kind}_pk`);
      if (!pk) throw new Error(`missing cached PK for ${kind}`);
      load_pk(KIND_ENUM[kind], pk);
      post({ step: "load", status: "in_progress", kind });
      if (cancelled) return;
    }
    post({ step: "load", status: "done" });

    // 3. Witness + prove per circuit.
    post({ step: "witness", status: "in_progress", kind: certKind });
    const certWgen = await assetStore.get(`${certKind}_wgen`);
    if (!certWgen) throw new Error(`missing witness-wasm for ${certKind}`);
    const certWtns = await calculateWitness(certKind, inputs.certJson, certWgen);
    if (cancelled) return;

    post({ step: "witness", status: "in_progress", kind: "device_sig_rs2048" });
    const deviceWgen = await assetStore.get("device_sig_rs2048_wgen");
    if (!deviceWgen) throw new Error("missing witness-wasm for device_sig_rs2048");
    const deviceWtns = await calculateWitness(
      "device_sig_rs2048",
      inputs.deviceJson,
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

    // 4. Submit both proofs to go-zkid-verifier.
    post({ step: "submit", status: "in_progress" });
    const verifyRes = await submitLinkVerify({
      challengeId: inputs.challengeId,
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
