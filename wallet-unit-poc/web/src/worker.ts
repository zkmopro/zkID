// Dedicated Worker with two phases, driven by separate messages.
//
//   warmup — download proving keys + witness wasm, init the spartan2_wasm
//            module + rayon pool, load PKs into per-kind Mutex slots.
//            Witness-wasm bytes are cached on the Worker so the prove
//            phase skips another OPFS round-trip.
//   prove  — witness + prove for both circuits using the loaded PKs.
//            Returns proof bytes back to the main thread, which owns
//            submission so the user can gate it with an explicit click.

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
import { calculateWitness } from "./witness";

// Worker message contract -------------------------------------------------

export interface ProveInput {
  certJson: string;
  deviceJson: string;
  certKind: Kind;
  challengeId: string;
  nullifier: string;
}

export type WorkerInMsg =
  | { type: "warmup" }
  | { type: "prove"; input: ProveInput }
  | { type: "cancel" };

export type Progress =
  // Warmup events feed the setup screen's Assets panel.
  | {
      step: "warmup";
      status: "in_progress" | "done";
      phase?: "init" | "threads" | "manifest" | "download" | "load";
      asset?: string;
      bytesDone?: number;
      bytesTotal?: number;
      kind?: Kind;
    }
  | { step: "warmup_done" }
  // Proving events drive the proving-screen step list.
  | { step: "witness"; status: "in_progress" | "done"; kind?: Kind }
  | {
      step: "prove";
      status: "in_progress" | "done";
      kind?: Kind;
      phase?: "prep" | "prove";
    }
  | {
      step: "proving_complete";
      certProofBytes: Uint8Array;
      deviceProofBytes: Uint8Array;
      certKind: Kind;
      challengeId: string;
      nullifier: string;
      provingMs: number;
    }
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
let warming = false;
let proving = false;
let warmed = false;

// witness-wasm kept in-memory after warmup (skips OPFS during prove).
const witnessCache: Partial<Record<Kind, Uint8Array>> = {};

// tsconfig lib is ES2023 + DOM (no WebWorker lib); cast to a narrow shape
// covering the APIs we actually use.
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
  if (data.type === "warmup") {
    if (warming || proving) return;
    warming = true;
    cancelled = false;
    runWarmup().finally(() => {
      warming = false;
    });
    return;
  }
  if (data.type === "prove") {
    if (warming || proving) return;
    if (!warmed) {
      postError("prove", new Error("Worker not warmed; run warmup first"));
      return;
    }
    proving = true;
    cancelled = false;
    runProve(data.input).finally(() => {
      proving = false;
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

async function runWarmup(): Promise<void> {
  try {
    post({ step: "warmup", status: "in_progress", phase: "init" });
    await init();
    if (cancelled) return;

    const threads = clampThreads();
    post({ step: "warmup", status: "in_progress", phase: "threads" });
    if (threads > 1) await initThreadPool(threads);
    if (cancelled) return;

    post({ step: "warmup", status: "in_progress", phase: "manifest" });
    await hydrateManifest();
    if (cancelled) return;

    // Download all three circuits' PK + witness-wasm. The cert-chain kind
    // (rs2048 vs rs4096) is only known after the card is read; keeping
    // both pre-loaded means Start proving has no extra wait.
    const kinds: Kind[] = [
      "cert_chain_rs2048",
      "cert_chain_rs4096",
      "device_sig_rs2048",
    ];
    for (const kind of kinds) {
      const m = CIRCUITS[kind];
      await ensureAsset(m.pkUrl, `${kind}_pk`, m.expected.pk, (p) =>
        post({
          step: "warmup",
          status: "in_progress",
          phase: "download",
          asset: `${KIND_LABEL[kind]} pk`,
          bytesDone: p.bytesDone,
          bytesTotal: p.bytesTotal,
          kind,
        }),
      );
      if (cancelled) return;
      await ensureAsset(
        m.witnessWasmUrl,
        `${kind}_wgen`,
        m.expected.witnessWasm,
        (p) =>
          post({
            step: "warmup",
            status: "in_progress",
            phase: "download",
            asset: `${KIND_LABEL[kind]} witness-wasm`,
            bytesDone: p.bytesDone,
            bytesTotal: p.bytesTotal,
            kind,
          }),
      );
      if (cancelled) return;
    }

    // Load PKs into the wasm crate and cache witness-wasm in Worker memory.
    for (const kind of kinds) {
      post({ step: "warmup", status: "in_progress", phase: "load", kind });
      const pk = await assetStore.get(`${kind}_pk`);
      if (!pk) throw new Error(`missing cached PK for ${kind}`);
      load_pk(KIND_ENUM[kind], pk);
      const wgen = await assetStore.get(`${kind}_wgen`);
      if (!wgen) throw new Error(`missing cached witness-wasm for ${kind}`);
      witnessCache[kind] = wgen;
      if (cancelled) return;
    }

    warmed = true;
    post({ step: "warmup", status: "done" });
    post({ step: "warmup_done" });
  } catch (err) {
    postError("warmup", err);
  }
}

async function runProve(inputs: ProveInput): Promise<void> {
  const t0 = performance.now();
  try {
    const { certKind } = inputs;

    const certWgen = witnessCache[certKind];
    if (!certWgen) throw new Error(`warmup did not cache witness-wasm for ${certKind}`);
    const deviceWgen = witnessCache["device_sig_rs2048"];
    if (!deviceWgen)
      throw new Error("warmup did not cache witness-wasm for device_sig_rs2048");

    post({ step: "witness", status: "in_progress", kind: certKind });
    const certWtns = await calculateWitness(certKind, inputs.certJson, certWgen);
    if (cancelled) return;
    post({ step: "witness", status: "done", kind: certKind });

    post({ step: "prove", status: "in_progress", kind: certKind, phase: "prep" });
    const certProofOut = prove(KIND_ENUM[certKind], certWtns) as {
      proof: ArrayLike<number>;
    };
    post({ step: "prove", status: "done", kind: certKind, phase: "prove" });
    if (cancelled) return;

    post({
      step: "witness",
      status: "in_progress",
      kind: "device_sig_rs2048",
    });
    const deviceWtns = await calculateWitness(
      "device_sig_rs2048",
      inputs.deviceJson,
      deviceWgen,
    );
    if (cancelled) return;
    post({ step: "witness", status: "done", kind: "device_sig_rs2048" });

    post({
      step: "prove",
      status: "in_progress",
      kind: "device_sig_rs2048",
      phase: "prep",
    });
    const deviceProofOut = prove(KIND_ENUM["device_sig_rs2048"], deviceWtns) as {
      proof: ArrayLike<number>;
    };
    post({
      step: "prove",
      status: "done",
      kind: "device_sig_rs2048",
      phase: "prove",
    });
    if (cancelled) return;

    const certProofBytes = new Uint8Array(certProofOut.proof);
    const deviceProofBytes = new Uint8Array(deviceProofOut.proof);
    post({
      step: "proving_complete",
      certProofBytes,
      deviceProofBytes,
      certKind,
      challengeId: inputs.challengeId,
      nullifier: inputs.nullifier,
      provingMs: performance.now() - t0,
    });
  } catch (err) {
    postError("prove", err);
  }
}
