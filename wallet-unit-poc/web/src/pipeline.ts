/**
 * zkID RS256 Proof Pipeline — Full WASM browser implementation.
 *
 * Steps:
 *   1. Load certificate input (test data)
 *   2. Generate witness (circom WASM in browser)
 *   3. Prove RS256 circuit (Spartan2 WASM)
 *   4. Verify proof (Spartan2 WASM)
 */

import { BrowserWitnessCalculator } from "./witness-calc-browser.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface StepLog {
  label: string;
  durationMs: number;
}

export interface LoadResult {
  circuitInput: Record<string, unknown>;
  inputSize: number;
  logs: StepLog[];
  totalMs: number;
}

export interface WitnessResult {
  witnessWtns: Uint8Array;
  logs: StepLog[];
  totalMs: number;
}

export interface ProveResult {
  proof: Uint8Array;
  instance: Uint8Array;
  proofSize: number;
  logs: StepLog[];
  totalMs: number;
}

export interface VerifyResult {
  valid: boolean;
  publicValues: string[];
  error?: string;
  logs: StepLog[];
  totalMs: number;
}

// ---------------------------------------------------------------------------
// Pipeline state (singleton)
// ---------------------------------------------------------------------------

// WASM module reference
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let wasmModule: any = null;

let witnessCalc: BrowserWitnessCalculator | null = null;
let rs256Pk: Uint8Array | null = null;
let rs256Vk: Uint8Array | null = null;

// State carried between steps
let currentInput: Record<string, unknown> | null = null;
let currentWitnessWtns: Uint8Array | null = null;
let currentProof: Uint8Array | null = null;
let currentInstance: Uint8Array | null = null;

// ---------------------------------------------------------------------------
// Step 0: Initialize WASM + load keys (called once on page load)
// ---------------------------------------------------------------------------

export type ProgressCallback = (message: string) => void;

export async function initWasm(
  onProgress?: ProgressCallback
): Promise<StepLog[]> {
  const logs: StepLog[] = [];

  // 1. Load WASM module
  onProgress?.("Loading WASM module...");
  let t = performance.now();
  wasmModule = await import("./wasm/openac_wasm.js");

  // Check SharedArrayBuffer availability (required for multi-threaded WASM)
  const hasSAB = typeof SharedArrayBuffer !== "undefined";
  console.log(`[init] SharedArrayBuffer available: ${hasSAB}`);
  console.log(`[init] crossOriginIsolated: ${crossOriginIsolated}`);

  // Use async init — wasm-bindgen-rayon needs this for SharedArrayBuffer memory
  onProgress?.("Initializing WASM...");
  try {
    await wasmModule.default("/openac_wasm_bg.wasm");
  } catch (e) {
    console.error("[init] WASM default() failed:", e);
    throw e;
  }
  logs.push({ label: "Load WASM module", durationMs: performance.now() - t });

  // 2. Initialize rayon thread pool (Web Workers + SharedArrayBuffer)
  onProgress?.("Initializing thread pool...");
  t = performance.now();
  const numThreads = navigator.hardwareConcurrency || 4;
  console.log(`[init] Starting thread pool with ${numThreads} threads...`);
  try {
    await wasmModule.initThreadPool(numThreads);
  } catch (e) {
    console.error("[init] initThreadPool failed:", e);
    throw e;
  }
  logs.push({
    label: `Thread pool initialized (${numThreads} threads)`,
    durationMs: performance.now() - t,
  });

  // 3. Initialize witness calculator
  onProgress?.("Initializing witness calculator...");
  t = performance.now();
  witnessCalc = new BrowserWitnessCalculator();
  logs.push({
    label: "Init witness calculator",
    durationMs: performance.now() - t,
  });

  // 3. Generate RS256 keys (setup) in WASM
  //    Keys depend on the circuit structure and must be generated per session.
  onProgress?.("Generating RS256 keys (setup)...");
  t = performance.now();
  const setupResult = wasmModule.setup_rs256();
  const pkBytes = new Uint8Array(setupResult.pk);
  rs256Vk = new Uint8Array(setupResult.vk);
  logs.push({
    label: `Setup keys (PK: ${formatBytes(pkBytes.length)}, VK: ${formatBytes(rs256Vk.length)})`,
    durationMs: performance.now() - t,
  });

  // 4. Load proving key into WASM memory for reuse across prove calls
  onProgress?.("Loading proving key into WASM memory...");
  t = performance.now();
  wasmModule.load_rs256_pk(pkBytes);
  rs256Pk = true as unknown as Uint8Array; // sentinel — PK is stored in WASM
  logs.push({
    label: "Load PK into WASM",
    durationMs: performance.now() - t,
  });

  return logs;
}

// ---------------------------------------------------------------------------
// Step 1: Load Certificate Input
// ---------------------------------------------------------------------------

export async function loadCertificate(
  onProgress?: ProgressCallback
): Promise<LoadResult> {
  const t0 = performance.now();
  const logs: StepLog[] = [];

  onProgress?.("Loading test certificate input...");
  const t = performance.now();
  const resp = await fetch("/assets/rs256-input.json");
  if (!resp.ok) throw new Error(`Failed to fetch: ${resp.status}`);
  currentInput = await resp.json();
  const inputJson = JSON.stringify(currentInput);
  logs.push({
    label: `Certificate data loaded (${formatBytes(inputJson.length)})`,
    durationMs: performance.now() - t,
  });

  return {
    circuitInput: currentInput!,
    inputSize: inputJson.length,
    logs,
    totalMs: performance.now() - t0,
  };
}

// ---------------------------------------------------------------------------
// Step 2: Generate Witness (Circom WASM in browser)
// ---------------------------------------------------------------------------

export async function generateWitness(
  onProgress?: ProgressCallback
): Promise<WitnessResult> {
  if (!currentInput) throw new Error("Run Step 1 first");
  if (!witnessCalc) throw new Error("Witness calculator not initialized");

  const t0 = performance.now();
  const logs: StepLog[] = [];

  // Remove fields the compiled circuit doesn't accept as inputs.
  // These are either outputs (user_rsa_extracted_modulus) or were internalized
  // in the circuit refactor (serial_number_offset).
  onProgress?.("Preparing circuit input...");
  const EXCLUDED_FIELDS = new Set([
    "serial_number_offset",
    "subject_dn",
    "subject_dn_length",
    "subject_dn_offset",
    "user_rsa_extracted_modulus",
  ]);

  const cleanedInput: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(currentInput)) {
    if (!EXCLUDED_FIELDS.has(key)) {
      cleanedInput[key] = value;
    }
  }

  // Calculate witness
  onProgress?.("Calculating witness (circom WASM)...");
  const t = performance.now();
  currentWitnessWtns = await witnessCalc.calculateRs256WitnessWtns(cleanedInput);
  logs.push({
    label: `Witness generated (${formatBytes(currentWitnessWtns.length)})`,
    durationMs: performance.now() - t,
  });

  return {
    witnessWtns: currentWitnessWtns,
    logs,
    totalMs: performance.now() - t0,
  };
}

// ---------------------------------------------------------------------------
// Step 3: Prove (Spartan2 WASM)
// ---------------------------------------------------------------------------

export async function prove(
  onProgress?: ProgressCallback
): Promise<ProveResult> {
  if (!currentWitnessWtns) throw new Error("Run Step 2 first");
  if (!rs256Pk) throw new Error("Keys not loaded");
  if (!wasmModule) throw new Error("WASM not initialized");

  const t0 = performance.now();
  const logs: StepLog[] = [];

  const threads = navigator.hardwareConcurrency || 1;
  onProgress?.(`Proving RS256 circuit (${threads} threads, witness: ${formatBytes(currentWitnessWtns!.length)})...`);
  console.log(`[prove] witness size: ${currentWitnessWtns!.length}`);
  const t = performance.now();
  const result = wasmModule.prove_rs256(currentWitnessWtns);
  currentProof = new Uint8Array(result.proof);
  currentInstance = new Uint8Array(result.instance);
  logs.push({
    label: `Proof generated (${formatBytes(currentProof.length)})`,
    durationMs: performance.now() - t,
  });

  return {
    proof: currentProof,
    instance: currentInstance,
    proofSize: currentProof.length,
    logs,
    totalMs: performance.now() - t0,
  };
}

// ---------------------------------------------------------------------------
// Step 4: Verify (Spartan2 WASM)
// ---------------------------------------------------------------------------

export async function verify(
  onProgress?: ProgressCallback
): Promise<VerifyResult> {
  if (!currentProof) throw new Error("Run Step 3 first");
  if (!rs256Vk) throw new Error("Keys not loaded");
  if (!wasmModule) throw new Error("WASM not initialized");

  const t0 = performance.now();
  const logs: StepLog[] = [];

  onProgress?.("Verifying RS256 proof (Spartan2 WASM)...");
  const t = performance.now();
  const result = wasmModule.verify_rs256(currentProof, rs256Vk);
  logs.push({
    label: "Proof verified",
    durationMs: performance.now() - t,
  });

  return {
    valid: result.valid,
    publicValues: result.public_values ?? [],
    error: result.error ?? undefined,
    logs,
    totalMs: performance.now() - t0,
  };
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export function formatMs(ms: number): string {
  if (ms < 1000) return `${ms.toFixed(0)}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}
