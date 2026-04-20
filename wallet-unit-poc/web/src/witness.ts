// Browser witness calculator for the three zkID circuits.
//
// Circom's witness_calculator.js ships as CJS with an implicit global assignment
// (`a = flatArray(input)`) that explodes under ESM strict mode. Fetch it as
// text, patch to a local binding, wrap as ESM via a blob URL, and import.
// The shared CJS file is identical across circomkit outputs for the same circom
// version, so `copy-assets.sh` copies it once into `public/assets/`.
//
// This module does NOT manage the .wasm download — callers feed in `Uint8Array`
// bytes (obtained via `asset-download::ensureAsset`) so the shim integrates
// with the OPFS/IDB cache rather than re-fetching via `fetch()`.

import type { CircuitKind } from "./manifest";

type CircuitInput = Record<string, unknown>;

interface WitnessCalculatorInstance {
  calculateWitness(input: CircuitInput, sanityCheck?: boolean): Promise<bigint[]>;
  calculateWTNSBin(input: CircuitInput, sanityCheck?: boolean): Promise<Uint8Array>;
}

type WitnessCalculatorBuilder = (
  wasmBytes: ArrayBuffer,
  options?: { sanityCheck?: boolean },
) => Promise<WitnessCalculatorInstance>;

let cachedBuilder: WitnessCalculatorBuilder | null = null;

async function loadBuilder(
  builderUrl: string,
): Promise<WitnessCalculatorBuilder> {
  if (cachedBuilder) return cachedBuilder;

  const response = await fetch(builderUrl);
  if (!response.ok) {
    throw new Error(
      `fetch witness_calculator.js from ${builderUrl}: ${response.status} ${response.statusText}`,
    );
  }
  const rawSource = await response.text();

  // The latent circom bug: undeclared `a = flatArray(input)` inside
  // `qualify_input`. Classic CJS creates a global silently; ESM strict mode
  // throws `a is not defined`. Patch to `let a = ...`.
  const source = rawSource.replace(
    /(\n\s*)a\s*=\s*flatArray\(input\);/,
    "$1let a = flatArray(input);",
  );

  const wrapped = `
    const module = { exports: undefined };
    ${source}
    export default module.exports;
  `;

  const blob = new Blob([wrapped], { type: "text/javascript" });
  const blobUrl = URL.createObjectURL(blob);
  try {
    const mod = (await import(/* @vite-ignore */ blobUrl)) as {
      default: WitnessCalculatorBuilder;
    };
    cachedBuilder = mod.default;
    return cachedBuilder;
  } finally {
    URL.revokeObjectURL(blobUrl);
  }
}

const calcByKind = new Map<CircuitKind, WitnessCalculatorInstance>();

/** Compute `.wtns` binary for a circuit input, using pre-fetched witness-gen
 *  WASM bytes. The calculator instance per circuit is cached inside the worker
 *  so repeated proofs don't re-instantiate. */
export async function calculateWitness(
  kind: CircuitKind,
  input: CircuitInput,
  witnessWasmBytes: Uint8Array,
  builderUrl = "/assets/witness_calculator.js",
): Promise<Uint8Array> {
  let calc = calcByKind.get(kind);
  if (!calc) {
    const builder = await loadBuilder(builderUrl);
    // Detach to a fresh ArrayBuffer (builder wants ArrayBuffer, not Uint8Array).
    const ab = witnessWasmBytes.slice().buffer;
    calc = await builder(ab, { sanityCheck: true });
    calcByKind.set(kind, calc);
  }
  return calc.calculateWTNSBin(input, true);
}

/** Exposed for tests / debugging — clears the per-circuit calculator cache. */
export function _resetWitnessCache(): void {
  cachedBuilder = null;
  calcByKind.clear();
}
