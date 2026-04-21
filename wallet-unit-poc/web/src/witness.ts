// Browser witness calculator loader for zkID circuits.

import type { CircuitKind } from "./manifest";

/** Inputs accepted by the witness calculator. */
export type CircuitInput = Record<string, unknown> | string;

interface WitnessCalculatorInstance {
  calculateWitness(
    input: Record<string, unknown>,
    sanityCheck?: boolean,
  ): Promise<bigint[]>;
  calculateWTNSBin(
    input: Record<string, unknown>,
    sanityCheck?: boolean,
  ): Promise<Uint8Array>;
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

  // Patch undeclared `a = flatArray(input)` for ESM strict mode.
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

/** Compute `.wtns` using pre-fetched witness-generator WASM bytes. */
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
  const parsed =
    typeof input === "string"
      ? (JSON.parse(input) as Record<string, unknown>)
      : input;
  return calc.calculateWTNSBin(parsed, true);
}

/** Test helper: clear calculator cache. */
export function _resetWitnessCache(): void {
  cachedBuilder = null;
  calcByKind.clear();
}
