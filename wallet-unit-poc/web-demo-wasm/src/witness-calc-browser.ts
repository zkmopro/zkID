/**
 * Browser-compatible witness calculator for RS256 circuit.
 * Uses fetch() to load circom-compiled WASM in the browser.
 */

// The witness_calculator.js is a CJS module. Vite handles the CJS->ESM conversion.
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore — CJS module, no types
import builder from "./assets/witness_calculator.js";

type CircuitInput = Record<string, unknown>;

interface WitnessCalculatorInstance {
  calculateWitness(
    input: CircuitInput,
    sanityCheck?: boolean
  ): Promise<bigint[]>;
  calculateWTNSBin(
    input: CircuitInput,
    sanityCheck?: boolean
  ): Promise<Uint8Array>;
}

export class BrowserWitnessCalculator {
  private rs256Calc: WitnessCalculatorInstance | null = null;

  private rs256WasmUrl: string;

  constructor(baseUrl = "") {
    this.rs256WasmUrl = `${baseUrl}/assets/rs256.wasm`;
  }

  private async loadCalc(url: string): Promise<WitnessCalculatorInstance> {
    const response = await fetch(url);
    if (!response.ok) {
      throw new Error(`Failed to fetch ${url}: ${response.status}`);
    }
    const wasmBytes = await response.arrayBuffer();
    return await builder(wasmBytes, { sanityCheck: true });
  }

  async calculateRs256WitnessWtns(inputs: CircuitInput): Promise<Uint8Array> {
    if (!this.rs256Calc) {
      this.rs256Calc = await this.loadCalc(this.rs256WasmUrl);
    }
    return await this.rs256Calc.calculateWTNSBin(inputs, true);
  }
}
