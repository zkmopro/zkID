/**
 * Browser-compatible witness calculator.
 * Replaces the Node.js WitnessCalculator (which uses fs.readFile)
 * with a fetch()-based version for the browser.
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
  private jwtCalc: WitnessCalculatorInstance | null = null;
  private showCalc: WitnessCalculatorInstance | null = null;
  private rs256Calc: WitnessCalculatorInstance | null = null;

  private jwtWasmUrl: string;
  private showWasmUrl: string;
  private rs256WasmUrl: string;

  constructor(baseUrl = "") {
    this.jwtWasmUrl = `${baseUrl}/jwt.wasm`;
    this.showWasmUrl = `${baseUrl}/show.wasm`;
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

  async calculateJwtWitness(inputs: CircuitInput): Promise<bigint[]> {
    if (!this.jwtCalc) {
      this.jwtCalc = await this.loadCalc(this.jwtWasmUrl);
    }
    return await this.jwtCalc.calculateWitness(inputs, true);
  }

  async calculateShowWitness(inputs: CircuitInput): Promise<bigint[]> {
    if (!this.showCalc) {
      this.showCalc = await this.loadCalc(this.showWasmUrl);
    }
    return await this.showCalc.calculateWitness(inputs, true);
  }

  async calculateJwtWitnessWtns(inputs: CircuitInput): Promise<Uint8Array> {
    if (!this.jwtCalc) {
      this.jwtCalc = await this.loadCalc(this.jwtWasmUrl);
    }
    return await this.jwtCalc.calculateWTNSBin(inputs, true);
  }

  async calculateShowWitnessWtns(inputs: CircuitInput): Promise<Uint8Array> {
    if (!this.showCalc) {
      this.showCalc = await this.loadCalc(this.showWasmUrl);
    }
    return await this.showCalc.calculateWTNSBin(inputs, true);
  }

  async calculateRs256WitnessWtns(inputs: CircuitInput): Promise<Uint8Array> {
    if (!this.rs256Calc) {
      this.rs256Calc = await this.loadCalc(this.rs256WasmUrl);
    }
    return await this.rs256Calc.calculateWTNSBin(inputs, true);
  }
}
