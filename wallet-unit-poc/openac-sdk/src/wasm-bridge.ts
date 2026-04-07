// Async loader and typed wrapper over the Spartan2 WASM module.
// Provides 4 high-level API methods aligned with the zkID paper protocol:
// 1. setup()      — Generate keys for both circuits (one-time)
// 2. precompute() — Prove Prepare circuit (once per credential)
// 3. present()    — Reblind Prepare + Prove Show + Reblind Show (per presentation)
// 4. verify()     — Verify both proofs + commitment check (per presentation)

import { WasmError } from "./errors.js";

interface WasmSetupResult {
  prepare_pk: Uint8Array;
  prepare_vk: Uint8Array;
  show_pk: Uint8Array;
  show_vk: Uint8Array;
}

interface WasmPrecomputeResult {
  proof: Uint8Array;
  instance: Uint8Array;
  witness: Uint8Array;
}

interface WasmPresentResult {
  prepare_proof: Uint8Array;
  prepare_instance: Uint8Array;
  show_proof: Uint8Array;
  show_instance: Uint8Array;
}

interface WasmVerifyResult {
  valid: boolean;
  prepare_public_values: string[];
  show_public_values: string[];
  error: string | null;
}

interface WasmSingleSetupResult {
  pk: Uint8Array;
  vk: Uint8Array;
}

interface WasmSingleVerifyResult {
  valid: boolean;
  public_values: string[];
}

interface OpenACWasmModule {
  init(): void;
  setup(): WasmSetupResult;
  precompute(pk: Uint8Array): WasmPrecomputeResult;
  present(
    preparePk: Uint8Array,
    prepareInstance: Uint8Array,
    prepareWitness: Uint8Array,
    showPk: Uint8Array,
    showInstance: Uint8Array,
    showWitness: Uint8Array,
  ): WasmPresentResult;
  verify(
    prepareProof: Uint8Array,
    prepareVk: Uint8Array,
    prepareInstance: Uint8Array,
    showProof: Uint8Array,
    showVk: Uint8Array,
    showInstance: Uint8Array,
  ): WasmVerifyResult;

  setup_prepare(): WasmSingleSetupResult;
  setup_show(): WasmSingleSetupResult;
  verify_single(proof: Uint8Array, vk: Uint8Array): WasmSingleVerifyResult;
  compare_comm_w_shared(instance1: Uint8Array, instance2: Uint8Array): boolean;
}

export interface SetupKeys {
  preparePk: Uint8Array;
  prepareVk: Uint8Array;
  showPk: Uint8Array;
  showVk: Uint8Array;
}

export interface PrecomputeState {
  proof: Uint8Array;
  instance: Uint8Array;
  witness: Uint8Array;
}

export interface PresentationProof {
  prepareProof: Uint8Array;
  prepareInstance: Uint8Array;
  showProof: Uint8Array;
  showInstance: Uint8Array;
}

export interface VerificationResult {
  valid: boolean;
  preparePublicValues: string[];
  showPublicValues: string[];
  error?: string;
}

export class WasmBridge {
  private wasm: OpenACWasmModule | null = null;
  private initialized = false;

  async init(wasmPath?: string): Promise<void> {
    if (this.initialized) return;

    if (wasmPath) {
      const module = await import(/* webpackIgnore: true */ wasmPath);
      this.wasm = module as OpenACWasmModule;
    } else {
      try {
        // @ts-expect-error Dynamic WASM import path resolved at runtime
        const module = await import("../wasm/pkg/openac_wasm.js");
        this.wasm = module as OpenACWasmModule;
      } catch {
        throw new WasmError(
          "WASM_LOAD_FAILED",
          "Could not load bundled WASM module. Build it first (npm run build:wasm) or provide wasmPath.",
        );
      }
    }

    if (this.wasm?.init) {
      this.wasm.init();
    }

    this.initialized = true;
  }

  get isInitialized(): boolean {
    return this.initialized;
  }

  private getWasm(): OpenACWasmModule {
    if (!this.wasm || !this.initialized) {
      throw new WasmError(
        "WASM_NOT_INITIALIZED",
        "WASM module not initialized. Call init() first.",
      );
    }
    return this.wasm;
  }

  async setup(): Promise<SetupKeys> {
    const wasm = this.getWasm();
    const result = wasm.setup();
    return {
      preparePk: new Uint8Array(result.prepare_pk),
      prepareVk: new Uint8Array(result.prepare_vk),
      showPk: new Uint8Array(result.show_pk),
      showVk: new Uint8Array(result.show_vk),
    };
  }

  async precompute(preparePk: Uint8Array): Promise<PrecomputeState> {
    const wasm = this.getWasm();
    const result = wasm.precompute(preparePk);
    return {
      proof: new Uint8Array(result.proof),
      instance: new Uint8Array(result.instance),
      witness: new Uint8Array(result.witness),
    };
  }

  async present(
    preparePk: Uint8Array,
    prepareInstance: Uint8Array,
    prepareWitness: Uint8Array,
    showPk: Uint8Array,
    showInstance: Uint8Array,
    showWitness: Uint8Array,
  ): Promise<PresentationProof> {
    const wasm = this.getWasm();
    const result = wasm.present(
      preparePk,
      prepareInstance,
      prepareWitness,
      showPk,
      showInstance,
      showWitness,
    );
    return {
      prepareProof: new Uint8Array(result.prepare_proof),
      prepareInstance: new Uint8Array(result.prepare_instance),
      showProof: new Uint8Array(result.show_proof),
      showInstance: new Uint8Array(result.show_instance),
    };
  }

  async verify(
    prepareProof: Uint8Array,
    prepareVk: Uint8Array,
    prepareInstance: Uint8Array,
    showProof: Uint8Array,
    showVk: Uint8Array,
    showInstance: Uint8Array,
  ): Promise<VerificationResult> {
    const wasm = this.getWasm();
    const result = wasm.verify(
      prepareProof,
      prepareVk,
      prepareInstance,
      showProof,
      showVk,
      showInstance,
    );
    return {
      valid: result.valid,
      preparePublicValues: result.prepare_public_values,
      showPublicValues: result.show_public_values,
      error: result.error ?? undefined,
    };
  }

  /** @deprecated Use setup() instead */
  async setupPrepare(): Promise<{ pk: Uint8Array; vk: Uint8Array }> {
    const wasm = this.getWasm();
    const result = wasm.setup_prepare();
    return { pk: new Uint8Array(result.pk), vk: new Uint8Array(result.vk) };
  }

  /** @deprecated Use setup() instead */
  async setupShow(): Promise<{ pk: Uint8Array; vk: Uint8Array }> {
    const wasm = this.getWasm();
    const result = wasm.setup_show();
    return { pk: new Uint8Array(result.pk), vk: new Uint8Array(result.vk) };
  }

  /** @deprecated Use verify() instead */
  async verifySingle(
    proof: Uint8Array,
    vk: Uint8Array,
  ): Promise<{ valid: boolean; publicValues: string[] }> {
    const wasm = this.getWasm();
    const result = wasm.verify_single(proof, vk);
    return { valid: result.valid, publicValues: result.public_values };
  }

  /** @deprecated Use verify() instead — commitment check is now internal */
  compareCommWShared(
    prepareInstance: Uint8Array,
    showInstance: Uint8Array,
  ): boolean {
    const wasm = this.getWasm();
    return wasm.compare_comm_w_shared(prepareInstance, showInstance);
  }
}
