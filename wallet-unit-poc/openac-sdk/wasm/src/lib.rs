use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use ecdsa_spartan2::{parse_witness, prove_circuit_in_memory, Rs256Circuit};
use ecdsa_spartan2::{Scalar, E};

use spartan2::{traits::snark::R1CSSNARKTrait, zk_spartan::R1CSSNARK};

// Re-export wasm-bindgen-rayon's thread pool initializer for multi-threaded WASM.
// JS calls: `await wasm.initThreadPool(navigator.hardwareConcurrency)`
pub use wasm_bindgen_rayon::init_thread_pool;

// ==========================================================================
// Result types for JS interop
// ==========================================================================

#[derive(Serialize, Deserialize)]
pub struct Rs256SetupResult {
    pub pk: Vec<u8>,
    pub vk: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct Rs256ProveResult {
    pub proof: Vec<u8>,
    pub instance: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct Rs256VerifyResult {
    pub valid: bool,
    pub public_values: Vec<String>,
    pub error: Option<String>,
}

#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
}

// ==========================================================================
// RS256 — Single-circuit RSA signature verification
// ==========================================================================

/// Setup RS256 circuit keys.
#[wasm_bindgen]
pub fn setup_rs256() -> Result<JsValue, JsError> {
    let circuit = Rs256Circuit::default();
    let (pk, vk) = R1CSSNARK::<E>::setup(circuit)
        .map_err(|e| JsError::new(&format!("RS256 setup failed: {:?}", e)))?;

    let result = Rs256SetupResult {
        pk: bincode::serialize(&pk)
            .map_err(|e| JsError::new(&format!("PK serialization failed: {}", e)))?,
        vk: bincode::serialize(&vk)
            .map_err(|e| JsError::new(&format!("VK serialization failed: {}", e)))?,
    };
    serde_wasm_bindgen::to_value(&result)
        .map_err(|e| JsError::new(&format!("JS conversion failed: {}", e)))
}

// Global storage for the RS256 proving key to avoid re-deserializing 744MB on every prove call
// and to allow freeing the input byte buffer before proving starts.
use std::sync::Mutex;
static RS256_PK: Mutex<Option<<R1CSSNARK<E> as R1CSSNARKTrait<E>>::ProverKey>> =
    Mutex::new(None);

/// Load and deserialize the RS256 proving key into WASM memory.
/// Call this once during init. The PK bytes can then be freed on the JS side.
#[wasm_bindgen]
pub fn load_rs256_pk(pk_bytes: &[u8]) -> Result<(), JsError> {
    let pk: <R1CSSNARK<E> as R1CSSNARKTrait<E>>::ProverKey = bincode::deserialize(pk_bytes)
        .map_err(|e| JsError::new(&format!("PK deserialization failed: {}", e)))?;
    let mut guard = RS256_PK.lock().unwrap();
    *guard = Some(pk);
    Ok(())
}

/// Prove RS256 circuit with externally generated witness.
/// Requires load_rs256_pk() to be called first.
#[wasm_bindgen]
pub fn prove_rs256(witness_wtns_bytes: &[u8]) -> Result<JsValue, JsError> {
    let guard = RS256_PK.lock().unwrap();
    let pk = guard
        .as_ref()
        .ok_or_else(|| JsError::new("RS256 PK not loaded. Call load_rs256_pk() first."))?;

    let witness_scalars = parse_witness(witness_wtns_bytes)
        .map_err(|e| JsError::new(&format!("Witness parsing failed: {:?}", e)))?;

    let circuit = Rs256Circuit::with_witness(witness_scalars);

    let (proof, instance, _witness) = prove_circuit_in_memory(circuit, pk)
        .map_err(|e| JsError::new(&format!("RS256 proving failed: {:?}", e)))?;

    let result = Rs256ProveResult {
        proof: bincode::serialize(&proof)
            .map_err(|e| JsError::new(&format!("Proof serialization failed: {}", e)))?,
        instance: bincode::serialize(&instance)
            .map_err(|e| JsError::new(&format!("Instance serialization failed: {}", e)))?,
    };
    serde_wasm_bindgen::to_value(&result)
        .map_err(|e| JsError::new(&format!("JS conversion failed: {}", e)))
}

/// Verify RS256 proof.
#[wasm_bindgen]
pub fn verify_rs256(proof_bytes: &[u8], vk_bytes: &[u8]) -> Result<JsValue, JsError> {
    let proof: R1CSSNARK<E> = bincode::deserialize(proof_bytes)
        .map_err(|e| JsError::new(&format!("Proof deserialization failed: {}", e)))?;
    let vk: <R1CSSNARK<E> as R1CSSNARKTrait<E>>::VerifierKey = bincode::deserialize(vk_bytes)
        .map_err(|e| JsError::new(&format!("VK deserialization failed: {}", e)))?;

    match proof.verify(&vk) {
        Ok(public_values) => {
            let result = Rs256VerifyResult {
                valid: true,
                public_values: public_values.iter().map(|s| format!("{:?}", s)).collect(),
                error: None,
            };
            serde_wasm_bindgen::to_value(&result)
                .map_err(|e| JsError::new(&format!("JS conversion failed: {}", e)))
        }
        Err(e) => {
            let result = Rs256VerifyResult {
                valid: false,
                public_values: vec![],
                error: Some(format!("Verification failed: {:?}", e)),
            };
            serde_wasm_bindgen::to_value(&result)
                .map_err(|e| JsError::new(&format!("JS conversion failed: {}", e)))
        }
    }
}
