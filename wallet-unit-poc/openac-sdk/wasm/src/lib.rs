use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use ecdsa_spartan2::{
    parse_witness, prove_circuit_in_memory, reblind_in_memory, PrepareCircuit, Rs256Circuit,
    ShowCircuit,
};
use ecdsa_spartan2::{Scalar, E};

use spartan2::{traits::snark::R1CSSNARKTrait, zk_spartan::R1CSSNARK};

use ff::Field;

// Re-export wasm-bindgen-rayon's thread pool initializer for multi-threaded WASM.
// JS calls: `await wasm.initThreadPool(navigator.hardwareConcurrency)`
pub use wasm_bindgen_rayon::init_thread_pool;

// ==========================================================================
// Result types for JS interop
// ==========================================================================

#[derive(Serialize, Deserialize)]
pub struct SetupResult {
    pub prepare_pk: Vec<u8>,
    pub prepare_vk: Vec<u8>,
    pub show_pk: Vec<u8>,
    pub show_vk: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct SingleSetupResult {
    pub pk: Vec<u8>,
    pub vk: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct PrecomputeResult {
    pub proof: Vec<u8>,
    pub instance: Vec<u8>,
    pub witness: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct PresentResult {
    pub prepare_proof: Vec<u8>,
    pub prepare_instance: Vec<u8>,
    pub show_proof: Vec<u8>,
    pub show_instance: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct VerifyResult {
    pub valid: bool,
    pub prepare_public_values: Vec<String>,
    pub show_public_values: Vec<String>,
    pub error: Option<String>,
}

#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
}

// ==========================================================================
// 1. SETUP
// ==========================================================================

#[wasm_bindgen]
pub fn setup() -> Result<JsValue, JsError> {
    let prepare_circuit = PrepareCircuit::default();
    let (prepare_pk, prepare_vk) = R1CSSNARK::<E>::setup(prepare_circuit)
        .map_err(|e| JsError::new(&format!("Prepare setup failed: {:?}", e)))?;

    let show_circuit = ShowCircuit::default();
    let (show_pk, show_vk) = R1CSSNARK::<E>::setup(show_circuit)
        .map_err(|e| JsError::new(&format!("Show setup failed: {:?}", e)))?;

    let result = SetupResult {
        prepare_pk: bincode::serialize(&prepare_pk)
            .map_err(|e| JsError::new(&format!("Prepare PK serialization failed: {}", e)))?,
        prepare_vk: bincode::serialize(&prepare_vk)
            .map_err(|e| JsError::new(&format!("Prepare VK serialization failed: {}", e)))?,
        show_pk: bincode::serialize(&show_pk)
            .map_err(|e| JsError::new(&format!("Show PK serialization failed: {}", e)))?,
        show_vk: bincode::serialize(&show_vk)
            .map_err(|e| JsError::new(&format!("Show VK serialization failed: {}", e)))?,
    };

    serde_wasm_bindgen::to_value(&result)
        .map_err(|e| JsError::new(&format!("JS conversion failed: {}", e)))
}

// ==========================================================================
// 2. PRECOMPUTE
// ==========================================================================

#[wasm_bindgen]
pub fn precompute(pk_bytes: &[u8]) -> Result<JsValue, JsError> {
    let pk: <R1CSSNARK<E> as R1CSSNARKTrait<E>>::ProverKey = bincode::deserialize(pk_bytes)
        .map_err(|e| JsError::new(&format!("PK deserialization failed: {}", e)))?;

    let circuit = PrepareCircuit::default();

    let (proof, instance, witness) = prove_circuit_in_memory(circuit, &pk)
        .map_err(|e| JsError::new(&format!("Prepare proving failed: {:?}", e)))?;

    let result = PrecomputeResult {
        proof: bincode::serialize(&proof)
            .map_err(|e| JsError::new(&format!("Proof serialization failed: {}", e)))?,
        instance: bincode::serialize(&instance)
            .map_err(|e| JsError::new(&format!("Instance serialization failed: {}", e)))?,
        witness: bincode::serialize(&witness)
            .map_err(|e| JsError::new(&format!("Witness serialization failed: {}", e)))?,
    };

    serde_wasm_bindgen::to_value(&result)
        .map_err(|e| JsError::new(&format!("JS conversion failed: {}", e)))
}

// ==========================================================================
// 2b. PRECOMPUTE FROM WITNESS
// ==========================================================================

#[wasm_bindgen]
pub fn precompute_from_witness(
    pk_bytes: &[u8],
    witness_wtns_bytes: &[u8],
) -> Result<JsValue, JsError> {
    let pk: <R1CSSNARK<E> as R1CSSNARKTrait<E>>::ProverKey = bincode::deserialize(pk_bytes)
        .map_err(|e| JsError::new(&format!("PK deserialization failed: {}", e)))?;

    let witness_scalars = parse_witness(witness_wtns_bytes)
        .map_err(|e| JsError::new(&format!("Witness parsing failed: {:?}", e)))?;

    let circuit = PrepareCircuit::with_witness(witness_scalars);

    let (proof, instance, witness) = prove_circuit_in_memory(circuit, &pk)
        .map_err(|e| JsError::new(&format!("Prepare proving failed: {:?}", e)))?;

    let result = PrecomputeResult {
        proof: bincode::serialize(&proof)
            .map_err(|e| JsError::new(&format!("Proof serialization failed: {}", e)))?,
        instance: bincode::serialize(&instance)
            .map_err(|e| JsError::new(&format!("Instance serialization failed: {}", e)))?,
        witness: bincode::serialize(&witness)
            .map_err(|e| JsError::new(&format!("Witness serialization failed: {}", e)))?,
    };

    serde_wasm_bindgen::to_value(&result)
        .map_err(|e| JsError::new(&format!("JS conversion failed: {}", e)))
}

#[wasm_bindgen]
pub fn precompute_show_from_witness(
    pk_bytes: &[u8],
    witness_wtns_bytes: &[u8],
) -> Result<JsValue, JsError> {
    let pk: <R1CSSNARK<E> as R1CSSNARKTrait<E>>::ProverKey = bincode::deserialize(pk_bytes)
        .map_err(|e| JsError::new(&format!("PK deserialization failed: {}", e)))?;

    let witness_scalars = parse_witness(witness_wtns_bytes)
        .map_err(|e| JsError::new(&format!("Witness parsing failed: {:?}", e)))?;

    let circuit = ShowCircuit::with_witness(witness_scalars);

    let (proof, instance, witness) = prove_circuit_in_memory(circuit, &pk)
        .map_err(|e| JsError::new(&format!("Show proving failed: {:?}", e)))?;

    let result = PrecomputeResult {
        proof: bincode::serialize(&proof)
            .map_err(|e| JsError::new(&format!("Proof serialization failed: {}", e)))?,
        instance: bincode::serialize(&instance)
            .map_err(|e| JsError::new(&format!("Instance serialization failed: {}", e)))?,
        witness: bincode::serialize(&witness)
            .map_err(|e| JsError::new(&format!("Witness serialization failed: {}", e)))?,
    };

    serde_wasm_bindgen::to_value(&result)
        .map_err(|e| JsError::new(&format!("JS conversion failed: {}", e)))
}

// ==========================================================================
// 3. PRESENT
// ==========================================================================

#[wasm_bindgen]
pub fn present(
    prepare_pk_bytes: &[u8],
    prepare_instance_bytes: &[u8],
    prepare_witness_bytes: &[u8],
    show_pk_bytes: &[u8],
    show_instance_bytes: &[u8],
    show_witness_bytes: &[u8],
) -> Result<JsValue, JsError> {
    let prepare_pk: <R1CSSNARK<E> as R1CSSNARKTrait<E>>::ProverKey =
        bincode::deserialize(prepare_pk_bytes)
            .map_err(|e| JsError::new(&format!("Prepare PK deserialization failed: {}", e)))?;
    let prepare_instance: spartan2::r1cs::SplitR1CSInstance<E> =
        bincode::deserialize(prepare_instance_bytes).map_err(|e| {
            JsError::new(&format!("Prepare instance deserialization failed: {}", e))
        })?;
    let prepare_witness: spartan2::r1cs::R1CSWitness<E> =
        bincode::deserialize(prepare_witness_bytes)
            .map_err(|e| JsError::new(&format!("Prepare witness deserialization failed: {}", e)))?;

    let show_pk: <R1CSSNARK<E> as R1CSSNARKTrait<E>>::ProverKey =
        bincode::deserialize(show_pk_bytes)
            .map_err(|e| JsError::new(&format!("Show PK deserialization failed: {}", e)))?;
    let show_instance: spartan2::r1cs::SplitR1CSInstance<E> =
        bincode::deserialize(show_instance_bytes)
            .map_err(|e| JsError::new(&format!("Show instance deserialization failed: {}", e)))?;
    let show_witness: spartan2::r1cs::R1CSWitness<E> = bincode::deserialize(show_witness_bytes)
        .map_err(|e| JsError::new(&format!("Show witness deserialization failed: {}", e)))?;

    // Generate shared blinds
    let num_shared = prepare_instance.num_shared_rows();
    let shared_blinds: Vec<Scalar> = (0..num_shared)
        .map(|_| Scalar::random(&mut rand::thread_rng()))
        .collect();

    // Reblind Prepare proof
    let (reblinded_prepare_proof, reblinded_prepare_instance, _reblinded_prepare_witness) =
        reblind_in_memory(
            &prepare_pk,
            prepare_instance,
            prepare_witness,
            &shared_blinds,
        )
        .map_err(|e| JsError::new(&format!("Prepare reblind failed: {:?}", e)))?;

    // Reblind Show proof with same shared blinds
    let (reblinded_show_proof, reblinded_show_instance, _reblinded_show_witness) =
        reblind_in_memory(&show_pk, show_instance, show_witness, &shared_blinds)
            .map_err(|e| JsError::new(&format!("Show reblind failed: {:?}", e)))?;

    let result = PresentResult {
        prepare_proof: bincode::serialize(&reblinded_prepare_proof)
            .map_err(|e| JsError::new(&format!("Prepare proof serialization failed: {}", e)))?,
        prepare_instance: bincode::serialize(&reblinded_prepare_instance)
            .map_err(|e| JsError::new(&format!("Prepare instance serialization failed: {}", e)))?,
        show_proof: bincode::serialize(&reblinded_show_proof)
            .map_err(|e| JsError::new(&format!("Show proof serialization failed: {}", e)))?,
        show_instance: bincode::serialize(&reblinded_show_instance)
            .map_err(|e| JsError::new(&format!("Show instance serialization failed: {}", e)))?,
    };

    serde_wasm_bindgen::to_value(&result)
        .map_err(|e| JsError::new(&format!("JS conversion failed: {}", e)))
}

// ==========================================================================
// 4. VERIFY
// ==========================================================================

#[wasm_bindgen]
pub fn verify(
    prepare_proof_bytes: &[u8],
    prepare_vk_bytes: &[u8],
    prepare_instance_bytes: &[u8],
    show_proof_bytes: &[u8],
    show_vk_bytes: &[u8],
    show_instance_bytes: &[u8],
) -> Result<JsValue, JsError> {
    let prepare_proof: R1CSSNARK<E> = bincode::deserialize(prepare_proof_bytes)
        .map_err(|e| JsError::new(&format!("Prepare proof deserialization failed: {}", e)))?;
    let prepare_vk: <R1CSSNARK<E> as R1CSSNARKTrait<E>>::VerifierKey =
        bincode::deserialize(prepare_vk_bytes)
            .map_err(|e| JsError::new(&format!("Prepare VK deserialization failed: {}", e)))?;
    let prepare_instance: spartan2::r1cs::SplitR1CSInstance<E> =
        bincode::deserialize(prepare_instance_bytes).map_err(|e| {
            JsError::new(&format!("Prepare instance deserialization failed: {}", e))
        })?;

    let show_proof: R1CSSNARK<E> = bincode::deserialize(show_proof_bytes)
        .map_err(|e| JsError::new(&format!("Show proof deserialization failed: {}", e)))?;
    let show_vk: <R1CSSNARK<E> as R1CSSNARKTrait<E>>::VerifierKey =
        bincode::deserialize(show_vk_bytes)
            .map_err(|e| JsError::new(&format!("Show VK deserialization failed: {}", e)))?;
    let show_instance: spartan2::r1cs::SplitR1CSInstance<E> =
        bincode::deserialize(show_instance_bytes)
            .map_err(|e| JsError::new(&format!("Show instance deserialization failed: {}", e)))?;

    // Compare shared commitments
    let commitment_valid = prepare_instance.comm_W_shared == show_instance.comm_W_shared;
    if !commitment_valid {
        let result = VerifyResult {
            valid: false,
            prepare_public_values: vec![],
            show_public_values: vec![],
            error: Some("Shared commitment mismatch: prepare and show proofs do not share the same private data".to_string()),
        };
        return serde_wasm_bindgen::to_value(&result)
            .map_err(|e| JsError::new(&format!("JS conversion failed: {}", e)));
    }

    // Verify Prepare proof
    let prepare_pv = match prepare_proof.verify(&prepare_vk) {
        Ok(pv) => pv,
        Err(e) => {
            let result = VerifyResult {
                valid: false,
                prepare_public_values: vec![],
                show_public_values: vec![],
                error: Some(format!("Prepare proof verification failed: {:?}", e)),
            };
            return serde_wasm_bindgen::to_value(&result)
                .map_err(|e| JsError::new(&format!("JS conversion failed: {}", e)));
        }
    };

    // Verify Show proof
    let show_pv = match show_proof.verify(&show_vk) {
        Ok(pv) => pv,
        Err(e) => {
            let result = VerifyResult {
                valid: false,
                prepare_public_values: vec![],
                show_public_values: vec![],
                error: Some(format!("Show proof verification failed: {:?}", e)),
            };
            return serde_wasm_bindgen::to_value(&result)
                .map_err(|e| JsError::new(&format!("JS conversion failed: {}", e)));
        }
    };

    let result = VerifyResult {
        valid: true,
        prepare_public_values: prepare_pv.iter().map(|s| format!("{:?}", s)).collect(),
        show_public_values: show_pv.iter().map(|s| format!("{:?}", s)).collect(),
        error: None,
    };
    serde_wasm_bindgen::to_value(&result)
        .map_err(|e| JsError::new(&format!("JS conversion failed: {}", e)))
}

// ==========================================================================
// Backward-compatible functions
// ==========================================================================

#[wasm_bindgen]
pub fn setup_prepare() -> Result<JsValue, JsError> {
    let circuit = PrepareCircuit::default();
    let (pk, vk) = R1CSSNARK::<E>::setup(circuit)
        .map_err(|e| JsError::new(&format!("Setup failed: {:?}", e)))?;

    let result = SingleSetupResult {
        pk: bincode::serialize(&pk)
            .map_err(|e| JsError::new(&format!("PK serialization failed: {}", e)))?,
        vk: bincode::serialize(&vk)
            .map_err(|e| JsError::new(&format!("VK serialization failed: {}", e)))?,
    };
    serde_wasm_bindgen::to_value(&result)
        .map_err(|e| JsError::new(&format!("JS conversion failed: {}", e)))
}

#[wasm_bindgen]
pub fn setup_show() -> Result<JsValue, JsError> {
    let circuit = ShowCircuit::default();
    let (pk, vk) = R1CSSNARK::<E>::setup(circuit)
        .map_err(|e| JsError::new(&format!("Setup failed: {:?}", e)))?;

    let result = SingleSetupResult {
        pk: bincode::serialize(&pk)
            .map_err(|e| JsError::new(&format!("PK serialization failed: {}", e)))?,
        vk: bincode::serialize(&vk)
            .map_err(|e| JsError::new(&format!("VK serialization failed: {}", e)))?,
    };
    serde_wasm_bindgen::to_value(&result)
        .map_err(|e| JsError::new(&format!("JS conversion failed: {}", e)))
}

#[wasm_bindgen]
pub fn verify_single(proof_bytes: &[u8], vk_bytes: &[u8]) -> Result<JsValue, JsError> {
    let proof: R1CSSNARK<E> = bincode::deserialize(proof_bytes)
        .map_err(|e| JsError::new(&format!("Proof deserialization failed: {}", e)))?;
    let vk: <R1CSSNARK<E> as R1CSSNARKTrait<E>>::VerifierKey = bincode::deserialize(vk_bytes)
        .map_err(|e| JsError::new(&format!("VK deserialization failed: {}", e)))?;

    match proof.verify(&vk) {
        Ok(public_values) => {
            let pv_strings: Vec<String> =
                public_values.iter().map(|s| format!("{:?}", s)).collect();
            let result = serde_json::json!({
                "valid": true,
                "public_values": pv_strings,
            });
            serde_wasm_bindgen::to_value(&result)
                .map_err(|e| JsError::new(&format!("JS conversion failed: {}", e)))
        }
        Err(_e) => {
            let result = serde_json::json!({
                "valid": false,
                "public_values": Vec::<String>::new(),
            });
            serde_wasm_bindgen::to_value(&result)
                .map_err(|e| JsError::new(&format!("JS conversion failed: {}", e)))
        }
    }
}

#[wasm_bindgen]
pub fn compare_comm_w_shared(
    instance1_bytes: &[u8],
    instance2_bytes: &[u8],
) -> Result<bool, JsError> {
    let instance1: spartan2::r1cs::SplitR1CSInstance<E> = bincode::deserialize(instance1_bytes)
        .map_err(|e| JsError::new(&format!("Instance1 deserialization failed: {}", e)))?;
    let instance2: spartan2::r1cs::SplitR1CSInstance<E> = bincode::deserialize(instance2_bytes)
        .map_err(|e| JsError::new(&format!("Instance2 deserialization failed: {}", e)))?;
    Ok(instance1.comm_W_shared == instance2.comm_W_shared)
}

// ==========================================================================
// RS256 — Single-circuit RSA signature verification
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
