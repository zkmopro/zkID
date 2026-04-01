use wasm_bindgen::prelude::*;

use spartan2::provider::T256HyraxEngine;
use spartan2::traits::Engine;
use spartan2::zk_spartan::R1CSSNARK;
use spartan2::traits::snark::R1CSSNARKTrait;

pub type E = T256HyraxEngine;
pub type Scalar = <E as Engine>::Scalar;

/// Initialize panic hook for better error messages in WASM
#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
}

/// Smoke test: verify Spartan2 types are accessible from WASM
/// Returns the name of the engine type as a string
#[wasm_bindgen]
pub fn spartan2_smoke_test() -> String {
    format!("Spartan2 WASM module loaded. Engine: T256HyraxEngine")
}

/// Verify a single proof given serialized proof and verifying key bytes.
/// This is the minimal viable WASM binding for server-generated proofs.
///
/// Arguments:
/// - `proof_bytes`: bincode-serialized R1CSSNARK<E> proof
/// - `vk_bytes`: bincode-serialized verifying key
///
/// Returns: JSON string with { valid: bool, public_values: string[], error?: string }
#[wasm_bindgen]
pub fn verify_proof(proof_bytes: &[u8], vk_bytes: &[u8]) -> Result<JsValue, JsError> {
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
        Err(e) => {
            let result = serde_json::json!({
                "valid": false,
                "public_values": Vec::<String>::new(),
                "error": format!("{:?}", e),
            });
            serde_wasm_bindgen::to_value(&result)
                .map_err(|e| JsError::new(&format!("JS conversion failed: {}", e)))
        }
    }
}
