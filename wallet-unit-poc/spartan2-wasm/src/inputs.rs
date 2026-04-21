//! Cert-chain + device-sig input builder wasm entry points.
//!
//! Thin wrapper around `zkid_input_builder::generate_split_inputs`. The
//! browser passes raw DER bytes + base64 signature + SMT proof; this module
//! parses them and produces the same JSON the circom witness calculator
//! consumes natively. Byte-for-byte parity with `ecdsa-spartan2`'s native
//! caller is pinned by `tests/input_builder_drift.rs` — any drift fails CI
//! before it can reach the browser and reproduce PR #40's
//! `Too many values for input signal __placeholder__` failure.

use rsa::{pkcs8::DecodePublicKey, traits::PublicKeyParts, RsaPublicKey};
use serde::Serialize;
use serde_wasm_bindgen::Serializer;
use wasm_bindgen::prelude::*;
use x509_cert::{der::{Decode, Encode}, Certificate};
use zkid_input_builder::{generate_split_inputs, types::SmtCircuitInputs, MAX_CERT_CHAIN_LENGTH};

/// Two-JSON return shape. `cert_chain` + `device_sig` match the keys the
/// circom witness calculator expects in its input file.
#[derive(Serialize)]
pub struct SplitInputsJs {
    pub cert_chain: serde_json::Value,
    pub device_sig: serde_json::Value,
}

fn build_split_inputs_core(
    user_cert_der: &[u8],
    issuer_cert_der: &[u8],
    user_signature_b64: &str,
    tbs: &[u8],
    serial_hex: &str,
    smt_inputs: Option<&SmtCircuitInputs>,
    k_issuer: usize,
    k_user: usize,
    max_cert_length: usize,
) -> Result<SplitInputsJs, String> {
    let user_cert = Certificate::from_der(user_cert_der)
        .map_err(|e| format!("user cert DER parse: {e}"))?;
    let issuer_cert = Certificate::from_der(issuer_cert_der)
        .map_err(|e| format!("issuer cert DER parse: {e}"))?;

    let (cert_chain, device_sig) = generate_split_inputs(
        &user_cert,
        &issuer_cert,
        user_signature_b64,
        tbs,
        serial_hex,
        smt_inputs,
        k_issuer,
        k_user,
        max_cert_length,
    )
    .map_err(|e| format!("generate_split_inputs: {e}"))?;

    Ok(SplitInputsJs {
        cert_chain,
        device_sig,
    })
}

/// Build cert-chain + device-sig circuit inputs from raw card + SMT data.
///
/// `smt_inputs` accepts either `null`/`undefined` (fills deterministic zero
/// defaults) or an object matching `SmtCircuitInputs` field names
/// (snake_case). `k_issuer` must be 17 (RSA-2048 issuer) or 34 (RSA-4096);
/// `k_user` must be 17 — MOICA user keys are always RSA-2048. Returns
/// `{ cert_chain, device_sig }` JSON objects ready to feed into the circom
/// witness calculator.
#[wasm_bindgen]
pub fn build_split_inputs(
    user_cert_der: &[u8],
    issuer_cert_der: &[u8],
    user_signature_b64: &str,
    tbs: &[u8],
    serial_hex: &str,
    smt_inputs: JsValue,
    k_issuer: u32,
    k_user: u32,
) -> Result<JsValue, JsError> {
    // Reject unsupported limb counts at the boundary. Letting through a
    // garbage k value silently produces a mis-shaped JSON that reappears
    // later as an opaque `Too many values for input signal __placeholder__`
    // witness failure — the precise regression class this phase prevents.
    if k_issuer != 17 && k_issuer != 34 {
        return Err(JsError::new(&format!(
            "unsupported k_issuer {k_issuer}; expected 17 (RSA-2048) or 34 (RSA-4096)"
        )));
    }
    if k_user != 17 {
        return Err(JsError::new(&format!(
            "unsupported k_user {k_user}; MOICA user keys are RSA-2048 (k_user=17)"
        )));
    }

    let smt: Option<SmtCircuitInputs> = if smt_inputs.is_null() || smt_inputs.is_undefined() {
        None
    } else {
        Some(
            serde_wasm_bindgen::from_value(smt_inputs)
                .map_err(|e| JsError::new(&format!("smt_inputs parse: {e}")))?,
        )
    };

    let out = build_split_inputs_core(
        user_cert_der,
        issuer_cert_der,
        user_signature_b64,
        tbs,
        serial_hex,
        smt.as_ref(),
        k_issuer as usize,
        k_user as usize,
        MAX_CERT_CHAIN_LENGTH,
    )
    .map_err(|e| JsError::new(&e))?;

    // `serde_json::Value::Object` serialises as a JS `Map` by default, which
    // `JSON.stringify` flattens to `"{}"`. The witness calculator then parses
    // an empty object and bails with "Not all inputs have been set. Only 0
    // out of N" — the same class of failure the `__placeholder__` drift test
    // is meant to catch. Force plain JS objects so downstream `JSON.stringify`
    // produces the circuit-input JSON the witness calc expects.
    let serializer = Serializer::new().serialize_maps_as_objects(true);
    out.serialize(&serializer)
        .map_err(|e| JsError::new(&e.to_string()))
}

/// Parse an X.509 certificate DER and return the RSA modulus bit width of
/// its subjectPublicKey. Used by the web app to deterministically select
/// `cert_chain_rs2048` vs `cert_chain_rs4096` from the detected card's
/// issuer cert, rather than the previous fragile DN-regex match that
/// picked the wrong circuit (kIssuer=17, 2057-bit cap) for MOICA-G3
/// cards with 4096-bit issuer keys.
#[wasm_bindgen]
pub fn cert_modulus_bits(cert_der: &[u8]) -> Result<u32, JsError> {
    let cert = Certificate::from_der(cert_der)
        .map_err(|e| JsError::new(&format!("cert DER parse: {e}")))?;
    let spki_der = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|e| JsError::new(&format!("SPKI encode: {e}")))?;
    let pubkey = RsaPublicKey::from_public_key_der(&spki_der)
        .map_err(|e| JsError::new(&format!("not an RSA cert: {e}")))?;
    let modulus_bytes = pubkey.n().to_bytes_be();
    let leading_zeros = modulus_bytes
        .iter()
        .next()
        .map(|b| b.leading_zeros())
        .unwrap_or(0);
    let bits = modulus_bytes.len() as u32 * 8 - leading_zeros;
    Ok(bits)
}

/// Parse the cert's `serialNumber` field and return it as a hex string with
/// leading zero bytes stripped. Matches `serial_bytes_to_hex_trimmed` in
/// `zkid-input-builder::cert` so the web path produces the same serial hex
/// the native CLI uses. Required because the user's real cert (and its
/// serial) is only known after HiPKI `/sign` returns — the /pkcs11info
/// entry may be a different cert from the same card.
#[wasm_bindgen]
pub fn cert_serial_hex(cert_der: &[u8]) -> Result<String, JsError> {
    let cert = Certificate::from_der(cert_der)
        .map_err(|e| JsError::new(&format!("cert DER parse: {e}")))?;
    let bytes = cert.tbs_certificate.serial_number.as_bytes();
    let trimmed: Vec<u8> = bytes
        .iter()
        .skip_while(|&&b| b == 0)
        .copied()
        .collect();
    let out = if trimmed.is_empty() { bytes } else { &trimmed };
    let mut s = String::with_capacity(out.len() * 2);
    for b in out {
        s.push_str(&format!("{b:02x}"));
    }
    Ok(s)
}

/// Compute `pk_blind = SHA-256(user_pk_be || tbs || "zkID/pk-commit/v1")`.
/// Exposed for debugging and UI consistency checks; the main wasm entry
/// point `build_split_inputs` computes this internally.
#[wasm_bindgen]
pub fn compute_pk_blind(user_pk_be: &[u8], tbs: &[u8]) -> String {
    use num_bigint::BigUint;
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(user_pk_be);
    hasher.update(tbs);
    hasher.update(b"zkID/pk-commit/v1");
    let digest = hasher.finalize();
    BigUint::from_bytes_be(&digest).to_string()
}

/// Native-target entry for the drift integration test. Never compiled for
/// wasm32 — the public `build_split_inputs` is the only exported surface.
#[cfg(not(target_arch = "wasm32"))]
pub fn build_split_inputs_native_for_test(
    user_cert_der: &[u8],
    issuer_cert_der: &[u8],
    user_signature_b64: &str,
    tbs: &[u8],
    serial_hex: &str,
    smt_inputs: Option<&SmtCircuitInputs>,
    k_issuer: usize,
    k_user: usize,
    max_cert_length: usize,
) -> Result<SplitInputsJs, String> {
    build_split_inputs_core(
        user_cert_der,
        issuer_cert_der,
        user_signature_b64,
        tbs,
        serial_hex,
        smt_inputs,
        k_issuer,
        k_user,
        max_cert_length,
    )
}
