//! Split circuit marker types for Phase 2 cert-chain + device-sig architecture.
//!
//! These implement [`RsaKeySize`] so they plug into the existing
//! [`Sha256RsaCircuit<T>`] generic and its SpartanCircuit impl — no new
//! circuit struct needed.

use super::sha256rsa_circuit::RsaKeySize;

// ── witnesscalc-generated witness functions ─────────────────────────────────
// Each macro produces a `{name}_witness(json: &str) -> Result<Vec<u8>>` function
// that calls the compiled C++ witness calculator at `../circom/build/cpp/{name}.*`.

#[cfg(feature = "cert_chain_rs2048")]
witnesscalc_adapter::witness!(cert_chain_rs2048);
#[cfg(feature = "cert_chain_rs4096")]
witnesscalc_adapter::witness!(cert_chain_rs4096);
#[cfg(feature = "device_sig_rs2048")]
witnesscalc_adapter::witness!(device_sig_rs2048);

// ── Cert chain Circuit A ────────────────────────────────────────────────────

/// Marker for CertChainRSA256 with RSA-2048 issuer + RSA-2048 user (MOICA-G2).
#[derive(Debug, Clone, Copy)]
pub struct CertChainRsa2048;

/// Marker for CertChainRSA256 with RSA-4096 issuer + RSA-2048 user (MOICA-G3).
#[derive(Debug, Clone, Copy)]
pub struct CertChainRsa4096;

#[allow(unused_variables)]
impl RsaKeySize for CertChainRsa2048 {
    /// k_issuer = 17 limbs (RSA-2048). User key is also 2048-bit.
    const RSA_K: usize = 17;
    const CIRCUIT_NAME: &'static str = "cert_chain_rs2048";
    /// Public signals: issuer_rsa_modulus[17] + smtRoot + serialNumber
    ///                 + subject_dn_hash(output) + pk_commit(output)
    const NUM_PUBLIC: usize = 21;
    const PROVING_KEY: &'static str = "cert_chain_rs2048_proving.key";
    const VERIFYING_KEY: &'static str = "cert_chain_rs2048_verifying.key";
    const PROOF: &'static str = "cert_chain_rs2048_proof.bin";
    const WITNESS: &'static str = "cert_chain_rs2048_witness.bin";
    const INSTANCE: &'static str = "cert_chain_rs2048_instance.bin";

    fn generate_witness_bytes(json: &str) -> Result<Vec<u8>, String> {
        #[cfg(feature = "cert_chain_rs2048")]
        return cert_chain_rs2048_witness(json).map_err(|e| e.to_string());
        #[cfg(not(feature = "cert_chain_rs2048"))]
        Err("Feature `cert_chain_rs2048` is not enabled".to_string())
    }
}

#[allow(unused_variables)]
impl RsaKeySize for CertChainRsa4096 {
    /// k_issuer = 34 limbs (RSA-4096 issuer key). User key is still 2048-bit,
    /// but the public input `issuer_rsa_modulus` is 34 limbs.
    const RSA_K: usize = 34;
    const CIRCUIT_NAME: &'static str = "cert_chain_rs4096";
    /// Public signals: issuer_rsa_modulus[34] + smtRoot + serialNumber
    ///                 + subject_dn_hash(output) + pk_commit(output)
    const NUM_PUBLIC: usize = 38;
    const PROVING_KEY: &'static str = "cert_chain_rs4096_proving.key";
    const VERIFYING_KEY: &'static str = "cert_chain_rs4096_verifying.key";
    const PROOF: &'static str = "cert_chain_rs4096_proof.bin";
    const WITNESS: &'static str = "cert_chain_rs4096_witness.bin";
    const INSTANCE: &'static str = "cert_chain_rs4096_instance.bin";

    fn generate_witness_bytes(json: &str) -> Result<Vec<u8>, String> {
        #[cfg(feature = "cert_chain_rs4096")]
        return cert_chain_rs4096_witness(json).map_err(|e| e.to_string());
        #[cfg(not(feature = "cert_chain_rs4096"))]
        Err("Feature `cert_chain_rs4096` is not enabled".to_string())
    }
}

// ── Device signature Circuit B ──────────────────────────────────────────────

/// Marker for DeviceSigRSA256 — always RSA-2048 (user keys are always 2048-bit).
#[derive(Debug, Clone, Copy)]
pub struct DeviceSigRsa2048;

/// Packed-tbs output field count: `ceil(1536 / 31) = 50`.
/// (`maxMessageLength` is 1536 in both cert_chain and device_sig during Phase 2;
/// Phase 3 will tighten device_sig's maxTbsLen to ~256, reducing this.)
const PACKED_TBS_FIELDS: usize = (1536 + 30) / 31;

#[allow(unused_variables)]
impl RsaKeySize for DeviceSigRsa2048 {
    /// User key is always RSA-2048: k = 17 limbs.
    const RSA_K: usize = 17;
    const CIRCUIT_NAME: &'static str = "device_sig_rs2048";
    /// Public signals: pk_commit(output) + packed_tbs[50](output)
    const NUM_PUBLIC: usize = 1 + PACKED_TBS_FIELDS;
    const PROVING_KEY: &'static str = "device_sig_rs2048_proving.key";
    const VERIFYING_KEY: &'static str = "device_sig_rs2048_verifying.key";
    const PROOF: &'static str = "device_sig_rs2048_proof.bin";
    const WITNESS: &'static str = "device_sig_rs2048_witness.bin";
    const INSTANCE: &'static str = "device_sig_rs2048_instance.bin";

    fn generate_witness_bytes(json: &str) -> Result<Vec<u8>, String> {
        #[cfg(feature = "device_sig_rs2048")]
        return device_sig_rs2048_witness(json).map_err(|e| e.to_string());
        #[cfg(not(feature = "device_sig_rs2048"))]
        Err("Feature `device_sig_rs2048` is not enabled".to_string())
    }
}

// ── Type aliases ────────────────────────────────────────────────────────────

use super::sha256rsa_circuit::{Rsa2048, Sha256RsaCircuit};

/// Cert-chain proof (Circuit A) for MOICA-G2 (RSA-2048 issuer + 2048 user).
pub type CertChainCircuit = Sha256RsaCircuit<CertChainRsa2048>;
/// Cert-chain proof (Circuit A) for MOICA-G3 (RSA-4096 issuer + 2048 user).
pub type CertChainFidoCircuit = Sha256RsaCircuit<CertChainRsa4096>;
/// Device-signature proof (Circuit B) — always RSA-2048 (user keys).
pub type DeviceSigCircuit = Sha256RsaCircuit<DeviceSigRsa2048>;

// ── Split input generation ──────────────────────────────────────────────────

use base64::Engine as _;
use der::Encode;
use num_bigint::BigUint;
use rsa::{pkcs8::DecodePublicKey, traits::PublicKeyParts, RsaPublicKey};
use sha2::{Digest, Sha256};
use x509_cert::Certificate;

const RSA_N: usize = 121;
const MAX_MESSAGE_LENGTH: usize = 1536;
const MAX_SUBJECT_DN_LENGTH: usize = 128;
const SMT_DEPTH: usize = 128;

/// Generate split circuit input JSONs for CertChain (Circuit A) + DeviceSig
/// (Circuit B).
///
/// Accepts already-parsed cert data (from HiPKI client or test fixtures) and
/// produces two JSON values. The caller writes them to the appropriate paths.
///
/// `pk_blind` is derived deterministically as:
///   `SHA-256(user_pk_bytes ‖ tbs ‖ "zkID/pk-commit/v1")` (decimal string)
///
/// Using `tbs` as the session-specific component ensures per-session freshness
/// without requiring a separate session_id parameter.
pub fn generate_split_inputs(
    user_cert: &Certificate,
    issuer_cert: &Certificate,
    user_signature_b64: &str,
    tbs: &[u8],
    serial_hex: &str,
    smt_inputs: Option<&crate::smt_client::SmtCircuitInputs>,
    k_issuer: usize,
    k_user: usize,
) -> Result<(serde_json::Value, serde_json::Value), Box<dyn std::error::Error>> {
    // Alias for calling pub(crate) static methods (type param is unused by these)
    type S = Sha256RsaCircuit<Rsa2048>;

    let zero_pad = |bytes: &[u8], length: usize| -> Vec<u64> {
        assert!(
            bytes.len() <= length,
            "Data too large: {} > {}",
            bytes.len(),
            length
        );
        let mut v: Vec<u64> = bytes.iter().map(|&b| b as u64).collect();
        v.resize(length, 0);
        v
    };

    // --- Parse cert DER data ---
    let user_cert_der = user_cert.to_der()?;
    let user_cert_tbs_der = user_cert.tbs_certificate.to_der()?;
    let user_offsets = S::parse_cert_offsets(&user_cert_der)?;
    let user_subject_der = user_cert.tbs_certificate.subject.to_der()?;

    // --- Extract user's RSA public key (for DeviceSig input + pk_blind) ---
    let user_spki_der = user_cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()?;
    let user_rsa_pub = RsaPublicKey::from_public_key_der(&user_spki_der)?;
    let user_modulus = BigUint::from_bytes_be(&user_rsa_pub.n().to_bytes_be());
    let user_pk_limbs = S::bigint_to_chunks(&user_modulus, k_user, RSA_N);

    // --- Extract issuer modulus + issuer's signature on user cert ---
    let issuer_spki_der = issuer_cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()?;
    let issuer_rsa_pub = RsaPublicKey::from_public_key_der(&issuer_spki_der)?;
    let issuer_modulus = BigUint::from_bytes_be(&issuer_rsa_pub.n().to_bytes_be());
    let issuer_rsa_modulus = S::bigint_to_chunks(&issuer_modulus, k_issuer, RSA_N);

    let issuer_sig_bytes = user_cert.signature.raw_bytes();
    let issuer_sig_biguint = BigUint::from_bytes_be(issuer_sig_bytes);
    let issuer_rsa_signature = S::bigint_to_chunks(&issuer_sig_biguint, k_issuer, RSA_N);

    // --- User's device signature on tbs ---
    let user_sig_bytes =
        base64::engine::general_purpose::STANDARD.decode(user_signature_b64)?;
    let user_sig_biguint = BigUint::from_bytes_be(&user_sig_bytes);
    let user_rsa_signature = S::bigint_to_chunks(&user_sig_biguint, k_user, RSA_N);

    // --- SHA-256 pad the messages ---
    let tbs_padded: Vec<String> = S::sha256_pad(tbs, MAX_MESSAGE_LENGTH)
        .iter()
        .map(|b| b.to_string())
        .collect();
    let tbs_padded_len = S::sha256_padded_length(tbs.len());
    let issuer_tbs_padded: Vec<String> =
        S::sha256_pad(&user_cert_tbs_der, MAX_MESSAGE_LENGTH)
            .iter()
            .map(|b| b.to_string())
            .collect();
    let issuer_tbs_padded_len = S::sha256_padded_length(user_cert_tbs_der.len());

    // --- pk_blind = SHA-256(user_pk_bytes ‖ tbs ‖ "zkID/pk-commit/v1") ---
    let user_pk_bytes = user_rsa_pub.n().to_bytes_be();
    let mut hasher = Sha256::new();
    hasher.update(&user_pk_bytes);
    hasher.update(tbs);
    hasher.update(b"zkID/pk-commit/v1");
    let pk_blind_hash = hasher.finalize();
    let pk_blind = BigUint::from_bytes_be(&pk_blind_hash).to_string();

    // --- Serial number ---
    let serial_decimal = BigUint::parse_bytes(serial_hex.as_bytes(), 16)
        .map(|n| n.to_string())
        .unwrap_or_else(|| "0".to_string());

    // --- SMT fields (use provided values or zero defaults) ---
    let (smt_root, smt_serial, smt_siblings, smt_old_key, smt_old_value, smt_is_old0) =
        match smt_inputs {
            Some(smt) => (
                smt.smt_root.clone(),
                smt.serial_number.clone(),
                smt.smt_siblings.clone(),
                smt.smt_old_key.clone(),
                smt.smt_old_value.clone(),
                smt.smt_is_old0.clone(),
            ),
            None => {
                let zeros = vec!["0".to_string(); SMT_DEPTH];
                (
                    "0".to_string(),
                    serial_decimal,
                    zeros,
                    "0".to_string(),
                    "0".to_string(),
                    "1".to_string(),
                )
            }
        };

    // === CertChain JSON (Circuit A) ===
    let cert_chain_json = serde_json::json!({
        "user_cert_zero_padded": zero_pad(&user_cert_der, MAX_MESSAGE_LENGTH),
        "actual_user_cert_length": user_cert_der.len(),
        "user_modulus_offset": user_offsets.modulus_offset,
        "user_modulus_tag_offset": user_offsets.modulus_tag_offset,
        "subject_dn": zero_pad(&user_subject_der, MAX_SUBJECT_DN_LENGTH),
        "subject_dn_offset": user_offsets.subject_dn_offset,
        "subject_dn_length": user_offsets.subject_dn_length,
        "serial_number_offset": user_offsets.serial_number_offset,
        "issuer_tbs": issuer_tbs_padded,
        "issuer_tbs_length": issuer_tbs_padded_len,
        "actual_issuer_tbs_length": user_cert_tbs_der.len(),
        "issuer_rsa_modulus": issuer_rsa_modulus,
        "issuer_rsa_signature": issuer_rsa_signature,
        "smtRoot": smt_root,
        "serialNumber": smt_serial,
        "smtSiblings": smt_siblings,
        "smtOldKey": smt_old_key,
        "smtOldValue": smt_old_value,
        "smtIsOld0": smt_is_old0,
        "pk_blind": pk_blind.clone(),
    });

    // === DeviceSig JSON (Circuit B) ===
    let device_sig_json = serde_json::json!({
        "tbs": tbs_padded,
        "tbs_length": tbs_padded_len,
        "user_pk_limbs": user_pk_limbs,
        "user_rsa_signature": user_rsa_signature,
        "pk_blind": pk_blind,
    });

    Ok((cert_chain_json, device_sig_json))
}
