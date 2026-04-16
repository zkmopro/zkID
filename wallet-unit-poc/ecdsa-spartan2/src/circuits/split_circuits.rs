//! Split circuit marker types (Phase 2 cert-chain + device-sig).
//!
//! Each marker implements [`RsaKeySize`] and plugs into [`Sha256RsaCircuit<T>`].

use super::cert::parse_cert_offsets;
use super::circuit::{RsaKeySize, Sha256RsaCircuit};
use super::encoding::{bigint_to_chunks, sha256_pad, sha256_padded_length, smt_fields_from_option, zero_pad_to_u64};

#[cfg(feature = "cert_chain_rs2048")]
witnesscalc_adapter::witness!(cert_chain_rs2048);
#[cfg(feature = "cert_chain_rs4096")]
witnesscalc_adapter::witness!(cert_chain_rs4096);
#[cfg(feature = "device_sig_rs2048")]
witnesscalc_adapter::witness!(device_sig_rs2048);

/// RSA-2048 issuer + RSA-2048 user (MOICA-G2).
#[derive(Debug, Clone, Copy)]
pub struct CertChainRsa2048;

/// RSA-4096 issuer + RSA-2048 user.
#[derive(Debug, Clone, Copy)]
pub struct CertChainRsa4096;

#[allow(unused_variables)]
impl RsaKeySize for CertChainRsa2048 {
    const RSA_K: usize = 17;
    const CIRCUIT_NAME: &'static str = "cert_chain_rs2048";
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
    const RSA_K: usize = 34;
    const CIRCUIT_NAME: &'static str = "cert_chain_rs4096";
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

/// Device signature -- always RSA-2048 (user keys).
#[derive(Debug, Clone, Copy)]
pub struct DeviceSigRsa2048;

/// ceil(MAX_MESSAGE_LENGTH / 31) -- packed-tbs output field count.
const PACKED_TBS_FIELDS: usize = (1536 + 30) / 31;

#[allow(unused_variables)]
impl RsaKeySize for DeviceSigRsa2048 {
    const RSA_K: usize = 17;
    const CIRCUIT_NAME: &'static str = "device_sig_rs2048";
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

pub type CertChainCircuit = Sha256RsaCircuit<CertChainRsa2048>;
pub type CertChainRs4096Circuit = Sha256RsaCircuit<CertChainRsa4096>;
pub type DeviceSigCircuit = Sha256RsaCircuit<DeviceSigRsa2048>;

use base64::Engine as _;
use der::Encode;
use num_bigint::BigUint;
use rsa::{pkcs8::DecodePublicKey, traits::PublicKeyParts, RsaPublicKey};
use sha2::{Digest, Sha256};
use x509_cert::Certificate;

const RSA_N: usize = 121;
pub const MAX_CERT_CHAIN_LENGTH: usize = 1536;
const MAX_MESSAGE_LENGTH: usize = 1536;
const MAX_SUBJECT_DN_LENGTH: usize = 128;
const SMT_DEPTH: usize = 128;

/// Build CertChain (Circuit A) + DeviceSig (Circuit B) input JSON values.
///
/// `pk_blind` = `SHA-256(user_pk_bytes || tbs || "zkID/pk-commit/v1")` -- using
/// `tbs` as the session-specific component provides per-session freshness.
pub fn generate_split_inputs(
    user_cert: &Certificate,
    issuer_cert: &Certificate,
    user_signature_b64: &str,
    tbs: &[u8],
    serial_hex: &str,
    smt_inputs: Option<&crate::smt_client::SmtCircuitInputs>,
    k_issuer: usize,
    k_user: usize,
    max_cert_length: usize,
) -> Result<(serde_json::Value, serde_json::Value), Box<dyn std::error::Error>> {
    let user_cert_der = user_cert.to_der()?;
    let user_cert_tbs_der = user_cert.tbs_certificate.to_der()?;
    let user_offsets = parse_cert_offsets(&user_cert_der)?;
    let user_subject_der = user_cert.tbs_certificate.subject.to_der()?;

    let user_spki_der = user_cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()?;
    let user_rsa_pub = RsaPublicKey::from_public_key_der(&user_spki_der)?;
    let user_modulus = BigUint::from_bytes_be(&user_rsa_pub.n().to_bytes_be());
    let user_pk_limbs = bigint_to_chunks(&user_modulus, k_user, RSA_N);

    let issuer_spki_der = issuer_cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()?;
    let issuer_rsa_pub = RsaPublicKey::from_public_key_der(&issuer_spki_der)?;
    let issuer_modulus = BigUint::from_bytes_be(&issuer_rsa_pub.n().to_bytes_be());
    let issuer_rsa_modulus = bigint_to_chunks(&issuer_modulus, k_issuer, RSA_N);

    let issuer_sig_bytes = user_cert.signature.raw_bytes();
    let issuer_sig_biguint = BigUint::from_bytes_be(issuer_sig_bytes);
    let issuer_rsa_signature = bigint_to_chunks(&issuer_sig_biguint, k_issuer, RSA_N);

    let user_sig_bytes =
        base64::engine::general_purpose::STANDARD.decode(user_signature_b64)?;
    let user_sig_biguint = BigUint::from_bytes_be(&user_sig_bytes);
    let user_rsa_signature = bigint_to_chunks(&user_sig_biguint, k_user, RSA_N);

    let tbs_padded: Vec<String> = sha256_pad(tbs, MAX_MESSAGE_LENGTH)
        .iter()
        .map(|b| b.to_string())
        .collect();
    let tbs_padded_len = sha256_padded_length(tbs.len());
    let issuer_tbs_padded: Vec<String> =
        sha256_pad(&user_cert_tbs_der, max_cert_length)
            .iter()
            .map(|b| b.to_string())
            .collect();
    let issuer_tbs_padded_len = sha256_padded_length(user_cert_tbs_der.len());

    let user_pk_bytes = user_rsa_pub.n().to_bytes_be();
    let mut hasher = Sha256::new();
    hasher.update(&user_pk_bytes);
    hasher.update(tbs);
    hasher.update(b"zkID/pk-commit/v1");
    let pk_blind_hash = hasher.finalize();
    let pk_blind = BigUint::from_bytes_be(&pk_blind_hash).to_string();

    let serial_decimal = BigUint::parse_bytes(serial_hex.as_bytes(), 16)
        .map(|n| n.to_string())
        .unwrap_or_else(|| "0".to_string());

    let (smt_root, smt_serial, smt_siblings, smt_old_key, smt_old_value, smt_is_old0) =
        smt_fields_from_option(smt_inputs, serial_decimal, SMT_DEPTH);

    let cert_chain_json = serde_json::json!({
        "user_cert_zero_padded": zero_pad_to_u64(&user_cert_der, max_cert_length),
        "actual_user_cert_length": user_cert_der.len(),
        "user_modulus_offset": user_offsets.modulus_offset,
        "user_modulus_tag_offset": user_offsets.modulus_tag_offset,
        "subject_dn": zero_pad_to_u64(&user_subject_der, MAX_SUBJECT_DN_LENGTH),
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
        "pk_blind": &pk_blind,
    });

    let device_sig_json = serde_json::json!({
        "tbs": tbs_padded,
        "tbs_length": tbs_padded_len,
        "user_pk_limbs": user_pk_limbs,
        "user_rsa_signature": user_rsa_signature,
        "pk_blind": pk_blind,
    });

    Ok((cert_chain_json, device_sig_json))
}
