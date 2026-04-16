//! RS256 Circuit implementation for certificate chain verification.
//!
//! This circuit verifies a certificate chain (user cert signed by issuer CA)
//! using RSA-SHA256 signatures, extracts the user's public key from the cert DER
//! in-circuit, and proves non-revocation via a Sparse Merkle Tree.

use crate::{paths::PathConfig, utils::parse_witness, Scalar, E};
use base64::Engine;
use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use crate::reader::load_r1cs_mmap;
use circom_scotia::synthesize;
use const_oid::db::rfc4519::*;
use der::Encode;
use der::{
    asn1::{PrintableStringRef, Utf8StringRef},
    Decode,
};
use ff::Field;
use num_bigint::BigUint;
use rsa::pkcs8::DecodePublicKey;
use rsa::signature::Verifier;
use rsa::traits::PublicKeyParts;
use rsa::{pkcs1v15::VerifyingKey, RsaPublicKey};
use serde::Deserialize;
use sha2::Sha256;
use spartan2::traits::circuit::SpartanCircuit;
use std::{
    any::type_name,
    fs::File,
    io::Read,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Instant,
};
use tracing::info;
use x509_cert::{
    der::{Length, Reader, SliceReader, Tag, TagNumber},
    Certificate,
};

// ── RSA key-size marker trait ─────────────────────────────────────────────────

/// Marker trait that carries all compile-time constants and the witness-generation
/// function for a specific RSA key size.
///
/// Implement this trait on a zero-sized marker type (e.g. [`Rsa2048`], [`Rsa4096`])
/// and use it as the type parameter of [`Sha256RsaCircuit<T>`].
pub trait RsaKeySize: Send + Sync + Clone + 'static {
    /// Number of 121-bit limbs that represent the RSA modulus/signature.
    /// (`k` in `RSAVerifier65537(121, k)`)
    const RSA_K: usize;
    /// Circomkit circuit name used to locate the R1CS / witness files.
    const CIRCUIT_NAME: &'static str;
    /// Number of public witness values the circuit exposes to Spartan.
    const NUM_PUBLIC: usize;
    // Artifact file names (kept here so the type carries its own paths).
    const PROVING_KEY: &'static str;
    const VERIFYING_KEY: &'static str;
    const PROOF: &'static str;
    const WITNESS: &'static str;
    const INSTANCE: &'static str;
    /// Call the witnesscalc-generated witness function for this key size.
    fn generate_witness_bytes(json: &str) -> Result<Vec<u8>, String>;
}

/// Generic RSA-SHA256 circuit backed by Spartan2.
///
/// The type parameter `T` selects the circuit variant at compile time.
/// See `split_circuits` module for available marker types (e.g. `CertChainRsa2048`).
#[derive(Clone)]
pub struct Sha256RsaCircuit<T: RsaKeySize> {
    /// Path configuration for resolving file paths
    path_config: PathConfig,
    /// Optional override for input JSON path
    input_path: Option<PathBuf>,
    /// Cached witness for reuse across synthesize and public_values calls
    cached_witness: Arc<Mutex<Option<Vec<Scalar>>>>,
    _marker: std::marker::PhantomData<T>,
}

impl<T: RsaKeySize> std::fmt::Debug for Sha256RsaCircuit<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sha256RsaCircuit")
            .field("circuit", &T::CIRCUIT_NAME)
            .field("path_config", &self.path_config)
            .field("input_path", &self.input_path)
            .finish()
    }
}

/// Response from HiPKI `/sign` API with `signatureType: "PKCS1"`.
#[derive(Deserialize)]
pub struct CardSignResponse {
    #[serde(rename = "cardSN")]
    pub card_sn: String,
    pub certb64: String,
    #[serde(rename = "func")]
    _func: String,
    #[serde(rename = "last_error")]
    _last_error: i32,
    #[serde(rename = "ret_code")]
    _ret_code: i32,
    pub signature: String,
    #[serde(rename = "version")]
    _version: String,
}

/// Response from RS4096 sign API (4096-bit issuer CA path).
#[derive(Deserialize)]
pub struct Rs4096SignResponse {
    pub error_code: String,
    pub error_message: String,
    pub result: Rs4096SignResult,
}

#[derive(Deserialize)]
pub struct Rs4096SignResult {
    pub hashed_id_num: String,
    pub signed_response: String,
    pub idp_checksum: String,
    pub cert: String,
}

/// Intermediate result from per-certificate RSA input generation.
pub(crate) struct RsaCircuitInput {
    pub(crate) message: Vec<String>,
    pub(crate) message_length: usize,
    pub(crate) rsa_modulus: Vec<String>,
    pub(crate) rsa_signature: Vec<String>,
}

/// SMT JSON fields: either cloned from a fetched proof or deterministic defaults.
pub(crate) fn smt_fields_from_option(
    smt_inputs: Option<&crate::smt_client::SmtCircuitInputs>,
    serial_decimal: String,
    sibling_depth: usize,
) -> (
    String,
    String,
    Vec<String>,
    String,
    String,
    String,
) {
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
            let zeros = vec!["0".to_string(); sibling_depth];
            (
                "0".to_string(),
                serial_decimal,
                zeros,
                "0".to_string(),
                "0".to_string(),
                "1".to_string(),
            )
        }
    }
}

/// DER INTEGER serial bytes to hex with leading zero bytes stripped.
pub fn serial_bytes_to_hex_trimmed(serial_bytes: &[u8]) -> String {
    let trimmed: Vec<u8> = serial_bytes
        .iter()
        .skip_while(|&&b| b == 0)
        .copied()
        .collect();
    hex::encode(if trimmed.is_empty() {
        serial_bytes
    } else {
        &trimmed
    })
}

/// Zero-pad `bytes` to `length` elements as `u64` wire values (Circom input style).
pub(crate) fn zero_pad_to_u64(bytes: &[u8], length: usize) -> Vec<u64> {
    assert!(
        bytes.len() <= length,
        "byte length {} exceeds maximum {}",
        bytes.len(),
        length
    );
    let mut v: Vec<u64> = bytes.iter().map(|&b| b as u64).collect();
    v.resize(length, 0);
    v
}

/// DER byte offsets for in-circuit modulus extraction.

#[derive(Debug)]
pub(crate) struct CertOffsets {
    pub(crate) modulus_offset: usize,       // first real modulus byte (after sign byte)
    pub(crate) modulus_tag_offset: usize,   // where 0x02 INTEGER tag is
    pub(crate) subject_dn_offset: usize,    // where subject DN starts
    pub(crate) subject_dn_length: usize,    // length of subject DN
    pub(crate) serial_number_offset: usize, // where serial number starts
}
// === HiPKI /pkcs11info?withcert=true response structs ===

/// A certificate entry from the PKCS#11 token.
#[derive(Deserialize, Debug)]
pub struct Pkcs11CertEntry {
    pub certb64: String,
    pub label: String,
    #[serde(default)]
    pub usage: Option<String>,
    #[serde(default)]
    pub sn: Option<String>,
    #[serde(rename = "subjectDN", default)]
    pub subject_dn: Option<String>,
    #[serde(rename = "issuerDN", default)]
    pub issuer_dn: Option<String>,
}

/// Token info containing certificates and keys.
#[derive(Deserialize, Debug)]
pub struct Pkcs11TokenInfo {
    #[serde(default)]
    pub certs: Vec<Pkcs11CertEntry>,
    #[serde(rename = "serialNumber", default)]
    pub serial_number: Option<String>,
}

/// A PKCS#11 slot with optional token.
#[derive(Deserialize, Debug)]
pub struct Pkcs11Slot {
    #[serde(default)]
    pub token: Option<Pkcs11TokenInfo>,
}

/// Response from HiPKI `/pkcs11info?withcert=true` API.
#[derive(Deserialize, Debug)]
pub struct Pkcs11InfoResponse {
    pub slots: Vec<Pkcs11Slot>,
}

impl<T: RsaKeySize> Default for Sha256RsaCircuit<T> {
    fn default() -> Self {
        Self {
            path_config: PathConfig::default(),
            input_path: None,
            cached_witness: Arc::new(Mutex::new(None)),
            _marker: std::marker::PhantomData,
        }
    }
}

impl<T: RsaKeySize> Sha256RsaCircuit<T> {
    /// Create a new Sha256RsaCircuit with PathConfig and optional input path override.
    pub fn new(path_config: PathConfig, input_path: Option<PathBuf>) -> Self {
        Self {
            path_config,
            input_path,
            cached_witness: Arc::new(Mutex::new(None)),
            _marker: std::marker::PhantomData,
        }
    }

    /// Create from just an input path (for backwards compatibility).
    /// Uses development PathConfig.
    pub fn with_input_path<P: Into<Option<PathBuf>>>(path: P) -> Self {
        Self {
            path_config: PathConfig::development(),
            input_path: path.into(),
            cached_witness: Arc::new(Mutex::new(None)),
            _marker: std::marker::PhantomData,
        }
    }

    /// Resolve the input JSON path using PathConfig.
    fn resolve_input_json(&self) -> PathBuf {
        self.input_path
            .as_ref()
            .map(|p| self.path_config.resolve(p))
            .unwrap_or_else(|| self.path_config.input_json(T::CIRCUIT_NAME))
    }

    /// Get the R1CS file path.
    fn r1cs_path(&self) -> PathBuf {
        self.path_config.r1cs_path(T::CIRCUIT_NAME)
    }

    // === Certificate extraction from PKCS#11 response ===

    /// Extract the issuer (CA) certificate from a pkcs11info response.
    /// Looks for the cert with label "CA Cert" in the first slot's token.
    pub fn extract_issuer_cert(
        pkcs11info: &Pkcs11InfoResponse,
    ) -> Result<Certificate, Box<dyn std::error::Error>> {
        let certs = pkcs11info
            .slots
            .first()
            .and_then(|s| s.token.as_ref())
            .map(|t| &t.certs)
            .ok_or("No token found in pkcs11info response")?;

        let ca_entry = certs
            .iter()
            .find(|c| c.label == "CA Cert")
            .ok_or("No cert with label 'CA Cert' found in pkcs11info response")?;

        let der = base64::engine::general_purpose::STANDARD.decode(&ca_entry.certb64)?;
        Ok(Certificate::from_der(&der)?)
    }

    /// Verify that the issuer certificate signed the user certificate.
    fn verify_issuer_signature(
        issuer_cert: &Certificate,
        user_cert: &Certificate,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let spki_der = issuer_cert
            .tbs_certificate
            .subject_public_key_info
            .to_der()?;
        let rsa_pub = RsaPublicKey::from_public_key_der(&spki_der)?;

        let sig_bytes = user_cert.signature.raw_bytes();
        let sig = rsa::pkcs1v15::Signature::try_from(sig_bytes)?;

        let user_tbs_der = user_cert.tbs_certificate.to_der()?;

        let verifying_key = VerifyingKey::<Sha256>::new(rsa_pub);
        verifying_key.verify(&user_tbs_der, &sig)?;
        Ok(())
    }

    /// Verify the card's raw PKCS#1 signature over the TBS data.
    fn verify_user_cert_signature(
        user_cert: &Certificate,
        user_signature_b64: &str,
        tbs: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let spki_der = user_cert.tbs_certificate.subject_public_key_info.to_der()?;
        let rsa_pub = RsaPublicKey::from_public_key_der(&spki_der)?;

        let sig_bytes = base64::engine::general_purpose::STANDARD.decode(user_signature_b64)?;
        let sig = rsa::pkcs1v15::Signature::try_from(sig_bytes.as_slice())?;

        let verifying_key = VerifyingKey::<Sha256>::new(rsa_pub);
        verifying_key.verify(tbs, &sig)?;
        Ok(())
    }

    pub fn fetch_cert_from_file(path: &str) -> Result<Certificate, Box<dyn std::error::Error>> {
        let bytes = std::fs::read(path)?;
        let cert = Certificate::from_der(&bytes)?;
        Ok(cert)
    }

    /// Generate user certificate from certb64
    pub fn generate_user_cert_from_certb64(
        certb64: &str,
    ) -> Result<Certificate, Box<dyn std::error::Error>> {
        let cert_der = base64::engine::general_purpose::STANDARD.decode(certb64)?;
        let user_cert = Certificate::from_der(&cert_der)?;
        Ok(user_cert)
    }

    // === Main entry points for circuit input generation ===

    /// Generate circuit input JSON from a parsed CardSignResponse.
    ///
    /// This is the primary entry point — accepts already-parsed API responses
    /// (from HiPKI client or test fixtures).
    pub fn generate_input(
        user_cert: &Certificate,
        user_signature_b64: &str,
        tbs: &[u8],
        issuer_cert: &Certificate,
        smt_server: Option<&str>,
        issuer_id: &str,
        output_path: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let subject_cn = Self::get_attr(&user_cert.tbs_certificate.subject, COMMON_NAME);
        let serial_hex =
            serial_bytes_to_hex_trimmed(user_cert.tbs_certificate.serial_number.as_bytes());
        info!(subject = %subject_cn, serial = %serial_hex, "Parsed user certificate");

        Self::verify_issuer_signature(issuer_cert, &user_cert)?;
        info!("Issuer signature verified on user cert");

        Self::verify_user_cert_signature(user_cert, user_signature_b64, tbs)?;
        info!(user_cert = %user_cert.tbs_certificate.subject, "User cert signature verified");

        let smt_inputs = if let Some(server_url) = smt_server {
            info!(url = %server_url, "Fetching SMT proof");
            Some(crate::smt_client::fetch_smt_proof(
                server_url,
                issuer_id,
                &serial_hex,
                128,
            )?)
        } else {
            None
        };

        let user_cert_tbs_der = user_cert.tbs_certificate.to_der()?;
        let issuer_sig_on_user_cert =
            base64::engine::general_purpose::STANDARD.encode(user_cert.signature.raw_bytes());

        let circuit_input = Self::generate_circuit_input(
            &user_cert,
            issuer_cert,
            &user_signature_b64,
            &issuer_sig_on_user_cert,
            tbs,
            &user_cert_tbs_der,
            &serial_hex,
            smt_inputs.as_ref(),
        )?;

        if let Some(parent) = std::path::Path::new(output_path).parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(output_path, serde_json::to_string_pretty(&circuit_input)?)?;
        info!(path = %output_path, "Circuit input written");
        Ok(())
    }

    /// Convenience wrapper that reads a sign response from a JSON file.
    /// Used for default mode with bundled test fixtures.
    pub fn generate_input_from_file(
        response_path: &Path,
        tbs: &[u8],
        issuer_cert: &Certificate,
        smt_server: Option<&str>,
        issuer_id: &str,
        output_path: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let response_string = std::fs::read_to_string(response_path)?;
        let response: CardSignResponse = serde_json::from_str(&response_string)?;
        let user_cert = Self::generate_user_cert_from_certb64(&response.certb64)?;

        Self::generate_input(
            &user_cert,
            &response.signature,
            tbs,
            issuer_cert,
            smt_server,
            issuer_id,
            output_path,
        )
    }

    pub fn generate_input_from_rs4096_file(
        response_path: &Path,
        tbs: &[u8],
        issuer_cert: &Certificate,
        smt_server: Option<&str>,
        issuer_id: &str,
        output_path: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let response_string = std::fs::read_to_string(response_path)?;
        let response: Rs4096SignResponse = serde_json::from_str(&response_string)?;
        let user_cert = Self::generate_user_cert_from_certb64(&response.result.cert)?;

        Self::generate_input(
            &user_cert,
            &response.result.signed_response,
            tbs,
            issuer_cert,
            smt_server,
            issuer_id,
            output_path,
        )
    }

    // === Per-certificate RSA input generation ===

    /// Generate RSA circuit input for a single certificate.
    /// Extracts the modulus from the cert and chunks both modulus and signature.
    pub(crate) fn generate_rsa_circuit_input(
        cert: &Certificate,
        signature_b64: &str,
        original_data: &[u8],
    ) -> Result<RsaCircuitInput, Box<dyn std::error::Error>> {
        const MAX_MESSAGE_LENGTH: usize = 1536;
        const RSA_N: usize = 121;

        let spki_der = cert.tbs_certificate.subject_public_key_info.to_der()?;
        let rsa_pub = RsaPublicKey::from_public_key_der(&spki_der)?;
        let modulus = BigUint::from_bytes_be(&rsa_pub.n().to_bytes_be());
        let rsa_modulus = Self::bigint_to_chunks(&modulus, T::RSA_K, RSA_N);

        let sig_bytes = base64::engine::general_purpose::STANDARD.decode(signature_b64)?;
        let sig_biguint = BigUint::from_bytes_be(&sig_bytes);
        let rsa_signature = Self::bigint_to_chunks(&sig_biguint, T::RSA_K, RSA_N);

        let message = Self::sha256_pad(original_data, MAX_MESSAGE_LENGTH);
        let padded_len = Self::sha256_padded_length(original_data.len());

        Ok(RsaCircuitInput {
            message: message.iter().map(|b| b.to_string()).collect(),
            message_length: padded_len,
            rsa_modulus,
            rsa_signature,
        })
    }

    // === Full circuit input assembly ===

    /// Combine user cert + issuer cert + SMT data into the full circuit input JSON.
    fn generate_circuit_input(
        user_cert: &Certificate,
        issuer_cert: &Certificate,
        user_signature_b64: &str,
        issuer_signature_b64: &str,
        user_tbs: &[u8],
        issuer_tbs: &[u8], // actually the user cert's TBS DER (what the issuer signed)
        serial_hex: &str,
        smt_inputs: Option<&crate::smt_client::SmtCircuitInputs>,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        const MAX_MESSAGE_LENGTH: usize = 1536;
        const MAX_SUBJECT_DN_LENGTH: usize = 128;

        let user_input = Self::generate_rsa_circuit_input(user_cert, user_signature_b64, user_tbs)?;
        let issuer_input =
            Self::generate_rsa_circuit_input(issuer_cert, issuer_signature_b64, issuer_tbs)?;

        let user_cert_der = user_cert.to_der()?;
        let user_offsets = Self::parse_cert_offsets(&user_cert_der)?;
        let user_subject_der = user_cert.tbs_certificate.subject.to_der()?;

        // Derive serial number as decimal string from hex
        let serial_decimal = BigUint::parse_bytes(serial_hex.as_bytes(), 16)
            .map(|n| n.to_string())
            .unwrap_or_else(|| "0".to_string());

        const SMT_SIBLING_DEPTH: usize = 128;
        let (smt_root, smt_serial, smt_siblings, smt_old_key, smt_old_value, smt_is_old0) =
            smt_fields_from_option(smt_inputs, serial_decimal, SMT_SIBLING_DEPTH);

        Ok(serde_json::json!({
            "tbs": user_input.message,
            "tbs_length": user_input.message_length,
            "issuer_tbs": issuer_input.message,
            "issuer_tbs_length": issuer_input.message_length,
            "actual_issuer_tbs_length": issuer_tbs.len(),
            "user_cert_zero_padded": zero_pad_to_u64(&user_cert_der, MAX_MESSAGE_LENGTH),
            "actual_user_cert_length": user_cert_der.len(),
            "user_modulus_offset": user_offsets.modulus_offset,
            "user_modulus_tag_offset": user_offsets.modulus_tag_offset,
            "subject_dn": zero_pad_to_u64(&user_subject_der, MAX_SUBJECT_DN_LENGTH),
            "subject_dn_offset": user_offsets.subject_dn_offset,
            "subject_dn_length": user_offsets.subject_dn_length,
            "serial_number_offset": user_offsets.serial_number_offset,
            "user_rsa_signature": user_input.rsa_signature,
            "issuer_rsa_modulus": issuer_input.rsa_modulus,
            "issuer_rsa_signature": issuer_input.rsa_signature,
            "smtRoot": smt_root,
            "serialNumber": smt_serial,
            "smtSiblings": smt_siblings,
            "smtOldKey": smt_old_key,
            "smtOldValue": smt_old_value,
            "smtIsOld0": smt_is_old0,
        }))
    }

    // === DER parsing helpers ===

    /// Find the RSA modulus and subject DN byte offsets in a DER-encoded certificate.
    pub(crate) fn parse_cert_offsets(der: &[u8]) -> Result<CertOffsets, Box<dyn std::error::Error>> {
        let (modulus_offset, modulus_tag_offset) = Self::find_modulus_offset(der)?;

        if der[modulus_tag_offset] != 0x02 {
            return Err(format!(
                "Modulus INTEGER tag wrong at {}: got 0x{:02x}",
                modulus_tag_offset, der[modulus_tag_offset]
            )
            .into());
        }

        let cert = Certificate::from_der(der)?;
        let subject_der = cert.tbs_certificate.subject.to_der()?;
        let subject_dn_offset =
            Self::find_subslice(der, &subject_der).ok_or("Subject DN not found in cert DER")?;
        let subject_dn_length = subject_der.len();

        // find trimmed bytes in cert_der — skips past tag+length automatically
        let tbs_der = Certificate::from_der(der)?.tbs_certificate.to_der()?;
        // find where TBS starts in the full cert_der
        let tbs_start = der
            .windows(tbs_der.len())
            .position(|w| w == tbs_der.as_slice())
            .ok_or("TBS not found in cert DER")?;
        // find serial offset within tbs_der
        let serial_offset_in_tbs = Self::find_serial_offset_in_tbs(&tbs_der)?;
        // final offset within full cert_der
        let serial_offset = tbs_start + serial_offset_in_tbs;

        Ok(CertOffsets {
            modulus_offset,
            modulus_tag_offset,
            subject_dn_offset,
            subject_dn_length,
            serial_number_offset: serial_offset,
        })
    }

    /// Returns (modulus_value_offset, integer_tag_offset) by navigating the SPKI structure.
    fn find_modulus_offset(der: &[u8]) -> Result<(usize, usize), Box<dyn std::error::Error>> {
        let cert = Certificate::from_der(der)?;
        let spki_der = cert.tbs_certificate.subject_public_key_info.to_der()?;

        let spki_abs = Self::find_subslice(der, &spki_der).ok_or("SPKI not found in cert DER")?;

        let mut pos = 0usize;

        // Skip outer SPKI SEQUENCE tag + length
        pos += 1;
        let (_, lb) = Self::read_der_len(&spki_der, pos);
        pos += lb;

        // Skip AlgorithmIdentifier SEQUENCE tag + length + content
        pos += 1;
        let (alg_len, alb) = Self::read_der_len(&spki_der, pos);
        pos += alb + alg_len;

        // Skip BIT STRING tag + length + unused-bits byte (0x00)
        pos += 1;
        let (_, blb) = Self::read_der_len(&spki_der, pos);
        pos += blb;
        pos += 1; // unused bits byte

        // Skip RSAPublicKey SEQUENCE tag + length
        pos += 1;
        let (_, slb) = Self::read_der_len(&spki_der, pos);
        pos += slb;

        // Now at INTEGER tag for modulus
        if spki_der[pos] != 0x02 {
            return Err(format!(
                "Expected INTEGER tag at spki pos {}, got 0x{:02x}",
                pos, spki_der[pos]
            )
            .into());
        }
        let tag_pos = pos;
        pos += 1;

        // Skip length field
        let (_mod_len, mlb) = Self::read_der_len(&spki_der, pos);
        pos += mlb;

        // Skip leading 0x00 sign byte if present
        if spki_der[pos] == 0x00 {
            pos += 1;
        }

        Ok((spki_abs + pos, spki_abs + tag_pos))
    }

    /// Read a DER length field. Returns (length_value, bytes_consumed).
    fn read_der_len(der: &[u8], pos: usize) -> (usize, usize) {
        if der[pos] & 0x80 == 0 {
            (der[pos] as usize, 1)
        } else {
            let num_len_bytes = (der[pos] & 0x7f) as usize;
            let value =
                (0..num_len_bytes).fold(0usize, |acc, i| (acc << 8) | der[pos + 1 + i] as usize);
            (value, 1 + num_len_bytes)
        }
    }

    /// Find first occurrence of needle in haystack.
    fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        if needle.is_empty() {
            return Some(0);
        }
        haystack.windows(needle.len()).position(|w| w == needle)
    }

    /// Compute the byte length of a DER header (tag byte + length encoding).
    fn header_len(header: &der::Header) -> usize {
        let tag_len = 1usize;
        let length_val: usize = header.length.try_into().unwrap();
        let length_encoding = if length_val < 128 {
            1 // short form
        } else if length_val < 256 {
            2 // 0x81 + 1 byte
        } else {
            3 // 0x82 + 2 bytes
        };
        tag_len + length_encoding
    }

    /// Find serial number offset in TBS DER using ASN.1 parser.
    fn find_serial_offset_in_tbs(tbs_der: &[u8]) -> Result<usize, Box<dyn std::error::Error>> {
        let mut r = SliceReader::new(tbs_der)?;

        // 1. Consume the outer SEQUENCE header (tag + length bytes)
        let seq_header = r.peek_header()?;
        assert_eq!(seq_header.tag, Tag::Sequence);
        let seq_header_len = Self::header_len(&seq_header);
        r.read_slice(seq_header_len.try_into()?)?; // advance past tag+length

        // 2. Skip optional [0] EXPLICIT version (tag 0xa0) if present
        let next = r.peek_header()?;
        if next.tag
            == (Tag::ContextSpecific {
                constructed: true,
                number: TagNumber::N0,
            })
        {
            // skip header + contents
            let skip: usize = Self::header_len(&next) + usize::try_from(next.length)?;
            r.read_slice(Length::new(skip as u16))?;
        }

        // 3. Now must be at INTEGER (serial number)
        let serial_header = r.peek_header()?;
        assert_eq!(serial_header.tag, Tag::Integer);

        let serial_header_len = Self::header_len(&serial_header);
        let tag_pos: usize = r.position().try_into()?;

        Ok(tag_pos + serial_header_len) // offset of serial value bytes
    }

    // === Utility functions ===

    pub(crate) fn bigint_to_chunks(n: &BigUint, count: usize, chunk_bits: usize) -> Vec<String> {
        let mask = (BigUint::from(1u64) << chunk_bits) - BigUint::from(1u64);
        let mut chunks = Vec::new();
        let mut val = n.clone();
        for _ in 0..count {
            let chunk = &val & &mask;
            chunks.push(chunk.to_string());
            val >>= chunk_bits;
        }
        chunks
    }

    pub(crate) fn sha256_pad(msg: &[u8], max_len: usize) -> Vec<u8> {
        let bit_len = (msg.len() as u64) * 8;
        let mut padded = msg.to_vec();
        padded.push(0x80);
        while padded.len() % 64 != 56 {
            padded.push(0);
        }
        padded.extend_from_slice(&bit_len.to_be_bytes());
        padded.resize(max_len, 0);
        padded
    }

    pub(crate) fn sha256_padded_length(original_len: usize) -> usize {
        let mut len = original_len + 1;
        while len % 64 != 56 {
            len += 1;
        }
        len + 8
    }

    fn get_attr(name: &x509_cert::name::Name, oid: const_oid::ObjectIdentifier) -> String {
        name.0
            .iter()
            .flat_map(|rdn| rdn.0.iter())
            .find(|attr| attr.oid == oid)
            .map(|attr| {
                if let Ok(s) = Utf8StringRef::try_from(&attr.value) {
                    s.as_str().to_string()
                } else if let Ok(s) = PrintableStringRef::try_from(&attr.value) {
                    s.as_str().to_string()
                } else {
                    String::from_utf8_lossy(attr.value.value()).to_string()
                }
            })
            .unwrap_or_default()
    }

    /// Generate witness for the RS256 circuit.
    pub fn generate_witness(&self) -> Result<Vec<Scalar>, SynthesisError> {
        let json_path = self.resolve_input_json();

        let mut file = File::open(&json_path).map_err(|e| {
            eprintln!("Failed to open input JSON at {:?}: {}", json_path, e);
            SynthesisError::AssignmentMissing
        })?;

        let mut json_string = String::new();
        file.read_to_string(&mut json_string).map_err(|e| {
            eprintln!("Failed to read input JSON: {}", e);
            SynthesisError::AssignmentMissing
        })?;

        // Generate witness using witnesscalc adapter.
        // Spawned on a dedicated thread with a large stack: the witnesscalc C++
        // library reallocates its internal buffer when the circuit is large
        // (sha256rsa4096 needs ~122 MB). On macOS, realloc() moves the
        // allocation and the library's stale interior pointers trigger SIGSEGV
        // on the main thread. A fresh thread with pre-committed virtual address
        // space makes realloc() more likely to grow in-place, avoiding the move.
        info!(
            "Generating witness using witnesscalc ({})...",
            T::CIRCUIT_NAME
        );
        let t0 = Instant::now();
        let witness_bytes = {
            let json_for_thread = json_string.clone();
            std::thread::Builder::new()
                .stack_size(256 * 1024 * 1024) // 256 MB
                .spawn(move || T::generate_witness_bytes(&json_for_thread))
                .map_err(|e| {
                    eprintln!("Failed to spawn witness thread: {e}");
                    SynthesisError::Unsatisfiable
                })?
                .join()
                .map_err(|_| {
                    eprintln!("Witness generation thread panicked");
                    SynthesisError::Unsatisfiable
                })?
                .map_err(|e| {
                    eprintln!("Witness generation failed: {e}");
                    SynthesisError::Unsatisfiable
                })?
        };
        info!("witnesscalc time: {} ms", t0.elapsed().as_millis());

        let witness = parse_witness(&witness_bytes)?;
        info!("witness generation completed: {} elements", witness.len());
        Ok(witness)
    }

    /// Get cached witness or generate and cache it.
    fn get_or_generate_witness(&self) -> Result<Vec<Scalar>, SynthesisError> {
        let mut cache = self.cached_witness.lock().unwrap();

        if let Some(ref witness) = *cache {
            return Ok(witness.clone());
        }

        let witness = self.generate_witness()?;
        *cache = Some(witness.clone());
        Ok(witness)
    }

    /// Pre-generate and cache the witness.
    /// Call this before memory-heavy operations (like setup) to avoid
    /// C++ witnesscalc allocation failures under memory pressure.
    pub fn warm_witness_cache(&self) -> Result<(), SynthesisError> {
        self.get_or_generate_witness()?;
        Ok(())
    }
}

impl<T: RsaKeySize> SpartanCircuit<E> for Sha256RsaCircuit<T> {
    fn synthesize<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
        _: &[AllocatedNum<Scalar>],
        _: &[AllocatedNum<Scalar>],
        _: Option<&[Scalar]>,
    ) -> Result<(), SynthesisError> {
        let cs_type = type_name::<CS>();
        let is_setup_phase = cs_type.contains("ShapeCS");

        if is_setup_phase {
            let r1cs_path = self.r1cs_path();
            let r1cs = load_r1cs_mmap(&r1cs_path)
                .expect("failed to load r1cs");
            synthesize(cs, r1cs, None)?;
            return Ok(());
        }

        // During prove, cs is SatisfyingAssignment whose enforce() is a no-op
        // (see Spartan2 src/bellpepper/solver.rs:70-78)
        // Allocate wires directly from the pre-computed witness instead.
        let witness = self.get_or_generate_witness()?;
        let num_inputs = T::NUM_PUBLIC + 1; // +1 for the constant-1 wire at index 0
        let num_aux = witness.len().saturating_sub(num_inputs);

        debug_assert!(
            witness.len() >= num_inputs,
            "witness too short: len={} but NUM_PUBLIC={} requires num_inputs={}",
            witness.len(),
            T::NUM_PUBLIC,
            num_inputs,
        );

        // Index 0 is the implicit constant-1 wire, so start at 1
        for i in 1..num_inputs {
            cs.alloc_input(|| format!("public_{i}"), || Ok(witness[i]))?;
        }
        for i in 0..num_aux {
            cs.alloc(|| format!("aux_{i}"), || Ok(witness[i + num_inputs]))?;
        }
        Ok(())
    }

    /// RS256 circuit has no shared values (single-stage, no device binding)
    fn shared<CS: ConstraintSystem<Scalar>>(
        &self,
        _cs: &mut CS,
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        // No shared values for single-stage RS256 circuit
        Ok(vec![])
    }

    /// RS256 circuit public inputs
    fn public_values(&self) -> Result<Vec<Scalar>, SynthesisError> {
        let num_public = T::NUM_PUBLIC;
        let witness = self.get_or_generate_witness().ok();

        let mut values = Vec::with_capacity(num_public);
        for idx in 1..=num_public {
            values.push(witness.as_ref().map(|w| w[idx]).unwrap_or(Scalar::ZERO));
        }
        Ok(values)
    }

    fn precommitted<CS: ConstraintSystem<Scalar>>(
        &self,
        _cs: &mut CS,
        _shared: &[AllocatedNum<Scalar>],
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        Ok(vec![])
    }

    fn num_challenges(&self) -> usize {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::split_circuits::CertChainRsa2048;

    // Sanitized test fixtures — synthetic CA + user cert with no personal data
    const SIGN_RESPONSE: &str = include_str!("../../tests/testdata/response_sign_test.json");
    const PKCS11_RESPONSE: &str = include_str!("../../tests/testdata/pkcs11info_test.json");

    fn load_user_cert() -> Certificate {
        let response: CardSignResponse = serde_json::from_str(SIGN_RESPONSE).unwrap();
        let der = base64::engine::general_purpose::STANDARD
            .decode(&response.certb64)
            .unwrap();
        Certificate::from_der(&der).unwrap()
    }

    fn load_issuer_cert() -> Certificate {
        let pkcs11: Pkcs11InfoResponse = serde_json::from_str(PKCS11_RESPONSE).unwrap();
        Sha256RsaCircuit::<CertChainRsa2048>::extract_issuer_cert(&pkcs11).unwrap()
    }

    #[test]
    fn test_extract_issuer_cert() {
        let pkcs11: Pkcs11InfoResponse = serde_json::from_str(PKCS11_RESPONSE).unwrap();
        let cert = Sha256RsaCircuit::<CertChainRsa2048>::extract_issuer_cert(&pkcs11).unwrap();
        let ou = Sha256RsaCircuit::<CertChainRsa2048>::get_attr(&cert.tbs_certificate.subject, ORGANIZATIONAL_UNIT_NAME);
        assert!(!ou.is_empty(), "Issuer cert should have an OU");
    }

    #[test]
    fn test_verify_issuer_signature() {
        let user_cert = load_user_cert();
        let issuer_cert = load_issuer_cert();
        Sha256RsaCircuit::<CertChainRsa2048>::verify_issuer_signature(&issuer_cert, &user_cert)
            .expect("Issuer should have signed the user cert");
    }

    #[test]
    fn test_parse_cert_offsets() {
        let user_cert = load_user_cert();
        let der = user_cert.to_der().unwrap();
        let offsets = Sha256RsaCircuit::<CertChainRsa2048>::parse_cert_offsets(&der).unwrap();

        assert_eq!(der[offsets.modulus_tag_offset], 0x02);
        assert!(offsets.modulus_offset > offsets.modulus_tag_offset);

        let spki_der = user_cert
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .unwrap();
        let rsa_pub = RsaPublicKey::from_public_key_der(&spki_der).unwrap();
        let expected_bytes = rsa_pub.n().to_bytes_be();

        let extracted = &der[offsets.modulus_offset..offsets.modulus_offset + expected_bytes.len()];
        assert_eq!(extracted, expected_bytes.as_slice());
    }

    #[test]
    fn test_rsa_circuit_input_dimensions() {
        let user_cert = load_user_cert();
        let input = Sha256RsaCircuit::<CertChainRsa2048>::generate_rsa_circuit_input(
            &user_cert, "AAAA", // dummy base64 signature
            b"test",
        )
        .unwrap();

        assert_eq!(input.message.len(), 1536);
        assert_eq!(input.rsa_modulus.len(), 17);
        assert_eq!(input.rsa_signature.len(), 17);
        assert!(input.message_length <= 1536);
    }

    #[test]
    fn test_generate_circuit_input_without_smt() {
        let user_cert = load_user_cert();
        let issuer_cert = load_issuer_cert();

        let response: CardSignResponse = serde_json::from_str(SIGN_RESPONSE).unwrap();
        let tbs = b"123456";
        let user_cert_tbs_der = user_cert.tbs_certificate.to_der().unwrap();
        let issuer_sig =
            base64::engine::general_purpose::STANDARD.encode(user_cert.signature.raw_bytes());
        let serial_hex = hex::encode(user_cert.tbs_certificate.serial_number.as_bytes());

        let input = Sha256RsaCircuit::<CertChainRsa2048>::generate_circuit_input(
            &user_cert,
            &issuer_cert,
            &response.signature,
            &issuer_sig,
            tbs,
            &user_cert_tbs_der,
            &serial_hex,
            None,
        )
        .unwrap();

        let obj = input.as_object().unwrap();

        // Verify all 18 fields are present
        assert!(obj.contains_key("tbs"));
        assert!(obj.contains_key("tbs_length"));
        assert!(obj.contains_key("issuer_tbs"));
        assert!(obj.contains_key("issuer_tbs_length"));
        assert!(obj.contains_key("actual_issuer_tbs_length"));
        assert!(obj.contains_key("user_cert_zero_padded"));
        assert!(obj.contains_key("actual_user_cert_length"));
        assert!(obj.contains_key("user_modulus_offset"));
        assert!(obj.contains_key("user_modulus_tag_offset"));
        assert!(obj.contains_key("user_rsa_signature"));
        assert!(obj.contains_key("issuer_rsa_modulus"));
        assert!(obj.contains_key("issuer_rsa_signature"));
        assert!(obj.contains_key("smtRoot"));
        assert!(obj.contains_key("serialNumber"));
        assert!(obj.contains_key("smtSiblings"));
        assert!(obj.contains_key("smtOldKey"));
        assert!(obj.contains_key("smtOldValue"));
        assert!(obj.contains_key("smtIsOld0"));

        // SMT defaults should be zero
        assert_eq!(obj["smtRoot"], "0");
        assert_eq!(obj["smtIsOld0"], "1");

        // Array dimensions
        assert_eq!(obj["tbs"].as_array().unwrap().len(), 1536);
        assert_eq!(obj["issuer_tbs"].as_array().unwrap().len(), 1536);
        assert_eq!(obj["user_cert_zero_padded"].as_array().unwrap().len(), 1536);
        assert_eq!(obj["issuer_rsa_modulus"].as_array().unwrap().len(), 17);
        assert_eq!(obj["user_rsa_signature"].as_array().unwrap().len(), 17);
        assert_eq!(obj["issuer_rsa_signature"].as_array().unwrap().len(), 17);
        assert_eq!(obj["smtSiblings"].as_array().unwrap().len(), 128);
    }
}
