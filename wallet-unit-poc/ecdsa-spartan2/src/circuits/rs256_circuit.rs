//! RS256 Circuit implementation for certificate chain verification.
//!
//! This circuit verifies a certificate chain (user cert signed by issuer CA)
//! using RSA-SHA256 signatures, extracts the user's public key from the cert DER
//! in-circuit, and proves non-revocation via a Sparse Merkle Tree.

use crate::{paths::PathConfig, utils::parse_witness, Scalar, E};
use base64::Engine;
use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use circom_scotia::{reader::load_r1cs, synthesize};
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
use x509_cert::Certificate;

witnesscalc_adapter::witness!(rs256);

/// RS256 Circuit for single-stage RSA signature verification and age proof.
///
/// This circuit combines:
/// - RSA signature verification (RS256/sha256WithRSAEncryption)
///
/// Unlike the ES256 flow which requires Prepare + Show circuits,
/// RS256 verification is done in a single circuit without device binding.
#[derive(Debug, Clone)]
pub struct Rs256Circuit {
    /// Path configuration for resolving file paths
    path_config: PathConfig,
    /// Optional override for input JSON path
    input_path: Option<PathBuf>,
    /// Cached witness for reuse across synthesize and public_values calls
    cached_witness: Arc<Mutex<Option<Vec<Scalar>>>>,
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

/// Intermediate result from per-certificate RSA input generation.
struct RsaCircuitInput {
    message: Vec<String>,
    message_length: usize,
    rsa_modulus: Vec<String>,
    rsa_signature: Vec<String>,
}

/// DER byte offsets for in-circuit extraction.
#[derive(Debug)]
struct CertOffsets {
    modulus_offset: usize,
    modulus_tag_offset: usize,
    serial_offset: usize,
    serial_length: usize,
    subject_dn_offset: usize,
    subject_dn_length: usize,
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

impl Default for Rs256Circuit {
    fn default() -> Self {
        Self {
            path_config: PathConfig::default(),
            input_path: None,
            cached_witness: Arc::new(Mutex::new(None)),
        }
    }
}

impl Rs256Circuit {
    /// Create a new Rs256Circuit with PathConfig and optional input path override.
    pub fn new(path_config: PathConfig, input_path: Option<PathBuf>) -> Self {
        Self {
            path_config,
            input_path,
            cached_witness: Arc::new(Mutex::new(None)),
        }
    }

    /// Create from just an input path (for backwards compatibility).
    /// Uses development PathConfig.
    pub fn with_input_path<P: Into<Option<PathBuf>>>(path: P) -> Self {
        Self {
            path_config: PathConfig::development(),
            input_path: path.into(),
            cached_witness: Arc::new(Mutex::new(None)),
        }
    }

    /// Resolve the input JSON path using PathConfig.
    fn resolve_input_json(&self) -> PathBuf {
        self.input_path
            .as_ref()
            .map(|p| self.path_config.resolve(p))
            .unwrap_or_else(|| self.path_config.input_json("rs256"))
    }

    /// Get the R1CS file path.
    fn r1cs_path(&self) -> PathBuf {
        self.path_config.r1cs_path("rs256")
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
    fn verify_card_signature(
        response: &CardSignResponse,
        tbs: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cert_der = base64::engine::general_purpose::STANDARD.decode(&response.certb64)?;
        let cert = Certificate::from_der(&cert_der)?;

        let spki_der = cert.tbs_certificate.subject_public_key_info.to_der()?;
        let rsa_pub = RsaPublicKey::from_public_key_der(&spki_der)?;

        let sig_bytes = base64::engine::general_purpose::STANDARD.decode(&response.signature)?;
        let sig = rsa::pkcs1v15::Signature::try_from(sig_bytes.as_slice())?;

        let verifying_key = VerifyingKey::<Sha256>::new(rsa_pub);
        verifying_key.verify(tbs, &sig)?;
        Ok(())
    }

    // === Main entry points for circuit input generation ===

    /// Generate circuit input JSON from a parsed CardSignResponse.
    ///
    /// This is the primary entry point — accepts already-parsed API responses
    /// (from HiPKI client or test fixtures).
    pub fn generate_input(
        sign_response: &CardSignResponse,
        tbs: &[u8],
        issuer_cert: &Certificate,
        smt_server: Option<&str>,
        issuer_id: &str,
        output_path: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cert_der =
            base64::engine::general_purpose::STANDARD.decode(&sign_response.certb64)?;
        let user_cert = Certificate::from_der(&cert_der)?;

        let subject_cn = Self::get_attr(&user_cert.tbs_certificate.subject, COMMON_NAME);
        // Strip leading 0x00 padding bytes from DER INTEGER encoding
        let serial_bytes = user_cert.tbs_certificate.serial_number.as_bytes();
        let trimmed: Vec<u8> = serial_bytes.iter().skip_while(|&&b| b == 0).copied().collect();
        let serial_hex = hex::encode(if trimmed.is_empty() { serial_bytes } else { &trimmed });
        info!(subject = %subject_cn, serial = %serial_hex, "Parsed user certificate");

        Self::verify_issuer_signature(issuer_cert, &user_cert)?;
        info!("Issuer signature verified on user cert");

        Self::verify_card_signature(sign_response, tbs)?;
        info!(card_sn = %sign_response.card_sn, "Card signature verified");

        let smt_inputs = if let Some(server_url) = smt_server {
            info!(url = %server_url, "Fetching SMT proof");
            Some(crate::smt_client::fetch_smt_proof(
                server_url, issuer_id, &serial_hex, 128,
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
            &sign_response.signature,
            &issuer_sig_on_user_cert,
            tbs,
            &user_cert_tbs_der,
            smt_inputs.as_ref(),
        )?;

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
        Self::generate_input(&response, tbs, issuer_cert, smt_server, issuer_id, output_path)
    }

    // === Per-certificate RSA input generation ===

    /// Generate RSA circuit input for a single certificate.
    /// Extracts the modulus from the cert and chunks both modulus and signature.
    fn generate_rsa_circuit_input(
        cert: &Certificate,
        signature_b64: &str,
        original_data: &[u8],
    ) -> Result<RsaCircuitInput, Box<dyn std::error::Error>> {
        const MAX_MESSAGE_LENGTH: usize = 1536;
        const RSA_N: usize = 121;
        const RSA_K: usize = 17;

        let spki_der = cert.tbs_certificate.subject_public_key_info.to_der()?;
        let rsa_pub = RsaPublicKey::from_public_key_der(&spki_der)?;
        let modulus = BigUint::from_bytes_be(&rsa_pub.n().to_bytes_be());
        let rsa_modulus = Self::bigint_to_chunks(&modulus, RSA_K, RSA_N);

        let sig_bytes = base64::engine::general_purpose::STANDARD.decode(signature_b64)?;
        let sig_biguint = BigUint::from_bytes_be(&sig_bytes);
        let rsa_signature = Self::bigint_to_chunks(&sig_biguint, RSA_K, RSA_N);

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
        smt_inputs: Option<&crate::smt_client::SmtCircuitInputs>,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        const MAX_MESSAGE_LENGTH: usize = 1536;

        let zero_pad = |bytes: &[u8]| -> Vec<u64> {
            assert!(
                bytes.len() <= MAX_MESSAGE_LENGTH,
                "Certificate too large: {} > {}",
                bytes.len(),
                MAX_MESSAGE_LENGTH
            );
            let mut v: Vec<u64> = bytes.iter().map(|&b| b as u64).collect();
            v.resize(MAX_MESSAGE_LENGTH, 0);
            v
        };

        let user_input =
            Self::generate_rsa_circuit_input(user_cert, user_signature_b64, user_tbs)?;
        let issuer_input =
            Self::generate_rsa_circuit_input(issuer_cert, issuer_signature_b64, issuer_tbs)?;

        let user_cert_der = user_cert.to_der()?;
        let user_offsets = Self::parse_cert_offsets(&user_cert_der)?;

        // SMT fields: use provided values or zero defaults
        // serialNumber is now extracted in-circuit, not passed as input
        let (smt_root, smt_siblings, smt_old_key, smt_old_value, smt_is_old0) =
            match smt_inputs {
                Some(smt) => (
                    smt.smt_root.clone(),
                    smt.smt_siblings.clone(),
                    smt.smt_old_key.clone(),
                    smt.smt_old_value.clone(),
                    smt.smt_is_old0.clone(),
                ),
                None => {
                    let zeros = vec!["0".to_string(); 128];
                    (
                        "0".to_string(),
                        zeros,
                        "0".to_string(),
                        "0".to_string(),
                        "1".to_string(),
                    )
                }
            };

        Ok(serde_json::json!({
            "tbs": user_input.message,
            "tbs_length": user_input.message_length,
            "issuer_tbs": issuer_input.message,
            "issuer_tbs_length": issuer_input.message_length,
            "actual_issuer_tbs_length": issuer_tbs.len(),
            "user_cert_zero_padded": zero_pad(&user_cert_der),
            "actual_user_cert_length": user_cert_der.len(),
            "user_modulus_offset": user_offsets.modulus_offset,
            "user_modulus_tag_offset": user_offsets.modulus_tag_offset,
            "user_rsa_signature": user_input.rsa_signature,
            "issuer_rsa_modulus": issuer_input.rsa_modulus,
            "issuer_rsa_signature": issuer_input.rsa_signature,
            "smtRoot": smt_root,
            "smtSiblings": smt_siblings,
            "smtOldKey": smt_old_key,
            "smtOldValue": smt_old_value,
            "smtIsOld0": smt_is_old0,
            "serial_offset": user_offsets.serial_offset,
            "serial_length": user_offsets.serial_length,
            "subject_dn_offset": user_offsets.subject_dn_offset,
            "subject_dn_length": user_offsets.subject_dn_length,
        }))
    }

    // === DER parsing helpers ===

    /// Find all DER byte offsets needed for in-circuit extraction.
    fn parse_cert_offsets(der: &[u8]) -> Result<CertOffsets, Box<dyn std::error::Error>> {
        let (modulus_offset, modulus_tag_offset) = Self::find_modulus_offset(der)?;

        if der[modulus_tag_offset] != 0x02 {
            return Err(format!(
                "Modulus INTEGER tag wrong at {}: got 0x{:02x}",
                modulus_tag_offset, der[modulus_tag_offset]
            )
            .into());
        }

        let (serial_offset, serial_length) = Self::parse_serial_offset(der)?;
        let (subject_dn_offset, subject_dn_length) = Self::parse_subject_dn_offset(der)?;

        Ok(CertOffsets {
            modulus_offset,
            modulus_tag_offset,
            serial_offset,
            serial_length,
            subject_dn_offset,
            subject_dn_length,
        })
    }

    /// Returns (modulus_value_offset, integer_tag_offset) by navigating the SPKI structure.
    fn find_modulus_offset(der: &[u8]) -> Result<(usize, usize), Box<dyn std::error::Error>> {
        let cert = Certificate::from_der(der)?;
        let spki_der = cert
            .tbs_certificate
            .subject_public_key_info
            .to_der()?;

        let spki_abs = Self::find_subslice(der, &spki_der)
            .ok_or("SPKI not found in cert DER")?;

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

    /// Find the serial number offset in the full certificate DER.
    /// Returns (tag_offset, value_length) where tag_offset points to the 0x02 INTEGER tag.
    ///
    /// DER TBS structure: SEQUENCE { version, serialNumber INTEGER, ... }
    fn parse_serial_offset(der: &[u8]) -> Result<(usize, usize), Box<dyn std::error::Error>> {
        let cert = Certificate::from_der(der)?;
        let tbs_der = cert.tbs_certificate.to_der()?;
        let tbs_abs = Self::find_subslice(der, &tbs_der)
            .ok_or("TBS not found in cert DER")?;

        let mut pos = 0usize;

        // Skip TBS SEQUENCE tag + length
        pos += 1;
        let (_, lb) = Self::read_der_len(&tbs_der, pos);
        pos += lb;

        // Skip version [0] EXPLICIT if present (tag = 0xa0)
        if tbs_der[pos] == 0xa0 {
            pos += 1;
            let (ver_len, vlb) = Self::read_der_len(&tbs_der, pos);
            pos += vlb + ver_len;
        }

        // Now at serialNumber INTEGER (tag = 0x02)
        if tbs_der[pos] != 0x02 {
            return Err(format!(
                "Expected INTEGER tag at TBS pos {}, got 0x{:02x}",
                pos, tbs_der[pos]
            ).into());
        }
        let tag_offset = tbs_abs + pos;
        pos += 1;

        let (serial_len, _) = Self::read_der_len(&tbs_der, pos);

        // serial_len is the full DER INTEGER value length, which may include
        // a leading 0x00 sign byte. The circuit's maxSerialLen (20) is large
        // enough to hold this. The leading zero doesn't change the packed
        // big-endian integer value (it's in the MSB position).
        Ok((tag_offset, serial_len))
    }

    /// Find the Subject DN offset in the full certificate DER.
    /// Returns (tag_offset, total_length) where tag_offset points to the 0x30 SEQUENCE tag.
    ///
    /// DER TBS structure: SEQUENCE { version, serialNumber, signatureAlgorithm,
    ///                               issuer, validity, subject, ... }
    fn parse_subject_dn_offset(der: &[u8]) -> Result<(usize, usize), Box<dyn std::error::Error>> {
        let cert = Certificate::from_der(der)?;
        let tbs_der = cert.tbs_certificate.to_der()?;
        let tbs_abs = Self::find_subslice(der, &tbs_der)
            .ok_or("TBS not found in cert DER")?;

        let mut pos = 0usize;

        // Skip TBS SEQUENCE tag + length
        pos += 1;
        let (_, lb) = Self::read_der_len(&tbs_der, pos);
        pos += lb;

        // Skip version [0] EXPLICIT if present
        if tbs_der[pos] == 0xa0 {
            pos += 1;
            let (ver_len, vlb) = Self::read_der_len(&tbs_der, pos);
            pos += vlb + ver_len;
        }

        // Skip serialNumber INTEGER
        pos += 1; // tag
        let (serial_len, slb) = Self::read_der_len(&tbs_der, pos);
        pos += slb + serial_len;

        // Skip signatureAlgorithm SEQUENCE
        pos += 1; // tag
        let (sig_alg_len, salb) = Self::read_der_len(&tbs_der, pos);
        pos += salb + sig_alg_len;

        // Skip issuer Name SEQUENCE
        pos += 1; // tag
        let (issuer_len, ilb) = Self::read_der_len(&tbs_der, pos);
        pos += ilb + issuer_len;

        // Skip validity SEQUENCE
        pos += 1; // tag
        let (validity_len, vlb) = Self::read_der_len(&tbs_der, pos);
        pos += vlb + validity_len;

        // Now at subject Name SEQUENCE (tag = 0x30)
        if tbs_der[pos] != 0x30 {
            return Err(format!(
                "Expected SEQUENCE tag at TBS pos {} (subject), got 0x{:02x}",
                pos, tbs_der[pos]
            ).into());
        }
        let tag_offset = tbs_abs + pos;
        pos += 1;
        let (subject_len, _) = Self::read_der_len(&tbs_der, pos);

        Ok((tag_offset, subject_len))
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

    // === Utility functions ===

    fn bigint_to_chunks(n: &BigUint, count: usize, chunk_bits: usize) -> Vec<String> {
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

    fn sha256_pad(msg: &[u8], max_len: usize) -> Vec<u8> {
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

    fn sha256_padded_length(original_len: usize) -> usize {
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

        // Generate witness using witnesscalc adapter
        info!("Generating witness using witnesscalc...");
        let t0 = Instant::now();
        let witness_bytes = rs256_witness(&json_string).map_err(|e| {
            eprintln!("Witness generation failed: {}", e);
            SynthesisError::Unsatisfiable
        })?;
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

impl SpartanCircuit<E> for Rs256Circuit {
    fn synthesize<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
        _: &[AllocatedNum<Scalar>],
        _: &[AllocatedNum<Scalar>],
        _: Option<&[Scalar]>,
    ) -> Result<(), SynthesisError> {
        let r1cs_path = self.r1cs_path();

        // Detect if we're in setup phase (ShapeCS) or prove phase (SatisfyingAssignment)
        // During setup, we only need constraint structure instead of actual witness values
        let cs_type = type_name::<CS>();
        let is_setup_phase = cs_type.contains("ShapeCS");

        if is_setup_phase {
            let r1cs = load_r1cs(&r1cs_path);
            // Pass None for witness during setup
            synthesize(cs, r1cs.unwrap(), None)?;
            return Ok(());
        }

        // Generate witness for prove phase
        let witness = self.get_or_generate_witness()?;

        let r1cs = load_r1cs(&r1cs_path);
        synthesize(cs, r1cs.unwrap(), Some(witness))?;
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
        let num_public = 275; // 17 (issuer_rsa_modulus) + 1 (smtRoot) + 256 (tbs_hash) + 1 (dn_nullifier)
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
        Rs256Circuit::extract_issuer_cert(&pkcs11).unwrap()
    }

    #[test]
    fn test_extract_issuer_cert() {
        let pkcs11: Pkcs11InfoResponse = serde_json::from_str(PKCS11_RESPONSE).unwrap();
        let cert = Rs256Circuit::extract_issuer_cert(&pkcs11).unwrap();
        let ou = Rs256Circuit::get_attr(
            &cert.tbs_certificate.subject,
            ORGANIZATIONAL_UNIT_NAME,
        );
        assert!(!ou.is_empty(), "Issuer cert should have an OU");
    }

    #[test]
    fn test_verify_issuer_signature() {
        let user_cert = load_user_cert();
        let issuer_cert = load_issuer_cert();
        Rs256Circuit::verify_issuer_signature(&issuer_cert, &user_cert)
            .expect("Issuer should have signed the user cert");
    }

    #[test]
    fn test_parse_cert_offsets() {
        let user_cert = load_user_cert();
        let der = user_cert.to_der().unwrap();
        let offsets = Rs256Circuit::parse_cert_offsets(&der).unwrap();

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
        let input = Rs256Circuit::generate_rsa_circuit_input(
            &user_cert,
            "AAAA", // dummy base64 signature
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
        let issuer_sig = base64::engine::general_purpose::STANDARD
            .encode(user_cert.signature.raw_bytes());

        let input = Rs256Circuit::generate_circuit_input(
            &user_cert,
            &issuer_cert,
            &response.signature,
            &issuer_sig,
            tbs,
            &user_cert_tbs_der,
            None,
        )
        .unwrap();

        let obj = input.as_object().unwrap();

        // Verify all expected fields are present
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
        assert!(obj.contains_key("smtSiblings"));
        assert!(obj.contains_key("smtOldKey"));
        assert!(obj.contains_key("smtOldValue"));
        assert!(obj.contains_key("smtIsOld0"));
        // New offset fields for in-circuit extraction
        assert!(obj.contains_key("serial_offset"));
        assert!(obj.contains_key("serial_length"));
        assert!(obj.contains_key("subject_dn_offset"));
        assert!(obj.contains_key("subject_dn_length"));
        // serialNumber removed (now extracted in-circuit)
        assert!(!obj.contains_key("serialNumber"));

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

    #[test]
    fn test_parse_serial_offset() {
        let user_cert = load_user_cert();
        let der = user_cert.to_der().unwrap();
        let (tag_offset, serial_len) = Rs256Circuit::parse_serial_offset(&der).unwrap();

        // Tag at offset should be 0x02 (INTEGER)
        assert_eq!(der[tag_offset], 0x02, "Serial tag should be 0x02 INTEGER");
        // Serial length should be reasonable (1-20 bytes for CDC certs)
        assert!(serial_len > 0 && serial_len <= 20, "Serial length {} out of range", serial_len);

        // Verify extracted bytes match the x509_cert parsed serial
        let expected_serial = user_cert.tbs_certificate.serial_number.as_bytes();
        let value_offset = tag_offset + 1 + if der[tag_offset + 1] & 0x80 != 0 {
            1 + (der[tag_offset + 1] & 0x7f) as usize
        } else {
            1
        };
        let extracted = &der[value_offset..value_offset + serial_len];
        assert_eq!(extracted, expected_serial, "Extracted serial should match parsed cert serial");
    }

    #[test]
    fn test_parse_subject_dn_offset() {
        let user_cert = load_user_cert();
        let der = user_cert.to_der().unwrap();
        let (tag_offset, dn_len) = Rs256Circuit::parse_subject_dn_offset(&der).unwrap();

        // Tag at offset should be 0x30 (SEQUENCE)
        assert_eq!(der[tag_offset], 0x30, "Subject DN tag should be 0x30 SEQUENCE");
        // DN length should be reasonable
        assert!(dn_len > 0 && dn_len <= 256, "DN length {} out of range", dn_len);
    }
}
