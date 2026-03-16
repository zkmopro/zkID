//! RS256 Circuit implementation for single-stage proof verification.
//!
//! This circuit verifies RS256 (RSA-SHA256) signatures and performs age verification
//! in a single stage, without requiring a separate Show circuit for device binding.

use crate::{paths::PathConfig, utils::parse_witness, Scalar, E};
use base64::Engine;
use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use circom_scotia::{reader::load_r1cs, synthesize};
use const_oid::db::rfc4519::*;
use der::Encode;
use der::{
    asn1::{PrintableStringRef, Utf8StringRef},
    oid::db::rfc4519::ORGANIZATION_NAME,
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
    path::PathBuf,
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

#[derive(Deserialize)]
struct CardSignResponse {
    #[serde(rename = "cardSN")]
    card_sn: String,
    certb64: String,
    #[serde(rename = "func")]
    _func: String,
    #[serde(rename = "last_error")]
    _last_error: i32,
    #[serde(rename = "ret_code")]
    _ret_code: i32,
    signature: String,
    #[serde(rename = "version")]
    _version: String,
}

struct RS256CircuitInput {
    message: Vec<String>,
    message_length: usize,
    rsa_modulus: Vec<String>,
    rsa_signature: Vec<String>,
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

    fn verify_issuer_signature(
        issuer_cert: &Certificate,
        user_cert: &Certificate, // ← add user cert parameter
    ) -> Result<(), Box<dyn std::error::Error>> {
        // 1. Extract issuer's RSA public key
        let spki_der = issuer_cert
            .tbs_certificate
            .subject_public_key_info
            .to_der()?;
        let rsa_pub = RsaPublicKey::from_public_key_der(&spki_der)?;
        println!("Issuer RSA key size: {} bits", rsa_pub.n().bits());

        // 2. Get the signature from the USER cert
        //    (this is MOICA's signature over the user's TBS)
        let sig_bytes = user_cert.signature.raw_bytes();
        let sig = rsa::pkcs1v15::Signature::try_from(sig_bytes)?;

        // 3. Get the TBS from the USER cert
        //    (this is what MOICA signed)
        let user_tbs_der = user_cert.tbs_certificate.to_der()?;

        // 4. Verify issuer signed the user cert's TBS
        let verifying_key = VerifyingKey::<Sha256>::new(rsa_pub);
        verifying_key.verify(&user_tbs_der, &sig)?;

        println!("✅ Issuer signature valid: MOICA signed the user cert");
        Ok(())
    }

    fn verify_card_signature(
        response: &CardSignResponse,
        tbs: &[u8], // the data that was signed,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // 1. Decode certificate
        let cert_der = base64::engine::general_purpose::STANDARD.decode(&response.certb64)?;
        let cert = Certificate::from_der(&cert_der)?;

        // 2. Extract RSA public key from certificate
        let spki_der = cert.tbs_certificate.subject_public_key_info.to_der()?;
        let rsa_pub = RsaPublicKey::from_public_key_der(&spki_der)?;

        println!("RSA key size: {} bits", rsa_pub.n().bits());

        // 3. Decode signature
        let sig_bytes = base64::engine::general_purpose::STANDARD.decode(&response.signature)?;
        let sig = rsa::pkcs1v15::Signature::try_from(sig_bytes.as_slice())?;

        // 4. Verify
        let verifying_key = VerifyingKey::<Sha256>::new(rsa_pub);
        verifying_key.verify(tbs, &sig)?;

        println!("✅ Signature verified for card: {}", response.card_sn);
        Ok(())
    }

    pub fn generate_input_from_response(response_path: &PathBuf, tbs: &[u8]) {
        let response_string = std::fs::read_to_string(response_path).unwrap();
        let response: CardSignResponse = serde_json::from_str(&response_string).unwrap();

        let issuer_cert_b64 = "MIIFKDCCAxCgAwIBAgIQUcO1wamhWIYJIiIx1hrArTANBgkqhkiG9w0BAQsFADA/MQswCQYDVQQGEwJUVzEwMC4GA1UECgwnR292ZXJubWVudCBSb290IENlcnRpZmljYXRpb24gQXV0aG9yaXR5MB4XDTE0MDEwMjA2MzEwNFoXDTM0MDEwMjA2MzEwNFowRzELMAkGA1UEBhMCVFcxEjAQBgNVBAoMCeihjOaUv+mZojEkMCIGA1UECwwb5YWn5pS/6YOo5oaR6K2J566h55CG5Lit5b+DMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAn9gInAVVnWPVqzS8XfaF+10vRLo3ulZAI4sAYxrOcFCTNQnQ+bZzb/6iqWgg4fvAxbIbMZfhbQ01eihjledeZEAvN66P/87iSBwiplWESeE1LrKEQkot4ic2F/YKXU9/u2Vk8ek6pQzoxNMNg5BACTYqAWC13VPoGPiPNErxLphj5VJopMgboiCUETh1UYy/TVAZUIHWMKpALi+eqThHJc+oJ1Qju0C715zdnRI3HQYkuFoF9vYiOSLJgVUeqJ538E3z4iuTUZ+jcohxfSFGt4e3hwPVqn/xhn+cYI8gbpxqOfAMLyv/+REKhb8Vwl2uILOKf29aEgJtCKHLxoEpHQIDAQABo4IBFjCCARIwHwYDVR0jBBgwFoAU1Wcd4Jx6LJzLxZjnHQcmKobsdM0wHQYDVR0OBBYEFPqbNGcJCpgi92JIi4ImpkXFwyKkMA4GA1UdDwEB/wQEAwIBBjAUBgNVHSAEDTALMAkGB2CGdmUAAwMwEgYDVR0TAQH/BAgwBgEB/wIBADA+BgNVHR8ENzA1MDOgMaAvhi1odHRwOi8vZ3JjYS5uYXQuZ292LnR3L3JlcG9zaXRvcnkvQ1JMMi9DQS5jcmwwVgYIKwYBBQUHAQEESjBIMEYGCCsGAQUFBzAChjpodHRwOi8vZ3JjYS5uYXQuZ292LnR3L3JlcG9zaXRvcnkvQ2VydHMvSXNzdWVkVG9UaGlzQ0EucDdiMA0GCSqGSIb3DQEBCwUAA4ICAQAYjLOx0ErTqE8Yul0WIRw7yl7UPy23z1xNn2lhs022lpTSWA8ebx3fATUnSPx6oBiGoxG8U/x+NV5DgUy7qenxXHscgOVZVpf7avGcrq8FYrZ0nRGmMCRC30lELnrrH7C9H8YTVZymh2Ovg2jtJHupvmvb43AV9T68T/739lmSkaw7/tu+Ea3Wtxlunzw++5ameC/UZ/1LN0qt/ImKlxBIhXmJbhrHGl20bQp3ZfvGtQ8n03rJtX6dbN2U+JQO4LMcY/3T6Q1sPy2KLA0f2sW4oUM13g8UCIQvhV029DKL3rkDL9xzUHfKBjD9LGDHgdzZ7FszBpFwWEEhsGZx5ZQgFexauozom2lfxSLyZRprWySpMCRlqhU/Vgmx4DwXwWimqH/gtD6cK9+88lcMqhC2d+Jy6D2OrhSbMMW5chfDW6BETxUBXQRBQ6pG8FfWH+f1WN2jytWvymqmvR31e8XsxUa3oOQUTO+NcKBkI3iH7DMR9N5PWwA5OVTrunAl8eC3cb9ZdIG6j27xMjNck46fYAIIp3uqyK1MTC6Z6e8yygL1pSW7/whNWL/4gp0EFyMkx7M1V8QmqYNaeVbRVFjDGZ30qh2Osr4mtEPImvHZFX8Sv0keMYemH9oLqyxYzhsb40XCWNzYC0RS73kTcXATtetNSsXzrxLfbno09jQHsg==";
        let issuer_cert = Certificate::from_der(
            &base64::engine::general_purpose::STANDARD
                .decode(&issuer_cert_b64)
                .unwrap(),
        )
        .unwrap();
        let issuer_cert_tbs = &issuer_cert.tbs_certificate;
        let issuer_cert_subject_cn = Self::get_attr(&issuer_cert_tbs.subject, COMMON_NAME);
        let issuer_cert_subject_org = Self::get_attr(&issuer_cert_tbs.subject, ORGANIZATION_NAME);
        let issuer_cert_subject_country = Self::get_attr(&issuer_cert_tbs.subject, COUNTRY_NAME);
        let issuer_cert_subject_serial = Self::get_attr(&issuer_cert_tbs.subject, SERIAL_NUMBER);
        let issuer_cert_issuer_cn = Self::get_attr(&issuer_cert_tbs.issuer, COMMON_NAME);
        let issuer_cert_issuer_org = Self::get_attr(&issuer_cert_tbs.issuer, ORGANIZATION_NAME);
        let issuer_cert_issuer_ou =
            Self::get_attr(&issuer_cert_tbs.issuer, ORGANIZATIONAL_UNIT_NAME);
        let issuer_cert_issuer_country = Self::get_attr(&issuer_cert_tbs.issuer, COUNTRY_NAME);
        let issuer_cert_not_before = issuer_cert_tbs.validity.not_before;
        let issuer_cert_not_after = issuer_cert_tbs.validity.not_after;
        let issuer_cert_serial = issuer_cert_tbs.serial_number.as_bytes();
        let issuer_cert_serial_hex = hex::encode(issuer_cert_serial);
        let issuer_cert_version = issuer_cert_tbs.version;
        println!("issuer_cert_subject_cn: {}", issuer_cert_subject_cn);
        println!("issuer_cert_subject_org: {}", issuer_cert_subject_org);
        println!(
            "issuer_cert_subject_country: {}",
            issuer_cert_subject_country
        );
        println!("issuer_cert_subject_serial: {}", issuer_cert_subject_serial);
        println!("issuer_cert_issuer_cn: {}", issuer_cert_issuer_cn);
        println!("issuer_cert_issuer_org: {}", issuer_cert_issuer_org);
        println!("issuer_cert_issuer_ou: {}", issuer_cert_issuer_ou);
        println!("issuer_cert_issuer_country: {}", issuer_cert_issuer_country);
        println!("issuer_cert_not_before: {:?}", issuer_cert_not_before);
        println!("issuer_cert_not_after: {:?}", issuer_cert_not_after);
        println!("issuer_cert_serial: {}", issuer_cert_serial_hex);
        println!("issuer_cert_version: {:?}", issuer_cert_version);

        // Decode base64
        let raw_bytes = base64::engine::general_purpose::STANDARD
            .decode(&response.certb64)
            .expect("Failed to decode base64");

        // Parse DER certificate
        let cert = Certificate::from_der(&raw_bytes).expect("Failed to parse certificate");
        let cert_tbs = &cert.tbs_certificate;

        // === Subject (who the cert is issued to) ===
        let subject_cn = Self::get_attr(&cert_tbs.subject, COMMON_NAME); // CN
        let subject_org = Self::get_attr(&cert_tbs.subject, ORGANIZATION_NAME); // O
        let subject_country = Self::get_attr(&cert_tbs.subject, COUNTRY_NAME); // C
        let subject_serial = Self::get_attr(&cert_tbs.subject, SERIAL_NUMBER); // serialNumber

        // === Issuer (who issued the cert) ===
        let issuer_cn = Self::get_attr(&cert_tbs.issuer, COMMON_NAME);
        let issuer_org = Self::get_attr(&cert_tbs.issuer, ORGANIZATION_NAME);
        let issuer_ou = Self::get_attr(&cert_tbs.issuer, ORGANIZATIONAL_UNIT_NAME); // OU
        let issuer_country = Self::get_attr(&cert_tbs.issuer, COUNTRY_NAME);

        // === Validity ===
        let not_before = cert_tbs.validity.not_before;
        let not_after = cert_tbs.validity.not_after;

        // === Serial Number ===
        let serial = cert_tbs.serial_number.as_bytes();
        let serial_hex = hex::encode(serial);

        // === Version ===
        let version = cert_tbs.version; // v1, v2, or v3

        // === Signature Algorithm ===
        let sig_alg_oid = cert.signature_algorithm.oid.to_string();
        let sig_alg_name = match sig_alg_oid.as_str() {
            "1.2.840.113549.1.1.11" => "SHA256withRSA",
            "1.2.840.113549.1.1.12" => "SHA384withRSA",
            "1.2.840.113549.1.1.13" => "SHA512withRSA",
            "1.2.840.113549.1.1.5" => "SHA1withRSA",
            _ => "Unknown",
        };

        // === Public Key Info ===
        let _pub_key_alg = cert_tbs.subject_public_key_info.algorithm.oid.to_string();
        let pub_key_bytes = cert_tbs
            .subject_public_key_info
            .subject_public_key
            .raw_bytes();
        let pub_key_bit_len = pub_key_bytes.len() * 8;

        // === Signature ===
        let signature_bytes = cert.signature.raw_bytes();

        // === TBS (To-Be-Signed) raw bytes ===
        let tbs_der = cert_tbs.to_der().unwrap();

        // === Extensions (v3) ===
        if let Some(extensions) = &cert_tbs.extensions {
            for ext in extensions.iter() {
                let oid = ext.extn_id.to_string();
                let _critical = ext.critical;
                let _value = ext.extn_value.as_bytes();

                match oid.as_str() {
                    "2.5.29.17" => println!("Subject Alt Name"),
                    "2.5.29.15" => println!("Key Usage"),
                    "2.5.29.19" => println!("Basic Constraints"),
                    "2.5.29.31" => println!("CRL Distribution Points"),
                    "2.5.29.35" => println!("Authority Key Identifier"),
                    "2.5.29.14" => println!("Subject Key Identifier"),
                    "1.3.6.1.5.5.7.1.1" => println!("Authority Info Access (OCSP/CA)"),
                    _ => println!("Extension OID: {}", oid),
                }
            }
        }

        // === Print everything ===
        println!("Subject CN: {}", subject_cn);
        println!("Subject Org: {}", subject_org);
        println!("Subject Country: {}", subject_country);
        println!("Subject Serial: {}", subject_serial);
        println!("Issuer CN: {}", issuer_cn);
        println!("Issuer Org: {}", issuer_org);
        println!("Issuer OU: {}", issuer_ou);
        println!("Issuer Country: {}", issuer_country);
        println!("Not Before: {:?}", not_before);
        println!("Not After: {:?}", not_after);
        println!("Serial: {}", serial_hex);
        println!("Version: {:?}", version);
        println!("Sig Algorithm: {} ({})", sig_alg_name, sig_alg_oid);
        println!("Public Key: {} bits", pub_key_bit_len);
        println!("TBS size: {} bytes", tbs_der.len());
        println!("Signature size: {} bytes", signature_bytes.len());

        match Self::verify_issuer_signature(&issuer_cert, &cert) {
            Ok(()) => println!("✅ MOICA signed the user cert"),
            Err(e) => println!("❌ Issuer verification failed: {}", e),
        }

        // Verify signature first
        match Self::verify_card_signature(&response, tbs) {
            Ok(()) => println!("Signature valid"),
            Err(e) => println!("❌ Verification failed: {}", e),
        }

        // Generate circuit input
        // user cert signature and tbs
        // let circuit_input = Self::generate_circuit_input(&cert, &response.signature, tbs);

        // issuer cert signature and user tbs
        // let circuit_input = Self::generate_circuit_input(
        //     &issuer_cert,
        //     &base64::engine::general_purpose::STANDARD.encode(cert.signature.raw_bytes()),
        //     &tbs_der,
        // );
        let circuit_input = Self::generate_circuit_input(&cert, &issuer_cert, &response.signature, &base64::engine::general_purpose::STANDARD.encode(cert.signature.raw_bytes()), &tbs, &tbs_der);
        std::fs::write(
            "rs256_input.json",
            serde_json::to_string_pretty(&circuit_input).unwrap(),
        )
        .unwrap();
        println!("Circuit input written to rs256_input.json");
    }

    fn generate_rsa_circuit_input(
        cert: &Certificate,
        signature: &str,
        original_data: &[u8],
    ) -> RS256CircuitInput {
        const MAX_MESSAGE_LENGTH: usize = 1536;
        const RSA_N: usize = 121;
        const RSA_K: usize = 17;

        // 1. Parse cert and extract RSA public key
        let spki_der = cert
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .unwrap();
        let rsa_pub = RsaPublicKey::from_public_key_der(&spki_der).unwrap();
        let modulus = BigUint::from_bytes_be(&rsa_pub.n().to_bytes_be());
        let rsa_modulus = Self::bigint_to_chunks(&modulus, RSA_K, RSA_N);

        // 2. Decode and chunk signature
        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(signature)
            .unwrap();
        let sig_biguint = BigUint::from_bytes_be(&sig_bytes);
        let rsa_signature = Self::bigint_to_chunks(&sig_biguint, RSA_K, RSA_N);

        // 3. SHA-256 pad the original data
        let message = Self::sha256_pad(original_data, MAX_MESSAGE_LENGTH);
        let padded_len = Self::sha256_padded_length(original_data.len());

        RS256CircuitInput {
            message: message.iter().map(|b| b.to_string()).collect::<Vec<_>>(),
            message_length: padded_len,
            rsa_modulus: rsa_modulus,
            rsa_signature: rsa_signature,
        }
    }

    fn generate_circuit_input(
        user_cert: &Certificate,
        issuer_cert: &Certificate,
        user_signature: &str,
        issuer_signature: &str,
        user_tbs: &[u8],
        issuer_tbs: &[u8],
    ) -> serde_json::Value {

        const MAX_MESSAGE_LENGTH: usize = 1536;
        let zero_pad = |bytes: &[u8]| -> Vec<u64> {
            assert!(
                bytes.len() <= MAX_MESSAGE_LENGTH,
                "too large: {} > {}",
                bytes.len(),
                MAX_MESSAGE_LENGTH
            );
            let mut v: Vec<u64> = bytes.iter().map(|&b| b as u64).collect();
            v.resize(MAX_MESSAGE_LENGTH, 0);
            v
        };
        
        let user_circuit_input = Self::generate_rsa_circuit_input(user_cert, user_signature, user_tbs);
        let issuer_circuit_input = Self::generate_rsa_circuit_input(issuer_cert, issuer_signature, issuer_tbs);

        serde_json::json!({
            "tbs": user_circuit_input.message,
            "tbs_length": user_circuit_input.message_length,
            "tbs_zero_padded": zero_pad(user_tbs),
            "actual_tbs_length": user_tbs.len(),
            "user_cert": issuer_circuit_input.message,
            "user_cert_length": issuer_circuit_input.message_length,
            "user_rsa_modulus": user_circuit_input.rsa_modulus,
            "user_rsa_signature": user_circuit_input.rsa_signature,
            "issuer_rsa_modulus": issuer_circuit_input.rsa_modulus,
            "issuer_rsa_signature": issuer_circuit_input.rsa_signature,
        })
    }

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

    // Helper function
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
        let num_public = 17; // 17 (rsaModulus limbs)
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
