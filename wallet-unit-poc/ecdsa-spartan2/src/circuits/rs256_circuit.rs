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

    fn verify_card_signature(
        response: &CardSignResponse,
        tbs: &[u8], // the data that was signed
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

    pub fn generate_input_from_response(
        response_path: &PathBuf,
        tbs: &[u8],
        smt_server: Option<&str>,
        issuer: &str,
        output_path: &str,
    ) {
        let response_string = std::fs::read_to_string(response_path).unwrap();
        let response: CardSignResponse = serde_json::from_str(&response_string).unwrap();

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
        let pub_key_bytes = cert_tbs.subject_public_key_info.subject_public_key.raw_bytes();
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

        let issuer_cn = cert
            .tbs_certificate
            .issuer
            .0
            .iter()
            .flat_map(|rdn| rdn.0.iter())
            .find(|attr| attr.oid == ORGANIZATION_NAME)
            .map(|attr| 
            // Try UTF8String first, then PrintableString
                if let Ok(s) = Utf8StringRef::try_from(&attr.value) {
                    s.as_str().to_string()
                } else if let Ok(s) = PrintableStringRef::try_from(&attr.value) {
                    s.as_str().to_string()
                } else {    
                    String::from_utf8_lossy(attr.value.value()).to_string()
                }
            )
            .unwrap_or_default();
        println!("issuer_cn: {}", issuer_cn);

        // Verify signature first
        match Self::verify_card_signature(&response, tbs) {
            Ok(()) => println!("Signature valid"),
            Err(e) => println!("❌ Verification failed: {}", e),
        }

        // Fetch SMT proof if server is specified
        let smt_inputs = if let Some(server_url) = smt_server {
            println!("Fetching SMT proof from {}...", server_url);
            match crate::smt_client::fetch_smt_proof(server_url, issuer, &serial_hex, 128) {
                Ok(inputs) => {
                    println!("  SMT root: {}...", &inputs.smt_root[..20.min(inputs.smt_root.len())]);
                    println!("  Serial (decimal): {}...", &inputs.serial_number[..20.min(inputs.serial_number.len())]);
                    println!("  isOld0: {}", inputs.smt_is_old0);
                    Some(inputs)
                }
                Err(e) => {
                    eprintln!("Failed to fetch SMT proof: {}", e);
                    std::process::exit(1);
                }
            }
        } else {
            None
        };

        // Generate circuit input
        let circuit_input = Self::generate_circuit_input(&response, tbs, smt_inputs.as_ref());
        std::fs::write(
            output_path,
            serde_json::to_string_pretty(&circuit_input).unwrap(),
        )
        .unwrap();
        println!("Circuit input written to {}", output_path);


    }

    fn generate_circuit_input(
        response: &CardSignResponse,
        original_data: &[u8],
        smt_inputs: Option<&crate::smt_client::SmtCircuitInputs>,
    ) -> serde_json::Value {
        const MAX_MESSAGE_LENGTH: usize = 1536;
        const RSA_N: usize = 121;
        const RSA_K: usize = 17;

        // 1. Parse cert and extract RSA public key
        let cert_der = base64::engine::general_purpose::STANDARD
            .decode(&response.certb64)
            .unwrap();
        let cert = Certificate::from_der(&cert_der).unwrap();
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
            .decode(&response.signature)
            .unwrap();
        let sig_biguint = BigUint::from_bytes_be(&sig_bytes);
        let rsa_signature = Self::bigint_to_chunks(&sig_biguint, RSA_K, RSA_N);

        // 3. SHA-256 pad the original data
        let message = Self::sha256_pad(original_data, MAX_MESSAGE_LENGTH);
        let padded_len = Self::sha256_padded_length(original_data.len());

        let mut input = serde_json::json!({
            "message": message.iter().map(|b| b.to_string()).collect::<Vec<_>>(),
            "messageLength": padded_len.to_string(),
            "rsaModulus": rsa_modulus,
            "rsaSignature": rsa_signature,
        });

        if let Some(smt) = smt_inputs {
            let obj = input.as_object_mut().unwrap();
            obj.insert("smtRoot".to_string(), serde_json::json!(smt.smt_root));
            obj.insert("serialNumber".to_string(), serde_json::json!(smt.serial_number));
            obj.insert("smtSiblings".to_string(), serde_json::json!(smt.smt_siblings));
            obj.insert("smtOldKey".to_string(), serde_json::json!(smt.smt_old_key));
            obj.insert("smtOldValue".to_string(), serde_json::json!(smt.smt_old_value));
            obj.insert("smtIsOld0".to_string(), serde_json::json!(smt.smt_is_old0));
        }

        input
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
        let num_public = 19; // 17 (rsaModulus limbs) + 1 (smtRoot) + 1 (serialNumber)
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
