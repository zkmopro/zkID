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

use super::sha256rsa_circuit::Sha256RsaCircuit;

/// Cert-chain proof (Circuit A) for MOICA-G2 (RSA-2048 issuer + 2048 user).
pub type CertChainCircuit = Sha256RsaCircuit<CertChainRsa2048>;
/// Cert-chain proof (Circuit A) for MOICA-G3 (RSA-4096 issuer + 2048 user).
pub type CertChainFidoCircuit = Sha256RsaCircuit<CertChainRsa4096>;
/// Device-signature proof (Circuit B) — always RSA-2048 (user keys).
pub type DeviceSigCircuit = Sha256RsaCircuit<DeviceSigRsa2048>;
