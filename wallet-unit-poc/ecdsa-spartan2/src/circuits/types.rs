//! Serde structs for HiPKI / PKCS#11 API responses.
//!
//! Implementation lives in `zkid-input-builder`; kept as a thin re-export so
//! downstream consumers (including the mobile crate) continue to resolve
//! `ecdsa_spartan2::circuits::types::*`.

pub use zkid_input_builder::types::{
    CardSignResponse, Pkcs11CertEntry, Pkcs11InfoResponse, Pkcs11Slot, Pkcs11TokenInfo,
    Rs4096SignResponse, Rs4096SignResult, SmtCircuitInputs,
};
