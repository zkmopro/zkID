//! Certificate DER parsing and extraction helpers.
//!
//! Implementation lives in `zkid-input-builder` so the browser prover shares
//! the exact offset-computation logic. Kept as a thin re-export to preserve
//! the `ecdsa_spartan2::circuits::cert` import path.

pub use zkid_input_builder::cert::{
    extract_issuer_cert, fetch_cert_from_file, generate_user_cert_from_certb64, parse_cert_offsets,
    serial_bytes_to_hex_trimmed, CertOffsets,
};
