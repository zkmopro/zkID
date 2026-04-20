//! Shared input builder for the zkID RS256 split circuits.
//!
//! Produces cert-chain + device-sig JSON inputs from raw certificate DER,
//! signatures, and SMT non-membership proof. Consumed by `ecdsa-spartan2`
//! (native prover) and `spartan2-wasm` (in-browser prover) so both paths
//! produce byte-identical JSON — which is the guard against reintroducing
//! the PR #40 "Too many values for input signal __placeholder__" bug class.

pub mod cert;
pub mod encoding;
pub mod split_inputs;
pub mod types;

pub use split_inputs::{generate_split_inputs, MAX_CERT_CHAIN_LENGTH};
