//! ECDSA and JWT circuit implementations using Spartan2
//!
//! This library provides zero-knowledge proof circuits for:
//! - ECDSA signature verification
//! - JWT token validation with selective disclosure
//!
//! The circuits use Spartan2's ZK-SNARK protocol with Hyrax polynomial commitment scheme.

use spartan2::{provider::T256HyraxEngine, traits::Engine};

pub type E = T256HyraxEngine;
pub type Scalar = <E as Engine>::Scalar;

pub mod circuits;
pub mod paths;
pub mod prover;
pub mod setup;
pub mod utils;

// Re-export commonly used types and functions
pub use circuits::{
    jwt_rs256_circuit::JwtRs256Circuit, prepare_circuit::PrepareCircuit,
    show_circuit::ShowCircuit,
};
pub use paths::PathConfig;
pub use prover::{
    generate_prepare_witness, generate_shared_blinds, prove_circuit, prove_circuit_in_memory,
    prove_circuit_with_pk, reblind, reblind_in_memory, reblind_with_loaded_data, run_circuit,
    verify_circuit, verify_circuit_with_loaded_data,
};
pub use setup::{
    load_instance, load_proof, load_proving_key, load_shared_blinds, load_verifying_key,
    load_witness, save_keys, setup_circuit_keys, setup_circuit_keys_no_save,
};
pub use utils::{
    bigint_to_scalar, calculate_jwt_output_indices, convert_bigint_to_scalar, parse_jwt_inputs,
    parse_show_inputs,
};
