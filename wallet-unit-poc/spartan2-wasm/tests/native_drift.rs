//! Native-target drift test: prove via spartan2-wasm, verify via ecdsa-spartan2.
//!
//! If ecdsa-spartan2 changes its transcript sequence, this test fails — forcing
//! a sync of the duplicated prove logic in spartan2-wasm.
//!
//! Runs on the default (native) target only. Never compiled for wasm32.

#![cfg(not(target_arch = "wasm32"))]

use ecdsa_spartan2::{
    circuits::{
        circuit::{RsaKeySize, Sha256RsaCircuit},
        split_circuits::{CertChainRsa2048, DeviceSigRsa2048},
    },
    setup::setup_circuit_keys_no_save,
};
use spartan2_wasm::{prove_native_for_test, CircuitKind};

fn fixture_input(kind: CircuitKind) -> String {
    let path = match kind {
        CircuitKind::CertChainRs2048 => "../circom/inputs/cert_chain_rs2048/input.json",
        CircuitKind::CertChainRs4096 => panic!("RS4096 fixture not available in unit tests"),
        CircuitKind::DeviceSigRs2048 => "../circom/inputs/device_sig_rs2048/input.json",
    };
    std::fs::read_to_string(path).expect("read fixture input")
}

/// `T::generate_witness_bytes` calls C++ witnesscalc which uses `realloc()` and
/// can SIGSEGV on macOS from the default 8 MB test thread. Wrap in a 256 MB
/// stack thread (mirrors `Sha256RsaCircuit::generate_witness` at
/// `ecdsa-spartan2/src/circuits/circuit.rs:143`).
fn witness_bytes_in_big_stack<T: RsaKeySize + Send + 'static>(input: String) -> Vec<u8> {
    std::thread::Builder::new()
        .stack_size(256 * 1024 * 1024)
        .spawn(move || T::generate_witness_bytes(&input))
        .expect("spawn big-stack thread")
        .join()
        .expect("big-stack thread panicked")
        .expect("witness-gen failed")
}

#[test]
fn cert_chain_rs2048_drift() {
    let input = fixture_input(CircuitKind::CertChainRs2048);
    let wtns = witness_bytes_in_big_stack::<CertChainRsa2048>(input);

    // `setup_circuit_keys_no_save` panics on failure; no `Result` wrapping.
    // `Sha256RsaCircuit::<T>::default()` is the canonical "shape-only" constructor
    // (see `ecdsa-spartan2/src/circuits/circuit.rs:59`).
    let (pk, vk) = setup_circuit_keys_no_save::<Sha256RsaCircuit<CertChainRsa2048>>(
        Sha256RsaCircuit::<CertChainRsa2048>::default(),
    );

    let pk_bytes = bincode::serialize(&pk).unwrap();
    let vk_bytes = bincode::serialize(&vk).unwrap();

    // Prove via spartan2-wasm's internal (non-JS) prove path.
    let (proof_bytes, _instance_bytes, public_values) =
        prove_native_for_test(CircuitKind::CertChainRs2048, &pk_bytes, &wtns)
            .expect("spartan2-wasm prove");

    // Verify via ecdsa-spartan2 public API — if transcripts drifted, `proof.verify`
    // returns Err and `verify_circuit_with_loaded_data` panics.
    let proof: spartan2_wasm::R1CSSNARKForTest =
        bincode::deserialize(&proof_bytes).unwrap();
    let vk_native: spartan2_wasm::VerifierKeyForTest = bincode::deserialize(&vk_bytes).unwrap();
    let pv = ecdsa_spartan2::prover::verify_circuit_with_loaded_data(&proof, &vk_native);

    assert_eq!(pv.len(), 21, "cert_chain_rs2048 NUM_PUBLIC");
    assert_eq!(pv, public_values, "public values round-trip");
}

#[test]
fn device_sig_rs2048_drift() {
    let input = fixture_input(CircuitKind::DeviceSigRs2048);
    let wtns = witness_bytes_in_big_stack::<DeviceSigRsa2048>(input);

    let (pk, vk) = setup_circuit_keys_no_save::<Sha256RsaCircuit<DeviceSigRsa2048>>(
        Sha256RsaCircuit::<DeviceSigRsa2048>::default(),
    );

    let pk_bytes = bincode::serialize(&pk).unwrap();
    let vk_bytes = bincode::serialize(&vk).unwrap();

    let (proof_bytes, _instance_bytes, public_values) =
        prove_native_for_test(CircuitKind::DeviceSigRs2048, &pk_bytes, &wtns).unwrap();

    let proof: spartan2_wasm::R1CSSNARKForTest = bincode::deserialize(&proof_bytes).unwrap();
    let vk_native: spartan2_wasm::VerifierKeyForTest = bincode::deserialize(&vk_bytes).unwrap();
    let pv = ecdsa_spartan2::prover::verify_circuit_with_loaded_data(&proof, &vk_native);

    assert_eq!(pv.len(), 51, "device_sig_rs2048 NUM_PUBLIC");
    assert_eq!(pv, public_values);
}
