use std::path::Path;
use web_time::Instant;

use crate::{
    setup::{
        load_instance, load_proof, load_proving_key, load_shared_blinds, load_verifying_key,
        load_witness, save_instance, save_proof, save_witness,
    },
    Scalar, E,
};

use spartan2::{
    bellpepper::{solver::SatisfyingAssignment, zk_r1cs::SpartanWitness},
    errors::SpartanError,
    provider::traits::DlogGroup,
    traits::{
        circuit::SpartanCircuit, snark::R1CSSNARKTrait, transcript::TranscriptEngineTrait, Engine,
    },
    zk_spartan::R1CSSNARK,
};
use tracing::info;

/// Run circuit using ZK-Spartan (setup, prepare, prove, verify)
pub fn run_circuit<C: SpartanCircuit<E> + Clone + std::fmt::Debug>(circuit: C) {
    // SETUP using ZK-Spartan
    let t0 = Instant::now();
    let (pk, vk) = R1CSSNARK::<E>::setup(circuit.clone()).expect("setup failed");
    let setup_ms = t0.elapsed().as_millis();
    info!(elapsed_ms = setup_ms, "ZK-Spartan setup");

    // PREPARE
    let t0 = Instant::now();
    let mut prep_snark =
        R1CSSNARK::<E>::prep_prove(&pk, circuit.clone(), false).expect("prep_prove failed");
    let prep_ms = t0.elapsed().as_millis();
    info!(elapsed_ms = prep_ms, "ZK-Spartan prep_prove");

    // PROVE
    let t0 = Instant::now();
    let proof =
        R1CSSNARK::<E>::prove(&pk, circuit.clone(), &mut prep_snark, false).expect("prove failed");
    let prove_ms = t0.elapsed().as_millis();
    info!(elapsed_ms = prove_ms, "ZK-Spartan prove");

    // VERIFY
    let t0 = Instant::now();
    proof.verify(&vk).expect("verify errored");
    let verify_ms = t0.elapsed().as_millis();
    info!(elapsed_ms = verify_ms, "ZK-Spartan verify");

    // Summary
    info!(
        "ZK-Spartan SUMMARY , setup={} ms, prep_prove={} ms, prove={} ms, verify={} ms",
        setup_ms, prep_ms, prove_ms, verify_ms
    );

    info!("comm_W_shared: {:?}", proof.comm_W_shared());
}

/// Only run the proving part of the circuit using ZK-Spartan (prep_prove, prove)
pub fn prove_circuit<C: SpartanCircuit<E> + Clone + std::fmt::Debug>(
    circuit: C,
    pk_path: impl AsRef<Path>,
    instance_path: impl AsRef<Path>,
    witness_path: impl AsRef<Path>,
    proof_path: impl AsRef<Path>,
) {
    let t0 = Instant::now();
    let pk = load_proving_key(&pk_path).expect("load proving key failed");
    info!("ZK-Spartan load proving key: {} ms", t0.elapsed().as_millis());
    drop(pk_path);

    prove_circuit_with_pk(circuit, &pk, instance_path, witness_path, proof_path);
    drop(pk);
}

/// Only run the proving part of the circuit using ZK-Spartan with a pre-loaded proving key
/// This is useful for benchmarking to exclude file I/O from timing measurements
pub fn prove_circuit_with_pk<C: SpartanCircuit<E> + Clone + std::fmt::Debug>(
    circuit: C,
    pk: &<R1CSSNARK<E> as R1CSSNARKTrait<E>>::ProverKey,
    instance_path: impl AsRef<Path>,
    witness_path: impl AsRef<Path>,
    proof_path: impl AsRef<Path>,
) {
    let t0 = Instant::now();
    let mut prep_snark =
        R1CSSNARK::<E>::prep_prove(&pk, circuit.clone(), false).expect("prep_prove failed");
    let prep_ms = t0.elapsed().as_millis();
    info!("ZK-Spartan prep_prove: {} ms", prep_ms);

    let t0 = Instant::now();
    let mut transcript = <E as Engine>::TE::new(b"R1CSSNARK");
    transcript.absorb(b"vk", &pk.vk_digest);

    let public_values = SpartanCircuit::<E>::public_values(&circuit)
        .map_err(|e| SpartanError::SynthesisError {
            reason: format!("Circuit does not provide public IO: {e}"),
        })
        .unwrap();

    // absorb the public values into the transcript
    transcript.absorb(b"public_values", &public_values.as_slice());

    let (instance, witness) = SatisfyingAssignment::r1cs_instance_and_witness(
        &mut prep_snark.ps,
        &pk.S,
        &pk.ck,
        &circuit,
        false,
        &mut transcript,
    )
    .unwrap();
    drop(prep_snark);
    drop(circuit);

    // generate a witness and proof
    let res = R1CSSNARK::<E>::prove_inner(&pk, &instance, &witness, &mut transcript).unwrap();
    let prove_ms = t0.elapsed().as_millis();

    info!("ZK-Spartan prove: {} ms", prove_ms);
    info!(
        "ZK-Spartan prep_prove: ({} ms) + prove: ({} ms) = TOTAL: {} ms",
        prep_ms, prove_ms, prep_ms + prove_ms
    );

    // Save instance and witness, then drop them before serialising the proof.
    if let Err(e) = save_instance(instance_path, &instance) {
        eprintln!("Failed to save instance: {}", e);
        std::process::exit(1);
    }
    drop(instance);

    if let Err(e) = save_witness(witness_path, &witness) {
        eprintln!("Failed to save witness: {}", e);
        std::process::exit(1);
    }
    drop(witness);

    if let Err(e) = save_proof(proof_path, &res) {
        eprintln!("Failed to save proof: {}", e);
        std::process::exit(1);
    }
    drop(res);
}

pub fn reblind<C: SpartanCircuit<E>>(
    circuit: C,
    pk_path: impl AsRef<Path>,
    instance_path: impl AsRef<Path>,
    witness_path: impl AsRef<Path>,
    proof_path: impl AsRef<Path>,
    shared_blinds_path: impl AsRef<Path>,
) {
    let pk = load_proving_key(&pk_path).expect("load proving key failed");
    let instance = load_instance(&instance_path).expect("load instance failed");
    let witness = load_witness(&witness_path).expect("load witness failed");
    let randomness =
        load_shared_blinds::<E>(&shared_blinds_path).expect("load shared_blinds failed");

    reblind_with_loaded_data(
        circuit,
        &pk,
        instance,
        witness,
        &randomness,
        instance_path,
        witness_path,
        proof_path,
    );
}

/// Reblind with pre-loaded data - useful for benchmarking to exclude file I/O
pub fn reblind_with_loaded_data<C: SpartanCircuit<E>>(
    circuit: C,
    pk: &<R1CSSNARK<E> as R1CSSNARKTrait<E>>::ProverKey,
    instance: spartan2::r1cs::SplitR1CSInstance<E>,
    witness: spartan2::r1cs::R1CSWitness<E>,
    randomness: &[<E as Engine>::Scalar],
    instance_path: impl AsRef<Path>,
    witness_path: impl AsRef<Path>,
    proof_path: impl AsRef<Path>,
) {
    assert_eq!(randomness.len(), instance.num_shared_rows());

    // Reblind instance and witness
    let mut reblind_transcript = <E as Engine>::TE::new(b"R1CSSNARK");
    reblind_transcript.absorb(b"vk", &pk.vk_digest);

    let public_values = SpartanCircuit::<E>::public_values(&circuit)
        .map_err(|e| SpartanError::SynthesisError {
            reason: format!("Circuit does not provide public IO: {e}"),
        })
        .unwrap();

    // absorb the public values into the reblind_transcript
    reblind_transcript.absorb(b"public_values", &public_values.as_slice());

    let (new_instance, new_witness) = SatisfyingAssignment::reblind_r1cs_instance_and_witness(
        &randomness,
        instance,
        witness,
        &pk.ck,
        &mut reblind_transcript,
    )
    .unwrap();

    println!(
        "new instance: {:?}",
        new_instance
            .clone()
            .comm_W_shared
            .map(|v| v.comm.iter().for_each(|v| println!("v: {:?}", v.affine())))
    );

    // generate a witness and proof
    let res =
        R1CSSNARK::<E>::prove_inner(&pk, &new_instance, &new_witness, &mut reblind_transcript)
            .unwrap();

    // Save the instance to file
    if let Err(e) = save_instance(instance_path, &new_instance) {
        eprintln!("Failed to save instance: {}", e);
        std::process::exit(1);
    }

    // Save the witness to file
    if let Err(e) = save_witness(witness_path, &new_witness) {
        eprintln!("Failed to save witness: {}", e);
        std::process::exit(1);
    }

    // Save the proof to file
    if let Err(e) = save_proof(proof_path, &res) {
        eprintln!("Failed to save proof: {}", e);
        std::process::exit(1);
    }
}

/// Prove a circuit and return results in memory (no file I/O).
/// This is the building block for the WASM `precompute()` API.
pub fn prove_circuit_in_memory<C: SpartanCircuit<E> + Clone + std::fmt::Debug>(
    circuit: C,
    pk: &<R1CSSNARK<E> as R1CSSNARKTrait<E>>::ProverKey,
) -> Result<
    (
        R1CSSNARK<E>,
        spartan2::r1cs::SplitR1CSInstance<E>,
        spartan2::r1cs::R1CSWitness<E>,
    ),
    SpartanError,
> {
    let t0 = Instant::now();
    let mut prep_snark = R1CSSNARK::<E>::prep_prove(&pk, circuit.clone(), false)?;
    let prep_ms = t0.elapsed().as_millis();
    info!("ZK-Spartan prep_prove (in-memory): {} ms", prep_ms);

    let t0 = Instant::now();
    let mut transcript = <E as Engine>::TE::new(b"R1CSSNARK");
    transcript.absorb(b"vk", &pk.vk_digest);

    let public_values =
        SpartanCircuit::<E>::public_values(&circuit).map_err(|e| SpartanError::SynthesisError {
            reason: format!("Circuit does not provide public IO: {e}"),
        })?;

    transcript.absorb(b"public_values", &public_values.as_slice());

    let (instance, witness) = SatisfyingAssignment::r1cs_instance_and_witness(
        &mut prep_snark.ps,
        &pk.S,
        &pk.ck,
        &circuit,
        false,
        &mut transcript,
    )
    .map_err(|e| SpartanError::SynthesisError {
        reason: format!("Instance/witness generation failed: {e}"),
    })?;

    let proof = R1CSSNARK::<E>::prove_inner(&pk, &instance, &witness, &mut transcript)?;
    let prove_ms = t0.elapsed().as_millis();

    info!(
        "ZK-Spartan prove (in-memory): prep={} ms, prove={} ms, total={} ms",
        prep_ms,
        prove_ms,
        prep_ms + prove_ms
    );

    Ok((proof, instance, witness))
}

/// Reblind a proof with shared randomness and return results in memory (no file I/O).
/// This is the building block for the WASM `present()` API.
pub fn reblind_in_memory<C: SpartanCircuit<E>>(
    circuit: C,
    pk: &<R1CSSNARK<E> as R1CSSNARKTrait<E>>::ProverKey,
    instance: spartan2::r1cs::SplitR1CSInstance<E>,
    witness: spartan2::r1cs::R1CSWitness<E>,
    randomness: &[<E as Engine>::Scalar],
) -> Result<
    (
        R1CSSNARK<E>,
        spartan2::r1cs::SplitR1CSInstance<E>,
        spartan2::r1cs::R1CSWitness<E>,
    ),
    SpartanError,
> {
    assert_eq!(randomness.len(), instance.num_shared_rows());

    let mut reblind_transcript = <E as Engine>::TE::new(b"R1CSSNARK");
    reblind_transcript.absorb(b"vk", &pk.vk_digest);

    let public_values =
        SpartanCircuit::<E>::public_values(&circuit).map_err(|e| SpartanError::SynthesisError {
            reason: format!("Circuit does not provide public IO: {e}"),
        })?;

    reblind_transcript.absorb(b"public_values", &public_values.as_slice());

    let (new_instance, new_witness) = SatisfyingAssignment::reblind_r1cs_instance_and_witness(
        &randomness,
        instance,
        witness,
        &pk.ck,
        &mut reblind_transcript,
    )
    .map_err(|e| SpartanError::SynthesisError {
        reason: format!("Reblind failed: {e}"),
    })?;

    let proof =
        R1CSSNARK::<E>::prove_inner(&pk, &new_instance, &new_witness, &mut reblind_transcript)?;

    info!("ZK-Spartan reblind (in-memory): complete");

    Ok((proof, new_instance, new_witness))
}

/// Only run the verification part using ZK-Spartan.
/// Returns the public values embedded in the proof.
pub fn verify_circuit(proof_path: impl AsRef<Path>, vk_path: impl AsRef<Path>) -> Vec<Scalar> {
    let proof = load_proof(&proof_path).expect("load proof failed");
    let vk = load_verifying_key(&vk_path).expect("load verifying key failed");

    verify_circuit_with_loaded_data(&proof, &vk)
}

/// Verify circuit with pre-loaded data - useful for benchmarking to exclude file I/O.
/// Returns the public values embedded in the proof.
pub fn verify_circuit_with_loaded_data(
    proof: &R1CSSNARK<E>,
    vk: &<R1CSSNARK<E> as R1CSSNARKTrait<E>>::VerifierKey,
) -> Vec<Scalar> {
    let t0 = Instant::now();
    let public_values = proof.verify(&vk).expect("verify errored");
    let verify_ms = t0.elapsed().as_millis();
    info!(elapsed_ms = verify_ms, "ZK-Spartan verify");

    info!("Verification successful! Time: {} ms", verify_ms);
    public_values
}
