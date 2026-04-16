use std::{
    fs::{create_dir_all, File},
    io::{BufReader, BufWriter, Cursor},
    path::Path,
    time::Instant,
};

use spartan2::{
    r1cs::{R1CSWitness, SplitR1CSInstance},
    traits::{circuit::SpartanCircuit, snark::R1CSSNARKTrait, Engine},
    zk_spartan::R1CSSNARK,
};
use tracing::info;

use crate::E;
use memmap2::MmapOptions;

fn ensure_parent_dir(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(parent) = path.parent() {
        create_dir_all(parent)?;
    }
    Ok(())
}

pub fn save_keys(
    pk_path: impl AsRef<Path>,
    vk_path: impl AsRef<Path>,
    pk: &<R1CSSNARK<E> as R1CSSNARKTrait<E>>::ProverKey,
    vk: &<R1CSSNARK<E> as R1CSSNARKTrait<E>>::VerifierKey,
) -> Result<(), Box<dyn std::error::Error>> {
    let pk_path = pk_path.as_ref();
    let vk_path = vk_path.as_ref();

    ensure_parent_dir(pk_path)?;
    ensure_parent_dir(vk_path)?;

    bincode::serialize_into(BufWriter::new(File::create(pk_path)?), pk)?;
    info!("Saved ZK-Spartan proving key to: {}", pk_path.display());

    bincode::serialize_into(BufWriter::new(File::create(vk_path)?), vk)?;
    info!("Saved ZK-Spartan verifying key to: {}", vk_path.display());

    Ok(())
}

#[allow(dead_code)]
pub fn load_keys(
    pk_path: impl AsRef<Path>,
    vk_path: impl AsRef<Path>,
) -> Result<
    (
        <R1CSSNARK<E> as R1CSSNARKTrait<E>>::ProverKey,
        <R1CSSNARK<E> as R1CSSNARKTrait<E>>::VerifierKey,
    ),
    Box<dyn std::error::Error>,
> {
    let pk_path = pk_path.as_ref();
    let vk_path = vk_path.as_ref();

    let pk_file = File::open(pk_path)?;
    let pk = bincode::deserialize_from(&mut BufReader::new(pk_file))?;

    info!("Loaded ZK-Spartan proving key from: {}", pk_path.display());

    let vk_file = File::open(vk_path)?;
    let vk = bincode::deserialize_from(&mut BufReader::new(vk_file))?;
    info!(
        "Loaded ZK-Spartan verifying key from: {}",
        vk_path.display()
    );

    Ok((pk, vk))
}

pub fn load_proving_key(
    pk_path: impl AsRef<Path>,
) -> Result<<R1CSSNARK<E> as R1CSSNARKTrait<E>>::ProverKey, Box<dyn std::error::Error>> {
    let pk_file = File::open(pk_path.as_ref())?;
    let pk_mmap = unsafe { MmapOptions::new().map(&pk_file)? };
    let pk: <R1CSSNARK<E> as R1CSSNARKTrait<E>>::ProverKey =
        bincode::deserialize_from(Cursor::new(&pk_mmap[..]))?;
    drop(pk_mmap);
    Ok(pk)
}

pub fn load_verifying_key(
    vk_path: impl AsRef<Path>,
) -> Result<<R1CSSNARK<E> as R1CSSNARKTrait<E>>::VerifierKey, Box<dyn std::error::Error>> {
    let vk_file = File::open(vk_path.as_ref())?;
    let vk_mmap = unsafe { MmapOptions::new().map(&vk_file)? };
    let vk: <R1CSSNARK<E> as R1CSSNARKTrait<E>>::VerifierKey =
        bincode::deserialize_from(Cursor::new(&vk_mmap[..]))?;
    drop(vk_mmap);
    Ok(vk)
}

pub fn save_shared_blinds<E: Engine>(
    shared_blinds_path: impl AsRef<Path>,
    shared_blinds: &[E::Scalar],
) -> Result<(), Box<dyn std::error::Error>> {
    let shared_blinds_path = shared_blinds_path.as_ref();
    ensure_parent_dir(shared_blinds_path)?;

    bincode::serialize_into(BufWriter::new(File::create(shared_blinds_path)?), shared_blinds)?;
    info!(
        "Saved ZK-Spartan shared_blinds to: {}",
        shared_blinds_path.display()
    );

    Ok(())
}

pub fn save_proof(
    proof_path: impl AsRef<Path>,
    proof: &R1CSSNARK<E>,
) -> Result<(), Box<dyn std::error::Error>> {
    let proof_path = proof_path.as_ref();
    ensure_parent_dir(proof_path)?;

    bincode::serialize_into(BufWriter::new(File::create(proof_path)?), proof)?;
    info!("Saved ZK-Spartan proof to: {}", proof_path.display());

    Ok(())
}

pub fn save_instance(
    instance_path: impl AsRef<Path>,
    instance: &SplitR1CSInstance<E>,
) -> Result<(), Box<dyn std::error::Error>> {
    let instance_path = instance_path.as_ref();
    ensure_parent_dir(instance_path)?;

    bincode::serialize_into(BufWriter::new(File::create(instance_path)?), instance)?;
    info!("Saved ZK-Spartan instance to: {}", instance_path.display());

    Ok(())
}

pub fn save_witness(
    witness_path: impl AsRef<Path>,
    witness: &R1CSWitness<E>,
) -> Result<(), Box<dyn std::error::Error>> {
    let witness_path = witness_path.as_ref();
    ensure_parent_dir(witness_path)?;

    bincode::serialize_into(BufWriter::new(File::create(witness_path)?), witness)?;
    info!("Saved ZK-Spartan witness to: {}", witness_path.display());

    Ok(())
}

pub fn load_shared_blinds<E: Engine>(
    shared_blinds_path: impl AsRef<Path>,
) -> Result<Vec<E::Scalar>, Box<dyn std::error::Error>> {
    let shared_blinds_path = shared_blinds_path.as_ref();
    let shared_blinds_file = File::open(shared_blinds_path)?;
    let shared_blinds: Vec<E::Scalar> =
        bincode::deserialize_from(&mut BufReader::new(shared_blinds_file))?;
    info!(
        "Loaded ZK-Spartan shared_blinds from: {}",
        shared_blinds_path.display()
    );
    Ok(shared_blinds)
}

pub fn load_proof(
    proof_path: impl AsRef<Path>,
) -> Result<R1CSSNARK<E>, Box<dyn std::error::Error>> {
    let proof_path = proof_path.as_ref();
    let proof_file = File::open(proof_path)?;
    let proof: R1CSSNARK<E> = bincode::deserialize_from(&mut BufReader::new(proof_file))?;
    info!("Loaded ZK-Spartan proof from: {}", proof_path.display());
    Ok(proof)
}

pub fn load_instance(
    instance_path: impl AsRef<Path>,
) -> Result<SplitR1CSInstance<E>, Box<dyn std::error::Error>> {
    let instance_path = instance_path.as_ref();
    let instance_file = File::open(instance_path)?;
    let instance: SplitR1CSInstance<E> =
        bincode::deserialize_from(&mut BufReader::new(instance_file))?;
    info!(
        "Loaded ZK-Spartan instance from: {}",
        instance_path.display()
    );
    Ok(instance)
}

pub fn load_witness(
    witness_path: impl AsRef<Path>,
) -> Result<R1CSWitness<E>, Box<dyn std::error::Error>> {
    let witness_path = witness_path.as_ref();
    let witness_file = File::open(witness_path)?;
    let witness: R1CSWitness<E> = bincode::deserialize_from(&mut BufReader::new(witness_file))?;
    info!("Loaded ZK-Spartan witness from: {}", witness_path.display());
    Ok(witness)
}

pub fn setup_circuit_keys<C: SpartanCircuit<E> + Clone + std::fmt::Debug>(
    circuit: C,
    pk_path: impl AsRef<Path>,
    vk_path: impl AsRef<Path>,
) {
    let pk_path = pk_path.as_ref();
    let vk_path = vk_path.as_ref();

    let t0 = Instant::now();
    let (pk, vk) = R1CSSNARK::<E>::setup(circuit.clone()).expect("setup failed");
    let setup_ms = t0.elapsed().as_millis();
    info!(
        elapsed_ms = setup_ms,
        "Setup completed (~{:.1}s)",
        setup_ms as f64 / 1000.0
    );

    if let Err(e) = save_keys(pk_path, vk_path, &pk, &vk) {
        eprintln!("Failed to save keys: {}", e);
        std::process::exit(1);
    }

    info!("Keys generated and saved successfully!");
    info!("Proving key: {}", pk_path.display());
    info!("Verifying key: {}", vk_path.display());
}

/// Setup circuit keys without saving to file - useful for benchmarking
/// Returns the proving and verifying keys
pub fn setup_circuit_keys_no_save<C: SpartanCircuit<E> + Clone + std::fmt::Debug>(
    circuit: C,
) -> (
    <R1CSSNARK<E> as R1CSSNARKTrait<E>>::ProverKey,
    <R1CSSNARK<E> as R1CSSNARKTrait<E>>::VerifierKey,
) {
    R1CSSNARK::<E>::setup(circuit.clone()).expect("setup failed")
}
