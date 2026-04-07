use ecdsa_spartan2::{
    parse_witness, paths::PathConfig, prove_circuit_in_memory, save_keys,
    setup_circuit_keys_no_save, Rs256Circuit, E,
};
use spartan2::{traits::snark::R1CSSNARKTrait, zk_spartan::R1CSSNARK};
use std::path::Path;
use tracing::info;
use tracing_subscriber::EnvFilter;

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse().unwrap()))
        .init();

    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(|s| s.as_str()).unwrap_or("setup");

    let config = PathConfig::development();

    match cmd {
        "setup" => {
            info!("Setting up RS256 circuit keys...");
            let rs256_circuit = Rs256Circuit::new(config.clone(), None);
            let (pk, vk) = setup_circuit_keys_no_save(rs256_circuit);

            let pk_path = config.key_path("rs256_proving.key");
            let vk_path = config.key_path("rs256_verifying.key");
            save_keys(&pk_path, &vk_path, &pk, &vk).expect("Failed to save RS256 keys");

            info!("RS256 keys generated!");
        }
        "prove-witness-only" => {
            // Test the witness-only proving path (same code path as WASM)
            // Requires a pre-generated .wtns file
            let wtns_path = args.get(2).expect("Usage: prove-witness-only <witness.wtns>");

            info!("Loading proving key...");
            let pk_path = config.key_path("rs256_proving.key");
            let pk_bytes = std::fs::read(&pk_path).expect("Failed to read PK");
            info!("PK size: {} bytes", pk_bytes.len());
            let pk: <R1CSSNARK<E> as R1CSSNARKTrait<E>>::ProverKey =
                bincode::deserialize(&pk_bytes).expect("Failed to deserialize PK");

            info!("Loading witness from {}...", wtns_path);
            let wtns_bytes = std::fs::read(wtns_path).expect("Failed to read witness");
            info!("Witness file size: {} bytes", wtns_bytes.len());
            let witness_scalars = parse_witness(&wtns_bytes).expect("Failed to parse witness");
            info!("Witness: {} scalars", witness_scalars.len());

            info!("Proving with witness-only path...");
            let circuit = Rs256Circuit::with_witness(witness_scalars);
            let (proof, _instance, _witness) =
                prove_circuit_in_memory(circuit, &pk).expect("Prove failed");
            info!("Prove succeeded!");

            info!("Verifying...");
            let vk_path = config.key_path("rs256_verifying.key");
            let vk_bytes = std::fs::read(&vk_path).expect("Failed to read VK");
            let vk: <R1CSSNARK<E> as R1CSSNARKTrait<E>>::VerifierKey =
                bincode::deserialize(&vk_bytes).expect("Failed to deserialize VK");
            let pv = proof.verify(&vk).expect("Verification failed");
            info!("Verified! {} public values", pv.len());
        }
        _ => {
            eprintln!("Usage: ecdsa-spartan2-jwt [setup|prove-witness-only <witness.wtns>]");
            std::process::exit(1);
        }
    }
}
