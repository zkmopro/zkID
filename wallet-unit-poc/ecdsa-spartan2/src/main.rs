//! CLI for running the Spartan-2 RS256 circuit.
//!
//! Two RSA key-size variants are supported, selected at build time via Cargo features
//! and at runtime via the `--fido` flag:
//!
//!   | Mode          | Feature flag      | Key size | CA             |
//!   |---------------|-------------------|----------|----------------|
//!   | Default/HiPKI | `sha256rsa2048`   | RSA-2048 | MOICA-G2       |
//!   | FIDO          | `sha256rsa4096`   | RSA-4096 | MOICA-G3       |
//!
//! # Generate circuit input
//!
//!   # Default mode — RSA-2048, bundled test fixtures
//!   cargo run --release --features sha256rsa2048 -- rs256 generate-input
//!
//!   # Live mode — RSA-2048, calls HiPKI LocalSignServer with a physical card
//!   cargo run --release --features sha256rsa2048 -- rs256 generate-input --tbs 123456 --pin 830929
//!
//!   # FIDO mode — RSA-4096, bundled test fixtures (MOICA-G3)
//!   cargo run --release --features sha256rsa4096 -- rs256 generate-input --fido
//!
//! # Setup / Prove / Verify  (RSA-2048)
//!
//!   cargo run --release --features sha256rsa2048 -- rs256 setup  --input ../circom/inputs/sha256rsa2048/input.json
//!   cargo run --release --features sha256rsa2048 -- rs256 prove  --input ../circom/inputs/sha256rsa2048/input.json
//!   cargo run --release --features sha256rsa2048 -- rs256 verify
//!
//! # Setup / Prove / Verify  (RSA-4096 / FIDO)
//!
//!   cargo run --release --features sha256rsa4096 -- rs256 setup  --fido --input ../circom/inputs/sha256rsa4096/input.json
//!   cargo run --release --features sha256rsa4096 -- rs256 prove  --fido --input ../circom/inputs/sha256rsa4096/input.json
//!   cargo run --release --features sha256rsa4096 -- rs256 verify --fido
//!
//! # Benchmark
//!
//!   cargo run --release --features sha256rsa2048 -- rs256 benchmark
//!   cargo run --release --features sha256rsa4096 -- rs256 benchmark --fido

use ecdsa_spartan2::{
    generate_split_inputs, hipki_client, load_proof, prove_circuit, prove_circuit_with_pk,
    run_circuit, save_keys, setup_circuit_keys, setup_circuit_keys_no_save, verify_circuit,
    verify_circuit_with_loaded_data, CertChainRsa2048, CertChainRsa4096, DeviceSigRsa2048,
    PathConfig, Rsa2048, Rsa4096, Rs256Circuit, Rs256FidoCircuit, RsaKeySize, Sha256RsaCircuit,
};
use std::{env::args, fs, path::PathBuf, process, time::Instant};
use tracing::info;
use tracing_subscriber::EnvFilter;

/// Helper function to get file size in bytes
fn get_file_size(path: &str) -> u64 {
    fs::metadata(path).map(|m| m.len()).unwrap_or(0)
}

/// Format bytes into human-readable size string
fn format_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.2} KB", bytes as f64 / 1024.0)
    } else {
        format!("{:.2} MB", bytes as f64 / (1024.0 * 1024.0))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CircuitAction {
    Run,
    Setup,
    Prove,
    Verify,
    Benchmark,
}

#[derive(Debug, Default, Clone)]
struct CommandOptions {
    input: Option<PathBuf>,
    /// Use RSA-4096 (FIDO/MOICA-G3) circuit instead of RSA-2048.
    fido: bool,
}

#[derive(Debug, Clone)]
struct ParsedCommand {
    action: CircuitAction,
    options: CommandOptions,
}

fn main() {
    tracing_subscriber::fmt()
        .with_target(false)
        .with_ansi(true)
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let args: Vec<String> = args().collect();
    let command_args: &[String] = if args.len() > 1 { &args[1..] } else { &[] };

    // ── generate-split-input: produces per-circuit JSONs for CertChain + DeviceSig ──
    if command_args.contains(&"generate-split-input".to_string()) {
        let mut fido = false;
        let mut smt_server: Option<String> = None;
        let mut issuer = "g2".to_string();
        let mut cert_chain_output = "../circom/inputs/cert_chain_rs2048/input.json".to_string();
        let device_sig_output = "../circom/inputs/device_sig_rs2048/input.json".to_string();

        let mut i = 2;
        while i < command_args.len() {
            match command_args[i].as_str() {
                "--fido" => {
                    fido = true;
                    cert_chain_output = "../circom/inputs/cert_chain_rs4096/input.json".to_string();
                    issuer = "g3".to_string();
                }
                "--smt-server" => {
                    i += 1;
                    smt_server = Some(command_args.get(i).cloned().unwrap_or_else(|| {
                        eprintln!("Missing value for --smt-server");
                        process::exit(1);
                    }));
                }
                "--issuer" => {
                    i += 1;
                    issuer = command_args.get(i).cloned().unwrap_or_else(|| {
                        eprintln!("Missing value for --issuer");
                        process::exit(1);
                    });
                }
                _ => {}
            }
            i += 1;
        }

        let (k_issuer, k_user) = if fido { (34, 17) } else { (17, 17) };

        // Load test fixtures (default mode — bundled certs + signatures)
        let default_tbs = b"e775f2805fb993e05a208dbff15d1c1";
        let (user_cert, user_sig_b64, issuer_cert, serial_hex) = if fido {
            let response_path = std::path::Path::new("tests/testdata/fido_response_sign.json");
            let issuer_cert = Rs256FidoCircuit::fetch_cert_from_file("tests/testdata/MOICA-G3.cer")
                .expect("Failed to load MOICA-G3 cert");
            let response_str = std::fs::read_to_string(response_path)
                .expect("Failed to read FIDO sign response");
            let response: ecdsa_spartan2::circuits::sha256rsa_circuit::FidoSignResponse =
                serde_json::from_str(&response_str).expect("Failed to parse FIDO response");
            let user_cert = Rs256FidoCircuit::generate_user_cert_from_certb64(&response.result.cert)
                .expect("Failed to parse user cert");
            let serial_bytes = user_cert.tbs_certificate.serial_number.as_bytes();
            let trimmed: Vec<u8> = serial_bytes.iter().skip_while(|&&b| b == 0).copied().collect();
            let serial_hex = hex::encode(if trimmed.is_empty() { serial_bytes } else { &trimmed });
            (user_cert, response.result.signed_response, issuer_cert, serial_hex)
        } else {
            let response_path = std::path::Path::new("tests/testdata/response_sign_test.json");
            let pkcs11_path = std::path::Path::new("tests/testdata/pkcs11info_test.json");
            let pkcs11_str = std::fs::read_to_string(pkcs11_path)
                .expect("Failed to read pkcs11 response");
            let pkcs11: ecdsa_spartan2::circuits::sha256rsa_circuit::Pkcs11InfoResponse =
                serde_json::from_str(&pkcs11_str).expect("Failed to parse pkcs11 response");
            let issuer_cert = Rs256Circuit::extract_issuer_cert(&pkcs11)
                .expect("Failed to extract issuer cert");
            let response_str = std::fs::read_to_string(response_path)
                .expect("Failed to read sign response");
            let response: ecdsa_spartan2::circuits::sha256rsa_circuit::CardSignResponse =
                serde_json::from_str(&response_str).expect("Failed to parse sign response");
            let user_cert = Rs256Circuit::generate_user_cert_from_certb64(&response.certb64)
                .expect("Failed to parse user cert");
            let serial_bytes = user_cert.tbs_certificate.serial_number.as_bytes();
            let trimmed: Vec<u8> = serial_bytes.iter().skip_while(|&&b| b == 0).copied().collect();
            let serial_hex = hex::encode(if trimmed.is_empty() { serial_bytes } else { &trimmed });
            (user_cert, response.signature, issuer_cert, serial_hex)
        };

        let smt_inputs = smt_server.as_ref().map(|url| {
            ecdsa_spartan2::smt_client::fetch_smt_proof(url, &issuer, &serial_hex, 128)
                .expect("Failed to fetch SMT proof")
        });

        info!("Generating split inputs (cert_chain + device_sig)...");
        let (cert_chain_json, device_sig_json) = generate_split_inputs(
            &user_cert, &issuer_cert, &user_sig_b64, default_tbs.as_slice(),
            &serial_hex, smt_inputs.as_ref(), k_issuer, k_user,
        )
        .unwrap_or_else(|e| {
            eprintln!("Error generating split inputs: {}", e);
            process::exit(1);
        });

        for (path, json) in [(&cert_chain_output, &cert_chain_json), (&device_sig_output, &device_sig_json)] {
            if let Some(parent) = std::path::Path::new(path).parent() {
                std::fs::create_dir_all(parent).ok();
            }
            std::fs::write(path, serde_json::to_string_pretty(json).unwrap())
                .unwrap_or_else(|e| {
                    eprintln!("Failed to write {}: {}", path, e);
                    process::exit(1);
                });
            info!(path = %path, "Written split input JSON");
        }
        process::exit(0);
    }

    // ── generate-input: legacy monolithic circuit input ──
    if command_args.contains(&"generate-input".to_string()) {
        let mut tbs_data: Option<String> = None;
        let mut pin: Option<String> = None;
        let mut hipki_server = hipki_client::default_server_url().to_string();
        let mut smt_server: Option<String> = None;
        let mut issuer = "g2".to_string();
        let mut output = "../circom/inputs/sha256rsa2048/input.json".to_string();
        let mut fido: bool = false;

        let mut i = 2; // skip "rs256 generate-input"
        while i < command_args.len() {
            match command_args[i].as_str() {
                "--tbs" => {
                    i += 1;
                    tbs_data = Some(command_args.get(i).cloned().unwrap_or_else(|| {
                        eprintln!("Missing value for --tbs");
                        process::exit(1);
                    }));
                }
                "--pin" => {
                    i += 1;
                    pin = Some(command_args.get(i).cloned().unwrap_or_else(|| {
                        eprintln!("Missing value for --pin");
                        process::exit(1);
                    }));
                }
                "--hipki-server" => {
                    i += 1;
                    hipki_server = command_args.get(i).cloned().unwrap_or_else(|| {
                        eprintln!("Missing value for --hipki-server");
                        process::exit(1);
                    });
                }
                "--smt-server" => {
                    i += 1;
                    smt_server = Some(command_args.get(i).cloned().unwrap_or_else(|| {
                        eprintln!("Missing value for --smt-server");
                        process::exit(1);
                    }));
                }
                "--issuer" => {
                    i += 1;
                    issuer = command_args.get(i).cloned().unwrap_or_else(|| {
                        eprintln!("Missing value for --issuer");
                        process::exit(1);
                    });
                }
                "--output" | "-o" => {
                    i += 1;
                    output = command_args.get(i).cloned().unwrap_or_else(|| {
                        eprintln!("Missing value for --output");
                        process::exit(1);
                    });
                }
                "--fido" | "-f" => {
                    fido = true;
                }
                "--help" | "-h" => {
                    print_generate_input_usage();
                    process::exit(0);
                }
                other => {
                    eprintln!("Unknown flag for generate-input: {}", other);
                    print_generate_input_usage();
                    process::exit(1);
                }
            }
            i += 1;
        }

        let result = if let (Some(tbs), Some(pin)) = (tbs_data, pin) {
            // Live mode (RSA-2048): call HiPKI APIs directly.
            if !cfg!(feature = "sha256rsa2048") {
                eprintln!(
                    "Error: live mode requires the `sha256rsa2048` feature. \
                     Rebuild with --features sha256rsa2048"
                );
                process::exit(1);
            }
            info!(server = %hipki_server, "Fetching cert chain from HiPKI");
            let pkcs11info = hipki_client::fetch_pkcs11info(&hipki_server).unwrap_or_else(|e| {
                eprintln!("Failed to fetch pkcs11info from {}: {}", hipki_server, e);
                process::exit(1);
            });
            let issuer_cert = Rs256Circuit::extract_issuer_cert(&pkcs11info).unwrap_or_else(|e| {
                eprintln!("Failed to extract issuer cert: {}", e);
                process::exit(1);
            });

            info!(tbs = %tbs, "Signing TBS via HiPKI");
            let sign_response =
                hipki_client::sign_tbs(&hipki_server, &tbs, &pin).unwrap_or_else(|e| {
                    eprintln!("Failed to sign via HiPKI: {}", e);
                    process::exit(1);
                });

            let user_cert = Rs256Circuit::generate_user_cert_from_certb64(&sign_response.certb64)
                .unwrap_or_else(|e| {
                    eprintln!("Failed to generate user cert: {}", e);
                    process::exit(1);
                });

            Rs256Circuit::generate_input(
                &user_cert,
                &sign_response.signature,
                tbs.as_bytes(),
                &issuer_cert,
                smt_server.as_deref(),
                &issuer,
                &output,
            )
        } else if fido {
            // FIDO mode uses RSA-4096 (MOICA-G3 CA).
            if !cfg!(feature = "sha256rsa4096") {
                eprintln!(
                    "Error: --fido requires the `sha256rsa4096` feature. \
                     Rebuild with --features sha256rsa4096"
                );
                process::exit(1);
            }
            let default_sign = "tests/testdata/fido_response_sign.json";
            // Download from https://moica.nat.gov.tw/repository/Certs/MOICA-G3.cer
            let default_cert = "tests/testdata/MOICA-G3.cer";
            let default_tbs = "e775f2805fb993e05a208dbff15d1c1";
            let fido_output = "../circom/inputs/sha256rsa4096/input.json".to_string();
            info!("Using bundled test fixtures (FIDO / RSA-4096 mode)");

            let issuer_cert =
                Rs256FidoCircuit::fetch_cert_from_file(default_cert).unwrap_or_else(|e| {
                    eprintln!("Failed to fetch issuer cert: {}", e);
                    process::exit(1);
                });

            Rs256FidoCircuit::generate_input_from_fido_file(
                &PathBuf::from(default_sign),
                default_tbs.as_bytes(),
                &issuer_cert,
                smt_server.as_deref(),
                &issuer,
                &fido_output,
            )
        } else {
            // Default mode (RSA-2048): use bundled test fixtures.
            if !cfg!(feature = "sha256rsa2048") {
                eprintln!(
                    "Error: default mode requires the `sha256rsa2048` feature. \
                     Rebuild with --features sha256rsa2048"
                );
                process::exit(1);
            }
            let default_sign = "tests/testdata/response_sign.json";
            // Download from https://moica.nat.gov.tw/repository/Certs/MOICA2.cer
            let default_cert = "tests/testdata/MOICA2.cer";
            let default_tbs = "e775f2805fb993e05a208dbff15d1c1";
            info!("Using bundled test fixtures (default / RSA-2048 mode)");

            let issuer_cert =
                Rs256Circuit::fetch_cert_from_file(default_cert).unwrap_or_else(|e| {
                    eprintln!("Failed to fetch issuer cert: {}", e);
                    process::exit(1);
                });

            Rs256Circuit::generate_input_from_file(
                &PathBuf::from(default_sign),
                default_tbs.as_bytes(),
                &issuer_cert,
                smt_server.as_deref(),
                &issuer,
                &output,
            )
        };

        if let Err(e) = result {
            eprintln!("Error generating circuit input: {}", e);
            process::exit(1);
        }
        process::exit(0);
    }

    let command = match parse_command(command_args) {
        Ok(cmd) => cmd,
        Err(err) => {
            eprintln!("Error: {}", err);
            print_usage();
            process::exit(1);
        }
    };

    // Dispatch based on top-level command
    let top_command = &command_args[0];
    match top_command.as_str() {
        "cert-chain" => execute_cert_chain(command.action, command.options),
        "device-sig" => execute_device_sig(command.action, command.options),
        _ => execute_rs256(command.action, command.options),
    }
}

/// Execute cert-chain (Circuit A) commands — dispatch by --fido flag.
fn execute_cert_chain(action: CircuitAction, options: CommandOptions) {
    if options.fido {
        if !cfg!(feature = "cert_chain_rs4096") {
            eprintln!(
                "Error: --fido requires the `cert_chain_rs4096` feature. \
                 Rebuild with --features cert_chain_rs4096"
            );
            process::exit(1);
        }
        execute_rs256_for::<CertChainRsa4096>(action, options);
    } else {
        if !cfg!(feature = "cert_chain_rs2048") {
            eprintln!(
                "Error: cert-chain commands require the `cert_chain_rs2048` feature. \
                 Rebuild with --features cert_chain_rs2048"
            );
            process::exit(1);
        }
        execute_rs256_for::<CertChainRsa2048>(action, options);
    }
}

/// Execute device-sig (Circuit B) commands — always RSA-2048.
fn execute_device_sig(action: CircuitAction, options: CommandOptions) {
    if !cfg!(feature = "device_sig_rs2048") {
        eprintln!(
            "Error: device-sig commands require the `device_sig_rs2048` feature. \
             Rebuild with --features device_sig_rs2048"
        );
        process::exit(1);
    }
    execute_rs256_for::<DeviceSigRsa2048>(action, options);
}

/// Execute RS256 circuit commands — dispatches to the correct key-size variant.
fn execute_rs256(action: CircuitAction, options: CommandOptions) {
    if options.fido {
        if !cfg!(feature = "sha256rsa4096") {
            eprintln!(
                "Error: --fido requires the `sha256rsa4096` feature. \
                 Rebuild with --features sha256rsa4096"
            );
            process::exit(1);
        }
        execute_rs256_for::<Rsa4096>(action, options);
    } else {
        if !cfg!(feature = "sha256rsa2048") {
            eprintln!(
                "Error: RS256 circuit commands require the `sha256rsa2048` feature. \
                 Rebuild with --features sha256rsa2048"
            );
            process::exit(1);
        }
        execute_rs256_for::<Rsa2048>(action, options);
    }
}

/// Generic execute — works for any RSA key size.
fn execute_rs256_for<T: RsaKeySize>(action: CircuitAction, options: CommandOptions) {
    let path_config = PathConfig::development();

    match action {
        CircuitAction::Setup => {
            info!(input = ?options.input, circuit = T::CIRCUIT_NAME, "Setting up Spartan-2 keys");
            let circuit = Sha256RsaCircuit::<T>::new(path_config.clone(), options.input);
            setup_circuit_keys(
                circuit,
                path_config.key_path(T::PROVING_KEY),
                path_config.key_path(T::VERIFYING_KEY),
            );
        }
        CircuitAction::Run => {
            info!(circuit = T::CIRCUIT_NAME, "Running circuit with ZK-Spartan");
            let circuit = Sha256RsaCircuit::<T>::new(path_config, options.input);
            run_circuit(circuit);
        }
        CircuitAction::Prove => {
            info!(circuit = T::CIRCUIT_NAME, "Proving circuit with ZK-Spartan");
            let circuit = Sha256RsaCircuit::<T>::new(path_config.clone(), options.input);
            prove_circuit(
                circuit,
                path_config.key_path(T::PROVING_KEY),
                path_config.artifact_path(T::INSTANCE),
                path_config.artifact_path(T::WITNESS),
                path_config.artifact_path(T::PROOF),
            );
        }
        CircuitAction::Verify => {
            info!(circuit = T::CIRCUIT_NAME, "Verifying proof with ZK-Spartan");
            verify_circuit(
                path_config.artifact_path(T::PROOF),
                path_config.key_path(T::VERIFYING_KEY),
            );
        }
        CircuitAction::Benchmark => {
            info!(circuit = T::CIRCUIT_NAME, "Running benchmark pipeline");
            run_rs256_benchmark_for::<T>(options.input);
        }
    }
}

/// Run benchmark for a specific RSA key-size circuit.
fn run_rs256_benchmark_for<T: RsaKeySize>(input_path: Option<PathBuf>) {
    let path_config = PathConfig::development();

    println!("\n╔════════════════════════════════════════════════╗");
    println!(
        "║  {} BENCHMARK PIPELINE  ║",
        T::CIRCUIT_NAME.to_uppercase()
    );
    println!("╚════════════════════════════════════════════════╝\n");

    // Step 0: Pre-generate witness while memory is clean
    let circuit = Sha256RsaCircuit::<T>::new(path_config.clone(), input_path.clone());
    info!("Pre-generating witness (before setup allocates keys)...");
    let t_witness = Instant::now();
    circuit
        .warm_witness_cache()
        .expect("witness generation failed");
    let witness_gen_ms = t_witness.elapsed().as_millis();
    println!("✓ Witness cached: {} ms\n", witness_gen_ms);

    info!("Step 1/3: Setting up {} circuit...", T::CIRCUIT_NAME);
    let t0 = Instant::now();
    let (pk, vk) = setup_circuit_keys_no_save(circuit.clone());
    let setup_ms = t0.elapsed().as_millis();
    println!("✓ Setup completed: {} ms\n", setup_ms);

    // Save keys
    if let Err(e) = save_keys(
        path_config.key_path(T::PROVING_KEY),
        path_config.key_path(T::VERIFYING_KEY),
        &pk,
        &vk,
    ) {
        eprintln!("Failed to save {} keys: {}", T::CIRCUIT_NAME, e);
        std::process::exit(1);
    }

    // Step 2: Prove
    info!("Step 2/3: Proving {} circuit...", T::CIRCUIT_NAME);
    let t0 = Instant::now();
    prove_circuit_with_pk(
        circuit,
        &pk,
        path_config.artifact_path(T::INSTANCE),
        path_config.artifact_path(T::WITNESS),
        path_config.artifact_path(T::PROOF),
    );
    let prove_ms = t0.elapsed().as_millis();
    println!("✓ Proof generated: {} ms\n", prove_ms);

    // Step 3: Verify
    info!("Step 3/3: Verifying {} proof...", T::CIRCUIT_NAME);
    let proof = load_proof(path_config.artifact_path(T::PROOF)).expect("load proof failed");
    let t0 = Instant::now();
    verify_circuit_with_loaded_data(&proof, &vk);
    let verify_ms = t0.elapsed().as_millis();
    println!("✓ Proof verified: {} ms\n", verify_ms);

    // Measure sizes
    let pk_bytes = get_file_size(&path_config.key_path(T::PROVING_KEY).to_string_lossy());
    let vk_bytes = get_file_size(&path_config.key_path(T::VERIFYING_KEY).to_string_lossy());
    let proof_bytes = get_file_size(&path_config.artifact_path(T::PROOF).to_string_lossy());
    let witness_bytes = get_file_size(&path_config.artifact_path(T::WITNESS).to_string_lossy());

    println!("\n╔════════════════════════════════════════════════╗");
    println!("║         RS256 BENCHMARK RESULTS                ║");
    println!("╠════════════════════════════════════════════════╣");
    println!("║ TIMING                                         ║");
    println!("╠════════════════════════════════════════════════╣");
    println!(
        "║ Witness Gen:              {:>10} ms        ║",
        witness_gen_ms
    );
    println!("║ Setup:                    {:>10} ms        ║", setup_ms);
    println!("║ Prove:                    {:>10} ms        ║", prove_ms);
    println!("║ Verify:                   {:>10} ms        ║", verify_ms);
    println!("╠════════════════════════════════════════════════╣");
    println!("║ SIZES                                          ║");
    println!("╠════════════════════════════════════════════════╣");
    println!(
        "║ Proving Key:               {:>12}        ║",
        format_size(pk_bytes)
    );
    println!(
        "║ Verifying Key:             {:>12}        ║",
        format_size(vk_bytes)
    );
    println!(
        "║ Proof:                     {:>12}        ║",
        format_size(proof_bytes)
    );
    println!(
        "║ Witness:                   {:>12}        ║",
        format_size(witness_bytes)
    );
    println!("╚════════════════════════════════════════════════╝\n");
}

fn parse_command(args: &[String]) -> Result<ParsedCommand, String> {
    if args.is_empty() {
        return Err("No command provided".into());
    }

    match args[0].as_str() {
        "-h" | "--help" => {
            print_usage();
            process::exit(0);
        }
        "rs256" => parse_circuit_command(&args[1..]),
        "cert-chain" => parse_circuit_command(&args[1..]),
        "device-sig" => parse_circuit_command(&args[1..]),
        other => Err(format!("Unknown command '{other}'")),
    }
}

fn parse_circuit_command(tail: &[String]) -> Result<ParsedCommand, String> {
    if tail.is_empty() {
        return Ok(ParsedCommand {
            action: CircuitAction::Run,
            options: CommandOptions::default(),
        });
    }

    let first = &tail[0];
    let (action, option_start) = match first.as_str() {
        "run" => (CircuitAction::Run, 1),
        "setup" => (CircuitAction::Setup, 1),
        "prove" => (CircuitAction::Prove, 1),
        "verify" => (CircuitAction::Verify, 1),
        "benchmark" => (CircuitAction::Benchmark, 1),
        s if s.starts_with('-') => (CircuitAction::Run, 0),
        other => {
            return Err(format!(
                "Unknown action '{other}'. Expected one of run|setup|prove|verify|benchmark."
            ))
        }
    };

    let options_slice = &tail[option_start..];
    let options = parse_options(options_slice)?;

    Ok(ParsedCommand { action, options })
}

fn parse_options(args: &[String]) -> Result<CommandOptions, String> {
    let mut options = CommandOptions::default();
    let mut index = 0;

    while index < args.len() {
        let arg = &args[index];
        if arg == "--input" || arg == "-i" {
            index += 1;
            let value = args
                .get(index)
                .ok_or_else(|| "Missing value for --input".to_string())?;
            options.input = Some(PathBuf::from(value));
        } else if let Some(value) = arg.strip_prefix("--input=") {
            if value.is_empty() {
                return Err("Missing value for --input".into());
            }
            options.input = Some(PathBuf::from(value));
        } else if arg == "--fido" || arg == "-f" {
            options.fido = true;
        } else if arg == "--help" || arg == "-h" {
            print_usage();
            process::exit(0);
        } else {
            return Err(format!("Unknown option '{arg}'"));
        }
        index += 1;
    }

    Ok(options)
}

fn print_generate_input_usage() {
    eprintln!(
        "Usage: ecdsa-spartan2 rs256 generate-input [options]

Generates circuit input JSON for the FullCertRSA256VerifyWithRevocation circuit.

Modes:
  Default (no args)    Uses bundled test fixtures (no card reader needed)
  Live (--tbs + --pin) Calls HiPKI LocalSignServer APIs directly

Options:
  --tbs <data>            TBS data for the card to sign (required for live mode)
  --pin <pin>             Card PIN, 6-8 digits (required for live mode)
  --hipki-server <url>    HiPKI server URL (default: http://localhost:61161)
  --smt-server <url>      Optional SMT revocation server URL
  --issuer <id>           Issuer ID for SMT lookup (default: g2)
  --output, -o <path>     Output path (default: ../circom/inputs/sha256rsa2048/input.json)

Examples:
  # Default mode (uses bundled test data, no card needed)
  RUST_LOG=info cargo run --release -- rs256 generate-input

  # Live mode (requires HiPKI LocalSignServer + card reader + card)
  RUST_LOG=info cargo run --release -- rs256 generate-input --tbs 123456 --pin 830929

  # Live mode with SMT revocation server
  RUST_LOG=info cargo run --release -- rs256 generate-input \\
    --tbs 123456 --pin 830929 --smt-server http://localhost:3000"
    );
}

fn print_usage() {
    eprintln!(
        "Usage:
  ecdsa-spartan2 rs256 <action> [options]

Actions:
  run                  Run the complete circuit (setup, prove, verify)
  setup                Generate proving and verifying keys
  generate-input       Generate circuit input (use --help for details)
  prove                Generate proof
  verify               Verify proof
  benchmark            Run complete benchmark pipeline

Options:
  --input, -i <path>   Override the circuit input JSON (run/prove/setup/benchmark)
  --fido, -f           Use RSA-4096 circuit (FIDO / MOICA-G3); default is RSA-2048

Examples:
  cargo run --release -- rs256 generate-input
  cargo run --release -- rs256 generate-input --fido
  cargo run --release -- rs256 generate-input --tbs 123456 --pin 830929
  cargo run --release -- rs256 setup --input ../circom/inputs/sha256rsa2048/input.json
  cargo run --release -- rs256 setup --fido --input ../circom/inputs/sha256rsa4096/input.json
  cargo run --release -- rs256 prove --input ../circom/inputs/sha256rsa2048/input.json
  cargo run --release -- rs256 prove --fido --input ../circom/inputs/sha256rsa4096/input.json
  cargo run --release -- rs256 verify
  cargo run --release -- rs256 verify --fido
  cargo run --release -- rs256 benchmark --input ../circom/inputs/sha256rsa2048/input.json"
    );
}
