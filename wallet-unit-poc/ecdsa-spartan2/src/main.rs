//! CLI for running the Spartan-2 RS256 circuit.
//!
//! Usage examples:
//!   cargo run --release -- rs256 generate-input                          # default mode
//!   cargo run --release -- rs256 generate-input --tbs 123456 --pin 8309  # live mode (HiPKI)
//!   cargo run --release -- rs256 setup --input ../circom/inputs/rs256/input.json
//!   cargo run --release -- rs256 prove --input ../circom/inputs/rs256/input.json
//!   cargo run --release -- rs256 verify

use ecdsa_spartan2::{
    circuits::rs256_circuit::{Pkcs11InfoResponse, Rs256Circuit},
    hipki_client,
    load_proof,
    paths::keys::{
        RS256_INSTANCE, RS256_PROOF, RS256_PROVING_KEY, RS256_VERIFYING_KEY, RS256_WITNESS,
    },
    prove_circuit, prove_circuit_with_pk, run_circuit, save_keys, setup_circuit_keys,
    setup_circuit_keys_no_save, verify_circuit, verify_circuit_with_loaded_data, PathConfig,
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

    if command_args.contains(&"generate-input".to_string()) {
        let mut tbs_data: Option<String> = None;
        let mut pin: Option<String> = None;
        let mut hipki_server = hipki_client::default_server_url().to_string();
        let mut smt_server: Option<String> = None;
        let mut issuer = "g2".to_string();
        let mut output = "../circom/inputs/rs256/input.json".to_string();

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
            // Live mode: call HiPKI APIs directly
            info!(server = %hipki_server, "Fetching cert chain from HiPKI");
            let pkcs11info = hipki_client::fetch_pkcs11info(&hipki_server).unwrap_or_else(|e| {
                eprintln!("Failed to fetch pkcs11info from {}: {}", hipki_server, e);
                process::exit(1);
            });
            let issuer_cert =
                Rs256Circuit::extract_issuer_cert(&pkcs11info).unwrap_or_else(|e| {
                    eprintln!("Failed to extract issuer cert: {}", e);
                    process::exit(1);
                });

            info!(tbs = %tbs, "Signing TBS via HiPKI");
            let sign_response =
                hipki_client::sign_tbs(&hipki_server, &tbs, &pin).unwrap_or_else(|e| {
                    eprintln!("Failed to sign via HiPKI: {}", e);
                    process::exit(1);
                });

            Rs256Circuit::generate_input(
                &sign_response,
                tbs.as_bytes(),
                &issuer_cert,
                smt_server.as_deref(),
                &issuer,
                &output,
            )
        } else {
            // Default mode: use bundled test fixtures
            let default_sign = "tests/testdata/response_sign.json";
            let default_pkcs11 = "tests/testdata/pkcs11info_withcert.json";
            let default_tbs = "123456";
            info!("Using bundled test fixtures (default mode)");

            let pkcs11_string = fs::read_to_string(default_pkcs11).unwrap_or_else(|e| {
                eprintln!("Failed to read {}: {}", default_pkcs11, e);
                process::exit(1);
            });
            let pkcs11info: Pkcs11InfoResponse =
                serde_json::from_str(&pkcs11_string).unwrap_or_else(|e| {
                    eprintln!("Failed to parse pkcs11info: {}", e);
                    process::exit(1);
                });
            let issuer_cert =
                Rs256Circuit::extract_issuer_cert(&pkcs11info).unwrap_or_else(|e| {
                    eprintln!("Failed to extract issuer cert: {}", e);
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

    execute_rs256(command.action, command.options);
}

/// Execute RS256 circuit commands (single-stage, no device binding)
fn execute_rs256(action: CircuitAction, options: CommandOptions) {
    let path_config = PathConfig::development();

    match action {
        CircuitAction::Setup => {
            info!(input = ?options.input, "Setting up Spartan-2 keys for the RS256 circuit");
            let circuit = Rs256Circuit::new(path_config.clone(), options.input.clone());
            setup_circuit_keys(
                circuit,
                path_config.key_path(RS256_PROVING_KEY),
                path_config.key_path(RS256_VERIFYING_KEY),
            );
        }
        CircuitAction::Run => {
            let circuit = Rs256Circuit::new(path_config, options.input.clone());
            info!("Running RS256 circuit with ZK-Spartan");
            run_circuit(circuit);
        }
        CircuitAction::Prove => {
            let circuit = Rs256Circuit::new(path_config.clone(), options.input.clone());
            info!("Proving RS256 circuit with ZK-Spartan");
            prove_circuit(
                circuit,
                path_config.key_path(RS256_PROVING_KEY),
                path_config.artifact_path(RS256_INSTANCE),
                path_config.artifact_path(RS256_WITNESS),
                path_config.artifact_path(RS256_PROOF),
            );
        }
        CircuitAction::Verify => {
            info!("Verifying RS256 proof with ZK-Spartan");
            verify_circuit(
                path_config.artifact_path(RS256_PROOF),
                path_config.key_path(RS256_VERIFYING_KEY),
            );
        }
        CircuitAction::Benchmark => {
            info!("RS256 benchmark pipeline...");
            run_rs256_benchmark(options.input);
        }
    }
}

/// Run benchmark for RS256 single-stage circuit
fn run_rs256_benchmark(input_path: Option<PathBuf>) {
    let path_config = PathConfig::development();

    println!("\n╔════════════════════════════════════════════════╗");
    println!("║      RS256 SINGLE-STAGE BENCHMARK PIPELINE     ║");
    println!("╚════════════════════════════════════════════════╝\n");

    // Step 0: Pre-generate witness while memory is clean
    let circuit = Rs256Circuit::new(path_config.clone(), input_path.clone());
    info!("Pre-generating witness (before setup allocates keys)...");
    let t_witness = Instant::now();
    circuit
        .warm_witness_cache()
        .expect("witness generation failed");
    let witness_gen_ms = t_witness.elapsed().as_millis();
    println!("✓ Witness cached: {} ms\n", witness_gen_ms);

    info!("Step 1/3: Setting up RS256 circuit...");
    let t0 = Instant::now();
    let (pk, vk) = setup_circuit_keys_no_save(circuit.clone());
    let setup_ms = t0.elapsed().as_millis();
    println!("✓ Setup completed: {} ms\n", setup_ms);

    // Save keys
    if let Err(e) = save_keys(
        path_config.key_path(RS256_PROVING_KEY),
        path_config.key_path(RS256_VERIFYING_KEY),
        &pk,
        &vk,
    ) {
        eprintln!("Failed to save RS256 keys: {}", e);
        std::process::exit(1);
    }

    // Step 2: Prove
    info!("Step 2/3: Proving RS256 circuit...");
    let t0 = Instant::now();
    prove_circuit_with_pk(
        circuit,
        &pk,
        path_config.artifact_path(RS256_INSTANCE),
        path_config.artifact_path(RS256_WITNESS),
        path_config.artifact_path(RS256_PROOF),
    );
    let prove_ms = t0.elapsed().as_millis();
    println!("✓ Proof generated: {} ms\n", prove_ms);

    // Step 3: Verify
    info!("Step 3/3: Verifying RS256 proof...");
    let proof = load_proof(path_config.artifact_path(RS256_PROOF)).expect("load proof failed");
    let t0 = Instant::now();
    verify_circuit_with_loaded_data(&proof, &vk);
    let verify_ms = t0.elapsed().as_millis();
    println!("✓ Proof verified: {} ms\n", verify_ms);

    // Measure sizes
    let pk_bytes = get_file_size(&path_config.key_path(RS256_PROVING_KEY).to_string_lossy());
    let vk_bytes = get_file_size(&path_config.key_path(RS256_VERIFYING_KEY).to_string_lossy());
    let proof_bytes = get_file_size(&path_config.artifact_path(RS256_PROOF).to_string_lossy());
    let witness_bytes = get_file_size(&path_config.artifact_path(RS256_WITNESS).to_string_lossy());

    println!("\n╔════════════════════════════════════════════════╗");
    println!("║         RS256 BENCHMARK RESULTS                ║");
    println!("╠════════════════════════════════════════════════╣");
    println!("║ TIMING                                         ║");
    println!("╠════════════════════════════════════════════════╣");
    println!("║ Witness Gen:              {:>10} ms        ║", witness_gen_ms);
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
    let options = match action {
        CircuitAction::Run
        | CircuitAction::Prove
        | CircuitAction::Setup
        | CircuitAction::Benchmark => parse_options(options_slice)?,
        CircuitAction::Verify => ensure_no_options(options_slice)?,
    };

    Ok(ParsedCommand { action, options })
}

fn ensure_no_options(args: &[String]) -> Result<CommandOptions, String> {
    if args.is_empty() {
        Ok(CommandOptions::default())
    } else {
        Err(format!("Unexpected options: {}", args.join(" ")))
    }
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
  --output, -o <path>     Output path (default: ../circom/inputs/rs256/input.json)

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

Examples:
  cargo run --release -- rs256 generate-input
  cargo run --release -- rs256 generate-input --tbs 123456 --pin 830929
  cargo run --release -- rs256 setup --input ../circom/inputs/rs256/input.json
  cargo run --release -- rs256 prove --input ../circom/inputs/rs256/input.json
  cargo run --release -- rs256 verify
  cargo run --release -- rs256 benchmark --input ../circom/inputs/rs256/input.json"
    );
}
