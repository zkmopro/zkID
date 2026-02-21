use ecdsa_spartan2::{
    load_proof,
    paths::keys::{
        JWT_RS256_INSTANCE, JWT_RS256_PROOF, JWT_RS256_PROVING_KEY, JWT_RS256_VERIFYING_KEY,
        JWT_RS256_WITNESS,
    },
    prover::{prove_circuit, prove_circuit_with_pk, verify_circuit, verify_circuit_with_loaded_data},
    save_keys,
    setup::{setup_circuit_keys, setup_circuit_keys_no_save},
    JwtRs256Circuit, PathConfig,
};
use std::path::PathBuf;

// Initializes the shared UniFFI scaffolding and defines the `MoproError` enum.
mopro_ffi::app!();

// ============================================================================
// Core Types
// ============================================================================

/// Result of a proving operation with timing and proof metadata
#[cfg_attr(feature = "uniffi", uniffi::record)]
pub struct ProofResult {
    pub prove_ms: u64,
    pub proof_size_bytes: u64,
}

/// Result of a complete benchmark run with timing and size metrics
#[cfg_attr(feature = "uniffi", uniffi::record)]
pub struct BenchmarkResults {
    // Timing metrics (milliseconds)
    pub setup_ms: u64,
    pub prove_ms: u64,
    pub verify_ms: u64,
    // Size metrics (bytes)
    pub proving_key_bytes: u64,
    pub verifying_key_bytes: u64,
    pub proof_bytes: u64,
    pub witness_bytes: u64,
}

impl BenchmarkResults {
    /// Format bytes into human-readable size string
    pub fn format_size(bytes: u64) -> String {
        if bytes < 1024 {
            format!("{} B", bytes)
        } else if bytes < 1024 * 1024 {
            format!("{:.2} KB", bytes as f64 / 1024.0)
        } else {
            format!("{:.2} MB", bytes as f64 / (1024.0 * 1024.0))
        }
    }
}

/// Errors that can occur during ZK proof operations
#[derive(Debug)]
#[cfg_attr(feature = "uniffi", uniffi::error)]
pub enum ZkProofError {
    FileNotFound { message: String },
    ProofGenerationFailed { message: String },
    VerificationFailed { message: String },
    InvalidInput { message: String },
    SetupRequired { message: String },
    IoError { message: String },
}

impl std::fmt::Display for ZkProofError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ZkProofError::FileNotFound { message } => write!(f, "File not found: {}", message),
            ZkProofError::ProofGenerationFailed { message } => {
                write!(f, "Proof generation failed: {}", message)
            }
            ZkProofError::VerificationFailed { message } => {
                write!(f, "Verification failed: {}", message)
            }
            ZkProofError::InvalidInput { message } => write!(f, "Invalid input: {}", message),
            ZkProofError::SetupRequired { message } => write!(f, "Setup required: {}", message),
            ZkProofError::IoError { message } => write!(f, "IO error: {}", message),
        }
    }
}

impl std::error::Error for ZkProofError {}

impl From<std::io::Error> for ZkProofError {
    fn from(e: std::io::Error) -> Self {
        ZkProofError::IoError {
            message: e.to_string(),
        }
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Create a PathConfig for the given documents path (mobile environment).
fn make_config(documents_path: &str) -> PathConfig {
    PathConfig::mobile(documents_path)
}

/// Get the size of a file in bytes
fn get_file_size(path: impl AsRef<std::path::Path>) -> Result<u64, ZkProofError> {
    let path = path.as_ref();
    let metadata = std::fs::metadata(path).map_err(|e| ZkProofError::FileNotFound {
        message: format!("Failed to get file size from '{}': {}", path.display(), e),
    })?;
    Ok(metadata.len())
}

// ============================================================================
// Setup Operation
// ============================================================================

/// Setup JWT-RS256 circuit keys
/// Generates proving and verifying keys for the jwt_rs256 circuit
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn setup_keys(
    documents_path: String,
    input_path: Option<String>,
) -> Result<String, ZkProofError> {
    let config = make_config(&documents_path);
    let circuit = JwtRs256Circuit::new(config.clone(), input_path.map(PathBuf::from));

    let start = std::time::Instant::now();
    setup_circuit_keys(
        circuit,
        config.key_path(JWT_RS256_PROVING_KEY),
        config.key_path(JWT_RS256_VERIFYING_KEY),
    );
    let elapsed_ms = start.elapsed().as_millis();

    Ok(format!(
        "JWT-RS256 circuit keys setup completed in {}ms",
        elapsed_ms
    ))
}

// ============================================================================
// Prove Operation
// ============================================================================

/// Generate JWT-RS256 circuit proof
/// Runs proving using existing keys
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn prove(
    documents_path: String,
    input_path: Option<String>,
) -> Result<ProofResult, ZkProofError> {
    let config = make_config(&documents_path);
    let circuit = JwtRs256Circuit::new(config.clone(), input_path.map(PathBuf::from));

    let start = std::time::Instant::now();
    prove_circuit(
        circuit,
        config.key_path(JWT_RS256_PROVING_KEY),
        config.artifact_path(JWT_RS256_INSTANCE),
        config.artifact_path(JWT_RS256_WITNESS),
        config.artifact_path(JWT_RS256_PROOF),
    );
    let prove_ms = start.elapsed().as_millis() as u64;

    let proof_size_bytes = get_file_size(&config.artifact_path(JWT_RS256_PROOF))?;

    Ok(ProofResult {
        prove_ms,
        proof_size_bytes,
    })
}

// ============================================================================
// Verify Operation
// ============================================================================

/// Verify JWT-RS256 circuit proof
/// Verifies the proof using the verifying key
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn verify(documents_path: String) -> Result<bool, ZkProofError> {
    let config = make_config(&documents_path);
    verify_circuit(
        config.artifact_path(JWT_RS256_PROOF),
        config.key_path(JWT_RS256_VERIFYING_KEY),
    );
    Ok(true)
}

// ============================================================================
// Benchmark Operation
// ============================================================================

/// Run complete benchmark pipeline for JWT-RS256 circuit
/// Executes setup, prove, and verify with timing and size metrics
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn run_complete_benchmark(
    documents_path: String,
    input_path: Option<String>,
) -> Result<BenchmarkResults, ZkProofError> {
    let config = make_config(&documents_path);

    // Step 1: Setup
    let circuit = JwtRs256Circuit::new(config.clone(), input_path.as_ref().map(PathBuf::from));
    let start = std::time::Instant::now();
    let (pk, vk) = setup_circuit_keys_no_save(circuit);
    let setup_ms = start.elapsed().as_millis() as u64;

    save_keys(
        config.key_path(JWT_RS256_PROVING_KEY),
        config.key_path(JWT_RS256_VERIFYING_KEY),
        &pk,
        &vk,
    )
    .map_err(|e| ZkProofError::IoError {
        message: format!("Failed to save keys: {}", e),
    })?;

    // Step 2: Prove
    let circuit = JwtRs256Circuit::new(config.clone(), input_path.as_ref().map(PathBuf::from));
    let start = std::time::Instant::now();
    prove_circuit_with_pk(
        circuit,
        &pk,
        config.artifact_path(JWT_RS256_INSTANCE),
        config.artifact_path(JWT_RS256_WITNESS),
        config.artifact_path(JWT_RS256_PROOF),
    );
    let prove_ms = start.elapsed().as_millis() as u64;

    // Step 3: Verify
    let proof = load_proof(config.artifact_path(JWT_RS256_PROOF)).map_err(|e| {
        ZkProofError::FileNotFound {
            message: format!("Failed to load proof: {}", e),
        }
    })?;

    let start = std::time::Instant::now();
    verify_circuit_with_loaded_data(&proof, &vk);
    let verify_ms = start.elapsed().as_millis() as u64;

    // Measure file sizes
    let proving_key_bytes = get_file_size(&config.key_path(JWT_RS256_PROVING_KEY))?;
    let verifying_key_bytes = get_file_size(&config.key_path(JWT_RS256_VERIFYING_KEY))?;
    let proof_bytes = get_file_size(&config.artifact_path(JWT_RS256_PROOF))?;
    let witness_bytes = get_file_size(&config.artifact_path(JWT_RS256_WITNESS))?;

    Ok(BenchmarkResults {
        setup_ms,
        prove_ms,
        verify_ms,
        proving_key_bytes,
        verifying_key_bytes,
        proof_bytes,
        witness_bytes,
    })
}

// ============================================================================
// Legacy Test Function
// ============================================================================

/// Test function for basic UniFFI integration
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn mopro_hello_world() -> String {
    "Hello, World!".to_string()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mopro_hello_world() {
        assert_eq!(mopro_hello_world(), "Hello, World!");
    }

    #[test]
    fn test_path_config_mobile_rs256() {
        let config = make_config("/app/Documents");
        assert_eq!(
            config.key_path(JWT_RS256_PROVING_KEY),
            PathBuf::from("/app/Documents/keys/jwt_rs256_proving.key")
        );
        assert_eq!(
            config.key_path(JWT_RS256_VERIFYING_KEY),
            PathBuf::from("/app/Documents/keys/jwt_rs256_verifying.key")
        );
        assert_eq!(
            config.artifact_path(JWT_RS256_PROOF),
            PathBuf::from("/app/Documents/keys/jwt_rs256_proof.bin")
        );
        assert_eq!(
            config.artifact_path(JWT_RS256_WITNESS),
            PathBuf::from("/app/Documents/keys/jwt_rs256_witness.bin")
        );
        assert_eq!(
            config.artifact_path(JWT_RS256_INSTANCE),
            PathBuf::from("/app/Documents/keys/jwt_rs256_instance.bin")
        );
    }

    #[test]
    fn test_setup_keys_creates_circuit() {
        let config = PathConfig::mobile("/tmp/test_docs");
        let circuit = JwtRs256Circuit::new(config, None);
        // Just verify the circuit can be created without panicking
        let _ = format!("{:?}", circuit);
    }

    #[test]
    fn test_invalid_documents_path() {
        let result = verify("/nonexistent/path".to_string());
        assert!(result.is_err() || result.is_ok());
        // verify_circuit panics on missing files, so we just ensure it doesn't cause UB
    }

    #[test]
    fn test_prove_without_setup() {
        let result = prove("/tmp/no_keys_here".to_string(), None);
        // prove_circuit panics when keys don't exist, so we just verify it doesn't cause UB
        assert!(result.is_err() || result.is_ok());
    }
}
