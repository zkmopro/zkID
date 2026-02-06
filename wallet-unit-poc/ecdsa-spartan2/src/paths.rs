//! Path config for cross-platform compatibility.

use std::path::{Path, PathBuf};

/// Path config for all file operations.
///
/// This struct replaces the previous pattern of changing the global working directory,
/// providing explicit, thread-safe path resolution.
#[derive(Clone, Debug)]
pub struct PathConfig {
    /// Base directory for all file operations (Documents dir on mobile, cwd in dev)
    pub base_dir: PathBuf,
    /// Whether running in mobile environment (affects path resolution patterns)
    pub is_mobile: bool,
}

impl Default for PathConfig {
    fn default() -> Self {
        Self::development()
    }
}

impl PathConfig {
    /// Create a new PathConfig with explicit settings.
    pub fn new(base_dir: impl Into<PathBuf>, is_mobile: bool) -> Self {
        Self {
            base_dir: base_dir.into(),
            is_mobile,
        }
    }

    /// Create config for mobile environment.
    ///
    /// Mobile apps typically extract assets to a Documents directory with a flat structure:
    /// - `{documents}/jwt_input.json`
    /// - `{documents}/show_input.json`
    /// - `{documents}/keys/*.key`
    /// - `{documents}/circom/build/jwt/jwt_js/jwt.r1cs`
    pub fn mobile(documents_path: impl Into<PathBuf>) -> Self {
        Self {
            base_dir: documents_path.into(),
            is_mobile: true,
        }
    }

    /// Create config for development environment.
    ///
    /// Development uses nested paths relative to the current working directory:
    /// - `../circom/inputs/jwt/default.json`
    /// - `../circom/inputs/show/default.json`
    /// - `keys/*.key`
    /// - `../circom/build/jwt/jwt_js/jwt.r1cs`
    pub fn development() -> Self {
        Self {
            base_dir: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            is_mobile: false,
        }
    }

    /// Resolve the input JSON path for a circuit.
    ///
    /// # Arguments
    /// * `circuit` - Circuit name: "jwt" for Prepare circuit, "show" for Show circuit
    ///
    /// # Returns
    /// Full path to the input JSON file.
    pub fn input_json(&self, circuit: &str) -> PathBuf {
        if self.is_mobile {
            // Mobile: flat structure in documents directory
            self.base_dir.join(format!("{}_input.json", circuit))
        } else {
            // Development: nested structure
            self.base_dir
                .join(format!("../circom/inputs/{}/default.json", circuit))
        }
    }

    /// Resolve the R1CS file path for a circuit.
    ///
    /// # Arguments
    /// * `circuit` - Circuit name: "jwt" or "show"
    ///
    /// # Returns
    /// Full path to the R1CS file.
    pub fn r1cs_path(&self, circuit: &str) -> PathBuf {
        self.base_dir
            .join("../circom/build")
            .join(circuit)
            .join(format!("{}_js", circuit))
            .join(format!("{}.r1cs", circuit))
    }

    /// Resolve a key file path (proving/verifying keys).
    ///
    /// # Arguments
    /// * `name` - Key filename (e.g., "prepare_proving.key")
    ///
    /// # Returns
    /// Full path to the key file.
    pub fn key_path(&self, name: &str) -> PathBuf {
        self.base_dir.join("keys").join(name)
    }

    /// Resolve an artifact file path (proofs, witnesses, instances).
    ///
    /// # Arguments
    /// * `name` - Artifact filename (e.g., "prepare_proof.bin")
    ///
    /// # Returns
    /// Full path to the artifact file.
    pub fn artifact_path(&self, name: &str) -> PathBuf {
        self.base_dir.join("keys").join(name)
    }

    /// Resolve the shared blinds file path.
    pub fn shared_blinds_path(&self) -> PathBuf {
        self.artifact_path("shared_blinds.bin")
    }

    /// Resolve an absolute path, joining relative paths with base_dir.
    ///
    /// If the path is already absolute, it's returned as-is.
    /// Otherwise, it's joined with the base directory.
    pub fn resolve(&self, path: &Path) -> PathBuf {
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            self.base_dir.join(path)
        }
    }
}

// Key file name constants
pub mod keys {
    pub const PREPARE_PROVING_KEY: &str = "prepare_proving.key";
    pub const PREPARE_VERIFYING_KEY: &str = "prepare_verifying.key";
    pub const SHOW_PROVING_KEY: &str = "show_proving.key";
    pub const SHOW_VERIFYING_KEY: &str = "show_verifying.key";
    pub const PREPARE_PROOF: &str = "prepare_proof.bin";
    pub const PREPARE_WITNESS: &str = "prepare_witness.bin";
    pub const PREPARE_INSTANCE: &str = "prepare_instance.bin";
    pub const SHOW_PROOF: &str = "show_proof.bin";
    pub const SHOW_WITNESS: &str = "show_witness.bin";
    pub const SHOW_INSTANCE: &str = "show_instance.bin";
    pub const SHARED_BLINDS: &str = "shared_blinds.bin";
    // JWT RS256 circuit keys (single-stage, no device binding)
    pub const JWT_RS256_PROVING_KEY: &str = "jwt_rs256_proving.key";
    pub const JWT_RS256_VERIFYING_KEY: &str = "jwt_rs256_verifying.key";
    pub const JWT_RS256_PROOF: &str = "jwt_rs256_proof.bin";
    pub const JWT_RS256_WITNESS: &str = "jwt_rs256_witness.bin";
    pub const JWT_RS256_INSTANCE: &str = "jwt_rs256_instance.bin";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mobile_config() {
        let config = PathConfig::mobile("/app/Documents");

        assert_eq!(
            config.input_json("jwt"),
            PathBuf::from("/app/Documents/jwt_input.json")
        );
        assert_eq!(
            config.input_json("show"),
            PathBuf::from("/app/Documents/show_input.json")
        );
        assert_eq!(
            config.key_path("prepare_proving.key"),
            PathBuf::from("/app/Documents/keys/prepare_proving.key")
        );
    }

    #[test]
    fn test_development_config() {
        let config = PathConfig::new("/project", false);

        assert_eq!(
            config.input_json("jwt"),
            PathBuf::from("/project/../circom/inputs/jwt/default.json")
        );
        assert_eq!(
            config.input_json("show"),
            PathBuf::from("/project/../circom/inputs/show/default.json")
        );
    }

    #[test]
    fn test_resolve_absolute() {
        let config = PathConfig::mobile("/app/Documents");

        let absolute = PathBuf::from("/custom/path/input.json");
        assert_eq!(config.resolve(&absolute), absolute);
    }

    #[test]
    fn test_resolve_relative() {
        let config = PathConfig::mobile("/app/Documents");

        let relative = PathBuf::from("custom/input.json");
        assert_eq!(
            config.resolve(&relative),
            PathBuf::from("/app/Documents/custom/input.json")
        );
    }
}
