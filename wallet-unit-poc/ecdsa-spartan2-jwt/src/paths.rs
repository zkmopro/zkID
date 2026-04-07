//! Path config for cross-platform compatibility.

use crate::circuit_size::CircuitSize;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
pub struct PathConfig {
    pub base_dir: PathBuf,
    pub is_mobile: bool,
    pub circuit_size: CircuitSize,
}

impl Default for PathConfig {
    fn default() -> Self {
        Self::development()
    }
}

impl PathConfig {
    pub fn new(base_dir: impl Into<PathBuf>, is_mobile: bool) -> Self {
        Self {
            base_dir: base_dir.into(),
            is_mobile,
            circuit_size: CircuitSize::default(),
        }
    }

    pub fn mobile(documents_path: impl Into<PathBuf>) -> Self {
        Self {
            base_dir: documents_path.into(),
            is_mobile: true,
            circuit_size: CircuitSize::default(),
        }
    }

    pub fn development() -> Self {
        Self {
            base_dir: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            is_mobile: false,
            circuit_size: CircuitSize::default(),
        }
    }

    pub fn development_with_size(circuit_size: CircuitSize) -> Self {
        Self {
            base_dir: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            is_mobile: false,
            circuit_size,
        }
    }

    pub fn input_json(&self, circuit: &str) -> PathBuf {
        if self.is_mobile {
            self.base_dir.join(format!("{}_input.json", circuit))
        } else {
            self.base_dir.join(format!(
                "../circom/inputs/{}/{}/default.json",
                circuit,
                self.circuit_size.as_str()
            ))
        }
    }

    pub fn r1cs_path(&self, circuit: &str) -> PathBuf {
        if self.is_mobile {
            self.base_dir
                .join("../circom/build")
                .join(circuit)
                .join(format!("{}_js", circuit))
                .join(format!("{}.r1cs", circuit))
        } else {
            let name = if circuit == "jwt" {
                self.circuit_size.circuit_name()
            } else {
                circuit
            };
            self.base_dir
                .join("../circom/build")
                .join(name)
                .join(format!("{}_js", name))
                .join(format!("{}.r1cs", name))
        }
    }

    pub fn key_path(&self, name: &str) -> PathBuf {
        if self.is_mobile {
            self.base_dir.join("keys").join(name)
        } else {
            self.base_dir
                .join("keys")
                .join(format!("{}_{}", self.circuit_size.as_str(), name))
        }
    }

    pub fn artifact_path(&self, name: &str) -> PathBuf {
        if self.is_mobile {
            self.base_dir.join("keys").join(name)
        } else {
            self.base_dir
                .join("keys")
                .join(format!("{}_{}", self.circuit_size.as_str(), name))
        }
    }

    pub fn shared_blinds_path(&self) -> PathBuf {
        self.artifact_path("shared_blinds.bin")
    }

    pub fn resolve(&self, path: &Path) -> PathBuf {
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            self.base_dir.join(path)
        }
    }
}

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
}
