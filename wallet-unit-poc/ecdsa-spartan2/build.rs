use std::path::Path;

#[cfg(feature = "sha256rsa2048")]
const SHA256RSA2048_CIRCUIT_NAME: &str = "sha256rsa2048";
#[cfg(feature = "sha256rsa4096")]
const SHA256RSA4096_CIRCUIT_NAME: &str = "sha256rsa4096";
#[cfg(feature = "cert_chain_rs2048")]
const CERT_CHAIN_RS2048_CIRCUIT_NAME: &str = "cert_chain_rs2048";
#[cfg(feature = "cert_chain_rs4096")]
const CERT_CHAIN_RS4096_CIRCUIT_NAME: &str = "cert_chain_rs4096";
#[cfg(feature = "device_sig_rs2048")]
const DEVICE_SIG_RS2048_CIRCUIT_NAME: &str = "device_sig_rs2048";

#[allow(unused_variables)]
fn main() {
    chkstk_stub::build();

    // Construct absolute path to circuits using CARGO_MANIFEST_DIR
    // This ensures the path resolves correctly regardless of working directory
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
    let circuits_dir = std::path::PathBuf::from(&manifest_dir)
        .parent() // Go up from ecdsa-spartan2/ to wallet-unit-poc/
        .expect("Failed to get parent directory")
        .join("circom/build/cpp");

    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set");

    // Check for pre-built witnesscalc cache from build_pod.sh
    if let Ok(witnesscalc_cache) = std::env::var("WITNESSCALC_PREBUILD_CACHE") {
        let target = std::env::var("TARGET").unwrap_or_default();

        // Only apply for iOS targets
        match target.as_str() {
            "aarch64-apple-ios-sim" | "aarch64-apple-ios" | "x86_64-apple-ios" => {
                let cache_src = Path::new(&witnesscalc_cache);
                let target_witnesscalc = Path::new(&out_dir).join("witnesscalc");

                // Symlink entire witnesscalc directory if cache exists and target doesn't
                if cache_src.exists() && !target_witnesscalc.exists() {
                    #[cfg(unix)]
                    {
                        println!(
                            "cargo:warning=Using cached witnesscalc from: {}",
                            cache_src.display()
                        );
                        std::os::unix::fs::symlink(&cache_src, &target_witnesscalc).ok();
                    }
                }
            }
            _ => {}
        }
    }

    // Stage only sha256rsa* circuit files so build_and_link doesn't try to
    // compile sha256rsa* circuits that may not exist in CI.
    let staging_dir = Path::new(&out_dir).join("circuit_staging");
    std::fs::create_dir_all(&staging_dir).expect("Failed to create staging directory");

    #[cfg(feature = "sha256rsa2048")]
    stage_circuit(&circuits_dir, &staging_dir, SHA256RSA2048_CIRCUIT_NAME);
    #[cfg(feature = "sha256rsa4096")]
    stage_circuit(&circuits_dir, &staging_dir, SHA256RSA4096_CIRCUIT_NAME);
    #[cfg(feature = "cert_chain_rs2048")]
    stage_circuit(&circuits_dir, &staging_dir, CERT_CHAIN_RS2048_CIRCUIT_NAME);
    #[cfg(feature = "cert_chain_rs4096")]
    stage_circuit(&circuits_dir, &staging_dir, CERT_CHAIN_RS4096_CIRCUIT_NAME);
    #[cfg(feature = "device_sig_rs2048")]
    stage_circuit(&circuits_dir, &staging_dir, DEVICE_SIG_RS2048_CIRCUIT_NAME);

    witnesscalc_adapter::build_and_link(staging_dir.to_str().unwrap());
}

#[allow(unused)]
fn stage_circuit(circuits_dir: &Path, staging_dir: &Path, circuit_name: &str) {
    for ext in &["cpp", "dat"] {
        let src = circuits_dir.join(format!("{}.{}", circuit_name, ext));
        let dst = staging_dir.join(format!("{}.{}", circuit_name, ext));
        if src.exists() {
            std::fs::copy(&src, &dst).unwrap_or_else(|e| {
                panic!(
                    "Failed to copy {} to {}: {}",
                    src.display(),
                    dst.display(),
                    e
                )
            });
        } else {
            panic!(
                "Required circuit file not found: {}. Run `yarn compile:{}` in the circom directory first.",
                src.display(),
                circuit_name
            );
        }
    }
}
