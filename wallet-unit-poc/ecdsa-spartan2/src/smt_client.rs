//! Client for the moica-revocation-smt server.
//!
//! Fetches non-membership proofs and converts them to circom-compatible
//! decimal string format.

use num_bigint::BigUint;
use serde::Deserialize;
use std::error::Error;

/// Raw response from the SMT server `GET /proof/{issuer}/{serial}`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SmtProofResponse {
    pub root: String,
    pub entry: Vec<String>,
    pub matching_entry: Option<Vec<String>>,
    pub siblings: Vec<String>,
}

/// Circuit-ready SMT inputs (all values are decimal strings).
#[derive(Debug, Clone)]
pub struct SmtCircuitInputs {
    pub smt_root: String,
    pub serial_number: String,
    pub smt_siblings: Vec<String>,
    pub smt_old_key: String,
    pub smt_old_value: String,
    pub smt_is_old0: String,
}

/// Convert a potentially 0x-prefixed hex string to a decimal string.
fn hex_to_decimal(val: &str) -> Result<String, Box<dyn Error>> {
    if let Some(hex_digits) = val.strip_prefix("0x").or_else(|| val.strip_prefix("0X")) {
        BigUint::parse_bytes(hex_digits.as_bytes(), 16)
            .map(|n| n.to_string())
            .ok_or_else(|| format!("invalid hex value: {}", val).into())
    } else {
        Ok(val.to_string())
    }
}

/// Fetch an SMT non-membership proof and convert to circuit inputs.
///
/// # Arguments
/// * `server_url` - Base URL (e.g., `http://localhost:3000`)
/// * `issuer_id`  - Issuer identifier (e.g., `"g2"`)
/// * `serial_hex` - Certificate serial number in hex
/// * `depth`      - SMT tree depth (must match circuit parameter, typically 128)
pub fn fetch_smt_proof(
    server_url: &str,
    issuer_id: &str,
    serial_hex: &str,
    depth: usize,
) -> Result<SmtCircuitInputs, Box<dyn Error>> {
    let url = format!(
        "{}/proof/{}/{}",
        server_url.trim_end_matches('/'),
        issuer_id,
        serial_hex
    );

    let resp: SmtProofResponse = ureq::get(&url).call()?.into_json()?;

    // Convert siblings to decimal, pad to depth
    let mut siblings: Vec<String> = resp
        .siblings
        .iter()
        .map(|s| hex_to_decimal(s))
        .collect::<Result<Vec<_>, _>>()?;
    siblings.resize(depth, "0".to_string());
    siblings.truncate(depth);

    let (old_key, old_value, is_old0): (String, String, String) = match &resp.matching_entry {
        Some(entry) if entry.len() >= 2 => (
            hex_to_decimal(&entry[0])?,
            hex_to_decimal(&entry[1])?,
            "0".to_string(),
        ),
        _ => ("0".to_string(), "0".to_string(), "1".to_string()),
    };

    Ok(SmtCircuitInputs {
        smt_root: hex_to_decimal(&resp.root)?,
        serial_number: hex_to_decimal(
            resp.entry.first().ok_or("empty entry array in SMT response")?,
        )?,
        smt_siblings: siblings,
        smt_old_key: old_key,
        smt_old_value: old_value,
        smt_is_old0: is_old0,
    })
}
