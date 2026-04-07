use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use bellpepper_core::SynthesisError;
use num_bigint::BigInt;
use serde_json::Value;
use std::{collections::HashMap, ops::Range, str::FromStr};

use crate::Scalar;

#[derive(Clone, Copy)]
pub enum FieldParser {
    BigIntScalar,
    U64Scalar,
    BigIntArray,
    U64Array,
    BigInt2DArray,
}

pub fn parse_inputs(
    json_value: &Value,
    field_defs: &[(&str, FieldParser)],
) -> Result<HashMap<String, Vec<BigInt>>, SynthesisError> {
    let mut inputs = HashMap::new();

    for (field_name, parser) in field_defs {
        let value = match parser {
            FieldParser::BigIntScalar => {
                vec![parse_bigint_scalar(json_value, field_name)
                    .map_err(|_| SynthesisError::AssignmentMissing)?]
            }
            FieldParser::U64Scalar => {
                vec![parse_u64_scalar(json_value, field_name)
                    .map_err(|_| SynthesisError::AssignmentMissing)?]
            }
            FieldParser::BigIntArray => parse_bigint_string_array(json_value, field_name)
                .map_err(|_| SynthesisError::AssignmentMissing)?,
            FieldParser::U64Array => parse_u64_array(json_value, field_name)
                .map_err(|_| SynthesisError::AssignmentMissing)?,
            FieldParser::BigInt2DArray => parse_2d_bigint_array(json_value, field_name)
                .map_err(|_| SynthesisError::AssignmentMissing)?,
        };
        inputs.insert(field_name.to_string(), value);
    }

    Ok(inputs)
}

pub fn parse_jwt_inputs(
    json_value: &Value,
) -> Result<HashMap<String, Vec<BigInt>>, SynthesisError> {
    let field_defs: &[(&str, FieldParser)] = &[
        ("sig_r", FieldParser::BigIntScalar),
        ("sig_s_inverse", FieldParser::BigIntScalar),
        ("pubKeyX", FieldParser::BigIntScalar),
        ("pubKeyY", FieldParser::BigIntScalar),
        ("messageLength", FieldParser::U64Scalar),
        ("periodIndex", FieldParser::U64Scalar),
        ("matchesCount", FieldParser::U64Scalar),
        ("message", FieldParser::BigIntArray),
        ("matchIndex", FieldParser::U64Array),
        ("matchLength", FieldParser::U64Array),
        ("claimLengths", FieldParser::BigIntArray),
        ("decodeFlags", FieldParser::U64Array),
        ("matchSubstring", FieldParser::BigInt2DArray),
        ("claims", FieldParser::BigInt2DArray),
        ("ageClaimIndex", FieldParser::U64Scalar),
    ];

    parse_inputs(json_value, field_defs)
}

pub fn parse_show_inputs(
    json_value: &Value,
) -> Result<HashMap<String, Vec<BigInt>>, SynthesisError> {
    let field_defs: &[(&str, FieldParser)] = &[
        ("deviceKeyX", FieldParser::BigIntScalar),
        ("deviceKeyY", FieldParser::BigIntScalar),
        ("sig_r", FieldParser::BigIntScalar),
        ("sig_s_inverse", FieldParser::BigIntScalar),
        ("messageHash", FieldParser::BigIntScalar),
        ("claim", FieldParser::BigIntArray),
        ("currentYear", FieldParser::BigIntScalar),
        ("currentMonth", FieldParser::BigIntScalar),
        ("currentDay", FieldParser::BigIntScalar),
    ];

    parse_inputs(json_value, field_defs)
}

pub fn bigint_to_scalar(bigint_val: BigInt) -> Result<Scalar, SynthesisError> {
    let bytes = bigint_val.to_bytes_le().1;

    if bytes.len() > 32 {
        return Err(SynthesisError::Unsatisfiable);
    }

    let mut padded = [0u8; 32];
    padded[..bytes.len()].copy_from_slice(&bytes);

    Scalar::from_bytes(&padded)
        .into_option()
        .ok_or(SynthesisError::Unsatisfiable)
}

pub fn convert_bigint_to_scalar(
    bigint_witness: Vec<BigInt>,
) -> Result<Vec<Scalar>, SynthesisError> {
    bigint_witness.into_iter().map(bigint_to_scalar).collect()
}

/// Parses the Circom witness binary format (.wtns) directly to Scalar vector
pub fn parse_witness(witness_bytes: &[u8]) -> Result<Vec<Scalar>, SynthesisError> {
    let mut pos = 0;

    if witness_bytes.len() < 12 || &witness_bytes[0..4] != b"wtns" {
        return Err(SynthesisError::Unsatisfiable);
    }
    pos += 4;

    // Skip version (4 bytes)
    pos += 4;

    let n_sections = u32::from_le_bytes(witness_bytes[pos..pos + 4].try_into().unwrap());
    pos += 4;

    let mut n8 = 0;

    for _ in 0..n_sections {
        if pos + 12 > witness_bytes.len() {
            return Err(SynthesisError::Unsatisfiable);
        }

        let section_id = u32::from_le_bytes(witness_bytes[pos..pos + 4].try_into().unwrap());
        pos += 4;

        let section_length =
            u64::from_le_bytes(witness_bytes[pos..pos + 8].try_into().unwrap()) as usize;
        pos += 8;

        match section_id {
            1 => {
                if pos + 4 > witness_bytes.len() {
                    return Err(SynthesisError::Unsatisfiable);
                }
                n8 = u32::from_le_bytes(witness_bytes[pos..pos + 4].try_into().unwrap()) as usize;
                pos += section_length;
            }

            2 => {
                if n8 == 0 {
                    return Err(SynthesisError::Unsatisfiable);
                }

                if pos + section_length > witness_bytes.len() {
                    return Err(SynthesisError::Unsatisfiable);
                }

                let witness_data = &witness_bytes[pos..pos + section_length];
                let num_elements = section_length / n8;

                let mut scalars = Vec::with_capacity(num_elements);

                for chunk in witness_data.chunks(n8) {
                    let mut padded = [0u8; 32];
                    padded[..chunk.len()].copy_from_slice(chunk);

                    let scalar = Scalar::from_bytes(&padded)
                        .into_option()
                        .ok_or(SynthesisError::Unsatisfiable)?;
                    scalars.push(scalar);
                }

                return Ok(scalars);
            }

            _ => {
                pos += section_length;
            }
        }
    }

    Err(SynthesisError::Unsatisfiable)
}

/// Convert HashMap<String, Vec<BigInt>> to JSON string for witnesscalc_adapter.
pub fn hashmap_to_json_string(
    inputs: &HashMap<String, Vec<BigInt>>,
    max_matches: usize,
    max_substring_length: usize,
    max_claims_length: usize,
) -> Result<String, SynthesisError> {
    use serde_json::json;

    let mut json_map = serde_json::Map::new();

    let two_d_fields: HashMap<&str, (usize, usize)> = [
        ("claims", (max_matches, max_claims_length)),
        ("matchSubstring", (max_matches, max_substring_length)),
    ]
    .iter()
    .cloned()
    .collect();

    for (key, values) in inputs.iter() {
        if let Some(&(rows, cols)) = two_d_fields.get(key.as_str()) {
            let mut array_2d = Vec::with_capacity(rows);
            for i in 0..rows {
                let start = i * cols;
                let end = start + cols;
                if end <= values.len() {
                    let row: Vec<String> = values[start..end]
                        .iter()
                        .map(|bigint| bigint.to_string())
                        .collect();
                    array_2d.push(json!(row));
                } else {
                    return Err(SynthesisError::Unsatisfiable);
                }
            }
            json_map.insert(key.clone(), json!(array_2d));
        } else {
            let string_array: Vec<String> =
                values.iter().map(|bigint| bigint.to_string()).collect();
            json_map.insert(key.clone(), json!(string_array));
        }
    }

    serde_json::to_string(&json_map).map_err(|_| SynthesisError::Unsatisfiable)
}

pub fn decode_base64(encoded: &str) -> Result<Vec<u8>, SynthesisError> {
    if encoded.len() % 4 == 1 {
        return Err(SynthesisError::AssignmentMissing);
    }

    let mut candidates = vec![encoded.to_string()];

    let mut padded = encoded.to_string();
    match encoded.len() % 4 {
        0 => {}
        2 => padded.push_str("=="),
        3 => padded.push('='),
        _ => {}
    }

    if padded != encoded {
        candidates.push(padded);
    }

    for candidate in candidates {
        if let Ok(decoded) = URL_SAFE_NO_PAD.decode(candidate.as_bytes()) {
            return Ok(decoded);
        }
        if let Ok(decoded) = URL_SAFE.decode(candidate.as_bytes()) {
            return Ok(decoded);
        }
        if let Ok(decoded) = STANDARD.decode(candidate.as_bytes()) {
            return Ok(decoded);
        }
    }

    Err(SynthesisError::AssignmentMissing)
}

fn parse_bigint_scalar(json: &Value, key: &str) -> Result<BigInt, String> {
    let s = json
        .get(key)
        .and_then(|v| v.as_str())
        .ok_or("Field must be a string")?;
    BigInt::from_str(s).map_err(|_| "Failed to parse as BigInt".to_string())
}

fn parse_u64_scalar(json: &Value, key: &str) -> Result<BigInt, String> {
    json.get(key)
        .and_then(|v| v.as_u64())
        .map(BigInt::from)
        .ok_or("Field must be a number".to_string())
}

fn parse_bigint_string_array(json: &Value, key: &str) -> Result<Vec<BigInt>, String> {
    let array = json
        .get(key)
        .and_then(|v| v.as_array())
        .ok_or("Field must be an array")?;

    array
        .iter()
        .map(|v| {
            let s = v.as_str().ok_or("Array element must be a string")?;
            BigInt::from_str(s).map_err(|_| "Failed to parse array element as BigInt".to_string())
        })
        .collect()
}

fn parse_u64_array(json: &Value, key: &str) -> Result<Vec<BigInt>, String> {
    json.get(key)
        .and_then(|v| v.as_array())
        .ok_or("Field must be an array")?
        .iter()
        .map(|v| {
            v.as_u64()
                .map(BigInt::from)
                .ok_or("Array element must be a number".to_string())
        })
        .collect()
}

fn parse_2d_bigint_array(json: &Value, key: &str) -> Result<Vec<BigInt>, String> {
    let outer_array = json
        .get(key)
        .and_then(|v| v.as_array())
        .ok_or("Field must be an array")?;

    let total_capacity: usize = outer_array
        .iter()
        .filter_map(|v| v.as_array())
        .map(|arr| arr.len())
        .sum();

    let mut result = Vec::with_capacity(total_capacity);

    for inner_value in outer_array.iter() {
        let inner_array = inner_value
            .as_array()
            .ok_or("Outer array element must be an array")?;

        for v in inner_array.iter() {
            let s = v.as_str().ok_or("Inner array element must be a string")?;
            let bigint =
                BigInt::from_str(s).map_err(|_| "Failed to parse inner array element as BigInt")?;
            result.push(bigint);
        }
    }

    Ok(result)
}

/// Layout information for the JWT circuit outputs within the witness vector.
#[derive(Debug, Clone, Copy)]
pub struct JwtOutputLayout {
    pub age_claim_start: usize,
    pub age_claim_len: usize,
    pub keybinding_x_index: usize,
    pub keybinding_y_index: usize,
}

impl JwtOutputLayout {
    pub fn age_claim_range(&self) -> Range<usize> {
        self.age_claim_start..self.age_claim_start + self.age_claim_len
    }
}

pub fn calculate_jwt_output_indices(
    _max_matches: usize,
    max_claims_length: usize,
) -> JwtOutputLayout {
    let decoded_len = (max_claims_length * 3) / 4;
    let age_claim_start = 1;
    let keybinding_x_index = age_claim_start + decoded_len;
    let keybinding_y_index = keybinding_x_index + 1;

    JwtOutputLayout {
        age_claim_start,
        age_claim_len: decoded_len,
        keybinding_x_index,
        keybinding_y_index,
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ShowWitnessLayout {
    pub device_key_x_index: usize,
    pub device_key_y_index: usize,
    pub claim_start: usize,
    pub claim_len: usize,
}

impl ShowWitnessLayout {
    pub fn claim_range(&self) -> Range<usize> {
        self.claim_start..self.claim_start + self.claim_len
    }
}

pub fn calculate_show_witness_indices(max_claims_length: usize) -> ShowWitnessLayout {
    let decoded_len = (max_claims_length * 3) / 4;

    ShowWitnessLayout {
        device_key_x_index: 2,
        device_key_y_index: 3,
        claim_start: 6,
        claim_len: decoded_len,
    }
}
