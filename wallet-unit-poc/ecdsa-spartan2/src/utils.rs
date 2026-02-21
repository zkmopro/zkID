use bellpepper_core::SynthesisError;
use num_bigint::BigInt;

use crate::Scalar;

/// Convert a single BigInt to Scalar
pub fn bigint_to_scalar(bigint_val: BigInt) -> Result<Scalar, SynthesisError> {
    let bytes = bigint_val.to_bytes_le().1;

    // Validate size before padding
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

    // Validate .wtns header (4 bytes magic)
    if witness_bytes.len() < 12 || &witness_bytes[0..4] != b"wtns" {
        return Err(SynthesisError::Unsatisfiable);
    }
    pos += 4;

    // Skip version (4 bytes)
    pos += 4;

    // Read number of sections (4 bytes)
    let n_sections = u32::from_le_bytes(witness_bytes[pos..pos + 4].try_into().unwrap());
    pos += 4;

    // Number of bytes per field element (from section 1)
    let mut n8 = 0;

    // Iterate through sections to find witness data (section_id = 2)
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
            // Section 1: Header metadata
            // Contains n8 (4 bytes), field q (32 bytes), n_witness_values (4 bytes)
            1 => {
                if pos + 4 > witness_bytes.len() {
                    return Err(SynthesisError::Unsatisfiable);
                }
                n8 = u32::from_le_bytes(witness_bytes[pos..pos + 4].try_into().unwrap()) as usize;
                pos += section_length; // Skip entire section
            }

            // Section 2: Witness data
            // Contains witness elements (n8 bytes each)
            2 => {
                if n8 == 0 {
                    return Err(SynthesisError::Unsatisfiable);
                }

                if pos + section_length > witness_bytes.len() {
                    return Err(SynthesisError::Unsatisfiable);
                }

                // Parse witness elements directly to Scalar
                let witness_data = &witness_bytes[pos..pos + section_length];
                let num_elements = section_length / n8;

                let mut scalars = Vec::with_capacity(num_elements);

                for chunk in witness_data.chunks(n8) {
                    // Pad to 32 bytes if needed (n8 might be less than 32)
                    let mut padded = [0u8; 32];
                    padded[..chunk.len()].copy_from_slice(chunk);

                    // Convert to Scalar
                    let scalar = Scalar::from_bytes(&padded)
                        .into_option()
                        .ok_or(SynthesisError::Unsatisfiable)?;
                    scalars.push(scalar);
                }

                return Ok(scalars);
            }

            // Skip any other section
            _ => {
                pos += section_length;
            }
        }
    }

    Err(SynthesisError::Unsatisfiable)
}
