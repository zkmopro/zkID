pub mod rs256_circuit;

use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use ff::PrimeField;

/// Allocate witness variables without adding constraints.
///
/// During proving, Spartan2 only reads witness values from the constraint system;
/// the proving key already contains the R1CS constraint matrices (A, B, C).
/// This allows proving without loading the R1CS file from disk, enabling
/// proof generation in browser/WASM environments.
pub fn synthesize_witness_only<F: PrimeField, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    witness: &[F],
    num_public: usize,
) -> Result<(), SynthesisError> {
    let num_inputs = 1 + num_public;
    if witness.len() < num_inputs {
        return Err(SynthesisError::Unsatisfiable);
    }
    let num_aux = witness.len() - num_inputs;

    for i in 1..num_inputs {
        AllocatedNum::alloc_input(cs.namespace(|| format!("public_{}", i)), || Ok(witness[i]))?;
    }
    for i in 0..num_aux {
        AllocatedNum::alloc(cs.namespace(|| format!("aux_{}", i)), || {
            Ok(witness[i + num_inputs])
        })?;
    }
    Ok(())
}
