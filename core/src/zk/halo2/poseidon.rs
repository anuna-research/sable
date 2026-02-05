//! # Poseidon Hash Circuit (REQ-004)
//!
//! Poseidon hash implementation for Halo2 circuits.
//! Used for commitment verification in the face verification circuit.
//!
//! ## Overview
//!
//! Poseidon is a ZK-friendly hash function designed for efficient
//! arithmetic circuit implementation. It's used in SABLE for:
//!
//! 1. **Feature Commitment**: Hash(features || salt) = commitment
//! 2. **Public Input Binding**: Ensures prover uses correct enrolled template
//!
//! ## Parameters
//!
//! Using standard Poseidon parameters:
//! - Width (t): 3 (2 inputs + 1 capacity)
//! - Rate (r): 2
//! - Full rounds (Rf): 8
//! - Partial rounds (Rp): 57

use halo2_base::gates::circuit::builder::BaseCircuitBuilder;
use halo2_base::gates::circuit::BaseCircuitParams;
use halo2_base::gates::GateChip;
use halo2_base::halo2_proofs::dev::MockProver;
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use halo2_base::poseidon::hasher::PoseidonHasher;
use halo2_base::poseidon::hasher::spec::OptimizedPoseidonSpec;
use halo2_base::AssignedValue;

use crate::error::{Result, SableError};

/// Poseidon parameters: width = 3, rate = 2
const T: usize = 3;
/// Rate parameter
const RATE: usize = 2;
/// Number of full rounds
const R_F: usize = 8;
/// Number of partial rounds
const R_P: usize = 57;

/// Circuit parameters (Poseidon needs larger circuit)
const K: u32 = 14; // 2^14 = 16384 rows
const NUM_ADVICE: usize = 4;
const NUM_LOOKUP_ADVICE: usize = 1;
const NUM_FIXED: usize = 1;
const LOOKUP_BITS: usize = 13;

/// Poseidon hash circuit for two inputs.
///
/// Computes Poseidon(a, b) in a ZK circuit.
pub struct PoseidonCircuit {
    /// First input
    a: Fr,
    /// Second input
    b: Fr,
}

impl PoseidonCircuit {
    /// Create a new Poseidon hash circuit.
    ///
    /// # Arguments
    /// * `a` - First field element
    /// * `b` - Second field element
    pub fn new(a: Fr, b: Fr) -> Self {
        Self { a, b }
    }

    /// Create from u64 values.
    pub fn from_u64(a: u64, b: u64) -> Self {
        Self {
            a: Fr::from(a),
            b: Fr::from(b),
        }
    }

    /// Generate circuit parameters.
    fn circuit_params() -> BaseCircuitParams {
        BaseCircuitParams {
            k: K as usize,
            num_advice_per_phase: vec![NUM_ADVICE],
            num_lookup_advice_per_phase: vec![NUM_LOOKUP_ADVICE],
            num_fixed: NUM_FIXED,
            lookup_bits: Some(LOOKUP_BITS),
            num_instance_columns: 1,
        }
    }

    /// Build the Poseidon hash circuit.
    fn build_circuit(&self, builder: &mut BaseCircuitBuilder<Fr>) -> AssignedValue<Fr> {
        let ctx = builder.main(0);
        let gate = GateChip::<Fr>::default();

        // Load inputs as witnesses
        let a = ctx.load_witness(self.a);
        let b = ctx.load_witness(self.b);

        // Initialize Poseidon hasher with spec from halo2_base
        let spec = OptimizedPoseidonSpec::<Fr, T, RATE>::new::<R_F, R_P, 0>();
        let mut hasher = PoseidonHasher::<Fr, T, RATE>::new(spec);
        hasher.initialize_consts(ctx, &gate);

        // Hash the two inputs
        let hash = hasher.hash_fix_len_array(ctx, &gate, &[a, b]);

        hash
    }

    /// Test the circuit using the mock prover.
    ///
    /// # Returns
    /// * `Ok(hash)` - The computed hash value
    /// * `Err` if circuit constraints are not satisfied
    pub fn test_circuit(&self) -> Result<Fr> {
        // Build circuit
        let mut builder = BaseCircuitBuilder::new(false).use_params(Self::circuit_params());
        let hash = self.build_circuit(&mut builder);

        // Make hash a public instance
        builder.assigned_instances[0].push(hash);

        // Get the hash value
        let hash_value = *hash.value();

        // Run mock prover with the computed hash as public input
        let prover = MockProver::run(K, &builder, vec![vec![hash_value]])
            .map_err(|e| SableError::ProofGeneration(format!("Mock prover failed: {:?}", e)))?;

        // Verify the circuit
        prover.verify().map_err(|e| {
            SableError::ProofVerification(format!("Circuit verification failed: {:?}", e))
        })?;

        Ok(hash_value)
    }
}

/// Utility function to hash two values in a circuit.
///
/// This creates a Poseidon hasher and computes hash(a, b).
pub fn poseidon_hash_pair(
    builder: &mut BaseCircuitBuilder<Fr>,
    a: AssignedValue<Fr>,
    b: AssignedValue<Fr>,
) -> AssignedValue<Fr> {
    let ctx = builder.main(0);
    let gate = GateChip::<Fr>::default();

    let spec = OptimizedPoseidonSpec::<Fr, T, RATE>::new::<R_F, R_P, 0>();
    let mut hasher = PoseidonHasher::<Fr, T, RATE>::new(spec);
    hasher.initialize_consts(ctx, &gate);

    hasher.hash_fix_len_array(ctx, &gate, &[a, b])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poseidon_circuit_basic() {
        // Test basic Poseidon hash computation
        let circuit = PoseidonCircuit::from_u64(42, 58);
        let hash = circuit.test_circuit().expect("Circuit should be valid");

        // Hash should be non-zero
        assert_ne!(hash, Fr::from(0));
    }

    #[test]
    fn test_poseidon_circuit_deterministic() {
        // Same inputs should produce same hash
        let circuit1 = PoseidonCircuit::from_u64(123, 456);
        let hash1 = circuit1.test_circuit().expect("Circuit should be valid");

        let circuit2 = PoseidonCircuit::from_u64(123, 456);
        let hash2 = circuit2.test_circuit().expect("Circuit should be valid");

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_poseidon_circuit_different_inputs() {
        // Different inputs should produce different hashes
        let circuit1 = PoseidonCircuit::from_u64(1, 2);
        let hash1 = circuit1.test_circuit().expect("Circuit should be valid");

        let circuit2 = PoseidonCircuit::from_u64(2, 1);
        let hash2 = circuit2.test_circuit().expect("Circuit should be valid");

        // Order matters
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_poseidon_circuit_zero_inputs() {
        // Zero inputs should work
        let circuit = PoseidonCircuit::from_u64(0, 0);
        let _hash = circuit.test_circuit().expect("Circuit should be valid");
        // Circuit validated successfully
    }

    #[test]
    fn test_poseidon_circuit_large_inputs() {
        // Large inputs should work
        let circuit = PoseidonCircuit::from_u64(u64::MAX, u64::MAX - 1);
        let hash = circuit.test_circuit().expect("Circuit should be valid");

        assert_ne!(hash, Fr::from(0));
    }
}
