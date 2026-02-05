//! # Hamming Distance Circuit (REQ-005)
//!
//! Computes Hamming distance between two byte arrays in a Halo2 circuit.
//! Used for face verification similarity measurement.
//!
//! ## Overview
//!
//! Hamming distance counts the number of differing bits between two
//! binary representations. For quantized face embeddings:
//!
//! 1. XOR each byte pair: diff[i] = a[i] ^ b[i]
//! 2. Count bits in each diff byte (popcount)
//! 3. Sum all bit counts = total Hamming distance
//!
//! ## Circuit Design
//!
//! - Uses lookup tables for efficient XOR and popcount operations
//! - Accumulates distance using standard addition gates
//! - Outputs total Hamming distance as public value
//!
//! ## Similarity Calculation
//!
//! For N bytes (N*8 bits total):
//! - Similarity = 1 - (hamming_distance / (N * 8))
//! - Example: 1024 bytes = 8192 bits
//!   - Distance 0 = 100% similar (identical)
//!   - Distance 4096 = 50% similar (threshold)
//!   - Distance 8192 = 0% similar (maximally different)

use halo2_base::gates::circuit::builder::BaseCircuitBuilder;
use halo2_base::gates::circuit::BaseCircuitParams;
use halo2_base::gates::GateChip;
use halo2_base::gates::GateInstructions;
use halo2_base::halo2_proofs::dev::MockProver;
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use halo2_base::AssignedValue;
use halo2_base::Context;

use crate::error::{Result, SableError};

/// Circuit parameters for Hamming distance
const K: u32 = 14; // 2^14 = 16384 rows
const NUM_ADVICE: usize = 4;
const NUM_LOOKUP_ADVICE: usize = 1;
const NUM_FIXED: usize = 1;
const LOOKUP_BITS: usize = 13;

/// Maximum embedding dimension for the circuit.
/// Using 64 bytes for testing (512 bits).
/// Production would use 1024 bytes (8192 bits).
pub const MAX_EMBEDDING_DIM: usize = 64;

/// Hamming distance circuit for comparing two byte arrays.
///
/// Computes the number of differing bits between two quantized embeddings.
pub struct HammingDistanceCircuit {
    /// First embedding (quantized bytes)
    embedding_a: Vec<u8>,
    /// Second embedding (quantized bytes)
    embedding_b: Vec<u8>,
}

impl HammingDistanceCircuit {
    /// Create a new Hamming distance circuit.
    ///
    /// # Arguments
    /// * `embedding_a` - First quantized embedding
    /// * `embedding_b` - Second quantized embedding
    ///
    /// # Panics
    /// Panics if embeddings have different lengths.
    pub fn new(embedding_a: Vec<u8>, embedding_b: Vec<u8>) -> Self {
        assert_eq!(
            embedding_a.len(),
            embedding_b.len(),
            "Embeddings must have the same length"
        );
        Self {
            embedding_a,
            embedding_b,
        }
    }

    /// Create a circuit with identical embeddings (distance = 0).
    pub fn identical(embedding: Vec<u8>) -> Self {
        Self {
            embedding_a: embedding.clone(),
            embedding_b: embedding,
        }
    }

    /// Create a circuit with maximally different embeddings.
    pub fn maximally_different(len: usize) -> Self {
        Self {
            embedding_a: vec![0x00; len],
            embedding_b: vec![0xFF; len],
        }
    }

    /// Calculate expected Hamming distance (for testing).
    pub fn expected_distance(&self) -> u64 {
        self.embedding_a
            .iter()
            .zip(self.embedding_b.iter())
            .map(|(&a, &b)| (a ^ b).count_ones() as u64)
            .sum()
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

    /// Build the Hamming distance circuit.
    fn build_circuit(&self, builder: &mut BaseCircuitBuilder<Fr>) -> AssignedValue<Fr> {
        let ctx = builder.main(0);
        let gate = GateChip::<Fr>::default();

        // Load embeddings as witnesses
        let a_vals: Vec<AssignedValue<Fr>> = self
            .embedding_a
            .iter()
            .map(|&b| ctx.load_witness(Fr::from(b as u64)))
            .collect();

        let b_vals: Vec<AssignedValue<Fr>> = self
            .embedding_b
            .iter()
            .map(|&b| ctx.load_witness(Fr::from(b as u64)))
            .collect();

        // Compute XOR and popcount for each byte pair
        let mut total_distance = ctx.load_constant(Fr::from(0u64));

        for (a, b) in a_vals.iter().zip(b_vals.iter()) {
            // Compute XOR: we need to decompose to bits, XOR, and count
            let xor_bits = compute_xor_bits(ctx, &gate, *a, *b);

            // Sum the XOR bits (each 1 bit = 1 distance)
            for bit in xor_bits {
                total_distance = gate.add(ctx, total_distance, bit);
            }
        }

        total_distance
    }

    /// Test the circuit using the mock prover.
    ///
    /// # Returns
    /// * `Ok(distance)` - The computed Hamming distance
    /// * `Err` if circuit constraints are not satisfied
    pub fn test_circuit(&self) -> Result<u64> {
        // Build circuit
        let mut builder = BaseCircuitBuilder::new(false).use_params(Self::circuit_params());
        let distance = self.build_circuit(&mut builder);

        // Make distance a public instance
        builder.assigned_instances[0].push(distance);

        // Get the distance value
        let distance_value = *distance.value();

        // Run mock prover
        let prover = MockProver::run(K, &builder, vec![vec![distance_value]])
            .map_err(|e| SableError::ProofGeneration(format!("Mock prover failed: {:?}", e)))?;

        // Verify the circuit
        prover.verify().map_err(|e| {
            SableError::ProofVerification(format!("Circuit verification failed: {:?}", e))
        })?;

        // Convert Fr to u64
        let bytes = distance_value.to_bytes();
        let result = u64::from_le_bytes(bytes[0..8].try_into().unwrap());

        Ok(result)
    }
}

/// Compute XOR of two 8-bit values and return the 8 result bits.
///
/// This decomposes both inputs to bits, XORs corresponding bits,
/// and returns the result bits (which can be summed for popcount).
fn compute_xor_bits(
    ctx: &mut Context<Fr>,
    gate: &GateChip<Fr>,
    a: AssignedValue<Fr>,
    b: AssignedValue<Fr>,
) -> Vec<AssignedValue<Fr>> {
    // Decompose a and b to 8 bits each
    let a_bits = decompose_to_bits(ctx, gate, a, 8);
    let b_bits = decompose_to_bits(ctx, gate, b, 8);

    // XOR corresponding bits: xor = a + b - 2*a*b
    a_bits
        .iter()
        .zip(b_bits.iter())
        .map(|(&a_bit, &b_bit)| {
            // XOR formula for bits: a ^ b = a + b - 2*a*b
            let sum = gate.add(ctx, a_bit, b_bit);
            let prod = gate.mul(ctx, a_bit, b_bit);
            let two_prod = gate.add(ctx, prod, prod);
            gate.sub(ctx, sum, two_prod)
        })
        .collect()
}

/// Decompose a field element to its bit representation.
///
/// Returns a vector of assigned values, each constrained to be 0 or 1,
/// such that the sum of bits[i] * 2^i equals the original value.
fn decompose_to_bits(
    ctx: &mut Context<Fr>,
    gate: &GateChip<Fr>,
    value: AssignedValue<Fr>,
    num_bits: usize,
) -> Vec<AssignedValue<Fr>> {
    // Get the actual value to decompose
    let val = *value.value();
    let val_bytes = val.to_bytes();
    let val_u64 = u64::from_le_bytes(val_bytes[0..8].try_into().unwrap());

    // Create bit witnesses
    let bits: Vec<AssignedValue<Fr>> = (0..num_bits)
        .map(|i| {
            let bit = ((val_u64 >> i) & 1) as u64;
            ctx.load_witness(Fr::from(bit))
        })
        .collect();

    // Constrain each bit to be 0 or 1: bit * (bit - 1) = 0
    for &bit in &bits {
        let one = ctx.load_constant(Fr::from(1u64));
        let bit_minus_one = gate.sub(ctx, bit, one);
        let product = gate.mul(ctx, bit, bit_minus_one);
        let zero = ctx.load_constant(Fr::from(0u64));
        ctx.constrain_equal(&product, &zero);
    }

    // Constrain that bits reconstruct the original value
    let mut reconstructed = ctx.load_constant(Fr::from(0u64));
    let mut power_of_two = Fr::from(1u64);

    for &bit in &bits {
        let power_const = ctx.load_constant(power_of_two);
        let weighted_bit = gate.mul(ctx, bit, power_const);
        reconstructed = gate.add(ctx, reconstructed, weighted_bit);
        power_of_two = power_of_two + power_of_two; // power_of_two *= 2
    }

    ctx.constrain_equal(&reconstructed, &value);

    bits
}

/// Utility function to compute Hamming distance outside of circuit.
///
/// This is for testing and comparison purposes.
pub fn hamming_distance(a: &[u8], b: &[u8]) -> u64 {
    assert_eq!(a.len(), b.len(), "Arrays must have same length");
    a.iter()
        .zip(b.iter())
        .map(|(&x, &y)| (x ^ y).count_ones() as u64)
        .sum()
}

/// Calculate similarity from Hamming distance.
///
/// Returns a value between 0.0 (maximally different) and 1.0 (identical).
pub fn hamming_similarity(distance: u64, total_bits: usize) -> f64 {
    1.0 - (distance as f64 / total_bits as f64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hamming_distance_identical() {
        let embedding = vec![0x12, 0x34, 0x56, 0x78];
        let circuit = HammingDistanceCircuit::identical(embedding);

        let distance = circuit.test_circuit().expect("Circuit should be valid");
        assert_eq!(distance, 0, "Identical embeddings should have 0 distance");
    }

    #[test]
    fn test_hamming_distance_one_bit_diff() {
        // 0x00 vs 0x01 = 1 bit different
        let circuit = HammingDistanceCircuit::new(vec![0x00], vec![0x01]);

        let distance = circuit.test_circuit().expect("Circuit should be valid");
        assert_eq!(distance, 1, "One bit difference");
    }

    #[test]
    fn test_hamming_distance_maximally_different() {
        // 0x00 vs 0xFF = 8 bits different per byte
        let circuit = HammingDistanceCircuit::maximally_different(4);

        let distance = circuit.test_circuit().expect("Circuit should be valid");
        assert_eq!(distance, 32, "4 bytes * 8 bits = 32 bits different");
    }

    #[test]
    fn test_hamming_distance_mixed() {
        // 0b00001111 vs 0b11110000 = 8 bits different
        let circuit = HammingDistanceCircuit::new(vec![0x0F], vec![0xF0]);

        let distance = circuit.test_circuit().expect("Circuit should be valid");
        assert_eq!(distance, 8);
    }

    #[test]
    fn test_hamming_distance_multiple_bytes() {
        let a = vec![0x00, 0xFF, 0x55, 0xAA];
        let b = vec![0xFF, 0x00, 0xAA, 0x55];
        let circuit = HammingDistanceCircuit::new(a.clone(), b.clone());

        let expected = hamming_distance(&a, &b);
        let computed = circuit.test_circuit().expect("Circuit should be valid");

        assert_eq!(computed, expected);
    }

    #[test]
    fn test_hamming_utility_function() {
        assert_eq!(hamming_distance(&[0x00], &[0x00]), 0);
        assert_eq!(hamming_distance(&[0x00], &[0x01]), 1);
        assert_eq!(hamming_distance(&[0x00], &[0xFF]), 8);
        assert_eq!(hamming_distance(&[0x00, 0x00], &[0xFF, 0xFF]), 16);
    }

    #[test]
    fn test_hamming_similarity() {
        // 8 bytes = 64 bits
        let total_bits = 64;

        // 0 distance = 100% similar
        assert!((hamming_similarity(0, total_bits) - 1.0).abs() < 0.001);

        // Half distance = 50% similar
        assert!((hamming_similarity(32, total_bits) - 0.5).abs() < 0.001);

        // Full distance = 0% similar
        assert!((hamming_similarity(64, total_bits) - 0.0).abs() < 0.001);
    }

    #[test]
    fn test_expected_distance() {
        let a = vec![0x12, 0x34];
        let b = vec![0x56, 0x78];
        let circuit = HammingDistanceCircuit::new(a.clone(), b.clone());

        let expected = hamming_distance(&a, &b);
        assert_eq!(circuit.expected_distance(), expected);
    }
}
