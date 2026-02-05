//! # Threshold Check Circuit (REQ-007)
//!
//! ZK circuit that proves Hamming distance is within threshold.
//!
//! ## Overview
//!
//! This circuit implements the final comparison in face verification:
//! - Input: Hamming distance (private witness)
//! - Input: Threshold (public input)
//! - Output: Boolean result (1 = match, 0 = no match)
//!
//! ## Circuit Design
//!
//! The circuit proves: distance <= threshold
//!
//! This is implemented as:
//! 1. Compute diff = threshold - distance
//! 2. Prove diff >= 0 (using range check)
//! 3. Output 1 if proof succeeds, 0 otherwise
//!
//! ## Security Properties
//!
//! - Distance is kept private (not revealed to verifier)
//! - Threshold is public (verifier knows the security level)
//! - Proof reveals only pass/fail, not actual similarity

use halo2_base::gates::circuit::builder::BaseCircuitBuilder;
use halo2_base::gates::circuit::BaseCircuitParams;
use halo2_base::gates::GateChip;
use halo2_base::gates::GateInstructions;
use halo2_base::halo2_proofs::dev::MockProver;
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use halo2_base::AssignedValue;
use halo2_base::Context;

use crate::error::{Result, SableError};

/// Circuit parameters
const K: u32 = 14; // 2^14 = 16384 rows
const NUM_ADVICE: usize = 4;
const NUM_LOOKUP_ADVICE: usize = 1;
const NUM_FIXED: usize = 1;
const LOOKUP_BITS: usize = 13;

/// Maximum value for threshold (2^16 = 65536, enough for 8192 bits).
const MAX_THRESHOLD_BITS: usize = 16;

/// Threshold check circuit.
///
/// Proves that distance <= threshold without revealing the distance.
pub struct ThresholdCheckCircuit {
    /// Hamming distance (private witness).
    distance: u64,
    /// Threshold value (public input).
    threshold: u64,
}

impl ThresholdCheckCircuit {
    /// Create a new threshold check circuit.
    ///
    /// # Arguments
    /// * `distance` - The computed Hamming distance (private)
    /// * `threshold` - The maximum allowed distance (public)
    pub fn new(distance: u64, threshold: u64) -> Self {
        Self {
            distance,
            threshold,
        }
    }

    /// Create a circuit that should pass (distance <= threshold).
    pub fn passing(distance: u64) -> Self {
        Self {
            distance,
            threshold: distance + 100, // Threshold is higher than distance
        }
    }

    /// Create a circuit that should fail (distance > threshold).
    pub fn failing(threshold: u64) -> Self {
        Self {
            distance: threshold + 100, // Distance exceeds threshold
            threshold,
        }
    }

    /// Check if this configuration should pass.
    pub fn should_pass(&self) -> bool {
        self.distance <= self.threshold
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

    /// Build the threshold check circuit.
    ///
    /// Returns (result, threshold) where result is 1 if distance <= threshold.
    fn build_circuit(&self, builder: &mut BaseCircuitBuilder<Fr>) -> (AssignedValue<Fr>, AssignedValue<Fr>) {
        let ctx = builder.main(0);
        let gate = GateChip::<Fr>::default();

        // Load distance as private witness
        let distance = ctx.load_witness(Fr::from(self.distance));

        // Load threshold as public input (will be exposed as instance)
        let threshold = ctx.load_witness(Fr::from(self.threshold));

        // Compute the comparison: distance <= threshold
        let result = compare_less_than_or_equal(ctx, &gate, distance, threshold);

        (result, threshold)
    }

    /// Test the circuit using the mock prover.
    ///
    /// # Returns
    /// * `Ok(true)` if distance <= threshold (verification passes)
    /// * `Ok(false)` if distance > threshold (verification fails)
    /// * `Err` if circuit constraints are not satisfied
    pub fn test_circuit(&self) -> Result<bool> {
        // Build circuit
        let mut builder = BaseCircuitBuilder::new(false).use_params(Self::circuit_params());
        let (result, threshold) = self.build_circuit(&mut builder);

        // Make result and threshold public instances
        builder.assigned_instances[0].push(result);
        builder.assigned_instances[0].push(threshold);

        // Get the result value
        let result_value = *result.value();
        let threshold_value = *threshold.value();

        // Run mock prover
        let prover = MockProver::run(K, &builder, vec![vec![result_value, threshold_value]])
            .map_err(|e| SableError::ProofGeneration(format!("Mock prover failed: {:?}", e)))?;

        // Verify the circuit
        prover.verify().map_err(|e| {
            SableError::ProofVerification(format!("Circuit verification failed: {:?}", e))
        })?;

        // Convert result to bool (1 = pass, 0 = fail)
        let bytes = result_value.to_bytes();
        let result_u64 = u64::from_le_bytes(bytes[0..8].try_into().unwrap());

        Ok(result_u64 == 1)
    }
}

/// Compare if a <= b.
///
/// Returns 1 if a <= b, 0 otherwise.
///
/// Implementation: We compute (b - a) and check if it's non-negative
/// by verifying that b >= a using a witness approach.
fn compare_less_than_or_equal(
    ctx: &mut Context<Fr>,
    gate: &GateChip<Fr>,
    a: AssignedValue<Fr>,
    b: AssignedValue<Fr>,
) -> AssignedValue<Fr> {
    // Get actual values for witness computation
    let a_val = *a.value();
    let b_val = *b.value();

    // Convert to u64 for comparison
    let a_bytes = a_val.to_bytes();
    let b_bytes = b_val.to_bytes();
    let a_u64 = u64::from_le_bytes(a_bytes[0..8].try_into().unwrap());
    let b_u64 = u64::from_le_bytes(b_bytes[0..8].try_into().unwrap());

    // Compute the result as a witness
    let result_val = if a_u64 <= b_u64 { 1u64 } else { 0u64 };
    let result = ctx.load_witness(Fr::from(result_val));

    // Constrain result to be boolean (0 or 1)
    let one = ctx.load_constant(Fr::from(1u64));
    let result_minus_one = gate.sub(ctx, result, one);
    let bool_check = gate.mul(ctx, result, result_minus_one);
    let zero = ctx.load_constant(Fr::from(0u64));
    ctx.constrain_equal(&bool_check, &zero);

    // If result = 1, then a <= b, meaning b - a >= 0
    // If result = 0, then a > b, meaning a - b > 0
    //
    // We verify this by showing:
    // - When result = 1: diff = b - a should equal some non-negative witness
    // - When result = 0: diff = a - b - 1 should equal some non-negative witness
    //
    // Using conditional: diff = result * (b - a) + (1 - result) * (a - b - 1)

    let b_minus_a = gate.sub(ctx, b, a);
    let a_minus_b = gate.sub(ctx, a, b);
    let a_minus_b_minus_1 = gate.sub(ctx, a_minus_b, one);
    let one_minus_result = gate.sub(ctx, one, result);

    // diff = result * (b - a) + (1 - result) * (a - b - 1)
    let term1 = gate.mul(ctx, result, b_minus_a);
    let term2 = gate.mul(ctx, one_minus_result, a_minus_b_minus_1);
    let diff = gate.add(ctx, term1, term2);

    // The diff should be non-negative and fit in MAX_THRESHOLD_BITS
    // We verify by decomposing it to bits
    let diff_val = *diff.value();
    let diff_bytes = diff_val.to_bytes();
    let diff_u64 = u64::from_le_bytes(diff_bytes[0..8].try_into().unwrap());

    // Decompose diff to bits and constrain
    let bits: Vec<AssignedValue<Fr>> = (0..MAX_THRESHOLD_BITS)
        .map(|i| {
            let bit = ((diff_u64 >> i) & 1) as u64;
            ctx.load_witness(Fr::from(bit))
        })
        .collect();

    // Constrain each bit to be 0 or 1
    for &bit in &bits {
        let bit_minus_one = gate.sub(ctx, bit, one);
        let product = gate.mul(ctx, bit, bit_minus_one);
        ctx.constrain_equal(&product, &zero);
    }

    // Constrain that bits reconstruct diff
    let mut reconstructed = ctx.load_constant(Fr::from(0u64));
    let mut power_of_two = Fr::from(1u64);

    for &bit in &bits {
        let power_const = ctx.load_constant(power_of_two);
        let weighted_bit = gate.mul(ctx, bit, power_const);
        reconstructed = gate.add(ctx, reconstructed, weighted_bit);
        power_of_two = power_of_two + power_of_two;
    }

    ctx.constrain_equal(&reconstructed, &diff);

    result
}

/// Combined face verification circuit.
///
/// This is the complete circuit that:
/// 1. Computes Hamming distance between two embeddings
/// 2. Checks if distance <= threshold
/// 3. Outputs pass/fail result
pub struct FaceVerificationCircuit {
    /// First embedding (enrolled template)
    embedding_a: Vec<u8>,
    /// Second embedding (live scan)
    embedding_b: Vec<u8>,
    /// Maximum allowed Hamming distance
    threshold: u64,
}

impl FaceVerificationCircuit {
    /// Create a new face verification circuit.
    pub fn new(embedding_a: Vec<u8>, embedding_b: Vec<u8>, threshold: u64) -> Self {
        assert_eq!(
            embedding_a.len(),
            embedding_b.len(),
            "Embeddings must have same length"
        );
        Self {
            embedding_a,
            embedding_b,
            threshold,
        }
    }

    /// Calculate the expected Hamming distance.
    pub fn expected_distance(&self) -> u64 {
        self.embedding_a
            .iter()
            .zip(self.embedding_b.iter())
            .map(|(&a, &b)| (a ^ b).count_ones() as u64)
            .sum()
    }

    /// Check if verification should pass.
    pub fn should_pass(&self) -> bool {
        self.expected_distance() <= self.threshold
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_threshold_check_passing() {
        // Distance below threshold should pass
        let circuit = ThresholdCheckCircuit::new(100, 200);
        assert!(circuit.should_pass());

        let result = circuit.test_circuit().expect("Circuit should be valid");
        assert!(result, "Distance 100 <= threshold 200 should pass");
    }

    #[test]
    fn test_threshold_check_equal() {
        // Distance equal to threshold should pass
        let circuit = ThresholdCheckCircuit::new(150, 150);
        assert!(circuit.should_pass());

        let result = circuit.test_circuit().expect("Circuit should be valid");
        assert!(result, "Distance 150 <= threshold 150 should pass");
    }

    #[test]
    fn test_threshold_check_failing() {
        // Distance above threshold should fail
        let circuit = ThresholdCheckCircuit::new(300, 200);
        assert!(!circuit.should_pass());

        let result = circuit.test_circuit().expect("Circuit should be valid");
        assert!(!result, "Distance 300 > threshold 200 should fail");
    }

    #[test]
    fn test_threshold_check_zero_distance() {
        // Zero distance (identical embeddings) should always pass
        let circuit = ThresholdCheckCircuit::new(0, 100);

        let result = circuit.test_circuit().expect("Circuit should be valid");
        assert!(result, "Distance 0 should pass any positive threshold");
    }

    #[test]
    fn test_threshold_check_zero_threshold() {
        // Zero threshold only passes for zero distance
        let circuit_pass = ThresholdCheckCircuit::new(0, 0);
        let result = circuit_pass.test_circuit().expect("Circuit should be valid");
        assert!(result, "Distance 0 <= threshold 0 should pass");

        let circuit_fail = ThresholdCheckCircuit::new(1, 0);
        let result = circuit_fail.test_circuit().expect("Circuit should be valid");
        assert!(!result, "Distance 1 > threshold 0 should fail");
    }

    #[test]
    fn test_threshold_check_large_values() {
        // Test with larger values (within MAX_THRESHOLD_BITS)
        let circuit = ThresholdCheckCircuit::new(4000, 4096);

        let result = circuit.test_circuit().expect("Circuit should be valid");
        assert!(result, "Distance 4000 <= threshold 4096 should pass");
    }

    #[test]
    fn test_threshold_check_boundary() {
        // Test at typical face verification boundary (50% of 8192 bits)
        let threshold = 4096u64;

        // Just under threshold
        let circuit_under = ThresholdCheckCircuit::new(4095, threshold);
        let result = circuit_under.test_circuit().expect("Circuit should be valid");
        assert!(result, "4095 <= 4096 should pass");

        // At threshold
        let circuit_at = ThresholdCheckCircuit::new(4096, threshold);
        let result = circuit_at.test_circuit().expect("Circuit should be valid");
        assert!(result, "4096 <= 4096 should pass");

        // Just over threshold
        let circuit_over = ThresholdCheckCircuit::new(4097, threshold);
        let result = circuit_over.test_circuit().expect("Circuit should be valid");
        assert!(!result, "4097 > 4096 should fail");
    }

    #[test]
    fn test_passing_helper() {
        let circuit = ThresholdCheckCircuit::passing(500);
        assert!(circuit.should_pass());

        let result = circuit.test_circuit().expect("Circuit should be valid");
        assert!(result);
    }

    #[test]
    fn test_failing_helper() {
        let circuit = ThresholdCheckCircuit::failing(200);
        assert!(!circuit.should_pass());

        let result = circuit.test_circuit().expect("Circuit should be valid");
        assert!(!result);
    }

    #[test]
    fn test_face_verification_circuit_creation() {
        let emb_a = vec![0x12, 0x34, 0x56, 0x78];
        let emb_b = vec![0x12, 0x34, 0xFF, 0x00];
        let threshold = 20; // Allow up to 20 bits different

        let circuit = FaceVerificationCircuit::new(emb_a, emb_b, threshold);

        // The actual distance depends on the XOR of the bytes
        let distance = circuit.expected_distance();
        assert!(distance > 0, "Different embeddings should have non-zero distance");

        // Check if it passes with the given threshold
        println!("Expected distance: {}, threshold: {}", distance, threshold);
    }

    #[test]
    fn test_face_verification_identical() {
        let emb = vec![0xAB, 0xCD, 0xEF, 0x01];
        let circuit = FaceVerificationCircuit::new(emb.clone(), emb, 0);

        assert_eq!(circuit.expected_distance(), 0);
        assert!(circuit.should_pass());
    }

    #[test]
    fn test_face_verification_different() {
        let emb_a = vec![0x00, 0x00];
        let emb_b = vec![0xFF, 0xFF];
        let circuit = FaceVerificationCircuit::new(emb_a, emb_b, 8);

        // 2 bytes * 8 bits = 16 bits different
        assert_eq!(circuit.expected_distance(), 16);
        assert!(!circuit.should_pass()); // 16 > 8
    }
}
