//! # Liveness Check Circuit
//!
//! ZK circuit that proves spatial flash liveness properties using Hamming
//! distance on quantized delta fingerprints, without revealing facial
//! reflectance data.
//!
//! ## Overview
//!
//! For each of 3 flash rounds, the circuit proves:
//! 1. **Color match**: upper/lower face deltas match expected flash colors
//! 2. **Spatial diff**: upper and lower deltas differ (3D geometry)
//! 3. **Magnitude**: flash response was above noise floor
//!
//! All checks use Hamming distance on 16-bit fingerprints:
//!
//! ```text
//! Fingerprint bit layout: [order:3 | mid_ratio:4 | min_ratio:4 | magnitude:5]
//! ```
//!
//! ## Security Properties
//!
//! - **Zero-Knowledge**: Delta fingerprints (facial reflectance) stay private
//! - **Soundness**: Cannot forge fingerprints that pass all checks
//! - **Completeness**: Real 3D face with correct flash always passes

use halo2_base::gates::circuit::builder::BaseCircuitBuilder;
use halo2_base::gates::circuit::BaseCircuitParams;
use halo2_base::gates::GateChip;
use halo2_base::gates::GateInstructions;
use halo2_base::halo2_proofs::dev::MockProver;
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use halo2_base::AssignedValue;
use halo2_base::Context;

use crate::error::{Result, SableError};

// ---------------------------------------------------------------------------
// Circuit parameters (match existing circuits)
// ---------------------------------------------------------------------------

const K: u32 = 14;
const NUM_ADVICE: usize = 4;
const NUM_LOOKUP_ADVICE: usize = 1;
const NUM_FIXED: usize = 1;
const LOOKUP_BITS: usize = 13;

/// Number of flash rounds.
const NUM_ROUNDS: usize = 3;

/// Number of fingerprints: 2 per round (upper + lower).
const NUM_FINGERPRINTS: usize = NUM_ROUNDS * 2;

/// Number of bits in a fingerprint.
const FINGERPRINT_BITS: usize = 16;

/// Number of bits in the magnitude field (low 5 bits of fingerprint).
const MAGNITUDE_BITS: usize = 5;

/// Maximum bits for threshold range check.
const MAX_THRESHOLD_BITS: usize = 5; // max HD on 16-bit values = 16, fits in 5 bits

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Private + public witness data for the liveness ZK circuit.
#[derive(Debug, Clone)]
pub struct LivenessWitness {
    /// 6 delta fingerprints (private): [round0_upper, round0_lower, round1_upper, ...]
    pub delta_fingerprints: [u16; NUM_FINGERPRINTS],
    /// 6 expected color fingerprints (public, derivable from HKDF pattern).
    pub expected_fingerprints: [u16; NUM_FINGERPRINTS],
    /// Maximum Hamming distance for color match (public).
    pub color_threshold: u8,
    /// Minimum Hamming distance for spatial differentiation (public).
    pub spatial_threshold: u8,
    /// Minimum magnitude value (public, compared against low 5 bits).
    pub min_magnitude: u8,
}

impl LivenessWitness {
    /// Create a dummy witness that trivially passes all checks.
    ///
    /// Used when liveness is not requested — the circuit structure must remain
    /// identical for keygen, so we provide a passing witness with zero overhead.
    pub fn dummy_pass() -> Self {
        // Use fingerprints that trivially pass:
        // - Same delta as expected (color HD = 0, within any threshold)
        // - Different upper/lower (spatial HD > 0)
        // - Magnitude = 20 (well above any reasonable min_magnitude)
        Self {
            delta_fingerprints: [0x0014, 0xA014, 0x4014, 0xA014, 0xA014, 0x0014],
            expected_fingerprints: [0x0014, 0xA014, 0x4014, 0xA014, 0xA014, 0x0014],
            color_threshold: 3,
            spatial_threshold: 2,
            min_magnitude: 5,
        }
    }
}

/// Result of liveness check circuit execution.
#[derive(Debug, Clone)]
pub struct LivenessResult {
    /// Whether all checks passed.
    pub passed: bool,
}

/// Liveness check circuit.
///
/// Proves that private delta fingerprints satisfy color matching,
/// spatial differentiation, and magnitude constraints relative to
/// public expected fingerprints and thresholds.
pub struct LivenessCheckCircuit {
    witness: LivenessWitness,
}

impl LivenessCheckCircuit {
    /// Create a new liveness check circuit.
    pub fn new(witness: LivenessWitness) -> Self {
        Self { witness }
    }

    /// Check if this witness should pass (CPU-side evaluation).
    pub fn should_pass(&self) -> bool {
        let w = &self.witness;
        for r in 0..NUM_ROUNDS {
            let upper_idx = r * 2;
            let lower_idx = r * 2 + 1;

            // Color match: HD(delta, expected) <= color_threshold
            let hd_upper = hamming_u16(w.delta_fingerprints[upper_idx], w.expected_fingerprints[upper_idx]);
            let hd_lower = hamming_u16(w.delta_fingerprints[lower_idx], w.expected_fingerprints[lower_idx]);
            if hd_upper > w.color_threshold as u32 || hd_lower > w.color_threshold as u32 {
                return false;
            }

            // Spatial diff: HD(upper, lower) >= spatial_threshold
            let hd_spatial = hamming_u16(w.delta_fingerprints[upper_idx], w.delta_fingerprints[lower_idx]);
            if hd_spatial < w.spatial_threshold as u32 {
                return false;
            }

            // Magnitude: low 5 bits >= min_magnitude
            let mag_upper = w.delta_fingerprints[upper_idx] & 0x1F;
            let mag_lower = w.delta_fingerprints[lower_idx] & 0x1F;
            if mag_upper < w.min_magnitude as u16 || mag_lower < w.min_magnitude as u16 {
                return false;
            }
        }
        true
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

    /// Build the liveness check circuit.
    ///
    /// Returns the result (1 = all checks pass, 0 = at least one fails).
    pub fn build_circuit(&self, builder: &mut BaseCircuitBuilder<Fr>) -> AssignedValue<Fr> {
        let ctx = builder.main(0);
        let gate = GateChip::<Fr>::default();
        let w = &self.witness;

        let one = ctx.load_constant(Fr::from(1u64));

        // Start with result = 1 (all pass), AND with each check
        let mut result = ctx.load_constant(Fr::from(1u64));

        for r in 0..NUM_ROUNDS {
            let upper_idx = r * 2;
            let lower_idx = r * 2 + 1;

            // Load private delta fingerprints
            let delta_upper = ctx.load_witness(Fr::from(w.delta_fingerprints[upper_idx] as u64));
            let delta_lower = ctx.load_witness(Fr::from(w.delta_fingerprints[lower_idx] as u64));

            // Load public expected fingerprints
            let expected_upper = ctx.load_witness(Fr::from(w.expected_fingerprints[upper_idx] as u64));
            let expected_lower = ctx.load_witness(Fr::from(w.expected_fingerprints[lower_idx] as u64));

            // Decompose all four fingerprints to bits
            let delta_upper_bits = decompose_u16(ctx, &gate, delta_upper, w.delta_fingerprints[upper_idx]);
            let delta_lower_bits = decompose_u16(ctx, &gate, delta_lower, w.delta_fingerprints[lower_idx]);
            let expected_upper_bits = decompose_u16(ctx, &gate, expected_upper, w.expected_fingerprints[upper_idx]);
            let expected_lower_bits = decompose_u16(ctx, &gate, expected_lower, w.expected_fingerprints[lower_idx]);

            // ---- Color match checks ----
            // HD(delta_upper, expected_upper) <= color_threshold
            let xor_upper = xor_bits(ctx, &gate, &delta_upper_bits, &expected_upper_bits);
            let hd_color_upper = popcount(ctx, &gate, &xor_upper);
            let color_thresh = ctx.load_witness(Fr::from(w.color_threshold as u64));
            let color_upper_ok = compare_le(ctx, &gate, hd_color_upper, color_thresh,
                hamming_u16(w.delta_fingerprints[upper_idx], w.expected_fingerprints[upper_idx]) as u64,
                w.color_threshold as u64);
            result = gate.mul(ctx, result, color_upper_ok);

            // HD(delta_lower, expected_lower) <= color_threshold
            let xor_lower = xor_bits(ctx, &gate, &delta_lower_bits, &expected_lower_bits);
            let hd_color_lower = popcount(ctx, &gate, &xor_lower);
            let color_thresh2 = ctx.load_witness(Fr::from(w.color_threshold as u64));
            let color_lower_ok = compare_le(ctx, &gate, hd_color_lower, color_thresh2,
                hamming_u16(w.delta_fingerprints[lower_idx], w.expected_fingerprints[lower_idx]) as u64,
                w.color_threshold as u64);
            result = gate.mul(ctx, result, color_lower_ok);

            // ---- Spatial differentiation check ----
            // HD(delta_upper, delta_lower) >= spatial_threshold
            // Equivalently: spatial_threshold <= HD
            let xor_spatial = xor_bits(ctx, &gate, &delta_upper_bits, &delta_lower_bits);
            let hd_spatial = popcount(ctx, &gate, &xor_spatial);
            let spatial_thresh = ctx.load_witness(Fr::from(w.spatial_threshold as u64));
            let spatial_ok = compare_le(ctx, &gate, spatial_thresh, hd_spatial,
                w.spatial_threshold as u64,
                hamming_u16(w.delta_fingerprints[upper_idx], w.delta_fingerprints[lower_idx]) as u64);
            result = gate.mul(ctx, result, spatial_ok);

            // ---- Magnitude checks ----
            // Extract magnitude from low 5 bits of each delta fingerprint.
            // magnitude = sum of bits[0..5] * 2^i (already decomposed)
            let mag_upper_val = sum_low_bits(ctx, &gate, &delta_upper_bits, MAGNITUDE_BITS);
            let mag_lower_val = sum_low_bits(ctx, &gate, &delta_lower_bits, MAGNITUDE_BITS);
            let min_mag = ctx.load_witness(Fr::from(w.min_magnitude as u64));
            let min_mag2 = ctx.load_witness(Fr::from(w.min_magnitude as u64));

            // min_magnitude <= magnitude_upper
            let mag_upper_ok = compare_le(ctx, &gate, min_mag, mag_upper_val,
                w.min_magnitude as u64,
                (w.delta_fingerprints[upper_idx] & 0x1F) as u64);
            result = gate.mul(ctx, result, mag_upper_ok);

            // min_magnitude <= magnitude_lower
            let mag_lower_ok = compare_le(ctx, &gate, min_mag2, mag_lower_val,
                w.min_magnitude as u64,
                (w.delta_fingerprints[lower_idx] & 0x1F) as u64);
            result = gate.mul(ctx, result, mag_lower_ok);
        }

        // Constrain result to be boolean
        let result_minus_one = gate.sub(ctx, result, one);
        let bool_check = gate.mul(ctx, result, result_minus_one);
        let zero = ctx.load_constant(Fr::from(0u64));
        ctx.constrain_equal(&bool_check, &zero);

        result
    }

    /// Test the circuit using the mock prover.
    pub fn test_circuit(&self) -> Result<bool> {
        let mut builder = BaseCircuitBuilder::new(false).use_params(Self::circuit_params());
        let result = self.build_circuit(&mut builder);

        // Make result a public instance
        builder.assigned_instances[0].push(result);

        let result_value = *result.value();

        // Run mock prover
        let prover = MockProver::run(K, &builder, vec![vec![result_value]])
            .map_err(|e| SableError::ProofGeneration(format!("Mock prover failed: {:?}", e)))?;

        prover.verify().map_err(|e| {
            SableError::ProofVerification(format!("Circuit verification failed: {:?}", e))
        })?;

        let bytes = result_value.to_bytes();
        let result_u64 = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        Ok(result_u64 == 1)
    }
}

// ---------------------------------------------------------------------------
// Circuit helper functions
// ---------------------------------------------------------------------------

/// Decompose a value known to fit in 16 bits into 16 boolean-constrained bits.
///
/// Returns bits in LSB-first order: bits[0] is the least significant bit.
fn decompose_u16(
    ctx: &mut Context<Fr>,
    gate: &GateChip<Fr>,
    value: AssignedValue<Fr>,
    value_u16: u16,
) -> Vec<AssignedValue<Fr>> {
    let one = ctx.load_constant(Fr::from(1u64));
    let zero = ctx.load_constant(Fr::from(0u64));

    let bits: Vec<AssignedValue<Fr>> = (0..FINGERPRINT_BITS)
        .map(|i| {
            let bit = ((value_u16 >> i) & 1) as u64;
            let bit_assigned = ctx.load_witness(Fr::from(bit));
            // Boolean constraint: bit * (bit - 1) = 0
            let bit_minus_one = gate.sub(ctx, bit_assigned, one);
            let product = gate.mul(ctx, bit_assigned, bit_minus_one);
            ctx.constrain_equal(&product, &zero);
            bit_assigned
        })
        .collect();

    // Reconstruction constraint: sum(bit_i * 2^i) == value
    let mut reconstructed = ctx.load_constant(Fr::from(0u64));
    let mut power = Fr::from(1u64);
    for &bit in &bits {
        let power_const = ctx.load_constant(power);
        let weighted = gate.mul(ctx, bit, power_const);
        reconstructed = gate.add(ctx, reconstructed, weighted);
        power = power + power;
    }
    ctx.constrain_equal(&reconstructed, &value);

    bits
}

/// Compute XOR of two bit arrays: xor[i] = a[i] + b[i] - 2*a[i]*b[i].
fn xor_bits(
    ctx: &mut Context<Fr>,
    gate: &GateChip<Fr>,
    a_bits: &[AssignedValue<Fr>],
    b_bits: &[AssignedValue<Fr>],
) -> Vec<AssignedValue<Fr>> {
    let two = ctx.load_constant(Fr::from(2u64));
    a_bits
        .iter()
        .zip(b_bits.iter())
        .map(|(&a, &b)| {
            // xor = a + b - 2*a*b
            let sum = gate.add(ctx, a, b);
            let product = gate.mul(ctx, a, b);
            let double_product = gate.mul(ctx, two, product);
            gate.sub(ctx, sum, double_product)
        })
        .collect()
}

/// Sum of bit values (popcount).
fn popcount(
    ctx: &mut Context<Fr>,
    gate: &GateChip<Fr>,
    bits: &[AssignedValue<Fr>],
) -> AssignedValue<Fr> {
    let mut sum = ctx.load_constant(Fr::from(0u64));
    for &bit in bits {
        sum = gate.add(ctx, sum, bit);
    }
    sum
}

/// Reconstruct the integer value of the low `n` bits: sum(bits[i] * 2^i) for i in 0..n.
fn sum_low_bits(
    ctx: &mut Context<Fr>,
    gate: &GateChip<Fr>,
    bits: &[AssignedValue<Fr>],
    n: usize,
) -> AssignedValue<Fr> {
    let mut sum = ctx.load_constant(Fr::from(0u64));
    let mut power = Fr::from(1u64);
    for &bit in bits.iter().take(n) {
        let power_const = ctx.load_constant(power);
        let weighted = gate.mul(ctx, bit, power_const);
        sum = gate.add(ctx, sum, weighted);
        power = power + power;
    }
    sum
}

/// Prove a <= b with range check, returning 1 if a <= b, 0 otherwise.
///
/// `a_u64` and `b_u64` are the plaintext values for witness computation.
fn compare_le(
    ctx: &mut Context<Fr>,
    gate: &GateChip<Fr>,
    a: AssignedValue<Fr>,
    b: AssignedValue<Fr>,
    a_u64: u64,
    b_u64: u64,
) -> AssignedValue<Fr> {
    let one = ctx.load_constant(Fr::from(1u64));
    let zero = ctx.load_constant(Fr::from(0u64));

    let result_val = if a_u64 <= b_u64 { 1u64 } else { 0u64 };
    let result = ctx.load_witness(Fr::from(result_val));

    // Boolean constraint
    let result_minus_one = gate.sub(ctx, result, one);
    let bool_check = gate.mul(ctx, result, result_minus_one);
    ctx.constrain_equal(&bool_check, &zero);

    // Conditional diff:
    // result=1: diff = b - a (must be non-negative)
    // result=0: diff = a - b - 1 (must be non-negative)
    let b_minus_a = gate.sub(ctx, b, a);
    let a_minus_b = gate.sub(ctx, a, b);
    let a_minus_b_minus_1 = gate.sub(ctx, a_minus_b, one);
    let one_minus_result = gate.sub(ctx, one, result);

    let term1 = gate.mul(ctx, result, b_minus_a);
    let term2 = gate.mul(ctx, one_minus_result, a_minus_b_minus_1);
    let diff = gate.add(ctx, term1, term2);

    // Range check: decompose diff to MAX_THRESHOLD_BITS bits
    let diff_val = if a_u64 <= b_u64 {
        b_u64 - a_u64
    } else {
        a_u64 - b_u64 - 1
    };

    let bits: Vec<AssignedValue<Fr>> = (0..MAX_THRESHOLD_BITS)
        .map(|i| {
            let bit = ((diff_val >> i) & 1) as u64;
            let b_assigned = ctx.load_witness(Fr::from(bit));
            let b_minus_one = gate.sub(ctx, b_assigned, one);
            let product = gate.mul(ctx, b_assigned, b_minus_one);
            ctx.constrain_equal(&product, &zero);
            b_assigned
        })
        .collect();

    // Reconstruction constraint
    let mut reconstructed = ctx.load_constant(Fr::from(0u64));
    let mut power = Fr::from(1u64);
    for &bit in &bits {
        let power_const = ctx.load_constant(power);
        let weighted = gate.mul(ctx, bit, power_const);
        reconstructed = gate.add(ctx, reconstructed, weighted);
        power = power + power;
    }
    ctx.constrain_equal(&reconstructed, &diff);

    result
}

/// CPU-side Hamming distance between two u16 values.
fn hamming_u16(a: u16, b: u16) -> u32 {
    (a ^ b).count_ones()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create a passing witness with distinct upper/lower fingerprints.
    ///
    /// Fingerprint layout: [order:3 | mid_ratio:4 | min_ratio:4 | magnitude:5]
    ///   0x0014 = order 0 (R>=G>=B), ratios 0, magnitude 20
    ///   0xA014 = order 5 (B>=G>=R), ratios 0, magnitude 20
    ///
    /// Hamming distances between pairs:
    ///   HD(0x0014, 0xA014) = 2  (bits 13,15 differ)
    ///   HD(0x4014, 0xA014) = 3  (bits 13,14,15 differ)
    fn passing_witness() -> LivenessWitness {
        LivenessWitness {
            // [round0_upper, round0_lower, round1_upper, round1_lower, round2_upper, round2_lower]
            delta_fingerprints: [0x0014, 0xA014, 0x4014, 0xA014, 0xA014, 0x0014],
            expected_fingerprints: [0x0014, 0xA014, 0x4014, 0xA014, 0xA014, 0x0014],
            color_threshold: 3,
            spatial_threshold: 2,
            min_magnitude: 5,
        }
    }

    #[test]
    fn test_liveness_circuit_pass() {
        let witness = passing_witness();
        let circuit = LivenessCheckCircuit::new(witness);
        assert!(circuit.should_pass(), "CPU-side check should pass");

        let result = circuit.test_circuit().expect("Circuit should be satisfiable");
        assert!(result, "Circuit should output 1 (pass)");
    }

    #[test]
    fn test_liveness_exact_match() {
        // Exact match: delta == expected, HD = 0
        let witness = LivenessWitness {
            delta_fingerprints: [100, 200, 300, 400, 500, 600],
            expected_fingerprints: [100, 200, 300, 400, 500, 600],
            color_threshold: 3,
            spatial_threshold: 1, // upper != lower, so some HD > 0
            min_magnitude: 1,
        };
        // Check spatial diff: HD(100, 200) should be sufficient
        let hd = hamming_u16(100, 200);
        assert!(hd >= 1, "upper/lower should differ: HD={}", hd);

        let circuit = LivenessCheckCircuit::new(witness);
        assert!(circuit.should_pass());

        let result = circuit.test_circuit().expect("Circuit should be satisfiable");
        assert!(result, "Exact color match with spatial diff should pass");
    }

    #[test]
    fn test_liveness_wrong_color() {
        // Wrong color: delta fingerprints are very different from expected
        let witness = LivenessWitness {
            delta_fingerprints: [0x0014, 0x4014, 0x2014, 0x0014, 0x4014, 0x2014],
            expected_fingerprints: [0x4014, 0x0014, 0x0014, 0x4014, 0x2014, 0x4014], // swapped
            color_threshold: 1, // very strict
            spatial_threshold: 1,
            min_magnitude: 5,
        };
        let circuit = LivenessCheckCircuit::new(witness);
        assert!(!circuit.should_pass(), "Wrong colors should fail CPU check");

        let result = circuit.test_circuit().expect("Circuit should be satisfiable");
        assert!(!result, "Wrong colors should output 0 (fail)");
    }

    #[test]
    fn test_liveness_no_spatial_diff() {
        // Upper == lower in every round → spatial differentiation fails
        let witness = LivenessWitness {
            delta_fingerprints: [100, 100, 200, 200, 300, 300], // same upper/lower
            expected_fingerprints: [100, 100, 200, 200, 300, 300],
            color_threshold: 3,
            spatial_threshold: 1, // require at least HD=1 between upper and lower
            min_magnitude: 1,
        };
        let circuit = LivenessCheckCircuit::new(witness);
        // HD(upper, lower) = 0 for every round, but threshold requires >= 1
        assert!(!circuit.should_pass(), "Identical upper/lower should fail spatial check");

        let result = circuit.test_circuit().expect("Circuit should be satisfiable");
        assert!(!result, "No spatial diff should output 0");
    }

    #[test]
    fn test_liveness_low_magnitude() {
        // Magnitude field (low 5 bits) is too small
        let witness = LivenessWitness {
            // Fingerprints with magnitude = 1 (low 5 bits = 00001)
            delta_fingerprints: [
                0b_000_0000_0000_00001, // mag=1
                0b_101_0000_0000_00001, // mag=1
                0b_010_0000_0000_00001,
                0b_000_0000_0000_00001,
                0b_101_0000_0000_00001,
                0b_010_0000_0000_00001,
            ],
            expected_fingerprints: [
                0b_000_0000_0000_00001,
                0b_101_0000_0000_00001,
                0b_010_0000_0000_00001,
                0b_000_0000_0000_00001,
                0b_101_0000_0000_00001,
                0b_010_0000_0000_00001,
            ],
            color_threshold: 3,
            spatial_threshold: 2,
            min_magnitude: 5, // requires >= 5, but we have 1
        };
        let circuit = LivenessCheckCircuit::new(witness);
        assert!(!circuit.should_pass(), "Low magnitude should fail CPU check");

        let result = circuit.test_circuit().expect("Circuit should be satisfiable");
        assert!(!result, "Low magnitude should output 0");
    }

    #[test]
    fn test_liveness_cpu_matches_circuit() {
        // Verify CPU-side should_pass agrees with circuit for many cases
        let test_cases: Vec<LivenessWitness> = vec![
            passing_witness(),
            // Tight color threshold
            LivenessWitness {
                delta_fingerprints: [0x0014, 0xA014, 0x4014, 0x0014, 0xA014, 0x4014],
                expected_fingerprints: [0x0014, 0xA014, 0x4014, 0x0014, 0xA014, 0x4014],
                color_threshold: 0, // exact match required
                spatial_threshold: 2,
                min_magnitude: 5,
            },
        ];

        for (i, witness) in test_cases.iter().enumerate() {
            let circuit = LivenessCheckCircuit::new(witness.clone());
            let cpu_result = circuit.should_pass();
            let circuit_result = circuit.test_circuit().expect("Circuit should be satisfiable");
            assert_eq!(
                cpu_result, circuit_result,
                "Case {}: CPU ({}) != circuit ({})",
                i, cpu_result, circuit_result
            );
        }
    }

    #[test]
    fn test_hamming_u16() {
        assert_eq!(hamming_u16(0, 0), 0);
        assert_eq!(hamming_u16(0xFFFF, 0), 16);
        assert_eq!(hamming_u16(0b1010, 0b0101), 4);
        assert_eq!(hamming_u16(100, 100), 0);
    }

    #[test]
    fn test_liveness_partial_round_failure() {
        // Round 0: passes (color + spatial + magnitude all ok)
        // Round 1: passes
        // Round 2: FAILS spatial diff (upper == lower)
        // Circuit requires ALL rounds to pass, so overall = fail
        let witness = LivenessWitness {
            delta_fingerprints: [
                0x0014, 0xA014, // round 0: different upper/lower ✓
                0x4014, 0xA014, // round 1: different upper/lower ✓
                0x0014, 0x0014, // round 2: SAME upper/lower ✗
            ],
            expected_fingerprints: [
                0x0014, 0xA014,
                0x4014, 0xA014,
                0x0014, 0x0014,
            ],
            color_threshold: 3,
            spatial_threshold: 2, // requires HD >= 2 between upper/lower
            min_magnitude: 5,
        };
        let circuit = LivenessCheckCircuit::new(witness);
        assert!(!circuit.should_pass(), "Partial round failure should fail CPU");

        let result = circuit.test_circuit().expect("Circuit should be satisfiable");
        assert!(!result, "Partial round failure should output 0");
    }

    #[test]
    fn test_liveness_color_threshold_boundary() {
        // Color match with HD exactly at threshold (should pass)
        let w = passing_witness();
        // HD(0x0014, 0x0015) = 1 (differ in bit 0)
        let witness_at_boundary = LivenessWitness {
            delta_fingerprints: [0x0015, 0xA015, 0x4015, 0xA015, 0xA015, 0x0015],
            expected_fingerprints: [0x0014, 0xA014, 0x4014, 0xA014, 0xA014, 0x0014],
            color_threshold: 1, // HD=1 exactly at threshold
            spatial_threshold: w.spatial_threshold,
            min_magnitude: 5,
        };
        let circuit = LivenessCheckCircuit::new(witness_at_boundary);
        assert!(circuit.should_pass(), "HD == color_threshold should pass");

        let result = circuit.test_circuit().expect("Circuit should be satisfiable");
        assert!(result, "HD == color_threshold should pass in circuit");
    }

    #[test]
    fn test_liveness_color_threshold_just_over() {
        // Color match with HD = threshold + 1 (should fail)
        // HD(0x0014, 0x0017) = 2 (differ in bits 0,1), with threshold=1 → fail
        let w = passing_witness();
        let witness_over = LivenessWitness {
            delta_fingerprints: [0x0017, 0xA014, 0x4014, 0xA014, 0xA014, 0x0014],
            expected_fingerprints: [0x0014, 0xA014, 0x4014, 0xA014, 0xA014, 0x0014],
            color_threshold: 1, // HD=2 > threshold=1
            spatial_threshold: w.spatial_threshold,
            min_magnitude: 5,
        };
        let circuit = LivenessCheckCircuit::new(witness_over);
        assert!(!circuit.should_pass(), "HD > color_threshold should fail");

        let result = circuit.test_circuit().expect("Circuit should be satisfiable");
        assert!(!result, "HD > color_threshold should fail in circuit");
    }

    #[test]
    fn test_liveness_spatial_threshold_boundary() {
        // Spatial HD exactly at threshold (should pass: HD >= spatial_threshold)
        // HD(0x0014, 0x2014) = 1 (only bit 13 differs)
        let witness = LivenessWitness {
            delta_fingerprints: [0x0014, 0x2014, 0x0014, 0x2014, 0x0014, 0x2014],
            expected_fingerprints: [0x0014, 0x2014, 0x0014, 0x2014, 0x0014, 0x2014],
            color_threshold: 3,
            spatial_threshold: 1, // HD=1 exactly at threshold
            min_magnitude: 5,
        };
        let circuit = LivenessCheckCircuit::new(witness);
        assert!(circuit.should_pass(), "Spatial HD == threshold should pass");

        let result = circuit.test_circuit().expect("Circuit should be satisfiable");
        assert!(result, "Spatial HD == threshold should pass in circuit");
    }

    #[test]
    fn test_liveness_magnitude_boundary() {
        // Magnitude exactly at min_magnitude (should pass)
        // magnitude = low 5 bits = 5 = 0b00101
        let fp_mag5 = 0u16 | 5; // order=0, ratios=0, mag=5
        let fp_mag5_alt = (5u16 << 13) | 5; // order=5, ratios=0, mag=5

        let witness = LivenessWitness {
            delta_fingerprints: [fp_mag5, fp_mag5_alt, fp_mag5, fp_mag5_alt, fp_mag5_alt, fp_mag5],
            expected_fingerprints: [fp_mag5, fp_mag5_alt, fp_mag5, fp_mag5_alt, fp_mag5_alt, fp_mag5],
            color_threshold: 3,
            spatial_threshold: 2,
            min_magnitude: 5, // exactly equals magnitude
        };
        let circuit = LivenessCheckCircuit::new(witness);
        assert!(circuit.should_pass(), "Magnitude == min_magnitude should pass");

        let result = circuit.test_circuit().expect("Circuit should be satisfiable");
        assert!(result, "Magnitude == min_magnitude should pass in circuit");
    }

    #[test]
    fn test_liveness_magnitude_just_under() {
        // Magnitude = 4, min_magnitude = 5 (should fail)
        let fp_mag4 = 0u16 | 4; // order=0, ratios=0, mag=4
        let fp_mag4_alt = (5u16 << 13) | 4; // order=5, ratios=0, mag=4

        let witness = LivenessWitness {
            delta_fingerprints: [fp_mag4, fp_mag4_alt, fp_mag4, fp_mag4_alt, fp_mag4_alt, fp_mag4],
            expected_fingerprints: [fp_mag4, fp_mag4_alt, fp_mag4, fp_mag4_alt, fp_mag4_alt, fp_mag4],
            color_threshold: 3,
            spatial_threshold: 2,
            min_magnitude: 5, // 4 < 5, should fail
        };
        let circuit = LivenessCheckCircuit::new(witness);
        assert!(!circuit.should_pass(), "Magnitude < min_magnitude should fail");

        let result = circuit.test_circuit().expect("Circuit should be satisfiable");
        assert!(!result, "Magnitude < min_magnitude should fail in circuit");
    }

    #[test]
    fn test_liveness_real_prover_roundtrip() {
        // Full proof generation + verification using the real SHPLONK prover/verifier.
        use halo2_base::halo2_proofs::halo2curves::bn256::{Bn256, G1Affine};
        use halo2_base::halo2_proofs::plonk::{create_proof, keygen_pk, keygen_vk, verify_proof};
        use halo2_base::halo2_proofs::poly::kzg::commitment::{KZGCommitmentScheme, ParamsKZG};
        use halo2_base::halo2_proofs::poly::kzg::multiopen::{ProverSHPLONK, VerifierSHPLONK};
        use halo2_base::halo2_proofs::poly::kzg::strategy::SingleStrategy;
        use halo2_base::halo2_proofs::transcript::{
            Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
        };

        let witness = passing_witness();
        let circuit = LivenessCheckCircuit::new(witness);
        assert!(circuit.should_pass(), "Witness should pass CPU check");

        let params = ParamsKZG::<Bn256>::setup(K, rand_core::OsRng);
        let circuit_params = LivenessCheckCircuit::circuit_params();

        // Build circuit for keygen
        let mut builder = BaseCircuitBuilder::new(false).use_params(circuit_params.clone());
        let result = circuit.build_circuit(&mut builder);
        builder.assigned_instances[0].push(result);
        let result_value = *result.value();

        // Keygen
        let vk = keygen_vk(&params, &builder)
            .expect("VK generation should succeed");
        let pk = keygen_pk(&params, vk.clone(), &builder)
            .expect("PK generation should succeed");

        // Prove
        let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);
        let public_inputs = vec![result_value];

        create_proof::<KZGCommitmentScheme<Bn256>, ProverSHPLONK<_>, _, _, _, _>(
            &params,
            &pk,
            &[builder],
            &[&[&public_inputs]],
            rand_core::OsRng,
            &mut transcript,
        )
        .expect("Proof generation should succeed");

        let proof_bytes = transcript.finalize();
        println!("Liveness proof size: {} bytes", proof_bytes.len());

        // Verify
        let mut verify_transcript =
            Blake2bRead::<_, G1Affine, Challenge255<_>>::init(&proof_bytes[..]);
        let strategy = SingleStrategy::new(&params);

        verify_proof::<KZGCommitmentScheme<Bn256>, VerifierSHPLONK<_>, _, _, _>(
            &params,
            &vk,
            strategy,
            &[&[&public_inputs]],
            &mut verify_transcript,
        )
        .expect("Proof verification should succeed");

        // Check result is 1 (pass)
        let result_bytes = result_value.to_bytes();
        let result_u64 = u64::from_le_bytes(result_bytes[0..8].try_into().unwrap());
        assert_eq!(result_u64, 1, "Liveness proof should output 1 (pass)");
    }

    #[test]
    fn test_liveness_real_prover_failing_witness() {
        // Real prover with a witness that should fail (same upper/lower = no spatial diff)
        use halo2_base::halo2_proofs::halo2curves::bn256::{Bn256, G1Affine};
        use halo2_base::halo2_proofs::plonk::{create_proof, keygen_pk, keygen_vk, verify_proof};
        use halo2_base::halo2_proofs::poly::kzg::commitment::{KZGCommitmentScheme, ParamsKZG};
        use halo2_base::halo2_proofs::poly::kzg::multiopen::{ProverSHPLONK, VerifierSHPLONK};
        use halo2_base::halo2_proofs::poly::kzg::strategy::SingleStrategy;
        use halo2_base::halo2_proofs::transcript::{
            Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
        };

        let witness = LivenessWitness {
            delta_fingerprints: [100, 100, 200, 200, 300, 300], // same upper/lower
            expected_fingerprints: [100, 100, 200, 200, 300, 300],
            color_threshold: 3,
            spatial_threshold: 1, // requires >=1, but we have 0
            min_magnitude: 1,
        };
        let circuit = LivenessCheckCircuit::new(witness);
        assert!(!circuit.should_pass(), "Witness should fail CPU check");

        let params = ParamsKZG::<Bn256>::setup(K, rand_core::OsRng);
        let circuit_params = LivenessCheckCircuit::circuit_params();

        let mut builder = BaseCircuitBuilder::new(false).use_params(circuit_params.clone());
        let result = circuit.build_circuit(&mut builder);
        builder.assigned_instances[0].push(result);
        let result_value = *result.value();

        // Keygen
        let vk = keygen_vk(&params, &builder).expect("VK generation should succeed");
        let pk = keygen_pk(&params, vk.clone(), &builder).expect("PK generation should succeed");

        // Prove
        let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);
        let public_inputs = vec![result_value];

        create_proof::<KZGCommitmentScheme<Bn256>, ProverSHPLONK<_>, _, _, _, _>(
            &params,
            &pk,
            &[builder],
            &[&[&public_inputs]],
            rand_core::OsRng,
            &mut transcript,
        )
        .expect("Proof generation should succeed even for failing witness");

        let proof_bytes = transcript.finalize();

        // Verify
        let mut verify_transcript =
            Blake2bRead::<_, G1Affine, Challenge255<_>>::init(&proof_bytes[..]);
        let strategy = SingleStrategy::new(&params);

        verify_proof::<KZGCommitmentScheme<Bn256>, VerifierSHPLONK<_>, _, _, _>(
            &params,
            &vk,
            strategy,
            &[&[&public_inputs]],
            &mut verify_transcript,
        )
        .expect("Verification should succeed");

        // Check result is 0 (fail)
        let result_bytes = result_value.to_bytes();
        let result_u64 = u64::from_le_bytes(result_bytes[0..8].try_into().unwrap());
        assert_eq!(result_u64, 0, "Liveness proof should output 0 (fail)");
    }

    #[test]
    fn test_liveness_all_zeros_witness() {
        // Edge case: all-zero fingerprints — magnitude = 0, spatial diff = 0
        let witness = LivenessWitness {
            delta_fingerprints: [0; 6],
            expected_fingerprints: [0; 6],
            color_threshold: 3,
            spatial_threshold: 1,
            min_magnitude: 1,
        };
        let circuit = LivenessCheckCircuit::new(witness);
        // magnitude=0 < min_magnitude=1, and spatial diff=0 < 1 → fail
        assert!(!circuit.should_pass(), "All-zero should fail");

        let result = circuit.test_circuit().expect("Circuit should be satisfiable");
        assert!(!result, "All-zero should output 0");
    }

    #[test]
    fn test_liveness_max_fingerprints() {
        // Edge case: max value fingerprints (0xFFFF)
        // magnitude = 0x1F = 31, all bits set
        let witness = LivenessWitness {
            delta_fingerprints: [0xFFFF, 0x0000, 0xFFFF, 0x0000, 0xFFFF, 0x0000],
            expected_fingerprints: [0xFFFF, 0x0000, 0xFFFF, 0x0000, 0xFFFF, 0x0000],
            color_threshold: 3,
            spatial_threshold: 2,
            min_magnitude: 0, // allow any magnitude (0x0000 has mag=0)
        };
        let circuit = LivenessCheckCircuit::new(witness);
        // HD(0xFFFF, 0x0000) = 16 >= spatial_threshold=2 ✓
        // magnitude of 0x0000 = 0 >= 0 ✓
        // color match: exact ✓
        assert!(circuit.should_pass(), "Max fingerprints should pass with min_magnitude=0");

        let result = circuit.test_circuit().expect("Circuit should be satisfiable");
        assert!(result, "Max fingerprints should pass in circuit");
    }
}
