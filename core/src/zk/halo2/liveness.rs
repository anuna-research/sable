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

/// Number of fingerprints: 4 per round (TL, TR, BL, BR).
const NUM_FINGERPRINTS: usize = NUM_ROUNDS * 4;

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
    /// 12 delta fingerprints (private): [r0_tl, r0_tr, r0_bl, r0_br, r1_tl, ...]
    pub delta_fingerprints: [u16; NUM_FINGERPRINTS],
    /// 12 expected color fingerprints (public, derivable from HKDF pattern).
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
        // - Adjacent quadrants differ (spatial HD > 0)
        // - Magnitude = 20 (well above any reasonable min_magnitude)
        //
        // Per round: [TL, TR, BL, BR] with sufficient pairwise Hamming distance
        // between adjacent pairs (TL-TR, TL-BL, TR-BR, BL-BR).
        Self {
            delta_fingerprints: [
                0x0014, 0xA014, 0x6014, 0xC014, // round 0
                0x0014, 0xA014, 0x6014, 0xC014, // round 1
                0x0014, 0xA014, 0x6014, 0xC014, // round 2
            ],
            expected_fingerprints: [
                0x0014, 0xA014, 0x6014, 0xC014,
                0x0014, 0xA014, 0x6014, 0xC014,
                0x0014, 0xA014, 0x6014, 0xC014,
            ],
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

/// Pack all liveness challenge parameters into a single Fr field element (CPU-side).
///
/// Packing format (LSB first):
/// ```text
/// fp[0] | fp[1] | ... | fp[11] | color_t | spatial_t | min_mag
///  16b     16b    ...    16b       8b        8b          8b
/// ```
/// Total: 12×16 + 3×8 = 216 bits. Fits in the 254-bit BN254 scalar field.
///
/// The verifier independently computes this from the HKDF-derived parameters
/// and checks it matches the public input, ensuring the prover used correct values.
pub fn challenge_digest(witness: &LivenessWitness) -> Fr {
    // Compute 2^n in Fr using repeated doubling
    let pow2 = |n: usize| -> Fr {
        let mut s = Fr::from(1u64);
        for _ in 0..n { s = s + s; }
        s
    };

    let mut digest = Fr::from(0u64);
    for (i, &fp) in witness.expected_fingerprints.iter().enumerate() {
        digest = digest + Fr::from(fp as u64) * pow2(16 * i);
    }
    digest = digest + Fr::from(witness.color_threshold as u64) * pow2(192);
    digest = digest + Fr::from(witness.spatial_threshold as u64) * pow2(200);
    digest = digest + Fr::from(witness.min_magnitude as u64) * pow2(208);
    digest
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
            let base = r * 4;
            let tl = base;
            let tr = base + 1;
            let bl = base + 2;
            let br = base + 3;

            // Color match: HD(delta, expected) <= color_threshold for all 4 quadrants
            for idx in [tl, tr, bl, br] {
                let hd = hamming_u16(w.delta_fingerprints[idx], w.expected_fingerprints[idx]);
                if hd > w.color_threshold as u32 {
                    return false;
                }
            }

            // Spatial diff: HD >= spatial_threshold for 4 adjacent pairs
            // TL-TR, TL-BL, TR-BR, BL-BR
            let adjacent_pairs = [(tl, tr), (tl, bl), (tr, br), (bl, br)];
            for (a, b) in adjacent_pairs {
                let hd = hamming_u16(w.delta_fingerprints[a], w.delta_fingerprints[b]);
                if hd < w.spatial_threshold as u32 {
                    return false;
                }
            }

            // Magnitude: low 5 bits >= min_magnitude for all 4 quadrants
            for idx in [tl, tr, bl, br] {
                let mag = w.delta_fingerprints[idx] & 0x1F;
                if mag < w.min_magnitude as u16 {
                    return false;
                }
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
    /// Returns `(liveness_result, challenge_digest)`:
    /// - `liveness_result`: 1 = all checks pass, 0 = at least one fails
    /// - `challenge_digest`: packed field element of expected fingerprints + thresholds,
    ///   exposed as a public input so the verifier can check the prover used correct
    ///   HKDF-derived challenge parameters.
    pub fn build_circuit(&self, builder: &mut BaseCircuitBuilder<Fr>) -> (AssignedValue<Fr>, AssignedValue<Fr>) {
        let ctx = builder.main(0);
        let gate = GateChip::<Fr>::default();
        let w = &self.witness;

        let one = ctx.load_constant(Fr::from(1u64));

        // Start with result = 1 (all pass), AND with each check
        let mut result = ctx.load_constant(Fr::from(1u64));

        // Load threshold witnesses ONCE, reuse everywhere (checks + digest).
        let color_thresh_witness = ctx.load_witness(Fr::from(w.color_threshold as u64));
        let spatial_thresh_witness = ctx.load_witness(Fr::from(w.spatial_threshold as u64));
        let min_mag_witness = ctx.load_witness(Fr::from(w.min_magnitude as u64));

        // Collect all expected fingerprint witnesses for digest packing
        let mut expected_witnesses: Vec<AssignedValue<Fr>> = Vec::with_capacity(NUM_FINGERPRINTS);

        // Adjacent pair indices within a round (TL=0, TR=1, BL=2, BR=3):
        // TL-TR, TL-BL, TR-BR, BL-BR
        let adjacent_pairs: [(usize, usize); 4] = [(0, 1), (0, 2), (1, 3), (2, 3)];

        for r in 0..NUM_ROUNDS {
            let base = r * 4;

            // Load private delta and public expected fingerprints for all 4 quadrants
            let mut delta_vals = Vec::with_capacity(4);
            let mut delta_bits_all = Vec::with_capacity(4);
            let mut expected_bits_all = Vec::with_capacity(4);

            for q in 0..4 {
                let idx = base + q;
                let delta = ctx.load_witness(Fr::from(w.delta_fingerprints[idx] as u64));
                let expected = ctx.load_witness(Fr::from(w.expected_fingerprints[idx] as u64));
                expected_witnesses.push(expected);

                let delta_bits = decompose_u16(ctx, &gate, delta, w.delta_fingerprints[idx]);
                let expected_bits = decompose_u16(ctx, &gate, expected, w.expected_fingerprints[idx]);

                // ---- Color match check ----
                let xor_color = xor_bits(ctx, &gate, &delta_bits, &expected_bits);
                let hd_color = popcount(ctx, &gate, &xor_color);
                let color_ok = compare_le(ctx, &gate, hd_color, color_thresh_witness,
                    hamming_u16(w.delta_fingerprints[idx], w.expected_fingerprints[idx]) as u64,
                    w.color_threshold as u64);
                result = gate.mul(ctx, result, color_ok);

                // ---- Magnitude check ----
                let mag_val = sum_low_bits(ctx, &gate, &delta_bits, MAGNITUDE_BITS);
                let mag_ok = compare_le(ctx, &gate, min_mag_witness, mag_val,
                    w.min_magnitude as u64,
                    (w.delta_fingerprints[idx] & 0x1F) as u64);
                result = gate.mul(ctx, result, mag_ok);

                delta_vals.push(delta);
                delta_bits_all.push(delta_bits);
                expected_bits_all.push(expected_bits);
            }

            // ---- Spatial differentiation checks (4 adjacent pairs) ----
            for &(a, b) in &adjacent_pairs {
                let xor_spatial = xor_bits(ctx, &gate, &delta_bits_all[a], &delta_bits_all[b]);
                let hd_spatial = popcount(ctx, &gate, &xor_spatial);
                let spatial_ok = compare_le(ctx, &gate, spatial_thresh_witness, hd_spatial,
                    w.spatial_threshold as u64,
                    hamming_u16(w.delta_fingerprints[base + a], w.delta_fingerprints[base + b]) as u64);
                result = gate.mul(ctx, result, spatial_ok);
            }
        }

        // Constrain result to be boolean
        let result_minus_one = gate.sub(ctx, result, one);
        let bool_check = gate.mul(ctx, result, result_minus_one);
        let zero = ctx.load_constant(Fr::from(0u64));
        ctx.constrain_equal(&bool_check, &zero);

        // ---- Build challenge digest in-circuit ----
        // Pack: fp[0..12] at 16-bit offsets, then color_t, spatial_t, min_mag at 8-bit offsets.
        // digest = sum(fp[i] * 2^(16*i)) + color_t * 2^192 + spatial_t * 2^200 + min_mag * 2^208
        //
        // Uses the SAME witness values as the checks above.
        let mut digest = ctx.load_constant(Fr::from(0u64));

        // Compute 2^n in Fr using repeated doubling
        let pow2_fr = |n: usize| -> Fr {
            let mut s = Fr::from(1u64);
            for _ in 0..n { s = s + s; }
            s
        };

        // Add expected fingerprints (each at 16-bit boundaries)
        for (i, &fp_witness) in expected_witnesses.iter().enumerate() {
            let shift_const = ctx.load_constant(pow2_fr(16 * i));
            let term = gate.mul(ctx, fp_witness, shift_const);
            digest = gate.add(ctx, digest, term);
        }

        // Add thresholds
        let shift_192_const = ctx.load_constant(pow2_fr(192));
        let color_term = gate.mul(ctx, color_thresh_witness, shift_192_const);
        digest = gate.add(ctx, digest, color_term);

        let shift_200_const = ctx.load_constant(pow2_fr(200));
        let spatial_term = gate.mul(ctx, spatial_thresh_witness, shift_200_const);
        digest = gate.add(ctx, digest, spatial_term);

        let shift_208_const = ctx.load_constant(pow2_fr(208));
        let min_mag_term = gate.mul(ctx, min_mag_witness, shift_208_const);
        digest = gate.add(ctx, digest, min_mag_term);

        (result, digest)
    }

    /// Test the circuit using the mock prover.
    pub fn test_circuit(&self) -> Result<bool> {
        let mut builder = BaseCircuitBuilder::new(false).use_params(Self::circuit_params());
        let (result, digest) = self.build_circuit(&mut builder);

        // Make result and digest public instances
        builder.assigned_instances[0].push(result);
        builder.assigned_instances[0].push(digest);

        let result_value = *result.value();
        let digest_value = *digest.value();

        // Run mock prover
        let prover = MockProver::run(K, &builder, vec![vec![result_value, digest_value]])
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

    /// Helper: create a passing witness with distinct quadrant fingerprints.
    ///
    /// Fingerprint layout: [order:3 | mid_ratio:4 | min_ratio:4 | magnitude:5]
    ///   0x0014 = order 0 (R>=G>=B), ratios 0, magnitude 20
    ///   0xA014 = order 5 (B>=G>=R), ratios 0, magnitude 20
    ///   0x4014 = order 2 (G>=R>=B), ratios 0, magnitude 20
    ///   0xE014 = order 7→clamped=7 (actually order=7 is invalid, use 0x6014 order=3)
    ///
    /// Actually let's use:
    ///   0x0014 (TL) order=0, 0xA014 (TR) order=5, 0x4014 (BL) order=2, 0x6014 (BR) order=3
    ///   All have magnitude 20 and sufficient pairwise HD for spatial checks.
    fn passing_witness() -> LivenessWitness {
        // Per round: [0x0014, 0xA014, 0x6014, 0xC014]
        //   All adjacent pairs have HD = 2 ≥ spatial_threshold(2)
        //   All magnitudes = 0x14 = 20 ≥ min_magnitude(5)
        //   delta == expected → color HD = 0 ≤ color_threshold(3)
        LivenessWitness {
            delta_fingerprints: [
                0x0014, 0xA014, 0x6014, 0xC014, // round 0
                0x0014, 0xA014, 0x6014, 0xC014, // round 1
                0x0014, 0xA014, 0x6014, 0xC014, // round 2
            ],
            expected_fingerprints: [
                0x0014, 0xA014, 0x6014, 0xC014,
                0x0014, 0xA014, 0x6014, 0xC014,
                0x0014, 0xA014, 0x6014, 0xC014,
            ],
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
        // Need 4 distinct values per round so adjacent pairs have HD >= 1
        // Values chosen so that (v & 0x1F) >= 1 for all v (800 & 0x1F = 0, so use 801)
        let witness = LivenessWitness {
            delta_fingerprints: [101, 201, 301, 401, 501, 601, 701, 801, 101, 201, 301, 401],
            expected_fingerprints: [101, 201, 301, 401, 501, 601, 701, 801, 101, 201, 301, 401],
            color_threshold: 3,
            spatial_threshold: 1,
            min_magnitude: 1,
        };

        let circuit = LivenessCheckCircuit::new(witness);
        assert!(circuit.should_pass());

        let result = circuit.test_circuit().expect("Circuit should be satisfiable");
        assert!(result, "Exact color match with spatial diff should pass");
    }

    #[test]
    fn test_liveness_wrong_color() {
        // Wrong color: delta fingerprints are adjacent-swapped from expected.
        // HD(0x0014, 0xA014) = popcount(0xA000) = 2, which exceeds color_threshold=1.
        let witness = LivenessWitness {
            delta_fingerprints: [
                0x0014, 0xA014, 0x6014, 0xC014,
                0x0014, 0xA014, 0x6014, 0xC014,
                0x0014, 0xA014, 0x6014, 0xC014,
            ],
            expected_fingerprints: [
                0xA014, 0x0014, 0xC014, 0x6014, // adjacent-swapped
                0xA014, 0x0014, 0xC014, 0x6014,
                0xA014, 0x0014, 0xC014, 0x6014,
            ],
            color_threshold: 1, // very strict — HD=2 exceeds this
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
        // All quadrants identical in every round → spatial differentiation fails
        let witness = LivenessWitness {
            delta_fingerprints: [100, 100, 100, 100, 200, 200, 200, 200, 300, 300, 300, 300],
            expected_fingerprints: [100, 100, 100, 100, 200, 200, 200, 200, 300, 300, 300, 300],
            color_threshold: 3,
            spatial_threshold: 1, // require at least HD=1 between adjacent pairs
            min_magnitude: 1,
        };
        let circuit = LivenessCheckCircuit::new(witness);
        assert!(!circuit.should_pass(), "Identical quadrants should fail spatial check");

        let result = circuit.test_circuit().expect("Circuit should be satisfiable");
        assert!(!result, "No spatial diff should output 0");
    }

    #[test]
    fn test_liveness_low_magnitude() {
        // Magnitude field (low 5 bits) is too small
        let witness = LivenessWitness {
            delta_fingerprints: [
                0b_000_0000_0000_00001, 0b_101_0000_0000_00001, 0b_010_0000_0000_00001, 0b_110_0000_0000_00001,
                0b_000_0000_0000_00001, 0b_101_0000_0000_00001, 0b_010_0000_0000_00001, 0b_110_0000_0000_00001,
                0b_000_0000_0000_00001, 0b_101_0000_0000_00001, 0b_010_0000_0000_00001, 0b_110_0000_0000_00001,
            ],
            expected_fingerprints: [
                0b_000_0000_0000_00001, 0b_101_0000_0000_00001, 0b_010_0000_0000_00001, 0b_110_0000_0000_00001,
                0b_000_0000_0000_00001, 0b_101_0000_0000_00001, 0b_010_0000_0000_00001, 0b_110_0000_0000_00001,
                0b_000_0000_0000_00001, 0b_101_0000_0000_00001, 0b_010_0000_0000_00001, 0b_110_0000_0000_00001,
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
                delta_fingerprints: [
                    0x0014, 0xA014, 0x6014, 0xC014,
                    0x0014, 0xA014, 0x6014, 0xC014,
                    0x0014, 0xA014, 0x6014, 0xC014,
                ],
                expected_fingerprints: [
                    0x0014, 0xA014, 0x6014, 0xC014,
                    0x0014, 0xA014, 0x6014, 0xC014,
                    0x0014, 0xA014, 0x6014, 0xC014,
                ],
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
        // Round 2: FAILS spatial diff (all quadrants same)
        let witness = LivenessWitness {
            delta_fingerprints: [
                0x0014, 0xA014, 0x6014, 0xC014, // round 0: distinct quadrants ✓
                0x4014, 0xA014, 0x0014, 0xE014, // round 1: distinct quadrants ✓
                0x0014, 0x0014, 0x0014, 0x0014, // round 2: ALL SAME ✗
            ],
            expected_fingerprints: [
                0x0014, 0xA014, 0x6014, 0xC014,
                0x4014, 0xA014, 0x0014, 0xE014,
                0x0014, 0x0014, 0x0014, 0x0014,
            ],
            color_threshold: 3,
            spatial_threshold: 2,
            min_magnitude: 5,
        };
        let circuit = LivenessCheckCircuit::new(witness);
        assert!(!circuit.should_pass(), "Partial round failure should fail CPU");

        let result = circuit.test_circuit().expect("Circuit should be satisfiable");
        assert!(!result, "Partial round failure should output 0");
    }

    #[test]
    fn test_liveness_color_threshold_boundary() {
        // Color match with HD exactly at threshold (should pass).
        // Delta values differ from expected by exactly 1 bit (bit 0 flipped).
        let w = passing_witness();
        let witness_at_boundary = LivenessWitness {
            delta_fingerprints: [
                0x0015, 0xA015, 0x6015, 0xC015,
                0x0015, 0xA015, 0x6015, 0xC015,
                0x0015, 0xA015, 0x6015, 0xC015,
            ],
            expected_fingerprints: [
                0x0014, 0xA014, 0x6014, 0xC014,
                0x0014, 0xA014, 0x6014, 0xC014,
                0x0014, 0xA014, 0x6014, 0xC014,
            ],
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
        // Color match with HD = threshold + 1 (should fail).
        // HD(0x0017, 0x0014) = 2 (differ in bits 0,1), with threshold=1 → fail
        let w = passing_witness();
        let witness_over = LivenessWitness {
            delta_fingerprints: [
                0x0017, 0xA014, 0x6014, 0xC014, // round 0 TL has HD=2
                0x0014, 0xA014, 0x6014, 0xC014,
                0x0014, 0xA014, 0x6014, 0xC014,
            ],
            expected_fingerprints: [
                0x0014, 0xA014, 0x6014, 0xC014,
                0x0014, 0xA014, 0x6014, 0xC014,
                0x0014, 0xA014, 0x6014, 0xC014,
            ],
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
        // Use values where all adjacent pairs have HD=1:
        // 0x0014 vs 0x2014: HD=1 (bit 13 differs)
        // 0x0014 vs 0x4014: HD=1 (bit 14)
        // 0x2014 vs 0x6014: HD=1 (bit 14)
        // 0x4014 vs 0x6014: HD=1 (bit 13)
        let witness = LivenessWitness {
            delta_fingerprints: [
                0x0014, 0x2014, 0x4014, 0x6014,
                0x0014, 0x2014, 0x4014, 0x6014,
                0x0014, 0x2014, 0x4014, 0x6014,
            ],
            expected_fingerprints: [
                0x0014, 0x2014, 0x4014, 0x6014,
                0x0014, 0x2014, 0x4014, 0x6014,
                0x0014, 0x2014, 0x4014, 0x6014,
            ],
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
        // Orders chosen so all 4 adjacent pairs have HD ≥ 2:
        //   fp0=0x0005 (order 0), fp1=0xA005 (order 5), fp2=0x6005 (order 3), fp3=0xC005 (order 6)
        //   HD(0,1)=2, HD(0,2)=2, HD(1,3)=2, HD(2,3)=2
        let fp0 = 0x0005u16;             // order=0, mag=5
        let fp1 = 0xA005u16;             // order=5, mag=5
        let fp2 = 0x6005u16;             // order=3, mag=5
        let fp3 = 0xC005u16;             // order=6, mag=5

        let witness = LivenessWitness {
            delta_fingerprints: [fp0, fp1, fp2, fp3, fp0, fp1, fp2, fp3, fp0, fp1, fp2, fp3],
            expected_fingerprints: [fp0, fp1, fp2, fp3, fp0, fp1, fp2, fp3, fp0, fp1, fp2, fp3],
            color_threshold: 3,
            spatial_threshold: 2,
            min_magnitude: 5,
        };
        let circuit = LivenessCheckCircuit::new(witness);
        assert!(circuit.should_pass(), "Magnitude == min_magnitude should pass");

        let result = circuit.test_circuit().expect("Circuit should be satisfiable");
        assert!(result, "Magnitude == min_magnitude should pass in circuit");
    }

    #[test]
    fn test_liveness_magnitude_just_under() {
        // Magnitude = 4, min_magnitude = 5 (should fail)
        let fp0 = 0x0004u16;
        let fp1 = 0xA004u16;
        let fp2 = 0x6004u16;
        let fp3 = 0xC004u16;

        let witness = LivenessWitness {
            delta_fingerprints: [fp0, fp1, fp2, fp3, fp0, fp1, fp2, fp3, fp0, fp1, fp2, fp3],
            expected_fingerprints: [fp0, fp1, fp2, fp3, fp0, fp1, fp2, fp3, fp0, fp1, fp2, fp3],
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
        let circuit = LivenessCheckCircuit::new(witness.clone());
        assert!(circuit.should_pass(), "Witness should pass CPU check");

        let params = ParamsKZG::<Bn256>::setup(K, rand_core::OsRng);
        let circuit_params = LivenessCheckCircuit::circuit_params();

        // Build circuit for keygen
        let mut builder = BaseCircuitBuilder::new(false).use_params(circuit_params.clone());
        let (result, digest) = circuit.build_circuit(&mut builder);
        builder.assigned_instances[0].push(result);
        builder.assigned_instances[0].push(digest);
        let result_value = *result.value();
        let digest_value = *digest.value();

        // Verify digest matches CPU-side computation
        let expected_digest = challenge_digest(&witness);
        assert_eq!(digest_value, expected_digest, "In-circuit digest should match CPU-side");

        // Keygen
        let vk = keygen_vk(&params, &builder)
            .expect("VK generation should succeed");
        let pk = keygen_pk(&params, vk.clone(), &builder)
            .expect("PK generation should succeed");

        // Prove
        let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);
        let public_inputs = vec![result_value, digest_value];

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
        // Real prover with a witness that should fail (all quadrants same = no spatial diff)
        use halo2_base::halo2_proofs::halo2curves::bn256::{Bn256, G1Affine};
        use halo2_base::halo2_proofs::plonk::{create_proof, keygen_pk, keygen_vk, verify_proof};
        use halo2_base::halo2_proofs::poly::kzg::commitment::{KZGCommitmentScheme, ParamsKZG};
        use halo2_base::halo2_proofs::poly::kzg::multiopen::{ProverSHPLONK, VerifierSHPLONK};
        use halo2_base::halo2_proofs::poly::kzg::strategy::SingleStrategy;
        use halo2_base::halo2_proofs::transcript::{
            Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
        };

        let witness = LivenessWitness {
            delta_fingerprints: [100, 100, 100, 100, 200, 200, 200, 200, 300, 300, 300, 300],
            expected_fingerprints: [100, 100, 100, 100, 200, 200, 200, 200, 300, 300, 300, 300],
            color_threshold: 3,
            spatial_threshold: 1, // requires >=1, but we have 0
            min_magnitude: 1,
        };
        let circuit = LivenessCheckCircuit::new(witness);
        assert!(!circuit.should_pass(), "Witness should fail CPU check");

        let params = ParamsKZG::<Bn256>::setup(K, rand_core::OsRng);
        let circuit_params = LivenessCheckCircuit::circuit_params();

        let mut builder = BaseCircuitBuilder::new(false).use_params(circuit_params.clone());
        let (result, digest) = circuit.build_circuit(&mut builder);
        builder.assigned_instances[0].push(result);
        builder.assigned_instances[0].push(digest);
        let result_value = *result.value();
        let digest_value = *digest.value();

        // Keygen
        let vk = keygen_vk(&params, &builder).expect("VK generation should succeed");
        let pk = keygen_pk(&params, vk.clone(), &builder).expect("PK generation should succeed");

        // Prove
        let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);
        let public_inputs = vec![result_value, digest_value];

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
            delta_fingerprints: [0; 12],
            expected_fingerprints: [0; 12],
            color_threshold: 3,
            spatial_threshold: 1,
            min_magnitude: 1,
        };
        let circuit = LivenessCheckCircuit::new(witness);
        assert!(!circuit.should_pass(), "All-zero should fail");

        let result = circuit.test_circuit().expect("Circuit should be satisfiable");
        assert!(!result, "All-zero should output 0");
    }

    #[test]
    fn test_liveness_max_fingerprints() {
        // Edge case: extreme fingerprint values with 4 distinct quadrants per round
        // [0xFFFF, 0x0000, 0x5555, 0xAAAA] — all adjacent pairs have HD ≥ 2
        let witness = LivenessWitness {
            delta_fingerprints: [
                0xFFFF, 0x0000, 0x5555, 0xAAAA,
                0xFFFF, 0x0000, 0x5555, 0xAAAA,
                0xFFFF, 0x0000, 0x5555, 0xAAAA,
            ],
            expected_fingerprints: [
                0xFFFF, 0x0000, 0x5555, 0xAAAA,
                0xFFFF, 0x0000, 0x5555, 0xAAAA,
                0xFFFF, 0x0000, 0x5555, 0xAAAA,
            ],
            color_threshold: 3,
            spatial_threshold: 2,
            min_magnitude: 0,
        };
        let circuit = LivenessCheckCircuit::new(witness);
        assert!(circuit.should_pass(), "Max fingerprints should pass with min_magnitude=0");

        let result = circuit.test_circuit().expect("Circuit should be satisfiable");
        assert!(result, "Max fingerprints should pass in circuit");
    }

    #[test]
    fn test_challenge_digest_packing() {
        // Verify the CPU-side challenge_digest packing is correct.
        let witness = passing_witness();
        let digest = challenge_digest(&witness);

        // Manually compute expected value using Fr arithmetic
        let pow2 = |n: usize| -> Fr {
            let mut s = Fr::from(1u64);
            for _ in 0..n { s = s + s; }
            s
        };

        let mut expected = Fr::from(0u64);
        for (i, &fp) in witness.expected_fingerprints.iter().enumerate() {
            expected = expected + Fr::from(fp as u64) * pow2(16 * i);
        }
        expected = expected + Fr::from(witness.color_threshold as u64) * pow2(192);
        expected = expected + Fr::from(witness.spatial_threshold as u64) * pow2(200);
        expected = expected + Fr::from(witness.min_magnitude as u64) * pow2(208);

        assert_eq!(digest, expected, "challenge_digest should match manual packing");
    }

    #[test]
    fn test_challenge_digest_circuit_matches_cpu() {
        // Verify the in-circuit digest matches the CPU-side computation.
        let witness = passing_witness();
        let expected_digest = challenge_digest(&witness);

        let circuit = LivenessCheckCircuit::new(witness);
        let mut builder = BaseCircuitBuilder::new(false)
            .use_params(LivenessCheckCircuit::circuit_params());
        let (_result, digest) = circuit.build_circuit(&mut builder);

        assert_eq!(
            *digest.value(), expected_digest,
            "In-circuit digest should match CPU-side challenge_digest"
        );
    }
}
