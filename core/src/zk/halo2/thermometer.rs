//! # Thermometer (Unary) Encoding Prototype
//!
//! Prototype of the L=9 thermometer matcher proposed by the accuracy spike
//! (`bench/accuracy/`). The spike found that SABLE's shipped *binary* Hamming
//! over u8 (8 bits/dim) discards ordinal structure -- adjacent quantization
//! levels 127 and 128 differ in 8 bits -- roughly doubling EER versus the float
//! cosine baseline. A thermometer/unary encoding fixes this: a value at level
//! `k` is encoded as `k` ones followed by zeros, so the **Hamming distance
//! between two thermometer codes equals the L1 distance between their levels**.
//!
//! ## Why L=9 specifically
//!
//! A thermometer code with `L` levels needs `L-1` bits per dimension. Choosing
//! `L = 9` gives exactly **8 bits/dim -- the same width as the current u8
//! binary encoding**. So the byte-level Hamming circuit
//! ([`crate::zk::halo2::hamming`]) is reused *unchanged*: the XOR + popcount
//! work is bit-for-bit identical. The only possible added cost is enforcing
//! that each byte is a *valid* thermometer code (its set bits are contiguous
//! from the LSB), since only 9 of the 256 byte values are legal.
//!
//! ## Valid thermometer bytes (L=9)
//!
//! | level | bits       | byte |
//! |-------|------------|------|
//! | 0     | `00000000` | 0x00 |
//! | 1     | `00000001` | 0x01 |
//! | 2     | `00000011` | 0x03 |
//! | ...   | ...        | ...  |
//! | 8     | `11111111` | 0xFF |
//!
//! A byte `b` is a valid code iff `b & (b + 1) == 0` (set bits are a contiguous
//! run from bit 0). The level is then simply `b.count_ones()`.

use halo2_base::gates::circuit::builder::BaseCircuitBuilder;
use halo2_base::gates::circuit::BaseCircuitParams;
use halo2_base::gates::{GateChip, GateInstructions};
use halo2_base::halo2_proofs::dev::MockProver;
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use halo2_base::AssignedValue;
use halo2_base::Context;

use super::hamming::decompose_to_bits;
use crate::error::{Result, SableError};

/// Number of thermometer levels in this prototype.
pub const LEVELS: u8 = 9;
/// Bits per dimension = LEVELS - 1 (== 8, matching the u8 binary encoding).
pub const BITS_PER_DIM: usize = (LEVELS - 1) as usize;

// Circuit parameters: identical to the binary Hamming circuit so the cost
// comparison is apples-to-apples.
const K: u32 = 14;
const NUM_ADVICE: usize = 4;
const NUM_LOOKUP_ADVICE: usize = 1;
const NUM_FIXED: usize = 1;
const LOOKUP_BITS: usize = 13;

// ===========================================================================
// Encoding (out-of-circuit)
// ===========================================================================

/// Map a thermometer level (0..=8) to its byte code.
///
/// level `k` -> `k` low bits set, e.g. 3 -> 0b0000_0111 = 0x07.
#[inline]
pub fn level_to_byte(level: u8) -> u8 {
    debug_assert!(level <= BITS_PER_DIM as u8, "level out of range");
    (((1u16 << level) - 1) & 0xFF) as u8
}

/// Recover the level from a (valid) thermometer byte.
#[inline]
pub fn byte_to_level(byte: u8) -> u8 {
    byte.count_ones() as u8
}

/// Is `byte` a valid thermometer code (set bits contiguous from the LSB)?
#[inline]
pub fn is_valid_thermometer_byte(byte: u8) -> bool {
    (byte & byte.wrapping_add(1)) == 0
}

/// Quantize a single prescaled value in [-1, 1] to a thermometer level (0..=8).
///
/// Rounds to the nearest level (cf. the binary quantizer, which truncates).
#[inline]
pub fn value_to_level(value: f64) -> u8 {
    let u = ((value + 1.0) / 2.0).clamp(0.0, 1.0);
    (u * BITS_PER_DIM as f64).round() as u8
}

/// Encode a vector of prescaled values in [-1, 1] to thermometer bytes.
pub fn encode(values: &[f64]) -> Vec<u8> {
    values
        .iter()
        .map(|&v| level_to_byte(value_to_level(v)))
        .collect()
}

/// Stats-free tanh prescale: squash each value into (-1, 1) with `tanh`.
///
/// This is the zero-configuration default for the production thermometer
/// encoding: unlike [`prescale_zscore`] it needs no fitted per-dimension
/// calibration constants, so enrollment and verification are guaranteed to use
/// identical scaling without shipping any calibration artifact. The deployer can
/// switch to [`prescale_zscore`] when they have representative calibration stats.
pub fn prescale_tanh(values: &[f64]) -> Vec<f64> {
    values.iter().map(|&v| v.tanh()).collect()
}

/// Per-dimension z-score prescale (standardize then tanh-squash into (-1, 1)).
///
/// Mirrors the `zscore` prescale that performed best in the Python spike. The
/// per-dim `mean`/`std` are enrollment-time calibration constants; both the
/// enrolled template and the fresh capture must use the *same* stats.
pub fn prescale_zscore(values: &[f64], mean: &[f64], std: &[f64]) -> Vec<f64> {
    values
        .iter()
        .zip(mean.iter())
        .zip(std.iter())
        .map(|((&v, &mu), &sd)| ((v - mu) / (sd + 1e-9)).tanh())
        .collect()
}

/// L1 distance between two level vectors (the value thermometer-Hamming equals).
pub fn levels_l1(a: &[u8], b: &[u8]) -> u64 {
    assert_eq!(a.len(), b.len(), "level vectors must match");
    a.iter()
        .zip(b.iter())
        .map(|(&x, &y)| (x as i64 - y as i64).unsigned_abs())
        .sum()
}

// ===========================================================================
// Circuit
// ===========================================================================

/// Thermometer Hamming-distance circuit.
///
/// Reuses the same byte decomposition + XOR + popcount as
/// [`crate::zk::halo2::hamming::HammingDistanceCircuit`]; with
/// `enforce_validity` it additionally constrains every byte to be a legal
/// thermometer code (so the prover cannot fake an ordinal distance with a
/// non-unary byte).
pub struct ThermometerHammingCircuit {
    code_a: Vec<u8>,
    code_b: Vec<u8>,
    enforce_validity: bool,
}

impl ThermometerHammingCircuit {
    /// Create from two thermometer byte vectors.
    pub fn new(code_a: Vec<u8>, code_b: Vec<u8>, enforce_validity: bool) -> Self {
        assert_eq!(code_a.len(), code_b.len(), "codes must have equal length");
        Self { code_a, code_b, enforce_validity }
    }

    /// Expected distance (out of circuit) = Hamming over bytes = L1 over levels.
    pub fn expected_distance(&self) -> u64 {
        super::hamming::hamming_distance(&self.code_a, &self.code_b)
    }

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

    fn build_circuit(&self, builder: &mut BaseCircuitBuilder<Fr>) -> AssignedValue<Fr> {
        let ctx = builder.main(0);
        let gate = GateChip::<Fr>::default();
        let mut total = ctx.load_constant(Fr::from(0u64));

        for (&a, &b) in self.code_a.iter().zip(self.code_b.iter()) {
            let a_val = ctx.load_witness(Fr::from(a as u64));
            let b_val = ctx.load_witness(Fr::from(b as u64));

            // Decompose each operand ONCE; reuse the bits for both XOR and the
            // validity check (same dominant cost as the binary circuit).
            let a_bits = decompose_to_bits(ctx, &gate, a_val, BITS_PER_DIM);
            let b_bits = decompose_to_bits(ctx, &gate, b_val, BITS_PER_DIM);

            if self.enforce_validity {
                enforce_thermometer(ctx, &gate, &a_bits);
                enforce_thermometer(ctx, &gate, &b_bits);
            }

            // XOR each bit pair and accumulate (a ^ b = a + b - 2ab).
            for (&abit, &bbit) in a_bits.iter().zip(b_bits.iter()) {
                let sum = gate.add(ctx, abit, bbit);
                let prod = gate.mul(ctx, abit, bbit);
                let two_prod = gate.add(ctx, prod, prod);
                let xor = gate.sub(ctx, sum, two_prod);
                total = gate.add(ctx, total, xor);
            }
        }
        total
    }

    /// Run the mock prover and return the computed distance.
    pub fn test_circuit(&self) -> Result<u64> {
        let mut builder = BaseCircuitBuilder::new(false).use_params(Self::circuit_params());
        let distance = self.build_circuit(&mut builder);
        builder.assigned_instances[0].push(distance);
        let distance_value = *distance.value();

        let prover = MockProver::run(K, &builder, vec![vec![distance_value]])
            .map_err(|e| SableError::ProofGeneration(format!("Mock prover failed: {:?}", e)))?;
        prover
            .verify()
            .map_err(|e| SableError::ProofVerification(format!("Circuit verification failed: {:?}", e)))?;

        let bytes = distance_value.to_bytes();
        Ok(u64::from_le_bytes(bytes[0..8].try_into().unwrap()))
    }
}

/// Constrain `bits` (LSB-first) to be a valid thermometer code: the set bits
/// must be contiguous from bit 0, i.e. bits are non-increasing
/// (`bits[i+1] <= bits[i]`). For booleans that is `bits[i+1] * (1 - bits[i]) = 0`.
pub(crate) fn enforce_thermometer(ctx: &mut Context<Fr>, gate: &GateChip<Fr>, bits: &[AssignedValue<Fr>]) {
    for pair in bits.windows(2) {
        let lo = pair[0]; // bits[i]
        let hi = pair[1]; // bits[i+1]
        let one = ctx.load_constant(Fr::from(1u64));
        let one_minus_lo = gate.sub(ctx, one, lo);
        let prod = gate.mul(ctx, hi, one_minus_lo);
        let zero = ctx.load_constant(Fr::from(0u64));
        ctx.constrain_equal(&prod, &zero);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_level_to_byte_mapping() {
        assert_eq!(level_to_byte(0), 0x00);
        assert_eq!(level_to_byte(1), 0x01);
        assert_eq!(level_to_byte(2), 0x03);
        assert_eq!(level_to_byte(3), 0x07);
        assert_eq!(level_to_byte(8), 0xFF);
        // round-trips
        for k in 0..=8u8 {
            assert_eq!(byte_to_level(level_to_byte(k)), k);
        }
    }

    #[test]
    fn test_valid_byte_detection() {
        for k in 0..=8u8 {
            assert!(is_valid_thermometer_byte(level_to_byte(k)));
        }
        // non-unary bytes are invalid
        assert!(!is_valid_thermometer_byte(0x0A)); // 0000_1010
        assert!(!is_valid_thermometer_byte(0xF0)); // 1111_0000
        assert!(!is_valid_thermometer_byte(0x05)); // 0000_0101
    }

    #[test]
    fn test_value_to_level_boundaries() {
        assert_eq!(value_to_level(-1.0), 0);
        assert_eq!(value_to_level(1.0), 8);
        assert_eq!(value_to_level(0.0), 4); // midpoint -> middle level
        assert_eq!(value_to_level(-2.0), 0); // clamps
        assert_eq!(value_to_level(2.0), 8); // clamps
    }

    #[test]
    fn test_thermo_hamming_equals_l1() {
        // For valid thermometer codes, byte Hamming distance == level L1.
        let vals_a = [-1.0, -0.5, 0.0, 0.5, 1.0, -0.25, 0.75, 0.1];
        let vals_b = [1.0, 0.5, 0.0, -0.5, -1.0, 0.25, -0.75, -0.1];
        let code_a = encode(&vals_a);
        let code_b = encode(&vals_b);
        let levels_a: Vec<u8> = code_a.iter().map(|&b| byte_to_level(b)).collect();
        let levels_b: Vec<u8> = code_b.iter().map(|&b| byte_to_level(b)).collect();

        let ham = super::super::hamming::hamming_distance(&code_a, &code_b);
        let l1 = levels_l1(&levels_a, &levels_b);
        assert_eq!(ham, l1, "thermometer Hamming must equal level L1");
    }

    #[test]
    fn test_circuit_distance_matches_l1() {
        let a = encode(&[-1.0, 0.0, 1.0, 0.5]);
        let b = encode(&[1.0, 0.0, -1.0, 0.25]);
        let expected = levels_l1(
            &a.iter().map(|&x| byte_to_level(x)).collect::<Vec<_>>(),
            &b.iter().map(|&x| byte_to_level(x)).collect::<Vec<_>>(),
        );
        let circuit = ThermometerHammingCircuit::new(a, b, true);
        let got = circuit.test_circuit().expect("valid thermometer circuit");
        assert_eq!(got, expected);
    }

    #[test]
    fn test_circuit_identical_is_zero() {
        let a = encode(&[-1.0, -0.3, 0.2, 0.9]);
        let circuit = ThermometerHammingCircuit::new(a.clone(), a, true);
        assert_eq!(circuit.test_circuit().unwrap(), 0);
    }

    #[test]
    fn test_validity_constraint_rejects_invalid_code() {
        // 0x0A is not a valid thermometer code; with enforcement the circuit
        // must reject it.
        let circuit = ThermometerHammingCircuit::new(vec![0x0A], vec![0x00], true);
        assert!(
            circuit.test_circuit().is_err(),
            "invalid thermometer byte must fail the validity constraint"
        );
        // Without enforcement the same bytes pass (cost-comparison baseline).
        let circuit_no_check = ThermometerHammingCircuit::new(vec![0x0A], vec![0x00], false);
        assert!(circuit_no_check.test_circuit().is_ok());
    }

    /// Advice-cell cost: binary Hamming vs thermometer (with/without validity),
    /// built on the identical circuit params. Run with:
    ///   cargo test --features halo2 -p sable-core --lib \
    ///       zk::halo2::thermometer::tests::measure -- --nocapture
    #[test]
    fn measure_advice_cell_cost() {
        use super::super::hamming::HammingDistanceCircuit;

        let n = 128usize; // cells scale linearly; ratio is width-independent
        let prod_dim = 1024usize;

        // deterministic, valid thermometer inputs for the thermo circuits
        let vals_a: Vec<f64> = (0..n).map(|i| (i as f64 / n as f64) * 2.0 - 1.0).collect();
        let vals_b: Vec<f64> = (0..n).map(|i| 1.0 - (i as f64 / n as f64) * 2.0).collect();
        let code_a = encode(&vals_a);
        let code_b = encode(&vals_b);
        // arbitrary bytes for the binary baseline (any u8 is legal there)
        let bin_a: Vec<u8> = (0..n).map(|i| (i * 7 % 256) as u8).collect();
        let bin_b: Vec<u8> = (0..n).map(|i| (i * 13 % 256) as u8).collect();

        let count = |build: &dyn Fn(&mut BaseCircuitBuilder<Fr>)| -> usize {
            let mut b =
                BaseCircuitBuilder::<Fr>::new(false).use_params(ThermometerHammingCircuit::circuit_params());
            build(&mut b);
            b.statistics().gate.total_advice_per_phase.iter().sum()
        };

        let binary = count(&|b| {
            HammingDistanceCircuit::new(bin_a.clone(), bin_b.clone()).build_circuit(b);
        });
        let thermo_novalid = count(&|b| {
            ThermometerHammingCircuit::new(code_a.clone(), code_b.clone(), false).build_circuit(b);
        });
        let thermo_valid = count(&|b| {
            ThermometerHammingCircuit::new(code_a.clone(), code_b.clone(), true).build_circuit(b);
        });

        let per = |c: usize| c as f64 / n as f64;
        let pct = |c: usize| (c as f64 / binary as f64 - 1.0) * 100.0;
        println!("\n=== Advice-cell cost (n={n} dims, {BITS_PER_DIM} bits/dim) ===");
        println!("binary Hamming (shipped) : {binary:>7} cells  ({:.1}/dim)", per(binary));
        println!("thermo, no validity      : {thermo_novalid:>7} cells  ({:.1}/dim)  {:+.1}% vs binary",
                 per(thermo_novalid), pct(thermo_novalid));
        println!("thermo, +validity        : {thermo_valid:>7} cells  ({:.1}/dim)  {:+.1}% vs binary",
                 per(thermo_valid), pct(thermo_valid));
        println!("extrapolated to {prod_dim} dims:");
        println!("  binary           ~{:>8} cells", binary / n * prod_dim);
        println!("  thermo +validity ~{:>8} cells", thermo_valid / n * prod_dim);
        println!("k=14 capacity = {} rows x {NUM_ADVICE} advice = {} cells\n",
                 1 << K, (1usize << K) * NUM_ADVICE);

        // Core matching cost must be identical (same decompose+XOR+popcount).
        assert_eq!(thermo_novalid, binary,
                   "thermometer without validity must match binary cell-for-cell");
    }

    #[test]
    fn test_prescale_zscore_centers() {
        let vals = [2.0, 4.0, 6.0];
        let mean = [4.0, 4.0, 4.0];
        let std = [2.0, 2.0, 2.0];
        let out = prescale_zscore(&vals, &mean, &std);
        assert!(out[1].abs() < 1e-6); // centered value -> tanh(0) = 0
        assert!(out[0] < 0.0 && out[2] > 0.0);
    }
}
