//! # Liveness Check Circuit
//!
//! ZK circuit that proves spatial flash liveness properties without revealing
//! facial reflectance data. Implements `docs/specs/SPEC-006-geometric-liveness.md`
//! (0.2.0): CON-094 (challenge digest) and CON-095 (liveness witness).
//!
//! ## What is proven
//!
//! For each of 3 flash rounds, the circuit proves:
//!
//! 1. **Colour match** (0.1.0): the four quadrant delta fingerprints are within
//!    `color_threshold` Hamming distance of the expected HKDF-derived colours.
//! 2. **Spatial diff** (0.1.0): adjacent quadrant deltas differ by at least
//!    `spatial_threshold`.
//! 3. **Magnitude** (0.1.0): every quadrant response is above `min_magnitude`.
//! 4. **Coverage floor** (REQ-120): at least `min_coverage` patches responded.
//! 5. **Convexity floor** (REQ-121): the photometric convexity score is at
//!    least `min_convexity`.
//! 6. **Corneal agreement** (REQ-122, when `corneal_enabled`): each eye's glint
//!    fingerprint agrees with the round's expected composite by *field
//!    semantics* — categorical `order` equal, ordinals within tolerance. Never
//!    Hamming (REQ-123, BUG-001).
//!
//! Checks 4–6 are switched on by their public thresholds. A threshold of zero
//! (or `corneal_enabled = 0`) is a check that does not run, and because the
//! thresholds are in the digest the verifier can see which checks were live.
//! No default threshold enters the relation (ADR-010).
//!
//! ## Challenge digest (CON-094)
//!
//! Every public parameter is hashed with Poseidon into one field element that
//! the verifier recomputes from what it issued:
//!
//! ```text
//! limb0 = Σ expected_fp[i] · 2^(16 i)                                    192 bits
//! limb1 = color_t ‖ spatial_t ‖ min_mag ‖ min_coverage ‖ corneal_enabled ‖
//!         ratio_tol ‖ mag_tol ‖ min_convexity ‖ expected_glint[0..3]      120 bits
//! limb2 = SHA-256(c_nonce ‖ s_nonce)[0..16]                               128 bits
//! limb3 = SHA-256(c_nonce ‖ s_nonce)[16..32]                              128 bits
//! digest = Poseidon(limb0, limb1, limb2, limb3)
//! ```
//!
//! Packing several fields into one limb is sound only because every field is
//! range-constrained to its slot width **in circuit** before use (REQ-124).
//! Without that, `color_t + 256` and `spatial_t − 1` pack to the same limb as
//! `(color_t, spatial_t)` while the checks run against the looser pair — the
//! defect recorded as BUG-002 against the 0.1.0 packing.
//!
//! ## Security Properties
//!
//! - **Zero-Knowledge**: delta fingerprints, convexity scores, coverage counts
//!   and glint fingerprints stay private.
//! - **Binding**: the public digest commits to every threshold, every expected
//!   value, and the challenge the pattern was derived from (REQ-119).
//! - **Completeness**: a real 3D face under the correct flash passes.
//!
//! What the circuit does **not** do: it does not make prover-supplied witnesses
//! honest. A compromised client that synthesises a consistent response still
//! proves. The physics cues raise the cost of that synthesis; only capture
//! attestation closes it.

use halo2_base::gates::circuit::builder::BaseCircuitBuilder;
use halo2_base::gates::circuit::BaseCircuitParams;
use halo2_base::gates::GateChip;
use halo2_base::gates::GateInstructions;
use halo2_base::halo2_proofs::dev::MockProver;
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use halo2_base::AssignedValue;
use halo2_base::Context;
use halo2_base::QuantumCell;
use sha2::{Digest, Sha256};

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
pub const NUM_ROUNDS: usize = 3;

/// Number of fingerprints: 4 per round (TL, TR, BL, BR).
pub const NUM_FINGERPRINTS: usize = NUM_ROUNDS * 4;

/// Eyes per round for the corneal check.
pub const NUM_EYES: usize = 2;

/// Glint fingerprints: one per eye per round, indexed `round * NUM_EYES + eye`.
pub const NUM_GLINTS: usize = NUM_ROUNDS * NUM_EYES;

/// Largest patch count the photometric extractor can produce (8×8 grid).
pub const MAX_PATCHES: u8 = 64;

/// Number of bits in a fingerprint.
const FINGERPRINT_BITS: usize = 16;

/// Delta Fingerprint field layout: `[order:3 | mid_ratio:4 | min_ratio:4 | magnitude:5]`.
const MAGNITUDE_BITS: usize = 5;
const MIN_RATIO_LO: usize = 5;
const RATIO_BITS: usize = 4;
const MID_RATIO_LO: usize = 9;
const ORDER_LO: usize = 13;
const ORDER_BITS: usize = 3;

/// Declared widths of the public parameters (CON-095).
const THRESHOLD_BITS: usize = 8;
const COVERAGE_BITS: usize = 7;
const RATIO_TOL_BITS: usize = 4;
const MAG_TOL_BITS: usize = 5;
const CONVEXITY_BITS: usize = 16;

/// Bit offsets inside digest limb 1 (CON-094).
const L1_COLOR_T: usize = 0;
const L1_SPATIAL_T: usize = 8;
const L1_MIN_MAG: usize = 16;
const L1_MIN_COVERAGE: usize = 24;
const L1_CORNEAL_ENABLED: usize = 32;
const L1_RATIO_TOL: usize = 40;
const L1_MAG_TOL: usize = 48;
const L1_MIN_CONVEXITY: usize = 56;
const L1_EXPECTED_GLINT: [usize; NUM_ROUNDS] = [72, 88, 104];

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Private + public witness data for the liveness ZK circuit (CON-095).
///
/// `Default` is the *unset* witness: passing 0.1.0 fingerprints, every 0.2.0
/// threshold at zero and the corneal check disabled. It is what the demo
/// server uses until the extractors are wired in and the presentation-attack
/// study fixes the constants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LivenessWitness {
    /// 12 delta fingerprints (private): `[r0_tl, r0_tr, r0_bl, r0_br, r1_tl, ...]`.
    pub delta_fingerprints: [u16; NUM_FINGERPRINTS],
    /// 12 expected colour fingerprints (public, derivable from the HKDF pattern).
    pub expected_fingerprints: [u16; NUM_FINGERPRINTS],
    /// Maximum Hamming distance for colour match (public).
    pub color_threshold: u8,
    /// Minimum Hamming distance for spatial differentiation (public).
    pub spatial_threshold: u8,
    /// Minimum magnitude value (public, compared against the low 5 bits).
    pub min_magnitude: u8,

    /// Responding patch count per round (private, ≤ 64). REQ-118 / REQ-120.
    pub responding_patches: [u8; NUM_ROUNDS],
    /// Coverage floor (public, ≤ 64). Zero disables the check. REQ-120.
    pub min_coverage: u8,
    /// Convexity score per round, Q15 over [0, 2] (private). REQ-113 / REQ-121.
    pub convexity_scores: [u16; NUM_ROUNDS],
    /// Convexity floor (public). Zero disables the check. REQ-121.
    pub min_convexity: u16,

    /// Whether the corneal check is live (public). REQ-122.
    pub corneal_enabled: bool,
    /// Allowed ordinal difference on the two ratio fields (public, ≤ 15).
    pub glint_ratio_tolerance: u8,
    /// Allowed ordinal difference on the magnitude field (public, ≤ 31).
    pub glint_magnitude_tolerance: u8,
    /// Glint fingerprint per eye per round (private), `round * 2 + eye`.
    pub glint_fingerprints: [u16; NUM_GLINTS],
    /// Expected area-weighted composite fingerprint per round (public).
    pub expected_glints: [u16; NUM_ROUNDS],

    /// `SHA-256(c_nonce ‖ s_nonce)` (public). REQ-119.
    pub challenge_id: [u8; 32],
}

impl Default for LivenessWitness {
    fn default() -> Self {
        Self::dummy_pass()
    }
}

impl LivenessWitness {
    /// Create a witness that trivially passes all checks.
    ///
    /// Used when liveness is not requested — the circuit structure must remain
    /// identical for keygen, so we provide a passing witness. The 0.2.0 checks
    /// are unset (thresholds zero, corneal disabled).
    pub fn dummy_pass() -> Self {
        // Per round: [TL, TR, BL, BR] with pairwise Hamming distance 2 between
        // adjacent pairs, magnitude 20, delta == expected.
        let fps = [
            0x0014, 0xA014, 0x6014, 0xC014, // round 0
            0x0014, 0xA014, 0x6014, 0xC014, // round 1
            0x0014, 0xA014, 0x6014, 0xC014, // round 2
        ];
        Self {
            delta_fingerprints: fps,
            expected_fingerprints: fps,
            color_threshold: 3,
            spatial_threshold: 2,
            min_magnitude: 5,
            responding_patches: [0; NUM_ROUNDS],
            min_coverage: 0,
            convexity_scores: [0; NUM_ROUNDS],
            min_convexity: 0,
            corneal_enabled: false,
            glint_ratio_tolerance: 0,
            glint_magnitude_tolerance: 0,
            glint_fingerprints: [0; NUM_GLINTS],
            expected_glints: [0; NUM_ROUNDS],
            challenge_id: [0; 32],
        }
    }

    /// Recogniser for the CON-095 witness grammar (native half).
    ///
    /// The Rust types already bound most fields; this rejects what they cannot.
    /// The in-circuit half (`build_from_values`) enforces the same widths so a
    /// prover who skips this check gains nothing.
    pub fn recognise(&self) -> Result<()> {
        for (r, &n) in self.responding_patches.iter().enumerate() {
            if n > MAX_PATCHES {
                return Err(SableError::InvalidInput(format!(
                    "responding_patches[{r}] = {n} exceeds {MAX_PATCHES}"
                )));
            }
        }
        if self.min_coverage > MAX_PATCHES {
            return Err(SableError::InvalidInput(format!(
                "min_coverage = {} exceeds {MAX_PATCHES}",
                self.min_coverage
            )));
        }
        if self.glint_ratio_tolerance > 15 {
            return Err(SableError::InvalidInput(format!(
                "glint_ratio_tolerance = {} exceeds 15",
                self.glint_ratio_tolerance
            )));
        }
        if self.glint_magnitude_tolerance > 31 {
            return Err(SableError::InvalidInput(format!(
                "glint_magnitude_tolerance = {} exceeds 31",
                self.glint_magnitude_tolerance
            )));
        }
        Ok(())
    }

    /// Widen every field to the integer form the circuit consumes.
    pub(crate) fn field_values(&self) -> LivenessFieldValues {
        let mut lo = [0u8; 16];
        let mut hi = [0u8; 16];
        lo.copy_from_slice(&self.challenge_id[..16]);
        hi.copy_from_slice(&self.challenge_id[16..]);
        LivenessFieldValues {
            delta: self.delta_fingerprints.map(u64::from),
            expected: self.expected_fingerprints.map(u64::from),
            color_threshold: self.color_threshold as u64,
            spatial_threshold: self.spatial_threshold as u64,
            min_magnitude: self.min_magnitude as u64,
            responding: self.responding_patches.map(u64::from),
            min_coverage: self.min_coverage as u64,
            convexity: self.convexity_scores.map(u64::from),
            min_convexity: self.min_convexity as u64,
            corneal_enabled: self.corneal_enabled as u64,
            ratio_tol: self.glint_ratio_tolerance as u64,
            mag_tol: self.glint_magnitude_tolerance as u64,
            glints: self.glint_fingerprints.map(u64::from),
            expected_glints: self.expected_glints.map(u64::from),
            challenge_lo: u128::from_le_bytes(lo),
            challenge_hi: u128::from_le_bytes(hi),
        }
    }
}

/// The circuit's view of a witness: every field as an integer.
///
/// Kept separate from [`LivenessWitness`] so tests can inject values the typed
/// witness cannot express (an aliased threshold above 255) and observe the
/// in-circuit range constraints reject them (TEST-151).
#[derive(Debug, Clone)]
pub(crate) struct LivenessFieldValues {
    pub delta: [u64; NUM_FINGERPRINTS],
    pub expected: [u64; NUM_FINGERPRINTS],
    pub color_threshold: u64,
    pub spatial_threshold: u64,
    pub min_magnitude: u64,
    pub responding: [u64; NUM_ROUNDS],
    pub min_coverage: u64,
    pub convexity: [u64; NUM_ROUNDS],
    pub min_convexity: u64,
    pub corneal_enabled: u64,
    pub ratio_tol: u64,
    pub mag_tol: u64,
    pub glints: [u64; NUM_GLINTS],
    pub expected_glints: [u64; NUM_ROUNDS],
    pub challenge_lo: u128,
    pub challenge_hi: u128,
}

/// Which check family a witness fails (OBS-085). Carries no witness values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LivenessCheck {
    /// Colour match against the expected fingerprint.
    Colour,
    /// Spatial differentiation between adjacent quadrants.
    Spatial,
    /// Response magnitude above the noise floor.
    Magnitude,
    /// Responding-patch coverage floor (REQ-120).
    Coverage,
    /// Convexity floor (REQ-121).
    Convexity,
    /// Corneal glint agreement (REQ-122).
    Corneal,
}

/// The first failing check and the round it failed in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LivenessFailure {
    /// Check family.
    pub check: LivenessCheck,
    /// Flash round index.
    pub round: usize,
}

/// Result of liveness check circuit execution.
#[derive(Debug, Clone)]
pub struct LivenessResult {
    /// Whether all checks passed.
    pub passed: bool,
}

/// `SHA-256(c_nonce ‖ s_nonce)`: the challenge identifier bound by REQ-119.
///
/// Both parties hold both nonces after the reveal, so both can compute it.
pub fn challenge_identifier(c_nonce: &[u8; 32], s_nonce: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(c_nonce);
    h.update(s_nonce);
    h.finalize().into()
}

/// Compute the challenge digest natively (CON-094).
///
/// Evaluates the identical in-circuit gadget in witness-generation mode, so the
/// native value cannot diverge from what the circuit exposes. The verifier
/// computes this from the parameters it issued and checks it against the
/// proof's public input.
pub fn challenge_digest(witness: &LivenessWitness) -> Fr {
    let v = witness.field_values();
    let mut builder =
        BaseCircuitBuilder::<Fr>::new(false).use_params(LivenessCheckCircuit::circuit_params());
    let ctx = builder.main(0);
    let gate = GateChip::<Fr>::default();

    // Natively there is nothing to constrain; load plain witnesses.
    let cells = PublicCells {
        expected: v.expected.iter().map(|&x| ctx.load_witness(Fr::from(x))).collect(),
        color_threshold: ctx.load_witness(Fr::from(v.color_threshold)),
        spatial_threshold: ctx.load_witness(Fr::from(v.spatial_threshold)),
        min_magnitude: ctx.load_witness(Fr::from(v.min_magnitude)),
        min_coverage: ctx.load_witness(Fr::from(v.min_coverage)),
        corneal_enabled: ctx.load_witness(Fr::from(v.corneal_enabled)),
        ratio_tol: ctx.load_witness(Fr::from(v.ratio_tol)),
        mag_tol: ctx.load_witness(Fr::from(v.mag_tol)),
        min_convexity: ctx.load_witness(Fr::from(v.min_convexity)),
        expected_glints: v.expected_glints.map(|x| ctx.load_witness(Fr::from(x))),
        challenge_lo: ctx.load_witness(fr_from_u128(v.challenge_lo)),
        challenge_hi: ctx.load_witness(fr_from_u128(v.challenge_hi)),
    };
    *digest_gadget(ctx, &gate, &cells).value()
}

/// The public parameter cells that feed the digest.
struct PublicCells {
    expected: Vec<AssignedValue<Fr>>,
    color_threshold: AssignedValue<Fr>,
    spatial_threshold: AssignedValue<Fr>,
    min_magnitude: AssignedValue<Fr>,
    min_coverage: AssignedValue<Fr>,
    corneal_enabled: AssignedValue<Fr>,
    ratio_tol: AssignedValue<Fr>,
    mag_tol: AssignedValue<Fr>,
    min_convexity: AssignedValue<Fr>,
    expected_glints: [AssignedValue<Fr>; NUM_ROUNDS],
    challenge_lo: AssignedValue<Fr>,
    challenge_hi: AssignedValue<Fr>,
}

/// CON-094 Q1: four limbs, one Poseidon hash.
fn digest_gadget(ctx: &mut Context<Fr>, gate: &GateChip<Fr>, p: &PublicCells) -> AssignedValue<Fr> {
    // limb0: the twelve expected fingerprints at 16-bit offsets.
    let fp_coeffs: Vec<QuantumCell<Fr>> = (0..NUM_FINGERPRINTS)
        .map(|i| QuantumCell::Constant(pow2_fr(FINGERPRINT_BITS * i)))
        .collect();
    let limb0 = gate.inner_product(ctx, p.expected.iter().copied(), fp_coeffs);

    // limb1: thresholds, tolerances, enable flag, expected glints.
    let fields = [
        (p.color_threshold, L1_COLOR_T),
        (p.spatial_threshold, L1_SPATIAL_T),
        (p.min_magnitude, L1_MIN_MAG),
        (p.min_coverage, L1_MIN_COVERAGE),
        (p.corneal_enabled, L1_CORNEAL_ENABLED),
        (p.ratio_tol, L1_RATIO_TOL),
        (p.mag_tol, L1_MAG_TOL),
        (p.min_convexity, L1_MIN_CONVEXITY),
        (p.expected_glints[0], L1_EXPECTED_GLINT[0]),
        (p.expected_glints[1], L1_EXPECTED_GLINT[1]),
        (p.expected_glints[2], L1_EXPECTED_GLINT[2]),
    ];
    let cells = fields.iter().map(|(c, _)| *c);
    let coeffs: Vec<QuantumCell<Fr>> = fields
        .iter()
        .map(|(_, off)| QuantumCell::Constant(pow2_fr(*off)))
        .collect();
    let limb1 = gate.inner_product(ctx, cells, coeffs);

    super::poseidon::poseidon_hash_cells(ctx, gate, &[limb0, limb1, p.challenge_lo, p.challenge_hi])
}

/// Liveness check circuit.
///
/// Proves that private delta fingerprints, coverage counts, convexity scores
/// and glint fingerprints satisfy the public thresholds, and exposes the
/// challenge digest binding those thresholds to the challenge.
pub struct LivenessCheckCircuit {
    witness: LivenessWitness,
}

impl LivenessCheckCircuit {
    /// Create a new liveness check circuit.
    pub fn new(witness: LivenessWitness) -> Self {
        Self { witness }
    }

    /// The witness this circuit was built from.
    pub fn witness(&self) -> &LivenessWitness {
        &self.witness
    }

    /// Check if this witness should pass (CPU-side evaluation).
    pub fn should_pass(&self) -> bool {
        self.first_failing_check().is_none()
    }

    /// Native mirror of the circuit: the first check that fails, if any.
    ///
    /// Emitted by the server as OBS-085 so a production failure is diagnosable
    /// from the check family and round alone.
    pub fn first_failing_check(&self) -> Option<LivenessFailure> {
        let w = &self.witness;
        for r in 0..NUM_ROUNDS {
            let base = r * 4;
            let idx = [base, base + 1, base + 2, base + 3];

            // Colour match: HD(delta, expected) <= color_threshold for all 4 quadrants.
            for &i in &idx {
                if hamming_u16(w.delta_fingerprints[i], w.expected_fingerprints[i])
                    > w.color_threshold as u32
                {
                    return Some(LivenessFailure { check: LivenessCheck::Colour, round: r });
                }
            }
            // Spatial diff: HD >= spatial_threshold for 4 adjacent pairs.
            for (a, b) in [(0, 1), (0, 2), (1, 3), (2, 3)] {
                if hamming_u16(w.delta_fingerprints[base + a], w.delta_fingerprints[base + b])
                    < w.spatial_threshold as u32
                {
                    return Some(LivenessFailure { check: LivenessCheck::Spatial, round: r });
                }
            }
            // Magnitude: low 5 bits >= min_magnitude for all 4 quadrants.
            for &i in &idx {
                if (w.delta_fingerprints[i] & 0x1F) < w.min_magnitude as u16 {
                    return Some(LivenessFailure { check: LivenessCheck::Magnitude, round: r });
                }
            }
            // REQ-120: coverage floor.
            if w.responding_patches[r] < w.min_coverage {
                return Some(LivenessFailure { check: LivenessCheck::Coverage, round: r });
            }
            // REQ-121: convexity floor.
            if w.convexity_scores[r] < w.min_convexity {
                return Some(LivenessFailure { check: LivenessCheck::Convexity, round: r });
            }
            // REQ-122: corneal agreement, field-wise (never Hamming, REQ-123).
            if w.corneal_enabled {
                for eye in 0..NUM_EYES {
                    let g = w.glint_fingerprints[r * NUM_EYES + eye];
                    if !crate::biometric::fingerprint::matches(
                        g,
                        w.expected_glints[r],
                        w.glint_ratio_tolerance,
                        w.glint_magnitude_tolerance,
                    ) {
                        return Some(LivenessFailure { check: LivenessCheck::Corneal, round: r });
                    }
                }
            }
        }
        None
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
    /// - `liveness_result`: 1 = all enabled checks pass, 0 = at least one fails
    /// - `challenge_digest`: Poseidon digest of every public parameter (CON-094),
    ///   exposed as a public input so the verifier can check the prover used the
    ///   parameters it issued.
    pub fn build_circuit(
        &self,
        builder: &mut BaseCircuitBuilder<Fr>,
    ) -> (AssignedValue<Fr>, AssignedValue<Fr>) {
        Self::build_from_values(builder, &self.witness.field_values())
    }

    /// Build from integer field values. The in-circuit half of the CON-095
    /// recogniser lives here: every field is decomposed to its declared width
    /// before it is compared or hashed (REQ-124).
    pub(crate) fn build_from_values(
        builder: &mut BaseCircuitBuilder<Fr>,
        v: &LivenessFieldValues,
    ) -> (AssignedValue<Fr>, AssignedValue<Fr>) {
        let ctx = builder.main(0);
        let gate = GateChip::<Fr>::default();

        let one = ctx.load_constant(Fr::from(1u64));
        let zero = ctx.load_constant(Fr::from(0u64));

        // Start with result = 1 (all pass), AND with each check.
        let mut result = ctx.load_constant(Fr::from(1u64));

        // ---- Public parameters, range-constrained once, reused everywhere ----
        let color_t = load_ranged(ctx, &gate, v.color_threshold, THRESHOLD_BITS);
        let spatial_t = load_ranged(ctx, &gate, v.spatial_threshold, THRESHOLD_BITS);
        let min_mag = load_ranged(ctx, &gate, v.min_magnitude, THRESHOLD_BITS);
        let min_coverage = load_ranged(ctx, &gate, v.min_coverage, COVERAGE_BITS);
        let max_patches = ctx.load_constant(Fr::from(MAX_PATCHES as u64));
        let cov_in_range = compare_le(ctx, &gate, min_coverage, max_patches, COVERAGE_BITS);
        ctx.constrain_equal(&cov_in_range, &one);
        let corneal_enabled = ctx.load_witness(Fr::from(v.corneal_enabled));
        gate.assert_bit(ctx, corneal_enabled);
        let ratio_tol = load_ranged(ctx, &gate, v.ratio_tol, RATIO_TOL_BITS);
        let mag_tol = load_ranged(ctx, &gate, v.mag_tol, MAG_TOL_BITS);
        let min_convexity = load_ranged(ctx, &gate, v.min_convexity, CONVEXITY_BITS);

        let mut expected_witnesses: Vec<AssignedValue<Fr>> = Vec::with_capacity(NUM_FINGERPRINTS);
        let mut expected_glint_cells: Vec<AssignedValue<Fr>> = Vec::with_capacity(NUM_ROUNDS);
        let mut expected_glint_bits: Vec<Vec<AssignedValue<Fr>>> = Vec::with_capacity(NUM_ROUNDS);
        for r in 0..NUM_ROUNDS {
            let (cell, bits) = load_with_bits(ctx, &gate, v.expected_glints[r], FINGERPRINT_BITS);
            expected_glint_cells.push(cell);
            expected_glint_bits.push(bits);
        }
        let not_enabled = gate.sub(ctx, one, corneal_enabled);

        // Adjacent pair indices within a round (TL=0, TR=1, BL=2, BR=3).
        let adjacent_pairs: [(usize, usize); 4] = [(0, 1), (0, 2), (1, 3), (2, 3)];

        for r in 0..NUM_ROUNDS {
            let base = r * 4;
            let mut delta_bits_all = Vec::with_capacity(4);

            for q in 0..4 {
                let idx = base + q;
                let (_delta, delta_bits) = load_with_bits(ctx, &gate, v.delta[idx], FINGERPRINT_BITS);
                let (expected, expected_bits) =
                    load_with_bits(ctx, &gate, v.expected[idx], FINGERPRINT_BITS);
                expected_witnesses.push(expected);

                // ---- Colour match: HD(delta, expected) <= color_threshold ----
                let xor_color = xor_bits(ctx, &gate, &delta_bits, &expected_bits);
                let hd_color = popcount(ctx, &gate, &xor_color);
                let color_ok = compare_le(ctx, &gate, hd_color, color_t, THRESHOLD_BITS);
                result = gate.mul(ctx, result, color_ok);

                // ---- Magnitude: low 5 bits >= min_magnitude ----
                let mag_val = bits_to_value(ctx, &gate, &delta_bits[..MAGNITUDE_BITS]);
                let mag_ok = compare_le(ctx, &gate, min_mag, mag_val, THRESHOLD_BITS);
                result = gate.mul(ctx, result, mag_ok);

                delta_bits_all.push(delta_bits);
            }

            // ---- Spatial differentiation: HD(adjacent) >= spatial_threshold ----
            for &(a, b) in &adjacent_pairs {
                let xor_spatial = xor_bits(ctx, &gate, &delta_bits_all[a], &delta_bits_all[b]);
                let hd_spatial = popcount(ctx, &gate, &xor_spatial);
                let spatial_ok = compare_le(ctx, &gate, spatial_t, hd_spatial, THRESHOLD_BITS);
                result = gate.mul(ctx, result, spatial_ok);
            }

            // ---- REQ-120: coverage floor (vacuous at min_coverage = 0) ----
            let responding = load_ranged(ctx, &gate, v.responding[r], COVERAGE_BITS);
            let resp_in_range = compare_le(ctx, &gate, responding, max_patches, COVERAGE_BITS);
            ctx.constrain_equal(&resp_in_range, &one);
            let coverage_ok = compare_le(ctx, &gate, min_coverage, responding, COVERAGE_BITS);
            result = gate.mul(ctx, result, coverage_ok);

            // ---- REQ-121: convexity floor (vacuous at min_convexity = 0) ----
            let convexity = load_ranged(ctx, &gate, v.convexity[r], CONVEXITY_BITS);
            let convexity_ok = compare_le(ctx, &gate, min_convexity, convexity, CONVEXITY_BITS);
            result = gate.mul(ctx, result, convexity_ok);

            // ---- REQ-122: corneal agreement, field-wise (REQ-123: never Hamming) ----
            let e_bits = &expected_glint_bits[r];
            let e_order = bits_to_value(ctx, &gate, &e_bits[ORDER_LO..ORDER_LO + ORDER_BITS]);
            let e_mid = bits_to_value(ctx, &gate, &e_bits[MID_RATIO_LO..MID_RATIO_LO + RATIO_BITS]);
            let e_min = bits_to_value(ctx, &gate, &e_bits[MIN_RATIO_LO..MIN_RATIO_LO + RATIO_BITS]);
            let e_mag = bits_to_value(ctx, &gate, &e_bits[..MAGNITUDE_BITS]);
            for eye in 0..NUM_EYES {
                let (_g, g_bits) =
                    load_with_bits(ctx, &gate, v.glints[r * NUM_EYES + eye], FINGERPRINT_BITS);
                let g_order = bits_to_value(ctx, &gate, &g_bits[ORDER_LO..ORDER_LO + ORDER_BITS]);
                let g_mid = bits_to_value(ctx, &gate, &g_bits[MID_RATIO_LO..MID_RATIO_LO + RATIO_BITS]);
                let g_min = bits_to_value(ctx, &gate, &g_bits[MIN_RATIO_LO..MIN_RATIO_LO + RATIO_BITS]);
                let g_mag = bits_to_value(ctx, &gate, &g_bits[..MAGNITUDE_BITS]);

                let order_ok = gate.is_equal(ctx, g_order, e_order);
                let mid_ok = within_tolerance(ctx, &gate, g_mid, e_mid, ratio_tol, RATIO_BITS);
                let min_ok = within_tolerance(ctx, &gate, g_min, e_min, ratio_tol, RATIO_BITS);
                let mag_ok = within_tolerance(ctx, &gate, g_mag, e_mag, mag_tol, MAGNITUDE_BITS);

                let mut eye_ok = gate.mul(ctx, order_ok, mid_ok);
                eye_ok = gate.mul(ctx, eye_ok, min_ok);
                eye_ok = gate.mul(ctx, eye_ok, mag_ok);

                // gated = (1 - enabled) + enabled * eye_ok
                let gated = gate.mul_add(ctx, corneal_enabled, eye_ok, not_enabled);
                result = gate.mul(ctx, result, gated);
            }
        }

        // Constrain result to be boolean.
        let result_minus_one = gate.sub(ctx, result, one);
        let bool_check = gate.mul(ctx, result, result_minus_one);
        ctx.constrain_equal(&bool_check, &zero);

        // ---- Challenge digest (CON-094), from the SAME cells the checks used ----
        let cells = PublicCells {
            expected: expected_witnesses,
            color_threshold: color_t,
            spatial_threshold: spatial_t,
            min_magnitude: min_mag,
            min_coverage,
            corneal_enabled,
            ratio_tol,
            mag_tol,
            min_convexity,
            expected_glints: [
                expected_glint_cells[0],
                expected_glint_cells[1],
                expected_glint_cells[2],
            ],
            challenge_lo: ctx.load_witness(fr_from_u128(v.challenge_lo)),
            challenge_hi: ctx.load_witness(fr_from_u128(v.challenge_hi)),
        };
        let digest = digest_gadget(ctx, &gate, &cells);

        (result, digest)
    }

    /// Test the circuit using the mock prover.
    pub fn test_circuit(&self) -> Result<bool> {
        self.witness.recognise()?;
        let mut builder = BaseCircuitBuilder::new(false).use_params(Self::circuit_params());
        let (result, digest) = self.build_circuit(&mut builder);

        // Make result and digest public instances.
        builder.assigned_instances[0].push(result);
        builder.assigned_instances[0].push(digest);

        let result_value = *result.value();
        let digest_value = *digest.value();

        let prover = MockProver::run(K, &builder, vec![vec![result_value, digest_value]])
            .map_err(|e| SableError::ProofGeneration(format!("Mock prover failed: {:?}", e)))?;

        prover.verify().map_err(|e| {
            SableError::ProofVerification(format!("Circuit verification failed: {:?}", e))
        })?;

        Ok(fr_to_u64(&result_value) == 1)
    }
}

// ---------------------------------------------------------------------------
// Circuit helper functions
// ---------------------------------------------------------------------------

/// Low 64 bits of a field element (values here are all small integers).
fn fr_to_u64(f: &Fr) -> u64 {
    let bytes = f.to_bytes();
    u64::from_le_bytes(bytes[0..8].try_into().expect("8 bytes"))
}

/// A 128-bit integer as a field element.
fn fr_from_u128(x: u128) -> Fr {
    Fr::from_raw([x as u64, (x >> 64) as u64, 0, 0])
}

/// 2^n in Fr by repeated doubling.
fn pow2_fr(n: usize) -> Fr {
    let mut s = Fr::from(1u64);
    for _ in 0..n {
        s = s + s;
    }
    s
}

/// Load a witness and constrain it to `bits` bits (REQ-124). Returns the cell.
fn load_ranged(ctx: &mut Context<Fr>, gate: &GateChip<Fr>, value: u64, bits: usize) -> AssignedValue<Fr> {
    let (cell, _) = load_with_bits(ctx, gate, value, bits);
    cell
}

/// Load a witness, constrain it to `bits` bits, and return the cell with its
/// boolean-constrained little-endian bit decomposition.
fn load_with_bits(
    ctx: &mut Context<Fr>,
    gate: &GateChip<Fr>,
    value: u64,
    bits: usize,
) -> (AssignedValue<Fr>, Vec<AssignedValue<Fr>>) {
    let cell = ctx.load_witness(Fr::from(value));
    let bits = decompose_bits(ctx, gate, cell, bits);
    (cell, bits)
}

/// Decompose a cell into `nbits` boolean-constrained bits (LSB first) and
/// constrain that they reconstruct the cell. A value that does not fit in
/// `nbits` makes the reconstruction constraint unsatisfiable.
fn decompose_bits(
    ctx: &mut Context<Fr>,
    gate: &GateChip<Fr>,
    value: AssignedValue<Fr>,
    nbits: usize,
) -> Vec<AssignedValue<Fr>> {
    let v = fr_to_u64(value.value());
    let bits: Vec<AssignedValue<Fr>> = (0..nbits)
        .map(|i| {
            let bit = ctx.load_witness(Fr::from((v >> i) & 1));
            gate.assert_bit(ctx, bit);
            bit
        })
        .collect();
    let reconstructed = bits_to_value(ctx, gate, &bits);
    ctx.constrain_equal(&reconstructed, &value);
    bits
}

/// Σ bits[i] · 2^i over a slice of boolean cells.
fn bits_to_value(ctx: &mut Context<Fr>, gate: &GateChip<Fr>, bits: &[AssignedValue<Fr>]) -> AssignedValue<Fr> {
    let coeffs: Vec<QuantumCell<Fr>> = (0..bits.len())
        .map(|i| QuantumCell::Constant(pow2_fr(i)))
        .collect();
    gate.inner_product(ctx, bits.iter().copied(), coeffs)
}

/// XOR of two bit arrays: xor[i] = a[i] + b[i] - 2·a[i]·b[i].
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
            let sum = gate.add(ctx, a, b);
            let product = gate.mul(ctx, a, b);
            let double_product = gate.mul(ctx, two, product);
            gate.sub(ctx, sum, double_product)
        })
        .collect()
}

/// Sum of bit values (popcount).
fn popcount(ctx: &mut Context<Fr>, gate: &GateChip<Fr>, bits: &[AssignedValue<Fr>]) -> AssignedValue<Fr> {
    let mut sum = ctx.load_constant(Fr::from(0u64));
    for &bit in bits {
        sum = gate.add(ctx, sum, bit);
    }
    sum
}

/// Prove `a <= b`, returning 1 if so and 0 otherwise.
///
/// `bits` must cover the largest possible |a − b|; the conditional difference is
/// range-checked to that width, so a difference that does not fit is
/// unsatisfiable rather than silently wrong.
fn compare_le(
    ctx: &mut Context<Fr>,
    gate: &GateChip<Fr>,
    a: AssignedValue<Fr>,
    b: AssignedValue<Fr>,
    bits: usize,
) -> AssignedValue<Fr> {
    let one = ctx.load_constant(Fr::from(1u64));
    let a_u = fr_to_u64(a.value());
    let b_u = fr_to_u64(b.value());

    let result = ctx.load_witness(Fr::from(u64::from(a_u <= b_u)));
    gate.assert_bit(ctx, result);

    // result = 1: diff = b - a      (non-negative)
    // result = 0: diff = a - b - 1  (non-negative)
    let b_minus_a = gate.sub(ctx, b, a);
    let a_minus_b = gate.sub(ctx, a, b);
    let a_minus_b_minus_1 = gate.sub(ctx, a_minus_b, one);
    let one_minus_result = gate.sub(ctx, one, result);
    let term1 = gate.mul(ctx, result, b_minus_a);
    let term2 = gate.mul(ctx, one_minus_result, a_minus_b_minus_1);
    let diff = gate.add(ctx, term1, term2);

    // Range check the difference.
    let _ = decompose_bits(ctx, gate, diff, bits);
    result
}

/// Prove `|a − b| <= tol` for `a, b < 2^width`, returning 1 or 0.
///
/// Uses an offset so the difference stays non-negative:
/// `d = a − b + 2^width ∈ [1, 2^(width+1) − 1]`, then
/// `2^width − tol <= d <= 2^width + tol`.
fn within_tolerance(
    ctx: &mut Context<Fr>,
    gate: &GateChip<Fr>,
    a: AssignedValue<Fr>,
    b: AssignedValue<Fr>,
    tol: AssignedValue<Fr>,
    width: usize,
) -> AssignedValue<Fr> {
    let off = ctx.load_constant(pow2_fr(width));
    let a_minus_b = gate.sub(ctx, a, b);
    let d = gate.add(ctx, a_minus_b, off);
    let lo = gate.sub(ctx, off, tol);
    let hi = gate.add(ctx, off, tol);
    let lo_ok = compare_le(ctx, gate, lo, d, width + 2);
    let hi_ok = compare_le(ctx, gate, d, hi, width + 2);
    gate.mul(ctx, lo_ok, hi_ok)
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
    use crate::biometric::fingerprint::quantize_colour;

    /// A passing 0.1.0 witness with distinct quadrant fingerprints.
    ///
    /// Per round: [0x0014, 0xA014, 0x6014, 0xC014] — all adjacent pairs have
    /// HD = 2 ≥ spatial_threshold(2), magnitude 20 ≥ min_magnitude(5), and
    /// delta == expected so colour HD = 0.
    fn passing_witness() -> LivenessWitness {
        LivenessWitness::dummy_pass()
    }

    /// A legacy witness: the 0.1.0 fields, everything else unset.
    fn legacy(
        delta: [u16; 12],
        expected: [u16; 12],
        color_threshold: u8,
        spatial_threshold: u8,
        min_magnitude: u8,
    ) -> LivenessWitness {
        LivenessWitness {
            delta_fingerprints: delta,
            expected_fingerprints: expected,
            color_threshold,
            spatial_threshold,
            min_magnitude,
            ..LivenessWitness::default()
        }
    }

    /// Build a fingerprint from its fields.
    fn fp(order: u16, mid: u16, min: u16, mag: u16) -> u16 {
        (order << 13) | (mid << 9) | (min << 5) | mag
    }

    /// Run the circuit on raw field values and report whether MockProver
    /// accepts it (used by the aliasing test, which the typed witness cannot
    /// express).
    fn mock_verify_values(v: &LivenessFieldValues) -> std::result::Result<Fr, String> {
        let mut builder =
            BaseCircuitBuilder::new(false).use_params(LivenessCheckCircuit::circuit_params());
        let (result, digest) = LivenessCheckCircuit::build_from_values(&mut builder, v);
        builder.assigned_instances[0].push(result);
        builder.assigned_instances[0].push(digest);
        let pubs = vec![*result.value(), *digest.value()];
        let prover = MockProver::run(K, &builder, vec![pubs]).map_err(|e| format!("{e:?}"))?;
        prover.verify().map_err(|e| format!("{e:?}"))?;
        Ok(*digest.value())
    }

    // -----------------------------------------------------------------
    // 0.1.0 behaviour, unchanged
    // -----------------------------------------------------------------

    #[test]
    fn test_liveness_circuit_pass() {
        let circuit = LivenessCheckCircuit::new(passing_witness());
        assert!(circuit.should_pass(), "CPU-side check should pass");
        assert!(circuit.test_circuit().expect("satisfiable"), "circuit should output 1");
    }

    #[test]
    fn test_liveness_exact_match() {
        let w = legacy(
            [101, 201, 301, 401, 501, 601, 701, 801, 101, 201, 301, 401],
            [101, 201, 301, 401, 501, 601, 701, 801, 101, 201, 301, 401],
            3,
            1,
            1,
        );
        let circuit = LivenessCheckCircuit::new(w);
        assert!(circuit.should_pass());
        assert!(circuit.test_circuit().expect("satisfiable"));
    }

    #[test]
    fn test_liveness_wrong_color() {
        let w = legacy(
            [0x0014, 0xA014, 0x6014, 0xC014, 0x0014, 0xA014, 0x6014, 0xC014, 0x0014, 0xA014, 0x6014, 0xC014],
            [0xA014, 0x0014, 0xC014, 0x6014, 0xA014, 0x0014, 0xC014, 0x6014, 0xA014, 0x0014, 0xC014, 0x6014],
            1,
            1,
            5,
        );
        let circuit = LivenessCheckCircuit::new(w);
        assert_eq!(
            circuit.first_failing_check().map(|f| f.check),
            Some(LivenessCheck::Colour)
        );
        assert!(!circuit.test_circuit().expect("satisfiable"));
    }

    #[test]
    fn test_liveness_no_spatial_diff() {
        let w = legacy(
            [100, 100, 100, 100, 200, 200, 200, 200, 300, 300, 300, 300],
            [100, 100, 100, 100, 200, 200, 200, 200, 300, 300, 300, 300],
            3,
            1,
            1,
        );
        let circuit = LivenessCheckCircuit::new(w);
        assert_eq!(
            circuit.first_failing_check().map(|f| f.check),
            Some(LivenessCheck::Spatial)
        );
        assert!(!circuit.test_circuit().expect("satisfiable"));
    }

    #[test]
    fn test_liveness_low_magnitude() {
        let fps = [
            0x0001, 0xA001, 0x4001, 0xC001, 0x0001, 0xA001, 0x4001, 0xC001, 0x0001, 0xA001, 0x4001, 0xC001,
        ];
        let circuit = LivenessCheckCircuit::new(legacy(fps, fps, 3, 2, 5));
        assert_eq!(
            circuit.first_failing_check().map(|f| f.check),
            Some(LivenessCheck::Magnitude)
        );
        assert!(!circuit.test_circuit().expect("satisfiable"));
    }

    #[test]
    fn test_liveness_partial_round_failure() {
        let w = legacy(
            [
                0x0014, 0xA014, 0x6014, 0xC014, // round 0 ok
                0x4014, 0xA014, 0x0014, 0xE014, // round 1 ok
                0x0014, 0x0014, 0x0014, 0x0014, // round 2 all same
            ],
            [
                0x0014, 0xA014, 0x6014, 0xC014, 0x4014, 0xA014, 0x0014, 0xE014, 0x0014, 0x0014, 0x0014,
                0x0014,
            ],
            3,
            2,
            5,
        );
        let circuit = LivenessCheckCircuit::new(w);
        assert_eq!(
            circuit.first_failing_check(),
            Some(LivenessFailure { check: LivenessCheck::Spatial, round: 2 })
        );
        assert!(!circuit.test_circuit().expect("satisfiable"));
    }

    #[test]
    fn test_liveness_color_threshold_boundary() {
        let w = legacy(
            [0x0015, 0xA015, 0x6015, 0xC015, 0x0015, 0xA015, 0x6015, 0xC015, 0x0015, 0xA015, 0x6015, 0xC015],
            [0x0014, 0xA014, 0x6014, 0xC014, 0x0014, 0xA014, 0x6014, 0xC014, 0x0014, 0xA014, 0x6014, 0xC014],
            1,
            2,
            5,
        );
        let circuit = LivenessCheckCircuit::new(w);
        assert!(circuit.should_pass(), "HD == color_threshold should pass");
        assert!(circuit.test_circuit().expect("satisfiable"));
    }

    #[test]
    fn test_liveness_color_threshold_just_over() {
        let w = legacy(
            [0x0017, 0xA014, 0x6014, 0xC014, 0x0014, 0xA014, 0x6014, 0xC014, 0x0014, 0xA014, 0x6014, 0xC014],
            [0x0014, 0xA014, 0x6014, 0xC014, 0x0014, 0xA014, 0x6014, 0xC014, 0x0014, 0xA014, 0x6014, 0xC014],
            1,
            2,
            5,
        );
        let circuit = LivenessCheckCircuit::new(w);
        assert!(!circuit.should_pass(), "HD > color_threshold should fail");
        assert!(!circuit.test_circuit().expect("satisfiable"));
    }

    #[test]
    fn test_liveness_large_threshold_is_satisfiable() {
        // 0.1.0 range-checked the comparison difference to 5 bits, so any
        // threshold above 31 made the circuit unsatisfiable. Thresholds are
        // 8-bit; the comparison must accept the whole declared width.
        let circuit = LivenessCheckCircuit::new(legacy(
            passing_witness().delta_fingerprints,
            passing_witness().expected_fingerprints,
            200,
            2,
            5,
        ));
        assert!(circuit.test_circuit().expect("a threshold of 200 must be satisfiable"));
    }

    #[test]
    fn test_liveness_spatial_threshold_boundary() {
        let fps = [
            0x0014, 0x2014, 0x4014, 0x6014, 0x0014, 0x2014, 0x4014, 0x6014, 0x0014, 0x2014, 0x4014, 0x6014,
        ];
        let circuit = LivenessCheckCircuit::new(legacy(fps, fps, 3, 1, 5));
        assert!(circuit.should_pass());
        assert!(circuit.test_circuit().expect("satisfiable"));
    }

    #[test]
    fn test_liveness_magnitude_boundary() {
        let fps = [
            0x0005, 0xA005, 0x6005, 0xC005, 0x0005, 0xA005, 0x6005, 0xC005, 0x0005, 0xA005, 0x6005, 0xC005,
        ];
        let circuit = LivenessCheckCircuit::new(legacy(fps, fps, 3, 2, 5));
        assert!(circuit.should_pass());
        assert!(circuit.test_circuit().expect("satisfiable"));
    }

    #[test]
    fn test_liveness_magnitude_just_under() {
        let fps = [
            0x0004, 0xA004, 0x6004, 0xC004, 0x0004, 0xA004, 0x6004, 0xC004, 0x0004, 0xA004, 0x6004, 0xC004,
        ];
        let circuit = LivenessCheckCircuit::new(legacy(fps, fps, 3, 2, 5));
        assert!(!circuit.should_pass());
        assert!(!circuit.test_circuit().expect("satisfiable"));
    }

    #[test]
    fn test_liveness_all_zeros_witness() {
        let circuit = LivenessCheckCircuit::new(legacy([0; 12], [0; 12], 3, 1, 1));
        assert!(!circuit.should_pass());
        assert!(!circuit.test_circuit().expect("satisfiable"));
    }

    #[test]
    fn test_liveness_max_fingerprints() {
        let fps = [
            0xFFFF, 0x0000, 0x5555, 0xAAAA, 0xFFFF, 0x0000, 0x5555, 0xAAAA, 0xFFFF, 0x0000, 0x5555, 0xAAAA,
        ];
        let circuit = LivenessCheckCircuit::new(legacy(fps, fps, 3, 2, 0));
        assert!(circuit.should_pass());
        assert!(circuit.test_circuit().expect("satisfiable"));
    }

    #[test]
    fn test_hamming_u16() {
        assert_eq!(hamming_u16(0, 0), 0);
        assert_eq!(hamming_u16(0xFFFF, 0), 16);
        assert_eq!(hamming_u16(0b1010, 0b0101), 4);
    }

    // -----------------------------------------------------------------
    // TEST-152 — legacy result preserved (CON-095 Q4, scope-invariant)
    // -----------------------------------------------------------------

    #[test]
    fn test_152_legacy_witnesses_decide_the_same() {
        // Every 0.1.0 test witness with its 0.1.0 expected result. Extending
        // it with unset 0.2.0 fields must not change the decision.
        let d = passing_witness().delta_fingerprints;
        let e = passing_witness().expected_fingerprints;
        let cases: Vec<(LivenessWitness, bool)> = vec![
            (legacy(d, e, 3, 2, 5), true),
            (legacy(d, e, 0, 2, 5), true),
            (
                legacy(
                    [101, 201, 301, 401, 501, 601, 701, 801, 101, 201, 301, 401],
                    [101, 201, 301, 401, 501, 601, 701, 801, 101, 201, 301, 401],
                    3,
                    1,
                    1,
                ),
                true,
            ),
            (
                legacy(
                    [100, 100, 100, 100, 200, 200, 200, 200, 300, 300, 300, 300],
                    [100, 100, 100, 100, 200, 200, 200, 200, 300, 300, 300, 300],
                    3,
                    1,
                    1,
                ),
                false,
            ),
            (legacy([0; 12], [0; 12], 3, 1, 1), false),
        ];
        for (i, (w, expected)) in cases.iter().enumerate() {
            let c = LivenessCheckCircuit::new(w.clone());
            assert_eq!(c.should_pass(), *expected, "case {i}: native");
            assert_eq!(c.test_circuit().expect("satisfiable"), *expected, "case {i}: circuit");
        }
    }

    // -----------------------------------------------------------------
    // TEST-140 / TEST-141 / TEST-146 — digest (REQ-116, REQ-117, REQ-119)
    // -----------------------------------------------------------------

    #[test]
    fn test_141_digest_native_equals_circuit_and_is_stable() {
        let w = passing_witness();
        let native1 = challenge_digest(&w);
        let native2 = challenge_digest(&w);
        assert_eq!(native1, native2, "digest must be deterministic");

        let circuit = LivenessCheckCircuit::new(w);
        let mut builder =
            BaseCircuitBuilder::new(false).use_params(LivenessCheckCircuit::circuit_params());
        let (_result, digest) = circuit.build_circuit(&mut builder);
        assert_eq!(*digest.value(), native1, "in-circuit digest must equal native digest");
    }

    #[test]
    fn test_140_every_public_field_changes_the_digest() {
        let base = passing_witness();
        let d0 = challenge_digest(&base);
        let mut variants: Vec<(&str, LivenessWitness)> = Vec::new();

        let mut w = base.clone();
        w.expected_fingerprints[7] ^= 1;
        variants.push(("expected_fingerprints", w));
        let mut w = base.clone();
        w.color_threshold += 1;
        variants.push(("color_threshold", w));
        let mut w = base.clone();
        w.spatial_threshold += 1;
        variants.push(("spatial_threshold", w));
        let mut w = base.clone();
        w.min_magnitude += 1;
        variants.push(("min_magnitude", w));
        let mut w = base.clone();
        w.min_coverage = 4;
        variants.push(("min_coverage", w));
        let mut w = base.clone();
        w.min_convexity = 1000;
        variants.push(("min_convexity", w));
        let mut w = base.clone();
        w.corneal_enabled = true;
        variants.push(("corneal_enabled", w));
        let mut w = base.clone();
        w.glint_ratio_tolerance = 2;
        variants.push(("glint_ratio_tolerance", w));
        let mut w = base.clone();
        w.glint_magnitude_tolerance = 2;
        variants.push(("glint_magnitude_tolerance", w));
        let mut w = base.clone();
        w.expected_glints[1] = 0x401F;
        variants.push(("expected_glints", w));

        let mut seen = vec![d0];
        for (name, w) in &variants {
            let d = challenge_digest(w);
            assert_ne!(d, d0, "{name} must change the digest");
            assert!(!seen.contains(&d), "{name} collided with an earlier variant");
            seen.push(d);
        }
    }

    #[test]
    fn test_140_private_fields_do_not_touch_the_digest() {
        let base = passing_witness();
        let d0 = challenge_digest(&base);

        let mut w = base.clone();
        w.delta_fingerprints[3] ^= 0x0101;
        assert_eq!(challenge_digest(&w), d0, "delta fingerprints are private");
        let mut w = base.clone();
        w.responding_patches = [16, 16, 16];
        assert_eq!(challenge_digest(&w), d0, "coverage counts are private");
        let mut w = base.clone();
        w.convexity_scores = [1243, 1243, 1243];
        assert_eq!(challenge_digest(&w), d0, "convexity scores are private");
        let mut w = base.clone();
        w.glint_fingerprints[2] = 0x001F;
        assert_eq!(challenge_digest(&w), d0, "glint fingerprints are private");
    }

    #[test]
    fn test_146_challenge_identifier_is_bound() {
        let c = [7u8; 32];
        let s = [9u8; 32];
        let mut w = passing_witness();
        w.challenge_id = challenge_identifier(&c, &s);
        let d0 = challenge_digest(&w);

        // Native equals in-circuit for a non-zero identifier.
        let mut builder =
            BaseCircuitBuilder::new(false).use_params(LivenessCheckCircuit::circuit_params());
        let (_r, digest) = LivenessCheckCircuit::new(w.clone()).build_circuit(&mut builder);
        assert_eq!(*digest.value(), d0);

        // One byte in either limb changes the digest.
        let mut lo = w.clone();
        lo.challenge_id[3] ^= 0x80;
        assert_ne!(challenge_digest(&lo), d0, "low limb must be bound");
        let mut hi = w.clone();
        hi.challenge_id[29] ^= 0x01;
        assert_ne!(challenge_digest(&hi), d0, "high limb must be bound");

        // A different server nonce yields a different identifier.
        assert_ne!(challenge_identifier(&c, &s), challenge_identifier(&c, &[10u8; 32]));
    }

    // -----------------------------------------------------------------
    // TEST-147 — coverage floor (REQ-120)
    // -----------------------------------------------------------------

    #[test]
    fn test_147_coverage_floor() {
        let mut w = passing_witness();
        w.min_coverage = 10;
        w.responding_patches = [10, 10, 10];
        let c = LivenessCheckCircuit::new(w.clone());
        assert!(c.should_pass());
        assert!(c.test_circuit().expect("satisfiable"), "exactly at the floor passes");

        w.responding_patches[1] = 9;
        let c = LivenessCheckCircuit::new(w.clone());
        assert_eq!(
            c.first_failing_check(),
            Some(LivenessFailure { check: LivenessCheck::Coverage, round: 1 })
        );
        assert!(!c.test_circuit().expect("satisfiable"), "one below the floor fails");

        // Vacuous at zero.
        w.min_coverage = 0;
        w.responding_patches = [0, 0, 0];
        let c = LivenessCheckCircuit::new(w);
        assert!(c.test_circuit().expect("satisfiable"), "min_coverage = 0 disables the check");
    }

    // -----------------------------------------------------------------
    // TEST-148 — convexity floor (REQ-121)
    // -----------------------------------------------------------------

    #[test]
    fn test_148_convexity_floor() {
        let mut w = passing_witness();
        w.min_convexity = 1243;
        w.convexity_scores = [1243, 1243, 1243];
        let c = LivenessCheckCircuit::new(w.clone());
        assert!(c.should_pass());
        assert!(c.test_circuit().expect("satisfiable"), "exactly at the floor passes");

        w.convexity_scores[2] = 1242;
        let c = LivenessCheckCircuit::new(w.clone());
        assert_eq!(
            c.first_failing_check(),
            Some(LivenessFailure { check: LivenessCheck::Convexity, round: 2 })
        );
        assert!(!c.test_circuit().expect("satisfiable"), "one below the floor fails");

        w.min_convexity = 0;
        w.convexity_scores = [0, 0, 0];
        let c = LivenessCheckCircuit::new(w);
        assert!(c.test_circuit().expect("satisfiable"), "min_convexity = 0 disables the check");
    }

    // -----------------------------------------------------------------
    // TEST-149 / TEST-150 — corneal agreement (REQ-122, REQ-123)
    // -----------------------------------------------------------------

    fn corneal_witness() -> LivenessWitness {
        let red = quantize_colour(&[255, 0, 0]);
        let green = quantize_colour(&[0, 255, 0]);
        let blue = quantize_colour(&[0, 0, 255]);
        let mut w = passing_witness();
        w.corneal_enabled = true;
        w.expected_glints = [red, green, blue];
        w.glint_fingerprints = [red, red, green, green, blue, blue];
        w
    }

    #[test]
    fn test_149_glints_matching_each_round_pass_at_zero_tolerance() {
        let c = LivenessCheckCircuit::new(corneal_witness());
        assert!(c.should_pass());
        assert!(c.test_circuit().expect("satisfiable"));
    }

    #[test]
    fn test_149_glint_from_previous_round_is_rejected_at_max_tolerance() {
        let mut w = corneal_witness();
        w.glint_ratio_tolerance = 15;
        w.glint_magnitude_tolerance = 31;
        // Round 1, left eye reflects round 0's composite.
        w.glint_fingerprints[2] = w.expected_glints[0];
        let c = LivenessCheckCircuit::new(w);
        assert_eq!(
            c.first_failing_check(),
            Some(LivenessFailure { check: LivenessCheck::Corneal, round: 1 })
        );
        assert!(
            !c.test_circuit().expect("satisfiable"),
            "a stale glint must fail on the categorical field, not the tolerances"
        );
    }

    #[test]
    fn test_149_ordinal_tolerance_boundary() {
        let expected = fp(2, 6, 3, 20);
        let mut w = passing_witness();
        w.corneal_enabled = true;
        w.expected_glints = [expected; 3];
        w.glint_fingerprints = [expected; 6];
        // Left eye of round 0: mid_ratio off by exactly 2, magnitude off by 3.
        w.glint_fingerprints[0] = fp(2, 8, 3, 17);
        w.glint_ratio_tolerance = 2;
        w.glint_magnitude_tolerance = 3;
        let c = LivenessCheckCircuit::new(w.clone());
        assert!(c.should_pass());
        assert!(c.test_circuit().expect("satisfiable"), "difference == tolerance passes");

        w.glint_ratio_tolerance = 1;
        let c = LivenessCheckCircuit::new(w.clone());
        assert!(!c.test_circuit().expect("satisfiable"), "ratio difference > tolerance fails");

        w.glint_ratio_tolerance = 2;
        w.glint_magnitude_tolerance = 2;
        let c = LivenessCheckCircuit::new(w);
        assert!(!c.test_circuit().expect("satisfiable"), "magnitude difference > tolerance fails");
    }

    #[test]
    fn test_149_disabled_corneal_check_is_vacuous() {
        let mut w = corneal_witness();
        w.corneal_enabled = false;
        w.glint_fingerprints = [0; NUM_GLINTS];
        let c = LivenessCheckCircuit::new(w);
        assert!(c.test_circuit().expect("satisfiable"));
    }

    #[test]
    fn test_150_glint_is_not_compared_by_hamming() {
        // Prohibited-action test for REQ-123 / BUG-001. Red and blue are
        // Hamming distance 1 apart; a Hamming check at any tolerance ≥ 1 would
        // accept a blue glint against a red challenge.
        let red = quantize_colour(&[255, 0, 0]);
        let blue = quantize_colour(&[0, 0, 255]);
        assert_eq!(hamming_u16(red, blue), 1, "BUG-001 premise");

        let mut w = passing_witness();
        w.corneal_enabled = true;
        w.glint_ratio_tolerance = 15;
        w.glint_magnitude_tolerance = 31;
        w.expected_glints = [red; 3];
        w.glint_fingerprints = [red; 6];
        w.glint_fingerprints[5] = blue;
        let c = LivenessCheckCircuit::new(w);
        assert!(
            !c.test_circuit().expect("satisfiable"),
            "a blue glint against a red challenge must be rejected"
        );
    }

    // -----------------------------------------------------------------
    // TEST-151 — threshold aliasing is unsatisfiable (REQ-124, BUG-002)
    // -----------------------------------------------------------------

    #[test]
    fn test_151_native_recogniser_rejects_out_of_range_fields() {
        let mut w = passing_witness();
        w.responding_patches[0] = 65;
        assert!(w.recognise().is_err());
        let mut w = passing_witness();
        w.min_coverage = 65;
        assert!(w.recognise().is_err());
        let mut w = passing_witness();
        w.glint_ratio_tolerance = 16;
        assert!(w.recognise().is_err());
        let mut w = passing_witness();
        w.glint_magnitude_tolerance = 32;
        assert!(w.recognise().is_err());
        assert!(passing_witness().recognise().is_ok());
    }

    #[test]
    fn test_151_aliased_thresholds_are_unsatisfiable_in_circuit() {
        let honest = passing_witness().field_values();
        let honest_digest = mock_verify_values(&honest).expect("honest witness verifies");

        // BUG-002: (t + 256, s - 1) packs to the same limb as (t, s).
        let mut aliased = honest.clone();
        aliased.color_threshold += 256;
        aliased.spatial_threshold -= 1;
        match mock_verify_values(&aliased) {
            Err(_) => {} // rejected: the range constraint holds
            Ok(d) => panic!(
                "aliased thresholds must be unsatisfiable; got a digest that {} the honest one",
                if d == honest_digest { "equals" } else { "differs from" }
            ),
        }

        // The same for a coverage count above the grammar bound.
        let mut wide = honest.clone();
        wide.responding[0] = 65;
        assert!(mock_verify_values(&wide).is_err(), "coverage above 64 must be unsatisfiable");

        // And for a tolerance above its declared width.
        let mut tol = honest;
        tol.ratio_tol = 16;
        assert!(mock_verify_values(&tol).is_err(), "ratio tolerance above 15 must be unsatisfiable");
    }

    // -----------------------------------------------------------------
    // Real prover round-trips
    // -----------------------------------------------------------------

    fn real_prover_roundtrip(witness: LivenessWitness) -> u64 {
        use halo2_base::halo2_proofs::halo2curves::bn256::{Bn256, G1Affine};
        use halo2_base::halo2_proofs::plonk::{create_proof, keygen_pk, keygen_vk, verify_proof};
        use halo2_base::halo2_proofs::poly::kzg::commitment::{KZGCommitmentScheme, ParamsKZG};
        use halo2_base::halo2_proofs::poly::kzg::multiopen::{ProverSHPLONK, VerifierSHPLONK};
        use halo2_base::halo2_proofs::poly::kzg::strategy::SingleStrategy;
        use halo2_base::halo2_proofs::transcript::{
            Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
        };

        let circuit = LivenessCheckCircuit::new(witness.clone());
        let params = ParamsKZG::<Bn256>::setup(K, rand_core::OsRng);

        let mut builder =
            BaseCircuitBuilder::new(false).use_params(LivenessCheckCircuit::circuit_params());
        let (result, digest) = circuit.build_circuit(&mut builder);
        builder.assigned_instances[0].push(result);
        builder.assigned_instances[0].push(digest);
        let result_value = *result.value();
        let digest_value = *digest.value();
        assert_eq!(digest_value, challenge_digest(&witness), "in-circuit digest must match native");

        let vk = keygen_vk(&params, &builder).expect("vk");
        let pk = keygen_pk(&params, vk.clone(), &builder).expect("pk");

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
        .expect("prove");
        let proof_bytes = transcript.finalize();
        println!("Liveness proof size: {} bytes", proof_bytes.len());

        let mut vt = Blake2bRead::<_, G1Affine, Challenge255<_>>::init(&proof_bytes[..]);
        verify_proof::<KZGCommitmentScheme<Bn256>, VerifierSHPLONK<_>, _, _, _>(
            &params,
            &vk,
            SingleStrategy::new(&params),
            &[&[&public_inputs]],
            &mut vt,
        )
        .expect("verify");

        fr_to_u64(&result_value)
    }

    #[test]
    fn test_liveness_real_prover_roundtrip() {
        assert_eq!(real_prover_roundtrip(passing_witness()), 1);
    }

    #[test]
    fn test_liveness_real_prover_failing_witness() {
        let w = legacy(
            [100, 100, 100, 100, 200, 200, 200, 200, 300, 300, 300, 300],
            [100, 100, 100, 100, 200, 200, 200, 200, 300, 300, 300, 300],
            3,
            1,
            1,
        );
        assert_eq!(real_prover_roundtrip(w), 0);
    }

    #[test]
    fn test_liveness_real_prover_with_all_checks_enabled() {
        let mut w = corneal_witness();
        w.min_coverage = 12;
        w.responding_patches = [16, 14, 12];
        w.min_convexity = 800;
        w.convexity_scores = [1243, 1100, 900];
        w.challenge_id = challenge_identifier(&[1u8; 32], &[2u8; 32]);
        assert_eq!(real_prover_roundtrip(w), 1);
    }

    // -----------------------------------------------------------------
    // OBS-084 — liveness gadget advice cells at the production shape
    // -----------------------------------------------------------------

    #[test]
    fn obs_084_liveness_gadget_advice_cells() {
        let params = BaseCircuitParams {
            k: 16,
            num_advice_per_phase: vec![NUM_ADVICE],
            num_lookup_advice_per_phase: vec![NUM_LOOKUP_ADVICE],
            num_fixed: NUM_FIXED,
            lookup_bits: Some(LOOKUP_BITS),
            num_instance_columns: 1,
        };
        let mut b = BaseCircuitBuilder::<Fr>::new(false).use_params(params);
        let _ = LivenessCheckCircuit::new(LivenessWitness::dummy_pass()).build_circuit(&mut b);
        let cells: usize = b.statistics().gate.total_advice_per_phase.iter().sum();
        println!(
            "OBS-084 liveness gadget advice cells = {cells}, rows = {}",
            cells.div_ceil(NUM_ADVICE)
        );
    }
}
