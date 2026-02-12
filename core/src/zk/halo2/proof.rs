//! # Proof Generator (REQ-008)
//!
//! Generates real ZK proofs for face verification using Halo2.
//!
//! ## Overview
//!
//! This module provides the complete proof generation pipeline:
//! 1. Setup: Generate proving and verification keys
//! 2. Prove: Create a proof given private witnesses
//! 3. Verify: Validate a proof against public inputs
//!
//! ## Security Properties
//!
//! - **Zero-Knowledge**: Proof reveals nothing about private inputs
//! - **Soundness**: False proofs cannot be created (except with negligible probability)
//! - **Completeness**: Valid inputs always produce valid proofs
//!
//! ## Performance Targets (NFR-001, NFR-002, NFR-003)
//!
//! - Proof generation: ≤1000ms
//! - Verification: ≤50ms
//! - Proof size: ≤10KB

use halo2_base::gates::circuit::builder::BaseCircuitBuilder;
use halo2_base::gates::circuit::BaseCircuitParams;
use halo2_base::gates::GateChip;
use halo2_base::gates::GateInstructions;
use halo2_base::halo2_proofs::halo2curves::bn256::{Bn256, Fr, G1Affine};
use halo2_base::halo2_proofs::plonk::{
    create_proof, keygen_pk, keygen_vk, verify_proof, ProvingKey, VerifyingKey,
};
use halo2_base::halo2_proofs::poly::kzg::commitment::{KZGCommitmentScheme, ParamsKZG};
use halo2_base::halo2_proofs::poly::kzg::multiopen::{ProverSHPLONK, VerifierSHPLONK};
use halo2_base::halo2_proofs::poly::kzg::strategy::SingleStrategy;
use halo2_base::halo2_proofs::transcript::{
    Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
};
use halo2_base::AssignedValue;

use crate::error::{Result, SableError};
use super::liveness::{LivenessCheckCircuit, LivenessWitness};

/// Circuit parameters for proof generation
const K: u32 = 14;
const NUM_ADVICE: usize = 4;
const NUM_LOOKUP_ADVICE: usize = 1;
const NUM_FIXED: usize = 1;
const LOOKUP_BITS: usize = 13;

/// Maximum threshold bits for comparison
const MAX_THRESHOLD_BITS: usize = 16;

/// A generated ZK proof with its public inputs.
#[derive(Clone)]
pub struct Proof {
    /// The serialized proof bytes
    pub proof_bytes: Vec<u8>,
    /// Public inputs: [face_result, threshold, liveness_result, challenge_digest]
    pub public_inputs: Vec<Fr>,
    /// Whether liveness was proven in ZK (derived from public_inputs[2]).
    pub liveness_passed: bool,
    /// Packed liveness challenge parameters (expected fingerprints + thresholds).
    /// The verifier checks this against independently computed HKDF-derived values.
    pub challenge_digest: Fr,
}

impl Proof {
    /// Get the proof size in bytes.
    pub fn size(&self) -> usize {
        self.proof_bytes.len()
    }

    /// Check if proof meets size requirement (≤10KB).
    pub fn meets_size_requirement(&self) -> bool {
        self.size() <= 10 * 1024
    }
}

/// Setup parameters for the proof system.
pub struct ProofSetup {
    /// KZG parameters (trusted setup)
    params: ParamsKZG<Bn256>,
    /// Circuit parameters
    circuit_params: BaseCircuitParams,
}

impl ProofSetup {
    /// Create new setup parameters.
    ///
    /// This generates the trusted setup parameters for the proof system.
    /// In production, this would use a ceremony or existing trusted setup.
    pub fn new() -> Self {
        let params = ParamsKZG::<Bn256>::setup(K, rand_core::OsRng);
        let circuit_params = BaseCircuitParams {
            k: K as usize,
            num_advice_per_phase: vec![NUM_ADVICE],
            num_lookup_advice_per_phase: vec![NUM_LOOKUP_ADVICE],
            num_fixed: NUM_FIXED,
            lookup_bits: Some(LOOKUP_BITS),
            num_instance_columns: 1,
        };
        Self {
            params,
            circuit_params,
        }
    }

    /// Get the KZG parameters.
    pub fn params(&self) -> &ParamsKZG<Bn256> {
        &self.params
    }

    /// Get the circuit parameters.
    pub fn circuit_params(&self) -> &BaseCircuitParams {
        &self.circuit_params
    }
}

impl Default for ProofSetup {
    fn default() -> Self {
        Self::new()
    }
}

/// Face verification prover.
///
/// Generates ZK proofs that a face matches within threshold.
pub struct FaceVerificationProver {
    /// Setup parameters
    setup: ProofSetup,
    /// Proving key (generated on first use)
    proving_key: Option<ProvingKey<G1Affine>>,
}

impl FaceVerificationProver {
    /// Create a new prover with fresh setup.
    pub fn new() -> Self {
        Self {
            setup: ProofSetup::new(),
            proving_key: None,
        }
    }

    /// Create a prover with existing setup.
    pub fn with_setup(setup: ProofSetup) -> Self {
        Self {
            setup,
            proving_key: None,
        }
    }

    /// Generate the proving key (done once, cached).
    fn ensure_proving_key(&mut self) -> Result<&ProvingKey<G1Affine>> {
        if self.proving_key.is_none() {
            // Build a dummy circuit for key generation.
            // Must have identical structure to the real circuit (threshold + liveness).
            let mut builder =
                BaseCircuitBuilder::new(false).use_params(self.setup.circuit_params.clone());

            let dummy_witness = LivenessWitness::dummy_pass();
            let (face_result, threshold_assigned, liveness_result, liveness_digest) =
                build_combined_circuit(&mut builder, 0, 1, &dummy_witness);

            // Set public instances: [face_result, threshold, liveness_result, challenge_digest]
            builder.assigned_instances[0].push(face_result);
            builder.assigned_instances[0].push(threshold_assigned);
            builder.assigned_instances[0].push(liveness_result);
            builder.assigned_instances[0].push(liveness_digest);

            // Generate verification key
            let vk = keygen_vk(&self.setup.params, &builder).map_err(|e| {
                SableError::ProofGeneration(format!("Failed to generate verification key: {:?}", e))
            })?;

            // Generate proving key
            let pk = keygen_pk(&self.setup.params, vk, &builder).map_err(|e| {
                SableError::ProofGeneration(format!("Failed to generate proving key: {:?}", e))
            })?;

            self.proving_key = Some(pk);
        }

        Ok(self.proving_key.as_ref().unwrap())
    }

    /// Generate a proof that distance <= threshold (without liveness).
    ///
    /// Backwards-compatible: liveness_result defaults to 1 (pass).
    pub fn prove(&mut self, distance: u64, threshold: u64) -> Result<Proof> {
        self.prove_with_liveness(distance, threshold, None)
    }

    /// Generate a proof that distance <= threshold, optionally including liveness.
    ///
    /// Public inputs: `[face_result, threshold, liveness_result, challenge_digest]`
    /// - When `liveness` is `None`, liveness_result = 1 (backwards compatible)
    /// - When `liveness` is `Some(witness)`, liveness_result = circuit output
    /// - `challenge_digest` is always present, packing the liveness parameters
    pub fn prove_with_liveness(
        &mut self,
        distance: u64,
        threshold: u64,
        liveness: Option<LivenessWitness>,
    ) -> Result<Proof> {
        // Ensure we have a proving key
        let _ = self.ensure_proving_key()?;

        let liveness_witness = liveness.unwrap_or_else(LivenessWitness::dummy_pass);

        // Build the combined circuit with real values
        let mut builder =
            BaseCircuitBuilder::new(false).use_params(self.setup.circuit_params.clone());

        let (result, threshold_assigned, liveness_result, liveness_digest) =
            build_combined_circuit(&mut builder, distance, threshold, &liveness_witness);

        // Set public instances: [face_result, threshold, liveness_result, challenge_digest]
        builder.assigned_instances[0].push(result);
        builder.assigned_instances[0].push(threshold_assigned);
        builder.assigned_instances[0].push(liveness_result);
        builder.assigned_instances[0].push(liveness_digest);

        // Get public input values
        let result_value = *result.value();
        let threshold_value = *threshold_assigned.value();
        let liveness_value = *liveness_result.value();
        let digest_value = *liveness_digest.value();
        let public_inputs = vec![result_value, threshold_value, liveness_value, digest_value];

        // Extract liveness result
        let liveness_bytes = liveness_value.to_bytes();
        let liveness_u64 = u64::from_le_bytes(liveness_bytes[0..8].try_into().unwrap());

        // Create transcript for proof
        let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);

        // Generate proof
        create_proof::<KZGCommitmentScheme<Bn256>, ProverSHPLONK<_>, _, _, _, _>(
            &self.setup.params,
            self.proving_key.as_ref().unwrap(),
            &[builder],
            &[&[&public_inputs]],
            rand_core::OsRng,
            &mut transcript,
        )
        .map_err(|e| SableError::ProofGeneration(format!("Failed to create proof: {:?}", e)))?;

        let proof_bytes = transcript.finalize();

        Ok(Proof {
            proof_bytes,
            public_inputs,
            liveness_passed: liveness_u64 == 1,
            challenge_digest: digest_value,
        })
    }

    /// Get the verification key.
    pub fn verification_key(&mut self) -> Result<VerifyingKey<G1Affine>> {
        let pk = self.ensure_proving_key()?;
        Ok(pk.get_vk().clone())
    }
}

impl Default for FaceVerificationProver {
    fn default() -> Self {
        Self::new()
    }
}

/// Face verification verifier.
///
/// Verifies ZK proofs of face matching.
pub struct FaceVerificationVerifier<'a> {
    /// Reference to KZG parameters (must match prover's setup)
    params: &'a ParamsKZG<Bn256>,
    /// Verification key
    verification_key: VerifyingKey<G1Affine>,
}

impl<'a> FaceVerificationVerifier<'a> {
    /// Create a verifier from a prover (shares the same setup).
    pub fn from_prover(prover: &'a mut FaceVerificationProver) -> Result<Self> {
        let vk = prover.verification_key()?;
        Ok(Self {
            params: prover.setup.params(),
            verification_key: vk,
        })
    }

    /// Create a verifier with explicit params and verification key.
    pub fn new(params: &'a ParamsKZG<Bn256>, verification_key: VerifyingKey<G1Affine>) -> Self {
        Self {
            params,
            verification_key,
        }
    }

    /// Verify a proof.
    ///
    /// # Arguments
    /// * `proof` - The proof to verify
    ///
    /// # Returns
    /// * `Ok(true)` if verification passes and result is true (match)
    /// * `Ok(false)` if verification passes but result is false (no match)
    /// * `Err` if verification fails
    pub fn verify(&self, proof: &Proof) -> Result<bool> {
        // Create transcript for verification
        let mut transcript =
            Blake2bRead::<_, G1Affine, Challenge255<_>>::init(&proof.proof_bytes[..]);

        // Create verification strategy
        let strategy = SingleStrategy::new(self.params);

        // Verify the proof
        verify_proof::<KZGCommitmentScheme<Bn256>, VerifierSHPLONK<_>, _, _, _>(
            self.params,
            &self.verification_key,
            strategy,
            &[&[&proof.public_inputs]],
            &mut transcript,
        )
        .map_err(|e| SableError::ProofVerification(format!("Proof verification failed: {:?}", e)))?;

        // Extract the result (first public input: 1 = match, 0 = no match)
        let result_bytes = proof.public_inputs[0].to_bytes();
        let result = u64::from_le_bytes(result_bytes[0..8].try_into().unwrap());

        Ok(result == 1)
    }

    /// Verify a proof and return the threshold used.
    pub fn verify_with_threshold(&self, proof: &Proof) -> Result<(bool, u64)> {
        let result = self.verify(proof)?;

        // Extract threshold (second public input)
        let threshold_bytes = proof.public_inputs[1].to_bytes();
        let threshold = u64::from_le_bytes(threshold_bytes[0..8].try_into().unwrap());

        Ok((result, threshold))
    }

    /// Verify a proof and return full details including liveness.
    pub fn verify_full(&self, proof: &Proof) -> Result<VerificationDetails> {
        let face_match = self.verify(proof)?;

        let threshold_bytes = proof.public_inputs[1].to_bytes();
        let threshold = u64::from_le_bytes(threshold_bytes[0..8].try_into().unwrap());

        // Extract liveness result (third public input)
        let liveness_passed = if proof.public_inputs.len() > 2 {
            let liveness_bytes = proof.public_inputs[2].to_bytes();
            u64::from_le_bytes(liveness_bytes[0..8].try_into().unwrap()) == 1
        } else {
            true // backwards compatible: old proofs without liveness default to pass
        };

        // Extract challenge digest (fourth public input)
        let challenge_digest = if proof.public_inputs.len() > 3 {
            proof.public_inputs[3]
        } else {
            Fr::from(0u64)
        };

        Ok(VerificationDetails {
            face_match,
            threshold,
            liveness_passed,
            challenge_digest,
        })
    }
}

/// Full verification result including face match and liveness status.
#[derive(Debug, Clone)]
pub struct VerificationDetails {
    /// Whether face verification passed (distance <= threshold).
    pub face_match: bool,
    /// The threshold value used.
    pub threshold: u64,
    /// Whether liveness was verified in ZK.
    pub liveness_passed: bool,
    /// Packed liveness challenge parameters (public input from the proof).
    /// The verifier checks this against independently computed HKDF-derived values.
    pub challenge_digest: Fr,
}

/// Build the combined threshold check + liveness circuit.
///
/// Returns (face_result, threshold, liveness_result, challenge_digest).
fn build_combined_circuit(
    builder: &mut BaseCircuitBuilder<Fr>,
    distance: u64,
    threshold: u64,
    liveness: &LivenessWitness,
) -> (AssignedValue<Fr>, AssignedValue<Fr>, AssignedValue<Fr>, AssignedValue<Fr>) {
    // --- Threshold check ---
    let ctx = builder.main(0);
    let gate = GateChip::<Fr>::default();

    let distance_assigned = ctx.load_witness(Fr::from(distance));
    let threshold_assigned = ctx.load_witness(Fr::from(threshold));
    let face_result = compare_less_than_or_equal(ctx, &gate, distance_assigned, threshold_assigned);

    // --- Liveness check ---
    let liveness_circuit = LivenessCheckCircuit::new(liveness.clone());
    let (liveness_result, liveness_digest) = liveness_circuit.build_circuit(builder);

    (face_result, threshold_assigned, liveness_result, liveness_digest)
}

/// Compare if a <= b (same as threshold_check.rs implementation).
fn compare_less_than_or_equal(
    ctx: &mut halo2_base::Context<Fr>,
    gate: &GateChip<Fr>,
    a: AssignedValue<Fr>,
    b: AssignedValue<Fr>,
) -> AssignedValue<Fr> {
    let a_val = *a.value();
    let b_val = *b.value();

    let a_bytes = a_val.to_bytes();
    let b_bytes = b_val.to_bytes();
    let a_u64 = u64::from_le_bytes(a_bytes[0..8].try_into().unwrap());
    let b_u64 = u64::from_le_bytes(b_bytes[0..8].try_into().unwrap());

    let result_val = if a_u64 <= b_u64 { 1u64 } else { 0u64 };
    let result = ctx.load_witness(Fr::from(result_val));

    // Boolean constraint
    let one = ctx.load_constant(Fr::from(1u64));
    let result_minus_one = gate.sub(ctx, result, one);
    let bool_check = gate.mul(ctx, result, result_minus_one);
    let zero = ctx.load_constant(Fr::from(0u64));
    ctx.constrain_equal(&bool_check, &zero);

    // Decomposition verification
    let b_minus_a = gate.sub(ctx, b, a);
    let a_minus_b = gate.sub(ctx, a, b);
    let a_minus_b_minus_1 = gate.sub(ctx, a_minus_b, one);
    let one_minus_result = gate.sub(ctx, one, result);

    let term1 = gate.mul(ctx, result, b_minus_a);
    let term2 = gate.mul(ctx, one_minus_result, a_minus_b_minus_1);
    let diff = gate.add(ctx, term1, term2);

    let diff_val = *diff.value();
    let diff_bytes = diff_val.to_bytes();
    let diff_u64 = u64::from_le_bytes(diff_bytes[0..8].try_into().unwrap());

    let bits: Vec<AssignedValue<Fr>> = (0..MAX_THRESHOLD_BITS)
        .map(|i| {
            let bit = ((diff_u64 >> i) & 1) as u64;
            ctx.load_witness(Fr::from(bit))
        })
        .collect();

    for &bit in &bits {
        let bit_minus_one = gate.sub(ctx, bit, one);
        let product = gate.mul(ctx, bit, bit_minus_one);
        ctx.constrain_equal(&product, &zero);
    }

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

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::liveness::challenge_digest;

    #[test]
    fn test_proof_setup() {
        let setup = ProofSetup::new();
        assert_eq!(setup.circuit_params().k, K as usize);
    }

    #[test]
    fn test_prover_creation() {
        let prover = FaceVerificationProver::new();
        assert!(prover.proving_key.is_none()); // Key generated lazily
    }

    #[test]
    fn test_prove_and_verify_passing() {
        let mut prover = FaceVerificationProver::new();

        // Distance below threshold should pass
        let proof = prover.prove(100, 200).expect("Proof generation should succeed");

        // Proof should meet size requirement
        println!("Proof size: {} bytes", proof.size());
        assert!(proof.meets_size_requirement(), "Proof should be ≤10KB");

        // Verify the proof using the same prover's setup
        let verifier =
            FaceVerificationVerifier::from_prover(&mut prover).expect("Should create verifier");

        let result = verifier.verify(&proof).expect("Verification should succeed");
        assert!(result, "Should verify as match (distance <= threshold)");
    }

    #[test]
    fn test_prove_and_verify_failing() {
        let mut prover = FaceVerificationProver::new();

        // Distance above threshold should fail
        let proof = prover.prove(300, 200).expect("Proof generation should succeed");

        let verifier =
            FaceVerificationVerifier::from_prover(&mut prover).expect("Should create verifier");

        let result = verifier.verify(&proof).expect("Verification should succeed");
        assert!(!result, "Should verify as no match (distance > threshold)");
    }

    #[test]
    fn test_verify_with_threshold() {
        let mut prover = FaceVerificationProver::new();
        let proof = prover.prove(50, 100).expect("Should generate proof");

        let verifier =
            FaceVerificationVerifier::from_prover(&mut prover).expect("Should create verifier");

        let (result, threshold) = verifier
            .verify_with_threshold(&proof)
            .expect("Should verify");

        assert!(result, "Should pass");
        assert_eq!(threshold, 100, "Threshold should be 100");
    }

    #[test]
    fn test_proof_at_boundary() {
        let mut prover = FaceVerificationProver::new();

        // Exactly at threshold
        let proof = prover.prove(100, 100).expect("Should generate proof");

        let verifier =
            FaceVerificationVerifier::from_prover(&mut prover).expect("Should create verifier");

        let result = verifier.verify(&proof).expect("Should verify");
        assert!(result, "Distance == threshold should pass");
    }

    #[test]
    fn test_proof_just_over_boundary() {
        let mut prover = FaceVerificationProver::new();

        // Just over threshold
        let proof = prover.prove(101, 100).expect("Should generate proof");

        let verifier =
            FaceVerificationVerifier::from_prover(&mut prover).expect("Should create verifier");

        let result = verifier.verify(&proof).expect("Should verify");
        assert!(!result, "Distance > threshold should fail");
    }

    #[test]
    fn test_prove_backwards_compatible_liveness() {
        // prove() without liveness should still work and set liveness_passed = true
        let mut prover = FaceVerificationProver::new();
        let proof = prover.prove(100, 200).expect("Should generate proof");

        assert!(proof.liveness_passed, "Backwards-compatible prove should have liveness_passed=true");
        assert_eq!(proof.public_inputs.len(), 4, "Should have 4 public inputs");

        // challenge_digest should match dummy witness
        let dummy_digest = challenge_digest(&LivenessWitness::dummy_pass());
        assert_eq!(proof.challenge_digest, dummy_digest, "Digest should match dummy witness");

        let verifier =
            FaceVerificationVerifier::from_prover(&mut prover).expect("Should create verifier");
        let details = verifier.verify_full(&proof).expect("Should verify");
        assert!(details.face_match, "Face should match");
        assert!(details.liveness_passed, "Liveness should pass");
        assert_eq!(details.threshold, 200);
        assert_eq!(details.challenge_digest, dummy_digest, "Verification details should include digest");
    }

    #[test]
    fn test_prove_with_liveness_passing() {
        let mut prover = FaceVerificationProver::new();

        let liveness = LivenessWitness {
            delta_fingerprints: [0x0014, 0xA014, 0x4014, 0xA014, 0xA014, 0x0014],
            expected_fingerprints: [0x0014, 0xA014, 0x4014, 0xA014, 0xA014, 0x0014],
            color_threshold: 3,
            spatial_threshold: 2,
            min_magnitude: 5,
        };

        let expected_digest = challenge_digest(&liveness);

        let proof = prover
            .prove_with_liveness(100, 200, Some(liveness))
            .expect("Should generate proof with liveness");

        assert!(proof.liveness_passed, "Liveness should pass");
        assert_eq!(proof.challenge_digest, expected_digest, "Digest should match liveness witness");

        let verifier =
            FaceVerificationVerifier::from_prover(&mut prover).expect("Should create verifier");
        let details = verifier.verify_full(&proof).expect("Should verify");
        assert!(details.face_match, "Face should match");
        assert!(details.liveness_passed, "Liveness should pass in verification");
        assert_eq!(details.challenge_digest, expected_digest, "Verification digest should match");
    }

    #[test]
    fn test_prove_with_liveness_failing() {
        let mut prover = FaceVerificationProver::new();

        // Liveness fails: same upper/lower (no spatial diff)
        let liveness = LivenessWitness {
            delta_fingerprints: [100, 100, 200, 200, 300, 300],
            expected_fingerprints: [100, 100, 200, 200, 300, 300],
            color_threshold: 3,
            spatial_threshold: 1,
            min_magnitude: 1,
        };

        let proof = prover
            .prove_with_liveness(100, 200, Some(liveness))
            .expect("Should generate proof even with failing liveness");

        assert!(!proof.liveness_passed, "Liveness should fail");

        let verifier =
            FaceVerificationVerifier::from_prover(&mut prover).expect("Should create verifier");
        let details = verifier.verify_full(&proof).expect("Should verify");
        assert!(details.face_match, "Face should still match");
        assert!(!details.liveness_passed, "Liveness should fail in verification");
    }

    #[test]
    fn test_perf_with_vs_without_liveness() {
        use std::time::Instant;

        // Measure with liveness
        let start = Instant::now();
        let mut prover_with = FaceVerificationProver::new();
        let liveness = LivenessWitness {
            delta_fingerprints: [0x0014, 0xA014, 0x4014, 0xA014, 0xA014, 0x0014],
            expected_fingerprints: [0x0014, 0xA014, 0x4014, 0xA014, 0xA014, 0x0014],
            color_threshold: 3,
            spatial_threshold: 2,
            min_magnitude: 5,
        };
        let proof_with = prover_with
            .prove_with_liveness(100, 200, Some(liveness))
            .expect("Should succeed");
        let keygen_plus_prove_with = start.elapsed();

        // Second prove (cached PK) to measure steady-state
        let start2 = Instant::now();
        let liveness2 = LivenessWitness::dummy_pass();
        let proof_with2 = prover_with
            .prove_with_liveness(50, 200, Some(liveness2))
            .expect("Should succeed");
        let prove_only_with = start2.elapsed();

        // Verify
        let start3 = Instant::now();
        let verifier = FaceVerificationVerifier::from_prover(&mut prover_with)
            .expect("Should create verifier");
        let details = verifier.verify_full(&proof_with2).expect("Should verify");
        let verify_time = start3.elapsed();

        println!("=== Performance with Liveness ===");
        println!("  Keygen + Prove: {:.1}ms", keygen_plus_prove_with.as_secs_f64() * 1000.0);
        println!("  Prove only:     {:.1}ms", prove_only_with.as_secs_f64() * 1000.0);
        println!("  Verify:         {:.1}ms", verify_time.as_secs_f64() * 1000.0);
        println!("  Proof size:     {} bytes", proof_with.size());
        println!("  Face match:     {}", details.face_match);
        println!("  Liveness ZK:    {}", details.liveness_passed);

        // Assertions (only meaningful in release mode, generous for debug)
        #[cfg(not(debug_assertions))]
        {
            assert!(prove_only_with.as_millis() < 1000, "Prove should be <1000ms in release");
            assert!(verify_time.as_millis() < 50, "Verify should be <50ms in release");
        }
        assert!(proof_with.meets_size_requirement(), "Proof should be ≤10KB");
    }
}
