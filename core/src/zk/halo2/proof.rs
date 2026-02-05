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
    /// Public inputs (threshold checked, threshold value)
    pub public_inputs: Vec<Fr>,
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
            // Build a dummy circuit for key generation
            let mut builder =
                BaseCircuitBuilder::new(false).use_params(self.setup.circuit_params.clone());

            // Build the threshold check circuit structure
            build_threshold_check_circuit(&mut builder, 0, 1);

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

    /// Generate a proof that distance <= threshold.
    ///
    /// # Arguments
    /// * `distance` - The computed Hamming distance (private)
    /// * `threshold` - The maximum allowed distance (public)
    ///
    /// # Returns
    /// * `Ok(Proof)` - The generated proof
    /// * `Err` if proof generation fails
    pub fn prove(&mut self, distance: u64, threshold: u64) -> Result<Proof> {
        // Ensure we have a proving key
        let _ = self.ensure_proving_key()?;

        // Build the actual circuit with real values
        let mut builder =
            BaseCircuitBuilder::new(false).use_params(self.setup.circuit_params.clone());

        let (result, threshold_assigned) =
            build_threshold_check_circuit(&mut builder, distance, threshold);

        // Set public instances
        builder.assigned_instances[0].push(result);
        builder.assigned_instances[0].push(threshold_assigned);

        // Get public input values
        let result_value = *result.value();
        let threshold_value = *threshold_assigned.value();
        let public_inputs = vec![result_value, threshold_value];

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
}

/// Build the threshold check circuit.
///
/// Returns (result, threshold) where result is 1 if distance <= threshold.
fn build_threshold_check_circuit(
    builder: &mut BaseCircuitBuilder<Fr>,
    distance: u64,
    threshold: u64,
) -> (AssignedValue<Fr>, AssignedValue<Fr>) {
    let ctx = builder.main(0);
    let gate = GateChip::<Fr>::default();

    // Load distance as private witness
    let distance_assigned = ctx.load_witness(Fr::from(distance));

    // Load threshold (will be public)
    let threshold_assigned = ctx.load_witness(Fr::from(threshold));

    // Compute comparison
    let result = compare_less_than_or_equal(ctx, &gate, distance_assigned, threshold_assigned);

    (result, threshold_assigned)
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
}
