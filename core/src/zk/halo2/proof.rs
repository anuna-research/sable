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

/// Circuit parameters for proof generation.
///
/// `K = 16` (vs the original 14). The matcher now computes the Hamming distance
/// *in-circuit* from the two 512-byte embeddings (rather than trusting a
/// precomputed scalar), and additionally binds the enrolled template to its
/// Poseidon commitment. Matcher ~195 cells/byte + ~24k cells for the Poseidon
/// binding ~= 144k advice cells (~36k rows); k=16 (65,536 rows) fits with margin
/// and proves in ~970ms on Apple Silicon (release).
const K: u32 = 16;
const NUM_ADVICE: usize = 4;
const NUM_LOOKUP_ADVICE: usize = 1;
const NUM_FIXED: usize = 1;
const LOOKUP_BITS: usize = 13;

/// Maximum threshold bits for comparison
const MAX_THRESHOLD_BITS: usize = 16;

/// Default embedding length (bytes) the prover's circuit is built for.
///
/// The circuit structure -- and therefore the proving/verifying keys -- depends
/// on the embedding length, so a prover is fixed to one dimension at keygen.
pub const DEFAULT_EMBEDDING_DIM: usize = 512;

/// A generated ZK proof with its public inputs.
#[derive(Clone)]
pub struct Proof {
    /// The serialized proof bytes
    pub proof_bytes: Vec<u8>,
    /// Public inputs: [face_result, threshold, liveness_result, challenge_digest, commitment]
    pub public_inputs: Vec<Fr>,
    /// Whether liveness was proven in ZK (derived from public_inputs[2]).
    pub liveness_passed: bool,
    /// Packed liveness challenge parameters (expected fingerprints + thresholds).
    /// The verifier checks this against independently computed HKDF-derived values.
    pub challenge_digest: Fr,
    /// Poseidon commitment to the enrolled template the proof was generated
    /// against (public_inputs[4]). The verifier checks this equals the value
    /// registered at enrollment, binding the proof to the correct template.
    pub commitment: Fr,
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
    /// Embedding length (bytes) this prover's circuit/keys are built for.
    embedding_dim: usize,
    /// Whether the circuit constrains each byte to be a valid thermometer code.
    /// True for the production thermometer encoding; set false only to prove over
    /// arbitrary (e.g. binary) bytes. Fixed at keygen (it changes the circuit).
    enforce_thermometer: bool,
}

impl FaceVerificationProver {
    /// Create a new prover with fresh setup for the default embedding length,
    /// enforcing thermometer validity (the production configuration).
    pub fn new() -> Self {
        Self::with_config(DEFAULT_EMBEDDING_DIM, true)
    }

    /// Create a new prover fixed to a specific embedding length (bytes),
    /// enforcing thermometer validity.
    pub fn with_embedding_dim(embedding_dim: usize) -> Self {
        Self::with_config(embedding_dim, true)
    }

    /// Create a prover fixed to an embedding length and whether to enforce
    /// thermometer-code validity in-circuit.
    pub fn with_config(embedding_dim: usize, enforce_thermometer: bool) -> Self {
        Self {
            setup: ProofSetup::new(),
            proving_key: None,
            embedding_dim,
            enforce_thermometer,
        }
    }

    /// Create a prover with existing setup (default embedding length).
    pub fn with_setup(setup: ProofSetup) -> Self {
        Self {
            setup,
            proving_key: None,
            embedding_dim: DEFAULT_EMBEDDING_DIM,
            enforce_thermometer: true,
        }
    }

    /// The embedding length (bytes) this prover is fixed to.
    pub fn embedding_dim(&self) -> usize {
        self.embedding_dim
    }

    /// Generate the proving key (done once, cached).
    fn ensure_proving_key(&mut self) -> Result<&ProvingKey<G1Affine>> {
        if self.proving_key.is_none() {
            // Build a dummy circuit for key generation.
            // Must have identical structure to the real circuit (threshold + liveness).
            let mut builder =
                BaseCircuitBuilder::new(false).use_params(self.setup.circuit_params.clone());

            let dummy_witness = LivenessWitness::dummy_pass();
            let dummy_a = vec![0u8; self.embedding_dim];
            let dummy_b = vec![0u8; self.embedding_dim];
            let (face_result, threshold_assigned, liveness_result, liveness_digest, commitment) =
                build_combined_circuit_from_embeddings(
                    &mut builder,
                    &dummy_a,
                    &dummy_b,
                    1,
                    &dummy_witness,
                    self.enforce_thermometer,
                );

            // Public instances: [face, threshold, liveness, challenge_digest, commitment]
            builder.assigned_instances[0].push(face_result);
            builder.assigned_instances[0].push(threshold_assigned);
            builder.assigned_instances[0].push(liveness_result);
            builder.assigned_instances[0].push(liveness_digest);
            builder.assigned_instances[0].push(commitment);

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

    /// Generate a proof that two embeddings match within `threshold` (no liveness).
    ///
    /// Convenience wrapper: synthesizes a pair of `embedding_dim`-byte vectors
    /// whose Hamming distance equals `distance`, then proves over them. The
    /// distance is still *computed in-circuit*, so it cannot be forged -- this
    /// is a test/back-compat shim over [`prove_with_embeddings`].
    pub fn prove(&mut self, distance: u64, threshold: u64) -> Result<Proof> {
        self.prove_with_liveness(distance, threshold, None)
    }

    /// Like [`prove`](Self::prove), optionally including liveness. Synthesizes
    /// embeddings with the given Hamming `distance` and delegates to
    /// [`prove_with_embeddings`](Self::prove_with_embeddings).
    pub fn prove_with_liveness(
        &mut self,
        distance: u64,
        threshold: u64,
        liveness: Option<LivenessWitness>,
    ) -> Result<Proof> {
        let (a, b) = embeddings_with_distance(self.embedding_dim, distance)?;
        self.prove_with_embeddings(&a, &b, threshold, liveness)
    }

    /// Generate a proof that `embedding_a` and `embedding_b` are within
    /// `threshold` Hamming distance, optionally including liveness.
    ///
    /// The distance is computed IN-CIRCUIT from the two byte vectors, closing
    /// the trusted-distance soundness gap (a prover can no longer supply an
    /// arbitrary distance). Both embeddings must be exactly `embedding_dim` bytes.
    ///
    /// Public inputs: `[face_result, threshold, liveness_result, challenge_digest]`
    pub fn prove_with_embeddings(
        &mut self,
        embedding_a: &[u8],
        embedding_b: &[u8],
        threshold: u64,
        liveness: Option<LivenessWitness>,
    ) -> Result<Proof> {
        if embedding_a.len() != self.embedding_dim || embedding_b.len() != self.embedding_dim {
            return Err(SableError::InvalidInput(format!(
                "embeddings must be {} bytes (got {} and {})",
                self.embedding_dim,
                embedding_a.len(),
                embedding_b.len()
            )));
        }

        // Ensure we have a proving key
        let _ = self.ensure_proving_key()?;

        let liveness_witness = liveness.unwrap_or_else(LivenessWitness::dummy_pass);

        // Build the combined circuit, computing the match distance in-circuit.
        let mut builder =
            BaseCircuitBuilder::new(false).use_params(self.setup.circuit_params.clone());

        let (result, threshold_assigned, liveness_result, liveness_digest, commitment) =
            build_combined_circuit_from_embeddings(
                &mut builder,
                embedding_a,
                embedding_b,
                threshold,
                &liveness_witness,
                self.enforce_thermometer,
            );

        // Public instances: [face, threshold, liveness, challenge_digest, commitment]
        builder.assigned_instances[0].push(result);
        builder.assigned_instances[0].push(threshold_assigned);
        builder.assigned_instances[0].push(liveness_result);
        builder.assigned_instances[0].push(liveness_digest);
        builder.assigned_instances[0].push(commitment);

        // Get public input values
        let result_value = *result.value();
        let threshold_value = *threshold_assigned.value();
        let liveness_value = *liveness_result.value();
        let digest_value = *liveness_digest.value();
        let commitment_value = *commitment.value();
        let public_inputs = vec![
            result_value,
            threshold_value,
            liveness_value,
            digest_value,
            commitment_value,
        ];

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
            commitment: commitment_value,
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

        // Extract enrolled-template commitment (fifth public input)
        let commitment = proof.public_inputs.get(4).copied().unwrap_or(Fr::from(0u64));

        Ok(VerificationDetails {
            face_match,
            threshold,
            liveness_passed,
            challenge_digest,
            commitment,
        })
    }

    /// Verify the proof AND that the enrolled template it bound matches the
    /// commitment registered at enrollment.
    ///
    /// Returns `Ok(true)` only if the proof is valid, the face matches, *and* the
    /// proof's commitment equals `registered_commitment`. A cryptographically
    /// valid proof that binds a *different* template than the registered one
    /// returns `Ok(false)` (authentication must fail): this is what stops a prover
    /// from matching against a template other than the one on file.
    pub fn verify_bound(&self, proof: &Proof, registered_commitment: Fr) -> Result<bool> {
        let face_match = self.verify(proof)?;
        let commitment = proof.public_inputs.get(4).copied().unwrap_or(Fr::from(0u64));
        if commitment != registered_commitment {
            return Ok(false);
        }
        Ok(face_match)
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
    /// Poseidon commitment to the enrolled template the proof bound. Check this
    /// against the value registered at enrollment via
    /// [`FaceVerificationVerifier::verify_bound`].
    pub commitment: Fr,
}

/// Synthesize two `dim`-byte vectors whose Hamming distance equals `distance`.
///
/// Used by the test/back-compat `prove`/`prove_with_liveness` shims so they can
/// exercise the in-circuit matcher from a scalar distance. `embedding_a` is all
/// zeros; `embedding_b` has exactly `distance` bits set (whole 0xFF bytes plus a
/// partial byte for the remainder).
fn embeddings_with_distance(dim: usize, distance: u64) -> Result<(Vec<u8>, Vec<u8>)> {
    let max = (dim as u64) * 8;
    if distance > max {
        return Err(SableError::InvalidInput(format!(
            "distance {} exceeds maximum {} for {}-byte embeddings",
            distance, max, dim
        )));
    }
    let a = vec![0u8; dim];
    let mut b = vec![0u8; dim];
    let full = (distance / 8) as usize;
    let rem = (distance % 8) as u8;
    for byte in b.iter_mut().take(full) {
        *byte = 0xFF;
    }
    if rem > 0 {
        b[full] = (1u8 << rem) - 1;
    }
    Ok((a, b))
}

/// Build the combined in-circuit-matcher + commitment-binding + liveness circuit:
///
/// 1. compute the Hamming distance IN-CIRCUIT from the two byte vectors (rather
///    than trusting a precomputed scalar) and compare it against `threshold`;
/// 2. bind the enrolled template to its Poseidon commitment (so a prover cannot
///    swap in a different enrolled template than the one registered); and
/// 3. prove liveness.
///
/// Steps 1-2 close the two soundness gaps: a malicious prover can no longer
/// supply an arbitrary small `distance`, nor prove against an unregistered
/// template. The enrolled bytes are loaded once and reused for both the distance
/// and the commitment.
///
/// Returns (face_result, threshold, liveness_result, challenge_digest,
/// commitment). The circuit structure (and therefore the proving/verifying keys)
/// depends on `embedding_a.len()`, so the keygen dummy must use the same length.
fn build_combined_circuit_from_embeddings(
    builder: &mut BaseCircuitBuilder<Fr>,
    embedding_a: &[u8],
    embedding_b: &[u8],
    threshold: u64,
    liveness: &LivenessWitness,
    enforce_thermometer: bool,
) -> (
    AssignedValue<Fr>,
    AssignedValue<Fr>,
    AssignedValue<Fr>,
    AssignedValue<Fr>,
    AssignedValue<Fr>,
) {
    debug_assert_eq!(embedding_a.len(), embedding_b.len(), "embeddings must match");

    let (face_result, threshold_assigned, commitment) = {
        let ctx = builder.main(0);
        let gate = GateChip::<Fr>::default();

        // Load the enrolled bytes ONCE; reuse them for both the distance and the
        // commitment so the two are bound to the same witness.
        let a_cells: Vec<AssignedValue<Fr>> = embedding_a
            .iter()
            .map(|&a| ctx.load_witness(Fr::from(a as u64)))
            .collect();

        // --- In-circuit Hamming distance: sum of per-byte XOR popcounts. ---
        // With `enforce_thermometer`, additionally constrain every byte to be a
        // valid thermometer code (set bits contiguous from the LSB), so the prover
        // cannot fake an ordinal L1 distance with a non-unary byte. The bits are
        // decomposed once and reused for both the validity check and the popcount.
        let bits = super::thermometer::BITS_PER_DIM;
        let mut distance = ctx.load_constant(Fr::from(0u64));
        for (&a_cell, &b) in a_cells.iter().zip(embedding_b.iter()) {
            let b_val = ctx.load_witness(Fr::from(b as u64));
            let contrib = if enforce_thermometer {
                let a_bits = super::hamming::decompose_to_bits(ctx, &gate, a_cell, bits);
                let b_bits = super::hamming::decompose_to_bits(ctx, &gate, b_val, bits);
                super::thermometer::enforce_thermometer(ctx, &gate, &a_bits);
                super::thermometer::enforce_thermometer(ctx, &gate, &b_bits);
                super::hamming::xor_popcount_from_bits(ctx, &gate, &a_bits, &b_bits)
            } else {
                super::hamming::xor_popcount(ctx, &gate, a_cell, b_val)
            };
            distance = gate.add(ctx, distance, contrib);
        }

        // --- Threshold check against the COMPUTED distance (not a trusted input). ---
        let threshold_assigned = ctx.load_witness(Fr::from(threshold));
        let face_result = compare_less_than_or_equal(ctx, &gate, distance, threshold_assigned);

        // --- Commitment binding: prove Poseidon(pack(enrolled)) == public. ---
        let commitment = super::poseidon::poseidon_commit_bytes(ctx, &gate, &a_cells);

        (face_result, threshold_assigned, commitment)
    };

    // --- Liveness check ---
    let liveness_circuit = LivenessCheckCircuit::new(liveness.clone());
    let (liveness_result, liveness_digest) = liveness_circuit.build_circuit(builder);

    (
        face_result,
        threshold_assigned,
        liveness_result,
        liveness_digest,
        commitment,
    )
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
        assert_eq!(proof.public_inputs.len(), 5, "Should have 5 public inputs (incl. commitment)");

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

    /// TEST-142 (SPEC-006 NFR-104): the composed production circuit at the
    /// 512-byte dimension must stay within 8,000 rows of the 0.1.0 shape, which
    /// measured 54,042 rows. Counted at k=17 so the builder never hits a
    /// capacity assert while counting.
    #[test]
    fn test_142_composed_circuit_row_budget_nfr_104() {
        const ROWS_0_1_0: usize = 54_042;
        const BUDGET_ROWS: usize = 8_000;
        let params = BaseCircuitParams {
            k: 17,
            num_advice_per_phase: vec![NUM_ADVICE],
            num_lookup_advice_per_phase: vec![NUM_LOOKUP_ADVICE],
            num_fixed: NUM_FIXED,
            lookup_bits: Some(LOOKUP_BITS),
            num_instance_columns: 1,
        };
        let mut bld = BaseCircuitBuilder::<Fr>::new(false).use_params(params);
        let a = vec![0u8; DEFAULT_EMBEDDING_DIM];
        let b = vec![0u8; DEFAULT_EMBEDDING_DIM];
        let dummy = LivenessWitness::dummy_pass();
        let _ = build_combined_circuit_from_embeddings(&mut bld, &a, &b, 2048, &dummy, true);
        let cells: usize = bld.statistics().gate.total_advice_per_phase.iter().sum();
        let rows = cells.div_ceil(NUM_ADVICE);
        println!("OBS-084 composed circuit: cells={cells} rows={rows} (0.1.0 rows={ROWS_0_1_0})");
        assert!(
            rows <= ROWS_0_1_0 + BUDGET_ROWS,
            "NFR-104: {rows} rows exceeds {ROWS_0_1_0} + {BUDGET_ROWS}"
        );
        assert!(rows + 128 <= 1 << 16, "must still fit k=16 with blinding margin");
    }

    #[test]
    fn test_prove_with_liveness_passing() {
        let mut prover = FaceVerificationProver::new();

        let liveness = LivenessWitness {
            delta_fingerprints: [0x0014, 0xA014, 0x6014, 0xC014, 0x0014, 0xA014, 0x6014, 0xC014, 0x0014, 0xA014, 0x6014, 0xC014],
            expected_fingerprints: [0x0014, 0xA014, 0x6014, 0xC014, 0x0014, 0xA014, 0x6014, 0xC014, 0x0014, 0xA014, 0x6014, 0xC014],
            color_threshold: 3,
            spatial_threshold: 2,
            min_magnitude: 5,
            ..LivenessWitness::default()
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

        // Liveness fails: same quadrants per round (no spatial diff)
        let liveness = LivenessWitness {
            delta_fingerprints: [100, 100, 100, 100, 200, 200, 200, 200, 300, 300, 300, 300],
            expected_fingerprints: [100, 100, 100, 100, 200, 200, 200, 200, 300, 300, 300, 300],
            color_threshold: 3,
            spatial_threshold: 1,
            min_magnitude: 1,
            ..LivenessWitness::default()
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
            delta_fingerprints: [0x0014, 0xA014, 0x6014, 0xC014, 0x0014, 0xA014, 0x6014, 0xC014, 0x0014, 0xA014, 0x6014, 0xC014],
            expected_fingerprints: [0x0014, 0xA014, 0x6014, 0xC014, 0x0014, 0xA014, 0x6014, 0xC014, 0x0014, 0xA014, 0x6014, 0xC014],
            color_threshold: 3,
            spatial_threshold: 2,
            min_magnitude: 5,
            ..LivenessWitness::default()
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

        // Contention-tolerant regression guards. This test runs inside the
        // parallel suite, where ~10 multithreaded k=16 proves contend for cores
        // and inflate each prove's wall-clock several-fold. The bounds below only
        // catch order-of-magnitude regressions (e.g. an accidental k=17 circuit);
        // the authoritative, tight timing numbers (~500ms prove, ~2ms verify) are
        // asserted by `spike_in_circuit_matcher`, which runs in isolation.
        #[cfg(not(debug_assertions))]
        {
            assert!(prove_only_with.as_millis() < 5000, "Prove regression: >5s (expected ~500ms isolated)");
            assert!(verify_time.as_millis() < 250, "Verify regression: >250ms (expected ~2ms isolated)");
        }
        assert!(proof_with.meets_size_requirement(), "Proof should be ≤10KB");
    }

    /// Phase 1 spike: measure the full in-circuit circuit (matcher + Poseidon
    /// commitment binding), exactly as production builds it.
    ///
    /// Confirms (a) distance is computed in-circuit and binds the result
    /// (soundness: distance > threshold cannot be proved as a pass), and
    /// (b) the real cell/k/proving cost at the 512-byte production dimension
    /// (k=16, ~970ms). Run explicitly (slow):
    ///   cargo test --features halo2 -p sable-core --lib --release \
    ///     zk::halo2::proof::tests::spike_in_circuit_matcher -- --ignored --nocapture
    #[test]
    #[ignore = "spike: slow, run explicitly with --ignored --nocapture"]
    fn spike_in_circuit_matcher() {
        use std::time::Instant;

        fn params_at(k: u32) -> BaseCircuitParams {
            BaseCircuitParams {
                k: k as usize,
                num_advice_per_phase: vec![NUM_ADVICE],
                num_lookup_advice_per_phase: vec![NUM_LOOKUP_ADVICE],
                num_fixed: NUM_FIXED,
                lookup_bits: Some(LOOKUP_BITS),
                num_instance_columns: 1,
            }
        }

        // Build the in-circuit combined circuit, push instances, return builder.
        fn build(k: u32, a: &[u8], b: &[u8], thr: u64) -> (BaseCircuitBuilder<Fr>, Vec<Fr>) {
            let dummy = LivenessWitness::dummy_pass();
            let mut bld = BaseCircuitBuilder::new(false).use_params(params_at(k));
            let (fr, th, lr, ld, cm) =
                build_combined_circuit_from_embeddings(&mut bld, a, b, thr, &dummy, true);
            let pubs = vec![*fr.value(), *th.value(), *lr.value(), *ld.value(), *cm.value()];
            for v in [fr, th, lr, ld, cm] {
                bld.assigned_instances[0].push(v);
            }
            (bld, pubs)
        }

        // Full keygen + prove + verify pipeline; returns (cells, keygen_ms, prove_ms,
        // verify_ms, proof_len, face_pass, verify_ok).
        fn run(k: u32, a: &[u8], b: &[u8], thr: u64) -> (usize, f64, f64, f64, usize, bool, bool) {
            let params = ParamsKZG::<Bn256>::setup(k, rand_core::OsRng);

            // Keygen uses a same-length dummy (structure depends on embedding length).
            let dummy_a = vec![0u8; a.len()];
            let dummy_b = vec![0u8; a.len()];
            let (kb, _) = build(k, &dummy_a, &dummy_b, thr);
            let cells: usize = kb.statistics().gate.total_advice_per_phase.iter().sum();
            let t = Instant::now();
            let vk = keygen_vk(&params, &kb).expect("vk");
            let pk = keygen_pk(&params, vk.clone(), &kb).expect("pk");
            let keygen_ms = t.elapsed().as_secs_f64() * 1000.0;

            let (bld, pubs) = build(k, a, b, thr);
            let face_pass = pubs[0] == Fr::from(1u64);

            let t = Instant::now();
            let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);
            create_proof::<KZGCommitmentScheme<Bn256>, ProverSHPLONK<_>, _, _, _, _>(
                &params, &pk, &[bld], &[&[&pubs]], rand_core::OsRng, &mut transcript,
            )
            .expect("prove");
            let proof = transcript.finalize();
            let prove_ms = t.elapsed().as_secs_f64() * 1000.0;

            let t = Instant::now();
            let strategy = SingleStrategy::new(&params);
            let mut vt = Blake2bRead::<_, G1Affine, Challenge255<_>>::init(&proof[..]);
            let ok = verify_proof::<KZGCommitmentScheme<Bn256>, VerifierSHPLONK<_>, _, _, _>(
                &params, &vk, strategy, &[&[&pubs]], &mut vt,
            )
            .is_ok();
            let verify_ms = t.elapsed().as_secs_f64() * 1000.0;

            (cells, keygen_ms, prove_ms, verify_ms, proof.len(), face_pass, ok)
        }

        // dim bytes, first `diff` bytes set to 0xFF => Hamming distance = diff*8.
        let make = |dim: usize, diff: usize| -> (Vec<u8>, Vec<u8>) {
            let a = vec![0u8; dim];
            let mut b = vec![0u8; dim];
            for x in b.iter_mut().take(diff.min(dim)) {
                *x = 0xFF;
            }
            (a, b)
        };

        println!("\n=== SPIKE: in-circuit matcher ===");

        // (1) Correctness + soundness at dim=64, k=14 (fits comfortably).
        let (a, b) = make(64, 10); // distance 80 <= 200 -> pass
        let (cells, kg, pv, vf, plen, fpass, ok) = run(14, &a, &b, 200);
        println!("dim=64  k=14  cells={cells}  keygen={kg:.0}ms  prove={pv:.0}ms  verify={vf:.1}ms  proof={plen}B  pass={fpass}  verify_ok={ok}");
        assert!(ok, "proof must verify");
        assert!(fpass, "distance 80 <= 200 must pass");

        let (a, b) = make(64, 40); // distance 320 > 200 -> MUST fail (soundness)
        let (.., fpass2, ok2) = run(14, &a, &b, 200);
        println!("dim=64  k=14  distance=320 thr=200 -> pass={fpass2}  verify_ok={ok2}  (soundness: distance is computed, not trusted)");
        assert!(ok2, "proof must verify");
        assert!(!fpass2, "distance 320 > 200 must NOT pass -- in-circuit distance binds the result");

        // (2) Cell-count scaling -> minimum k for each dimension.
        println!("--- cell scaling (k derived with 20% headroom) ---");
        let mut k_for_512 = 14u32;
        for &dim in &[64usize, 128, 256, 512] {
            let (a, b) = make(dim, dim / 8);
            let (bld, _) = build(17, &a, &b, 200); // count at large k to avoid capacity asserts
            let cells: usize = bld.statistics().gate.total_advice_per_phase.iter().sum();
            let min_rows = cells.div_ceil(NUM_ADVICE);
            // True minimal k: rows must cover the advice cells plus a small
            // blinding/lookup-table margin (halo2 reserves a handful of rows).
            let mut k = LOOKUP_BITS as u32 + 1;
            while (1usize << k) < min_rows + 128 {
                k += 1;
            }
            println!("dim={dim:<4} cells={cells:<8} min_rows={min_rows:<8} -> k>={k}");
            if dim == 512 {
                k_for_512 = k;
            }
        }

        // (3) Decisive number: real prove at the 512-byte production dimension.
        let (a, b) = make(512, 64); // distance 512 (< 2048 threshold @ 50%) -> pass
        let (cells, kg, pv, vf, plen, fpass, ok) = run(k_for_512, &a, &b, 2048);
        println!("dim=512 k={k_for_512}  cells={cells}  keygen={kg:.0}ms  prove={pv:.0}ms  verify={vf:.1}ms  proof={plen}B  pass={fpass}  verify_ok={ok}");
        assert!(ok && fpass, "512-dim production-shape proof must verify and pass");
        assert_eq!(k_for_512, 16, "512-byte matcher + commitment binding must fit k=16");
        // Authoritative timing bounds (isolated, release). Generous vs the ~970ms
        // observed to tolerate slower CI hardware, but tight enough to catch a
        // regression to k=17+ (multi-second) territory.
        #[cfg(not(debug_assertions))]
        {
            assert!(pv < 1800.0, "isolated prove should be <1.8s (observed ~970ms), got {pv:.0}ms");
            assert!(vf < 50.0, "isolated verify should be <50ms (observed ~2ms), got {vf:.1}ms");
            assert!(plen <= 10 * 1024, "proof should be <=10KB");
        }
        println!("=== end spike ===\n");
    }

    /// task-bind-commitment soundness: a proof bound to one enrolled template
    /// must NOT verify against a different registered commitment.
    #[test]
    fn test_commitment_binding_rejects_wrong_template() {
        // Two distinct enrolled templates of VALID thermometer codes (levels 0..=8),
        // so they pass the in-circuit validity constraint, yet commit differently.
        use crate::zk::halo2::thermometer::level_to_byte;
        let enrolled: Vec<u8> =
            (0..DEFAULT_EMBEDDING_DIM).map(|i| level_to_byte((i % 9) as u8)).collect();
        let other: Vec<u8> =
            (0..DEFAULT_EMBEDDING_DIM).map(|i| level_to_byte(((i + 4) % 9) as u8)).collect();
        let registered = crate::zk::halo2::poseidon::poseidon_commit_bytes_value(&enrolled);
        let registered_other = crate::zk::halo2::poseidon::poseidon_commit_bytes_value(&other);
        assert_ne!(registered, registered_other, "distinct templates must commit differently");

        // Prove a match against the enrolled template (live == enrolled -> distance 0).
        let mut prover = FaceVerificationProver::new();
        let proof = prover
            .prove_with_embeddings(&enrolled, &enrolled, 2048, None)
            .expect("proof should generate");

        // The proof's commitment must equal the natively-registered value: the
        // in-circuit Poseidon agrees with poseidon_commit_bytes_value.
        assert_eq!(proof.commitment, registered, "in-circuit commitment must match native");

        let verifier =
            FaceVerificationVerifier::from_prover(&mut prover).expect("verifier");
        // Bound check against the correct registration passes...
        assert!(
            verifier.verify_bound(&proof, registered).expect("verify"),
            "proof must verify against the template it was bound to"
        );
        // ...but against a DIFFERENT registered commitment it must fail, even
        // though the proof is itself cryptographically valid.
        assert!(
            !verifier.verify_bound(&proof, registered_other).expect("verify"),
            "proof must NOT verify against a different enrolled template"
        );
    }
}
