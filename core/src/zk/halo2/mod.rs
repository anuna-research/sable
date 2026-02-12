//! # Halo2 Zero-Knowledge Proof Circuits
//!
//! This module contains Halo2-based ZK circuits for SABLE face verification.
//! Halo2 provides transparent setup (no trusted ceremony required).
//!
//! ## Overview
//!
//! The Halo2 implementation provides privacy-preserving face verification:
//!
//! 1. **Quantization**: Convert f64 embeddings to u8 bytes
//! 2. **Hamming Distance**: Count differing bits between embeddings
//! 3. **Threshold Check**: Prove distance ≤ threshold without revealing distance
//! 4. **Proof Generation**: Create compact SNARK proofs (~2KB)
//!
//! ## Modules
//!
//! - [`hello`] - Hello world circuit for validation and benchmarking
//! - [`quantizer`] - f64 to u8 feature quantization (CON-003)
//! - [`poseidon`] - Poseidon hash circuit for commitments (REQ-004)
//! - [`hamming`] - Hamming distance calculation in ZK (REQ-005)
//! - [`threshold`] - Threshold configuration and calibration (REQ-006)
//! - [`threshold_check`] - Threshold comparison circuit (REQ-007)
//! - [`proof`] - Real proof generation and verification (REQ-008)
//!
//! ## Quick Start
//!
//! ```rust,ignore
//! use sable_core::zk::halo2::{
//!     FaceVerificationProver, FaceVerificationVerifier,
//!     FeatureQuantizer, hamming_distance, ThresholdConfig,
//! };
//!
//! // 1. Quantize embeddings
//! let enrolled = FeatureQuantizer::quantize(&enrolled_f64);
//! let live = FeatureQuantizer::quantize(&live_f64);
//!
//! // 2. Calculate Hamming distance
//! let distance = hamming_distance(&enrolled, &live);
//!
//! // 3. Get threshold (50% similarity)
//! let config = ThresholdConfig::new(enrolled.len(), 0.5);
//! let threshold = config.max_hamming_distance();
//!
//! // 4. Generate ZK proof
//! let mut prover = FaceVerificationProver::new();
//! let proof = prover.prove(distance, threshold)?;
//!
//! // 5. Verify proof
//! let verifier = FaceVerificationVerifier::from_prover(&mut prover)?;
//! let is_match = verifier.verify(&proof)?;
//! ```
//!
//! ## Why Halo2?
//!
//! - **Transparent setup**: No trusted ceremony required (vs Groth16)
//! - **Flexible**: PLONKish arithmetization allows efficient custom gates
//! - **Proven**: Used in production systems (Zcash, Scroll, Axiom)
//!
//! ## Performance (Release Mode, Apple Silicon)
//!
//! | Operation | Time | Target |
//! |-----------|------|--------|
//! | Proof Generation (face + liveness) | ~250ms | ≤1000ms (NFR-001) |
//! | Verification | ~1.8ms | ≤50ms (NFR-002) |
//! | Proof Size | 2.08KB | ≤10KB (NFR-003) |
//!
//! ## Security Properties
//!
//! - **Zero-Knowledge**: Distance value is private
//! - **Soundness**: False proofs have negligible probability
//! - **Completeness**: Valid inputs always produce valid proofs

pub mod hamming;
pub mod hello;
pub mod liveness;
pub mod poseidon;
pub mod proof;
pub mod quantizer;
pub mod threshold;
pub mod threshold_check;

#[cfg(test)]
mod tests;

pub use hamming::{HammingDistanceCircuit, hamming_distance, hamming_similarity, MAX_EMBEDDING_DIM};
pub use hello::HelloCircuit;
pub use poseidon::{PoseidonCircuit, poseidon_hash_pair};
pub use proof::{FaceVerificationProver, FaceVerificationVerifier, Proof, ProofSetup, VerificationDetails};
pub use quantizer::{FeatureQuantizer, QuantizedEmbedding, FACE_EMBEDDING_DIM};
pub use threshold::{ThresholdConfig, VerificationResult, precomputed};
pub use threshold_check::{ThresholdCheckCircuit, FaceVerificationCircuit};
pub use liveness::{LivenessCheckCircuit, LivenessWitness, LivenessResult};

// Re-export types needed for external use
pub use halo2_base::halo2_proofs::halo2curves::bn256::Fr as Halo2Fr;
