//! Fuzz target for Pedersen commitment operations (REQ-024)
//!
//! This fuzz target tests Pedersen commitment creation, serialization,
//! and verification with arbitrary inputs.
//!
//! ## Test Coverage
//! - Commitment creation with arbitrary field elements
//! - Serialization and deserialization round-trips
//! - Commitment homomorphism properties
//! - Opening verification
//! - Batch commitment operations

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use blstrs::Scalar as Fr;
use ff::Field;
use sable_core::crypto::pedersen::{
    commit, commit_default, Commitment, CommitmentOpening, Generators,
    batch_commit, batch_verify,
};
use sable_core::COMMITMENT_SIZE;

/// Input structure for fuzzing Pedersen commitments
#[derive(Debug, Arbitrary)]
struct PedersenInput {
    /// Message value as raw bytes (will be converted to Fr)
    message_bytes: [u8; 32],
    /// Randomness value as raw bytes (will be converted to Fr)
    randomness_bytes: [u8; 32],
    /// Test operation type
    operation: CommitmentOperation,
    /// Additional messages for batch operations
    batch_messages: Vec<[u8; 32]>,
    /// Additional randomness for batch operations
    batch_randomness: Vec<[u8; 32]>,
    /// Invalid commitment bytes for deserialization testing
    invalid_bytes: [u8; 48],
}

#[derive(Debug, Arbitrary, Clone, Copy)]
enum CommitmentOperation {
    /// Create and verify single commitment
    Single,
    /// Test serialization round-trip
    SerializeRoundTrip,
    /// Test homomorphic addition
    HomomorphicAdd,
    /// Test scalar multiplication
    ScalarMul,
    /// Test batch commitment
    BatchCommit,
    /// Test invalid deserialization
    InvalidDeserialize,
}

/// Convert arbitrary bytes to a field element
fn bytes_to_fr(bytes: &[u8; 32]) -> Fr {
    // Use the bytes to create a deterministic field element
    // We reduce the bytes modulo the field order
    let mut val = Fr::ZERO;
    for (i, chunk) in bytes.chunks(8).enumerate() {
        let mut arr = [0u8; 8];
        let len = chunk.len().min(8);
        arr[..len].copy_from_slice(&chunk[..len]);
        let u = u64::from_le_bytes(arr);
        val = val + Fr::from(u) * Fr::from((i as u64 + 1) * 256);
    }
    val
}

fuzz_target!(|input: PedersenInput| {
    // Convert input bytes to field elements
    let message = bytes_to_fr(&input.message_bytes);
    let randomness = bytes_to_fr(&input.randomness_bytes);

    // Get generators (should always succeed)
    let generators = Generators::get();

    match input.operation {
        CommitmentOperation::Single => {
            // Test 1: Single commitment creation should not panic
            let commitment = commit(message, randomness, generators);

            // Commitment should be valid (not identity)
            assert!(commitment.is_valid(), "Commitment should be valid");

            // Opening should verify correctly
            let opening = CommitmentOpening::new(message, randomness);
            assert!(opening.verify(&commitment, generators), "Opening must verify");

            // Same inputs should produce same commitment (deterministic)
            let commitment2 = commit(message, randomness, generators);
            assert_eq!(commitment, commitment2, "Commitment must be deterministic");

            // Test with default generators
            let commitment_default = commit_default(message, randomness);
            assert_eq!(commitment, commitment_default, "Default generators should match");
        }

        CommitmentOperation::SerializeRoundTrip => {
            // Test 2: Serialization round-trip
            let commitment = commit(message, randomness, generators);
            let bytes = commitment.to_bytes();

            // Bytes should be correct length
            assert_eq!(bytes.len(), COMMITMENT_SIZE, "Serialized commitment must be 48 bytes");

            // Deserialization should succeed
            let recovered = Commitment::from_bytes(&bytes);
            assert!(recovered.is_ok(), "Deserialization should succeed");
            assert_eq!(commitment, recovered.unwrap(), "Round-trip must preserve commitment");
        }

        CommitmentOperation::HomomorphicAdd => {
            // Test 3: Homomorphic addition property
            // C(m1, r1) + C(m2, r2) = C(m1+m2, r1+r2)
            let mut message_bytes2 = input.message_bytes;
            message_bytes2[0] = message_bytes2[0].wrapping_add(1);
            let message2 = bytes_to_fr(&message_bytes2);

            let mut randomness_bytes2 = input.randomness_bytes;
            randomness_bytes2[0] = randomness_bytes2[0].wrapping_add(1);
            let randomness2 = bytes_to_fr(&randomness_bytes2);

            let c1 = commit(message, randomness, generators);
            let c2 = commit(message2, randomness2, generators);

            let sum_commit = c1.add(&c2);
            let expected_commit = commit(message + message2, randomness + randomness2, generators);

            assert_eq!(sum_commit, expected_commit, "Homomorphic addition must hold");
        }

        CommitmentOperation::ScalarMul => {
            // Test 4: Scalar multiplication
            // k * C(m, r) = C(k*m, k*r)
            let scalar = bytes_to_fr(&input.batch_messages.first()
                .copied()
                .unwrap_or([1u8; 32]));

            let commitment = commit(message, randomness, generators);
            let scaled = commitment.mul_scalar(&scalar);
            let expected = commit(scalar * message, scalar * randomness, generators);

            assert_eq!(scaled, expected, "Scalar multiplication must hold");
        }

        CommitmentOperation::BatchCommit => {
            // Test 5: Batch commitment operations
            if !input.batch_messages.is_empty() && input.batch_messages.len() == input.batch_randomness.len() {
                let messages: Vec<Fr> = input.batch_messages.iter()
                    .map(bytes_to_fr)
                    .collect();
                let randomness_vec: Vec<Fr> = input.batch_randomness.iter()
                    .map(bytes_to_fr)
                    .collect();

                let commitments = batch_commit(&messages, &randomness_vec, generators);
                assert!(commitments.is_ok(), "Batch commit should succeed");

                let commitments = commitments.unwrap();
                assert_eq!(commitments.len(), messages.len(), "Batch size must match");

                // Create openings and verify batch
                let openings: Vec<_> = messages.iter()
                    .zip(randomness_vec.iter())
                    .map(|(&m, &r)| CommitmentOpening::new(m, r))
                    .collect();

                let valid = batch_verify(&commitments, &openings, generators);
                assert!(valid, "Batch verification must succeed");
            }
        }

        CommitmentOperation::InvalidDeserialize => {
            // Test 6: Invalid deserialization should not panic
            let result = Commitment::from_bytes(&input.invalid_bytes);
            // Result may be Ok or Err, but should never panic
            let _ = result;

            // Also test with all-zeros (likely invalid point)
            let zeros = [0u8; 48];
            let result_zeros = Commitment::from_bytes(&zeros);
            let _ = result_zeros;

            // Test with all-ones
            let ones = [0xFF; 48];
            let result_ones = Commitment::from_bytes(&ones);
            let _ = result_ones;
        }
    }
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bytes_to_fr_deterministic() {
        let bytes = [0x42u8; 32];
        let fr1 = bytes_to_fr(&bytes);
        let fr2 = bytes_to_fr(&bytes);
        assert_eq!(fr1, fr2);
    }

    #[test]
    fn test_generators_singleton() {
        let g1 = Generators::get();
        let g2 = Generators::get();
        assert_eq!(g1.g, g2.g);
        assert_eq!(g1.h, g2.h);
    }
}
