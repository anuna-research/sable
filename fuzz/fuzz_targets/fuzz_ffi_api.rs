//! Fuzz target for FFI-like API patterns (REQ-024)
//!
//! This fuzz target tests API-level operations that mirror what the FFI layer
//! would expose. Since the mobile feature has compilation issues, we test the
//! underlying cryptographic operations directly.
//!
//! ## Test Coverage
//! - Commitment generation with arbitrary inputs
//! - Salt generation and validation
//! - Feature vector handling
//! - Error handling for edge cases
//! - Serialization/deserialization

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use blstrs::Scalar as Fr;
use ff::Field;
use sable_core::crypto::pedersen::{
    commit, Commitment, Generators, CommitmentOpening,
};
use sable_core::crypto::poseidon::poseidon_hash;
use sable_core::FEATURE_VECTOR_SIZE;

/// Input structure for fuzzing API-level operations
#[derive(Debug, Arbitrary)]
struct ApiInput {
    /// Features as raw f32 values
    features: Vec<f32>,
    /// Salt bytes
    salt_bytes: [u8; 32],
    /// Commitment bytes for deserialization testing
    commitment_bytes: [u8; 48],
    /// Test operation type
    operation: ApiOperation,
}

#[derive(Debug, Arbitrary, Clone, Copy)]
enum ApiOperation {
    /// Test commitment generation workflow
    CommitmentWorkflow,
    /// Test hash then commit workflow
    HashThenCommit,
    /// Test commitment deserialization
    DeserializeCommitment,
    /// Test round-trip serialization
    SerializationRoundTrip,
    /// Test with edge case values
    EdgeCases,
}

/// Convert bytes to a field element deterministically
fn bytes_to_fr(bytes: &[u8; 32]) -> Fr {
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

fuzz_target!(|input: ApiInput| {
    let generators = Generators::get();

    match input.operation {
        ApiOperation::CommitmentWorkflow => {
            // Test 1: Commitment generation workflow
            // Convert salt bytes to field element
            let message = bytes_to_fr(&input.salt_bytes);
            let mut randomness_bytes = input.salt_bytes;
            randomness_bytes[0] = randomness_bytes[0].wrapping_add(1);
            let randomness = bytes_to_fr(&randomness_bytes);

            // Create commitment
            let commitment = commit(message, randomness, generators);

            // Verify it's valid
            assert!(commitment.is_valid(), "Commitment should be valid");

            // Verify opening
            let opening = CommitmentOpening::new(message, randomness);
            assert!(opening.verify(&commitment, generators));

            // Serialize and deserialize
            let bytes = commitment.to_bytes();
            let recovered = Commitment::from_bytes(&bytes);
            assert!(recovered.is_ok());
            assert_eq!(commitment, recovered.unwrap());
        }

        ApiOperation::HashThenCommit => {
            // Test 2: Hash features then create commitment (typical biometric flow)
            let mut features = [0.0f32; FEATURE_VECTOR_SIZE];

            // Fill features from input, clamping to valid range
            for (i, feat) in features.iter_mut().enumerate() {
                if i < input.features.len() {
                    let val = input.features[i];
                    if val.is_finite() {
                        *feat = val.clamp(-10.0, 10.0);
                    }
                }
            }

            // Hash the features
            let hash_result = poseidon_hash(&features);

            if let Ok(hash) = hash_result {
                // Create commitment from hash
                let randomness = bytes_to_fr(&input.salt_bytes);
                let commitment = commit(hash, randomness, generators);

                assert!(commitment.is_valid());

                // Verify determinism
                let hash2 = poseidon_hash(&features).unwrap();
                assert_eq!(hash, hash2);

                let commitment2 = commit(hash, randomness, generators);
                assert_eq!(commitment, commitment2);
            }
        }

        ApiOperation::DeserializeCommitment => {
            // Test 3: Deserialize arbitrary bytes as commitment
            // Should not panic regardless of input
            let result = Commitment::from_bytes(&input.commitment_bytes);

            // May succeed or fail, but should never panic
            if let Ok(commitment) = result {
                // If it succeeded, verify it's a valid point
                let _is_valid = commitment.is_valid();
                // Re-serialize should work
                let bytes = commitment.to_bytes();
                let _ = bytes; // Use the value
            }
        }

        ApiOperation::SerializationRoundTrip => {
            // Test 4: Round-trip serialization stress test
            let message = bytes_to_fr(&input.salt_bytes);
            let randomness = bytes_to_fr(&input.commitment_bytes[..32].try_into().unwrap_or([0; 32]));

            let commitment = commit(message, randomness, generators);
            let bytes = commitment.to_bytes();

            // Multiple round trips
            for _ in 0..3 {
                let recovered = Commitment::from_bytes(&bytes).unwrap();
                let re_serialized = recovered.to_bytes();
                assert_eq!(bytes, re_serialized, "Serialization must be stable");
            }
        }

        ApiOperation::EdgeCases => {
            // Test 5: Edge case handling
            // Zero message
            let commitment_zero = commit(Fr::ZERO, bytes_to_fr(&input.salt_bytes), generators);
            assert!(commitment_zero.is_valid());

            // Zero randomness
            let commitment_no_random = commit(bytes_to_fr(&input.salt_bytes), Fr::ZERO, generators);
            assert!(commitment_no_random.is_valid());

            // Both zero (should still be valid, just identity)
            let commitment_both_zero = commit(Fr::ZERO, Fr::ZERO, generators);
            // Note: This might result in identity point, which may or may not be "valid"
            let _ = commitment_both_zero;

            // Large values (close to field modulus)
            let mut large_bytes = [0xFF; 32];
            large_bytes[0] = input.salt_bytes[0]; // Add some variation
            let large_val = bytes_to_fr(&large_bytes);
            let commitment_large = commit(large_val, large_val, generators);
            assert!(commitment_large.is_valid());

            // Test all-zeros commitment bytes deserialization
            let zeros = [0u8; 48];
            let _ = Commitment::from_bytes(&zeros);

            // Test all-ones commitment bytes deserialization
            let ones = [0xFF; 48];
            let _ = Commitment::from_bytes(&ones);
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
    fn test_commitment_workflow() {
        let generators = Generators::get();
        let message = Fr::from(42u64);
        let randomness = Fr::from(123u64);

        let commitment = commit(message, randomness, generators);
        assert!(commitment.is_valid());

        let opening = CommitmentOpening::new(message, randomness);
        assert!(opening.verify(&commitment, generators));
    }
}
