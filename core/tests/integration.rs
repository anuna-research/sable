//! Integration tests for SABLE core functionality
//! 
//! These tests verify the complete biometric commitment workflow
//! and ensure all components work together correctly.

use sable_core::{
    crypto::{
        poseidon::{poseidon_hash, normalize_features},
        pedersen::{Commitment, CommitmentOpening, Generators, commit_with_opening},
        bls381::{Bls12381, Fr},
        rng::SecureRng,
    },
    FEATURE_VECTOR_SIZE,
};
use rand_core::RngCore;

/// Test the complete biometric commitment workflow
#[test] 
fn test_biometric_commitment_workflow() {
    // Step 1: Simulate biometric feature extraction
    let mut raw_features = vec![0.0f32; FEATURE_VECTOR_SIZE];
    
    // Fill with realistic biometric-like data
    for (i, feature) in raw_features.iter_mut().enumerate() {
        *feature = ((i * 13 + 37) % 200) as f32 / 100.0 - 1.0; // Range [-1, 1]
    }
    
    // Step 2: Normalize the features (z-score normalization)
    let normalized_features = normalize_features(&raw_features).expect("Normalization should succeed");
    
    // Verify normalization worked
    let mean: f32 = normalized_features.iter().sum::<f32>() / normalized_features.len() as f32;
    assert!(mean.abs() < 0.01, "Mean should be near zero");
    
    // Step 3: Hash the normalized features using Poseidon
    let feature_hash = poseidon_hash(&normalized_features).expect("Poseidon hash should succeed");
    
    // Step 4: Create a Pedersen commitment
    let opening = CommitmentOpening::new_with_random_salt(feature_hash)
        .expect("Should create opening with random salt");
        
    let generators = Generators::new().expect("Should derive generators");
    let commitment = commit_with_opening(&opening, &generators);
    
    // Step 5: Verify the commitment
    assert!(commitment.is_valid(), "Commitment should be valid");
    assert!(opening.verify(&commitment, &generators), "Opening should verify");
    
    // Step 6: Test serialization/deserialization
    let commitment_bytes = commitment.to_bytes();
    let recovered_commitment = Commitment::from_bytes(&commitment_bytes)
        .expect("Should deserialize commitment");
    assert_eq!(commitment, recovered_commitment, "Serialization should be lossless");
    
    // Step 7: Test that same features produce same commitment (deterministic)
    let second_hash = poseidon_hash(&normalized_features).expect("Second hash should succeed");
    assert_eq!(feature_hash, second_hash, "Hash should be deterministic");
    
    let second_commitment = commit_with_opening(&opening, &generators);
    assert_eq!(commitment, second_commitment, "Commitment should be deterministic");
}

/// Test biometric template matching scenario
#[test]
fn test_biometric_template_matching() {
    // Simulate enrolled template
    let mut enrolled_features = [0.0f32; FEATURE_VECTOR_SIZE];
    for (i, feature) in enrolled_features.iter_mut().enumerate() {
        *feature = (i as f32).sin() * 0.8; // Smooth pattern
    }
    
    // Normalize and commit to enrolled template
    let normalized_enrolled = normalize_features(&enrolled_features).unwrap();
    let enrolled_hash = poseidon_hash(&normalized_enrolled).unwrap();
    let enrolled_opening = CommitmentOpening::new_with_random_salt(enrolled_hash).unwrap();
    let enrolled_commitment = commit_with_opening(&enrolled_opening, &Generators::default());
    
    // Simulate live capture (similar but with some noise)
    let mut live_features = enrolled_features;
    // Add small noise using our secure RNG
    let mut rng = SecureRng::new().unwrap();
    for feature in &mut live_features {
        let noise = ((rng.next_u32() as f32) / (u32::MAX as f32) - 0.5) * 0.01;
        *feature += noise;
    }
    
    let normalized_live = normalize_features(&live_features).unwrap();
    let live_hash = poseidon_hash(&normalized_live).unwrap();
    let live_opening = CommitmentOpening::new_with_random_salt(live_hash).unwrap();
    let live_commitment = commit_with_opening(&live_opening, &Generators::default());
    
    // In a real system, the commitments would be different due to noise
    // but the zk-SNARK would prove they're within threshold
    assert_ne!(enrolled_commitment, live_commitment, 
               "Different features should produce different commitments");
    
    // Both commitments should be valid
    assert!(enrolled_commitment.is_valid());
    assert!(live_commitment.is_valid());
}

/// Test commitment homomorphic properties
#[test]
fn test_commitment_homomorphism() {
    let generators = Generators::new().unwrap();
    
    // Create two commitments
    let msg1 = Fr::from(100u64);
    let rand1 = Fr::from(200u64);
    let opening1 = CommitmentOpening::new(msg1, rand1);
    let commit1 = commit_with_opening(&opening1, &generators);
    
    let msg2 = Fr::from(300u64);
    let rand2 = Fr::from(400u64);
    let opening2 = CommitmentOpening::new(msg2, rand2);
    let commit2 = commit_with_opening(&opening2, &generators);
    
    // Test additive homomorphism: C1 + C2 = commit(m1+m2, r1+r2)
    let sum_commit = commit1.add(&commit2);
    let expected_opening = CommitmentOpening::new(msg1 + msg2, rand1 + rand2);
    let expected_commit = commit_with_opening(&expected_opening, &generators);
    
    assert_eq!(sum_commit, expected_commit, "Additive homomorphism should hold");
}

/// Test error handling and edge cases
#[test]
fn test_error_handling() {
    // Test invalid feature vector size
    let wrong_size_features = vec![0.0f32; 100]; // Wrong size
    assert!(normalize_features(&wrong_size_features).is_err());
    
    // Test features with infinite values
    let mut invalid_features = [0.0f32; FEATURE_VECTOR_SIZE];
    invalid_features[0] = f32::INFINITY;
    assert!(poseidon_hash(&invalid_features).is_err());
    
    // Test zero variance features
    let zero_variance_features = [1.0f32; FEATURE_VECTOR_SIZE]; // All same value
    assert!(normalize_features(&zero_variance_features).is_err());
    
    // Test invalid commitment bytes
    let invalid_bytes = [0u8; 48]; // All zeros
    assert!(Commitment::from_bytes(&invalid_bytes).is_err());
}

/// Test cryptographic security properties
#[test]
fn test_security_properties() {
    let generators = Generators::new().unwrap();
    
    // Test that generators are independent
    generators.verify().expect("Generators should be independent");
    assert_ne!(generators.g, generators.h, "Generators should be different");
    
    // Test commitment binding: different messages -> different commitments
    let same_randomness = Fr::from(42u64);
    let msg1 = Fr::from(1u64);
    let msg2 = Fr::from(2u64);
    
    let commit1 = sable_core::crypto::pedersen::commit(msg1, same_randomness, &generators);
    let commit2 = sable_core::crypto::pedersen::commit(msg2, same_randomness, &generators);
    
    assert_ne!(commit1, commit2, "Different messages should give different commitments");
    
    // Test commitment hiding: same message, different randomness -> different commitments  
    let same_message = Fr::from(42u64);
    let rand1 = Fr::from(1u64);
    let rand2 = Fr::from(2u64);
    
    let commit3 = sable_core::crypto::pedersen::commit(same_message, rand1, &generators);
    let commit4 = sable_core::crypto::pedersen::commit(same_message, rand2, &generators);
    
    assert_ne!(commit3, commit4, "Different randomness should give different commitments");
}

/// Test performance constraints
#[test]
fn test_performance_constraints() {
    use std::time::Instant;
    
    // Test that key operations complete within reasonable time
    let features = [0.1f32; FEATURE_VECTOR_SIZE];
    
    // Poseidon hash should be reasonably fast (production implementation)
    // Note: Debug builds are much slower, so we use a more lenient threshold
    let start = Instant::now();
    let _hash = poseidon_hash(&features).unwrap();
    let hash_duration = start.elapsed();
    #[cfg(debug_assertions)]
    let max_hash_ms = 5000; // Debug builds are ~10x slower
    #[cfg(not(debug_assertions))]
    let max_hash_ms = 500;
    assert!(hash_duration.as_millis() < max_hash_ms, "Hash should complete in <{}ms", max_hash_ms);
    
    // Commitment should be fast
    let start = Instant::now();
    let randomness = Bls12381::random_scalar().unwrap();
    let _commitment = sable_core::crypto::pedersen::commit_default(_hash, randomness);
    let commit_duration = start.elapsed();
    #[cfg(debug_assertions)]
    let max_commit_ms = 500; // Debug builds are slower
    #[cfg(not(debug_assertions))]
    let max_commit_ms = 50;
    assert!(commit_duration.as_millis() < max_commit_ms, "Commitment should complete in <{}ms", max_commit_ms);
    
    // Serialization should be fast
    let start = Instant::now();
    let _bytes = _commitment.to_bytes();
    let serialize_duration = start.elapsed();
    #[cfg(debug_assertions)]
    let max_serialize_ms = 10; // Debug builds are slower
    #[cfg(not(debug_assertions))]
    let max_serialize_ms = 1;
    assert!(serialize_duration.as_millis() < max_serialize_ms, "Serialization should complete in <{}ms", max_serialize_ms);
}

/// Test thread safety and concurrent usage
#[test]
fn test_concurrent_usage() {
    use std::sync::Arc;
    use std::thread;
    
    let generators = Arc::new(Generators::new().unwrap());
    let mut handles = vec![];
    
    // Spawn multiple threads doing concurrent operations
    for i in 0..4 {
        let generators_clone = Arc::clone(&generators);
        let handle = thread::spawn(move || {
            let features = [i as f32 * 0.1; FEATURE_VECTOR_SIZE];
            let hash = poseidon_hash(&features).unwrap();
            let randomness = Bls12381::random_scalar().unwrap();
            let commitment = sable_core::crypto::pedersen::commit(hash, randomness, &generators_clone);
            commitment
        });
        handles.push(handle);
    }
    
    // Collect results
    let commitments: Vec<_> = handles.into_iter()
        .map(|h| h.join().unwrap())
        .collect();
    
    // All commitments should be valid and different
    for commitment in &commitments {
        assert!(commitment.is_valid());
    }
    
    // All should be different (different inputs)
    for i in 0..commitments.len() {
        for j in i+1..commitments.len() {
            assert_ne!(commitments[i], commitments[j]);
        }
    }
}

/// Test deterministic behavior
#[test]
fn test_deterministic_behavior() {
    // Same inputs should always produce same outputs
    let features = [0.123f32; FEATURE_VECTOR_SIZE];
    let message = Fr::from(42u64);
    let randomness = Fr::from(123u64);
    
    // Multiple runs should be identical
    for _ in 0..5 {
        let hash1 = poseidon_hash(&features).unwrap();
        let hash2 = poseidon_hash(&features).unwrap();
        assert_eq!(hash1, hash2, "Hash should be deterministic");
        
        let commit1 = sable_core::crypto::pedersen::commit_default(message, randomness);
        let commit2 = sable_core::crypto::pedersen::commit_default(message, randomness);
        assert_eq!(commit1, commit2, "Commitment should be deterministic");
        
        let generators1 = Generators::new().unwrap();
        let generators2 = Generators::new().unwrap();
        assert_eq!(generators1, generators2, "Generators should be deterministic");
    }
}
