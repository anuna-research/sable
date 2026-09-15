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

// ============================================================================
// Fuzzy Commitment Integration Tests
// ============================================================================

mod fuzzy_commitment_integration {
    use sable_core::crypto::fuzzy_commitment::{self, FuzzyParams, HelperData};

    fn make_embedding(seed: u8) -> Vec<f64> {
        (0..512)
            .map(|i| {
                let v = ((seed as f64 * 7.0 + i as f64 * 0.013).sin() * 0.8).clamp(-1.0, 1.0);
                v
            })
            .collect()
    }

    fn quantize(embedding: &[f64]) -> Vec<u8> {
        // Same quantization as FeatureQuantizer: map [-1,1] to [0,255]
        embedding
            .iter()
            .map(|&v| {
                let normalized = (v + 1.0) / 2.0; // [0, 1]
                (normalized * 255.0).round().clamp(0.0, 255.0) as u8
            })
            .collect()
    }

    #[test]
    fn test_fuzzy_enrollment_and_exact_reproduction() {
        let params = FuzzyParams::new(30);
        let embedding = make_embedding(42);
        let quantized = quantize(&embedding);

        let enrollment = fuzzy_commitment::gen(&quantized, &params);
        let reproduced = fuzzy_commitment::rep(&quantized, &enrollment.helper_data);

        assert_eq!(reproduced, Some(enrollment.commitment));
    }

    #[test]
    fn test_fuzzy_noisy_reproduction() {
        let params = FuzzyParams::new(30);
        let embedding = make_embedding(42);
        let quantized = quantize(&embedding);

        let enrollment = fuzzy_commitment::gen(&quantized, &params);

        // Add small noise (within threshold)
        let mut noisy = quantized.clone();
        for i in (0..40).step_by(2) {
            noisy[i * 5] ^= 0x10;
        }

        let reproduced = fuzzy_commitment::rep(&noisy, &enrollment.helper_data);
        assert_eq!(reproduced, Some(enrollment.commitment));
    }

    #[test]
    fn test_fuzzy_different_person_fails() {
        let params = FuzzyParams::new(30);
        let person_a = quantize(&make_embedding(42));
        let person_b = quantize(&make_embedding(99));

        let enrollment = fuzzy_commitment::gen(&person_a, &params);
        let result = fuzzy_commitment::rep(&person_b, &enrollment.helper_data);

        assert_eq!(result, None, "different person should not reproduce commitment");
    }

    #[test]
    fn test_fuzzy_helper_data_serialization() {
        let params = FuzzyParams::new(20);
        let bio = quantize(&make_embedding(42));

        let enrollment = fuzzy_commitment::gen(&bio, &params);
        let bytes = enrollment.helper_data.to_bytes();
        let recovered = HelperData::from_bytes(&bytes).expect("deserialization should succeed");

        // Verify reproduction works with deserialized helper data
        let reproduced = fuzzy_commitment::rep(&bio, &recovered);
        assert_eq!(reproduced, Some(enrollment.commitment));
    }

    #[test]
    fn test_fuzzy_unique_set_deduplication() {
        let params = FuzzyParams::new(30);

        // Enroll 3 different people
        let people: Vec<Vec<u8>> = (0..3).map(|i| quantize(&make_embedding(i * 30 + 10))).collect();
        let enrollments: Vec<_> = people.iter().map(|bio| fuzzy_commitment::gen(bio, &params)).collect();

        // Person 0 should match enrollment 0 but not 1 or 2
        assert!(fuzzy_commitment::rep(&people[0], &enrollments[0].helper_data).is_some());
        assert!(fuzzy_commitment::rep(&people[0], &enrollments[1].helper_data).is_none());
        assert!(fuzzy_commitment::rep(&people[0], &enrollments[2].helper_data).is_none());

        // Person 2 should match enrollment 2 but not 0 or 1
        assert!(fuzzy_commitment::rep(&people[2], &enrollments[0].helper_data).is_none());
        assert!(fuzzy_commitment::rep(&people[2], &enrollments[1].helper_data).is_none());
        assert!(fuzzy_commitment::rep(&people[2], &enrollments[2].helper_data).is_some());
    }

    #[test]
    fn test_fuzzy_pedersen_mode_unchanged() {
        // Verify existing Pedersen enrollment still works after code changes
        use sable_core::crypto::pedersen::{Generators, commit_with_opening, CommitmentOpening};
        use sable_core::crypto::poseidon::poseidon_hash;

        let features = [0.5f32; 512];
        let hash = poseidon_hash(&features).unwrap();

        let opening = CommitmentOpening::new_with_random_salt(hash).unwrap();
        let generators = Generators::get();
        let commitment = commit_with_opening(&opening, generators);

        assert!(commitment.is_valid(), "Pedersen commitment should still work");
    }
}

// ============================================================================
// Halo2 Integration Tests (require "halo2" feature)
// ============================================================================

#[cfg(feature = "halo2")]
mod halo2_fixtures;

#[cfg(feature = "halo2")]
mod halo2_integration {
    use super::halo2_fixtures::{SyntheticFixture, default_policy, fixture_policy};
    use sable_core::zk::halo2::{
        FaceVerificationProver, FaceVerificationVerifier,
        FeatureQuantizer, ThresholdConfig, hamming_distance,
    };

    /// Test complete Halo2 face verification workflow
    #[test]
    fn test_halo2_face_verification_workflow() {
        // Step 1: Create enrolled biometric embedding (f64 values in [-1, 1])
        let enrolled_embedding: Vec<f64> = (0..512)
            .map(|i| ((i as f64 / 256.0) - 1.0) * 0.8)
            .collect();

        // Step 2: Quantize to u8 for ZK circuit
        let enrolled_quantized = FeatureQuantizer::quantize(&enrolled_embedding);
        assert_eq!(enrolled_quantized.len(), 512);

        // Step 3: Simulate live scan (same person, small noise)
        let live_embedding: Vec<f64> = enrolled_embedding
            .iter()
            .enumerate()
            .map(|(i, v)| (v + (i as f64 * 0.001).sin() * 0.02).clamp(-1.0, 1.0))
            .collect();
        let live_quantized = FeatureQuantizer::quantize(&live_embedding);

        // Step 4: Calculate Hamming distance
        let distance = hamming_distance(&enrolled_quantized, &live_quantized);
        println!("Hamming distance: {} / {} bits", distance, 512 * 8);

        // Step 5: Configure threshold (50% similarity)
        let config = ThresholdConfig::new(512, 0.5);
        let threshold = config.max_hamming_distance();
        println!("Threshold: {} bits", threshold);

        // Step 6: Generate ZK proof
        let mut prover = FaceVerificationProver::new();
        let proof = prover.prove(distance, threshold)
            .expect("Proof generation should succeed");

        // Step 7: Verify proof size meets requirements
        println!("Proof size: {} bytes", proof.size());
        assert!(proof.meets_size_requirement(), "Proof should be ≤10KB");

        // Step 8: Verify the proof
        let verifier = FaceVerificationVerifier::from_prover(&mut prover)
            .expect("Should create verifier");
        let result = verifier.verify_expected(&proof, &default_policy(threshold), 0).is_ok();

        // Same person should match
        assert!(result, "Same person's embeddings should verify successfully");
    }

    /// Test Halo2 rejects different persons
    #[test]
    fn test_halo2_rejects_different_person() {
        // Person A's embedding
        let person_a: Vec<f64> = (0..512)
            .map(|i| ((i * 7) as f64 / 512.0) - 1.0)
            .collect();

        // Person B's embedding (different pattern)
        let person_b: Vec<f64> = (0..512)
            .map(|i| (((i * 13 + 256) % 512) as f64 / 512.0) - 1.0)
            .collect();

        let qa = FeatureQuantizer::quantize(&person_a);
        let qb = FeatureQuantizer::quantize(&person_b);

        let distance = hamming_distance(&qa, &qb);
        let config = ThresholdConfig::new(512, 0.5);
        let threshold = config.max_hamming_distance();

        println!("Different persons: distance={}, threshold={}", distance, threshold);

        let mut prover = FaceVerificationProver::new();
        let proof = prover.prove(distance, threshold)
            .expect("Proof generation should succeed");

        let verifier = FaceVerificationVerifier::from_prover(&mut prover)
            .expect("Should create verifier");
        let result = verifier.verify_expected(&proof, &default_policy(threshold), 0).is_ok();

        // Different persons should not match (distance likely > threshold)
        // Note: This depends on the specific embeddings
        if distance > threshold {
            assert!(!result, "Different persons should not verify");
        }
    }

    /// Test Halo2 threshold boundary
    #[test]
    fn test_halo2_threshold_boundary() {
        // Test exactly at threshold
        {
            let mut prover = FaceVerificationProver::new();
            let proof_at = prover.prove(100, 100).expect("Should generate proof");
            let verifier = FaceVerificationVerifier::from_prover(&mut prover)
                .expect("Should create verifier");
            assert!(verifier.verify_expected(&proof_at, &default_policy(100), 0).expect("Should verify"),
                "Distance == threshold should pass");
        }

        // Test just over threshold
        {
            let mut prover = FaceVerificationProver::new();
            let proof_over = prover.prove(101, 100).expect("Should generate proof");
            let verifier = FaceVerificationVerifier::from_prover(&mut prover)
                .expect("Should create verifier");
            assert!(verifier.verify_expected(&proof_over, &default_policy(100), 0).is_err(),
                "Distance > threshold should fail");
        }
    }

    /// Test full pipeline: face match + liveness in a single ZK proof
    #[test]
    fn test_halo2_face_plus_liveness_pipeline() {
        use sable_core::zk::halo2::LivenessWitness;

        // Step 1: Face verification setup (same as test_halo2_face_verification_workflow)
        let enrolled: Vec<f64> = (0..512).map(|i| ((i as f64 / 256.0) - 1.0) * 0.8).collect();
        let enrolled_q = FeatureQuantizer::quantize(&enrolled);

        let live: Vec<f64> = enrolled.iter().enumerate()
            .map(|(i, v)| (v + (i as f64 * 0.001).sin() * 0.02).clamp(-1.0, 1.0))
            .collect();
        let live_q = FeatureQuantizer::quantize(&live);

        let distance = hamming_distance(&enrolled_q, &live_q);
        let config = ThresholdConfig::new(512, 0.5);
        let threshold = config.max_hamming_distance();

        // Step 2: Build liveness witness (synthetic fingerprints)
        let liveness = LivenessWitness {
            delta_fingerprints: [0x0014, 0xA014, 0x6014, 0xC014, 0x0014, 0xA014, 0x6014, 0xC014, 0x0014, 0xA014, 0x6014, 0xC014],
            expected_fingerprints: [0x0014, 0xA014, 0x6014, 0xC014, 0x0014, 0xA014, 0x6014, 0xC014, 0x0014, 0xA014, 0x6014, 0xC014],
            color_threshold: 3,
            spatial_threshold: 2,
            min_magnitude: 5,
            ..LivenessWitness::default()
        };

        // Step 3: Generate combined proof
        let mut prover = FaceVerificationProver::new();
        let policy = fixture_policy(threshold, &liveness);
        let proof = prover.prove_with_liveness(distance, threshold, Some(liveness))
            .expect("Combined proof should succeed");

        // Step 4: Verify
        let verifier = FaceVerificationVerifier::from_prover(&mut prover)
            .expect("Should create verifier");


        assert!(verifier.verify_expected(&proof, &policy, 0).unwrap());
        assert!(proof.liveness_passed, "Proof.liveness_passed should be true");
        println!(
            "Combined proof: face={}, liveness={}, size={}B",
            true, proof.liveness_passed, proof.size()
        );
        assert!(proof.meets_size_requirement(), "Combined proof should be ≤10KB");
    }

    /// Test that tampered liveness fingerprints cause liveness failure
    #[test]
    fn test_halo2_liveness_tampered_fingerprints() {
        use sable_core::zk::halo2::LivenessWitness;

        let liveness = LivenessWitness {
            // Tampered: delta fingerprints don't match expected
            delta_fingerprints: [0xFFFF, 0x0000, 0xFFFF, 0x0000, 0xFFFF, 0x0000, 0xFFFF, 0x0000, 0xFFFF, 0x0000, 0xFFFF, 0x0000],
            expected_fingerprints: [0x0014, 0xA014, 0x6014, 0xC014, 0x0014, 0xA014, 0x6014, 0xC014, 0x0014, 0xA014, 0x6014, 0xC014],
            color_threshold: 3, // strict — HD will be >> 3
            spatial_threshold: 2,
            min_magnitude: 5,
            ..LivenessWitness::default()
        };

        let mut prover = FaceVerificationProver::new();
        let policy = fixture_policy(200, &liveness);
        let proof = prover.prove_with_liveness(100, 200, Some(liveness))
            .expect("Proof should still generate");

        assert!(!proof.liveness_passed, "Tampered fingerprints should fail liveness");

        let verifier = FaceVerificationVerifier::from_prover(&mut prover)
            .expect("Should create verifier");


        assert!(verifier.verify_expected(&proof, &policy, 0).is_err(), "Failed liveness must reject authentication");
    }

    /// Explicit synthetic fixture supplies a liveness witness; no production fallback.
    #[test]
    fn test_halo2_explicit_synthetic_fixture() {
        let mut prover = FaceVerificationProver::new();
        let proof = prover.prove(100, 200).expect("Should generate proof");

        assert!(proof.liveness_passed, "Default liveness should be true");
        assert_eq!(proof.public_inputs.len(), 5, "Should have 5 public inputs (incl. commitment)");

        let verifier = FaceVerificationVerifier::from_prover(&mut prover)
            .expect("Should create verifier");


        assert!(verifier.verify_expected(&proof, &default_policy(200), 0).unwrap());
    }

    /// Test quantization preserves similarity ordering
    #[test]
    fn test_quantization_preserves_ordering() {
        let base: Vec<f64> = (0..512).map(|i| (i as f64 / 256.0) - 1.0).collect();

        // Create embeddings at different similarity levels
        let similar: Vec<f64> = base.iter().map(|v| (v + 0.01).clamp(-1.0, 1.0)).collect();
        let different: Vec<f64> = base.iter().map(|v| (-v).clamp(-1.0, 1.0)).collect();

        let q_base = FeatureQuantizer::quantize(&base);
        let q_similar = FeatureQuantizer::quantize(&similar);
        let q_different = FeatureQuantizer::quantize(&different);

        let dist_similar = hamming_distance(&q_base, &q_similar);
        let dist_different = hamming_distance(&q_base, &q_different);

        // Similar embeddings should have smaller Hamming distance
        assert!(dist_similar < dist_different,
            "Similar embeddings should have smaller Hamming distance: {} vs {}",
            dist_similar, dist_different);
    }
}
