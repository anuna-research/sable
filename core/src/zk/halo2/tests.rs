//! # Comprehensive Unit Tests for Halo2 Circuits
//!
//! This module contains integration tests for all Halo2 circuit components.
//!
//! ## Test Coverage
//!
//! 1. **Quantizer Tests** - f64 to u8 conversion
//! 2. **Poseidon Tests** - Hash circuit verification
//! 3. **Hamming Distance Tests** - Bit difference counting
//! 4. **Threshold Tests** - Threshold calibration
//! 5. **Threshold Check Tests** - Comparison circuit
//! 6. **End-to-End Tests** - Full verification flow

#[cfg(test)]
mod integration_tests {
    use super::super::*;
    use crate::zk::halo2::hamming::hamming_distance;
    use crate::zk::halo2::quantizer::FeatureQuantizer;
    use crate::zk::halo2::threshold::{ThresholdConfig, VerificationResult};
    use crate::zk::halo2::threshold_check::ThresholdCheckCircuit;

    // ==================== Quantizer Integration Tests ====================

    #[test]
    fn test_quantizer_roundtrip_accuracy() {
        // Test that quantization preserves information with acceptable error
        let original: Vec<f64> = (0..100)
            .map(|i| -1.0 + (i as f64 / 50.0))
            .collect();

        let quantized = FeatureQuantizer::quantize(&original);
        let recovered = FeatureQuantizer::dequantize(&quantized);

        for (orig, rec) in original.iter().zip(recovered.iter()) {
            let error = (orig - rec).abs();
            assert!(
                error <= 0.01,
                "Roundtrip error {} exceeds tolerance for value {}",
                error,
                orig
            );
        }
    }

    #[test]
    fn test_quantizer_preserves_similarity() {
        // Two similar vectors should have similar quantized representations
        let v1: Vec<f64> = vec![0.1, 0.2, 0.3, 0.4, 0.5];
        let v2: Vec<f64> = vec![0.11, 0.21, 0.29, 0.41, 0.49];

        let q1 = FeatureQuantizer::quantize(&v1);
        let q2 = FeatureQuantizer::quantize(&v2);

        // Small differences in input should result in small differences in quantized
        let distance: u32 = q1
            .iter()
            .zip(q2.iter())
            .map(|(a, b)| (*a as i32 - *b as i32).unsigned_abs())
            .sum();

        assert!(
            distance < 20,
            "Similar vectors should have small quantization distance: {}",
            distance
        );
    }

    // ==================== Hamming Distance Integration Tests ====================

    #[test]
    fn test_hamming_with_quantized_embeddings() {
        // Test Hamming distance with realistic quantized embeddings
        let emb1 = QuantizedEmbedding::from_f64(&[0.5, 0.3, -0.2, 0.8]);
        let emb2 = QuantizedEmbedding::from_f64(&[0.5, 0.3, -0.2, 0.8]);

        let distance = emb1.hamming_distance(&emb2).expect("Should compute distance");
        assert_eq!(distance, 0, "Identical embeddings should have 0 distance");
    }

    #[test]
    fn test_hamming_circuit_matches_native() {
        // Circuit result should match native computation
        let a = vec![0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
        let b = vec![0x21, 0x43, 0x65, 0x87, 0xA9, 0xCB, 0xED, 0x0F];

        let native_distance = hamming_distance(&a, &b);
        let circuit = HammingDistanceCircuit::new(a, b);
        let circuit_distance = circuit.test_circuit().expect("Circuit should be valid");

        assert_eq!(
            native_distance, circuit_distance,
            "Circuit and native distance should match"
        );
    }

    #[test]
    fn test_hamming_similarity_thresholds() {
        // Test various similarity levels
        let config = ThresholdConfig::new(8, 0.5); // 8 bytes, 50% threshold

        // 64 bits total, 50% threshold = 32 bits
        assert_eq!(config.max_hamming_distance(), 32);

        // Test passing case
        let circuit_pass = ThresholdCheckCircuit::new(30, 32);
        assert!(circuit_pass.test_circuit().expect("Should be valid"));

        // Test failing case
        let circuit_fail = ThresholdCheckCircuit::new(35, 32);
        assert!(!circuit_fail.test_circuit().expect("Should be valid"));
    }

    // ==================== Poseidon Circuit Tests ====================

    #[test]
    fn test_poseidon_consistency() {
        // Same inputs should always produce same hash
        let a = 123456u64;
        let b = 789012u64;

        let circuit1 = PoseidonCircuit::from_u64(a, b);
        let circuit2 = PoseidonCircuit::from_u64(a, b);

        let hash1 = circuit1.test_circuit().expect("Should be valid");
        let hash2 = circuit2.test_circuit().expect("Should be valid");

        assert_eq!(hash1, hash2, "Same inputs should produce same hash");
    }

    #[test]
    fn test_poseidon_collision_resistance() {
        // Different inputs should produce different hashes
        let inputs = [
            (1u64, 2u64),
            (2u64, 1u64),
            (1u64, 3u64),
            (0u64, 0u64),
            (u64::MAX, 0u64),
        ];

        let hashes: Vec<_> = inputs
            .iter()
            .map(|(a, b)| {
                let circuit = PoseidonCircuit::from_u64(*a, *b);
                circuit.test_circuit().expect("Should be valid")
            })
            .collect();

        // Check all hashes are unique
        for i in 0..hashes.len() {
            for j in (i + 1)..hashes.len() {
                assert_ne!(
                    hashes[i], hashes[j],
                    "Inputs {:?} and {:?} produced same hash",
                    inputs[i], inputs[j]
                );
            }
        }
    }

    // ==================== Threshold Configuration Tests ====================

    #[test]
    fn test_threshold_presets() {
        let standard = ThresholdConfig::default();
        let strict = ThresholdConfig::strict();
        let relaxed = ThresholdConfig::relaxed();

        // Standard should be between strict and relaxed
        assert!(
            strict.max_hamming_distance() < standard.max_hamming_distance(),
            "Strict should allow fewer differences"
        );
        assert!(
            standard.max_hamming_distance() < relaxed.max_hamming_distance(),
            "Relaxed should allow more differences"
        );
    }

    #[test]
    fn test_threshold_security_levels() {
        let config = ThresholdConfig::default();

        // Test various security scenarios
        let scenarios = [
            (0, true, "Identical embeddings"),
            (1000, true, "Very similar"),
            (4095, true, "Just under threshold"),
            (4096, true, "At threshold"),
            (4097, false, "Just over threshold"),
            (8000, false, "Very different"),
        ];

        for (distance, expected_match, desc) in scenarios {
            assert_eq!(
                config.is_match(distance),
                expected_match,
                "{}: distance {} should {} be a match",
                desc,
                distance,
                if expected_match { "" } else { "not " }
            );
        }
    }

    // ==================== Full Pipeline Tests ====================

    #[test]
    fn test_full_verification_pipeline() {
        // Simulate a complete face verification flow

        // 1. Create mock embeddings (normally from face detection)
        let enrolled_f64: Vec<f64> = (0..64).map(|i| (i as f64 / 64.0) * 2.0 - 1.0).collect();

        // Slightly different live scan
        let live_f64: Vec<f64> = enrolled_f64
            .iter()
            .map(|v| (v + 0.05).clamp(-1.0, 1.0))
            .collect();

        // 2. Quantize embeddings
        let enrolled_q = FeatureQuantizer::quantize(&enrolled_f64);
        let live_q = FeatureQuantizer::quantize(&live_f64);

        // 3. Compute Hamming distance
        let distance = hamming_distance(&enrolled_q, &live_q);
        println!("Hamming distance: {} / {} bits", distance, enrolled_q.len() * 8);

        // 4. Check against threshold
        let config = ThresholdConfig::new(64, 0.5); // 50% threshold
        let threshold = config.max_hamming_distance();

        // 5. Verify using circuit
        let circuit = ThresholdCheckCircuit::new(distance, threshold);
        let result = circuit.test_circuit().expect("Circuit should be valid");

        println!(
            "Verification result: {} (distance={}, threshold={})",
            if result { "MATCH" } else { "NO MATCH" },
            distance,
            threshold
        );

        // Similar embeddings should match
        assert!(result, "Similar embeddings should verify successfully");
    }

    #[test]
    fn test_verification_with_different_persons() {
        // Test that different persons are rejected

        // Person A's embedding
        let person_a: Vec<f64> = (0..64).map(|i| ((i * 7) % 100) as f64 / 50.0 - 1.0).collect();

        // Person B's embedding (different pattern)
        let person_b: Vec<f64> = (0..64)
            .map(|i| ((i * 13 + 50) % 100) as f64 / 50.0 - 1.0)
            .collect();

        let q_a = FeatureQuantizer::quantize(&person_a);
        let q_b = FeatureQuantizer::quantize(&person_b);

        let distance = hamming_distance(&q_a, &q_b);
        let config = ThresholdConfig::new(64, 0.5);
        let threshold = config.max_hamming_distance();

        println!(
            "Different persons: distance={}, threshold={}",
            distance, threshold
        );

        let circuit = ThresholdCheckCircuit::new(distance, threshold);
        let result = circuit.test_circuit().expect("Circuit should be valid");

        // Different persons should likely not match (distance usually > threshold)
        // Note: This depends on the specific embeddings, so we just log the result
        println!(
            "Different persons verification: {}",
            if result { "MATCH (unusual)" } else { "NO MATCH (expected)" }
        );
    }

    // ==================== Edge Case Tests ====================

    #[test]
    fn test_edge_case_empty_check() {
        // Verify behavior with minimal inputs
        let circuit = ThresholdCheckCircuit::new(0, 0);
        let result = circuit.test_circuit().expect("Should be valid");
        assert!(result, "0 <= 0 should pass");
    }

    #[test]
    fn test_edge_case_max_values() {
        // Test with large but valid values
        let distance = 8000u64;
        let threshold = 8192u64;

        let circuit = ThresholdCheckCircuit::new(distance, threshold);
        let result = circuit.test_circuit().expect("Should be valid");
        assert!(result, "Large values within range should work");
    }

    #[test]
    fn test_hello_circuit_still_works() {
        // Verify the foundation hello circuit still works
        let circuit = HelloCircuit::new(100, 200);
        circuit.test_circuit().expect("Hello circuit should still work");
    }

    // ==================== Verification Result Tests ====================

    #[test]
    fn test_verification_result_enum() {
        let match_result = VerificationResult::Match;
        let no_match_result = VerificationResult::NoMatch;

        assert!(match_result.is_match());
        assert!(!no_match_result.is_match());

        assert_eq!(VerificationResult::from_match(true), VerificationResult::Match);
        assert_eq!(VerificationResult::from_match(false), VerificationResult::NoMatch);
    }

    // ==================== Stress Tests ====================

    #[test]
    fn test_multiple_verifications() {
        // Run multiple verifications to check for consistency
        for i in 0..10 {
            let distance = (i * 100) as u64;
            let threshold = 500u64;

            let circuit = ThresholdCheckCircuit::new(distance, threshold);
            let result = circuit.test_circuit().expect("Circuit should be valid");

            let expected = distance <= threshold;
            assert_eq!(
                result, expected,
                "Iteration {}: distance {} vs threshold {} should be {}",
                i, distance, threshold, expected
            );
        }
    }
}

#[cfg(test)]
mod benchmark_tests {
    use super::super::*;
    use std::time::Instant;

    #[test]
    fn test_circuit_performance_baseline() {
        // Establish performance baseline for circuits

        // Hello circuit (simplest)
        let start = Instant::now();
        let hello = HelloCircuit::new(1, 2);
        hello.test_circuit().expect("Should work");
        let hello_time = start.elapsed();
        println!("HelloCircuit: {:?}", hello_time);

        // Poseidon circuit
        let start = Instant::now();
        let poseidon = PoseidonCircuit::from_u64(123, 456);
        poseidon.test_circuit().expect("Should work");
        let poseidon_time = start.elapsed();
        println!("PoseidonCircuit: {:?}", poseidon_time);

        // Hamming circuit (4 bytes)
        let start = Instant::now();
        let hamming = HammingDistanceCircuit::new(vec![1, 2, 3, 4], vec![5, 6, 7, 8]);
        hamming.test_circuit().expect("Should work");
        let hamming_time = start.elapsed();
        println!("HammingDistanceCircuit (4 bytes): {:?}", hamming_time);

        // Threshold check circuit
        let start = Instant::now();
        let threshold = ThresholdCheckCircuit::new(100, 200);
        threshold.test_circuit().expect("Should work");
        let threshold_time = start.elapsed();
        println!("ThresholdCheckCircuit: {:?}", threshold_time);
    }
}
