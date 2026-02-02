//! Fuzz target for Poseidon hash function (REQ-024)
//!
//! This fuzz target tests the Poseidon hash implementation with arbitrary inputs
//! to ensure it handles all edge cases without panicking.
//!
//! ## Test Coverage
//! - Empty and minimal inputs
//! - Maximum size inputs (512 features)
//! - Boundary values (NaN, Infinity, -Infinity)
//! - Extreme values (very large, very small, negative)
//! - All zeros and all ones patterns
//! - Random feature distributions

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use sable_core::crypto::poseidon::poseidon_hash;
use sable_core::FEATURE_VECTOR_SIZE;

/// Input structure for fuzzing Poseidon hash
#[derive(Debug, Arbitrary)]
struct PoseidonInput {
    /// Raw feature values that will be converted to f32 array
    features: Vec<f32>,
    /// Whether to include edge case values
    include_edge_cases: bool,
    /// Index to inject edge case (if include_edge_cases is true)
    edge_case_index: u16,
    /// Type of edge case to inject
    edge_case_type: EdgeCaseType,
}

#[derive(Debug, Arbitrary, Clone, Copy)]
enum EdgeCaseType {
    Zero,
    NegativeZero,
    SmallPositive,
    SmallNegative,
    LargePositive,
    LargeNegative,
    MaxFinite,
    MinFinite,
    Infinity,
    NegInfinity,
    NaN,
    Subnormal,
}

impl EdgeCaseType {
    fn to_f32(self) -> f32 {
        match self {
            EdgeCaseType::Zero => 0.0,
            EdgeCaseType::NegativeZero => -0.0,
            EdgeCaseType::SmallPositive => f32::MIN_POSITIVE,
            EdgeCaseType::SmallNegative => -f32::MIN_POSITIVE,
            EdgeCaseType::LargePositive => 9.99,  // Just under the limit
            EdgeCaseType::LargeNegative => -9.99, // Just under the limit
            EdgeCaseType::MaxFinite => f32::MAX,
            EdgeCaseType::MinFinite => f32::MIN,
            EdgeCaseType::Infinity => f32::INFINITY,
            EdgeCaseType::NegInfinity => f32::NEG_INFINITY,
            EdgeCaseType::NaN => f32::NAN,
            EdgeCaseType::Subnormal => 1.0e-40, // Subnormal number
        }
    }
}

fuzz_target!(|input: PoseidonInput| {
    // Build feature array with proper size
    let mut features = [0.0f32; FEATURE_VECTOR_SIZE];

    // Fill with fuzzed values, clamping to valid range for hash function
    for (i, feature) in features.iter_mut().enumerate() {
        if i < input.features.len() {
            let val = input.features[i];
            // Clamp to valid range if finite, otherwise use 0
            if val.is_finite() {
                *feature = val.clamp(-10.0, 10.0);
            } else {
                *feature = 0.0;
            }
        }
    }

    // Inject edge case if requested
    if input.include_edge_cases {
        let idx = (input.edge_case_index as usize) % FEATURE_VECTOR_SIZE;
        features[idx] = input.edge_case_type.to_f32();
    }

    // Test 1: Hash should not panic on any input (may return error for invalid inputs)
    let result = poseidon_hash(&features);

    // If hash succeeds, verify the result is deterministic
    if let Ok(hash1) = &result {
        // Same input should produce same output
        let hash2 = poseidon_hash(&features);
        if let Ok(h2) = hash2 {
            assert_eq!(*hash1, h2, "Poseidon hash must be deterministic");
        }
    }

    // Test 2: Different inputs should (usually) produce different outputs
    // Skip this for invalid inputs
    if result.is_ok() {
        let mut modified_features = features;
        // Slightly modify one feature
        let modify_idx = (input.edge_case_index as usize) % FEATURE_VECTOR_SIZE;
        if modified_features[modify_idx].is_finite() && modified_features[modify_idx].abs() < 9.9 {
            modified_features[modify_idx] += 0.001;
            let modified_result = poseidon_hash(&modified_features);
            // Note: We don't assert inequality as collisions are theoretically possible,
            // but they should be extremely rare
            let _ = modified_result;
        }
    }
});

// Additional test for poseidon hash
#[cfg(test)]
mod poseidon_tests {
    use super::*;

    #[test]
    fn test_poseidon_edge_cases() {
        // Test with valid input
        let features = [0.5f32; FEATURE_VECTOR_SIZE];
        let result = poseidon_hash(&features);
        assert!(result.is_ok(), "Valid input should succeed");

        // Test determinism
        let hash1 = poseidon_hash(&features).unwrap();
        let hash2 = poseidon_hash(&features).unwrap();
        assert_eq!(hash1, hash2, "Hash must be deterministic");
    }
}
