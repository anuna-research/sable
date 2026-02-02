//! Fuzz target for feature normalization functions (REQ-024)
//!
//! This fuzz target specifically tests the z-score normalization and
//! related preprocessing functions with edge cases.
//!
//! ## Test Coverage
//! - Empty vectors
//! - Single element vectors
//! - Constant vectors (zero variance)
//! - Extreme values
//! - NaN and infinity handling
//! - Very small and very large vectors
//! - Subnormal numbers

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use sable_core::biometric::feature_extraction::zscore_normalize;
use sable_core::crypto::poseidon::normalize_features;
use sable_core::FEATURE_VECTOR_SIZE;

/// Input structure for fuzzing normalization
#[derive(Debug, Arbitrary)]
struct NormalizationInput {
    /// Raw feature values
    raw_features: Vec<f64>,
    /// Specific edge case type to inject
    edge_case: NormalizationEdgeCase,
    /// Position to inject edge case
    edge_position: u16,
    /// Whether to test Poseidon normalize_features (requires 512 elements)
    test_poseidon_normalize: bool,
}

#[derive(Debug, Arbitrary, Clone, Copy)]
enum NormalizationEdgeCase {
    /// No edge case, use raw values
    None,
    /// All values are identical (zero variance)
    Constant,
    /// Single NaN value
    SingleNaN,
    /// Single Infinity
    SingleInfinity,
    /// Single negative infinity
    SingleNegInfinity,
    /// Very large values (close to f64::MAX)
    VeryLarge,
    /// Very small values (close to f64::MIN_POSITIVE)
    VerySmall,
    /// Mix of positive and negative extremes
    MixedExtremes,
    /// All zeros
    AllZeros,
    /// Alternating positive and negative
    Alternating,
    /// Subnormal numbers only
    Subnormal,
    /// Monotonically increasing
    Monotonic,
}

impl NormalizationEdgeCase {
    /// Apply edge case to feature vector
    fn apply(&self, features: &mut Vec<f64>, position: usize) {
        if features.is_empty() {
            return;
        }

        let pos = position % features.len();

        match self {
            NormalizationEdgeCase::None => {}

            NormalizationEdgeCase::Constant => {
                let val = features.first().copied().unwrap_or(0.5);
                for f in features.iter_mut() {
                    *f = val;
                }
            }

            NormalizationEdgeCase::SingleNaN => {
                features[pos] = f64::NAN;
            }

            NormalizationEdgeCase::SingleInfinity => {
                features[pos] = f64::INFINITY;
            }

            NormalizationEdgeCase::SingleNegInfinity => {
                features[pos] = f64::NEG_INFINITY;
            }

            NormalizationEdgeCase::VeryLarge => {
                for f in features.iter_mut() {
                    *f = 1e300;
                }
            }

            NormalizationEdgeCase::VerySmall => {
                for f in features.iter_mut() {
                    *f = 1e-300;
                }
            }

            NormalizationEdgeCase::MixedExtremes => {
                for (i, f) in features.iter_mut().enumerate() {
                    *f = if i % 2 == 0 { 1e300 } else { -1e300 };
                }
            }

            NormalizationEdgeCase::AllZeros => {
                for f in features.iter_mut() {
                    *f = 0.0;
                }
            }

            NormalizationEdgeCase::Alternating => {
                for (i, f) in features.iter_mut().enumerate() {
                    *f = if i % 2 == 0 { 1.0 } else { -1.0 };
                }
            }

            NormalizationEdgeCase::Subnormal => {
                for f in features.iter_mut() {
                    *f = 1e-320; // Subnormal
                }
            }

            NormalizationEdgeCase::Monotonic => {
                for (i, f) in features.iter_mut().enumerate() {
                    *f = i as f64;
                }
            }
        }
    }
}

fuzz_target!(|input: NormalizationInput| {
    // Test 1: Z-score normalization on arbitrary vectors
    {
        let mut features = input.raw_features.clone();

        // Apply edge case
        let pos = input.edge_position as usize;
        input.edge_case.apply(&mut features, pos);

        // Original values for comparison
        let original = features.clone();

        // Should not panic
        zscore_normalize(&mut features);

        // Verify properties after normalization
        if !original.is_empty() {
            // Check all values are finite (or NaN if input had NaN)
            let had_non_finite = original.iter().any(|f| !f.is_finite());

            if !had_non_finite {
                // After normalization, all values should still be finite
                // unless the input had zero variance (constant vector)
                let variance = calculate_variance(&original);

                if variance > 1e-10 {
                    // Should be normalized
                    for f in &features {
                        assert!(f.is_finite(), "Normalized value should be finite");
                    }

                    // Mean should be approximately zero
                    let mean = features.iter().sum::<f64>() / features.len() as f64;
                    assert!(
                        mean.abs() < 1e-10 || !mean.is_finite(),
                        "Mean should be ~0 after z-score, got {}",
                        mean
                    );
                }
            }
        }
    }

    // Test 2: Poseidon normalize_features (requires exactly 512 elements)
    if input.test_poseidon_normalize {
        let mut features: Vec<f32> = input.raw_features.iter()
            .map(|&f| f as f32)
            .take(FEATURE_VECTOR_SIZE)
            .collect();

        // Pad or truncate to exactly 512
        features.resize(FEATURE_VECTOR_SIZE, 0.5);

        // Convert edge cases to f32 range and apply
        let pos = (input.edge_position as usize) % FEATURE_VECTOR_SIZE;
        match input.edge_case {
            NormalizationEdgeCase::Constant => {
                let val = features[0];
                for f in features.iter_mut() {
                    *f = val;
                }
            }
            NormalizationEdgeCase::AllZeros => {
                for f in features.iter_mut() {
                    *f = 0.0;
                }
            }
            NormalizationEdgeCase::Alternating => {
                for (i, f) in features.iter_mut().enumerate() {
                    *f = if i % 2 == 0 { 1.0 } else { -1.0 };
                }
            }
            NormalizationEdgeCase::Monotonic => {
                for (i, f) in features.iter_mut().enumerate() {
                    *f = (i as f32) / (FEATURE_VECTOR_SIZE as f32);
                }
            }
            NormalizationEdgeCase::SingleNaN => {
                features[pos] = f32::NAN;
            }
            NormalizationEdgeCase::SingleInfinity => {
                features[pos] = f32::INFINITY;
            }
            _ => {}
        }

        // Should not panic
        let result = normalize_features(&features);

        // If successful, verify output properties
        if let Ok(normalized) = result {
            assert_eq!(normalized.len(), FEATURE_VECTOR_SIZE);

            // All values should be finite
            for f in &normalized {
                assert!(f.is_finite(), "Normalized value must be finite");
            }

            // Check normalization properties
            let mean: f32 = normalized.iter().sum::<f32>() / normalized.len() as f32;
            let variance: f32 = normalized.iter()
                .map(|x| (x - mean).powi(2))
                .sum::<f32>() / normalized.len() as f32;

            // Mean should be close to 0
            assert!(mean.abs() < 0.01, "Mean should be ~0, got {}", mean);
            // Variance should be close to 1
            assert!((variance.sqrt() - 1.0).abs() < 0.01, "Std should be ~1, got {}", variance.sqrt());
        }
    }

    // Test 3: Edge case - empty vector
    {
        let mut empty: Vec<f64> = vec![];
        zscore_normalize(&mut empty);
        assert!(empty.is_empty(), "Empty vector should remain empty");
    }

    // Test 4: Edge case - single element
    {
        let mut single = vec![42.0];
        let _original = single[0];
        zscore_normalize(&mut single);
        // Single element can't be normalized (zero variance), should remain unchanged
        assert_eq!(single.len(), 1);
    }
});

/// Calculate variance of a vector
fn calculate_variance(data: &[f64]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mean = data.iter().sum::<f64>() / data.len() as f64;
    if !mean.is_finite() {
        return 0.0;
    }

    data.iter()
        .map(|x| {
            let diff = x - mean;
            if diff.is_finite() {
                diff.powi(2)
            } else {
                0.0
            }
        })
        .sum::<f64>() / data.len() as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zscore_basic() {
        let mut features = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        zscore_normalize(&mut features);

        let mean: f64 = features.iter().sum::<f64>() / features.len() as f64;
        assert!(mean.abs() < 1e-10, "Mean should be ~0");

        let variance: f64 = features.iter()
            .map(|x| (x - mean).powi(2))
            .sum::<f64>() / features.len() as f64;
        assert!((variance.sqrt() - 1.0).abs() < 1e-10, "Std should be ~1");
    }

    #[test]
    fn test_zscore_constant() {
        let mut features = vec![5.0; 100];
        zscore_normalize(&mut features);
        // Should remain constant (can't normalize zero variance)
        assert!(features.iter().all(|&x| x == 5.0));
    }

    #[test]
    fn test_poseidon_normalize_invalid() {
        // Zero variance should fail
        let features = [0.5f32; FEATURE_VECTOR_SIZE];
        let result = normalize_features(&features);
        assert!(result.is_err(), "Zero variance should fail");

        // Wrong size should fail
        let wrong_size = [0.5f32; 100];
        let result = normalize_features(&wrong_size);
        assert!(result.is_err(), "Wrong size should fail");
    }
}
