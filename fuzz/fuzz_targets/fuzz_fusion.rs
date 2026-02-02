//! Fuzz target for multi-modal biometric fusion (REQ-024)
//!
//! This fuzz target tests the fusion algorithms that combine palm vein
//! and palm print features into unified templates.
//!
//! ## Test Coverage
//! - Single modality fusion (vein only, print only)
//! - Multi-modal weighted fusion
//! - Adaptive weighted fusion
//! - Verification score computation
//! - Decision-level fusion
//! - Fusion weight validation
//! - Edge cases in similarity computation

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use sable_core::biometric::{
    BiometricModality, ModalityFeatureVector,
};
use sable_core::biometric::fusion::{
    fuse_modalities, adaptive_weighted_fusion, compute_verification_score,
    decision_level_fusion, validate_fusion_weights, assess_feature_quality,
    FusionConfig, FusionMethod, FusionMetrics,
};

/// Input structure for fuzzing fusion operations
#[derive(Debug, Arbitrary)]
struct FusionInput {
    /// Vein features (512 dimensions expected)
    vein_features: Vec<f64>,
    /// Vein confidence score
    vein_confidence: f32,
    /// Print features (256 dimensions expected)
    print_features: Vec<f64>,
    /// Print confidence score
    print_confidence: f32,
    /// Test operation type
    operation: FusionOperation,
    /// Fusion weights to test
    test_weights: Vec<f32>,
    /// Decision for vein modality
    vein_decision: bool,
    /// Decision for print modality
    print_decision: bool,
    /// Score for vein modality
    vein_score: f32,
    /// Score for print modality
    print_score: f32,
    /// Genuine scores for metrics
    genuine_scores: Vec<f32>,
    /// Impostor scores for metrics
    impostor_scores: Vec<f32>,
}

#[derive(Debug, Arbitrary, Clone, Copy)]
enum FusionOperation {
    /// Fuse with both modalities
    FuseBoth,
    /// Fuse with vein only
    FuseVeinOnly,
    /// Fuse with print only
    FusePrintOnly,
    /// Fuse with neither (should fail)
    FuseNone,
    /// Adaptive weighted fusion
    AdaptiveFusion,
    /// Compute verification score
    VerificationScore,
    /// Decision-level fusion
    DecisionFusion,
    /// Validate fusion weights
    ValidateWeights,
    /// Assess feature quality
    AssessQuality,
    /// Calculate fusion metrics
    CalculateMetrics,
    /// Test all fusion methods
    AllMethods,
}

/// Create a ModalityFeatureVector from fuzz input
fn create_vein_features(input: &FusionInput) -> ModalityFeatureVector {
    let mut features = input.vein_features.clone();

    // Ensure proper dimension (512)
    features.resize(512, 0.5);

    // Clamp all values to valid range
    for f in features.iter_mut() {
        if !f.is_finite() {
            *f = 0.5;
        }
        *f = f.clamp(0.0, 1.0);
    }

    let confidence = if input.vein_confidence.is_finite() {
        (input.vein_confidence as f64).clamp(0.0, 1.0)
    } else {
        0.5
    };

    ModalityFeatureVector::new(BiometricModality::PalmVein, features, confidence)
}

/// Create a ModalityFeatureVector from fuzz input
fn create_print_features(input: &FusionInput) -> ModalityFeatureVector {
    let mut features = input.print_features.clone();

    // Ensure proper dimension (256)
    features.resize(256, 0.5);

    // Clamp all values to valid range
    for f in features.iter_mut() {
        if !f.is_finite() {
            *f = 0.5;
        }
        *f = f.clamp(0.0, 1.0);
    }

    let confidence = if input.print_confidence.is_finite() {
        (input.print_confidence as f64).clamp(0.0, 1.0)
    } else {
        0.5
    };

    ModalityFeatureVector::new(BiometricModality::PalmPrint, features, confidence)
}

fuzz_target!(|input: FusionInput| {
    let vein = create_vein_features(&input);
    let print = create_print_features(&input);

    match input.operation {
        FusionOperation::FuseBoth => {
            // Test 1: Fuse with both modalities present
            let result = fuse_modalities(Some(&vein), Some(&print));
            assert!(result.is_ok(), "Fusion with both modalities should succeed");

            let fused = result.unwrap();
            assert_eq!(fused.modality, BiometricModality::PalmMultiModal);
            assert_eq!(fused.features.len(), 512);
            assert!(fused.confidence >= 0.0 && fused.confidence <= 1.0);

            // All features should be valid
            for f in &fused.features {
                assert!(f.is_finite(), "Fused features must be finite");
                assert!(*f >= 0.0 && *f <= 1.0, "Fused features must be in [0,1]");
            }
        }

        FusionOperation::FuseVeinOnly => {
            // Test 2: Fuse with vein only
            let result = fuse_modalities(Some(&vein), None);
            assert!(result.is_ok(), "Fusion with vein only should succeed");

            let fused = result.unwrap();
            assert_eq!(fused.modality, BiometricModality::PalmVein);
            assert_eq!(fused.features.len(), 512);
            // Reduced confidence for single modality
            assert!(fused.confidence <= vein.confidence);
        }

        FusionOperation::FusePrintOnly => {
            // Test 3: Fuse with print only
            let result = fuse_modalities(None, Some(&print));
            assert!(result.is_ok(), "Fusion with print only should succeed");

            let fused = result.unwrap();
            assert_eq!(fused.modality, BiometricModality::PalmPrint);
            assert_eq!(fused.features.len(), 512);
        }

        FusionOperation::FuseNone => {
            // Test 4: Fuse with neither (should fail)
            let result = fuse_modalities(None, None);
            assert!(result.is_err(), "Fusion with no modalities should fail");
        }

        FusionOperation::AdaptiveFusion => {
            // Test 5: Adaptive weighted fusion
            let result = adaptive_weighted_fusion(Some(&vein), Some(&print));

            // Should succeed if both confidences sum to non-zero
            if vein.confidence + print.confidence > 0.0 {
                assert!(result.is_ok(), "Adaptive fusion should succeed with non-zero confidence");
                let fused = result.unwrap();
                assert_eq!(fused.features.len(), 512);
            }
        }

        FusionOperation::VerificationScore => {
            // Test 6: Compute verification score
            let live_vein = create_vein_features(&FusionInput {
                vein_features: input.print_features.iter().map(|f| f + 0.01).collect(),
                vein_confidence: input.vein_confidence,
                ..input.clone()
            });
            let live_print = create_print_features(&FusionInput {
                print_features: input.vein_features.iter().take(256).map(|f| f + 0.01).collect(),
                print_confidence: input.print_confidence,
                ..input.clone()
            });

            let result = compute_verification_score(
                Some(&vein),
                Some(&print),
                Some(&live_vein),
                Some(&live_print),
            );

            assert!(result.is_ok(), "Verification score computation should succeed");
            let score = result.unwrap();
            assert!(score >= 0.0 && score <= 1.0, "Score must be in [0,1], got {}", score);
        }

        FusionOperation::DecisionFusion => {
            // Test 7: Decision-level fusion
            let vein_score = if input.vein_score.is_finite() {
                (input.vein_score as f64).clamp(0.0, 1.0)
            } else {
                0.5
            };
            let print_score = if input.print_score.is_finite() {
                (input.print_score as f64).clamp(0.0, 1.0)
            } else {
                0.5
            };

            let result = decision_level_fusion(
                Some(input.vein_decision),
                Some(input.print_decision),
                Some(vein_score),
                Some(print_score),
            );

            assert!(result.is_ok(), "Decision fusion should succeed");
            let (decision, score) = result.unwrap();
            assert!(score >= 0.0 && score <= 1.0, "Combined score must be in [0,1]");

            // OR rule: decision should be true if either input is true
            assert_eq!(decision, input.vein_decision || input.print_decision);
        }

        FusionOperation::ValidateWeights => {
            // Test 8: Validate fusion weights
            let weights: Vec<f64> = input.test_weights.iter()
                .map(|&w| w as f64)
                .filter(|w| w.is_finite())
                .collect();

            let result = validate_fusion_weights(&weights);

            // Calculate expected validity
            let sum: f64 = weights.iter().sum();
            let all_non_negative = weights.iter().all(|&w| w >= 0.0);
            let expected_valid = !weights.is_empty() && all_non_negative && (sum - 1.0).abs() < 1e-6;

            match result {
                Ok(()) => assert!(expected_valid, "Validation passed but weights invalid: {:?}", weights),
                Err(_) => assert!(!expected_valid, "Validation failed but weights valid: {:?}", weights),
            }

            // Test specific cases
            assert!(validate_fusion_weights(&[0.6, 0.4]).is_ok());
            assert!(validate_fusion_weights(&[0.5, 0.5]).is_ok());
            assert!(validate_fusion_weights(&[1.0]).is_ok());
            assert!(validate_fusion_weights(&[0.5, 0.3]).is_err()); // Sum != 1
            assert!(validate_fusion_weights(&[-0.1, 1.1]).is_err()); // Negative
            assert!(validate_fusion_weights(&[]).is_err()); // Empty
        }

        FusionOperation::AssessQuality => {
            // Test 9: Assess feature quality
            let quality = assess_feature_quality(&vein);
            assert!(quality >= 0.0 && quality <= 1.0, "Quality must be in [0,1]");

            let print_quality = assess_feature_quality(&print);
            assert!(print_quality >= 0.0 && print_quality <= 1.0);
        }

        FusionOperation::CalculateMetrics => {
            // Test 10: Calculate fusion metrics
            let genuine: Vec<f64> = input.genuine_scores.iter()
                .filter(|s| s.is_finite())
                .map(|&s| (s as f64).clamp(0.0, 1.0))
                .collect();

            let impostor: Vec<f64> = input.impostor_scores.iter()
                .filter(|s| s.is_finite())
                .map(|&s| (s as f64).clamp(0.0, 1.0))
                .collect();

            if !genuine.is_empty() && !impostor.is_empty() {
                let threshold = 0.5;
                let metrics = FusionMetrics::from_scores(&genuine, &impostor, threshold);

                assert!(metrics.accuracy >= 0.0 && metrics.accuracy <= 1.0);
                assert!(metrics.false_accept_rate >= 0.0 && metrics.false_accept_rate <= 1.0);
                assert!(metrics.false_reject_rate >= 0.0 && metrics.false_reject_rate <= 1.0);
                assert!(metrics.equal_error_rate >= 0.0);
            }
        }

        FusionOperation::AllMethods => {
            // Test 11: Test all fusion methods via FusionConfig
            for method in [
                FusionMethod::WeightedScore,
                FusionMethod::MaxScore,
                FusionMethod::MinScore,
                FusionMethod::ProductScore,
            ] {
                let config = FusionConfig::new(0.6, 0.4, 0.77, method);
                assert!(config.is_ok(), "FusionConfig should accept valid weights");
            }

            // Invalid config should fail
            let invalid_config = FusionConfig::new(0.5, 0.3, 0.77, FusionMethod::WeightedScore);
            assert!(invalid_config.is_err(), "Invalid weights should fail");
        }
    }
});

// Implement Clone for FusionInput for test operations
impl Clone for FusionInput {
    fn clone(&self) -> Self {
        Self {
            vein_features: self.vein_features.clone(),
            vein_confidence: self.vein_confidence,
            print_features: self.print_features.clone(),
            print_confidence: self.print_confidence,
            operation: self.operation,
            test_weights: self.test_weights.clone(),
            vein_decision: self.vein_decision,
            print_decision: self.print_decision,
            vein_score: self.vein_score,
            print_score: self.print_score,
            genuine_scores: self.genuine_scores.clone(),
            impostor_scores: self.impostor_scores.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fusion_default_config() {
        let config = FusionConfig::default();
        assert_eq!(config.vein_weight, 0.6);
        assert_eq!(config.print_weight, 0.4);
        assert!(validate_fusion_weights(&config.weights()).is_ok());
    }

    #[test]
    fn test_fusion_weight_validation() {
        // Valid cases
        assert!(validate_fusion_weights(&[0.6, 0.4]).is_ok());
        assert!(validate_fusion_weights(&[0.5, 0.5]).is_ok());
        assert!(validate_fusion_weights(&[0.333, 0.333, 0.334]).is_ok());
        assert!(validate_fusion_weights(&[1.0]).is_ok());

        // Invalid cases
        assert!(validate_fusion_weights(&[]).is_err());
        assert!(validate_fusion_weights(&[0.5]).is_err());
        assert!(validate_fusion_weights(&[0.5, 0.6]).is_err());
        assert!(validate_fusion_weights(&[-0.1, 1.1]).is_err());
    }

    #[test]
    fn test_fuse_modalities_none() {
        let result = fuse_modalities(None, None);
        assert!(result.is_err());
    }
}
