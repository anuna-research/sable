// Multi-modal Biometric Fusion Module
//
// Ported from research Scheme implementation
// Implements weighted score-level fusion for palm vein + palm print modalities
// Based on research configuration: 0.6 vein weight + 0.4 print weight

use super::{ModalityFeatureVector, BiometricModality};
use super::constant_time::constant_time_distance_to_similarity;
use super::thresholds::{
    GLOBAL_MATCH_THRESHOLD, VEIN_FUSION_WEIGHT, PRINT_FUSION_WEIGHT
};
use crate::error::{Result, SableError};

/// Tolerance for floating-point comparison when validating fusion weights
const EPSILON: f64 = 1e-6;

/// REQ-008: Validate that fusion weights sum to 1.0
///
/// Verifies that multi-modal fusion weights sum to 1.0 within floating-point tolerance.
/// This validation is performed at configuration time and before fusion operations.
///
/// # Arguments
/// * `weights` - Slice of fusion weights to validate
///
/// # Returns
/// * `Ok(())` if weights are valid (sum to 1.0, all non-negative, non-empty)
/// * `Err(SableError::InvalidInput)` if validation fails
///
/// # Examples
/// ```
/// use sable_core::biometric::fusion::validate_fusion_weights;
///
/// // Valid weights
/// assert!(validate_fusion_weights(&[0.6, 0.4]).is_ok());
/// assert!(validate_fusion_weights(&[0.5, 0.3, 0.2]).is_ok());
///
/// // Invalid weights
/// assert!(validate_fusion_weights(&[0.5, 0.3]).is_err()); // Sum != 1.0
/// assert!(validate_fusion_weights(&[-0.1, 1.1]).is_err()); // Negative weight
/// assert!(validate_fusion_weights(&[]).is_err()); // Empty
/// ```
pub fn validate_fusion_weights(weights: &[f64]) -> Result<()> {
    // Check for empty weights
    if weights.is_empty() {
        return Err(SableError::InvalidInput(
            "Fusion weights must sum to 1.0".into()
        ));
    }

    // Check for negative weights
    for &weight in weights {
        if weight < 0.0 {
            return Err(SableError::InvalidInput(
                "Fusion weights must sum to 1.0".into()
            ));
        }
    }

    // Check that weights sum to 1.0
    let sum: f64 = weights.iter().sum();
    if (sum - 1.0).abs() > EPSILON {
        return Err(SableError::InvalidInput(
            "Fusion weights must sum to 1.0".into()
        ));
    }

    Ok(())
}

/// Fusion configuration from research
///
/// REQ-009: Uses centralized threshold constants for consistency.
/// See thresholds module for ADR-001 explaining threshold relationships.
pub struct FusionConfig {
    /// Weight for palm vein modality (from thresholds::VEIN_FUSION_WEIGHT)
    pub vein_weight: f64,
    /// Weight for palm print modality (from thresholds::PRINT_FUSION_WEIGHT)
    pub print_weight: f64,
    /// Final verification threshold (from thresholds::GLOBAL_MATCH_THRESHOLD)
    /// REQ-009: This is max(modality_thresholds) for consistent security
    pub threshold: f64,
    /// Fusion method
    pub method: FusionMethod,
}

impl FusionConfig {
    /// REQ-008: Create a new FusionConfig with validated weights
    ///
    /// # Arguments
    /// * `vein_weight` - Weight for palm vein modality
    /// * `print_weight` - Weight for palm print modality
    /// * `threshold` - Verification threshold
    /// * `method` - Fusion method to use
    ///
    /// # Returns
    /// * `Ok(FusionConfig)` if weights are valid
    /// * `Err(SableError::InvalidInput)` if weights don't sum to 1.0
    pub fn new(
        vein_weight: f64,
        print_weight: f64,
        threshold: f64,
        method: FusionMethod,
    ) -> Result<Self> {
        // REQ-008: Validate weights at configuration time
        validate_fusion_weights(&[vein_weight, print_weight])?;

        Ok(Self {
            vein_weight,
            print_weight,
            threshold,
            method,
        })
    }

    /// Get the weights as a slice for validation
    pub fn weights(&self) -> [f64; 2] {
        [self.vein_weight, self.print_weight]
    }
}

impl Default for FusionConfig {
    fn default() -> Self {
        // REQ-009: Use centralized threshold constants for consistency
        // These weights are validated at compile-time via the constant values
        Self {
            vein_weight: VEIN_FUSION_WEIGHT,
            print_weight: PRINT_FUSION_WEIGHT,
            threshold: GLOBAL_MATCH_THRESHOLD,
            method: FusionMethod::WeightedScore,
        }
    }
}

/// Fusion method for combining multi-modal biometric scores.
#[derive(Debug, Clone, Copy)]
pub enum FusionMethod {
    /// Weighted score-level fusion (research method)
    WeightedScore,
    /// Maximum score fusion
    MaxScore,
    /// Minimum score fusion
    MinScore,
    /// Product rule fusion
    ProductScore,
}

/// Fuse palm vein and palm print features into unified 512-dim vector for SABLE
/// This creates a single feature vector suitable for SABLE's crypto layer
pub fn fuse_modalities(
    vein_features: Option<&ModalityFeatureVector>,
    print_features: Option<&ModalityFeatureVector>,
) -> Result<ModalityFeatureVector> {
    match (vein_features, print_features) {
        (Some(vein), Some(print)) => {
            // Full multi-modal fusion
            let fused_features = fuse_feature_vectors(vein, print)?;
            Ok(ModalityFeatureVector::new(
                BiometricModality::PalmMultiModal,
                fused_features,
                (vein.confidence + print.confidence) / 2.0
            ))
        },
        (Some(vein), None) => {
            // Vein only - pad to 512 dimensions  
            let mut padded_features = vein.features.clone();
            while padded_features.len() < 512 {
                padded_features.push(0.5); // Neutral padding
            }
            padded_features.truncate(512);
            
            Ok(ModalityFeatureVector::new(
                BiometricModality::PalmVein,
                padded_features,
                vein.confidence * 0.8 // Reduced confidence for single modality
            ))
        },
        (None, Some(print)) => {
            // Print only - pad to 512 dimensions
            let mut padded_features = print.features.clone();
            while padded_features.len() < 512 {
                padded_features.push(0.5); // Neutral padding  
            }
            padded_features.truncate(512);
            
            Ok(ModalityFeatureVector::new(
                BiometricModality::PalmPrint,
                padded_features,
                print.confidence * 0.8 // Reduced confidence for single modality
            ))
        },
        (None, None) => {
            // REQ-005: Generic error message
            Err(SableError::InvalidInput("Insufficient biometric data".into()))
        }
    }
}

/// Fuse two feature vectors using research-based weighted combination
fn fuse_feature_vectors(
    vein: &ModalityFeatureVector,
    print: &ModalityFeatureVector,
) -> Result<Vec<f64>> {
    let config = FusionConfig::default();

    // REQ-008: Runtime validation of fusion weights before operation
    validate_fusion_weights(&config.weights())?;

    match config.method {
        FusionMethod::WeightedScore => {
            weighted_feature_fusion(vein, print, config.vein_weight, config.print_weight)
        },
        FusionMethod::MaxScore => max_feature_fusion(vein, print),
        FusionMethod::MinScore => min_feature_fusion(vein, print),
        FusionMethod::ProductScore => product_feature_fusion(vein, print),
    }
}

/// Weighted score-level fusion (primary research method)
/// Creates 512-dim vector: [vein_features * 0.6] ⊕ [print_features * 0.4]
fn weighted_feature_fusion(
    vein: &ModalityFeatureVector,
    print: &ModalityFeatureVector,
    vein_weight: f64,
    print_weight: f64,
) -> Result<Vec<f64>> {
    // REQ-008: Runtime validation of fusion weights before operation
    validate_fusion_weights(&[vein_weight, print_weight])?;

    let mut fused = Vec::with_capacity(512);

    // Strategy: Interleave weighted features to preserve both modalities
    let vein_len = vein.features.len();
    let print_len = print.features.len();
    
    // Calculate how to distribute 512 dimensions
    let vein_dims = (512.0 * vein_weight).round() as usize; // ~307 dimensions
    let print_dims = 512 - vein_dims;                      // ~205 dimensions
    
    // Add weighted vein features
    for i in 0..vein_dims {
        let idx = (i * vein_len) / vein_dims;
        let weighted_feature = vein.features.get(idx).unwrap_or(&0.5) * vein_weight;
        fused.push(weighted_feature);
    }
    
    // Add weighted print features
    for i in 0..print_dims {
        let idx = (i * print_len) / print_dims;
        let weighted_feature = print.features.get(idx).unwrap_or(&0.5) * print_weight;
        fused.push(weighted_feature);
    }
    
    // Normalize fused features to [0,1] range
    normalize_features(&mut fused);
    
    Ok(fused)
}

/// Maximum feature fusion - take element-wise maximum
fn max_feature_fusion(
    vein: &ModalityFeatureVector,
    print: &ModalityFeatureVector,
) -> Result<Vec<f64>> {
    let mut fused = Vec::with_capacity(512);
    
    for i in 0..512 {
        let vein_val = vein.features.get(i % vein.features.len()).unwrap_or(&0.5);
        let print_val = print.features.get(i % print.features.len()).unwrap_or(&0.5);
        fused.push(vein_val.max(*print_val));
    }
    
    Ok(fused)
}

/// Minimum feature fusion - take element-wise minimum  
fn min_feature_fusion(
    vein: &ModalityFeatureVector,
    print: &ModalityFeatureVector,
) -> Result<Vec<f64>> {
    let mut fused = Vec::with_capacity(512);
    
    for i in 0..512 {
        let vein_val = vein.features.get(i % vein.features.len()).unwrap_or(&0.5);
        let print_val = print.features.get(i % print.features.len()).unwrap_or(&0.5);
        fused.push(vein_val.min(*print_val));
    }
    
    Ok(fused)
}

/// Product rule fusion - multiply corresponding features
fn product_feature_fusion(
    vein: &ModalityFeatureVector,
    print: &ModalityFeatureVector,
) -> Result<Vec<f64>> {
    let mut fused = Vec::with_capacity(512);
    
    for i in 0..512 {
        let vein_val = vein.features.get(i % vein.features.len()).unwrap_or(&0.5);
        let print_val = print.features.get(i % print.features.len()).unwrap_or(&0.5);
        fused.push(vein_val * print_val);
    }
    
    normalize_features(&mut fused);
    Ok(fused)
}

/// Compute verification score between enrolled and live templates
/// Returns weighted score using research-based fusion
pub fn compute_verification_score(
    enrolled_vein: Option<&ModalityFeatureVector>,
    enrolled_print: Option<&ModalityFeatureVector>,
    live_vein: Option<&ModalityFeatureVector>,
    live_print: Option<&ModalityFeatureVector>,
) -> Result<f64> {
    let config = FusionConfig::default();

    // REQ-008: Runtime validation of fusion weights before operation
    validate_fusion_weights(&config.weights())?;

    let mut scores = Vec::new();
    let mut weights = Vec::new();
    
    // Compute vein score if both modalities present
    if let (Some(enrolled), Some(live)) = (enrolled_vein, live_vein) {
        let vein_score = compute_modality_score(enrolled, live)?;
        scores.push(vein_score);
        weights.push(config.vein_weight);
    }
    
    // Compute print score if both modalities present
    if let (Some(enrolled), Some(live)) = (enrolled_print, live_print) {
        let print_score = compute_modality_score(enrolled, live)?;
        scores.push(print_score);
        weights.push(config.print_weight);
    }
    
    if scores.is_empty() {
        // REQ-005: Generic error message
        return Err(SableError::InvalidInput("Insufficient biometric data for verification".into()));
    }
    
    // Weighted score fusion
    let weighted_sum: f64 = scores.iter().zip(weights.iter())
        .map(|(score, weight)| score * weight)
        .sum();
    let weight_sum: f64 = weights.iter().sum();
    
    Ok(weighted_sum / weight_sum)
}

/// Compute similarity score between two feature vectors of same modality.
///
/// REQ-004: Uses constant-time distance calculation and similarity conversion
/// to prevent timing side-channel attacks during biometric matching.
fn compute_modality_score(
    enrolled: &ModalityFeatureVector,
    live: &ModalityFeatureVector,
) -> Result<f64> {
    if enrolled.modality != live.modality {
        // REQ-005: Generic error message - doesn't reveal modality types
        return Err(SableError::InvalidInput("Incompatible biometric data".into()));
    }

    // Use constant-time Euclidean distance (REQ-004)
    let distance = enrolled.euclidean_distance(live)?;

    // Research threshold-based normalization
    let max_distance = match enrolled.modality {
        BiometricModality::PalmVein => 2.0,      // Research-calibrated max distance
        BiometricModality::PalmPrint => 1.5,     // Research-calibrated max distance
        BiometricModality::PalmMultiModal => 2.5, // Research-calibrated max distance
    };

    // Use constant-time distance-to-similarity conversion (REQ-004)
    Ok(constant_time_distance_to_similarity(distance, max_distance))
}

/// Advanced fusion with adaptive weighting based on quality
pub fn adaptive_weighted_fusion(
    vein_features: Option<&ModalityFeatureVector>,
    print_features: Option<&ModalityFeatureVector>,
) -> Result<ModalityFeatureVector> {
    match (vein_features, print_features) {
        (Some(vein), Some(print)) => {
            // Adaptive weighting based on confidence scores
            let total_confidence = vein.confidence + print.confidence;
            let vein_weight = vein.confidence / total_confidence;
            let print_weight = print.confidence / total_confidence;

            // REQ-008: Runtime validation of adaptive fusion weights
            // Note: weighted_feature_fusion also validates, but we validate here
            // for early failure with clear context
            validate_fusion_weights(&[vein_weight, print_weight])?;

            let fused_features = weighted_feature_fusion(vein, print, vein_weight, print_weight)?;
            
            Ok(ModalityFeatureVector::new(
                BiometricModality::PalmMultiModal,
                fused_features,
                (vein.confidence + print.confidence) / 2.0
            ))
        },
        _ => {
            // Fall back to standard fusion
            fuse_modalities(vein_features, print_features)
        }
    }
}

/// Feature quality assessment for fusion decisions
pub fn assess_feature_quality(features: &ModalityFeatureVector) -> f64 {
    // Quality metrics based on feature statistics
    let mean = features.features.iter().sum::<f64>() / features.features.len() as f64;
    let variance = features.features.iter()
        .map(|&x| (x - mean).powi(2))
        .sum::<f64>() / features.features.len() as f64;
    let std_dev = variance.sqrt();
    
    // Quality score based on feature distribution
    let distribution_quality = (std_dev * 4.0).min(1.0); // Higher variance = better quality
    let confidence_quality = features.confidence;
    
    (distribution_quality + confidence_quality) / 2.0
}

/// Decision-level fusion for final verification
///
/// REQ-008: This function uses validated fusion weights from FusionConfig.
/// The weights are validated at configuration time.
pub fn decision_level_fusion(
    vein_decision: Option<bool>,
    print_decision: Option<bool>,
    vein_score: Option<f64>,
    print_score: Option<f64>,
) -> Result<(bool, f64)> {
    let config = FusionConfig::default();

    // REQ-008: Runtime validation of fusion weights
    validate_fusion_weights(&config.weights())?;

    match (vein_decision, print_decision, vein_score, print_score) {
        (Some(vein_ok), Some(print_ok), Some(v_score), Some(p_score)) => {
            // Both modalities available
            let combined_score = v_score * config.vein_weight + p_score * config.print_weight;
            let decision = vein_ok || print_ok; // OR rule for leniency
            Ok((decision, combined_score))
        },
        (Some(decision), None, Some(score), None) |
        (None, Some(decision), None, Some(score)) => {
            // Single modality
            Ok((decision, score * 0.8)) // Reduced confidence for single modality
        },
        _ => {
            // No valid data
            Ok((false, 0.0))
        }
    }
}

/// Normalize feature vector to [0,1] range
fn normalize_features(features: &mut [f64]) {
    if features.is_empty() {
        return;
    }
    
    let min_val = features.iter().fold(f64::INFINITY, |a, &b| a.min(b));
    let max_val = features.iter().fold(f64::NEG_INFINITY, |a, &b| a.max(b));
    let range = max_val - min_val;
    
    if range > 0.0 {
        for feature in features {
            *feature = (*feature - min_val) / range;
        }
    }
}

/// Performance metrics for fusion evaluation
#[derive(Debug, Clone)]
pub struct FusionMetrics {
    /// Overall accuracy (1 - error rate)
    pub accuracy: f64,
    /// False accept rate (FAR)
    pub false_accept_rate: f64,
    /// False reject rate (FRR)
    pub false_reject_rate: f64,
    /// Equal error rate (EER)
    pub equal_error_rate: f64,
}

impl FusionMetrics {
    /// Calculate metrics from genuine and impostor scores
    pub fn from_scores(genuine_scores: &[f64], impostor_scores: &[f64], threshold: f64) -> Self {
        let false_rejects = genuine_scores.iter()
            .filter(|&&score| score < threshold)
            .count();
        let false_accepts = impostor_scores.iter()
            .filter(|&&score| score >= threshold)
            .count();
            
        let frr = false_rejects as f64 / genuine_scores.len() as f64;
        let far = false_accepts as f64 / impostor_scores.len() as f64;
        let accuracy = 1.0 - (frr + far) / 2.0;
        
        // EER calculation (simplified)
        let eer = (frr + far) / 2.0;
        
        Self {
            accuracy,
            false_accept_rate: far,
            false_reject_rate: frr,
            equal_error_rate: eer,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::biometric::BiometricModality;

    fn create_test_vein_features() -> ModalityFeatureVector {
        let features: Vec<f64> = (0..512).map(|i| (i as f64) / 512.0).collect();
        ModalityFeatureVector::new(BiometricModality::PalmVein, features, 0.95)
    }

    fn create_test_print_features() -> ModalityFeatureVector {
        let features: Vec<f64> = (0..256).map(|i| (i as f64) / 256.0 + 0.1).collect();
        ModalityFeatureVector::new(BiometricModality::PalmPrint, features, 0.90)
    }

    #[test]
    fn test_weighted_fusion() {
        let vein = create_test_vein_features();
        let print = create_test_print_features();
        
        let fused = fuse_modalities(Some(&vein), Some(&print)).unwrap();
        
        assert_eq!(fused.modality, BiometricModality::PalmMultiModal);
        assert_eq!(fused.features.len(), 512);
        assert!(fused.confidence > 0.9);
    }

    #[test]
    fn test_single_modality_fusion() {
        let vein = create_test_vein_features();
        
        let fused = fuse_modalities(Some(&vein), None).unwrap();
        
        assert_eq!(fused.modality, BiometricModality::PalmVein);
        assert_eq!(fused.features.len(), 512);
        assert!(fused.confidence > 0.7); // Reduced for single modality
    }

    #[test]
    fn test_verification_score() {
        let enrolled_vein = create_test_vein_features();
        let live_vein = create_test_vein_features();
        let enrolled_print = create_test_print_features();
        let live_print = create_test_print_features();
        
        let score = compute_verification_score(
            Some(&enrolled_vein),
            Some(&enrolled_print),
            Some(&live_vein),
            Some(&live_print),
        ).unwrap();
        
        assert!(score >= 0.0);
        assert!(score <= 1.0);
        assert!(score > 0.5); // Should be high for identical features
    }

    #[test]
    fn test_adaptive_fusion() {
        let vein = create_test_vein_features();
        let print = create_test_print_features();
        
        let fused = adaptive_weighted_fusion(Some(&vein), Some(&print)).unwrap();
        
        assert_eq!(fused.modality, BiometricModality::PalmMultiModal);
        assert_eq!(fused.features.len(), 512);
    }

    #[test]
    fn test_decision_level_fusion() {
        let (decision, score) = decision_level_fusion(
            Some(true),
            Some(false),
            Some(0.8),
            Some(0.6)
        ).unwrap();

        assert_eq!(decision, true); // OR rule
        assert!(score > 0.6);
        assert!(score < 0.8);
    }

    #[test]
    fn test_feature_normalization() {
        let mut features = vec![0.0, 5.0, 10.0, 15.0, 20.0];
        normalize_features(&mut features);
        
        assert_eq!(features[0], 0.0);
        assert_eq!(features[4], 1.0);
        assert!(features.iter().all(|&x| x >= 0.0 && x <= 1.0));
    }

    #[test]
    fn test_fusion_config() {
        let config = FusionConfig::default();

        // REQ-009: Verify config uses centralized threshold constants
        assert_eq!(config.vein_weight, VEIN_FUSION_WEIGHT);
        assert_eq!(config.print_weight, PRINT_FUSION_WEIGHT);
        assert_eq!(config.threshold, GLOBAL_MATCH_THRESHOLD);
    }

    #[test]
    fn test_fusion_config_uses_consistent_thresholds() {
        // REQ-009: Verify FusionConfig uses the centralized constants
        let config = FusionConfig::default();

        // Weights should match the module constants
        assert_eq!(config.vein_weight, 0.6, "Vein weight should be 0.6");
        assert_eq!(config.print_weight, 0.4, "Print weight should be 0.4");

        // Threshold should be the global threshold (max of modality thresholds)
        assert_eq!(config.threshold, 0.80, "Threshold should be 0.80 (GLOBAL_MATCH_THRESHOLD)");
    }

    // REQ-008: Tests for fusion weight validation

    #[test]
    fn test_validate_fusion_weights_valid_research_weights() {
        // Research-defined weights: 0.6 vein + 0.4 print = 1.0
        assert!(validate_fusion_weights(&[0.6, 0.4]).is_ok());
    }

    #[test]
    fn test_validate_fusion_weights_valid_equal_weights() {
        // Equal weights: 0.5 + 0.5 = 1.0
        assert!(validate_fusion_weights(&[0.5, 0.5]).is_ok());
    }

    #[test]
    fn test_validate_fusion_weights_valid_three_modalities() {
        // Three modalities: 0.5 + 0.3 + 0.2 = 1.0
        assert!(validate_fusion_weights(&[0.5, 0.3, 0.2]).is_ok());
    }

    #[test]
    fn test_validate_fusion_weights_valid_single_modality() {
        // Single modality with full weight
        assert!(validate_fusion_weights(&[1.0]).is_ok());
    }

    #[test]
    fn test_validate_fusion_weights_valid_within_epsilon() {
        // Weights that sum to 1.0 within floating-point tolerance
        let weights = [0.333333333, 0.333333333, 0.333333334];
        assert!(validate_fusion_weights(&weights).is_ok());
    }

    #[test]
    fn test_validate_fusion_weights_invalid_sum_too_low() {
        // Sum = 0.8, should fail
        let result = validate_fusion_weights(&[0.5, 0.3]);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("Fusion weights must sum to 1.0"));
    }

    #[test]
    fn test_validate_fusion_weights_invalid_sum_too_high() {
        // Sum = 1.2, should fail
        let result = validate_fusion_weights(&[0.7, 0.5]);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("Fusion weights must sum to 1.0"));
    }

    #[test]
    fn test_validate_fusion_weights_invalid_empty() {
        // Empty weights should fail
        let result = validate_fusion_weights(&[]);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("Fusion weights must sum to 1.0"));
    }

    #[test]
    fn test_validate_fusion_weights_invalid_negative() {
        // Negative weight should fail (even if sum is 1.0)
        let result = validate_fusion_weights(&[-0.1, 1.1]);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("Fusion weights must sum to 1.0"));
    }

    #[test]
    fn test_validate_fusion_weights_invalid_all_zeros() {
        // All zeros don't sum to 1.0
        let result = validate_fusion_weights(&[0.0, 0.0]);
        assert!(result.is_err());
    }

    #[test]
    fn test_fusion_config_new_valid() {
        // Valid configuration should succeed
        let config = FusionConfig::new(0.6, 0.4, 0.77, FusionMethod::WeightedScore);
        assert!(config.is_ok());
        let config = config.unwrap();
        assert_eq!(config.vein_weight, 0.6);
        assert_eq!(config.print_weight, 0.4);
    }

    #[test]
    fn test_fusion_config_new_invalid_weights() {
        // Invalid weights should fail at configuration time
        let config = FusionConfig::new(0.7, 0.5, 0.77, FusionMethod::WeightedScore);
        assert!(config.is_err());
    }

    #[test]
    fn test_fusion_config_weights_method() {
        let config = FusionConfig::default();
        let weights = config.weights();
        assert_eq!(weights, [0.6, 0.4]);
        assert!(validate_fusion_weights(&weights).is_ok());
    }
}
