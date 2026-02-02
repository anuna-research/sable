// SABLE Biometric Threshold Constants Module
//
// REQ-009: Defines consistent threshold strategy for biometric verification
//
// ADR-001: Threshold Consistency Strategy
// =======================================
//
// Problem: There was inconsistency between global threshold (0.77) and modality
// thresholds (0.75 for vein, 0.80 for print).
//
// Decision: Use GLOBAL_MATCH_THRESHOLD = max(modality_thresholds) = 0.80
//
// Rationale:
// - Using the maximum ensures no single modality can weaken overall security
// - Individual modalities can use their research-calibrated thresholds internally
// - The global threshold for final verification decisions uses the strictest standard
//
// Consequences:
// - Slightly higher false reject rate for vein-only verification
// - Stronger security guarantee: if either modality passes at its threshold,
//   the combined score must still meet the global (stricter) threshold
// - Multi-modal fusion typically exceeds global threshold due to complementary features

/// Modality-specific verification threshold for palm vein matching.
///
/// From research: Palm vein patterns have inherent variability that requires
/// a slightly lower threshold (0.75) to maintain acceptable false reject rates.
/// This threshold was calibrated on research datasets to achieve ~0.1% FRR.
pub const VEIN_MATCH_THRESHOLD: f64 = 0.75;

/// Modality-specific verification threshold for palm print matching.
///
/// From research: Palm print ridge patterns are more stable than vein patterns,
/// allowing a higher threshold (0.80) for improved security.
/// This threshold was calibrated on research datasets to achieve ~0.01% FAR.
pub const PRINT_MATCH_THRESHOLD: f64 = 0.80;

/// Global verification threshold for final match decisions.
///
/// ADR-001: This is set to max(VEIN_MATCH_THRESHOLD, PRINT_MATCH_THRESHOLD) = 0.80
/// to ensure consistent security. Using the maximum ensures no modality can
/// weaken the overall system security.
///
/// For multi-modal fusion, the combined score must meet this threshold.
/// The fusion weights (0.6 vein + 0.4 print) typically produce scores
/// above this threshold for genuine users due to complementary features.
pub const GLOBAL_MATCH_THRESHOLD: f64 = 0.80;

/// Fusion weight for palm vein modality.
///
/// From research: Vein patterns contribute 60% to the fused score due to
/// their higher discriminative power and resistance to spoofing.
pub const VEIN_FUSION_WEIGHT: f64 = 0.6;

/// Fusion weight for palm print modality.
///
/// From research: Print patterns contribute 40% to the fused score,
/// complementing vein features with surface texture information.
pub const PRINT_FUSION_WEIGHT: f64 = 0.4;

/// Get the threshold for a specific biometric modality.
///
/// Returns the research-calibrated threshold for individual modality matching.
/// For final verification decisions, use GLOBAL_MATCH_THRESHOLD instead.
#[inline]
pub const fn threshold_for_modality(modality: super::BiometricModality) -> f64 {
    match modality {
        super::BiometricModality::PalmVein => VEIN_MATCH_THRESHOLD,
        super::BiometricModality::PalmPrint => PRINT_MATCH_THRESHOLD,
        super::BiometricModality::PalmMultiModal => GLOBAL_MATCH_THRESHOLD,
    }
}

/// Validate that threshold constants are internally consistent.
///
/// This is a compile-time assertion that GLOBAL_MATCH_THRESHOLD equals
/// the maximum of the modality thresholds.
#[inline]
pub const fn validate_threshold_consistency() -> bool {
    // Global threshold should equal max(vein, print) thresholds
    let max_modality = if VEIN_MATCH_THRESHOLD > PRINT_MATCH_THRESHOLD {
        VEIN_MATCH_THRESHOLD
    } else {
        PRINT_MATCH_THRESHOLD
    };

    // Use f64 comparison with small epsilon for floating point
    // Since these are constants, direct comparison is safe
    (GLOBAL_MATCH_THRESHOLD - max_modality).abs() < 0.0001
}

// Compile-time assertion that thresholds are consistent
const _: () = assert!(validate_threshold_consistency(),
    "GLOBAL_MATCH_THRESHOLD must equal max(VEIN_MATCH_THRESHOLD, PRINT_MATCH_THRESHOLD)");

#[cfg(test)]
mod tests {
    use super::*;
    use crate::biometric::BiometricModality;

    #[test]
    fn test_threshold_values() {
        assert_eq!(VEIN_MATCH_THRESHOLD, 0.75);
        assert_eq!(PRINT_MATCH_THRESHOLD, 0.80);
        assert_eq!(GLOBAL_MATCH_THRESHOLD, 0.80);
    }

    #[test]
    fn test_global_threshold_is_max_of_modalities() {
        let max_modality = VEIN_MATCH_THRESHOLD.max(PRINT_MATCH_THRESHOLD);
        assert_eq!(GLOBAL_MATCH_THRESHOLD, max_modality,
            "GLOBAL_MATCH_THRESHOLD must equal max(VEIN_MATCH_THRESHOLD, PRINT_MATCH_THRESHOLD)");
    }

    #[test]
    fn test_threshold_consistency_check() {
        assert!(validate_threshold_consistency(),
            "Threshold consistency validation failed");
    }

    #[test]
    fn test_threshold_for_modality() {
        assert_eq!(threshold_for_modality(BiometricModality::PalmVein), VEIN_MATCH_THRESHOLD);
        assert_eq!(threshold_for_modality(BiometricModality::PalmPrint), PRINT_MATCH_THRESHOLD);
        assert_eq!(threshold_for_modality(BiometricModality::PalmMultiModal), GLOBAL_MATCH_THRESHOLD);
    }

    #[test]
    fn test_fusion_weights_sum_to_one() {
        let weight_sum = VEIN_FUSION_WEIGHT + PRINT_FUSION_WEIGHT;
        assert!((weight_sum - 1.0).abs() < 0.0001,
            "Fusion weights must sum to 1.0, got {}", weight_sum);
    }

    #[test]
    fn test_thresholds_in_valid_range() {
        // All thresholds should be between 0.5 and 1.0 for meaningful verification
        assert!(VEIN_MATCH_THRESHOLD >= 0.5 && VEIN_MATCH_THRESHOLD <= 1.0);
        assert!(PRINT_MATCH_THRESHOLD >= 0.5 && PRINT_MATCH_THRESHOLD <= 1.0);
        assert!(GLOBAL_MATCH_THRESHOLD >= 0.5 && GLOBAL_MATCH_THRESHOLD <= 1.0);
    }

    #[test]
    fn test_print_threshold_at_least_vein_threshold() {
        // Print threshold should be >= vein threshold (stricter or equal)
        // This ensures GLOBAL = PRINT for the current calibration
        assert!(PRINT_MATCH_THRESHOLD >= VEIN_MATCH_THRESHOLD,
            "Print threshold should be at least as strict as vein threshold");
    }
}
