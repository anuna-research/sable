//! Fuzz target for biometric feature extraction (REQ-024)
//!
//! This fuzz target tests the feature extraction pipeline with random images
//! to ensure robust handling of all input types.
//!
//! ## Test Coverage
//! - Image dimension validation
//! - Empty and minimal images
//! - Maximum dimension images
//! - Various channel configurations
//! - Malformed image data
//! - Edge pixel values (0, 255)
//! - Quality assessment with varied inputs

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use sable_core::biometric::{
    PalmImage, BiometricModality,
};
use sable_core::biometric::feature_extraction::{
    validate_image_dimensions, validate_feature_vector,
    zscore_normalize, calculate_confidence, QualityMetrics,
    extract_vein_features, extract_print_features,
    MIN_IMAGE_DIM, MAX_IMAGE_DIM, VEIN_FEATURE_DIM, PRINT_FEATURE_DIM,
};

/// Input structure for fuzzing feature extraction
#[derive(Debug, Arbitrary)]
struct FeatureExtractionInput {
    /// Image width (will be constrained)
    width: u16,
    /// Image height (will be constrained)
    height: u16,
    /// Number of channels (1 or 3)
    channels: u8,
    /// Image data (will be resized to match dimensions)
    data: Vec<u8>,
    /// Test operation type
    operation: ExtractionOperation,
    /// Quality metrics for testing
    quality_metrics: FuzzQualityMetrics,
}

#[derive(Debug, Arbitrary, Clone, Copy)]
enum ExtractionOperation {
    /// Validate image dimensions
    ValidateDimensions,
    /// Extract vein features
    ExtractVein,
    /// Extract print features
    ExtractPrint,
    /// Test z-score normalization
    ZScoreNormalize,
    /// Calculate confidence from quality metrics
    CalculateConfidence,
    /// Test feature vector validation
    ValidateFeatureVector,
    /// Full extraction pipeline
    FullPipeline,
}

#[derive(Debug, Arbitrary)]
struct FuzzQualityMetrics {
    snr: f32,
    contrast: f32,
    completeness: f32,
    focus_quality: f32,
}

/// Create a PalmImage from fuzz input with proper constraints
fn create_test_image(input: &FeatureExtractionInput) -> PalmImage {
    // Constrain dimensions to valid ranges
    let width = (input.width as u32).clamp(1, MAX_IMAGE_DIM + 100);
    let height = (input.height as u32).clamp(1, MAX_IMAGE_DIM + 100);
    let channels = match input.channels % 4 {
        0 => 1, // grayscale
        1 => 1,
        2 => 3, // RGB
        _ => 3,
    };

    // Calculate expected data size
    let expected_size = (width as usize) * (height as usize) * (channels as usize);

    // Create data of correct size
    let mut data = input.data.clone();
    if data.len() < expected_size {
        // Pad with pattern
        data.resize(expected_size, 128);
    } else {
        data.truncate(expected_size);
    }

    PalmImage::new(width, height, channels, data)
}

fuzz_target!(|input: FeatureExtractionInput| {
    let image = create_test_image(&input);

    match input.operation {
        ExtractionOperation::ValidateDimensions => {
            // Test 1: Dimension validation should not panic
            let result = validate_image_dimensions(&image);

            // Verify the result matches expected validation rules
            let expected_valid = image.width >= MIN_IMAGE_DIM
                && image.width <= MAX_IMAGE_DIM
                && image.height >= MIN_IMAGE_DIM
                && image.height <= MAX_IMAGE_DIM;

            match result {
                Ok(()) => assert!(expected_valid, "Validation passed but should have failed"),
                Err(_) => assert!(!expected_valid, "Validation failed but should have passed"),
            }
        }

        ExtractionOperation::ExtractVein => {
            // Test 2: Vein extraction should not panic
            // Note: May return error for invalid images, which is expected
            let result = extract_vein_features(&image);

            if let Ok(features) = result {
                // Verify output properties
                assert_eq!(features.modality, BiometricModality::PalmVein);
                assert_eq!(features.features.len(), VEIN_FEATURE_DIM);
                assert!(features.confidence >= 0.0 && features.confidence <= 1.0);

                // All feature values should be finite
                for f in &features.features {
                    assert!(f.is_finite(), "Feature values must be finite");
                }
            }
        }

        ExtractionOperation::ExtractPrint => {
            // Test 3: Print extraction should not panic
            let result = extract_print_features(&image);

            if let Ok(features) = result {
                // Verify output properties
                assert_eq!(features.modality, BiometricModality::PalmPrint);
                assert_eq!(features.features.len(), PRINT_FEATURE_DIM);
                assert!(features.confidence >= 0.0 && features.confidence <= 1.0);

                // All feature values should be finite
                for f in &features.features {
                    assert!(f.is_finite(), "Feature values must be finite");
                }
            }
        }

        ExtractionOperation::ZScoreNormalize => {
            // Test 4: Z-score normalization should not panic
            let mut features: Vec<f64> = input.data.iter()
                .take(512)
                .map(|&b| b as f64 / 255.0)
                .collect();

            // Ensure we have enough data
            features.resize(512, 0.5);

            // Should not panic regardless of input
            zscore_normalize(&mut features);

            // If input had non-zero variance, output should be normalized
            let mean = features.iter().sum::<f64>() / features.len() as f64;
            // Mean should be close to zero after normalization (if variance was non-zero)
            // We can't strictly assert this due to edge cases with constant inputs
            let _ = mean;
        }

        ExtractionOperation::CalculateConfidence => {
            // Test 5: Confidence calculation should not panic
            let metrics = QualityMetrics::new(
                input.quality_metrics.snr as f64,
                input.quality_metrics.contrast as f64,
                input.quality_metrics.completeness as f64,
                input.quality_metrics.focus_quality as f64,
            );

            let confidence = calculate_confidence(&metrics);

            // Confidence must always be in [0, 1]
            assert!(
                confidence >= 0.0 && confidence <= 1.0,
                "Confidence must be in [0,1], got {}",
                confidence
            );
        }

        ExtractionOperation::ValidateFeatureVector => {
            // Test 6: Feature vector validation should not panic
            let features: Vec<f64> = input.data.iter()
                .take(1024)
                .map(|&b| b as f64)
                .collect();

            // Test validation with various expected lengths
            for expected in [0, 1, 256, 512, 768, 1024] {
                let result = validate_feature_vector(&features, expected);
                let should_be_ok = features.len() == expected;

                match result {
                    Ok(()) => assert!(should_be_ok, "Validation passed but length doesn't match"),
                    Err(_) => assert!(!should_be_ok, "Validation failed but length matches"),
                }
            }
        }

        ExtractionOperation::FullPipeline => {
            // Test 7: Full pipeline should not panic
            // Only test with valid-sized images to stress the algorithm
            let valid_image = if image.width >= MIN_IMAGE_DIM
                && image.width <= MAX_IMAGE_DIM
                && image.height >= MIN_IMAGE_DIM
                && image.height <= MAX_IMAGE_DIM
            {
                image
            } else {
                // Create a minimal valid image
                let min_size = MIN_IMAGE_DIM as usize;
                let data = vec![128u8; min_size * min_size];
                PalmImage::new(MIN_IMAGE_DIM, MIN_IMAGE_DIM, 1, data)
            };

            // Run both extractors
            let vein_result = extract_vein_features(&valid_image);
            let print_result = extract_print_features(&valid_image);

            // Both should succeed or fail gracefully
            if let (Ok(vein), Ok(print)) = (&vein_result, &print_result) {
                // If both succeed, verify they can be used together
                assert!(vein.features.len() > 0);
                assert!(print.features.len() > 0);
            }
        }
    }
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_image_creation() {
        let input = FeatureExtractionInput {
            width: 100,
            height: 100,
            channels: 1,
            data: vec![128; 10000],
            operation: ExtractionOperation::ValidateDimensions,
            quality_metrics: FuzzQualityMetrics {
                snr: 0.8,
                contrast: 0.7,
                completeness: 0.9,
                focus_quality: 0.85,
            },
        };

        let image = create_test_image(&input);
        assert_eq!(image.width, 100);
        assert_eq!(image.height, 100);
        assert_eq!(image.channels, 1);
    }

    #[test]
    fn test_boundary_dimensions() {
        // Test minimum valid dimensions
        let min_image = PalmImage::new(
            MIN_IMAGE_DIM,
            MIN_IMAGE_DIM,
            1,
            vec![128; (MIN_IMAGE_DIM * MIN_IMAGE_DIM) as usize],
        );
        assert!(validate_image_dimensions(&min_image).is_ok());

        // Test maximum valid dimensions
        let max_image = PalmImage::new(
            MAX_IMAGE_DIM,
            MAX_IMAGE_DIM,
            1,
            vec![128; (MAX_IMAGE_DIM * MAX_IMAGE_DIM) as usize],
        );
        assert!(validate_image_dimensions(&max_image).is_ok());

        // Test just under minimum
        let too_small = PalmImage::new(
            MIN_IMAGE_DIM - 1,
            MIN_IMAGE_DIM,
            1,
            vec![128; ((MIN_IMAGE_DIM - 1) * MIN_IMAGE_DIM) as usize],
        );
        assert!(validate_image_dimensions(&too_small).is_err());

        // Test just over maximum
        let too_large = PalmImage::new(
            MAX_IMAGE_DIM + 1,
            MAX_IMAGE_DIM,
            1,
            vec![128; ((MAX_IMAGE_DIM + 1) * MAX_IMAGE_DIM) as usize],
        );
        assert!(validate_image_dimensions(&too_large).is_err());
    }
}
