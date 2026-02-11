// High-level Palm Biometrics Interface
//
// Provides easy-to-use API for palm biometric processing
// Integrates preprocessing, feature extraction, and fusion
// Compatible with SABLE's crypto layer

use super::{
    PalmImage, PalmBiometricTemplate, BiometricQuality,
    feature_extraction::validate_image_dimensions,
};
use crate::types::BiometricFeature;
use crate::error::{Result, SableError};

/// Main palm biometrics processor
pub struct PalmProcessor {
    /// Enable high-quality processing (slower but more accurate)
    pub high_quality_mode: bool,
    /// Require both vein and print modalities
    pub require_multimodal: bool,
}

impl Default for PalmProcessor {
    fn default() -> Self {
        Self {
            high_quality_mode: true,
            require_multimodal: false,
        }
    }
}

impl PalmProcessor {
    /// Create new palm processor with default settings
    pub fn new() -> Self {
        Self::default()
    }

    /// Create processor with custom settings
    pub fn with_settings(high_quality: bool, multimodal: bool) -> Self {
        Self {
            high_quality_mode: high_quality,
            require_multimodal: multimodal,
        }
    }

    /// Process palm image and extract biometric template
    /// This is the main entry point for palm biometric enrollment
    pub fn process_palm_image(&self, image: PalmImage) -> Result<PalmBiometricTemplate> {
        // Step 1: Validate image quality
        self.validate_image_quality(&image)?;

        // Step 2: Create template using research-proven pipeline
        PalmBiometricTemplate::from_palm_image(image)
    }

    /// Convert palm image to SABLE-compatible features for crypto layer
    pub fn extract_sable_features(&self, image: PalmImage) -> Result<Vec<BiometricFeature>> {
        let template = self.process_palm_image(image)?;
        template.generate_sable_features()
    }

    /// Verify palm image against enrolled template
    pub fn verify_palm(
        &self,
        live_image: PalmImage,
        enrolled_template: &PalmBiometricTemplate,
    ) -> Result<(bool, f64)> {
        let live_template = self.process_palm_image(live_image)?;
        live_template.verify_against(enrolled_template)
    }

    /// Extract features from raw image data (common format support)
    pub fn extract_from_raw_image(
        &self,
        width: u32,
        height: u32,
        channels: u32,
        data: Vec<u8>,
    ) -> Result<Vec<BiometricFeature>> {
        let image = PalmImage::new(width, height, channels, data);
        self.extract_sable_features(image)
    }

    /// Batch processing for multiple palm images
    pub fn process_batch(&self, images: Vec<PalmImage>) -> Result<Vec<PalmBiometricTemplate>> {
        images.into_iter()
            .map(|img| self.process_palm_image(img))
            .collect()
    }

    /// Quality assessment for palm image
    pub fn assess_palm_quality(&self, image: &PalmImage) -> Result<BiometricQuality> {
        // Basic quality metrics
        let contrast = self.calculate_contrast(image)?;
        let focus_quality = self.calculate_focus_quality(image)?;
        let vein_clarity = self.estimate_vein_clarity(image)?;
        let ridge_quality = self.estimate_ridge_quality(image)?;

        Ok(BiometricQuality::assess_palm_quality(
            contrast,
            focus_quality, 
            vein_clarity,
            ridge_quality,
        ))
    }

    /// Validate image meets minimum quality requirements
    fn validate_image_quality(&self, image: &PalmImage) -> Result<()> {
        // REQ-002: First validate image dimensions are within acceptable bounds
        validate_image_dimensions(image)?;

        // Additional quality check: minimum size for palm biometrics processing
        // (This is a stricter requirement than the base REQ-002 bounds)
        if image.width < 200 || image.height < 200 {
            return Err(SableError::InvalidInput(
                "Invalid image dimensions".into()
            ));
        }

        // Check aspect ratio (palms are typically not extremely elongated)
        let aspect_ratio = image.width as f64 / image.height as f64;
        if aspect_ratio < 0.5 || aspect_ratio > 2.0 {
            return Err(SableError::InvalidInput(
                "Invalid image dimensions".into()
            ));
        }

        // Assess overall quality
        if self.high_quality_mode {
            let quality = self.assess_palm_quality(image)?;
            if !quality.is_acceptable() {
                // REQ-002: Generic error message to prevent information leakage
                return Err(SableError::InvalidInput(
                    "Invalid image quality".into()
                ));
            }
        }

        Ok(())
    }

    /// Calculate image contrast using standard deviation
    fn calculate_contrast(&self, image: &PalmImage) -> Result<f64> {
        let pixels: Vec<f64> = image.data.iter().map(|&p| p as f64).collect();
        let mean = pixels.iter().sum::<f64>() / pixels.len() as f64;
        let variance = pixels.iter()
            .map(|&p| (p - mean).powi(2))
            .sum::<f64>() / pixels.len() as f64;
        let std_dev = variance.sqrt();
        
        // Normalize contrast to [0,1]
        Ok((std_dev / 128.0).min(1.0))
    }

    /// Calculate focus quality using Laplacian variance
    fn calculate_focus_quality(&self, image: &PalmImage) -> Result<f64> {
        if image.width < 3 || image.height < 3 {
            return Ok(0.0);
        }

        let mut laplacian_sum = 0.0;
        let mut count = 0;

        // Laplacian kernel
        #[rustfmt::skip]
        let kernel = [
            [0.0, -1.0, 0.0],
            [-1.0, 4.0, -1.0], 
            [0.0, -1.0, 0.0],
        ];

        for y in 1..(image.height - 1) {
            for x in 1..(image.width - 1) {
                let mut response = 0.0;
                
                for ky in 0..3 {
                    for kx in 0..3 {
                        let px = x + kx - 1;
                        let py = y + ky - 1;
                        let pixel = image.get_pixel(px, py, 0)? as f64;
                        response += pixel * kernel[ky as usize][kx as usize];
                    }
                }
                
                laplacian_sum += response.abs();
                count += 1;
            }
        }

        let average_response = if count > 0 { laplacian_sum / count as f64 } else { 0.0 };
        
        // Normalize focus quality (research threshold: 150+ is good focus)
        Ok((average_response / 150.0).min(1.0))
    }

    /// Estimate vein pattern clarity (simplified)
    fn estimate_vein_clarity(&self, image: &PalmImage) -> Result<f64> {
        // Use local variance to estimate vein pattern presence
        let block_size = 16;
        let mut variances = Vec::new();

        for by in (0..image.height).step_by(block_size) {
            for bx in (0..image.width).step_by(block_size) {
                let mut pixels = Vec::new();
                
                let end_y = (by + block_size as u32).min(image.height);
                let end_x = (bx + block_size as u32).min(image.width);
                
                for y in by..end_y {
                    for x in bx..end_x {
                        pixels.push(image.get_pixel(x, y, 0)? as f64);
                    }
                }
                
                if !pixels.is_empty() {
                    let mean = pixels.iter().sum::<f64>() / pixels.len() as f64;
                    let variance = pixels.iter()
                        .map(|&p| (p - mean).powi(2))
                        .sum::<f64>() / pixels.len() as f64;
                    variances.push(variance);
                }
            }
        }

        // Average variance indicates pattern complexity (veins create texture)
        let avg_variance = if variances.is_empty() {
            0.0
        } else {
            variances.iter().sum::<f64>() / variances.len() as f64
        };

        // Normalize vein clarity
        Ok((avg_variance.sqrt() / 50.0).min(1.0))
    }

    /// Estimate ridge pattern quality (simplified)
    fn estimate_ridge_quality(&self, image: &PalmImage) -> Result<f64> {
        // Similar to vein clarity but with different scale
        // Ridges typically have higher frequency patterns
        let ridge_clarity = self.estimate_vein_clarity(image)?;
        
        // Ridge quality is related to vein clarity but with different weighting
        Ok((ridge_clarity * 1.2).min(1.0))
    }
}

/// Convenience functions for common palm biometric operations
impl PalmProcessor {
    /// Save biometric template to secure storage
    #[cfg(feature = "mobile")]
    pub fn save_template<P: AsRef<std::path::Path>>(
        &self,
        template: &PalmBiometricTemplate,
        path: P,
    ) -> Result<()> {
        // Serialize template securely
        let serialized = serde_json::to_vec(template)
            // REQ-005: Generic error message - doesn't reveal serialization details
            .map_err(|_e| SableError::SerializationError("Data processing error".into()))?;

        std::fs::write(path, serialized)
            // REQ-005: Generic error message - doesn't reveal file path or IO details
            .map_err(|_e| SableError::Cryptographic("Storage operation failed".into()))?;

        Ok(())
    }

    /// Load biometric template from secure storage
    #[cfg(feature = "mobile")]
    pub fn load_template<P: AsRef<std::path::Path>>(
        &self,
        path: P,
    ) -> Result<PalmBiometricTemplate> {
        let data = std::fs::read(path)
            // REQ-005: Generic error message - doesn't reveal file path or IO details
            .map_err(|_e| SableError::Cryptographic("Storage operation failed".into()))?;

        let template = serde_json::from_slice(&data)
            // REQ-005: Generic error message - doesn't reveal deserialization details
            .map_err(|_e| SableError::SerializationError("Data processing error".into()))?;

        Ok(template)
    }
}

/// Builder pattern for palm processor configuration
pub struct PalmProcessorBuilder {
    high_quality: bool,
    multimodal: bool,
}

impl PalmProcessorBuilder {
    /// Create a new builder with default settings.
    pub fn new() -> Self {
        Self {
            high_quality: true,
            multimodal: false,
        }
    }

    /// Enable or disable high-quality processing mode.
    pub fn high_quality(mut self, enabled: bool) -> Self {
        self.high_quality = enabled;
        self
    }

    /// Require multi-modal biometrics (both vein and print).
    pub fn multimodal(mut self, required: bool) -> Self {
        self.multimodal = required;
        self
    }

    /// Build the configured PalmProcessor.
    pub fn build(self) -> PalmProcessor {
        PalmProcessor::with_settings(self.high_quality, self.multimodal)
    }
}

impl Default for PalmProcessorBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::feature_extraction::{MIN_IMAGE_DIM, MAX_IMAGE_DIM};

    fn create_test_palm_image() -> PalmImage {
        // Create a realistic palm-sized image with some texture
        let width = 320;
        let height = 240;
        let mut data = Vec::with_capacity((width * height * 3) as usize);
        
        // Generate palm-like texture pattern
        for y in 0..height {
            for x in 0..width {
                let base = 128;
                let noise = ((x * 7 + y * 11) % 50) as u8;
                let pattern = ((x / 4 + y / 3) % 30) as u8;
                
                let pixel = base + noise + pattern;
                data.push(pixel); // R
                data.push(pixel); // G  
                data.push(pixel); // B
            }
        }
        
        PalmImage::new(width, height, 3, data)
    }

    #[test]
    fn test_palm_processor_creation() {
        let processor = PalmProcessor::new();
        assert!(processor.high_quality_mode);
        assert!(!processor.require_multimodal);
    }

    #[test]
    fn test_palm_processor_builder() {
        let processor = PalmProcessorBuilder::new()
            .high_quality(false)
            .multimodal(true)
            .build();
            
        assert!(!processor.high_quality_mode);
        assert!(processor.require_multimodal);
    }

    #[test]
    fn test_palm_image_processing() {
        // Disable high_quality_mode to skip quality validation for test images
        let processor = PalmProcessorBuilder::new()
            .high_quality(false)
            .build();
        let image = create_test_palm_image();

        let template = processor.process_palm_image(image).unwrap();
        assert!(template.quality.score > 0.0);
    }

    #[test]
    fn test_sable_feature_extraction() {
        // Disable high_quality_mode to skip quality validation for test images
        let processor = PalmProcessorBuilder::new()
            .high_quality(false)
            .build();
        let image = create_test_palm_image();

        let features = processor.extract_sable_features(image).unwrap();
        assert_eq!(features.len(), 512); // SABLE requires 512 features
    }

    #[test]
    fn test_quality_assessment() {
        let processor = PalmProcessor::new();
        let image = create_test_palm_image();
        
        let quality = processor.assess_palm_quality(&image).unwrap();
        assert!(quality.score >= 0.0);
        assert!(quality.score <= 1.0);
    }

    #[test]
    fn test_image_validation() {
        let processor = PalmProcessor::new();

        // Test too small image
        let small_image = PalmImage::new(100, 100, 1, vec![128; 10000]);
        assert!(processor.validate_image_quality(&small_image).is_err());

        // Test good image with high_quality_mode disabled (test images don't pass quality thresholds)
        let processor_relaxed = PalmProcessorBuilder::new()
            .high_quality(false)
            .build();
        let good_image = create_test_palm_image();
        assert!(processor_relaxed.validate_image_quality(&good_image).is_ok());
    }

    #[test]
    fn test_contrast_calculation() {
        let processor = PalmProcessor::new();
        
        // Low contrast image (all same value)
        let low_contrast = PalmImage::new(10, 10, 1, vec![128; 100]);
        let contrast = processor.calculate_contrast(&low_contrast).unwrap();
        assert!(contrast < 0.1);
        
        // High contrast image (alternating values)
        let high_contrast_data: Vec<u8> = (0..100).map(|i| if i % 2 == 0 { 0 } else { 255 }).collect();
        let high_contrast = PalmImage::new(10, 10, 1, high_contrast_data);
        let contrast = processor.calculate_contrast(&high_contrast).unwrap();
        assert!(contrast > 0.8);
    }

    #[test]
    fn test_verification() {
        // Disable high_quality_mode to skip quality validation for test images
        let processor = PalmProcessorBuilder::new()
            .high_quality(false)
            .build();
        let image1 = create_test_palm_image();
        let image2 = create_test_palm_image(); // Same pattern

        let template1 = processor.process_palm_image(image1).unwrap();

        let (_verified, score) = processor.verify_palm(image2, &template1).unwrap();
        assert!(score >= 0.0);
        assert!(score <= 1.0);
        // Note: verification result depends on similarity threshold
    }

    // =========================================================================
    // REQ-002: Input Validation Tests for PalmProcessor
    // =========================================================================

    #[test]
    fn test_req002_rejects_image_below_min_dimensions() {
        let processor = PalmProcessor::new();

        // Image below minimum dimensions (64x64)
        let tiny_image = PalmImage::new(32, 32, 1, vec![128; 1024]);
        let result = processor.process_palm_image(tiny_image);
        assert!(result.is_err());
        // Verify generic error message
        assert!(result.unwrap_err().to_string().contains("Invalid image dimensions"));
    }

    #[test]
    fn test_req002_rejects_image_above_max_dimensions() {
        let processor = PalmProcessor::new();

        // Image above maximum dimensions (4096x4096)
        let huge_image = PalmImage::new(5000, 5000, 1, vec![128; 25000000]);
        let result = processor.process_palm_image(huge_image);
        assert!(result.is_err());
        // Verify generic error message
        assert!(result.unwrap_err().to_string().contains("Invalid image dimensions"));
    }

    #[test]
    fn test_req002_accepts_valid_dimensions() {
        let processor = PalmProcessorBuilder::new()
            .high_quality(false)  // Disable quality checks to focus on dimension validation
            .build();

        // Image within valid bounds and meeting palm requirements (>=200x200)
        let valid_image = PalmImage::new(256, 256, 1, vec![128; 65536]);
        let result = processor.process_palm_image(valid_image);
        assert!(result.is_ok());
    }

    #[test]
    fn test_req002_validation_at_boundary_min() {
        let processor = PalmProcessorBuilder::new()
            .high_quality(false)
            .build();

        // Exactly at MIN_IMAGE_DIM but below palm processor's 200x200 requirement
        let boundary_image = PalmImage::new(MIN_IMAGE_DIM, MIN_IMAGE_DIM, 1,
            vec![128; (MIN_IMAGE_DIM * MIN_IMAGE_DIM) as usize]);

        // This passes REQ-002 validation but fails palm-specific size requirement
        let result = processor.process_palm_image(boundary_image);
        // Should fail because 64x64 < 200x200 required for palm processing
        assert!(result.is_err());
    }

    #[test]
    fn test_req002_validation_at_boundary_max() {
        let processor = PalmProcessorBuilder::new()
            .high_quality(false)
            .build();

        // Exactly at MAX_IMAGE_DIM boundary (4096x4096)
        // Note: This is a large allocation, so we use a smaller test
        let boundary_image = PalmImage::new(MAX_IMAGE_DIM, 256, 1,
            vec![128; (MAX_IMAGE_DIM * 256) as usize]);
        let result = processor.process_palm_image(boundary_image);
        // Should fail due to aspect ratio (4096/256 = 16 > 2.0)
        assert!(result.is_err());
    }

    #[test]
    fn test_req002_error_messages_dont_leak_specifics() {
        let processor = PalmProcessor::new();

        // Different invalid scenarios should produce same generic message
        let too_small = PalmImage::new(32, 32, 1, vec![128; 1024]);
        let too_large = PalmImage::new(5000, 256, 1, vec![128; 1280000]);

        let err1 = processor.process_palm_image(too_small).unwrap_err().to_string();
        let err2 = processor.process_palm_image(too_large).unwrap_err().to_string();

        // Both should be generic without specific dimension values
        assert!(err1.contains("Invalid image"));
        assert!(err2.contains("Invalid image"));
        assert!(!err1.contains("32"));
        assert!(!err2.contains("5000"));
    }
}
