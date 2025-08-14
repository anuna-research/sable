// Palm Image Preprocessing Module
//
// Ported from research Scheme implementation
// Provides noise reduction, contrast enhancement, and normalization
// optimized for palm vein and print feature extraction

use super::{PalmImage, BiometricQuality};
use crate::error::{Result, SableError};
use std::f64::consts::PI;

/// Preprocessing configuration matching research parameters
pub struct PreprocessingConfig {
    /// Enable ROI (Region of Interest) extraction
    pub roi_extraction: bool,
    /// Noise reduction method
    pub noise_reduction: NoiseReductionMethod,
    /// Contrast enhancement method
    pub contrast_enhancement: ContrastMethod,
    /// Normalization method
    pub normalization: NormalizationMethod,
}

impl Default for PreprocessingConfig {
    fn default() -> Self {
        // Match research configuration from Scheme implementation
        Self {
            roi_extraction: true,
            noise_reduction: NoiseReductionMethod::Gaussian,
            contrast_enhancement: ContrastMethod::CLAHE,
            normalization: NormalizationMethod::MinMax,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum NoiseReductionMethod {
    Gaussian,
    Median,
    Bilateral,
}

#[derive(Debug, Clone, Copy)]
pub enum ContrastMethod {
    CLAHE,           // Contrast Limited Adaptive Histogram Equalization
    HistogramEq,     // Global histogram equalization
    LocalAdaptive,   // Local adaptive enhancement
}

#[derive(Debug, Clone, Copy)]
pub enum NormalizationMethod {
    MinMax,          // Scale to [0,1]
    ZScore,          // Zero mean, unit variance
}

/// Main preprocessing pipeline ported from Scheme research
pub fn preprocess_palm_image(image: PalmImage) -> Result<PalmImage> {
    let config = PreprocessingConfig::default();
    preprocess_palm_image_with_config(image, config)
}

/// Preprocessing with custom configuration
pub fn preprocess_palm_image_with_config(
    mut image: PalmImage, 
    config: PreprocessingConfig
) -> Result<PalmImage> {
    // Step 1: ROI extraction (extract central palm region)
    if config.roi_extraction {
        image = extract_roi(image)?;
        image.add_preprocessing_step("roi_extraction".to_string());
    }

    // Step 2: Noise reduction
    image = apply_noise_reduction(image, config.noise_reduction)?;
    image.add_preprocessing_step(format!("noise_reduction_{:?}", config.noise_reduction));

    // Step 3: Contrast enhancement  
    image = apply_contrast_enhancement(image, config.contrast_enhancement)?;
    image.add_preprocessing_step(format!("contrast_{:?}", config.contrast_enhancement));

    // Step 4: Normalization
    image = apply_normalization(image, config.normalization)?;
    image.add_preprocessing_step(format!("normalization_{:?}", config.normalization));

    Ok(image)
}

/// Extract Region of Interest (central palm area)
/// Ported from research Scheme function
fn extract_roi(image: PalmImage) -> Result<PalmImage> {
    // Research shows optimal ROI is central 70% of palm image
    let roi_factor = 0.7;
    let new_width = (image.width as f64 * roi_factor) as u32;
    let new_height = (image.height as f64 * roi_factor) as u32;
    
    let start_x = (image.width - new_width) / 2;
    let start_y = (image.height - new_height) / 2;

    let mut roi_data = Vec::new();
    
    // Extract ROI region
    for y in start_y..(start_y + new_height) {
        for x in start_x..(start_x + new_width) {
            for c in 0..image.channels {
                let pixel = image.get_pixel(x, y, c)?;
                roi_data.push(pixel);
            }
        }
    }

    Ok(PalmImage::new(new_width, new_height, image.channels, roi_data))
}

/// Apply noise reduction using specified method
fn apply_noise_reduction(image: PalmImage, method: NoiseReductionMethod) -> Result<PalmImage> {
    match method {
        NoiseReductionMethod::Gaussian => apply_gaussian_filter(image),
        NoiseReductionMethod::Median => apply_median_filter(image),
        NoiseReductionMethod::Bilateral => apply_bilateral_filter(image),
    }
}

/// Gaussian noise reduction (research-proven for palm biometrics)
fn apply_gaussian_filter(image: PalmImage) -> Result<PalmImage> {
    // 5x5 Gaussian kernel (sigma = 1.0) from research
    #[rustfmt::skip]
    let kernel: [[f64; 5]; 5] = [
        [0.003765, 0.015019, 0.023792, 0.015019, 0.003765],
        [0.015019, 0.059912, 0.094907, 0.059912, 0.015019],
        [0.023792, 0.094907, 0.150342, 0.094907, 0.023792],
        [0.015019, 0.059912, 0.094907, 0.059912, 0.015019],
        [0.003765, 0.015019, 0.023792, 0.015019, 0.003765],
    ];

    let mut filtered_data = vec![0u8; image.data.len()];
    
    for y in 2..(image.height - 2) {
        for x in 2..(image.width - 2) {
            for c in 0..image.channels {
                let mut sum = 0.0;
                
                // Apply 5x5 kernel
                for ky in 0..5 {
                    for kx in 0..5 {
                        let px = (x + kx - 2) as u32;
                        let py = (y + ky - 2) as u32;
                        let pixel_val = image.get_pixel(px, py, c)? as f64;
                        sum += pixel_val * kernel[ky as usize][kx as usize];
                    }
                }
                
                let idx = ((y * image.width + x) * image.channels + c) as usize;
                filtered_data[idx] = (sum.round().max(0.0).min(255.0)) as u8;
            }
        }
    }
    
    // Copy border pixels unchanged
    copy_image_borders(&image, &mut filtered_data)?;

    Ok(PalmImage::new(image.width, image.height, image.channels, filtered_data))
}

/// Median filter for impulse noise removal
fn apply_median_filter(image: PalmImage) -> Result<PalmImage> {
    let mut filtered_data = vec![0u8; image.data.len()];
    
    for y in 1..(image.height - 1) {
        for x in 1..(image.width - 1) {
            for c in 0..image.channels {
                let mut neighborhood = Vec::new();
                
                // Collect 3x3 neighborhood
                for dy in -1..=1 {
                    for dx in -1..=1 {
                        let px = (x as i32 + dx) as u32;
                        let py = (y as i32 + dy) as u32;
                        neighborhood.push(image.get_pixel(px, py, c)?);
                    }
                }
                
                // Find median
                neighborhood.sort_unstable();
                let median = neighborhood[4]; // Middle element of 9
                
                let idx = ((y * image.width + x) * image.channels + c) as usize;
                filtered_data[idx] = median;
            }
        }
    }
    
    copy_image_borders(&image, &mut filtered_data)?;
    Ok(PalmImage::new(image.width, image.height, image.channels, filtered_data))
}

/// Bilateral filter (edge-preserving)
fn apply_bilateral_filter(image: PalmImage) -> Result<PalmImage> {
    let sigma_spatial: f64 = 2.0;
    let sigma_range: f64 = 50.0;
    let mut filtered_data = vec![0u8; image.data.len()];
    
    for y in 2..(image.height - 2) {
        for x in 2..(image.width - 2) {
            for c in 0..image.channels {
                let center_pixel = image.get_pixel(x, y, c)? as f64;
                let mut sum = 0.0;
                let mut weight_sum = 0.0;
                
                // 5x5 neighborhood
                for dy in -2..=2 {
                    for dx in -2..=2 {
                        let px = (x as i32 + dx) as u32;
                        let py = (y as i32 + dy) as u32;
                        let neighbor_pixel = image.get_pixel(px, py, c)? as f64;
                        
                        // Spatial weight
                        let spatial_dist = ((dx * dx + dy * dy) as f64).sqrt();
                        let spatial_weight = (-spatial_dist.powi(2) / (2.0 * sigma_spatial.powi(2))).exp();
                        
                        // Range weight
                        let range_dist = (center_pixel - neighbor_pixel).abs();
                        let range_weight = (-range_dist.powi(2) / (2.0 * sigma_range.powi(2))).exp();
                        
                        let weight = spatial_weight * range_weight;
                        sum += neighbor_pixel * weight;
                        weight_sum += weight;
                    }
                }
                
                let filtered_pixel = if weight_sum > 0.0 { sum / weight_sum } else { center_pixel };
                let idx = ((y * image.width + x) * image.channels + c) as usize;
                filtered_data[idx] = (filtered_pixel.round().max(0.0).min(255.0)) as u8;
            }
        }
    }
    
    copy_image_borders(&image, &mut filtered_data)?;
    Ok(PalmImage::new(image.width, image.height, image.channels, filtered_data))
}

/// Apply contrast enhancement using specified method
fn apply_contrast_enhancement(image: PalmImage, method: ContrastMethod) -> Result<PalmImage> {
    match method {
        ContrastMethod::CLAHE => apply_clahe(image),
        ContrastMethod::HistogramEq => apply_histogram_equalization(image),
        ContrastMethod::LocalAdaptive => apply_local_adaptive_enhancement(image),
    }
}

/// CLAHE (Contrast Limited Adaptive Histogram Equalization)
/// Research shows this is optimal for palm biometrics
fn apply_clahe(image: PalmImage) -> Result<PalmImage> {
    let clip_limit = 2.0; // Research parameter
    let tile_size = 32;   // Research parameter
    
    let mut enhanced_data = image.data.clone();
    
    // Simplified CLAHE implementation
    // In production, would use full adaptive histogram equalization
    let tiles_x = (image.width + tile_size - 1) / tile_size;
    let tiles_y = (image.height + tile_size - 1) / tile_size;
    
    for tile_y in 0..tiles_y {
        for tile_x in 0..tiles_x {
            let start_x = tile_x * tile_size;
            let start_y = tile_y * tile_size;
            let end_x = (start_x + tile_size).min(image.width);
            let end_y = (start_y + tile_size).min(image.height);
            
            // Apply histogram equalization to this tile
            enhance_tile_contrast(&mut enhanced_data, &image, start_x, start_y, end_x, end_y)?;
        }
    }
    
    Ok(PalmImage::new(image.width, image.height, image.channels, enhanced_data))
}

/// Enhance contrast in image tile
fn enhance_tile_contrast(
    data: &mut [u8],
    image: &PalmImage,
    start_x: u32, start_y: u32,
    end_x: u32, end_y: u32,
) -> Result<()> {
    for c in 0..image.channels {
        // Build histogram for this tile and channel
        let mut histogram = [0u32; 256];
        let mut pixel_count = 0;
        
        for y in start_y..end_y {
            for x in start_x..end_x {
                let pixel = image.get_pixel(x, y, c)?;
                histogram[pixel as usize] += 1;
                pixel_count += 1;
            }
        }
        
        // Build cumulative distribution
        let mut cdf = [0.0; 256];
        let mut sum = 0;
        for i in 0..256 {
            sum += histogram[i];
            cdf[i] = sum as f64 / pixel_count as f64;
        }
        
        // Apply histogram equalization
        for y in start_y..end_y {
            for x in start_x..end_x {
                let pixel = image.get_pixel(x, y, c)?;
                let enhanced = (cdf[pixel as usize] * 255.0).round() as u8;
                let idx = ((y * image.width + x) * image.channels + c) as usize;
                data[idx] = enhanced;
            }
        }
    }
    
    Ok(())
}

/// Global histogram equalization
fn apply_histogram_equalization(image: PalmImage) -> Result<PalmImage> {
    let mut equalized_data = image.data.clone();
    
    for c in 0..image.channels {
        // Build global histogram
        let mut histogram = [0u32; 256];
        for pixel in image.data.iter().step_by(image.channels as usize).skip(c as usize) {
            histogram[*pixel as usize] += 1;
        }
        
        // Build CDF
        let pixel_count = (image.width * image.height) as f64;
        let mut cdf = [0.0; 256];
        let mut sum = 0;
        for i in 0..256 {
            sum += histogram[i];
            cdf[i] = sum as f64 / pixel_count;
        }
        
        // Apply equalization
        for i in (c as usize..equalized_data.len()).step_by(image.channels as usize) {
            let pixel = equalized_data[i];
            equalized_data[i] = (cdf[pixel as usize] * 255.0).round() as u8;
        }
    }
    
    Ok(PalmImage::new(image.width, image.height, image.channels, equalized_data))
}

/// Local adaptive contrast enhancement
fn apply_local_adaptive_enhancement(image: PalmImage) -> Result<PalmImage> {
    // Simplified local adaptive enhancement
    apply_clahe(image) // Use CLAHE as approximation
}

/// Apply normalization using specified method
fn apply_normalization(image: PalmImage, method: NormalizationMethod) -> Result<PalmImage> {
    match method {
        NormalizationMethod::MinMax => apply_min_max_normalization(image),
        NormalizationMethod::ZScore => apply_z_score_normalization(image),
    }
}

/// Min-Max normalization to [0,1] range (scaled to u8)
fn apply_min_max_normalization(image: PalmImage) -> Result<PalmImage> {
    let mut normalized_data = image.data.clone();
    
    for c in 0..image.channels {
        // Find min and max for this channel
        let channel_pixels: Vec<u8> = image.data.iter()
            .skip(c as usize)
            .step_by(image.channels as usize)
            .copied()
            .collect();
            
        let min_val = *channel_pixels.iter().min().unwrap_or(&0) as f64;
        let max_val = *channel_pixels.iter().max().unwrap_or(&255) as f64;
        let range = max_val - min_val;
        
        if range > 0.0 {
            // Normalize to [0,255] range
            for i in (c as usize..normalized_data.len()).step_by(image.channels as usize) {
                let pixel = normalized_data[i] as f64;
                let normalized = ((pixel - min_val) / range * 255.0).round();
                normalized_data[i] = (normalized.max(0.0).min(255.0)) as u8;
            }
        }
    }
    
    Ok(PalmImage::new(image.width, image.height, image.channels, normalized_data))
}

/// Z-score normalization (zero mean, unit variance)
fn apply_z_score_normalization(image: PalmImage) -> Result<PalmImage> {
    let mut normalized_data = image.data.clone();
    
    for c in 0..image.channels {
        // Calculate mean and std dev for this channel
        let channel_pixels: Vec<f64> = image.data.iter()
            .skip(c as usize)
            .step_by(image.channels as usize)
            .map(|&p| p as f64)
            .collect();
            
        let mean: f64 = channel_pixels.iter().sum::<f64>() / channel_pixels.len() as f64;
        let variance: f64 = channel_pixels.iter()
            .map(|&p| (p - mean).powi(2))
            .sum::<f64>() / channel_pixels.len() as f64;
        let std_dev = variance.sqrt();
        
        if std_dev > 0.0 {
            // Z-score normalize and scale to [0,255]
            for i in (c as usize..normalized_data.len()).step_by(image.channels as usize) {
                let pixel = normalized_data[i] as f64;
                let z_score = (pixel - mean) / std_dev;
                // Scale z-score to [0,255] assuming ~3 sigma range
                let scaled = ((z_score + 3.0) / 6.0 * 255.0).round();
                normalized_data[i] = (scaled.max(0.0).min(255.0)) as u8;
            }
        }
    }
    
    Ok(PalmImage::new(image.width, image.height, image.channels, normalized_data))
}

/// Copy border pixels unchanged (helper function)
fn copy_image_borders(source: &PalmImage, dest: &mut [u8]) -> Result<()> {
    // Copy top and bottom rows
    for y in [0, source.height - 1] {
        for x in 0..source.width {
            for c in 0..source.channels {
                let pixel = source.get_pixel(x, y, c)?;
                let idx = ((y * source.width + x) * source.channels + c) as usize;
                dest[idx] = pixel;
            }
        }
    }
    
    // Copy left and right columns
    for y in 1..(source.height - 1) {
        for x in [0, source.width - 1] {
            for c in 0..source.channels {
                let pixel = source.get_pixel(x, y, c)?;
                let idx = ((y * source.width + x) * source.channels + c) as usize;
                dest[idx] = pixel;
            }
        }
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_image() -> PalmImage {
        let data = (0..100).map(|i| (i % 256) as u8).collect();
        PalmImage::new(10, 10, 1, data)
    }

    #[test]
    fn test_roi_extraction() {
        let image = create_test_image();
        let roi = extract_roi(image).unwrap();
        assert!(roi.width < 10);
        assert!(roi.height < 10);
    }

    #[test]
    fn test_gaussian_filter() {
        let image = create_test_image();
        let filtered = apply_gaussian_filter(image).unwrap();
        assert_eq!(filtered.width, 10);
        assert_eq!(filtered.height, 10);
    }

    #[test]
    fn test_preprocessing_pipeline() {
        let image = create_test_image();
        let processed = preprocess_palm_image(image).unwrap();
        assert!(!processed.preprocessing_steps.is_empty());
        assert!(processed.preprocessing_steps.contains(&"roi_extraction".to_string()));
    }

    #[test]
    fn test_min_max_normalization() {
        let data = vec![0, 50, 100, 150, 255];
        let image = PalmImage::new(5, 1, 1, data);
        let normalized = apply_min_max_normalization(image).unwrap();
        
        // Should maintain relative ordering
        let pixel1 = normalized.get_pixel(0, 0, 0).unwrap();
        let pixel2 = normalized.get_pixel(4, 0, 0).unwrap();
        assert_eq!(pixel1, 0);   // Min should be 0
        assert_eq!(pixel2, 255); // Max should be 255
    }
}
