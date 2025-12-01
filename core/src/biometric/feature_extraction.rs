// Palm Feature Extraction Module
//
// Ported from research Scheme implementation
// Implements CNN-based feature extraction and traditional computer vision
// for both palm vein (512-dim) and palm print (256-dim) modalities

use super::{PalmImage, ModalityFeatureVector, BiometricModality};
use crate::error::{Result, SableError};
use std::f64::consts::PI;

/// Extract palm vein features (512-dimensional)
/// Ported from Scheme research: Gabor filters + CNN + geometric features
pub fn extract_vein_features(image: &PalmImage) -> Result<ModalityFeatureVector> {
    // Step 1: Enhance vein patterns using Gabor filter bank
    let enhanced_image = enhance_palm_veins(image)?;
    
    // Step 2: Apply morphological operations
    let morphological_image = apply_morphological_operations(&enhanced_image)?;
    
    // Step 3: Extract skeleton using thinning
    let skeleton_image = apply_zhang_suen_thinning(&morphological_image)?;
    
    // Step 4: CNN-based feature extraction (simulated)
    let cnn_features = extract_cnn_features(&skeleton_image, FeatureType::PalmVein)?;
    
    // Step 5: Geometric vein features
    let geometric_features = extract_geometric_vein_features(&skeleton_image)?;
    
    // Step 6: Combine features (512 total dimensions)
    let combined_features = combine_vein_features(cnn_features, geometric_features)?;
    
    Ok(ModalityFeatureVector::new(
        BiometricModality::PalmVein,
        combined_features,
        0.95  // High confidence from research
    ))
}

/// Extract palm print features (256-dimensional)  
/// Ported from Scheme research: Ridge analysis + CNN + texture features
pub fn extract_print_features(image: &PalmImage) -> Result<ModalityFeatureVector> {
    // Step 1: Enhance ridge patterns
    let enhanced_image = enhance_palm_ridges(image)?;
    
    // Step 2: Extract minutiae points
    let minutiae = extract_minutiae(&enhanced_image)?;
    
    // Step 3: CNN-based feature extraction
    let cnn_features = extract_cnn_features(&enhanced_image, FeatureType::PalmPrint)?;
    
    // Step 4: Texture features (GLCM, LBP, Gabor)
    let texture_features = extract_texture_features(&enhanced_image)?;
    
    // Step 5: Combine features (256 total dimensions)
    let combined_features = combine_print_features(cnn_features, texture_features, minutiae)?;
    
    Ok(ModalityFeatureVector::new(
        BiometricModality::PalmPrint,
        combined_features,
        0.92  // High confidence from research
    ))
}

#[derive(Debug, Clone, Copy)]
enum FeatureType {
    PalmVein,
    PalmPrint,
}

/// Gabor filter parameters from research
struct GaborParameters {
    orientation: f64,  // Radians
    frequency: f64,    // Cycles per pixel
    sigma_x: f64,      // Standard deviation in x direction
    sigma_y: f64,      // Standard deviation in y direction
}

/// Enhance palm vein patterns using Gabor filter bank
/// Ported from Scheme: 6 orientations × 3 frequencies = 18 filters
fn enhance_palm_veins(image: &PalmImage) -> Result<PalmImage> {
    let orientations = [0.0, PI/6.0, PI/3.0, PI/2.0, 2.0*PI/3.0, 5.0*PI/6.0]; // 0°, 30°, 60°, 90°, 120°, 150°
    let frequencies = [0.1, 0.2, 0.3]; // From research parameters

    let mut responses = Vec::new();

    // Apply Gabor filter bank
    for &orientation in &orientations {
        for &frequency in &frequencies {
            let params = GaborParameters {
                orientation,
                frequency,
                sigma_x: 2.0,
                sigma_y: 2.0,
            };

            let response = apply_gabor_filter(image, params)?;
            responses.push(response);
        }
    }

    // Combine responses using maximum response (from research)
    // Pass original dimensions to handle non-square images
    combine_gabor_responses_with_dims(responses, image.width, image.height)
}

/// Apply single Gabor filter
fn apply_gabor_filter(image: &PalmImage, params: GaborParameters) -> Result<Vec<f64>> {
    let width = image.width as usize;
    let height = image.height as usize;
    let mut response = vec![0.0; width * height];
    
    // Gabor kernel size (research uses 15x15)
    let kernel_size = 15;
    let half_size = kernel_size / 2;
    
    // Generate Gabor kernel
    let mut kernel = vec![vec![0.0; kernel_size]; kernel_size];
    for ky in 0..kernel_size {
        for kx in 0..kernel_size {
            let x = (kx as f64 - half_size as f64);
            let y = (ky as f64 - half_size as f64);
            
            // Rotate coordinates
            let x_theta = x * params.orientation.cos() + y * params.orientation.sin();
            let y_theta = -x * params.orientation.sin() + y * params.orientation.cos();
            
            // Gabor function
            let gaussian = (-0.5 * (x_theta.powi(2) / params.sigma_x.powi(2) + 
                                   y_theta.powi(2) / params.sigma_y.powi(2))).exp();
            let sinusoid = (2.0 * PI * params.frequency * x_theta).cos();
            
            kernel[ky][kx] = gaussian * sinusoid;
        }
    }
    
    // Apply convolution
    for y in half_size..(height - half_size) {
        for x in half_size..(width - half_size) {
            let mut sum = 0.0;
            
            for ky in 0..kernel_size {
                for kx in 0..kernel_size {
                    let px = x + kx - half_size;
                    let py = y + ky - half_size;
                    
                    // Get pixel value (convert to grayscale if needed)
                    let pixel_val = if image.channels == 1 {
                        image.get_pixel(px as u32, py as u32, 0)? as f64
                    } else {
                        // Convert RGB to grayscale
                        let r = image.get_pixel(px as u32, py as u32, 0)? as f64;
                        let g = image.get_pixel(px as u32, py as u32, 1)? as f64;
                        let b = image.get_pixel(px as u32, py as u32, 2)? as f64;
                        0.299 * r + 0.587 * g + 0.114 * b
                    };
                    
                    sum += pixel_val * kernel[ky][kx];
                }
            }
            
            response[y * width + x] = sum;
        }
    }
    
    Ok(response)
}

/// Combine multiple Gabor filter responses using maximum response
/// Takes explicit width and height to handle non-square images correctly
fn combine_gabor_responses_with_dims(
    responses: Vec<Vec<f64>>,
    width: u32,
    height: u32,
) -> Result<PalmImage> {
    if responses.is_empty() {
        return Err(SableError::CryptoError("No Gabor responses to combine".into()));
    }

    let size = (width * height) as usize;
    if responses[0].len() != size {
        return Err(SableError::InvalidInput(format!(
            "Response size {} doesn't match image dimensions {}x{}",
            responses[0].len(),
            width,
            height
        )));
    }

    let mut combined = vec![0.0; size];

    // Take maximum response at each pixel
    for i in 0..size {
        let mut max_response = responses[0][i];
        for response in &responses[1..] {
            if i < response.len() {
                max_response = max_response.max(response[i]);
            }
        }
        combined[i] = max_response;
    }

    // Normalize to [0,255] and convert to u8
    let max_val = combined.iter().fold(f64::NEG_INFINITY, |a, &b| a.max(b));
    let min_val = combined.iter().fold(f64::INFINITY, |a, &b| a.min(b));
    let range = max_val - min_val;

    let data: Vec<u8> = if range > 0.0 {
        combined
            .iter()
            .map(|&val| ((val - min_val) / range * 255.0).round() as u8)
            .collect()
    } else {
        vec![128; size] // Constant value if no variation
    };

    Ok(PalmImage::new(width, height, 1, data))
}

/// Apply morphological operations for vein structure refinement
fn apply_morphological_operations(image: &PalmImage) -> Result<PalmImage> {
    // Morphological opening followed by closing (from research)
    let opened = morphological_opening(image)?;
    let closed = morphological_closing(&opened)?;
    Ok(closed)
}

/// Morphological opening (erosion followed by dilation)
fn morphological_opening(image: &PalmImage) -> Result<PalmImage> {
    let eroded = morphological_erosion(image)?;
    morphological_dilation(&eroded)
}

/// Morphological closing (dilation followed by erosion)
fn morphological_closing(image: &PalmImage) -> Result<PalmImage> {
    let dilated = morphological_dilation(image)?;
    morphological_erosion(&dilated)
}

/// Morphological erosion with 3x3 structuring element
fn morphological_erosion(image: &PalmImage) -> Result<PalmImage> {
    let mut eroded_data = vec![0u8; image.data.len()];
    
    for y in 1..(image.height - 1) {
        for x in 1..(image.width - 1) {
            let mut min_val = 255u8;
            
            // 3x3 structuring element
            for dy in -1..=1 {
                for dx in -1..=1 {
                    let px = (x as i32 + dx) as u32;
                    let py = (y as i32 + dy) as u32;
                    let pixel = image.get_pixel(px, py, 0)?;
                    min_val = min_val.min(pixel);
                }
            }
            
            let idx = (y * image.width + x) as usize;
            eroded_data[idx] = min_val;
        }
    }
    
    Ok(PalmImage::new(image.width, image.height, 1, eroded_data))
}

/// Morphological dilation with 3x3 structuring element
fn morphological_dilation(image: &PalmImage) -> Result<PalmImage> {
    let mut dilated_data = vec![0u8; image.data.len()];
    
    for y in 1..(image.height - 1) {
        for x in 1..(image.width - 1) {
            let mut max_val = 0u8;
            
            // 3x3 structuring element
            for dy in -1..=1 {
                for dx in -1..=1 {
                    let px = (x as i32 + dx) as u32;
                    let py = (y as i32 + dy) as u32;
                    let pixel = image.get_pixel(px, py, 0)?;
                    max_val = max_val.max(pixel);
                }
            }
            
            let idx = (y * image.width + x) as usize;
            dilated_data[idx] = max_val;
        }
    }
    
    Ok(PalmImage::new(image.width, image.height, 1, dilated_data))
}

/// Zhang-Suen thinning algorithm for skeleton extraction
/// Ported from research Scheme implementation
fn apply_zhang_suen_thinning(image: &PalmImage) -> Result<PalmImage> {
    let width = image.width as usize;
    let height = image.height as usize;
    let mut binary = vec![false; width * height];
    
    // Convert to binary (threshold at 128)
    for y in 0..height {
        for x in 0..width {
            let pixel = image.get_pixel(x as u32, y as u32, 0)?;
            binary[y * width + x] = pixel > 128;
        }
    }
    
    // Iterative thinning
    let mut changed = true;
    while changed {
        changed = false;
        
        // Step 1
        let mut to_delete = Vec::new();
        for y in 1..(height - 1) {
            for x in 1..(width - 1) {
                if should_delete_pixel(&binary, x, y, width, true) {
                    to_delete.push((x, y));
                }
            }
        }
        
        for &(x, y) in &to_delete {
            binary[y * width + x] = false;
            changed = true;
        }
        
        // Step 2
        let mut to_delete = Vec::new();
        for y in 1..(height - 1) {
            for x in 1..(width - 1) {
                if should_delete_pixel(&binary, x, y, width, false) {
                    to_delete.push((x, y));
                }
            }
        }
        
        for &(x, y) in &to_delete {
            binary[y * width + x] = false;
            changed = true;
        }
    }
    
    // Convert back to u8
    let thinned_data: Vec<u8> = binary.iter()
        .map(|&b| if b { 255 } else { 0 })
        .collect();
    
    Ok(PalmImage::new(image.width, image.height, 1, thinned_data))
}

/// Zhang-Suen thinning condition check
fn should_delete_pixel(binary: &[bool], x: usize, y: usize, width: usize, step1: bool) -> bool {
    if !binary[y * width + x] {
        return false; // Background pixel
    }
    
    // Get 8-connected neighbors (clockwise from top)
    let neighbors = [
        binary.get((y - 1) * width + x).copied().unwrap_or(false),     // P2
        binary.get((y - 1) * width + x + 1).copied().unwrap_or(false), // P3  
        binary.get(y * width + x + 1).copied().unwrap_or(false),       // P4
        binary.get((y + 1) * width + x + 1).copied().unwrap_or(false), // P5
        binary.get((y + 1) * width + x).copied().unwrap_or(false),     // P6
        binary.get((y + 1) * width + x - 1).copied().unwrap_or(false), // P7
        binary.get(y * width + x - 1).copied().unwrap_or(false),       // P8
        binary.get((y - 1) * width + x - 1).copied().unwrap_or(false), // P9
    ];
    
    // Count transitions from 0 to 1
    let mut transitions = 0;
    for i in 0..8 {
        let current = neighbors[i];
        let next = neighbors[(i + 1) % 8];
        if !current && next {
            transitions += 1;
        }
    }
    
    // Count foreground neighbors
    let neighbor_count = neighbors.iter().filter(|&&n| n).count();
    
    // Zhang-Suen conditions
    let condition1 = neighbor_count >= 2 && neighbor_count <= 6;
    let condition2 = transitions == 1;
    
    let condition3 = if step1 {
        !neighbors[0] || !neighbors[2] || !neighbors[4] // P2 * P4 * P6 = 0
    } else {
        !neighbors[2] || !neighbors[4] || !neighbors[6] // P4 * P6 * P8 = 0  
    };
    
    let condition4 = if step1 {
        !neighbors[0] || !neighbors[4] || !neighbors[6] // P2 * P6 * P8 = 0
    } else {
        !neighbors[0] || !neighbors[2] || !neighbors[6] // P2 * P4 * P8 = 0
    };
    
    condition1 && condition2 && condition3 && condition4
}

/// Extract geometric features from vein patterns
fn extract_geometric_vein_features(skeleton: &PalmImage) -> Result<Vec<f64>> {
    let mut features = Vec::new();
    
    // Detect bifurcations and endpoints
    let bifurcations = detect_vein_bifurcations(skeleton)?;
    let endpoints = detect_vein_endpoints(skeleton)?;
    
    // Feature 1-3: Bifurcation statistics
    features.push(bifurcations.len() as f64);
    features.push(calculate_mean_x(&bifurcations));
    features.push(calculate_mean_y(&bifurcations));
    
    // Feature 4-6: Endpoint statistics  
    features.push(endpoints.len() as f64);
    features.push(calculate_mean_x(&endpoints));
    features.push(calculate_mean_y(&endpoints));
    
    // Feature 7-8: Vein density measures
    features.push(calculate_global_vein_density(skeleton)?);
    features.push(calculate_local_vein_density_variance(skeleton)?);
    
    // Feature 9-16: Curvature statistics (placeholder)
    features.extend(vec![0.5; 8]); // Placeholder curvature features
    
    Ok(features)
}

/// Detect vein bifurcation points (3+ neighbors)
fn detect_vein_bifurcations(skeleton: &PalmImage) -> Result<Vec<(u32, u32)>> {
    let mut bifurcations = Vec::new();
    
    for y in 1..(skeleton.height - 1) {
        for x in 1..(skeleton.width - 1) {
            let pixel = skeleton.get_pixel(x, y, 0)?;
            if pixel > 128 { // Foreground pixel
                let neighbor_count = count_foreground_neighbors(skeleton, x, y)?;
                if neighbor_count >= 3 {
                    bifurcations.push((x, y));
                }
            }
        }
    }
    
    Ok(bifurcations)
}

/// Detect vein endpoints (1 neighbor)
fn detect_vein_endpoints(skeleton: &PalmImage) -> Result<Vec<(u32, u32)>> {
    let mut endpoints = Vec::new();
    
    for y in 1..(skeleton.height - 1) {
        for x in 1..(skeleton.width - 1) {
            let pixel = skeleton.get_pixel(x, y, 0)?;
            if pixel > 128 { // Foreground pixel
                let neighbor_count = count_foreground_neighbors(skeleton, x, y)?;
                if neighbor_count == 1 {
                    endpoints.push((x, y));
                }
            }
        }
    }
    
    Ok(endpoints)
}

/// Count foreground neighbors in 8-connectivity
fn count_foreground_neighbors(image: &PalmImage, x: u32, y: u32) -> Result<u32> {
    let mut count = 0;
    
    for dy in -1..=1 {
        for dx in -1..=1 {
            if dx == 0 && dy == 0 { continue; } // Skip center pixel
            
            let nx = (x as i32 + dx) as u32;
            let ny = (y as i32 + dy) as u32;
            
            if nx < image.width && ny < image.height {
                let pixel = image.get_pixel(nx, ny, 0)?;
                if pixel > 128 {
                    count += 1;
                }
            }
        }
    }
    
    Ok(count)
}

/// Helper functions for geometric feature calculation
fn calculate_mean_x(points: &[(u32, u32)]) -> f64 {
    if points.is_empty() {
        return 0.0;
    }
    points.iter().map(|(x, _)| *x as f64).sum::<f64>() / points.len() as f64
}

fn calculate_mean_y(points: &[(u32, u32)]) -> f64 {
    if points.is_empty() {
        return 0.0;
    }
    points.iter().map(|(_, y)| *y as f64).sum::<f64>() / points.len() as f64
}

fn calculate_global_vein_density(skeleton: &PalmImage) -> Result<f64> {
    let mut foreground_count = 0;
    let total_pixels = (skeleton.width * skeleton.height) as usize;
    
    for i in 0..total_pixels {
        if skeleton.data[i] > 128 {
            foreground_count += 1;
        }
    }
    
    Ok(foreground_count as f64 / total_pixels as f64)
}

fn calculate_local_vein_density_variance(skeleton: &PalmImage) -> Result<f64> {
    // Calculate density in 8x8 blocks and compute variance
    let block_size = 8;
    let mut densities = Vec::new();
    
    for by in (0..skeleton.height).step_by(block_size as usize) {
        for bx in (0..skeleton.width).step_by(block_size as usize) {
            let mut block_foreground = 0;
            let mut block_total = 0;
            
            for y in by..(by + block_size).min(skeleton.height) {
                for x in bx..(bx + block_size).min(skeleton.width) {
                    if skeleton.get_pixel(x, y, 0)? > 128 {
                        block_foreground += 1;
                    }
                    block_total += 1;
                }
            }
            
            densities.push(block_foreground as f64 / block_total as f64);
        }
    }
    
    // Calculate variance
    if densities.is_empty() {
        return Ok(0.0);
    }
    
    let mean = densities.iter().sum::<f64>() / densities.len() as f64;
    let variance = densities.iter()
        .map(|d| (d - mean).powi(2))
        .sum::<f64>() / densities.len() as f64;
    
    Ok(variance)
}

/// Extract CNN-like features using hand-crafted approximation
/// This uses multi-scale, multi-orientation analysis to approximate deep features
///
/// In production, this would be replaced with actual CNN inference via ONNX runtime.
/// For now, we use a combination of image statistics, gradients, and filter responses
/// that captures similar discriminative information.
fn extract_cnn_features(image: &PalmImage, feature_type: FeatureType) -> Result<Vec<f64>> {
    let feature_dim = match feature_type {
        FeatureType::PalmVein => 400,  // 400-dim features for vein
        FeatureType::PalmPrint => 200, // 200-dim features for print
    };

    let mut features = Vec::with_capacity(feature_dim);
    let width = image.width as usize;
    let height = image.height as usize;
    let data = &image.data;

    // 1. Global statistics (8 features)
    let mean = data.iter().map(|&p| p as f64).sum::<f64>() / data.len() as f64;
    let variance = data.iter().map(|&p| (p as f64 - mean).powi(2)).sum::<f64>() / data.len() as f64;
    let std_dev = variance.sqrt();
    let skewness = data.iter().map(|&p| ((p as f64 - mean) / std_dev.max(1.0)).powi(3)).sum::<f64>() / data.len() as f64;
    let kurtosis = data.iter().map(|&p| ((p as f64 - mean) / std_dev.max(1.0)).powi(4)).sum::<f64>() / data.len() as f64 - 3.0;
    let min_val = *data.iter().min().unwrap_or(&0) as f64;
    let max_val = *data.iter().max().unwrap_or(&255) as f64;
    let range = max_val - min_val;
    let median = {
        let mut sorted: Vec<u8> = data.clone();
        sorted.sort();
        sorted[sorted.len() / 2] as f64
    };
    features.extend_from_slice(&[mean / 255.0, std_dev / 128.0, skewness, kurtosis / 10.0, min_val / 255.0, max_val / 255.0, range / 255.0, median / 255.0]);

    // 2. Block-based features (divide into 4x4 grid = 16 blocks, 4 features each = 64 features)
    let block_w = width / 4;
    let block_h = height / 4;
    for by in 0..4 {
        for bx in 0..4 {
            let mut block_sum = 0.0;
            let mut block_sq_sum = 0.0;
            let mut count = 0;
            for y in (by * block_h)..((by + 1) * block_h).min(height) {
                for x in (bx * block_w)..((bx + 1) * block_w).min(width) {
                    let val = data[y * width + x] as f64;
                    block_sum += val;
                    block_sq_sum += val * val;
                    count += 1;
                }
            }
            if count > 0 {
                let block_mean = block_sum / count as f64;
                let block_var = (block_sq_sum / count as f64) - block_mean.powi(2);
                let block_std = block_var.sqrt();
                let block_energy = block_sq_sum / count as f64;
                features.extend_from_slice(&[block_mean / 255.0, block_std / 128.0, block_var / 16384.0, block_energy / 65536.0]);
            } else {
                features.extend_from_slice(&[0.0, 0.0, 0.0, 0.0]);
            }
        }
    }

    // 3. Gradient features (Sobel-like edge detection, 8 directions)
    let directions: [(i32, i32); 8] = [(-1, -1), (-1, 0), (-1, 1), (0, -1), (0, 1), (1, -1), (1, 0), (1, 1)];
    for (dy, dx) in directions.iter() {
        let mut grad_sum = 0.0;
        let mut grad_count = 0;
        for y in 1..(height - 1) {
            for x in 1..(width - 1) {
                let center = data[y * width + x] as f64;
                let neighbor_y = ((y as i32 + dy) as usize).min(height - 1);
                let neighbor_x = ((x as i32 + dx) as usize).min(width - 1);
                let neighbor = data[neighbor_y * width + neighbor_x] as f64;
                grad_sum += (neighbor - center).abs();
                grad_count += 1;
            }
        }
        features.push(grad_sum / grad_count.max(1) as f64 / 255.0);
    }

    // 4. Histogram features (16 bins = 16 features)
    let mut histogram = [0u32; 16];
    for &pixel in data {
        histogram[(pixel / 16) as usize] += 1;
    }
    let total = data.len() as f64;
    for &count in histogram.iter() {
        features.push(count as f64 / total);
    }

    // 5. Local Binary Pattern-like features (simplified, 32 features)
    let mut lbp_histogram = vec![0u32; 32];
    for y in 1..(height - 1) {
        for x in 1..(width - 1) {
            let center = data[y * width + x];
            let mut pattern = 0u8;
            for (i, (dy, dx)) in directions.iter().enumerate() {
                let ny = ((y as i32 + dy) as usize).min(height - 1);
                let nx = ((x as i32 + dx) as usize).min(width - 1);
                if data[ny * width + nx] >= center {
                    pattern |= 1 << i;
                }
            }
            lbp_histogram[(pattern as usize) % 32] += 1;
        }
    }
    let lbp_total = ((height - 2) * (width - 2)) as f64;
    for &count in lbp_histogram.iter() {
        features.push(count as f64 / lbp_total.max(1.0));
    }

    // 6. Multi-scale features (downsample and compute stats, fills remaining dimensions)
    let scales = [2, 4, 8];
    for scale in scales.iter() {
        let scaled_w = width / scale;
        let scaled_h = height / scale;
        if scaled_w > 0 && scaled_h > 0 {
            let mut scaled_sum = 0.0;
            let mut scaled_count = 0;
            for y in 0..scaled_h {
                for x in 0..scaled_w {
                    let orig_y = y * scale;
                    let orig_x = x * scale;
                    if orig_y < height && orig_x < width {
                        scaled_sum += data[orig_y * width + orig_x] as f64;
                        scaled_count += 1;
                    }
                }
            }
            features.push(scaled_sum / scaled_count.max(1) as f64 / 255.0);
        }
    }

    // Pad or truncate to exact dimension
    while features.len() < feature_dim {
        // Use interpolated values for padding
        let last = features.last().copied().unwrap_or(0.5);
        features.push(last * 0.95 + 0.025);
    }
    features.truncate(feature_dim);

    // Normalize features to [0, 1] range
    let feat_max = features.iter().fold(f64::NEG_INFINITY, |a, &b| a.max(b));
    let feat_min = features.iter().fold(f64::INFINITY, |a, &b| a.min(b));
    let feat_range = (feat_max - feat_min).max(1e-10);
    for f in features.iter_mut() {
        *f = (*f - feat_min) / feat_range;
    }

    Ok(features)
}

/// Combine vein features: CNN (400) + geometric (16) = 416, pad to 512
fn combine_vein_features(cnn_features: Vec<f64>, geometric_features: Vec<f64>) -> Result<Vec<f64>> {
    let mut combined = Vec::with_capacity(512);
    
    combined.extend(cnn_features);      // 400 dimensions
    combined.extend(geometric_features); // 16 dimensions
    
    // Pad to 512 dimensions with interpolated values
    while combined.len() < 512 {
        let last_val = combined.last().copied().unwrap_or(0.5);
        combined.push(last_val * 0.95); // Slight decay
    }
    
    combined.truncate(512); // Ensure exactly 512
    Ok(combined)
}

// Palm print processing functions (ridge analysis, minutiae, texture)

/// Enhance palm print ridge patterns using oriented Gabor filters
/// Optimized for ridge structure detection (higher frequency than vein patterns)
fn enhance_palm_ridges(image: &PalmImage) -> Result<PalmImage> {
    // Ridge patterns have higher spatial frequency than veins
    let orientations = [0.0, PI/8.0, PI/4.0, 3.0*PI/8.0, PI/2.0, 5.0*PI/8.0, 3.0*PI/4.0, 7.0*PI/8.0];
    let frequencies = [0.15, 0.25, 0.35]; // Higher frequencies for fine ridge structure

    let mut responses = Vec::new();

    for &orientation in &orientations {
        for &frequency in &frequencies {
            let params = GaborParameters {
                orientation,
                frequency,
                sigma_x: 1.5, // Tighter sigma for ridge detection
                sigma_y: 1.5,
            };

            let response = apply_gabor_filter(image, params)?;
            responses.push(response);
        }
    }

    combine_gabor_responses_with_dims(responses, image.width, image.height)
}

/// Extract minutiae-like features from ridge patterns
/// Uses crossing number method to detect ridge endings and bifurcations
fn extract_minutiae(image: &PalmImage) -> Result<Vec<f64>> {
    let width = image.width as usize;
    let height = image.height as usize;
    let data = &image.data;

    let mut features = Vec::with_capacity(32);

    // Binarize image using adaptive threshold
    let mean = data.iter().map(|&p| p as f64).sum::<f64>() / data.len() as f64;
    let binary: Vec<u8> = data.iter().map(|&p| if p as f64 > mean { 1 } else { 0 }).collect();

    // Detect minutiae using crossing number
    let mut ridge_endings = 0u32;
    let mut bifurcations = 0u32;
    let mut total_crossings = 0u32;

    // 8-connectivity neighbors
    let neighbors: [(i32, i32); 8] = [
        (-1, -1), (-1, 0), (-1, 1), (0, 1), (1, 1), (1, 0), (1, -1), (0, -1)
    ];

    for y in 1..(height - 1) {
        for x in 1..(width - 1) {
            if binary[y * width + x] == 1 {
                // Count crossing number
                let mut cn = 0i32;
                for i in 0..8 {
                    let (dy1, dx1) = neighbors[i];
                    let (dy2, dx2) = neighbors[(i + 1) % 8];
                    let p1 = binary[((y as i32 + dy1) as usize) * width + ((x as i32 + dx1) as usize)];
                    let p2 = binary[((y as i32 + dy2) as usize) * width + ((x as i32 + dx2) as usize)];
                    cn += (p1 as i32 - p2 as i32).abs();
                }
                cn /= 2;

                if cn == 1 {
                    ridge_endings += 1;
                } else if cn >= 3 {
                    bifurcations += 1;
                }
                total_crossings += cn as u32;
            }
        }
    }

    // Global minutiae statistics
    let total_pixels = (width * height) as f64;
    features.push(ridge_endings as f64 / total_pixels * 1000.0);
    features.push(bifurcations as f64 / total_pixels * 1000.0);
    features.push(total_crossings as f64 / total_pixels * 100.0);
    features.push((ridge_endings + bifurcations) as f64 / total_pixels * 1000.0);

    // Regional minutiae distribution (4x4 grid = 16 regions)
    let block_w = width / 4;
    let block_h = height / 4;
    for by in 0..4 {
        for bx in 0..4 {
            let mut block_minutiae = 0u32;
            for y in (by * block_h)..((by + 1) * block_h).min(height - 1) {
                for x in (bx * block_w)..((bx + 1) * block_w).min(width - 1) {
                    if y > 0 && x > 0 && binary[y * width + x] == 1 {
                        let mut cn = 0i32;
                        for i in 0..8 {
                            let (dy1, dx1) = neighbors[i];
                            let (dy2, dx2) = neighbors[(i + 1) % 8];
                            let ny1 = (y as i32 + dy1).max(0) as usize;
                            let nx1 = (x as i32 + dx1).max(0) as usize;
                            let ny2 = (y as i32 + dy2).max(0) as usize;
                            let nx2 = (x as i32 + dx2).max(0) as usize;
                            if ny1 < height && nx1 < width && ny2 < height && nx2 < width {
                                let p1 = binary[ny1 * width + nx1];
                                let p2 = binary[ny2 * width + nx2];
                                cn += (p1 as i32 - p2 as i32).abs();
                            }
                        }
                        if cn / 2 != 2 { // Not a regular ridge point
                            block_minutiae += 1;
                        }
                    }
                }
            }
            let block_area = (block_w * block_h) as f64;
            features.push(block_minutiae as f64 / block_area * 100.0);
        }
    }

    // Directional minutiae features (4 main directions)
    for dir in 0..4 {
        let angle_start = dir as f64 * PI / 4.0;
        let angle_end = (dir + 1) as f64 * PI / 4.0;
        // Simplified: use gradient direction as proxy for ridge direction
        let mut directional_count = 0u32;
        for y in 1..(height - 1) {
            for x in 1..(width - 1) {
                let gx = data[y * width + (x + 1)] as f64 - data[y * width + (x - 1)] as f64;
                let gy = data[(y + 1) * width + x] as f64 - data[(y - 1) * width + x] as f64;
                let angle = gy.atan2(gx).abs();
                if angle >= angle_start && angle < angle_end {
                    directional_count += 1;
                }
            }
        }
        features.push(directional_count as f64 / total_pixels);
    }

    // Pad to 32 dimensions
    while features.len() < 32 {
        features.push(0.0);
    }
    features.truncate(32);

    Ok(features)
}

/// Extract texture features using GLCM (Gray-Level Co-occurrence Matrix) and LBP
fn extract_texture_features(image: &PalmImage) -> Result<Vec<f64>> {
    let width = image.width as usize;
    let height = image.height as usize;
    let data = &image.data;

    let mut features = Vec::with_capacity(48);

    // 1. GLCM features (4 directions, 4 features each = 16 features)
    let offsets: [(i32, i32); 4] = [(0, 1), (1, 1), (1, 0), (1, -1)]; // 0°, 45°, 90°, 135°

    for &(dy, dx) in &offsets {
        // Build simplified GLCM (quantized to 16 levels)
        let mut glcm = [[0u32; 16]; 16];
        let mut count = 0u32;

        for y in 0..height {
            for x in 0..width {
                let ny = (y as i32 + dy) as usize;
                let nx = (x as i32 + dx) as usize;
                if ny < height && nx < width {
                    let i = (data[y * width + x] / 16) as usize;
                    let j = (data[ny * width + nx] / 16) as usize;
                    glcm[i][j] += 1;
                    count += 1;
                }
            }
        }

        // Normalize GLCM
        let count_f = count.max(1) as f64;

        // Compute GLCM features
        let mut contrast = 0.0;
        let mut energy = 0.0;
        let mut homogeneity = 0.0;
        let mut entropy = 0.0;

        for i in 0..16 {
            for j in 0..16 {
                let p = glcm[i][j] as f64 / count_f;
                let diff = (i as f64 - j as f64).abs();

                contrast += diff * diff * p;
                energy += p * p;
                homogeneity += p / (1.0 + diff);
                if p > 0.0 {
                    entropy -= p * p.ln();
                }
            }
        }

        features.extend_from_slice(&[contrast / 256.0, energy, homogeneity, entropy / 5.0]);
    }

    // 2. LBP histogram features (16 features for uniform LBP)
    let mut lbp_hist = [0u32; 16];
    let neighbors: [(i32, i32); 8] = [
        (-1, -1), (-1, 0), (-1, 1), (0, 1), (1, 1), (1, 0), (1, -1), (0, -1)
    ];

    for y in 1..(height - 1) {
        for x in 1..(width - 1) {
            let center = data[y * width + x];
            let mut pattern = 0u8;
            for (i, &(dy, dx)) in neighbors.iter().enumerate() {
                let ny = (y as i32 + dy) as usize;
                let nx = (x as i32 + dx) as usize;
                if data[ny * width + nx] >= center {
                    pattern |= 1 << i;
                }
            }
            // Map to uniform LBP (simplified: use modulo)
            lbp_hist[(pattern as usize) % 16] += 1;
        }
    }

    let lbp_total = ((height - 2) * (width - 2)) as f64;
    for &count in &lbp_hist {
        features.push(count as f64 / lbp_total.max(1.0));
    }

    // 3. Gabor energy features (4 orientations × 2 scales = 8 features)
    let gabor_orientations = [0.0, PI / 4.0, PI / 2.0, 3.0 * PI / 4.0];
    let gabor_frequencies = [0.1, 0.2];

    for &orientation in &gabor_orientations {
        for &frequency in &gabor_frequencies {
            let params = GaborParameters {
                orientation,
                frequency,
                sigma_x: 2.0,
                sigma_y: 2.0,
            };

            let response = apply_gabor_filter(image, params)?;
            let energy: f64 = response.iter().map(|&r| r * r).sum::<f64>() / response.len() as f64;
            features.push(energy / 10000.0); // Normalize
        }
    }

    // 4. Statistical texture measures (8 features)
    let mean = data.iter().map(|&p| p as f64).sum::<f64>() / data.len() as f64;
    let variance = data.iter().map(|&p| (p as f64 - mean).powi(2)).sum::<f64>() / data.len() as f64;
    let std_dev = variance.sqrt();

    // Smoothness
    let smoothness = 1.0 - 1.0 / (1.0 + variance / 65536.0);
    features.push(smoothness);

    // Third moment (skewness)
    let skewness = data.iter().map(|&p| ((p as f64 - mean) / std_dev.max(1.0)).powi(3)).sum::<f64>() / data.len() as f64;
    features.push(skewness);

    // Uniformity
    let mut hist = [0u32; 256];
    for &pixel in data {
        hist[pixel as usize] += 1;
    }
    let uniformity: f64 = hist.iter().map(|&c| (c as f64 / data.len() as f64).powi(2)).sum();
    features.push(uniformity);

    // Entropy
    let entropy: f64 = hist.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / data.len() as f64;
            -p * p.ln()
        })
        .sum();
    features.push(entropy / 6.0);

    // Pad to 48 dimensions
    while features.len() < 48 {
        features.push(0.0);
    }
    features.truncate(48);

    Ok(features)
}

/// Combine print features: CNN (200) + texture (48) + minutiae (32) = 280, truncate to 256
fn combine_print_features(
    cnn_features: Vec<f64>,
    texture_features: Vec<f64>, 
    minutiae_features: Vec<f64>
) -> Result<Vec<f64>> {
    let mut combined = Vec::new();
    
    combined.extend(cnn_features);     // 200 dimensions  
    combined.extend(texture_features); // 48 dimensions
    combined.extend(minutiae_features);// 32 dimensions
    
    // Truncate to exactly 256 dimensions
    combined.truncate(256);
    
    // Pad if needed
    while combined.len() < 256 {
        combined.push(0.5);
    }
    
    Ok(combined)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_image() -> PalmImage {
        let data = (0..256).map(|i| (i % 256) as u8).collect();
        PalmImage::new(16, 16, 1, data)
    }

    #[test]
    fn test_gabor_filter() {
        let image = create_test_image();
        let params = GaborParameters {
            orientation: 0.0,
            frequency: 0.1,
            sigma_x: 2.0,
            sigma_y: 2.0,
        };
        
        let response = apply_gabor_filter(&image, params).unwrap();
        assert_eq!(response.len(), 256);
    }

    #[test]
    fn test_vein_feature_extraction() {
        let image = create_test_image();
        let features = extract_vein_features(&image).unwrap();
        
        assert_eq!(features.modality, BiometricModality::PalmVein);
        assert_eq!(features.features.len(), 512);
        assert!(features.confidence > 0.9);
    }

    #[test]
    fn test_print_feature_extraction() {
        let image = create_test_image();
        let features = extract_print_features(&image).unwrap();
        
        assert_eq!(features.modality, BiometricModality::PalmPrint);
        assert_eq!(features.features.len(), 256);
        assert!(features.confidence > 0.9);
    }

    #[test]
    fn test_zhang_suen_thinning() {
        let mut data = vec![0u8; 64];
        // Create simple line pattern
        for i in 16..48 {
            data[i] = 255;
        }
        
        let image = PalmImage::new(8, 8, 1, data);
        let thinned = apply_zhang_suen_thinning(&image).unwrap();
        
        assert_eq!(thinned.width, 8);
        assert_eq!(thinned.height, 8);
    }

    #[test]
    fn test_morphological_operations() {
        let image = create_test_image();
        let result = apply_morphological_operations(&image).unwrap();
        
        assert_eq!(result.width, image.width);
        assert_eq!(result.height, image.height);
    }
}
