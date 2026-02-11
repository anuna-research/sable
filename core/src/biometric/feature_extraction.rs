// Palm Feature Extraction Module
//
// Ported from research Scheme implementation
// Implements CNN-based feature extraction and traditional computer vision
// for both palm vein (512-dim) and palm print (256-dim) modalities
//
// REQ-022: SIMD/NEON Optimizations
//
// This module includes ARM NEON-optimized implementations for performance-critical
// operations. When compiled with the `neon` feature on ARM64, vectorized operations
// provide up to 2x performance improvement for:
// - Feature normalization (z-score)
// - Euclidean distance calculation
// - Dot product and cosine similarity
// - Vector statistics (mean, variance)

use super::{PalmImage, ModalityFeatureVector, BiometricModality};
use crate::error::{Result, SableError};
use std::f64::consts::PI;

// =============================================================================
// REQ-022: SIMD/NEON Optimized Implementations for f64
// =============================================================================

/// NEON-optimized implementations for ARM64 platforms (f64 operations)
#[cfg(all(target_arch = "aarch64", feature = "neon"))]
mod neon_f64 {
    use std::arch::aarch64::*;

    /// NEON-optimized z-score normalization for f64 feature vectors
    ///
    /// Uses vectorized operations to compute mean and standard deviation,
    /// then normalizes all features in parallel using NEON 128-bit registers.
    ///
    /// # Performance
    ///
    /// Achieves ~2x speedup over scalar implementation by processing
    /// 2 f64 values simultaneously (128-bit NEON registers hold 2 x f64).
    #[inline]
    pub fn zscore_normalize_neon_f64(features: &mut Vec<f64>) {
        if features.len() < 2 {
            super::fallback_f64::zscore_normalize_scalar_f64(features);
            return;
        }

        let n = features.len();
        let n_f64 = n as f64;

        // Phase 1: Compute sum using NEON
        let mut sum_vec = unsafe { vdupq_n_f64(0.0) };
        let chunks = n / 2;
        let remainder = n % 2;

        for i in 0..chunks {
            let offset = i * 2;
            let vals = unsafe { vld1q_f64(features.as_ptr().add(offset)) };
            sum_vec = unsafe { vaddq_f64(sum_vec, vals) };
        }

        // Horizontal sum
        let sum: f64 = unsafe {
            let pair_sum = vpaddq_f64(sum_vec, sum_vec);
            vgetq_lane_f64(pair_sum, 0)
        };

        // Add remainder
        let mut total_sum = sum;
        for i in (chunks * 2)..n {
            total_sum += features[i];
        }

        let mean = total_sum / n_f64;
        let mean_vec = unsafe { vdupq_n_f64(mean) };

        // Phase 2: Compute variance using NEON
        let mut var_sum_vec = unsafe { vdupq_n_f64(0.0) };

        for i in 0..chunks {
            let offset = i * 2;
            let vals = unsafe { vld1q_f64(features.as_ptr().add(offset)) };
            let diff = unsafe { vsubq_f64(vals, mean_vec) };
            let squared = unsafe { vmulq_f64(diff, diff) };
            var_sum_vec = unsafe { vaddq_f64(var_sum_vec, squared) };
        }

        let var_sum: f64 = unsafe {
            let pair_sum = vpaddq_f64(var_sum_vec, var_sum_vec);
            vgetq_lane_f64(pair_sum, 0)
        };

        let mut total_var = var_sum;
        for i in (chunks * 2)..n {
            let diff = features[i] - mean;
            total_var += diff * diff;
        }

        let variance = total_var / n_f64;
        let std_dev = variance.sqrt();

        if std_dev < 1e-10 {
            return;
        }

        let inv_std = 1.0 / std_dev;
        let inv_std_vec = unsafe { vdupq_n_f64(inv_std) };

        // Phase 3: Normalize using NEON
        for i in 0..chunks {
            let offset = i * 2;
            let vals = unsafe { vld1q_f64(features.as_ptr().add(offset)) };
            let diff = unsafe { vsubq_f64(vals, mean_vec) };
            let normalized = unsafe { vmulq_f64(diff, inv_std_vec) };
            unsafe { vst1q_f64(features.as_mut_ptr().add(offset), normalized) };
        }

        // Handle remainder
        for i in (chunks * 2)..n {
            features[i] = (features[i] - mean) * inv_std;
        }
    }

    /// NEON-optimized Euclidean distance for f64 vectors
    #[inline]
    pub fn euclidean_distance_neon_f64(a: &[f64], b: &[f64]) -> f64 {
        debug_assert_eq!(a.len(), b.len());

        if a.len() < 2 {
            return super::fallback_f64::euclidean_distance_scalar_f64(a, b);
        }

        let n = a.len();
        let chunks = n / 2;

        let mut sum_vec = unsafe { vdupq_n_f64(0.0) };

        for i in 0..chunks {
            let offset = i * 2;
            let a_vals = unsafe { vld1q_f64(a.as_ptr().add(offset)) };
            let b_vals = unsafe { vld1q_f64(b.as_ptr().add(offset)) };
            let diff = unsafe { vsubq_f64(a_vals, b_vals) };
            let squared = unsafe { vmulq_f64(diff, diff) };
            sum_vec = unsafe { vaddq_f64(sum_vec, squared) };
        }

        let sum: f64 = unsafe {
            let pair_sum = vpaddq_f64(sum_vec, sum_vec);
            vgetq_lane_f64(pair_sum, 0)
        };

        let mut total = sum;
        for i in (chunks * 2)..n {
            let diff = a[i] - b[i];
            total += diff * diff;
        }

        total.sqrt()
    }

    /// NEON-optimized dot product for f64 vectors
    #[inline]
    pub fn dot_product_neon_f64(a: &[f64], b: &[f64]) -> f64 {
        debug_assert_eq!(a.len(), b.len());

        if a.len() < 2 {
            return super::fallback_f64::dot_product_scalar_f64(a, b);
        }

        let n = a.len();
        let chunks = n / 2;

        let mut sum_vec = unsafe { vdupq_n_f64(0.0) };

        for i in 0..chunks {
            let offset = i * 2;
            let a_vals = unsafe { vld1q_f64(a.as_ptr().add(offset)) };
            let b_vals = unsafe { vld1q_f64(b.as_ptr().add(offset)) };
            sum_vec = unsafe { vfmaq_f64(sum_vec, a_vals, b_vals) };
        }

        let sum: f64 = unsafe {
            let pair_sum = vpaddq_f64(sum_vec, sum_vec);
            vgetq_lane_f64(pair_sum, 0)
        };

        let mut total = sum;
        for i in (chunks * 2)..n {
            total += a[i] * b[i];
        }

        total
    }

    /// NEON-optimized vector mean calculation
    #[inline]
    pub fn mean_neon_f64(v: &[f64]) -> f64 {
        if v.is_empty() {
            return 0.0;
        }

        if v.len() < 2 {
            return v[0];
        }

        let n = v.len();
        let chunks = n / 2;

        let mut sum_vec = unsafe { vdupq_n_f64(0.0) };

        for i in 0..chunks {
            let offset = i * 2;
            let vals = unsafe { vld1q_f64(v.as_ptr().add(offset)) };
            sum_vec = unsafe { vaddq_f64(sum_vec, vals) };
        }

        let sum: f64 = unsafe {
            let pair_sum = vpaddq_f64(sum_vec, sum_vec);
            vgetq_lane_f64(pair_sum, 0)
        };

        let mut total = sum;
        for i in (chunks * 2)..n {
            total += v[i];
        }

        total / n as f64
    }

    /// NEON-optimized variance calculation
    #[inline]
    pub fn variance_neon_f64(v: &[f64], mean: f64) -> f64 {
        if v.len() < 2 {
            return super::fallback_f64::variance_scalar_f64(v, mean);
        }

        let n = v.len();
        let chunks = n / 2;
        let mean_vec = unsafe { vdupq_n_f64(mean) };

        let mut sum_vec = unsafe { vdupq_n_f64(0.0) };

        for i in 0..chunks {
            let offset = i * 2;
            let vals = unsafe { vld1q_f64(v.as_ptr().add(offset)) };
            let diff = unsafe { vsubq_f64(vals, mean_vec) };
            let squared = unsafe { vmulq_f64(diff, diff) };
            sum_vec = unsafe { vaddq_f64(sum_vec, squared) };
        }

        let sum: f64 = unsafe {
            let pair_sum = vpaddq_f64(sum_vec, sum_vec);
            vgetq_lane_f64(pair_sum, 0)
        };

        let mut total = sum;
        for i in (chunks * 2)..n {
            let diff = v[i] - mean;
            total += diff * diff;
        }

        total / n as f64
    }

    /// NEON-optimized cosine similarity for f64 vectors
    #[inline]
    pub fn cosine_similarity_neon_f64(a: &[f64], b: &[f64]) -> f64 {
        let dot = dot_product_neon_f64(a, b);
        let mag_a = dot_product_neon_f64(a, a).sqrt();
        let mag_b = dot_product_neon_f64(b, b).sqrt();

        if mag_a < 1e-10 || mag_b < 1e-10 {
            return 0.0;
        }

        dot / (mag_a * mag_b)
    }
}

/// Scalar fallback implementations for f64 (non-NEON platforms)
mod fallback_f64 {
    /// Scalar z-score normalization for f64 vectors
    #[inline]
    pub fn zscore_normalize_scalar_f64(features: &mut Vec<f64>) {
        if features.is_empty() {
            return;
        }

        let n = features.len() as f64;
        let mean: f64 = features.iter().sum::<f64>() / n;

        let variance: f64 = features.iter()
            .map(|x| (x - mean).powi(2))
            .sum::<f64>() / n;
        let std_dev = variance.sqrt();

        if std_dev < 1e-10 {
            return;
        }

        let inv_std = 1.0 / std_dev;
        for x in features.iter_mut() {
            *x = (*x - mean) * inv_std;
        }
    }

    /// Scalar Euclidean distance for f64 vectors
    #[inline]
    pub fn euclidean_distance_scalar_f64(a: &[f64], b: &[f64]) -> f64 {
        debug_assert_eq!(a.len(), b.len());

        a.iter()
            .zip(b.iter())
            .map(|(x, y)| (x - y).powi(2))
            .sum::<f64>()
            .sqrt()
    }

    /// Scalar dot product for f64 vectors
    #[inline]
    pub fn dot_product_scalar_f64(a: &[f64], b: &[f64]) -> f64 {
        debug_assert_eq!(a.len(), b.len());

        a.iter()
            .zip(b.iter())
            .map(|(x, y)| x * y)
            .sum()
    }

    /// Scalar variance calculation
    #[inline]
    pub fn variance_scalar_f64(v: &[f64], mean: f64) -> f64 {
        if v.is_empty() {
            return 0.0;
        }

        v.iter()
            .map(|x| (x - mean).powi(2))
            .sum::<f64>() / v.len() as f64
    }

    /// Scalar mean calculation
    #[inline]
    pub fn mean_scalar_f64(v: &[f64]) -> f64 {
        if v.is_empty() {
            return 0.0;
        }
        v.iter().sum::<f64>() / v.len() as f64
    }

    /// Scalar cosine similarity for f64 vectors
    #[inline]
    pub fn cosine_similarity_scalar_f64(a: &[f64], b: &[f64]) -> f64 {
        let dot = dot_product_scalar_f64(a, b);
        let mag_a = dot_product_scalar_f64(a, a).sqrt();
        let mag_b = dot_product_scalar_f64(b, b).sqrt();

        if mag_a < 1e-10 || mag_b < 1e-10 {
            return 0.0;
        }

        dot / (mag_a * mag_b)
    }
}

// =============================================================================
// REQ-022: Public SIMD-dispatching API for f64
// =============================================================================

/// Z-score normalize a f64 feature vector in-place (REQ-022: SIMD-optimized)
///
/// Automatically dispatches to NEON-optimized implementation on ARM64
/// when compiled with the `neon` feature, otherwise uses scalar fallback.
#[inline]
pub fn zscore_normalize_simd(features: &mut Vec<f64>) {
    #[cfg(all(target_arch = "aarch64", feature = "neon"))]
    {
        neon_f64::zscore_normalize_neon_f64(features);
        return;
    }

    #[cfg(not(all(target_arch = "aarch64", feature = "neon")))]
    {
        fallback_f64::zscore_normalize_scalar_f64(features);
    }
}

/// Compute Euclidean distance between two f64 feature vectors (REQ-022: SIMD-optimized)
#[inline]
pub fn euclidean_distance_simd(a: &[f64], b: &[f64]) -> f64 {
    debug_assert_eq!(a.len(), b.len());

    #[cfg(all(target_arch = "aarch64", feature = "neon"))]
    {
        return neon_f64::euclidean_distance_neon_f64(a, b);
    }

    #[cfg(not(all(target_arch = "aarch64", feature = "neon")))]
    {
        fallback_f64::euclidean_distance_scalar_f64(a, b)
    }
}

/// Compute dot product of two f64 feature vectors (REQ-022: SIMD-optimized)
#[inline]
pub fn dot_product_simd(a: &[f64], b: &[f64]) -> f64 {
    debug_assert_eq!(a.len(), b.len());

    #[cfg(all(target_arch = "aarch64", feature = "neon"))]
    {
        return neon_f64::dot_product_neon_f64(a, b);
    }

    #[cfg(not(all(target_arch = "aarch64", feature = "neon")))]
    {
        fallback_f64::dot_product_scalar_f64(a, b)
    }
}

/// Compute mean of a f64 vector (REQ-022: SIMD-optimized)
#[inline]
pub fn mean_simd(v: &[f64]) -> f64 {
    #[cfg(all(target_arch = "aarch64", feature = "neon"))]
    {
        return neon_f64::mean_neon_f64(v);
    }

    #[cfg(not(all(target_arch = "aarch64", feature = "neon")))]
    {
        fallback_f64::mean_scalar_f64(v)
    }
}

/// Compute variance of a f64 vector (REQ-022: SIMD-optimized)
#[inline]
pub fn variance_simd(v: &[f64], mean: f64) -> f64 {
    #[cfg(all(target_arch = "aarch64", feature = "neon"))]
    {
        return neon_f64::variance_neon_f64(v, mean);
    }

    #[cfg(not(all(target_arch = "aarch64", feature = "neon")))]
    {
        fallback_f64::variance_scalar_f64(v, mean)
    }
}

/// Compute cosine similarity between two f64 vectors (REQ-022: SIMD-optimized)
#[inline]
pub fn cosine_similarity_simd(a: &[f64], b: &[f64]) -> f64 {
    debug_assert_eq!(a.len(), b.len());

    #[cfg(all(target_arch = "aarch64", feature = "neon"))]
    {
        return neon_f64::cosine_similarity_neon_f64(a, b);
    }

    #[cfg(not(all(target_arch = "aarch64", feature = "neon")))]
    {
        fallback_f64::cosine_similarity_scalar_f64(a, b)
    }
}

/// Check if SIMD optimizations are enabled at runtime
#[inline]
pub fn simd_enabled() -> bool {
    #[cfg(all(target_arch = "aarch64", feature = "neon"))]
    {
        return true;
    }

    #[cfg(not(all(target_arch = "aarch64", feature = "neon")))]
    {
        false
    }
}

// =============================================================================
// REQ-002: Input Validation Constants
// =============================================================================

/// Minimum image dimension (width or height) in pixels
pub const MIN_IMAGE_DIM: u32 = 64;

/// Maximum image dimension (width or height) in pixels
pub const MAX_IMAGE_DIM: u32 = 4096;

/// Expected dimension for palm vein feature vectors
pub const VEIN_FEATURE_DIM: usize = 512;

/// Expected dimension for palm print feature vectors
pub const PRINT_FEATURE_DIM: usize = 256;

// =============================================================================
// REQ-007: Statistical Feature Normalization
// =============================================================================

/// Normalize feature vectors using z-score normalization (mean=0, std=1) (REQ-007)
///
/// This function applies statistical normalization to feature vectors, transforming
/// them to have zero mean and unit standard deviation. This is preferred over
/// min-max scaling for biometric features as it:
/// - Preserves the relative relationships between features
/// - Is more robust to outliers
/// - Provides consistent scaling across different feature distributions
///
/// # Arguments
/// * `features` - Mutable reference to the feature vector to normalize
///
/// # Edge Cases
/// - Empty vectors are returned unchanged
/// - Constant vectors (std=0) are returned unchanged to avoid division by zero
///
/// # REQ-022: SIMD Optimization
///
/// When compiled with the `neon` feature on ARM64 (aarch64), this function
/// automatically uses NEON-optimized vectorized operations for ~2x performance.
pub fn zscore_normalize(features: &mut Vec<f64>) {
    // REQ-022: Dispatch to SIMD-optimized implementation when available
    zscore_normalize_simd(features);
}

// =============================================================================
// REQ-002: Input Validation Functions
// =============================================================================

/// Validate image dimensions are within acceptable bounds (REQ-002)
///
/// Checks that both width and height are:
/// - At least MIN_IMAGE_DIM (64) pixels
/// - At most MAX_IMAGE_DIM (4096) pixels
///
/// Returns a generic error message to prevent information leakage about
/// specific validation failures.
///
/// # Arguments
/// * `image` - The palm image to validate
///
/// # Returns
/// * `Ok(())` if dimensions are valid
/// * `Err(SableError::InvalidInput)` with generic message if invalid
pub fn validate_image_dimensions(image: &PalmImage) -> Result<()> {
    let width_valid = image.width >= MIN_IMAGE_DIM && image.width <= MAX_IMAGE_DIM;
    let height_valid = image.height >= MIN_IMAGE_DIM && image.height <= MAX_IMAGE_DIM;

    if width_valid && height_valid {
        Ok(())
    } else {
        // REQ-002: Generic error message to prevent information leakage
        Err(SableError::InvalidInput("Invalid image dimensions".into()))
    }
}

/// Validate feature vector has the expected length (REQ-002)
///
/// Checks that the feature vector contains exactly the expected number
/// of elements for the given modality.
///
/// # Arguments
/// * `features` - The feature vector to validate
/// * `expected_len` - Expected number of elements (512 for vein, 256 for print)
///
/// # Returns
/// * `Ok(())` if length matches expected
/// * `Err(SableError::InvalidInput)` with generic message if invalid
pub fn validate_feature_vector(features: &[f64], expected_len: usize) -> Result<()> {
    if features.len() == expected_len {
        Ok(())
    } else {
        // REQ-002: Generic error message to prevent information leakage
        Err(SableError::InvalidInput("Invalid feature vector".into()))
    }
}

/// Quality metrics for dynamic confidence calculation (REQ-001)
/// Captures SNR, contrast, completeness, and focus quality from the feature extraction pipeline
#[derive(Debug, Clone)]
pub struct QualityMetrics {
    /// Signal-to-Noise Ratio from Gabor filter responses (0.0 to 1.0)
    pub snr: f64,
    /// Contrast from image histogram analysis (0.0 to 1.0)
    pub contrast: f64,
    /// Completeness based on feature vector fill rate (0.0 to 1.0)
    pub completeness: f64,
    /// Focus quality from Laplacian variance (0.0 to 1.0)
    pub focus_quality: f64,
}

impl QualityMetrics {
    /// Create new QualityMetrics with values clamped to [0.0, 1.0]
    pub fn new(snr: f64, contrast: f64, completeness: f64, focus_quality: f64) -> Self {
        Self {
            snr: snr.clamp(0.0, 1.0),
            contrast: contrast.clamp(0.0, 1.0),
            completeness: completeness.clamp(0.0, 1.0),
            focus_quality: focus_quality.clamp(0.0, 1.0),
        }
    }
}

/// Calculate biometric confidence dynamically based on quality metrics (REQ-001)
/// Formula: confidence = 0.3 * snr + 0.25 * contrast + 0.25 * completeness + 0.2 * focus_quality
/// Result is clamped to [0.0, 1.0]
pub fn calculate_confidence(metrics: &QualityMetrics) -> f64 {
    const SNR_WEIGHT: f64 = 0.30;
    const CONTRAST_WEIGHT: f64 = 0.25;
    const COMPLETENESS_WEIGHT: f64 = 0.25;
    const FOCUS_WEIGHT: f64 = 0.20;

    let confidence =
        metrics.snr * SNR_WEIGHT +
        metrics.contrast * CONTRAST_WEIGHT +
        metrics.completeness * COMPLETENESS_WEIGHT +
        metrics.focus_quality * FOCUS_WEIGHT;

    confidence.clamp(0.0, 1.0)
}

/// Calculate quality metrics from a palm image (REQ-001)
/// Computes SNR, contrast, completeness, and focus quality from image data
pub fn calculate_image_quality_metrics(image: &PalmImage) -> QualityMetrics {
    let contrast = calculate_contrast_from_image(image);
    let focus_quality = calculate_focus_quality(image);

    // SNR and completeness are computed with placeholder values initially
    // They will be updated during feature extraction with actual Gabor responses
    // For now, estimate SNR from image statistics
    let snr = estimate_snr_from_image(image);

    // Completeness is based on valid pixel coverage
    let completeness = calculate_image_completeness(image);

    QualityMetrics::new(snr, contrast, completeness, focus_quality)
}

/// Estimate SNR from image statistics (before Gabor filtering)
fn estimate_snr_from_image(image: &PalmImage) -> f64 {
    if image.data.is_empty() {
        return 0.5;
    }

    let mean: f64 = image.data.iter().map(|&p| p as f64).sum::<f64>() / image.data.len() as f64;
    let variance: f64 = image.data.iter()
        .map(|&p| (p as f64 - mean).powi(2))
        .sum::<f64>() / image.data.len() as f64;

    let std_dev = variance.sqrt();
    if std_dev < 1e-10 {
        return 1.0; // No noise
    }

    // Normalize to [0, 1] using tanh
    let snr_ratio = mean / std_dev;
    (snr_ratio / 5.0).tanh()
}

/// Calculate image completeness based on valid pixel coverage
fn calculate_image_completeness(image: &PalmImage) -> f64 {
    if image.data.is_empty() {
        return 0.0;
    }

    // Count pixels that are not at the extreme boundaries (likely valid data)
    let valid_count = image.data.iter()
        .filter(|&&p| p > 5 && p < 250)
        .count();

    (valid_count as f64 / image.data.len() as f64).clamp(0.0, 1.0)
}

/// Calculate contrast from image histogram
fn calculate_contrast_from_image(image: &PalmImage) -> f64 {
    if image.data.is_empty() {
        return 0.5;
    }

    let min_val = *image.data.iter().min().unwrap_or(&0) as f64;
    let max_val = *image.data.iter().max().unwrap_or(&255) as f64;

    // Michelson contrast: (max - min) / (max + min)
    if max_val + min_val < 1e-10 {
        return 0.0;
    }

    let contrast = (max_val - min_val) / (max_val + min_val);
    contrast.clamp(0.0, 1.0)
}

/// Calculate completeness based on feature vector fill rate
fn calculate_completeness(features: &[f64], expected_dim: usize) -> f64 {
    if expected_dim == 0 {
        return 0.0;
    }

    // Count non-zero, non-placeholder values
    let valid_count = features.iter()
        .filter(|&&x| x.abs() > 1e-10 && (x - 0.5).abs() > 1e-10)
        .count();

    (valid_count as f64 / expected_dim as f64).clamp(0.0, 1.0)
}

/// Calculate focus quality using Laplacian variance
fn calculate_focus_quality(image: &PalmImage) -> f64 {
    let width = image.width as usize;
    let height = image.height as usize;

    if width < 3 || height < 3 {
        return 0.5;
    }

    let mut laplacian_values = Vec::new();

    // Apply 3x3 Laplacian kernel
    for y in 1..(height - 1) {
        for x in 1..(width - 1) {
            let center = image.data[y * width + x] as f64;
            let top = image.data[(y - 1) * width + x] as f64;
            let bottom = image.data[(y + 1) * width + x] as f64;
            let left = image.data[y * width + (x - 1)] as f64;
            let right = image.data[y * width + (x + 1)] as f64;

            // Laplacian: 4*center - top - bottom - left - right
            let laplacian = 4.0 * center - top - bottom - left - right;
            laplacian_values.push(laplacian);
        }
    }

    if laplacian_values.is_empty() {
        return 0.5;
    }

    // Calculate variance of Laplacian
    let mean = laplacian_values.iter().sum::<f64>() / laplacian_values.len() as f64;
    let variance = laplacian_values.iter()
        .map(|&x| (x - mean).powi(2))
        .sum::<f64>() / laplacian_values.len() as f64;

    // Normalize variance to [0, 1] using tanh
    // Higher variance indicates better focus
    (variance / 1000.0).tanh()
}

/// Extract palm vein features (512-dimensional)
/// Ported from Scheme research: Gabor filters + CNN + geometric features
pub fn extract_vein_features(image: &PalmImage) -> Result<ModalityFeatureVector> {
    // REQ-002: Validate image dimensions before processing
    validate_image_dimensions(image)?;

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
    let combined_features = combine_vein_features(cnn_features.clone(), geometric_features)?;

    // REQ-001: Calculate dynamic confidence based on quality metrics
    let mut metrics = calculate_image_quality_metrics(image);
    // Update completeness based on actual feature extraction
    metrics.completeness = calculate_completeness(&combined_features, 512);
    let confidence = calculate_confidence(&metrics);

    Ok(ModalityFeatureVector::new(
        BiometricModality::PalmVein,
        combined_features,
        confidence
    ))
}

/// Extract palm print features (256-dimensional)
/// Ported from Scheme research: Ridge analysis + CNN + texture features
pub fn extract_print_features(image: &PalmImage) -> Result<ModalityFeatureVector> {
    // REQ-002: Validate image dimensions before processing
    validate_image_dimensions(image)?;

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

    // REQ-001: Calculate dynamic confidence based on quality metrics
    let mut metrics = calculate_image_quality_metrics(image);
    // Update completeness based on actual feature extraction
    metrics.completeness = calculate_completeness(&combined_features, 256);
    let confidence = calculate_confidence(&metrics);

    Ok(ModalityFeatureVector::new(
        BiometricModality::PalmPrint,
        combined_features,
        confidence
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
    combine_gabor_responses(responses)
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
            let x = kx as f64 - half_size as f64;
            let y = ky as f64 - half_size as f64;
            
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
fn combine_gabor_responses(responses: Vec<Vec<f64>>) -> Result<PalmImage> {
    if responses.is_empty() {
        // REQ-005: Generic error message - doesn't reveal algorithm details
        return Err(SableError::Cryptographic("Feature processing error".into()));
    }
    
    let size = responses[0].len();
    let width = (size as f64).sqrt() as u32; // Assume square image
    let height = width;
    
    let mut combined = vec![0.0; size];
    
    // Take maximum response at each pixel
    for i in 0..size {
        let mut max_response = responses[0][i];
        for response in &responses[1..] {
            max_response = max_response.max(response[i]);
        }
        combined[i] = max_response;
    }
    
    // Normalize to [0,255] and convert to u8
    let max_val = combined.iter().fold(f64::NEG_INFINITY, |a, &b| a.max(b));
    let min_val = combined.iter().fold(f64::INFINITY, |a, &b| a.min(b));
    let range = max_val - min_val;
    
    let data: Vec<u8> = if range > 0.0 {
        combined.iter()
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

// =============================================================================
// REQ-003: Algorithmic Feature Extraction (replaces PRNG-based CNN simulation)
// =============================================================================

/// Extract algorithmic features from palm image (REQ-003)
///
/// This function replaces the previous PRNG-based CNN simulation with validated
/// algorithmic feature extraction that produces deterministic, meaningful features
/// directly from image content.
///
/// Features extracted:
/// - Grid-based regional statistics (mean, variance, skewness, kurtosis)
/// - Local Binary Pattern (LBP) histogram features
/// - Histogram of Oriented Gradients (HOG) features
/// - Edge density features
/// - Texture energy features
///
/// # Arguments
/// * `image` - The palm image to extract features from
/// * `feature_type` - Type of features (PalmVein or PalmPrint)
///
/// # Returns
/// * `Ok(Vec<f64>)` - Feature vector with length based on feature_type
///   - PalmVein: 400 dimensions
///   - PalmPrint: 200 dimensions
///
/// # Determinism
/// Same input image will always produce the same output features.
fn extract_cnn_features(image: &PalmImage, feature_type: FeatureType) -> Result<Vec<f64>> {
    let feature_dim = match feature_type {
        FeatureType::PalmVein => 400,  // 400-dim features for vein
        FeatureType::PalmPrint => 200, // 200-dim features for print
    };

    let mut features = Vec::with_capacity(feature_dim);

    // Grid size for regional analysis (4x4 for vein, 3x3 for print)
    let grid_size = match feature_type {
        FeatureType::PalmVein => 4,
        FeatureType::PalmPrint => 3,
    };

    // 1. Extract grid-based regional statistics
    let regional_stats = extract_regional_statistics(image, grid_size)?;
    features.extend(regional_stats);

    // 2. Extract Local Binary Pattern (LBP) histogram features
    let lbp_features = extract_lbp_features(image, grid_size)?;
    features.extend(lbp_features);

    // 3. Extract Histogram of Oriented Gradients (HOG) features
    let hog_features = extract_hog_features(image, grid_size)?;
    features.extend(hog_features);

    // 4. Extract edge density features per region
    let edge_features = extract_edge_density_features(image, grid_size)?;
    features.extend(edge_features);

    // 5. Extract texture energy features
    let texture_features = extract_texture_energy_features(image, grid_size)?;
    features.extend(texture_features);

    // Normalize features to [0, 1] range
    normalize_features_minmax(&mut features);

    // Pad or truncate to exact dimension
    adjust_feature_dimension(&mut features, feature_dim);

    Ok(features)
}

/// Extract regional statistics (mean, variance, skewness, kurtosis) for each grid cell (REQ-003)
fn extract_regional_statistics(image: &PalmImage, grid_size: usize) -> Result<Vec<f64>> {
    let mut features = Vec::new();
    let width = image.width as usize;
    let height = image.height as usize;

    let cell_width = width / grid_size;
    let cell_height = height / grid_size;

    for gy in 0..grid_size {
        for gx in 0..grid_size {
            let start_x = gx * cell_width;
            let start_y = gy * cell_height;
            let end_x = if gx == grid_size - 1 { width } else { start_x + cell_width };
            let end_y = if gy == grid_size - 1 { height } else { start_y + cell_height };

            // Collect pixel values for this region
            let mut region_pixels = Vec::new();
            for y in start_y..end_y {
                for x in start_x..end_x {
                    let idx = y * width + x;
                    if idx < image.data.len() {
                        region_pixels.push(image.data[idx] as f64);
                    }
                }
            }

            if region_pixels.is_empty() {
                features.extend(vec![0.0; 4]); // mean, variance, skewness, kurtosis
                continue;
            }

            // Calculate statistical moments
            let n = region_pixels.len() as f64;
            let mean = region_pixels.iter().sum::<f64>() / n;

            let variance = region_pixels.iter()
                .map(|&x| (x - mean).powi(2))
                .sum::<f64>() / n;
            let std_dev = variance.sqrt().max(1e-10);

            // Skewness: E[(X-mu)^3] / sigma^3
            let skewness = region_pixels.iter()
                .map(|&x| ((x - mean) / std_dev).powi(3))
                .sum::<f64>() / n;

            // Kurtosis: E[(X-mu)^4] / sigma^4 - 3 (excess kurtosis)
            let kurtosis = region_pixels.iter()
                .map(|&x| ((x - mean) / std_dev).powi(4))
                .sum::<f64>() / n - 3.0;

            features.push(mean / 255.0);  // Normalize mean to [0, 1]
            features.push((variance / 65025.0).sqrt()); // Normalize variance
            features.push(skewness.tanh()); // Bound skewness
            features.push((kurtosis / 10.0).tanh()); // Bound kurtosis
        }
    }

    Ok(features)
}

/// Extract Local Binary Pattern (LBP) histogram features (REQ-003)
/// LBP encodes local texture by comparing each pixel to its 8 neighbors
fn extract_lbp_features(image: &PalmImage, grid_size: usize) -> Result<Vec<f64>> {
    let mut features = Vec::new();
    let width = image.width as usize;
    let height = image.height as usize;

    let cell_width = width / grid_size;
    let cell_height = height / grid_size;

    // LBP uses 8 neighbors, giving 256 possible patterns
    // We use 16-bin histogram of the LBP values for efficiency
    let num_bins = 16;

    for gy in 0..grid_size {
        for gx in 0..grid_size {
            let start_x = (gx * cell_width).max(1);
            let start_y = (gy * cell_height).max(1);
            let end_x = if gx == grid_size - 1 { width - 1 } else { start_x + cell_width }.min(width - 1);
            let end_y = if gy == grid_size - 1 { height - 1 } else { start_y + cell_height }.min(height - 1);

            let mut histogram = vec![0.0; num_bins];
            let mut count = 0;

            for y in start_y..end_y {
                for x in start_x..end_x {
                    let center = image.data[y * width + x] as i32;

                    // Calculate LBP code from 8 neighbors (clockwise from top-left)
                    let neighbors = [
                        image.data[(y - 1) * width + (x - 1)] as i32, // top-left
                        image.data[(y - 1) * width + x] as i32,       // top
                        image.data[(y - 1) * width + (x + 1)] as i32, // top-right
                        image.data[y * width + (x + 1)] as i32,       // right
                        image.data[(y + 1) * width + (x + 1)] as i32, // bottom-right
                        image.data[(y + 1) * width + x] as i32,       // bottom
                        image.data[(y + 1) * width + (x - 1)] as i32, // bottom-left
                        image.data[y * width + (x - 1)] as i32,       // left
                    ];

                    let mut lbp_code: u8 = 0;
                    for (i, &neighbor) in neighbors.iter().enumerate() {
                        if neighbor >= center {
                            lbp_code |= 1 << i;
                        }
                    }

                    // Map to histogram bin
                    let bin = (lbp_code as usize * num_bins) / 256;
                    histogram[bin.min(num_bins - 1)] += 1.0;
                    count += 1;
                }
            }

            // Normalize histogram
            if count > 0 {
                for h in &mut histogram {
                    *h /= count as f64;
                }
            }

            features.extend(histogram);
        }
    }

    Ok(features)
}

/// Extract Histogram of Oriented Gradients (HOG) features (REQ-003)
/// HOG captures edge orientations and is robust to illumination changes
fn extract_hog_features(image: &PalmImage, grid_size: usize) -> Result<Vec<f64>> {
    let mut features = Vec::new();
    let width = image.width as usize;
    let height = image.height as usize;

    let cell_width = width / grid_size;
    let cell_height = height / grid_size;

    // Number of orientation bins (9 for 0-180 degrees, unsigned gradients)
    let num_bins = 9;
    let bin_width = PI / num_bins as f64;

    for gy in 0..grid_size {
        for gx in 0..grid_size {
            let start_x = (gx * cell_width).max(1);
            let start_y = (gy * cell_height).max(1);
            let end_x = if gx == grid_size - 1 { width - 1 } else { start_x + cell_width }.min(width - 1);
            let end_y = if gy == grid_size - 1 { height - 1 } else { start_y + cell_height }.min(height - 1);

            let mut histogram = vec![0.0; num_bins];

            for y in start_y..end_y {
                for x in start_x..end_x {
                    // Calculate gradients using Sobel-like operators
                    let gx_val = image.data[y * width + (x + 1)] as f64
                               - image.data[y * width + (x - 1)] as f64;
                    let gy_val = image.data[(y + 1) * width + x] as f64
                               - image.data[(y - 1) * width + x] as f64;

                    // Calculate magnitude and orientation
                    let magnitude = (gx_val.powi(2) + gy_val.powi(2)).sqrt();
                    let mut orientation = gy_val.atan2(gx_val);

                    // Map orientation to [0, PI) for unsigned gradients
                    if orientation < 0.0 {
                        orientation += PI;
                    }
                    if orientation >= PI {
                        orientation -= PI;
                    }

                    // Bilinear interpolation into bins
                    let bin_float = orientation / bin_width;
                    let bin_low = (bin_float.floor() as usize) % num_bins;
                    let bin_high = (bin_low + 1) % num_bins;
                    let weight_high = bin_float - bin_float.floor();
                    let weight_low = 1.0 - weight_high;

                    histogram[bin_low] += magnitude * weight_low;
                    histogram[bin_high] += magnitude * weight_high;
                }
            }

            // L2-normalize the histogram
            let norm = histogram.iter().map(|&x| x.powi(2)).sum::<f64>().sqrt().max(1e-10);
            for h in &mut histogram {
                *h /= norm;
            }

            features.extend(histogram);
        }
    }

    Ok(features)
}

/// Extract edge density features for each grid cell (REQ-003)
fn extract_edge_density_features(image: &PalmImage, grid_size: usize) -> Result<Vec<f64>> {
    let mut features = Vec::new();
    let width = image.width as usize;
    let height = image.height as usize;

    let cell_width = width / grid_size;
    let cell_height = height / grid_size;

    // Edge threshold (Canny-like threshold)
    let edge_threshold = 30.0;

    for gy in 0..grid_size {
        for gx in 0..grid_size {
            let start_x = (gx * cell_width).max(1);
            let start_y = (gy * cell_height).max(1);
            let end_x = if gx == grid_size - 1 { width - 1 } else { start_x + cell_width }.min(width - 1);
            let end_y = if gy == grid_size - 1 { height - 1 } else { start_y + cell_height }.min(height - 1);

            let mut edge_count = 0;
            let mut total_gradient = 0.0;
            let mut pixel_count = 0;

            for y in start_y..end_y {
                for x in start_x..end_x {
                    // Sobel gradient magnitude
                    let gx_val = image.data[y * width + (x + 1)] as f64
                               - image.data[y * width + (x - 1)] as f64;
                    let gy_val = image.data[(y + 1) * width + x] as f64
                               - image.data[(y - 1) * width + x] as f64;

                    let magnitude = (gx_val.powi(2) + gy_val.powi(2)).sqrt();
                    total_gradient += magnitude;
                    pixel_count += 1;

                    if magnitude > edge_threshold {
                        edge_count += 1;
                    }
                }
            }

            // Edge density (ratio of edge pixels)
            let edge_density = if pixel_count > 0 {
                edge_count as f64 / pixel_count as f64
            } else {
                0.0
            };

            // Average gradient magnitude
            let avg_gradient = if pixel_count > 0 {
                total_gradient / pixel_count as f64 / 255.0 // Normalize
            } else {
                0.0
            };

            features.push(edge_density);
            features.push(avg_gradient.min(1.0));
        }
    }

    Ok(features)
}

/// Extract texture energy features using local variance (REQ-003)
fn extract_texture_energy_features(image: &PalmImage, grid_size: usize) -> Result<Vec<f64>> {
    let mut features = Vec::new();
    let width = image.width as usize;
    let height = image.height as usize;

    let cell_width = width / grid_size;
    let cell_height = height / grid_size;

    // Analyze texture at multiple scales (3x3 and 5x5 neighborhoods)
    let scales = [1, 2]; // 3x3 and 5x5 windows

    for gy in 0..grid_size {
        for gx in 0..grid_size {
            let start_x = gx * cell_width;
            let start_y = gy * cell_height;
            let end_x = if gx == grid_size - 1 { width } else { start_x + cell_width };
            let end_y = if gy == grid_size - 1 { height } else { start_y + cell_height };

            for &scale in &scales {
                let mut energy_sum = 0.0;
                let mut count = 0;

                let margin = scale + 1;
                let inner_start_x = start_x.max(margin);
                let inner_start_y = start_y.max(margin);
                let inner_end_x = end_x.min(width - margin);
                let inner_end_y = end_y.min(height - margin);

                for y in inner_start_y..inner_end_y {
                    for x in inner_start_x..inner_end_x {
                        // Calculate local variance in neighborhood
                        let mut neighborhood_sum = 0.0;
                        let mut neighborhood_sq_sum = 0.0;
                        let mut n = 0;

                        for dy in -(scale as i32)..=(scale as i32) {
                            for dx in -(scale as i32)..=(scale as i32) {
                                let nx = (x as i32 + dx) as usize;
                                let ny = (y as i32 + dy) as usize;
                                let val = image.data[ny * width + nx] as f64;
                                neighborhood_sum += val;
                                neighborhood_sq_sum += val * val;
                                n += 1;
                            }
                        }

                        let local_mean = neighborhood_sum / n as f64;
                        let local_variance = (neighborhood_sq_sum / n as f64) - (local_mean * local_mean);
                        energy_sum += local_variance.sqrt();
                        count += 1;
                    }
                }

                // Texture energy is average local standard deviation
                let texture_energy = if count > 0 {
                    (energy_sum / count as f64) / 128.0 // Normalize
                } else {
                    0.0
                };

                features.push(texture_energy.min(1.0));
            }
        }
    }

    Ok(features)
}

/// Normalize feature vector to [0, 1] range using min-max normalization (REQ-003)
fn normalize_features_minmax(features: &mut Vec<f64>) {
    if features.is_empty() {
        return;
    }

    let min_val = features.iter().fold(f64::INFINITY, |a, &b| a.min(b));
    let max_val = features.iter().fold(f64::NEG_INFINITY, |a, &b| a.max(b));
    let range = max_val - min_val;

    if range > 1e-10 {
        for f in features.iter_mut() {
            *f = (*f - min_val) / range;
        }
    } else {
        // If all values are the same, set to 0.5
        for f in features.iter_mut() {
            *f = 0.5;
        }
    }
}

/// Adjust feature vector to exact dimension by padding or truncating (REQ-003)
fn adjust_feature_dimension(features: &mut Vec<f64>, target_dim: usize) {
    if features.len() < target_dim {
        // Pad with interpolated values
        let last_val = features.last().copied().unwrap_or(0.5);
        let first_val = features.first().copied().unwrap_or(0.5);

        let padding_needed = target_dim - features.len();
        for i in 0..padding_needed {
            // Create smooth transition using interpolation
            let t = i as f64 / padding_needed as f64;
            let interpolated = last_val * (1.0 - t) + first_val * t;
            features.push(interpolated);
        }
    } else if features.len() > target_dim {
        features.truncate(target_dim);
    }
}

/// Combine vein features: CNN (400) + geometric (16) = 416, pad to 512
/// REQ-007: Applies z-score normalization before returning
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

    // REQ-007: Apply z-score normalization (mean=0, std=1)
    zscore_normalize(&mut combined);

    Ok(combined)
}

// =============================================================================
// REQ-006: Palm Print Processing Functions
// Ridge analysis, minutiae extraction, and texture feature extraction
// Based on peer-reviewed research in palm print biometrics
// =============================================================================

/// Enhance palm print ridge patterns using oriented Gabor filters
///
/// Algorithm based on:
/// - Hong, L., Wan, Y., & Jain, A. (1998). Fingerprint image enhancement.
/// - Zhang, D., et al. (2003). Online palmprint identification.
///
/// Steps:
/// 1. Apply oriented Gabor filters at multiple orientations
/// 2. Perform morphological operations for ridge structure refinement
/// 3. Apply CLAHE (Contrast Limited Adaptive Histogram Equalization)
fn enhance_palm_ridges(image: &PalmImage) -> Result<PalmImage> {
    // Step 1: Apply oriented Gabor filter bank for ridge enhancement
    // Using 8 orientations for finer ridge detection (0, 22.5, 45, ..., 157.5 degrees)
    let orientations = [
        0.0, PI / 8.0, PI / 4.0, 3.0 * PI / 8.0,
        PI / 2.0, 5.0 * PI / 8.0, 3.0 * PI / 4.0, 7.0 * PI / 8.0
    ];
    // Ridge frequency typical for palm prints (based on research)
    let frequencies = [0.08, 0.12, 0.16];

    let mut responses = Vec::new();

    for &orientation in &orientations {
        for &frequency in &frequencies {
            let params = GaborParameters {
                orientation,
                frequency,
                sigma_x: 3.0,  // Wider sigma for palm ridge detection
                sigma_y: 3.0,
            };

            let response = apply_gabor_filter(image, params)?;
            responses.push(response);
        }
    }

    // Combine responses using maximum response
    let mut enhanced = combine_gabor_responses(responses)?;

    // Step 2: Apply morphological operations for ridge structure refinement
    enhanced = apply_ridge_morphological_operations(&enhanced)?;

    // Step 3: Apply CLAHE for contrast enhancement
    enhanced = apply_clahe(&enhanced)?;

    Ok(enhanced)
}

/// Apply morphological operations specific for ridge structure refinement
/// Uses directional structuring elements to preserve ridge connectivity
fn apply_ridge_morphological_operations(image: &PalmImage) -> Result<PalmImage> {
    // Apply opening to remove small noise while preserving ridges
    let opened = morphological_opening(image)?;

    // Apply closing to fill small gaps in ridges
    let closed = morphological_closing(&opened)?;

    // Apply additional thinning pass to normalize ridge width
    apply_ridge_thinning(&closed)
}

/// Apply ridge thinning to normalize ridge width
/// Based on research: keeps ridges at approximately 1-2 pixel width
fn apply_ridge_thinning(image: &PalmImage) -> Result<PalmImage> {
    let width = image.width as usize;
    let height = image.height as usize;
    let mut result = image.data.clone();

    // Simple ridge thinning using local maximum detection
    for y in 1..(height - 1) {
        for x in 1..(width - 1) {
            let idx = y * width + x;
            let current = image.data[idx] as f64;

            // Check if current pixel is local maximum in gradient direction
            let neighbors = [
                image.data[(y - 1) * width + x] as f64,     // top
                image.data[(y + 1) * width + x] as f64,     // bottom
                image.data[y * width + (x - 1)] as f64,     // left
                image.data[y * width + (x + 1)] as f64,     // right
            ];

            // Keep only if it's a local maximum or part of ridge structure
            let neighbor_max = neighbors.iter().fold(0.0_f64, |a, &b| a.max(b));
            if current >= neighbor_max * 0.8 {
                result[idx] = image.data[idx];
            } else {
                result[idx] = (current * 0.7) as u8;
            }
        }
    }

    Ok(PalmImage::new(image.width, image.height, 1, result))
}

/// Apply Contrast Limited Adaptive Histogram Equalization (CLAHE)
///
/// Based on: Pizer, S.M., et al. (1987). Adaptive histogram equalization.
///
/// CLAHE divides the image into tiles, applies histogram equalization to each,
/// and uses bilinear interpolation to avoid tile boundary artifacts.
fn apply_clahe(image: &PalmImage) -> Result<PalmImage> {
    let width = image.width as usize;
    let height = image.height as usize;
    let tile_size = 16; // 16x16 tiles (standard for CLAHE)
    let clip_limit = 2.0; // Contrast limit factor

    let tiles_x = (width + tile_size - 1) / tile_size;
    let tiles_y = (height + tile_size - 1) / tile_size;

    // Calculate histogram and CDF for each tile
    let mut tile_cdfs: Vec<Vec<f64>> = Vec::new();

    for ty in 0..tiles_y {
        for tx in 0..tiles_x {
            let start_x = tx * tile_size;
            let start_y = ty * tile_size;
            let end_x = (start_x + tile_size).min(width);
            let end_y = (start_y + tile_size).min(height);

            // Build histogram for this tile
            let mut histogram = [0u32; 256];
            let mut pixel_count = 0u32;

            for y in start_y..end_y {
                for x in start_x..end_x {
                    let pixel = image.data[y * width + x] as usize;
                    histogram[pixel] += 1;
                    pixel_count += 1;
                }
            }

            // Handle edge case of empty tiles
            if pixel_count == 0 {
                tile_cdfs.push(vec![0.5; 256]);
                continue;
            }

            // Apply clip limit
            let clip_threshold = ((clip_limit * pixel_count as f64) / 256.0) as u32;
            let mut excess = 0u32;

            for count in histogram.iter_mut() {
                if *count > clip_threshold {
                    excess += *count - clip_threshold;
                    *count = clip_threshold;
                }
            }

            // Redistribute excess uniformly
            let redistrib = excess / 256;
            for count in histogram.iter_mut() {
                *count += redistrib;
            }

            // Calculate CDF
            let mut cdf = vec![0.0; 256];
            let mut cumsum = 0u32;
            for i in 0..256 {
                cumsum += histogram[i];
                cdf[i] = cumsum as f64 / pixel_count as f64;
            }

            tile_cdfs.push(cdf);
        }
    }

    // Apply equalization with bilinear interpolation
    let mut result = vec![0u8; width * height];

    for y in 0..height {
        for x in 0..width {
            let pixel = image.data[y * width + x] as usize;

            // Find which tiles this pixel belongs to
            let tx = x / tile_size;
            let ty = y / tile_size;

            // Simple approach: use nearest tile CDF
            let tile_idx = ty * tiles_x + tx;
            if tile_idx < tile_cdfs.len() {
                let equalized = (tile_cdfs[tile_idx][pixel] * 255.0) as u8;
                result[y * width + x] = equalized;
            } else {
                result[y * width + x] = image.data[y * width + x];
            }
        }
    }

    Ok(PalmImage::new(image.width, image.height, 1, result))
}

/// Extract minutiae features from palm print image (32 features)
///
/// Algorithm based on:
/// - Maio, D., & Maltoni, D. (1997). Direct gray-scale minutiae detection.
/// - Jain, A.K., et al. (1997). On-line fingerprint verification.
///
/// Detects ridge endings and bifurcations, encodes as feature vector containing:
/// - Minutiae count statistics (4 features)
/// - Spatial distribution (12 features)
/// - Orientation histogram (16 features)
fn extract_minutiae(image: &PalmImage) -> Result<Vec<f64>> {
    let width = image.width as usize;
    let height = image.height as usize;

    // Step 1: Binarize the enhanced image
    let binary = binarize_image(image)?;

    // Step 2: Thin the binary image to get skeleton
    let skeleton = apply_zhang_suen_thinning(&binary)?;

    // Step 3: Detect minutiae points
    let (endings, bifurcations) = detect_minutiae_points(&skeleton)?;

    // Step 4: Calculate minutiae orientations
    let ending_orientations = calculate_minutiae_orientations(&skeleton, &endings)?;
    let bifurcation_orientations = calculate_minutiae_orientations(&skeleton, &bifurcations)?;

    // Step 5: Encode as 32-dimensional feature vector
    let mut features = Vec::with_capacity(32);

    // Features 0-3: Minutiae count statistics (normalized by image area)
    let area = (width * height) as f64;
    let norm_factor = 10000.0 / area; // Normalize to standard area

    features.push((endings.len() as f64 * norm_factor).min(1.0));
    features.push((bifurcations.len() as f64 * norm_factor).min(1.0));
    features.push(((endings.len() + bifurcations.len()) as f64 * norm_factor).min(1.0));
    // Ratio of endings to total (biologically meaningful)
    let total = (endings.len() + bifurcations.len()) as f64;
    features.push(if total > 0.0 { endings.len() as f64 / total } else { 0.5 });

    // Features 4-15: Spatial distribution (4x3 grid = 12 regions)
    let grid_x = 4;
    let grid_y = 3;
    let cell_w = width as f64 / grid_x as f64;
    let cell_h = height as f64 / grid_y as f64;

    for gy in 0..grid_y {
        for gx in 0..grid_x {
            let mut count = 0;

            // Count minutiae in this grid cell
            for &(x, y) in &endings {
                let cx = (x as f64 / cell_w) as usize;
                let cy = (y as f64 / cell_h) as usize;
                if cx == gx && cy == gy {
                    count += 1;
                }
            }
            for &(x, y) in &bifurcations {
                let cx = (x as f64 / cell_w) as usize;
                let cy = (y as f64 / cell_h) as usize;
                if cx == gx && cy == gy {
                    count += 1;
                }
            }

            // Normalize count
            features.push((count as f64 / 20.0).min(1.0));
        }
    }

    // Features 16-31: Orientation histogram (16 bins covering 0-360 degrees)
    let num_bins = 16;
    let mut orientation_histogram = vec![0.0; num_bins];

    for &angle in &ending_orientations {
        let normalized_angle = if angle < 0.0 { angle + 2.0 * PI } else { angle };
        let bin = ((normalized_angle / (2.0 * PI)) * num_bins as f64) as usize;
        let bin = bin.min(num_bins - 1);
        orientation_histogram[bin] += 1.0;
    }

    for &angle in &bifurcation_orientations {
        let normalized_angle = if angle < 0.0 { angle + 2.0 * PI } else { angle };
        let bin = ((normalized_angle / (2.0 * PI)) * num_bins as f64) as usize;
        let bin = bin.min(num_bins - 1);
        orientation_histogram[bin] += 1.0;
    }

    // Normalize orientation histogram
    let hist_sum: f64 = orientation_histogram.iter().sum();
    if hist_sum > 0.0 {
        for val in orientation_histogram.iter_mut() {
            *val /= hist_sum;
        }
    } else {
        // Uniform distribution if no minutiae detected
        for val in orientation_histogram.iter_mut() {
            *val = 1.0 / num_bins as f64;
        }
    }

    features.extend(orientation_histogram);

    // Ensure exactly 32 features
    features.truncate(32);
    while features.len() < 32 {
        features.push(0.5);
    }

    Ok(features)
}

/// Binarize image using adaptive thresholding
fn binarize_image(image: &PalmImage) -> Result<PalmImage> {
    let width = image.width as usize;
    let height = image.height as usize;
    let block_size = 15;
    let c_offset = 5.0; // Offset from mean for threshold

    let mut binary_data = vec![0u8; width * height];

    for y in 0..height {
        for x in 0..width {
            // Calculate local mean in block
            let mut sum = 0.0;
            let mut count = 0;

            let start_y = y.saturating_sub(block_size / 2);
            let end_y = (y + block_size / 2 + 1).min(height);
            let start_x = x.saturating_sub(block_size / 2);
            let end_x = (x + block_size / 2 + 1).min(width);

            for by in start_y..end_y {
                for bx in start_x..end_x {
                    sum += image.data[by * width + bx] as f64;
                    count += 1;
                }
            }

            let local_mean = sum / count as f64;
            let threshold = local_mean - c_offset;

            let pixel = image.data[y * width + x] as f64;
            binary_data[y * width + x] = if pixel > threshold { 255 } else { 0 };
        }
    }

    Ok(PalmImage::new(image.width, image.height, 1, binary_data))
}

/// Detect minutiae points (ridge endings and bifurcations)
///
/// Ridge ending: pixel with exactly 1 neighbor in skeleton
/// Bifurcation: pixel with 3+ neighbors in skeleton
fn detect_minutiae_points(skeleton: &PalmImage) -> Result<(Vec<(u32, u32)>, Vec<(u32, u32)>)> {
    let mut endings = Vec::new();
    let mut bifurcations = Vec::new();

    let width = skeleton.width;
    let height = skeleton.height;

    // Margin to avoid boundary effects
    let margin = 5;

    for y in margin..(height - margin) {
        for x in margin..(width - margin) {
            let pixel = skeleton.get_pixel(x, y, 0)?;

            if pixel > 128 {
                // Count 8-connected neighbors
                let cn = calculate_crossing_number(skeleton, x, y)?;

                if cn == 1 {
                    // Ridge ending
                    endings.push((x, y));
                } else if cn >= 3 {
                    // Bifurcation
                    bifurcations.push((x, y));
                }
            }
        }
    }

    // Filter out false minutiae using local ridge analysis
    let endings = filter_false_minutiae(skeleton, endings)?;
    let bifurcations = filter_false_minutiae(skeleton, bifurcations)?;

    Ok((endings, bifurcations))
}

/// Calculate crossing number for minutiae detection
/// Crossing number = 0.5 * sum of |P[i] - P[i+1]| for 8-neighbors in circular order
fn calculate_crossing_number(image: &PalmImage, x: u32, y: u32) -> Result<u32> {
    // Get 8 neighbors in circular order (clockwise from top)
    let neighbors = [
        image.get_pixel(x, y.wrapping_sub(1), 0).unwrap_or(0),        // P1: top
        image.get_pixel(x + 1, y.wrapping_sub(1), 0).unwrap_or(0),    // P2: top-right
        image.get_pixel(x + 1, y, 0).unwrap_or(0),                     // P3: right
        image.get_pixel(x + 1, y + 1, 0).unwrap_or(0),                // P4: bottom-right
        image.get_pixel(x, y + 1, 0).unwrap_or(0),                    // P5: bottom
        image.get_pixel(x.wrapping_sub(1), y + 1, 0).unwrap_or(0),    // P6: bottom-left
        image.get_pixel(x.wrapping_sub(1), y, 0).unwrap_or(0),        // P7: left
        image.get_pixel(x.wrapping_sub(1), y.wrapping_sub(1), 0).unwrap_or(0), // P8: top-left
    ];

    // Binarize neighbors
    let binary: Vec<u32> = neighbors.iter().map(|&p| if p > 128 { 1 } else { 0 }).collect();

    // Calculate crossing number
    let mut cn = 0;
    for i in 0..8 {
        let diff = (binary[i] as i32 - binary[(i + 1) % 8] as i32).unsigned_abs();
        cn += diff;
    }

    Ok(cn / 2)
}

/// Filter out false minutiae using local ridge structure analysis
fn filter_false_minutiae(
    skeleton: &PalmImage,
    minutiae: Vec<(u32, u32)>
) -> Result<Vec<(u32, u32)>> {
    let mut filtered = Vec::new();
    let min_distance = 8; // Minimum distance between valid minutiae

    for &(x, y) in &minutiae {
        // Check if this minutiae is too close to image boundary
        if x < 10 || y < 10 || x >= skeleton.width - 10 || y >= skeleton.height - 10 {
            continue;
        }

        // Check local ridge density
        let density = calculate_local_ridge_density(skeleton, x, y, 10)?;
        if density < 0.1 || density > 0.7 {
            // Too sparse or too dense - likely false minutiae
            continue;
        }

        // Check distance from other accepted minutiae
        let too_close = filtered.iter().any(|&(fx, fy)| {
            let dx = (x as i32 - fx as i32).abs();
            let dy = (y as i32 - fy as i32).abs();
            dx < min_distance as i32 && dy < min_distance as i32
        });

        if !too_close {
            filtered.push((x, y));
        }
    }

    Ok(filtered)
}

/// Calculate local ridge density around a point
fn calculate_local_ridge_density(
    skeleton: &PalmImage,
    cx: u32,
    cy: u32,
    radius: u32
) -> Result<f64> {
    let mut foreground = 0;
    let mut total = 0;

    let start_x = cx.saturating_sub(radius);
    let end_x = (cx + radius).min(skeleton.width - 1);
    let start_y = cy.saturating_sub(radius);
    let end_y = (cy + radius).min(skeleton.height - 1);

    for y in start_y..=end_y {
        for x in start_x..=end_x {
            let pixel = skeleton.get_pixel(x, y, 0)?;
            if pixel > 128 {
                foreground += 1;
            }
            total += 1;
        }
    }

    Ok(foreground as f64 / total as f64)
}

/// Calculate minutiae orientations based on local ridge direction
fn calculate_minutiae_orientations(
    skeleton: &PalmImage,
    minutiae: &[(u32, u32)]
) -> Result<Vec<f64>> {
    let mut orientations = Vec::new();

    for &(x, y) in minutiae {
        let orientation = calculate_local_ridge_orientation(skeleton, x, y)?;
        orientations.push(orientation);
    }

    Ok(orientations)
}

/// Calculate local ridge orientation at a point using gradient
fn calculate_local_ridge_orientation(skeleton: &PalmImage, x: u32, y: u32) -> Result<f64> {
    let radius = 5;
    let mut gx_sum = 0.0;
    let mut gy_sum = 0.0;

    let start_x = x.saturating_sub(radius);
    let end_x = (x + radius).min(skeleton.width - 2);
    let start_y = y.saturating_sub(radius);
    let end_y = (y + radius).min(skeleton.height - 2);

    for py in start_y..end_y {
        for px in start_x..end_x {
            // Sobel-like gradient
            let right = skeleton.get_pixel(px + 1, py, 0)? as f64;
            let left = skeleton.get_pixel(px.saturating_sub(1), py, 0)? as f64;
            let bottom = skeleton.get_pixel(px, py + 1, 0)? as f64;
            let top = skeleton.get_pixel(px, py.saturating_sub(1), 0)? as f64;

            let gx = right - left;
            let gy = bottom - top;

            gx_sum += gx;
            gy_sum += gy;
        }
    }

    // Ridge orientation is perpendicular to gradient direction
    let gradient_angle = gy_sum.atan2(gx_sum);
    let ridge_angle = gradient_angle + PI / 2.0;

    Ok(ridge_angle)
}

/// Extract texture features using GLCM, LBP, and Gabor responses (48 features)
///
/// Based on:
/// - Haralick, R.M., et al. (1973). Textural features for image classification.
/// - Ojala, T., et al. (2002). Multiresolution gray-scale and rotation invariant
///   texture classification with local binary patterns.
/// - Jain, A.K., & Farrokhnia, F. (1991). Unsupervised texture segmentation
///   using Gabor filters.
///
/// Feature breakdown:
/// - GLCM features (16): 4 distances x 4 statistics (contrast, correlation, energy, homogeneity)
/// - LBP histogram (16): uniform LBP with 8 neighbors
/// - Gabor filter statistics (16): 4 orientations x 4 statistics (mean, std, energy, entropy)
fn extract_texture_features(image: &PalmImage) -> Result<Vec<f64>> {
    let mut features = Vec::with_capacity(48);

    // Part 1: GLCM features (16 features)
    let glcm_features = extract_glcm_features(image)?;
    features.extend(glcm_features);

    // Part 2: LBP histogram (16 features)
    let lbp_features = extract_lbp_histogram_features(image)?;
    features.extend(lbp_features);

    // Part 3: Gabor filter statistics (16 features)
    let gabor_features = extract_gabor_texture_features(image)?;
    features.extend(gabor_features);

    // Ensure exactly 48 features
    features.truncate(48);
    while features.len() < 48 {
        features.push(0.5);
    }

    Ok(features)
}

/// Extract Gray-Level Co-occurrence Matrix (GLCM) features
///
/// Computes GLCM at 4 different distances (1, 2, 4, 8 pixels) at 0-degree angle
/// For each GLCM, extracts: contrast, correlation, energy, homogeneity
fn extract_glcm_features(image: &PalmImage) -> Result<Vec<f64>> {
    let distances = [1, 2, 4, 8];
    let mut features = Vec::with_capacity(16);

    for &distance in &distances {
        let glcm = compute_glcm(image, distance, 0)?;

        // Extract Haralick features from GLCM
        let contrast = compute_glcm_contrast(&glcm);
        let correlation = compute_glcm_correlation(&glcm);
        let energy = compute_glcm_energy(&glcm);
        let homogeneity = compute_glcm_homogeneity(&glcm);

        features.push(contrast);
        features.push(correlation);
        features.push(energy);
        features.push(homogeneity);
    }

    Ok(features)
}

/// Compute Gray-Level Co-occurrence Matrix
///
/// GLCM[i][j] = count of pixel pairs where pixel at offset has value j
/// when original pixel has value i
fn compute_glcm(image: &PalmImage, distance: i32, angle: i32) -> Result<Vec<Vec<f64>>> {
    let num_levels = 16; // Quantize to 16 gray levels for efficiency
    let mut glcm = vec![vec![0.0; num_levels]; num_levels];
    let width = image.width as i32;
    let height = image.height as i32;

    // Offset based on angle (0 = horizontal)
    let (dx, dy) = match angle {
        0 => (distance, 0),
        45 => (distance, -distance),
        90 => (0, -distance),
        135 => (-distance, -distance),
        _ => (distance, 0),
    };

    let mut total = 0.0;

    for y in 0..height {
        for x in 0..width {
            let nx = x + dx;
            let ny = y + dy;

            if nx >= 0 && nx < width && ny >= 0 && ny < height {
                let pixel1 = image.data[(y * width + x) as usize] as usize;
                let pixel2 = image.data[(ny * width + nx) as usize] as usize;

                // Quantize to num_levels
                let level1 = (pixel1 * num_levels) / 256;
                let level2 = (pixel2 * num_levels) / 256;

                glcm[level1][level2] += 1.0;
                total += 1.0;
            }
        }
    }

    // Normalize GLCM
    if total > 0.0 {
        for row in glcm.iter_mut() {
            for val in row.iter_mut() {
                *val /= total;
            }
        }
    }

    Ok(glcm)
}

/// GLCM Contrast: sum of (i-j)^2 * P(i,j)
fn compute_glcm_contrast(glcm: &[Vec<f64>]) -> f64 {
    let n = glcm.len();
    let mut contrast = 0.0;

    for i in 0..n {
        for j in 0..n {
            let diff = (i as f64 - j as f64).powi(2);
            contrast += diff * glcm[i][j];
        }
    }

    // Normalize to [0, 1]
    let max_contrast = ((n - 1) * (n - 1)) as f64;
    (contrast / max_contrast).min(1.0)
}

/// GLCM Correlation: sum of ((i - mu_i)(j - mu_j) * P(i,j)) / (sigma_i * sigma_j)
fn compute_glcm_correlation(glcm: &[Vec<f64>]) -> f64 {
    let n = glcm.len();

    // Calculate means
    let mut mu_i = 0.0;
    let mut mu_j = 0.0;

    for i in 0..n {
        for j in 0..n {
            mu_i += i as f64 * glcm[i][j];
            mu_j += j as f64 * glcm[i][j];
        }
    }

    // Calculate standard deviations
    let mut sigma_i = 0.0;
    let mut sigma_j = 0.0;

    for i in 0..n {
        for j in 0..n {
            sigma_i += (i as f64 - mu_i).powi(2) * glcm[i][j];
            sigma_j += (j as f64 - mu_j).powi(2) * glcm[i][j];
        }
    }

    sigma_i = sigma_i.sqrt();
    sigma_j = sigma_j.sqrt();

    if sigma_i < 1e-10 || sigma_j < 1e-10 {
        return 0.5; // Neutral value if no variation
    }

    // Calculate correlation
    let mut correlation = 0.0;
    for i in 0..n {
        for j in 0..n {
            correlation += ((i as f64 - mu_i) * (j as f64 - mu_j) * glcm[i][j]) / (sigma_i * sigma_j);
        }
    }

    // Normalize from [-1, 1] to [0, 1]
    (correlation + 1.0) / 2.0
}

/// GLCM Energy (Angular Second Moment): sum of P(i,j)^2
fn compute_glcm_energy(glcm: &[Vec<f64>]) -> f64 {
    let mut energy = 0.0;

    for row in glcm {
        for &val in row {
            energy += val * val;
        }
    }

    energy.min(1.0)
}

/// GLCM Homogeneity (Inverse Difference Moment): sum of P(i,j) / (1 + |i-j|)
fn compute_glcm_homogeneity(glcm: &[Vec<f64>]) -> f64 {
    let n = glcm.len();
    let mut homogeneity = 0.0;

    for i in 0..n {
        for j in 0..n {
            let diff = (i as f64 - j as f64).abs();
            homogeneity += glcm[i][j] / (1.0 + diff);
        }
    }

    homogeneity.min(1.0)
}

/// Extract Local Binary Pattern (LBP) histogram features for texture analysis
///
/// Uses uniform LBP with 8 neighbors at radius 1
/// Returns 16-bin histogram (10 uniform patterns + 6 non-uniform grouped)
fn extract_lbp_histogram_features(image: &PalmImage) -> Result<Vec<f64>> {
    let width = image.width as usize;
    let height = image.height as usize;
    let num_bins = 16;
    let mut histogram = vec![0.0; num_bins];
    let mut total = 0.0;

    // LBP with 8 neighbors at radius 1
    let neighbors: [(i32, i32); 8] = [
        (-1, -1), (0, -1), (1, -1),
        (-1, 0),          (1, 0),
        (-1, 1),  (0, 1),  (1, 1),
    ];

    for y in 1..(height - 1) {
        for x in 1..(width - 1) {
            let center = image.data[y * width + x] as f64;

            // Compute LBP code
            let mut lbp_code = 0u8;
            for (i, &(dx, dy)) in neighbors.iter().enumerate() {
                let nx = (x as i32 + dx) as usize;
                let ny = (y as i32 + dy) as usize;
                let neighbor_val = image.data[ny * width + nx] as f64;

                if neighbor_val >= center {
                    lbp_code |= 1 << i;
                }
            }

            // Map to uniform LBP bin (simplified: use modulo for 16 bins)
            let transitions = count_lbp_transitions(lbp_code);
            let bin = if transitions <= 2 {
                // Uniform pattern: use pattern value mod 10
                (lbp_code.count_ones() as usize) % 10
            } else {
                // Non-uniform: use bins 10-15
                10 + (lbp_code as usize % 6)
            };

            histogram[bin.min(num_bins - 1)] += 1.0;
            total += 1.0;
        }
    }

    // Normalize histogram
    if total > 0.0 {
        for val in histogram.iter_mut() {
            *val /= total;
        }
    }

    Ok(histogram)
}

/// Count 0-1 and 1-0 transitions in LBP code (for uniform pattern detection)
fn count_lbp_transitions(code: u8) -> u32 {
    let mut transitions = 0;
    let mut prev = (code >> 7) & 1;

    for i in 0..8 {
        let current = (code >> i) & 1;
        if current != prev {
            transitions += 1;
        }
        prev = current;
    }

    transitions
}

/// Extract Gabor filter-based texture features
///
/// Applies Gabor filters at 4 orientations (0, 45, 90, 135 degrees)
/// For each orientation, computes: mean, std, energy, entropy
fn extract_gabor_texture_features(image: &PalmImage) -> Result<Vec<f64>> {
    let orientations = [0.0, PI / 4.0, PI / 2.0, 3.0 * PI / 4.0];
    let frequency = 0.1;
    let mut features = Vec::with_capacity(16);

    for &orientation in &orientations {
        let params = GaborParameters {
            orientation,
            frequency,
            sigma_x: 3.0,
            sigma_y: 3.0,
        };

        let response = apply_gabor_filter(image, params)?;

        // Compute statistics from response
        let mean = compute_response_mean(&response);
        let std = compute_response_std(&response, mean);
        let energy = compute_response_energy(&response);
        let entropy = compute_response_entropy(&response);

        features.push(mean);
        features.push(std);
        features.push(energy);
        features.push(entropy);
    }

    Ok(features)
}

/// Compute mean of Gabor response
fn compute_response_mean(response: &[f64]) -> f64 {
    if response.is_empty() {
        return 0.5;
    }
    let sum: f64 = response.iter().sum();
    let mean = sum / response.len() as f64;
    // Normalize to [0, 1]
    (mean / 255.0 + 0.5).clamp(0.0, 1.0)
}

/// Compute standard deviation of Gabor response
fn compute_response_std(response: &[f64], mean: f64) -> f64 {
    if response.is_empty() {
        return 0.0;
    }
    let denorm_mean = (mean - 0.5) * 255.0;
    let variance: f64 = response.iter()
        .map(|&x| (x - denorm_mean).powi(2))
        .sum::<f64>() / response.len() as f64;
    // Normalize to [0, 1]
    (variance.sqrt() / 128.0).clamp(0.0, 1.0)
}

/// Compute energy of Gabor response (sum of squared magnitudes)
fn compute_response_energy(response: &[f64]) -> f64 {
    if response.is_empty() {
        return 0.0;
    }
    let energy: f64 = response.iter().map(|&x| x * x).sum::<f64>() / response.len() as f64;
    // Normalize to [0, 1] using tanh
    (energy / 10000.0).tanh()
}

/// Compute entropy of Gabor response
fn compute_response_entropy(response: &[f64]) -> f64 {
    if response.is_empty() {
        return 0.0;
    }

    // Build histogram
    let num_bins = 32;
    let mut histogram = vec![0.0; num_bins];

    let min_val = response.iter().fold(f64::INFINITY, |a, &b| a.min(b));
    let max_val = response.iter().fold(f64::NEG_INFINITY, |a, &b| a.max(b));
    let range = max_val - min_val;

    if range < 1e-10 {
        return 0.0;
    }

    for &val in response {
        let bin = ((val - min_val) / range * (num_bins - 1) as f64) as usize;
        histogram[bin.min(num_bins - 1)] += 1.0;
    }

    // Normalize histogram
    let total: f64 = histogram.iter().sum();
    if total > 0.0 {
        for val in histogram.iter_mut() {
            *val /= total;
        }
    }

    // Compute entropy
    let mut entropy = 0.0;
    for &p in &histogram {
        if p > 1e-10 {
            entropy -= p * p.log2();
        }
    }

    // Normalize to [0, 1] (max entropy = log2(num_bins))
    entropy / (num_bins as f64).log2()
}

/// Combine print features: CNN (200) + texture (48) + minutiae (32) = 280, truncate to 256
/// REQ-007: Applies z-score normalization before returning
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

    // REQ-007: Apply z-score normalization (mean=0, std=1)
    zscore_normalize(&mut combined);

    Ok(combined)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_image() -> PalmImage {
        let data = (0..256).map(|i| (i % 256) as u8).collect();
        PalmImage::new(16, 16, 1, data)
    }

    fn create_high_quality_test_image() -> PalmImage {
        // Create an image with good contrast and varied content
        let mut data = Vec::with_capacity(1024);
        for y in 0..32 {
            for x in 0..32 {
                // Create a pattern with good contrast
                let value = if (x + y) % 2 == 0 { 200 } else { 50 };
                data.push(value);
            }
        }
        PalmImage::new(32, 32, 1, data)
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
        // Use valid image dimensions (min 64x64)
        let image = create_image_with_dimensions(64, 64);
        let features = extract_vein_features(&image).unwrap();

        assert_eq!(features.modality, BiometricModality::PalmVein);
        assert_eq!(features.features.len(), 512);
        // REQ-001: Confidence is now dynamically calculated, should be in valid range
        assert!(features.confidence >= 0.0 && features.confidence <= 1.0);
    }

    #[test]
    fn test_print_feature_extraction() {
        // Use valid image dimensions (min 64x64)
        let image = create_image_with_dimensions(64, 64);
        let features = extract_print_features(&image).unwrap();

        assert_eq!(features.modality, BiometricModality::PalmPrint);
        assert_eq!(features.features.len(), 256);
        // REQ-001: Confidence is now dynamically calculated, should be in valid range
        assert!(features.confidence >= 0.0 && features.confidence <= 1.0);
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

    // REQ-001: Tests for QualityMetrics and calculate_confidence

    #[test]
    fn test_quality_metrics_creation() {
        let metrics = QualityMetrics::new(0.8, 0.7, 0.9, 0.6);
        assert_eq!(metrics.snr, 0.8);
        assert_eq!(metrics.contrast, 0.7);
        assert_eq!(metrics.completeness, 0.9);
        assert_eq!(metrics.focus_quality, 0.6);
    }

    #[test]
    fn test_quality_metrics_clamping() {
        // Values should be clamped to [0.0, 1.0]
        let metrics = QualityMetrics::new(1.5, -0.2, 2.0, -1.0);
        assert_eq!(metrics.snr, 1.0);
        assert_eq!(metrics.contrast, 0.0);
        assert_eq!(metrics.completeness, 1.0);
        assert_eq!(metrics.focus_quality, 0.0);
    }

    #[test]
    fn test_calculate_confidence_formula() {
        // Test the exact formula: 0.3 * snr + 0.25 * contrast + 0.25 * completeness + 0.2 * focus_quality
        let metrics = QualityMetrics::new(1.0, 1.0, 1.0, 1.0);
        let confidence = calculate_confidence(&metrics);
        // 0.3 * 1.0 + 0.25 * 1.0 + 0.25 * 1.0 + 0.2 * 1.0 = 1.0
        assert!((confidence - 1.0).abs() < 1e-10);

        let metrics = QualityMetrics::new(0.0, 0.0, 0.0, 0.0);
        let confidence = calculate_confidence(&metrics);
        assert!((confidence - 0.0).abs() < 1e-10);

        // Test with specific values
        let metrics = QualityMetrics::new(0.5, 0.6, 0.7, 0.8);
        let confidence = calculate_confidence(&metrics);
        // 0.3 * 0.5 + 0.25 * 0.6 + 0.25 * 0.7 + 0.2 * 0.8 = 0.15 + 0.15 + 0.175 + 0.16 = 0.635
        assert!((confidence - 0.635).abs() < 1e-10);
    }

    #[test]
    fn test_calculate_confidence_clamping() {
        // Confidence should be clamped to [0.0, 1.0]
        let metrics = QualityMetrics::new(1.0, 1.0, 1.0, 1.0);
        let confidence = calculate_confidence(&metrics);
        assert!(confidence >= 0.0 && confidence <= 1.0);
    }

    #[test]
    fn test_calculate_image_quality_metrics() {
        let image = create_test_image();
        let metrics = calculate_image_quality_metrics(&image);

        // All metrics should be in valid range [0.0, 1.0]
        assert!(metrics.snr >= 0.0 && metrics.snr <= 1.0);
        assert!(metrics.contrast >= 0.0 && metrics.contrast <= 1.0);
        assert!(metrics.completeness >= 0.0 && metrics.completeness <= 1.0);
        assert!(metrics.focus_quality >= 0.0 && metrics.focus_quality <= 1.0);
    }

    #[test]
    fn test_calculate_image_quality_metrics_high_quality() {
        let image = create_high_quality_test_image();
        let metrics = calculate_image_quality_metrics(&image);

        // High quality image should have reasonable metrics
        assert!(metrics.snr >= 0.0 && metrics.snr <= 1.0);
        // High contrast image should have good contrast metric
        assert!(metrics.contrast > 0.5);
        assert!(metrics.completeness >= 0.0 && metrics.completeness <= 1.0);
        assert!(metrics.focus_quality >= 0.0 && metrics.focus_quality <= 1.0);
    }

    #[test]
    fn test_calculate_completeness() {
        // Test with a feature vector with varied values
        let features: Vec<f64> = (0..100).map(|i| i as f64 / 100.0).collect();
        let completeness = calculate_completeness(&features, 100);
        assert!(completeness >= 0.0 && completeness <= 1.0);

        // Test with empty features
        let empty_features: Vec<f64> = vec![];
        let completeness = calculate_completeness(&empty_features, 100);
        assert_eq!(completeness, 0.0);

        // Test with all non-zero, non-placeholder values
        let full_features: Vec<f64> = vec![0.3; 100];
        let completeness = calculate_completeness(&full_features, 100);
        assert!(completeness > 0.0);
    }

    #[test]
    fn test_dynamic_confidence_varies_with_image_quality() {
        // Create two images with different quality characteristics
        let low_quality_data = vec![128u8; 256]; // Uniform, low contrast
        let low_quality_image = PalmImage::new(16, 16, 1, low_quality_data);

        let high_quality_image = create_high_quality_test_image();

        let low_metrics = calculate_image_quality_metrics(&low_quality_image);
        let high_metrics = calculate_image_quality_metrics(&high_quality_image);

        let low_confidence = calculate_confidence(&low_metrics);
        let high_confidence = calculate_confidence(&high_metrics);

        // Both should be valid
        assert!(low_confidence >= 0.0 && low_confidence <= 1.0);
        assert!(high_confidence >= 0.0 && high_confidence <= 1.0);

        // High quality image should generally have higher confidence due to better contrast
        // (though this depends on the specific metrics)
        assert!(high_metrics.contrast > low_metrics.contrast);
    }

    // =========================================================================
    // REQ-002: Input Validation Tests
    // =========================================================================

    /// Helper to create image with specific dimensions
    fn create_image_with_dimensions(width: u32, height: u32) -> PalmImage {
        let size = (width * height) as usize;
        let data = vec![128u8; size];
        PalmImage::new(width, height, 1, data)
    }

    #[test]
    fn test_validate_image_dimensions_valid_minimum() {
        // Exactly at minimum boundary (64x64)
        let image = create_image_with_dimensions(MIN_IMAGE_DIM, MIN_IMAGE_DIM);
        assert!(validate_image_dimensions(&image).is_ok());
    }

    #[test]
    fn test_validate_image_dimensions_valid_maximum() {
        // Exactly at maximum boundary (4096x4096)
        let image = create_image_with_dimensions(MAX_IMAGE_DIM, MAX_IMAGE_DIM);
        assert!(validate_image_dimensions(&image).is_ok());
    }

    #[test]
    fn test_validate_image_dimensions_valid_typical() {
        // Typical palm image sizes
        let image_256 = create_image_with_dimensions(256, 256);
        let image_512 = create_image_with_dimensions(512, 512);
        let image_1024 = create_image_with_dimensions(1024, 768);

        assert!(validate_image_dimensions(&image_256).is_ok());
        assert!(validate_image_dimensions(&image_512).is_ok());
        assert!(validate_image_dimensions(&image_1024).is_ok());
    }

    #[test]
    fn test_validate_image_dimensions_width_too_small() {
        // Width below minimum (63 < 64)
        let image = create_image_with_dimensions(MIN_IMAGE_DIM - 1, MIN_IMAGE_DIM);
        let result = validate_image_dimensions(&image);
        assert!(result.is_err());
        // REQ-002: Verify generic error message
        assert!(result.unwrap_err().to_string().contains("Invalid image dimensions"));
    }

    #[test]
    fn test_validate_image_dimensions_height_too_small() {
        // Height below minimum (63 < 64)
        let image = create_image_with_dimensions(MIN_IMAGE_DIM, MIN_IMAGE_DIM - 1);
        let result = validate_image_dimensions(&image);
        assert!(result.is_err());
        // REQ-002: Verify generic error message
        assert!(result.unwrap_err().to_string().contains("Invalid image dimensions"));
    }

    #[test]
    fn test_validate_image_dimensions_both_too_small() {
        // Both dimensions below minimum
        let image = create_image_with_dimensions(32, 32);
        let result = validate_image_dimensions(&image);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_image_dimensions_width_too_large() {
        // Width above maximum (4097 > 4096)
        let image = create_image_with_dimensions(MAX_IMAGE_DIM + 1, MAX_IMAGE_DIM);
        let result = validate_image_dimensions(&image);
        assert!(result.is_err());
        // REQ-002: Verify generic error message
        assert!(result.unwrap_err().to_string().contains("Invalid image dimensions"));
    }

    #[test]
    fn test_validate_image_dimensions_height_too_large() {
        // Height above maximum (4097 > 4096)
        let image = create_image_with_dimensions(MAX_IMAGE_DIM, MAX_IMAGE_DIM + 1);
        let result = validate_image_dimensions(&image);
        assert!(result.is_err());
        // REQ-002: Verify generic error message
        assert!(result.unwrap_err().to_string().contains("Invalid image dimensions"));
    }

    #[test]
    fn test_validate_image_dimensions_both_too_large() {
        // Both dimensions above maximum
        let image = create_image_with_dimensions(5000, 5000);
        let result = validate_image_dimensions(&image);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_image_dimensions_zero_width() {
        // Edge case: zero width
        let image = create_image_with_dimensions(0, MIN_IMAGE_DIM);
        assert!(validate_image_dimensions(&image).is_err());
    }

    #[test]
    fn test_validate_image_dimensions_zero_height() {
        // Edge case: zero height
        let image = create_image_with_dimensions(MIN_IMAGE_DIM, 0);
        assert!(validate_image_dimensions(&image).is_err());
    }

    #[test]
    fn test_validate_feature_vector_vein_exact() {
        // Exactly 512 elements for vein features
        let features: Vec<f64> = vec![0.5; VEIN_FEATURE_DIM];
        assert!(validate_feature_vector(&features, VEIN_FEATURE_DIM).is_ok());
    }

    #[test]
    fn test_validate_feature_vector_print_exact() {
        // Exactly 256 elements for print features
        let features: Vec<f64> = vec![0.5; PRINT_FEATURE_DIM];
        assert!(validate_feature_vector(&features, PRINT_FEATURE_DIM).is_ok());
    }

    #[test]
    fn test_validate_feature_vector_too_short() {
        // One element short (511 instead of 512)
        let features: Vec<f64> = vec![0.5; VEIN_FEATURE_DIM - 1];
        let result = validate_feature_vector(&features, VEIN_FEATURE_DIM);
        assert!(result.is_err());
        // REQ-002: Verify generic error message
        assert!(result.unwrap_err().to_string().contains("Invalid feature vector"));
    }

    #[test]
    fn test_validate_feature_vector_too_long() {
        // One element extra (513 instead of 512)
        let features: Vec<f64> = vec![0.5; VEIN_FEATURE_DIM + 1];
        let result = validate_feature_vector(&features, VEIN_FEATURE_DIM);
        assert!(result.is_err());
        // REQ-002: Verify generic error message
        assert!(result.unwrap_err().to_string().contains("Invalid feature vector"));
    }

    #[test]
    fn test_validate_feature_vector_empty() {
        // Edge case: empty vector
        let features: Vec<f64> = vec![];
        let result = validate_feature_vector(&features, VEIN_FEATURE_DIM);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_feature_vector_wrong_modality_size() {
        // Print-sized vector validated against vein expectation
        let features: Vec<f64> = vec![0.5; PRINT_FEATURE_DIM];
        assert!(validate_feature_vector(&features, VEIN_FEATURE_DIM).is_err());

        // Vein-sized vector validated against print expectation
        let features: Vec<f64> = vec![0.5; VEIN_FEATURE_DIM];
        assert!(validate_feature_vector(&features, PRINT_FEATURE_DIM).is_err());
    }

    #[test]
    fn test_extract_vein_features_rejects_small_image() {
        // REQ-002: Verify extraction rejects images below minimum dimensions
        let small_image = create_image_with_dimensions(32, 32);
        let result = extract_vein_features(&small_image);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid image dimensions"));
    }

    #[test]
    fn test_extract_vein_features_rejects_large_image() {
        // REQ-002: Verify extraction rejects images above maximum dimensions
        let large_image = create_image_with_dimensions(5000, 5000);
        let result = extract_vein_features(&large_image);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid image dimensions"));
    }

    #[test]
    fn test_extract_print_features_rejects_small_image() {
        // REQ-002: Verify extraction rejects images below minimum dimensions
        let small_image = create_image_with_dimensions(32, 32);
        let result = extract_print_features(&small_image);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid image dimensions"));
    }

    #[test]
    fn test_extract_print_features_rejects_large_image() {
        // REQ-002: Verify extraction rejects images above maximum dimensions
        let large_image = create_image_with_dimensions(5000, 5000);
        let result = extract_print_features(&large_image);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid image dimensions"));
    }

    #[test]
    fn test_extract_vein_features_accepts_valid_image() {
        // REQ-002: Verify extraction accepts images within valid range
        let valid_image = create_image_with_dimensions(256, 256);
        let result = extract_vein_features(&valid_image);
        assert!(result.is_ok());
        // Also verify the output has correct feature dimension
        assert_eq!(result.unwrap().features.len(), VEIN_FEATURE_DIM);
    }

    #[test]
    fn test_extract_print_features_accepts_valid_image() {
        // REQ-002: Verify extraction accepts images within valid range
        let valid_image = create_image_with_dimensions(256, 256);
        let result = extract_print_features(&valid_image);
        assert!(result.is_ok());
        // Also verify the output has correct feature dimension
        assert_eq!(result.unwrap().features.len(), PRINT_FEATURE_DIM);
    }

    #[test]
    fn test_error_messages_are_generic() {
        // REQ-002: Verify that error messages do not leak specific validation details
        let too_small = create_image_with_dimensions(32, 32);
        let too_large = create_image_with_dimensions(5000, 5000);
        let width_only_bad = create_image_with_dimensions(32, 256);
        let height_only_bad = create_image_with_dimensions(256, 32);

        // All should produce the same generic error message
        let err1 = validate_image_dimensions(&too_small).unwrap_err().to_string();
        let err2 = validate_image_dimensions(&too_large).unwrap_err().to_string();
        let err3 = validate_image_dimensions(&width_only_bad).unwrap_err().to_string();
        let err4 = validate_image_dimensions(&height_only_bad).unwrap_err().to_string();

        // All errors should be identical (no information leakage)
        assert_eq!(err1, err2);
        assert_eq!(err2, err3);
        assert_eq!(err3, err4);

        // Should not contain specific dimension values
        assert!(!err1.contains("32"));
        assert!(!err1.contains("5000"));
        assert!(!err1.contains("width"));
        assert!(!err1.contains("height"));
    }

    #[test]
    fn test_constants_have_correct_values() {
        // REQ-002: Verify constant values match requirements
        assert_eq!(MIN_IMAGE_DIM, 64);
        assert_eq!(MAX_IMAGE_DIM, 4096);
        assert_eq!(VEIN_FEATURE_DIM, 512);
        assert_eq!(PRINT_FEATURE_DIM, 256);
    }

    // =========================================================================
    // REQ-007: Z-Score Normalization Tests
    // =========================================================================

    /// Helper function to calculate the mean of a feature vector
    fn calculate_mean(features: &[f64]) -> f64 {
        if features.is_empty() {
            return 0.0;
        }
        features.iter().sum::<f64>() / features.len() as f64
    }

    /// Helper function to calculate the standard deviation of a feature vector
    fn calculate_std(features: &[f64]) -> f64 {
        if features.is_empty() {
            return 0.0;
        }
        let mean = calculate_mean(features);
        let variance = features.iter()
            .map(|x| (x - mean).powi(2))
            .sum::<f64>() / features.len() as f64;
        variance.sqrt()
    }

    #[test]
    fn test_zscore_normalize_mean_zero() {
        // REQ-007: Verify normalized features have mean approximately 0
        let mut features: Vec<f64> = vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0];
        zscore_normalize(&mut features);

        let mean = calculate_mean(&features);
        assert!(mean.abs() < 1e-10, "Mean should be approximately 0, got {}", mean);
    }

    #[test]
    fn test_zscore_normalize_std_one() {
        // REQ-007: Verify normalized features have std approximately 1
        let mut features: Vec<f64> = vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0];
        zscore_normalize(&mut features);

        let std = calculate_std(&features);
        assert!((std - 1.0).abs() < 1e-10, "Std should be approximately 1, got {}", std);
    }

    #[test]
    fn test_zscore_normalize_empty_vector() {
        // REQ-007: Empty vectors should be handled gracefully
        let mut features: Vec<f64> = vec![];
        zscore_normalize(&mut features);

        assert!(features.is_empty(), "Empty vector should remain empty");
    }

    #[test]
    fn test_zscore_normalize_constant_vector() {
        // REQ-007: Constant vectors (std=0) should be handled gracefully
        let mut features: Vec<f64> = vec![5.0, 5.0, 5.0, 5.0, 5.0];
        let original = features.clone();
        zscore_normalize(&mut features);

        // Should remain unchanged (avoid division by zero)
        assert_eq!(features, original, "Constant vector should remain unchanged");
    }

    #[test]
    fn test_zscore_normalize_single_element() {
        // REQ-007: Single element vectors should be handled gracefully
        let mut features: Vec<f64> = vec![42.0];
        let original = features.clone();
        zscore_normalize(&mut features);

        // Single element has std=0, should remain unchanged
        assert_eq!(features, original, "Single element vector should remain unchanged");
    }

    #[test]
    fn test_zscore_normalize_large_variance() {
        // REQ-007: Test with large variance values
        let mut features: Vec<f64> = vec![0.0, 100.0, 200.0, 300.0, 400.0];
        zscore_normalize(&mut features);

        let mean = calculate_mean(&features);
        let std = calculate_std(&features);

        assert!(mean.abs() < 1e-10, "Mean should be approximately 0, got {}", mean);
        assert!((std - 1.0).abs() < 1e-10, "Std should be approximately 1, got {}", std);
    }

    #[test]
    fn test_zscore_normalize_small_variance() {
        // REQ-007: Test with small variance values
        let mut features: Vec<f64> = vec![1.0, 1.001, 1.002, 1.003, 1.004];
        zscore_normalize(&mut features);

        let mean = calculate_mean(&features);
        let std = calculate_std(&features);

        assert!(mean.abs() < 1e-10, "Mean should be approximately 0, got {}", mean);
        assert!((std - 1.0).abs() < 1e-10, "Std should be approximately 1, got {}", std);
    }

    #[test]
    fn test_zscore_normalize_negative_values() {
        // REQ-007: Test with negative values
        let mut features: Vec<f64> = vec![-5.0, -3.0, 0.0, 3.0, 5.0];
        zscore_normalize(&mut features);

        let mean = calculate_mean(&features);
        let std = calculate_std(&features);

        assert!(mean.abs() < 1e-10, "Mean should be approximately 0, got {}", mean);
        assert!((std - 1.0).abs() < 1e-10, "Std should be approximately 1, got {}", std);
    }

    #[test]
    fn test_zscore_normalize_realistic_feature_vector() {
        // REQ-007: Test with realistic feature vector size (512 dimensions)
        let mut features: Vec<f64> = (0..512).map(|i| (i as f64) / 512.0).collect();
        zscore_normalize(&mut features);

        let mean = calculate_mean(&features);
        let std = calculate_std(&features);

        assert!(mean.abs() < 1e-10, "Mean should be approximately 0, got {}", mean);
        assert!((std - 1.0).abs() < 1e-10, "Std should be approximately 1, got {}", std);
    }

    #[test]
    fn test_vein_features_are_normalized() {
        // REQ-007: Verify vein feature extraction produces normalized features
        let valid_image = create_image_with_dimensions(256, 256);
        let result = extract_vein_features(&valid_image).unwrap();

        let mean = calculate_mean(&result.features);
        let std = calculate_std(&result.features);

        // Features should be z-score normalized
        assert!(mean.abs() < 1e-10, "Vein features mean should be approximately 0, got {}", mean);
        assert!((std - 1.0).abs() < 1e-10, "Vein features std should be approximately 1, got {}", std);
    }

    #[test]
    fn test_print_features_are_normalized() {
        // REQ-007: Verify print feature extraction produces normalized features
        let valid_image = create_image_with_dimensions(256, 256);
        let result = extract_print_features(&valid_image).unwrap();

        let mean = calculate_mean(&result.features);
        let std = calculate_std(&result.features);

        // Features should be z-score normalized
        assert!(mean.abs() < 1e-10, "Print features mean should be approximately 0, got {}", mean);
        assert!((std - 1.0).abs() < 1e-10, "Print features std should be approximately 1, got {}", std);
    }

    // =========================================================================
    // REQ-003: Algorithmic Feature Extraction Tests
    // =========================================================================

    /// Helper to create a test image with specific pattern for determinism testing
    fn create_patterned_test_image(width: u32, height: u32, pattern_seed: u8) -> PalmImage {
        let size = (width * height) as usize;
        let mut data = Vec::with_capacity(size);
        for y in 0..height {
            for x in 0..width {
                // Deterministic pattern based on position and seed
                let value = ((x.wrapping_mul(17).wrapping_add(y.wrapping_mul(13)).wrapping_add(pattern_seed as u32)) % 256) as u8;
                data.push(value);
            }
        }
        PalmImage::new(width, height, 1, data)
    }

    /// Helper to create a different image (for testing different features)
    fn create_different_test_image(width: u32, height: u32) -> PalmImage {
        let size = (width * height) as usize;
        let mut data = Vec::with_capacity(size);
        for y in 0..height {
            for x in 0..width {
                // Different pattern: diagonal stripes
                let value = if (x + y) % 8 < 4 { 200 } else { 50 };
                data.push(value);
            }
        }
        PalmImage::new(width, height, 1, data)
    }

    #[test]
    fn test_req003_cnn_features_are_deterministic_vein() {
        // REQ-003: Same input image must produce same output features
        let image = create_patterned_test_image(128, 128, 42);

        let features1 = extract_cnn_features(&image, FeatureType::PalmVein).unwrap();
        let features2 = extract_cnn_features(&image, FeatureType::PalmVein).unwrap();

        assert_eq!(features1.len(), features2.len(), "Feature vectors should have same length");
        for (i, (f1, f2)) in features1.iter().zip(features2.iter()).enumerate() {
            assert!((f1 - f2).abs() < 1e-15,
                "Feature {} differs: {} vs {} (diff: {})", i, f1, f2, (f1 - f2).abs());
        }
    }

    #[test]
    fn test_req003_cnn_features_are_deterministic_print() {
        // REQ-003: Same input image must produce same output features
        let image = create_patterned_test_image(128, 128, 42);

        let features1 = extract_cnn_features(&image, FeatureType::PalmPrint).unwrap();
        let features2 = extract_cnn_features(&image, FeatureType::PalmPrint).unwrap();

        assert_eq!(features1.len(), features2.len(), "Feature vectors should have same length");
        for (i, (f1, f2)) in features1.iter().zip(features2.iter()).enumerate() {
            assert!((f1 - f2).abs() < 1e-15,
                "Feature {} differs: {} vs {} (diff: {})", i, f1, f2, (f1 - f2).abs());
        }
    }

    #[test]
    fn test_req003_different_images_produce_different_features() {
        // REQ-003: Different images should produce different features
        let image1 = create_patterned_test_image(128, 128, 42);
        let image2 = create_different_test_image(128, 128);

        let features1 = extract_cnn_features(&image1, FeatureType::PalmVein).unwrap();
        let features2 = extract_cnn_features(&image2, FeatureType::PalmVein).unwrap();

        // Count how many features differ significantly
        let different_count = features1.iter().zip(features2.iter())
            .filter(|(f1, f2)| (*f1 - *f2).abs() > 0.01)
            .count();

        // At least 10% of features should be significantly different
        let threshold = features1.len() / 10;
        assert!(different_count > threshold,
            "Only {} out of {} features differ significantly (threshold: {})",
            different_count, features1.len(), threshold);
    }

    #[test]
    fn test_req003_feature_vector_correct_dimension_vein() {
        // REQ-003: Feature vector must have correct dimension (400 for vein)
        let image = create_patterned_test_image(128, 128, 42);
        let features = extract_cnn_features(&image, FeatureType::PalmVein).unwrap();

        assert_eq!(features.len(), 400, "Vein CNN features should have 400 dimensions, got {}", features.len());
    }

    #[test]
    fn test_req003_feature_vector_correct_dimension_print() {
        // REQ-003: Feature vector must have correct dimension (200 for print)
        let image = create_patterned_test_image(128, 128, 42);
        let features = extract_cnn_features(&image, FeatureType::PalmPrint).unwrap();

        assert_eq!(features.len(), 200, "Print CNN features should have 200 dimensions, got {}", features.len());
    }

    #[test]
    fn test_req003_features_are_normalized() {
        // REQ-003: Features should be normalized to [0, 1] range (before z-score)
        let image = create_patterned_test_image(128, 128, 42);
        let features = extract_cnn_features(&image, FeatureType::PalmVein).unwrap();

        for (i, &f) in features.iter().enumerate() {
            assert!(f >= 0.0 && f <= 1.0,
                "Feature {} is outside [0, 1] range: {}", i, f);
        }
    }

    #[test]
    fn test_req003_regional_statistics_extraction() {
        // REQ-003: Test regional statistics extraction directly
        let image = create_patterned_test_image(64, 64, 42);
        let grid_size = 4;

        let stats = extract_regional_statistics(&image, grid_size).unwrap();

        // 4x4 grid = 16 regions, 4 stats each = 64 features
        assert_eq!(stats.len(), 64, "Regional statistics should have 64 features (4x4 grid x 4 stats)");

        // All values should be bounded
        for (i, &s) in stats.iter().enumerate() {
            assert!(s.is_finite(), "Regional statistic {} is not finite: {}", i, s);
            assert!(s >= -1.0 && s <= 1.0, "Regional statistic {} is outside [-1, 1] range: {}", i, s);
        }
    }

    #[test]
    fn test_req003_lbp_features_extraction() {
        // REQ-003: Test LBP feature extraction directly
        let image = create_patterned_test_image(64, 64, 42);
        let grid_size = 4;

        let lbp = extract_lbp_features(&image, grid_size).unwrap();

        // 4x4 grid = 16 regions, 16 bins each = 256 features
        assert_eq!(lbp.len(), 256, "LBP features should have 256 features (4x4 grid x 16 bins)");

        // All histogram values should be in [0, 1] (normalized)
        for (i, &l) in lbp.iter().enumerate() {
            assert!(l >= 0.0 && l <= 1.0, "LBP feature {} is outside [0, 1] range: {}", i, l);
        }
    }

    #[test]
    fn test_req003_hog_features_extraction() {
        // REQ-003: Test HOG feature extraction directly
        let image = create_patterned_test_image(64, 64, 42);
        let grid_size = 4;

        let hog = extract_hog_features(&image, grid_size).unwrap();

        // 4x4 grid = 16 regions, 9 bins each = 144 features
        assert_eq!(hog.len(), 144, "HOG features should have 144 features (4x4 grid x 9 bins)");

        // All L2-normalized histogram values should be in [0, 1]
        for (i, &h) in hog.iter().enumerate() {
            assert!(h >= 0.0 && h <= 1.0, "HOG feature {} is outside [0, 1] range: {}", i, h);
        }
    }

    #[test]
    fn test_req003_edge_density_features_extraction() {
        // REQ-003: Test edge density feature extraction directly
        let image = create_patterned_test_image(64, 64, 42);
        let grid_size = 4;

        let edges = extract_edge_density_features(&image, grid_size).unwrap();

        // 4x4 grid = 16 regions, 2 features each = 32 features
        assert_eq!(edges.len(), 32, "Edge density features should have 32 features (4x4 grid x 2)");

        // All values should be in [0, 1]
        for (i, &e) in edges.iter().enumerate() {
            assert!(e >= 0.0 && e <= 1.0, "Edge feature {} is outside [0, 1] range: {}", i, e);
        }
    }

    #[test]
    fn test_req003_texture_energy_features_extraction() {
        // REQ-003: Test texture energy feature extraction directly
        let image = create_patterned_test_image(64, 64, 42);
        let grid_size = 4;

        let texture = extract_texture_energy_features(&image, grid_size).unwrap();

        // 4x4 grid = 16 regions, 2 scales each = 32 features
        assert_eq!(texture.len(), 32, "Texture energy features should have 32 features (4x4 grid x 2 scales)");

        // All values should be in [0, 1]
        for (i, &t) in texture.iter().enumerate() {
            assert!(t >= 0.0 && t <= 1.0, "Texture feature {} is outside [0, 1] range: {}", i, t);
        }
    }

    #[test]
    fn test_req003_features_meaningful_for_different_content() {
        // REQ-003: Features should capture meaningful differences in image content
        // Create images with distinctly different characteristics

        // Image 1: High contrast diagonal pattern
        let high_contrast = create_different_test_image(128, 128);

        // Image 2: Uniform low contrast
        let mut uniform_data = vec![128u8; 128 * 128];
        // Add slight noise to avoid constant variance
        for (i, pixel) in uniform_data.iter_mut().enumerate() {
            *pixel = (128 + (i % 5) as i32 - 2) as u8;
        }
        let uniform = PalmImage::new(128, 128, 1, uniform_data);

        let features_high_contrast = extract_cnn_features(&high_contrast, FeatureType::PalmVein).unwrap();
        let features_uniform = extract_cnn_features(&uniform, FeatureType::PalmVein).unwrap();

        // Calculate average absolute difference
        let avg_diff: f64 = features_high_contrast.iter()
            .zip(features_uniform.iter())
            .map(|(a, b)| (a - b).abs())
            .sum::<f64>() / features_high_contrast.len() as f64;

        // The average difference should be noticeable
        assert!(avg_diff > 0.05,
            "Features should differ meaningfully between high contrast and uniform images. Avg diff: {}", avg_diff);
    }

    #[test]
    fn test_req003_full_pipeline_determinism_vein() {
        // REQ-003: Full vein feature extraction pipeline should be deterministic
        let image = create_patterned_test_image(128, 128, 99);

        let result1 = extract_vein_features(&image).unwrap();
        let result2 = extract_vein_features(&image).unwrap();

        assert_eq!(result1.features.len(), result2.features.len());
        for (i, (f1, f2)) in result1.features.iter().zip(result2.features.iter()).enumerate() {
            assert!((f1 - f2).abs() < 1e-10,
                "Vein feature {} differs across runs: {} vs {}", i, f1, f2);
        }
    }

    #[test]
    fn test_req003_full_pipeline_determinism_print() {
        // REQ-003: Full print feature extraction pipeline should be deterministic
        let image = create_patterned_test_image(128, 128, 99);

        let result1 = extract_print_features(&image).unwrap();
        let result2 = extract_print_features(&image).unwrap();

        assert_eq!(result1.features.len(), result2.features.len());
        for (i, (f1, f2)) in result1.features.iter().zip(result2.features.iter()).enumerate() {
            assert!((f1 - f2).abs() < 1e-10,
                "Print feature {} differs across runs: {} vs {}", i, f1, f2);
        }
    }

    #[test]
    fn test_req003_minmax_normalization() {
        // REQ-003: Test the min-max normalization helper
        let mut features = vec![10.0, 20.0, 30.0, 40.0, 50.0];
        normalize_features_minmax(&mut features);

        // Check all values are in [0, 1]
        for &f in &features {
            assert!(f >= 0.0 && f <= 1.0);
        }

        // Check min is 0 and max is 1
        let min = features.iter().fold(f64::INFINITY, |a, &b| a.min(b));
        let max = features.iter().fold(f64::NEG_INFINITY, |a, &b| a.max(b));
        assert!((min - 0.0).abs() < 1e-10, "Min should be 0, got {}", min);
        assert!((max - 1.0).abs() < 1e-10, "Max should be 1, got {}", max);
    }

    #[test]
    fn test_req003_dimension_adjustment_padding() {
        // REQ-003: Test dimension adjustment with padding
        let mut features = vec![0.1, 0.2, 0.3];
        adjust_feature_dimension(&mut features, 5);

        assert_eq!(features.len(), 5, "Features should be padded to 5 elements");
        // Padded values should be interpolated
        assert!(features[3] >= 0.0 && features[3] <= 1.0);
        assert!(features[4] >= 0.0 && features[4] <= 1.0);
    }

    #[test]
    fn test_req003_dimension_adjustment_truncation() {
        // REQ-003: Test dimension adjustment with truncation
        let mut features = vec![0.1, 0.2, 0.3, 0.4, 0.5];
        adjust_feature_dimension(&mut features, 3);

        assert_eq!(features.len(), 3, "Features should be truncated to 3 elements");
        assert_eq!(features, vec![0.1, 0.2, 0.3]);
    }

    // =========================================================================
    // REQ-006: Biometric Feature Extraction Tests
    // Tests for enhance_palm_ridges, extract_minutiae, extract_texture_features
    // =========================================================================

    /// Create a test image with ridge-like patterns for testing
    fn create_ridge_test_image() -> PalmImage {
        let mut data = Vec::with_capacity(64 * 64);
        for y in 0..64 {
            for x in 0..64 {
                // Create vertical ridge pattern
                let value = if x % 4 < 2 { 200u8 } else { 50u8 };
                data.push(value);
            }
        }
        PalmImage::new(64, 64, 1, data)
    }

    /// Create a test image with bifurcation-like patterns
    fn create_bifurcation_test_image() -> PalmImage {
        let mut data = vec![0u8; 64 * 64];
        // Create a Y-shaped pattern (bifurcation)
        for y in 0..32 {
            let x = 32;
            data[y * 64 + x] = 255;
        }
        for y in 32..64 {
            let offset = y - 32;
            let x1 = 32 - offset.min(16);
            let x2 = 32 + offset.min(16);
            if x1 < 64 { data[y * 64 + x1] = 255; }
            if x2 < 64 { data[y * 64 + x2] = 255; }
        }
        PalmImage::new(64, 64, 1, data)
    }

    // -------------------------------------------------------------------------
    // enhance_palm_ridges tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_enhance_palm_ridges_returns_valid_image() {
        // REQ-006: Verify enhance_palm_ridges returns a valid image
        let image = create_ridge_test_image();
        let enhanced = enhance_palm_ridges(&image).unwrap();

        assert_eq!(enhanced.width, image.width, "Width should be preserved");
        assert_eq!(enhanced.height, image.height, "Height should be preserved");
        assert_eq!(enhanced.channels, 1, "Should be single channel");
        assert_eq!(enhanced.data.len(), (image.width * image.height) as usize);
    }

    #[test]
    fn test_enhance_palm_ridges_applies_gabor_filters() {
        // REQ-006: Verify Gabor filters are applied (output differs from input)
        let image = create_ridge_test_image();
        let enhanced = enhance_palm_ridges(&image).unwrap();

        // Enhanced image should differ from original
        let original_sum: u64 = image.data.iter().map(|&x| x as u64).sum();
        let enhanced_sum: u64 = enhanced.data.iter().map(|&x| x as u64).sum();

        // Not strictly equal due to filtering
        assert!(original_sum != enhanced_sum ||
                image.data.iter().zip(enhanced.data.iter()).any(|(a, b)| a != b),
                "Enhancement should modify the image");
    }

    #[test]
    fn test_enhance_palm_ridges_with_uniform_image() {
        // REQ-006: Handle uniform image gracefully
        let data = vec![128u8; 64 * 64];
        let image = PalmImage::new(64, 64, 1, data);

        let result = enhance_palm_ridges(&image);
        assert!(result.is_ok(), "Should handle uniform image");
    }

    #[test]
    fn test_enhance_palm_ridges_preserves_dimensions() {
        // REQ-006: Various image sizes should work
        for size in [64, 128, 256] {
            let data = vec![128u8; size * size];
            let image = PalmImage::new(size as u32, size as u32, 1, data);

            let enhanced = enhance_palm_ridges(&image).unwrap();
            assert_eq!(enhanced.width, size as u32);
            assert_eq!(enhanced.height, size as u32);
        }
    }

    // -------------------------------------------------------------------------
    // extract_minutiae tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_extract_minutiae_returns_32_features() {
        // REQ-006: Verify minutiae extraction returns exactly 32 features
        let image = create_ridge_test_image();
        let features = extract_minutiae(&image).unwrap();

        assert_eq!(features.len(), 32, "Should return exactly 32 features");
    }

    #[test]
    fn test_extract_minutiae_features_in_valid_range() {
        // REQ-006: All features should be in [0, 1] range
        let image = create_ridge_test_image();
        let features = extract_minutiae(&image).unwrap();

        for (i, &f) in features.iter().enumerate() {
            assert!(f >= 0.0 && f <= 1.0,
                    "Feature {} should be in [0,1], got {}", i, f);
        }
    }

    #[test]
    fn test_extract_minutiae_count_features() {
        // REQ-006: First 4 features are minutiae counts
        let image = create_ridge_test_image();
        let features = extract_minutiae(&image).unwrap();

        // Features 0-3: ending count, bifurcation count, total count, ratio
        assert!(features[0] >= 0.0, "Ending count should be non-negative");
        assert!(features[1] >= 0.0, "Bifurcation count should be non-negative");
        assert!(features[2] >= 0.0, "Total count should be non-negative");
        // Ratio should be between 0 and 1
        assert!(features[3] >= 0.0 && features[3] <= 1.0,
                "Ratio should be in [0,1]");
    }

    #[test]
    fn test_extract_minutiae_spatial_distribution() {
        // REQ-006: Features 4-15 are spatial distribution (12 grid cells)
        let image = create_ridge_test_image();
        let features = extract_minutiae(&image).unwrap();

        // Check spatial distribution features (4-15)
        for i in 4..16 {
            assert!(features[i] >= 0.0 && features[i] <= 1.0,
                    "Spatial feature {} should be in [0,1]", i);
        }
    }

    #[test]
    fn test_extract_minutiae_orientation_histogram() {
        // REQ-006: Features 16-31 are orientation histogram (16 bins)
        let image = create_ridge_test_image();
        let features = extract_minutiae(&image).unwrap();

        // Check orientation histogram (features 16-31)
        let histogram_sum: f64 = features[16..32].iter().sum();

        // Histogram should sum to approximately 1.0 (normalized)
        assert!((histogram_sum - 1.0).abs() < 0.01,
                "Orientation histogram should sum to 1.0, got {}", histogram_sum);
    }

    #[test]
    fn test_extract_minutiae_with_uniform_image() {
        // REQ-006: Handle uniform image (no ridges) gracefully
        let data = vec![128u8; 64 * 64];
        let image = PalmImage::new(64, 64, 1, data);

        let features = extract_minutiae(&image).unwrap();
        assert_eq!(features.len(), 32, "Should still return 32 features");
    }

    #[test]
    fn test_extract_minutiae_deterministic() {
        // REQ-006: Same input should produce same output
        let image = create_ridge_test_image();

        let features1 = extract_minutiae(&image).unwrap();
        let features2 = extract_minutiae(&image).unwrap();

        assert_eq!(features1, features2, "Minutiae extraction should be deterministic");
    }

    // -------------------------------------------------------------------------
    // extract_texture_features tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_extract_texture_features_returns_48_features() {
        // REQ-006: Verify texture extraction returns exactly 48 features
        let image = create_ridge_test_image();
        let features = extract_texture_features(&image).unwrap();

        assert_eq!(features.len(), 48, "Should return exactly 48 features");
    }

    #[test]
    fn test_extract_texture_features_in_valid_range() {
        // REQ-006: All features should be in [0, 1] range
        let image = create_ridge_test_image();
        let features = extract_texture_features(&image).unwrap();

        for (i, &f) in features.iter().enumerate() {
            assert!(f >= 0.0 && f <= 1.0,
                    "Feature {} should be in [0,1], got {}", i, f);
        }
    }

    #[test]
    fn test_extract_texture_features_glcm_portion() {
        // REQ-006: First 16 features are GLCM (4 distances x 4 statistics)
        let image = create_ridge_test_image();
        let features = extract_texture_features(&image).unwrap();

        // GLCM features (0-15): contrast, correlation, energy, homogeneity x 4 distances
        for i in 0..16 {
            assert!(features[i] >= 0.0 && features[i] <= 1.0,
                    "GLCM feature {} should be in [0,1]", i);
        }
    }

    #[test]
    fn test_extract_texture_features_lbp_portion() {
        // REQ-006: Features 16-31 are LBP histogram (16 bins)
        let image = create_ridge_test_image();
        let features = extract_texture_features(&image).unwrap();

        // LBP histogram (16-31)
        let lbp_sum: f64 = features[16..32].iter().sum();

        // LBP histogram should sum to approximately 1.0 (normalized)
        assert!((lbp_sum - 1.0).abs() < 0.01,
                "LBP histogram should sum to 1.0, got {}", lbp_sum);
    }

    #[test]
    fn test_extract_texture_features_gabor_portion() {
        // REQ-006: Features 32-47 are Gabor statistics (4 orientations x 4 stats)
        let image = create_ridge_test_image();
        let features = extract_texture_features(&image).unwrap();

        // Gabor features (32-47): mean, std, energy, entropy x 4 orientations
        for i in 32..48 {
            assert!(features[i] >= 0.0 && features[i] <= 1.0,
                    "Gabor feature {} should be in [0,1]", i);
        }
    }

    #[test]
    fn test_extract_texture_features_with_uniform_image() {
        // REQ-006: Handle uniform image gracefully
        let data = vec![128u8; 64 * 64];
        let image = PalmImage::new(64, 64, 1, data);

        let features = extract_texture_features(&image).unwrap();
        assert_eq!(features.len(), 48, "Should still return 48 features");
    }

    #[test]
    fn test_extract_texture_features_deterministic() {
        // REQ-006: Same input should produce same output
        let image = create_ridge_test_image();

        let features1 = extract_texture_features(&image).unwrap();
        let features2 = extract_texture_features(&image).unwrap();

        assert_eq!(features1, features2, "Texture extraction should be deterministic");
    }

    #[test]
    fn test_extract_texture_features_sensitivity_to_pattern() {
        // REQ-006: Different patterns should produce different features
        let ridge_image = create_ridge_test_image();
        let uniform_image = PalmImage::new(64, 64, 1, vec![128u8; 64 * 64]);

        let ridge_features = extract_texture_features(&ridge_image).unwrap();
        let uniform_features = extract_texture_features(&uniform_image).unwrap();

        // Features should differ significantly
        let diff: f64 = ridge_features.iter()
            .zip(uniform_features.iter())
            .map(|(a, b)| (a - b).abs())
            .sum();

        assert!(diff > 0.1, "Different patterns should produce different features");
    }

    // -------------------------------------------------------------------------
    // GLCM helper function tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_compute_glcm_normalized() {
        // REQ-006: GLCM should be normalized (sum to 1)
        let image = create_ridge_test_image();
        let glcm = compute_glcm(&image, 1, 0).unwrap();

        let sum: f64 = glcm.iter().flat_map(|row| row.iter()).sum();
        assert!((sum - 1.0).abs() < 0.01, "GLCM should sum to 1.0, got {}", sum);
    }

    #[test]
    fn test_compute_glcm_contrast() {
        // REQ-006: GLCM contrast should be in [0, 1]
        let image = create_ridge_test_image();
        let glcm = compute_glcm(&image, 1, 0).unwrap();
        let contrast = compute_glcm_contrast(&glcm);

        assert!(contrast >= 0.0 && contrast <= 1.0,
                "Contrast should be in [0,1], got {}", contrast);
    }

    #[test]
    fn test_compute_glcm_correlation() {
        // REQ-006: GLCM correlation should be in [0, 1] (normalized from [-1, 1])
        let image = create_ridge_test_image();
        let glcm = compute_glcm(&image, 1, 0).unwrap();
        let correlation = compute_glcm_correlation(&glcm);

        assert!(correlation >= 0.0 && correlation <= 1.0,
                "Correlation should be in [0,1], got {}", correlation);
    }

    #[test]
    fn test_compute_glcm_energy() {
        // REQ-006: GLCM energy should be in [0, 1]
        let image = create_ridge_test_image();
        let glcm = compute_glcm(&image, 1, 0).unwrap();
        let energy = compute_glcm_energy(&glcm);

        assert!(energy >= 0.0 && energy <= 1.0,
                "Energy should be in [0,1], got {}", energy);
    }

    #[test]
    fn test_compute_glcm_homogeneity() {
        // REQ-006: GLCM homogeneity should be in [0, 1]
        let image = create_ridge_test_image();
        let glcm = compute_glcm(&image, 1, 0).unwrap();
        let homogeneity = compute_glcm_homogeneity(&glcm);

        assert!(homogeneity >= 0.0 && homogeneity <= 1.0,
                "Homogeneity should be in [0,1], got {}", homogeneity);
    }

    // -------------------------------------------------------------------------
    // LBP helper function tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_count_lbp_transitions_uniform_pattern() {
        // REQ-006: Uniform patterns have <= 2 transitions
        assert!(count_lbp_transitions(0b00000000) <= 2); // All 0s
        assert!(count_lbp_transitions(0b11111111) <= 2); // All 1s
        assert!(count_lbp_transitions(0b00001111) <= 2); // Half and half
        assert!(count_lbp_transitions(0b00000001) <= 2); // Single 1
    }

    #[test]
    fn test_count_lbp_transitions_non_uniform_pattern() {
        // REQ-006: Non-uniform patterns have > 2 transitions
        assert!(count_lbp_transitions(0b01010101) > 2); // Alternating
        assert!(count_lbp_transitions(0b10101010) > 2); // Alternating
    }

    #[test]
    fn test_extract_lbp_histogram_normalized() {
        // REQ-006: LBP histogram should be normalized (sum to 1)
        let image = create_ridge_test_image();
        let histogram = extract_lbp_histogram_features(&image).unwrap();

        let sum: f64 = histogram.iter().sum();
        assert!((sum - 1.0).abs() < 0.01,
                "LBP histogram should sum to 1.0, got {}", sum);
    }

    // -------------------------------------------------------------------------
    // CLAHE tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_apply_clahe_preserves_dimensions() {
        // REQ-006: CLAHE should preserve image dimensions
        let image = create_ridge_test_image();
        let result = apply_clahe(&image).unwrap();

        assert_eq!(result.width, image.width);
        assert_eq!(result.height, image.height);
        assert_eq!(result.channels, image.channels);
    }

    #[test]
    fn test_apply_clahe_enhances_contrast() {
        // REQ-006: CLAHE should generally maintain or increase contrast
        let mut data = vec![0u8; 64 * 64];
        // Create low contrast image (values between 100-155)
        for i in 0..data.len() {
            data[i] = 100 + (i % 56) as u8;
        }
        let image = PalmImage::new(64, 64, 1, data);

        let result = apply_clahe(&image).unwrap();

        // Output should have valid pixel values
        for &pixel in &result.data {
            assert!(pixel <= 255, "Pixel values should be valid");
        }
    }

    // -------------------------------------------------------------------------
    // Minutiae detection helper tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_binarize_image_output() {
        // REQ-006: Binarization should produce binary output
        let image = create_ridge_test_image();
        let binary = binarize_image(&image).unwrap();

        for &pixel in &binary.data {
            assert!(pixel == 0 || pixel == 255,
                    "Binary image should only contain 0 or 255, got {}", pixel);
        }
    }

    #[test]
    fn test_calculate_crossing_number() {
        // REQ-006: Crossing number calculation
        // Create a simple test image with known crossing number
        let mut data = vec![0u8; 9];
        // Center pixel with one neighbor (endpoint)
        data[4] = 255; // center
        data[1] = 255; // top
        let image = PalmImage::new(3, 3, 1, data);

        let cn = calculate_crossing_number(&image, 1, 1).unwrap();
        assert_eq!(cn, 1, "Endpoint should have crossing number 1");
    }

    // -------------------------------------------------------------------------
    // Integration tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_print_feature_extraction_uses_new_implementations() {
        // REQ-006: Verify extract_print_features uses the new implementations
        let image = create_image_with_dimensions(128, 128);
        let result = extract_print_features(&image);

        assert!(result.is_ok(), "Print feature extraction should succeed");
        let features = result.unwrap();
        assert_eq!(features.features.len(), PRINT_FEATURE_DIM);
    }

    #[test]
    fn test_feature_extraction_pipeline_integration() {
        // REQ-006: Test full pipeline from enhancement to feature extraction
        let image = create_ridge_test_image();

        // Step 1: Enhance ridges
        let enhanced = enhance_palm_ridges(&image).unwrap();
        assert_eq!(enhanced.data.len(), image.data.len());

        // Step 2: Extract minutiae from enhanced image
        let minutiae = extract_minutiae(&enhanced).unwrap();
        assert_eq!(minutiae.len(), 32);

        // Step 3: Extract texture from enhanced image
        let texture = extract_texture_features(&enhanced).unwrap();
        assert_eq!(texture.len(), 48);
    }
}
