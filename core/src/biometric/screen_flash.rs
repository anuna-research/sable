//! # Screen Flash Reflectance Ratio Check
//!
//! RGB controlled-illumination liveness analysis using screen flash reflectance.
//! All signals are extracted locally and proven in zero-knowledge.
//!
//! ## Overview
//!
//! This module implements REQ-062 and REQ-068 from SPEC-001-A:
//! - Reflectance variance from spatial distribution of flash/baseline ratios
//! - Reflectance gradient scoring via finite differences on reflectance maps
//! - Highlight softness analysis for subsurface scattering detection
//! - Channel consistency checking across R/G/B reflectance maps
//!
//! ## Theory (Tang et al., NDSS 2018 "Face Flashing")
//!
//! Real 3D faces produce spatially varied reflectance ratios due to uneven
//! geometry (nose, cheeks, forehead). Flat attack surfaces (screens, paper,
//! silicone) produce uniform ratios. By flashing random colors and analyzing
//! the reflected light, we can distinguish real skin from flat surfaces with
//! 98.8% accuracy.
//!
//! ## Privacy Guarantees
//!
//! - All reflectance signals are private circuit inputs (never transmitted)
//! - Verifier learns only aggregate pass/fail boolean
//! - No logging of individual signal values (NFR-023)
//!
//! ## References
//!
//! - Tang et al. (2018) - Face Flashing: a Secure Liveness Detection Protocol
//!   based on Light Reflections (NDSS 2018)
//! - ISO/IEC 30107-3:2017 - Biometric PAD testing
//!
//! **IMPORTANT:** This code is AI-generated and requires security audit before
//! production use. See ADR-004 for design rationale.

use crate::biometric::PalmImage;
use crate::error::{Result, SableError};
use zeroize::Zeroize;

// ============================================================================
// REQ-062: Research-Validated Reflectance Thresholds
// See ADR-004 and Tang et al. (NDSS 2018)
// ============================================================================

/// Minimum reflectance variance: 0.05 (3D geometry produces spatial variation)
/// Fixed-point representation: 0.05 * 65536 = 3277
pub const REFLECTANCE_VARIANCE_MIN: u16 = 3277;

/// Minimum reflectance gradient: 0.03 (smooth nose-to-cheek transitions)
/// Fixed-point representation: 0.03 * 65536 = 1966
pub const REFLECTANCE_GRADIENT_MIN: u16 = 1966;

/// Minimum highlight softness: 0.15 (subsurface scattering falloff)
/// Fixed-point representation: 0.15 * 65536 = 9830
pub const HIGHLIGHT_SOFTNESS_MIN: u16 = 9830;

/// Maximum channel consistency: 0.95 (real skin has wavelength-dependent albedo)
/// Fixed-point representation: 0.95 * 65536 = 62259
/// NOTE: This is a MAX threshold — high values indicate flat/screen attack
pub const CHANNEL_CONSISTENCY_MAX: u16 = 62259;

/// Minimum pixel intensity to avoid division by zero in reflectance computation
const MIN_PIXEL_INTENSITY: f64 = 1.0;

/// Anchor region size (center NxN pixels) for reflectance normalization
const ANCHOR_REGION_SIZE: u32 = 10;

/// Highlight threshold: pixels with reflectance ratio > 1.5 are highlights
const HIGHLIGHT_RATIO_THRESHOLD: f64 = 1.5;

// ============================================================================
// REQ-062: Screen Flash Threshold Configuration
// ============================================================================

/// Research-validated screen flash reflectance thresholds.
///
/// All values are 16-bit fixed-point (value / 65536 = float).
/// See ADR-004 for threshold derivation and Tang et al. (NDSS 2018).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScreenFlashThresholds {
    /// Minimum reflectance variance (0.05 default)
    pub reflectance_variance_min: u16,
    /// Minimum reflectance gradient score (0.03 default)
    pub reflectance_gradient_min: u16,
    /// Minimum highlight softness (0.15 default)
    pub highlight_softness_min: u16,
    /// Maximum channel consistency (0.95 default) — high = suspicious
    pub channel_consistency_max: u16,
}

impl Default for ScreenFlashThresholds {
    fn default() -> Self {
        Self {
            reflectance_variance_min: REFLECTANCE_VARIANCE_MIN,
            reflectance_gradient_min: REFLECTANCE_GRADIENT_MIN,
            highlight_softness_min: HIGHLIGHT_SOFTNESS_MIN,
            channel_consistency_max: CHANNEL_CONSISTENCY_MAX,
        }
    }
}

impl ScreenFlashThresholds {
    /// Create thresholds optimized for high-security environments.
    ///
    /// Tightens all thresholds to reduce false acceptance at cost of
    /// slightly higher false rejection.
    pub fn high_security() -> Self {
        Self {
            reflectance_variance_min: 4915,  // 0.075
            reflectance_gradient_min: 2949,  // 0.045
            highlight_softness_min: 13107,   // 0.20
            channel_consistency_max: 58982,  // 0.90
        }
    }

    /// Validate that a threshold configuration is sane.
    pub fn validate(&self) -> Result<()> {
        // Min thresholds must be > 0
        if self.reflectance_variance_min == 0
            || self.reflectance_gradient_min == 0
            || self.highlight_softness_min == 0
        {
            return Err(SableError::InvalidInput(
                "Invalid threshold configuration".into(),
            ));
        }
        // Max threshold must leave room for legitimate values
        if self.channel_consistency_max == 0 {
            return Err(SableError::InvalidInput(
                "Invalid threshold configuration".into(),
            ));
        }
        Ok(())
    }
}

// ============================================================================
// REQ-062: Screen Flash Signal Structure
// ============================================================================

/// Extracted screen flash reflectance signals.
///
/// All values are 16-bit fixed-point for circuit compatibility.
/// This struct implements `Zeroize` to clear sensitive biometric data.
///
/// **Privacy:** These values are NEVER transmitted or logged.
/// They exist only as private circuit witness inputs.
#[derive(Clone)]
pub struct ScreenFlashSignals {
    /// Reflectance variance: spatial variance of reflectance ratios.
    /// High for 3D surfaces (real faces), low for flat surfaces.
    /// Range: [0, 65535] where 65535 = 1.0 normalized
    pub reflectance_variance: u16,

    /// Reflectance gradient score: smooth spatial transitions in reflectance.
    /// Real faces show smooth nose-to-cheek gradients.
    /// Range: [0, 65535] normalized
    pub reflectance_gradient: u16,

    /// Highlight softness: falloff profile of bright spots.
    /// Real skin has gradual subsurface scattering falloff.
    /// Range: [0, 65535] normalized
    pub highlight_softness: u16,

    /// Channel consistency: correlation between R/G/B reflectance maps.
    /// Screens have ~1.0 (uniform), real skin has ~0.7-0.9.
    /// Range: [0, 65535] where 65535 = 1.0
    /// NOTE: This has a MAX threshold — high values are suspicious.
    pub channel_consistency: u16,
}

impl Zeroize for ScreenFlashSignals {
    fn zeroize(&mut self) {
        self.reflectance_variance = 0;
        self.reflectance_gradient = 0;
        self.highlight_softness = 0;
        self.channel_consistency = 0;
    }
}

impl Drop for ScreenFlashSignals {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ScreenFlashSignals {
    /// Check if all signals pass the given thresholds.
    ///
    /// This is a preliminary check before circuit proof generation.
    /// The circuit enforces the same thresholds cryptographically.
    ///
    /// **Note:** Does not reveal which threshold failed (REQ-005).
    pub fn passes_thresholds(&self, thresholds: &ScreenFlashThresholds) -> bool {
        // 3 minimum checks
        let variance_ok = self.reflectance_variance >= thresholds.reflectance_variance_min;
        let gradient_ok = self.reflectance_gradient >= thresholds.reflectance_gradient_min;
        let softness_ok = self.highlight_softness >= thresholds.highlight_softness_min;

        // 1 maximum check (high channel consistency = suspicious)
        let consistency_ok = self.channel_consistency <= thresholds.channel_consistency_max;

        variance_ok && gradient_ok && softness_ok && consistency_ok
    }

    /// Convert to circuit witness format (field elements).
    ///
    /// Returns values as u64 for Fr::from() conversion.
    pub fn to_circuit_witness(&self) -> ScreenFlashWitness {
        ScreenFlashWitness {
            reflectance_variance: self.reflectance_variance as u64,
            reflectance_gradient: self.reflectance_gradient as u64,
            highlight_softness: self.highlight_softness as u64,
            channel_consistency: self.channel_consistency as u64,
        }
    }
}

// ============================================================================
// Circuit Witness Format
// ============================================================================

/// Circuit witness format for screen flash signals.
///
/// Values are u64 for direct conversion to field elements.
#[derive(Clone)]
pub struct ScreenFlashWitness {
    /// Reflectance variance as u64 for field element conversion.
    pub reflectance_variance: u64,
    /// Reflectance gradient as u64 for field element conversion.
    pub reflectance_gradient: u64,
    /// Highlight softness as u64 for field element conversion.
    pub highlight_softness: u64,
    /// Channel consistency as u64 for field element conversion.
    pub channel_consistency: u64,
}

// ============================================================================
// REQ-062: Screen Flash Signal Extraction
// ============================================================================

/// Extracts screen flash reflectance signals from baseline/flash image pairs.
///
/// Implements controlled-illumination analysis per Tang et al. (NDSS 2018).
pub struct ScreenFlashExtractor {
    /// Thresholds for validation
    thresholds: ScreenFlashThresholds,
}

impl ScreenFlashExtractor {
    /// Create a new extractor with default thresholds.
    pub fn new() -> Self {
        Self {
            thresholds: ScreenFlashThresholds::default(),
        }
    }

    /// Create with custom thresholds.
    pub fn with_thresholds(thresholds: ScreenFlashThresholds) -> Result<Self> {
        thresholds.validate()?;
        Ok(Self { thresholds })
    }

    /// Extract all screen flash signals from a baseline/flash image pair.
    ///
    /// # Arguments
    /// * `baseline` - Image captured before flash (ambient lighting)
    /// * `flash` - Image captured during screen flash
    ///
    /// # Returns
    /// * `ScreenFlashSignals` containing all extracted values
    ///
    /// # Errors
    /// * Dimension mismatch between baseline and flash
    /// * Images not RGB (3 channels)
    /// * Insufficient resolution
    pub fn extract_signals(
        &self,
        baseline: &PalmImage,
        flash: &PalmImage,
    ) -> Result<ScreenFlashSignals> {
        self.validate_inputs(baseline, flash)?;

        let reflectance_variance = self.compute_reflectance_variance(baseline, flash)?;
        let reflectance_gradient = self.compute_reflectance_gradient_score(baseline, flash)?;
        let highlight_softness = self.compute_highlight_softness(baseline, flash)?;
        let channel_consistency = self.compute_channel_consistency(baseline, flash)?;

        Ok(ScreenFlashSignals {
            reflectance_variance,
            reflectance_gradient,
            highlight_softness,
            channel_consistency,
        })
    }

    /// Validate that extracted signals meet thresholds.
    ///
    /// Returns only pass/fail to avoid leaking which signal failed.
    pub fn validate_signals(&self, signals: &ScreenFlashSignals) -> bool {
        signals.passes_thresholds(&self.thresholds)
    }

    // ========================================================================
    // Private: Input Validation
    // ========================================================================

    fn validate_inputs(&self, baseline: &PalmImage, flash: &PalmImage) -> Result<()> {
        // Dimensions must match
        if baseline.width != flash.width
            || baseline.height != flash.height
            || baseline.channels != flash.channels
        {
            return Err(SableError::InvalidInput(
                "Image dimension mismatch".into(),
            ));
        }

        // Must be RGB (3 channels)
        if baseline.channels != 3 {
            return Err(SableError::InvalidInput(
                "RGB images required".into(),
            ));
        }

        // Minimum resolution
        if baseline.width < 64 || baseline.height < 64 {
            return Err(SableError::InvalidInput(
                "Insufficient image resolution".into(),
            ));
        }

        Ok(())
    }

    // ========================================================================
    // Private: Reflectance Map Computation
    // ========================================================================

    /// Compute per-pixel reflectance map for a single channel.
    ///
    /// For each pixel: ratio = flash[i] / max(baseline[i], MIN_PIXEL_INTENSITY)
    /// Normalized by anchor region (center 10x10 mean).
    fn compute_reflectance_map(
        &self,
        baseline: &PalmImage,
        flash: &PalmImage,
        channel: u32,
    ) -> Result<Vec<f64>> {
        let w = baseline.width;
        let h = baseline.height;
        let pixel_count = (w * h) as usize;
        let mut ratios = Vec::with_capacity(pixel_count);

        // Compute raw ratios
        for y in 0..h {
            for x in 0..w {
                let b = baseline.get_pixel(x, y, channel)? as f64;
                let f = flash.get_pixel(x, y, channel)? as f64;
                let ratio = f / b.max(MIN_PIXEL_INTENSITY);
                ratios.push(ratio);
            }
        }

        // Compute anchor (center region mean)
        let cx = w / 2;
        let cy = h / 2;
        let half = ANCHOR_REGION_SIZE / 2;
        let ax_start = cx.saturating_sub(half);
        let ay_start = cy.saturating_sub(half);
        let ax_end = (ax_start + ANCHOR_REGION_SIZE).min(w);
        let ay_end = (ay_start + ANCHOR_REGION_SIZE).min(h);

        let mut anchor_sum = 0.0;
        let mut anchor_count = 0u32;
        for y in ay_start..ay_end {
            for x in ax_start..ax_end {
                let idx = (y * w + x) as usize;
                anchor_sum += ratios[idx];
                anchor_count += 1;
            }
        }

        let anchor_mean = if anchor_count > 0 {
            anchor_sum / anchor_count as f64
        } else {
            1.0
        };

        // Normalize by anchor
        if anchor_mean > 0.0 {
            for ratio in &mut ratios {
                *ratio /= anchor_mean;
            }
        }

        Ok(ratios)
    }

    // ========================================================================
    // Private: Signal 1 — Reflectance Variance
    // ========================================================================

    /// Spatial variance of reflectance map averaged across RGB channels.
    /// High for 3D surfaces (real faces), low for flat surfaces.
    fn compute_reflectance_variance(
        &self,
        baseline: &PalmImage,
        flash: &PalmImage,
    ) -> Result<u16> {
        let mut total_variance = 0.0;

        for ch in 0..3 {
            let map = self.compute_reflectance_map(baseline, flash, ch)?;
            let n = map.len() as f64;
            let mean = map.iter().sum::<f64>() / n;
            let variance = map.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / n;
            total_variance += variance;
        }

        let avg_variance = total_variance / 3.0;

        // Normalize: typical range [0, 0.5] -> [0, 1]
        let normalized = (avg_variance / 0.5).min(1.0);
        Ok((normalized * 65535.0) as u16)
    }

    // ========================================================================
    // Private: Signal 2 — Reflectance Gradient Score
    // ========================================================================

    /// Sobel-like finite differences on reflectance map.
    /// Real faces show smooth nose-to-cheek gradients.
    fn compute_reflectance_gradient_score(
        &self,
        baseline: &PalmImage,
        flash: &PalmImage,
    ) -> Result<u16> {
        let w = baseline.width;
        let h = baseline.height;
        let mut total_gradient = 0.0;

        for ch in 0..3 {
            let map = self.compute_reflectance_map(baseline, flash, ch)?;
            let mut gradient_sum = 0.0;
            let mut count = 0u64;

            // Finite differences (skip borders)
            for y in 1..(h - 1) {
                for x in 1..(w - 1) {
                    let idx = (y * w + x) as usize;
                    let dx = map[idx + 1] - map[idx - 1]; // horizontal gradient
                    let dy = map[((y + 1) * w + x) as usize]
                        - map[((y - 1) * w + x) as usize]; // vertical gradient
                    let magnitude = (dx * dx + dy * dy).sqrt();
                    gradient_sum += magnitude;
                    count += 1;
                }
            }

            if count > 0 {
                total_gradient += gradient_sum / count as f64;
            }
        }

        let avg_gradient = total_gradient / 3.0;

        // Normalize: typical range [0, 0.3] -> [0, 1]
        let normalized = (avg_gradient / 0.3).min(1.0);
        Ok((normalized * 65535.0) as u16)
    }

    // ========================================================================
    // Private: Signal 3 — Highlight Softness
    // ========================================================================

    /// Falloff profile of bright spots (ratio > 1.5).
    /// Real skin has gradual subsurface scattering falloff.
    /// Returns neutral default (32767) when no highlights found.
    fn compute_highlight_softness(
        &self,
        baseline: &PalmImage,
        flash: &PalmImage,
    ) -> Result<u16> {
        let w = baseline.width;
        let h = baseline.height;

        // Use green channel (best skin response)
        let map = self.compute_reflectance_map(baseline, flash, 1)?;

        // Find highlight pixels
        let mut highlight_positions: Vec<(u32, u32)> = Vec::new();
        for y in 0..h {
            for x in 0..w {
                let idx = (y * w + x) as usize;
                if map[idx] > HIGHLIGHT_RATIO_THRESHOLD {
                    highlight_positions.push((x, y));
                }
            }
        }

        // No highlights: return neutral value (passes threshold)
        if highlight_positions.is_empty() {
            return Ok(32767);
        }

        // Measure falloff around each highlight: average ratio drop per pixel distance
        let mut total_softness = 0.0;
        let mut softness_count = 0u64;
        let sample_radius = 5u32;

        for &(hx, hy) in &highlight_positions {
            let center_idx = (hy * w + hx) as usize;
            let center_val = map[center_idx];

            // Sample at increasing distances
            let mut distance_drops: Vec<f64> = Vec::new();
            for r in 1..=sample_radius {
                let mut ring_sum = 0.0;
                let mut ring_count = 0u32;

                // Sample 4 cardinal directions
                for &(dx, dy) in &[(r as i32, 0), (-(r as i32), 0), (0, r as i32), (0, -(r as i32))] {
                    let nx = hx as i32 + dx;
                    let ny = hy as i32 + dy;
                    if nx >= 0 && nx < w as i32 && ny >= 0 && ny < h as i32 {
                        let nidx = (ny as u32 * w + nx as u32) as usize;
                        ring_sum += map[nidx];
                        ring_count += 1;
                    }
                }

                if ring_count > 0 {
                    let ring_mean = ring_sum / ring_count as f64;
                    let drop = center_val - ring_mean;
                    distance_drops.push(drop);
                }
            }

            // Softness = how gradually the drop happens (lower max derivative = softer)
            if distance_drops.len() >= 2 {
                let max_step = distance_drops
                    .windows(2)
                    .map(|w| (w[1] - w[0]).abs())
                    .fold(0.0f64, f64::max);

                // Invert: small max_step = soft falloff = high softness
                let softness = 1.0 / (1.0 + max_step * 10.0);
                total_softness += softness;
                softness_count += 1;
            }
        }

        if softness_count == 0 {
            return Ok(32767); // Neutral default
        }

        let avg_softness = total_softness / softness_count as f64;
        let normalized = avg_softness.min(1.0);
        Ok((normalized * 65535.0) as u16)
    }

    // ========================================================================
    // Private: Signal 4 — Channel Consistency
    // ========================================================================

    /// Pearson correlation between R/G/B reflectance maps.
    /// Screens have ~1.0 (uniform), real skin has ~0.7-0.9
    /// (wavelength-dependent albedo).
    fn compute_channel_consistency(
        &self,
        baseline: &PalmImage,
        flash: &PalmImage,
    ) -> Result<u16> {
        let map_r = self.compute_reflectance_map(baseline, flash, 0)?;
        let map_g = self.compute_reflectance_map(baseline, flash, 1)?;
        let map_b = self.compute_reflectance_map(baseline, flash, 2)?;

        // Compute pairwise Pearson correlations
        let corr_rg = pearson_correlation(&map_r, &map_g);
        let corr_rb = pearson_correlation(&map_r, &map_b);
        let corr_gb = pearson_correlation(&map_g, &map_b);

        // Average of absolute correlations
        let avg_corr = (corr_rg.abs() + corr_rb.abs() + corr_gb.abs()) / 3.0;

        // Convert to fixed-point
        let normalized = avg_corr.min(1.0);
        Ok((normalized * 65535.0) as u16)
    }
}

impl Default for ScreenFlashExtractor {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Private Helpers
// ============================================================================

/// Pearson correlation coefficient between two equal-length vectors.
fn pearson_correlation(x: &[f64], y: &[f64]) -> f64 {
    let n = x.len() as f64;
    if n == 0.0 {
        return 0.0;
    }

    let mean_x = x.iter().sum::<f64>() / n;
    let mean_y = y.iter().sum::<f64>() / n;

    let mut cov = 0.0;
    let mut var_x = 0.0;
    let mut var_y = 0.0;

    for i in 0..x.len() {
        let dx = x[i] - mean_x;
        let dy = y[i] - mean_y;
        cov += dx * dy;
        var_x += dx * dx;
        var_y += dy * dy;
    }

    let denom = (var_x * var_y).sqrt();
    if denom < 1e-12 {
        return 0.0;
    }

    cov / denom
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_image(w: u32, h: u32, channels: u32, fill: u8) -> PalmImage {
        let data = vec![fill; (w * h * channels) as usize];
        PalmImage::new(w, h, channels, data)
    }

    /// Create an image with spatially varied pixel values simulating 3D geometry.
    /// Center is brighter, edges are dimmer (like a face lit by flash).
    /// Uses steep radial falloff and per-channel variation to simulate real skin.
    fn create_varied_image(w: u32, h: u32) -> PalmImage {
        let cx = w as f64 / 2.0;
        let cy = h as f64 / 2.0;
        let max_dist = ((cx * cx) + (cy * cy)).sqrt();
        let mut data = Vec::with_capacity((w * h * 3) as usize);

        for y in 0..h {
            for x in 0..w {
                let dx = x as f64 - cx;
                let dy = y as f64 - cy;
                let dist = (dx * dx + dy * dy).sqrt();
                // Steeper falloff (squared) for more dramatic 3D geometry effect
                let falloff = (1.0 - (dist / max_dist)).powi(2);

                // Large dynamic range with different per-channel response
                // (wavelength-dependent albedo: skin reflects R > G > B)
                let r = (30.0 + 225.0 * falloff) as u8;
                let g = (25.0 + 190.0 * falloff * 0.85) as u8;
                let b = (20.0 + 150.0 * falloff * 0.7) as u8;
                data.push(r);
                data.push(g);
                data.push(b);
            }
        }

        PalmImage::new(w, h, 3, data)
    }

    // ====================================================================
    // Threshold Tests
    // ====================================================================

    #[test]
    fn test_threshold_defaults() {
        let thresholds = ScreenFlashThresholds::default();
        assert!(thresholds.validate().is_ok());
        assert_eq!(thresholds.reflectance_variance_min, REFLECTANCE_VARIANCE_MIN);
        assert_eq!(thresholds.reflectance_gradient_min, REFLECTANCE_GRADIENT_MIN);
        assert_eq!(thresholds.highlight_softness_min, HIGHLIGHT_SOFTNESS_MIN);
        assert_eq!(thresholds.channel_consistency_max, CHANNEL_CONSISTENCY_MAX);
    }

    #[test]
    fn test_threshold_bad_config() {
        let bad = ScreenFlashThresholds {
            reflectance_variance_min: 0,
            ..Default::default()
        };
        assert!(bad.validate().is_err());

        let bad2 = ScreenFlashThresholds {
            channel_consistency_max: 0,
            ..Default::default()
        };
        assert!(bad2.validate().is_err());
    }

    #[test]
    fn test_threshold_high_security() {
        let high = ScreenFlashThresholds::high_security();
        let default = ScreenFlashThresholds::default();

        assert!(high.validate().is_ok());
        // High security has tighter thresholds
        assert!(high.reflectance_variance_min > default.reflectance_variance_min);
        assert!(high.reflectance_gradient_min > default.reflectance_gradient_min);
        assert!(high.highlight_softness_min > default.highlight_softness_min);
        assert!(high.channel_consistency_max < default.channel_consistency_max);
    }

    // ====================================================================
    // Input Validation Tests
    // ====================================================================

    #[test]
    fn test_dimension_mismatch() {
        let extractor = ScreenFlashExtractor::new();
        let baseline = create_test_image(128, 128, 3, 100);
        let flash = create_test_image(64, 64, 3, 200);

        let result = extractor.extract_signals(&baseline, &flash);
        assert!(result.is_err());
    }

    #[test]
    fn test_grayscale_rejected() {
        let extractor = ScreenFlashExtractor::new();
        let baseline = create_test_image(128, 128, 1, 100);
        let flash = create_test_image(128, 128, 1, 200);

        let result = extractor.extract_signals(&baseline, &flash);
        assert!(result.is_err());
    }

    #[test]
    fn test_too_small() {
        let extractor = ScreenFlashExtractor::new();
        let baseline = create_test_image(32, 32, 3, 100);
        let flash = create_test_image(32, 32, 3, 200);

        let result = extractor.extract_signals(&baseline, &flash);
        assert!(result.is_err());
    }

    // ====================================================================
    // Real Skin Simulation Test
    // ====================================================================

    #[test]
    fn test_real_skin_passes_thresholds() {
        let extractor = ScreenFlashExtractor::new();

        // Baseline: uniform ambient lighting
        let baseline = create_test_image(128, 128, 3, 100);

        // Flash: varied response simulating 3D face geometry
        let flash = create_varied_image(128, 128);

        let signals = extractor.extract_signals(&baseline, &flash).unwrap();
        let thresholds = ScreenFlashThresholds::default();

        // Real skin should produce high variance and gradient
        assert!(
            signals.reflectance_variance >= thresholds.reflectance_variance_min,
            "variance {} < min {}",
            signals.reflectance_variance,
            thresholds.reflectance_variance_min
        );
        assert!(
            signals.reflectance_gradient >= thresholds.reflectance_gradient_min,
            "gradient {} < min {}",
            signals.reflectance_gradient,
            thresholds.reflectance_gradient_min
        );
    }

    // ====================================================================
    // Attack Detection Tests
    // ====================================================================

    #[test]
    fn test_screen_attack_fails() {
        let extractor = ScreenFlashExtractor::new();

        // Screen attack: uniform baseline and uniform flash (flat surface)
        // All channels respond identically -> high channel consistency
        let baseline = create_test_image(128, 128, 3, 100);
        let flash = create_test_image(128, 128, 3, 200);

        let signals = extractor.extract_signals(&baseline, &flash).unwrap();
        let thresholds = ScreenFlashThresholds::default();

        // Flat surface: low variance, low gradient
        assert!(
            signals.reflectance_variance < thresholds.reflectance_variance_min,
            "screen variance {} should be < min {}",
            signals.reflectance_variance,
            thresholds.reflectance_variance_min
        );
        assert!(
            signals.reflectance_gradient < thresholds.reflectance_gradient_min,
            "screen gradient {} should be < min {}",
            signals.reflectance_gradient,
            thresholds.reflectance_gradient_min
        );

        // Overall: should fail
        assert!(!signals.passes_thresholds(&thresholds));
    }

    #[test]
    fn test_paper_attack_fails() {
        let extractor = ScreenFlashExtractor::new();

        // Paper attack: nearly uniform response (flat but slight noise)
        let baseline = create_test_image(128, 128, 3, 100);
        let mut flash_data = vec![0u8; (128 * 128 * 3) as usize];
        // Add tiny variation to simulate paper texture (but still very flat)
        for i in 0..flash_data.len() {
            flash_data[i] = 150 + ((i % 3) as u8); // R=150, G=151, B=152
        }
        let flash = PalmImage::new(128, 128, 3, flash_data);

        let signals = extractor.extract_signals(&baseline, &flash).unwrap();
        let thresholds = ScreenFlashThresholds::default();

        // Paper: low variance + low gradient
        assert!(
            signals.reflectance_variance < thresholds.reflectance_variance_min,
            "paper variance {} should be < min {}",
            signals.reflectance_variance,
            thresholds.reflectance_variance_min
        );

        // Overall: should fail
        assert!(!signals.passes_thresholds(&thresholds));
    }

    // ====================================================================
    // Zeroize Test
    // ====================================================================

    #[test]
    fn test_zeroize_clears_signals() {
        let mut signals = ScreenFlashSignals {
            reflectance_variance: 12345,
            reflectance_gradient: 23456,
            highlight_softness: 34567,
            channel_consistency: 45678,
        };

        signals.zeroize();

        assert_eq!(signals.reflectance_variance, 0);
        assert_eq!(signals.reflectance_gradient, 0);
        assert_eq!(signals.highlight_softness, 0);
        assert_eq!(signals.channel_consistency, 0);
    }

    // ====================================================================
    // Witness Conversion Test
    // ====================================================================

    #[test]
    fn test_witness_conversion() {
        let signals = ScreenFlashSignals {
            reflectance_variance: 5000,
            reflectance_gradient: 3000,
            highlight_softness: 15000,
            channel_consistency: 50000,
        };

        let witness = signals.to_circuit_witness();

        assert_eq!(witness.reflectance_variance, 5000u64);
        assert_eq!(witness.reflectance_gradient, 3000u64);
        assert_eq!(witness.highlight_softness, 15000u64);
        assert_eq!(witness.channel_consistency, 50000u64);
    }

    // ====================================================================
    // Boundary Value Tests
    // ====================================================================

    #[test]
    fn test_signals_at_exact_thresholds() {
        let thresholds = ScreenFlashThresholds::default();

        // Exactly at thresholds: should pass
        let signals = ScreenFlashSignals {
            reflectance_variance: thresholds.reflectance_variance_min,
            reflectance_gradient: thresholds.reflectance_gradient_min,
            highlight_softness: thresholds.highlight_softness_min,
            channel_consistency: thresholds.channel_consistency_max,
        };
        assert!(signals.passes_thresholds(&thresholds));

        // One below variance min: should fail
        let fail_variance = ScreenFlashSignals {
            reflectance_variance: thresholds.reflectance_variance_min - 1,
            ..signals.clone()
        };
        assert!(!fail_variance.passes_thresholds(&thresholds));

        // One above consistency max: should fail
        let fail_consistency = ScreenFlashSignals {
            channel_consistency: thresholds.channel_consistency_max + 1,
            ..signals.clone()
        };
        assert!(!fail_consistency.passes_thresholds(&thresholds));
    }

    #[test]
    fn test_extractor_with_custom_thresholds() {
        let thresholds = ScreenFlashThresholds::high_security();
        let extractor = ScreenFlashExtractor::with_thresholds(thresholds).unwrap();

        let baseline = create_test_image(128, 128, 3, 100);
        let flash = create_test_image(128, 128, 3, 200);

        let signals = extractor.extract_signals(&baseline, &flash).unwrap();
        // Flat surface should definitely fail high security
        assert!(!extractor.validate_signals(&signals));
    }

    #[test]
    fn test_pearson_correlation_identical() {
        let x = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let y = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let corr = pearson_correlation(&x, &y);
        assert!((corr - 1.0).abs() < 1e-10);
    }

    #[test]
    fn test_pearson_correlation_uncorrelated() {
        let x = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let y = vec![3.0, 3.0, 3.0, 3.0, 3.0]; // constant = zero variance
        let corr = pearson_correlation(&x, &y);
        assert_eq!(corr, 0.0); // zero variance -> returns 0
    }
}
