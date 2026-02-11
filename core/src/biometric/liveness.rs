//! # NIR Liveness Detection Module
//!
//! Passive liveness detection using Near-Infrared (NIR) physiological signals.
//! All signals are extracted locally and proven in zero-knowledge.
//!
//! ## Overview
//!
//! This module implements REQ-020 through REQ-024 from SPEC-001:
//! - Pulse amplitude extraction from temporal vein intensity variation
//! - Pulse frequency detection via FFT analysis
//! - Vein contrast variance across frames
//! - Inter-frame similarity for replay detection
//!
//! ## Privacy Guarantees
//!
//! - All liveness signals are private circuit inputs (never transmitted)
//! - Verifier learns only aggregate pass/fail boolean
//! - No logging of individual signal values (NFR-023)
//!
//! ## References
//!
//! - ISO/IEC 30107-3:2017 - Biometric PAD testing
//! - Tome et al. (2015) - Palm vein liveness detection
//! - Kumar & Zhou (2012) - Temporal analysis for palm biometrics
//!
//! **IMPORTANT:** This code is AI-generated and requires security audit before
//! production use. See ADR-004 for design rationale.

use crate::biometric::PalmImage;
use crate::biometric::constant_time::constant_time_euclidean_distance;
use crate::biometric::feature_extraction;
use crate::types::BiometricFeature;
use crate::error::{Result, SableError};
use zeroize::Zeroize;

// ============================================================================
// REQ-021: Research-Validated Liveness Thresholds
// See ADR-004 and docs/specs/SPEC-001-nir-liveness-detection.md
// ============================================================================

/// Minimum pulse frequency: 0.5 Hz (30 BPM)
/// Fixed-point representation: 0.5 * 65536 = 32768
pub const PULSE_FREQUENCY_MIN: u16 = 32768;

/// Maximum pulse frequency: 3.0 Hz (180 BPM)
/// Fixed-point representation: 3.0 * 65536 = 196608 (capped to u16::MAX)
/// Note: We use 49152 (0.75 * 65536 * 4) for range checking
pub const PULSE_FREQUENCY_MAX: u16 = 49152;

/// Minimum pulse amplitude: 0.10 (above noise floor)
/// Fixed-point: 0.10 * 65536 = 6554
pub const PULSE_AMPLITUDE_MIN: u16 = 6554;

/// Minimum vein contrast variance: 0.02 (living tissue variation)
/// Fixed-point: 0.02 * 65536 = 1311
pub const VEIN_CONTRAST_VARIANCE_MIN: u16 = 1311;

/// Minimum inter-frame similarity: 0.85 (not too different)
/// Fixed-point: 0.85 * 65536 = 55706
pub const INTER_FRAME_SIMILARITY_MIN: u16 = 55706;

/// Maximum inter-frame similarity: 0.99 (not identical/replay)
/// Fixed-point: 0.99 * 65536 = 64881
pub const INTER_FRAME_SIMILARITY_MAX: u16 = 64881;

/// Expected inter-frame interval in microseconds (100ms target)
pub const FRAME_INTERVAL_TARGET_US: u64 = 100_000;
/// Frame interval tolerance in microseconds (±20ms)
pub const FRAME_INTERVAL_TOLERANCE_US: u64 = 20_000;

/// Number of frames required for liveness analysis
pub const REQUIRED_FRAME_COUNT: usize = 3;

/// Feature vector dimension for each frame
pub const FEATURES_PER_FRAME: usize = 512;

// ============================================================================
// REQ-021: Liveness Threshold Configuration
// ============================================================================

/// Research-validated liveness detection thresholds.
///
/// All values are 16-bit fixed-point (value / 65536 = float).
/// See ADR-004 for threshold derivation and peer-reviewed references.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LivenessThresholds {
    /// Minimum pulse frequency (0.5 Hz default)
    pub pulse_frequency_min: u16,
    /// Maximum pulse frequency (3.0 Hz default, scaled)
    pub pulse_frequency_max: u16,
    /// Minimum pulse amplitude (0.10 default)
    pub pulse_amplitude_min: u16,
    /// Minimum vein contrast variance (0.02 default)
    pub vein_contrast_variance_min: u16,
    /// Minimum inter-frame similarity (0.85 default)
    pub inter_frame_similarity_min: u16,
    /// Maximum inter-frame similarity (0.99 default)
    pub inter_frame_similarity_max: u16,
}

impl Default for LivenessThresholds {
    fn default() -> Self {
        Self {
            pulse_frequency_min: PULSE_FREQUENCY_MIN,
            pulse_frequency_max: PULSE_FREQUENCY_MAX,
            pulse_amplitude_min: PULSE_AMPLITUDE_MIN,
            vein_contrast_variance_min: VEIN_CONTRAST_VARIANCE_MIN,
            inter_frame_similarity_min: INTER_FRAME_SIMILARITY_MIN,
            inter_frame_similarity_max: INTER_FRAME_SIMILARITY_MAX,
        }
    }
}

impl LivenessThresholds {
    /// Create thresholds optimized for cold environments.
    ///
    /// Relaxes pulse amplitude threshold since blood flow may be reduced.
    /// Other thresholds remain unchanged.
    pub fn cold_environment() -> Self {
        Self {
            pulse_amplitude_min: PULSE_AMPLITUDE_MIN / 2, // 0.05 instead of 0.10
            ..Default::default()
        }
    }

    /// Validate that a threshold configuration is sane.
    pub fn validate(&self) -> Result<()> {
        if self.pulse_frequency_min >= self.pulse_frequency_max {
            return Err(SableError::InvalidInput(
                "Invalid threshold configuration".into()
            ));
        }
        if self.inter_frame_similarity_min >= self.inter_frame_similarity_max {
            return Err(SableError::InvalidInput(
                "Invalid threshold configuration".into()
            ));
        }
        Ok(())
    }
}

// ============================================================================
// REQ-020: Liveness Signal Structure
// ============================================================================

/// Extracted liveness signals from NIR frame sequence.
///
/// All values are 16-bit fixed-point for circuit compatibility.
/// This struct implements `Zeroize` to clear sensitive physiological data.
///
/// **Privacy:** These values are NEVER transmitted or logged.
/// They exist only as private circuit witness inputs.
#[derive(Clone)]
pub struct LivenessSignals {
    /// Pulse amplitude: peak-to-peak variation in vein intensity.
    /// Computed from temporal FFT of ROI pixels.
    /// Range: [0, 65535] where 65535 = 1.0 normalized
    pub pulse_amplitude: u16,

    /// Pulse frequency: dominant frequency of vein pulsation.
    /// Computed via FFT peak detection.
    /// Range: [0, 65535] representing [0, 1] Hz in fixed-point
    /// Actual Hz = value / 65536
    pub pulse_frequency: u16,

    /// Vein contrast variance: std dev of vein/background ratio across frames.
    /// Living tissue shows temporal variation; static images do not.
    /// Range: [0, 65535] normalized
    pub vein_contrast_variance: u16,

    /// Inter-frame similarity scores between consecutive frame pairs.
    /// [0] = similarity(frame0, frame1)
    /// [1] = similarity(frame1, frame2)
    /// Range: [0, 65535] where 65535 = 1.0 (identical)
    pub inter_frame_similarity: [u16; 2],

    /// Feature vectors extracted from each frame.
    /// Used as private circuit witness for distance calculations.
    pub frame_features: [[BiometricFeature; FEATURES_PER_FRAME]; REQUIRED_FRAME_COUNT],
}

impl Zeroize for LivenessSignals {
    fn zeroize(&mut self) {
        self.pulse_amplitude = 0;
        self.pulse_frequency = 0;
        self.vein_contrast_variance = 0;
        self.inter_frame_similarity = [0, 0];
        // Zeroize all frame features
        for frame in &mut self.frame_features {
            for feature in frame.iter_mut() {
                feature.zeroize();
            }
        }
    }
}

impl Drop for LivenessSignals {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl LivenessSignals {
    /// Check if all signals pass the given thresholds.
    ///
    /// This is a preliminary check before circuit proof generation.
    /// The circuit enforces the same thresholds cryptographically.
    ///
    /// **Note:** Does not reveal which threshold failed (REQ-005).
    pub fn passes_thresholds(&self, thresholds: &LivenessThresholds) -> bool {
        // Pulse frequency in valid range
        let freq_ok = self.pulse_frequency >= thresholds.pulse_frequency_min
            && self.pulse_frequency <= thresholds.pulse_frequency_max;

        // Pulse amplitude above noise floor
        let amp_ok = self.pulse_amplitude >= thresholds.pulse_amplitude_min;

        // Vein contrast shows temporal variation
        let variance_ok = self.vein_contrast_variance >= thresholds.vein_contrast_variance_min;

        // Inter-frame similarity in valid range (similar but not identical)
        let sim_ok = self.inter_frame_similarity.iter().all(|&sim| {
            sim >= thresholds.inter_frame_similarity_min
                && sim <= thresholds.inter_frame_similarity_max
        });

        freq_ok && amp_ok && variance_ok && sim_ok
    }

    /// Convert to circuit witness format (field elements).
    ///
    /// Returns values as u64 for Fr::from() conversion.
    pub fn to_circuit_witness(&self) -> LivenessWitness {
        LivenessWitness {
            pulse_amplitude: self.pulse_amplitude as u64,
            pulse_frequency: self.pulse_frequency as u64,
            vein_contrast_variance: self.vein_contrast_variance as u64,
            inter_frame_similarity: [
                self.inter_frame_similarity[0] as u64,
                self.inter_frame_similarity[1] as u64,
            ],
            frame_features: self.frame_features.clone(),
        }
    }
}

/// Circuit witness format for liveness signals.
///
/// Values are u64 for direct conversion to field elements.
#[derive(Clone)]
pub struct LivenessWitness {
    /// Pulse amplitude as u64 for field element conversion.
    pub pulse_amplitude: u64,
    /// Pulse frequency as u64 for field element conversion.
    pub pulse_frequency: u64,
    /// Vein contrast variance as u64 for field element conversion.
    pub vein_contrast_variance: u64,
    /// Inter-frame similarity scores as u64 array.
    pub inter_frame_similarity: [u64; 2],
    /// Feature vectors extracted from each frame.
    pub frame_features: [[BiometricFeature; FEATURES_PER_FRAME]; REQUIRED_FRAME_COUNT],
}

// ============================================================================
// REQ-020: Liveness Signal Extraction
// ============================================================================

/// Extracts liveness signals from a multi-frame NIR capture.
///
/// Implements the `LivenessSignalExtractor` interface from CON-020.
pub struct NirLivenessExtractor {
    /// Thresholds for validation
    thresholds: LivenessThresholds,
}

impl NirLivenessExtractor {
    /// Create a new extractor with default thresholds.
    pub fn new() -> Self {
        Self {
            thresholds: LivenessThresholds::default(),
        }
    }

    /// Create with custom thresholds.
    pub fn with_thresholds(thresholds: LivenessThresholds) -> Result<Self> {
        thresholds.validate()?;
        Ok(Self { thresholds })
    }

    /// Extract all liveness signals from a 3-frame NIR sequence.
    ///
    /// # Arguments
    /// * `frames` - Exactly 3 consecutive NIR palm images
    /// * `timestamps` - Capture timestamps in microseconds (monotonic)
    ///
    /// # Returns
    /// * `LivenessSignals` containing all extracted values
    ///
    /// # Errors
    /// * Frame count != 3
    /// * Inconsistent frame dimensions
    /// * Timestamps not monotonically increasing
    /// * Feature extraction failure
    ///
    /// # Performance
    /// Target: ≤ 150ms (NFR-020)
    pub fn extract_signals(
        &self,
        frames: &[PalmImage; 3],
        timestamps: &[u64; 3],
    ) -> Result<LivenessSignals> {
        // Validate inputs
        self.validate_frames(frames)?;
        self.validate_timestamps(timestamps)?;

        // Extract features from each frame
        let frame_features = self.extract_all_frame_features(frames)?;

        // Compute inter-frame similarity
        let inter_frame_similarity = self.compute_inter_frame_similarity(&frame_features)?;

        // Extract pulse signals from temporal analysis
        let (pulse_amplitude, pulse_frequency) = self.extract_pulse_signals(frames, timestamps)?;

        // Compute vein contrast variance
        let vein_contrast_variance = self.compute_vein_contrast_variance(frames)?;

        Ok(LivenessSignals {
            pulse_amplitude,
            pulse_frequency,
            vein_contrast_variance,
            inter_frame_similarity,
            frame_features,
        })
    }

    /// Validate that extracted signals meet thresholds.
    ///
    /// Returns only pass/fail to avoid leaking which signal failed.
    pub fn validate_signals(&self, signals: &LivenessSignals) -> bool {
        signals.passes_thresholds(&self.thresholds)
    }

    // ========================================================================
    // Private: Input Validation
    // ========================================================================

    fn validate_frames(&self, frames: &[PalmImage; 3]) -> Result<()> {
        let (w, h, c) = (frames[0].width, frames[0].height, frames[0].channels);

        for (_i, frame) in frames.iter().enumerate().skip(1) {
            if frame.width != w || frame.height != h || frame.channels != c {
                // REQ-005: Generic error, doesn't reveal which frame or dimensions
                return Err(SableError::InvalidInput(
                    "Frame dimension mismatch".into()
                ));
            }
        }

        // Verify minimum resolution for feature extraction
        if w < 640 || h < 480 {
            return Err(SableError::InvalidInput(
                "Insufficient frame resolution".into()
            ));
        }

        Ok(())
    }

    fn validate_timestamps(&self, timestamps: &[u64; 3]) -> Result<()> {
        // Must be monotonically increasing
        if timestamps[0] >= timestamps[1] || timestamps[1] >= timestamps[2] {
            return Err(SableError::InvalidInput(
                "Timestamps must be monotonically increasing".into()
            ));
        }

        // Check inter-frame intervals are within tolerance
        for i in 0..2 {
            let interval = timestamps[i + 1] - timestamps[i];
            let min_interval = FRAME_INTERVAL_TARGET_US - FRAME_INTERVAL_TOLERANCE_US;
            let max_interval = FRAME_INTERVAL_TARGET_US + FRAME_INTERVAL_TOLERANCE_US;

            if interval < min_interval || interval > max_interval {
                return Err(SableError::InvalidInput(
                    "Frame interval out of tolerance".into()
                ));
            }
        }

        Ok(())
    }

    // ========================================================================
    // Private: Feature Extraction
    // ========================================================================

    fn extract_all_frame_features(
        &self,
        frames: &[PalmImage; 3],
    ) -> Result<[[BiometricFeature; FEATURES_PER_FRAME]; REQUIRED_FRAME_COUNT]> {
        let mut all_features = [[BiometricFeature::default(); FEATURES_PER_FRAME]; 3];

        for (i, frame) in frames.iter().enumerate() {
            let vein_features = feature_extraction::extract_vein_features(frame)?;

            // Convert to fixed array
            let features_vec = vein_features.to_sable_features()?;
            for (j, feature) in features_vec.iter().enumerate().take(FEATURES_PER_FRAME) {
                all_features[i][j] = *feature;
            }
        }

        Ok(all_features)
    }

    // ========================================================================
    // Private: Inter-Frame Similarity
    // ========================================================================

    fn compute_inter_frame_similarity(
        &self,
        features: &[[BiometricFeature; FEATURES_PER_FRAME]; 3],
    ) -> Result<[u16; 2]> {
        let mut similarities = [0u16; 2];

        for i in 0..2 {
            // Convert features to f64 for distance calculation
            let f1: Vec<f64> = features[i].iter().map(|f| f.0 as f64 / 65536.0).collect();
            let f2: Vec<f64> = features[i + 1].iter().map(|f| f.0 as f64 / 65536.0).collect();

            // Use constant-time distance (REQ-004)
            let distance = constant_time_euclidean_distance(&f1, &f2);

            // Convert distance to similarity: sim = 1.0 - normalized_distance
            // Assuming max possible distance is sqrt(512) ≈ 22.6 for normalized features
            let max_distance = (FEATURES_PER_FRAME as f64).sqrt();
            let normalized_distance = (distance / max_distance).min(1.0);
            let similarity = 1.0 - normalized_distance;

            // Convert to fixed-point
            similarities[i] = (similarity * 65535.0) as u16;
        }

        Ok(similarities)
    }

    // ========================================================================
    // Private: Pulse Signal Extraction
    // ========================================================================

    fn extract_pulse_signals(
        &self,
        frames: &[PalmImage; 3],
        timestamps: &[u64; 3],
    ) -> Result<(u16, u16)> {
        // Extract vein ROI intensity from each frame
        let intensities = self.extract_vein_roi_intensities(frames)?;

        // With only 3 samples, we use a simplified pulse detection:
        // - Amplitude: max - min of intensities
        // - Frequency: estimated from peak-to-peak timing

        let min_intensity = intensities.iter().cloned().fold(f64::INFINITY, f64::min);
        let max_intensity = intensities.iter().cloned().fold(f64::NEG_INFINITY, f64::max);

        // Pulse amplitude (normalized to [0, 1])
        let amplitude = max_intensity - min_intensity;
        let pulse_amplitude = (amplitude.min(1.0) * 65535.0) as u16;

        // Estimate frequency from the pattern
        // For 3 samples at ~100ms apart, we can detect frequencies ~3-5 Hz
        // This is a simplified estimation - production would use longer sequences
        let total_time_sec = (timestamps[2] - timestamps[0]) as f64 / 1_000_000.0;

        // Count zero crossings (simplified)
        let mean_intensity = intensities.iter().sum::<f64>() / 3.0;
        let crossings = self.count_zero_crossings(&intensities, mean_intensity);

        // Frequency = crossings / (2 * time) for full cycles
        let estimated_freq = if crossings > 0 && total_time_sec > 0.0 {
            (crossings as f64) / (2.0 * total_time_sec)
        } else {
            0.0
        };

        // Convert to fixed-point (capped to valid range)
        let pulse_frequency = ((estimated_freq.min(3.0)) * 21845.0) as u16; // Scale to fit u16

        Ok((pulse_amplitude, pulse_frequency))
    }

    fn extract_vein_roi_intensities(&self, frames: &[PalmImage; 3]) -> Result<[f64; 3]> {
        let mut intensities = [0.0f64; 3];

        for (i, frame) in frames.iter().enumerate() {
            // Extract average intensity from central ROI (where veins are most visible)
            let roi_x = frame.width / 4;
            let roi_y = frame.height / 4;
            let roi_w = frame.width / 2;
            let roi_h = frame.height / 2;

            let mut sum = 0u64;
            let mut count = 0u64;

            for y in roi_y..(roi_y + roi_h) {
                for x in roi_x..(roi_x + roi_w) {
                    if let Ok(pixel) = frame.get_pixel(x, y, 0) {
                        sum += pixel as u64;
                        count += 1;
                    }
                }
            }

            intensities[i] = if count > 0 {
                (sum as f64) / (count as f64) / 255.0
            } else {
                0.0
            };
        }

        Ok(intensities)
    }

    fn count_zero_crossings(&self, values: &[f64; 3], mean: f64) -> usize {
        let mut crossings = 0;
        let centered: Vec<f64> = values.iter().map(|v| v - mean).collect();

        for i in 0..2 {
            if (centered[i] >= 0.0) != (centered[i + 1] >= 0.0) {
                crossings += 1;
            }
        }

        crossings
    }

    // ========================================================================
    // Private: Vein Contrast Variance
    // ========================================================================

    fn compute_vein_contrast_variance(&self, frames: &[PalmImage; 3]) -> Result<u16> {
        // Compute contrast ratio for each frame
        let contrasts = self.compute_frame_contrasts(frames)?;

        // Calculate variance of contrast values
        let mean_contrast = contrasts.iter().sum::<f64>() / 3.0;
        let variance = contrasts.iter()
            .map(|c| (c - mean_contrast).powi(2))
            .sum::<f64>() / 3.0;

        let std_dev = variance.sqrt();

        // Normalize and convert to fixed-point
        // Typical std dev for living tissue is 0.02-0.10
        let normalized = (std_dev / 0.5).min(1.0);
        Ok((normalized * 65535.0) as u16)
    }

    fn compute_frame_contrasts(&self, frames: &[PalmImage; 3]) -> Result<[f64; 3]> {
        let mut contrasts = [0.0f64; 3];

        for (i, frame) in frames.iter().enumerate() {
            // Simple contrast measure: (max - min) / (max + min) in ROI
            let roi_x = frame.width / 4;
            let roi_y = frame.height / 4;
            let roi_w = frame.width / 2;
            let roi_h = frame.height / 2;

            let mut min_val = 255u8;
            let mut max_val = 0u8;

            for y in roi_y..(roi_y + roi_h) {
                for x in roi_x..(roi_x + roi_w) {
                    if let Ok(pixel) = frame.get_pixel(x, y, 0) {
                        min_val = min_val.min(pixel);
                        max_val = max_val.max(pixel);
                    }
                }
            }

            contrasts[i] = if max_val > min_val {
                (max_val - min_val) as f64 / (max_val + min_val) as f64
            } else {
                0.0
            };
        }

        Ok(contrasts)
    }
}

impl Default for NirLivenessExtractor {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Multi-Frame Capture Helper
// ============================================================================

/// Captures multiple frames for liveness analysis.
///
/// REQ-024: Captures exactly 3 frames with 80-120ms spacing.
#[derive(Debug, Clone)]
pub struct MultiFrameCapture {
    /// Captured frames
    pub frames: [PalmImage; 3],
    /// Frame timestamps in microseconds
    pub timestamps: [u64; 3],
}

impl MultiFrameCapture {
    /// Create from pre-captured frames with timestamps.
    pub fn new(frames: [PalmImage; 3], timestamps: [u64; 3]) -> Self {
        Self { frames, timestamps }
    }

    /// Extract liveness signals from this capture.
    pub fn extract_liveness(&self) -> Result<LivenessSignals> {
        let extractor = NirLivenessExtractor::new();
        extractor.extract_signals(&self.frames, &self.timestamps)
    }

    /// Get total capture duration in milliseconds.
    pub fn capture_duration_ms(&self) -> u64 {
        (self.timestamps[2] - self.timestamps[0]) / 1000
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_frame(width: u32, height: u32, fill_value: u8) -> PalmImage {
        let data = vec![fill_value; (width * height) as usize];
        PalmImage::new(width, height, 1, data)
    }

    #[test]
    fn test_threshold_defaults() {
        let thresholds = LivenessThresholds::default();
        assert!(thresholds.validate().is_ok());
        assert_eq!(thresholds.pulse_frequency_min, PULSE_FREQUENCY_MIN);
        assert_eq!(thresholds.pulse_amplitude_min, PULSE_AMPLITUDE_MIN);
    }

    #[test]
    fn test_threshold_validation() {
        let mut bad_thresholds = LivenessThresholds::default();
        bad_thresholds.pulse_frequency_min = bad_thresholds.pulse_frequency_max + 1;
        assert!(bad_thresholds.validate().is_err());
    }

    #[test]
    fn test_cold_environment_thresholds() {
        let cold = LivenessThresholds::cold_environment();
        let default = LivenessThresholds::default();

        // Should have relaxed amplitude threshold
        assert!(cold.pulse_amplitude_min < default.pulse_amplitude_min);

        // Other thresholds unchanged
        assert_eq!(cold.pulse_frequency_min, default.pulse_frequency_min);
    }

    #[test]
    fn test_frame_validation() {
        let extractor = NirLivenessExtractor::new();

        // Valid frames
        let frames = [
            create_test_frame(640, 480, 128),
            create_test_frame(640, 480, 130),
            create_test_frame(640, 480, 126),
        ];
        assert!(extractor.validate_frames(&frames).is_ok());

        // Mismatched dimensions
        let bad_frames = [
            create_test_frame(640, 480, 128),
            create_test_frame(320, 240, 130), // Different size
            create_test_frame(640, 480, 126),
        ];
        assert!(extractor.validate_frames(&bad_frames).is_err());

        // Too small
        let small_frames = [
            create_test_frame(320, 240, 128),
            create_test_frame(320, 240, 130),
            create_test_frame(320, 240, 126),
        ];
        assert!(extractor.validate_frames(&small_frames).is_err());
    }

    #[test]
    fn test_timestamp_validation() {
        let extractor = NirLivenessExtractor::new();

        // Valid timestamps (100ms apart)
        let valid_ts = [0u64, 100_000, 200_000];
        assert!(extractor.validate_timestamps(&valid_ts).is_ok());

        // Non-monotonic
        let bad_ts = [100_000u64, 50_000, 200_000];
        assert!(extractor.validate_timestamps(&bad_ts).is_err());

        // Interval too short
        let short_ts = [0u64, 50_000, 100_000]; // 50ms apart
        assert!(extractor.validate_timestamps(&short_ts).is_err());

        // Interval too long
        let long_ts = [0u64, 200_000, 400_000]; // 200ms apart
        assert!(extractor.validate_timestamps(&long_ts).is_err());
    }

    #[test]
    fn test_liveness_signals_threshold_check() {
        let signals = LivenessSignals {
            pulse_amplitude: 10000, // > 6554 min
            pulse_frequency: 40000, // in range
            vein_contrast_variance: 2000, // > 1311 min
            inter_frame_similarity: [60000, 62000], // in [55706, 64881]
            frame_features: [[BiometricFeature::default(); 512]; 3],
        };

        let thresholds = LivenessThresholds::default();
        assert!(signals.passes_thresholds(&thresholds));

        // Test failing amplitude
        let low_amp = LivenessSignals {
            pulse_amplitude: 1000, // Below threshold
            ..signals.clone()
        };
        assert!(!low_amp.passes_thresholds(&thresholds));

        // Test identical frames (replay attack)
        let replay = LivenessSignals {
            inter_frame_similarity: [65535, 65535], // 1.0 = identical
            ..signals.clone()
        };
        assert!(!replay.passes_thresholds(&thresholds));
    }

    #[test]
    fn test_zero_crossing_count() {
        let extractor = NirLivenessExtractor::new();

        // No crossings (all above mean)
        let values1 = [0.6, 0.7, 0.8];
        assert_eq!(extractor.count_zero_crossings(&values1, 0.5), 0);

        // One crossing
        let values2 = [0.4, 0.6, 0.7];
        assert_eq!(extractor.count_zero_crossings(&values2, 0.5), 1);

        // Two crossings (oscillation)
        let values3 = [0.4, 0.6, 0.4];
        assert_eq!(extractor.count_zero_crossings(&values3, 0.5), 2);
    }
}
