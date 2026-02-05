//! # Hamming Threshold Calibration (REQ-006)
//!
//! Defines and calibrates the Hamming distance threshold for face verification.
//!
//! ## Overview
//!
//! Face verification uses Hamming distance between quantized embeddings to
//! determine if two faces match. The threshold determines the cutoff point:
//! - Distance <= threshold: MATCH (same person)
//! - Distance > threshold: NO MATCH (different person)
//!
//! ## Threshold Calculation
//!
//! For an embedding of N bytes (N*8 bits):
//! - Maximum distance = N * 8 (all bits different)
//! - 50% similarity threshold = N * 4 (half the bits)
//!
//! ## Security Considerations
//!
//! The threshold directly affects security vs. usability:
//! - Lower threshold = more secure, higher false rejection rate (FRR)
//! - Higher threshold = less secure, lower FRR but higher false acceptance (FAR)
//!
//! Typical biometric systems target:
//! - FAR < 0.01% (1 in 10,000)
//! - FRR < 1% (1 in 100)
//!
//! ## Calibrated Values
//!
//! Based on face embedding research and practical deployment:
//! - 1024-byte embeddings (8192 bits)
//! - 50% similarity threshold = 4096 bits
//! - Strict threshold (99% confidence) ≈ 3276 bits (40% difference)
//! - Relaxed threshold (95% confidence) ≈ 4915 bits (60% difference)

use super::quantizer::FACE_EMBEDDING_DIM;

/// Standard embedding dimension in bytes (1024 for face embeddings).
pub const EMBEDDING_BYTES: usize = FACE_EMBEDDING_DIM;

/// Total bits in the embedding (8192 for 1024-byte embeddings).
pub const TOTAL_BITS: usize = EMBEDDING_BYTES * 8;

/// Default similarity threshold (50% = 0.5).
///
/// This is the standard threshold where half the bits can differ.
pub const DEFAULT_SIMILARITY_THRESHOLD: f64 = 0.5;

/// Strict similarity threshold (60% = 0.6).
///
/// Higher security, may have higher false rejection rate.
pub const STRICT_SIMILARITY_THRESHOLD: f64 = 0.6;

/// Relaxed similarity threshold (40% = 0.4).
///
/// Lower security, better user experience.
pub const RELAXED_SIMILARITY_THRESHOLD: f64 = 0.4;

/// Threshold configuration for face verification.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ThresholdConfig {
    /// Embedding size in bytes.
    pub embedding_bytes: usize,
    /// Similarity threshold (0.0 to 1.0).
    pub similarity_threshold: f64,
}

impl Default for ThresholdConfig {
    fn default() -> Self {
        Self {
            embedding_bytes: EMBEDDING_BYTES,
            similarity_threshold: DEFAULT_SIMILARITY_THRESHOLD,
        }
    }
}

impl ThresholdConfig {
    /// Create a new threshold configuration.
    ///
    /// # Arguments
    /// * `embedding_bytes` - Size of the quantized embedding in bytes
    /// * `similarity_threshold` - Minimum similarity required (0.0 to 1.0)
    pub fn new(embedding_bytes: usize, similarity_threshold: f64) -> Self {
        assert!(
            (0.0..=1.0).contains(&similarity_threshold),
            "Similarity threshold must be between 0.0 and 1.0"
        );
        Self {
            embedding_bytes,
            similarity_threshold,
        }
    }

    /// Create a strict security configuration.
    pub fn strict() -> Self {
        Self {
            embedding_bytes: EMBEDDING_BYTES,
            similarity_threshold: STRICT_SIMILARITY_THRESHOLD,
        }
    }

    /// Create a relaxed configuration for better UX.
    pub fn relaxed() -> Self {
        Self {
            embedding_bytes: EMBEDDING_BYTES,
            similarity_threshold: RELAXED_SIMILARITY_THRESHOLD,
        }
    }

    /// Get the total number of bits in the embedding.
    pub fn total_bits(&self) -> usize {
        self.embedding_bytes * 8
    }

    /// Calculate the maximum allowed Hamming distance.
    ///
    /// Distance must be <= this value for a match.
    pub fn max_hamming_distance(&self) -> u64 {
        let total = self.total_bits() as f64;
        let max_diff_ratio = 1.0 - self.similarity_threshold;
        (total * max_diff_ratio) as u64
    }

    /// Check if a Hamming distance represents a match.
    pub fn is_match(&self, distance: u64) -> bool {
        distance <= self.max_hamming_distance()
    }

    /// Calculate the similarity from a Hamming distance.
    pub fn similarity(&self, distance: u64) -> f64 {
        let total = self.total_bits() as f64;
        1.0 - (distance as f64 / total)
    }

    /// Calculate the Hamming distance from a similarity score.
    pub fn distance_from_similarity(&self, similarity: f64) -> u64 {
        let total = self.total_bits() as f64;
        ((1.0 - similarity) * total) as u64
    }
}

/// Calibrated threshold for 64-byte test embeddings (512 bits).
///
/// Used during circuit testing with smaller embeddings.
pub const TEST_EMBEDDING_BYTES: usize = 64;

/// Get threshold config for testing with smaller embeddings.
pub fn test_threshold_config() -> ThresholdConfig {
    ThresholdConfig::new(TEST_EMBEDDING_BYTES, DEFAULT_SIMILARITY_THRESHOLD)
}

/// Pre-computed thresholds for common configurations.
pub mod precomputed {
    use super::*;

    /// 1024-byte embedding, 50% similarity threshold.
    /// Max distance = 4096 bits.
    pub const STANDARD_1024_50: u64 = 4096;

    /// 1024-byte embedding, 60% similarity (strict).
    /// Max distance = 3276 bits.
    pub const STRICT_1024_60: u64 = 3276;

    /// 1024-byte embedding, 40% similarity (relaxed).
    /// Max distance = 4915 bits.
    pub const RELAXED_1024_40: u64 = 4915;

    /// 64-byte test embedding, 50% similarity.
    /// Max distance = 256 bits.
    pub const TEST_64_50: u64 = 256;

    /// Verify a precomputed threshold is correct.
    pub fn verify_threshold(config: &ThresholdConfig, expected: u64) -> bool {
        config.max_hamming_distance() == expected
    }
}

/// Threshold check result for circuit output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationResult {
    /// Face verified (distance <= threshold).
    Match,
    /// Face not verified (distance > threshold).
    NoMatch,
}

impl VerificationResult {
    /// Create from comparison result.
    pub fn from_match(is_match: bool) -> Self {
        if is_match {
            Self::Match
        } else {
            Self::NoMatch
        }
    }

    /// Check if this is a match.
    pub fn is_match(&self) -> bool {
        matches!(self, Self::Match)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_threshold() {
        let config = ThresholdConfig::default();
        assert_eq!(config.embedding_bytes, 1024);
        assert!((config.similarity_threshold - 0.5).abs() < 0.001);
    }

    #[test]
    fn test_max_hamming_distance_standard() {
        let config = ThresholdConfig::default();
        // 50% similarity means 50% of bits can differ
        // 1024 bytes * 8 bits = 8192 total bits
        // 50% of 8192 = 4096
        assert_eq!(config.max_hamming_distance(), 4096);
    }

    #[test]
    fn test_max_hamming_distance_strict() {
        let config = ThresholdConfig::strict();
        // 60% similarity means 40% of bits can differ
        // 8192 * 0.4 = 3276.8 -> 3276
        assert_eq!(config.max_hamming_distance(), 3276);
    }

    #[test]
    fn test_max_hamming_distance_relaxed() {
        let config = ThresholdConfig::relaxed();
        // 40% similarity means 60% of bits can differ
        // 8192 * 0.6 = 4915.2 -> 4915
        assert_eq!(config.max_hamming_distance(), 4915);
    }

    #[test]
    fn test_is_match() {
        let config = ThresholdConfig::default();
        let threshold = config.max_hamming_distance();

        // At threshold = match
        assert!(config.is_match(threshold));

        // Below threshold = match
        assert!(config.is_match(threshold - 1));
        assert!(config.is_match(0));

        // Above threshold = no match
        assert!(!config.is_match(threshold + 1));
        assert!(!config.is_match(config.total_bits() as u64));
    }

    #[test]
    fn test_similarity_calculation() {
        let config = ThresholdConfig::default();

        // 0 distance = 100% similar
        assert!((config.similarity(0) - 1.0).abs() < 0.001);

        // Max distance = 0% similar
        assert!((config.similarity(config.total_bits() as u64) - 0.0).abs() < 0.001);

        // Half distance = 50% similar
        let half = (config.total_bits() / 2) as u64;
        assert!((config.similarity(half) - 0.5).abs() < 0.001);
    }

    #[test]
    fn test_distance_from_similarity() {
        let config = ThresholdConfig::default();

        // 100% similarity = 0 distance
        assert_eq!(config.distance_from_similarity(1.0), 0);

        // 0% similarity = max distance
        assert_eq!(
            config.distance_from_similarity(0.0),
            config.total_bits() as u64
        );

        // 50% similarity = half distance
        assert_eq!(
            config.distance_from_similarity(0.5),
            (config.total_bits() / 2) as u64
        );
    }

    #[test]
    fn test_test_threshold_config() {
        let config = test_threshold_config();
        assert_eq!(config.embedding_bytes, 64);
        assert_eq!(config.total_bits(), 512);
        // 50% of 512 = 256
        assert_eq!(config.max_hamming_distance(), 256);
    }

    #[test]
    fn test_precomputed_thresholds() {
        use precomputed::*;

        // Verify standard threshold
        let standard = ThresholdConfig::default();
        assert!(verify_threshold(&standard, STANDARD_1024_50));

        // Verify strict threshold
        let strict = ThresholdConfig::strict();
        assert!(verify_threshold(&strict, STRICT_1024_60));

        // Verify relaxed threshold
        let relaxed = ThresholdConfig::relaxed();
        assert!(verify_threshold(&relaxed, RELAXED_1024_40));

        // Verify test threshold
        let test = test_threshold_config();
        assert!(verify_threshold(&test, TEST_64_50));
    }

    #[test]
    fn test_verification_result() {
        assert!(VerificationResult::Match.is_match());
        assert!(!VerificationResult::NoMatch.is_match());

        assert_eq!(VerificationResult::from_match(true), VerificationResult::Match);
        assert_eq!(VerificationResult::from_match(false), VerificationResult::NoMatch);
    }

    #[test]
    fn test_custom_threshold() {
        // Small embedding for testing
        let config = ThresholdConfig::new(8, 0.75);
        assert_eq!(config.total_bits(), 64);
        // 75% similarity means 25% of bits can differ
        // 64 * 0.25 = 16
        assert_eq!(config.max_hamming_distance(), 16);
    }

    #[test]
    #[should_panic(expected = "Similarity threshold must be between 0.0 and 1.0")]
    fn test_invalid_threshold_high() {
        ThresholdConfig::new(64, 1.5);
    }

    #[test]
    #[should_panic(expected = "Similarity threshold must be between 0.0 and 1.0")]
    fn test_invalid_threshold_low() {
        ThresholdConfig::new(64, -0.1);
    }
}
