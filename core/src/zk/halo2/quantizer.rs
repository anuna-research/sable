//! # Feature Quantizer (CON-003)
//!
//! Converts f64 face embeddings to u8 bytes for efficient Hamming distance
//! calculation in ZK circuits.
//!
//! ## Overview
//!
//! Neural network face embeddings are typically f64 values in range [-1, 1].
//! For ZK circuit efficiency, we quantize these to u8 bytes (0-255) using
//! linear quantization.
//!
//! ## Quantization Formula
//!
//! ```text
//! u8_value = clamp((f64_value + 1.0) * 127.5, 0, 255)
//! ```
//!
//! This maps:
//! - -1.0 → 0
//! -  0.0 → 127/128
//! -  1.0 → 255
//!
//! ## Why Quantization?
//!
//! 1. **Circuit Efficiency**: XOR operations on bytes are much cheaper than
//!    field arithmetic for floating point comparison
//! 2. **Hamming Distance**: Byte-level XOR enables efficient similarity
//!    measurement in ZK circuits
//! 3. **Storage**: 8x reduction vs f64 (1 byte vs 8 bytes per feature)
//!
//! ## Example
//!
//! ```rust,ignore
//! use sable_core::zk::halo2::quantizer::FeatureQuantizer;
//!
//! let embeddings = vec![0.5, -0.3, 0.8, -1.0, 1.0];
//! let quantized = FeatureQuantizer::quantize(&embeddings);
//! // quantized = [191, 89, 229, 0, 255]
//!
//! let recovered = FeatureQuantizer::dequantize(&quantized);
//! // recovered ≈ [0.5, -0.3, 0.8, -1.0, 1.0] (with quantization error)
//! ```

use crate::error::{Result, SableError};

/// Feature dimension for face embeddings (Human library outputs 1024-dim).
pub const FACE_EMBEDDING_DIM: usize = 1024;

/// Quantization range minimum (maps to 0).
const QUANT_MIN: f64 = -1.0;

/// Quantization range maximum (maps to 255).
const QUANT_MAX: f64 = 1.0;

/// Feature quantizer for converting f64 embeddings to u8 bytes.
///
/// Implements CON-003 from SPEC-001.
pub struct FeatureQuantizer;

impl FeatureQuantizer {
    /// Quantize a single f64 value to u8.
    ///
    /// Maps [-1.0, 1.0] → [0, 255] linearly.
    /// Values outside the range are clamped.
    #[inline]
    pub fn quantize_single(value: f64) -> u8 {
        let normalized = (value - QUANT_MIN) / (QUANT_MAX - QUANT_MIN);
        let scaled = normalized * 255.0;
        scaled.clamp(0.0, 255.0) as u8
    }

    /// Dequantize a single u8 value back to f64.
    ///
    /// Maps [0, 255] → [-1.0, 1.0] linearly.
    #[inline]
    pub fn dequantize_single(value: u8) -> f64 {
        let normalized = value as f64 / 255.0;
        QUANT_MIN + normalized * (QUANT_MAX - QUANT_MIN)
    }

    /// Quantize a vector of f64 embeddings to u8 bytes.
    ///
    /// # Arguments
    /// * `embeddings` - Face embedding vector (typically 1024 dimensions)
    ///
    /// # Returns
    /// Vector of quantized u8 values
    pub fn quantize(embeddings: &[f64]) -> Vec<u8> {
        embeddings.iter().map(|&v| Self::quantize_single(v)).collect()
    }

    /// Quantize embeddings into a fixed-size array.
    ///
    /// # Arguments
    /// * `embeddings` - Face embedding vector (must be exactly N elements)
    ///
    /// # Returns
    /// * `Ok([u8; N])` - Fixed-size quantized array
    /// * `Err` if input length doesn't match N
    pub fn quantize_fixed<const N: usize>(embeddings: &[f64]) -> Result<[u8; N]> {
        if embeddings.len() != N {
            return Err(SableError::InvalidInput(format!(
                "Expected {} embeddings, got {}",
                N,
                embeddings.len()
            )));
        }

        let mut result = [0u8; N];
        for (i, &v) in embeddings.iter().enumerate() {
            result[i] = Self::quantize_single(v);
        }
        Ok(result)
    }

    /// Dequantize a vector of u8 bytes back to f64 embeddings.
    ///
    /// # Arguments
    /// * `quantized` - Quantized byte vector
    ///
    /// # Returns
    /// Vector of f64 embeddings (approximately original values)
    pub fn dequantize(quantized: &[u8]) -> Vec<f64> {
        quantized.iter().map(|&v| Self::dequantize_single(v)).collect()
    }

    /// Calculate the maximum quantization error for a single value.
    ///
    /// The quantization step size is (QUANT_MAX - QUANT_MIN) / 255 ≈ 0.00784.
    /// Maximum error is half the step size ≈ 0.00392.
    pub fn max_quantization_error() -> f64 {
        (QUANT_MAX - QUANT_MIN) / 255.0 / 2.0
    }

    /// Validate that embeddings are within the expected range.
    ///
    /// # Arguments
    /// * `embeddings` - Face embedding vector
    ///
    /// # Returns
    /// * `Ok(())` if all values are in [-1.0, 1.0]
    /// * `Err` if any value is out of range
    pub fn validate_range(embeddings: &[f64]) -> Result<()> {
        for (i, &v) in embeddings.iter().enumerate() {
            if v < QUANT_MIN || v > QUANT_MAX {
                return Err(SableError::InvalidInput(format!(
                    "Embedding[{}] = {} is out of range [{}, {}]",
                    i, v, QUANT_MIN, QUANT_MAX
                )));
            }
        }
        Ok(())
    }

    /// Normalize embeddings to [-1, 1] range using min-max scaling.
    ///
    /// Use this if embeddings are not already normalized.
    pub fn normalize(embeddings: &[f64]) -> Vec<f64> {
        if embeddings.is_empty() {
            return vec![];
        }

        let min = embeddings.iter().cloned().fold(f64::INFINITY, f64::min);
        let max = embeddings.iter().cloned().fold(f64::NEG_INFINITY, f64::max);

        if (max - min).abs() < f64::EPSILON {
            // All values are the same, return zeros
            return vec![0.0; embeddings.len()];
        }

        embeddings
            .iter()
            .map(|&v| 2.0 * (v - min) / (max - min) - 1.0)
            .collect()
    }
}

/// Quantized face embedding (1024 bytes).
#[derive(Clone, Debug)]
pub struct QuantizedEmbedding {
    /// Quantized feature bytes.
    pub bytes: Vec<u8>,
}

impl QuantizedEmbedding {
    /// Create from f64 embeddings.
    pub fn from_f64(embeddings: &[f64]) -> Self {
        Self {
            bytes: FeatureQuantizer::quantize(embeddings),
        }
    }

    /// Convert back to f64 embeddings.
    pub fn to_f64(&self) -> Vec<f64> {
        FeatureQuantizer::dequantize(&self.bytes)
    }

    /// Get the number of features.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Calculate Hamming distance to another embedding.
    ///
    /// Hamming distance counts the number of differing bits.
    pub fn hamming_distance(&self, other: &QuantizedEmbedding) -> Result<u32> {
        if self.bytes.len() != other.bytes.len() {
            return Err(SableError::InvalidInput(
                "Embedding dimensions must match".into(),
            ));
        }

        let distance: u32 = self
            .bytes
            .iter()
            .zip(other.bytes.iter())
            .map(|(&a, &b)| (a ^ b).count_ones())
            .sum();

        Ok(distance)
    }

    /// Calculate normalized Hamming similarity (0.0 to 1.0).
    ///
    /// 1.0 = identical, 0.0 = maximally different
    pub fn hamming_similarity(&self, other: &QuantizedEmbedding) -> Result<f64> {
        let distance = self.hamming_distance(other)?;
        let max_distance = (self.bytes.len() * 8) as f64; // 8 bits per byte
        Ok(1.0 - (distance as f64 / max_distance))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quantize_boundary_values() {
        // Test boundary values
        assert_eq!(FeatureQuantizer::quantize_single(-1.0), 0);
        assert_eq!(FeatureQuantizer::quantize_single(1.0), 255);
        assert_eq!(FeatureQuantizer::quantize_single(0.0), 127); // or 128 depending on rounding
    }

    #[test]
    fn test_quantize_midpoints() {
        // Test midpoint values
        let mid_low = FeatureQuantizer::quantize_single(-0.5);
        let mid_high = FeatureQuantizer::quantize_single(0.5);

        assert!(mid_low > 50 && mid_low < 80); // Around 63-64
        assert!(mid_high > 175 && mid_high < 210); // Around 191-192
    }

    #[test]
    fn test_quantize_clamping() {
        // Values outside range should be clamped
        assert_eq!(FeatureQuantizer::quantize_single(-2.0), 0);
        assert_eq!(FeatureQuantizer::quantize_single(2.0), 255);
        assert_eq!(FeatureQuantizer::quantize_single(-100.0), 0);
        assert_eq!(FeatureQuantizer::quantize_single(100.0), 255);
    }

    #[test]
    fn test_dequantize_boundary_values() {
        // Test boundary dequantization
        assert!((FeatureQuantizer::dequantize_single(0) - (-1.0)).abs() < 0.01);
        assert!((FeatureQuantizer::dequantize_single(255) - 1.0).abs() < 0.01);
    }

    #[test]
    fn test_roundtrip_accuracy() {
        // Test roundtrip accuracy
        let original = vec![-1.0, -0.5, 0.0, 0.5, 1.0];
        let quantized = FeatureQuantizer::quantize(&original);
        let recovered = FeatureQuantizer::dequantize(&quantized);

        for (orig, rec) in original.iter().zip(recovered.iter()) {
            let error = (orig - rec).abs();
            assert!(
                error <= FeatureQuantizer::max_quantization_error() * 2.0,
                "Roundtrip error {} exceeds max {}",
                error,
                FeatureQuantizer::max_quantization_error() * 2.0
            );
        }
    }

    #[test]
    fn test_quantize_fixed() {
        let embeddings = vec![0.1, 0.2, 0.3, 0.4];
        let result: [u8; 4] = FeatureQuantizer::quantize_fixed(&embeddings).unwrap();
        assert_eq!(result.len(), 4);

        // Wrong size should fail
        let err = FeatureQuantizer::quantize_fixed::<5>(&embeddings);
        assert!(err.is_err());
    }

    #[test]
    fn test_validate_range() {
        let valid = vec![-1.0, 0.0, 1.0, 0.5, -0.5];
        assert!(FeatureQuantizer::validate_range(&valid).is_ok());

        let invalid = vec![0.0, 1.5]; // 1.5 is out of range
        assert!(FeatureQuantizer::validate_range(&invalid).is_err());
    }

    #[test]
    fn test_normalize() {
        let unnormalized = vec![0.0, 50.0, 100.0];
        let normalized = FeatureQuantizer::normalize(&unnormalized);

        assert!((normalized[0] - (-1.0)).abs() < 0.001);
        assert!((normalized[1] - 0.0).abs() < 0.001);
        assert!((normalized[2] - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_quantized_embedding_hamming() {
        let emb1 = QuantizedEmbedding::from_f64(&[0.0, 0.0, 0.0, 0.0]);
        let emb2 = QuantizedEmbedding::from_f64(&[0.0, 0.0, 0.0, 0.0]);

        // Identical embeddings should have 0 Hamming distance
        assert_eq!(emb1.hamming_distance(&emb2).unwrap(), 0);
        assert!((emb1.hamming_similarity(&emb2).unwrap() - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_quantized_embedding_different() {
        let emb1 = QuantizedEmbedding::from_f64(&[-1.0, -1.0, -1.0, -1.0]);
        let emb2 = QuantizedEmbedding::from_f64(&[1.0, 1.0, 1.0, 1.0]);

        // Maximally different embeddings
        let distance = emb1.hamming_distance(&emb2).unwrap();
        assert!(distance > 0);

        let similarity = emb1.hamming_similarity(&emb2).unwrap();
        assert!(similarity < 0.5); // Should be quite dissimilar
    }

    #[test]
    fn test_max_quantization_error() {
        let error = FeatureQuantizer::max_quantization_error();
        // Error should be around 0.004 (half of 1/255 * 2)
        assert!(error > 0.003 && error < 0.005);
    }
}
