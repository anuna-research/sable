//! # Core Types for SABLE Library
//!
//! This module defines the fundamental data types used throughout SABLE:
//!
//! - [`BiometricFeature`] - Normalized biometric feature value (0-65535)
//! - [`Distance`] - Distance metric between biometric feature vectors
//! - [`Hash`] - Cryptographic hash output (32 bytes)
//! - [`Salt`] - Cryptographic salt for commitment randomness (32 bytes)
//! - [`Timestamp`] - Unix timestamp in seconds
//!
//! ## Example
//!
//! ```rust,no_run
//! use sable_core::types::{BiometricFeature, Distance, Salt, Timestamp};
//! use sable_core::crypto::rng::SecureRng;
//!
//! // Create biometric feature from normalized float (0.0-1.0)
//! let feature = BiometricFeature::new(0.75);
//!
//! // Create distance threshold
//! let threshold = Distance::new(0.25); // 25% similarity threshold
//!
//! // Generate random salt
//! let mut rng = SecureRng::new().expect("RNG failed");
//! let salt = Salt::random(&mut rng);
//!
//! // Get current timestamp
//! let now = Timestamp::now();
//! ```
//!
//! ## Security Notes
//!
//! - [`Salt`] implements [`ZeroizeOnDrop`] to securely clear memory
//! - Feature values are quantized to 16-bit for mobile compatibility

use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(feature = "mobile")]
use serde::{Deserialize, Serialize};

/// Biometric feature value (0-65535 range for mobile compatibility).
///
/// This type represents a single element in a biometric feature vector.
/// Values are quantized to 16-bit unsigned integers for efficient storage
/// and mobile platform compatibility.
///
/// # Example
///
/// ```rust
/// use sable_core::types::BiometricFeature;
///
/// // Create from normalized float (0.0-1.0)
/// let feature = BiometricFeature::new(0.5);
/// assert_eq!(feature.0, 32767); // Approximately 0.5 * 65535
///
/// // Access the raw value
/// let value = feature.value();
/// assert!((value - 0.5).abs() < 0.001);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "mobile", derive(Serialize, Deserialize))]
pub struct BiometricFeature(pub u16);

impl Zeroize for BiometricFeature {
    fn zeroize(&mut self) {
        self.0 = 0;
    }
}

impl BiometricFeature {
    /// Create a biometric feature from a floating point value (0.0-1.0).
    ///
    /// Values outside the range are clamped to [0.0, 1.0].
    ///
    /// # Arguments
    ///
    /// * `value` - Normalized feature value between 0.0 and 1.0
    ///
    /// # Example
    ///
    /// ```rust
    /// use sable_core::types::BiometricFeature;
    /// let feature = BiometricFeature::new(0.75);
    /// ```
    pub fn new(value: f64) -> Self {
        Self((value * 65535.0).clamp(0.0, 65535.0) as u16)
    }

    /// Create a biometric feature from a u32 value (clamped to u16 range).
    pub fn from(value: u32) -> Self {
        Self((value as u16).min(65535))
    }

    /// Get the feature value as a normalized float (0.0-1.0).
    ///
    /// # Returns
    ///
    /// The feature value normalized to the range [0.0, 1.0].
    pub fn value(&self) -> f64 {
        self.0 as f64 / 65535.0
    }
}

/// Distance metric between biometric feature vectors.
///
/// This type represents the similarity distance (typically Euclidean) between
/// two biometric feature vectors. Lower values indicate more similar biometrics.
///
/// The distance is stored as a scaled integer for precision and efficient
/// comparison operations.
///
/// # Example
///
/// ```rust
/// use sable_core::types::Distance;
///
/// // Create distance threshold (0.25 = 25% dissimilarity)
/// let threshold = Distance::new(0.25);
///
/// // Use for verification decisions
/// // if computed_distance <= threshold { /* match */ }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "mobile", derive(Serialize, Deserialize))]
pub struct Distance(pub u32);

impl Distance {
    /// Create a distance from a floating point value.
    ///
    /// # Arguments
    ///
    /// * `value` - Distance value (typically 0.0-1.0 for normalized features)
    ///
    /// The value is scaled internally for precision.
    pub fn new(value: f64) -> Self {
        Self((value * 1000000.0) as u32) // Scale for precision
    }

    /// Create a distance metric from a raw u32 value.
    pub fn from(value: u32) -> Self {
        Self(value)
    }

    /// Get the distance as a floating point value.
    pub fn value(&self) -> f64 {
        self.0 as f64 / 1000000.0
    }
}

/// Cryptographic hash output (32 bytes / 256 bits).
///
/// This type wraps a 256-bit hash value, typically from SHA-256 or
/// Poseidon hash functions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hash(pub [u8; 32]);

/// Cryptographic salt for commitment randomness (32 bytes / 256 bits).
///
/// The salt provides the hiding property for Pedersen commitments. It must
/// be generated using a cryptographically secure random number generator
/// and kept secret.
///
/// # Security
///
/// - Salt is automatically zeroed on drop ([`ZeroizeOnDrop`])
/// - Generate using [`Salt::random()`] with [`SecureRng`](crate::crypto::rng::SecureRng)
/// - Store in hardware keystore when available (TEE/Secure Enclave)
///
/// # Example
///
/// ```rust,no_run
/// use sable_core::types::Salt;
/// use sable_core::crypto::rng::SecureRng;
///
/// let mut rng = SecureRng::new().expect("RNG initialization failed");
/// let salt = Salt::random(&mut rng);
///
/// // Salt is automatically zeroed when dropped
/// ```
#[derive(Debug, Clone, ZeroizeOnDrop)]
#[cfg_attr(feature = "mobile", derive(Serialize, Deserialize))]
pub struct Salt(pub [u8; 32]);

impl Salt {
    /// Generate a random salt
    pub fn random(rng: &mut impl rand_core::RngCore) -> Self {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }
    
    /// Create salt from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::error::SableError> {
        if bytes.len() != 32 {
            return Err(crate::error::SableError::InvalidFeature);
        }
        let mut salt_bytes = [0u8; 32];
        salt_bytes.copy_from_slice(bytes);
        Ok(Self(salt_bytes))
    }
    
    /// Convert salt to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>, crate::error::SableError> {
        Ok(self.0.to_vec())
    }
}

impl Zeroize for Salt {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

/// Unix timestamp in seconds.
///
/// Used for temporal validity checks in ZK proofs to ensure biometric
/// captures are recent (within the allowed time window).
///
/// # Example
///
/// ```rust
/// use sable_core::types::Timestamp;
///
/// // Get current timestamp
/// let now = Timestamp::now();
///
/// // Create from Unix timestamp
/// let specific = Timestamp::from_unix(1704067200); // 2024-01-01 00:00:00 UTC
///
/// // Compare timestamps
/// assert!(now >= specific);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "mobile", derive(Serialize, Deserialize))]
pub struct Timestamp(pub u64);

impl Timestamp {
    /// Create a timestamp from the current system time.
    ///
    /// # Panics
    ///
    /// Returns a default timestamp (0) if system time is before Unix epoch.
    pub fn now() -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        Self(duration.as_secs())
    }

    /// Create a timestamp from a Unix timestamp value (seconds since epoch).
    ///
    /// # Arguments
    ///
    /// * `value` - Unix timestamp in seconds
    pub fn from_unix(value: u64) -> Self {
        Self(value)
    }

    /// Create a timestamp from a u64 Unix timestamp value.
    pub fn from(value: u64) -> Self {
        Self(value)
    }

    /// Get the raw Unix timestamp value in seconds.
    pub fn as_secs(&self) -> u64 {
        self.0
    }

    /// Calculate elapsed time since this timestamp in seconds.
    ///
    /// Returns 0 if the timestamp is in the future.
    pub fn elapsed_seconds(&self) -> f64 {
        let now = Self::now();
        if now.0 >= self.0 {
            (now.0 - self.0) as f64
        } else {
            0.0
        }
    }
}
