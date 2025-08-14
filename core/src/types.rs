//! Core types for SABLE library

use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(feature = "mobile")]
use serde::{Deserialize, Serialize};

/// Biometric feature value (0-65535 range for mobile compatibility)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "mobile", derive(Serialize, Deserialize))]
pub struct BiometricFeature(pub u16);

impl BiometricFeature {
    /// Create a biometric feature from a floating point value (0.0-1.0)
    pub fn new(value: f64) -> Self {
        Self((value * 65535.0).clamp(0.0, 65535.0) as u16)
    }
    
    /// Create a biometric feature from a u32 value (clamped to u16 range)
    pub fn from(value: u32) -> Self {
        Self((value as u16).min(65535))
    }
}

/// Distance metric between biometric features
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "mobile", derive(Serialize, Deserialize))]
pub struct Distance(pub u32);

impl Distance {
    /// Create a distance from a floating point value
    pub fn new(value: f64) -> Self {
        Self((value * 1000000.0) as u32) // Scale to microseconds for precision
    }
    
    /// Create a distance metric from a u32 value
    pub fn from(value: u32) -> Self {
        Self(value)
    }
}

/// Cryptographic hash output
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hash(pub [u8; 32]);

/// Cryptographic salt for commitment randomness
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

/// Unix timestamp in seconds
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "mobile", derive(Serialize, Deserialize))]
pub struct Timestamp(pub u64);

impl Timestamp {
    /// Create a timestamp from the current time
    pub fn now() -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        Self(duration.as_secs())
    }
    
    /// Create a timestamp from a Unix timestamp value
    pub fn from_unix(value: u64) -> Self {
        Self(value)
    }
    
    /// Create a timestamp from a u64 Unix timestamp value
    pub fn from(value: u64) -> Self {
        Self(value)
    }
}
