//! Core types for SABLE library

use zeroize::{Zeroize, ZeroizeOnDrop};

/// Biometric feature value (0-65535 range for mobile compatibility)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BiometricFeature(pub u16);

impl BiometricFeature {
    /// Create a biometric feature from a u32 value (clamped to u16 range)
    pub fn from(value: u32) -> Self {
        Self((value as u16).min(65535))
    }
}

/// Distance metric between biometric features
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Distance(pub u32);

impl Distance {
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
pub struct Salt(pub [u8; 32]);

impl Zeroize for Salt {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

/// Unix timestamp in seconds
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Timestamp(pub u64);

impl Timestamp {
    /// Create a timestamp from a u64 Unix timestamp value
    pub fn from(value: u64) -> Self {
        Self(value)
    }
}
