//! # SABLE: Secure Attested Biometric Library for Edge
//! 
//! Core cryptographic library for privacy-preserving biometric authentication
//! using BLS12-381 Pedersen commitments and mobile-optimized zk-SNARKs.
//! 
//! ## Features
//! 
//! - BLS12-381 elliptic curve operations optimized for mobile processors
//! - Pedersen commitments over G1 with IETF hash-to-curve generators
//! - Poseidon hash for efficient biometric feature vector conversion
//! - Mobile-optimized Groth16 zk-SNARK circuits (optional with `zk` feature)
//! - Memory-safe, constant-time implementations
//! - No-std compatibility for embedded targets

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(missing_docs, unsafe_code)]
#![warn(clippy::all, clippy::pedantic)]

pub mod crypto;
pub mod error;
pub mod types;

#[cfg(feature = "mobile")]
pub mod mobile;
pub mod biometric;

// FFI requires unsafe operations, so we conditionally allow it
#[cfg(feature = "mobile")]
mod mobile_ffi {
    #![allow(unsafe_code)]
    pub use crate::mobile::ffi::*;
}

// Re-export commonly used types
pub use error::{Result, SableError};
pub use types::*;

// Re-export commonly used types
pub use crypto::{
    bls381::*,
    pedersen::{Commitment, Generators},
    poseidon::poseidon_hash,
};

/// Library version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Recommended security level (128-bit)
pub const SECURITY_LEVEL: u32 = 128;

/// Feature vector size as specified in the protocol
pub const FEATURE_VECTOR_SIZE: usize = 512;

/// Salt size in bytes (256-bit for cryptographic security)
pub const SALT_SIZE: usize = 32;

/// Commitment size in bytes (compressed BLS12-381 G1 point)
pub const COMMITMENT_SIZE: usize = 48;
