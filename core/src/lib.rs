//! # SABLE - Secure Attested Biometric Library for Edge
//!
//! SABLE provides privacy-preserving biometric verification using zero-knowledge proofs.
//! It enables authentication where biometric data never leaves the user's device while
//! still providing cryptographic proof of identity.
//!
//! ## Quick Start
//!
//! ```rust
//! use sable_core::crypto::{bls381::Fr, pedersen, rng::SecureRng};
//! use sable_core::types::Salt;
//!
//! // Generate a random salt for the commitment
//! let mut rng = SecureRng::new().expect("Failed to create RNG");
//! let salt = Salt::random(&mut rng);
//!
//! // Create a Pedersen commitment (stored publicly, biometrics stay private)
//! let generators = pedersen::Generators::default();
//! let message = Fr::from(42u64);
//! let randomness = Fr::from(123u64);
//! let commitment = pedersen::commit(message, randomness, &generators);
//! ```
//!
//! ## Architecture Overview
//!
//! SABLE is designed as a layered architecture:
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    Mobile Applications                       │
//! │                 (Android JNI / iOS Swift)                   │
//! ├─────────────────────────────────────────────────────────────┤
//! │                      FFI Layer                               │
//! │            (C-compatible function exports)                  │
//! ├─────────────────────────────────────────────────────────────┤
//! │                    Mobile Module                             │
//! │     (MobileSable, Keystore, Sensors, Energy Management)     │
//! ├───────────────┬───────────────┬───────────────┬─────────────┤
//! │   Biometric   │    Crypto     │      P2P      │ Attestation │
//! │   Processing  │  Primitives   │  Communication│  (X.509)    │
//! └───────────────┴───────────────┴───────────────┴─────────────┘
//! ```
//!
//! ## Modules
//!
//! - [`crypto`] - Cryptographic primitives (BLS12-381, Poseidon hash, Pedersen commitments, Groth16 proofs)
//! - [`biometric`] - Palm biometric processing (vein/print extraction, multi-modal fusion)
//! - [`mobile`] - Mobile platform integration (Android/iOS FFI, keystore, sensors)
//! - [`p2p`] - Peer-to-peer communication (BLE, NFC, secure sessions)
//! - [`attestation`] - X.509 certificate handling and trust management
//!
//! ## Feature Flags
//!
//! - `std` (default) - Standard library support
//! - `mobile` - Mobile platform FFI and keystore integration
//! - `zk` - Zero-knowledge proof generation (Groth16 circuits)
//!
//! ## Platform Support
//!
//! | Platform | Architecture | Status |
//! |----------|-------------|--------|
//! | Android  | aarch64     | Supported via JNI |
//! | Android  | armv7       | Supported via JNI |
//! | iOS      | aarch64     | Supported via Swift FFI |
//! | Linux    | x86_64      | Full support |
//! | macOS    | aarch64     | Full support |
//!
//! ## Security Considerations
//!
//! - **Constant-time operations**: All cryptographic operations are implemented in
//!   constant time to prevent timing side-channel attacks (REQ-004)
//! - **Memory safety**: Sensitive data is zeroized on drop using the `zeroize` crate
//! - **Error sanitization**: External error messages do not leak implementation details (REQ-005)
//! - **Hardware backing**: Supports TEE/Secure Enclave storage on mobile platforms
//!
//! ## Core Features
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

pub mod attestation;
pub mod crypto;
pub mod error;
pub mod p2p;
pub mod types;
pub mod zk;

#[cfg(feature = "mobile")]
pub mod mobile;
/// Biometric processing module for palm vein and print feature extraction.
///
/// This module provides:
/// - Palm biometric image preprocessing and feature extraction
/// - Multi-modal fusion (vein + print)
/// - Constant-time distance calculations for secure biometric matching (REQ-004)
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
