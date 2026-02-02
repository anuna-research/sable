//! Core cryptographic primitives for SABLE
//!
//! This module implements the fundamental cryptographic building blocks for
//! privacy-preserving biometric verification:
//!
//! ## Modules
//!
//! - [`bls381`] - BLS12-381 elliptic curve operations
//! - [`hashing`] - IETF hash-to-curve for generator derivation
//! - [`poseidon`] - Poseidon hash for biometric feature vectors (SNARK-friendly)
//! - [`pedersen`] - Pedersen commitments over G1
//! - [`rng`] - Secure random number generation
//! - [`groth16`] - Zero-knowledge proof generation (requires `zk` feature)
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use sable_core::crypto::{pedersen, poseidon, rng::SecureRng};
//! use sable_core::types::Salt;
//!
//! // Generate random salt
//! let mut rng = SecureRng::new().expect("RNG initialization failed");
//! let salt = Salt::random(&mut rng);
//!
//! // Hash biometric features to a field element
//! let features = [0.5f32; 512]; // 512-dimensional feature vector
//! let hash = poseidon::poseidon_hash(&features).expect("Hash failed");
//!
//! // Create Pedersen commitment: C = g^hash * h^salt
//! let generators = pedersen::Generators::get();
//! // ... use hash and salt to create commitment
//! ```
//!
//! ## Security Properties
//!
//! - **Constant-time**: All operations are implemented in constant time (REQ-004)
//! - **Memory-safe**: Sensitive data is zeroized on drop
//! - **Side-channel resistant**: No secret-dependent branching or memory access

pub mod bls381;
pub mod hashing;
pub mod pedersen;
pub mod poseidon;
pub mod rng;

#[cfg(feature = "zk")]
pub mod groth16;

// Re-export commonly used items
pub use bls381::{Fr, G1Affine, G1Projective};
pub use hashing::hash_to_curve_g1;
pub use pedersen::{commit, Commitment, Generators};
pub use poseidon::poseidon_hash;
pub use rng::SecureRng;
