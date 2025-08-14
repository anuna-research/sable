//! Core cryptographic primitives for SABLE
//! 
//! This module implements the fundamental cryptographic building blocks:
//! - BLS12-381 elliptic curve operations
//! - IETF hash-to-curve for generator derivation
//! - Poseidon hash for biometric feature vectors
//! - Pedersen commitments over G1
//! - Secure random number generation

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
