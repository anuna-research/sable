//! # SABLE Mobile Integration
//!
//! This module provides mobile platform integration for SABLE, including:
//! - C-compatible FFI interfaces for Android (JNI) and iOS (Swift)
//! - Hardware keystore abstractions (Android Keystore, iOS Secure Enclave)
//! - Biometric sensor interfaces
//! - Energy-efficient operation management
//!
//! ## Quick Start (Rust)
//!
//! ```rust,no_run
//! use sable_core::mobile::MobileSable;
//! use sable_core::types::{Distance, Salt, Timestamp};
//! use sable_core::crypto::rng::SecureRng;
//!
//! // Initialize SABLE for mobile use
//! let sable = MobileSable::new().expect("Failed to initialize");
//!
//! // Generate cryptographic salt
//! let mut rng = SecureRng::new().expect("RNG failed");
//! let salt = Salt::random(&mut rng);
//!
//! // Biometric features (from palm scan)
//! let features: Vec<f64> = (0..512).map(|i| (i as f64) / 512.0).collect();
//!
//! // Generate commitment (store publicly, keep salt private)
//! let commitment = sable.generate_commitment(&features, &salt)
//!     .expect("Commitment failed");
//!
//! // Generate ZK proof (during verification)
//! let threshold = Distance::new(0.25);
//! let timestamp = Timestamp::now();
//! let proof = sable.generate_proof(&features, &salt, &commitment, threshold, timestamp)
//!     .expect("Proof generation failed");
//!
//! // Verify proof (can be done on server)
//! let valid = sable.verify_proof(&proof, &commitment, threshold, timestamp)
//!     .expect("Verification failed");
//! ```
//!
//! ## FFI Usage (C/JNI/Swift)
//!
//! See the [`ffi`] module for C-compatible function exports:
//! - `sable_new()` - Create SABLE instance
//! - `sable_free()` - Free SABLE instance
//! - `sable_generate_salt()` - Generate cryptographic salt
//! - `sable_generate_commitment()` - Generate Pedersen commitment
//! - `sable_generate_proof()` - Generate ZK proof
//! - `sable_verify_proof()` - Verify ZK proof
//!
//! ## Modules
//!
//! - [`ffi`] - C-compatible FFI exports for Android JNI and iOS Swift
//! - [`keystore`] - Hardware keystore abstractions (TEE/Secure Enclave)
//! - [`sensors`] - Biometric sensor interfaces
//! - [`energy`] - Energy-efficient operation management
//!
//! ## Platform Support
//!
//! | Platform | Keystore | Biometric Auth |
//! |----------|----------|----------------|
//! | Android  | Android Keystore (TEE) | BiometricPrompt |
//! | iOS      | Secure Enclave | LocalAuthentication |

pub mod energy;
pub mod ffi;
pub mod keystore;
pub mod sensors;

// Re-export core types for mobile use
pub use crate::types::*;
pub use crate::crypto::*;
pub use crate::error::{SableError, Result};

use crate::crypto::groth16::SableGroth16;
use crate::crypto::pedersen::PedersenCommitment;
use crate::types::{BiometricFeature, Distance, Salt, Timestamp};

/// Mobile-optimized SABLE instance with simplified API
pub struct MobileSable {
    prover: SableGroth16,
}

impl MobileSable {
    /// Create new mobile SABLE instance
    pub fn new() -> Result<Self> {
        Ok(Self {
            prover: SableGroth16::new()?,
        })
    }
    
    /// Generate commitment from biometric features
    pub fn generate_commitment(
        &self,
        features: &[f64],
        salt: &Salt,
    ) -> Result<PedersenCommitment> {
        // Convert to BiometricFeature vector
        let biometric_features: Vec<BiometricFeature> = features
            .iter()
            .map(|&f| BiometricFeature::new(f))
            .collect();
            
        self.prover.generate_commitment(&biometric_features, salt)
    }
    
    /// Generate zero-knowledge proof for biometric verification
    pub fn generate_proof(
        &self,
        features: &[f64],
        salt: &Salt,
        commitment: &PedersenCommitment,
        threshold: Distance,
        current_time: Timestamp,
    ) -> Result<Vec<u8>> {
        // Convert to BiometricFeature vector
        let biometric_features: Vec<BiometricFeature> = features
            .iter()
            .map(|&f| BiometricFeature::new(f))
            .collect();
            
        let proof = self.prover.prove(
            &biometric_features,
            salt,
            commitment,
            threshold,
            current_time,
        )?;
        
        // Serialize proof to bytes for mobile transfer
        Ok(bincode::serialize(&proof)?)
    }
    
    /// Verify zero-knowledge proof
    pub fn verify_proof(
        &self,
        proof_bytes: &[u8],
        commitment: &PedersenCommitment,
        threshold: Distance,
        current_time: Timestamp,
    ) -> Result<bool> {
        // Deserialize proof from bytes
        let proof = bincode::deserialize(proof_bytes)?;
        
        self.prover.verify(&proof, commitment, threshold, current_time)
    }
}

impl Default for MobileSable {
    fn default() -> Self {
        Self::new().expect("Failed to create mobile SABLE instance")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::rng::SecureRng;

    #[test]
    fn test_mobile_sable_creation() {
        let mobile = MobileSable::new();
        assert!(mobile.is_ok());
    }
    
    #[test]
    fn test_mobile_commitment_generation() {
        let mobile = MobileSable::new().unwrap();
        let mut rng = SecureRng::new();
        let salt = Salt::random(&mut rng);
        
        let features = vec![0.1, 0.2, 0.3, 0.4, 0.5];
        let commitment = mobile.generate_commitment(&features, &salt);
        assert!(commitment.is_ok());
    }
    
    #[test]
    fn test_mobile_proof_generation() {
        let mobile = MobileSable::new().unwrap();
        let mut rng = SecureRng::new();
        let salt = Salt::random(&mut rng);
        
        let features = vec![0.1, 0.2, 0.3, 0.4, 0.5];
        let commitment = mobile.generate_commitment(&features, &salt).unwrap();
        
        let threshold = Distance::new(0.5);
        let current_time = Timestamp::now();
        
        let proof = mobile.generate_proof(
            &features,
            &salt,
            &commitment,
            threshold,
            current_time,
        );
        assert!(proof.is_ok());
    }
}
