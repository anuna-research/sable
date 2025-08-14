// SABLE Mobile Integration
// 
// This module provides C-compatible FFI interfaces for mobile platforms,
// enabling integration with Android (via JNI) and iOS (via Swift).

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
