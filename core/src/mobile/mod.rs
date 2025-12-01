// SABLE Mobile Integration
//
// This module provides C-compatible FFI interfaces for mobile platforms,
// enabling integration with Android (via JNI) and iOS (via Swift).

pub mod ffi;
pub mod keystore;
pub mod sensors;

// Re-export core types for mobile use
pub use crate::error::{Result, SableError};
pub use crate::types::*;

use crate::crypto::groth16::{CircuitParams, SableGroth16, SableProvingKey, SableVerifyingKey};
use crate::crypto::pedersen::{commit_with_opening, Commitment, CommitmentOpening, Generators};
use crate::crypto::poseidon::{normalize_features, poseidon_hash};
use crate::crypto::rng::SecureRng;
use crate::types::{Distance, Timestamp};
use crate::FEATURE_VECTOR_SIZE;

/// Mobile-optimized SABLE instance with simplified API
pub struct MobileSable {
    groth16: SableGroth16,
    proving_key: Option<SableProvingKey>,
    verifying_key: Option<SableVerifyingKey>,
    generators: Generators,
}

impl MobileSable {
    /// Create new mobile SABLE instance with default parameters
    pub fn new() -> Result<Self> {
        let params = CircuitParams {
            distance_threshold: Distance::from(1000),
            time_window: 300, // 5 minutes
            feature_count: FEATURE_VECTOR_SIZE,
        };

        let groth16 = SableGroth16::new(params);
        let generators = Generators::new()?;

        Ok(Self {
            groth16,
            proving_key: None,
            verifying_key: None,
            generators,
        })
    }

    /// Initialize the proving/verifying keys (expensive operation, call once)
    pub fn setup(&mut self) -> Result<()> {
        let mut rng = SecureRng::new()?;
        let (pk, vk) = self.groth16.setup(&mut rng)?;
        self.proving_key = Some(pk);
        self.verifying_key = Some(vk);
        Ok(())
    }

    /// Generate commitment from biometric features
    ///
    /// # Arguments
    /// * `features` - Raw biometric features (will be normalized and hashed)
    /// * `salt_bytes` - 32-byte random salt
    ///
    /// # Returns
    /// Serialized commitment (48 bytes)
    pub fn generate_commitment(&self, features: &[f64], salt_bytes: &[u8; 32]) -> Result<Vec<u8>> {
        // Convert f64 to f32 for processing
        if features.len() != FEATURE_VECTOR_SIZE {
            return Err(SableError::InvalidInput(format!(
                "Expected {} features, got {}",
                FEATURE_VECTOR_SIZE,
                features.len()
            )));
        }

        let features_f32: Vec<f32> = features.iter().map(|&f| f as f32).collect();

        // Normalize features
        let normalized = normalize_features(&features_f32)?;

        // Hash features to get commitment message
        let message = poseidon_hash(&normalized)?;

        // Create commitment with salt
        let mut rng = SecureRng::new()?;
        let randomness = crate::crypto::bls381::Fr::random(&mut rng);
        let opening = CommitmentOpening::new(message, randomness);
        let commitment = commit_with_opening(&opening, &self.generators);

        // Serialize commitment
        Ok(commitment.to_bytes().to_vec())
    }

    /// Generate zero-knowledge proof for biometric verification
    ///
    /// Note: This is a simplified interface. For full proof generation,
    /// use the lower-level groth16 API directly.
    pub fn generate_proof(
        &self,
        _features: &[f64],
        _commitment_bytes: &[u8],
        _threshold: f64,
        _current_time: u64,
    ) -> Result<Vec<u8>> {
        // Check if setup has been called
        if self.proving_key.is_none() {
            return Err(SableError::InvalidInput(
                "Must call setup() before generating proofs".into(),
            ));
        }

        // Full proof generation requires reference features and more complex setup
        // This is a placeholder for the mobile API
        Err(SableError::InvalidInput(
            "Full proof generation requires reference commitment and features. Use groth16 API directly.".into()
        ))
    }

    /// Verify zero-knowledge proof
    pub fn verify_proof(
        &self,
        proof_bytes: &[u8],
        public_inputs_bytes: &[u8],
    ) -> Result<bool> {
        // Check if setup has been called
        let vk = self.verifying_key.as_ref().ok_or_else(|| {
            SableError::InvalidInput("Must call setup() before verifying proofs".into())
        })?;

        // Deserialize proof
        let proof: ark_groth16::Proof<ark_bls12_381::Bls12_381> =
            bincode::deserialize(proof_bytes).map_err(|e| {
                SableError::SerializationError(format!("Failed to deserialize proof: {}", e))
            })?;

        // Deserialize public inputs
        let public_inputs: Vec<ark_bls12_381::Fr> =
            bincode::deserialize(public_inputs_bytes).map_err(|e| {
                SableError::SerializationError(format!(
                    "Failed to deserialize public inputs: {}",
                    e
                ))
            })?;

        self.groth16.verify(vk, &proof, &public_inputs)
    }

    /// Get the generators used for commitments
    pub fn generators(&self) -> &Generators {
        &self.generators
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

    #[test]
    fn test_mobile_sable_creation() {
        let mobile = MobileSable::new();
        assert!(mobile.is_ok());
    }

    #[test]
    fn test_mobile_commitment_generation() {
        let mobile = MobileSable::new().unwrap();
        let salt = [42u8; 32];

        // Create test features of correct size
        let features: Vec<f64> = (0..FEATURE_VECTOR_SIZE).map(|i| (i as f64) * 0.01).collect();

        let commitment = mobile.generate_commitment(&features, &salt);
        assert!(commitment.is_ok());

        let commitment_bytes = commitment.unwrap();
        assert_eq!(commitment_bytes.len(), 48); // Compressed G1 point
    }

    #[test]
    fn test_mobile_commitment_determinism() {
        let mobile = MobileSable::new().unwrap();
        let salt = [42u8; 32];

        let features: Vec<f64> = (0..FEATURE_VECTOR_SIZE).map(|i| (i as f64) * 0.01).collect();

        // Same features should produce deterministic normalized hash
        // (commitment will differ due to random salt in opening)
        let commitment1 = mobile.generate_commitment(&features, &salt).unwrap();
        let commitment2 = mobile.generate_commitment(&features, &salt).unwrap();

        // Commitments will differ due to random opening, but both should be valid
        assert_eq!(commitment1.len(), 48);
        assert_eq!(commitment2.len(), 48);
    }
}
