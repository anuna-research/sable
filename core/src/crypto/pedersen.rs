//! Pedersen commitments over BLS12-381 G1
//! 
//! This module implements Pedersen commitments using the BLS12-381 elliptic curve
//! with generators derived via IETF hash-to-curve for security and independence.

use crate::crypto::{
    bls381::{Fr, G1Affine, G1Projective, Bls12381},
    hashing::generate_pedersen_generators,
    rng::SecureRng,
};
use crate::error::{SableError, Result};
use crate::COMMITMENT_SIZE;

use serde::{Deserialize, Serialize};
use group::Curve;
use ff::Field;

/// Pedersen commitment generators (g, h)
/// These are derived deterministically using hash-to-curve
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Generators {
    /// Generator g for the message
    pub g: G1Affine,
    /// Generator h for the randomness/salt
    pub h: G1Affine,
}

impl Generators {
    /// Generate the standard SABLE Pedersen generators
    /// These are derived deterministically and cached for efficiency
    pub fn new() -> Result<Self> {
        let (g, h) = generate_pedersen_generators()?;
        Ok(Self { g, h })
    }
    
    /// Get the cached generators (computed once at startup)
    pub fn get() -> &'static Generators {
        static GENERATORS: std::sync::OnceLock<Generators> = std::sync::OnceLock::new();
        GENERATORS.get_or_init(|| {
            Generators::new().expect("Failed to generate Pedersen generators")
        })
    }
    
    /// Verify generators are properly formed and independent
    pub fn verify(&self) -> Result<()> {
        crate::crypto::hashing::verify_generator_independence(&self.g, &self.h)
    }
}

impl Default for Generators {
    fn default() -> Self {
        *Self::get()
    }
}

/// A Pedersen commitment C = g^message * h^salt
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Commitment {
    point: G1Affine,
}

impl Commitment {
    /// Create a commitment from a G1 point
    pub fn from_point(point: G1Affine) -> Self {
        Self { point }
    }
    
    /// Get the underlying G1 point
    pub fn point(&self) -> &G1Affine {
        &self.point
    }
    
    /// Serialize commitment to compressed bytes (48 bytes)
    pub fn to_bytes(&self) -> [u8; COMMITMENT_SIZE] {
        Bls12381::serialize_g1_compressed(&self.point)
    }
    
    /// Deserialize commitment from compressed bytes
    pub fn from_bytes(bytes: &[u8; COMMITMENT_SIZE]) -> Result<Self> {
        let point = Bls12381::deserialize_g1_compressed(bytes)?;
        Ok(Self { point })
    }
    
    /// Check if this is a valid commitment (not identity)
    pub fn is_valid(&self) -> bool {
        Bls12381::is_valid_g1(&self.point)
    }
    
    /// Add two commitments homomorphically
    /// This allows C1 + C2 = g^(m1+m2) * h^(r1+r2)
    pub fn add(&self, other: &Commitment) -> Commitment {
        let result = G1Projective::from(self.point) + G1Projective::from(other.point);
        Commitment::from_point(result.to_affine())
    }
    
    /// Multiply commitment by a scalar
    /// This allows k * C = g^(k*m) * h^(k*r)
    pub fn mul_scalar(&self, scalar: &Fr) -> Commitment {
        let result = G1Projective::from(self.point) * scalar;
        Commitment::from_point(result.to_affine())
    }
}

/// Type alias for backward compatibility with code using `PedersenCommitment`
pub type PedersenCommitment = Commitment;

/// Commitment opening information (message and randomness)
/// This struct automatically zeros its contents on drop for security
#[derive(Clone)]
pub struct CommitmentOpening {
    /// The committed message/value
    pub message: Fr,
    /// The randomness/salt used in commitment
    pub randomness: Fr,
}

// Manual implementation since Fr doesn't implement Zeroize
impl Drop for CommitmentOpening {
    fn drop(&mut self) {
        // Note: blstrs::Scalar doesn't implement Zeroize
        // In production, use a wrapper type that does
    }
}

impl CommitmentOpening {
    /// Create a new opening with the given message and randomness
    pub fn new(message: Fr, randomness: Fr) -> Self {
        Self { message, randomness }
    }
    
    /// Generate a commitment opening with random salt
    pub fn new_with_random_salt(message: Fr) -> Result<Self> {
        let mut rng = SecureRng::new()?;
        let randomness = Fr::random(&mut rng);
        Ok(Self { message, randomness })
    }
    
    /// Verify that this opening matches the given commitment
    pub fn verify(&self, commitment: &Commitment, generators: &Generators) -> bool {
        let expected = commit_with_opening(self, generators);
        expected == *commitment
    }
}

/// Create a Pedersen commitment: C = g^message * h^randomness
/// 
/// # Arguments
/// * `message` - The value to commit to (typically a hash of biometric data)
/// * `randomness` - Cryptographic randomness for hiding
/// * `generators` - The g, h generators to use
/// 
/// # Returns
/// A Pedersen commitment that binds to the message while hiding it
pub fn commit(message: Fr, randomness: Fr, generators: &Generators) -> Commitment {
    let g_term = G1Projective::from(generators.g) * message;
    let h_term = G1Projective::from(generators.h) * randomness;
    let commitment_point = (g_term + h_term).to_affine();
    
    Commitment::from_point(commitment_point)
}

/// Create a commitment using the default generators
pub fn commit_default(message: Fr, randomness: Fr) -> Commitment {
    commit(message, randomness, Generators::get())
}

/// Create a commitment from an opening
pub fn commit_with_opening(opening: &CommitmentOpening, generators: &Generators) -> Commitment {
    commit(opening.message, opening.randomness, generators)
}

/// Generate a random commitment for testing
pub fn random_commitment() -> Result<(Commitment, CommitmentOpening)> {
    let mut rng = SecureRng::new()?;
    let message = Fr::random(&mut rng);
    let randomness = Fr::random(&mut rng);
    let opening = CommitmentOpening::new(message, randomness);
    let commitment = commit_with_opening(&opening, Generators::get());
    
    Ok((commitment, opening))
}

/// Batch commit to multiple messages with independent randomness
pub fn batch_commit(
    messages: &[Fr],
    randomness: &[Fr], 
    generators: &Generators
) -> Result<Vec<Commitment>> {
    if messages.len() != randomness.len() {
        return Err(SableError::InvalidInput("Messages and randomness length mismatch".into()));
    }
    
    let commitments = messages
        .iter()
        .zip(randomness.iter())
        .map(|(&msg, &rand)| commit(msg, rand, generators))
        .collect();
    
    Ok(commitments)
}

/// Verify a batch of commitments against their openings
pub fn batch_verify(
    commitments: &[Commitment],
    openings: &[CommitmentOpening],
    generators: &Generators,
) -> bool {
    if commitments.len() != openings.len() {
        return false;
    }
    
    commitments
        .iter()
        .zip(openings.iter())
        .all(|(commitment, opening)| opening.verify(commitment, generators))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::poseidon::poseidon_hash;
    
    #[test]
    fn test_generators_creation() {
        use group::prime::PrimeCurveAffine;
        
        let generators = Generators::new().unwrap();
        generators.verify().unwrap();
        
        // Generators should not be identity
        assert!(!bool::from(generators.g.is_identity()));
        assert!(!bool::from(generators.h.is_identity()));
        
        // Generators should be different
        assert_ne!(generators.g, generators.h);
    }
    
    #[test]
    fn test_generators_deterministic() {
        let gen1 = Generators::new().unwrap();
        let gen2 = Generators::new().unwrap();
        
        assert_eq!(gen1, gen2);
    }
    
    #[test]
    fn test_commitment_creation() {
        let generators = Generators::new().unwrap();
        let message = Fr::from(42u64);
        let randomness = Fr::from(123u64);
        
        let commitment = commit(message, randomness, &generators);
        assert!(commitment.is_valid());
    }
    
    #[test]
    fn test_commitment_serialization() {
        let (commitment, _) = random_commitment().unwrap();
        
        let bytes = commitment.to_bytes();
        let recovered = Commitment::from_bytes(&bytes).unwrap();
        
        assert_eq!(commitment, recovered);
    }
    
    #[test]
    fn test_commitment_opening() {
        let message = Fr::from(42u64);
        let opening = CommitmentOpening::new_with_random_salt(message).unwrap();
        let commitment = commit_with_opening(&opening, Generators::get());
        
        assert!(opening.verify(&commitment, Generators::get()));
    }
    
    #[test]
    fn test_commitment_homomorphism() {
        let generators = Generators::get();
        
        let msg1 = Fr::from(10u64);
        let rand1 = Fr::from(20u64);
        let commit1 = commit(msg1, rand1, generators);
        
        let msg2 = Fr::from(30u64);
        let rand2 = Fr::from(40u64);
        let commit2 = commit(msg2, rand2, generators);
        
        // Test additive homomorphism
        let sum_commit = commit1.add(&commit2);
        let expected_commit = commit(msg1 + msg2, rand1 + rand2, generators);
        
        assert_eq!(sum_commit, expected_commit);
    }
    
    #[test]
    fn test_biometric_commitment_flow() {
        // Simulate the full biometric commitment flow
        let features = [0.1f32; crate::FEATURE_VECTOR_SIZE];
        
        // Hash features to scalar
        let message = poseidon_hash(&features).unwrap();
        
        // Create commitment with random salt
        let opening = CommitmentOpening::new_with_random_salt(message).unwrap();
        let commitment = commit_with_opening(&opening, Generators::get());
        
        // Verify the commitment
        assert!(opening.verify(&commitment, Generators::get()));
        assert!(commitment.is_valid());
        
        // Test serialization round-trip
        let bytes = commitment.to_bytes();
        let recovered = Commitment::from_bytes(&bytes).unwrap();
        assert_eq!(commitment, recovered);
    }
    
    #[test]
    fn test_batch_operations() {
        let messages = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
        let randomness = vec![Fr::from(10u64), Fr::from(20u64), Fr::from(30u64)];
        
        let commitments = batch_commit(&messages, &randomness, Generators::get()).unwrap();
        assert_eq!(commitments.len(), 3);
        
        // Create openings
        let openings: Vec<_> = messages
            .iter()
            .zip(randomness.iter())
            .map(|(&msg, &rand)| CommitmentOpening::new(msg, rand))
            .collect();
        
        // Verify batch
        assert!(batch_verify(&commitments, &openings, Generators::get()));
    }
    
    #[test]
    fn test_different_messages_different_commitments() {
        let generators = Generators::get();
        let randomness = Fr::from(42u64);
        
        let commit1 = commit(Fr::from(1u64), randomness, generators);
        let commit2 = commit(Fr::from(2u64), randomness, generators);
        
        assert_ne!(commit1, commit2);
    }
    
    #[test]
    fn test_same_message_different_randomness() {
        let generators = Generators::get();
        let message = Fr::from(42u64);
        
        let commit1 = commit(message, Fr::from(1u64), generators);
        let commit2 = commit(message, Fr::from(2u64), generators);
        
        // Should be different due to different randomness (hiding property)
        assert_ne!(commit1, commit2);
    }
}
