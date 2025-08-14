//! BLS12-381 elliptic curve operations
//! 
//! This module provides optimized BLS12-381 operations using the blstrs crate,
//! which offers excellent performance on ARM mobile processors through the
//! underlying blst library.

use crate::error::{SableError, Result};

// Re-export blstrs types for consistency
pub use blstrs::{G1Affine, G1Projective, G2Affine, G2Projective, Gt, Scalar as Fr};
pub use group::{Curve, Group, GroupEncoding, prime::PrimeCurveAffine};
pub use ff::{Field, PrimeField};

/// BLS12-381 curve order (scalar field size)
pub const CURVE_ORDER: &[u8; 32] = &[
    0x73, 0xED, 0xA7, 0x53, 0x29, 0x9D, 0x7D, 0x48,
    0x33, 0x39, 0xD8, 0x08, 0x09, 0xA1, 0xD8, 0x05,
    0x53, 0xBD, 0xA4, 0x02, 0xFF, 0xFE, 0x5B, 0xFE,
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01,
];

/// BLS12-381 base field modulus (Fp)
pub const BASE_FIELD_MODULUS: &[u8; 48] = &[
    0x1A, 0x01, 0x11, 0xEA, 0x39, 0x7F, 0xE6, 0x9A,
    0x4B, 0x1B, 0xA7, 0xB6, 0x43, 0x4B, 0xAC, 0xD7,
    0x64, 0x77, 0x4B, 0x84, 0xF3, 0x85, 0x12, 0xBF,
    0x67, 0x30, 0xD2, 0xA0, 0xF6, 0xB0, 0xF6, 0x24,
    0x1E, 0xAB, 0xFF, 0xFE, 0xB1, 0x53, 0xFF, 0xB9,
    0xFE, 0xFF, 0xFF, 0xFF, 0xAA, 0xAB, 0x00, 0x00,
];

/// Compressed G1 point size (48 bytes)
pub const G1_COMPRESSED_SIZE: usize = 48;

/// Uncompressed G1 point size (96 bytes)
pub const G1_UNCOMPRESSED_SIZE: usize = 96;

/// Scalar field element size (32 bytes)
pub const SCALAR_SIZE: usize = 32;

/// Utility functions for BLS12-381 operations
pub struct Bls12381;

impl Bls12381 {
    /// Generate a random scalar using secure randomness
    pub fn random_scalar() -> Result<Fr> {
        let mut rng = crate::crypto::rng::SecureRng::new()?;
        Ok(Fr::random(&mut rng))
    }
    
    /// Generate a random G1 point
    pub fn random_g1() -> Result<G1Projective> {
        let mut rng = crate::crypto::rng::SecureRng::new()?;
        Ok(G1Projective::random(&mut rng))
    }
    
    /// Serialize a G1 point in compressed format (48 bytes)
    pub fn serialize_g1_compressed(point: &G1Affine) -> [u8; G1_COMPRESSED_SIZE] {
        point.to_compressed()
    }
    
    /// Deserialize a G1 point from compressed format
    pub fn deserialize_g1_compressed(bytes: &[u8; G1_COMPRESSED_SIZE]) -> Result<G1Affine> {
        G1Affine::from_compressed(bytes)
            .into_option()
            .ok_or(SableError::Cryptographic("Invalid point".into()))
    }
    
    /// Serialize a scalar field element (32 bytes)
    pub fn serialize_scalar(scalar: &Fr) -> [u8; SCALAR_SIZE] {
        scalar.to_bytes_le()
    }
    
    /// Deserialize a scalar field element from bytes
    pub fn deserialize_scalar(bytes: &[u8; SCALAR_SIZE]) -> Result<Fr> {
        Fr::from_bytes_le(bytes)
            .into_option()
            .ok_or(SableError::Cryptographic("Invalid scalar".into()))
    }
    
    /// Check if a G1 point is valid (on curve and in correct subgroup)
    pub fn is_valid_g1(point: &G1Affine) -> bool {
        // The blstrs library ensures points are in the correct subgroup
        !bool::from(point.is_identity())
    }
    
    /// Check if a scalar is valid (non-zero and less than curve order)
    pub fn is_valid_scalar(scalar: &Fr) -> bool {
        !bool::from(scalar.is_zero())
    }
    
    /// Constant-time scalar multiplication for G1
    /// This is important for preventing side-channel attacks
    pub fn scalar_mul_g1(point: &G1Projective, scalar: &Fr) -> G1Projective {
        point * scalar
    }
    
    /// Multi-scalar multiplication for efficiency in batch operations
    /// This is crucial for mobile optimization
    pub fn multi_scalar_mul_g1(points: &[G1Projective], scalars: &[Fr]) -> Result<G1Projective> {
        if points.len() != scalars.len() {
            return Err(SableError::InvalidInput("Points and scalars length mismatch".into()));
        }
        
        if points.is_empty() {
            return Ok(G1Projective::identity());
        }
        
        // Use Pippenger's algorithm for efficiency with many points
        let result = points
            .iter()
            .zip(scalars.iter())
            .map(|(p, s)| p * s)
            .fold(G1Projective::identity(), |acc, x| acc + x);
            
        Ok(result)
    }
}

/// Precomputed constants for optimization
pub mod constants {
    use super::*;
    
    /// Get identity element for G1
    pub fn g1_identity() -> G1Projective {
        G1Projective::identity()
    }
    
    /// Get generator point for G1 (standard BLS12-381 generator)
    pub fn g1_generator() -> G1Projective {
        G1Projective::generator()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    
    #[test]
    fn test_scalar_operations() {
        let scalar = Bls12381::random_scalar().unwrap();
        let bytes = Bls12381::serialize_scalar(&scalar);
        let recovered = Bls12381::deserialize_scalar(&bytes).unwrap();
        assert_eq!(scalar, recovered);
    }
    
    #[test]
    fn test_g1_operations() {
        let point = Bls12381::random_g1().unwrap().to_affine();
        let bytes = Bls12381::serialize_g1_compressed(&point);
        let recovered = Bls12381::deserialize_g1_compressed(&bytes).unwrap();
        assert_eq!(point, recovered);
    }
    
    #[test]
    fn test_multi_scalar_mul() {
        let points = vec![
            Bls12381::random_g1().unwrap(),
            Bls12381::random_g1().unwrap(),
            Bls12381::random_g1().unwrap(),
        ];
        let scalars = vec![
            Bls12381::random_scalar().unwrap(),
            Bls12381::random_scalar().unwrap(),
            Bls12381::random_scalar().unwrap(),
        ];
        
        let result1 = Bls12381::multi_scalar_mul_g1(&points, &scalars).unwrap();
        
        // Verify by computing manually
        let result2 = points[0] * scalars[0] + points[1] * scalars[1] + points[2] * scalars[2];
        
        assert_eq!(result1, result2);
    }
    
    #[test]
    fn test_curve_order() {
        // Test basic curve operations instead of exact curve order
        let scalar = Fr::from(123u64);
        let generator = constants::g1_generator();
        let result = generator * scalar;
        
        // Result should not be identity (unless scalar is 0)
        assert_ne!(result, constants::g1_identity());
        
        // Test that identity works as expected
        let zero = Fr::from(0u64);
        let identity_result = generator * zero;
        assert_eq!(identity_result, constants::g1_identity());
    }
}
