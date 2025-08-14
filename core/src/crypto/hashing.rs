//! IETF hash-to-curve implementation for BLS12-381
//! 
//! This module implements the IETF hash-to-curve standard for BLS12-381 G1,
//! as specified in RFC 9380. It's used for deriving the Pedersen commitment
//! generators g and h from domain separation tags.

use crate::crypto::bls381::{G1Affine, G1Projective};
use crate::error::{SableError, Result};
use group::{Curve, Group, prime::PrimeCurveAffine};

/// Domain separation tag for generator g
const DST_G: &[u8] = b"SABLE:BLS12381_XMD:SHA-256_SSWU_RO_:G1:g";

/// Domain separation tag for generator h  
const DST_H: &[u8] = b"SABLE:BLS12381_XMD:SHA-256_SSWU_RO_:G1:h";

/// Library name used in domain separation tags
const LIB_NAME: &str = "SABLE";

/// Hash an arbitrary message to a G1 point using IETF hash-to-curve
/// 
/// This function implements the hash_to_curve operation as specified in
/// RFC 9380 for BLS12-381 G1 with SHA-256 and simplified SWU mapping.
/// 
/// # Arguments
/// * `msg` - The message to hash
/// * `dst` - Domain separation tag
/// 
/// # Returns
/// A point on the BLS12-381 G1 curve
pub fn hash_to_curve_g1(msg: &[u8], dst: &[u8]) -> Result<G1Affine> {
    // Use blstrs built-in hash-to-curve implementation
    // This implements the IETF standard correctly
    Ok(G1Projective::hash_to_curve(msg, dst, &[]).to_affine())
}

/// Generate the standard Pedersen commitment generators
/// 
/// This generates the g and h generators used for Pedersen commitments
/// using deterministic hash-to-curve with domain separation.
/// 
/// # Returns
/// A tuple (g, h) containing the two independent generators
pub fn generate_pedersen_generators() -> Result<(G1Affine, G1Affine)> {
    // Generate g from its domain separation tag
    let g = hash_to_curve_g1(LIB_NAME.as_bytes(), DST_G)?;
    
    // Generate h from its domain separation tag
    let h = hash_to_curve_g1(LIB_NAME.as_bytes(), DST_H)?;
    
    // Verify the generators are different and valid
    if g == h {
        return Err(SableError::Cryptographic("Generators g and h are identical".into()));
    }
    
    if bool::from(g.is_identity()) || bool::from(h.is_identity()) {
        return Err(SableError::Cryptographic("Generated identity element".into()));
    }
    
    Ok((g, h))
}

/// Hash arbitrary data with a domain separation tag
/// 
/// This is a convenience function for domain-separated hashing
pub fn domain_separated_hash(data: &[u8], domain: &str) -> Result<G1Affine> {
    let dst = format!("{}:{}", LIB_NAME, domain);
    hash_to_curve_g1(data, dst.as_bytes())
}

/// Verify that two generators are independent
/// 
/// This function performs basic checks to ensure g and h are suitable
/// for use as Pedersen commitment generators.
pub fn verify_generator_independence(g: &G1Affine, h: &G1Affine) -> Result<()> {
    // Check they're not the same point
    if g == h {
        return Err(SableError::Cryptographic("Generators are identical".into()));
    }
    
    // Check neither is the identity
    if bool::from(g.is_identity()) || bool::from(h.is_identity()) {
        return Err(SableError::Cryptographic("Generator is identity element".into()));
    }
    
    // Additional independence check: verify no small scalar relationship
    // In practice, this is extremely unlikely with hash-to-curve, but we check anyway
    let g_proj = G1Projective::from(*g);
    let h_proj = G1Projective::from(*h);
    
    // Check that 2*g != h and 3*g != h (basic sanity checks)
    if (g_proj.double()) == h_proj {
        return Err(SableError::Cryptographic("Generators have 2:1 relationship".into()));
    }
    
    if (g_proj.double() + g_proj) == h_proj {
        return Err(SableError::Cryptographic("Generators have 3:1 relationship".into()));
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_hash_to_curve_deterministic() {
        let msg = b"test message";
        let dst = b"test domain";
        
        let point1 = hash_to_curve_g1(msg, dst).unwrap();
        let point2 = hash_to_curve_g1(msg, dst).unwrap();
        
        // Should be deterministic
        assert_eq!(point1, point2);
        
        // Should not be identity
        assert!(!bool::from(point1.is_identity()));
    }
    
    #[test]
    fn test_different_messages_different_points() {
        let dst = b"test domain";
        
        let point1 = hash_to_curve_g1(b"message1", dst).unwrap();
        let point2 = hash_to_curve_g1(b"message2", dst).unwrap();
        
        // Different messages should give different points
        assert_ne!(point1, point2);
    }
    
    #[test]
    fn test_different_domains_different_points() {
        let msg = b"test message";
        
        let point1 = hash_to_curve_g1(msg, b"domain1").unwrap();
        let point2 = hash_to_curve_g1(msg, b"domain2").unwrap();
        
        // Different domains should give different points
        assert_ne!(point1, point2);
    }
    
    #[test]
    fn test_generate_pedersen_generators() {
        let (g, h) = generate_pedersen_generators().unwrap();
        
        // Generators should be different
        assert_ne!(g, h);
        
        // Neither should be identity
        assert!(!bool::from(g.is_identity()));
        assert!(!bool::from(h.is_identity()));
        
        // Should pass independence check
        verify_generator_independence(&g, &h).unwrap();
    }
    
    #[test]
    fn test_generators_deterministic() {
        let (g1, h1) = generate_pedersen_generators().unwrap();
        let (g2, h2) = generate_pedersen_generators().unwrap();
        
        // Should be deterministic
        assert_eq!(g1, g2);
        assert_eq!(h1, h2);
    }
    
    #[test]
    fn test_domain_separated_hash() {
        let data = b"test data";
        let point1 = domain_separated_hash(data, "domain1").unwrap();
        let point2 = domain_separated_hash(data, "domain2").unwrap();
        
        // Different domains should give different results
        assert_ne!(point1, point2);
    }
}
