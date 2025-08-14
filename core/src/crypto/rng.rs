//! Secure random number generation
//! 
//! This module provides secure random number generation using platform
//! entropy sources. It prioritizes security over performance and uses
//! getrandom for cryptographic randomness.

use crate::error::{SableError, Result};
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;

/// Secure random number generator wrapper
/// 
/// This struct wraps getrandom to provide a consistent interface
/// for cryptographic random number generation across platforms.
pub struct SecureRng {
    // We don't store state - getrandom provides entropy directly
    _private: (),
}

impl SecureRng {
    /// Create a new secure RNG instance
    pub fn new() -> Result<Self> {
        // Test that we can generate random bytes
        let mut test_bytes = [0u8; 1];
        getrandom::getrandom(&mut test_bytes).map_err(|_| SableError::RandomGeneration)?;
        
        Ok(Self { _private: () })
    }
    
    /// Generate random bytes into the provided buffer
    pub fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<()> {
        getrandom::getrandom(dest).map_err(|_| SableError::RandomGeneration)?;
        Ok(())
    }
    
    /// Generate a random array of the specified size
    pub fn random_bytes<const N: usize>(&mut self) -> Result<[u8; N]> {
        let mut bytes = [0u8; N];
        self.fill_bytes(&mut bytes)?;
        Ok(bytes)
    }
    
    /// Generate a cryptographically secure 256-bit salt
    pub fn generate_salt(&mut self) -> Result<[u8; 32]> {
        self.random_bytes::<32>()
    }
    
    /// Generate a cryptographically secure nonce
    pub fn generate_nonce(&mut self) -> Result<[u8; 32]> {
        self.random_bytes::<32>()
    }
}

impl RngCore for SecureRng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        self.fill_bytes(&mut bytes).expect("RNG failure");
        u32::from_le_bytes(bytes)
    }
    
    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        self.fill_bytes(&mut bytes).expect("RNG failure");
        u64::from_le_bytes(bytes)
    }
    
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.fill_bytes(dest).expect("RNG failure");
    }
    
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> core::result::Result<(), rand_core::Error> {
        match self.fill_bytes(dest) {
            Ok(()) => Ok(()),
            Err(_) => Err(rand_core::Error::from(core::num::NonZeroU32::new(1).unwrap())),
        }
    }
}

impl CryptoRng for SecureRng {}

impl Default for SecureRng {
    fn default() -> Self {
        Self::new().expect("Failed to create secure RNG")
    }
}

/// Secure memory for storing sensitive cryptographic material
/// 
/// This structure automatically zeros its contents when dropped
/// to prevent sensitive data from remaining in memory.
#[derive(Clone, Debug)]
pub struct SecureBytes<const N: usize> {
    bytes: [u8; N],
}

impl<const N: usize> SecureBytes<N> {
    /// Create a new SecureBytes with random content
    pub fn random() -> Result<Self> {
        let mut rng = SecureRng::new()?;
        let bytes = rng.random_bytes::<N>()?;
        Ok(Self { bytes })
    }
    
    /// Create from existing bytes
    pub fn from_bytes(bytes: [u8; N]) -> Self {
        Self { bytes }
    }
    
    /// Get a reference to the inner bytes
    /// 
    /// # Security Note
    /// Be careful not to copy these bytes to insecure memory
    pub fn as_bytes(&self) -> &[u8; N] {
        &self.bytes
    }
    
    /// Convert to array, consuming self
    pub fn into_bytes(self) -> [u8; N] {
        self.bytes
    }
}

impl<const N: usize> AsRef<[u8]> for SecureBytes<N> {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl<const N: usize> Drop for SecureBytes<N> {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl<const N: usize> Zeroize for SecureBytes<N> {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}

// Constant-time comparison to prevent timing attacks
impl<const N: usize> PartialEq for SecureBytes<N> {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        self.bytes.ct_eq(&other.bytes).into()
    }
}

impl<const N: usize> Eq for SecureBytes<N> {}

/// Type aliases for common sizes
/// 32-byte cryptographic salt
pub type Salt = SecureBytes<32>;
/// 32-byte cryptographic nonce
pub type Nonce = SecureBytes<32>;

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_secure_rng() {
        let mut rng = SecureRng::new().unwrap();
        
        // Test that we get different random values
        let bytes1 = rng.random_bytes::<32>().unwrap();
        let bytes2 = rng.random_bytes::<32>().unwrap();
        assert_ne!(bytes1, bytes2);
        
        // Test salt generation
        let salt1 = rng.generate_salt().unwrap();
        let salt2 = rng.generate_salt().unwrap();
        assert_ne!(salt1, salt2);
    }
    
    #[test]
    fn test_secure_bytes() {
        let secure1 = SecureBytes::<32>::random().unwrap();
        let secure2 = SecureBytes::<32>::random().unwrap();
        
        // Should be different
        assert_ne!(secure1, secure2);
        
        // Test from_bytes
        let bytes = [42u8; 16];
        let secure = SecureBytes::from_bytes(bytes);
        assert_eq!(secure.as_bytes(), &bytes);
    }
    
    #[test]
    fn test_rng_core_interface() {
        let mut rng = SecureRng::new().unwrap();
        
        // Test the RngCore interface
        let val1 = rng.next_u32();
        let val2 = rng.next_u32();
        assert_ne!(val1, val2);
        
        let val3 = rng.next_u64();
        let val4 = rng.next_u64();
        assert_ne!(val3, val4);
    }
}
