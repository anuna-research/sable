// SABLE Hardware Keystore Abstraction
//
// Provides secure storage abstractions for mobile platforms:
// - Android: Android Keystore (TEE/SE)
// - iOS: Secure Enclave via Keychain Services

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

use crate::types::{Salt, Timestamp};
use crate::crypto::pedersen::PedersenCommitment;
use crate::error::{Result, SableError};

/// Keystore entry types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KeystoreEntry {
    /// Biometric salt for commitment generation
    Salt(Salt),
    /// Stored biometric commitment
    Commitment(PedersenCommitment),
    /// Stored proving key (for setup reuse)
    ProvingKey(Vec<u8>),
    /// Generic encrypted blob
    EncryptedData(Vec<u8>),
}

/// Keystore access policies
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum AccessPolicy {
    /// Require biometric authentication
    BiometricOnly,
    /// Require device unlock (PIN/Pattern/Password)
    DeviceCredential, 
    /// Require both biometric and device credential
    BiometricAndCredential,
    /// No additional authentication required
    None,
}

/// Hardware security level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecurityLevel {
    /// Hardware-backed security (TEE/Secure Enclave)
    Hardware,
    /// Software-only security
    Software,
    /// Unknown security level
    Unknown,
}

/// Keystore metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeystoreMetadata {
    pub created_at: Timestamp,
    pub access_policy: AccessPolicy,
    pub security_level: SecurityLevel,
    pub key_alias: String,
}

/// Abstract keystore trait for platform implementations
pub trait Keystore {
    /// Store entry with given alias and access policy
    fn store(
        &mut self,
        alias: &str,
        entry: KeystoreEntry,
        policy: AccessPolicy,
    ) -> Result<()>;
    
    /// Retrieve entry by alias
    fn retrieve(&self, alias: &str) -> Result<KeystoreEntry>;
    
    /// Delete entry by alias
    fn delete(&mut self, alias: &str) -> Result<()>;
    
    /// List all stored aliases
    fn list_aliases(&self) -> Result<Vec<String>>;
    
    /// Check if alias exists
    fn contains(&self, alias: &str) -> bool;
    
    /// Get keystore metadata for alias
    fn get_metadata(&self, alias: &str) -> Result<KeystoreMetadata>;
    
    /// Get hardware security level
    fn security_level(&self) -> SecurityLevel;
    
    /// Check if biometric authentication is available
    fn biometric_available(&self) -> bool;
}

/// In-memory keystore implementation (for testing)
#[derive(Default)]
pub struct MemoryKeystore {
    entries: HashMap<String, KeystoreEntry>,
    metadata: HashMap<String, KeystoreMetadata>,
}

impl MemoryKeystore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Keystore for MemoryKeystore {
    fn store(
        &mut self,
        alias: &str,
        entry: KeystoreEntry,
        policy: AccessPolicy,
    ) -> Result<()> {
        let metadata = KeystoreMetadata {
            created_at: Timestamp::now(),
            access_policy: policy,
            security_level: SecurityLevel::Software,
            key_alias: alias.to_string(),
        };
        
        self.entries.insert(alias.to_string(), entry);
        self.metadata.insert(alias.to_string(), metadata);
        Ok(())
    }
    
    fn retrieve(&self, alias: &str) -> Result<KeystoreEntry> {
        self.entries
            .get(alias)
            .cloned()
            .ok_or_else(|| SableError::CryptoError("Key not found".into()))
    }
    
    fn delete(&mut self, alias: &str) -> Result<()> {
        self.entries.remove(alias);
        self.metadata.remove(alias);
        Ok(())
    }
    
    fn list_aliases(&self) -> Result<Vec<String>> {
        Ok(self.entries.keys().cloned().collect())
    }
    
    fn contains(&self, alias: &str) -> bool {
        self.entries.contains_key(alias)
    }
    
    fn get_metadata(&self, alias: &str) -> Result<KeystoreMetadata> {
        self.metadata
            .get(alias)
            .cloned()
            .ok_or_else(|| SableError::CryptoError("Metadata not found".into()))
    }
    
    fn security_level(&self) -> SecurityLevel {
        SecurityLevel::Software
    }
    
    fn biometric_available(&self) -> bool {
        false // Memory keystore doesn't support biometrics
    }
}

/// Platform-specific keystore factory
pub struct KeystoreFactory;

impl KeystoreFactory {
    /// Create keystore instance for current platform
    pub fn create() -> Box<dyn Keystore> {
        // For now, return memory keystore
        // Platform-specific implementations will be added
        Box::new(MemoryKeystore::new())
    }
    
    /// Create Android keystore instance
    #[cfg(target_os = "android")]
    pub fn create_android() -> Box<dyn Keystore> {
        // TODO: Implement Android Keystore integration
        Box::new(AndroidKeystore::new())
    }
    
    /// Create iOS keystore instance  
    #[cfg(target_os = "ios")]
    pub fn create_ios() -> Box<dyn Keystore> {
        // TODO: Implement iOS Keychain/Secure Enclave integration
        Box::new(IOSKeystore::new())
    }
}

/// SABLE keystore manager with high-level operations
pub struct SableKeystore {
    keystore: Box<dyn Keystore>,
}

impl SableKeystore {
    /// Create new SABLE keystore manager
    pub fn new() -> Self {
        Self {
            keystore: KeystoreFactory::create(),
        }
    }
    
    /// Store biometric salt securely
    pub fn store_salt(&mut self, user_id: &str, salt: Salt) -> Result<()> {
        let alias = format!("sable.salt.{}", user_id);
        self.keystore.store(
            &alias,
            KeystoreEntry::Salt(salt),
            AccessPolicy::BiometricOnly,
        )
    }
    
    /// Retrieve biometric salt
    pub fn get_salt(&self, user_id: &str) -> Result<Salt> {
        let alias = format!("sable.salt.{}", user_id);
        match self.keystore.retrieve(&alias)? {
            KeystoreEntry::Salt(salt) => Ok(salt),
            _ => Err(SableError::CryptoError("Invalid salt entry".into())),
        }
    }
    
    /// Store biometric commitment
    pub fn store_commitment(&mut self, user_id: &str, commitment: PedersenCommitment) -> Result<()> {
        let alias = format!("sable.commitment.{}", user_id);
        self.keystore.store(
            &alias,
            KeystoreEntry::Commitment(commitment),
            AccessPolicy::DeviceCredential,
        )
    }
    
    /// Retrieve biometric commitment
    pub fn get_commitment(&self, user_id: &str) -> Result<PedersenCommitment> {
        let alias = format!("sable.commitment.{}", user_id);
        match self.keystore.retrieve(&alias)? {
            KeystoreEntry::Commitment(commitment) => Ok(commitment),
            _ => Err(SableError::CryptoError("Invalid commitment entry".into())),
        }
    }
    
    /// Store proving key for reuse
    pub fn store_proving_key(&mut self, proving_key: Vec<u8>) -> Result<()> {
        let alias = "sable.proving_key".to_string();
        self.keystore.store(
            &alias,
            KeystoreEntry::ProvingKey(proving_key),
            AccessPolicy::None,
        )
    }
    
    /// Retrieve proving key
    pub fn get_proving_key(&self) -> Result<Vec<u8>> {
        let alias = "sable.proving_key";
        match self.keystore.retrieve(alias)? {
            KeystoreEntry::ProvingKey(key) => Ok(key),
            _ => Err(SableError::CryptoError("Invalid proving key entry".into())),
        }
    }
    
    /// Delete all SABLE entries for user
    pub fn delete_user_data(&mut self, user_id: &str) -> Result<()> {
        let salt_alias = format!("sable.salt.{}", user_id);
        let commitment_alias = format!("sable.commitment.{}", user_id);
        
        let _ = self.keystore.delete(&salt_alias);
        let _ = self.keystore.delete(&commitment_alias);
        
        Ok(())
    }
    
    /// Get hardware security level
    pub fn security_level(&self) -> SecurityLevel {
        self.keystore.security_level()
    }
    
    /// Check biometric availability
    pub fn biometric_available(&self) -> bool {
        self.keystore.biometric_available()
    }
}

// Platform-specific implementations will be added in separate files
// when JNI/Swift bindings are implemented

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::rng::SecureRng;

    #[test]
    fn test_memory_keystore() {
        let mut keystore = MemoryKeystore::new();
        let mut rng = SecureRng::new();
        let salt = Salt::random(&mut rng);
        
        // Store salt
        keystore.store("test_salt", KeystoreEntry::Salt(salt.clone()), AccessPolicy::None).unwrap();
        
        // Retrieve salt
        let retrieved = keystore.retrieve("test_salt").unwrap();
        match retrieved {
            KeystoreEntry::Salt(retrieved_salt) => {
                assert_eq!(salt.to_bytes().unwrap(), retrieved_salt.to_bytes().unwrap());
            }
            _ => panic!("Wrong entry type"),
        }
        
        // Check metadata
        let metadata = keystore.get_metadata("test_salt").unwrap();
        assert_eq!(metadata.key_alias, "test_salt");
        assert_eq!(metadata.security_level, SecurityLevel::Software);
    }
    
    #[test]
    fn test_sable_keystore() {
        let mut sable_keystore = SableKeystore::new();
        let mut rng = SecureRng::new();
        let salt = Salt::random(&mut rng);
        
        // Store and retrieve salt
        sable_keystore.store_salt("user123", salt.clone()).unwrap();
        let retrieved_salt = sable_keystore.get_salt("user123").unwrap();
        
        assert_eq!(salt.to_bytes().unwrap(), retrieved_salt.to_bytes().unwrap());
        
        // Clean up
        sable_keystore.delete_user_data("user123").unwrap();
    }
}
