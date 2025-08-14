//! Error types for SABLE library

use thiserror::Error;

/// SABLE error types for cryptographic operations
#[derive(Debug, Error)]
pub enum SableError {
    /// Invalid commitment data or format
    #[error("Invalid commitment: {0}")]
    InvalidCommitment(String),
    
    /// zk-SNARK proof generation failed
    #[error("Proof generation failed: {0}")]
    ProofGeneration(String),
    
    /// zk-SNARK proof verification failed
    #[error("Proof verification failed: {0}")]
    ProofVerification(String),
    
    /// General cryptographic operation error
    #[error("Cryptographic error: {0}")]
    Cryptographic(String),
    
    /// Invalid input parameters or data
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    
    /// Random number generation failed
    #[error("Random number generation failed")]
    RandomGeneration,
}

/// Convenient Result type alias for SABLE operations
pub type Result<T> = std::result::Result<T, SableError>;
