//! Error types for SABLE library
//!
//! This module provides both internal errors (SableError) for detailed logging
//! and public errors (PublicError) for external exposure without information leakage.
//!
//! REQ-005: Sanitize error messages to prevent information leakage.
//! The system returns generic error codes without revealing implementation details
//! for all external-facing error conditions.

use thiserror::Error;
use std::fmt;

/// Generic error codes for external exposure (REQ-005)
///
/// These error codes are safe to expose to external callers as they do not
/// reveal implementation details, file paths, internal state, timing information,
/// or algorithm details.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum PublicErrorCode {
    /// Invalid input parameters or data format
    InvalidInput = 1001,
    /// Processing operation failed
    ProcessingFailed = 1002,
    /// Internal system error
    SystemError = 1003,
}

/// Public error type for external exposure (REQ-005)
///
/// This error type provides generic error messages suitable for external callers.
/// Internal detailed errors should be logged separately for administrator access.
#[derive(Debug, Clone)]
pub struct PublicError {
    /// Generic error code
    pub code: PublicErrorCode,
    /// Generic error message (sanitized)
    message: &'static str,
}

impl PublicError {
    /// Create a new PublicError with the given code
    pub fn new(code: PublicErrorCode) -> Self {
        let message = match code {
            PublicErrorCode::InvalidInput => "Invalid input provided",
            PublicErrorCode::ProcessingFailed => "Operation could not be completed",
            PublicErrorCode::SystemError => "An internal error occurred",
        };
        Self { code, message }
    }

    /// Get the error code as a numeric value
    pub fn code_value(&self) -> u32 {
        self.code as u32
    }

    /// Get the sanitized error message
    pub fn message(&self) -> &'static str {
        self.message
    }
}

impl fmt::Display for PublicError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.code_value(), self.message)
    }
}

impl std::error::Error for PublicError {}

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
    
    /// Invalid biometric feature
    #[error("Invalid biometric feature")]
    InvalidFeature,
    
    /// Cryptographic operation error (alias for backward compatibility)
    #[error("Crypto error: {0}")]
    CryptoError(String),
    
    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),
}

impl SableError {
    /// Convert internal error to public error for external exposure (REQ-005)
    ///
    /// This method maps detailed internal errors to generic public error codes,
    /// preventing information leakage about implementation details, file paths,
    /// internal state, timing information, or algorithm details.
    ///
    /// The original SableError should be logged internally for administrator access
    /// before calling this method.
    pub fn to_public_error(&self) -> PublicError {
        match self {
            // Input validation errors -> InvalidInput
            SableError::InvalidCommitment(_) => PublicError::new(PublicErrorCode::InvalidInput),
            SableError::InvalidInput(_) => PublicError::new(PublicErrorCode::InvalidInput),
            SableError::InvalidFeature => PublicError::new(PublicErrorCode::InvalidInput),

            // Processing/crypto operation errors -> ProcessingFailed
            SableError::ProofGeneration(_) => PublicError::new(PublicErrorCode::ProcessingFailed),
            SableError::ProofVerification(_) => PublicError::new(PublicErrorCode::ProcessingFailed),
            SableError::Cryptographic(_) => PublicError::new(PublicErrorCode::ProcessingFailed),
            SableError::CryptoError(_) => PublicError::new(PublicErrorCode::ProcessingFailed),

            // System-level errors -> SystemError
            SableError::RandomGeneration => PublicError::new(PublicErrorCode::SystemError),
            SableError::SerializationError(_) => PublicError::new(PublicErrorCode::SystemError),
        }
    }

    /// Get a sanitized error message suitable for external exposure (REQ-005)
    ///
    /// Returns a generic message that does not reveal implementation details.
    pub fn to_public_message(&self) -> &'static str {
        self.to_public_error().message()
    }

    /// Get the public error code for external exposure (REQ-005)
    pub fn to_public_code(&self) -> u32 {
        self.to_public_error().code_value()
    }
}

// Error conversions for mobile features
#[cfg(feature = "mobile")]
impl From<Box<bincode::ErrorKind>> for SableError {
    fn from(err: Box<bincode::ErrorKind>) -> Self {
        SableError::SerializationError(err.to_string())
    }
}

/// Convenient Result type alias for SABLE operations
pub type Result<T> = std::result::Result<T, SableError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_public_error_code_values() {
        assert_eq!(PublicErrorCode::InvalidInput as u32, 1001);
        assert_eq!(PublicErrorCode::ProcessingFailed as u32, 1002);
        assert_eq!(PublicErrorCode::SystemError as u32, 1003);
    }

    #[test]
    fn test_public_error_messages_are_generic() {
        let invalid_input = PublicError::new(PublicErrorCode::InvalidInput);
        let processing_failed = PublicError::new(PublicErrorCode::ProcessingFailed);
        let system_error = PublicError::new(PublicErrorCode::SystemError);

        // Messages should be generic and not reveal implementation details
        assert_eq!(invalid_input.message(), "Invalid input provided");
        assert_eq!(processing_failed.message(), "Operation could not be completed");
        assert_eq!(system_error.message(), "An internal error occurred");

        // Ensure messages don't contain sensitive information patterns
        for error in [&invalid_input, &processing_failed, &system_error] {
            let msg = error.message();
            assert!(!msg.contains("file"), "Message should not mention files");
            assert!(!msg.contains("path"), "Message should not mention paths");
            assert!(!msg.contains("algorithm"), "Message should not mention algorithms");
            assert!(!msg.contains("key"), "Message should not mention keys");
        }
    }

    #[test]
    fn test_public_error_display() {
        let error = PublicError::new(PublicErrorCode::InvalidInput);
        let display = format!("{}", error);
        assert_eq!(display, "[1001] Invalid input provided");
    }

    #[test]
    fn test_sable_error_to_public_input_errors() {
        // All input validation errors should map to InvalidInput
        let errors = vec![
            SableError::InvalidCommitment("detailed commitment error".into()),
            SableError::InvalidInput("detailed input error".into()),
            SableError::InvalidFeature,
        ];

        for error in errors {
            let public = error.to_public_error();
            assert_eq!(public.code, PublicErrorCode::InvalidInput);
            // Verify the public message doesn't contain the original detail
            assert!(!public.message().contains("detailed"));
            assert!(!public.message().contains("commitment"));
        }
    }

    #[test]
    fn test_sable_error_to_public_processing_errors() {
        // All processing errors should map to ProcessingFailed
        let errors = vec![
            SableError::ProofGeneration("proof generation detail".into()),
            SableError::ProofVerification("verification detail".into()),
            SableError::Cryptographic("crypto detail".into()),
            SableError::CryptoError("crypto error detail".into()),
        ];

        for error in errors {
            let public = error.to_public_error();
            assert_eq!(public.code, PublicErrorCode::ProcessingFailed);
            // Verify the public message doesn't contain sensitive details
            assert!(!public.message().contains("proof"));
            assert!(!public.message().contains("crypto"));
            assert!(!public.message().contains("verification"));
        }
    }

    #[test]
    fn test_sable_error_to_public_system_errors() {
        // All system errors should map to SystemError
        let errors = vec![
            SableError::RandomGeneration,
            SableError::SerializationError("serialization detail at /path/to/file".into()),
        ];

        for error in errors {
            let public = error.to_public_error();
            assert_eq!(public.code, PublicErrorCode::SystemError);
            // Verify the public message doesn't contain sensitive details
            assert!(!public.message().contains("random"));
            assert!(!public.message().contains("serialization"));
            assert!(!public.message().contains("/path"));
        }
    }

    #[test]
    fn test_to_public_message() {
        let error = SableError::InvalidCommitment("secret commitment data".into());
        let message = error.to_public_message();

        // The message should be generic
        assert_eq!(message, "Invalid input provided");
        // The message should not contain the original detail
        assert!(!message.contains("secret"));
        assert!(!message.contains("commitment"));
    }

    #[test]
    fn test_to_public_code() {
        let error = SableError::ProofGeneration("secret algorithm detail".into());
        let code = error.to_public_code();

        assert_eq!(code, 1002); // ProcessingFailed
    }

    #[test]
    fn test_error_sanitization_prevents_info_leakage() {
        // Create errors with sensitive information
        let sensitive_errors = vec![
            SableError::InvalidInput("at index 42 of array".into()),
            SableError::CryptoError("using BLS12-381 curve with invalid point".into()),
            SableError::SerializationError("failed to read /etc/secrets/key.pem".into()),
            SableError::ProofGeneration("SNARK proof failed with constraint 123".into()),
        ];

        for error in sensitive_errors {
            let public = error.to_public_error();
            let message = public.message();

            // Verify no implementation details are leaked
            assert!(!message.contains("index"));
            assert!(!message.contains("array"));
            assert!(!message.contains("BLS12"));
            assert!(!message.contains("curve"));
            assert!(!message.contains("/etc"));
            assert!(!message.contains(".pem"));
            assert!(!message.contains("SNARK"));
            assert!(!message.contains("constraint"));
        }
    }
}
