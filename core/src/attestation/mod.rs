//! # Attestation Module for X.509 Certificate Integration
//!
//! This module provides X.509 certificate infrastructure for binding SABLE
//! biometric commitments to government-issued attestations.
//!
//! ## Requirements Implemented
//!
//! - **REQ-018**: X.509 certificate integration with custom OID extensions
//! - **REQ-019**: Certificate chain validation with OCSP/CRL revocation checking
//! - **REQ-020**: Trust store management for government PKI integration
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use sable_core::attestation::{
//!     SableCertificate, TrustStore, ChainValidator, TrustLevel
//! };
//!
//! // Initialize trust store with government root CAs
//! let mut trust_store = TrustStore::new();
//! // trust_store.add_root_certificate(gov_root_cert, TrustLevel::Government)?;
//!
//! // Validate certificate chain
//! let validator = ChainValidator::new();
//! // let result = validator.validate_chain(&cert_chain)?;
//!
//! // Create SABLE certificate with commitment binding
//! // let sable_cert = SableCertificate::new(subject, commitment, signing_key)?;
//! ```
//!
//! ## Features
//!
//! - X.509v3 certificate creation with SABLE-specific extensions
//! - Custom OID extensions for commitment binding
//! - Certificate parsing from DER format
//! - Certificate signature verification
//! - Government attestation support
//! - Certificate chain validation up to trusted root CAs
//! - OCSP (Online Certificate Status Protocol) revocation checking
//! - CRL (Certificate Revocation List) revocation checking
//! - Trust store management with multiple trust levels
//! - Certificate pinning for known issuers
//! - Secure trust store import/export with signature verification
//!
//! ## Modules
//!
//! - [`x509`] - X.509v3 certificate creation and parsing
//! - [`chain`] - Certificate chain validation and revocation checking
//! - [`truststore`] - Trust store management for root CAs
//!
//! ## Custom OIDs
//!
//! SABLE uses custom OID extensions under the arc `1.3.6.1.4.1.99999.1`:
//! - `.1` - SABLE Commitment (48-byte BLS12-381 G1 point)
//! - `.2` - Issued At timestamp
//! - `.3` - Proof Type identifier

pub mod chain;
pub mod truststore;
pub mod x509;

pub use chain::{
    ChainBuilder, ChainValidator, Crl, CrlEntry, OcspResponse, OcspStatus,
    RevocationReason, ValidationResult, certificate_fingerprint,
};
pub use truststore::{CertificatePin, TrustLevel, TrustStore, TrustedRoot};
pub use x509::{
    ProofType, SableCertificate, SableExtension, SigningKey, VerifyingKey,
    OID_SABLE_COMMITMENT, OID_SABLE_ISSUED_AT, OID_SABLE_PROOF_TYPE, SABLE_OID_PREFIX,
};
