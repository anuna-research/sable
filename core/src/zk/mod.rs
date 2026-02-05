//! # Zero-Knowledge Proof Module
//!
//! This module provides zero-knowledge proof implementations for SABLE.
//!
//! ## Available Backends
//!
//! - [`halo2`] - Halo2 circuits (transparent setup, requires `halo2` feature)
//!
//! ## Feature Flags
//!
//! - `halo2` - Enable Halo2-based circuits (transparent setup)
//! - `zk` - Enable Groth16-based circuits (trusted setup, existing implementation)

#[cfg(feature = "halo2")]
pub mod halo2;
