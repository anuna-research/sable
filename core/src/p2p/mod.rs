//! # Peer-to-Peer Communication Module for SABLE
//!
//! This module provides secure P2P communications for proximity-based biometric
//! verification between mobile devices.
//!
//! ## Features
//!
//! - ECDH key exchange with X25519 (REQ-016)
//! - ChaCha20-Poly1305 authenticated encryption
//! - 30-second session timeout
//! - Nonce-based replay prevention
//! - BLE GATT-based transport for proximity verification (REQ-015)
//! - NFC peer-to-peer transport for offline verification (REQ-014)
//! - Message fragmentation and reassembly with integrity verification (REQ-017)
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use sable_core::p2p::{SessionManager, BleTransport, NfcTransport};
//!
//! // Create session manager
//! let mut session_manager = SessionManager::new();
//!
//! // Initiate a new session (prover side)
//! let session = session_manager.create_session()
//!     .expect("Session creation failed");
//!
//! // Session provides encrypted channel for proof exchange
//! // let encrypted = session.encrypt(&proof_bytes)?;
//! // let decrypted = session.decrypt(&received_bytes)?;
//! ```
//!
//! ## Modules
//!
//! - [`session`] - Secure session management with X25519 key exchange
//! - [`ble`] - BLE GATT transport for proximity verification
//! - [`nfc`] - NFC transport for offline/contactless verification
//! - [`fragmentation`] - Message fragmentation for MTU-limited transports
//!
//! ## Security Properties
//!
//! - **Forward secrecy**: Each session uses ephemeral ECDH keys
//! - **Replay protection**: Nonces prevent message replay attacks
//! - **Timeout**: Sessions automatically expire after 30 seconds
//! - **Integrity**: All messages are authenticated with Poly1305

pub mod ble;
pub mod fragmentation;
pub mod nfc;
pub mod session;

// Re-export commonly used items
pub use session::{
    Nonce, Session, SessionId, SessionManager, SessionState, SESSION_TIMEOUT,
};

// Re-export BLE transport items
pub use ble::{
    BleTransport, BleTransportBuilder, FragmentFlags, FragmentHeader, GattCharacteristic,
    DEFAULT_BLE_MTU, MAX_BLE_MTU, MIN_BLE_MTU, SABLE_SERVICE_UUID,
};

// Re-export NFC transport items
pub use nfc::{
    AckStatus, NdefRecord, NfcMessageType, NfcTransport, MAX_NDEF_PAYLOAD, SABLE_TYPE_NAME,
};

// Re-export fragmentation items (REQ-017)
pub use fragmentation::{
    Fragment, Fragmenter, MessageFragmentHeader, ReassemblyBuffer, ReassemblyManager,
    CHECKSUM_SIZE, DEFAULT_MAX_FRAGMENT_SIZE, FRAGMENT_OVERHEAD, MIN_PAYLOAD_SIZE,
    STANDARD_PROOF_SIZE,
};
