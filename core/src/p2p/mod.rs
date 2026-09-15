//! P2P transport primitives. Authenticated session replacement is in progress.
//!
//! The former raw-X25519 sessions and their BLE/NFC wrappers are withdrawn:
//! they did not authenticate peers. They compile only as legacy unit-test fixtures.
//! Fragmentation alone does not provide peer authentication or message integrity
//! against an attacker. Do not use it as an authenticated channel.
//!
//! The internal Noise replacement is not exported until attestation identity
//! binding and transport integration have passed their security tests.
//!
//! ```compile_fail
//! use sable_core::p2p::SessionManager;
//! ```
//! ```compile_fail
//! use sable_core::p2p::session::SessionManager;
//! ```
//! ```compile_fail
//! use sable_core::p2p::BleTransport;
//! ```
//! ```compile_fail
//! use sable_core::p2p::NfcTransport;
//! ```
//! ```compile_fail
//! use sable_core::p2p::ble::BleTransport;
//! ```
//! ```compile_fail
//! use sable_core::p2p::nfc::NfcTransport;
//! ```

#[cfg(test)]
pub(crate) mod authenticated;
#[cfg(test)]
pub mod ble;
pub mod fragmentation;
#[cfg(test)]
pub mod nfc;
#[cfg(test)]
pub mod session;

#[cfg(test)]
pub use session::{Nonce, Session, SessionId, SessionManager, SessionState, SESSION_TIMEOUT};
#[cfg(test)]
pub use ble::{
    BleTransport, BleTransportBuilder, FragmentFlags, FragmentHeader, GattCharacteristic,
    DEFAULT_BLE_MTU, MAX_BLE_MTU, MIN_BLE_MTU, SABLE_SERVICE_UUID,
};
#[cfg(test)]
pub use nfc::{
    AckStatus, NdefRecord, NfcMessageType, NfcTransport, MAX_NDEF_PAYLOAD, SABLE_TYPE_NAME,
};
pub use fragmentation::{
    Fragment, Fragmenter, MessageFragmentHeader, ReassemblyBuffer, ReassemblyManager,
    CHECKSUM_SIZE, DEFAULT_MAX_FRAGMENT_SIZE, FRAGMENT_OVERHEAD, MIN_PAYLOAD_SIZE,
    STANDARD_PROOF_SIZE,
};
