//! BLE GATT-based transport for proximity-based verification (REQ-015)
//!
//! This module provides Bluetooth Low Energy transport support for SABLE,
//! enabling secure proximity-based biometric verification using:
//! - MTU negotiation for optimal data transfer
//! - GATT characteristic-based message exchange
//! - Message fragmentation and reassembly for large payloads
//!
//! # BLE Communication Model
//!
//! The BLE transport uses a custom GATT service with three characteristics:
//! - KeyExchange: For ECDH public key exchange
//! - ProofData: For transmitting ZK proofs and biometric data
//! - Status: For acknowledgments and status updates
//!
//! # MTU Handling
//!
//! BLE has limited MTU (Maximum Transmission Unit), typically 23 bytes by default.
//! This module handles MTU negotiation and automatic message fragmentation to
//! support larger payloads required for cryptographic operations.

use crate::error::{Result, SableError};
use crate::p2p::SessionManager;

/// Default BLE MTU (negotiable) - standard BLE 4.0 ATT_MTU
pub const DEFAULT_BLE_MTU: usize = 23;

/// Maximum BLE MTU (BLE 5.0 extended data length)
pub const MAX_BLE_MTU: usize = 512;

/// Minimum BLE MTU (cannot go below this)
pub const MIN_BLE_MTU: usize = 23;

/// ATT header overhead (3 bytes for ATT_HANDLE_VALUE_NTF/IND)
pub const ATT_HEADER_SIZE: usize = 3;

/// SABLE BLE Service UUID
pub const SABLE_SERVICE_UUID: &str = "12345678-1234-5678-1234-56789abcdef0";

/// SABLE Key Exchange Characteristic UUID
pub const KEY_EXCHANGE_CHAR_UUID: &str = "12345678-1234-5678-1234-56789abcdef1";

/// SABLE Proof Data Characteristic UUID
pub const PROOF_DATA_CHAR_UUID: &str = "12345678-1234-5678-1234-56789abcdef2";

/// SABLE Status Characteristic UUID
pub const STATUS_CHAR_UUID: &str = "12345678-1234-5678-1234-56789abcdef3";

/// Fragment header size (sequence number + total fragments + flags)
pub const FRAGMENT_HEADER_SIZE: usize = 4;

/// GATT Characteristics for SABLE BLE communication
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GattCharacteristic {
    /// Characteristic for ECDH key exchange
    KeyExchange,
    /// Characteristic for ZK proof transmission
    ProofData,
    /// Characteristic for status/acknowledgment
    Status,
}

impl GattCharacteristic {
    /// Get the UUID for this characteristic
    pub fn uuid(&self) -> &'static str {
        match self {
            GattCharacteristic::KeyExchange => KEY_EXCHANGE_CHAR_UUID,
            GattCharacteristic::ProofData => PROOF_DATA_CHAR_UUID,
            GattCharacteristic::Status => STATUS_CHAR_UUID,
        }
    }

    /// Get all characteristics
    pub fn all() -> [GattCharacteristic; 3] {
        [
            GattCharacteristic::KeyExchange,
            GattCharacteristic::ProofData,
            GattCharacteristic::Status,
        ]
    }
}

/// Fragment flags for message reconstruction
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FragmentFlags(u8);

impl FragmentFlags {
    /// First fragment of a message
    pub const FIRST: u8 = 0x01;
    /// Last fragment of a message
    pub const LAST: u8 = 0x02;
    /// Single fragment (complete message)
    pub const SINGLE: u8 = Self::FIRST | Self::LAST;

    /// Create new fragment flags
    pub fn new(flags: u8) -> Self {
        Self(flags)
    }

    /// Check if this is the first fragment
    pub fn is_first(&self) -> bool {
        self.0 & Self::FIRST != 0
    }

    /// Check if this is the last fragment
    pub fn is_last(&self) -> bool {
        self.0 & Self::LAST != 0
    }

    /// Check if this is a single (complete) message
    pub fn is_single(&self) -> bool {
        self.0 == Self::SINGLE
    }

    /// Get the raw flags value
    pub fn value(&self) -> u8 {
        self.0
    }
}

/// BLE message fragment header
#[derive(Debug, Clone, Copy)]
pub struct FragmentHeader {
    /// Sequence number of this fragment (0-indexed)
    pub sequence: u8,
    /// Total number of fragments
    pub total: u8,
    /// Message ID (to correlate fragments)
    pub message_id: u8,
    /// Fragment flags
    pub flags: FragmentFlags,
}

impl FragmentHeader {
    /// Create a new fragment header
    pub fn new(sequence: u8, total: u8, message_id: u8, flags: FragmentFlags) -> Self {
        Self {
            sequence,
            total,
            message_id,
            flags,
        }
    }

    /// Serialize the header to bytes
    pub fn to_bytes(&self) -> [u8; FRAGMENT_HEADER_SIZE] {
        [self.sequence, self.total, self.message_id, self.flags.value()]
    }

    /// Parse a header from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < FRAGMENT_HEADER_SIZE {
            return Err(SableError::InvalidInput(
                "Fragment header too short".into(),
            ));
        }
        Ok(Self {
            sequence: bytes[0],
            total: bytes[1],
            message_id: bytes[2],
            flags: FragmentFlags::new(bytes[3]),
        })
    }
}

/// BLE Transport for SABLE proximity-based verification
pub struct BleTransport {
    /// Current negotiated MTU
    mtu: usize,
    /// Session manager for cryptographic operations
    session_manager: SessionManager,
    /// Current message ID counter
    message_id_counter: u8,
}

impl BleTransport {
    /// Create a new BLE transport with the default MTU
    pub fn new() -> Self {
        Self {
            mtu: DEFAULT_BLE_MTU,
            session_manager: SessionManager::new(),
            message_id_counter: 0,
        }
    }

    /// Create a new BLE transport with a specific MTU
    pub fn with_mtu(mtu: usize) -> Self {
        Self {
            mtu: mtu.clamp(MIN_BLE_MTU, MAX_BLE_MTU),
            session_manager: SessionManager::new(),
            message_id_counter: 0,
        }
    }

    /// Get the current MTU
    pub fn mtu(&self) -> usize {
        self.mtu
    }

    /// Get the effective payload size (MTU minus ATT and fragment headers)
    pub fn payload_size(&self) -> usize {
        self.mtu.saturating_sub(ATT_HEADER_SIZE + FRAGMENT_HEADER_SIZE)
    }

    /// Get mutable access to the session manager
    pub fn session_manager_mut(&mut self) -> &mut SessionManager {
        &mut self.session_manager
    }

    /// Get read-only access to the session manager
    pub fn session_manager(&self) -> &SessionManager {
        &self.session_manager
    }

    /// Negotiate MTU with peer
    ///
    /// Returns the negotiated MTU, which is the minimum of our MTU and peer's MTU,
    /// clamped to valid BLE MTU range.
    ///
    /// # Arguments
    ///
    /// * `peer_mtu` - The MTU advertised by the peer device
    ///
    /// # Returns
    ///
    /// The negotiated MTU that will be used for this connection
    pub fn negotiate_mtu(&mut self, peer_mtu: usize) -> usize {
        // Negotiate to the minimum of both MTUs, clamped to valid range
        let negotiated = self.mtu.min(peer_mtu).clamp(MIN_BLE_MTU, MAX_BLE_MTU);
        self.mtu = negotiated;
        negotiated
    }

    /// Get the next message ID
    fn next_message_id(&mut self) -> u8 {
        let id = self.message_id_counter;
        self.message_id_counter = self.message_id_counter.wrapping_add(1);
        id
    }

    /// Fragment message for BLE transmission
    ///
    /// Splits a message into fragments that fit within the current MTU.
    /// Each fragment includes a header for reassembly.
    ///
    /// # Arguments
    ///
    /// * `msg` - The message to fragment
    ///
    /// # Returns
    ///
    /// A vector of fragments, each ready for BLE transmission
    pub fn fragment_for_mtu(&mut self, msg: &[u8]) -> Vec<Vec<u8>> {
        let payload_size = self.payload_size();

        // Handle empty message
        if msg.is_empty() {
            let message_id = self.next_message_id();
            let header = FragmentHeader::new(0, 1, message_id, FragmentFlags::new(FragmentFlags::SINGLE));
            return vec![header.to_bytes().to_vec()];
        }

        // Calculate number of fragments needed
        let num_fragments = (msg.len() + payload_size - 1) / payload_size;
        let num_fragments = num_fragments.min(255); // Max 255 fragments
        let message_id = self.next_message_id();

        let mut fragments = Vec::with_capacity(num_fragments);

        for (i, chunk) in msg.chunks(payload_size).enumerate() {
            if i >= 255 {
                break; // Safety limit
            }

            let flags = match (i == 0, i == num_fragments - 1) {
                (true, true) => FragmentFlags::SINGLE,
                (true, false) => FragmentFlags::FIRST,
                (false, true) => FragmentFlags::LAST,
                (false, false) => 0,
            };

            let header = FragmentHeader::new(
                i as u8,
                num_fragments as u8,
                message_id,
                FragmentFlags::new(flags),
            );

            let mut fragment = Vec::with_capacity(FRAGMENT_HEADER_SIZE + chunk.len());
            fragment.extend_from_slice(&header.to_bytes());
            fragment.extend_from_slice(chunk);
            fragments.push(fragment);
        }

        fragments
    }

    /// Reassemble fragmented message
    ///
    /// Reconstructs a message from its fragments. Fragments must be in order
    /// and belong to the same message.
    ///
    /// # Arguments
    ///
    /// * `fragments` - The fragments to reassemble
    ///
    /// # Returns
    ///
    /// The reassembled message, or an error if reassembly fails
    pub fn reassemble(&self, fragments: &[Vec<u8>]) -> Result<Vec<u8>> {
        if fragments.is_empty() {
            return Err(SableError::InvalidInput("No fragments to reassemble".into()));
        }

        // Parse headers and validate
        let mut headers = Vec::with_capacity(fragments.len());
        for fragment in fragments {
            let header = FragmentHeader::from_bytes(fragment)?;
            headers.push(header);
        }

        // Validate fragment sequence
        let first_header = &headers[0];
        let expected_total = first_header.total as usize;
        let message_id = first_header.message_id;

        if fragments.len() != expected_total {
            return Err(SableError::InvalidInput(format!(
                "Expected {} fragments, got {}",
                expected_total,
                fragments.len()
            )));
        }

        // Validate all fragments belong to same message and are in sequence
        for (i, header) in headers.iter().enumerate() {
            if header.message_id != message_id {
                return Err(SableError::InvalidInput(
                    "Fragment message ID mismatch".into(),
                ));
            }
            if header.sequence as usize != i {
                return Err(SableError::InvalidInput(format!(
                    "Fragment sequence mismatch: expected {}, got {}",
                    i, header.sequence
                )));
            }
            if header.total != expected_total as u8 {
                return Err(SableError::InvalidInput(
                    "Fragment total count mismatch".into(),
                ));
            }
        }

        // Validate first and last flags
        if fragments.len() == 1 {
            if !headers[0].flags.is_single() {
                return Err(SableError::InvalidInput(
                    "Single fragment must have SINGLE flag".into(),
                ));
            }
        } else {
            if !headers[0].flags.is_first() {
                return Err(SableError::InvalidInput(
                    "First fragment must have FIRST flag".into(),
                ));
            }
            if !headers[headers.len() - 1].flags.is_last() {
                return Err(SableError::InvalidInput(
                    "Last fragment must have LAST flag".into(),
                ));
            }
        }

        // Reassemble the message
        let mut message = Vec::new();
        for fragment in fragments {
            if fragment.len() > FRAGMENT_HEADER_SIZE {
                message.extend_from_slice(&fragment[FRAGMENT_HEADER_SIZE..]);
            }
        }

        Ok(message)
    }

    /// Create GATT write operations for a characteristic
    ///
    /// Prepares data for transmission over a specific GATT characteristic,
    /// fragmenting if necessary.
    ///
    /// # Arguments
    ///
    /// * `characteristic` - The GATT characteristic to write to
    /// * `data` - The data to write
    ///
    /// # Returns
    ///
    /// A vector of fragments ready for GATT write operations
    pub fn create_gatt_write(
        &mut self,
        _characteristic: GattCharacteristic,
        data: &[u8],
    ) -> Vec<Vec<u8>> {
        // Fragment the data for the characteristic
        self.fragment_for_mtu(data)
    }

    /// Parse a received GATT notification/indication
    ///
    /// Extracts the fragment header and payload from a received BLE packet.
    ///
    /// # Arguments
    ///
    /// * `data` - The received data
    ///
    /// # Returns
    ///
    /// A tuple of (header, payload)
    pub fn parse_gatt_read(&self, data: &[u8]) -> Result<(FragmentHeader, Vec<u8>)> {
        let header = FragmentHeader::from_bytes(data)?;
        let payload = if data.len() > FRAGMENT_HEADER_SIZE {
            data[FRAGMENT_HEADER_SIZE..].to_vec()
        } else {
            Vec::new()
        };
        Ok((header, payload))
    }
}

impl Default for BleTransport {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for BLE transport configuration
pub struct BleTransportBuilder {
    mtu: usize,
}

impl BleTransportBuilder {
    /// Create a new builder with default settings
    pub fn new() -> Self {
        Self {
            mtu: DEFAULT_BLE_MTU,
        }
    }

    /// Set the initial MTU
    pub fn mtu(mut self, mtu: usize) -> Self {
        self.mtu = mtu.clamp(MIN_BLE_MTU, MAX_BLE_MTU);
        self
    }

    /// Build the BLE transport
    pub fn build(self) -> BleTransport {
        BleTransport::with_mtu(self.mtu)
    }
}

impl Default for BleTransportBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(DEFAULT_BLE_MTU, 23);
        assert_eq!(MAX_BLE_MTU, 512);
        assert_eq!(MIN_BLE_MTU, 23);
        assert_eq!(ATT_HEADER_SIZE, 3);
        assert_eq!(FRAGMENT_HEADER_SIZE, 4);
    }

    #[test]
    fn test_gatt_characteristic_uuids() {
        assert_eq!(
            GattCharacteristic::KeyExchange.uuid(),
            "12345678-1234-5678-1234-56789abcdef1"
        );
        assert_eq!(
            GattCharacteristic::ProofData.uuid(),
            "12345678-1234-5678-1234-56789abcdef2"
        );
        assert_eq!(
            GattCharacteristic::Status.uuid(),
            "12345678-1234-5678-1234-56789abcdef3"
        );
    }

    #[test]
    fn test_gatt_characteristic_all() {
        let all = GattCharacteristic::all();
        assert_eq!(all.len(), 3);
        assert_eq!(all[0], GattCharacteristic::KeyExchange);
        assert_eq!(all[1], GattCharacteristic::ProofData);
        assert_eq!(all[2], GattCharacteristic::Status);
    }

    #[test]
    fn test_fragment_flags() {
        let first = FragmentFlags::new(FragmentFlags::FIRST);
        assert!(first.is_first());
        assert!(!first.is_last());
        assert!(!first.is_single());

        let last = FragmentFlags::new(FragmentFlags::LAST);
        assert!(!last.is_first());
        assert!(last.is_last());
        assert!(!last.is_single());

        let single = FragmentFlags::new(FragmentFlags::SINGLE);
        assert!(single.is_first());
        assert!(single.is_last());
        assert!(single.is_single());

        let middle = FragmentFlags::new(0);
        assert!(!middle.is_first());
        assert!(!middle.is_last());
        assert!(!middle.is_single());
    }

    #[test]
    fn test_fragment_header_serialization() {
        let header = FragmentHeader::new(5, 10, 42, FragmentFlags::new(FragmentFlags::FIRST));
        let bytes = header.to_bytes();

        assert_eq!(bytes[0], 5);  // sequence
        assert_eq!(bytes[1], 10); // total
        assert_eq!(bytes[2], 42); // message_id
        assert_eq!(bytes[3], FragmentFlags::FIRST); // flags

        let parsed = FragmentHeader::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.sequence, 5);
        assert_eq!(parsed.total, 10);
        assert_eq!(parsed.message_id, 42);
        assert!(parsed.flags.is_first());
    }

    #[test]
    fn test_fragment_header_from_bytes_too_short() {
        let result = FragmentHeader::from_bytes(&[1, 2, 3]);
        assert!(result.is_err());
    }

    #[test]
    fn test_ble_transport_default_mtu() {
        let transport = BleTransport::new();
        assert_eq!(transport.mtu(), DEFAULT_BLE_MTU);
    }

    #[test]
    fn test_ble_transport_with_mtu() {
        let transport = BleTransport::with_mtu(100);
        assert_eq!(transport.mtu(), 100);

        // Test clamping to max
        let transport = BleTransport::with_mtu(1000);
        assert_eq!(transport.mtu(), MAX_BLE_MTU);

        // Test clamping to min
        let transport = BleTransport::with_mtu(10);
        assert_eq!(transport.mtu(), MIN_BLE_MTU);
    }

    #[test]
    fn test_negotiate_mtu_peer_smaller() {
        let mut transport = BleTransport::with_mtu(256);
        let negotiated = transport.negotiate_mtu(128);
        assert_eq!(negotiated, 128);
        assert_eq!(transport.mtu(), 128);
    }

    #[test]
    fn test_negotiate_mtu_self_smaller() {
        let mut transport = BleTransport::with_mtu(128);
        let negotiated = transport.negotiate_mtu(256);
        assert_eq!(negotiated, 128);
        assert_eq!(transport.mtu(), 128);
    }

    #[test]
    fn test_negotiate_mtu_clamps_to_valid_range() {
        let mut transport = BleTransport::with_mtu(256);

        // Peer requests too small MTU
        let negotiated = transport.negotiate_mtu(10);
        assert_eq!(negotiated, MIN_BLE_MTU);

        // Reset
        transport = BleTransport::with_mtu(256);

        // Peer requests too large MTU
        let negotiated = transport.negotiate_mtu(1000);
        assert_eq!(negotiated, 256); // Our MTU is smaller
    }

    #[test]
    fn test_payload_size() {
        let transport = BleTransport::with_mtu(100);
        // Payload = MTU - ATT_HEADER - FRAGMENT_HEADER = 100 - 3 - 4 = 93
        assert_eq!(transport.payload_size(), 93);
    }

    #[test]
    fn test_payload_size_minimum_mtu() {
        let transport = BleTransport::with_mtu(MIN_BLE_MTU);
        // Payload = 23 - 3 - 4 = 16
        assert_eq!(transport.payload_size(), 16);
    }

    #[test]
    fn test_fragment_small_message() {
        let mut transport = BleTransport::with_mtu(100);
        let msg = b"Hello, BLE!";
        let fragments = transport.fragment_for_mtu(msg);

        assert_eq!(fragments.len(), 1);

        // Verify fragment header
        let header = FragmentHeader::from_bytes(&fragments[0]).unwrap();
        assert_eq!(header.sequence, 0);
        assert_eq!(header.total, 1);
        assert!(header.flags.is_single());

        // Verify payload
        assert_eq!(&fragments[0][FRAGMENT_HEADER_SIZE..], msg);
    }

    #[test]
    fn test_fragment_empty_message() {
        let mut transport = BleTransport::with_mtu(100);
        let msg: &[u8] = &[];
        let fragments = transport.fragment_for_mtu(msg);

        assert_eq!(fragments.len(), 1);
        assert_eq!(fragments[0].len(), FRAGMENT_HEADER_SIZE);

        let header = FragmentHeader::from_bytes(&fragments[0]).unwrap();
        assert!(header.flags.is_single());
    }

    #[test]
    fn test_fragment_large_message() {
        let mut transport = BleTransport::with_mtu(MIN_BLE_MTU);
        let _payload_size = transport.payload_size(); // 16 bytes

        // Create message that spans multiple fragments
        let msg: Vec<u8> = (0..50).collect();
        let fragments = transport.fragment_for_mtu(&msg);

        // With 16 byte payload, 50 bytes needs ceil(50/16) = 4 fragments
        assert_eq!(fragments.len(), 4);

        // Verify first fragment
        let header0 = FragmentHeader::from_bytes(&fragments[0]).unwrap();
        assert_eq!(header0.sequence, 0);
        assert_eq!(header0.total, 4);
        assert!(header0.flags.is_first());
        assert!(!header0.flags.is_last());

        // Verify middle fragments
        let header1 = FragmentHeader::from_bytes(&fragments[1]).unwrap();
        assert_eq!(header1.sequence, 1);
        assert!(!header1.flags.is_first());
        assert!(!header1.flags.is_last());

        let header2 = FragmentHeader::from_bytes(&fragments[2]).unwrap();
        assert_eq!(header2.sequence, 2);
        assert!(!header2.flags.is_first());
        assert!(!header2.flags.is_last());

        // Verify last fragment
        let header3 = FragmentHeader::from_bytes(&fragments[3]).unwrap();
        assert_eq!(header3.sequence, 3);
        assert!(!header3.flags.is_first());
        assert!(header3.flags.is_last());
    }

    #[test]
    fn test_reassemble_single_fragment() {
        let mut transport = BleTransport::with_mtu(100);
        let msg = b"Hello, BLE!";
        let fragments = transport.fragment_for_mtu(msg);

        let reassembled = transport.reassemble(&fragments).unwrap();
        assert_eq!(reassembled, msg);
    }

    #[test]
    fn test_reassemble_multiple_fragments() {
        let mut transport = BleTransport::with_mtu(MIN_BLE_MTU);
        let msg: Vec<u8> = (0..50).collect();
        let fragments = transport.fragment_for_mtu(&msg);

        let reassembled = transport.reassemble(&fragments).unwrap();
        assert_eq!(reassembled, msg);
    }

    #[test]
    fn test_reassemble_empty_fragments() {
        let transport = BleTransport::new();
        let result = transport.reassemble(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_reassemble_mismatched_total() {
        let mut transport = BleTransport::with_mtu(MIN_BLE_MTU);
        let msg: Vec<u8> = (0..50).collect();
        let mut fragments = transport.fragment_for_mtu(&msg);

        // Remove a fragment
        fragments.pop();

        let result = transport.reassemble(&fragments);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Expected"));
    }

    #[test]
    fn test_reassemble_mismatched_message_id() {
        let mut transport = BleTransport::with_mtu(MIN_BLE_MTU);

        // Create first message's fragments
        let msg1: Vec<u8> = (0..30).collect();
        let mut fragments1 = transport.fragment_for_mtu(&msg1);

        // Create second message's fragments
        let msg2: Vec<u8> = (30..60).collect();
        let fragments2 = transport.fragment_for_mtu(&msg2);

        // Mix fragments from different messages
        fragments1[1] = fragments2[1].clone();

        let result = transport.reassemble(&fragments1);
        assert!(result.is_err());
    }

    #[test]
    fn test_reassemble_wrong_sequence() {
        let mut transport = BleTransport::with_mtu(MIN_BLE_MTU);
        let msg: Vec<u8> = (0..50).collect();
        let mut fragments = transport.fragment_for_mtu(&msg);

        // Swap fragments out of order
        fragments.swap(1, 2);

        let result = transport.reassemble(&fragments);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("sequence mismatch"));
    }

    #[test]
    fn test_create_gatt_write() {
        let mut transport = BleTransport::with_mtu(100);
        let data = b"Proof data";

        let writes = transport.create_gatt_write(GattCharacteristic::ProofData, data);

        assert_eq!(writes.len(), 1);
        assert_eq!(&writes[0][FRAGMENT_HEADER_SIZE..], data);
    }

    #[test]
    fn test_parse_gatt_read() {
        let mut transport = BleTransport::with_mtu(100);
        let data = b"Test data";
        let fragments = transport.fragment_for_mtu(data);

        let (header, payload) = transport.parse_gatt_read(&fragments[0]).unwrap();

        assert_eq!(header.sequence, 0);
        assert_eq!(header.total, 1);
        assert!(header.flags.is_single());
        assert_eq!(payload, data);
    }

    #[test]
    fn test_builder_default() {
        let transport = BleTransportBuilder::new().build();
        assert_eq!(transport.mtu(), DEFAULT_BLE_MTU);
    }

    #[test]
    fn test_builder_custom_mtu() {
        let transport = BleTransportBuilder::new()
            .mtu(256)
            .build();
        assert_eq!(transport.mtu(), 256);
    }

    #[test]
    fn test_builder_mtu_clamping() {
        let transport = BleTransportBuilder::new()
            .mtu(1000)
            .build();
        assert_eq!(transport.mtu(), MAX_BLE_MTU);
    }

    #[test]
    fn test_message_id_counter_wraps() {
        let mut transport = BleTransport::new();

        // Advance counter near wrap point
        transport.message_id_counter = 254;

        let _ = transport.fragment_for_mtu(b"msg1"); // Uses 254
        let _ = transport.fragment_for_mtu(b"msg2"); // Uses 255
        let fragments = transport.fragment_for_mtu(b"msg3"); // Uses 0 (wrapped)

        let header = FragmentHeader::from_bytes(&fragments[0]).unwrap();
        assert_eq!(header.message_id, 0);
    }

    #[test]
    fn test_roundtrip_various_sizes() {
        let mut transport = BleTransport::with_mtu(50);

        // Test various message sizes
        for size in [0, 1, 10, 43, 44, 45, 100, 500, 1000] {
            let msg: Vec<u8> = (0..size).map(|i| i as u8).collect();
            let fragments = transport.fragment_for_mtu(&msg);
            let reassembled = transport.reassemble(&fragments).unwrap();
            assert_eq!(reassembled, msg, "Failed for size {}", size);
        }
    }

    #[test]
    fn test_session_manager_access() {
        let mut transport = BleTransport::new();

        // Test immutable access
        let _ = transport.session_manager();

        // Test mutable access
        let session_manager = transport.session_manager_mut();
        let result = session_manager.initiate();
        assert!(result.is_ok());
    }
}
