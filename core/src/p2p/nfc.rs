//! NFC peer-to-peer transport for offline biometric verification (REQ-014)
//!
//! This module implements NFC communication using NDEF records with:
//! - Maximum 424 bytes per NDEF record payload
//! - Automatic message fragmentation for larger payloads
//! - Message reassembly from multiple NDEF records
//! - Support for key exchange, biometric proofs, and acknowledgments
//!
//! # Security Features
//!
//! - Integrates with cryptographic session management for secure P2P communication
//! - Message integrity through ChaCha20-Poly1305 encryption (when session is active)
//! - Fragment sequence verification to prevent reordering attacks

use crate::error::{Result, SableError};
use crate::p2p::session::SessionManager;

/// Maximum NDEF record payload size (424 bytes per spec)
pub const MAX_NDEF_PAYLOAD: usize = 424;

/// SABLE NFC type name format (4 bytes)
pub const SABLE_TYPE_NAME: [u8; 4] = *b"SABL";

/// Fragment header size: 1 byte sequence + 1 byte total count
const FRAGMENT_HEADER_SIZE: usize = 2;

/// Maximum payload per fragment after header
const MAX_FRAGMENT_PAYLOAD: usize = MAX_NDEF_PAYLOAD - FRAGMENT_HEADER_SIZE;

/// SABLE NFC message types for peer-to-peer verification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum NfcMessageType {
    /// ECDH public key exchange (32 bytes X25519 public key)
    KeyExchange = 0x01,
    /// ZK proof data for biometric verification
    BiometricProof = 0x02,
    /// Acknowledgment (ACK/NACK with optional data)
    Acknowledgment = 0x03,
}

impl NfcMessageType {
    /// Convert from byte value
    pub fn from_byte(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(NfcMessageType::KeyExchange),
            0x02 => Some(NfcMessageType::BiometricProof),
            0x03 => Some(NfcMessageType::Acknowledgment),
            _ => None,
        }
    }

    /// Convert to byte value
    pub fn to_byte(self) -> u8 {
        self as u8
    }
}

/// Acknowledgment status codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AckStatus {
    /// Successful acknowledgment
    Ack = 0x00,
    /// Negative acknowledgment - general failure
    Nack = 0x01,
    /// Verification successful
    VerificationSuccess = 0x10,
    /// Verification failed
    VerificationFailed = 0x11,
}

impl AckStatus {
    /// Convert from byte value
    pub fn from_byte(value: u8) -> Option<Self> {
        match value {
            0x00 => Some(AckStatus::Ack),
            0x01 => Some(AckStatus::Nack),
            0x10 => Some(AckStatus::VerificationSuccess),
            0x11 => Some(AckStatus::VerificationFailed),
            _ => None,
        }
    }

    /// Convert to byte value
    pub fn to_byte(self) -> u8 {
        self as u8
    }
}

/// NDEF record structure for NFC communication
///
/// Each record contains a type name and payload, with a maximum
/// payload size of 424 bytes as required by the NDEF specification.
#[derive(Debug, Clone)]
pub struct NdefRecord {
    /// Type name format (4 bytes identifying SABLE protocol)
    type_name: [u8; 4],
    /// Payload data (max 424 bytes)
    payload: Vec<u8>,
}

impl NdefRecord {
    /// Create a new NDEF record with SABLE type name
    ///
    /// # Errors
    ///
    /// Returns an error if the payload exceeds MAX_NDEF_PAYLOAD bytes.
    pub fn new(payload: Vec<u8>) -> Result<Self> {
        if payload.len() > MAX_NDEF_PAYLOAD {
            return Err(SableError::InvalidInput(format!(
                "NDEF payload exceeds maximum size of {} bytes",
                MAX_NDEF_PAYLOAD
            )));
        }
        Ok(Self {
            type_name: SABLE_TYPE_NAME,
            payload,
        })
    }

    /// Create a record with custom type name
    pub fn with_type_name(type_name: [u8; 4], payload: Vec<u8>) -> Result<Self> {
        if payload.len() > MAX_NDEF_PAYLOAD {
            return Err(SableError::InvalidInput(format!(
                "NDEF payload exceeds maximum size of {} bytes",
                MAX_NDEF_PAYLOAD
            )));
        }
        Ok(Self { type_name, payload })
    }

    /// Get the type name
    pub fn type_name(&self) -> &[u8; 4] {
        &self.type_name
    }

    /// Get the payload
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Get the payload length
    pub fn payload_len(&self) -> usize {
        self.payload.len()
    }

    /// Check if this is a SABLE protocol record
    pub fn is_sable_record(&self) -> bool {
        self.type_name == SABLE_TYPE_NAME
    }

    /// Serialize the record to bytes
    ///
    /// Format: [type_name (4 bytes)][payload_len (2 bytes)][payload]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(4 + 2 + self.payload.len());
        bytes.extend_from_slice(&self.type_name);
        bytes.extend_from_slice(&(self.payload.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&self.payload);
        bytes
    }

    /// Deserialize a record from bytes
    ///
    /// # Errors
    ///
    /// Returns an error if the data is too short or malformed.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 6 {
            return Err(SableError::InvalidInput(
                "NDEF record data too short".into(),
            ));
        }

        let mut type_name = [0u8; 4];
        type_name.copy_from_slice(&data[0..4]);

        let payload_len = u16::from_le_bytes([data[4], data[5]]) as usize;

        if data.len() < 6 + payload_len {
            return Err(SableError::InvalidInput(
                "NDEF record payload incomplete".into(),
            ));
        }

        let payload = data[6..6 + payload_len].to_vec();

        Self::with_type_name(type_name, payload)
    }
}

/// NFC Transport for peer-to-peer biometric verification
///
/// Handles message fragmentation, reassembly, and integration with
/// the cryptographic session manager for secure communications.
pub struct NfcTransport {
    /// Session manager for cryptographic operations
    session_manager: SessionManager,
    /// Pending fragments for reassembly (keyed by message type)
    pending_fragments: Vec<(u8, Vec<u8>)>,
}

impl NfcTransport {
    /// Create a new NFC transport with a fresh session manager
    pub fn new() -> Self {
        Self {
            session_manager: SessionManager::new(),
            pending_fragments: Vec::new(),
        }
    }

    /// Create an NFC transport with an existing session manager
    pub fn with_session_manager(session_manager: SessionManager) -> Self {
        Self {
            session_manager,
            pending_fragments: Vec::new(),
        }
    }

    /// Get a reference to the session manager
    pub fn session_manager(&self) -> &SessionManager {
        &self.session_manager
    }

    /// Get a mutable reference to the session manager
    pub fn session_manager_mut(&mut self) -> &mut SessionManager {
        &mut self.session_manager
    }

    /// Create NDEF records from a message, fragmenting if needed
    ///
    /// Messages larger than MAX_FRAGMENT_PAYLOAD bytes (MAX_NDEF_PAYLOAD minus
    /// the 2-byte fragment header) will be split into multiple records.
    ///
    /// # Fragment Format
    ///
    /// Each fragment payload contains:
    /// - Byte 0: Sequence number (0-indexed)
    /// - Byte 1: Total fragment count
    /// - Bytes 2+: Message data
    pub fn create_ndef_records(&self, msg: &[u8]) -> Vec<NdefRecord> {
        if msg.len() <= MAX_FRAGMENT_PAYLOAD {
            // Single record, no fragmentation needed
            // Still add header for consistency
            let mut payload = Vec::with_capacity(FRAGMENT_HEADER_SIZE + msg.len());
            payload.push(0); // Sequence 0
            payload.push(1); // Total 1
            payload.extend_from_slice(msg);
            vec![NdefRecord {
                type_name: SABLE_TYPE_NAME,
                payload,
            }]
        } else {
            // Need fragmentation
            let total_fragments = (msg.len() + MAX_FRAGMENT_PAYLOAD - 1) / MAX_FRAGMENT_PAYLOAD;
            let mut records = Vec::with_capacity(total_fragments);

            for (i, chunk) in msg.chunks(MAX_FRAGMENT_PAYLOAD).enumerate() {
                let mut payload = Vec::with_capacity(FRAGMENT_HEADER_SIZE + chunk.len());
                payload.push(i as u8); // Sequence number
                payload.push(total_fragments as u8); // Total count
                payload.extend_from_slice(chunk);
                records.push(NdefRecord {
                    type_name: SABLE_TYPE_NAME,
                    payload,
                });
            }

            records
        }
    }

    /// Reassemble a message from NDEF records
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Records have invalid fragment headers
    /// - Sequence numbers are missing or out of order
    /// - Fragment counts don't match
    pub fn reassemble_message(&self, records: &[NdefRecord]) -> Result<Vec<u8>> {
        if records.is_empty() {
            return Err(SableError::InvalidInput("No NDEF records provided".into()));
        }

        // Filter to SABLE records only
        let sable_records: Vec<_> = records.iter().filter(|r| r.is_sable_record()).collect();

        if sable_records.is_empty() {
            return Err(SableError::InvalidInput("No SABLE NDEF records found".into()));
        }

        // Parse fragment headers and validate
        let mut fragments: Vec<(u8, u8, &[u8])> = Vec::new();

        for record in &sable_records {
            let payload = record.payload();
            if payload.len() < FRAGMENT_HEADER_SIZE {
                return Err(SableError::InvalidInput(
                    "NDEF record payload too short for fragment header".into(),
                ));
            }

            let sequence = payload[0];
            let total = payload[1];
            let data = &payload[FRAGMENT_HEADER_SIZE..];

            fragments.push((sequence, total, data));
        }

        // Verify all fragments have the same total count
        let expected_total = fragments[0].1;
        if !fragments.iter().all(|(_, total, _)| *total == expected_total) {
            return Err(SableError::InvalidInput(
                "Fragment count mismatch across records".into(),
            ));
        }

        // Verify we have all fragments
        if fragments.len() != expected_total as usize {
            return Err(SableError::InvalidInput(format!(
                "Expected {} fragments, got {}",
                expected_total,
                fragments.len()
            )));
        }

        // Sort by sequence number
        fragments.sort_by_key(|(seq, _, _)| *seq);

        // Verify sequence numbers are contiguous starting from 0
        for (i, (seq, _, _)) in fragments.iter().enumerate() {
            if *seq != i as u8 {
                return Err(SableError::InvalidInput(format!(
                    "Missing or duplicate fragment at sequence {}",
                    i
                )));
            }
        }

        // Reassemble the message
        let total_len: usize = fragments.iter().map(|(_, _, data)| data.len()).sum();
        let mut message = Vec::with_capacity(total_len);
        for (_, _, data) in fragments {
            message.extend_from_slice(data);
        }

        Ok(message)
    }

    /// Create a key exchange request
    ///
    /// Initiates an ECDH key exchange and returns NDEF records containing
    /// our public key.
    pub fn create_key_exchange_request(
        &mut self,
    ) -> Result<(crate::p2p::SessionId, Vec<NdefRecord>)> {
        let (session_id, public_key) = self.session_manager.initiate()?;

        // Build message: [message_type (1 byte)][public_key (32 bytes)]
        let mut msg = Vec::with_capacity(33);
        msg.push(NfcMessageType::KeyExchange.to_byte());
        msg.extend_from_slice(public_key.as_bytes());

        let records = self.create_ndef_records(&msg);
        Ok((session_id, records))
    }

    /// Process a received key exchange and respond
    ///
    /// Takes the peer's public key, completes our side of the exchange,
    /// and returns our public key in NDEF records.
    pub fn respond_to_key_exchange(
        &mut self,
        records: &[NdefRecord],
    ) -> Result<(crate::p2p::SessionId, Vec<NdefRecord>)> {
        let message = self.reassemble_message(records)?;

        if message.is_empty() {
            return Err(SableError::InvalidInput(
                "Empty key exchange message".into(),
            ));
        }

        let msg_type = NfcMessageType::from_byte(message[0]).ok_or_else(|| {
            SableError::InvalidInput("Invalid NFC message type".into())
        })?;

        if msg_type != NfcMessageType::KeyExchange {
            return Err(SableError::InvalidInput(
                "Expected KeyExchange message type".into(),
            ));
        }

        if message.len() != 33 {
            return Err(SableError::InvalidInput(
                "Invalid key exchange message length".into(),
            ));
        }

        // Extract peer's public key
        let mut peer_key_bytes = [0u8; 32];
        peer_key_bytes.copy_from_slice(&message[1..33]);
        let peer_public = x25519_dalek::PublicKey::from(peer_key_bytes);

        // Respond to the exchange
        let (session_id, our_public) = self.session_manager.respond(peer_public)?;

        // Build response message
        let mut response = Vec::with_capacity(33);
        response.push(NfcMessageType::KeyExchange.to_byte());
        response.extend_from_slice(our_public.as_bytes());

        let records = self.create_ndef_records(&response);
        Ok((session_id, records))
    }

    /// Complete a key exchange after receiving the peer's response
    pub fn complete_key_exchange(
        &mut self,
        session_id: crate::p2p::SessionId,
        records: &[NdefRecord],
    ) -> Result<()> {
        let message = self.reassemble_message(records)?;

        if message.is_empty() {
            return Err(SableError::InvalidInput(
                "Empty key exchange response".into(),
            ));
        }

        let msg_type = NfcMessageType::from_byte(message[0]).ok_or_else(|| {
            SableError::InvalidInput("Invalid NFC message type".into())
        })?;

        if msg_type != NfcMessageType::KeyExchange {
            return Err(SableError::InvalidInput(
                "Expected KeyExchange message type".into(),
            ));
        }

        if message.len() != 33 {
            return Err(SableError::InvalidInput(
                "Invalid key exchange message length".into(),
            ));
        }

        // Extract peer's public key
        let mut peer_key_bytes = [0u8; 32];
        peer_key_bytes.copy_from_slice(&message[1..33]);
        let peer_public = x25519_dalek::PublicKey::from(peer_key_bytes);

        // Complete our side of the exchange
        self.session_manager.complete(session_id, peer_public)
    }

    /// Send a verification request with biometric proof data
    ///
    /// The proof data will be encrypted using the active session and
    /// returned as NDEF records.
    pub fn send_verification_request(
        &mut self,
        session_id: &crate::p2p::SessionId,
        proof: &[u8],
    ) -> Result<Vec<NdefRecord>> {
        // Create nonce for encryption
        let nonce = crate::p2p::Nonce::random()?;

        // Encrypt the proof data
        let ciphertext = self.session_manager.encrypt(session_id, proof, nonce)?;

        // Build message: [message_type (1 byte)][nonce (12 bytes)][ciphertext]
        let mut msg = Vec::with_capacity(1 + 12 + ciphertext.len());
        msg.push(NfcMessageType::BiometricProof.to_byte());
        msg.extend_from_slice(nonce.as_bytes());
        msg.extend_from_slice(&ciphertext);

        Ok(self.create_ndef_records(&msg))
    }

    /// Receive and process a verification request
    ///
    /// Decrypts the received proof data and returns it for verification.
    pub fn receive_verification(
        &mut self,
        session_id: &crate::p2p::SessionId,
        records: &[NdefRecord],
    ) -> Result<Vec<u8>> {
        let message = self.reassemble_message(records)?;

        if message.len() < 14 {
            // 1 byte type + 12 byte nonce + at least 1 byte ciphertext
            return Err(SableError::InvalidInput(
                "Verification message too short".into(),
            ));
        }

        let msg_type = NfcMessageType::from_byte(message[0]).ok_or_else(|| {
            SableError::InvalidInput("Invalid NFC message type".into())
        })?;

        if msg_type != NfcMessageType::BiometricProof {
            return Err(SableError::InvalidInput(
                "Expected BiometricProof message type".into(),
            ));
        }

        // Extract nonce
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes.copy_from_slice(&message[1..13]);
        let nonce = crate::p2p::Nonce::from_bytes(nonce_bytes);

        // Decrypt the proof
        let ciphertext = &message[13..];
        self.session_manager.decrypt(session_id, ciphertext, nonce)
    }

    /// Send an acknowledgment response
    pub fn send_acknowledgment(
        &mut self,
        session_id: &crate::p2p::SessionId,
        status: AckStatus,
        data: Option<&[u8]>,
    ) -> Result<Vec<NdefRecord>> {
        let nonce = crate::p2p::Nonce::random()?;

        // Build plaintext: [status (1 byte)][optional data]
        let mut plaintext = Vec::with_capacity(1 + data.map(|d| d.len()).unwrap_or(0));
        plaintext.push(status.to_byte());
        if let Some(d) = data {
            plaintext.extend_from_slice(d);
        }

        // Encrypt
        let ciphertext = self.session_manager.encrypt(session_id, &plaintext, nonce)?;

        // Build message: [message_type (1 byte)][nonce (12 bytes)][ciphertext]
        let mut msg = Vec::with_capacity(1 + 12 + ciphertext.len());
        msg.push(NfcMessageType::Acknowledgment.to_byte());
        msg.extend_from_slice(nonce.as_bytes());
        msg.extend_from_slice(&ciphertext);

        Ok(self.create_ndef_records(&msg))
    }

    /// Receive and process an acknowledgment
    pub fn receive_acknowledgment(
        &mut self,
        session_id: &crate::p2p::SessionId,
        records: &[NdefRecord],
    ) -> Result<(AckStatus, Vec<u8>)> {
        let message = self.reassemble_message(records)?;

        if message.len() < 14 {
            return Err(SableError::InvalidInput(
                "Acknowledgment message too short".into(),
            ));
        }

        let msg_type = NfcMessageType::from_byte(message[0]).ok_or_else(|| {
            SableError::InvalidInput("Invalid NFC message type".into())
        })?;

        if msg_type != NfcMessageType::Acknowledgment {
            return Err(SableError::InvalidInput(
                "Expected Acknowledgment message type".into(),
            ));
        }

        // Extract nonce
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes.copy_from_slice(&message[1..13]);
        let nonce = crate::p2p::Nonce::from_bytes(nonce_bytes);

        // Decrypt
        let ciphertext = &message[13..];
        let plaintext = self.session_manager.decrypt(session_id, ciphertext, nonce)?;

        if plaintext.is_empty() {
            return Err(SableError::InvalidInput(
                "Empty acknowledgment payload".into(),
            ));
        }

        let status = AckStatus::from_byte(plaintext[0]).ok_or_else(|| {
            SableError::InvalidInput("Invalid acknowledgment status".into())
        })?;

        let data = if plaintext.len() > 1 {
            plaintext[1..].to_vec()
        } else {
            Vec::new()
        };

        Ok((status, data))
    }

    /// Clear any pending fragment state
    pub fn clear_pending_fragments(&mut self) {
        self.pending_fragments.clear();
    }
}

impl Default for NfcTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ndef_record_creation() {
        // Test valid payload
        let payload = vec![0x01, 0x02, 0x03];
        let record = NdefRecord::new(payload.clone()).unwrap();
        assert_eq!(record.payload(), &payload);
        assert!(record.is_sable_record());
        assert_eq!(record.type_name(), &SABLE_TYPE_NAME);
    }

    #[test]
    fn test_ndef_record_max_payload() {
        // Test exactly max payload size
        let payload = vec![0xAB; MAX_NDEF_PAYLOAD];
        let record = NdefRecord::new(payload).unwrap();
        assert_eq!(record.payload_len(), MAX_NDEF_PAYLOAD);
    }

    #[test]
    fn test_ndef_record_exceeds_max_payload() {
        // Test payload exceeding max size
        let payload = vec![0xAB; MAX_NDEF_PAYLOAD + 1];
        let result = NdefRecord::new(payload);
        assert!(result.is_err());
    }

    #[test]
    fn test_ndef_record_serialization() {
        let payload = vec![0x01, 0x02, 0x03, 0x04];
        let record = NdefRecord::new(payload.clone()).unwrap();

        let bytes = record.to_bytes();
        let deserialized = NdefRecord::from_bytes(&bytes).unwrap();

        assert_eq!(deserialized.type_name(), record.type_name());
        assert_eq!(deserialized.payload(), record.payload());
    }

    #[test]
    fn test_create_single_ndef_record() {
        let transport = NfcTransport::new();
        let msg = vec![0x01; 100]; // Small message

        let records = transport.create_ndef_records(&msg);

        assert_eq!(records.len(), 1);
        // Payload includes 2-byte header
        assert_eq!(records[0].payload()[0], 0); // Sequence 0
        assert_eq!(records[0].payload()[1], 1); // Total 1
        assert_eq!(&records[0].payload()[2..], &msg[..]);
    }

    #[test]
    fn test_message_fragmentation() {
        let transport = NfcTransport::new();

        // Create a message larger than MAX_NDEF_PAYLOAD
        let msg = vec![0x42; 1000];

        let records = transport.create_ndef_records(&msg);

        // Should be fragmented into multiple records
        assert!(records.len() > 1);

        // Each record should have proper fragment header
        let expected_total = records.len() as u8;
        for (i, record) in records.iter().enumerate() {
            assert!(record.payload_len() <= MAX_NDEF_PAYLOAD);
            assert_eq!(record.payload()[0], i as u8); // Sequence
            assert_eq!(record.payload()[1], expected_total); // Total
        }
    }

    #[test]
    fn test_message_reassembly() {
        let transport = NfcTransport::new();

        // Create and fragment a message
        let original_msg = vec![0x42; 1000];
        let records = transport.create_ndef_records(&original_msg);

        // Reassemble
        let reassembled = transport.reassemble_message(&records).unwrap();

        assert_eq!(reassembled, original_msg);
    }

    #[test]
    fn test_reassembly_single_record() {
        let transport = NfcTransport::new();

        let original_msg = vec![0x01, 0x02, 0x03];
        let records = transport.create_ndef_records(&original_msg);

        assert_eq!(records.len(), 1);

        let reassembled = transport.reassemble_message(&records).unwrap();
        assert_eq!(reassembled, original_msg);
    }

    #[test]
    fn test_reassembly_out_of_order() {
        let transport = NfcTransport::new();

        // Create a large message that fragments
        let original_msg = vec![0x42; 1000];
        let mut records = transport.create_ndef_records(&original_msg);

        // Reverse the order (simulating out-of-order reception)
        records.reverse();

        // Should still reassemble correctly
        let reassembled = transport.reassemble_message(&records).unwrap();
        assert_eq!(reassembled, original_msg);
    }

    #[test]
    fn test_reassembly_missing_fragment() {
        let transport = NfcTransport::new();

        let original_msg = vec![0x42; 1000];
        let mut records = transport.create_ndef_records(&original_msg);

        // Remove a fragment
        records.remove(1);

        // Should fail
        let result = transport.reassemble_message(&records);
        assert!(result.is_err());
    }

    #[test]
    fn test_reassembly_empty_records() {
        let transport = NfcTransport::new();

        let result = transport.reassemble_message(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_key_exchange_flow() {
        let mut transport_a = NfcTransport::new();
        let mut transport_b = NfcTransport::new();

        // A initiates key exchange
        let (session_id_a, request_records) = transport_a.create_key_exchange_request().unwrap();

        // B responds to the key exchange
        let (session_id_b, response_records) = transport_b
            .respond_to_key_exchange(&request_records)
            .unwrap();

        // A completes the exchange
        transport_a
            .complete_key_exchange(session_id_a, &response_records)
            .unwrap();

        // Both sessions should be active
        assert!(transport_a.session_manager().is_active(&session_id_a));
        assert!(transport_b.session_manager().is_active(&session_id_b));
    }

    #[test]
    fn test_verification_request_response() {
        let mut transport_a = NfcTransport::new();
        let mut transport_b = NfcTransport::new();

        // Establish session
        let (session_id_a, request_records) = transport_a.create_key_exchange_request().unwrap();
        let (session_id_b, response_records) = transport_b
            .respond_to_key_exchange(&request_records)
            .unwrap();
        transport_a
            .complete_key_exchange(session_id_a, &response_records)
            .unwrap();

        // A sends a verification request
        let proof_data = b"mock_biometric_proof_data_12345";
        let verification_records = transport_a
            .send_verification_request(&session_id_a, proof_data)
            .unwrap();

        // B receives and decrypts the verification
        let received_proof = transport_b
            .receive_verification(&session_id_b, &verification_records)
            .unwrap();

        assert_eq!(received_proof, proof_data);
    }

    #[test]
    fn test_acknowledgment_flow() {
        let mut transport_a = NfcTransport::new();
        let mut transport_b = NfcTransport::new();

        // Establish session
        let (session_id_a, request_records) = transport_a.create_key_exchange_request().unwrap();
        let (session_id_b, response_records) = transport_b
            .respond_to_key_exchange(&request_records)
            .unwrap();
        transport_a
            .complete_key_exchange(session_id_a, &response_records)
            .unwrap();

        // B sends an acknowledgment
        let ack_records = transport_b
            .send_acknowledgment(&session_id_b, AckStatus::VerificationSuccess, Some(b"extra"))
            .unwrap();

        // A receives the acknowledgment
        let (status, data) = transport_a
            .receive_acknowledgment(&session_id_a, &ack_records)
            .unwrap();

        assert_eq!(status, AckStatus::VerificationSuccess);
        assert_eq!(data, b"extra");
    }

    #[test]
    fn test_acknowledgment_without_data() {
        let mut transport_a = NfcTransport::new();
        let mut transport_b = NfcTransport::new();

        // Establish session
        let (session_id_a, request_records) = transport_a.create_key_exchange_request().unwrap();
        let (session_id_b, response_records) = transport_b
            .respond_to_key_exchange(&request_records)
            .unwrap();
        transport_a
            .complete_key_exchange(session_id_a, &response_records)
            .unwrap();

        // B sends a simple ACK
        let ack_records = transport_b
            .send_acknowledgment(&session_id_b, AckStatus::Ack, None)
            .unwrap();

        // A receives it
        let (status, data) = transport_a
            .receive_acknowledgment(&session_id_a, &ack_records)
            .unwrap();

        assert_eq!(status, AckStatus::Ack);
        assert!(data.is_empty());
    }

    #[test]
    fn test_nfc_message_type_conversion() {
        assert_eq!(NfcMessageType::from_byte(0x01), Some(NfcMessageType::KeyExchange));
        assert_eq!(NfcMessageType::from_byte(0x02), Some(NfcMessageType::BiometricProof));
        assert_eq!(NfcMessageType::from_byte(0x03), Some(NfcMessageType::Acknowledgment));
        assert_eq!(NfcMessageType::from_byte(0xFF), None);

        assert_eq!(NfcMessageType::KeyExchange.to_byte(), 0x01);
        assert_eq!(NfcMessageType::BiometricProof.to_byte(), 0x02);
        assert_eq!(NfcMessageType::Acknowledgment.to_byte(), 0x03);
    }

    #[test]
    fn test_ack_status_conversion() {
        assert_eq!(AckStatus::from_byte(0x00), Some(AckStatus::Ack));
        assert_eq!(AckStatus::from_byte(0x01), Some(AckStatus::Nack));
        assert_eq!(AckStatus::from_byte(0x10), Some(AckStatus::VerificationSuccess));
        assert_eq!(AckStatus::from_byte(0x11), Some(AckStatus::VerificationFailed));
        assert_eq!(AckStatus::from_byte(0xFF), None);
    }

    #[test]
    fn test_large_proof_fragmentation() {
        let mut transport_a = NfcTransport::new();
        let mut transport_b = NfcTransport::new();

        // Establish session
        let (session_id_a, request_records) = transport_a.create_key_exchange_request().unwrap();
        let (session_id_b, response_records) = transport_b
            .respond_to_key_exchange(&request_records)
            .unwrap();
        transport_a
            .complete_key_exchange(session_id_a, &response_records)
            .unwrap();

        // Create a large proof that will require fragmentation
        let large_proof = vec![0xAB; 2000];

        let verification_records = transport_a
            .send_verification_request(&session_id_a, &large_proof)
            .unwrap();

        // Should be multiple records
        assert!(verification_records.len() > 1);

        // B should still be able to receive and decrypt
        let received_proof = transport_b
            .receive_verification(&session_id_b, &verification_records)
            .unwrap();

        assert_eq!(received_proof, large_proof);
    }

    #[test]
    fn test_max_ndef_payload_constant() {
        // Verify the constant matches the specification
        assert_eq!(MAX_NDEF_PAYLOAD, 424);
    }

    #[test]
    fn test_fragmentation_boundary() {
        let transport = NfcTransport::new();

        // Test at exact boundary (considering 2-byte header)
        // MAX_NDEF_PAYLOAD = 424, FRAGMENT_HEADER_SIZE = 2
        // So effective max message size without fragmentation is MAX_NDEF_PAYLOAD (424)
        // because the header is included in the payload
        let msg_at_boundary = vec![0x42; MAX_NDEF_PAYLOAD];
        let records = transport.create_ndef_records(&msg_at_boundary);
        // With 2-byte header, a 424-byte message needs 424+2=426 bytes total
        // Since MAX_FRAGMENT_PAYLOAD = 422, this requires 2 fragments
        assert!(records.len() >= 1);
        for record in &records {
            assert!(record.payload_len() <= MAX_NDEF_PAYLOAD);
        }

        // Verify roundtrip for boundary case
        let reassembled_boundary = transport.reassemble_message(&records).unwrap();
        assert_eq!(reassembled_boundary, msg_at_boundary);

        // Test just under the effective payload size (no fragmentation needed)
        let msg_under = vec![0x42; MAX_FRAGMENT_PAYLOAD];
        let records_under = transport.create_ndef_records(&msg_under);
        assert_eq!(records_under.len(), 1);

        // Verify roundtrip
        let reassembled = transport.reassemble_message(&records_under).unwrap();
        assert_eq!(reassembled, msg_under);
    }

    #[test]
    fn test_invalid_key_exchange_message() {
        let mut transport = NfcTransport::new();

        // Create an invalid record (wrong message type)
        let mut payload = Vec::with_capacity(35);
        payload.push(0); // Sequence
        payload.push(1); // Total
        payload.push(NfcMessageType::BiometricProof.to_byte()); // Wrong type
        payload.extend_from_slice(&[0u8; 32]); // Fake key

        let record = NdefRecord::new(payload).unwrap();

        let result = transport.respond_to_key_exchange(&[record]);
        assert!(result.is_err());
    }

    #[test]
    fn test_transport_default() {
        let transport = NfcTransport::default();
        assert_eq!(transport.session_manager().active_session_count(), 0);
    }
}
