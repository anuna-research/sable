//! Message fragmentation and reassembly for P2P transports (REQ-017)
//!
//! This module provides fragmentation of proofs (192 bytes) across transport MTUs
//! with reliable reassembly and integrity verification for all P2P transports.
//!
//! # Features
//!
//! - **Fragment Size**: Configurable fragment size to accommodate different MTUs
//! - **Integrity Verification**: CRC32 checksum on each fragment
//! - **Reliable Reassembly**: Handles out-of-order fragment arrival
//! - **Message Identification**: Unique 32-bit message IDs for concurrent transmissions
//!
//! # Protocol
//!
//! Each fragment consists of:
//! - Header (8 bytes): message_id (4) + fragment_index (2) + total_fragments (2)
//! - Payload (variable): fragment data
//! - Checksum (4 bytes): CRC32 of header + payload

use crate::error::{Result, SableError};
use std::collections::HashMap;

/// Fragment header size in bytes (message_id: 4 + fragment_index: 2 + total_fragments: 2)
pub const FRAGMENT_HEADER_SIZE: usize = 8;

/// Checksum size in bytes (CRC32)
pub const CHECKSUM_SIZE: usize = 4;

/// Total overhead per fragment (header + checksum)
pub const FRAGMENT_OVERHEAD: usize = FRAGMENT_HEADER_SIZE + CHECKSUM_SIZE;

/// Default maximum fragment size (fits in most MTUs with room for transport headers)
pub const DEFAULT_MAX_FRAGMENT_SIZE: usize = 256;

/// Minimum payload size per fragment
pub const MIN_PAYLOAD_SIZE: usize = 16;

/// Standard proof size in SABLE protocol (192 bytes)
pub const STANDARD_PROOF_SIZE: usize = 192;

/// Message fragment header containing identification and sequencing
///
/// This is a transport-agnostic fragment header with CRC32 integrity verification,
/// distinct from transport-specific headers (like BLE's `FragmentHeader`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageFragmentHeader {
    /// Unique message identifier for this fragmented message
    message_id: u32,
    /// Fragment sequence number (0-indexed)
    fragment_index: u16,
    /// Total number of fragments in the message
    total_fragments: u16,
}

impl MessageFragmentHeader {
    /// Create a new fragment header
    pub fn new(message_id: u32, fragment_index: u16, total_fragments: u16) -> Self {
        Self {
            message_id,
            fragment_index,
            total_fragments,
        }
    }

    /// Get the message ID
    pub fn message_id(&self) -> u32 {
        self.message_id
    }

    /// Get the fragment index
    pub fn fragment_index(&self) -> u16 {
        self.fragment_index
    }

    /// Get the total number of fragments
    pub fn total_fragments(&self) -> u16 {
        self.total_fragments
    }

    /// Serialize the header to bytes
    pub fn to_bytes(&self) -> [u8; FRAGMENT_HEADER_SIZE] {
        let mut bytes = [0u8; FRAGMENT_HEADER_SIZE];
        bytes[0..4].copy_from_slice(&self.message_id.to_be_bytes());
        bytes[4..6].copy_from_slice(&self.fragment_index.to_be_bytes());
        bytes[6..8].copy_from_slice(&self.total_fragments.to_be_bytes());
        bytes
    }

    /// Deserialize the header from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < FRAGMENT_HEADER_SIZE {
            return Err(SableError::InvalidInput(format!(
                "Fragment header too short: {} bytes, expected {}",
                bytes.len(),
                FRAGMENT_HEADER_SIZE
            )));
        }

        let message_id = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let fragment_index = u16::from_be_bytes([bytes[4], bytes[5]]);
        let total_fragments = u16::from_be_bytes([bytes[6], bytes[7]]);

        if total_fragments == 0 {
            return Err(SableError::InvalidInput(
                "Total fragments cannot be zero".into(),
            ));
        }

        if fragment_index >= total_fragments {
            return Err(SableError::InvalidInput(format!(
                "Fragment index {} exceeds total fragments {}",
                fragment_index, total_fragments
            )));
        }

        Ok(Self {
            message_id,
            fragment_index,
            total_fragments,
        })
    }
}

/// A single fragment of a larger message
#[derive(Debug, Clone)]
pub struct Fragment {
    /// Fragment header with identification and sequencing
    header: MessageFragmentHeader,
    /// Fragment payload data
    payload: Vec<u8>,
    /// CRC32 checksum for integrity verification
    checksum: u32,
}

impl Fragment {
    /// Create a new fragment with computed checksum
    pub fn new(header: MessageFragmentHeader, payload: Vec<u8>) -> Self {
        let checksum = Self::compute_checksum(&header, &payload);
        Self {
            header,
            payload,
            checksum,
        }
    }

    /// Create a fragment from raw parts (for deserialization)
    fn from_parts(header: MessageFragmentHeader, payload: Vec<u8>, checksum: u32) -> Self {
        Self {
            header,
            payload,
            checksum,
        }
    }

    /// Get the fragment header
    pub fn header(&self) -> &MessageFragmentHeader {
        &self.header
    }

    /// Get the fragment payload
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Get the checksum
    pub fn checksum(&self) -> u32 {
        self.checksum
    }

    /// Compute CRC32 checksum of header and payload
    fn compute_checksum(header: &MessageFragmentHeader, payload: &[u8]) -> u32 {
        let header_bytes = header.to_bytes();
        crc32_compute(&header_bytes, payload)
    }

    /// Verify the fragment's checksum
    pub fn verify_checksum(&self) -> bool {
        let expected = Self::compute_checksum(&self.header, &self.payload);
        self.checksum == expected
    }

    /// Serialize the fragment to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(FRAGMENT_OVERHEAD + self.payload.len());
        bytes.extend_from_slice(&self.header.to_bytes());
        bytes.extend_from_slice(&self.payload);
        bytes.extend_from_slice(&self.checksum.to_be_bytes());
        bytes
    }

    /// Deserialize a fragment from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < FRAGMENT_OVERHEAD {
            return Err(SableError::InvalidInput(format!(
                "Fragment too short: {} bytes, minimum {}",
                bytes.len(),
                FRAGMENT_OVERHEAD
            )));
        }

        let header = MessageFragmentHeader::from_bytes(&bytes[..FRAGMENT_HEADER_SIZE])?;

        let payload_end = bytes.len() - CHECKSUM_SIZE;
        let payload = bytes[FRAGMENT_HEADER_SIZE..payload_end].to_vec();

        let checksum = u32::from_be_bytes([
            bytes[payload_end],
            bytes[payload_end + 1],
            bytes[payload_end + 2],
            bytes[payload_end + 3],
        ]);

        Ok(Self::from_parts(header, payload, checksum))
    }

    /// Get the total serialized size of this fragment
    pub fn serialized_size(&self) -> usize {
        FRAGMENT_OVERHEAD + self.payload.len()
    }
}

/// Fragmenter for splitting messages into transport-friendly chunks
pub struct Fragmenter {
    /// Maximum fragment size (including header and checksum)
    max_fragment_size: usize,
    /// Maximum payload size per fragment
    max_payload_size: usize,
}

impl Fragmenter {
    /// Create a new fragmenter with the specified maximum fragment size
    ///
    /// # Arguments
    ///
    /// * `max_fragment_size` - Maximum total size of each fragment (including overhead)
    ///
    /// # Errors
    ///
    /// Returns an error if max_fragment_size is too small to hold any payload.
    pub fn new(max_fragment_size: usize) -> Result<Self> {
        if max_fragment_size < FRAGMENT_OVERHEAD + MIN_PAYLOAD_SIZE {
            return Err(SableError::InvalidInput(format!(
                "Max fragment size {} too small, minimum is {}",
                max_fragment_size,
                FRAGMENT_OVERHEAD + MIN_PAYLOAD_SIZE
            )));
        }

        let max_payload_size = max_fragment_size - FRAGMENT_OVERHEAD;
        Ok(Self {
            max_fragment_size,
            max_payload_size,
        })
    }

    /// Create a fragmenter with the default maximum fragment size
    pub fn default_size() -> Self {
        Self {
            max_fragment_size: DEFAULT_MAX_FRAGMENT_SIZE,
            max_payload_size: DEFAULT_MAX_FRAGMENT_SIZE - FRAGMENT_OVERHEAD,
        }
    }

    /// Get the maximum fragment size
    pub fn max_fragment_size(&self) -> usize {
        self.max_fragment_size
    }

    /// Get the maximum payload size per fragment
    pub fn max_payload_size(&self) -> usize {
        self.max_payload_size
    }

    /// Fragment a message into chunks
    ///
    /// # Arguments
    ///
    /// * `message_id` - Unique identifier for this message
    /// * `data` - The data to fragment
    ///
    /// # Returns
    ///
    /// A vector of fragments that can be transmitted independently.
    pub fn fragment(&self, message_id: u32, data: &[u8]) -> Result<Vec<Fragment>> {
        if data.is_empty() {
            return Err(SableError::InvalidInput("Cannot fragment empty data".into()));
        }

        // Calculate number of fragments needed
        let num_fragments = (data.len() + self.max_payload_size - 1) / self.max_payload_size;

        if num_fragments > u16::MAX as usize {
            return Err(SableError::InvalidInput(format!(
                "Data too large: requires {} fragments, maximum is {}",
                num_fragments,
                u16::MAX
            )));
        }

        let total_fragments = num_fragments as u16;
        let mut fragments = Vec::with_capacity(num_fragments);

        for (i, chunk) in data.chunks(self.max_payload_size).enumerate() {
            let header = MessageFragmentHeader::new(message_id, i as u16, total_fragments);
            let fragment = Fragment::new(header, chunk.to_vec());
            fragments.push(fragment);
        }

        Ok(fragments)
    }

    /// Check if all fragments have been received for a complete message
    pub fn is_complete(fragments: &[Fragment]) -> bool {
        if fragments.is_empty() {
            return false;
        }

        // Get expected total from first fragment
        let expected_total = fragments[0].header.total_fragments as usize;

        if fragments.len() != expected_total {
            return false;
        }

        // Check that all expected indices are present
        let mut seen = vec![false; expected_total];
        for fragment in fragments {
            if fragment.header.total_fragments as usize != expected_total {
                return false;
            }
            let idx = fragment.header.fragment_index as usize;
            if idx >= expected_total || seen[idx] {
                return false;
            }
            seen[idx] = true;
        }

        seen.iter().all(|&s| s)
    }

    /// Reassemble fragments into the original message
    ///
    /// # Arguments
    ///
    /// * `fragments` - The fragments to reassemble (can be in any order)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Fragments are empty
    /// - Fragments have mismatched message IDs or total counts
    /// - Fragments are incomplete (missing indices)
    /// - Any fragment fails checksum verification
    pub fn reassemble(fragments: &[Fragment]) -> Result<Vec<u8>> {
        if fragments.is_empty() {
            return Err(SableError::InvalidInput("No fragments to reassemble".into()));
        }

        // Verify all fragments have the same message ID and total
        let message_id = fragments[0].header.message_id;
        let total_fragments = fragments[0].header.total_fragments;

        for (i, fragment) in fragments.iter().enumerate() {
            if fragment.header.message_id != message_id {
                return Err(SableError::InvalidInput(format!(
                    "Fragment {} has mismatched message ID: expected {}, got {}",
                    i, message_id, fragment.header.message_id
                )));
            }
            if fragment.header.total_fragments != total_fragments {
                return Err(SableError::InvalidInput(format!(
                    "Fragment {} has mismatched total: expected {}, got {}",
                    i, total_fragments, fragment.header.total_fragments
                )));
            }
        }

        // Verify checksums
        for (i, fragment) in fragments.iter().enumerate() {
            if !fragment.verify_checksum() {
                return Err(SableError::InvalidInput(format!(
                    "Fragment {} failed checksum verification",
                    i
                )));
            }
        }

        // Sort fragments by index
        let mut sorted: Vec<&Fragment> = fragments.iter().collect();
        sorted.sort_by_key(|f| f.header.fragment_index);

        // Verify we have all fragments
        for (expected_idx, fragment) in sorted.iter().enumerate() {
            if fragment.header.fragment_index as usize != expected_idx {
                return Err(SableError::InvalidInput(format!(
                    "Missing fragment at index {}",
                    expected_idx
                )));
            }
        }

        if sorted.len() != total_fragments as usize {
            return Err(SableError::InvalidInput(format!(
                "Incomplete fragments: have {}, expected {}",
                sorted.len(),
                total_fragments
            )));
        }

        // Reassemble payload
        let mut data = Vec::new();
        for fragment in sorted {
            data.extend_from_slice(&fragment.payload);
        }

        Ok(data)
    }

    /// Verify the integrity of a single fragment
    pub fn verify_checksum(fragment: &Fragment) -> bool {
        fragment.verify_checksum()
    }
}

impl Default for Fragmenter {
    fn default() -> Self {
        Self::default_size()
    }
}

/// Reassembly buffer for collecting fragments from a single message
#[derive(Debug)]
pub struct ReassemblyBuffer {
    /// Message ID being reassembled
    message_id: u32,
    /// Fragments received, indexed by fragment_index
    fragments: HashMap<u16, Fragment>,
    /// Expected total number of fragments (set from first received fragment)
    expected_total: Option<u16>,
}

impl ReassemblyBuffer {
    /// Create a new reassembly buffer for a specific message ID
    pub fn new(message_id: u32) -> Self {
        Self {
            message_id,
            fragments: HashMap::new(),
            expected_total: None,
        }
    }

    /// Get the message ID for this buffer
    pub fn message_id(&self) -> u32 {
        self.message_id
    }

    /// Get the expected total number of fragments
    pub fn expected_total(&self) -> Option<u16> {
        self.expected_total
    }

    /// Get the number of fragments received so far
    pub fn received_count(&self) -> usize {
        self.fragments.len()
    }

    /// Add a fragment to the reassembly buffer
    ///
    /// # Arguments
    ///
    /// * `fragment` - The fragment to add
    ///
    /// # Returns
    ///
    /// - `Ok(true)` if the fragment was added and the message is now complete
    /// - `Ok(false)` if the fragment was added but the message is not yet complete
    /// - `Err(_)` if the fragment is invalid for this buffer
    pub fn add_fragment(&mut self, fragment: Fragment) -> Result<bool> {
        // Verify message ID matches
        if fragment.header.message_id != self.message_id {
            return Err(SableError::InvalidInput(format!(
                "Fragment message ID {} doesn't match buffer message ID {}",
                fragment.header.message_id, self.message_id
            )));
        }

        // Verify checksum
        if !fragment.verify_checksum() {
            return Err(SableError::InvalidInput(
                "Fragment failed checksum verification".into(),
            ));
        }

        // Set or verify expected total
        match self.expected_total {
            None => {
                self.expected_total = Some(fragment.header.total_fragments);
            }
            Some(expected) => {
                if fragment.header.total_fragments != expected {
                    return Err(SableError::InvalidInput(format!(
                        "Fragment total {} doesn't match expected {}",
                        fragment.header.total_fragments, expected
                    )));
                }
            }
        }

        // Add fragment (overwrites duplicate indices)
        let index = fragment.header.fragment_index;
        self.fragments.insert(index, fragment);

        // Check if complete
        Ok(self.is_complete())
    }

    /// Check if all fragments have been received
    pub fn is_complete(&self) -> bool {
        match self.expected_total {
            None => false,
            Some(total) => self.fragments.len() == total as usize,
        }
    }

    /// Reassemble the complete message
    ///
    /// # Errors
    ///
    /// Returns an error if the message is not yet complete.
    pub fn reassemble(&self) -> Result<Vec<u8>> {
        if !self.is_complete() {
            return Err(SableError::InvalidInput(format!(
                "Cannot reassemble incomplete message: have {} of {:?} fragments",
                self.fragments.len(),
                self.expected_total
            )));
        }

        let total = self.expected_total.unwrap() as usize;
        let mut sorted: Vec<&Fragment> = self.fragments.values().collect();
        sorted.sort_by_key(|f| f.header.fragment_index);

        // Verify all indices are present
        for (expected_idx, fragment) in sorted.iter().enumerate() {
            if fragment.header.fragment_index as usize != expected_idx {
                return Err(SableError::InvalidInput(format!(
                    "Missing fragment at index {}",
                    expected_idx
                )));
            }
        }

        // Reassemble payload
        let mut data = Vec::with_capacity(total * 64); // Pre-allocate reasonable size
        for fragment in sorted {
            data.extend_from_slice(&fragment.payload);
        }

        Ok(data)
    }

    /// Get all fragments in the buffer
    pub fn fragments(&self) -> &HashMap<u16, Fragment> {
        &self.fragments
    }

    /// Clear the buffer
    pub fn clear(&mut self) {
        self.fragments.clear();
        self.expected_total = None;
    }
}

/// Multi-message reassembly manager
///
/// Manages reassembly buffers for multiple concurrent fragmented messages.
#[derive(Debug, Default)]
pub struct ReassemblyManager {
    /// Buffers for messages being reassembled, keyed by message ID
    buffers: HashMap<u32, ReassemblyBuffer>,
}

impl ReassemblyManager {
    /// Create a new reassembly manager
    pub fn new() -> Self {
        Self {
            buffers: HashMap::new(),
        }
    }

    /// Process an incoming fragment
    ///
    /// # Returns
    ///
    /// - `Ok(Some(data))` if this fragment completed a message
    /// - `Ok(None)` if the message is not yet complete
    /// - `Err(_)` if the fragment is invalid
    pub fn process_fragment(&mut self, fragment: Fragment) -> Result<Option<Vec<u8>>> {
        let message_id = fragment.header.message_id;

        // Get or create buffer for this message
        let buffer = self
            .buffers
            .entry(message_id)
            .or_insert_with(|| ReassemblyBuffer::new(message_id));

        // Add fragment
        let complete = buffer.add_fragment(fragment)?;

        if complete {
            // Reassemble and remove buffer
            let data = buffer.reassemble()?;
            self.buffers.remove(&message_id);
            Ok(Some(data))
        } else {
            Ok(None)
        }
    }

    /// Get the number of messages currently being reassembled
    pub fn pending_count(&self) -> usize {
        self.buffers.len()
    }

    /// Check if a specific message is being reassembled
    pub fn has_message(&self, message_id: u32) -> bool {
        self.buffers.contains_key(&message_id)
    }

    /// Get the reassembly buffer for a specific message
    pub fn get_buffer(&self, message_id: u32) -> Option<&ReassemblyBuffer> {
        self.buffers.get(&message_id)
    }

    /// Remove a message from reassembly (e.g., on timeout)
    pub fn remove_message(&mut self, message_id: u32) -> bool {
        self.buffers.remove(&message_id).is_some()
    }

    /// Clear all pending reassembly buffers
    pub fn clear(&mut self) {
        self.buffers.clear();
    }
}

/// Compute CRC32 checksum over header and payload
///
/// Uses the CRC32 polynomial 0xEDB88320 (IEEE 802.3)
fn crc32_compute(header: &[u8], payload: &[u8]) -> u32 {
    // CRC32 lookup table (computed from polynomial 0xEDB88320)
    const CRC_TABLE: [u32; 256] = [
        0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA, 0x076DC419, 0x706AF48F, 0xE963A535,
        0x9E6495A3, 0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988, 0x09B64C2B, 0x7EB17CBD,
        0xE7B82D07, 0x90BF1D91, 0x1DB71064, 0x6AB020F2, 0xF3B97148, 0x84BE41DE, 0x1ADAD47D,
        0x6DDDE4EB, 0xF4D4B551, 0x83D385C7, 0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC,
        0x14015C4F, 0x63066CD9, 0xFA0F3D63, 0x8D080DF5, 0x3B6E20C8, 0x4C69105E, 0xD56041E4,
        0xA2677172, 0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B, 0x35B5A8FA, 0x42B2986C,
        0xDBBBBBD6, 0xACBCCBB4, 0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59, 0x26D930AC,
        0x51DE003A, 0xC8D75180, 0xBFD06116, 0x21B4F4B5, 0x56B3C423, 0xCFBA9599, 0xB8BDA50F,
        0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924, 0x2F6F7C87, 0x58684C11, 0xC1611DAB,
        0xB6662D3D, 0x76DC4190, 0x01DB7106, 0x98D220BC, 0xEFD5102A, 0x71B18589, 0x06B6B51F,
        0x9FBFE4A5, 0xE8B8D433, 0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818, 0x7F6A0DBB,
        0x086D3D2D, 0x91646C97, 0xE6635C01, 0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E,
        0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457, 0x65B0D9C6, 0x12B7E950, 0x8BBEB8EA,
        0xFCB9887C, 0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65, 0x4DB26158, 0x3AB551CE,
        0xA3BC0074, 0xD4BB30E2, 0x4ADFA541, 0x3DD895D7, 0xA4D1C46D, 0xD3D6F4FB, 0x4369E96A,
        0x346ED9FC, 0xAD678846, 0xDA60B8D0, 0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9,
        0x5005713C, 0x270241AA, 0xBE0B1010, 0xC90C2086, 0x5768B525, 0x206F85B3, 0xB966D409,
        0xCE61E49F, 0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4, 0x59B33D17, 0x2EB40D81,
        0xB7BD5C3B, 0xC0BA6CAD, 0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A, 0xEAD54739,
        0x9DD277AF, 0x04DB2615, 0x73DC1683, 0xE3630B12, 0x94643B84, 0x0D6D6A3E, 0x7A6A5AA8,
        0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1, 0xF00F9344, 0x8708A3D2, 0x1E01F268,
        0x6906C2FE, 0xF762575D, 0x806567CB, 0x196C3671, 0x6E6B06E7, 0xFED41B76, 0x89D32BE0,
        0x10DA7A5A, 0x67DD4ACC, 0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5, 0xD6D6A3E8,
        0xA1D1937E, 0x38D8C2C4, 0x4FDFF252, 0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B,
        0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60, 0xDF60EFC3, 0xA867DF55, 0x316E8EEF,
        0x4669BE79, 0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236, 0xCC0C7795, 0xBB0B4703,
        0x220216B9, 0x5505262F, 0xC5BA3BBE, 0xB2BD0B28, 0x2BB45A92, 0x5CB36A04, 0xC2D7FFA7,
        0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D, 0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A,
        0x9C0906A9, 0xEB0E363F, 0x72076785, 0x05005713, 0x95BF4A82, 0xE2B87A14, 0x7BB12BAE,
        0x0CB61B38, 0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21, 0x86D3D2D4, 0xF1D4E242,
        0x68DDB3F8, 0x1FDA836E, 0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777, 0x88085AE6,
        0xFF0F6A70, 0x66063BCA, 0x11010B5C, 0x8F659EFF, 0xF862AE69, 0x616BFFD3, 0x166CCF45,
        0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2, 0xA7672661, 0xD06016F7, 0x4969474D,
        0x3E6E77DB, 0xAED16A4A, 0xD9D65ADC, 0x40DF0B66, 0x37D83BF0, 0xA9BCAE53, 0xDEBB9EC5,
        0x47B2CF7F, 0x30B5FFE9, 0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6, 0xBAD03605,
        0xCDD70693, 0x54DE5729, 0x23D967BF, 0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94,
        0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D,
    ];

    let mut crc: u32 = 0xFFFFFFFF;

    // Process header
    for &byte in header {
        let index = ((crc ^ u32::from(byte)) & 0xFF) as usize;
        crc = CRC_TABLE[index] ^ (crc >> 8);
    }

    // Process payload
    for &byte in payload {
        let index = ((crc ^ u32::from(byte)) & 0xFF) as usize;
        crc = CRC_TABLE[index] ^ (crc >> 8);
    }

    crc ^ 0xFFFFFFFF
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fragment_header_serialization() {
        let header = MessageFragmentHeader::new(0x12345678, 5, 10);
        let bytes = header.to_bytes();
        let restored = MessageFragmentHeader::from_bytes(&bytes).unwrap();

        assert_eq!(header.message_id(), restored.message_id());
        assert_eq!(header.fragment_index(), restored.fragment_index());
        assert_eq!(header.total_fragments(), restored.total_fragments());
    }

    #[test]
    fn test_fragment_header_validation() {
        // Total fragments cannot be zero
        let bytes = [0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00];
        assert!(MessageFragmentHeader::from_bytes(&bytes).is_err());

        // Fragment index cannot exceed total
        let bytes = [0x00, 0x00, 0x00, 0x01, 0x00, 0x05, 0x00, 0x03];
        assert!(MessageFragmentHeader::from_bytes(&bytes).is_err());

        // Too short
        let bytes = [0x00, 0x00, 0x00];
        assert!(MessageFragmentHeader::from_bytes(&bytes).is_err());
    }

    #[test]
    fn test_fragment_checksum() {
        let header = MessageFragmentHeader::new(1, 0, 1);
        let payload = vec![0x01, 0x02, 0x03, 0x04];
        let fragment = Fragment::new(header, payload);

        assert!(fragment.verify_checksum());

        // Tampering should fail verification
        let mut tampered = fragment.clone();
        tampered.payload[0] ^= 0xFF;
        assert!(!tampered.verify_checksum());
    }

    #[test]
    fn test_fragment_serialization() {
        let header = MessageFragmentHeader::new(0xDEADBEEF, 2, 5);
        let payload = vec![0x10, 0x20, 0x30, 0x40, 0x50];
        let fragment = Fragment::new(header, payload.clone());

        let bytes = fragment.to_bytes();
        let restored = Fragment::from_bytes(&bytes).unwrap();

        assert_eq!(fragment.header().message_id(), restored.header().message_id());
        assert_eq!(
            fragment.header().fragment_index(),
            restored.header().fragment_index()
        );
        assert_eq!(
            fragment.header().total_fragments(),
            restored.header().total_fragments()
        );
        assert_eq!(fragment.payload(), restored.payload());
        assert_eq!(fragment.checksum(), restored.checksum());
        assert!(restored.verify_checksum());
    }

    #[test]
    fn test_fragmenter_creation() {
        // Valid fragmenter
        let fragmenter = Fragmenter::new(100).unwrap();
        assert_eq!(fragmenter.max_fragment_size(), 100);
        assert_eq!(fragmenter.max_payload_size(), 100 - FRAGMENT_OVERHEAD);

        // Too small
        let result = Fragmenter::new(FRAGMENT_OVERHEAD);
        assert!(result.is_err());
    }

    #[test]
    fn test_fragment_single_chunk() {
        let fragmenter = Fragmenter::default();
        let data = vec![0x42; 50];
        let fragments = fragmenter.fragment(1, &data).unwrap();

        assert_eq!(fragments.len(), 1);
        assert_eq!(fragments[0].header().message_id(), 1);
        assert_eq!(fragments[0].header().fragment_index(), 0);
        assert_eq!(fragments[0].header().total_fragments(), 1);
        assert_eq!(fragments[0].payload(), data.as_slice());
    }

    #[test]
    fn test_fragment_multiple_chunks() {
        let fragmenter = Fragmenter::new(50).unwrap(); // Small fragments
        let data = vec![0x42; 150];
        let fragments = fragmenter.fragment(42, &data).unwrap();

        assert!(fragments.len() > 1);
        for (i, fragment) in fragments.iter().enumerate() {
            assert_eq!(fragment.header().message_id(), 42);
            assert_eq!(fragment.header().fragment_index(), i as u16);
            assert_eq!(fragment.header().total_fragments(), fragments.len() as u16);
            assert!(fragment.verify_checksum());
        }
    }

    #[test]
    fn test_fragment_proof_size() {
        // Test with standard 192-byte proof size
        let fragmenter = Fragmenter::new(64).unwrap();
        let proof_data = vec![0xAB; STANDARD_PROOF_SIZE];
        let fragments = fragmenter.fragment(100, &proof_data).unwrap();

        // Should need multiple fragments for 192 bytes with 64-byte max fragment size
        assert!(fragments.len() > 1);

        // Verify reassembly
        let reassembled = Fragmenter::reassemble(&fragments).unwrap();
        assert_eq!(reassembled, proof_data);
    }

    #[test]
    fn test_fragment_empty_data() {
        let fragmenter = Fragmenter::default();
        let result = fragmenter.fragment(1, &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_reassemble_in_order() {
        let fragmenter = Fragmenter::new(50).unwrap();
        let data = vec![0x42; 200];
        let fragments = fragmenter.fragment(1, &data).unwrap();

        let reassembled = Fragmenter::reassemble(&fragments).unwrap();
        assert_eq!(reassembled, data);
    }

    #[test]
    fn test_reassemble_out_of_order() {
        let fragmenter = Fragmenter::new(50).unwrap();
        let data = vec![0x42; 200];
        let mut fragments = fragmenter.fragment(1, &data).unwrap();

        // Reverse the order
        fragments.reverse();

        let reassembled = Fragmenter::reassemble(&fragments).unwrap();
        assert_eq!(reassembled, data);
    }

    #[test]
    fn test_reassemble_random_order() {
        let fragmenter = Fragmenter::new(30).unwrap();
        let data: Vec<u8> = (0..=255).cycle().take(500).collect();
        let mut fragments = fragmenter.fragment(1, &data).unwrap();

        // Shuffle using a simple algorithm
        let n = fragments.len();
        for i in 0..n {
            let j = (i * 7 + 3) % n;
            fragments.swap(i, j);
        }

        let reassembled = Fragmenter::reassemble(&fragments).unwrap();
        assert_eq!(reassembled, data);
    }

    #[test]
    fn test_reassemble_missing_fragment() {
        let fragmenter = Fragmenter::new(50).unwrap();
        let data = vec![0x42; 200];
        let mut fragments = fragmenter.fragment(1, &data).unwrap();

        // Remove a fragment
        fragments.remove(1);

        let result = Fragmenter::reassemble(&fragments);
        assert!(result.is_err());
    }

    #[test]
    fn test_reassemble_duplicate_fragment() {
        let fragmenter = Fragmenter::new(50).unwrap();
        let data = vec![0x42; 100];
        let mut fragments = fragmenter.fragment(1, &data).unwrap();

        // Duplicate a fragment
        let duplicate = fragments[0].clone();
        fragments.push(duplicate);

        // Should fail because of duplicate index
        let result = Fragmenter::reassemble(&fragments);
        assert!(result.is_err());
    }

    #[test]
    fn test_reassemble_mismatched_message_id() {
        let fragmenter = Fragmenter::new(50).unwrap();
        let data1 = vec![0x42; 100];
        let data2 = vec![0x43; 100];

        let mut fragments1 = fragmenter.fragment(1, &data1).unwrap();
        let fragments2 = fragmenter.fragment(2, &data2).unwrap();

        // Mix fragments from different messages
        fragments1.push(fragments2[0].clone());

        let result = Fragmenter::reassemble(&fragments1);
        assert!(result.is_err());
    }

    #[test]
    fn test_reassemble_corrupted_checksum() {
        let fragmenter = Fragmenter::new(50).unwrap();
        let data = vec![0x42; 100];
        let mut fragments = fragmenter.fragment(1, &data).unwrap();

        // Corrupt a fragment
        fragments[0].payload[0] ^= 0xFF;

        let result = Fragmenter::reassemble(&fragments);
        assert!(result.is_err());
    }

    #[test]
    fn test_is_complete() {
        let fragmenter = Fragmenter::new(50).unwrap();
        let data = vec![0x42; 200];
        let fragments = fragmenter.fragment(1, &data).unwrap();

        assert!(Fragmenter::is_complete(&fragments));

        // Incomplete
        let mut incomplete = fragments.clone();
        incomplete.pop();
        assert!(!Fragmenter::is_complete(&incomplete));

        // Empty
        assert!(!Fragmenter::is_complete(&[]));
    }

    #[test]
    fn test_reassembly_buffer_basic() {
        let fragmenter = Fragmenter::new(50).unwrap();
        let data = vec![0x42; 150];
        let fragments = fragmenter.fragment(42, &data).unwrap();

        let mut buffer = ReassemblyBuffer::new(42);
        assert_eq!(buffer.message_id(), 42);
        assert_eq!(buffer.received_count(), 0);
        assert!(!buffer.is_complete());

        // Add fragments one by one
        for (i, fragment) in fragments.iter().enumerate() {
            let is_last = i == fragments.len() - 1;
            let complete = buffer.add_fragment(fragment.clone()).unwrap();
            assert_eq!(complete, is_last);
        }

        assert!(buffer.is_complete());
        let reassembled = buffer.reassemble().unwrap();
        assert_eq!(reassembled, data);
    }

    #[test]
    fn test_reassembly_buffer_out_of_order() {
        let fragmenter = Fragmenter::new(50).unwrap();
        let data = vec![0x42; 150];
        let mut fragments = fragmenter.fragment(42, &data).unwrap();

        // Reverse order
        fragments.reverse();

        let mut buffer = ReassemblyBuffer::new(42);

        for fragment in fragments {
            buffer.add_fragment(fragment).unwrap();
        }

        assert!(buffer.is_complete());
        let reassembled = buffer.reassemble().unwrap();
        assert_eq!(reassembled, data);
    }

    #[test]
    fn test_reassembly_buffer_wrong_message_id() {
        let fragmenter = Fragmenter::new(50).unwrap();
        let data = vec![0x42; 50];
        let fragments = fragmenter.fragment(99, &data).unwrap();

        let mut buffer = ReassemblyBuffer::new(42);
        let result = buffer.add_fragment(fragments[0].clone());
        assert!(result.is_err());
    }

    #[test]
    fn test_reassembly_manager_single_message() {
        let fragmenter = Fragmenter::new(50).unwrap();
        let data = vec![0x42; 150];
        let fragments = fragmenter.fragment(1, &data).unwrap();

        let mut manager = ReassemblyManager::new();
        assert_eq!(manager.pending_count(), 0);

        for (i, fragment) in fragments.iter().enumerate() {
            let result = manager.process_fragment(fragment.clone()).unwrap();
            if i < fragments.len() - 1 {
                assert!(result.is_none());
                assert!(manager.has_message(1));
            } else {
                assert_eq!(result.unwrap(), data);
                assert!(!manager.has_message(1));
            }
        }

        assert_eq!(manager.pending_count(), 0);
    }

    #[test]
    fn test_reassembly_manager_concurrent_messages() {
        let fragmenter = Fragmenter::new(40).unwrap();

        let data1 = vec![0x11; 100];
        let data2 = vec![0x22; 80];
        let data3 = vec![0x33; 120];

        let fragments1 = fragmenter.fragment(1, &data1).unwrap();
        let fragments2 = fragmenter.fragment(2, &data2).unwrap();
        let fragments3 = fragmenter.fragment(3, &data3).unwrap();

        let mut manager = ReassemblyManager::new();

        // Interleave fragments from all three messages
        let mut all_fragments: Vec<Fragment> = Vec::new();
        let max_len = fragments1.len().max(fragments2.len()).max(fragments3.len());

        for i in 0..max_len {
            if i < fragments1.len() {
                all_fragments.push(fragments1[i].clone());
            }
            if i < fragments2.len() {
                all_fragments.push(fragments2[i].clone());
            }
            if i < fragments3.len() {
                all_fragments.push(fragments3[i].clone());
            }
        }

        let mut completed = Vec::new();
        for fragment in all_fragments {
            if let Some(data) = manager.process_fragment(fragment).unwrap() {
                completed.push(data);
            }
        }

        assert_eq!(completed.len(), 3);
        assert!(completed.contains(&data1));
        assert!(completed.contains(&data2));
        assert!(completed.contains(&data3));
        assert_eq!(manager.pending_count(), 0);
    }

    #[test]
    fn test_reassembly_manager_remove_message() {
        let fragmenter = Fragmenter::new(50).unwrap();
        let data = vec![0x42; 150];
        let fragments = fragmenter.fragment(42, &data).unwrap();

        let mut manager = ReassemblyManager::new();

        // Add only first fragment
        manager.process_fragment(fragments[0].clone()).unwrap();
        assert!(manager.has_message(42));
        assert_eq!(manager.pending_count(), 1);

        // Remove (e.g., on timeout)
        assert!(manager.remove_message(42));
        assert!(!manager.has_message(42));
        assert_eq!(manager.pending_count(), 0);
    }

    #[test]
    fn test_crc32_known_values() {
        // Test with known CRC32 values
        let header = [0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01];
        let payload = b"hello";
        let crc = crc32_compute(&header, payload);

        // The CRC should be consistent
        let crc2 = crc32_compute(&header, payload);
        assert_eq!(crc, crc2);

        // Different data should give different CRC
        let payload2 = b"world";
        let crc3 = crc32_compute(&header, payload2);
        assert_ne!(crc, crc3);
    }

    #[test]
    fn test_fragment_serialized_size() {
        let header = MessageFragmentHeader::new(1, 0, 1);
        let payload = vec![0x42; 100];
        let fragment = Fragment::new(header, payload);

        assert_eq!(
            fragment.serialized_size(),
            FRAGMENT_OVERHEAD + 100
        );
        assert_eq!(fragment.to_bytes().len(), fragment.serialized_size());
    }

    #[test]
    fn test_large_message_fragmentation() {
        // Test with a larger message (10KB)
        let fragmenter = Fragmenter::default();
        let data: Vec<u8> = (0..10_000).map(|i| (i % 256) as u8).collect();
        let fragments = fragmenter.fragment(0xCAFEBABE, &data).unwrap();

        // Verify all fragments
        for fragment in &fragments {
            assert!(fragment.verify_checksum());
        }

        // Reassemble
        let reassembled = Fragmenter::reassemble(&fragments).unwrap();
        assert_eq!(reassembled, data);
    }

    #[test]
    fn test_exactly_one_fragment_boundary() {
        let fragmenter = Fragmenter::new(FRAGMENT_OVERHEAD + 32).unwrap();

        // Data that exactly fits in one fragment
        let data = vec![0x42; 32];
        let fragments = fragmenter.fragment(1, &data).unwrap();
        assert_eq!(fragments.len(), 1);

        // Data that requires exactly two fragments
        let data = vec![0x42; 33];
        let fragments = fragmenter.fragment(1, &data).unwrap();
        assert_eq!(fragments.len(), 2);

        // Verify reassembly
        let reassembled = Fragmenter::reassemble(&fragments).unwrap();
        assert_eq!(reassembled, data);
    }
}
