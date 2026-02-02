//! Cryptographic session management for P2P communications (REQ-016)
//!
//! This module implements secure session management using:
//! - X25519 ECDH for key exchange
//! - ChaCha20-Poly1305 for authenticated encryption
//! - 30-second session timeout
//! - 96-bit random nonce with replay prevention
//!
//! # Security Features
//!
//! - **Perfect Forward Secrecy**: Ephemeral keys ensure past sessions remain secure
//! - **Replay Prevention**: Each nonce can only be used once per session
//! - **Session Timeout**: Sessions expire after 30 seconds of inactivity
//! - **Authenticated Encryption**: ChaCha20-Poly1305 provides confidentiality and integrity

use crate::crypto::rng::SecureRng;
use crate::error::{Result, SableError};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305,
};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};
use zeroize::ZeroizeOnDrop;

/// Session timeout duration (30 seconds as specified in REQ-016)
pub const SESSION_TIMEOUT: Duration = Duration::from_secs(30);

/// Nonce size in bytes (96 bits = 12 bytes for ChaCha20-Poly1305)
pub const NONCE_SIZE: usize = 12;

/// Session ID size in bytes (128 bits for uniqueness)
pub const SESSION_ID_SIZE: usize = 16;

/// 96-bit nonce for replay prevention
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Nonce([u8; NONCE_SIZE]);

impl Nonce {
    /// Create a new random nonce
    pub fn random() -> Result<Self> {
        let mut rng = SecureRng::new()?;
        let bytes = rng.random_bytes::<NONCE_SIZE>()?;
        Ok(Self(bytes))
    }

    /// Create a nonce from bytes
    pub fn from_bytes(bytes: [u8; NONCE_SIZE]) -> Self {
        Self(bytes)
    }

    /// Get the nonce bytes
    pub fn as_bytes(&self) -> &[u8; NONCE_SIZE] {
        &self.0
    }

    /// Convert to array
    pub fn to_bytes(self) -> [u8; NONCE_SIZE] {
        self.0
    }
}

impl AsRef<[u8]> for Nonce {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; NONCE_SIZE]> for Nonce {
    fn from(bytes: [u8; NONCE_SIZE]) -> Self {
        Self(bytes)
    }
}

/// Unique session identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId([u8; SESSION_ID_SIZE]);

impl SessionId {
    /// Create a new random session ID
    pub fn random() -> Result<Self> {
        let mut rng = SecureRng::new()?;
        let bytes = rng.random_bytes::<SESSION_ID_SIZE>()?;
        Ok(Self(bytes))
    }

    /// Create a session ID from bytes
    pub fn from_bytes(bytes: [u8; SESSION_ID_SIZE]) -> Self {
        Self(bytes)
    }

    /// Get the session ID bytes
    pub fn as_bytes(&self) -> &[u8; SESSION_ID_SIZE] {
        &self.0
    }

    /// Convert to array
    pub fn to_bytes(self) -> [u8; SESSION_ID_SIZE] {
        self.0
    }
}

impl AsRef<[u8]> for SessionId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; SESSION_ID_SIZE]> for SessionId {
    fn from(bytes: [u8; SESSION_ID_SIZE]) -> Self {
        Self(bytes)
    }
}

/// Session state in the ECDH key exchange lifecycle
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Session initiated, waiting for peer's public key
    Initiated,
    /// Key exchange complete, session is active
    Active,
    /// Session has expired
    Expired,
}

/// Derived session key for encryption/decryption
#[derive(Clone, ZeroizeOnDrop)]
struct SessionKey([u8; 32]);

impl SessionKey {
    /// Derive a session key from the shared secret using HKDF-like derivation
    fn from_shared_secret(shared_secret: &SharedSecret) -> Self {
        // Use the raw shared secret bytes directly
        // In production, consider HKDF for additional key derivation
        let mut key = [0u8; 32];
        key.copy_from_slice(shared_secret.as_bytes());
        Self(key)
    }

    fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// A cryptographic session for P2P communication
pub struct Session {
    /// Unique session identifier
    id: SessionId,
    /// Derived session key for encryption (only available after key exchange)
    session_key: Option<SessionKey>,
    /// Our ephemeral secret (consumed during key exchange)
    our_secret: Option<EphemeralSecret>,
    /// Our public key (for sending to peer)
    our_public: PublicKey,
    /// Peer's public key (set after receiving their key)
    peer_public: Option<PublicKey>,
    /// Time the session was created
    created_at: Instant,
    /// Last activity time (for timeout calculation)
    last_activity: Instant,
    /// Set of nonces already seen (for replay prevention)
    nonces_seen: HashSet<Nonce>,
    /// Current session state
    state: SessionState,
}

impl Session {
    /// Create a new session with fresh ephemeral keys
    fn new(id: SessionId) -> Result<Self> {
        let mut rng = SecureRng::new()?;
        let secret = EphemeralSecret::random_from_rng(&mut rng);
        let public = PublicKey::from(&secret);

        let now = Instant::now();
        Ok(Self {
            id,
            session_key: None,
            our_secret: Some(secret),
            our_public: public,
            peer_public: None,
            created_at: now,
            last_activity: now,
            nonces_seen: HashSet::new(),
            state: SessionState::Initiated,
        })
    }

    /// Get the session ID
    pub fn id(&self) -> &SessionId {
        &self.id
    }

    /// Get our public key to send to peer
    pub fn our_public_key(&self) -> &PublicKey {
        &self.our_public
    }

    /// Get the peer's public key (if set)
    pub fn peer_public_key(&self) -> Option<&PublicKey> {
        self.peer_public.as_ref()
    }

    /// Get the current session state
    pub fn state(&self) -> SessionState {
        self.state
    }

    /// Check if the session has expired
    pub fn is_expired(&self) -> bool {
        self.last_activity.elapsed() > SESSION_TIMEOUT || self.state == SessionState::Expired
    }

    /// Get the session age
    pub fn age(&self) -> Duration {
        self.created_at.elapsed()
    }

    /// Get time since last activity
    pub fn idle_time(&self) -> Duration {
        self.last_activity.elapsed()
    }

    /// Complete the key exchange with the peer's public key
    fn complete_exchange(&mut self, peer_public: PublicKey) -> Result<()> {
        if self.state != SessionState::Initiated {
            return Err(SableError::Cryptographic(
                "Session not in initiated state".into(),
            ));
        }

        let secret = self
            .our_secret
            .take()
            .ok_or_else(|| SableError::Cryptographic("Ephemeral secret already consumed".into()))?;

        // Perform ECDH key exchange
        let shared_secret = secret.diffie_hellman(&peer_public);

        // Derive session key
        self.session_key = Some(SessionKey::from_shared_secret(&shared_secret));
        self.peer_public = Some(peer_public);
        self.state = SessionState::Active;
        self.last_activity = Instant::now();

        Ok(())
    }

    /// Encrypt a message using the session key
    fn encrypt(&mut self, plaintext: &[u8], nonce: Nonce) -> Result<Vec<u8>> {
        if self.state != SessionState::Active {
            return Err(SableError::Cryptographic("Session not active".into()));
        }

        if self.is_expired() {
            self.state = SessionState::Expired;
            return Err(SableError::Cryptographic("Session expired".into()));
        }

        let session_key = self
            .session_key
            .as_ref()
            .ok_or_else(|| SableError::Cryptographic("No session key available".into()))?;

        let cipher = ChaCha20Poly1305::new_from_slice(session_key.as_bytes())
            .map_err(|e| SableError::Cryptographic(format!("Failed to create cipher: {}", e)))?;

        let ciphertext = cipher
            .encrypt(
                chacha20poly1305::Nonce::from_slice(nonce.as_bytes()),
                plaintext,
            )
            .map_err(|e| SableError::Cryptographic(format!("Encryption failed: {}", e)))?;

        self.last_activity = Instant::now();
        Ok(ciphertext)
    }

    /// Decrypt a message, rejecting replayed nonces
    fn decrypt(&mut self, ciphertext: &[u8], nonce: Nonce) -> Result<Vec<u8>> {
        if self.state != SessionState::Active {
            return Err(SableError::Cryptographic("Session not active".into()));
        }

        if self.is_expired() {
            self.state = SessionState::Expired;
            return Err(SableError::Cryptographic("Session expired".into()));
        }

        // Check for replay attack
        if self.nonces_seen.contains(&nonce) {
            return Err(SableError::Cryptographic(
                "Replay attack detected: nonce already used".into(),
            ));
        }

        let session_key = self
            .session_key
            .as_ref()
            .ok_or_else(|| SableError::Cryptographic("No session key available".into()))?;

        let cipher = ChaCha20Poly1305::new_from_slice(session_key.as_bytes())
            .map_err(|e| SableError::Cryptographic(format!("Failed to create cipher: {}", e)))?;

        let plaintext = cipher
            .decrypt(
                chacha20poly1305::Nonce::from_slice(nonce.as_bytes()),
                ciphertext,
            )
            .map_err(|e| SableError::Cryptographic(format!("Decryption failed: {}", e)))?;

        // Record the nonce to prevent replay
        self.nonces_seen.insert(nonce);
        self.last_activity = Instant::now();
        Ok(plaintext)
    }

    /// Mark the session as expired
    fn expire(&mut self) {
        self.state = SessionState::Expired;
        // Clear session key for security
        self.session_key = None;
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        // Ensure session key is cleared
        self.session_key = None;
        // Clear nonces
        self.nonces_seen.clear();
    }
}

/// Manager for cryptographic P2P sessions
pub struct SessionManager {
    /// Active sessions indexed by ID
    sessions: HashMap<SessionId, Session>,
}

impl SessionManager {
    /// Create a new session manager
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
        }
    }

    /// Initiate a new ECDH key exchange
    ///
    /// Returns the session ID and our public key to send to the peer.
    pub fn initiate(&mut self) -> Result<(SessionId, PublicKey)> {
        // Clean up expired sessions first
        self.cleanup_expired();

        let id = SessionId::random()?;
        let session = Session::new(id)?;
        let public_key = *session.our_public_key();

        self.sessions.insert(id, session);
        Ok((id, public_key))
    }

    /// Complete the key exchange with the peer's public key
    ///
    /// After this, the session is active and ready for encryption/decryption.
    pub fn complete(&mut self, id: SessionId, peer_public: PublicKey) -> Result<()> {
        let session = self
            .sessions
            .get_mut(&id)
            .ok_or_else(|| SableError::InvalidInput("Session not found".into()))?;

        if session.is_expired() {
            self.sessions.remove(&id);
            return Err(SableError::Cryptographic("Session expired".into()));
        }

        session.complete_exchange(peer_public)
    }

    /// Create a session from a received public key (responder side)
    ///
    /// This is used when receiving a key exchange initiation from a peer.
    /// Returns the session ID and our public key to send back.
    pub fn respond(&mut self, peer_public: PublicKey) -> Result<(SessionId, PublicKey)> {
        // Clean up expired sessions first
        self.cleanup_expired();

        let id = SessionId::random()?;
        let mut session = Session::new(id)?;
        let our_public = *session.our_public_key();

        // Complete our side of the exchange immediately
        session.complete_exchange(peer_public)?;

        self.sessions.insert(id, session);
        Ok((id, our_public))
    }

    /// Encrypt a message for a session
    ///
    /// Returns the ciphertext. The caller is responsible for transmitting
    /// the nonce along with the ciphertext.
    pub fn encrypt(&mut self, id: &SessionId, plaintext: &[u8], nonce: Nonce) -> Result<Vec<u8>> {
        let session = self
            .sessions
            .get_mut(id)
            .ok_or_else(|| SableError::InvalidInput("Session not found".into()))?;

        if session.is_expired() {
            self.sessions.remove(id);
            return Err(SableError::Cryptographic("Session expired".into()));
        }

        session.encrypt(plaintext, nonce)
    }

    /// Decrypt a message, rejecting replayed nonces
    ///
    /// Returns the plaintext if decryption succeeds and the nonce hasn't been used before.
    pub fn decrypt(
        &mut self,
        id: &SessionId,
        ciphertext: &[u8],
        nonce: Nonce,
    ) -> Result<Vec<u8>> {
        let session = self
            .sessions
            .get_mut(id)
            .ok_or_else(|| SableError::InvalidInput("Session not found".into()))?;

        if session.is_expired() {
            self.sessions.remove(id);
            return Err(SableError::Cryptographic("Session expired".into()));
        }

        session.decrypt(ciphertext, nonce)
    }

    /// Get a session by ID
    pub fn get(&self, id: &SessionId) -> Option<&Session> {
        self.sessions.get(id)
    }

    /// Check if a session exists and is active
    pub fn is_active(&self, id: &SessionId) -> bool {
        self.sessions
            .get(id)
            .map(|s| s.state() == SessionState::Active && !s.is_expired())
            .unwrap_or(false)
    }

    /// Get the number of active sessions
    pub fn active_session_count(&self) -> usize {
        self.sessions
            .values()
            .filter(|s| s.state() == SessionState::Active && !s.is_expired())
            .count()
    }

    /// Clean up expired sessions
    pub fn cleanup_expired(&mut self) {
        let expired_ids: Vec<SessionId> = self
            .sessions
            .iter()
            .filter(|(_, session)| session.is_expired())
            .map(|(id, _)| *id)
            .collect();

        for id in expired_ids {
            if let Some(mut session) = self.sessions.remove(&id) {
                session.expire();
            }
        }
    }

    /// Terminate a specific session
    pub fn terminate(&mut self, id: &SessionId) -> bool {
        if let Some(mut session) = self.sessions.remove(id) {
            session.expire();
            true
        } else {
            false
        }
    }

    /// Terminate all sessions
    pub fn terminate_all(&mut self) {
        for (_, mut session) in self.sessions.drain() {
            session.expire();
        }
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nonce_random() {
        let nonce1 = Nonce::random().unwrap();
        let nonce2 = Nonce::random().unwrap();
        assert_ne!(nonce1, nonce2, "Random nonces should be unique");
    }

    #[test]
    fn test_nonce_from_bytes() {
        let bytes = [1u8; NONCE_SIZE];
        let nonce = Nonce::from_bytes(bytes);
        assert_eq!(nonce.as_bytes(), &bytes);
        assert_eq!(nonce.to_bytes(), bytes);
    }

    #[test]
    fn test_session_id_random() {
        let id1 = SessionId::random().unwrap();
        let id2 = SessionId::random().unwrap();
        assert_ne!(id1, id2, "Random session IDs should be unique");
    }

    #[test]
    fn test_session_establishment() {
        let mut manager_a = SessionManager::new();
        let mut manager_b = SessionManager::new();

        // A initiates
        let (session_id_a, public_key_a) = manager_a.initiate().unwrap();

        // B responds to A's public key
        let (session_id_b, public_key_b) = manager_b.respond(public_key_a).unwrap();

        // A completes with B's public key
        manager_a.complete(session_id_a, public_key_b).unwrap();

        // Both sessions should be active
        assert!(manager_a.is_active(&session_id_a));
        assert!(manager_b.is_active(&session_id_b));
    }

    #[test]
    fn test_encryption_decryption_roundtrip() {
        let mut manager_a = SessionManager::new();
        let mut manager_b = SessionManager::new();

        // Establish session
        let (session_id_a, public_key_a) = manager_a.initiate().unwrap();
        let (session_id_b, public_key_b) = manager_b.respond(public_key_a).unwrap();
        manager_a.complete(session_id_a, public_key_b).unwrap();

        // A sends message to B
        let message = b"Hello, secure world!";
        let nonce = Nonce::random().unwrap();
        let ciphertext = manager_a.encrypt(&session_id_a, message, nonce).unwrap();

        // B decrypts
        let plaintext = manager_b.decrypt(&session_id_b, &ciphertext, nonce).unwrap();
        assert_eq!(plaintext, message);

        // B sends message to A
        let response = b"Hello back!";
        let nonce2 = Nonce::random().unwrap();
        let ciphertext2 = manager_b.encrypt(&session_id_b, response, nonce2).unwrap();

        // A decrypts
        let plaintext2 = manager_a
            .decrypt(&session_id_a, &ciphertext2, nonce2)
            .unwrap();
        assert_eq!(plaintext2, response);
    }

    #[test]
    fn test_replay_attack_prevention() {
        let mut manager_a = SessionManager::new();
        let mut manager_b = SessionManager::new();

        // Establish session
        let (session_id_a, public_key_a) = manager_a.initiate().unwrap();
        let (session_id_b, public_key_b) = manager_b.respond(public_key_a).unwrap();
        manager_a.complete(session_id_a, public_key_b).unwrap();

        // A sends message to B
        let message = b"Secret message";
        let nonce = Nonce::random().unwrap();
        let ciphertext = manager_a.encrypt(&session_id_a, message, nonce).unwrap();

        // B decrypts successfully first time
        let plaintext = manager_b.decrypt(&session_id_b, &ciphertext, nonce).unwrap();
        assert_eq!(plaintext, message);

        // Replay attack: trying to decrypt with same nonce should fail
        let result = manager_b.decrypt(&session_id_b, &ciphertext, nonce);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Replay attack detected"));
    }

    #[test]
    fn test_session_timeout() {
        // Create a session with immediate expiration for testing
        let mut manager = SessionManager::new();
        let (session_id, public_key) = manager.initiate().unwrap();

        // Get a peer key
        let mut rng = SecureRng::new().unwrap();
        let peer_secret = EphemeralSecret::random_from_rng(&mut rng);
        let peer_public = PublicKey::from(&peer_secret);

        manager.complete(session_id, peer_public).unwrap();

        // Session should be active initially
        assert!(manager.is_active(&session_id));

        // Manually expire the session by manipulating internal state
        // In production, this would happen after 30 seconds of inactivity
        if let Some(session) = manager.sessions.get_mut(&session_id) {
            session.state = SessionState::Expired;
        }

        // Session should now be expired
        assert!(!manager.is_active(&session_id));
    }

    #[test]
    fn test_timeout_enforcement() {
        // This test verifies the 30-second timeout constant is set correctly
        assert_eq!(SESSION_TIMEOUT, Duration::from_secs(30));
    }

    #[test]
    fn test_cleanup_expired() {
        let mut manager = SessionManager::new();

        // Create a session
        let (session_id, public_key) = manager.initiate().unwrap();
        let mut rng = SecureRng::new().unwrap();
        let peer_secret = EphemeralSecret::random_from_rng(&mut rng);
        let peer_public = PublicKey::from(&peer_secret);
        manager.complete(session_id, peer_public).unwrap();

        // Initially should have one session
        assert_eq!(manager.active_session_count(), 1);

        // Mark as expired
        if let Some(session) = manager.sessions.get_mut(&session_id) {
            session.state = SessionState::Expired;
        }

        // Cleanup should remove it
        manager.cleanup_expired();
        assert_eq!(manager.active_session_count(), 0);
        assert!(manager.get(&session_id).is_none());
    }

    #[test]
    fn test_session_terminate() {
        let mut manager = SessionManager::new();

        let (session_id, public_key) = manager.initiate().unwrap();
        let mut rng = SecureRng::new().unwrap();
        let peer_secret = EphemeralSecret::random_from_rng(&mut rng);
        let peer_public = PublicKey::from(&peer_secret);
        manager.complete(session_id, peer_public).unwrap();

        assert!(manager.is_active(&session_id));

        // Terminate the session
        assert!(manager.terminate(&session_id));
        assert!(!manager.is_active(&session_id));
        assert!(manager.get(&session_id).is_none());

        // Terminating again should return false
        assert!(!manager.terminate(&session_id));
    }

    #[test]
    fn test_session_terminate_all() {
        let mut manager = SessionManager::new();

        // Create multiple sessions
        let mut rng = SecureRng::new().unwrap();
        for _ in 0..5 {
            let (session_id, _) = manager.initiate().unwrap();
            let peer_secret = EphemeralSecret::random_from_rng(&mut rng);
            let peer_public = PublicKey::from(&peer_secret);
            manager.complete(session_id, peer_public).unwrap();
        }

        assert_eq!(manager.active_session_count(), 5);

        manager.terminate_all();
        assert_eq!(manager.active_session_count(), 0);
    }

    #[test]
    fn test_encrypt_before_key_exchange_complete() {
        let mut manager = SessionManager::new();
        let (session_id, _) = manager.initiate().unwrap();

        // Session is initiated but not active
        let nonce = Nonce::random().unwrap();
        let result = manager.encrypt(&session_id, b"test", nonce);
        assert!(result.is_err());
    }

    #[test]
    fn test_session_not_found() {
        let mut manager = SessionManager::new();
        let fake_id = SessionId::random().unwrap();
        let nonce = Nonce::random().unwrap();

        let result = manager.encrypt(&fake_id, b"test", nonce);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Session not found"));
    }

    #[test]
    fn test_large_message_encryption() {
        let mut manager_a = SessionManager::new();
        let mut manager_b = SessionManager::new();

        // Establish session
        let (session_id_a, public_key_a) = manager_a.initiate().unwrap();
        let (session_id_b, public_key_b) = manager_b.respond(public_key_a).unwrap();
        manager_a.complete(session_id_a, public_key_b).unwrap();

        // Large message (1MB)
        let large_message = vec![0x42u8; 1024 * 1024];
        let nonce = Nonce::random().unwrap();
        let ciphertext = manager_a
            .encrypt(&session_id_a, &large_message, nonce)
            .unwrap();

        let plaintext = manager_b
            .decrypt(&session_id_b, &ciphertext, nonce)
            .unwrap();
        assert_eq!(plaintext, large_message);
    }

    #[test]
    fn test_empty_message_encryption() {
        let mut manager_a = SessionManager::new();
        let mut manager_b = SessionManager::new();

        // Establish session
        let (session_id_a, public_key_a) = manager_a.initiate().unwrap();
        let (session_id_b, public_key_b) = manager_b.respond(public_key_a).unwrap();
        manager_a.complete(session_id_a, public_key_b).unwrap();

        // Empty message
        let empty_message: &[u8] = &[];
        let nonce = Nonce::random().unwrap();
        let ciphertext = manager_a
            .encrypt(&session_id_a, empty_message, nonce)
            .unwrap();

        let plaintext = manager_b
            .decrypt(&session_id_b, &ciphertext, nonce)
            .unwrap();
        assert_eq!(plaintext, empty_message);
    }

    #[test]
    fn test_multiple_concurrent_sessions() {
        let mut manager = SessionManager::new();
        let mut peer_manager = SessionManager::new();
        let mut sessions = Vec::new();

        // Create multiple sessions
        for i in 0..10 {
            let (session_id, public_key) = manager.initiate().unwrap();
            let (peer_session_id, peer_public_key) = peer_manager.respond(public_key).unwrap();
            manager.complete(session_id, peer_public_key).unwrap();
            sessions.push((session_id, peer_session_id, i));
        }

        // Verify all sessions work independently
        for (session_id, peer_session_id, i) in &sessions {
            let message = format!("Message for session {}", i);
            let nonce = Nonce::random().unwrap();
            let ciphertext = manager
                .encrypt(session_id, message.as_bytes(), nonce)
                .unwrap();
            let plaintext = peer_manager
                .decrypt(peer_session_id, &ciphertext, nonce)
                .unwrap();
            assert_eq!(plaintext, message.as_bytes());
        }

        assert_eq!(manager.active_session_count(), 10);
    }

    #[test]
    fn test_session_state_transitions() {
        let mut manager = SessionManager::new();

        // Initial state: Initiated
        let (session_id, _) = manager.initiate().unwrap();
        assert_eq!(
            manager.get(&session_id).unwrap().state(),
            SessionState::Initiated
        );

        // After completion: Active
        let mut rng = SecureRng::new().unwrap();
        let peer_secret = EphemeralSecret::random_from_rng(&mut rng);
        let peer_public = PublicKey::from(&peer_secret);
        manager.complete(session_id, peer_public).unwrap();
        assert_eq!(
            manager.get(&session_id).unwrap().state(),
            SessionState::Active
        );

        // Cannot complete again
        let peer_secret2 = EphemeralSecret::random_from_rng(&mut rng);
        let peer_public2 = PublicKey::from(&peer_secret2);
        assert!(manager.complete(session_id, peer_public2).is_err());
    }

    #[test]
    fn test_tampered_ciphertext_detection() {
        let mut manager_a = SessionManager::new();
        let mut manager_b = SessionManager::new();

        // Establish session
        let (session_id_a, public_key_a) = manager_a.initiate().unwrap();
        let (session_id_b, public_key_b) = manager_b.respond(public_key_a).unwrap();
        manager_a.complete(session_id_a, public_key_b).unwrap();

        // Encrypt a message
        let message = b"Authenticated message";
        let nonce = Nonce::random().unwrap();
        let mut ciphertext = manager_a.encrypt(&session_id_a, message, nonce).unwrap();

        // Tamper with the ciphertext
        if !ciphertext.is_empty() {
            ciphertext[0] ^= 0xFF;
        }

        // Decryption should fail due to authentication
        let result = manager_b.decrypt(&session_id_b, &ciphertext, nonce);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Decryption failed"));
    }
}
