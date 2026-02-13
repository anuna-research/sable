use parking_lot::RwLock;
use sable_core::crypto::pedersen::Commitment;
use sable_core::zk::halo2::FaceVerificationProver;
use std::collections::HashMap;
use std::sync::Arc;

/// Session data for an enrolled user
#[derive(Clone)]
pub struct EnrollmentSession {
    pub session_id: String,
    #[allow(dead_code)]
    pub commitment: Commitment,
    pub commitment_bytes: [u8; 48],
    pub features: [f32; 512],
    /// Original 1024-dim face embedding for cosine similarity comparison
    pub face_embedding: Option<Vec<f64>>,
    /// Quantized embedding for Halo2 ZK proofs (Hamming distance)
    pub quantized_embedding: Vec<u8>,
    #[allow(dead_code)]
    pub salt_bytes: [u8; 32],
    #[allow(dead_code)]
    pub created_at: std::time::Instant,
}

/// Screen flash liveness result stored per session
#[derive(Clone)]
#[allow(dead_code)]
pub struct LivenessResult {
    pub passed: bool,
    pub reflectance_variance: f64,
    pub reflectance_gradient: f64,
    pub highlight_softness: f64,
    pub channel_consistency: f64,
    pub checked_at: std::time::Instant,
}

/// Authentication challenge data
#[derive(Clone)]
pub struct AuthChallenge {
    pub challenge_id: String,
    pub session_id: String,
    pub nonce: [u8; 32],
    /// Client commitment (hex-encoded SHA-256 hash) for liveness binding.
    /// When present, the server can verify that the client committed to specific
    /// data before the challenge nonce was revealed.
    pub client_commitment: Option<String>,
    pub created_at: std::time::Instant,
}

/// Application state shared across handlers
#[derive(Clone)]
pub struct AppState {
    /// Enrolled sessions by session_id
    pub sessions: Arc<RwLock<HashMap<String, EnrollmentSession>>>,
    /// Active authentication challenges
    pub challenges: Arc<RwLock<HashMap<String, AuthChallenge>>>,
    /// Halo2 ZK prover (shared for setup reuse)
    pub halo2_prover: Arc<RwLock<FaceVerificationProver>>,
    /// Pending liveness results by challenge_id (single-use)
    pub liveness_results: Arc<RwLock<HashMap<String, LivenessResult>>>,
}

impl AppState {
    pub fn new() -> Self {
        tracing::info!("Initializing Halo2 ZK prover (this may take a few seconds)...");
        let prover = FaceVerificationProver::new();
        tracing::info!("Halo2 ZK prover initialized");

        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            challenges: Arc::new(RwLock::new(HashMap::new())),
            halo2_prover: Arc::new(RwLock::new(prover)),
            liveness_results: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn store_session(&self, session: EnrollmentSession) {
        let mut sessions = self.sessions.write();
        sessions.insert(session.session_id.clone(), session);
    }

    pub fn get_session(&self, session_id: &str) -> Option<EnrollmentSession> {
        let sessions = self.sessions.read();
        sessions.get(session_id).cloned()
    }

    pub fn store_challenge(&self, challenge: AuthChallenge) {
        let mut challenges = self.challenges.write();
        challenges.insert(challenge.challenge_id.clone(), challenge);
    }

    #[allow(dead_code)]
    pub fn get_challenge(&self, challenge_id: &str) -> Option<AuthChallenge> {
        let challenges = self.challenges.read();
        challenges.get(challenge_id).cloned()
    }

    pub fn remove_challenge(&self, challenge_id: &str) -> Option<AuthChallenge> {
        let mut challenges = self.challenges.write();
        challenges.remove(challenge_id)
    }

    pub fn store_liveness_result(&self, challenge_id: String, result: LivenessResult) {
        let mut results = self.liveness_results.write();
        results.insert(challenge_id, result);
    }

    pub fn get_liveness_result(&self, challenge_id: &str) -> Option<LivenessResult> {
        let results = self.liveness_results.read();
        results.get(challenge_id).cloned()
    }

    pub fn take_liveness_result(&self, challenge_id: &str) -> Option<LivenessResult> {
        let mut results = self.liveness_results.write();
        results.remove(challenge_id)
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}
