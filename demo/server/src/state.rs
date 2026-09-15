use parking_lot::RwLock;
use zeroize::Zeroize;
use sable_core::zk::halo2::{FaceVerificationProver, Halo2Fr};
use crate::verification_policy::PendingVerification;
use crate::cache::TtlCache;
use crate::auth::Principal;
use std::time::Duration;
use std::sync::Arc;

/// Session data for an enrolled user
#[derive(Clone)]
pub struct EnrollmentSession {
    pub session_id: String,
    pub commitment_bytes: [u8; 48],
    /// Original 1024-dim face embedding for cosine similarity comparison
    pub face_embedding: Vec<f64>,
    /// Quantized embedding for Halo2 ZK proofs (Hamming distance)
    pub quantized_embedding: Vec<u8>,
    /// Poseidon commitment to the quantized template, registered at enrollment.
    /// The ZK proof binds to this so a prover cannot match against a different
    /// template (see `FaceVerificationVerifier::verify_expected`).
    pub template_commitment: Halo2Fr,
    #[allow(dead_code)]
    pub created_at: std::time::Instant,
}

impl Drop for EnrollmentSession {
    fn drop(&mut self) {
        self.face_embedding.zeroize();
        self.quantized_embedding.zeroize();
    }
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
    /// Single-use verifier-owned policies for consumed authentication challenges.
    verification_policies: Arc<RwLock<TtlCache<PendingVerification>>>,
    /// Enrolled sessions by session_id
    sessions: Arc<RwLock<TtlCache<EnrollmentSession>>>,
    /// Active authentication challenges
    challenges: Arc<RwLock<TtlCache<AuthChallenge>>>,
    /// Halo2 ZK prover (shared for setup reuse)
    pub halo2_prover: Arc<RwLock<FaceVerificationProver>>,
    /// Pending liveness results by challenge_id (single-use)
    liveness_results: Arc<RwLock<TtlCache<LivenessResult>>>,
}

impl AppState {
    pub fn new() -> Self {
        tracing::info!("Initializing Halo2 ZK prover (this may take a few seconds)...");
        let prover = FaceVerificationProver::new();
        tracing::info!("Halo2 ZK prover initialized");

        Self {
            verification_policies: Arc::new(RwLock::new(TtlCache::new(256, Duration::from_secs(30)))),
            sessions: Arc::new(RwLock::new(TtlCache::new(128, Duration::from_secs(15 * 60)))),
            challenges: Arc::new(RwLock::new(TtlCache::new(256, Duration::from_secs(30)))),
            halo2_prover: Arc::new(RwLock::new(prover)),
            liveness_results: Arc::new(RwLock::new(TtlCache::new(256, Duration::from_secs(30)))),
        }
    }

    pub fn store_session(&self, principal: &Principal, session: EnrollmentSession) -> Result<(), String> {
        let mut sessions = self.sessions.write();
        if sessions.count_prefix(&principal.prefix()) >= 4 { return Err("Enrollment quota exhausted".into()); }
        sessions.insert(principal.key(&session.session_id), session)
    }

    pub(crate) fn store_verification_policy(&self, principal: &Principal, id: String, policy: PendingVerification, now: u64) -> Result<(), String> {
        let mut policies = self.verification_policies.write();
        let monotonic_now = std::time::Instant::now();
        policies.retain(|_, value| value.is_current(now, monotonic_now));
        if !policy.is_current(now, monotonic_now) || policies.len() >= 256 || policies.contains_key(&principal.key(&id)) || policies.count_prefix(&principal.prefix()) >= 8 {
            return Err("Verification policy expired or capacity exhausted".into());
        }
        policies.insert(principal.key(&id), policy)
    }

    pub(crate) fn take_verification_policy(&self, principal: &Principal, id: &str) -> Option<PendingVerification> {
        self.verification_policies.write().remove(&principal.key(id))
    }

    pub fn get_session(&self, principal: &Principal, session_id: &str) -> Option<EnrollmentSession> {
        let sessions = self.sessions.read();
        sessions.get(&principal.key(session_id)).cloned()
    }

    pub fn store_challenge(&self, principal: &Principal, challenge: AuthChallenge) -> Result<(), String> {
        let mut challenges = self.challenges.write();
        if challenges.count_prefix(&principal.prefix()) >= 8 { return Err("Challenge quota exhausted".into()); }
        challenges.insert(principal.key(&challenge.challenge_id), challenge)
    }

    #[allow(dead_code)]
    pub fn get_challenge(&self, principal: &Principal, challenge_id: &str) -> Option<AuthChallenge> {
        let challenges = self.challenges.read();
        challenges.get(&principal.key(challenge_id)).cloned()
    }

    pub fn remove_challenge(&self, principal: &Principal, challenge_id: &str) -> Option<AuthChallenge> {
        let mut challenges = self.challenges.write();
        challenges.remove(&principal.key(challenge_id))
    }

    pub fn store_liveness_result(&self, principal: &Principal, challenge_id: String, result: LivenessResult) -> Result<(), String> {
        let mut results = self.liveness_results.write();
        if results.count_prefix(&principal.prefix()) >= 8 { return Err("Liveness quota exhausted".into()); }
        results.insert(principal.key(&challenge_id), result)
    }

    pub fn get_liveness_result(&self, principal: &Principal, challenge_id: &str) -> Option<LivenessResult> {
        let results = self.liveness_results.read();
        results.get(&principal.key(challenge_id)).cloned()
    }

    pub fn take_liveness_result(&self, principal: &Principal, challenge_id: &str) -> Option<LivenessResult> {
        let mut results = self.liveness_results.write();
        results.remove(&principal.key(challenge_id))
    }

    /// Release expired records even when the service receives no traffic.
    pub fn evict_expired(&self) {
        self.sessions.write().retain(|_, _| true);
        self.challenges.write().retain(|_, _| true);
        self.liveness_results.write().retain(|_, _| true);
        self.verification_policies.write().retain(|_, _| true);
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}
