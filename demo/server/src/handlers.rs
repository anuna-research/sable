use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    Json,
    Extension,
};
use serde::{Deserialize, Serialize};
use crate::auth::Principal;
use crate::verification_policy::PendingVerification;
// Note: PalmProcessor is available for production use with proper biometric sensors
// For webcam demo, we use image-based feature extraction instead
use sable_core::biometric::screen_flash::{ScreenFlashExtractor, ScreenFlashThresholds};
use sable_core::biometric::rolling_shutter::{
    derive_temporal_symbols, maximum_unambiguous_errors, TemporalObservation,
    TEMPORAL_SYMBOLS,
};
use sable_core::biometric::corneal;
use sable_core::biometric::fingerprint::{self, Fields};
use sable_core::biometric::photometric::{self, PatchGrid};
use sable_core::biometric::PalmImage;
use sable_core::crypto::pedersen::{CommitmentOpening, Generators, commit_with_opening};
use sable_core::crypto::poseidon::poseidon_hash;
use sable_core::crypto::rng::SecureRng;
use std::time::Instant;

// Halo2 ZK proof system
use sable_core::zk::halo2::{
    FaceVerificationVerifier, Proof, LivenessWitness, LivenessCheckCircuit,
    challenge_identifier,
    hamming_distance, ThresholdConfig, Halo2Fr,
    poseidon_commit_bytes_value,
    thermometer_encode, thermometer_prescale_tanh,
    challenge_digest as compute_challenge_digest,
};

use crate::flash_challenge::{
    compute_liveness_evidence, crop_face_region, derive_flash_pattern, verify_client_commitment,
    verify_spatial_flash,
};
use crate::state::{AppState, AuthChallenge, EnrollmentSession, LivenessResult};

// Feature vector size (must match SABLE core)
const FEATURE_VECTOR_SIZE: usize = 512;

// ============================================================================
// Enrollment Endpoint
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct EnrollRequest {
    /// Display identifier only; the authenticated principal owns the enrollment.
    #[allow(dead_code)]
    pub user_id: String,
    /// Face embedding from Human library (1024-dimensional)
    pub face_embedding: Option<Vec<f64>>,
}

#[derive(Debug, Serialize)]
pub struct EnrollResponse {
    pub session_id: String,
    pub commitment_hex: String,
    pub quality_score: f32,
    pub timings: EnrollTimings,
}

#[derive(Debug, Serialize)]
pub struct EnrollTimings {
    pub feature_generation_ms: f64,
    pub poseidon_hash_ms: f64,
    pub pedersen_commit_ms: f64,
    pub total_ms: f64,
}

pub async fn enroll(
    Extension(principal): Extension<Principal>,
    State(state): State<AppState>,
    Json(req): Json<EnrollRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let total_start = Instant::now();

    // Enrollment requires captured input; identifiers cannot synthesize a template.
    let feature_start = Instant::now();
    let (features, quality_score) = if let Some(embedding) = &req.face_embedding {
        // Convert 1024-dim face embedding to 512 ZK-compatible features
        convert_face_embedding_to_features(embedding)?
    } else {
        return Err(bad_liveness_input("face_embedding is required for enrollment".into()));
    };
    let feature_time = feature_start.elapsed();

    // Hash features with Poseidon
    let hash_start = Instant::now();
    let feature_hash = poseidon_hash(&features).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Poseidon hash failed: {}", e),
            }),
        )
    })?;
    let hash_time = hash_start.elapsed();

    // Create Pedersen commitment
    let commit_start = Instant::now();
    let _rng = SecureRng::new().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("RNG initialization failed: {}", e),
            }),
        )
    })?;

    let opening = CommitmentOpening::new_with_random_salt(feature_hash).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Commitment opening failed: {}", e),
            }),
        )
    })?;

    let generators = Generators::get();
    let commitment = commit_with_opening(&opening, generators);
    let commit_time = commit_start.elapsed();

    let total_time = total_start.elapsed();

    // Store session
    let session_id = uuid::Uuid::new_v4().to_string();
    let commitment_bytes = commitment.to_bytes();

    // Create the matcher template for Halo2 ZK proofs using the THERMOMETER
    // (ordinal) encoding: byte-Hamming distance then equals L1 distance between
    // quantization levels, recovering the accuracy that binary Hamming discards.
    // Prescale is stats-free tanh (the zero-config default); enrollment and
    // verification must use the identical prescale+encoding.
    let features_f64: Vec<f64> = features.iter().map(|&f| f as f64).collect();
    let quantized_embedding = thermometer_encode(&thermometer_prescale_tanh(&features_f64));

    // Register the Poseidon commitment the ZK proof will bind to (must match the
    // in-circuit hash; poseidon_commit_bytes_value computes it via the same gates).
    let template_commitment = poseidon_commit_bytes_value(&quantized_embedding);

    let session = EnrollmentSession {
        session_id: session_id.clone(),
        commitment_bytes,
        face_embedding: req.face_embedding.ok_or_else(|| bad_liveness_input("face_embedding is required".into()))?,
        quantized_embedding,
        template_commitment,
        created_at: Instant::now(),
    };
    state.store_session(&principal, session).map_err(storage_unavailable)?;

    Ok(Json(EnrollResponse {
        session_id,
        commitment_hex: hex::encode(commitment_bytes),
        quality_score,
        timings: EnrollTimings {
            feature_generation_ms: feature_time.as_secs_f64() * 1000.0,
            poseidon_hash_ms: hash_time.as_secs_f64() * 1000.0,
            pedersen_commit_ms: commit_time.as_secs_f64() * 1000.0,
            total_ms: total_time.as_secs_f64() * 1000.0,
        },
    }))
}

// ============================================================================
// Authentication Challenge Endpoint
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct ChallengeRequest {
    pub session_id: String,
    /// Optional client commitment (hex-encoded SHA-256 hash).
    /// When provided, binds the client to data committed before the nonce is revealed,
    /// enabling server-side liveness verification in a later step.
    pub client_commitment: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ChallengeResponse {
    pub challenge_id: String,
    pub nonce_hex: String,
    pub commitment_hex: String,
}

pub async fn auth_challenge(
    Extension(principal): Extension<Principal>,
    State(state): State<AppState>,
    Json(req): Json<ChallengeRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    require_nonce_hex(req.client_commitment.as_deref(), "client_commitment")
        .map_err(bad_liveness_input)?;
    // Verify session exists
    let session = state.get_session(&principal, &req.session_id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Session not found".to_string(),
            }),
        )
    })?;

    // Generate challenge nonce
    let mut rng = SecureRng::new().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("RNG failed: {}", e),
            }),
        )
    })?;

    let nonce = rng.generate_nonce().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Nonce generation failed: {}", e),
            }),
        )
    })?;

    let challenge_id = uuid::Uuid::new_v4().to_string();
    let challenge = AuthChallenge {
        challenge_id: challenge_id.clone(),
        session_id: req.session_id,
        nonce,
        client_commitment: req.client_commitment,
        created_at: Instant::now(),
    };

    state.store_challenge(&principal, challenge).map_err(storage_unavailable)?;

    Ok(Json(ChallengeResponse {
        challenge_id,
        nonce_hex: hex::encode(nonce),
        commitment_hex: hex::encode(session.commitment_bytes),
    }))
}

// ============================================================================
// Proof Generation Endpoint
// ============================================================================

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProveRequest {
    pub challenge_id: String,
    /// Obsolete simulation field. Any supplied value is rejected.
    pub noise_level: Option<f32>,
    /// Face embedding from Human library (1024-dimensional) for live scan
    pub face_embedding: Option<Vec<f64>>,
    /// Client nonce (hex-encoded 32-byte nonce) for spatial color challenge verification.
    /// When provided alongside `flash_frames`, the server verifies H(c_nonce) matches
    /// the client_commitment from the challenge, recomputes the expected flash pattern,
    /// and performs per-region color matching against the captured frames.
    pub c_nonce: Option<String>,
    /// Base64-encoded JPEG frames for spatial color challenge: [baseline, round1, round2, round3].
    /// The baseline frame is captured before any flash; the 3 round frames are captured
    /// during each flash round with split-screen colors.
    pub flash_frames: Option<Vec<String>>,
    /// Corneal crops for the glint check (SPEC-006 REQ-114, CON-093):
    /// `[baseline, round1, round2, round3]`, each `[left_eye, right_eye]` as
    /// base64 PNG or JPEG data URLs. All eight crops must share one size.
    pub eye_crops: Option<Vec<Vec<String>>>,
    /// Decoded rolling-shutter row bands supplied by a capture integration.
    /// This evidence is observe-only in the demo and cannot authorize the
    /// circuit's protected-capture gate.
    pub rolling_shutter: Option<RollingShutterObservationRequest>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RollingShutterObservationRequest {
    pub observed_symbols: [u8; TEMPORAL_SYMBOLS],
    pub initial_phase: u8,
    pub frame_tick_deltas: [u16; 2],
}

/// Per-round region match score for spatial color verification.
#[derive(Debug, Clone, Serialize)]
pub struct RegionScoreResponse {
    /// Flash round index (0-based).
    pub round: usize,
    /// Cosine similarity of top-left delta vs. expected TL color.
    pub tl_score: f64,
    /// Cosine similarity of top-right delta vs. expected TR color.
    pub tr_score: f64,
    /// Cosine similarity of bottom-left delta vs. expected BL color.
    pub bl_score: f64,
    /// Cosine similarity of bottom-right delta vs. expected BR color.
    pub br_score: f64,
    /// Mean of 4 adjacent-pair spatial diff scores.
    pub spatial_diff_score: f64,
}

#[derive(Debug, Serialize)]
pub struct ProveResponse {
    pub proof_hex: String,
    pub public_inputs_hex: Vec<String>,
    pub distance: f32,
    pub hamming_distance: u64,
    pub hamming_threshold: u64,
    pub quality_score: f32,
    pub proof_size_bytes: usize,
    pub liveness_passed: Option<bool>,
    /// Whether the spatial color challenge passed (if c_nonce was provided).
    pub color_challenge_passed: Option<bool>,
    /// Whether liveness was proven inside the ZK proof (not just plaintext check).
    pub liveness_proved_in_zk: Option<bool>,
    /// Per-round region match scores from spatial color verification.
    pub region_match_scores: Option<Vec<RegionScoreResponse>>,
    /// Average spatial differentiation score across rounds.
    pub spatial_differentiation_score: Option<f64>,
    /// Photometric convexity evidence per flash round (SPEC-006 REQ-111..113).
    /// Observational for now: the circuit floors are zero (ADR-010).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub photometric_rounds: Option<Vec<PhotometricRoundResponse>>,
    /// Corneal glint evidence per flash round (SPEC-006 REQ-114..115).
    /// Observational unless SABLE_CORNEAL_TOLERANCE is set (ADR-010).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub corneal_rounds: Option<Vec<CornealRoundResponse>>,
    /// Every public liveness parameter the circuit was run with, so the UI can
    /// say which checks were live. All are demo settings (ADR-010).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub liveness_parameters: Option<LivenessParameters>,
    /// The first sub-check the native pre-check failed, if any (OBS-085).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub liveness_failing_check: Option<LivenessFailureResponse>,
    /// Observe-only rolling-shutter relation diagnostics. This is never camera
    /// attestation and does not affect authentication in the demo profile.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rolling_shutter_observation: Option<RollingShutterObservationResponse>,
    pub timings: ProveTimings,
    pub what_was_proven: Vec<String>,
    pub what_stayed_private: Vec<String>,
}

/// Per-round photometric evidence reported back to the client.
#[derive(Debug, Serialize)]
pub struct PhotometricRoundResponse {
    pub round: usize,
    /// Patches (of a 4×4 grid) that responded to the flash at all (REQ-118).
    pub responding_patches: u8,
    /// Mean L1 deviation of patch illumination mixes, Q15 over [0, 2] (REQ-113).
    pub convexity_score: u16,
}

/// A delta fingerprint unpacked into its fields for human reading.
#[derive(Debug, Serialize)]
pub struct FingerprintResponse {
    pub hex: String,
    /// Channel ordering, categorical 0..=5.
    pub order: u8,
    pub mid_ratio: u8,
    pub min_ratio: u8,
    pub magnitude: u8,
}

impl From<u16> for FingerprintResponse {
    fn from(fp: u16) -> Self {
        let Fields { order, mid_ratio, min_ratio, magnitude } = fingerprint::unpack(fp);
        Self { hex: format!("{fp:04x}"), order, mid_ratio, min_ratio, magnitude }
    }
}

/// Per-round corneal glint evidence reported back to the client.
#[derive(Debug, Serialize)]
pub struct CornealRoundResponse {
    pub round: usize,
    pub left_glint: FingerprintResponse,
    pub right_glint: FingerprintResponse,
    /// Area-weighted composite of the four quadrant colours.
    pub expected_glint: FingerprintResponse,
    /// Whether the in-circuit check was live for this proof.
    pub enabled: bool,
    /// Field-wise agreement per eye at the configured tolerances; absent when
    /// the check is not enabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agrees: Option<[bool; 2]>,
}

/// Public liveness parameters as run, echoed for the result screen.
#[derive(Debug, Clone, Serialize)]
pub struct LivenessParameters {
    pub color_threshold: u8,
    pub spatial_threshold: u8,
    pub min_magnitude: u8,
    pub magnitude_scale: u32,
    pub min_coverage: u8,
    pub min_convexity: u16,
    pub corneal_enabled: bool,
    pub glint_ratio_tolerance: u8,
    pub glint_magnitude_floor: u8,
}

/// Which sub-check the native mirror of the circuit failed first.
#[derive(Debug, Clone, Serialize)]
pub struct LivenessFailureResponse {
    pub check: String,
    pub round: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct RollingShutterObservationResponse {
    pub mode: &'static str,
    pub enabled_in_circuit: bool,
    pub capture_validated: bool,
    pub relation_matched: bool,
    pub phase_matched: bool,
    pub timing_matched: bool,
    pub symbol_mismatches: u8,
    pub maximum_symbol_errors: u8,
}

/// Geometry floors from `SABLE_GEOMETRY_FLOORS="<min_coverage>,<min_convexity>"`.
///
/// Coverage is a patch count out of 16 (4×4 grid, ≤ 64); convexity is Q15 over
/// [0, 2]. Zero disables a floor. Any non-zero value here is a *demo* setting:
/// SPEC-006 ADR-010 reserves the real constants for EXP-003.
fn geometry_floors_from_env() -> (u8, u16) {
    let Ok(raw) = std::env::var("SABLE_GEOMETRY_FLOORS") else { return (0, 0) };
    let Some((a, b)) = raw.split_once(',') else { return (0, 0) };
    let coverage: u8 = a.trim().parse().unwrap_or(0);
    let convexity: u16 = b.trim().parse().unwrap_or(0);
    (coverage.min(64), convexity)
}

/// Corneal parameters from `SABLE_CORNEAL_TOLERANCE="<ratio>,<magnitude_floor>"`.
///
/// The first value is the allowed ordinal difference on the two ratio fields;
/// the second is the minimum observed glint magnitude (BUG-003: the composite
/// carries no magnitude, so this is a floor, not a tolerance). Unset means the
/// check ships disabled (ADR-010). Values are clamped to the witness widths
/// (ratio ≤ 15, floor ≤ 31).
fn corneal_tolerances_from_env() -> Option<(u8, u8)> {
    let raw = std::env::var("SABLE_CORNEAL_TOLERANCE").ok()?;
    let (a, b) = raw.split_once(',')?;
    let ratio: u8 = a.trim().parse().ok()?;
    let magnitude: u8 = b.trim().parse().ok()?;
    Some((ratio.min(15), magnitude.min(31)))
}

/// Legacy liveness thresholds from `SABLE_LIVENESS_THRESHOLDS="<colour>,<spatial>,<magnitude>"`.
///
/// Colour: maximum Hamming distance over the 11 direction bits of a quadrant
/// fingerprint against the expected colour. Spatial: minimum Hamming distance
/// between adjacent quadrant fingerprints. Magnitude: minimum observed
/// magnitude per quadrant at the configured `SABLE_MAGNITUDE_SCALE`. Defaults
/// are the demo's historical guesses (5, 1, 3); none is validated (ADR-010).
fn liveness_thresholds_from_env() -> (u8, u8, u8) {
    const DEFAULT: (u8, u8, u8) = (5, 1, 3);
    let Ok(raw) = std::env::var("SABLE_LIVENESS_THRESHOLDS") else { return DEFAULT };
    let parts: Vec<Option<u8>> = raw.split(',').map(|p| p.trim().parse().ok()).collect();
    match parts.as_slice() {
        [Some(c), Some(s), Some(m)] => (*c, *s, (*m).min(31)),
        _ => DEFAULT,
    }
}

fn rolling_shutter_observe_enabled() -> bool {
    std::env::var("SABLE_ROLLING_SHUTTER_OBSERVE")
        .map(|value| matches!(value.trim(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
}

#[derive(Debug, Serialize)]
pub struct ProveTimings {
    pub feature_scan_ms: f64,
    pub distance_calc_ms: f64,
    pub proof_generation_ms: f64,
    pub total_ms: f64,
}

pub async fn auth_prove(
    Extension(principal): Extension<Principal>,
    State(state): State<AppState>,
    Json(req): Json<ProveRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let total_start = Instant::now();
    require_capture_input(&req).map_err(bad_liveness_input)?;
    let corneal_tolerances = corneal_tolerances_from_env();
    require_corneal_evidence(&req, corneal_tolerances.is_some()).map_err(bad_liveness_input)?;
    let rolling_shutter_observe = rolling_shutter_observe_enabled();

    // Get and validate challenge
    let challenge = state.remove_challenge(&principal, &req.challenge_id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Challenge not found or expired".to_string(),
            }),
        )
    })?;

    require_nonce_hex(challenge.client_commitment.as_deref(), "client_commitment")
        .map_err(bad_liveness_input)?;

    // Check challenge hasn't expired (30 second window)
    if challenge.created_at.elapsed() >= std::time::Duration::from_secs(30) {
        // Clear any pending liveness tied to this challenge.
        let _ = state.take_liveness_result(&principal, &challenge.challenge_id);
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Challenge expired".to_string(),
            }),
        ));
    }

    // Get enrollment session
    let session = state.get_session(&principal, &challenge.session_id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Session not found".to_string(),
            }),
        )
    })?;

    // Only caller-supplied capture input may produce a proof.
    let scan_start = Instant::now();
    let live_embedding = req.face_embedding.as_ref()
        .ok_or_else(|| bad_liveness_input("face_embedding is required".into()))?;
    let (live_features, quality_score) = convert_face_embedding_to_features(live_embedding)?;
    let scan_time = scan_start.elapsed();

    // Both embeddings are mandatory; there is no simulated-distance fallback.
    let distance_start = Instant::now();
    let distance = (1.0 - cosine_similarity(&session.face_embedding, live_embedding)) as f32;
    let distance_time = distance_start.elapsed();

    // Check if face matches (similarity threshold)
    // Distance < 0.5 means similarity > 50% (match)
    const MATCH_THRESHOLD: f32 = 0.5;
    if distance >= MATCH_THRESHOLD {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Face does not match enrolled template".into(),
            }),
        ));
    }

    // Encode live features with the SAME thermometer encoding as enrollment, so
    // byte-Hamming distance equals the L1 distance between quantization levels.
    let live_features_f64: Vec<f64> = live_features.iter().map(|&f| f as f64).collect();
    let live_quantized = thermometer_encode(&thermometer_prescale_tanh(&live_features_f64));

    // Calculate Hamming distance between enrolled and live embeddings
    // (== L1 distance between thermometer levels).
    let hamming_dist = hamming_distance(&session.quantized_embedding, &live_quantized);

    // Threshold = 50% of max byte-Hamming (2048 for 512 bytes). NOTE: this is a
    // placeholder operating point inherited from the binary matcher. The
    // thermometer L1 distance has a different genuine/impostor distribution, so
    // this should be recalibrated from data at the desired EER operating point
    // (a deployer-set parameter, like the prescale constants). Tracked as
    // task-recalibrate-threshold in docs/plans/in-circuit-matcher.spl.
    let threshold_config = ThresholdConfig::new(session.quantized_embedding.len(), 0.5);
    let threshold = threshold_config.max_hamming_distance();


    // Consume challenge-bound liveness result (single-use).
    let mut liveness_passed = state
        .take_liveness_result(&principal, &challenge.challenge_id)
        .map(|r| r.passed);

    // ========================================================================
    // Spatial Color Challenge Verification (optional, before proof generation)
    // ========================================================================
    let mut color_challenge_passed: Option<bool> = None;
    let mut region_match_scores: Option<Vec<RegionScoreResponse>> = None;
    let mut spatial_differentiation_score: Option<f64> = None;
    let mut photometric_rounds: Option<Vec<PhotometricRoundResponse>> = None;
    let mut corneal_rounds: Option<Vec<CornealRoundResponse>> = None;
    let mut liveness_parameters: Option<LivenessParameters> = None;
    let mut liveness_failing_check: Option<LivenessFailureResponse> = None;
    let mut rolling_shutter_observation: Option<RollingShutterObservationResponse> = None;
    let mut liveness_witness: Option<LivenessWitness> = None;

    if let (Some(c_nonce_hex), Some(frames_b64)) = (&req.c_nonce, &req.flash_frames) {
        // a. Decode c_nonce from hex
        let c_nonce_bytes = hex::decode(c_nonce_hex).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!("Invalid c_nonce hex: {}", e),
                }),
            )
        })?;

        if c_nonce_bytes.len() != 32 {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!(
                        "c_nonce must be 32 bytes, got {}",
                        c_nonce_bytes.len()
                    ),
                }),
            ));
        }

        let mut c_nonce_32 = [0u8; 32];
        c_nonce_32.copy_from_slice(&c_nonce_bytes);

        // SPEC-008: both sides derive the same temporal waveform from the joint
        // nonce. The demo accepts decoded bands only in explicit observe mode;
        // it has no protected mobile capture validator and cannot arm rejection.
        let temporal_expected_symbols =
            derive_temporal_symbols(&c_nonce_32, &challenge.nonce).map_err(|error| {
                bad_liveness_input(format!("Rolling-shutter derivation failed: {error}"))
            })?;
        let temporal_max_symbol_errors =
            maximum_unambiguous_errors(&temporal_expected_symbols);
        let temporal_request = if rolling_shutter_observe {
            req.rolling_shutter
        } else {
            None
        };
        let temporal_recognised = temporal_request
            .map(|observation| TemporalObservation {
                symbols: observation.observed_symbols,
                initial_phase: observation.initial_phase,
                frame_tick_deltas: observation.frame_tick_deltas,
            }
            .recognise()
            .is_ok())
            .unwrap_or(false);
        let recognised_request = temporal_request.filter(|_| temporal_recognised);
        let temporal_observed_symbols = recognised_request
            .map(|observation| observation.observed_symbols)
            .unwrap_or(temporal_expected_symbols);
        let temporal_initial_phase = recognised_request
            .map(|observation| observation.initial_phase)
            .unwrap_or(0);
        let temporal_frame_tick_deltas = recognised_request
            .map(|observation| observation.frame_tick_deltas)
            .unwrap_or([4, 4]);
        if let Some(observation) = temporal_request {
            let phase_distance = temporal_recognised.then(|| {
                observation.initial_phase.min(
                    TEMPORAL_SYMBOLS as u8 - observation.initial_phase,
                )
            });
            let phase_matched = phase_distance.map(|distance| distance <= 1).unwrap_or(false);
            let timing_matched = temporal_recognised && observation.frame_tick_deltas == [4, 4];
            let symbol_mismatches = if temporal_recognised {
                observation
                    .observed_symbols
                    .iter()
                    .enumerate()
                    .filter(|(index, symbol)| {
                        **symbol
                            != temporal_expected_symbols
                                [(observation.initial_phase as usize + *index) % TEMPORAL_SYMBOLS]
                    })
                    .count() as u8
            } else {
                TEMPORAL_SYMBOLS as u8
            };
            rolling_shutter_observation = Some(RollingShutterObservationResponse {
                mode: "observe-only",
                enabled_in_circuit: false,
                capture_validated: false,
                relation_matched: phase_matched
                    && timing_matched
                    && symbol_mismatches <= temporal_max_symbol_errors,
                phase_matched,
                timing_matched,
                symbol_mismatches,
                maximum_symbol_errors: temporal_max_symbol_errors,
            });
        }

        // b. Verify H(c_nonce) matches challenge.client_commitment (if present)
        if let Some(commitment_hex) = &challenge.client_commitment {
            let commitment_bytes = hex::decode(commitment_hex).map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: format!("Invalid client_commitment hex in challenge: {}", e),
                    }),
                )
            })?;

            if commitment_bytes.len() != 32 {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: format!(
                            "client_commitment must be 32 bytes, got {}",
                            commitment_bytes.len()
                        ),
                    }),
                ));
            }

            let mut commitment_32 = [0u8; 32];
            commitment_32.copy_from_slice(&commitment_bytes);

            if !verify_client_commitment(&c_nonce_32, &commitment_32) {
                return Err((
                    StatusCode::UNAUTHORIZED,
                    Json(ErrorResponse {
                        error: "Client commitment mismatch: H(c_nonce) does not match stored commitment".to_string(),
                    }),
                ));
            }

        }

        // c. Recompute pattern = derive_flash_pattern(&c_nonce_32, &challenge.nonce)
        let pattern = derive_flash_pattern(&c_nonce_32, &challenge.nonce);

        // d. Decode flash_frames: [0] = baseline, [1..4] = flash frames
        if frames_b64.len() != 4 {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!(
                        "flash_frames must contain exactly 4 frames (baseline + 3 rounds), got {}",
                        frames_b64.len()
                    ),
                }),
            ));
        }

        let baseline = decode_base64_jpeg(&frames_b64[0]).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!("Invalid baseline flash frame: {}", e),
                }),
            )
        })?;

        let mut flash_frames_decoded = Vec::with_capacity(3);
        for (i, frame_b64) in frames_b64[1..].iter().enumerate() {
            let frame = decode_base64_jpeg(frame_b64).map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: format!("Invalid flash frame {}: {}", i + 1, e),
                    }),
                )
            })?;
            flash_frames_decoded.push(frame);
        }

        // e. Call verify_spatial_flash(&baseline, &flash_frames, &pattern)
        let spatial_result = verify_spatial_flash(&baseline, &flash_frames_decoded, &pattern)
            .map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: format!("Spatial flash verification failed: {}", e),
                    }),
                )
            })?;


        // g. Compute delta fingerprints for ZK liveness proof
        let (delta_fps, expected_fps, _raw_deltas) =
            compute_liveness_evidence(&baseline, &flash_frames_decoded, &pattern);

        let (color_threshold, spatial_threshold, min_magnitude) = liveness_thresholds_from_env();

        // g2. Photometric convexity evidence per round (SPEC-006 REQ-111..113,
        // REQ-118). Crop the fixed central face region used by the spatial gate
        // before laying out patches, so background illumination cannot count as
        // facial coverage or convexity. Floors are configured by the operator;
        // zero leaves each check observational (ADR-010).
        let mut responding_patches = [0u8; 3];
        let mut convexity_scores = [0u16; 3];
        let mut photometric_report = Vec::with_capacity(3);
        let face_baseline = crop_face_region(&baseline).map_err(bad_liveness_input)?;
        for (r, (flash, round)) in flash_frames_decoded
            .iter()
            .zip(pattern.rounds.iter())
            .enumerate()
        {
            let quadrant_colours = [
                round.tl_color.to_array(),
                round.tr_color.to_array(),
                round.bl_color.to_array(),
                round.br_color.to_array(),
            ];
            let face_flash = crop_face_region(flash).map_err(bad_liveness_input)?;
            match photometric::extract(
                &face_baseline,
                &face_flash,
                &quadrant_colours,
                PatchGrid::default(),
            ) {
                Ok(pr) => {
                    // A 4×4 grid has 16 patches; the witness field admits ≤ 64.
                    responding_patches[r] = pr.responding_patches.min(64) as u8;
                    convexity_scores[r] = pr.convexity_score;
                    photometric_report.push(PhotometricRoundResponse {
                        round: r,
                        responding_patches: responding_patches[r],
                        convexity_score: pr.convexity_score,
                    });
                }
                Err(_e) => {
                    // Observational only while the floors are zero: leave the
                    // round at zero rather than failing the request.
                }
            }
        }
        photometric_rounds = Some(photometric_report);

        // g3. Corneal glint evidence per eye per round (SPEC-006 REQ-114..115,
        // CON-093). The client localises the irises and sends crops; the server
        // fingerprints each crop's delta against the baseline crop and derives
        // the expected composite from the quadrant colours weighted by the
        // grid split. The check enters the circuit only when the operator has
        // set SABLE_CORNEAL_TOLERANCE (ADR-010); otherwise the values are
        // carried and logged but the check is vacuous.
        let mut glint_fingerprints = [0u16; 6];
        let mut expected_glints = [0u16; 3];
        let corneal_live = corneal_tolerances.is_some();
        if let Some(crops_b64) = &req.eye_crops {
            let crops = decode_eye_crops(crops_b64).map_err(bad_liveness_input)?;
            let mut report = Vec::with_capacity(3);
            for (r, round) in pattern.rounds.iter().enumerate() {
                let quadrant_colours = [
                    round.tl_color.to_array(),
                    round.tr_color.to_array(),
                    round.bl_color.to_array(),
                    round.br_color.to_array(),
                ];
                // Quadrant areas from the same split the client renders
                // (35%–65%), scaled to integers.
                let sx = 0.5 + round.offset_x * 0.3 - 0.15;
                let sy = 0.5 + round.offset_y * 0.3 - 0.15;
                let weights = [
                    (sx * sy * 10_000.0) as u32,
                    ((1.0 - sx) * sy * 10_000.0) as u32,
                    (sx * (1.0 - sy) * 10_000.0) as u32,
                    ((1.0 - sx) * (1.0 - sy) * 10_000.0) as u32,
                ];
                let expected = corneal::expected_composite(&quadrant_colours, &weights)
                    .map_err(|e| bad_liveness_input(e.to_string()))?;
                let mut observed = [0u16; 2];
                for eye in 0..2 {
                    observed[eye] = corneal::glint_fingerprint(&crops[0][eye], &crops[r + 1][eye])
                        .map_err(|e| {
                            bad_liveness_input(format!("Invalid eye crop round {r} eye {eye}: {e}"))
                        })?;
                }
                glint_fingerprints[r * 2] = observed[0];
                glint_fingerprints[r * 2 + 1] = observed[1];
                expected_glints[r] = expected;

                let agrees = corneal_tolerances.map(|(ratio, mag)| {
                    [
                        corneal::agrees(observed[0], expected, ratio, mag),
                        corneal::agrees(observed[1], expected, ratio, mag),
                    ]
                });
                report.push(CornealRoundResponse {
                    round: r,
                    left_glint: observed[0].into(),
                    right_glint: observed[1].into(),
                    expected_glint: expected.into(),
                    enabled: corneal_live,
                    agrees,
                });
            }
            corneal_rounds = Some(report);
        }
        let (glint_ratio_tolerance, glint_magnitude_floor) = if corneal_live {
            corneal_tolerances.unwrap_or((0, 0))
        } else {
            (0, 0)
        };
        let (min_coverage, min_convexity) = geometry_floors_from_env();
        liveness_parameters = Some(LivenessParameters {
            color_threshold,
            spatial_threshold,
            min_magnitude,
            magnitude_scale: crate::flash_challenge::magnitude_scale(),
            min_coverage,
            min_convexity,
            corneal_enabled: corneal_live,
            glint_ratio_tolerance,
            glint_magnitude_floor,
        });

        let witness = LivenessWitness {
            delta_fingerprints: delta_fps,
            expected_fingerprints: expected_fps,
            // Demo guesses unless SABLE_LIVENESS_THRESHOLDS overrides them.
            color_threshold,
            spatial_threshold,
            min_magnitude,
            // SPEC-006 0.2.0 (REQ-119): bind the joint coin-flip identifier so
            // the proof answers this challenge and no other.
            challenge_id: challenge_identifier(&c_nonce_32, &challenge.nonce),
            // Photometric floors default to zero (ADR-010); SABLE_GEOMETRY_FLOORS
            // arms them as an explicit demo setting, visible in the digest.
            responding_patches,
            convexity_scores,
            min_coverage,
            min_convexity,
            // Corneal evidence is carried whenever the client sent eye crops;
            // the check is live only with SABLE_CORNEAL_TOLERANCE set.
            corneal_enabled: corneal_live,
            glint_ratio_tolerance,
            glint_magnitude_floor,
            glint_fingerprints,
            expected_glints,
            temporal_observed_symbols,
            temporal_expected_symbols,
            temporal_initial_phase,
            temporal_expected_phase: 0,
            temporal_phase_tolerance: 1,
            temporal_frame_tick_deltas,
            temporal_frame_tick_tolerance: 0,
            temporal_max_symbol_errors,
            temporal_enabled: false,
            temporal_capture_validated: false,
            ..LivenessWitness::default()
        };

        // OBS-085: which check family the native pre-check fails, without values.
        match LivenessCheckCircuit::new(witness.clone()).first_failing_check() {
            None => (),
            Some(f) => {
                liveness_failing_check = Some(LivenessFailureResponse {
                    check: format!("{:?}", f.check),
                    round: f.round,
                });
            }
        }
        liveness_witness = Some(witness);

        // f. Reject a failed spatial challenge. This runs after the extractors
        // and the OBS-085 pre-check on purpose: EXP-003 needs the geometric
        // evidence and the circuit's would-be verdict for presentation attacks,
        // which are exactly the requests this rejects.
        if !spatial_result.passed {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "Spatial color challenge failed".into(),
                }),
            ));
        }



        // h. Set response fields
        color_challenge_passed = Some(spatial_result.passed);
        liveness_passed = Some(spatial_result.passed);
        spatial_differentiation_score = Some(spatial_result.overall_spatial_score);
        region_match_scores = Some(
            spatial_result
                .region_scores
                .iter()
                .map(|s| RegionScoreResponse {
                    round: s.round,
                    tl_score: s.tl_score,
                    tr_score: s.tr_score,
                    bl_score: s.bl_score,
                    br_score: s.br_score,
                    spatial_diff_score: s.spatial_diff_score,
                })
                .collect(),
        );

        // Spatial color challenge is the primary liveness mechanism.
        // It is reflected directly in this proof response.
    }

    // ========================================================================
    // Generate Halo2 ZK Proof (face match + mandatory liveness)
    // ========================================================================
    let proof_start = Instant::now();
    if liveness_witness.is_none() || color_challenge_passed != Some(true) {
        return Err(bad_liveness_input("A validated liveness transcript is required".into()));
    }
    let now = unix_seconds().map_err(bad_liveness_input)?;
    let policy = PendingVerification::new(sable_core::zk::halo2::ExpectedPolicy {
        registered_template: session.template_commitment,
        threshold,
        challenge_digest: compute_challenge_digest(liveness_witness.as_ref().ok_or_else(|| bad_liveness_input("Missing witness".into()))?),
        required_liveness: true,
        circuit_id: sable_core::zk::halo2::AUTH_CIRCUIT_V2.into(),
        expires_at: now.saturating_add(30).saturating_sub(challenge.created_at.elapsed().as_secs()),
    }, challenge.created_at).map_err(bad_liveness_input)?;

    let (proof_bytes, halo2_result, liveness_proved_in_zk, proof_challenge_digest, proof_commitment) = {
        let mut prover = state.halo2_prover.write();
        if !policy.is_current(unix_seconds().map_err(bad_liveness_input)?, Instant::now()) {
            return Err(bad_liveness_input("Verification policy expired".into()));
        }
        // Distance is computed IN-CIRCUIT from the two embeddings (the prover no
        // longer trusts a precomputed scalar). `hamming_dist` is retained only
        // for logging and the response; the proof's public result is authoritative.
        match prover.prove_with_embeddings(
            &session.quantized_embedding,
            &live_quantized,
            threshold,
            liveness_witness,
        ) {
            Ok(proof) => {
                // Binding check: the proof must commit to the template registered
                // at enrollment. Holds by construction here (we prove over the
                // enrolled bytes), but enforcing it makes the soundness property
                // explicit and would catch any template/keys mismatch.
                let template_bound = proof.commitment == session.template_commitment;
                let result = template_bound && hamming_dist <= threshold;
                let liveness_zk = proof.liveness_passed;
                (proof.proof_bytes, result, liveness_zk, proof.challenge_digest, proof.commitment)
            }
            Err(e) => {
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: format!("Halo2 proof generation failed: {}", e),
                    }),
                ));
            }
        }
    };

    let proof_time = proof_start.elapsed();


    // If Halo2 says no match, return error
    if !halo2_result {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Face does not match enrolled template".into(),
            }),
        ));
    }

    state.store_verification_policy(&principal, challenge.challenge_id.clone(), policy, unix_seconds().map_err(bad_liveness_input)?)
        .map_err(bad_liveness_input)?;

    // Canonical wire encoding matches the circuit's five public instances.
    let public_inputs = {
        use ff::PrimeField;
        [Halo2Fr::from(1), Halo2Fr::from(threshold), Halo2Fr::from(u64::from(liveness_proved_in_zk)), proof_challenge_digest, proof_commitment]
            .iter().map(|value| hex::encode(value.to_repr())).collect()
    };

    let total_time = total_start.elapsed();

    Ok(Json(ProveResponse {
        proof_hex: hex::encode(&proof_bytes),
        public_inputs_hex: public_inputs,
        distance,
        hamming_distance: hamming_dist,
        hamming_threshold: threshold,
        quality_score,
        proof_size_bytes: proof_bytes.len(),
        liveness_passed,
        color_challenge_passed,
        liveness_proved_in_zk: if color_challenge_passed.is_some() { Some(liveness_proved_in_zk) } else { None },
        region_match_scores,
        spatial_differentiation_score,
        photometric_rounds,
        corneal_rounds,
        liveness_parameters: liveness_parameters.clone(),
        liveness_failing_check,
        rolling_shutter_observation,
        timings: ProveTimings {
            feature_scan_ms: scan_time.as_secs_f64() * 1000.0,
            distance_calc_ms: distance_time.as_secs_f64() * 1000.0,
            proof_generation_ms: proof_time.as_secs_f64() * 1000.0,
            total_ms: total_time.as_secs_f64() * 1000.0,
        },
        what_was_proven: {
            // Only statements the Halo2 circuit actually constrains are labelled
            // "in circuit"; server-side checks are labelled as such.
            let mut proven = vec![
                "The live embedding is within the Hamming threshold of the enrolled template, on thermometer-encoded features (in circuit)".to_string(),
                format!("Hamming distance ≤ {} (public threshold; the distance itself stays private)", threshold),
                "The template used is the one committed at enrolment: its Poseidon commitment is a public input (in circuit)".to_string(),
                "The proof answers this challenge and no other: the liveness digest binds both coin-flip nonces and every public liveness parameter (in circuit)".to_string(),
                format!("Server-side scan quality check passed (score {:.2}; not in circuit)", quality_score),
            ];
            if liveness_proved_in_zk && color_challenge_passed == Some(true) {
                proven.push("Liveness relation satisfied: colour, spatial and magnitude checks on the reflected-flash fingerprints, public liveness bit = 1 (in circuit)".to_string());
            } else if color_challenge_passed == Some(true) {
                proven.push("Server-side spatial reflectance check passed; the circuit's quantised check did not, so the proof's liveness bit is 0 (see BUG-003)".to_string());
            }
            if let Some(p) = &liveness_parameters {
                let mut live = Vec::new();
                if p.min_coverage > 0 { live.push(format!("coverage ≥ {}/16", p.min_coverage)); }
                if p.min_convexity > 0 { live.push(format!("convexity ≥ {:.3}", p.min_convexity as f64 / 32768.0)); }
                if p.corneal_enabled { live.push("corneal glint agreement".to_string()); }
                if live.is_empty() {
                    proven.push("Coverage, convexity and corneal floors are carried in the digest at zero: observational until EXP-003 fixes them (SPEC-006 ADR-010)".to_string());
                } else {
                    proven.push(format!("Geometric checks live in circuit: {} (demo settings, not validated; the floors are bound in the digest)", live.join(", ")));
                }
            }
            proven
        },
        what_stayed_private: {
            let mut private = vec![
                "The live embedding and the enrolled template (512 quantised bytes each)".to_string(),
                "The exact Hamming distance (only that it is within the threshold)".to_string(),
                "These are private inputs to the proof, but the demo server receives and processes them".to_string(),
            ];
            if color_challenge_passed.is_some() {
                private.push("The twelve reflected-colour fingerprints (one per screen quadrant per round)".to_string());
                private.push("Per-round patch coverage, convexity scores and corneal glint fingerprints (private witnesses)".to_string());
            }
            if liveness_passed.is_some() {
                private.push("Captured frames and eye crops are uploaded to the demo server; they are not on-device private".to_string());
            }
            private
        },
    }))
}

// ============================================================================
// Verification Endpoint
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct VerifyRequest {
    pub proof_hex: String,
    #[allow(dead_code)]
    pub public_inputs_hex: Vec<String>,
    /// Optional challenge ID to look up pending liveness result.
    pub challenge_id: Option<String>,
    /// Backwards-compatible field (no longer used for liveness lookup).
    #[allow(dead_code)]
    pub session_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct VerifyResponse {
    pub valid: bool,
    pub verification_time_ms: f64,
    pub details: VerificationDetails,
}

#[derive(Debug, Serialize)]
pub struct VerificationDetails {
    pub commitment_valid: bool,
    pub distance_check_passed: bool,
    pub temporal_check_passed: Option<bool>,
    pub quality_check_passed: bool,
    pub liveness_check_passed: Option<bool>,
    /// Whether liveness was verified inside the ZK proof (from public_inputs[2]).
    pub liveness_proved_in_zk: bool,
}

pub async fn verify(
    Extension(principal): Extension<Principal>,
    State(state): State<AppState>,
    Json(req): Json<VerifyRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let start = Instant::now();

    // Validate and decode proof
    if req.public_inputs_hex.len() != 5 || req.proof_hex.len() > 20 * 1024 {
        return Err(bad_liveness_input("Invalid proof or public input count".into()));
    }
    let proof_bytes = hex::decode(&req.proof_hex).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid proof hex".to_string(),
            }),
        )
    })?;

    let challenge_id = req.challenge_id.as_deref()
        .ok_or_else(|| bad_liveness_input("challenge_id is required".into()))?;
    let policy = state.take_verification_policy(&principal, challenge_id)
        .ok_or_else(|| bad_liveness_input("Challenge not found, expired or already consumed".into()))?;
    let encoded: Result<Vec<[u8; 32]>, _> = req.public_inputs_hex.iter().map(|value| {
        require_nonce_hex(Some(value), "public instance")?;
        let bytes = hex::decode(value).map_err(|_| "Invalid instance encoding".to_string())?;
        bytes.try_into().map_err(|_| "Invalid instance length".to_string())
    }).collect();
    let public_inputs = sable_core::zk::halo2::decode_instances(&encoded.map_err(bad_liveness_input)?)
        .map_err(|_| bad_liveness_input("Non-canonical public input".into()))?;
    let liveness_val = public_inputs[2] == Halo2Fr::from(1);
    let digest_val = public_inputs[3];
    let commitment_val = public_inputs[4];
    let proof = Proof {
        proof_bytes,
        public_inputs,
        liveness_passed: liveness_val,
        challenge_digest: digest_val,
        commitment: commitment_val,
    };
    let verification_now = unix_seconds().map_err(bad_liveness_input)?;
    policy.validate(&proof, verification_now, Instant::now()).map_err(bad_liveness_input)?;

    // Verify using Halo2
    let verification_result = {
        let mut prover = state.halo2_prover.write();
        match FaceVerificationVerifier::from_prover(&mut prover) {
            Ok(verifier) => verifier.verify_expected(&proof, &policy.expected, unix_seconds().map_err(bad_liveness_input)?),
            Err(e) => Err(e),
        }
    };

    // Key generation/verification can cross the deadline after the initial check.
    // The consumed policy must remain expired even if the wall clock rolls back.
    policy.validate(&proof, unix_seconds().map_err(bad_liveness_input)?, Instant::now())
        .map_err(bad_liveness_input)?;
    let verification_time = start.elapsed();

    // Look up liveness result if challenge_id provided.
    let liveness_check = req
        .challenge_id
        .as_deref()
        .and_then(|cid| state.get_liveness_result(&principal, cid))
        .map(|r| r.passed);

    match verification_result {
        Ok(is_match) => {
            Ok(Json(VerifyResponse {
                valid: is_match,
                verification_time_ms: verification_time.as_secs_f64() * 1000.0,
                details: VerificationDetails {
                    commitment_valid: true,
                    distance_check_passed: is_match,
                    temporal_check_passed: None,
                    quality_check_passed: true,
                    liveness_check_passed: liveness_check,
                    liveness_proved_in_zk: proof.liveness_passed,
                },
            }))
        }
        Err(_e) => {
            // Return valid=false rather than error for invalid proofs
            Ok(Json(VerifyResponse {
                valid: false,
                verification_time_ms: verification_time.as_secs_f64() * 1000.0,
                details: VerificationDetails {
                    commitment_valid: false,
                    distance_check_passed: false,
                    temporal_check_passed: None,
                    quality_check_passed: true,
                    liveness_check_passed: liveness_check,
                    liveness_proved_in_zk: false,
                },
            }))
        }
    }
}

// ============================================================================
// Health Check
// ============================================================================

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
}

pub async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "healthy".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

// ============================================================================
// Screen Flash Liveness Endpoint
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct ScreenFlashRequest {
    /// Challenge ID to bind liveness to a single authentication attempt.
    pub challenge_id: String,
    /// Optional session ID for client-side consistency checks.
    pub session_id: Option<String>,
    /// Baseline image (before flash) as base64-encoded JPEG
    pub baseline_image: String,
    /// Flash image (during flash) as base64-encoded JPEG
    pub flash_image: String,
}

#[derive(Debug, Serialize)]
pub struct ScreenFlashResponse {
    pub passed: bool,
    pub signals: LivenessSignals,
    pub timing_ms: f64,
}

#[derive(Debug, Serialize)]
pub struct LivenessSignals {
    pub reflectance_variance: f64,
    pub reflectance_gradient: f64,
    pub highlight_softness: f64,
    pub channel_consistency: f64,
}

pub async fn screen_flash_check(
    Extension(principal): Extension<Principal>,
    State(state): State<AppState>,
    Json(req): Json<ScreenFlashRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let start = Instant::now();

    // Verify challenge exists (liveness is challenge-bound and single-use).
    let challenge = state.get_challenge(&principal, &req.challenge_id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Challenge not found or expired".to_string(),
            }),
        )
    })?;

    if challenge.created_at.elapsed() >= std::time::Duration::from_secs(30) {
        let _ = state.take_liveness_result(&principal, &req.challenge_id);
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Challenge expired".to_string(),
            }),
        ));
    }

    if let Some(session_id) = &req.session_id {
        if session_id != &challenge.session_id {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Session does not match challenge".to_string(),
                }),
            ));
        }
    }

    // Verify session exists
    state.get_session(&principal, &challenge.session_id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Session not found".to_string(),
            }),
        )
    })?;

    // Decode baseline image
    let baseline_img = decode_base64_jpeg(&req.baseline_image).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("Invalid baseline image: {}", e),
            }),
        )
    })?;

    // Decode flash image
    let flash_img = decode_base64_jpeg(&req.flash_image).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("Invalid flash image: {}", e),
            }),
        )
    })?;

    // ---- Ratio-Laplacian smoothness check ----
    // The key physics: a photo on a screen has HIGH-FREQUENCY variation in the
    // reflectance ratio because the displayed image modulates the baseline
    // denominator. A real 3D face produces only SMOOTH, LOW-FREQUENCY ratio
    // variation from geometry. We detect this by computing the Laplacian (2nd
    // derivative) of the ratio map — high energy = photo attack.
    let smoothness = check_ratio_smoothness(&baseline_img, &flash_img);


    // Run screen flash extractor with high-security thresholds
    let thresholds = ScreenFlashThresholds::high_security();
    let extractor = ScreenFlashExtractor::with_thresholds(thresholds).unwrap();
    let signals = extractor
        .extract_signals(&baseline_img, &flash_img)
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!("Signal extraction failed: {}", e),
                }),
            )
        })?;

    let reflectance_passed = signals.passes_thresholds(&thresholds);

    // Both checks must pass: reflectance signals AND ratio smoothness
    let passed = reflectance_passed && smoothness.passed;

    let timing = start.elapsed();

    // Convert fixed-point signals to float for display
    let variance_f = signals.reflectance_variance as f64 / 65535.0;
    let gradient_f = signals.reflectance_gradient as f64 / 65535.0;
    let softness_f = signals.highlight_softness as f64 / 65535.0;
    let consistency_f = signals.channel_consistency as f64 / 65535.0;


    // Store result for this specific challenge (single-use in auth_prove).
    state.store_liveness_result(&principal,
        req.challenge_id,
        LivenessResult {
            passed,
            reflectance_variance: variance_f,
            reflectance_gradient: gradient_f,
            highlight_softness: softness_f,
            channel_consistency: consistency_f,
            checked_at: Instant::now(),
        },
    ).map_err(storage_unavailable)?;

    Ok(Json(ScreenFlashResponse {
        passed,
        signals: LivenessSignals {
            reflectance_variance: variance_f,
            reflectance_gradient: gradient_f,
            highlight_softness: softness_f,
            channel_consistency: consistency_f,
        },
        timing_ms: timing.as_secs_f64() * 1000.0,
    }))
}

/// Result of ratio-Laplacian smoothness check.
struct RatioSmoothnessCheck {
    /// Whether the check passed.
    passed: bool,
}

/// Detect photo-on-screen attacks using the Laplacian of the reflectance ratio.
///
/// Physics: ratio = flash_pixel / baseline_pixel.
///
/// For a REAL face: both baseline (ambient) and flash vary smoothly with 3D
/// geometry, so the ratio varies smoothly → low Laplacian energy.
///
/// For a PHOTO on a screen: the baseline contains the displayed photo's
/// high-frequency content (edges, textures). The flash adds a relatively
/// uniform specular/ambient contribution. So ratio = (emission + flash) /
/// emission = 1 + flash/emission. Since emission varies at the photo's spatial
/// frequency, the ratio inherits that high-frequency structure → high
/// Laplacian energy.
///
/// This is the fundamental physical distinction that cannot be spoofed by
/// simply displaying a face photo.
fn check_ratio_smoothness(baseline: &PalmImage, flash: &PalmImage) -> RatioSmoothnessCheck {
    let w = baseline.width as usize;
    let h = baseline.height as usize;

    // Minimum baseline intensity to avoid dark-pixel amplification
    let min_intensity: f64 = 15.0;

    // Block size for downsampling — suppresses sensor noise and JPEG artifacts
    // while preserving spatial structure. 8×8 blocks on 640×480 → 80×60 grid.
    let block = 8usize;
    let dw = w / block;
    let dh = h / block;

    if dw < 3 || dh < 3 {
        return RatioSmoothnessCheck {
            passed: false,
        };
    }

    // 1. Compute block-averaged luminance ratio map (downsampled)
    let mut ratio_map: Vec<f64> = Vec::with_capacity(dw * dh);
    let mut total_ratio = 0.0;

    for by in 0..dh {
        for bx in 0..dw {
            let mut b_sum = 0.0;
            let mut f_sum = 0.0;
            let mut pix_count = 0.0;

            for dy in 0..block {
                for dx in 0..block {
                    let px = bx * block + dx;
                    let py = by * block + dy;
                    if px < w && py < h {
                        let idx = (py * w + px) * 3;
                        b_sum += (baseline.data[idx] as f64
                            + baseline.data[idx + 1] as f64
                            + baseline.data[idx + 2] as f64)
                            / 3.0;
                        f_sum += (flash.data[idx] as f64
                            + flash.data[idx + 1] as f64
                            + flash.data[idx + 2] as f64)
                            / 3.0;
                        pix_count += 1.0;
                    }
                }
            }

            let b_avg = (b_sum / pix_count).max(min_intensity);
            let f_avg = f_sum / pix_count;
            let ratio = (f_avg / b_avg).clamp(0.3, 4.0);
            ratio_map.push(ratio);
            total_ratio += ratio;
        }
    }

    let mean_ratio = total_ratio / ratio_map.len() as f64;

    // 2. Compute discrete Laplacian energy on the downsampled ratio map
    let mut laplacian_sum_sq = 0.0;
    let mut count = 0u64;

    for y in 1..(dh - 1) {
        for x in 1..(dw - 1) {
            let idx = y * dw + x;
            let lap = ratio_map[idx - 1]
                + ratio_map[idx + 1]
                + ratio_map[idx - dw]
                + ratio_map[idx + dw]
                - 4.0 * ratio_map[idx];
            laplacian_sum_sq += lap * lap;
            count += 1;
        }
    }

    let laplacian_energy = if count > 0 {
        laplacian_sum_sq / count as f64
    } else {
        0.0
    };

    // After 8×8 block averaging, sensor noise is suppressed ~64× in variance.
    // Structural patterns (photo edges/textures) persist at the block scale.
    // Real face: smooth ratio → very low Laplacian energy
    // Photo attack: ratio inherits photo structure → higher Laplacian energy
    // Threshold tuned from empirical observations.
    let passed = laplacian_energy < 0.35 && mean_ratio > 0.95;

    RatioSmoothnessCheck {
        passed,
    }
}

fn bad_liveness_input(error: String) -> (StatusCode, Json<ErrorResponse>) {
    (StatusCode::BAD_REQUEST, Json(ErrorResponse { error }))
}

fn storage_unavailable(error: String) -> (StatusCode, Json<ErrorResponse>) {
    (StatusCode::SERVICE_UNAVAILABLE, Json(ErrorResponse { error }))
}

fn unix_seconds() -> Result<u64, String> {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_secs()).map_err(|_| "Verifier clock unavailable".into())
}

fn require_nonce_hex(value: Option<&str>, field: &str) -> Result<(), String> {
    let value = value.ok_or_else(|| format!("{field} is required"))?;
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err(format!("{field} must be 32 bytes of lowercase hexadecimal"));
    }
    Ok(())
}

/// Reject incomplete captures before looking up a challenge or decoding images.
/// This validates structure only; capture provenance is a separate trust boundary.
fn require_capture_input(req: &ProveRequest) -> Result<(), String> {
    if req.noise_level.is_some() {
        return Err("Simulation is unavailable on authentication routes".into());
    }
    let embedding = req.face_embedding.as_ref().ok_or("face_embedding is required")?;
    if embedding.len() != 1024 || embedding.iter().any(|v| !v.is_finite()) {
        return Err("face_embedding must contain exactly 1024 finite values".into());
    }
    if !embedding.iter().any(|v| *v != 0.0) {
        return Err("face_embedding must have nonzero magnitude".into());
    }
    require_nonce_hex(req.c_nonce.as_deref(), "c_nonce")?;
    let frames = req.flash_frames.as_ref().ok_or("flash_frames is required")?;
    if frames.len() != 4 || frames.iter().any(|frame| frame.is_empty()) {
        return Err("flash_frames must contain baseline and three nonempty flash frames".into());
    }
    Ok(())
}

#[cfg(test)]
mod capture_input_security_tests {
    use super::*;

    fn capture() -> ProveRequest {
        ProveRequest {
            challenge_id: "challenge".into(),
            noise_level: None,
            face_embedding: Some(vec![0.1; 1024]),
            c_nonce: Some("01".repeat(32)),
            flash_frames: Some(vec!["encoded frame".into(); 4]),
            eye_crops: None,
            rolling_shutter: None,
        }
    }

    #[test]
    fn test_169_untrusted_request_cannot_claim_capture_validation() {
        let request = serde_json::from_str::<ProveRequest>(
            r#"{
                "challenge_id":"challenge",
                "capture_validated":true
            }"#,
        );
        assert!(request.is_err());
        let nested_claim = serde_json::from_str::<ProveRequest>(
            r#"{
                "challenge_id":"challenge",
                "rolling_shutter":{
                    "observed_symbols":[2,1,3,0,3,2,1,3,1,2,1,0],
                    "initial_phase":0,
                    "frame_tick_deltas":[4,4],
                    "capture_validated":true
                }
            }"#,
        );
        assert!(nested_claim.is_err());

        let mut request = capture();
        request.rolling_shutter = Some(RollingShutterObservationRequest {
            observed_symbols: [2, 1, 3, 0, 3, 2, 1, 3, 1, 2, 1, 0],
            initial_phase: 0,
            frame_tick_deltas: [4, 4],
        });
        let observation = request.rolling_shutter.unwrap();
        assert!(TemporalObservation {
            symbols: observation.observed_symbols,
            initial_phase: observation.initial_phase,
            frame_tick_deltas: observation.frame_tick_deltas,
        }
        .recognise()
        .is_ok());

        let report = RollingShutterObservationResponse {
            mode: "observe-only",
            enabled_in_circuit: false,
            capture_validated: false,
            relation_matched: true,
            phase_matched: true,
            timing_matched: true,
            symbol_mismatches: 0,
            maximum_symbol_errors: 1,
        };
        let encoded = serde_json::to_string(&report).unwrap();
        assert!(encoded.contains("observe-only"));
        assert!(!encoded.contains("attest"));
    }

    #[test]
    fn rolling_shutter_json_grammar_rejects_malformed_objects() {
        let wrap = |body: &str| {
            serde_json::from_str::<ProveRequest>(&format!(
                r#"{{"challenge_id":"challenge","rolling_shutter":{body}}}"#
            ))
        };
        assert!(wrap(
            r#"{"observed_symbols":[0,1],"initial_phase":0,"frame_tick_deltas":[4,4]}"#
        )
        .is_err());
        assert!(wrap(
            r#"{"observed_symbols":[2,1,3,0,3,2,1,3,1,2,1,0],"initial_phase":0,"initial_phase":1,"frame_tick_deltas":[4,4]}"#
        )
        .is_err());
        assert!(wrap(
            r#"{"observed_symbols":[2,1,3,0,3,2,1,3,1,2,1,256],"initial_phase":0,"frame_tick_deltas":[4,4]}"#
        )
        .is_err());
        assert!(wrap(
            r#"{"observed_symbols":[2,1,3,0,3,2,1,3,1,2,1,0],"initial_phase":0}"#
        )
        .is_err());
    }

    #[tokio::test]
    async fn authentication_routes_reject_omissions_and_policy_replay() {
        use sable_core::zk::halo2::{ExpectedPolicy, AUTH_CIRCUIT_V2};
        let state = AppState::new();
        let principal = Principal("alice".into());
        let missing = EnrollRequest { user_id: "known-user".into(), face_embedding: None };
        assert!(enroll(Extension(principal.clone()), State(state.clone()), Json(missing)).await.is_err());
        let attack: ProveRequest = serde_json::from_str(r#"{"challenge_id":"target"}"#).unwrap();
        assert!(auth_prove(Extension(principal.clone()), State(state.clone()), Json(attack)).await.is_err());
        let challenge = ChallengeRequest { session_id: "target".into(), client_commitment: None };
        assert!(auth_challenge(Extension(principal.clone()), State(state.clone()), Json(challenge)).await.is_err());
        let now = unix_seconds().unwrap();
        let policy = ExpectedPolicy {
            registered_template: Halo2Fr::from(17),
            threshold: 200,
            challenge_digest: Halo2Fr::from(23),
            required_liveness: true,
            circuit_id: AUTH_CIRCUIT_V2.into(),
            expires_at: now + 30,
        };
        let pending = || PendingVerification::new(policy.clone(), Instant::now()).unwrap();
        state.store_verification_policy(&principal, "target".into(), pending(), now).unwrap();
        assert!(state.store_verification_policy(&principal, "target".into(), pending(), now).is_err());
        // All-zero instances have valid encoding but conflict with trusted policy.
        let request = || VerifyRequest {
            proof_hex: "00".into(),
            public_inputs_hex: vec!["00".repeat(32); 5],
            challenge_id: Some("target".into()),
            session_id: None,
        };
        let other = Principal("bob".into());
        assert!(verify(Extension(other.clone()), State(state.clone()), Json(request())).await.is_err());
        // Bob's failed verification must not consume Alice's policy.
        assert!(state.take_verification_policy(&other, "target").is_none());
        let preserved = state.take_verification_policy(&principal, "target").unwrap();
        state.store_verification_policy(&principal, "target".into(), preserved, now).unwrap();
        state.store_challenge(&principal, AuthChallenge {
            challenge_id: "owned-challenge".into(), session_id: "owned-session".into(), nonce: [1; 32],
            client_commitment: Some("01".repeat(32)), created_at: Instant::now(),
        }).unwrap();
        assert!(state.get_challenge(&other, "owned-challenge").is_none());
        assert!(state.remove_challenge(&other, "owned-challenge").is_none());
        assert!(state.remove_challenge(&principal, "owned-challenge").is_some());
        let session = |id: &str| EnrollmentSession {
            session_id: id.into(), commitment_bytes: [0; 48],
            face_embedding: vec![0.0; 1024], quantized_embedding: vec![0; 512],
            template_commitment: Halo2Fr::from(17), created_at: Instant::now(),
        };
        for id in ["one", "two", "three", "four"] {
            state.store_session(&principal, session(id)).unwrap();
        }
        assert!(state.store_session(&principal, session("five")).is_err());
        assert!(state.get_session(&other, "one").is_none());
        state.store_session(&other, session("one")).unwrap();
        assert!(state.get_session(&principal, "one").is_some());
        assert!(state.get_session(&other, "one").is_some());
        // Exercise the actual API composition, not just direct handler calls.
        use axum::{body::Body, http::Request};
        use tower::ServiceExt;
        let credentials = crate::auth::Credentials::from_json(&format!(
            r#"[{{"principal":"alice","token":"{}"}},{{"principal":"bob","token":"{}"}}]"#,
            "ab".repeat(32), "cd".repeat(32),
        )).unwrap();
        let app = crate::routes::api_router(state.clone(), credentials);
        let unauthorized = Request::builder().uri("/auth/prove").method("POST")
            .header("content-length", "999999999").body(Body::empty()).unwrap();
        assert_eq!(app.clone().oneshot(unauthorized).await.unwrap().status(), StatusCode::UNAUTHORIZED);
        let health = Request::builder().uri("/health").body(Body::empty()).unwrap();
        assert_eq!(app.clone().oneshot(health).await.unwrap().status(), StatusCode::OK);
        let challenge_request = |token: &str| Request::builder().uri("/auth/challenge").method("POST")
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(Body::from(format!(r#"{{"session_id":"two","client_commitment":"{}","principal":"alice"}}"#, "01".repeat(32)))).unwrap();
        assert_eq!(app.clone().oneshot(challenge_request(&"cd".repeat(32))).await.unwrap().status(), StatusCode::NOT_FOUND);
        assert_eq!(app.oneshot(challenge_request(&"ab".repeat(32))).await.unwrap().status(), StatusCode::OK);
        assert!(verify(Extension(principal.clone()), State(state.clone()), Json(request())).await.is_err());
        assert!(state.take_verification_policy(&principal, "target").is_none());
        assert!(verify(Extension(principal.clone()), State(state.clone()), Json(request())).await.is_err());
        let mut expired = policy;
        expired.expires_at = now;
        assert!(state.store_verification_policy(&principal, "expired".into(),
            PendingVerification::new(expired.clone(), Instant::now()).unwrap(), now).is_err());
        // Rolling back the wall clock cannot admit a policy whose original
        // challenge's monotonic deadline already passed during proof generation.
        expired.expires_at = now + 30;
        assert!(state.store_verification_policy(&principal, "slow-proof".into(),
            PendingVerification::new(expired, Instant::now() - std::time::Duration::from_secs(31)).unwrap(),
            now - 10).is_err());
    }

    #[test]
    fn challenge_only_attack_and_partial_captures_are_rejected() {
        let attack: ProveRequest = serde_json::from_str(r#"{"challenge_id":"target"}"#).unwrap();
        assert!(require_capture_input(&attack).is_err());
        assert!(require_capture_input(&capture()).is_ok());
        for field in ["face_embedding", "c_nonce", "flash_frames"] {
            let mut req = capture();
            match field {
                "face_embedding" => req.face_embedding = None,
                "c_nonce" => req.c_nonce = None,
                _ => req.flash_frames = None,
            }
            assert!(require_capture_input(&req).is_err(), "{field}");
        }
        let mut req = capture();
        req.noise_level = Some(0.0);
        assert!(require_capture_input(&req).is_err());
    }

    #[test]
    fn malformed_embeddings_and_frame_sets_are_rejected() {
        for embedding in [vec![], vec![0.1; 1023], vec![0.1; 1025], vec![0.0; 1024], vec![f64::NAN; 1024], vec![f64::INFINITY; 1024]] {
            let mut req = capture();
            req.face_embedding = Some(embedding);
            assert!(require_capture_input(&req).is_err());
        }
        for frames in [vec![], vec!["frame".into(); 3], vec!["frame".into(); 5], vec![String::new(); 4]] {
            let mut req = capture();
            req.flash_frames = Some(frames);
            assert!(require_capture_input(&req).is_err());
        }
    }

    #[test]
    fn commitments_and_nonces_require_canonical_encoding() {
        assert!(require_nonce_hex(None, "commitment").is_err());
        for invalid in [String::new(), "00".repeat(31), "00".repeat(33), "AA".repeat(32), "gg".repeat(32), format!("0x{}", "00".repeat(32))] {
            assert!(require_nonce_hex(Some(&invalid), "commitment").is_err());
        }
        assert!(require_nonce_hex(Some(&"ab".repeat(32)), "commitment").is_ok());
    }

    #[test]
    fn enrollment_conversion_rejects_invalid_numeric_inputs() {
        for invalid in [vec![0.0; 1024], vec![f64::NAN; 1024], vec![f64::INFINITY; 1024], vec![f64::MAX; 1024], vec![1e37; 1024], vec![0.1; 1023]] {
            assert!(convert_face_embedding_to_features(&invalid).is_err());
        }
        assert!(convert_face_embedding_to_features(&vec![0.1; 1024]).is_ok());
    }
}

fn require_corneal_evidence(req: &ProveRequest, enabled: bool) -> Result<(), String> {
    if enabled && (req.eye_crops.is_none() || req.c_nonce.is_none() || req.flash_frames.is_none()) {
        return Err("Configured corneal check requires eye_crops, c_nonce and flash_frames".into());
    }
    Ok(())
}

/// Validate all eight crops before computing any corneal evidence.
fn decode_eye_crops(encoded: &[Vec<String>]) -> Result<Vec<[PalmImage; 2]>, String> {
    if encoded.len() != 4 || encoded.iter().any(|pair| pair.len() != 2) {
        return Err("eye_crops must be 4 frames × 2 eyes".into());
    }
    let mut dimensions = None;
    let mut crops = Vec::with_capacity(4);
    for pair in encoded {
        let left = decode_base64_image(&pair[0])?;
        let right = decode_base64_image(&pair[1])?;
        for image in [&left, &right] {
            let size = (image.width, image.height);
            if !(8..=256).contains(&size.0)
                || !(8..=256).contains(&size.1)
                || dimensions.is_some_and(|expected| expected != size)
            {
                return Err("All eye crops must share dimensions in [8, 256]".into());
            }
            dimensions = Some(size);
        }
        crops.push([left, right]);
    }
    Ok(crops)
}

/// Decode a base64 (optionally data-URL) PNG or JPEG into an RGB8 image.
///
/// Eye crops arrive as PNG: at ~16 px a JPEG's chroma subsampling would smear
/// the very colour the glint check measures.
fn decode_base64_image(input: &str) -> std::result::Result<PalmImage, String> {
    crate::images::decode(input, crate::images::CaptureImage::Eye)
}

fn decode_base64_jpeg(input: &str) -> std::result::Result<PalmImage, String> {
    crate::images::decode(input, crate::images::CaptureImage::Frame)
}

// ============================================================================
// Error Types
// ============================================================================

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Convert 1024-dimensional face embedding to 512 ZK-compatible features
///
/// The Human library produces a 1024-dimensional face embedding. We convert this
/// to 512 features suitable for ZK proof generation by averaging adjacent pairs
/// and normalizing to the expected range.
fn convert_face_embedding_to_features(
    embedding: &[f64],
) -> Result<([f32; FEATURE_VECTOR_SIZE], f32), (StatusCode, Json<ErrorResponse>)> {
    const FACE_EMBEDDING_SIZE: usize = 1024;

    // Validate embedding size
    if embedding.len() != FACE_EMBEDDING_SIZE {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!(
                    "Invalid face embedding size: expected {}, got {}",
                    FACE_EMBEDDING_SIZE,
                    embedding.len()
                ),
            }),
        ));
    }

    let mut features = [0.0f32; FEATURE_VECTOR_SIZE];
    if embedding.iter().any(|value| !value.is_finite()) || !embedding.iter().any(|value| *value != 0.0) {
        return Err(bad_liveness_input("Embedding must be finite and nonzero".into()));
    }
    // Leave headroom for 512-element f32 sums of squared feature differences.
    let component_limit = f64::from(f32::MAX).sqrt() / 1024.0;
    if embedding.iter().any(|value| value.abs() > component_limit) {
        return Err(bad_liveness_input("Embedding exceeds supported numeric range".into()));
    }

    // Convert 1024-dim to 512-dim by averaging adjacent pairs
    // This preserves the discriminative information while matching our ZK circuit size
    for i in 0..FEATURE_VECTOR_SIZE {
        let idx = i * 2;
        let avg = (embedding[idx] + embedding[idx + 1]) / 2.0;
        // Normalize to [-2, 2] range (face embeddings are typically in [-1, 1])
        features[i] = (avg * 2.0) as f32;
        if !features[i].is_finite() {
            return Err(bad_liveness_input("Embedding exceeds supported numeric range".into()));
        }
    }

    // Calculate quality score based on embedding statistics
    // Higher variance in the embedding indicates a more distinctive face
    let mean: f64 = embedding.iter().sum::<f64>() / FACE_EMBEDDING_SIZE as f64;
    let variance: f64 = embedding.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / FACE_EMBEDDING_SIZE as f64;
    let std_dev = variance.sqrt();

    // Quality score based on embedding characteristics
    // Good embeddings have reasonable variance (not too flat, not too noisy)
    let quality_score = (std_dev * 2.0).min(1.0).max(0.5) as f32;

    Ok((features, quality_score))
}

/// Calculate cosine similarity between two face embedding vectors
/// Returns a value in [-1, 1] where 1 = identical, 0 = orthogonal, -1 = opposite
fn cosine_similarity(a: &[f64], b: &[f64]) -> f64 {
    if a.len() != b.len() || a.is_empty() {
        return 0.0;
    }

    let dot_product: f64 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
    let norm_a: f64 = a.iter().map(|x| x * x).sum::<f64>().sqrt();
    let norm_b: f64 = b.iter().map(|x| x * x).sum::<f64>().sqrt();

    if norm_a == 0.0 || norm_b == 0.0 {
        return 0.0;
    }

    dot_product / (norm_a * norm_b)
}

// ============================================================================
// Deterministic fuzzy authentication and deduplication were withdrawn (SBL-RT-010).

#[cfg(test)]
mod liveness_input_tests {
    use super::*;
    use base64::Engine;
    use image::ImageEncoder;

    fn png(side: u32) -> String {
        let mut bytes = Vec::new();
        image::codecs::png::PngEncoder::new(&mut bytes)
            .write_image(
                &vec![100; (side * side * 3) as usize],
                side,
                side,
                image::ExtendedColorType::Rgb8,
            )
            .unwrap();
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    #[test]
    fn configured_corneal_check_requires_all_capture_inputs() {
        let complete = serde_json::json!({
            "challenge_id": "test", "c_nonce": "00", "flash_frames": [], "eye_crops": []
        });
        let req = serde_json::from_value(complete.clone()).unwrap();
        assert!(require_corneal_evidence(&req, true).is_ok());
        for field in ["c_nonce", "flash_frames", "eye_crops"] {
            let mut missing = complete.clone();
            missing.as_object_mut().unwrap().remove(field);
            let req = serde_json::from_value(missing).unwrap();
            assert!(
                require_corneal_evidence(&req, true).is_err(),
                "missing {field}"
            );
            assert!(require_corneal_evidence(&req, false).is_ok());
        }
    }

    #[test]
    fn corneal_crops_reject_invalid_shapes_images_and_dimensions() {
        let valid = vec![vec![png(16); 2]; 4];
        assert_eq!(decode_eye_crops(&valid).unwrap().len(), 4);
        assert!(decode_eye_crops(&valid[..3]).is_err());
        for replacement in [
            vec![],
            vec![png(16)],
            vec![png(4); 2],
            vec![png(24); 2],
            vec!["invalid".into(); 2],
        ] {
            let mut invalid = valid.clone();
            invalid[2] = replacement;
            assert!(decode_eye_crops(&invalid).is_err());
        }
        // Even a consistent size per eye must not allow different sizes between eyes.
        assert!(decode_eye_crops(&vec![vec![png(16), png(24)]; 4]).is_err());
    }
}
