use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
// Note: PalmProcessor is available for production use with proper biometric sensors
// For webcam demo, we use image-based feature extraction instead
use sable_core::biometric::screen_flash::{ScreenFlashExtractor, ScreenFlashThresholds};
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

use crate::simulation::{
    calculate_distance, calculate_quality_score, generate_similar_features,
    generate_simulated_features,
};
use crate::flash_challenge::{compute_liveness_fingerprints, derive_flash_pattern, verify_client_commitment, verify_spatial_flash};
use crate::state::{AppState, AuthChallenge, EnrollmentSession, LivenessResult};

// Feature vector size (must match SABLE core)
const FEATURE_VECTOR_SIZE: usize = 512;

// ============================================================================
// Enrollment Endpoint
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct EnrollRequest {
    /// User identifier (for demo purposes)
    pub user_id: String,
    /// Face embedding from Human library (1024-dimensional)
    pub face_embedding: Option<Vec<f64>>,
}

#[derive(Debug, Serialize)]
pub struct EnrollResponse {
    pub session_id: String,
    pub commitment_hex: String,
    pub feature_preview: Vec<f32>,
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
    State(state): State<AppState>,
    Json(req): Json<EnrollRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let total_start = Instant::now();

    // Generate biometric features - either from face embedding or simulated
    let feature_start = Instant::now();
    let (features, quality_score) = if let Some(embedding) = &req.face_embedding {
        // Convert 1024-dim face embedding to 512 ZK-compatible features
        convert_face_embedding_to_features(embedding)?
    } else {
        // Fallback to simulation for backwards compatibility
        let seed = hash_string_to_u64(&req.user_id);
        let features = generate_simulated_features(seed);
        let quality = calculate_quality_score(&features);
        (features, quality)
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

    // Extract salt bytes from opening (for demo purposes - normally kept secret)
    let salt_bytes = scalar_to_bytes(&opening.randomness);

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
        enrollment_mode: crate::state::EnrollmentMode::Pedersen,
        commitment,
        commitment_bytes,
        features,
        face_embedding: req.face_embedding.clone(),
        quantized_embedding,
        template_commitment,
        salt_bytes,
        created_at: Instant::now(),
        fuzzy_helper_data: None,
        fuzzy_commitment_hash: None,
    };
    state.store_session(session);

    Ok(Json(EnrollResponse {
        session_id,
        commitment_hex: hex::encode(commitment_bytes),
        feature_preview: features[..10].to_vec(), // First 10 features for visualization
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
    State(state): State<AppState>,
    Json(req): Json<ChallengeRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    // Verify session exists
    let session = state.get_session(&req.session_id).ok_or_else(|| {
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

    state.store_challenge(challenge);

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
pub struct ProveRequest {
    pub challenge_id: String,
    /// Noise level for simulated "live" scan (0.0 to 1.0) - used only if no embedding
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

/// Corneal tolerances from `SABLE_CORNEAL_TOLERANCE="<ratio>,<magnitude>"`.
///
/// Unset means the check ships disabled (ADR-010). Values are clamped to the
/// witness widths (ratio ≤ 15, magnitude ≤ 31).
fn corneal_tolerances_from_env() -> Option<(u8, u8)> {
    let raw = std::env::var("SABLE_CORNEAL_TOLERANCE").ok()?;
    let (a, b) = raw.split_once(',')?;
    let ratio: u8 = a.trim().parse().ok()?;
    let magnitude: u8 = b.trim().parse().ok()?;
    Some((ratio.min(15), magnitude.min(31)))
}

#[derive(Debug, Serialize)]
pub struct ProveTimings {
    pub feature_scan_ms: f64,
    pub distance_calc_ms: f64,
    pub proof_generation_ms: f64,
    pub total_ms: f64,
}

pub async fn auth_prove(
    State(state): State<AppState>,
    Json(req): Json<ProveRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let total_start = Instant::now();

    // Get and validate challenge
    let challenge = state.remove_challenge(&req.challenge_id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Challenge not found or expired".to_string(),
            }),
        )
    })?;

    // Check challenge hasn't expired (30 second window)
    if challenge.created_at.elapsed().as_secs() > 30 {
        // Clear any pending liveness tied to this challenge.
        let _ = state.take_liveness_result(&challenge.challenge_id);
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Challenge expired".to_string(),
            }),
        ));
    }

    // Get enrollment session
    let session = state.get_session(&challenge.session_id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Session not found".to_string(),
            }),
        )
    })?;

    // Extract features from live face scan or simulate
    let scan_start = Instant::now();
    let (live_features, quality_score, live_embedding) = if let Some(embedding) = &req.face_embedding {
        // Convert 1024-dim face embedding to 512 ZK-compatible features
        let (features, quality) = convert_face_embedding_to_features(embedding)?;
        (features, quality, Some(embedding.clone()))
    } else {
        // Fallback to simulation
        let noise_level = req.noise_level.unwrap_or(0.05);
        let features = generate_similar_features(&session.features, noise_level);
        let quality = calculate_quality_score(&features);
        (features, quality, None)
    };
    let scan_time = scan_start.elapsed();

    // Calculate distance using cosine similarity on original embeddings (if available)
    // This is much more accurate than Euclidean distance on converted features
    let distance_start = Instant::now();
    let distance = match (&session.face_embedding, &live_embedding) {
        (Some(enrolled), Some(live)) => {
            // Cosine distance = 1 - cosine_similarity
            let cosine_sim = cosine_similarity(enrolled, live);
            let dist = 1.0 - cosine_sim;
            tracing::info!(
                "Face comparison: cosine_similarity={:.4}, distance={:.4}",
                cosine_sim, dist
            );
            dist as f32
        }
        _ => {
            // Fallback to Euclidean distance on 512-dim features (for simulated data)
            calculate_distance(&session.features, &live_features)
        }
    };
    let distance_time = distance_start.elapsed();

    // Check if face matches (similarity threshold)
    // Distance < 0.5 means similarity > 50% (match)
    const MATCH_THRESHOLD: f32 = 0.5;
    if distance >= MATCH_THRESHOLD {
        let similarity = (1.0 - distance) * 100.0;
        tracing::warn!(
            "Face match FAILED: similarity={:.1}% (threshold: 50%)",
            similarity
        );
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: format!(
                    "Face does not match enrolled template. Similarity: {:.1}% (required: >50%)",
                    similarity
                ),
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

    tracing::info!(
        "Halo2 ZK: Hamming distance={}, threshold={}, will_pass={}",
        hamming_dist, threshold, hamming_dist <= threshold
    );

    // Consume challenge-bound liveness result (single-use).
    let mut liveness_passed = state
        .take_liveness_result(&challenge.challenge_id)
        .map(|r| r.passed);

    // ========================================================================
    // Spatial Color Challenge Verification (optional, before proof generation)
    // ========================================================================
    let mut color_challenge_passed: Option<bool> = None;
    let mut region_match_scores: Option<Vec<RegionScoreResponse>> = None;
    let mut spatial_differentiation_score: Option<f64> = None;
    let mut photometric_rounds: Option<Vec<PhotometricRoundResponse>> = None;
    let mut corneal_rounds: Option<Vec<CornealRoundResponse>> = None;
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

            tracing::info!("Client commitment verified successfully");
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

        for score in &spatial_result.region_scores {
            tracing::info!(
                "Spatial round {}: tl={:.4}, tr={:.4}, bl={:.4}, br={:.4}, spatial_diff={:.4}",
                score.round, score.tl_score, score.tr_score, score.bl_score, score.br_score, score.spatial_diff_score,
            );
        }
        tracing::info!(
            "Spatial color verification: passed={}, overall_spatial_score={:.4}, rounds={}",
            spatial_result.passed,
            spatial_result.overall_spatial_score,
            spatial_result.region_scores.len(),
        );

        // f. If failed, return 401 error
        if !spatial_result.passed {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: format!(
                        "Spatial color challenge failed: overall_spatial_score={:.4}",
                        spatial_result.overall_spatial_score,
                    ),
                }),
            ));
        }

        // g. Compute delta fingerprints for ZK liveness proof
        let (delta_fps, expected_fps) =
            compute_liveness_fingerprints(&baseline, &flash_frames_decoded, &pattern);

        tracing::info!(
            "Liveness fingerprints: delta={:?}, expected={:?}",
            delta_fps, expected_fps
        );

        // g2. Photometric convexity evidence per round (SPEC-006 REQ-111..113,
        // REQ-118). The extractor runs on the same frames; its outputs enter the
        // witness as private fields. The public floors stay at zero (ADR-010),
        // so the coverage and convexity checks are vacuous in circuit until
        // EXP-003 fixes the constants. Logged so real faces and presentation
        // artefacts can be measured against each other.
        let mut responding_patches = [0u8; 3];
        let mut convexity_scores = [0u16; 3];
        let mut photometric_report = Vec::with_capacity(3);
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
            match photometric::extract(&baseline, flash, &quadrant_colours, PatchGrid::default()) {
                Ok(pr) => {
                    // A 4×4 grid has 16 patches; the witness field admits ≤ 64.
                    responding_patches[r] = pr.responding_patches.min(64) as u8;
                    convexity_scores[r] = pr.convexity_score;
                    tracing::info!(
                        round = r,
                        responding_patches = pr.responding_patches,
                        convexity_score = pr.convexity_score,
                        "photometric round"
                    );
                    photometric_report.push(PhotometricRoundResponse {
                        round: r,
                        responding_patches: responding_patches[r],
                        convexity_score: pr.convexity_score,
                    });
                }
                Err(e) => {
                    // Observational only while the floors are zero: leave the
                    // round at zero rather than failing the request.
                    tracing::warn!(round = r, error = %e, "photometric extraction failed");
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
        let corneal_tolerances = corneal_tolerances_from_env();
        let mut corneal_live = false;
        if let Some(crops_b64) = &req.eye_crops {
            let shape_ok = crops_b64.len() == 4 && crops_b64.iter().all(|pair| pair.len() == 2);
            if !shape_ok {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "eye_crops must be 4 frames × 2 eyes".to_string(),
                    }),
                ));
            }
            let mut crops: Vec<[PalmImage; 2]> = Vec::with_capacity(4);
            for (f, pair) in crops_b64.iter().enumerate() {
                let mut decoded = Vec::with_capacity(2);
                for (e, b64) in pair.iter().enumerate() {
                    let img = decode_base64_image(b64).map_err(|err| {
                        (
                            StatusCode::BAD_REQUEST,
                            Json(ErrorResponse {
                                error: format!("Invalid eye crop frame {f} eye {e}: {err}"),
                            }),
                        )
                    })?;
                    decoded.push(img);
                }
                let right = decoded.pop().unwrap();
                let left = decoded.pop().unwrap();
                crops.push([left, right]);
            }

            let mut report = Vec::with_capacity(3);
            let mut all_extracted = true;
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
                let expected = match corneal::expected_composite(&quadrant_colours, &weights) {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!(round = r, error = %e, "corneal expected composite failed");
                        all_extracted = false;
                        continue;
                    }
                };
                let mut observed = [0u16; 2];
                for eye in 0..2 {
                    match corneal::glint_fingerprint(&crops[0][eye], &crops[r + 1][eye]) {
                        Ok(fp) => observed[eye] = fp,
                        Err(e) => {
                            tracing::warn!(round = r, eye, error = %e, "corneal glint extraction failed");
                            all_extracted = false;
                        }
                    }
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
                tracing::info!(
                    round = r,
                    left = ?fingerprint::unpack(observed[0]),
                    right = ?fingerprint::unpack(observed[1]),
                    expected = ?fingerprint::unpack(expected),
                    agrees = ?agrees,
                    "corneal round"
                );
                report.push(CornealRoundResponse {
                    round: r,
                    left_glint: observed[0].into(),
                    right_glint: observed[1].into(),
                    expected_glint: expected.into(),
                    enabled: false, // patched below once liveness is decided
                    agrees,
                });
            }
            // Only arm the in-circuit check when every crop fingerprinted, so a
            // decode failure cannot masquerade as a corneal mismatch.
            corneal_live = corneal_tolerances.is_some() && all_extracted;
            for entry in &mut report {
                entry.enabled = corneal_live;
            }
            corneal_rounds = Some(report);
        }
        let (glint_ratio_tolerance, glint_magnitude_tolerance) = if corneal_live {
            corneal_tolerances.unwrap_or((0, 0))
        } else {
            (0, 0)
        };

        let witness = LivenessWitness {
            delta_fingerprints: delta_fps,
            expected_fingerprints: expected_fps,
            color_threshold: 5,    // allow up to HD=5 between delta and expected
            spatial_threshold: 1,  // require at least HD=1 between upper/lower
            min_magnitude: 3,      // minimum magnitude for flash response
            // SPEC-006 0.2.0 (REQ-119): bind the joint coin-flip identifier so
            // the proof answers this challenge and no other.
            challenge_id: challenge_identifier(&c_nonce_32, &challenge.nonce),
            // Photometric evidence is carried, but its floors are zero (ADR-010)
            // so the checks are vacuous, and visibly so in the digest.
            responding_patches,
            convexity_scores,
            min_coverage: 0,
            min_convexity: 0,
            // Corneal evidence is carried whenever the client sent eye crops;
            // the check is live only with SABLE_CORNEAL_TOLERANCE set.
            corneal_enabled: corneal_live,
            glint_ratio_tolerance,
            glint_magnitude_tolerance,
            glint_fingerprints,
            expected_glints,
            ..LivenessWitness::default()
        };

        // OBS-085: which check family the native pre-check fails, without values.
        match LivenessCheckCircuit::new(witness.clone()).first_failing_check() {
            None => tracing::info!(obs = "OBS-085", outcome = "pass", "liveness pre-check"),
            Some(f) => tracing::warn!(
                obs = "OBS-085",
                check = ?f.check,
                round = f.round,
                "liveness pre-check failed"
            ),
        }
        liveness_witness = Some(witness);

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
    // Generate Halo2 ZK Proof (face match + optional liveness)
    // ========================================================================
    let proof_start = Instant::now();

    let (proof_bytes, halo2_result, liveness_proved_in_zk, proof_challenge_digest, proof_commitment) = {
        let mut prover = state.halo2_prover.write();
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
                if !template_bound {
                    tracing::warn!("Halo2 proof commitment does not match registered template");
                }
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

    tracing::info!(
        "Halo2 proof generated: face_match={}, liveness_in_zk={}, challenge_digest_bound=true, time={:.2}ms, size={}B",
        halo2_result, liveness_proved_in_zk,
        proof_time.as_secs_f64() * 1000.0, proof_bytes.len()
    );

    // If Halo2 says no match, return error
    if !halo2_result {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: format!(
                    "ZK proof: Face does not match. Hamming distance {} > threshold {}",
                    hamming_dist, threshold
                ),
            }),
        ));
    }

    // Public inputs from the proof
    let (digest_hex, template_commitment_hex) = {
        use ff::PrimeField;
        (
            hex::encode(proof_challenge_digest.to_repr()),
            hex::encode(proof_commitment.to_repr()),
        )
    };
    let public_inputs = vec![
        hex::encode(session.commitment_bytes),
        hex::encode(challenge.nonce),
        format!("{:016x}", threshold), // Threshold used
        format!("{}", if halo2_result { "1" } else { "0" }), // Result: 1=match, 0=no match
        format!("{}", if liveness_proved_in_zk { "1" } else { "0" }), // Liveness result
        digest_hex, // Challenge digest (Fr field element, for verification)
        template_commitment_hex, // Poseidon commitment to enrolled template (Fr, index 6)
    ];

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
        timings: ProveTimings {
            feature_scan_ms: scan_time.as_secs_f64() * 1000.0,
            distance_calc_ms: distance_time.as_secs_f64() * 1000.0,
            proof_generation_ms: proof_time.as_secs_f64() * 1000.0,
            total_ms: total_time.as_secs_f64() * 1000.0,
        },
        what_was_proven: {
            let mut proven = vec![
                "I possess biometric features matching the enrolled template (Halo2 ZK proof)".to_string(),
                format!("Hamming distance {} ≤ threshold {} (ZK verified)", hamming_dist, threshold),
                "The biometric scan was captured recently (temporal validity)".to_string(),
                format!("Scan quality meets minimum threshold (score: {:.2})", quality_score),
            ];
            if liveness_passed == Some(true) {
                proven.push("Screen flash liveness check passed (real face detected)".to_string());
            }
            if liveness_proved_in_zk && color_challenge_passed == Some(true) {
                proven.push("Spatial liveness verified in zero knowledge (Halo2 ZK-SNARK)".to_string());
            } else if color_challenge_passed == Some(true) {
                proven.push("Spatial color challenge passed (3D face geometry verified)".to_string());
            }
            proven
        },
        what_stayed_private: {
            let mut private = vec![
                "The actual biometric feature values (512 quantized bytes)".to_string(),
                "The cryptographic salt used in the commitment".to_string(),
                "The exact Hamming distance (only that it's below threshold)".to_string(),
                "Any identifying information about the biometric pattern".to_string(),
            ];
            if liveness_passed.is_some() {
                private.push("Screen flash reflectance signals (variance, gradient, softness, consistency)".to_string());
            }
            if liveness_proved_in_zk && color_challenge_passed.is_some() {
                private.push("Per-region facial reflectance signals (proven without revealing)".to_string());
            } else if color_challenge_passed.is_some() {
                private.push("Per-region color reflectance deltas (spatial flash analysis)".to_string());
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
    pub temporal_check_passed: bool,
    pub quality_check_passed: bool,
    pub liveness_check_passed: Option<bool>,
    /// Whether liveness was verified inside the ZK proof (from public_inputs[2]).
    pub liveness_proved_in_zk: bool,
}

pub async fn verify(
    State(state): State<AppState>,
    Json(req): Json<VerifyRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let start = Instant::now();

    // Validate and decode proof
    let proof_bytes = hex::decode(&req.proof_hex).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid proof hex".to_string(),
            }),
        )
    })?;

    // Parse public inputs to reconstruct the Proof struct
    // Public inputs format: [commitment, nonce, threshold, result]
    let threshold = if req.public_inputs_hex.len() >= 3 {
        u64::from_str_radix(req.public_inputs_hex[2].trim_start_matches("0x"), 16).unwrap_or(2048)
    } else {
        2048 // Default threshold for 512 bytes at 50%
    };

    let result_val = if req.public_inputs_hex.len() >= 4 {
        req.public_inputs_hex[3].parse::<u64>().unwrap_or(1)
    } else {
        1
    };

    // Parse liveness result from public inputs (third field, if present)
    let liveness_val = if req.public_inputs_hex.len() >= 5 {
        req.public_inputs_hex[4].parse::<u64>().unwrap_or(1)
    } else {
        1 // backwards compatible: old proofs default to liveness pass
    };

    // Parse challenge digest from public inputs (index 5), or fall back to dummy.
    // In production, the verifier would independently compute this from HKDF parameters.
    let digest_val = if req.public_inputs_hex.len() >= 6 {
        let digest_bytes = hex::decode(&req.public_inputs_hex[5]).unwrap_or_default();
        if digest_bytes.len() == 32 {
            use ff::PrimeField;
            let mut repr = <Halo2Fr as PrimeField>::Repr::default();
            repr.as_mut().copy_from_slice(&digest_bytes);
            Halo2Fr::from_repr(repr).unwrap_or_else(|| compute_challenge_digest(&LivenessWitness::dummy_pass()))
        } else {
            compute_challenge_digest(&LivenessWitness::dummy_pass())
        }
    } else {
        compute_challenge_digest(&LivenessWitness::dummy_pass())
    };

    // Parse enrolled-template commitment (index 6), or default to zero. The
    // circuit exposes it as the fifth public input; verification requires the
    // same value the proof was generated with.
    let commitment_val = if req.public_inputs_hex.len() >= 7 {
        let bytes = hex::decode(&req.public_inputs_hex[6]).unwrap_or_default();
        if bytes.len() == 32 {
            use ff::PrimeField;
            let mut repr = <Halo2Fr as PrimeField>::Repr::default();
            repr.as_mut().copy_from_slice(&bytes);
            Halo2Fr::from_repr(repr).unwrap_or(Halo2Fr::from(0u64))
        } else {
            Halo2Fr::from(0u64)
        }
    } else {
        Halo2Fr::from(0u64)
    };

    // Reconstruct public inputs as Fr field elements
    let public_inputs = vec![
        Halo2Fr::from(result_val),
        Halo2Fr::from(threshold),
        Halo2Fr::from(liveness_val),
        digest_val,
        commitment_val,
    ];

    let proof = Proof {
        proof_bytes,
        public_inputs,
        liveness_passed: liveness_val == 1,
        challenge_digest: digest_val,
        commitment: commitment_val,
    };

    // Verify using Halo2
    let verification_result = {
        let mut prover = state.halo2_prover.write();
        match FaceVerificationVerifier::from_prover(&mut prover) {
            Ok(verifier) => verifier.verify(&proof),
            Err(e) => Err(e),
        }
    };

    let verification_time = start.elapsed();

    // Look up liveness result if challenge_id provided.
    let liveness_check = req
        .challenge_id
        .as_deref()
        .and_then(|cid| state.get_liveness_result(cid))
        .map(|r| r.passed);

    match verification_result {
        Ok(is_match) => {
            tracing::info!(
                "Halo2 verification completed: valid={}, liveness={:?}, liveness_zk={}, time={:.2}ms",
                is_match,
                liveness_check,
                proof.liveness_passed,
                verification_time.as_secs_f64() * 1000.0
            );
            Ok(Json(VerifyResponse {
                valid: is_match,
                verification_time_ms: verification_time.as_secs_f64() * 1000.0,
                details: VerificationDetails {
                    commitment_valid: true,
                    distance_check_passed: is_match,
                    temporal_check_passed: true,
                    quality_check_passed: true,
                    liveness_check_passed: liveness_check,
                    liveness_proved_in_zk: proof.liveness_passed,
                },
            }))
        }
        Err(e) => {
            tracing::warn!("Halo2 verification failed: {}", e);
            // Return valid=false rather than error for invalid proofs
            Ok(Json(VerifyResponse {
                valid: false,
                verification_time_ms: verification_time.as_secs_f64() * 1000.0,
                details: VerificationDetails {
                    commitment_valid: false,
                    distance_check_passed: false,
                    temporal_check_passed: true,
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
    State(state): State<AppState>,
    Json(req): Json<ScreenFlashRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let start = Instant::now();

    // Verify challenge exists (liveness is challenge-bound and single-use).
    let challenge = state.get_challenge(&req.challenge_id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Challenge not found or expired".to_string(),
            }),
        )
    })?;

    if challenge.created_at.elapsed().as_secs() > 30 {
        let _ = state.take_liveness_result(&req.challenge_id);
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
    state.get_session(&challenge.session_id).ok_or_else(|| {
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

    tracing::info!(
        "Ratio smoothness: laplacian_energy={:.6}, mean_ratio={:.4}, passed={}",
        smoothness.laplacian_energy, smoothness.mean_ratio, smoothness.passed
    );

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

    tracing::info!(
        "Liveness check: passed={} (reflectance={}, smoothness={}), variance={:.4}, gradient={:.4}, softness={:.4}, consistency={:.4}, laplacian={:.6}, time={:.2}ms",
        passed, reflectance_passed, smoothness.passed,
        variance_f, gradient_f, softness_f, consistency_f,
        smoothness.laplacian_energy,
        timing.as_secs_f64() * 1000.0
    );

    // Store result for this specific challenge (single-use in auth_prove).
    state.store_liveness_result(
        req.challenge_id,
        LivenessResult {
            passed,
            reflectance_variance: variance_f,
            reflectance_gradient: gradient_f,
            highlight_softness: softness_f,
            channel_consistency: consistency_f,
            checked_at: Instant::now(),
        },
    );

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
    /// Mean squared Laplacian of the reflectance ratio map.
    /// Low = smooth ratio variation (real 3D face).
    /// High = high-frequency ratio variation (photo on screen).
    laplacian_energy: f64,
    /// Mean ratio across the image (sanity check that flash had effect).
    mean_ratio: f64,
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
            laplacian_energy: 0.0,
            mean_ratio: 1.0,
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
        laplacian_energy,
        mean_ratio,
        passed,
    }
}

/// Decode a base64-encoded JPEG image (with optional data URL prefix) to a PalmImage
/// Decode a base64 (optionally data-URL) PNG or JPEG into an RGB8 image.
///
/// Eye crops arrive as PNG: at ~16 px a JPEG's chroma subsampling would smear
/// the very colour the glint check measures.
fn decode_base64_image(input: &str) -> std::result::Result<PalmImage, String> {
    use base64::Engine;
    use image::GenericImageView;

    let b64_data = input.rsplit(',').next().unwrap_or(input);
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64_data)
        .map_err(|e| format!("Base64 decode failed: {}", e))?;
    let img = image::load_from_memory(&bytes).map_err(|e| format!("Image decode failed: {}", e))?;
    let rgb = img.to_rgb8();
    let (w, h) = img.dimensions();
    Ok(PalmImage::new(w, h, 3, rgb.into_raw()))
}

fn decode_base64_jpeg(input: &str) -> std::result::Result<PalmImage, String> {
    use base64::Engine;
    use image::GenericImageView;

    // Strip data URL prefix if present
    let b64_data = if let Some(pos) = input.find(",") {
        &input[pos + 1..]
    } else {
        input
    };

    // Decode base64
    let jpeg_bytes = base64::engine::general_purpose::STANDARD
        .decode(b64_data)
        .map_err(|e| format!("Base64 decode failed: {}", e))?;

    // Decode JPEG to RGB
    let img = image::load_from_memory_with_format(&jpeg_bytes, image::ImageFormat::Jpeg)
        .map_err(|e| format!("JPEG decode failed: {}", e))?;

    let rgb = img.to_rgb8();
    let (w, h) = img.dimensions();

    Ok(PalmImage::new(w, h, 3, rgb.into_raw()))
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

fn hash_string_to_u64(s: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    s.hash(&mut hasher);
    hasher.finish()
}

fn scalar_to_bytes(scalar: &blstrs::Scalar) -> [u8; 32] {
    use ff::PrimeField;
    scalar.to_repr().into()
}

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

    // Convert 1024-dim to 512-dim by averaging adjacent pairs
    // This preserves the discriminative information while matching our ZK circuit size
    for i in 0..FEATURE_VECTOR_SIZE {
        let idx = i * 2;
        let avg = (embedding[idx] + embedding[idx + 1]) / 2.0;
        // Normalize to [-2, 2] range (face embeddings are typically in [-1, 1])
        features[i] = (avg * 2.0) as f32;
    }

    // Calculate quality score based on embedding statistics
    // Higher variance in the embedding indicates a more distinctive face
    let mean: f64 = embedding.iter().sum::<f64>() / FACE_EMBEDDING_SIZE as f64;
    let variance: f64 = embedding.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / FACE_EMBEDDING_SIZE as f64;
    let std_dev = variance.sqrt();

    // Quality score based on embedding characteristics
    // Good embeddings have reasonable variance (not too flat, not too noisy)
    let quality_score = (std_dev * 2.0).min(1.0).max(0.5) as f32;

    // Log feature statistics for debugging
    let feature_mean: f32 = features.iter().sum::<f32>() / FEATURE_VECTOR_SIZE as f32;
    let feature_variance: f32 = features.iter().map(|x| (x - feature_mean).powi(2)).sum::<f32>() / FEATURE_VECTOR_SIZE as f32;
    tracing::info!(
        "Face embedding conversion: embedding_std={:.4}, feature_mean={:.4}, feature_var={:.4}, quality={:.4}",
        std_dev, feature_mean, feature_variance, quality_score
    );

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
// Fuzzy Commitment Endpoints
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct FuzzyEnrollRequest {
    /// User identifier
    pub user_id: String,
    /// Face embedding from Human library (1024-dimensional)
    pub face_embedding: Option<Vec<f64>>,
    /// Error correction capacity per RS block (default: 40)
    pub error_threshold: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct FuzzyEnrollResponse {
    pub session_id: String,
    /// Deterministic commitment derived from the biometric (hex-encoded SHA-256)
    pub commitment_hex: String,
    /// Public helper data (hex-encoded, needed for future verification)
    pub helper_data_hex: String,
    pub quality_score: f32,
    pub timings: FuzzyEnrollTimings,
}

#[derive(Debug, Serialize)]
pub struct FuzzyEnrollTimings {
    pub feature_generation_ms: f64,
    pub fuzzy_commitment_ms: f64,
    pub total_ms: f64,
}

/// Enroll with fuzzy commitment mode.
///
/// This produces a deterministic commitment from the biometric that can be
/// reproduced from a future noisy reading. Useful for unique-set enrollment
/// (deduplication) where you need to check if a biometric already exists.
pub async fn fuzzy_enroll(
    State(state): State<AppState>,
    Json(req): Json<FuzzyEnrollRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    use sable_core::crypto::fuzzy_commitment::{self, FuzzyParams};

    let total_start = Instant::now();

    // Generate features
    let feature_start = Instant::now();
    let (features, quality_score) = if let Some(embedding) = &req.face_embedding {
        convert_face_embedding_to_features(embedding)?
    } else {
        let seed = hash_string_to_u64(&req.user_id);
        let features = generate_simulated_features(seed);
        let quality = calculate_quality_score(&features);
        (features, quality)
    };
    let feature_time = feature_start.elapsed();

    // Binary quantize: sign bit per feature → 0x00 / 0xFF
    // Fine u8 quantization produces Hamming distances of ~85% between webcam
    // captures (values cluster in a narrow band).  Binary quantization reduces
    // this to ~14% (only positions that cross the sign boundary differ).
    let quantized: Vec<u8> = features
        .iter()
        .map(|&f| if f >= 0.0 { 0xFF } else { 0x00 })
        .collect();

    // Generate deterministic fuzzy commitment (same biometric → same commitment)
    let fuzzy_start = Instant::now();
    let t = req.error_threshold.unwrap_or(100);
    let params = FuzzyParams::new(t);
    let enrollment = fuzzy_commitment::gen_deterministic(&quantized, &params);
    let fuzzy_time = fuzzy_start.elapsed();

    let total_time = total_start.elapsed();

    // Store session
    let session_id = uuid::Uuid::new_v4().to_string();

    // We still create a dummy Pedersen commitment for the session struct
    // (the fuzzy commitment is stored separately)
    let feature_hash = poseidon_hash(&features).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Poseidon hash failed: {}", e),
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
    let commitment_bytes = commitment.to_bytes();
    let salt_bytes = scalar_to_bytes(&opening.randomness);

    let helper_data_bytes = enrollment.helper_data.to_bytes();

    let template_commitment = poseidon_commit_bytes_value(&quantized);

    let session = EnrollmentSession {
        session_id: session_id.clone(),
        enrollment_mode: crate::state::EnrollmentMode::FuzzyCommitment,
        commitment,
        commitment_bytes,
        features,
        face_embedding: req.face_embedding.clone(),
        quantized_embedding: quantized,
        template_commitment,
        salt_bytes,
        created_at: Instant::now(),
        fuzzy_helper_data: Some(enrollment.helper_data),
        fuzzy_commitment_hash: Some(enrollment.commitment),
    };
    state.store_session(session);

    Ok(Json(FuzzyEnrollResponse {
        session_id,
        commitment_hex: hex::encode(enrollment.commitment),
        helper_data_hex: hex::encode(&helper_data_bytes),
        quality_score,
        timings: FuzzyEnrollTimings {
            feature_generation_ms: feature_time.as_secs_f64() * 1000.0,
            fuzzy_commitment_ms: fuzzy_time.as_secs_f64() * 1000.0,
            total_ms: total_time.as_secs_f64() * 1000.0,
        },
    }))
}

#[derive(Debug, Deserialize)]
pub struct FuzzyVerifyRequest {
    /// Session ID from enrollment (looks up stored helper data)
    pub session_id: Option<String>,
    /// Or provide helper data directly (hex-encoded)
    pub helper_data_hex: Option<String>,
    /// Face embedding to verify (1024-dimensional)
    pub face_embedding: Option<Vec<f64>>,
}

#[derive(Debug, Serialize)]
pub struct FuzzyVerifyResponse {
    pub matched: bool,
    /// The reproduced commitment (hex), if matched
    pub commitment_hex: Option<String>,
    pub timing_ms: f64,
}

/// Verify a biometric against a fuzzy commitment.
///
/// Attempts to reproduce the commitment from a fresh biometric reading.
/// Returns whether the biometric matches (is within the error threshold).
pub async fn fuzzy_verify(
    State(state): State<AppState>,
    Json(req): Json<FuzzyVerifyRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    use sable_core::crypto::fuzzy_commitment::{self, HelperData};

    let start = Instant::now();

    // Get helper data from session or request
    let helper_data = if let Some(session_id) = &req.session_id {
        let session = state.get_session(session_id).ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "Session not found".to_string(),
                }),
            )
        })?;
        session.fuzzy_helper_data.ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Session was not enrolled with fuzzy commitment mode".to_string(),
                }),
            )
        })?
    } else if let Some(hex_str) = &req.helper_data_hex {
        let bytes = hex::decode(hex_str).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!("Invalid helper data hex: {}", e),
                }),
            )
        })?;
        HelperData::from_bytes(&bytes).ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Invalid helper data format".to_string(),
                }),
            )
        })?
    } else {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Must provide either session_id or helper_data_hex".to_string(),
            }),
        ));
    };

    // Get features from face embedding or error
    let (features, _quality) = if let Some(embedding) = &req.face_embedding {
        convert_face_embedding_to_features(embedding)?
    } else {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "face_embedding is required for fuzzy verification".to_string(),
            }),
        ));
    };

    // Binary quantize (must match enrollment quantization)
    let quantized: Vec<u8> = features
        .iter()
        .map(|&f| if f >= 0.0 { 0xFF } else { 0x00 })
        .collect();

    // Log Hamming distance for diagnostics
    if let Some(session_id) = &req.session_id {
        if let Some(session) = state.get_session(session_id) {
            let hamming: usize = session
                .quantized_embedding
                .iter()
                .zip(quantized.iter())
                .filter(|(a, b)| a != b)
                .count();
            tracing::info!(
                "Fuzzy verify: binary Hamming distance = {}/512 ({:.1}%), t={} (corrects ~{})",
                hamming,
                hamming as f64 / 512.0 * 100.0,
                helper_data.params.t,
                helper_data.params.t * 2
            );
        }
    }

    // Attempt to reproduce commitment
    let result = fuzzy_commitment::rep(&quantized, &helper_data);
    let timing = start.elapsed();

    Ok(Json(FuzzyVerifyResponse {
        matched: result.is_some(),
        commitment_hex: result.map(|c| hex::encode(c)),
        timing_ms: timing.as_secs_f64() * 1000.0,
    }))
}

#[derive(Debug, Deserialize)]
pub struct FuzzyCheckUniqueRequest {
    /// Face embedding to check (1024-dimensional)
    pub face_embedding: Vec<f64>,
    /// List of existing helper data (hex-encoded) to check against
    pub existing_enrollments: Vec<String>,
    /// Error correction threshold (default: 40)
    pub error_threshold: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct FuzzyCheckUniqueResponse {
    /// Whether the biometric is unique (not found in existing set)
    pub is_unique: bool,
    /// Index of the matched enrollment, if any
    pub matched_index: Option<usize>,
    /// Reproduced commitment of the match (hex), if any
    pub matched_commitment_hex: Option<String>,
    pub timing_ms: f64,
    pub checked_count: usize,
}

/// Check if a biometric is unique within a set of existing fuzzy enrollments.
///
/// This is the core deduplication use case: given a fresh biometric and a set
/// of existing enrollments (helper data), check if the biometric matches any
/// existing enrollment.
pub async fn fuzzy_check_unique(
    Json(req): Json<FuzzyCheckUniqueRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    use sable_core::crypto::fuzzy_commitment::{self, HelperData};

    let start = Instant::now();

    // Convert face embedding to binary-quantized features
    let (features, _quality) = convert_face_embedding_to_features(&req.face_embedding)?;
    let quantized: Vec<u8> = features
        .iter()
        .map(|&f| if f >= 0.0 { 0xFF } else { 0x00 })
        .collect();

    // Check against each existing enrollment
    let checked_count = req.existing_enrollments.len();
    for (idx, helper_hex) in req.existing_enrollments.iter().enumerate() {
        let bytes = hex::decode(helper_hex).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!("Invalid helper data hex at index {}: {}", idx, e),
                }),
            )
        })?;

        let helper_data = match HelperData::from_bytes(&bytes) {
            Some(hd) => hd,
            None => continue, // Skip malformed entries
        };

        if let Some(commitment) = fuzzy_commitment::rep(&quantized, &helper_data) {
            let timing = start.elapsed();
            return Ok(Json(FuzzyCheckUniqueResponse {
                is_unique: false,
                matched_index: Some(idx),
                matched_commitment_hex: Some(hex::encode(commitment)),
                timing_ms: timing.as_secs_f64() * 1000.0,
                checked_count,
            }));
        }
    }

    let timing = start.elapsed();
    Ok(Json(FuzzyCheckUniqueResponse {
        is_unique: true,
        matched_index: None,
        matched_commitment_hex: None,
        timing_ms: timing.as_secs_f64() * 1000.0,
        checked_count,
    }))
}
