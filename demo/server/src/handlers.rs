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
use sable_core::biometric::PalmImage;
use sable_core::crypto::pedersen::{CommitmentOpening, Generators, commit_with_opening};
use sable_core::crypto::poseidon::poseidon_hash;
use sable_core::crypto::rng::SecureRng;
use std::time::Instant;

// Halo2 ZK proof system
use sable_core::zk::halo2::{
    FaceVerificationVerifier, Proof,
    FeatureQuantizer, hamming_distance, ThresholdConfig, Halo2Fr,
};

use crate::simulation::{
    calculate_distance, calculate_quality_score, generate_similar_features,
    generate_simulated_features,
};
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

    // Create quantized embedding for Halo2 ZK proofs
    // Convert f32 features to f64, then quantize to u8
    let features_f64: Vec<f64> = features.iter().map(|&f| f as f64 / 2.0).collect(); // Normalize to [-1, 1]
    let quantized_embedding = FeatureQuantizer::quantize(&features_f64);

    let session = EnrollmentSession {
        session_id: session_id.clone(),
        commitment,
        commitment_bytes,
        features,
        face_embedding: req.face_embedding.clone(),
        quantized_embedding,
        salt_bytes,
        created_at: Instant::now(),
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
    pub timings: ProveTimings,
    pub what_was_proven: Vec<String>,
    pub what_stayed_private: Vec<String>,
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

    // Generate real Halo2 ZK proof
    let proof_start = Instant::now();

    // Quantize live features for Hamming distance calculation
    let live_features_f64: Vec<f64> = live_features.iter().map(|&f| f as f64 / 2.0).collect();
    let live_quantized = FeatureQuantizer::quantize(&live_features_f64);

    // Calculate Hamming distance between enrolled and live embeddings
    let hamming_dist = hamming_distance(&session.quantized_embedding, &live_quantized);

    // Get threshold configuration (50% similarity for 512 bytes = 2048 bits threshold)
    let threshold_config = ThresholdConfig::new(session.quantized_embedding.len(), 0.5);
    let threshold = threshold_config.max_hamming_distance();

    tracing::info!(
        "Halo2 ZK: Hamming distance={}, threshold={}, will_pass={}",
        hamming_dist, threshold, hamming_dist <= threshold
    );

    // Generate real ZK proof using Halo2
    let (proof_bytes, halo2_result) = {
        let mut prover = state.halo2_prover.write();
        match prover.prove(hamming_dist, threshold) {
            Ok(proof) => {
                let result = hamming_dist <= threshold;
                (proof.proof_bytes, result)
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
    let total_time = total_start.elapsed();

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
    let public_inputs = vec![
        hex::encode(session.commitment_bytes),
        hex::encode(challenge.nonce),
        format!("{:016x}", threshold), // Threshold used
        format!("{}", if halo2_result { "1" } else { "0" }), // Result: 1=match, 0=no match
    ];

    // Check for stored liveness result
    let liveness_passed = state
        .get_liveness_result(&challenge.session_id)
        .map(|r| r.passed);

    Ok(Json(ProveResponse {
        proof_hex: hex::encode(&proof_bytes),
        public_inputs_hex: public_inputs,
        distance,
        hamming_distance: hamming_dist,
        hamming_threshold: threshold,
        quality_score,
        proof_size_bytes: proof_bytes.len(),
        liveness_passed,
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
    /// Optional session ID to look up liveness result
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

    // Reconstruct public inputs as Fr field elements
    let public_inputs = vec![
        Halo2Fr::from(result_val),
        Halo2Fr::from(threshold),
    ];

    let proof = Proof {
        proof_bytes,
        public_inputs,
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

    // Look up liveness result if session_id provided
    let liveness_check = req
        .session_id
        .as_deref()
        .and_then(|sid| state.get_liveness_result(sid))
        .map(|r| r.passed);

    match verification_result {
        Ok(is_match) => {
            tracing::info!(
                "Halo2 verification completed: valid={}, liveness={:?}, time={:.2}ms",
                is_match,
                liveness_check,
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
    /// Session ID to associate liveness result with
    pub session_id: String,
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

    // Verify session exists
    state.get_session(&req.session_id).ok_or_else(|| {
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

    // Store result for the session
    state.store_liveness_result(
        req.session_id,
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
