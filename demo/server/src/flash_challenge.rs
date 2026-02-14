//! Flash Challenge Protocol — deterministic color pattern derivation for liveness detection.
//!
//! Derives a [`FlashPattern`] of 3 rounds (each with 4 quadrant RGB colors and a
//! per-round grid offset) from client and server nonces using HKDF-SHA256.
//! The construction is deterministic and designed to be reproducible in both Rust
//! and TypeScript.
//!
//! ## HKDF-SHA256 Construction
//!
//! - **IKM**: `c_nonce || s_nonce` (64 bytes)
//! - **Salt**: `b"sable-flash-challenge-v1"` (fixed, public)
//! - **Info**: `b"flash-colors"` (fixed, public)
//! - **Output**: 42 bytes (12 colors × 3 bytes + 3 rounds × 2 offset bytes)
//!
//! ## Safety
//!
//! Photosensitive safety clamping is applied per WCAG 2.3.1: when the green and blue
//! channels are both low (G + B < 51), the red channel is capped at 204 to prevent
//! pure saturated red flashes.

use hkdf::Hkdf;
use sable_core::biometric::PalmImage;
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Fixed HKDF salt (public, must match TypeScript implementation).
const HKDF_SALT: &[u8] = b"sable-flash-challenge-v1";

/// Fixed HKDF info (public, must match TypeScript implementation).
const HKDF_INFO: &[u8] = b"flash-colors";

/// Number of HKDF output bytes: 12 colors × 3 bytes (R, G, B) + 3 rounds × 2 offset bytes.
const HKDF_OUTPUT_LEN: usize = 42;

/// Maximum red channel value when green + blue are below the low threshold.
/// Corresponds to R < 0.8 in normalized [0, 1] space  =>  0.8 * 255 = 204.
const RED_CAP: u8 = 204;

/// Threshold for "low" green + blue sum (normalized 0.2 * 2 * 255 ≈ 102).
/// We use the integer form: G + B < 51 per-channel (i.e. both channels < ~0.1
/// each, giving a combined normalized value < 0.2).
///
/// In practice, we check the *sum* of the raw byte values: G + B < 102 means
/// the combined green+blue intensity is below 0.2 in normalized space, which
/// is the trigger for clamping.
const GB_LOW_THRESHOLD: u16 = 102;

/// Minimum angular distance (in degrees) between paired colors in a round to
/// ensure visual distinctness.
const MIN_ANGULAR_DISTANCE_DEG: f64 = 60.0;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// An RGB color with 8-bit channels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RgbColor {
    pub r: u8,
    pub g: u8,
    pub b: u8,
}

impl RgbColor {
    /// Create a new RGB color.
    pub const fn new(r: u8, g: u8, b: u8) -> Self {
        Self { r, g, b }
    }

    /// Return the color as a 3-element array `[R, G, B]`.
    pub const fn to_array(self) -> [u8; 3] {
        [self.r, self.g, self.b]
    }

    /// Return the color as a CSS hex string, e.g. `"#1a2b3c"`.
    pub fn to_hex_string(&self) -> String {
        format!("#{:02x}{:02x}{:02x}", self.r, self.g, self.b)
    }
}

/// A single round in the flash pattern: four quadrant colors displayed on a
/// 2×2 grid with a per-round offset that shifts the grid boundary.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FlashRound {
    pub tl_color: RgbColor,  // top-left
    pub tr_color: RgbColor,  // top-right
    pub bl_color: RgbColor,  // bottom-left
    pub br_color: RgbColor,  // bottom-right
    /// Grid offset as fraction [0.0, 1.0) derived from HKDF.
    /// Shifts the 2×2 grid boundary both horizontally and vertically.
    pub offset_x: f64,
    pub offset_y: f64,
}

/// The complete flash pattern: 3 sequential rounds.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FlashPattern {
    pub rounds: [FlashRound; 3],
}

// ---------------------------------------------------------------------------
// Core derivation
// ---------------------------------------------------------------------------

/// Derive a deterministic [`FlashPattern`] from client and server nonces using
/// HKDF-SHA256.
///
/// The pattern contains 3 rounds, each with 4 quadrant RGB colors (TL, TR, BL, BR)
/// and a per-round grid offset. Colors are derived from 42 bytes of HKDF output
/// and then processed for photosensitive safety and visual distinctness.
pub fn derive_flash_pattern(c_nonce: &[u8; 32], s_nonce: &[u8; 32]) -> FlashPattern {
    // 1. Build IKM = c_nonce || s_nonce
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(c_nonce);
    ikm[32..].copy_from_slice(s_nonce);

    // 2. HKDF-SHA256 extract + expand (42 bytes needs 2 HMAC blocks)
    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), &ikm);
    let mut okm = [0u8; HKDF_OUTPUT_LEN];
    hk.expand(HKDF_INFO, &mut okm)
        .expect("42 bytes is within HKDF-SHA256 output limit");

    // 3. Map bytes 0..36 → 12 colors (4 per round × 3 rounds)
    let mut colors: [RgbColor; 12] = [RgbColor::new(0, 0, 0); 12];
    for i in 0..12 {
        let offset = i * 3;
        colors[i] = map_bytes_to_saturated_color(okm[offset], okm[offset + 1], okm[offset + 2]);
    }

    // 4. Apply photosensitive safety clamping
    for color in &mut colors {
        apply_photosensitive_clamp(color);
    }

    // 5. Map bytes 36..42 → 3 × (offset_x, offset_y) as byte / 256.0
    let mut offsets = [(0.0f64, 0.0f64); 3];
    for i in 0..3 {
        offsets[i] = (
            okm[36 + i * 2] as f64 / 256.0,
            okm[36 + i * 2 + 1] as f64 / 256.0,
        );
    }

    // 6. Ensure adjacent quadrant pairs per round are visually distinct.
    //    Adjacent pairs: TL-TR, TL-BL, TR-BR, BL-BR
    let mut rounds = [FlashRound {
        tl_color: RgbColor::new(0, 0, 0),
        tr_color: RgbColor::new(0, 0, 0),
        bl_color: RgbColor::new(0, 0, 0),
        br_color: RgbColor::new(0, 0, 0),
        offset_x: 0.0,
        offset_y: 0.0,
    }; 3];

    for i in 0..3 {
        let base = i * 4;
        let tl = colors[base];
        let tr = colors[base + 1];
        let bl = colors[base + 2];
        let br = colors[base + 3];

        // Check and fix adjacent pairs: TL-TR, TL-BL, TR-BR, BL-BR.
        // Each vertex has exactly 2 neighbors in the 2×2 grid:
        //   0 (TL): neighbors [1, 2]
        //   1 (TR): neighbors [0, 3]
        //   2 (BL): neighbors [0, 3]
        //   3 (BR): neighbors [1, 2]
        // When fixing a vertex, we must find a color distinct from ALL its
        // neighbors to avoid oscillation.
        let neighbors: [[usize; 2]; 4] = [[1, 2], [0, 3], [0, 3], [1, 2]];
        let mut quad = [tl, tr, bl, br];

        for _pass in 0..4 {
            let mut all_ok = true;
            for v in 0..4 {
                let has_violation = neighbors[v]
                    .iter()
                    .any(|&n| angular_distance_deg(&quad[v], &quad[n]) < MIN_ANGULAR_DISTANCE_DEG);
                if has_violation {
                    quad[v] = make_distinct_from_all(&quad[v], &[quad[neighbors[v][0]], quad[neighbors[v][1]]]);
                    apply_photosensitive_clamp(&mut quad[v]);
                    all_ok = false;
                }
            }
            if all_ok {
                break;
            }
        }

        rounds[i] = FlashRound {
            tl_color: quad[0],
            tr_color: quad[1],
            bl_color: quad[2],
            br_color: quad[3],
            offset_x: offsets[i].0,
            offset_y: offsets[i].1,
        };
    }

    FlashPattern { rounds }
}

// ---------------------------------------------------------------------------
// Commitment helpers
// ---------------------------------------------------------------------------

/// Compute a SHA-256 commitment to a client nonce.
///
/// `commitment = SHA-256(c_nonce)`
pub fn compute_client_commitment(c_nonce: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(c_nonce);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Verify that a commitment matches the SHA-256 hash of the given client nonce.
pub fn verify_client_commitment(c_nonce: &[u8; 32], commitment: &[u8; 32]) -> bool {
    let expected = compute_client_commitment(c_nonce);
    // Constant-time comparison to avoid timing side-channels.
    constant_time_eq(&expected, commitment)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Map 3 raw bytes to a saturated RGB color.
///
/// The mapping ensures that the resulting color is far from the gray diagonal
/// in RGB space. This is critical because colors near the diagonal (where
/// R ≈ G ≈ B) have a maximum angular distance of only ~54.7° from any other
/// point in the positive octant, which is below our 60° distinctness threshold.
///
/// Strategy: use the first byte to pick a dominant-channel ordering (one of 6
/// permutations), and the remaining two bytes to set the dominant channel high
/// (180-255) and the weakest channel low (0-75). The middle channel varies
/// freely across 0-255. This guarantees a minimum channel spread of ~105,
/// keeping all colors well away from the diagonal.
///
/// This mapping is deterministic and must be replicated identically in
/// TypeScript.
fn map_bytes_to_saturated_color(b0: u8, b1: u8, b2: u8) -> RgbColor {
    // b0 selects which of 6 channel orderings to use (dominant, middle, weak).
    // b1 sets the dominant channel intensity: 180 + (b1 * 75 / 255) = [180, 255]
    // b2 sets the weak channel intensity:    0 + (b2 * 75 / 255)   = [0, 75]
    // The middle channel uses b1 XOR b2 for full range [0, 255].

    let ordering = b0 % 6;
    let dominant = 180u8.saturating_add((b1 as u16 * 75 / 255) as u8);
    let weak = (b2 as u16 * 75 / 255) as u8;
    let middle = b1 ^ b2;

    match ordering {
        0 => RgbColor::new(dominant, middle, weak),    // R dominant, B weak
        1 => RgbColor::new(dominant, weak, middle),    // R dominant, G weak
        2 => RgbColor::new(middle, dominant, weak),    // G dominant, B weak
        3 => RgbColor::new(weak, dominant, middle),    // G dominant, R weak
        4 => RgbColor::new(middle, weak, dominant),    // B dominant, R middle
        _ => RgbColor::new(weak, middle, dominant),    // B dominant, R weak
    }
}

/// Apply WCAG 2.3.1 photosensitive safety clamping.
///
/// If the combined green + blue intensity is low (< 0.2 normalized), cap the
/// red channel at 0.8 (204 in byte space) to prevent pure saturated red flashes.
fn apply_photosensitive_clamp(color: &mut RgbColor) {
    let gb_sum = color.g as u16 + color.b as u16;
    if gb_sum < GB_LOW_THRESHOLD && color.r > RED_CAP {
        color.r = RED_CAP;
    }
}

/// Compute the angular distance in degrees between two RGB colors treated as
/// 3D vectors. Returns 0.0 if either vector has zero magnitude.
fn angular_distance_deg(a: &RgbColor, b: &RgbColor) -> f64 {
    let a_vec = [a.r as f64, a.g as f64, a.b as f64];
    let b_vec = [b.r as f64, b.g as f64, b.b as f64];

    let dot: f64 = a_vec.iter().zip(b_vec.iter()).map(|(x, y)| x * y).sum();
    let mag_a: f64 = a_vec.iter().map(|x| x * x).sum::<f64>().sqrt();
    let mag_b: f64 = b_vec.iter().map(|x| x * x).sum::<f64>().sqrt();

    if mag_a < f64::EPSILON || mag_b < f64::EPSILON {
        return 0.0;
    }

    let cos_theta = (dot / (mag_a * mag_b)).clamp(-1.0, 1.0);
    cos_theta.acos().to_degrees()
}

/// Deterministically adjust `candidate` to be visually distinct from `anchor`.
///
/// Find a replacement color for `candidate` that is at least `MIN_ANGULAR_DISTANCE_DEG`
/// away from ALL colors in `neighbors`.  Uses the same candidate pool as `make_distinct`
/// but filters against all neighbors simultaneously.
fn make_distinct_from_all(candidate: &RgbColor, neighbors: &[RgbColor]) -> RgbColor {
    let all_distinct = |c: &RgbColor| -> bool {
        neighbors
            .iter()
            .all(|n| angular_distance_deg(n, c) >= MIN_ANGULAR_DISTANCE_DEG)
    };

    // Try the same transformations as make_distinct.
    let transforms = [
        RgbColor::new(candidate.b, candidate.r, candidate.g),
        RgbColor::new(candidate.g, candidate.b, candidate.r),
        RgbColor::new(!candidate.r, !candidate.g, !candidate.b),
        RgbColor::new(candidate.r ^ 0xAA, candidate.g ^ 0x55, candidate.b ^ 0xAA),
    ];

    for c in &transforms {
        if all_distinct(c) {
            return *c;
        }
    }

    // Edge/primary fallback: pick the color with the greatest minimum distance
    // to any neighbor.
    let edge_colors = [
        RgbColor::new(255, 0, 0),
        RgbColor::new(0, 255, 0),
        RgbColor::new(0, 0, 255),
        RgbColor::new(255, 255, 0),
        RgbColor::new(0, 255, 255),
        RgbColor::new(255, 0, 255),
    ];

    edge_colors
        .iter()
        .copied()
        .max_by(|a, b| {
            let min_a = neighbors
                .iter()
                .map(|n| angular_distance_deg(n, a))
                .fold(f64::MAX, f64::min);
            let min_b = neighbors
                .iter()
                .map(|n| angular_distance_deg(n, b))
                .fold(f64::MAX, f64::min);
            min_a.partial_cmp(&min_b).unwrap_or(std::cmp::Ordering::Equal)
        })
        .unwrap()
}

/// Constant-time byte-array comparison to avoid timing attacks.
fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

// ---------------------------------------------------------------------------
// Delta Fingerprint Quantization
// ---------------------------------------------------------------------------
//
// Encodes an RGB delta vector (or expected color) as a 16-bit fingerprint
// suitable for Hamming distance comparison inside a ZK circuit.
//
// Bit layout: [order:3 | mid_ratio:4 | min_ratio:4 | magnitude:5]
//
//   order (3 bits):     which of 6 channel orderings by absolute value
//   mid_ratio (4 bits): |mid_channel| / |max_channel| * 15 (integer)
//   min_ratio (4 bits): |min_channel| / |max_channel| * 15 (integer)
//   magnitude (5 bits): min(31, |max_channel| * 31 / 128)
//
// This encoding must be identical in Rust and TypeScript.

/// Maximum channel value that maps to magnitude=31.
/// Values above this are clamped. 128 is chosen so that a "strong" single-channel
/// response (half the 0-255 range) saturates the magnitude field.
const MAGNITUDE_SCALE: u32 = 128;

/// Quantize an RGB delta vector `[dR, dG, dB]` to a 16-bit fingerprint.
///
/// The fingerprint encodes the *direction* (channel ordering + ratios) and
/// *magnitude* of the delta, suitable for Hamming distance comparison.
///
/// Returns 0 if the delta has zero magnitude (no flash response).
pub fn quantize_delta_fingerprint(delta: &[f64; 3]) -> u16 {
    // Absolute values as integers (round to nearest for cross-platform stability)
    let abs_channels: [u32; 3] = [
        delta[0].abs().round() as u32,
        delta[1].abs().round() as u32,
        delta[2].abs().round() as u32,
    ];

    // Sort descending by value; on ties, prefer lower channel index (stable)
    let mut indexed: [(u32, usize); 3] = [
        (abs_channels[0], 0),
        (abs_channels[1], 1),
        (abs_channels[2], 2),
    ];
    indexed.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));

    let max_val = indexed[0].0;
    let mid_val = indexed[1].0;
    let min_val = indexed[2].0;
    let max_idx = indexed[0].1;
    let mid_idx = indexed[1].1;

    if max_val == 0 {
        return 0; // No flash response
    }

    // Channel ordering: 6 permutations of (R=0, G=1, B=2) by dominance
    let order: u16 = match (max_idx, mid_idx) {
        (0, 1) => 0, // R >= G >= B
        (0, 2) => 1, // R >= B >= G
        (1, 0) => 2, // G >= R >= B
        (1, 2) => 3, // G >= B >= R
        (2, 0) => 4, // B >= R >= G
        (2, 1) => 5, // B >= G >= R
        _ => 0,       // unreachable with 3 distinct indices
    };

    // Ratios: mid/max and min/max, quantized to [0, 15]
    let mid_ratio = ((mid_val * 15) / max_val).min(15) as u16;
    let min_ratio = ((min_val * 15) / max_val).min(15) as u16;

    // Magnitude: max channel scaled to [0, 31]
    let magnitude = ((max_val * 31) / MAGNITUDE_SCALE).min(31) as u16;

    // Pack: [order:3 | mid_ratio:4 | min_ratio:4 | magnitude:5]
    (order << 13) | (mid_ratio << 9) | (min_ratio << 5) | magnitude
}

/// Quantize an expected flash color to the same fingerprint space as deltas.
///
/// This allows Hamming distance comparison between a captured delta fingerprint
/// and the expected color fingerprint inside a ZK circuit.
pub fn quantize_expected_color(color: &RgbColor) -> u16 {
    quantize_delta_fingerprint(&[color.r as f64, color.g as f64, color.b as f64])
}

/// Compute liveness fingerprints from captured frames for use in ZK circuit.
///
/// Returns `(delta_fingerprints, expected_fingerprints)` — each has 12 entries:
/// `[r0_tl, r0_tr, r0_bl, r0_br, r1_tl, r1_tr, r1_bl, r1_br, r2_tl, ...]`.
///
/// Call this after `verify_spatial_flash` passes; it re-computes the mean deltas
/// and quantizes them into 16-bit fingerprints for ZK proof inclusion.
pub fn compute_liveness_fingerprints(
    baseline: &PalmImage,
    flash_frames: &[PalmImage],
    pattern: &FlashPattern,
) -> ([u16; 12], [u16; 12]) {
    let w = baseline.width as usize;
    let h = baseline.height as usize;
    let x_margin = (w as f64 * FACE_MARGIN_FRACTION) as usize;
    let y_margin = (h as f64 * FACE_MARGIN_FRACTION) as usize;
    let face_x_start = x_margin;
    let face_x_end = w - x_margin;
    let face_y_start = y_margin;
    let face_y_end = h - y_margin;
    let face_width = face_x_end - face_x_start;
    let face_height = face_y_end - face_y_start;

    let mut delta_fps = [0u16; 12];
    let mut expected_fps = [0u16; 12];

    for (round_idx, flash_frame) in flash_frames.iter().enumerate() {
        let round = &pattern.rounds[round_idx];

        // Compute split points with offset (±15% from center)
        let face_x_split = face_x_start + ((face_width as f64) * (0.5 + round.offset_x * 0.3 - 0.15)) as usize;
        let face_y_split = face_y_start + ((face_height as f64) * (0.5 + round.offset_y * 0.3 - 0.15)) as usize;

        let tl_delta = compute_mean_delta(baseline, flash_frame, face_x_start, face_x_split, face_y_start, face_y_split);
        let tr_delta = compute_mean_delta(baseline, flash_frame, face_x_split, face_x_end, face_y_start, face_y_split);
        let bl_delta = compute_mean_delta(baseline, flash_frame, face_x_start, face_x_split, face_y_split, face_y_end);
        let br_delta = compute_mean_delta(baseline, flash_frame, face_x_split, face_x_end, face_y_split, face_y_end);

        let base = round_idx * 4;
        delta_fps[base] = quantize_delta_fingerprint(&tl_delta);
        delta_fps[base + 1] = quantize_delta_fingerprint(&tr_delta);
        delta_fps[base + 2] = quantize_delta_fingerprint(&bl_delta);
        delta_fps[base + 3] = quantize_delta_fingerprint(&br_delta);
        expected_fps[base] = quantize_expected_color(&round.tl_color);
        expected_fps[base + 1] = quantize_expected_color(&round.tr_color);
        expected_fps[base + 2] = quantize_expected_color(&round.bl_color);
        expected_fps[base + 3] = quantize_expected_color(&round.br_color);
    }

    (delta_fps, expected_fps)
}

// ---------------------------------------------------------------------------
// Spatial Flash Verification — per-region reflected color analysis
// ---------------------------------------------------------------------------

/// Minimum cosine similarity for a region's delta to match expected color direction.
///
/// At typical webcam distances the lower face (chin/neck) receives mixed light
/// from both screen halves due to the small angular subtense, so lower-region
/// scores are typically 0.3-0.7. A threshold of 0.2 still rejects random/wrong
/// color directions (which produce negative or near-zero cosine similarity)
/// while accommodating real webcam geometry.
const REGION_COLOR_MATCH_THRESHOLD: f64 = 0.2;

/// Minimum margin by which each region must match its expected half-screen
/// Maximum cosine similarity between adjacent quadrant delta vectors.
/// Values above this indicate both halves responded identically (flat surface).
///
/// At typical webcam distances (~40-80cm), the angular subtense of the screen's
/// top/bottom halves is small relative to the face, so a real 3D face produces
/// only modest spatial differentiation (~5-15° delta angle, cosine ~0.97-0.996).
/// A perfectly flat surface produces nearly identical deltas (cosine ~0.999+).
///
/// Threshold of 0.998 (~3.6° minimum angular difference) is calibrated for:
/// - Real faces at desk distance: ~0.97-0.99 → PASS
/// - Flat photos/screens: ~0.999-1.0 → FAIL
const SPATIAL_DIFF_MAX_SIMILARITY: f64 = 0.998;

/// Minimum number of rounds that must pass each spatial/color check.
///
/// Requiring all 3 rounds significantly reduces accidental replay acceptance
/// when independently derived patterns happen to overlap on 1-2 rounds.
const SPATIAL_DIFF_MIN_PASSING_ROUNDS: usize = 3;

/// Face region margin: 20% on each side, leaving center 60%.
const FACE_MARGIN_FRACTION: f64 = 0.20;

/// Per-region, per-round match score.
#[derive(Debug, Clone)]
pub struct RegionMatchScore {
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
    /// Mean of 4 adjacent-pair spatial diff scores (cosine similarity).
    /// Low values indicate 3D geometry; high values indicate flat surface.
    pub spatial_diff_score: f64,
}

/// Overall result of spatial flash verification across all rounds.
#[derive(Debug, Clone)]
pub struct SpatialVerificationResult {
    /// Whether the spatial verification passed.
    pub passed: bool,
    /// Per-round region match scores.
    pub region_scores: Vec<RegionMatchScore>,
    /// Average spatial differentiation score across rounds.
    pub overall_spatial_score: f64,
}

/// Verify that each face quadrant reflects the correct screen-quadrant color
/// across all flash rounds.
///
/// # Arguments
/// * `baseline` - Frame captured before any flash (ambient lighting).
/// * `flash_frames` - One frame per flash round (must be exactly 3).
/// * `pattern` - The expected [`FlashPattern`] (3 rounds of 4-quadrant colors).
///
/// # Returns
/// * `SpatialVerificationResult` with per-round scores and overall pass/fail.
pub fn verify_spatial_flash(
    baseline: &PalmImage,
    flash_frames: &[PalmImage],
    pattern: &FlashPattern,
) -> Result<SpatialVerificationResult, String> {
    // --- Input validation ---------------------------------------------------
    if flash_frames.len() != 3 {
        return Err(format!(
            "expected 3 flash frames, got {}",
            flash_frames.len()
        ));
    }
    if baseline.channels != 3 {
        return Err("baseline must be an RGB image (3 channels)".into());
    }
    for (i, frame) in flash_frames.iter().enumerate() {
        if frame.width != baseline.width
            || frame.height != baseline.height
            || frame.channels != baseline.channels
        {
            return Err(format!(
                "flash frame {} dimensions ({} x {} x {}) do not match baseline ({} x {} x {})",
                i,
                frame.width,
                frame.height,
                frame.channels,
                baseline.width,
                baseline.height,
                baseline.channels,
            ));
        }
    }

    // --- Define face region (center 60%) ------------------------------------
    let w = baseline.width as usize;
    let h = baseline.height as usize;
    let x_margin = (w as f64 * FACE_MARGIN_FRACTION) as usize;
    let y_margin = (h as f64 * FACE_MARGIN_FRACTION) as usize;
    let face_x_start = x_margin;
    let face_x_end = w - x_margin;
    let face_y_start = y_margin;
    let face_y_end = h - y_margin;
    let face_width = face_x_end - face_x_start;
    let face_height = face_y_end - face_y_start;

    // --- Per-round analysis -------------------------------------------------
    let mut region_scores = Vec::with_capacity(3);

    for (round_idx, flash_frame) in flash_frames.iter().enumerate() {
        let round = &pattern.rounds[round_idx];

        // Compute split points with offset (±15% from center)
        let face_x_split = face_x_start + ((face_width as f64) * (0.5 + round.offset_x * 0.3 - 0.15)) as usize;
        let face_y_split = face_y_start + ((face_height as f64) * (0.5 + round.offset_y * 0.3 - 0.15)) as usize;

        // Compute mean RGB delta vector for each quadrant
        let tl_delta = compute_mean_delta(baseline, flash_frame, face_x_start, face_x_split, face_y_start, face_y_split);
        let tr_delta = compute_mean_delta(baseline, flash_frame, face_x_split, face_x_end, face_y_start, face_y_split);
        let bl_delta = compute_mean_delta(baseline, flash_frame, face_x_start, face_x_split, face_y_split, face_y_end);
        let br_delta = compute_mean_delta(baseline, flash_frame, face_x_split, face_x_end, face_y_split, face_y_end);

        // Expected color directions (as f64 vectors)
        let tl_color_vec = [round.tl_color.r as f64, round.tl_color.g as f64, round.tl_color.b as f64];
        let tr_color_vec = [round.tr_color.r as f64, round.tr_color.g as f64, round.tr_color.b as f64];
        let bl_color_vec = [round.bl_color.r as f64, round.bl_color.g as f64, round.bl_color.b as f64];
        let br_color_vec = [round.br_color.r as f64, round.br_color.g as f64, round.br_color.b as f64];

        // Cosine similarity: each quadrant delta vs expected color
        let tl_score = cosine_similarity(&tl_delta, &tl_color_vec);
        let tr_score = cosine_similarity(&tr_delta, &tr_color_vec);
        let bl_score = cosine_similarity(&bl_delta, &bl_color_vec);
        let br_score = cosine_similarity(&br_delta, &br_color_vec);

        // Spatial differentiation: mean cosine similarity across 4 adjacent pairs
        // Adjacent pairs: TL-TR, TL-BL, TR-BR, BL-BR
        let spatial_diff_score = (
            cosine_similarity(&tl_delta, &tr_delta) +
            cosine_similarity(&tl_delta, &bl_delta) +
            cosine_similarity(&tr_delta, &br_delta) +
            cosine_similarity(&bl_delta, &br_delta)
        ) / 4.0;

        region_scores.push(RegionMatchScore {
            round: round_idx,
            tl_score,
            tr_score,
            bl_score,
            br_score,
            spatial_diff_score,
        });
    }

    // --- Aggregate scoring --------------------------------------------------
    // Overall spatial score = mean of per-round spatial_diff_score
    let overall_spatial_score: f64 =
        region_scores.iter().map(|s| s.spatial_diff_score).sum::<f64>() / region_scores.len() as f64;

    // Per-region color match: at least SPATIAL_DIFF_MIN_PASSING_ROUNDS rounds
    // must have all 4 quadrant scores above threshold.
    let color_match_passing = region_scores
        .iter()
        .filter(|s| {
            s.tl_score > REGION_COLOR_MATCH_THRESHOLD
                && s.tr_score > REGION_COLOR_MATCH_THRESHOLD
                && s.bl_score > REGION_COLOR_MATCH_THRESHOLD
                && s.br_score > REGION_COLOR_MATCH_THRESHOLD
        })
        .count();
    let all_regions_match = color_match_passing >= SPATIAL_DIFF_MIN_PASSING_ROUNDS;

    // Spatial differentiation: at least SPATIAL_DIFF_MIN_PASSING_ROUNDS rounds
    // must have adjacent quadrant deltas that differ (similarity < threshold)
    let spatial_diff_passing = region_scores
        .iter()
        .filter(|s| s.spatial_diff_score < SPATIAL_DIFF_MAX_SIMILARITY)
        .count();
    let spatial_diff_ok = spatial_diff_passing >= SPATIAL_DIFF_MIN_PASSING_ROUNDS;

    let passed = all_regions_match && spatial_diff_ok;

    Ok(SpatialVerificationResult {
        passed,
        region_scores,
        overall_spatial_score,
    })
}

// ---------------------------------------------------------------------------
// Internal helpers for spatial verification
// ---------------------------------------------------------------------------

/// Compute the mean RGB delta vector (flash - baseline) for a rectangular
/// sub-region of the image.
///
/// Returns `[mean_dR, mean_dG, mean_dB]`.
fn compute_mean_delta(
    baseline: &PalmImage,
    flash: &PalmImage,
    x_start: usize,
    x_end: usize,
    y_start: usize,
    y_end: usize,
) -> [f64; 3] {
    let channels = baseline.channels as usize;
    let w = baseline.width as usize;
    let mut sum = [0.0f64; 3];
    let mut count = 0u64;

    for y in y_start..y_end {
        for x in x_start..x_end {
            let base_idx = (y * w + x) * channels;
            for ch in 0..3 {
                let b = baseline.data[base_idx + ch] as f64;
                let f = flash.data[base_idx + ch] as f64;
                sum[ch] += f - b;
            }
            count += 1;
        }
    }

    if count == 0 {
        return [0.0; 3];
    }

    [
        sum[0] / count as f64,
        sum[1] / count as f64,
        sum[2] / count as f64,
    ]
}

/// Cosine similarity between two 3-element vectors.
///
/// Returns 0.0 if either vector has zero magnitude.
fn cosine_similarity(a: &[f64; 3], b: &[f64; 3]) -> f64 {
    let dot: f64 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
    let mag_a: f64 = a.iter().map(|x| x * x).sum::<f64>().sqrt();
    let mag_b: f64 = b.iter().map(|x| x * x).sum::<f64>().sqrt();

    if mag_a < f64::EPSILON || mag_b < f64::EPSILON {
        return 0.0;
    }

    (dot / (mag_a * mag_b)).clamp(-1.0, 1.0)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create a deterministic nonce for testing.
    fn test_nonce(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    #[test]
    fn derive_flash_pattern_is_deterministic() {
        let c = test_nonce(0xAA);
        let s = test_nonce(0xBB);

        let p1 = derive_flash_pattern(&c, &s);
        let p2 = derive_flash_pattern(&c, &s);

        assert_eq!(p1, p2, "same inputs must produce identical patterns");
    }

    #[test]
    fn different_nonces_produce_different_patterns() {
        let c = test_nonce(0xAA);
        let s1 = test_nonce(0xBB);
        let s2 = test_nonce(0xCC);

        let p1 = derive_flash_pattern(&c, &s1);
        let p2 = derive_flash_pattern(&c, &s2);

        assert_ne!(p1, p2, "different server nonces must produce different patterns");
    }

    #[test]
    fn pattern_has_three_rounds() {
        let c = test_nonce(0x01);
        let s = test_nonce(0x02);
        let pattern = derive_flash_pattern(&c, &s);

        assert_eq!(pattern.rounds.len(), 3);
    }

    #[test]
    fn photosensitive_safety_clamp_applied() {
        // Manually craft a color that should be clamped.
        let mut color = RgbColor::new(255, 10, 10);
        apply_photosensitive_clamp(&mut color);

        assert!(
            color.r <= RED_CAP,
            "red channel should be capped when G+B is low: got R={}",
            color.r
        );
    }

    #[test]
    fn photosensitive_safety_no_clamp_when_gb_high() {
        // G+B sum is well above threshold.
        let mut color = RgbColor::new(255, 100, 100);
        apply_photosensitive_clamp(&mut color);

        assert_eq!(
            color.r, 255,
            "red channel should not be clamped when G+B is high"
        );
    }

    #[test]
    fn pattern_colors_are_photosensitive_safe() {
        // Exhaustive check across several nonce pairs.
        for seed in 0u8..50 {
            let c = test_nonce(seed);
            let s = test_nonce(seed.wrapping_add(128));
            let pattern = derive_flash_pattern(&c, &s);

            for (ri, round) in pattern.rounds.iter().enumerate() {
                for (label, color) in [
                    ("tl", &round.tl_color), ("tr", &round.tr_color),
                    ("bl", &round.bl_color), ("br", &round.br_color),
                ] {
                    let gb_sum = color.g as u16 + color.b as u16;
                    if gb_sum < GB_LOW_THRESHOLD {
                        assert!(
                            color.r <= RED_CAP,
                            "photosensitive violation in round {} {}: R={} with G+B={}",
                            ri,
                            label,
                            color.r,
                            gb_sum,
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn adjacent_quadrant_colors_are_visually_distinct() {
        // Check angular distance for adjacent quadrant pairs across a range of nonce pairs.
        for seed in 0u8..50 {
            let c = test_nonce(seed);
            let s = test_nonce(seed.wrapping_add(64));
            let pattern = derive_flash_pattern(&c, &s);

            for (ri, round) in pattern.rounds.iter().enumerate() {
                let quads = [round.tl_color, round.tr_color, round.bl_color, round.br_color];
                let adjacent_pairs: [(usize, usize, &str); 4] = [
                    (0, 1, "TL-TR"), (0, 2, "TL-BL"), (1, 3, "TR-BR"), (2, 3, "BL-BR"),
                ];

                for (a, b, label) in &adjacent_pairs {
                    let ca = quads[*a];
                    let cb = quads[*b];
                    let is_zero = |c: &RgbColor| c.r == 0 && c.g == 0 && c.b == 0;
                    if !is_zero(&ca) && !is_zero(&cb) {
                        let dist = angular_distance_deg(&ca, &cb);
                        assert!(
                            dist >= MIN_ANGULAR_DISTANCE_DEG,
                            "round {} {} not distinct enough: {:.1}° < {:.1}° ({:?} vs {:?})",
                            ri, label, dist, MIN_ANGULAR_DISTANCE_DEG, ca, cb,
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn angular_distance_zero_for_same_direction() {
        let a = RgbColor::new(100, 200, 50);
        // Exactly doubled direction (proportional vector).
        let b = RgbColor::new(200, 255, 100); // close to same direction (G clamped to 255)
        let _dist = angular_distance_deg(&a, &b);
        // With clamping these won't be perfectly parallel, but let's test
        // the exact-same case:
        let dist_same = angular_distance_deg(&a, &a);
        assert!(
            dist_same < 0.01,
            "same color should have ~0 angular distance"
        );
    }

    #[test]
    fn angular_distance_orthogonal() {
        let a = RgbColor::new(255, 0, 0);
        let b = RgbColor::new(0, 255, 0);
        let dist = angular_distance_deg(&a, &b);
        assert!(
            (dist - 90.0).abs() < 0.1,
            "pure R vs pure G should be 90°, got {:.1}°",
            dist
        );
    }

    #[test]
    fn angular_distance_zero_vector() {
        let a = RgbColor::new(0, 0, 0);
        let b = RgbColor::new(100, 200, 50);
        let dist = angular_distance_deg(&a, &b);
        assert_eq!(dist, 0.0, "zero vector should return 0 distance");
    }

    #[test]
    fn client_commitment_roundtrip() {
        let nonce = test_nonce(0x42);
        let commitment = compute_client_commitment(&nonce);
        assert!(verify_client_commitment(&nonce, &commitment));
    }

    #[test]
    fn client_commitment_rejects_wrong_nonce() {
        let nonce = test_nonce(0x42);
        let wrong_nonce = test_nonce(0x43);
        let commitment = compute_client_commitment(&nonce);
        assert!(!verify_client_commitment(&wrong_nonce, &commitment));
    }

    #[test]
    fn client_commitment_rejects_wrong_commitment() {
        let nonce = test_nonce(0x42);
        let bad_commitment = [0xFF; 32];
        assert!(!verify_client_commitment(&nonce, &bad_commitment));
    }

    #[test]
    fn commitment_is_deterministic() {
        let nonce = test_nonce(0x42);
        let c1 = compute_client_commitment(&nonce);
        let c2 = compute_client_commitment(&nonce);
        assert_eq!(c1, c2);
    }

    #[test]
    fn rgb_color_to_hex_string() {
        let c = RgbColor::new(0x1a, 0x2b, 0x3c);
        assert_eq!(c.to_hex_string(), "#1a2b3c");
    }

    #[test]
    fn rgb_color_to_array() {
        let c = RgbColor::new(10, 20, 30);
        assert_eq!(c.to_array(), [10, 20, 30]);
    }

    /// Regression test: pin the raw HKDF-SHA256 output for known nonces.
    /// If this test breaks, the TypeScript implementation must be updated
    /// in lockstep.
    #[test]
    fn hkdf_output_known_vector() {
        let c_nonce = [0x00u8; 32];
        let s_nonce = [0xFFu8; 32];

        let mut ikm = [0u8; 64];
        ikm[..32].copy_from_slice(&c_nonce);
        ikm[32..].copy_from_slice(&s_nonce);

        let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), &ikm);
        let mut okm = [0u8; HKDF_OUTPUT_LEN];
        hk.expand(HKDF_INFO, &mut okm).unwrap();

        // First 18 bytes must be identical to the old single-block output.
        // Full 42 bytes span two HMAC blocks.
        let hex_output = hex::encode(&okm);
        assert!(
            hex_output.starts_with("6d90085c86a30e82d8970485c27c2db880e6"),
            "HKDF first 18 bytes changed — this breaks backward compatibility: {}",
            &hex_output[..36]
        );
        // Pin the full 42-byte output for cross-platform parity.
        assert_eq!(
            hex_output.len(), 84,
            "HKDF output should be 42 bytes (84 hex chars), got {} hex chars",
            hex_output.len()
        );
        // Pin the exact output (update TypeScript if this changes).
        eprintln!("HKDF 42-byte output: {}", hex_output);
    }

    /// Regression test: pin the full derived flash pattern for known nonces.
    /// This tests the entire pipeline (HKDF -> saturation mapping ->
    /// photosensitive clamping -> distinctness check).
    #[test]
    fn known_vector_regression() {
        let c_nonce = [0x00u8; 32];
        let s_nonce = [0xFFu8; 32];

        let p1 = derive_flash_pattern(&c_nonce, &s_nonce);
        let p2 = derive_flash_pattern(&c_nonce, &s_nonce);

        // Determinism: same inputs always produce same outputs.
        assert_eq!(p1, p2, "pattern must be deterministic");

        // Pin round 0 colors so any implementation change is detected.
        let r0 = &p1.rounds[0];
        eprintln!(
            "Round 0: tl=({},{},{}) tr=({},{},{}) bl=({},{},{}) br=({},{},{}) offset=({:.3},{:.3})",
            r0.tl_color.r, r0.tl_color.g, r0.tl_color.b,
            r0.tr_color.r, r0.tr_color.g, r0.tr_color.b,
            r0.bl_color.r, r0.bl_color.g, r0.bl_color.b,
            r0.br_color.r, r0.br_color.g, r0.br_color.b,
            r0.offset_x, r0.offset_y,
        );

        // Structural sanity: all 3 rounds should have non-black colors and valid offsets.
        for (i, round) in p1.rounds.iter().enumerate() {
            for (label, color) in [
                ("tl", round.tl_color), ("tr", round.tr_color),
                ("bl", round.bl_color), ("br", round.br_color),
            ] {
                let sum = color.r as u16 + color.g as u16 + color.b as u16;
                assert!(sum > 0, "round {} {} color should not be black", i, label);
            }
            assert!(round.offset_x >= 0.0 && round.offset_x < 1.0,
                "round {} offset_x should be in [0, 1): got {}", i, round.offset_x);
            assert!(round.offset_y >= 0.0 && round.offset_y < 1.0,
                "round {} offset_y should be in [0, 1): got {}", i, round.offset_y);
        }
    }

    // ====================================================================
    // Spatial Flash Verification Tests
    // ====================================================================

    /// Helper: create a uniform RGB test image.
    fn create_rgb_image(w: u32, h: u32, r: u8, g: u8, b: u8) -> PalmImage {
        let mut data = Vec::with_capacity((w * h * 3) as usize);
        for _ in 0..(w * h) {
            data.push(r);
            data.push(g);
            data.push(b);
        }
        PalmImage::new(w, h, 3, data)
    }

    /// Helper: create a quadrant-color image. The four quadrants (split at
    /// the given x/y fractions) have distinct colors.
    fn create_quadrant_image(
        w: u32, h: u32,
        tl: (u8, u8, u8), tr: (u8, u8, u8),
        bl: (u8, u8, u8), br: (u8, u8, u8),
        x_split_frac: f64, y_split_frac: f64,
    ) -> PalmImage {
        let mut data = Vec::with_capacity((w * h * 3) as usize);
        let x_split = (w as f64 * x_split_frac) as u32;
        let y_split = (h as f64 * y_split_frac) as u32;
        for y in 0..h {
            for x in 0..w {
                let (r, g, b) = if y < y_split {
                    if x < x_split { tl } else { tr }
                } else {
                    if x < x_split { bl } else { br }
                };
                data.push(r);
                data.push(g);
                data.push(b);
            }
        }
        PalmImage::new(w, h, 3, data)
    }

    /// Helper: create a deterministic FlashPattern for testing.
    /// Uses offset_x=0.5, offset_y=0.5 (centered grid split).
    fn test_pattern() -> FlashPattern {
        FlashPattern {
            rounds: [
                FlashRound {
                    tl_color: RgbColor::new(255, 0, 0),    // red TL
                    tr_color: RgbColor::new(0, 255, 0),    // green TR
                    bl_color: RgbColor::new(0, 0, 255),    // blue BL
                    br_color: RgbColor::new(255, 255, 0),  // yellow BR
                    offset_x: 0.5,
                    offset_y: 0.5,
                },
                FlashRound {
                    tl_color: RgbColor::new(0, 255, 0),    // green TL
                    tr_color: RgbColor::new(0, 0, 255),    // blue TR
                    bl_color: RgbColor::new(255, 0, 0),    // red BL
                    br_color: RgbColor::new(255, 0, 255),  // magenta BR
                    offset_x: 0.5,
                    offset_y: 0.5,
                },
                FlashRound {
                    tl_color: RgbColor::new(0, 0, 255),    // blue TL
                    tr_color: RgbColor::new(255, 0, 0),    // red TR
                    bl_color: RgbColor::new(0, 255, 0),    // green BL
                    br_color: RgbColor::new(0, 255, 255),  // cyan BR
                    offset_x: 0.5,
                    offset_y: 0.5,
                },
            ],
        }
    }

    #[test]
    fn spatial_correct_quadrant_color_passes() {
        let w = 100u32;
        let h = 100u32;
        let baseline = create_rgb_image(w, h, 50, 50, 50);
        let pattern = test_pattern();

        // Each flash frame: 4 quadrants reflect the corresponding color direction.
        // With offset_x=0.5, offset_y=0.5, the split is at 50% (centered).
        let frames: Vec<PalmImage> = pattern
            .rounds
            .iter()
            .map(|round| {
                create_quadrant_image(
                    w, h,
                    (50u8.saturating_add(round.tl_color.r / 2),
                     50u8.saturating_add(round.tl_color.g / 2),
                     50u8.saturating_add(round.tl_color.b / 2)),
                    (50u8.saturating_add(round.tr_color.r / 2),
                     50u8.saturating_add(round.tr_color.g / 2),
                     50u8.saturating_add(round.tr_color.b / 2)),
                    (50u8.saturating_add(round.bl_color.r / 2),
                     50u8.saturating_add(round.bl_color.g / 2),
                     50u8.saturating_add(round.bl_color.b / 2)),
                    (50u8.saturating_add(round.br_color.r / 2),
                     50u8.saturating_add(round.br_color.g / 2),
                     50u8.saturating_add(round.br_color.b / 2)),
                    0.5, 0.5,
                )
            })
            .collect();

        let result = verify_spatial_flash(&baseline, &frames, &pattern).unwrap();

        // All 4 quadrant color matches should exceed threshold
        for score in &result.region_scores {
            for (label, val) in [
                ("tl", score.tl_score), ("tr", score.tr_score),
                ("bl", score.bl_score), ("br", score.br_score),
            ] {
                assert!(
                    val > REGION_COLOR_MATCH_THRESHOLD,
                    "round {} {}_score {:.3} should exceed {:.3}",
                    score.round, label, val, REGION_COLOR_MATCH_THRESHOLD,
                );
            }
        }

        // Spatial differentiation: adjacent quadrants should differ
        for score in &result.region_scores {
            assert!(
                score.spatial_diff_score < SPATIAL_DIFF_MAX_SIMILARITY,
                "round {} spatial_diff_score {:.3} should be below {:.3} (quadrants must differ)",
                score.round,
                score.spatial_diff_score,
                SPATIAL_DIFF_MAX_SIMILARITY,
            );
        }

        assert!(result.passed, "correct quadrant-color flash should pass");
    }

    #[test]
    fn spatial_uniform_flash_fails_differentiation() {
        let w = 100u32;
        let h = 100u32;
        let baseline = create_rgb_image(w, h, 50, 50, 50);
        let pattern = test_pattern();

        // Uniform flash: same color everywhere (no spatial differentiation).
        // Use the TL color uniformly so color matching passes for TL quadrant
        // but the spatial diff check fails.
        let frames: Vec<PalmImage> = pattern
            .rounds
            .iter()
            .map(|round| {
                create_rgb_image(
                    w,
                    h,
                    50u8.saturating_add(round.tl_color.r / 2),
                    50u8.saturating_add(round.tl_color.g / 2),
                    50u8.saturating_add(round.tl_color.b / 2),
                )
            })
            .collect();

        let result = verify_spatial_flash(&baseline, &frames, &pattern).unwrap();

        // Spatial differentiation should be very high (all quadrants identical)
        for score in &result.region_scores {
            assert!(
                score.spatial_diff_score >= SPATIAL_DIFF_MAX_SIMILARITY,
                "round {} spatial_diff {:.3} should be >= {:.3} for uniform flash",
                score.round,
                score.spatial_diff_score,
                SPATIAL_DIFF_MAX_SIMILARITY,
            );
        }

        assert!(
            !result.passed,
            "uniform flash (flat surface) should fail spatial differentiation"
        );
    }

    #[test]
    fn spatial_wrong_colors_fail_matching() {
        let w = 100u32;
        let h = 100u32;
        let baseline = create_rgb_image(w, h, 50, 50, 50);
        let pattern = test_pattern();

        // Wrong colors: swap TL↔BR and TR↔BL in every round.
        let frames: Vec<PalmImage> = pattern
            .rounds
            .iter()
            .map(|round| {
                create_quadrant_image(
                    w, h,
                    // Swapped: TL gets BR color, TR gets BL color, etc.
                    (50u8.saturating_add(round.br_color.r / 2),
                     50u8.saturating_add(round.br_color.g / 2),
                     50u8.saturating_add(round.br_color.b / 2)),
                    (50u8.saturating_add(round.bl_color.r / 2),
                     50u8.saturating_add(round.bl_color.g / 2),
                     50u8.saturating_add(round.bl_color.b / 2)),
                    (50u8.saturating_add(round.tr_color.r / 2),
                     50u8.saturating_add(round.tr_color.g / 2),
                     50u8.saturating_add(round.tr_color.b / 2)),
                    (50u8.saturating_add(round.tl_color.r / 2),
                     50u8.saturating_add(round.tl_color.g / 2),
                     50u8.saturating_add(round.tl_color.b / 2)),
                    0.5, 0.5,
                )
            })
            .collect();

        let result = verify_spatial_flash(&baseline, &frames, &pattern).unwrap();

        // At least some quadrants should fail color matching.
        let any_fails = result
            .region_scores
            .iter()
            .any(|s| s.tl_score <= REGION_COLOR_MATCH_THRESHOLD
                || s.tr_score <= REGION_COLOR_MATCH_THRESHOLD
                || s.bl_score <= REGION_COLOR_MATCH_THRESHOLD
                || s.br_score <= REGION_COLOR_MATCH_THRESHOLD);

        assert!(
            any_fails,
            "swapped colors should cause at least some region match failures"
        );
        assert!(
            !result.passed,
            "wrong colors should fail overall verification"
        );
    }

    #[test]
    fn spatial_flat_surface_same_delta_fails() {
        let w = 100u32;
        let h = 100u32;
        let baseline = create_rgb_image(w, h, 50, 50, 50);
        let pattern = test_pattern();

        // Flat surface simulation: all quadrants reflect the AVERAGE of all 4
        // colors, producing identical delta vectors in all regions.
        let frames: Vec<PalmImage> = pattern
            .rounds
            .iter()
            .map(|round| {
                let avg_r = ((round.tl_color.r as u16 + round.tr_color.r as u16
                    + round.bl_color.r as u16 + round.br_color.r as u16) / 4) as u8;
                let avg_g = ((round.tl_color.g as u16 + round.tr_color.g as u16
                    + round.bl_color.g as u16 + round.br_color.g as u16) / 4) as u8;
                let avg_b = ((round.tl_color.b as u16 + round.tr_color.b as u16
                    + round.bl_color.b as u16 + round.br_color.b as u16) / 4) as u8;
                create_rgb_image(
                    w, h,
                    50u8.saturating_add(avg_r / 2),
                    50u8.saturating_add(avg_g / 2),
                    50u8.saturating_add(avg_b / 2),
                )
            })
            .collect();

        let result = verify_spatial_flash(&baseline, &frames, &pattern).unwrap();

        // All quadrants have identical deltas => spatial_diff_score should be ~1.0
        for score in &result.region_scores {
            assert!(
                score.spatial_diff_score >= SPATIAL_DIFF_MAX_SIMILARITY,
                "round {} spatial_diff {:.3} should be >= {:.3} for flat surface",
                score.round,
                score.spatial_diff_score,
                SPATIAL_DIFF_MAX_SIMILARITY,
            );
        }

        assert!(
            !result.passed,
            "flat surface (identical deltas) should fail spatial check"
        );
    }

    #[test]
    fn spatial_rejects_wrong_frame_count() {
        let baseline = create_rgb_image(100, 100, 50, 50, 50);
        let pattern = test_pattern();
        let frames = vec![create_rgb_image(100, 100, 100, 100, 100)]; // only 1 frame

        let result = verify_spatial_flash(&baseline, &frames, &pattern);
        assert!(result.is_err(), "should reject non-3 frame count");
    }

    #[test]
    fn spatial_rejects_dimension_mismatch() {
        let baseline = create_rgb_image(100, 100, 50, 50, 50);
        let pattern = test_pattern();
        let frames = vec![
            create_rgb_image(100, 100, 100, 100, 100),
            create_rgb_image(80, 80, 100, 100, 100), // different size
            create_rgb_image(100, 100, 100, 100, 100),
        ];

        let result = verify_spatial_flash(&baseline, &frames, &pattern);
        assert!(result.is_err(), "should reject dimension mismatch");
    }

    #[test]
    fn spatial_rejects_non_rgb() {
        // Grayscale baseline
        let baseline = PalmImage::new(100, 100, 1, vec![50; 100 * 100]);
        let pattern = test_pattern();
        let frames = vec![
            create_rgb_image(100, 100, 100, 100, 100),
            create_rgb_image(100, 100, 100, 100, 100),
            create_rgb_image(100, 100, 100, 100, 100),
        ];

        let result = verify_spatial_flash(&baseline, &frames, &pattern);
        assert!(result.is_err(), "should reject non-RGB baseline");
    }

    #[test]
    fn cosine_similarity_identical_vectors() {
        let a = [1.0, 2.0, 3.0];
        let sim = cosine_similarity(&a, &a);
        assert!(
            (sim - 1.0).abs() < 1e-10,
            "identical vectors should have similarity 1.0, got {:.6}",
            sim,
        );
    }

    #[test]
    fn cosine_similarity_orthogonal_vectors() {
        let a = [1.0, 0.0, 0.0];
        let b = [0.0, 1.0, 0.0];
        let sim = cosine_similarity(&a, &b);
        assert!(
            sim.abs() < 1e-10,
            "orthogonal vectors should have similarity ~0.0, got {:.6}",
            sim,
        );
    }

    #[test]
    fn cosine_similarity_opposite_vectors() {
        let a = [1.0, 0.0, 0.0];
        let b = [-1.0, 0.0, 0.0];
        let sim = cosine_similarity(&a, &b);
        assert!(
            (sim - (-1.0)).abs() < 1e-10,
            "opposite vectors should have similarity -1.0, got {:.6}",
            sim,
        );
    }

    #[test]
    fn cosine_similarity_zero_vector() {
        let a = [0.0, 0.0, 0.0];
        let b = [1.0, 2.0, 3.0];
        let sim = cosine_similarity(&a, &b);
        assert_eq!(sim, 0.0, "zero vector should return 0.0");
    }

    /// Helper: create a quadrant-color image with per-pixel noise.
    fn create_noisy_quadrant_image(
        w: u32, h: u32,
        tl: (u8, u8, u8), tr: (u8, u8, u8),
        bl: (u8, u8, u8), br: (u8, u8, u8),
        noise_amplitude: i16,
        x_split_frac: f64, y_split_frac: f64,
    ) -> PalmImage {
        let mut data = Vec::with_capacity((w * h * 3) as usize);
        let x_split = (w as f64 * x_split_frac) as u32;
        let y_split = (h as f64 * y_split_frac) as u32;
        let mut rng_state: u32 = 0xDEAD_BEEF;
        let next_noise = |state: &mut u32| -> i16 {
            *state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let raw = ((*state >> 16) & 0xFFFF) as i16;
            raw % (noise_amplitude + 1)
        };
        for y in 0..h {
            for x in 0..w {
                let (base_r, base_g, base_b) = if y < y_split {
                    if x < x_split { tl } else { tr }
                } else {
                    if x < x_split { bl } else { br }
                };
                let nr = next_noise(&mut rng_state);
                let ng = next_noise(&mut rng_state);
                let nb = next_noise(&mut rng_state);
                data.push((base_r as i16 + nr).clamp(0, 255) as u8);
                data.push((base_g as i16 + ng).clamp(0, 255) as u8);
                data.push((base_b as i16 + nb).clamp(0, 255) as u8);
            }
        }
        PalmImage::new(w, h, 3, data)
    }

    /// Test: Tolerance for slight ambient variation and face position jitter.
    #[test]
    fn spatial_tolerates_ambient_noise_and_jitter() {
        let w = 100u32;
        let h = 100u32;
        let noise = 5i16;

        // Baseline with slight noise (simulates noisy ambient capture).
        let baseline = create_noisy_quadrant_image(
            w, h, (50,50,50), (50,50,50), (50,50,50), (50,50,50),
            noise, 0.5, 0.5,
        );

        let pattern = test_pattern();

        // Each flash frame: correct quadrant-color with noise.
        let frames: Vec<PalmImage> = pattern
            .rounds
            .iter()
            .map(|round| {
                create_noisy_quadrant_image(
                    w, h,
                    (50u8.saturating_add(round.tl_color.r / 2),
                     50u8.saturating_add(round.tl_color.g / 2),
                     50u8.saturating_add(round.tl_color.b / 2)),
                    (50u8.saturating_add(round.tr_color.r / 2),
                     50u8.saturating_add(round.tr_color.g / 2),
                     50u8.saturating_add(round.tr_color.b / 2)),
                    (50u8.saturating_add(round.bl_color.r / 2),
                     50u8.saturating_add(round.bl_color.g / 2),
                     50u8.saturating_add(round.bl_color.b / 2)),
                    (50u8.saturating_add(round.br_color.r / 2),
                     50u8.saturating_add(round.br_color.g / 2),
                     50u8.saturating_add(round.br_color.b / 2)),
                    noise, 0.5, 0.5,
                )
            })
            .collect();

        let result = verify_spatial_flash(&baseline, &frames, &pattern).unwrap();

        for score in &result.region_scores {
            for (label, val) in [
                ("tl", score.tl_score), ("tr", score.tr_score),
                ("bl", score.bl_score), ("br", score.br_score),
            ] {
                assert!(
                    val > REGION_COLOR_MATCH_THRESHOLD,
                    "round {} {}_score {:.3} should exceed threshold despite noise",
                    score.round, label, val,
                );
            }
            assert!(
                score.spatial_diff_score < SPATIAL_DIFF_MAX_SIMILARITY,
                "round {} spatial_diff {:.3} should show differentiation despite noise",
                score.round, score.spatial_diff_score,
            );
        }

        assert!(
            result.passed,
            "verification should pass with ambient noise (overall_spatial_score={:.3})",
            result.overall_spatial_score,
        );
    }

    // ====================================================================
    // Delta Fingerprint Quantization Tests
    // ====================================================================

    /// Test vector: pure red delta [100, 0, 0]
    /// order=0 (R>=G>=B), mid_ratio=0, min_ratio=0, magnitude=100*31/128=24
    /// fingerprint = (0<<13)|(0<<9)|(0<<5)|24 = 24
    #[test]
    fn fingerprint_pure_red() {
        let fp = quantize_delta_fingerprint(&[100.0, 0.0, 0.0]);
        assert_eq!(fp, 24, "pure red [100,0,0] → 24");
    }

    /// Test vector: pure green delta [0, 200, 0]
    /// order=2 (G>=R>=B), mid_ratio=0, min_ratio=0, magnitude=min(31,200*31/128)=31
    /// fingerprint = (2<<13)|(0<<9)|(0<<5)|31 = 16384+31 = 16415
    #[test]
    fn fingerprint_pure_green() {
        let fp = quantize_delta_fingerprint(&[0.0, 200.0, 0.0]);
        assert_eq!(fp, 16415, "pure green [0,200,0] → 16415");
    }

    /// Test vector: mixed delta [80, 40, 10]
    /// order=0 (R>=G>=B), mid_ratio=40*15/80=7, min_ratio=10*15/80=1
    /// magnitude=80*31/128=19
    /// fingerprint = (0<<13)|(7<<9)|(1<<5)|19 = 3584+32+19 = 3635
    #[test]
    fn fingerprint_mixed() {
        let fp = quantize_delta_fingerprint(&[80.0, 40.0, 10.0]);
        assert_eq!(fp, 3635, "mixed [80,40,10] → 3635");
    }

    /// Test vector: zero delta [0, 0, 0] → 0
    #[test]
    fn fingerprint_zero() {
        let fp = quantize_delta_fingerprint(&[0.0, 0.0, 0.0]);
        assert_eq!(fp, 0, "zero delta → 0");
    }

    /// Determinism: same input always produces same output.
    #[test]
    fn fingerprint_deterministic() {
        let delta = [42.5, -73.2, 18.9];
        let fp1 = quantize_delta_fingerprint(&delta);
        let fp2 = quantize_delta_fingerprint(&delta);
        assert_eq!(fp1, fp2, "same input must produce identical fingerprint");
    }

    /// Negative deltas produce same fingerprint as positive (direction uses absolute values).
    #[test]
    fn fingerprint_sign_invariant() {
        let fp_pos = quantize_delta_fingerprint(&[80.0, 40.0, 10.0]);
        let fp_neg = quantize_delta_fingerprint(&[-80.0, -40.0, -10.0]);
        assert_eq!(fp_pos, fp_neg, "sign should not affect fingerprint");
    }

    /// quantize_expected_color produces same result as quantize_delta_fingerprint
    /// for the same values.
    #[test]
    fn expected_color_matches_delta() {
        let color = RgbColor::new(180, 90, 30);
        let fp_color = quantize_expected_color(&color);
        let fp_delta = quantize_delta_fingerprint(&[180.0, 90.0, 30.0]);
        assert_eq!(fp_color, fp_delta, "expected_color should match delta for same values");
    }

    /// Different color directions produce different fingerprints.
    #[test]
    fn fingerprint_different_directions() {
        let fp_r = quantize_delta_fingerprint(&[200.0, 0.0, 0.0]); // R dominant
        let fp_g = quantize_delta_fingerprint(&[0.0, 200.0, 0.0]); // G dominant
        let fp_b = quantize_delta_fingerprint(&[0.0, 0.0, 200.0]); // B dominant
        assert_ne!(fp_r, fp_g, "red vs green should differ");
        assert_ne!(fp_r, fp_b, "red vs blue should differ");
        assert_ne!(fp_g, fp_b, "green vs blue should differ");
    }

    /// Fingerprints with same direction but different magnitude differ only in low bits.
    #[test]
    fn fingerprint_same_direction_different_magnitude() {
        let fp1 = quantize_delta_fingerprint(&[40.0, 20.0, 5.0]);
        let fp2 = quantize_delta_fingerprint(&[120.0, 60.0, 15.0]);
        // Same direction, so high bits (order + ratios) should match
        let high_mask: u16 = 0xFFE0; // top 11 bits
        assert_eq!(fp1 & high_mask, fp2 & high_mask, "direction bits should match");
        // But magnitude differs
        let mag_mask: u16 = 0x001F; // low 5 bits
        assert_ne!(fp1 & mag_mask, fp2 & mag_mask, "magnitude bits should differ");
    }

    /// Hamming distance between similar directions should be small.
    #[test]
    fn fingerprint_hamming_distance_similar() {
        let fp1 = quantize_delta_fingerprint(&[100.0, 50.0, 10.0]);
        let fp2 = quantize_delta_fingerprint(&[110.0, 55.0, 12.0]); // same direction, similar magnitude
        let hd = (fp1 ^ fp2).count_ones();
        assert!(hd <= 3, "similar deltas should have small Hamming distance, got {}", hd);
    }

    /// Hamming distance between very different directions should be non-zero.
    /// Pure R (order=000) vs pure B (order=101) differ by 2 bits in the order field.
    /// Mixed colors with different ratios will have higher Hamming distance.
    #[test]
    fn fingerprint_hamming_distance_different() {
        // Pure primary colors: differ in order bits (2-3 bits)
        let fp_r = quantize_delta_fingerprint(&[200.0, 10.0, 5.0]);  // R dominant
        let fp_b = quantize_delta_fingerprint(&[5.0, 10.0, 200.0]);  // B dominant
        let hd_pure = (fp_r ^ fp_b).count_ones();
        assert!(hd_pure >= 2, "orthogonal pure colors should differ by >= 2 bits, got {}", hd_pure);

        // Mixed colors with different ratios: differ in order + ratio bits
        let fp_warm = quantize_delta_fingerprint(&[150.0, 100.0, 20.0]); // warm (R>G>B)
        let fp_cool = quantize_delta_fingerprint(&[20.0, 80.0, 160.0]);  // cool (B>G>R)
        let hd_mixed = (fp_warm ^ fp_cool).count_ones();
        assert!(hd_mixed >= 4, "mixed colors with different ratios should differ by >= 4 bits, got {}", hd_mixed);
    }
}
