//! # Photometric convexity extraction
//!
//! Implements [[SPEC-006-geometric-liveness]] REQ-111, REQ-112, REQ-113.
//!
//! Each spatial-flash round lights four screen quadrants **simultaneously** in
//! four HKDF-derived colours and captures one frame. That is a colour-multiplexed
//! photometric stereo rig: four known light directions, demultiplexed by colour.
//! The existing extraction reduces each face quadrant to a chromatic fingerprint
//! and discards the geometry; this module recovers it.
//!
//! ## What the score measures
//!
//! For each patch of an N×N grid we project the patch's mean RGB delta onto each
//! quadrant's emitted colour direction and normalise, giving a **mix** — the
//! patch's relative illumination by the four lamps. The discriminator is how much
//! those mixes vary *across* patches.
//!
//! A plane presents the same normal everywhere, so every patch receives the same
//! relative mix and the variation is small. A convex surface rotates its normal
//! from patch to patch, swinging the mix toward whichever lamp each patch faces.
//!
//! Two intuitive alternatives were implemented and falsified by
//! `convexity_separates_plane_from_hemisphere`; both are recorded in ADR-007 of
//! `docs/specs/SPEC-006-geometric-liveness.md`:
//!
//! 1. *Nearest-lamp agreement* — a plane scores identically (16/16), because with
//!    finite-distance lamps the nearest lamp dominates on a plane too.
//! 2. *Per-patch response contrast* — no separation (plane 0.6462, hemisphere
//!    0.6446). Projecting onto four lamp colours measures the delta's colour
//!    direction, which is a chromatic quantity of the same class as the existing
//!    fingerprint, i.e. the weakness this module exists to remove. With four
//!    lamps and three colour channels a single frame cannot demultiplex four
//!    sources; only the *spatial* pattern of the mix carries geometry.
//!
//! Each mix is normalised before comparison, so the score is invariant to
//! exposure and to albedo — which is what makes it invariant across skin
//! tones (NFR-106).
//!
//! **IMPORTANT:** thresholds are deliberately absent. Per ADR-010 no operating
//! constant enters the trusted relation until a presentation-attack study fixes
//! it. Callers supply their own.

use crate::biometric::PalmImage;
use crate::error::{Result, SableError};

/// Fixed-point scale for response projection, chosen so integer division in the
/// spread ratio keeps sub-unit precision at realistic delta magnitudes.
const RESPONSE_SCALE: i64 = 1 << 16;

/// Number of screen quadrants illuminated per round: TL, TR, BL, BR.
pub const NUM_QUADRANTS: usize = 4;

/// Minimum accepted frame dimension (CON-092 P1).
const MIN_DIM: u32 = 64;

/// Grid dimension bounds (CON-092 P2).
const MIN_GRID_N: usize = 2;
const MAX_GRID_N: usize = 8;

/// Patch grid laid over the face region.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PatchGrid {
    /// Patches per side; the grid is `n × n`.
    pub n: usize,
}

impl Default for PatchGrid {
    /// REQ-111: default grid dimension is 4.
    fn default() -> Self {
        Self { n: 4 }
    }
}

/// Q15 fixed-point unity: mix components sum to this when a patch responded.
pub const Q15_ONE: i64 = 1 << 15;

/// Per-round photometric analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhotometricRound {
    /// Per-patch response to each quadrant light, row-major, `n²` entries.
    pub responses: Vec<[i64; NUM_QUADRANTS]>,
    /// Per-patch normalised illumination mix in Q15; all-zero if the patch had
    /// no response (REQ-112).
    pub mixes: Vec<[i64; NUM_QUADRANTS]>,
    /// Mean L1 deviation of patch mixes from the round mean, Q15 over [0, 2]
    /// (REQ-113).
    pub convexity_score: u16,
}

/// Extract photometric convexity evidence from one flash round.
///
/// `quadrant_colours` are the emitted RGB colours for TL, TR, BL, BR.
///
/// Implements CON-092. Full recognition of the frame pair happens before any
/// arithmetic; no partial output is produced on a rejected input.
pub fn extract(
    baseline: &PalmImage,
    flash: &PalmImage,
    quadrant_colours: &[[u8; 3]; NUM_QUADRANTS],
    grid: PatchGrid,
) -> Result<PhotometricRound> {
    recognise(baseline, flash, grid)?;

    let n = grid.n;
    let patch_count = n * n;
    let mut responses = Vec::with_capacity(patch_count);
    let mut mixes = Vec::with_capacity(patch_count);

    // Unit-direction denominators for each lamp colour, computed once.
    let norms: [i64; NUM_QUADRANTS] =
        core::array::from_fn(|k| colour_norm(&quadrant_colours[k]));

    for row in 0..n {
        for col in 0..n {
            let delta = mean_delta(baseline, flash, grid, row, col);
            let r: [i64; NUM_QUADRANTS] = core::array::from_fn(|k| {
                project(&delta, &quadrant_colours[k], norms[k])
            });

            // REQ-112: normalise to a mix. A patch with no response contributes
            // an all-zero mix rather than a division fault.
            let total: i64 = r.iter().sum();
            let mix: [i64; NUM_QUADRANTS] = if total <= 0 {
                [0; NUM_QUADRANTS]
            } else {
                core::array::from_fn(|k| r[k] * Q15_ONE / total)
            };

            responses.push(r);
            mixes.push(mix);
        }
    }

    // REQ-113: mean L1 deviation of each patch mix from the round mean mix.
    let mean_mix: [i64; NUM_QUADRANTS] =
        core::array::from_fn(|k| mixes.iter().map(|m| m[k]).sum::<i64>() / patch_count as i64);
    let deviation_sum: i64 = mixes
        .iter()
        .map(|m| (0..NUM_QUADRANTS).map(|k| (m[k] - mean_mix[k]).abs()).sum::<i64>())
        .sum();
    let convexity_score = (deviation_sum / patch_count as i64).clamp(0, u16::MAX as i64) as u16;

    Ok(PhotometricRound {
        responses,
        mixes,
        convexity_score,
    })
}

/// Recogniser for the CON-092 input grammar. Runs to completion before any
/// semantic action (LangSec: recognise before acting).
fn recognise(baseline: &PalmImage, flash: &PalmImage, grid: PatchGrid) -> Result<()> {
    if baseline.width != flash.width || baseline.height != flash.height {
        return Err(SableError::InvalidInput(
            "baseline and flash dimensions differ".into(),
        ));
    }
    if baseline.channels != 3 || flash.channels != 3 {
        return Err(SableError::InvalidInput("frames must be RGB8".into()));
    }
    if baseline.width < MIN_DIM || baseline.height < MIN_DIM {
        return Err(SableError::InvalidInput("frame smaller than 64x64".into()));
    }
    if !(MIN_GRID_N..=MAX_GRID_N).contains(&grid.n) {
        return Err(SableError::InvalidInput("grid.n outside [2, 8]".into()));
    }
    let expected = (baseline.width as usize) * (baseline.height as usize) * 3;
    if baseline.data.len() != expected || flash.data.len() != expected {
        return Err(SableError::InvalidInput(
            "pixel buffer length does not match dimensions".into(),
        ));
    }
    Ok(())
}

/// Mean per-channel delta (flash − baseline) over one patch.
fn mean_delta(
    baseline: &PalmImage,
    flash: &PalmImage,
    grid: PatchGrid,
    row: usize,
    col: usize,
) -> [i64; 3] {
    let w = baseline.width as usize;
    let h = baseline.height as usize;
    let x0 = col * w / grid.n;
    let x1 = ((col + 1) * w / grid.n).max(x0 + 1);
    let y0 = row * h / grid.n;
    let y1 = ((row + 1) * h / grid.n).max(y0 + 1);

    let mut sum = [0i64; 3];
    let mut count = 0i64;
    for y in y0..y1 {
        for x in x0..x1 {
            let idx = (y * w + x) * 3;
            for c in 0..3 {
                sum[c] += flash.data[idx + c] as i64 - baseline.data[idx + c] as i64;
            }
            count += 1;
        }
    }
    if count == 0 {
        return [0; 3];
    }
    core::array::from_fn(|c| sum[c] / count)
}

/// Euclidean norm of a lamp colour, as an integer.
fn colour_norm(colour: &[u8; 3]) -> i64 {
    let sq: i64 = colour.iter().map(|&c| (c as i64) * (c as i64)).sum();
    sq.isqrt()
}

/// Project a delta onto a lamp's unit colour direction.
///
/// Clamped at zero: a Lambertian response cannot be negative, and a negative
/// projection means the delta points away from that lamp's colour.
fn project(delta: &[i64; 3], colour: &[u8; 3], norm: i64) -> i64 {
    if norm == 0 {
        return 0;
    }
    let dot: i64 = (0..3).map(|c| delta[c] * colour[c] as i64).sum();
    let scaled = dot.saturating_mul(RESPONSE_SCALE) / norm;
    scaled.max(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------------------------------------------------------------
    // Synthetic renderer — gives tests ground-truth geometry so the structural
    // assertions hold without any field-calibrated threshold (ADR-010).
    // ---------------------------------------------------------------------

    const DIM: u32 = 96;
    /// Lamp positions in mm: TL, TR, BL, BR of a phone screen at arm's length.
    const LAMPS: [[f64; 3]; 4] = [
        [-35.0, 35.0, 350.0],
        [35.0, 35.0, 350.0],
        [-35.0, -35.0, 350.0],
        [35.0, -35.0, 350.0],
    ];
    const COLOURS: [[u8; 3]; 4] = [[255, 0, 0], [0, 255, 0], [0, 0, 255], [255, 255, 0]];
    /// Half-width of the rendered face patch in mm.
    const EXTENT: f64 = 60.0;

    fn blank(dim: u32, level: u8) -> PalmImage {
        PalmImage {
            width: dim,
            height: dim,
            channels: 3,
            data: vec![level; (dim * dim * 3) as usize],
            preprocessing_steps: vec![],
        }
    }

    /// Render a surface under the four lamps. `normal_at` returns a unit normal
    /// for a point on the surface, in the same frame as `LAMPS`.
    fn render(normal_at: impl Fn(f64, f64) -> [f64; 3], gain: f64) -> PalmImage {
        let dim = DIM as usize;
        let mut img = blank(DIM, 0);
        for py in 0..dim {
            for px in 0..dim {
                let x = (px as f64 + 0.5) / dim as f64 * 2.0 * EXTENT - EXTENT;
                let y = EXTENT - (py as f64 + 0.5) / dim as f64 * 2.0 * EXTENT;
                let n = normal_at(x, y);
                let mut acc = [0.0f64; 3];
                for (k, lamp) in LAMPS.iter().enumerate() {
                    let d = [lamp[0] - x, lamp[1] - y, lamp[2]];
                    let r = (d[0] * d[0] + d[1] * d[1] + d[2] * d[2]).sqrt();
                    let ndl = (n[0] * d[0] + n[1] * d[1] + n[2] * d[2]) / r;
                    let irr = ndl.max(0.0) / (r * r) * 1.0e7 * gain;
                    for c in 0..3 {
                        acc[c] += irr * COLOURS[k][c] as f64 / 255.0;
                    }
                }
                let idx = (py * dim + px) * 3;
                for c in 0..3 {
                    img.data[idx + c] = acc[c].round().clamp(0.0, 255.0) as u8;
                }
            }
        }
        img
    }

    fn plane(_x: f64, _y: f64) -> [f64; 3] {
        [0.0, 0.0, 1.0]
    }

    fn hemisphere(x: f64, y: f64) -> [f64; 3] {
        const R: f64 = 90.0;
        let z = (R * R - x * x - y * y).max(1.0).sqrt();
        let m = (x * x + y * y + z * z).sqrt();
        [x / m, y / m, z / m]
    }

    // ---------------------------------------------------------------------
    // TEST-135 — patch response extraction (REQ-111)
    // ---------------------------------------------------------------------

    #[test]
    fn single_lamp_dominates_its_own_colour_channel() {
        // Only the red lamp is lit; every patch must respond most to quadrant 0.
        let base = blank(DIM, 0);
        let mut flash = blank(DIM, 0);
        for px in flash.data.chunks_mut(3) {
            px[0] = 120; // pure red delta
        }
        let out = extract(&base, &flash, &COLOURS, PatchGrid::default()).unwrap();
        assert_eq!(out.responses.len(), 16);
        for r in &out.responses {
            let best = r.iter().enumerate().max_by_key(|(_, v)| **v).unwrap().0;
            assert_eq!(best, 0, "pure red delta should favour the red lamp");
        }
    }

    #[test]
    fn rejects_mismatched_dimensions() {
        let base = blank(DIM, 0);
        let flash = blank(DIM + 32, 0);
        assert!(extract(&base, &flash, &COLOURS, PatchGrid::default()).is_err());
    }

    #[test]
    fn rejects_grid_outside_bounds() {
        let base = blank(DIM, 0);
        let flash = blank(DIM, 10);
        assert!(extract(&base, &flash, &COLOURS, PatchGrid { n: 1 }).is_err());
        assert!(extract(&base, &flash, &COLOURS, PatchGrid { n: 9 }).is_err());
    }

    #[test]
    fn rejects_undersized_frame() {
        let small = blank(32, 0);
        assert!(extract(&small, &small, &COLOURS, PatchGrid::default()).is_err());
    }

    #[test]
    fn response_count_matches_grid() {
        let base = blank(DIM, 0);
        let flash = blank(DIM, 40);
        for n in MIN_GRID_N..=MAX_GRID_N {
            let out = extract(&base, &flash, &COLOURS, PatchGrid { n }).unwrap();
            assert_eq!(out.responses.len(), n * n);
            assert_eq!(out.mixes.len(), n * n);
        }
    }

    // ---------------------------------------------------------------------
    // TEST-136 — per-patch illumination mix (REQ-112)
    // ---------------------------------------------------------------------

    #[test]
    fn each_mix_sums_to_unity_or_zero() {
        let base = blank(DIM, 10);
        let flash = render(hemisphere, 1.0);
        let out = extract(&base, &flash, &COLOURS, PatchGrid::default()).unwrap();
        for m in &out.mixes {
            let total: i64 = m.iter().sum();
            assert!(
                total == 0 || (total - Q15_ONE).abs() <= NUM_QUADRANTS as i64,
                "mix sum {total} is neither zero nor Q15 unity"
            );
        }
    }

    #[test]
    fn zero_delta_yields_zero_mix_not_a_fault() {
        let base = blank(DIM, 77);
        let flash = blank(DIM, 77); // identical → zero delta everywhere
        let out = extract(&base, &flash, &COLOURS, PatchGrid::default()).unwrap();
        assert!(out.mixes.iter().all(|m| m.iter().all(|&v| v == 0)));
        assert_eq!(out.convexity_score, 0);
    }

    #[test]
    fn uniform_illumination_yields_near_zero_convexity() {
        // A spatially uniform delta means every patch has an identical mix, so
        // the cross-patch deviation must vanish. This is the flat-surface limit.
        let base = blank(DIM, 0);
        let mut flash = blank(DIM, 0);
        for px in flash.data.chunks_mut(3) {
            px[0] = 90;
            px[1] = 60;
            px[2] = 30;
        }
        let out = extract(&base, &flash, &COLOURS, PatchGrid::default()).unwrap();
        assert_eq!(
            out.convexity_score, 0,
            "spatially uniform illumination must produce zero cross-patch variation"
        );
    }

    // ---------------------------------------------------------------------
    // TEST-137 — convexity separation (REQ-113). Structural, threshold-free.
    //
    // This is the assertion that falsified the nearest-lamp formulation.
    // It MUST NOT be weakened to an absolute threshold.
    // ---------------------------------------------------------------------

    #[test]
    fn convexity_separates_plane_from_hemisphere() {
        let base = blank(DIM, 0);
        let flat = render(plane, 1.0);
        let curved = render(hemisphere, 1.0);

        let flat_score = extract(&base, &flat, &COLOURS, PatchGrid::default())
            .unwrap()
            .convexity_score;
        let curved_score = extract(&base, &curved, &COLOURS, PatchGrid::default())
            .unwrap()
            .convexity_score;

        println!("convexity: plane={flat_score} hemisphere={curved_score}");
        assert!(
            curved_score > flat_score,
            "hemisphere ({curved_score}) must score above plane ({flat_score})"
        );
        // Separation must be decisive, not marginal: a discriminator that only
        // just orders the two would not survive sensor noise. Simulated ratio is
        // ~2.9x; require at least 2x so the test fails loudly on regression.
        assert!(
            curved_score >= flat_score.saturating_mul(2),
            "separation too weak: hemisphere {curved_score} vs plane {flat_score}"
        );
    }

    // ---------------------------------------------------------------------
    // TEST-144 — albedo invariance (NFR-106)
    // ---------------------------------------------------------------------

    #[test]
    fn convexity_is_invariant_to_uniform_gain() {
        let base = blank(DIM, 0);
        let reference = extract(&base, &render(hemisphere, 1.0), &COLOURS, PatchGrid::default())
            .unwrap()
            .convexity_score as i32;

        // NFR-106 allows 5/255; expressed against the Q15 score that is
        // 5/255 * 65535 ≈ 1285.
        const TOLERANCE: i32 = 1285;
        for gain in [0.5, 0.75, 1.5, 2.0] {
            let score = extract(&base, &render(hemisphere, gain), &COLOURS, PatchGrid::default())
                .unwrap()
                .convexity_score as i32;
            assert!(
                (score - reference).abs() <= TOLERANCE,
                "gain {gain}: score {score} deviates from {reference} beyond NFR-106 tolerance"
            );
        }
    }
}

