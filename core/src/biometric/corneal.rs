//! # Corneal glint liveness
//!
//! Implements [[SPEC-006-geometric-liveness]] REQ-114 and REQ-115.
//!
//! The cornea is a convex mirror of radius ≈ 7.8 mm, so it forms a virtual image
//! of whatever the eye faces — including the screen emitting the flash pattern. A
//! replayed or synthesised face carries the *attacker's* ambient scene in that
//! glint, not the verifier's unpredictable challenge colours.
//!
//! ## Why mean colour and not spatial structure
//!
//! The virtual image of an object subtending angle θ has size `(R/2)·θ`, i.e.
//! `3.9 mm · θ`. Against an 11.7 mm iris on a 1920 px front camera at 70° HFOV:
//!
//! | setting | screen | distance | iris | glint | per 2×2 cell |
//! |---------|--------|----------|------|-------|--------------|
//! | phone, arm's length | 70 mm | 350 mm | 45.8 px | 3.0 px | 1.5 px |
//! | laptop 14in | 300 mm | 600 mm | 26.7 px | 4.4 px | 2.2 px |
//!
//! A phone — the stated target — leaves 1.5 px per cell, so resolving a 2×2
//! colour pattern inside the glint is not possible. This module therefore encodes
//! the glint's *overall* colour and derives security from agreement across the
//! three-round sequence, which an artefact fixed before the challenge cannot
//! track. See ADR-008.
//!
//! **IMPORTANT:** eye localisation is out of scope (CON-093). Callers supply a
//! cropped corneal region. Thresholds are caller-supplied per ADR-010.

use crate::biometric::fingerprint::{matches, quantize_colour, quantize_delta};
use crate::biometric::PalmImage;
use crate::error::{Result, SableError};

/// Accepted eye-region dimension bounds (CON-093 P1).
///
/// The upper bound is enforced as well as the lower: without it
/// `width * height * 3` can wrap on a 64-bit target, admitting a tiny buffer
/// against enormous declared dimensions.
const MIN_EYE_DIM: u32 = 8;
const MAX_EYE_DIM: u32 = 4096;

/// Number of screen quadrants contributing to the reflected composite.
pub const NUM_QUADRANTS: usize = 4;

/// Encode the mean RGB delta of a corneal region as a [`Delta Fingerprint`].
///
/// Implements CON-093. Recognition completes before any arithmetic.
pub fn glint_fingerprint(baseline_eye: &PalmImage, flash_eye: &PalmImage) -> Result<u16> {
    recognise(baseline_eye, flash_eye)?;

    let n = (baseline_eye.width as usize) * (baseline_eye.height as usize);
    let mut sum = [0i64; 3];
    for i in 0..n {
        for c in 0..3 {
            sum[c] += flash_eye.data[i * 3 + c] as i64 - baseline_eye.data[i * 3 + c] as i64;
        }
    }
    let mean = [
        sum[0] as f64 / n as f64,
        sum[1] as f64 / n as f64,
        sum[2] as f64 / n as f64,
    ];
    Ok(quantize_delta(&mean))
}

/// Fingerprint of the area-weighted composite of the four quadrant colours.
///
/// The cornea reflects the whole screen at once, so the expected glint colour is
/// the quadrants' composite rather than any single quadrant. `weights` are the
/// quadrant areas; the HKDF-derived grid offset makes them unequal.
pub fn expected_composite(
    quadrant_colours: &[[u8; 3]; NUM_QUADRANTS],
    weights: &[u32; NUM_QUADRANTS],
) -> Result<u16> {
    let total: u64 = weights.iter().map(|&w| w as u64).sum();
    if total == 0 {
        return Err(SableError::InvalidInput(
            "quadrant weights sum to zero".into(),
        ));
    }
    let mut composite = [0u8; 3];
    for c in 0..3 {
        let acc: u64 = (0..NUM_QUADRANTS)
            .map(|k| quadrant_colours[k][c] as u64 * weights[k] as u64)
            .sum();
        composite[c] = (acc / total).min(255) as u8;
    }
    Ok(quantize_colour(&composite))
}

/// Whether an observed glint agrees with the round's expected composite.
///
/// Uses the structured field comparison, **not** Hamming distance: the
/// fingerprint's `order` field is categorical, so a bit distance would accept a
/// blue glint against a red challenge (BUG-001). Thresholds are caller-supplied
/// per ADR-010.
pub fn agrees(observed: u16, expected: u16, max_ratio_delta: u8, max_magnitude_delta: u8) -> bool {
    matches(observed, expected, max_ratio_delta, max_magnitude_delta)
}

/// Recogniser for the CON-093 input grammar.
fn recognise(baseline_eye: &PalmImage, flash_eye: &PalmImage) -> Result<()> {
    if baseline_eye.width != flash_eye.width || baseline_eye.height != flash_eye.height {
        return Err(SableError::InvalidInput(
            "eye region dimensions differ".into(),
        ));
    }
    if baseline_eye.channels != 3 || flash_eye.channels != 3 {
        return Err(SableError::InvalidInput("eye region must be RGB8".into()));
    }
    if !(MIN_EYE_DIM..=MAX_EYE_DIM).contains(&baseline_eye.width)
        || !(MIN_EYE_DIM..=MAX_EYE_DIM).contains(&baseline_eye.height)
    {
        return Err(SableError::InvalidInput(
            "eye region dimensions outside [8, 4096]".into(),
        ));
    }
    let expected = (baseline_eye.width as usize)
        .checked_mul(baseline_eye.height as usize)
        .and_then(|px| px.checked_mul(3))
        .ok_or_else(|| SableError::InvalidInput("eye dimensions overflow".into()))?;
    if baseline_eye.data.len() != expected || flash_eye.data.len() != expected {
        return Err(SableError::InvalidInput(
            "eye pixel buffer length does not match dimensions".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const EQUAL: [u32; NUM_QUADRANTS] = [1, 1, 1, 1];

    fn eye(dim: u32, rgb: [u8; 3]) -> PalmImage {
        let mut data = Vec::with_capacity((dim * dim * 3) as usize);
        for _ in 0..(dim * dim) {
            data.extend_from_slice(&rgb);
        }
        PalmImage {
            width: dim,
            height: dim,
            channels: 3,
            data,
            preprocessing_steps: vec![],
        }
    }

    // -----------------------------------------------------------------
    // TEST-138 — glint fingerprint (REQ-114)
    // -----------------------------------------------------------------

    #[test]
    fn red_dominant_glint_encodes_order_zero() {
        let base = eye(16, [0, 0, 0]);
        let flash = eye(16, [200, 30, 10]);
        let fp = glint_fingerprint(&base, &flash).unwrap();
        assert_eq!(fp >> 13, 0, "red-dominant glint should encode order 0");
    }

    #[test]
    fn rejects_undersized_eye_region() {
        let tiny = eye(4, [10, 10, 10]);
        assert!(glint_fingerprint(&tiny, &tiny).is_err());
    }

    #[test]
    fn rejects_mismatched_eye_dimensions() {
        let a = eye(16, [0, 0, 0]);
        let b = eye(24, [0, 0, 0]);
        assert!(glint_fingerprint(&a, &b).is_err());
    }

    #[test]
    fn rejects_eye_dimensions_above_grammar_bound() {
        let mut big = eye(16, [0, 0, 0]);
        big.width = 8192;
        big.height = 8192;
        let base = eye(16, [0, 0, 0]);
        assert!(glint_fingerprint(&base, &big).is_err());
    }

    #[test]
    fn rejects_eye_length_computation_overflow() {
        let base = PalmImage {
            width: 3_062_868_337,
            height: 2_007_567_422,
            channels: 3,
            data: vec![0u8; 26],
            preprocessing_steps: vec![],
        };
        let mut evil = base.clone();
        evil.data = vec![1u8; 26];
        assert!(
            glint_fingerprint(&base, &evil).is_err(),
            "overflowing eye dimensions must be rejected, not wrapped"
        );
    }

    #[test]
    fn zero_delta_glint_encodes_zero() {
        let same = eye(16, [90, 90, 90]);
        assert_eq!(glint_fingerprint(&same, &same).unwrap(), 0);
    }

    // -----------------------------------------------------------------
    // TEST-139 — corneal agreement (REQ-115)
    // -----------------------------------------------------------------

    #[test]
    fn glint_matching_this_round_composite_agrees() {
        let colours = [[255, 0, 0], [255, 40, 0], [200, 20, 0], [255, 10, 10]];
        let expected = expected_composite(&colours, &EQUAL).unwrap();

        // The eye reflects the composite of the four quadrants.
        let base = eye(16, [0, 0, 0]);
        let flash = eye(16, [241, 17, 2]);
        let observed = glint_fingerprint(&base, &flash).unwrap();

        assert!(
            agrees(observed, expected, 2, 2),
            "observed {observed:#06x} should agree with expected {expected:#06x}"
        );
    }

    #[test]
    fn glint_matching_the_previous_round_is_rejected() {
        // This is the replay case REQ-115 exists for: an artefact reflecting a
        // stale challenge cannot track an unpredictable sequence.
        let this_round = [[255, 0, 0], [255, 40, 0], [200, 20, 0], [255, 10, 10]];
        let prev_round = [[0, 0, 255], [0, 40, 255], [0, 20, 200], [10, 10, 255]];

        let expected = expected_composite(&this_round, &EQUAL).unwrap();
        let stale = expected_composite(&prev_round, &EQUAL).unwrap();

        // Generous tolerances: the rejection must come from the categorical
        // order field, not from a tight ordinal bound.
        assert!(
            !agrees(stale, expected, 15, 31),
            "a glint reflecting the previous round must not agree with this one"
        );
    }

    #[test]
    fn composite_is_area_weighted() {
        let colours = [[255, 0, 0], [0, 0, 0], [0, 0, 0], [0, 0, 0]];
        // Dominated by quadrant 0 → red; then dominated by quadrant 1 → black.
        let red_heavy = expected_composite(&colours, &[100, 1, 1, 1]).unwrap();
        let red_light = expected_composite(&colours, &[1, 100, 100, 100]).unwrap();
        assert_ne!(
            red_heavy, red_light,
            "composite must respond to quadrant areas"
        );
    }

    #[test]
    fn zero_weights_are_rejected() {
        let colours = [[255, 0, 0], [0, 255, 0], [0, 0, 255], [255, 255, 0]];
        assert!(expected_composite(&colours, &[0, 0, 0, 0]).is_err());
    }
}
