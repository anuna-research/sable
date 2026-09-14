//! # Delta fingerprint encoding
//!
//! The 16-bit code used to summarise a flash response for in-circuit comparison.
//!
//! ```text
//! bit  15 14 13 | 12 11 10 9 | 8 7 6 5  | 4 3 2 1 0
//!      order    | mid_ratio  | min_ratio| magnitude
//! ```
//!
//! `order` selects one of six orderings of R/G/B by absolute value; the two
//! ratios are `|mid|/|max|` and `|min|/|max|` scaled to `[0,15]`; `magnitude` is
//! the dominant channel scaled to `[0,31]`. A zero delta encodes as `0x0000`.
//!
//! The fields are narrow and the layout fixed because the in-circuit check is a
//! lookup-backed popcount. Note that popcount over this layout is **not** a
//! colour metric — `order` is categorical, so red and blue sit one bit apart.
//! Use [`matches`] for colour comparison; see
//! `docs/specs/BUG-001-hamming-over-categorical-order-field.md`.
//!
//! ## Why this lives in `core`
//!
//! This encoding is a contract shared by the circuit, the demo server, and the
//! browser client. It previously lived in `demo/server`, which put a shared
//! contract inside one of its consumers (Constitutional Principle 15). A second
//! implementation exists in TypeScript; the two MUST agree bit-for-bit, and a
//! divergence is a soundness bug rather than a rendering bug. Consolidating the
//! Rust side here is the first half of removing that hazard — see
//! `docs/specs/SPEC-006-geometric-liveness.md`, "Known Defects".

/// Maximum channel value that maps to `magnitude = 31`.
///
/// 128 is chosen so a strong single-channel response — half the 0-255 range —
/// saturates the field.
pub const MAGNITUDE_SCALE: u32 = 128;

/// Quantise an RGB delta vector `[dR, dG, dB]` to a 16-bit fingerprint.
///
/// Encodes the *direction* (channel ordering plus ratios) and *magnitude* of the
/// delta. Returns 0 when the delta has zero magnitude.
///
/// The encoding is sign-invariant: a delta and its negation encode identically,
/// because channels are taken in absolute value.
pub fn quantize_delta(delta: &[f64; 3]) -> u16 {
    quantize_delta_scaled(delta, MAGNITUDE_SCALE)
}

/// Mask selecting the direction fields (`order`, `mid_ratio`, `min_ratio`) and
/// dropping `magnitude`. The colour check compares direction only (BUG-003).
pub const DIRECTION_MASK: u16 = 0xFFE0;

/// The direction fields of a fingerprint with the magnitude cleared.
pub const fn direction(fp: u16) -> u16 {
    fp & DIRECTION_MASK
}

/// [`quantize_delta`] with a caller-supplied magnitude scale.
///
/// `scale` is the maximum channel delta that maps to `magnitude = 31`. It is a
/// prover-side calibration for the capture device, not a public parameter of
/// the relation: the delta fingerprints are private witnesses, so the verifier
/// never sees the scale and gains nothing from binding it. What the verifier
/// does control is the public `min_magnitude` floor, which only means something
/// once the deployment has fixed its scale (BUG-003, ADR-010).
pub fn quantize_delta_scaled(delta: &[f64; 3], scale: u32) -> u16 {
    let scale = scale.max(1);
    // Round to nearest for cross-platform stability.
    let abs_channels: [u32; 3] = [
        delta[0].abs().round() as u32,
        delta[1].abs().round() as u32,
        delta[2].abs().round() as u32,
    ];

    // Sort descending; on ties prefer the lower channel index so the encoding is
    // total and deterministic.
    let mut indexed: [(u32, usize); 3] = [
        (abs_channels[0], 0),
        (abs_channels[1], 1),
        (abs_channels[2], 2),
    ];
    indexed.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));

    let (max_val, max_idx) = (indexed[0].0, indexed[0].1);
    let (mid_val, mid_idx) = (indexed[1].0, indexed[1].1);
    let min_val = indexed[2].0;

    if max_val == 0 {
        return 0; // no flash response
    }

    let order: u16 = match (max_idx, mid_idx) {
        (0, 1) => 0, // R >= G >= B
        (0, 2) => 1, // R >= B >= G
        (1, 0) => 2, // G >= R >= B
        (1, 2) => 3, // G >= B >= R
        (2, 0) => 4, // B >= R >= G
        (2, 1) => 5, // B >= G >= R
        _ => 0,      // unreachable with three distinct indices
    };

    let mid_ratio = ((mid_val * 15) / max_val).min(15) as u16;
    let min_ratio = ((min_val * 15) / max_val).min(15) as u16;
    let magnitude = ((max_val * 31) / scale).min(31) as u16;

    (order << 13) | (mid_ratio << 9) | (min_ratio << 5) | magnitude
}

/// Quantise an RGB colour into the *direction* half of the fingerprint space.
///
/// The magnitude field is zero. An emitted colour has a brightness, but a
/// reflected delta has a magnitude in different units (distance, albedo,
/// exposure), so an expected fingerprint must carry no magnitude to compare
/// against. Magnitude is judged only against a floor (BUG-003).
pub fn quantize_colour(colour: &[u8; 3]) -> u16 {
    direction(quantize_delta(&[colour[0] as f64, colour[1] as f64, colour[2] as f64]))
}

/// Hamming distance between two fingerprints.
///
/// # This is not a colour metric
///
/// `order` is a *categorical* field, so bit-adjacency does not imply
/// value-adjacency: order 0 (`R≥G≥B`) and order 4 (`B≥R≥G`) are one bit apart and
/// denote opposite colour directions. Measured, red and blue are Hamming distance
/// 1 apart while red and yellow are 4.
///
/// Use [`matches`] to compare fingerprints by colour. This function remains for
/// the in-circuit popcount path and for diagnostics. See
/// `docs/specs/BUG-001-hamming-over-categorical-order-field.md`.
pub fn hamming_distance(a: u16, b: u16) -> u32 {
    (a ^ b).count_ones()
}

/// The four fields of a fingerprint, unpacked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fields {
    /// Categorical: which of six channel orderings holds. Compare by equality.
    pub order: u8,
    /// Ordinal: `|mid| / |max|` in `[0, 15]`.
    pub mid_ratio: u8,
    /// Ordinal: `|min| / |max|` in `[0, 15]`.
    pub min_ratio: u8,
    /// Ordinal: dominant channel strength in `[0, 31]`.
    pub magnitude: u8,
}

/// Unpack a fingerprint into its constituent fields.
pub fn unpack(fp: u16) -> Fields {
    Fields {
        order: ((fp >> 13) & 0x07) as u8,
        mid_ratio: ((fp >> 9) & 0x0F) as u8,
        min_ratio: ((fp >> 5) & 0x0F) as u8,
        magnitude: (fp & 0x1F) as u8,
    }
}

/// Compare two fingerprints by field semantics rather than as a bit string.
///
/// `order` must match exactly — it is categorical. The ratio fields must lie
/// within `max_ratio_delta` of the expected. The observed `magnitude` must be
/// at least `magnitude_floor`; the expected magnitude is ignored because an
/// expected fingerprint carries none (BUG-003). This is the comparison BUG-001
/// requires; thresholds stay caller-supplied per ADR-010.
pub fn matches(observed: u16, expected: u16, max_ratio_delta: u8, magnitude_floor: u8) -> bool {
    let (o, e) = (unpack(observed), unpack(expected));
    o.order == e.order
        && o.mid_ratio.abs_diff(e.mid_ratio) <= max_ratio_delta
        && o.min_ratio.abs_diff(e.min_ratio) <= max_ratio_delta
        && o.magnitude >= magnitude_floor
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pure_red_encodes_order_zero() {
        let fp = quantize_delta(&[100.0, 0.0, 0.0]);
        assert_eq!(fp >> 13, 0);
    }

    #[test]
    fn pure_blue_encodes_order_four_or_five() {
        let fp = quantize_delta(&[0.0, 0.0, 100.0]);
        // B dominant; R and G tie at zero, tie-break prefers the lower index (R).
        assert_eq!(fp >> 13, 4);
    }

    #[test]
    fn zero_delta_encodes_zero() {
        assert_eq!(quantize_delta(&[0.0, 0.0, 0.0]), 0);
    }

    #[test]
    fn encoding_is_sign_invariant() {
        let a = quantize_delta(&[80.0, -40.0, 20.0]);
        let b = quantize_delta(&[-80.0, 40.0, -20.0]);
        assert_eq!(a, b);
    }

    #[test]
    fn magnitude_saturates_at_scale() {
        let at = quantize_delta(&[MAGNITUDE_SCALE as f64, 0.0, 0.0]) & 0x1F;
        let beyond = quantize_delta(&[255.0, 0.0, 0.0]) & 0x1F;
        assert_eq!(at, 31);
        assert_eq!(beyond, 31);
    }

    #[test]
    fn same_direction_different_magnitude_shares_direction_bits() {
        let a = quantize_delta(&[100.0, 50.0, 25.0]);
        let b = quantize_delta(&[40.0, 20.0, 10.0]);
        assert_eq!(a >> 5, b >> 5, "direction bits should agree");
        assert_ne!(a & 0x1F, b & 0x1F, "magnitude should differ");
    }

    #[test]
    fn hamming_of_identical_is_zero() {
        let fp = quantize_delta(&[10.0, 20.0, 30.0]);
        assert_eq!(hamming_distance(fp, fp), 0);
    }

    /// Regression pin for BUG-001. This asserts the *defect*, so that any future
    /// change to the encoding which happens to fix it fails here loudly and the
    /// bug can be closed deliberately rather than silently.
    #[test]
    fn hamming_is_not_a_colour_metric() {
        let red = quantize_colour(&[255, 0, 0]);
        let green = quantize_colour(&[0, 255, 0]);
        let blue = quantize_colour(&[0, 0, 255]);
        let yellow = quantize_colour(&[255, 255, 0]);

        assert_eq!(hamming_distance(red, green), 1, "BUG-001");
        assert_eq!(hamming_distance(red, blue), 1, "BUG-001");
        assert_eq!(hamming_distance(red, yellow), 4, "BUG-001");
        assert!(
            hamming_distance(red, blue) < hamming_distance(red, yellow),
            "BUG-001: opposite colours are closer than adjacent ones"
        );
    }

    #[test]
    fn structured_match_rejects_wrong_colour_direction() {
        let red = quantize_colour(&[255, 0, 0]);
        let green = quantize_colour(&[0, 255, 0]);
        let blue = quantize_colour(&[0, 0, 255]);

        // Generous tolerances; order equality alone must carry the rejection.
        assert!(!matches(green, red, 15, 31));
        assert!(!matches(blue, red, 15, 31));
        assert!(matches(red, red, 0, 0));
    }

    #[test]
    fn structured_match_admits_near_colours() {
        let a = quantize_colour(&[255, 20, 5]);
        let b = quantize_colour(&[250, 26, 8]);
        assert_eq!(unpack(a).order, unpack(b).order);
        assert!(matches(a, b, 2, 0));
    }

    /// BUG-003: an expected fingerprint carries no magnitude.
    #[test]
    fn expected_colour_has_zero_magnitude() {
        for c in [[255u8, 0, 0], [0, 255, 0], [10, 20, 30], [255, 255, 255]] {
            assert_eq!(quantize_colour(&c) & 0x1F, 0, "{c:?}");
        }
    }

    /// BUG-003: the observed magnitude is judged against a floor, never
    /// against the expected side.
    #[test]
    fn structured_match_treats_magnitude_as_a_floor() {
        let expected = quantize_colour(&[255, 0, 0]);
        let weak = quantize_delta(&[4.0, 0.0, 0.0]); // magnitude 0 at scale 128
        let faint = quantize_delta(&[8.0, 0.0, 0.0]); // magnitude 1
        assert_eq!(faint & 0x1F, 1);
        assert!(matches(faint, expected, 0, 1));
        assert!(matches(faint, expected, 0, 0));
        assert!(!matches(faint, expected, 0, 2));
        assert!(matches(weak, expected, 0, 0));
        assert!(!matches(weak, expected, 0, 1));
    }

    #[test]
    fn scaled_quantiser_rescales_magnitude_only() {
        let d = [8.0, 4.0, 2.0];
        let coarse = quantize_delta_scaled(&d, 128);
        let fine = quantize_delta_scaled(&d, 16);
        assert_eq!(direction(coarse), direction(fine));
        assert_eq!(coarse & 0x1F, 1);
        assert_eq!(fine & 0x1F, 15);
        assert_eq!(quantize_delta(&d), coarse);
    }

    #[test]
    fn unpack_roundtrips_field_bounds() {
        for fp in [0u16, 0xFFFF, 0x021F, 0xA21F] {
            let f = unpack(fp);
            assert!(f.order <= 7 && f.mid_ratio <= 15 && f.min_ratio <= 15 && f.magnitude <= 31);
        }
    }
}
