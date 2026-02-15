//! Reusable Fuzzy Commitment scheme for deterministic biometric commitments.
//!
//! Implements the code-offset construction (Juels & Wattenberg 1999) using
//! Reed-Solomon error correction over GF(2^8). This allows deriving a stable,
//! deterministic commitment from noisy biometric data.
//!
//! # Construction
//!
//! **Gen** (enrollment): Given biometric `w ∈ [u8; 512]`:
//! 1. Split into two 255-element blocks + 2 tail bytes
//! 2. For each block: sample random RS message, encode to codeword, XOR with biometric
//! 3. Hash combined messages to produce deterministic 32-byte commitment
//! 4. Return `(commitment, helper_data)`
//!
//! **Rep** (reproduction): Given fresh biometric `w'` and `helper_data`:
//! 1. XOR `w'` with stored delta to get `error ⊕ codeword`
//! 2. RS-decode to recover original messages
//! 3. Re-derive commitment hash and verify
//!
//! # Security Properties
//!
//! - **Hiding**: The code-offset delta leaks at most `n - k` symbols of entropy
//! - **Binding**: SHA-256 commitment is computationally binding
//! - **Reusable**: Independent random codewords per enrollment (ROM security)
//! - **Robust**: Commitment verification detects helper data tampering

use super::gf256;
use super::reed_solomon::ReedSolomon;
use sha2::{Digest, Sha256};

/// The full biometric vector length.
const BIOMETRIC_DIM: usize = 512;

/// RS block length (max for GF(256)).
const RS_BLOCK_LEN: usize = 255;

/// Number of RS blocks needed to cover 512 dimensions.
/// Two blocks of 255 cover 510 dims; the remaining 2 are tail bytes.
const NUM_BLOCKS: usize = 2;

/// Number of tail bytes not covered by RS blocks.
const TAIL_LEN: usize = BIOMETRIC_DIM - NUM_BLOCKS * RS_BLOCK_LEN; // = 2

/// Parameters for the fuzzy commitment scheme.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FuzzyParams {
    /// Error correction capacity per RS block (max differing symbols per block).
    pub t: usize,
    /// RS message length per block: k = 255 - 2*t.
    pub k: usize,
}

impl FuzzyParams {
    /// Create parameters with given error correction capacity per block.
    ///
    /// `t` is the max number of differing u8 positions tolerated per 255-element block.
    /// Total tolerance across the full 512-dim vector is approximately `2*t`.
    pub fn new(t: usize) -> Self {
        assert!(t > 0, "error correction capacity must be > 0");
        let parity = 2 * t;
        assert!(parity < RS_BLOCK_LEN, "t too large for RS(255, k)");
        Self {
            t,
            k: RS_BLOCK_LEN - parity,
        }
    }

    /// Default parameters tuned for face embeddings.
    ///
    /// t=40 per block allows ~80 differing u8 positions out of 510 (~15.7%).
    /// This provides good tolerance for genuine biometric variation while
    /// maintaining sufficient entropy in the commitment.
    pub fn default_face() -> Self {
        Self::new(40)
    }
}

/// Public helper data stored alongside the commitment.
///
/// This data is NOT secret — it is designed to leak minimal information
/// about the biometric. The entropy loss is bounded by `2 * (255 - k)` symbols.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HelperData {
    /// Code-offset deltas: w ⊕ codeword, for each RS block.
    /// Layout: [block_0: 255 bytes | block_1: 255 bytes | tail: 2 bytes]
    pub delta: Vec<u8>,
    /// SHA-256 commitment over the RS messages (32 bytes).
    pub commitment: [u8; 32],
    /// Parameters used during enrollment.
    pub params: FuzzyParams,
}

impl HelperData {
    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        // Simple format: [t: u8][k: u8][delta: 512][commitment: 32]
        let mut bytes = Vec::with_capacity(2 + BIOMETRIC_DIM + 32);
        bytes.push(self.params.t as u8);
        bytes.push(self.params.k as u8);
        bytes.extend_from_slice(&self.delta);
        bytes.extend_from_slice(&self.commitment);
        bytes
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 2 + BIOMETRIC_DIM + 32 {
            return None;
        }
        let t = bytes[0] as usize;
        let k = bytes[1] as usize;
        if k + 2 * t != RS_BLOCK_LEN {
            return None;
        }
        let delta = bytes[2..2 + BIOMETRIC_DIM].to_vec();
        let mut commitment = [0u8; 32];
        commitment.copy_from_slice(&bytes[2 + BIOMETRIC_DIM..2 + BIOMETRIC_DIM + 32]);
        Some(Self {
            delta,
            commitment,
            params: FuzzyParams { t, k },
        })
    }
}

/// Result of the Gen (enrollment) operation.
pub struct Enrollment {
    /// Deterministic 32-byte commitment derived from the biometric.
    pub commitment: [u8; 32],
    /// Public helper data (to be stored for later reproduction).
    pub helper_data: HelperData,
}

/// Generate a fuzzy commitment from a biometric vector (enrollment).
///
/// This is the **Gen** operation. It produces a deterministic commitment
/// and public helper data that enables future reproduction from a noisy
/// biometric reading.
///
/// # Arguments
/// - `biometric`: Quantized biometric feature vector `[u8; 512]`
/// - `params`: Error correction parameters
///
/// # Returns
/// `Enrollment` containing the commitment and helper data.
pub fn gen(biometric: &[u8], params: &FuzzyParams) -> Enrollment {
    assert_eq!(
        biometric.len(),
        BIOMETRIC_DIM,
        "biometric must be {BIOMETRIC_DIM} bytes"
    );

    let rs = ReedSolomon::new(RS_BLOCK_LEN, params.k);

    // SHA-256 hasher accumulates all RS messages for the final commitment
    let mut hasher = Sha256::new();

    let mut delta = Vec::with_capacity(BIOMETRIC_DIM);

    // Process each RS block
    for block_idx in 0..NUM_BLOCKS {
        let bio_start = block_idx * RS_BLOCK_LEN;
        let bio_block = &biometric[bio_start..bio_start + RS_BLOCK_LEN];

        // Generate random RS message
        let message = random_message(params.k);

        // Encode to codeword
        let codeword = rs.encode(&message);

        // Code-offset: δ = w ⊕ c (component-wise XOR)
        for (w_byte, c_byte) in bio_block.iter().zip(codeword.iter()) {
            delta.push(gf256::add(*w_byte, *c_byte));
        }

        // Accumulate message into commitment hash
        hasher.update(&message);
    }

    // Handle tail bytes: XOR with a hash-derived mask
    let tail_start = NUM_BLOCKS * RS_BLOCK_LEN;
    let tail_bytes = &biometric[tail_start..];
    let tail_mask = derive_tail_mask(&hasher);
    for (i, &w_byte) in tail_bytes.iter().enumerate() {
        delta.push(gf256::add(w_byte, tail_mask[i]));
    }

    // Include tail bytes in commitment (masked)
    hasher.update(tail_bytes);

    let commitment: [u8; 32] = hasher.finalize().into();

    let helper_data = HelperData {
        delta,
        commitment,
        params: params.clone(),
    };

    Enrollment {
        commitment,
        helper_data,
    }
}

/// Reproduce a commitment from a fresh biometric reading.
///
/// This is the **Rep** operation. Given a fresh (noisy) biometric reading
/// and the stored helper data, it attempts to recover the original commitment.
///
/// # Arguments
/// - `biometric`: Fresh biometric reading `[u8; 512]`
/// - `helper_data`: Stored helper data from enrollment
///
/// # Returns
/// - `Some(commitment)`: The 32-byte commitment if biometric is within threshold
/// - `None`: If the biometric is too different (beyond error correction capacity)
pub fn rep(biometric: &[u8], helper_data: &HelperData) -> Option<[u8; 32]> {
    assert_eq!(
        biometric.len(),
        BIOMETRIC_DIM,
        "biometric must be {BIOMETRIC_DIM} bytes"
    );
    assert_eq!(helper_data.delta.len(), BIOMETRIC_DIM);

    let rs = ReedSolomon::new(RS_BLOCK_LEN, helper_data.params.k);

    let mut hasher = Sha256::new();

    // Decode each RS block
    for block_idx in 0..NUM_BLOCKS {
        let bio_start = block_idx * RS_BLOCK_LEN;
        let bio_block = &biometric[bio_start..bio_start + RS_BLOCK_LEN];
        let delta_block = &helper_data.delta[bio_start..bio_start + RS_BLOCK_LEN];

        // y = w' ⊕ δ = w' ⊕ (w ⊕ c) = (w' ⊕ w) ⊕ c = e ⊕ c
        let y: Vec<u8> = bio_block
            .iter()
            .zip(delta_block.iter())
            .map(|(&w, &d)| gf256::add(w, d))
            .collect();

        // RS decode: recover codeword, then extract message
        let message = rs.decode(&y).ok()?;

        hasher.update(&message);
    }

    // Recover tail bytes
    let tail_start = NUM_BLOCKS * RS_BLOCK_LEN;
    let tail_mask = derive_tail_mask(&hasher);
    let tail_bytes: Vec<u8> = biometric[tail_start..]
        .iter()
        .zip(helper_data.delta[tail_start..].iter())
        .enumerate()
        .map(|(i, (&w, &d))| {
            // recovered_tail = w' ⊕ δ_tail ... but the tail isn't error-corrected.
            // We XOR w' with the delta, then unmask to get original tail bytes.
            // δ_tail = w_orig ⊕ mask, so w' ⊕ δ_tail = w' ⊕ w_orig ⊕ mask
            // If w' == w_orig (tail bytes match), this recovers mask, then
            // we'd need the original tail bytes. This is tricky without ECC.
            //
            // Simpler approach: the tail bytes contribute to the commitment hash
            // but are recovered by XOR: recovered = w' ⊕ (delta - mask) ...
            // Actually, for the tail we store δ = w ⊕ mask, so
            // w = δ ⊕ mask. The fresh reading w' may differ from w.
            // Without ECC on the tail, we just use the original w from delta.
            let _ = (w, i);
            gf256::add(d, tail_mask[i]) // Recover original tail byte from delta
        })
        .collect();

    hasher.update(&tail_bytes);

    let commitment: [u8; 32] = hasher.finalize().into();

    // Verify commitment matches
    if commitment == helper_data.commitment {
        Some(commitment)
    } else {
        None
    }
}

/// Derive a mask for the 2 tail bytes from the current hasher state.
fn derive_tail_mask(hasher: &Sha256) -> [u8; TAIL_LEN] {
    // Clone the hasher and finalize with a domain separator to get the mask
    let mut mask_hasher = hasher.clone();
    mask_hasher.update(b"sable-fuzzy-tail-mask");
    let hash: [u8; 32] = mask_hasher.finalize().into();
    let mut mask = [0u8; TAIL_LEN];
    mask.copy_from_slice(&hash[..TAIL_LEN]);
    mask
}

/// Generate a random message of given length using OS randomness.
fn random_message(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    getrandom::getrandom(&mut buf).expect("OS RNG should not fail");
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_biometric(seed: u8) -> Vec<u8> {
        (0..BIOMETRIC_DIM)
            .map(|i| seed.wrapping_add(i as u8).wrapping_mul(7))
            .collect()
    }

    fn add_noise(bio: &[u8], num_errors: usize, magnitude: u8) -> Vec<u8> {
        let mut noisy = bio.to_vec();
        // Deterministically add errors at spaced positions
        for i in 0..num_errors {
            let pos = (i * 7 + 3) % BIOMETRIC_DIM;
            noisy[pos] ^= magnitude;
        }
        noisy
    }

    #[test]
    fn test_exact_match_reproduces_commitment() {
        let params = FuzzyParams::new(30);
        let bio = make_biometric(42);

        let enrollment = gen(&bio, &params);
        let reproduced = rep(&bio, &enrollment.helper_data);

        assert_eq!(
            reproduced,
            Some(enrollment.commitment),
            "exact match should reproduce commitment"
        );
    }

    #[test]
    fn test_noisy_within_threshold() {
        let params = FuzzyParams::new(30); // t=30 per block, ~60 total tolerance
        let bio = make_biometric(42);

        let enrollment = gen(&bio, &params);

        // Add 20 errors total (well within 2*30=60 capacity)
        let noisy = add_noise(&bio, 20, 0x42);
        let reproduced = rep(&noisy, &enrollment.helper_data);

        assert_eq!(
            reproduced,
            Some(enrollment.commitment),
            "noisy input within threshold should reproduce commitment"
        );
    }

    #[test]
    fn test_noisy_beyond_threshold_fails() {
        let params = FuzzyParams::new(5); // t=5 per block, ~10 total tolerance
        let bio = make_biometric(42);

        let enrollment = gen(&bio, &params);

        // Add 100 errors (way beyond capacity)
        let noisy = add_noise(&bio, 100, 0xFF);
        let reproduced = rep(&noisy, &enrollment.helper_data);

        assert_eq!(
            reproduced, None,
            "noisy input beyond threshold should fail"
        );
    }

    #[test]
    fn test_different_biometrics_different_commitments() {
        let params = FuzzyParams::new(30);
        let bio1 = make_biometric(42);
        let bio2 = make_biometric(99);

        let enrollment1 = gen(&bio1, &params);
        let enrollment2 = gen(&bio2, &params);

        // Different biometrics produce different commitments
        // (with overwhelming probability since messages are random)
        assert_ne!(enrollment1.commitment, enrollment2.commitment);
    }

    #[test]
    fn test_different_biometric_cannot_reproduce() {
        let params = FuzzyParams::new(30);
        let bio1 = make_biometric(42);
        let bio2 = make_biometric(99);

        let enrollment = gen(&bio1, &params);
        let reproduced = rep(&bio2, &enrollment.helper_data);

        assert_eq!(
            reproduced, None,
            "different biometric should not reproduce commitment"
        );
    }

    #[test]
    fn test_helper_data_serialization_roundtrip() {
        let params = FuzzyParams::new(30);
        let bio = make_biometric(42);

        let enrollment = gen(&bio, &params);
        let bytes = enrollment.helper_data.to_bytes();
        let recovered = HelperData::from_bytes(&bytes).expect("should deserialize");

        assert_eq!(recovered.delta, enrollment.helper_data.delta);
        assert_eq!(recovered.commitment, enrollment.helper_data.commitment);
        assert_eq!(recovered.params.t, enrollment.helper_data.params.t);
        assert_eq!(recovered.params.k, enrollment.helper_data.params.k);
    }

    #[test]
    fn test_default_face_params() {
        let params = FuzzyParams::default_face();
        assert_eq!(params.t, 40);
        assert_eq!(params.k, 175); // 255 - 80
    }

    #[test]
    fn test_benchmark_gen_rep() {
        let params = FuzzyParams::default_face(); // t=40
        let bio = make_biometric(42);

        // Warm up
        let enrollment = gen(&bio, &params);
        let _ = rep(&bio, &enrollment.helper_data);

        // Benchmark Gen
        let start = std::time::Instant::now();
        let iterations = 10;
        for _ in 0..iterations {
            let _ = gen(&bio, &params);
        }
        let gen_avg = start.elapsed() / iterations;
        eprintln!("Gen avg: {:?}", gen_avg);
        assert!(
            gen_avg.as_millis() < 100,
            "Gen should be < 100ms, was {:?}",
            gen_avg
        );

        // Benchmark Rep
        let start = std::time::Instant::now();
        for _ in 0..iterations {
            let _ = rep(&bio, &enrollment.helper_data);
        }
        let rep_avg = start.elapsed() / iterations;
        eprintln!("Rep avg: {:?}", rep_avg);
        assert!(
            rep_avg.as_millis() < 200,
            "Rep should be < 200ms, was {:?}",
            rep_avg
        );
    }

    #[test]
    fn test_parameter_tuning_face_embeddings() {
        // Test various error thresholds to find the sweet spot
        let bio = make_biometric(42);

        for t in [10, 20, 30, 40, 50] {
            let params = FuzzyParams::new(t);

            let enrollment = gen(&bio, &params);

            // Count how many errors can be corrected
            let mut max_corrected = 0;
            for num_errors in (0..=2 * t + 10).step_by(5) {
                let noisy = add_noise(&bio, num_errors, 0xFF);
                if rep(&noisy, &enrollment.helper_data).is_some() {
                    max_corrected = num_errors;
                } else {
                    break;
                }
            }

            eprintln!(
                "t={}: k={}, max_corrected~={}, entropy={}bits",
                t,
                params.k,
                max_corrected,
                params.k * 8 * 2 // two blocks
            );
        }
    }

    #[test]
    fn test_errors_distributed_across_blocks() {
        let params = FuzzyParams::new(20); // t=20 per block
        let bio = make_biometric(42);

        let enrollment = gen(&bio, &params);

        // Put 15 errors in first block and 15 in second block (30 total, within 2*20=40)
        let mut noisy = bio.clone();
        for i in 0..15 {
            noisy[i * 10] ^= 0x77; // First block (positions 0-254)
        }
        for i in 0..15 {
            noisy[255 + i * 10] ^= 0x88; // Second block (positions 255-509)
        }

        let reproduced = rep(&noisy, &enrollment.helper_data);
        assert_eq!(
            reproduced,
            Some(enrollment.commitment),
            "errors distributed across blocks should be corrected"
        );
    }
}
