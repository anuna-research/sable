//! Rolling-shutter temporal challenge primitives (SPEC-008).
//!
//! This module owns the platform-independent nonce-to-waveform mapping and the
//! fixed-size evidence grammar consumed by the Halo2 liveness circuit. Camera
//! capture and row-band decoding remain platform responsibilities because they
//! need device-specific exposure and readout calibration.

use hkdf::Hkdf;
use sha2::Sha256;

use crate::error::{Result, SableError};

/// Number of symbols in one challenge waveform.
pub const TEMPORAL_SYMBOLS: usize = 12;
/// Number of frames in one temporal burst.
pub const TEMPORAL_FRAMES: usize = 3;
/// Number of row-band observations assigned to each frame.
pub const SYMBOLS_PER_FRAME: usize = TEMPORAL_SYMBOLS / TEMPORAL_FRAMES;
/// Number of inter-frame timing deltas.
pub const FRAME_DELTAS: usize = TEMPORAL_FRAMES - 1;

const HKDF_SALT: &[u8] = b"sable-rolling-shutter-v1";
const HKDF_INFO: &[u8] = b"temporal-symbols";
const HKDF_OUTPUT_LEN: usize = 4_080;

/// Four display symbols. The numeric representation is part of CON-098.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TemporalSymbol {
    /// Red display symbol.
    Red = 0,
    /// Green display symbol.
    Green = 1,
    /// Blue display symbol.
    Blue = 2,
    /// White display symbol.
    White = 3,
}

impl TemporalSymbol {
    /// Convert a recognised two-bit value to a symbol.
    pub fn try_from_u8(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::Red),
            1 => Ok(Self::Green),
            2 => Ok(Self::Blue),
            3 => Ok(Self::White),
            _ => Err(SableError::InvalidInput(format!(
                "temporal symbol {value} is outside 0..=3"
            ))),
        }
    }

    /// RGB value used by display integrations.
    pub const fn rgb(self) -> [u8; 3] {
        match self {
            Self::Red => [204, 0, 0],
            Self::Green => [0, 255, 0],
            Self::Blue => [0, 0, 255],
            Self::White => [255, 255, 255],
        }
    }
}

/// Derive a uniform no-adjacent-repeat waveform from the joint nonce.
///
/// The first byte selects one of four symbols. Every later byte selects one
/// of the three symbols other than its predecessor, in ascending numeric order.
pub fn derive_temporal_symbols(
    client_nonce: &[u8; 32],
    server_nonce: &[u8; 32],
) -> Result<[u8; TEMPORAL_SYMBOLS]> {
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(client_nonce);
    ikm[32..].copy_from_slice(server_nonce);

    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), &ikm);
    let mut okm = [0u8; HKDF_OUTPUT_LEN];
    hk.expand(HKDF_INFO, &mut okm)
        .expect("4080 bytes is within the HKDF-SHA256 output limit");

    let mut cursor = 0usize;
    while cursor < okm.len() {
        let mut candidate = [0u8; TEMPORAL_SYMBOLS];
        candidate[0] = okm[cursor] % 4;
        cursor += 1;
        let mut complete = true;
        for i in 1..TEMPORAL_SYMBOLS {
            let rank = loop {
                let Some(&byte) = okm.get(cursor) else {
                    complete = false;
                    break 0;
                };
                cursor += 1;
                if byte < 255 {
                    break byte % 3;
                }
            };
            if !complete {
                break;
            }
            let previous = candidate[i - 1];
            // Map rank 0..=2 to the ordered alphabet with `previous` removed.
            candidate[i] = if rank >= previous { rank + 1 } else { rank };
        }
        if complete && valid_temporal_sequence(&candidate) {
            return Ok(candidate);
        }
    }
    Err(SableError::InvalidInput(
        "HKDF expansion contained no valid temporal waveform".into(),
    ))
}

/// Check the public waveform grammar from SPEC-008 CON-098.
pub fn valid_temporal_sequence(symbols: &[u8; TEMPORAL_SYMBOLS]) -> bool {
    if symbols.iter().any(|&symbol| symbol > 3)
        || (0..TEMPORAL_SYMBOLS).any(|i| symbols[i] == symbols[(i + 1) % TEMPORAL_SYMBOLS])
    {
        return false;
    }

    // A full cyclic period excludes a sequence equal to any non-trivial rotation.
    if (1..TEMPORAL_SYMBOLS).any(|shift| {
        (0..TEMPORAL_SYMBOLS).all(|i| symbols[i] == symbols[(i + shift) % TEMPORAL_SYMBOLS])
    }) {
        return false;
    }

    let mut windows = [false; 256];
    for start in 0..TEMPORAL_SYMBOLS {
        let mut packed = 0usize;
        for offset in 0..SYMBOLS_PER_FRAME {
            packed |= (symbols[(start + offset) % TEMPORAL_SYMBOLS] as usize) << (2 * offset);
        }
        if windows[packed] {
            return false;
        }
        windows[packed] = true;
    }
    true
}

/// Minimum Hamming distance between two distinct cyclic rotations.
pub fn minimum_rotation_distance(symbols: &[u8; TEMPORAL_SYMBOLS]) -> u8 {
    (1..TEMPORAL_SYMBOLS)
        .map(|shift| {
            (0..TEMPORAL_SYMBOLS)
                .filter(|&i| symbols[i] != symbols[(i + shift) % TEMPORAL_SYMBOLS])
                .count() as u8
        })
        .min()
        .unwrap_or(0)
}

/// Largest error budget whose Hamming balls around rotations remain disjoint.
pub fn maximum_unambiguous_errors(symbols: &[u8; TEMPORAL_SYMBOLS]) -> u8 {
    minimum_rotation_distance(symbols).saturating_sub(1) / 2
}

/// Private evidence produced by a calibrated capture integration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TemporalObservation {
    /// Four ordered row-band symbols from each of three frames.
    pub symbols: [u8; TEMPORAL_SYMBOLS],
    /// Rotation of the expected waveform at the first observed band.
    pub initial_phase: u8,
    /// Capture-start deltas in device-profile ticks between adjacent frames.
    pub frame_tick_deltas: [u16; FRAME_DELTAS],
}

impl TemporalObservation {
    /// Recognise the fixed evidence grammar before semantic use.
    pub fn recognise(&self) -> Result<()> {
        for (i, &symbol) in self.symbols.iter().enumerate() {
            if symbol > 3 {
                return Err(SableError::InvalidInput(format!(
                    "observed temporal symbol {i} is outside 0..=3"
                )));
            }
        }
        if self.initial_phase >= TEMPORAL_SYMBOLS as u8 {
            return Err(SableError::InvalidInput(format!(
                "initial temporal phase {} is outside 0..={} ",
                self.initial_phase,
                TEMPORAL_SYMBOLS - 1
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_160_rll_derivation_is_deterministic_and_no_repeat() {
        let client = [0x11; 32];
        let server = [0xA5; 32];
        let got = derive_temporal_symbols(&client, &server).unwrap();
        assert_eq!(got, [2, 1, 3, 0, 3, 2, 1, 3, 1, 2, 1, 0]);
        assert!(got.windows(2).all(|pair| pair[0] != pair[1]));
        assert!(got.iter().all(|&symbol| symbol <= 3));
        assert!(valid_temporal_sequence(&got));
        assert!(minimum_rotation_distance(&got) >= 3);
    }

    #[test]
    fn test_161_observation_grammar_rejects_symbol_and_phase_overflow() {
        let valid = TemporalObservation {
            symbols: [0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3],
            initial_phase: 11,
            frame_tick_deltas: [4, 4],
        };
        valid.recognise().unwrap();

        let mut bad_symbol = valid;
        bad_symbol.symbols[7] = 4;
        assert!(bad_symbol.recognise().is_err());

        let mut bad_phase = valid;
        bad_phase.initial_phase = 12;
        assert!(bad_phase.recognise().is_err());
    }

    #[test]
    fn periodic_and_duplicate_window_sequences_are_rejected() {
        assert!(!valid_temporal_sequence(&[
            0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3
        ]));
        assert!(!valid_temporal_sequence(&[
            0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 2
        ]));
    }
}
