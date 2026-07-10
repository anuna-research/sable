"""Faithful Python port of SABLE's quantization + Hamming matching.

This mirrors `core/src/zk/halo2/quantizer.rs` and `hamming.rs` exactly so the
accuracy numbers reflect what the ZK circuit actually computes -- not an
approximation.

The one subtlety that matters: SABLE matches on *plain binary* Hamming distance
over the raw u8 bytes. Adjacent integer values can differ in many bits
(127 = 0b0111_1111 vs 128 = 0b1000_0000 differ in 8 bits), so the encoding
discards ordinal structure. This module also provides Gray-code and
thermometer (ordinal/L1) variants so the spike can tell *which* design choice
costs accuracy: the 8-bit quantization, or the binary-Hamming encoding.

All scoring functions return a *similarity score* where higher = more similar,
so downstream metrics code is uniform across conditions.
"""

from __future__ import annotations

import numpy as np

QUANT_MIN = -1.0
QUANT_MAX = 1.0


# ---------------------------------------------------------------------------
# Quantization  (mirrors FeatureQuantizer::quantize_single)
# ---------------------------------------------------------------------------

def quantize(emb: np.ndarray) -> np.ndarray:
    """f64 embeddings in [-1, 1] -> u8 bytes in [0, 255].

    Rust: ((v - MIN)/(MAX - MIN) * 255).clamp(0, 255) as u8
    `as u8` truncates toward zero; after clamping to [0, 255] that is floor().
    numpy `.astype(np.uint8)` on the clipped positive float truncates the same
    way, so this matches the Rust output bit-for-bit.
    """
    normalized = (emb - QUANT_MIN) / (QUANT_MAX - QUANT_MIN)
    scaled = normalized * 255.0
    return np.clip(scaled, 0.0, 255.0).astype(np.uint8)


def dequantize(q: np.ndarray) -> np.ndarray:
    """u8 -> f64 (inverse of quantize, with quantization error)."""
    return QUANT_MIN + (q.astype(np.float64) / 255.0) * (QUANT_MAX - QUANT_MIN)


# ---------------------------------------------------------------------------
# Pre-scaling into the [-1, 1] window the quantizer assumes.
#
# The quantizer assumes embeddings already live in [-1, 1]. Real backbones
# rarely do (L2-normalized vectors cluster near 0; others have wide tails).
# How you map into the window changes everything, so make it an explicit knob.
# ---------------------------------------------------------------------------

def prescale(emb: np.ndarray, mode: str, stats: dict | None = None) -> tuple[np.ndarray, dict]:
    """Map raw embeddings into [-1, 1] before quantization.

    Returns (scaled, stats). Pass the returned `stats` back in for the probe/
    gallery split so enrollment and verification use identical scaling (fitting
    scaling on the probe set would leak and inflate results).

    modes:
      none      : assume already in [-1, 1], just clip.
      tanh      : squash with tanh (smooth, handles tails, no fitted stats).
      minmax    : global min-max over all dims (mirrors quantizer.rs normalize()).
      zscore    : per-dim standardize then tanh-squash. Spreads an L2-normalized
                  cloud off the 127/128 boundary -- the most likely "fix" if the
                  raw distribution is the problem.
    """
    stats = stats or {}
    if mode == "none":
        return np.clip(emb, QUANT_MIN, QUANT_MAX), stats
    if mode == "tanh":
        return np.tanh(emb), stats
    if mode == "minmax":
        lo = stats.get("lo", float(emb.min()))
        hi = stats.get("hi", float(emb.max()))
        rng = (hi - lo) or 1.0
        scaled = 2.0 * (emb - lo) / rng - 1.0
        return np.clip(scaled, QUANT_MIN, QUANT_MAX), {"lo": lo, "hi": hi}
    if mode == "zscore":
        mu = stats.get("mu", emb.mean(axis=0))
        sd = stats.get("sd", emb.std(axis=0) + 1e-9)
        return np.tanh((emb - mu) / sd), {"mu": mu, "sd": sd}
    raise ValueError(f"unknown prescale mode: {mode!r}")


# ---------------------------------------------------------------------------
# Bit encodings (per byte -> bits), for the Hamming conditions
# ---------------------------------------------------------------------------

def _gray(q: np.ndarray) -> np.ndarray:
    """Binary-reflected Gray code: adjacent values differ in exactly 1 bit."""
    q = q.astype(np.uint8)
    return q ^ (q >> 1)


_POPCOUNT = np.array([bin(i).count("1") for i in range(256)], dtype=np.uint16)


def _hamming_bytes(a: np.ndarray, b: np.ndarray) -> np.ndarray:
    """Row-wise Hamming distance between two (N, D) uint8 arrays."""
    return _POPCOUNT[np.bitwise_xor(a, b)].sum(axis=1).astype(np.float64)


# ---------------------------------------------------------------------------
# Pairwise scoring conditions.  Each takes two (N, D) arrays of *pre-scaled*
# float embeddings and returns (N,) similarity scores (higher = more similar).
# ---------------------------------------------------------------------------

def score_float_cosine(a: np.ndarray, b: np.ndarray) -> np.ndarray:
    an = a / (np.linalg.norm(a, axis=1, keepdims=True) + 1e-12)
    bn = b / (np.linalg.norm(b, axis=1, keepdims=True) + 1e-12)
    return (an * bn).sum(axis=1)


def score_quant_cosine(a: np.ndarray, b: np.ndarray) -> np.ndarray:
    """Cosine on dequantized values -- isolates *rounding* error alone,
    with no binary-Hamming penalty. Gap vs float_cosine = cost of 8-bit
    rounding; gap vs hamming_binary = cost of the binary encoding."""
    return score_float_cosine(dequantize(quantize(a)).astype(np.float64),
                              dequantize(quantize(b)).astype(np.float64))


def score_hamming_binary(a: np.ndarray, b: np.ndarray) -> np.ndarray:
    """THE REAL SABLE PATH: plain binary Hamming over u8 bytes."""
    return -_hamming_bytes(quantize(a), quantize(b))


def score_hamming_gray(a: np.ndarray, b: np.ndarray) -> np.ndarray:
    """Gray-coded Hamming -- same 8 bits/dim, but adjacent levels cost 1 bit.
    A cheap circuit change (one XOR-shift). If this recovers accuracy, the
    binary encoding -- not quantization -- is the culprit."""
    return -_hamming_bytes(_gray(quantize(a)), _gray(quantize(b)))


def score_quant_l1(a: np.ndarray, b: np.ndarray) -> np.ndarray:
    """L1 on quantized levels == Hamming of a thermometer/unary encoding
    (exact ordinal distance). Shows the accuracy ceiling reachable in Hamming
    space, at the cost of many more bits per dim (more circuit constraints)."""
    qa = quantize(a).astype(np.int32)
    qb = quantize(b).astype(np.int32)
    return -np.abs(qa - qb).sum(axis=1).astype(np.float64)


# ---------------------------------------------------------------------------
# Thermometer (unary) encoding at L levels.
#
# Quantize each dim to one of L levels, then thermometer-encode: a value at
# level k -> k ones followed by (L-1-k) zeros, using L-1 bits/dim. The Hamming
# distance between two thermometer codes equals |level_a - level_b| EXACTLY, so
# we compute it as L1 over the level quantization (no need to expand the bits).
#
#   bits/dim = L - 1.   L=9  ->  8 bits/dim == SAME budget as binary u8 today.
#                       L=256 -> 255 bits/dim (the ordinal ceiling).
# ---------------------------------------------------------------------------

def thermo_levels(emb: np.ndarray, levels: int) -> np.ndarray:
    """Quantize prescaled [-1,1] embeddings to integer levels [0, L-1]
    (round to nearest level)."""
    u = (emb - QUANT_MIN) / (QUANT_MAX - QUANT_MIN)          # -> [0, 1]
    lvl = np.rint(np.clip(u, 0.0, 1.0) * (levels - 1))
    return lvl.astype(np.int32)


def score_thermo(a: np.ndarray, b: np.ndarray, levels: int) -> np.ndarray:
    """Thermometer-Hamming similarity at L levels (= -L1 over level codes)."""
    la = thermo_levels(a, levels)
    lb = thermo_levels(b, levels)
    return -np.abs(la - lb).sum(axis=1).astype(np.float64)


def thermo_bits_per_dim(levels: int) -> int:
    return levels - 1


CONDITIONS = {
    "float_cosine": score_float_cosine,
    "quant_cosine": score_quant_cosine,
    "hamming_binary": score_hamming_binary,   # <- what SABLE ships today
    "hamming_gray": score_hamming_gray,
    "quant_l1_thermo": score_quant_l1,
}
