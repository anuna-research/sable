#!/usr/bin/env python3
"""Information-theoretic analysis of the EXP-001 rolling-shutter channel.

The physical model is the one stated in ``rolling_shutter_sim.py``.  This
program evaluates only the SABLE target configurations (120 Hz display,
20/33 ms sensor readout, and <= 2 ms exposure), using exact integration of the
piecewise-constant display waveform and batched NumPy simulation.

The random variable X is the sequence of complete interior bands visible in a
frame after the same first/last partial-band removal used by EXP-001.  Y is the
corresponding decoded sequence.  Mutual information is therefore measured per
captured frame, including insertion/deletion outcomes, rather than inferred
from the exact-recovery percentage.
"""

from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import dataclass
import itertools
import math

import numpy as np


ALPHABET = np.asarray(
    [
        [1.0, 0.0, 0.0],  # R
        [0.0, 1.0, 0.0],  # G
        [0.0, 0.0, 1.0],  # B
        [1.0, 1.0, 1.0],  # W
    ]
)
PROTOTYPES = ALPHABET / ALPHABET.sum(axis=1, keepdims=True)
SYMBOL_NAMES = "RGBW"

ANCHOR_E = 2500.0 / (100.0 * 0.18 * 0.033)
READ_NOISE_E = 3.0
SKIN_REFLECTANCE = 0.35
MIN_RUN = 3


@dataclass(frozen=True)
class Config:
    readout_ms: float
    exposure_ms: float


def rll_sequences(rng: np.random.Generator, count: int, length: int) -> np.ndarray:
    """Uniform samples from the four-symbol, no-adjacent-repeat codebook."""
    seq = np.empty((count, length), dtype=np.int8)
    seq[:, 0] = rng.integers(0, 4, size=count)
    for i in range(1, length):
        # Select uniformly from {0,1,2,3} excluding the previous symbol.
        draw = rng.integers(0, 3, size=count)
        seq[:, i] = draw + (draw >= seq[:, i - 1])
    return seq


def segment(labels: np.ndarray) -> tuple[int, ...]:
    """EXP-001 run filtering and re-merging, with -1 representing no label."""
    runs: list[list[int]] = []
    for raw in labels:
        label = int(raw)
        if label < 0:
            continue
        if runs and runs[-1][0] == label:
            runs[-1][1] += 1
        else:
            runs.append([label, 1])
    kept = [label for label, count in runs if count >= MIN_RUN]
    merged: list[int] = []
    for label in kept:
        if not merged or merged[-1] != label:
            merged.append(label)
    return tuple(merged)


def entropy(counts: Counter[tuple[int, ...]]) -> float:
    total = sum(counts.values())
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


def mutual_information(
    joint: Counter[tuple[tuple[int, ...], tuple[int, ...]]],
    xs: Counter[tuple[int, ...]],
    ys: Counter[tuple[int, ...]],
) -> float:
    total = sum(joint.values())
    value = 0.0
    for (x, y), nxy in joint.items():
        pxy = nxy / total
        value += pxy * math.log2((nxy * total) / (xs[x] * ys[y]))
    return value


def fixed_replay_success(xs: Counter[tuple[int, ...]], tolerance: int) -> float:
    """Best fixed pre-challenge response under same-length Hamming tolerance."""
    total = sum(xs.values())
    best = 0
    for guess in xs:
        accepted = sum(
            count
            for actual, count in xs.items()
            if len(actual) == len(guess)
            and sum(a != b for a, b in zip(actual, guess)) <= tolerance
        )
        best = max(best, accepted)
    return best / total


def wilson(successes: int, total: int, z: float = 1.959963984540054) -> tuple[float, float]:
    p = successes / total
    denom = 1.0 + z * z / total
    centre = (p + z * z / (2 * total)) / denom
    radius = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denom
    return centre - radius, centre + radius


def simulate(config: Config, trials: int, rows: int, seed: int, batch_size: int) -> dict[str, float]:
    refresh_hz = 120.0
    period = 1.0 / refresh_hz
    readout = config.readout_ms / 1000.0
    exposure = config.exposure_ms / 1000.0
    if exposure > period:
        raise ValueError("exact fast path assumes exposure <= one display period")

    rng = np.random.default_rng(seed)
    xs: Counter[tuple[int, ...]] = Counter()
    ys: Counter[tuple[int, ...]] = Counter()
    joint: Counter[tuple[tuple[int, ...], tuple[int, ...]]] = Counter()
    exact = usable = complete_symbols = 0

    seq_len = math.ceil((period + readout + exposure) / period) + 1
    row_offsets = np.arange(rows, dtype=np.float64) * readout / rows
    electron_scale = ANCHOR_E * 40.0 * SKIN_REFLECTANCE * exposure

    remaining = trials
    while remaining:
        size = min(batch_size, remaining)
        remaining -= size
        seq = rll_sequences(rng, size, seq_len)
        phase = rng.uniform(0.0, period, size=size)
        starts = phase[:, None] + row_offsets[None, :]
        ends = starts + exposure

        first_index = np.floor(starts / period).astype(np.int64)
        boundary = (first_index + 1) * period
        first_weight = np.clip((np.minimum(ends, boundary) - starts) / exposure, 0.0, 1.0)
        second_weight = 1.0 - first_weight
        row_numbers = np.arange(size)[:, None]
        first_symbol = seq[row_numbers, first_index]
        second_symbol = seq[row_numbers, first_index + 1]
        mean_colour = (
            ALPHABET[first_symbol] * first_weight[:, :, None]
            + ALPHABET[second_symbol] * second_weight[:, :, None]
        )

        electrons = electron_scale * mean_colour
        shot_sigma = np.sqrt(np.maximum(electrons, 1e-9)) / math.sqrt(600.0)
        read_sigma = READ_NOISE_E / math.sqrt(600.0)
        signal = electrons + rng.normal(size=electrons.shape) * np.hypot(shot_sigma, read_sigma)
        totals = signal.sum(axis=2)
        normalised = np.divide(
            signal,
            totals[:, :, None],
            out=np.zeros_like(signal),
            where=totals[:, :, None] > 0,
        )
        distances = ((normalised[:, :, None, :] - PROTOTYPES[None, None, :, :]) ** 2).sum(axis=3)
        decoded = distances.argmin(axis=2).astype(np.int8)
        decoded[totals <= 0] = -1

        centre_index = np.floor((starts + exposure / 2.0) / period).astype(np.int64)
        truth = seq[row_numbers, centre_index]

        for i in range(size):
            x = segment(truth[i])[1:-1]
            if not x:
                continue
            y = segment(decoded[i])[1:-1]
            usable += 1
            complete_symbols += len(x)
            exact += x == y
            xs[x] += 1
            ys[y] += 1
            joint[(x, y)] += 1

    lo, hi = wilson(exact, usable)
    h_x = entropy(xs)
    mi = mutual_information(joint, xs, ys)
    p0 = fixed_replay_success(xs, 0)
    p1 = fixed_replay_success(xs, 1)
    return {
        "usable": usable,
        "exact": exact / usable,
        "exact_lo": lo,
        "exact_hi": hi,
        "mean_symbols": complete_symbols / usable,
        "h_x": h_x,
        "h_inf": -math.log2(p0),
        "mi": mi,
        "conditional": h_x - mi,
        "replay_p0": p0,
        "replay_p1": p1,
        "replay_bits1": -math.log2(p1),
        "x_support": len(xs),
        "y_support": len(ys),
    }


def qary_ball(n: int, tolerance: int, q: int = 4) -> int:
    return sum(math.comb(n, i) * (q - 1) ** i for i in range(tolerance + 1))


def window_occurrence_probability(
    challenge_length: int,
    guessed_window: tuple[int, ...],
    tolerance: int,
) -> float:
    """Probability a fixed replay matches some freely aligned challenge window.

    Dynamic programming follows the uniform four-state RLL Markov source.  This
    models a verifier that permits the prover to choose capture phase after the
    challenge: the fixed replay succeeds if it is close to *any* contiguous
    window, not merely the window at one verifier-fixed position.
    """
    width = len(guessed_window)
    states: dict[tuple[tuple[int, ...], bool], float] = {((), False): 1.0}
    for _ in range(challenge_length):
        following: dict[tuple[tuple[int, ...], bool], float] = {}
        for (recent, matched), probability in states.items():
            choices = [symbol for symbol in range(4) if not recent or symbol != recent[-1]]
            for symbol in choices:
                full = recent + (symbol,)
                window_matches = len(full) >= width and sum(
                    actual != expected
                    for actual, expected in zip(full[-width:], guessed_window)
                ) <= tolerance
                keep = full[-(width - 1):] if width > 1 else ()
                key = (keep, matched or window_matches)
                following[key] = following.get(key, 0.0) + probability / len(choices)
        states = following
    return sum(probability for (_, matched), probability in states.items() if matched)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--trials", type=int, default=100_000)
    parser.add_argument("--rows", type=int, default=64)
    parser.add_argument("--seed", type=int, default=20260915)
    parser.add_argument("--batch-size", type=int, default=2_000)
    args = parser.parse_args()

    configs = [
        Config(20.0, 0.5),
        Config(20.0, 1.0),
        Config(20.0, 2.0),
        Config(33.0, 0.5),
        Config(33.0, 1.0),
        Config(33.0, 2.0),
    ]
    print(f"trials/config={args.trials}, rows={args.rows}, seed={args.seed}, 120 Hz, 600 px, 40 lux")
    print("| T_ro | T_exp | complete symbols | exact recovery (95% CI) | H(X) | I(X;Y) | H_inf(X) | fixed replay t=1 |")
    print("|---:|---:|---:|---:|---:|---:|---:|---:|")
    for index, config in enumerate(configs):
        result = simulate(config, args.trials, args.rows, args.seed + index, args.batch_size)
        print(
            f"| {config.readout_ms:.0f} ms | {config.exposure_ms:.1f} ms "
            f"| {result['mean_symbols']:.3f} "
            f"| {100*result['exact']:.2f}% [{100*result['exact_lo']:.2f}, {100*result['exact_hi']:.2f}] "
            f"| {result['h_x']:.3f} bits | {result['mi']:.3f} bits "
            f"| {result['h_inf']:.3f} bits "
            f"| {100*result['replay_p1']:.2f}% ({result['replay_bits1']:.3f} bits) |"
        )

    print("\nConservative precomputed-forgery bounds for a fixed n-symbol RLL codeword")
    print("| symbols n | codebook bits | t=0 | t=1 | t=2 |")
    print("|---:|---:|---:|---:|---:|")
    for n in (6, 9, 12):
        codebook = 4 * 3 ** (n - 1)
        bits = math.log2(codebook)
        security = [max(0.0, math.log2(codebook / qary_ball(n, t))) for t in range(3)]
        print(
            f"| {n} | {bits:.3f} "
            f"| {security[0]:.3f} bits | {security[1]:.3f} bits | {security[2]:.3f} bits |"
        )

    print("\nBest fixed replay when prover may choose any challenge-window alignment")
    print("| challenge symbols | replay-window symbols | exact success | one-error success |")
    print("|---:|---:|---:|---:|")
    for n in (6, 9, 12):
        for width in (1, 2, 3, 4):
            # The attacker need not obey the challenge encoder, so maximize
            # over every four-ary replay string, including adjacent repeats.
            candidates = list(itertools.product(range(4), repeat=width))
            exact = max(window_occurrence_probability(n, word, 0) for word in candidates)
            one_error = max(window_occurrence_probability(n, word, 1) for word in candidates)
            print(
                f"| {n} | {width} | {100*exact:.2f}% ({-math.log2(exact):.3f} bits) "
                f"| {100*one_error:.2f}% ({-math.log2(one_error):.3f} bits) |"
            )


if __name__ == "__main__":
    main()
