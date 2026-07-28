#!/usr/bin/env python3
"""EXP-001: rolling-shutter symbol channel feasibility sweep.

Forward-simulates a phone display emitting a symbol sequence, a CMOS rolling
shutter sampling it row by row, and a noisy sensor, then attempts to decode the
sequence from row means.

Model, stated so it can be argued with:

  Row r integrates emitted light over [t0 + r*T_ro/H, t0 + r*T_ro/H + T_exp].
  Signal is converted to photoelectrons via an anchor: a grey card (rho=0.18) at
  100 lux with a 33 ms exposure lands at 2500 e- (roughly half full-well for a
  1.4 um pixel). Shot noise is Poisson, read noise Gaussian.

The anchor is an ESTIMATE, not a measurement. Absolute electron counts may be off
by a factor of a few; the *relative* conclusions across the sweep are far more
robust than the absolute SNR figures.

Deterministic under --seed. No I/O beyond stdout.
"""
import argparse
import itertools
import math
import random

# Alphabet: four maximally separated display colours, normalised to unit scale.
ALPHABET = {
    "R": (1.0, 0.0, 0.0),
    "G": (0.0, 1.0, 0.0),
    "B": (0.0, 0.0, 1.0),
    "W": (1.0, 1.0, 1.0),
}
SYMBOLS = list(ALPHABET)

# Sensor anchor: grey card, 100 lux, 33 ms -> 2500 e-.
ANCHOR_E = 2500.0 / (100.0 * 0.18 * 0.033)  # e- per (lux * reflectance * second)
READ_NOISE_E = 3.0
SKIN_REFLECTANCE = 0.35


def emitted(t, seq, frame_period):
    """Display output at time t: one alphabet colour per display frame."""
    idx = int(t / frame_period)
    if idx < 0 or idx >= len(seq):
        return (0.0, 0.0, 0.0)
    return ALPHABET[seq[idx]]


def integrate_row(t_start, t_exp, seq, frame_period, steps=64):
    """Mean emitted colour over one row's exposure window."""
    acc = [0.0, 0.0, 0.0]
    dt = t_exp / steps
    for i in range(steps):
        c = emitted(t_start + (i + 0.5) * dt, seq, frame_period)
        for k in range(3):
            acc[k] += c[k]
    return [a / steps for a in acc]


def simulate_frame(seq, refresh_hz, t_ro_ms, t_exp_ms, rows, face_px,
                   illuminance_lux, phase, rng):
    """Return (decoded_symbols_per_row, truth_symbols_per_row)."""
    frame_period = 1.0 / refresh_hz
    t_ro = t_ro_ms / 1000.0
    t_exp = t_exp_ms / 1000.0

    decoded, truth = [], []
    for r in range(rows):
        t_row = phase + r * t_ro / rows
        mean_colour = integrate_row(t_row, t_exp, seq, frame_period)

        # Photoelectrons per pixel, per channel, then averaged across the face.
        signal = []
        for ch in mean_colour:
            e = ANCHOR_E * illuminance_lux * SKIN_REFLECTANCE * t_exp * ch
            # Row mean over face_px pixels: shot noise averages down by sqrt(n).
            shot_sigma = math.sqrt(max(e, 1e-9)) / math.sqrt(face_px)
            read_sigma = READ_NOISE_E / math.sqrt(face_px)
            signal.append(e + rng.gauss(0.0, math.hypot(shot_sigma, read_sigma)))

        # Decode: nearest alphabet colour after normalising out overall gain.
        total = sum(signal)
        if total <= 0:
            decoded.append(None)
        else:
            norm = [s / total for s in signal]
            best, best_d = None, float("inf")
            for sym, col in ALPHABET.items():
                ct = sum(col)
                cn = [c / ct for c in col]
                d = sum((a - b) ** 2 for a, b in zip(norm, cn))
                if d < best_d:
                    best, best_d = sym, d
            decoded.append(best)

        # Ground truth: the symbol at the centre of this row's exposure.
        idx = int((t_row + t_exp / 2) / frame_period)
        truth.append(seq[idx] if 0 <= idx < len(seq) else None)

    return decoded, truth


def segment(labels):
    """Collapse a per-row label list into its run-length symbol sequence.

    Rows straddling a symbol boundary are inherently ambiguous, so per-row
    accuracy is the wrong metric: what the channel carries is the *sequence*.
    Runs shorter than MIN_RUN are treated as boundary artefacts and dropped.
    """
    MIN_RUN = 3
    runs = []
    for lab in labels:
        if lab is None:
            continue
        if runs and runs[-1][0] == lab:
            runs[-1][1] += 1
        else:
            runs.append([lab, 1])

    kept = [lab for lab, n in runs if n >= MIN_RUN]

    # Re-merge after filtering. A single glitched row inside a run splits it in
    # two; dropping the glitch without merging would report the run twice.
    merged = []
    for lab in kept:
        if not merged or merged[-1] != lab:
            merged.append(lab)
    return merged


def run_length_limited(n, rng):
    """Symbol sequence in which adjacent symbols always differ.

    A uniformly random sequence lets adjacent symbols repeat, which merges two
    display frames into one indistinguishable band and destroys the timing
    information the channel exists to carry. Any real challenge encoder must
    forbid it, so the simulation models the encoder that would actually ship.
    """
    seq = [rng.choice(SYMBOLS)]
    while len(seq) < n:
        seq.append(rng.choice([s for s in SYMBOLS if s != seq[-1]]))
    return seq


def run_config(refresh_hz, t_ro_ms, t_exp_ms, face_px, illuminance_lux,
               trials, rows, rng):
    """Sequence-recovery rate over trials, plus symbols visible per frame."""
    frame_period_ms = 1000.0 / refresh_hz
    symbols_visible = t_ro_ms / frame_period_ms

    recovered = usable = 0
    for _ in range(trials):
        n_sym = int(t_ro_ms / frame_period_ms) + 3
        seq = run_length_limited(n_sym, rng)
        phase = rng.uniform(0, frame_period_ms / 1000.0)
        dec, tru = simulate_frame(seq, refresh_hz, t_ro_ms, t_exp_ms, rows,
                                  face_px, illuminance_lux, phase, rng)
        # Drop the first and last band: they are partial, clipped by the frame
        # edge, so their extent is not determined by the display timing.
        st, sd = segment(tru)[1:-1], segment(dec)[1:-1]
        if len(st) < 1:
            continue          # frame too short to carry an interior band
        usable += 1
        if st == sd:
            recovered += 1
    return (recovered / usable if usable else 0.0), symbols_visible


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--trials", type=int, default=200)
    ap.add_argument("--rows", type=int, default=64, help="sampled sensor rows")
    ap.add_argument("--seed", type=int, default=20260728)
    args = ap.parse_args()
    rng = random.Random(args.seed)

    refreshes = [60, 120]
    t_ros = [10, 20, 33]
    t_exps = [0.5, 1, 2, 4, 8, 16]
    face_pxs = [300, 600]
    illums = [20, 40, 80]

    print(f"EXP-001 rolling-shutter sweep  (trials={args.trials}, seed={args.seed})")
    print("recoverable = sequence recovered in >= 99% of frames AND >= 2 symbols visible\n")
    print(f"{'refresh':>8} {'T_ro':>5} {'T_exp':>6} {'face_px':>8} {'lux':>4} "
          f"{'sym/frm':>8} {'seq-rec':>9}  verdict")

    recoverable = []
    for refresh, t_ro, t_exp, face_px, lux in itertools.product(
            refreshes, t_ros, t_exps, face_pxs, illums):
        acc, sym = run_config(refresh, t_ro, t_exp, face_px, lux,
                              args.trials, args.rows, rng)
        ok = acc >= 0.99 and sym >= 2.0
        if ok:
            recoverable.append((refresh, t_ro, t_exp, face_px, lux, acc, sym))
        # Print a readable subset: all rows at the larger face, else only passes.
        if face_px == 600 or ok:
            print(f"{refresh:>8} {t_ro:>5} {t_exp:>6} {face_px:>8} {lux:>4} "
                  f"{sym:>8.2f} {acc*100:>8.2f}%  {'RECOVERABLE' if ok else ''}")

    print(f"\nrecoverable configurations: {len(recoverable)}")
    if recoverable:
        by_exp = {}
        for r in recoverable:
            by_exp.setdefault(r[2], []).append(r)
        print("longest exposure that still works, per refresh/T_ro:")
        seen = {}
        for refresh, t_ro, t_exp, face_px, lux, acc, sym in recoverable:
            key = (refresh, t_ro)
            if key not in seen or t_exp > seen[key][0]:
                seen[key] = (t_exp, lux, face_px)
        for (refresh, t_ro), (t_exp, lux, face_px) in sorted(seen.items()):
            print(f"  {refresh} Hz, T_ro {t_ro} ms -> T_exp up to {t_exp} ms "
                  f"(at {lux} lux, {face_px} px wide)")


if __name__ == "__main__":
    main()
