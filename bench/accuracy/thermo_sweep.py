#!/usr/bin/env python3
"""Thermometer-encoding sweep: accuracy vs bit/constraint budget.

The week-1 spike showed SABLE's plain binary Hamming over u8 (8 bits/dim) costs
~2x EER vs float because it discards ordinal structure, while a full ordinal
encoding recovers most of it. This sweep answers the redesign question: **how
few thermometer levels are enough, and what do they cost?**

A thermometer/unary code at L levels uses L-1 bits/dim and its Hamming distance
equals the L1 distance over the L-level quantization (see sable_quant). So:

    L = 9    -> 8 bits/dim  == SAME budget as binary u8 today (the key compare)
    L = 256  -> 255 bits/dim (ordinal ceiling; ~32x the bits)

Circuit-cost note: bits/dim is the honest first-order proxy for constraint
count (XOR + popcount scale with total bits). Actual Halo2 lookup-table cost
needs circuit-level analysis -- this orders the options, it doesn't price them.

Reference rows: float_cosine (ceiling) and hamming_binary (what ships today).

Examples:
    python thermo_sweep.py --embeddings /tmp/lfw_human.npz --prescale zscore
    python thermo_sweep.py --synthetic --dim 1024 --out thermo.csv
"""

from __future__ import annotations

import argparse
import csv
from pathlib import Path

import numpy as np

import datasets
import metrics
import sable_quant as sq

DEFAULT_LEVELS = [2, 4, 8, 9, 16, 32, 64, 128, 256]
BINARY_BITS_PER_DIM = 8  # SABLE's current u8 binary Hamming


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--embeddings")
    src.add_argument("--synthetic", action="store_true")
    src.add_argument("--lfw-pairs")
    src.add_argument("--pairs-list")
    p.add_argument("--lfw-embeddings")
    p.add_argument("--named-embeddings")
    p.add_argument("--prescale", default="zscore",
                   choices=["none", "tanh", "minmax", "zscore"],
                   help="fixed prescale so the sweep isolates the level effect")
    p.add_argument("--levels", type=int, nargs="+", default=DEFAULT_LEVELS,
                   help="thermometer level counts to sweep")
    p.add_argument("--dim", type=int, default=1024)
    p.add_argument("--n-pairs", type=int, default=3000)
    p.add_argument("--genuine-corr", type=float, default=0.92)
    p.add_argument("--seed", type=int, default=0)
    p.add_argument("--out")
    args = p.parse_args(argv)

    emb_a, emb_b, match = datasets.resolve_pairs(
        embeddings=args.embeddings, lfw_pairs=args.lfw_pairs,
        lfw_embeddings=args.lfw_embeddings, pairs_list=args.pairs_list,
        named_embeddings=args.named_embeddings, use_synthetic=args.synthetic,
        dim=args.dim, n_pairs=args.n_pairs, genuine_corr=args.genuine_corr,
        seed=args.seed)
    dim = emb_a.shape[1]
    far_points = (1e-2, 1e-3)

    a, stats = sq.prescale(emb_a, args.prescale)
    b, _ = sq.prescale(emb_b, args.prescale, stats)

    print(f"\nPairs: {len(match)} ({int(match.sum())} gen / "
          f"{int((1-match).sum())} imp)  dim={dim}  prescale={args.prescale}")

    # --- reference points ---------------------------------------------------
    r_float = metrics.evaluate("float_cosine", sq.score_float_cosine(a, b),
                               match, far_points=far_points)
    r_bin = metrics.evaluate("hamming_binary", sq.score_hamming_binary(a, b),
                             match, far_points=far_points, dim=dim, is_hamming=True)
    eer_float, eer_bin = r_float.eer, r_bin.eer
    gap = max(eer_bin - eer_float, 1e-9)  # the loss thermo must recover

    # --- thermometer sweep --------------------------------------------------
    rows = []
    for L in sorted(set(args.levels)):
        r = metrics.evaluate(f"thermo_L{L}", sq.score_thermo(a, b, L),
                             match, far_points=far_points)
        bpd = sq.thermo_bits_per_dim(L)
        recovery = (eer_bin - r.eer) / gap  # 1.0 = matches float; 0 = no better than binary
        rows.append({
            "encoding": f"thermo L={L}",
            "levels": L,
            "bits_per_dim": bpd,
            "total_bits": dim * bpd,
            "rel_bits_vs_binary": bpd / BINARY_BITS_PER_DIM,
            "eer": r.eer,
            "tar_far_1e-2": r.tar_at_far[1e-2],
            "tar_far_1e-3": r.tar_at_far[1e-3],
            "recovery_vs_binary": recovery,
        })

    # --- print --------------------------------------------------------------
    print(f"\nfloat_cosine   EER {eer_float*100:6.2f}%   (ceiling)")
    print(f"hamming_binary EER {eer_bin*100:6.2f}%   "
          f"(8 bits/dim -- what SABLE ships)  TAR@1e-3={r_bin.tar_at_far[1e-3]*100:.1f}%")
    print(f"\n{'encoding':<12}{'bits/dim':>9}{'xbits':>7}{'EER':>9}"
          f"{'TAR@1e-2':>10}{'TAR@1e-3':>10}{'recovery':>10}")
    print("-" * 67)
    for row in rows:
        mark = "  <- = binary budget" if row["bits_per_dim"] == BINARY_BITS_PER_DIM else ""
        print(f"{row['encoding']:<12}{row['bits_per_dim']:>9}"
              f"{row['rel_bits_vs_binary']:>6.2f}x{row['eer']*100:>8.2f}%"
              f"{row['tar_far_1e-2']*100:>9.1f}%{row['tar_far_1e-3']*100:>9.1f}%"
              f"{row['recovery_vs_binary']*100:>9.0f}%{mark}")

    # cheapest encoding recovering >=90% of the binary->float gap
    good = [r for r in rows if r["recovery_vs_binary"] >= 0.90]
    if good:
        best = min(good, key=lambda r: r["bits_per_dim"])
        print(f"\n>> cheapest >=90%-recovery: {best['encoding']} "
              f"({best['bits_per_dim']} bits/dim, "
              f"{best['rel_bits_vs_binary']:.2f}x binary, EER {best['eer']*100:.2f}%)")
    else:
        print("\n>> no swept level recovered >=90% of the gap "
              "(try more levels or a different prescale)")

    if args.out:
        out = Path(args.out)
        with out.open("w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
            w.writeheader(); w.writerows(rows)
        print(f"\nwrote {out}")


if __name__ == "__main__":
    main()
