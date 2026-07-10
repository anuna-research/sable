#!/usr/bin/env python3
"""Week-1 go/no-go accuracy spike for SABLE's quantize + Hamming matcher.

Runs the same verification pairs through five scoring conditions and reports
EER / AUC / TAR@FAR for each, so you can read off:

  * float_cosine      -- backbone's ceiling (what the embedding can do)
  * quant_cosine      -- cost of 8-bit rounding ALONE
  * hamming_binary    -- what SABLE ships TODAY (binary Hamming over u8)
  * hamming_gray      -- cheap encoding fix (one XOR-shift in-circuit)
  * quant_l1_thermo   -- ordinal/thermometer ceiling in Hamming space

Decision rule for the spike:
  - hamming_binary EER close to float_cosine  -> approach is sound, proceed.
  - hamming_binary collapses but gray/thermo recover -> redesign the encoding
    (Gray code is nearly free; thermometer costs constraints), then proceed.
  - nothing in Hamming space recovers          -> rethink matching (learned
    binary hashing) before targeting S&P.

Examples:
  # validate the harness end-to-end with no model (sanity check only):
  python benchmark.py --synthetic --dim 1024

  # real run with embeddings exported from the deployed Human library:
  python benchmark.py --embeddings lfw_human_embeddings.npz --prescale zscore

  # standard LFW protocol from a name->embedding npz + pairs.txt:
  python benchmark.py --lfw-pairs pairs.txt --lfw-embeddings names.npz
"""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

import numpy as np

import datasets
import metrics
import sable_quant as sq

# Only true bit-Hamming conditions get the "% similar over dim*8 bits" readout;
# quant_l1_thermo is L1 over levels, so that framing doesn't apply to it.
BIT_HAMMING_CONDITIONS = {"hamming_binary", "hamming_gray"}


def run(emb_a, emb_b, match, prescale_mode, far_points):
    dim = emb_a.shape[1]
    print(f"\nPairs: {len(match)}  ({int(match.sum())} genuine, "
          f"{int((1-match).sum())} impostor)   dim={dim}   "
          f"prescale={prescale_mode}")

    # Fit prescale stats on the GALLERY side only (emb_a), apply to both, so we
    # never leak probe-side statistics into the operating point.
    a_scaled, stats = sq.prescale(emb_a, prescale_mode)
    b_scaled, _ = sq.prescale(emb_b, prescale_mode, stats)

    # Quick distribution sanity line: where do quantized values land? If this
    # clusters at 127-128, binary Hamming is expected to suffer.
    q = sq.quantize(a_scaled)
    print(f"quantized byte distribution: min={q.min()} "
          f"p50={int(np.median(q))} max={q.max()} "
          f"frac@127-128={(np.isin(q,[127,128]).mean())*100:.1f}%")

    results = []
    for name, fn in sq.CONDITIONS.items():
        scores = fn(a_scaled, b_scaled)
        results.append(metrics.evaluate(
            name, scores, match, far_points=far_points,
            dim=dim, is_hamming=(name in BIT_HAMMING_CONDITIONS)))
    return results


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--embeddings", help="npz: (emb_a,emb_b,match) or (embeddings,labels)")
    src.add_argument("--synthetic", action="store_true", help="generate synthetic pairs")
    src.add_argument("--lfw-pairs", help="LFW pairs.txt (needs --lfw-embeddings)")
    src.add_argument("--pairs-list", help="generic 'keyA keyB match' manifest (needs --named-embeddings)")

    p.add_argument("--lfw-embeddings", help="npz mapping Name_0001 -> vector (object array or dict)")
    p.add_argument("--named-embeddings", help="npz mapping key -> vector (for --pairs-list)")
    p.add_argument("--prescale", default="none",
                   choices=["none", "tanh", "minmax", "zscore"],
                   help="map embeddings into [-1,1] before quantizing")
    p.add_argument("--dim", type=int, default=1024, help="synthetic embedding dim")
    p.add_argument("--n-pairs", type=int, default=3000, help="synthetic pair count")
    p.add_argument("--no-l2norm", action="store_true",
                   help="synthetic: do NOT L2-normalize (off the boundary)")
    p.add_argument("--genuine-corr", type=float, default=0.92,
                   help="synthetic: genuine-pair correlation (lower = harder)")
    p.add_argument("--seed", type=int, default=0)
    p.add_argument("--out", help="write results CSV here")
    p.add_argument("--sweep-prescale", action="store_true",
                   help="run every prescale mode (find the best window)")
    args = p.parse_args(argv)

    if args.synthetic:
        emb_a, emb_b, match = datasets.synthetic(
            dim=args.dim, n_pairs=args.n_pairs, seed=args.seed,
            genuine_corr=args.genuine_corr, l2_normalize=not args.no_l2norm)
        print(f"[synthetic] dim={args.dim} l2norm={not args.no_l2norm} "
              f"-- harness validation only, NOT real accuracy")
    elif args.lfw_pairs:
        if not args.lfw_embeddings:
            p.error("--lfw-pairs requires --lfw-embeddings")
        raw = np.load(args.lfw_embeddings, allow_pickle=True)
        emb_by_name = {k: np.asarray(raw[k], np.float64) for k in raw.files}
        emb_a, emb_b, match = datasets.load_lfw_pairs(args.lfw_pairs, emb_by_name)
    elif args.pairs_list:
        if not args.named_embeddings:
            p.error("--pairs-list requires --named-embeddings")
        emb_a, emb_b, match = datasets.load_pairs_list(args.pairs_list, args.named_embeddings)
    else:
        emb_a, emb_b, match = datasets.load_pairs(args.embeddings)

    if len(match) == 0:
        sys.exit("no pairs loaded")

    far_points = (1e-1, 1e-2, 1e-3)
    modes = (["none", "tanh", "minmax", "zscore"]
             if args.sweep_prescale else [args.prescale])

    all_rows = []
    for mode in modes:
        results = run(emb_a, emb_b, match, mode, far_points)
        print("\n" + metrics.format_table(results, far_points))
        for row in metrics.to_csv_rows(results, far_points):
            row["prescale"] = mode
            all_rows.append(row)

    # Decision hint
    by_name = {r["condition"]: r for r in all_rows}
    if "float_cosine" in by_name and "hamming_binary" in by_name:
        base = by_name["float_cosine"]["eer"]
        ham = by_name["hamming_binary"]["eer"]
        print(f"\n>> float_cosine EER {base*100:.2f}%  vs  "
              f"hamming_binary EER {ham*100:.2f}%   "
              f"(degradation {((ham-base)*100):+.2f} pts)")

    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(all_rows[0].keys()))
            w.writeheader()
            w.writerows(all_rows)
        print(f"\nwrote {out}")


if __name__ == "__main__":
    main()
