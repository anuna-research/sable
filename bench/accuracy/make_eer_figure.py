#!/usr/bin/env python3
"""Regenerate the EER comparison bar chart (papers/figs/encoding_eer.pdf) from
the saved results/summary.csv, without needing the raw embeddings.

This mirrors plot_eer_bars() in make_paper_artifacts.py, but sources the EERs
from the committed summary instead of recomputing from /tmp embeddings (which
are not retained). Use make_paper_artifacts.py when the embeddings are present
and you want table + figures recomputed together.

Run from bench/accuracy with system python3 (numpy + matplotlib):
    python3 make_eer_figure.py [--summary results/summary.csv] [--out ../../docs/papers]
"""

from __future__ import annotations

import argparse
import csv
from pathlib import Path

import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

# Same ordering/labels as make_paper_artifacts.py so the figure matches the table.
CELLS = [("lfw", "LFW"), ("calfw", "CALFW"), ("cplfw", "CPLFW")]
BACKBONES = [("faceres", "FaceRes"), ("arcface", "ArcFace")]
# (summary.csv column, legend label)
ENCODINGS = [
    ("float_cosine", "float cosine"),
    ("hamming_binary", "binary Hamming"),
    ("thermo_L9", "thermometer L9"),
]


def load_grid(summary: Path):
    grid = {}
    with summary.open() as f:
        for row in csv.DictReader(f):
            grid[(row["dataset"], row["backbone"])] = {
                key: float(row[key]) for key, _ in ENCODINGS
            }
    return grid


def plot_eer_bars(grid, figs: Path):
    figs.mkdir(parents=True, exist_ok=True)
    cells = [(ds, bb) for ds, _ in CELLS for bb, _ in BACKBONES if (ds, bb) in grid]
    labels = [f"{d.upper()}\n{b}" for d, b in cells]
    x = np.arange(len(cells))
    w = 0.26
    fig, ax = plt.subplots(figsize=(8, 3.4))
    for i, (key, lab) in enumerate(ENCODINGS):
        vals = [grid[c][key] * 100 for c in cells]
        ax.bar(x + (i - 1) * w, vals, w, label=lab)
    ax.set_ylabel("EER (%)")
    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=8)
    ax.legend(fontsize=8, ncol=3, loc="upper left")
    ax.grid(axis="y", alpha=0.3)
    ax.set_title("Matcher encoding effect on verification EER")
    fig.tight_layout()
    for ext in ("pdf", "png"):
        fig.savefig(figs / f"encoding_eer.{ext}", dpi=150)
    plt.close(fig)
    print(f"wrote {figs / 'encoding_eer.pdf'}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--summary", default="results/summary.csv")
    ap.add_argument("--out", default="../../docs/papers")
    args = ap.parse_args()
    grid = load_grid(Path(args.summary))
    if not grid:
        raise SystemExit("no rows in summary")
    plot_eer_bars(grid, Path(args.out).resolve() / "figs")
    print("done.")


if __name__ == "__main__":
    main()
