#!/usr/bin/env python3
"""Convert the Node extractor's output (<base>.bin + <base>.json) into an npz
that benchmark.py consumes.

Two output formats:

  default (identity-labelled):
      keys: embeddings (N,1024) float32, labels (N,) str, names (N,) str
      -> python benchmark.py --embeddings out.npz        # harness samples pairs

  --name-keyed (for the canonical LFW pairs.txt protocol):
      one array per image name (e.g. "Aaron_Peirsol_0001" -> (1024,))
      -> python benchmark.py --lfw-pairs pairs.txt --lfw-embeddings out.npz

Usage:
    python human_to_npz.py <base> <out.npz> [--name-keyed]
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np


def load_raw(base: str) -> tuple[np.ndarray, list[str], list[str]]:
    base = base[:-4] if base.endswith(".bin") else base
    meta = json.loads(Path(f"{base}.json").read_text())
    dim, n = meta["dim"], meta["n"]
    flat = np.fromfile(f"{base}.bin", dtype="<f4")
    if flat.size != n * dim:
        raise ValueError(
            f"{base}.bin has {flat.size} floats, expected {n}*{dim}={n*dim}")
    emb = flat.reshape(n, dim).astype(np.float32)
    return emb, meta["labels"], meta["names"]


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("base", help="extractor output base name (without .bin/.json)")
    p.add_argument("out", help="output .npz")
    p.add_argument("--name-keyed", action="store_true",
                   help="emit one array per image name (for LFW pairs.txt)")
    args = p.parse_args()

    emb, labels, names = load_raw(args.base)
    print(f"loaded {emb.shape[0]} embeddings, dim={emb.shape[1]}, "
          f"{len(set(labels))} identities")

    if args.name_keyed:
        if len(set(names)) != len(names):
            print("warning: duplicate name keys; last occurrence wins")
        np.savez(args.out, **{name: emb[i] for i, name in enumerate(names)})
    else:
        np.savez(args.out,
                 embeddings=emb,
                 labels=np.array(labels),
                 names=np.array(names))
    print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
