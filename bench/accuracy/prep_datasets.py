#!/usr/bin/env python3
"""Materialize LFW / CALFW / CPLFW into a uniform layout for the paper batch:

    <out>/<dataset>/images/<key>.jpg     one image per key (filename stem)
    <out>/<dataset>/pairs.txt            rows "keyA keyB match"  (1=same, 0=diff)

Each dataset's protocol + images live in different HF repos (the hard sets ship
pair *filenames* separately from the aligned images), so this script knows the
per-repo schema and joins them by filename key.

Run with the parquet venv:  /tmp/lfwenv/bin/python prep_datasets.py <dataset> <out> [--limit N]

Sources:
  lfw   : logasja/lfw (default: image+label, 13233) -> sampled 6000 pairs
  calfw : images marcelohaps/calfw (image+source_filename) + pairs hero-nq1310/calfw-labels
  cplfw : images LSIbabnikz/cplfw (jpg+__key__)       + pairs hero-nq1310/cplfw-labels
"""

from __future__ import annotations

import argparse
import io
import json
import os
import ssl
import sys
import urllib.request
from collections import defaultdict
from pathlib import Path

import pyarrow.parquet as pq
from PIL import Image

HF = "https://huggingface.co"

# venv python often lacks system CA certs; prefer certifi, fall back to unverified.
try:
    import certifi
    _CTX = ssl.create_default_context(cafile=certifi.where())
except Exception:
    _CTX = ssl._create_unverified_context()


def _open(url: str):
    return urllib.request.urlopen(url, timeout=120, context=_CTX)


def parquet_shards(repo: str, config: str, split: str) -> list[str]:
    with _open(f"{HF}/api/datasets/{repo}/parquet") as r:
        j = json.load(r)
    return j[config][split]


def fetch(url: str, dest: Path):
    if dest.exists() and dest.stat().st_size > 0:
        return
    dest.parent.mkdir(parents=True, exist_ok=True)
    with _open(url) as r, open(dest, "wb") as f:
        f.write(r.read())


def stem(name: str) -> str:
    return os.path.splitext(os.path.basename(name))[0]


def save_image(cell, key: str, images_dir: Path) -> bool:
    """Decode an HF image cell (dict{bytes,path} or raw bytes) to images/<key>.jpg."""
    data = cell["bytes"] if isinstance(cell, dict) else cell
    if not data:
        return False
    dest = images_dir / f"{key}.jpg"
    if dest.exists():
        return True
    try:
        Image.open(io.BytesIO(data)).convert("RGB").save(dest)
        return True
    except Exception:
        return False


def read_tables(repo, config, split, work: Path):
    for i, url in enumerate(parquet_shards(repo, config, split)):
        p = work / f"{repo.replace('/', '_')}_{config}_{split}_{i}.parquet"
        fetch(url, p)
        yield pq.read_table(p)


# --------------------------------------------------------------------------
def prep_images_keyed(repo, config, split, images_dir, work, key_col, img_col,
                      limit=0) -> set[str]:
    """Save images keyed by `key_col`; return the set of keys written."""
    keys = set()
    n = 0
    for t in read_tables(repo, config, split, work):
        cols = t.column_names
        kc = key_col if key_col in cols else None
        ic = img_col if img_col in cols else next(
            (c for c in cols if c in ("image", "jpg", "img")), None)
        for row in range(t.num_rows):
            if limit and n >= limit:
                return keys
            img_cell = t.column(ic)[row].as_py()
            if kc:
                key = stem(str(t.column(kc)[row].as_py()))
            elif isinstance(img_cell, dict) and img_cell.get("path"):
                key = stem(img_cell["path"])
            else:
                key = f"img_{n:06d}"
            if save_image(img_cell, key, images_dir):
                keys.add(key)
                n += 1
            if n % 1000 == 0 and n:
                print(f"  {repo}: {n} images", flush=True)
    return keys


def write_pairs(repo, config, splits, pairs_path: Path, valid_keys: set[str],
                work: Path):
    rows, missing = [], 0
    for split in splits:
        for t in read_tables(repo, config, split, work):
            cols = t.column_names
            c1 = "img1" if "img1" in cols else cols[0]
            c2 = "img2" if "img2" in cols else cols[1]
            cl = "label" if "label" in cols else cols[2]
            for r in range(t.num_rows):
                ka = stem(str(t.column(c1)[r].as_py()))
                kb = stem(str(t.column(c2)[r].as_py()))
                m = int(t.column(cl)[r].as_py())
                if ka in valid_keys and kb in valid_keys:
                    rows.append(f"{ka} {kb} {m}")
                else:
                    missing += 1
    pairs_path.write_text("\n".join(rows) + "\n")
    print(f"  wrote {len(rows)} pairs ({missing} dropped: missing image) -> {pairs_path}")


def sample_pairs_from_labels(repo, config, split, images_dir, pairs_path, work,
                             n_genuine=3000, n_impostor=3000, limit=0):
    """LFW: save images keyed by filename + sample balanced pairs from labels."""
    by_label = defaultdict(list)
    n = 0
    for t in read_tables(repo, config, split, work):
        for r in range(t.num_rows):
            if limit and n >= limit:
                break
            img_cell = t.column("image")[r].as_py()
            label = t.column("label")[r].as_py()
            path = img_cell.get("path") if isinstance(img_cell, dict) else None
            key = stem(path) if path else f"img_{n:06d}"
            if save_image(img_cell, key, images_dir):
                by_label[label].append(key)
                n += 1
                if n % 1000 == 0:
                    print(f"  lfw: {n} images", flush=True)
    # deterministic pair sampling (no RNG -> reproducible)
    import random
    rng = random.Random(0)
    multi = [v for v in by_label.values() if len(v) >= 2]
    all_keys = [k for v in by_label.values() for k in v]
    rows = []
    for _ in range(n_genuine):
        grp = rng.choice(multi)
        a, b = rng.sample(grp, 2)
        rows.append(f"{a} {b} 1")
    label_of = {k: lab for lab, ks in by_label.items() for k in ks}
    while len([r for r in rows if r.endswith(" 0")]) < n_impostor:
        a, b = rng.choice(all_keys), rng.choice(all_keys)
        if label_of[a] != label_of[b]:
            rows.append(f"{a} {b} 0")
    pairs_path.write_text("\n".join(rows) + "\n")
    print(f"  wrote {len(rows)} sampled pairs -> {pairs_path}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dataset", choices=["lfw", "calfw", "cplfw"])
    ap.add_argument("out")
    ap.add_argument("--limit", type=int, default=0, help="cap images (validation)")
    args = ap.parse_args()

    base = Path(args.out) / args.dataset
    images = base / "images"
    images.mkdir(parents=True, exist_ok=True)
    work = Path(args.out) / "_parquet"
    pairs = base / "pairs.txt"

    if args.dataset == "lfw":
        sample_pairs_from_labels("logasja/lfw", "default", "train", images, pairs,
                                 work, limit=args.limit)
    elif args.dataset == "calfw":
        keys = prep_images_keyed("marcelohaps/calfw", "default", "aligned", images,
                                 work, key_col="source_filename", img_col="image",
                                 limit=args.limit)
        write_pairs("hero-nq1310/calfw-labels", "default", ["train", "test"], pairs,
                    keys, work)
    elif args.dataset == "cplfw":
        keys = prep_images_keyed("LSIbabnikz/cplfw", "default", "train", images,
                                 work, key_col="__key__", img_col="jpg",
                                 limit=args.limit)
        write_pairs("hero-nq1310/cplfw-labels", "default", ["train", "test"], pairs,
                    keys, work)

    n_imgs = len(list(images.glob("*.jpg")))
    print(f"\n{args.dataset}: {n_imgs} images in {images}, pairs in {pairs}")
    if n_imgs == 0:
        sys.exit("no images materialized")


if __name__ == "__main__":
    main()
