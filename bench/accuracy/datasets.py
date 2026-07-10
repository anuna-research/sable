"""Pair construction for verification benchmarks.

Three input paths, in order of fidelity to the real system:

1. Explicit pairs npz:  keys emb_a (P,D), emb_b (P,D), match (P,)  [0/1]
   Use this to replicate a standard protocol (e.g. the LFW 6000-pair list)
   with embeddings exported from the *deployed* Human library.

2. Identity-labelled npz: keys embeddings (N,D), labels (N,) [identity ids]
   The harness samples genuine (same-id) and impostor (diff-id) pairs.

3. Synthetic: correlated genuine/impostor Gaussian embeddings. Lets you
   validate the harness itself (and sanity-check that float_cosine separates)
   before any model is wired up. NOT a substitute for real data.
"""

from __future__ import annotations

import numpy as np


def _rng(seed: int) -> np.random.Generator:
    return np.random.default_rng(seed)


def load_pairs(npz_path: str) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Return (emb_a, emb_b, match) from an npz file (path 1 or 2)."""
    data = np.load(npz_path, allow_pickle=False)
    keys = set(data.files)
    if {"emb_a", "emb_b", "match"} <= keys:
        return (data["emb_a"].astype(np.float64),
                data["emb_b"].astype(np.float64),
                data["match"].astype(int))
    if {"embeddings", "labels"} <= keys:
        return pairs_from_labels(data["embeddings"].astype(np.float64),
                                 data["labels"])
    raise ValueError(
        f"{npz_path}: expected keys (emb_a,emb_b,match) or (embeddings,labels); "
        f"got {sorted(keys)}")


def pairs_from_labels(emb: np.ndarray, labels: np.ndarray,
                      n_genuine: int = 3000, n_impostor: int = 3000,
                      seed: int = 0) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Sample balanced genuine/impostor pairs from identity-labelled embeddings."""
    rng = _rng(seed)
    labels = np.asarray(labels)
    by_id: dict = {}
    for i, lab in enumerate(labels):
        by_id.setdefault(lab, []).append(i)
    multi = [idxs for idxs in by_id.values() if len(idxs) >= 2]

    a_idx, b_idx, match = [], [], []

    # genuine: two distinct samples of the same identity
    if not multi:
        raise ValueError("no identity has >=2 samples; cannot form genuine pairs")
    for _ in range(n_genuine):
        idxs = multi[rng.integers(len(multi))]
        i, j = rng.choice(idxs, size=2, replace=False)
        a_idx.append(i); b_idx.append(j); match.append(1)

    # impostor: two samples from different identities
    n = len(emb)
    while len(match) < n_genuine + n_impostor:
        i, j = rng.integers(n), rng.integers(n)
        if labels[i] != labels[j]:
            a_idx.append(i); b_idx.append(j); match.append(0)

    return emb[a_idx], emb[b_idx], np.array(match, dtype=int)


def load_lfw_pairs(pairs_txt: str, emb_by_name: dict[str, np.ndarray]
                   ) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Parse the canonical LFW pairs.txt and look up embeddings by image key.

    emb_by_name maps "Name_0001" -> embedding vector. Lines are either
    `Name  n1  n2` (genuine) or `Name1  n1  Name2  n2` (impostor).
    """
    a, b, match = [], [], []
    missing = 0

    def key(name, num):
        return f"{name}_{int(num):04d}"

    with open(pairs_txt) as fh:
        for line in fh:
            parts = line.split()
            if len(parts) == 3:
                k1, k2, m = key(parts[0], parts[1]), key(parts[0], parts[2]), 1
            elif len(parts) == 4:
                k1, k2, m = key(parts[0], parts[1]), key(parts[2], parts[3]), 0
            else:
                continue
            if k1 not in emb_by_name or k2 not in emb_by_name:
                missing += 1
                continue
            a.append(emb_by_name[k1]); b.append(emb_by_name[k2]); match.append(m)

    if missing:
        print(f"[lfw] warning: {missing} pairs skipped (missing embeddings)")
    return np.array(a, np.float64), np.array(b, np.float64), np.array(match, int)


def load_pairs_list(pairs_list: str, named_npz: str
                    ) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Generic pre-paired protocol: a whitespace/comma-separated manifest with
    rows `keyA keyB match`, plus a name-keyed npz mapping key -> embedding.

    Used for CALFW/CPLFW/LFW where the protocol is fixed and images are keyed
    by filename. Lines starting with '#' are ignored.
    """
    raw = np.load(named_npz, allow_pickle=True)
    emb_by_name = {k: np.asarray(raw[k], np.float64) for k in raw.files}
    a, b, match = [], [], []
    missing = 0
    with open(pairs_list) as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.replace(",", " ").split()
            if len(parts) < 3:
                continue
            ka, kb, m = parts[0], parts[1], int(parts[2])
            if ka not in emb_by_name or kb not in emb_by_name:
                missing += 1
                continue
            a.append(emb_by_name[ka]); b.append(emb_by_name[kb]); match.append(m)
    if missing:
        print(f"[pairs-list] warning: {missing} pairs skipped (missing embeddings)")
    if not match:
        raise ValueError(f"no usable pairs from {pairs_list}")
    return np.array(a, np.float64), np.array(b, np.float64), np.array(match, int)


def resolve_pairs(*, embeddings=None, lfw_pairs=None, lfw_embeddings=None,
                  pairs_list=None, named_embeddings=None,
                  use_synthetic=False, dim=1024, n_pairs=3000, seed=0,
                  genuine_corr=0.92, l2_normalize=True
                  ) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Single entry point shared by benchmark.py and thermo_sweep.py.
    Exactly one source of {embeddings, lfw_pairs, pairs_list, use_synthetic}."""
    if use_synthetic:
        return synthetic(dim=dim, n_pairs=n_pairs, seed=seed,
                         genuine_corr=genuine_corr, l2_normalize=l2_normalize)
    if pairs_list:
        if not named_embeddings:
            raise ValueError("pairs_list requires named_embeddings")
        return load_pairs_list(pairs_list, named_embeddings)
    if lfw_pairs:
        if not lfw_embeddings:
            raise ValueError("lfw_pairs requires lfw_embeddings")
        raw = np.load(lfw_embeddings, allow_pickle=True)
        emb_by_name = {k: np.asarray(raw[k], np.float64) for k in raw.files}
        return load_lfw_pairs(lfw_pairs, emb_by_name)
    if embeddings:
        return load_pairs(embeddings)
    raise ValueError("no embedding source provided")


def synthetic(dim: int = 1024, n_pairs: int = 3000, seed: int = 0,
              genuine_corr: float = 0.92, l2_normalize: bool = True
              ) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Correlated Gaussian pairs for harness validation.

    l2_normalize mimics the realistic case where embeddings lie on the unit
    sphere -- which is exactly the distribution that drives every component
    toward the 127/128 quantization boundary. Toggle it to see the effect.
    """
    rng = _rng(seed)
    half = n_pairs // 2

    base = rng.standard_normal((n_pairs, dim))
    # genuine: b is a noisy copy of a; impostor: independent
    noise = rng.standard_normal((n_pairs, dim))
    b = np.empty_like(base)
    b[:half] = genuine_corr * base[:half] + np.sqrt(1 - genuine_corr**2) * noise[:half]
    b[half:] = rng.standard_normal((n_pairs - half, dim))
    a = base
    match = np.concatenate([np.ones(half, int), np.zeros(n_pairs - half, int)])

    if l2_normalize:
        a = a / np.linalg.norm(a, axis=1, keepdims=True)
        b = b / np.linalg.norm(b, axis=1, keepdims=True)
    return a, b, match
