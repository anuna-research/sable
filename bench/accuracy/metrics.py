"""Verification metrics: EER, AUC, TAR@FAR, and the data-driven threshold.

Pure numpy -- no sklearn dependency, so the spike runs anywhere.

Convention: `scores` are similarities (higher = more similar), `labels` are 1
for genuine (same identity) and 0 for impostor (different identity).
"""

from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np


@dataclass
class Result:
    condition: str
    n_genuine: int
    n_impostor: int
    auc: float
    eer: float
    eer_threshold: float
    # TAR (= 1 - FNMR) at fixed FAR (= FMR) operating points
    tar_at_far: dict[float, float] = field(default_factory=dict)
    # For Hamming conditions the threshold is a bit-distance; we also express it
    # as % similarity to compare against the paper's arbitrary "50%" claim.
    eer_threshold_human: str = ""


def _roc(scores: np.ndarray, labels: np.ndarray):
    """Return (far, tar, thresholds) sorted by ascending threshold-cut.

    A pair is accepted when score >= threshold. We sweep thresholds at every
    distinct score value.
    """
    order = np.argsort(-scores, kind="mergesort")  # high score first
    s = scores[order]
    y = labels[order]
    n_pos = max(int(y.sum()), 1)
    n_neg = max(int((1 - y).sum()), 1)

    tp = np.cumsum(y)
    fp = np.cumsum(1 - y)
    tar = tp / n_pos
    far = fp / n_neg

    # Prepend the (0,0) operating point (accept nothing).
    far = np.concatenate(([0.0], far))
    tar = np.concatenate(([0.0], tar))
    thr = np.concatenate(([np.inf], s))
    return far, tar, thr


def _auc(far: np.ndarray, tar: np.ndarray) -> float:
    return float(np.trapz(tar, far))


def _eer(far: np.ndarray, tar: np.ndarray, thr: np.ndarray):
    """Equal error rate: where FAR == FRR (FRR = 1 - TAR)."""
    frr = 1.0 - tar
    diff = far - frr
    # find sign change in (far - frr)
    idx = np.where(np.diff(np.sign(diff)) != 0)[0]
    if len(idx) == 0:
        i = int(np.argmin(np.abs(diff)))
        return float((far[i] + frr[i]) / 2), float(thr[i])
    i = idx[0]
    # linear interpolation between i and i+1
    x0, x1 = diff[i], diff[i + 1]
    t = 0.0 if (x1 - x0) == 0 else x0 / (x0 - x1)
    eer = float(far[i] + t * (far[i + 1] - far[i]))
    threshold = float(thr[i] + t * (thr[i + 1] - thr[i]))
    return eer, threshold


def _tar_at_far(far: np.ndarray, tar: np.ndarray, target: float) -> float:
    """Highest TAR achievable while keeping FAR <= target."""
    mask = far <= target
    return float(tar[mask].max()) if mask.any() else 0.0


def evaluate(condition: str, scores: np.ndarray, labels: np.ndarray,
             far_points=(1e-1, 1e-2, 1e-3),
             dim: int | None = None, is_hamming: bool = False) -> Result:
    labels = labels.astype(int)
    far, tar, thr = _roc(scores, labels)
    eer, eer_thr = _eer(far, tar, thr)

    human = ""
    if is_hamming and dim is not None:
        # scores are negative bit-distance; recover the distance threshold and
        # express as % similarity over the dim*8 bit space.
        dist = -eer_thr
        total_bits = dim * 8
        sim_pct = 100.0 * (1.0 - dist / total_bits)
        human = f"d_H<= {dist:.0f}/{total_bits}  ({sim_pct:.1f}% similar)"

    return Result(
        condition=condition,
        n_genuine=int(labels.sum()),
        n_impostor=int((1 - labels).sum()),
        auc=_auc(far, tar),
        eer=eer,
        eer_threshold=eer_thr,
        tar_at_far={p: _tar_at_far(far, tar, p) for p in far_points},
        eer_threshold_human=human,
    )


def format_table(results: list[Result], far_points=(1e-1, 1e-2, 1e-3)) -> str:
    far_cols = "".join(f"  TAR@FAR={p:<7g}" for p in far_points)
    lines = [
        f"{'condition':<18}{'EER':>8}{'AUC':>8}{far_cols}   threshold",
        "-" * (18 + 16 + len(far_points) * 17 + 12),
    ]
    for r in results:
        tars = "".join(f"  {r.tar_at_far.get(p, 0.0)*100:>11.2f}%" for p in far_points)
        thr = r.eer_threshold_human or f"{r.eer_threshold:.4f}"
        lines.append(
            f"{r.condition:<18}{r.eer*100:>7.2f}%{r.auc:>8.4f}{tars}   {thr}"
        )
    return "\n".join(lines)


def to_csv_rows(results: list[Result], far_points=(1e-1, 1e-2, 1e-3)) -> list[dict]:
    rows = []
    for r in results:
        row = {
            "condition": r.condition,
            "eer": r.eer,
            "auc": r.auc,
            "eer_threshold": r.eer_threshold,
            "eer_threshold_human": r.eer_threshold_human,
            "n_genuine": r.n_genuine,
            "n_impostor": r.n_impostor,
        }
        for p in far_points:
            row[f"tar_at_far_{p:g}"] = r.tar_at_far.get(p, 0.0)
        rows.append(row)
    return rows
