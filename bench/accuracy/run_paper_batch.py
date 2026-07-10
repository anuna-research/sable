#!/usr/bin/env python3
"""Restartable driver for the paper-grade accuracy batch.

For each dataset in {lfw, calfw, cplfw} and each backbone in {faceres, arcface}:
  1. prep      -> images/ + pairs.txt        (lfwenv python: pyarrow+pillow)
  2. extract   -> <backbone>.npz             (faceres: node; arcface: arcenv)
  3. benchmark -> <ds>_<bb>_bench.csv         (system python3 + numpy)
  4. thermo    -> <ds>_<bb>_thermo.csv

Every stage checks for its output and skips if present, so the job is
re-runnable after any failure. Stages print `>>> STAGE ...` / `!!! FAIL ...`
markers so a Monitor can track progress and catch errors. A final SUMMARY
collates the key EERs.

Run (typically in background):  python3 run_paper_batch.py
Env overrides: DATA, LFWPY, ARCPY, NODE, SYSPY
"""

from __future__ import annotations

import csv
import os
import subprocess
import sys
from pathlib import Path

BENCH = Path(__file__).resolve().parent
DATA = Path(os.environ.get("DATA", "/tmp/sable_paper"))
LFWPY = os.environ.get("LFWPY", "/tmp/lfwenv/bin/python")
ARCPY = os.environ.get("ARCPY", "/tmp/arcenv/bin/python")
NODE = os.environ.get("NODE", "node")
SYSPY = os.environ.get("SYSPY", "python3")
HUMAN_EXPORT = BENCH / "human_export"

DATASETS = ["lfw", "calfw", "cplfw"]
LOGS = DATA / "logs"


def run(cmd, log, cwd=None):
    """Run a command, tee output to a log file, raise on failure."""
    LOGS.mkdir(parents=True, exist_ok=True)
    logp = LOGS / log
    print(f"    $ {' '.join(str(c) for c in cmd)}  (log: {logp})", flush=True)
    with open(logp, "w") as fh:
        p = subprocess.run(cmd, cwd=cwd, stdout=fh, stderr=subprocess.STDOUT)
    if p.returncode != 0:
        tail = "\n".join(logp.read_text().splitlines()[-15:])
        raise RuntimeError(f"command failed ({p.returncode}); tail:\n{tail}")


def stage_prep(ds):
    base = DATA / ds
    pairs = base / "pairs.txt"
    imgs = base / "images"
    if pairs.exists() and imgs.exists() and any(imgs.glob("*.jpg")):
        print(f"  [skip] prep {ds}", flush=True)
        return
    print(f">>> STAGE prep {ds}", flush=True)
    run([LFWPY, str(BENCH / "prep_datasets.py"), ds, str(DATA)], f"prep_{ds}.log")


def stage_faceres(ds):
    base = DATA / ds
    npz = base / "faceres.npz"
    if npz.exists():
        print(f"  [skip] faceres extract {ds}", flush=True)
        return
    print(f">>> STAGE faceres extract {ds}", flush=True)
    bin_base = str(base / "faceres_raw")
    run([NODE, "extract_human.mjs", str(base / "images"), bin_base, "--flat"],
        f"faceres_extract_{ds}.log", cwd=HUMAN_EXPORT)
    run([SYSPY, str(BENCH / "human_to_npz.py"), bin_base, str(npz), "--name-keyed"],
        f"faceres_npz_{ds}.log")


def stage_arcface(ds):
    base = DATA / ds
    npz = base / "arcface.npz"
    if npz.exists():
        print(f"  [skip] arcface extract {ds}", flush=True)
        return
    print(f">>> STAGE arcface extract {ds}", flush=True)
    run([ARCPY, str(BENCH / "extract_embeddings.py"), str(base / "images"),
         str(npz), "--backend", "insight", "--flat"], f"arcface_extract_{ds}.log")


def stage_eval(ds, bb):
    base = DATA / ds
    npz = base / f"{bb}.npz"
    pairs = base / "pairs.txt"
    bench_csv = base / f"{ds}_{bb}_bench.csv"
    thermo_csv = base / f"{ds}_{bb}_thermo.csv"
    if not bench_csv.exists():
        print(f">>> STAGE benchmark {ds}/{bb}", flush=True)
        run([SYSPY, str(BENCH / "benchmark.py"), "--pairs-list", str(pairs),
             "--named-embeddings", str(npz), "--sweep-prescale",
             "--out", str(bench_csv)], f"bench_{ds}_{bb}.log", cwd=BENCH)
    else:
        print(f"  [skip] benchmark {ds}/{bb}", flush=True)
    if not thermo_csv.exists():
        print(f">>> STAGE thermo {ds}/{bb}", flush=True)
        run([SYSPY, str(BENCH / "thermo_sweep.py"), "--pairs-list", str(pairs),
             "--named-embeddings", str(npz), "--prescale", "zscore",
             "--out", str(thermo_csv)], f"thermo_{ds}_{bb}.log", cwd=BENCH)
    else:
        print(f"  [skip] thermo {ds}/{bb}", flush=True)


def best_eer(csv_path, condition):
    """Min EER for a condition across prescale modes in a bench CSV."""
    if not csv_path.exists():
        return None
    best = None
    with open(csv_path) as fh:
        for row in csv.DictReader(fh):
            if row["condition"] == condition:
                e = float(row["eer"])
                best = e if best is None else min(best, e)
    return best


def thermo_l9_eer(csv_path):
    if not csv_path.exists():
        return None
    with open(csv_path) as fh:
        for row in csv.DictReader(fh):
            if int(row["levels"]) == 9:
                return float(row["eer"])
    return None


def summarize():
    print("\n" + "=" * 78, flush=True)
    print("SUMMARY  (best EER across prescale modes; lower=better)", flush=True)
    print(f"{'dataset':<8}{'backbone':<10}{'float_cos':>10}{'binary_ham':>12}"
          f"{'thermo_L9':>11}{'pairs':>8}", flush=True)
    print("-" * 78, flush=True)
    rows = []
    for ds in DATASETS:
        base = DATA / ds
        for bb in ("faceres", "arcface"):
            bcsv = base / f"{ds}_{bb}_bench.csv"
            tcsv = base / f"{ds}_{bb}_thermo.csv"
            fc = best_eer(bcsv, "float_cosine")
            hb = best_eer(bcsv, "hamming_binary")
            t9 = thermo_l9_eer(tcsv)
            npairs = 0
            if (base / "pairs.txt").exists():
                npairs = sum(1 for _ in open(base / "pairs.txt") if _.strip())
            fmt = lambda x: f"{x*100:.2f}%" if x is not None else "  --  "
            print(f"{ds:<8}{bb:<10}{fmt(fc):>10}{fmt(hb):>12}{fmt(t9):>11}{npairs:>8}",
                  flush=True)
            rows.append({"dataset": ds, "backbone": bb, "float_cosine": fc,
                         "hamming_binary": hb, "thermo_L9": t9, "pairs": npairs})
    print("=" * 78, flush=True)
    with open(DATA / "summary.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader(); w.writerows(rows)
    print(f"wrote {DATA / 'summary.csv'}", flush=True)


def main():
    DATA.mkdir(parents=True, exist_ok=True)
    print(f"=== paper batch: DATA={DATA} ===", flush=True)
    for ds in DATASETS:
        try:
            stage_prep(ds)
            stage_faceres(ds)
            stage_arcface(ds)
            for bb in ("faceres", "arcface"):
                stage_eval(ds, bb)
            print(f"### DONE dataset {ds}", flush=True)
        except Exception as e:
            print(f"!!! FAIL dataset {ds}: {e}", flush=True)
            continue
    summarize()
    print("=== batch complete ===", flush=True)


if __name__ == "__main__":
    main()
