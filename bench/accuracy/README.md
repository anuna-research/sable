# SABLE accuracy spike (week-1 go/no-go)

Measures how SABLE's matching pipeline — 8-bit quantization followed by **plain
binary Hamming distance** over the `u8` bytes — affects face-verification
accuracy versus the float embedding it starts from. This is the experiment that
decides whether the current approach can target a top-tier security venue
(S&P/CCS) or needs a redesign first.

The Python quantizer is a bit-for-bit port of
`core/src/zk/halo2/quantizer.rs` (verified by `test_sable_quant.py`), so these
numbers reflect what the ZK circuit actually computes.

## The question

A naive concern: binary Hamming over quantized bytes throws away ordinal
structure. Adjacent values `127 = 0b0111_1111` and `128 = 0b1000_0000` differ
in **8 bits**. If the embedding backbone produces L2-normalized vectors (most
do), every component clusters near 0 and quantizes right onto that boundary —
potentially catastrophic. We measure it instead of guessing.

## Conditions reported

| condition         | what it isolates |
|-------------------|------------------|
| `float_cosine`    | backbone ceiling (cosine on raw floats) |
| `quant_cosine`    | cost of 8-bit **rounding** alone |
| `hamming_binary`  | **what SABLE ships today** (binary Hamming over u8) |
| `hamming_gray`    | cheap in-circuit fix: Gray code (one XOR-shift) |
| `quant_l1_thermo` | ordinal/thermometer ceiling in Hamming space (more bits) |

Each reports EER, AUC, and TAR@FAR (1e-1/1e-2/1e-3). For the bit-Hamming
conditions the EER threshold is also shown as a `% similar` over the `dim*8` bit
space — compare against the paper's arbitrary "50% similarity / 4096 bits".

## Quickstart

```bash
pip install -r requirements.txt          # just numpy for the core harness
python test_sable_quant.py               # verify the port matches Rust

# 1) validate the harness with no model (plumbing check; synthetic is saturated):
python benchmark.py --synthetic --dim 1024

# 2) see the conditions actually separate on harder synthetic data:
python benchmark.py --synthetic --dim 1024 --genuine-corr 0.18 --prescale none
```

## Real run

Get embeddings into an `.npz`, then benchmark. **Two source options, by fidelity:**

**(A) Deployed model — do this for the number that counts.** `human_export/`
runs the *same* `@vladmandic/human` FaceRes (1024-d) config as the deployed web
app (`demo/web/src/components/faceEmbedding.ts`), so the embeddings match
production. Point it at an ImageFolder dataset (`root/<identity>/<image>.jpg`,
which is exactly the LFW layout):

```bash
cd human_export && npm install            # @tensorflow/tfjs-node + @vladmandic/human
node extract_human.mjs ~/data/lfw lfw_human    # -> lfw_human.bin + lfw_human.json
cd ..

# identity-labelled (harness samples balanced pairs):
python human_to_npz.py human_export/lfw_human lfw_human.npz
python benchmark.py --embeddings lfw_human.npz --sweep-prescale --out results.csv

# OR the canonical LFW 6000-pair protocol:
python human_to_npz.py human_export/lfw_human lfw_named.npz --name-keyed
python benchmark.py --lfw-pairs pairs.txt --lfw-embeddings lfw_named.npz --sweep-prescale
```

The extractor config mirrors the web app's; the only intentional difference is
the backend (`tensorflow`/Node vs `webgl`/browser). FaceRes weights are
identical, so embeddings are equivalent up to negligible float error. **Keep
`extract_human.mjs`'s config in sync with `faceEmbedding.ts`.**

You can also hand-build the npz yourself with either layout:
- `emb_a (P,D), emb_b (P,D), match (P,)`, or
- `embeddings (N,D), labels (N,)` (identity strings — harness samples pairs).

**(B) Fast first look — Python backbone (512-d, NOT the deployed model):**

```bash
python extract_embeddings.py /path/to/lfw out.npz --backend insight
python benchmark.py --embeddings out.npz --sweep-prescale
```

LFW protocol directly from `pairs.txt`:

```bash
python benchmark.py --lfw-pairs pairs.txt --lfw-embeddings names.npz
```

## `--prescale`

The quantizer assumes embeddings already lie in `[-1, 1]`; real ones don't.
How you map into that window dominates the result, so it's an explicit knob:
`none` (clip), `tanh`, `minmax` (mirrors `quantizer.rs normalize()`), `zscore`
(per-dim standardize + tanh — spreads an L2-normalized cloud off the boundary).
Stats are fit on the gallery side only (no probe leakage). Use
`--sweep-prescale` to try all four.

## Reading the result

- `hamming_binary` EER ≈ `float_cosine` → **approach is sound, proceed to the
  full benchmark suite** (LFW + CFP-FP + AgeDB + IJB-B/C).
- `hamming_binary` collapses but `hamming_gray`/`quant_l1_thermo` recover →
  **the binary encoding is the culprit, not quantization.** Redesign the
  in-circuit encoding (Gray ≈ free; thermometer costs constraints) and re-run.
- Nothing in Hamming space recovers → **rethink matching** (learned binary
  hashing / a trained-for-Hamming head) before targeting S&P; ship the current
  contribution to PoPETs meanwhile.

The `quantized byte distribution` line (esp. `frac@127-128`) tells you at a
glance whether boundary clustering is in play for your data + prescale choice.

## Files

- `sable_quant.py` — faithful quantizer, encodings, scoring conditions
- `metrics.py` — EER / AUC / TAR@FAR / data-driven threshold (numpy only)
- `datasets.py` — pairs npz / identity-labelled / LFW protocol / synthetic
- `benchmark.py` — CLI orchestrator
- `extract_embeddings.py` — optional Python-backbone extractor (512-d, fast look)
- `human_export/` — Node extractor using the deployed Human FaceRes config (1024-d)
- `human_to_npz.py` — convert Human extractor output into a benchmark npz
- `test_sable_quant.py` — cross-check against `quantizer.rs`
