# EXP-004: Information-theoretic analysis of the rolling-shutter channel

| Field | Value |
|-------|-------|
| id | EXP-004 |
| date | 2026-09-15 |
| status | complete for the simulation model; hardware validation open |
| method | 100,000 trials/configuration, seed 20260915 |
| implementation | `rolling_shutter_information.py` |
| confidence | medium for the mathematical analysis; low for physical-device values |

## Question

How much challenge information does SABLE's rolling-shutter channel
actually convey, what precomputed-replay probability follows from it, and how
does unknown capture phase change the bound?

This is a standard combination of four analyses:

1. Shannon entropy of the challenge symbols that survive capture;
2. mutual information between the visible sequence and decoder output;
3. empirical min-entropy / optimal modal-string guessing for a fixed replay;
4. coding-theoretic acceptance-ball size when symbol errors are tolerated.

Applying those tools to SABLE's capture and attacker model is system-specific.
In particular, no channel-capacity calculation supplies security against an
attacker that learns the challenge and may construct arbitrary pixels.

## Model and method

The physical and noise model is the model of record from EXP-001: a 120 Hz
four-colour display, a row-scanned camera, a grey-card-derived electron anchor,
skin reflectance 0.35, shot/read noise averaged across a 600-pixel face, and 64
sampled rows. The alphabet is `R,G,B,W`, with adjacent repeats prohibited.

EXP-004 replaces EXP-001's 64-point numerical exposure integral with the exact
integral of the same piecewise-constant display waveform, allowing 100,000
trials per target configuration. It otherwise retains EXP-001's decoder and its
rule of removing the first and last partial bands.

For each usable simulated frame:

- `X` is the sequence of complete interior ground-truth bands;
- `Y` is the decoded interior sequence, including insertion/deletion outcomes;
- `H(X)` is the Shannon entropy per frame;
- `I(X;Y)` is the plug-in mutual-information estimate over complete strings;
- `H_inf(X) = -log2(max_x P[X=x])` is the plug-in modal-string exponent,
  conditioned on a usable simulated frame. It is not conditional min-entropy or
  an exact noisy-replay success probability.

The 95% interval shown for exact recovery is a Wilson binomial interval. The
entropy and mutual-information values are plug-in estimates and have sampling
bias not represented by that interval. All numerical results remain simulation
results, not claims about a phone.

## Measured channel information

All rows below use 120 Hz, 600 face pixels and 40 lux.

| `T_ro` | `T_exp` | Complete symbols/frame | Exact recovery (95% CI) | `H(X)` | `I(X;Y)` | `H_inf(X)` |
|---:|---:|---:|---:|---:|---:|---:|
| 20 ms | 0.5 ms | 1.215 | 97.55% [97.46, 97.65] | 3.092 bits | 2.880 bits | 2.337 bits |
| 20 ms | 1.0 ms | 1.212 | 94.96% [94.82, 95.10] | 3.083 bits | 2.701 bits | 2.337 bits |
| 20 ms | 2.0 ms | 1.213 | 76.95% [76.69, 77.21] | 3.084 bits | 2.282 bits | 2.341 bits |
| 33 ms | 0.5 ms | 2.652 | 97.52% [97.42, 97.62] | 5.550 bits | 5.345 bits | 5.083 bits |
| 33 ms | 1.0 ms | 2.653 | 94.92% [94.78, 95.05] | 5.551 bits | 5.182 bits | 5.060 bits |
| 33 ms | 2.0 ms | 2.650 | 89.80% [89.61, 89.99] | 5.549 bits | 4.911 bits | 5.052 bits |

The distinction between *visible symbol slots* and *complete checked symbols*
matters. EXP-001 reports 2.4 slots at 20 ms and 3.96 at 33 ms. Once the two
uncontrolled edge bands are removed, the decoder checks only 1.2 and 2.65
complete symbols on average. Under the simulator, `X` has about 3.1 or 5.6 bits
of source entropy per usable frame and `Y` retains 2.3--2.9 or 4.9--5.3 bits of
mutual information, not the 30 bits present in the coin-flip seed. This is not
channel capacity or extractable security entropy.

At 0.5 ms, the plug-in mutual information is 93%--96% of the estimated `H(X)`.
Longer exposure mostly increases conditional uncertainty rather than changing
the challenge entropy: at 20/2 ms only 2.28 of 3.08 bits survive.

## Fixed-position replay bounds

A length-`n` four-colour run-length-limited codebook has

```text
|C_n| = 4 * 3^(n-1)
H(C_n) = 2 + (n-1) log2(3).
```

The following are conservative bounds. For tolerance `t`, the numerator uses
the unrestricted four-ary Hamming ball
`sum(i=0..t) choose(n,i) * 3^i`; invalid RLL neighbours only make the true
acceptance set smaller.

| Fixed-position symbols | Codebook entropy | Exact | One error | Two errors |
|---:|---:|---:|---:|---:|
| 6 | 9.925 bits | 9.925 bits | 5.677 bits | 2.658 bits |
| 9 | 14.680 bits | 14.680 bits | 9.872 bits | 6.220 bits |
| 12 | 19.435 bits | 19.435 bits | 14.225 bits | 10.133 bits |

Thus an error budget must be designed as an error-correcting code, not added as
a loose Hamming threshold. Two tolerated symbol errors consume
`log2(631) = 9.302` bits from a 12-symbol challenge.

## Unknown phase: the window attack

The fixed-position bound does not apply if the prover may choose any phase after
seeing the challenge. A stored `m`-symbol response then passes whenever it occurs
in *any* length-`m` window of the challenge. Dynamic programming over the exact
uniform RLL source, maximized over all four-ary fixed replay strings, gives the
optimal probabilities below for this discrete model.

| Challenge symbols | Stored-window symbols | Exact replay | Replay with one error |
|---:|---:|---:|---:|
| 6 | 1 | 82.20% | 100.00% |
| 6 | 2 | 37.04% | 99.18% |
| 6 | 3 | 11.01% | 58.85% |
| 6 | 4 | 2.78% | 22.02% |
| 12 | 1 | 96.83% | 100.00% |
| 12 | 2 | 64.08% | 100.00% |
| 12 | 3 | 25.53% | 89.89% |
| 12 | 4 | 8.19% | 51.39% |

A longer challenge makes a freely aligned short-window replay *more* likely,
because it supplies more candidate windows. This is the strongest design result
from the analysis.

The circuit must not accept independent existential phase offsets for short
frames. It must establish one ordered timeline across the full capture:

```text
challenge position ─────────────────────────────────────────>
                    frame 0       frame 1       frame 2
sensor timeline       [------]      [------]      [------]
                       one phase + constrained frame progression
```

At minimum, the relation needs a single initial phase, bounded frame-to-frame
timing progression, no arbitrary substring selection, and a code with an
explicit accepted-set volume. A validated timeline is needed to authenticate
phase progression; it does not authenticate pixel provenance. Preventing a
fully malicious prover from choosing both timing and row content requires a
protected capture-and-timing path or an explicitly restricted attacker model.

## Security interpretation

For a response fixed independently before challenge issuance and checked at fixed positions,
the table gives an information-theoretic replay bound. For an attacker that
learns the challenge before constructing its response,

```text
H_inf(challenge | challenge) = 0.
```

The attack becomes deterministic synthesis rather than guessing. If arbitrary
pixel injection lets the attacker reproduce the honest conditional distribution
`P(Y | challenge)`, no statistical verifier can distinguish the two. EXP-004
therefore contributes simulated channel reliability and computed replay
probability under the stated discrete model; a validated implementation could
use that temporal relation under a protected-capture or restricted-synthesis
model.

## Decisions and next measurements

1. Treat entropy as measured channel information, never as the coin-flip seed
   width.
2. Do not claim meaningful single-frame replay security for a 20 ms readout.
3. Require an ordered multi-frame codeword and bind phase progression in-circuit.
4. Select an error-correcting RLL code with a stated codebook size and minimum
   distance; do not tolerate raw symbol errors without accounting for the
   resulting acceptance volume.
5. Extend EXP-002 hardware capture to retain the issued/decoded strings, erasures
   and phase estimates. Those observations are sufficient to recompute every
   metric in this report on real devices.
6. Evaluate adaptive LED, replay-display and synthetic-frame distributions in
   EXP-003. Mutual information alone measures channel reliability, not separation
   between genuine and attack responses.
