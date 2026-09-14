# BUG-003: Expected fingerprints carry emitted-colour magnitude; observed fingerprints carry delta magnitude

| Field | Value |
|-------|-------|
| id | BUG-003 |
| severity | High — the proven liveness bit is 0 for real faces, and the corneal check cannot be armed |
| priority | P1 — blocks every threshold decision in [[EXP-003-presentation-attack-study]] |
| status | open (diagnosed on live data; fix proposed, not implemented) |
| found | 2026-09-14, first real-face run of the demo with OBS-085 and the corneal path wired |
| root cause class | Unit mismatch across a comparison: absolute colour vs. reflected delta |

## Specification Reference

[[SPEC-006-geometric-liveness#REQ-114]] (glint extraction),
[[SPEC-006-geometric-liveness#REQ-115]] / [[SPEC-006-geometric-liveness#REQ-122]]
(corneal agreement), [[SPEC-006-geometric-liveness#CON-093]] (`expected_composite`),
the 0.1.0 colour check (`color_threshold`, Hamming over the full 16-bit fingerprint),
[[Delta Fingerprint]].

## Environment

Branch `feat/SPEC-006-geometric-liveness` at `95c13c6`. Demo server with
`halo2-proofs`, MacBook webcam at 640×480, screen flash at normal brightness,
ambient indoor light. `core/src/biometric/fingerprint.rs` with
`MAGNITUDE_SCALE = 128`; `demo/server/src/flash_challenge.rs`
`quantize_expected_color`; `core/src/biometric/corneal.rs` `expected_composite`.

## Steps to Reproduce

1. Start the demo server and web client; enrol and authenticate with a real face
   so the three flash rounds run.
2. Read the server log lines `Liveness fingerprints`, `corneal round`, `OBS-085`
   and `Halo2 proof generated`.

## Expected Behaviour

A real face under the flash produces delta fingerprints that the in-circuit
colour check accepts, so `liveness_in_zk = true`. Corneal glints whose channel
order matches the challenge composite can be accepted by `agrees` at some
finite magnitude tolerance.

## Actual Behaviour

Observed on the first run (values from the log):

```
delta    = [0x5600 0x4600 0x5441 0x5261 0xB261 0x7600 0xB881 0x7841 0x9261 0x8401 0x9401 0x8C41]
expected = [0x401F 0x001F 0x083F 0x769F 0x401F 0xA67F 0xA83F 0x1C1F 0x801F 0x001F 0x123F 0xAA9F]
OBS-085: liveness pre-check failed check=Colour round=0
Halo2 proof generated: face_match=true, liveness_in_zk=false

corneal r0 left  order 2 mid  2 min 0 mag 1 | right order 3 mid 10 min  5 mag 1 | expected order 2 mid 13 min 4 mag 30
corneal r1 left  order 3 mid 15 min 0 mag 1 | right order 3 mid 12 min 10 mag 1 | expected order 3 mid 12 min 7 mag 31
corneal r2 left  order 4 mid  3 min 1 mag 2 | right order 4 mid  6 min  4 mag 2 | expected order 4 mid 14 min 5 mag 29
```

Two manifestations of one defect:

1. **Colour check (0.1.0, in circuit).** Every expected fingerprint has
   magnitude 31 because `quantize_expected_color` feeds the emitted RGB (values
   up to 255) through the delta quantiser, saturating the field. Every observed
   fingerprint has magnitude 0–1 because a face at arm's length reflects the
   screen as a 4–8 unit RGB delta, and `MAGNITUDE_SCALE = 128` maps that to
   `round(max · 31 / 128) ≤ 1`. The check is a Hamming distance over all 16 bits
   with `color_threshold = 5`; the five magnitude bits alone differ in up to five
   positions, so any ratio disagreement pushes the distance past the threshold.
   The proof therefore carries `liveness = 0` while the server's floating-point
   cosine check reports a pass. The demo UI showed only the latter until
   `95c13c6`+1.

2. **Corneal check (0.2.0).** `expected_composite` quantises the emitted
   composite colour, so its magnitude is 29–31. The observed glint delta is 1–2.
   `agrees` requires `|mag_obs − mag_exp| ≤ max_magnitude_delta`, so the check
   passes only with a tolerance ≥ 28, at which point the magnitude field is
   not being compared at all. The `order` field, which is the actual security
   claim (the eye reflected the colour we chose), matched in 5 of 6 eye-rounds.
   The ratio fields are quantisation noise at this signal level: with a maximum
   channel delta of 4–8 units, one unit of noise moves a 16-step ratio by 2–4
   steps.

The `min_magnitude` check has the same exposure: with observed magnitudes of
0–1 and the demo's `min_magnitude = 3`, it fails on every round the colour check
would have passed.

## Evidence

Log excerpt above. `fingerprint.rs` documents `MAGNITUDE_SCALE = 128` as
"a strong single-channel response — half the 0–255 range — saturates the
field"; a webcam behind auto-exposure and a screen at a few hundred nits never
produces that. `flash_challenge.rs:440` applies the delta quantiser to an
absolute colour. `corneal.rs:70` does the same via `quantize_colour`.

## Root Cause

**The expected side and the observed side are in different units.** Expected
fingerprints encode *what the screen emitted*; observed fingerprints encode
*how much the reflection changed*. The order and ratio fields are unit-free
directions and compare correctly. The magnitude field is not: emitted
brightness and reflected delta differ by a factor set by distance, skin albedo,
screen brightness and exposure, none of which the verifier knows. Comparing
them, or bit-mixing them into a Hamming distance, compares a constant 31 to a
number that is structurally small.

## Resolution (proposed)

1. **Take magnitude out of the expected side.** `quantize_expected_color` and
   `expected_composite` produce fingerprints with `magnitude = 0`, and the
   in-circuit colour check masks the low five bits before the Hamming distance
   (or, better, compares order and ratios field-wise as REQ-123 already
   requires for the glint). Magnitude is then judged only against a floor
   (`min_magnitude`, `glint_magnitude_floor`), which is what it always meant.
2. **Rescale magnitude for the deployment.** `MAGNITUDE_SCALE` becomes a
   per-challenge public parameter alongside the thresholds (ADR-010 applies:
   no default enters the relation), so a webcam deployment can use a scale of
   16 or 32 and a phone-in-hand deployment something else. Until EXP-003
   measures the distribution, the demo should log the raw mean deltas.
3. **Make ratio tolerance conditional on magnitude.** At magnitude ≤ 2 the
   ratio fields carry no information; `agrees` (and the circuit's ordinal
   comparison) should treat them as satisfied below a magnitude floor and
   apply the tolerance only above it. Order stays strict.
4. **Demo honesty (done in the commit after `95c13c6`).** The result and
   verification screens display the proof's own liveness bit next to the
   server's floating-point check, and say when they disagree.

Regression tests to add: a fixture with observed magnitude 1 and expected
magnitude 31 with identical order and ratios must pass the colour check; a
glint with matching order and magnitude 1 against an expected composite must
be accepted by `agrees` with a finite magnitude tolerance once magnitude is
removed from the expected side.

## Related

[[BUG-001]] (order is categorical, never Hamming — the same insight, one field
over), [[BUG-002-unconstrained-threshold-aliasing]] (range constraints that the
new public scale parameter must also satisfy), [[EXP-003-presentation-attack-study]].
