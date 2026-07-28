# BUG-001: Liveness colour check accepts opposite colours

**Severity:** S2 — Major
**Priority:** P1
**Status:** confirmed
**Reported by:** agent (Claude Opus 5) during [[SPEC-006-geometric-liveness]] Phase 3
**Assigned to:** unassigned

## Specification Reference

- Violates: the colour-match obligation of [[SPEC-001-B-zk-liveness-integration]],
  realised as the `color_threshold` check in `core/src/zk/halo2/liveness.rs`
- Related: no existing TEST covers cross-colour discrimination, which is why this
  survived — see Root Cause

## Environment

- `core/src/zk/halo2/liveness.rs` (in-circuit check), encoder previously at
  `demo/server/src/flash_challenge.rs:388`, now `core/src/biometric/fingerprint.rs`
- Detected by: Red Gate test `glint_matching_the_previous_round_is_rejected`
- Detection method: test generation from [[SPEC-006-geometric-liveness#REQ-115]]
- Confidence: high — directly observed and reproduced

## Steps to Reproduce

1. Encode two saturated colours with `quantize_delta` / `quantize_colour`.
2. Take the Hamming distance between the resulting fingerprints.
3. Observe the distance for perceptually opposite colours.

Measured distance matrix:

```
              red   green    blue  yellow    cyan magenta
     red        0       1       1       4       6       5   fp=0x001f
   green        1       0       2       5       5       6   fp=0x401f
    blue        1       2       0       5       7       6   fp=0x801f
  yellow        4       5       5       0       2       1   fp=0x1e1f
    cyan        6       5       7       2       0       1   fp=0x7e1f
 magenta        5       6       6       1       1       0   fp=0x3e1f
```

## Expected Behaviour

A response reflecting a colour materially different from the challenge colour
should fail the colour-match check.

## Actual Behaviour

With the in-circuit `color_threshold` of 3, **green and blue both satisfy a red
challenge** (distance 1). All three primaries are mutually within distance 2.
Conversely red and yellow are distance 4 and are *rejected*, though yellow is far
closer to red than blue is. The ordering the check induces is close to unrelated
to colour similarity.

## Evidence

The matrix above, produced against the shipped encoder. Reproduced as a
regression test — see Resolution.

## Root Cause

- **Category:** design-error
- **Analysis:** the fingerprint packs a 3-bit `order` field that is
  **categorical** — one of six orderings of R/G/B by magnitude. Hamming distance
  is only meaningful over fields where bit-adjacency implies value-adjacency. It
  does not hold here: order 0 (`R≥G≥B`) and order 4 (`B≥R≥G`) are one bit apart
  and denote opposite colour directions.

  For saturated colours the `mid_ratio`, `min_ratio` and `magnitude` fields are
  identical (`0`, `0`, `31`), so the entire distance is carried by those three
  categorical bits — of which at most 3 can ever differ. The check cannot separate
  colours that differ only in channel ordering, which is exactly the discrimination
  the spatial-flash protocol depends on.

  This is a design error rather than an implementation error: the encoder and the
  circuit each do what they were specified to do. The defect is in composing a
  categorical code with a metric that assumes ordinality.

- **Why no test caught it:** the existing fingerprint tests assert *self*-distance
  and same-direction/different-magnitude behaviour. None asserts that a *wrong*
  colour is rejected — a missing negative-output test in the sense of
  [[PROTO-001]] requirement-targeted decomposition.

## Impact

The colour-match half of the spatial-flash liveness check does not constrain
colour as intended. An artefact reflecting the wrong primary satisfies it. This
weakens, but does not by itself defeat, the protocol: the spatial-differentiation
check and [[SPEC-006-geometric-liveness#REQ-113]] are independent.

Because the check is inside the proven relation, its verdict is what a verifier
relies on — so this is a soundness-relevant defect, not a UX one.

## Proposed Resolution

Compare the fields by their own semantics rather than as an undifferentiated bit
string:

- `order` — **categorical**: require exact equality, or a caller-supplied
  permitted-substitution set. Never a bit distance.
- `mid_ratio`, `min_ratio`, `magnitude` — **ordinal**: bounded absolute
  difference per field.

Both are cheap in-circuit: equality is one constraint, and bounded difference
reuses the existing range-check machinery. Neither needs a new gadget.

Measurable acceptance criterion: with the resolution in place, the distance
relation MUST reject every ordered pair from the matrix above whose channel
ordering differs, at whatever threshold is chosen for the ordinal fields.

## Resolution

- **Fix:** not yet applied to the in-circuit check. `core/src/biometric/corneal.rs`
  uses the structured comparison above rather than Hamming distance, so
  [[SPEC-006-geometric-liveness#REQ-115]] is unaffected.
- **Verified by:** `corneal::tests::glint_matching_the_previous_round_is_rejected`,
  `fingerprint::tests::hamming_is_not_a_colour_metric` (regression, records the
  defect explicitly)
- **Regression test added:** yes
- **Outstanding:** the `color_threshold` check in `core/src/zk/halo2/liveness.rs`
  still uses Hamming distance and remains affected. Fixing it changes a proven
  relation and therefore requires the Tier 1 review that
  [[SPEC-006-geometric-liveness]] records as outstanding.
