# BUG-002: Unconstrained thresholds alias inside the challenge digest packing

| Field | Value |
|-------|-------|
| id | BUG-002 |
| severity | High — soundness of the proven liveness relation |
| priority | P1 — fixed in the same revision that migrates the digest |
| status | open (fix specified, implementation in progress) |
| found | 2026-09-14, review of [[SPEC-006-geometric-liveness]] 0.1.0 packing |
| root cause class | Missing input validation at a trust boundary |

## Specification Reference

[[SPEC-006-geometric-liveness#REQ-117]] (digest), [[SPEC-006-geometric-liveness#REQ-124]]
(the fix), [[SPEC-006-geometric-liveness#CON-094]], [[SPEC-006-geometric-liveness#CON-095]].

## Environment

`core/src/zk/halo2/liveness.rs` as of commit `5d0876e`, `challenge_digest` and
`LivenessCheckCircuit::build_circuit`. halo2-lib on BN254, K=14 standalone,
K=16 composed.

## Steps to Reproduce

1. Take any passing witness with `color_threshold = t`, `spatial_threshold = s`.
2. Build a second witness with `color_threshold = t + 256` and
   `spatial_threshold = s − 1`, everything else equal.
3. Compute the challenge digest for both.

## Expected Behaviour

The second witness is rejected, or at minimum produces a different digest, so a
verifier recomputing the digest from `(t, s)` refuses the proof.

## Actual Behaviour

Both witnesses produce the same digest. The packing is
`color_t · 2^192 + spatial_t · 2^200 + …` with `color_t` and `spatial_t` loaded as
unconstrained field witnesses. `(t + 256) · 2^192 + (s − 1) · 2^200 = t · 2^192 +
s · 2^200`. The circuit then evaluates the colour check against `t + 256`, which
every fingerprint pair satisfies, and the spatial check against `s − 1`, which is
looser. The proof verifies against the honest digest.

The same construction applies between `spatial_threshold` and `min_magnitude`
(offset 2^200 → 2^208), and — since the fingerprint slots are 16 bits and the
expected fingerprints are decomposed to 16 boolean-constrained bits — does **not**
apply to the fingerprints. The defect is confined to the three threshold fields,
which are exactly the fields that decide how strict the relation is.

## Evidence

`liveness.rs:232-234` loads the thresholds with `ctx.load_witness` and no range
constraint; `liveness.rs:319-329` multiplies them by fixed powers of two and sums.
No `decompose` or `range_check` touches them. Confirmed by reading; a reproducing
test is [[SPEC-006-geometric-liveness#TEST-151]].

## Root Cause

**Input validation missing at a trust boundary.** The witness is prover-supplied.
Fields packed at adjacent offsets are only independent when each is constrained
to its slot width. The 0.1.0 design constrained the fingerprints (because the
Hamming gadget needed bits) and not the thresholds (because the comparison gadget
did not), and the digest inherited the gap.

## Resolution

[[SPEC-006-geometric-liveness#REQ-124]]: every field that enters the digest is
decomposed to its declared width in circuit before use, and the native
recogniser ([[SPEC-006-geometric-liveness#CON-095]]) rejects out-of-range
fields before synthesis. The Poseidon migration ([[SPEC-006-geometric-liveness#ADR-009]])
does not by itself fix this — packed limbs alias identically — which is why the
range constraint is a separate requirement rather than a side effect.

Regression test: [[SPEC-006-geometric-liveness#TEST-151]].
