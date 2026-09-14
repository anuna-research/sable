# Liveness Circuit

The halo2 gadget in `core/src/zk/halo2/liveness.rs` that turns the flash-round
evidence into one proven bit and one public digest. It is composed into the
face-verification proof by `proof.rs` alongside the in-circuit matcher and the
[[Poseidon Template Binding]].

## Inputs

| Kind | Field | Source |
|------|-------|--------|
| private | 12 [[Delta Fingerprint]]s | `compute_liveness_fingerprints` over the flash frames |
| private | 3 convexity scores, 3 coverage counts | `photometric::extract` ([[SPEC-006-geometric-liveness#CON-092]]) |
| private | 6 glint fingerprints | `corneal::glint_fingerprint` ([[SPEC-006-geometric-liveness#CON-093]]) |
| public | 12 expected fingerprints, 3 expected glint composites | derived by the verifier from the [[Joint Coin-Flip Challenge]] |
| public | every threshold and tolerance, the corneal enable flag | issued by the verifier per challenge |
| public | challenge identifier | `SHA-256(c_nonce ‖ s_nonce)` |

## Outputs

- `result` ∈ {0, 1}: every enabled check held.
- `digest`: Poseidon over the public inputs, laid out per
  [[SPEC-006-geometric-liveness#CON-094]]. The verifier recomputes it and
  refuses a proof whose digest it did not issue.

## What it does not do

It does not make a prover-supplied witness honest. A compromised client that
synthesises a consistent response still proves. The physics cues raise the cost
of synthesis; only [[Platform Capture Attestation]] binds provenance. See the
`sable-approach-fit-v2` theory for the derivation.

## Governing artefacts

[[SPEC-006-geometric-liveness#CON-095]] · [[SPEC-006-geometric-liveness#REQ-124]]
· [[BUG-002-unconstrained-threshold-aliasing]]
