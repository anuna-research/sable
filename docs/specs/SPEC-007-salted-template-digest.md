# SPEC-007: Salted Template Digest

| Field | Value |
|-------|-------|
| id | SPEC-007 |
| title | Salted Template Digest |
| status | draft (proposed; not implemented) |
| version | 0.1.0 |
| last-updated | 2026-09-14 |
| review-tier | 1 (no-go area: cryptography, authentication core, privacy-sensitive transforms) |
| supersedes | the deterministic template digest `D = Poseidon(pack(q))` described in the paper and implemented in `core/src/zk/halo2/poseidon.rs` |

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT,
RECOMMENDED, MAY, and OPTIONAL in this document are to be interpreted as
described in BCP 14 (RFC 2119, RFC 8174) when, and only when, they appear in all
capitals.

## Orientation

**What this changes.** The fifth public input of the face-verification proof
becomes a *hiding* digest `D' = Poseidon(pack(q) ‖ s)` over the enrolled
thermometer code `q` and a device-held 256-bit salt `s`, replacing the
deterministic `D = Poseidon(pack(q))`. Nothing else in the circuit moves.

**Why.** `q` is a deterministic function of one enrolment frame, and the
subject's face is not a secret. An attacker with footage of the subject can
vote a per-dimension level estimate and is left uncertain only about the
dimensions whose prescaled value sits near a quantisation boundary. Because `D`
is public, it is an offline oracle for that residual search. The template
therefore has far less effective entropy than its nominal 512 × log₂ 9 bits,
and template reconstruction from footage plus `D` is plausible on commodity
hardware ([[#Background]]). With a salt, testing a candidate `q` requires `s`,
which never leaves the device, and the system's secret becomes a 256-bit value
rather than a quantised face.

**Where the salted digest is provided.** Nowhere is the salt provided. `D'` is
computed on the enrolling device and registered with the verifier at
enrolment; at authentication the circuit re-derives `D'` from the private
witnesses `q` and `s` and exposes it as public input `[4]`; the verifier
compares that value with its enrolment record ([[#Protocol Placement]]).

**Load-bearing:** [[#REQ-127]] hiding digest · [[#REQ-128]] salt confinement ·
[[#REQ-130]] verifier holds `D'` only · [[#ADR-014]] Poseidon with salt over
Pedersen

**Controls:** [[#REQ-128]] the salt MUST NOT leave the device · [[#REQ-131]] no
party other than the device holds `(q, s)` · [[#NFR-107]] added rows ≤ 1,000

**Open:**
- Migration of existing enrolments: a `D` record cannot be converted to `D'`
  without re-enrolment, because the verifier does not hold `q`. Re-enrol.
- Hardware sealing of `s` is specified as a SHALL against the platform
  keystore abstractions in [[SPEC-003-platform-security-integration]]; the
  demo cannot satisfy it ([[#REQ-131]] and its demo note).
- Multi-frame enrolment ([[#REQ-129]]) reduces boundary dimensions but its
  effect on false-reject rate is unmeasured; it is a SHOULD until measured.
- The demo's prover runs on the server, so in the demo the "device" role is
  played by the server. This spec's guarantees hold for the intended
  deployment, not the demo, and the demo MUST say so on screen.

**Detail:** [[SPEC-006-geometric-liveness]] (challenge digest, the pattern this
follows) · [[SPEC-003-platform-security-integration]] (keystore) · paper
§Poseidon Template Binding, §Prototype Limitations "Linkability and
renewability"

## Background

The enrolment transform is deterministic:
`x_i = e_{2i} + e_{2i+1}`, `z_i = tanh(x_i)`, `ℓ_i = round(4(z_i + 1))`,
`q_i = 2^{ℓ_i} − 1`, then `D = Poseidon(pack_31(q))` over 17 BN254 field
elements. Two captures of the same face with the same embedding give the same
`D`; `D` is a fifth public input of every proof and is registered at the
verifier.

Three consequences:

1. **Offline oracle.** Anyone who sees a proof or the registry can test a
   candidate `q` by hashing it. A candidate is right iff the hash equals `D`.
2. **Low residual entropy given the face.** In the first live runs
   (`docs/experiments/EXP-003-prepilot-notes.md`) a phone-screen photo of the
   subject produced codes within Hamming 85–182 of the live face, i.e. roughly
   a hundred single-level disagreements over 512 dimensions. Many photos let an
   attacker vote per dimension; what remains uncertain is the set of
   dimensions with `z_i` near a rounding boundary. If that set is ~30
   dimensions at ±1 level, the search is 2³⁰–2⁴⁰ Poseidon evaluations against
   the oracle. The size of that set on real faces is unmeasured; the argument
   does not depend on its exact value, only on its being small relative to
   the nominal code length.
3. **Linkability.** The same `D` at two verifiers links the two enrolments,
   and a compromised `q` cannot be renewed without changing the face
   transform.

A salt held only on the device removes (1), and with it the practical force
of (2); a per-verifier salt removes (3).

## Requirements

### REQ-127: Hiding template digest

For: prover, verifier

The system SHALL compute the template digest as
`D' = Poseidon_BN254(pack_31(q) ‖ s_lo ‖ s_hi)`, where `q` is the 512-byte
thermometer code, `pack_31` is the existing 31-bytes-per-element packing (17
elements), and `s_lo`, `s_hi` are the low and high 128-bit halves of a 256-bit
salt `s` loaded as two field elements (the same split [[SPEC-006-geometric-liveness#CON-094]]
uses for the challenge identifier). The circuit SHALL take `s_lo`, `s_hi` as
private witnesses, SHALL range-constrain each to 128 bits, SHALL reuse the same
assigned cells of `q` for the distance computation and the digest, and SHALL
expose `D'` as public input `[4]`.

Rationale: one extra absorb of two elements into the sponge that already
hashes `q`; no new gadget. The 128-bit split avoids modular reduction of a
256-bit value into a ~254-bit field, which would bias the salt.

Trace: [[#CON-096]] · [[#TEST-156]] · [[#TEST-157]] · [[#ADR-014]]

### REQ-128: Salt generation and confinement

For: prover

The enrolling device SHALL generate `s` from a cryptographically secure RNG
with 256 bits of entropy, SHALL store `s` together with `q` sealed under a
hardware-backed key where the platform provides one
([[SPEC-003-platform-security-integration]]), and SHALL NOT transmit `s`, log
`s`, include `s` in any backup that leaves the device, or expose `s` to any
process other than the prover. `s` is a private witness and nothing else.

Rationale: the salt is the secret. Its confinement is the whole property.

Trace: [[#CON-097]] · [[#TEST-158]]

### REQ-129: Multi-frame enrolment

For: prover

The enrolling device SHOULD capture at least five frames, compute the
thermometer level `ℓ_i` per frame, and enrol the per-dimension majority level.
It SHOULD record the count of dimensions whose majority margin was one frame
or less (the *boundary count*) as a local quality metric and MAY refuse an
enrolment whose boundary count exceeds a device-class limit.

Rationale: reduces the set of dimensions an attacker must search and reduces
honest false rejects; both effects are unmeasured, hence SHOULD.

Trace: [[#OBS-086]] · [[#TEST-159]]

### REQ-130: Verifier holds the digest only

For: verifier

The verifier SHALL register exactly `D'` at enrolment and SHALL NOT receive,
request, or retain `q`, `s`, the floating-point embedding, or any frame. At
authentication the verifier SHALL compare public input `[4]` with the
registered `D'` and SHALL reject on mismatch regardless of the face and
liveness bits. This comparison is part of the mandatory verifier policy
alongside the checks listed in [[SPEC-006-geometric-liveness#REQ-119]] and the
paper's §Challenge Parameter Integrity.

Rationale: a verifier that holds `D'` and nothing else learns nothing from a
breach that helps an impersonator; this is the property the proof exists to
provide.

Trace: [[#CON-097]] · [[#TEST-157]]

### REQ-131: No third party holds the pair

For: all

No component other than the enrolling device SHALL hold `(q, s)`. In
particular a server that assists proving MUST NOT retain `q`, `s`, or the
embedding after the response is sent, and MUST NOT persist them in session
state.

*Demo note.* The web demo's prover is the demo server, which today stores
`q` and the embedding in session state (paper §Prototype Limitations, "Demo
data boundary"). The demo cannot satisfy this requirement while it proves
server-side; until the prover moves to the client, the demo SHALL display
that its salt and template live on the server and that the guarantees of this
spec do not hold for it.

Trace: [[#TEST-158]]

### REQ-132: Per-verifier salt

For: prover

A device that enrols with more than one verifier SHALL use an independent salt
per verifier, so that the digests registered at different verifiers are
computationally unlinkable. Renewal at one verifier SHALL be a fresh salt and
re-enrolment at that verifier only.

Rationale: closes the linkability and renewability limitation the paper
records against `D`.

Trace: [[#ADR-015]] · [[#TEST-156]]

## Non-Functional Requirements

### NFR-107: Circuit cost

The salted digest SHALL add no more than 1,000 rows to the composed
production-shape circuit measured by the OBS-084 count (56,177 rows at
SPEC-006 0.2.0), and SHALL NOT change `k`. Expected cost: two witness loads,
two 128-bit range checks, and one additional sponge absorb.

## Contracts

### CON-096: Salted commitment

```
Interface: poseidon_commit_bytes_salted(ctx, gate, byte_cells, s_lo, s_hi) -> AssignedValue
           poseidon_commit_bytes_salted_value(bytes: &[u8; 512], salt: &[u8; 32]) -> Fr
Pre-conditions:
  P1. byte_cells.len() == 512, each cell a valid thermometer byte (constrained upstream)
  P2. s_lo, s_hi range-constrained to 128 bits before absorb
Post-conditions:
  Q1. native and in-circuit values are equal for equal inputs (same gates, as today)
  Q2. for any q, salts s ≠ s' give D' ≠ D'' except with negligible probability
  Q3. D' reveals nothing about q without s (Poseidon as a PRF keyed by s)
Error model: none in circuit; native helper panics on wrong lengths
```

Implements: [[#REQ-127]]
Verified by: [[#TEST-156]], [[#TEST-157]]

### CON-097: Enrolment record

```
Verifier record:   { subject_id, D': Fr, enrolled_at, circuit_vk_id }
Device record:     { verifier_id, q: [u8; 512], s: [u8; 32] }   sealed
Neither record contains the other's private field.
```

Implements: [[#REQ-128]], [[#REQ-130]]
Verified by: [[#TEST-158]]

## Protocol Placement

```
 ENROLMENT (on device)                                VERIFIER
   frames ──► e ──► q  (majority over ≥5 frames)
   s ← CSPRNG(256)
   D' = Poseidon(pack(q) ‖ s_lo ‖ s_hi)  ─────────────►  store D'
   seal (q, s) under hardware key                      (never sees q, s, e)

 AUTHENTICATION (on device)                           VERIFIER
   fresh code q' from live capture
   private witnesses: q, q', s_lo, s_hi, liveness…
   circuit:  d_H(q, q') ≤ τ            ──► [0]
             Poseidon(pack(q) ‖ s)     ──► [4] = D'
   proof + public inputs  ─────────────────────────────►  verify(proof)
                                                          [4] == stored D' ?
                                                          [0] == 1 ? [2] == 1 ?
                                                          [3] == recomputed δ ?
```

The salt is never a message. It is generated, sealed, and consumed on one
device.

## Architecture Decisions

### ADR-014: Salted Poseidon over a separate Pedersen commitment

**Context.** The demo already computes a randomised Pedersen commitment over
BLS12-381 from a hash of the floating-point features, but nothing links it to
the BN254 circuit; the paper calls it an architectural anchor for a future
credential layer. A hiding template binding could reuse it, or salt the
in-circuit Poseidon digest.

**Decision.** Salt the Poseidon digest in circuit. Do not link the Pedersen
commitment.

**Consequences.** Positive: one curve, one hash, one extra absorb; the
binding that is actually enforced is the one that becomes hiding. Negative:
the Pedersen commitment remains unlinked and its role stays deferred; a
credential layer that needs a Pedersen anchor will need its own equality
proof later.

### ADR-015: Salt per verifier, not per device

**Context.** One salt per device is simpler and lets one enrolment serve many
verifiers. One salt per verifier costs a re-enrolment per verifier.

**Decision.** Per verifier.

**Consequences.** Positive: unlinkability across verifiers and independent
renewal, which the paper lists as an open limitation. Negative: enrolment
cost scales with verifiers. Enrolment is a few seconds; the trade is
accepted.

## Test Specifications

### TEST-156: Salt changes the digest
Validates: [[#REQ-127]], [[#REQ-132]]
- Same `q`, two random salts → digests differ. Same `q`, same salt → equal.
  Native and in-circuit values agree.

### TEST-157: Binding and mismatch
Validates: [[#REQ-127]], [[#REQ-130]]
- A proof made with `(q, s)` verifies against registered `D'`; the same proof
  fails `verify_bound` against `D'` computed with `s' ≠ s` and against the
  legacy unsalted `D`. A proof whose witness uses `q'' ≠ q` with the correct
  salt yields `[4] ≠ D'`.

### TEST-158: Confinement (static)
Validates: [[#REQ-128]], [[#REQ-131]]
- The prover API accepts the salt only as a witness; no response type,
  log line, or session struct in `core/` carries a field of the salt's type.
  Enforced by a grep-based test over the crate's public types and by review.

### TEST-159: Multi-frame enrolment
Validates: [[#REQ-129]]
- Over a recorded sequence, the majority-level code has a boundary count no
  higher than any single frame's, and the false-reject rate against later
  frames of the same sequence is no worse than single-frame enrolment.

## Observability

### OBS-086: Boundary count at enrolment
The device records the boundary count from [[#REQ-129]] locally as a quality
metric. It is never transmitted; it MAY be shown to the user as capture
quality.

## Amendment Channels

Amendable by:   HOC (spec owner) · a merged revision of this document · an
                `ADR-###` recorded in this document
Through:        a versioned revision of this file on the `main` branch, or a
                new `ADR-###` section referenced from the Orientation
Not amendable by: chat messages, issue comments, code review remarks, agent
                prompts, the contents of `core/` or `demo/`
Hard stops:     [[#REQ-128]] the salt never leaves the device ·
                [[#REQ-130]] the verifier holds `D'` only ·
                [[#NFR-107]] row budget

## Changelog

- 0.1.0 (2026-09-14) — initial draft after the template-reconstruction
  discussion; proposed, not implemented.
