# SPEC-006: Geometric and Corneal Liveness Cues

| Field | Value |
|-------|-------|
| id | SPEC-006 |
| title | Geometric and Corneal Liveness Cues |
| status | draft |
| version | 0.2.0 |
| last-updated | 2026-09-14 |
| review-tier | 1 (no-go area: cryptography, authentication core, privacy-sensitive transforms) |

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT,
RECOMMENDED, MAY, and OPTIONAL in this document are to be interpreted as
described in BCP 14 (RFC 2119, RFC 8174) when, and only when, they appear in all
capitals.

## Orientation

**Intent:** The existing spatial-flash check proves that face quadrants reflect
*different colours*. It does not prove the face has *shape*. This spec adds two
cues that do — a geometric one derived from light already being emitted, and a
corneal one — without new capture hardware, and carries both into the
[[Liveness Circuit]] so the proof, not the server, enforces them. Version 0.2.0
also binds the proof to the [[Joint Coin-Flip Challenge]] that produced the flash
pattern, so a proof answers one challenge and no other.

**Metaphor:** The screen is already a four-lamp photographic studio firing three
times. Today we only check that the lamps were different colours; this spec reads
the *shadows*.

**Structure:**

```
  baseline + 3 flash frames
        │
        ▼
  ┌──────────────────┐   patch responses   ┌────────────────────┐
  │ Photometric      │────────────────────▶│ Per-patch spread   │
  │ extractor        │   per quadrant      │ + convexity score  │
  │ [[#CON-092]]     │                     │ (pure core)        │
  └──────────────────┘                     └─────────┬──────────┘
        │                                            │
        │ eye region                                 │ 4-bit spread codes
        ▼                                            ▼
  ┌──────────────────┐   u16 fingerprint   ┌────────────────────┐
  │ Corneal glint    │────────────────────▶│ Liveness circuit   │
  │ [[#CON-093]]     │  (existing encoder) │ [[#CON-095]] k=16  │
  └──────────────────┘                     │  coverage ≥ floor  │
                                           │  convexity ≥ floor │
  c_nonce ‖ s_nonce ──▶ challenge_id ─────▶│  glint ≈ composite │
        (SHA-256, both sides)              │  Poseidon digest   │
                                           │  [[#CON-094]]      │
                                           └─────────┬──────────┘
                                                     │ public: result, digest
                                                     ▼
                                             verifier recomputes digest
                                             from nonces + thresholds
        arrows point inward → the circuit never calls the extractors
```

**Decisions:** [[#ADR-007]] response contrast instead of an explicit normal
solve · [[#ADR-008]] reuse the existing quantiser for the glint · [[#ADR-009]]
Poseidon digest replaces the 216-bit packing · [[#ADR-010]] thresholds ship unset
· [[#ADR-011]] nonces bound by digest, HKDF stays verifier-side · [[#ADR-012]]
field-wise glint comparison in circuit, never Hamming

**Load-bearing:** [[#REQ-113]] convexity discriminator · [[#REQ-115]] corneal
agreement · [[#REQ-117]] digest migration · [[#REQ-119]] nonce binding ·
[[#REQ-121]] in-circuit convexity floor · [[#REQ-123]] no Hamming on the glint ·
[[#NFR-104]] circuit row budget

**Controls:** [[#REQ-123]] prohibits Hamming comparison of the glint in circuit ·
[[#REQ-124]] requires every digest field to be range-constrained to its declared
width ([[BUG-002-unconstrained-threshold-aliasing]]) · [[#ADR-010]] no threshold
default enters the relation · [[#NFR-104]] row budget is a hard stop before k=17

**Enable path:** every new check is switched on by its public threshold. A
threshold of zero (or `corneal_enabled = 0`) makes the check vacuous, and because
thresholds are inside the digest the verifier can see which checks were live.
Rollback is the verifier refusing digests whose thresholds it did not issue. No
redeploy is needed to change a threshold; the verifier issues it per challenge.

**Open:**
- [[BUG-003-expected-fingerprint-magnitude-mismatch]]: expected fingerprints
  carry emitted-colour magnitude (31) while observed carry reflected-delta
  magnitude (0–2 on a webcam), so the 0.1.0 colour check yields
  `liveness = 0` for real faces and the corneal check cannot be armed at a
  finite magnitude tolerance. Fix proposed there; blocks EXP-003 thresholds.
- Operating thresholds cannot be set without a presentation-attack study —
  see [[#ADR-010]] and [[EXP-003-presentation-attack-study]] (owner: HOC). This
  spec ships the mechanism, not the constants.
- Eye localisation is out of scope; [[#CON-093]] takes a pre-cropped region.
  The demo client localises the irises with the Human face-mesh iris model and
  sends per-eye PNG crops; the server fingerprints them and carries the glints
  and expected composites in the witness. The check is live only when the
  operator sets `SABLE_CORNEAL_TOLERANCE=<ratio>,<magnitude>`; otherwise
  `corneal_enabled = 0` (ADR-010). Selecting a production
  [[Face Landmark Model]] remains deferred (owner: HOC).
- The demo server calls the photometric extractor per round and carries
  `responding_patches` and `convexity_scores` in the witness, but runs the
  circuit with both floors at zero, so the checks are vacuous until
  [[EXP-003-presentation-attack-study]] fixes the constants. The per-round
  values are logged and returned in the prove response for that study.
- In-circuit HKDF derivation of the expected fingerprints is deferred; the
  verifier derives them and the digest binds them to the nonces
  ([[#ADR-011]]). Ceiling recorded there.
- The rolling-shutter timing axis is not in this spec. It enters as its own REQ
  set only after [[EXP-002-rolling-shutter-hardware]] passes.
- Tier 1 review obligation (cross-model adversarial review + human domain
  expert) is **not** satisfied by the authoring session (owner: HOC).

**Detail:** [[SPEC-001-A-rgb-liveness-detection]] ·
[[SPEC-001-B-zk-liveness-integration]] · [[PROTO-001]]

## Background

`compute_liveness_fingerprints` reduces each face quadrant to a mean RGB delta and
encodes it with [[Delta Fingerprint]] — a purely *chromatic* code of channel
ordering, two ratios, and magnitude. The in-circuit "spatial" test is a Hamming
distance between those codes, so it fires when adjacent face regions reflect
different colours. Since the screen quadrants *emit* different colours, geometry
enters only through second-order mixing weights.

Meanwhile each round lights four quadrants **simultaneously** with four
HKDF-derived colours and captures one frame. That is a colour-multiplexed
[[Photometric Stereo]] rig: four known light directions, colour-demultiplexed,
three times over. The capture is already correct; the extraction discards the
geometry. This spec recovers it.

## Requirements

### REQ-111: Patch-grid photometric response extraction

The system SHALL compute, for each patch of an N×N grid over the face region and
each of the four quadrant lights, a scalar response equal to the projection of
that patch's mean RGB delta onto the quadrant's emitted colour direction, FOR
every flash round, WITH the grid dimension N configurable and defaulting to 4.

Rationale: projecting onto the known emitted colour demultiplexes the four
simultaneous lights without solving a linear system, which keeps the extractor at
Simplicity Ladder rung 5.

Trace: [[#TEST-135]] · [[#CON-092]]

### REQ-112: Per-patch illumination mix

The system SHALL derive, for each patch, a normalised mix vector whose four
components are that patch's quadrant responses divided by their sum, WITH the
vector set to all-zero when the sum is zero.

Rationale: the mix is the patch's *relative* illumination by the four lamps. It
is scale-free, so it discards exposure and albedo while retaining the geometric
signal.

Trace: [[#TEST-136]] · [[#CON-092]]

### REQ-113: Convexity discriminator

The system SHALL compute a scalar convexity score equal to the mean over
**responding** patches of the L1 distance between that patch's mix vector and the
mean mix vector of responding patches, expressed as Q15 fixed point over [0, 2],
AND SHALL report zero when fewer than two patches responded.

A patch is *responding* when at least one of its four quadrant responses is
non-zero.

Rationale: what distinguishes a face from a photograph is not how any single
patch is lit but how the lighting *varies across* patches. A plane presents
essentially the same normal everywhere, so every patch receives the same relative
mix of the four lamps and the cross-patch variation is small. A convex surface
rotates its normal from patch to patch, swinging the mix toward whichever lamp
each patch faces. Simulated: plane 0.0129, hemisphere 0.0375 — a 2.9× separation.

Because each mix is normalised before comparison, the score is invariant to
exposure and albedo, satisfying [[#NFR-106]].

Restricting to responding patches is load-bearing, not a tidiness measure.
Averaging over *all* patches lets missing signal masquerade as geometry: on a 4×4
grid, eight identical responding patches beside eight dark ones score 16,384 —
thirteen times the hemisphere's 1,243 — purely because the zero mixes drag the
mean to the midpoint. Absence of evidence MUST NOT read as evidence.

Two formulations were specified, implemented, tested against synthetic geometry,
and **rejected** before this one. Both are recorded in [[#ADR-007]] because both
are intuitive and a future reader will otherwise re-propose them.

Trace: [[#TEST-137]] · [[#CON-092]] · [[#NFR-106]]

### REQ-118: Coverage reporting

The system SHALL report the number of responding patches alongside the convexity
score, FOR each flash round.

Rationale: coverage is the only signal separating "the subject is flat" from "the
subject was barely lit", and a score derived from two patches is not evidence.
Consumers gate on coverage before trusting the score; the floor is caller-supplied
per [[#ADR-010]].

Trace: [[#TEST-145]] · [[#CON-092]]

### REQ-114: Corneal glint fingerprint extraction

The system SHALL encode the mean RGB delta of a supplied corneal region using the
existing [[Delta Fingerprint]] encoder, FOR each eye and each flash round,
producing one 16-bit fingerprint per eye per round.

Trace: [[#TEST-138]] · [[#CON-093]] · [[#ADR-008]]

### REQ-115: Corneal agreement with the challenge sequence

The system SHALL verify that each eye's glint fingerprint agrees with the
fingerprint of the *area-weighted composite* of the four quadrant colours for
that round, WHERE agreement requires exact equality of the categorical `order`
field and per-field bounded difference of the ordinal fields.

The comparison MUST NOT be a Hamming distance over the packed fingerprint. See
[[BUG-001-hamming-over-categorical-order-field]]: `order` is categorical, so a bit
distance rates red and blue as one apart while red and yellow are four apart, and
would accept a blue glint against a red challenge.

Rationale: the cornea is a convex mirror whose virtual image of the screen is
approximately 3 px across at phone viewing distance (see [[#ADR-008]]), so the
resolvable quantity is the glint's overall colour, not its spatial structure.
Security derives from *temporal* agreement — the composite changes per round under
an unpredictable HKDF sequence, so a static artefact or pre-recorded replay cannot
track it.

Trace: [[#TEST-139]] · [[#CON-093]]

### REQ-116: Witness binding

The system SHALL include every public parameter of the liveness relation in the
challenge digest — the twelve expected fingerprints, the three legacy thresholds,
the coverage floor, the convexity floor, the corneal enable flag and tolerances,
the three expected glint composites, and the challenge identifier — SO THAT a
prover cannot substitute a parameter the verifier did not issue.

Private witnesses (delta fingerprints, convexity scores, coverage counts, glint
fingerprints) are NOT in the digest. They are what the proof hides.

Trace: [[#TEST-140]] · [[#CON-094]]

### REQ-117: Challenge digest migration

The system SHALL compute the challenge digest as a Poseidon hash over the
parameter vector INSTEAD OF a bit-packing into a single field element.

Rationale: the existing packing consumes 216 of 254 available bits
(`12×16 + 3×8`). The witness fields added by [[#REQ-116]] exceed the remainder.

Trace: [[#TEST-141]] · [[#CON-094]] · [[#ADR-009]]

### REQ-119: Challenge nonce binding

For: verifier

WHEN a liveness proof is generated, the system SHALL include in the challenge
digest a 256-bit challenge identifier equal to `SHA-256(c_nonce ‖ s_nonce)`,
carried as two 128-bit limbs.

Rationale: the flash pattern is derived from the joint coin-flip
(`HKDF(c_nonce ‖ s_nonce)`, see [[Joint Coin-Flip Challenge]]). Today the digest
binds the *expected fingerprints* but not the nonces they came from, so the
relation the proof establishes is "this response matches these fingerprints",
and the link from fingerprints back to a specific fresh challenge lives only in
the verifier's process. Binding the identifier makes "this response answers
challenge X" part of the proven statement, so a proof cannot be re-presented
against a second session that happened to issue the same colours.

The identifier is a hash of both nonces rather than the nonces themselves because
each nonce is 256 bits and the two together would need four limbs for no gain:
the verifier already knows both and can recompute the hash.

Acceptance:
- Two witnesses identical except for the challenge identifier produce different
  digests.

Trace: [[#TEST-146]] · [[#CON-094]] · [[#ADR-011]]

### REQ-120: In-circuit coverage floor

For: verifier

WHEN `min_coverage > 0`, the system SHALL constrain, for every flash round, that
the number of responding patches is at least `min_coverage`, AND SHALL set the
liveness result to zero when any round falls below it.

Rationale: [[#REQ-118]] made coverage a reported value. Reporting is not
enforcing. A convexity score over two patches is not evidence, and the check that
says so must be in the relation, not in the caller.

Acceptance:
- A witness with one round at `min_coverage − 1` responding patches yields
  result 0.
- A witness with every round at exactly `min_coverage` yields result 1 when all
  other checks pass.

Trace: [[#TEST-147]] · [[#CON-095]]

### REQ-121: In-circuit convexity floor

For: verifier

WHEN `min_convexity > 0`, the system SHALL constrain, for every flash round, that
the convexity score is at least `min_convexity`, AND SHALL set the liveness
result to zero when any round falls below it.

Rationale: this is the geometry axis. The score is prover-supplied, so the
circuit does not make it honest; what it does is fix the threshold the server
may not lower after the fact, and it makes a pass a *proven* pass rather than a
server assertion. Per [[#ADR-010]] the floor ships with no default.

Acceptance:
- A witness with one round at `min_convexity − 1` yields result 0.
- A witness with every round at exactly `min_convexity` yields result 1 when all
  other checks pass.

Trace: [[#TEST-148]] · [[#CON-095]]

### REQ-122: In-circuit corneal agreement

For: verifier

WHEN `corneal_enabled = 1`, the system SHALL constrain, for each eye and each
flash round, that the glint fingerprint's categorical `order` field equals the
expected composite's `order` field AND that each ordinal field (`mid_ratio`,
`min_ratio`, `magnitude`) differs from the composite's by no more than the
corresponding public tolerance, AND SHALL set the liveness result to zero when
any eye in any round disagrees.

Rationale: this is the sequence axis. The composite changes per round under the
HKDF sequence, so an artefact that reflects a stale challenge fails at the
categorical field regardless of tolerance. Moving the check from
[[#CON-093]]'s `agrees` into the circuit gives the same guarantee as
[[#REQ-121]]: the tolerances are fixed in the digest and a pass is proven.

Acceptance:
- Glints equal to each round's composite pass under tolerance zero.
- A glint equal to the *previous* round's composite fails under the maximum
  ordinal tolerances (15, 15, 31).

Trace: [[#TEST-149]] · [[#CON-095]] · [[#ADR-012]]

### REQ-123: No Hamming comparison of the glint in circuit

The system SHALL NOT compare a glint fingerprint against its expected composite
by Hamming distance WHEN enforcing [[#REQ-122]].

Rationale: [[BUG-001-hamming-over-categorical-order-field]]. The `order` field
is categorical; a bit distance rates red and blue one apart. The existing
`color_threshold` check is Hamming-based and remains affected; this requirement
stops the defect propagating into the new check.

Trace:
- [[#TEST-150]] (prohibited-action)
- [[#TEST-152]] (scope-invariant)

### REQ-124: Range-constrained digest fields

The system SHALL constrain every field that enters the challenge digest to its
declared bit width in circuit BEFORE that field is used in any check or packed
into a digest limb.

Rationale: [[BUG-002-unconstrained-threshold-aliasing]]. The 0.1.0 packing
loads `color_threshold`, `spatial_threshold` and `min_magnitude` as unconstrained
witnesses at adjacent 8-bit offsets. A prover can choose
`color_threshold' = color_threshold + 256` and
`spatial_threshold' = spatial_threshold − 1`, which packs to the *same* digest
the verifier recomputes, while the circuit's checks run against the looser
`color_threshold'`. Any field that is packed beside another field, in a bit
packing or inside a Poseidon limb, has this aliasing unless its width is
enforced.

Acceptance:
- A witness whose thresholds are aliased as above is unsatisfiable: the circuit
  rejects it at synthesis rather than producing a matching digest.

Trace:
- [[#TEST-151]] (prohibited-action)
- [[#CON-095]]

## Non-Functional Requirements

### NFR-104: Circuit row budget

Added in-circuit constraints SHALL consume ≤ 8,000 advice rows UNDER the k=16
production shape WITH the existing circuit measured at 54,042 of 65,536 rows.

Rationale: exceeding the remaining ~11,494 rows forces k=17 and approximately
doubles proving time from the published 1.19 s.

Trace: [[#TEST-142]] · [[#OBS-084]]

### NFR-105: Extraction latency

Patch-grid extraction SHALL complete in ≤ 50 ms per round UNDER a 640×480 face
region on an Apple M-series CPU WITH 95th percentile.

Trace: [[#TEST-143]]

### NFR-106: Albedo invariance

The convexity score SHALL vary by ≤ 5 units of 255 UNDER a uniform scaling of all
input pixel intensities in the range [0.5, 2.0].

Rationale: a scale-invariant discriminator is invariant to exposure *and* to skin
tone, which removes a demographic-fairness failure mode that absolute-amplitude
measures carry.

Trace: [[#TEST-144]]

## Contracts

### CON-092: Photometric extractor

```
Interface: photometric::extract(baseline, flash, quadrant_colours, grid) -> PhotometricRound
Pre-conditions:
  P1. baseline and flash have identical dimensions, each ≥ 64×64
  P2. grid.n ∈ [2, 8]
  P3. quadrant_colours contains exactly 4 entries
Post-conditions:
  Q1. responses has exactly grid.n² × 4 entries          (REQ-111)
  Q2. each patch mix sums to Q15 unity, or is all-zero    (REQ-112)
  Q3. convexity_score ∈ [0, 65535] as Q15 over [0,2]      (REQ-113)
  Q4. convexity_score = 0 when responding_patches < 2     (REQ-113)
  Q5. responding_patches ∈ [0, grid.n²]                   (REQ-118)
Error model: SableError::InvalidInput on any precondition violation; no partial output.
```

**Input grammar** (LangSec, Constitutional Principle 14). The extractor sits at a
trust boundary — frames originate outside the enclave. The accepted language is
regular and fully recognised before any arithmetic:

Both dimension bounds are enforced. The upper bound is not decorative: without
it `width × height × 3` wraps on a 64-bit target, so declared dimensions of
3_062_868_337 × 2_007_567_422 reduce to an expected length of 26 bytes and a
26-byte buffer passes the length check. The product is additionally computed with
checked arithmetic as defence in depth.

```abnf
frame        = width height pixel-array
width        = %d64-4096
height       = %d64-4096
pixel-array  = 3(width * height) OCTET   ; RGB8, no padding, no stride
grid-n       = %d2-8
quad-colours = 4 rgb
rgb          = 3OCTET
```

Implements: [[#REQ-111]], [[#REQ-112]], [[#REQ-113]]
Verified by: [[#TEST-135]], [[#TEST-136]], [[#TEST-137]], [[#TEST-144]]

### CON-093: Corneal extractor

```
Interface: corneal::glint_fingerprint(baseline_eye, flash_eye) -> u16
           corneal::expected_composite(colours, area_weights) -> u16
           corneal::agrees(observed, expected, max_ratio_delta, max_magnitude_delta) -> bool
Pre-conditions:
  P1. baseline_eye and flash_eye have identical dimensions, each ≥ 8×8
Post-conditions:
  Q1. output is a valid Delta Fingerprint: order ≤ 5                 (REQ-114)
  Q2. a zero delta yields fingerprint 0                              (REQ-114)
  Q3. agreement requires order equality, never a bit distance        (REQ-115)
Error model: SableError::InvalidInput on precondition violation.
```

Eye localisation is **not** part of this contract; the caller supplies a cropped
region. See [[#Open]].

Implements: [[#REQ-114]], [[#REQ-115]]
Verified by: [[#TEST-138]], [[#TEST-139]]

### CON-094: Challenge digest

```
Interface: challenge_digest(witness: &LivenessWitness) -> Fr
           (native) — evaluates the identical in-circuit gadget in witness-
           generation mode, so native and in-circuit values cannot diverge
Pre-conditions:
  P1. witness recognised by CON-095 (every field within its declared width)
Post-conditions:
  Q1. digest = Poseidon(limb0 ‖ limb1 ‖ limb2 ‖ limb3) where
        limb0 = Σ_i expected_fp[i] · 2^(16·i)                      (192 bits)
        limb1 = color_t ‖ spatial_t ‖ min_mag ‖ min_coverage ‖
                corneal_enabled ‖ glint_ratio_tol ‖ glint_mag_tol ‖
                min_convexity ‖ expected_glint[0..3]                (≤ 120 bits)
        limb2 = challenge_id[0..16]  little-endian                  (128 bits)
        limb3 = challenge_id[16..32] little-endian                  (128 bits)
  Q2. digest is collision-resistant over the public parameter set   (REQ-117)
  Q3. changing any single public field changes the digest           (REQ-116)
  Q4. changing the challenge identifier changes the digest          (REQ-119)
  Q5. no private witness field participates                         (REQ-116)
Error model: total function over a recognised witness.
```

Packing several narrow fields into one limb is deliberate: Poseidon cost scales
with the number of absorbed elements, and four limbs is two permutations where
twenty-four bare fields would be twelve. The packing is sound only because
[[#REQ-124]] enforces every field's width in circuit; without that the limb has
the aliasing defect of the 0.1.0 packing.

Implements: [[#REQ-116]], [[#REQ-117]], [[#REQ-119]]
Verified by: [[#TEST-140]], [[#TEST-141]], [[#TEST-146]]

### CON-095: Liveness witness

```
Interface: LivenessCheckCircuit::build_circuit(builder) -> (result, digest)
           LivenessWitness::recognise(&self) -> Result<()>
Pre-conditions (recognised natively AND range-constrained in circuit):
  P1. delta_fingerprints[12], expected_fingerprints[12]     each ≤ 0xFFFF
  P2. color_threshold, spatial_threshold, min_magnitude     each ≤ 0xFF
  P3. responding_patches[3]                                 each ≤ 64
  P4. min_coverage                                          ≤ 64
  P5. convexity_scores[3], min_convexity                    each ≤ 0xFFFF
  P6. corneal_enabled                                       ∈ {0, 1}
  P7. glint_fingerprints[6], expected_glints[3]             each ≤ 0xFFFF
  P8. glint_ratio_tolerance ≤ 15, glint_magnitude_tolerance ≤ 31
  P9. challenge_id                                          32 octets
Post-conditions:
  Q1. result ∈ {0, 1}
  Q2. result = 1  iff  every check in REQ-111..REQ-122 that is enabled holds
  Q3. digest satisfies CON-094
  Q4. with min_coverage = min_convexity = corneal_enabled = 0 the result equals
      the 0.1.0 result for the same twelve fingerprints and thresholds
Error model: native recogniser returns SableError::InvalidInput; an in-circuit
             width violation is unsatisfiable (no proof exists).
```

**Input grammar** (LangSec, Constitutional Principle 14). The witness crosses a
trust boundary — the prover supplies it. The language is regular and is
recognised twice: natively before synthesis so a malformed witness fails fast,
and in circuit so a prover who skips the native check gains nothing.

```abnf
witness        = 12fp 12fp thresholds geometry corneal challenge-id
fp             = %x0000-FFFF
thresholds     = u8 u8 u8                  ; color, spatial, min_magnitude
geometry       = 3coverage u8 3fp fp       ; responding, min_coverage,
                                           ; convexity, min_convexity
coverage       = %d0-64
corneal        = bit ratio-tol mag-tol 6fp 3fp
bit            = %d0-1
ratio-tol      = %d0-15
mag-tol        = %d0-31
challenge-id   = 32OCTET
```

Implements: [[#REQ-120]], [[#REQ-121]], [[#REQ-122]], [[#REQ-123]], [[#REQ-124]]
Verified by: [[#TEST-147]], [[#TEST-148]], [[#TEST-149]], [[#TEST-150]],
[[#TEST-151]], [[#TEST-152]]

## Architecture Decisions

### ADR-007: Response contrast instead of an explicit normal solve

**Context.** Recovering surface normals from the four-lamp rig is the textbook
[[Photometric Stereo]] approach, requiring a per-patch least-squares solve.

**Decision.** Score the *cross-patch variation* of the normalised illumination
mix, rather than solving for normals.

**Consequences.** Positive: no linear algebra, no calibration of absolute light
directions, and the mix is normalised so the score tolerates unknown pose,
exposure, and albedo. Negative: strictly less information than a normal field —
it distinguishes convex from flat but not convex from a well-formed 3D mask.
Simplicity Ladder rung 5 rather than 6.

**Alternatives rejected — both were implemented and falsified by [[#TEST-137]].**

1. *Nearest-lamp agreement.* "Each patch's nearest lamp dominates." With lamps at
   finite distance the nearest lamp dominates on a plane too, through
   inverse-square falloff alone: simulated plane and hemisphere **both scored
   16/16**.
2. *Per-patch response contrast.* "The strongest and weakest lamp responses differ
   more on a curved surface." They do not, measurably: simulated plane 0.6462,
   hemisphere 0.6446 — no separation, and the wrong sign. The reason is
   instructive: projecting a delta onto four lamp colours measures the delta's
   *colour direction* against a fixed colour set. That is a chromatic quantity —
   the same class of measurement as the existing [[Delta Fingerprint]], and
   therefore the very weakness this spec exists to remove.

   The lesson generalises: with four lamps and three colour channels the system is
   underdetermined, so no single frame can fully demultiplex four lamps. Only the
   *spatial* pattern of the mix carries geometry.
3. *Full normal solve* — rung 6, and needs a calibrated [[Device Profile]] to fix
   the absolute light directions.

### ADR-008: Reuse the existing fingerprint encoder for the corneal glint

**Context.** The corneal virtual image of an object subtending angle θ has size
`(R/2)·θ` with `R ≈ 7.8 mm`. Against an 11.7 mm iris and a 1920 px front camera
at 70° HFOV, a phone screen at arm's length yields a glint ≈ 3 px across — about
1.5 px per cell of a 2×2 pattern.

**Decision.** Encode the glint's *mean* colour with the existing
[[Delta Fingerprint]] encoder and check it with the existing in-circuit Hamming
gadget. Do not attempt to resolve spatial structure within the glint.

**Consequences.** Positive: Simplicity Ladder rung 4 — no new encoder, no new
circuit gadget, and the design survives contact with the optics. Negative:
weaker per-round evidence; security rests on agreement across the three-round
sequence rather than within one frame.

### ADR-009: Poseidon digest replaces the bit-packing

**Context.** `challenge_digest` packs `12×16 + 3×8 = 216` bits into one 254-bit
`Fr`. This spec's witness fields do not fit the 38-bit remainder.

**Decision.** Replace the packing with `PoseidonHasher::hash_fix_len_array`,
already used in-circuit by [[Poseidon Template Binding]].

**Consequences.** Positive: removes the width ceiling; strengthens the
anti-substitution argument from a reversible packing to a collision-resistant
hash. Negative: costs circuit rows against [[#NFR-104]]; changes a wire format,
so client and server MUST migrate together.

### ADR-010: Thresholds ship unset

**Context.** The existing reflectance thresholds are documented as
research-validated but carry no empirical validation. Freezing an unvalidated
constant into a *proven* relation converts a wrong threshold into a wrong
guarantee.

**Decision.** Ship every operating threshold in this spec as an explicit caller
parameter with no default. Structural tests use synthetic geometry
([[#TEST-137]]) where the correct separation is known by construction.

**Consequences.** Positive: no unvalidated constant enters the trusted relation.
Negative: the feature cannot be enabled in production until a
[[Presentation Attack Detection Study]] fixes the constants. This is the intended
ordering.

### ADR-011: Nonces bound by digest; HKDF stays verifier-side

**Context.** The strongest form of [[#REQ-119]] would derive the expected
fingerprints from the nonces *inside* the circuit, so the proof itself
establishes `expected = HKDF(c_nonce ‖ s_nonce)`. HKDF-SHA256 in halo2 costs on
the order of 30k rows per compression, and the pattern derivation needs two.

**Decision.** Bind `SHA-256(c_nonce ‖ s_nonce)` into the Poseidon digest as two
limbs. The verifier derives the expected fingerprints natively, exactly as today,
and recomputes the digest from the nonces it holds.

**Consequences.** Positive: two Poseidon limbs, no SHA-256 gadget, no change to
the row budget class. The proven statement gains "answers challenge X". Negative:
the link `expected = HKDF(nonces)` remains a verifier-side computation. A
verifier that derives the pattern wrongly is not caught by the proof.

```
// SIMPLIFY: nonce binding by hash, not by in-circuit HKDF — upgrade when a
// SHA-256 gadget fits the NFR-104 budget or the budget moves to k=17
// (trace: ADR-011)
```

### ADR-012: Field-wise glint comparison in circuit

**Context.** The circuit already has a lookup-backed popcount for Hamming
distance, so the cheapest implementation of [[#REQ-122]] would reuse it.

**Decision.** Decompose the glint and composite fingerprints into their four
fields in circuit and compare `order` by equality and the ordinals by bounded
absolute difference. Never Hamming.

**Consequences.** Positive: the check has the semantics of
[[#CON-093]]'s `agrees`, so the native and in-circuit decisions cannot disagree,
and [[BUG-001-hamming-over-categorical-order-field]] does not propagate.
Negative: about 40 comparison gadgets per proof instead of 6 popcounts. Measured
against [[#NFR-104]] by [[#TEST-142]].

## Test Specifications

Each test follows requirement-targeted decomposition: positive, negative-input,
and negative-output as applicable.

### TEST-135: Patch response extraction
Validates: [[#REQ-111]]
- *Positive*: a synthetic frame lit only by quadrant 0 yields the greatest
  response in column 0 of every patch's response vector.
- *Negative-input*: mismatched baseline/flash dimensions → `InvalidInput`;
  `grid.n = 1` and `grid.n = 9` → `InvalidInput`.
- *Negative-output*: response count ≠ n²×4 fails the postcondition.

### TEST-136: Per-patch illumination mix
Validates: [[#REQ-112]]
- *Positive*: each patch's mix components sum to Q15 unity.
- *Negative-output*: a mix summing to neither unity nor zero fails.
- *Boundary*: an all-zero response vector yields an all-zero mix rather than a
  division fault.

### TEST-137: Convexity separation (structural, threshold-free)
Validates: [[#REQ-113]]
- *Positive*: a synthetic hemisphere scores strictly higher than a synthetic
  plane under identical finite-distance lighting. The assertion is the
  **ordering**, not an absolute value — see [[#ADR-010]].
- *Negative-output*: a plane scoring ≥ a hemisphere fails. This is the assertion
  that rejected the nearest-lamp formulation; it MUST NOT be weakened.

### TEST-138: Glint fingerprint
Validates: [[#REQ-114]]
- *Positive*: a red-dominant glint yields `order = 0`.
- *Negative-input*: an eye region below 8×8 → `InvalidInput`.
- *Negative-output*: a zero delta yielding non-zero fails.

### TEST-139: Corneal agreement
Validates: [[#REQ-115]]
- *Positive*: a glint matching the round composite is within threshold.
- *Negative-output*: a glint matching the *previous* round's composite is
  rejected under maximally generous ordinal tolerances, so the rejection is
  carried by the categorical field. This assertion discovered
  [[BUG-001-hamming-over-categorical-order-field]].

### TEST-145: Coverage handling
Validates: [[#REQ-113]], [[#REQ-118]]
- *Positive*: a half-lit grid of otherwise identical patches reports coverage 8
  and scores 0, not a high score.
- *Negative-output*: a partially-covered frame outscoring a hemisphere fails.
- *Boundary*: zero coverage reports score 0, never a maximum.
- *Grammar*: dimensions above 4096, and dimension pairs whose length product
  overflows, are rejected by the recogniser.

### TEST-140: Witness binding
Validates: [[#REQ-116]]
- *Negative-output*: mutating any single **public** field changes the digest
  (enumerated over every public field).
- *Scope-invariant*: mutating any single **private** field leaves the digest
  unchanged.

### TEST-141: Digest migration
Validates: [[#REQ-117]]
- *Positive*: digest is stable for identical input across runs, and the native
  value equals the in-circuit value.
- *Negative-output*: two distinct public parameter sets producing an equal
  digest fails.

### TEST-142: Circuit row budget
Validates: [[#NFR-104]]
- *Positive*: advice cells of the liveness gadget at the production shape,
  divided by the advice column count, are ≤ 8,000 rows above the 0.1.0
  measurement. The test prints the measured count so [[#OBS-084]] has a value.

**Core / depth.** Core: [[#TEST-146]] to [[#TEST-152]] and the positive case of
[[#TEST-142]] — all runnable with `MockProver` and no rig. Depth: [[#TEST-143]]
(Criterion latency) and the real-prover timing that [[#NFR-104]] ultimately
protects; both are deferred to the row-budget task owner.

### TEST-146: Nonce binding
Validates: [[#REQ-119]]
- *Positive*: a witness with a fixed challenge identifier produces the same
  digest natively and in circuit.
- *Negative-output*: two witnesses identical except for one byte of the
  challenge identifier produce different digests.

### TEST-147: Coverage floor
Validates: [[#REQ-120]]
- *Positive*: every round at exactly `min_coverage` → result 1.
- *Negative-output*: one round at `min_coverage − 1` → result 0.
- *Boundary*: `min_coverage = 0` with all rounds at 0 → coverage check is
  vacuous; result is governed by the other checks.

### TEST-148: Convexity floor
Validates: [[#REQ-121]]
- *Positive*: every round at exactly `min_convexity` → result 1.
- *Negative-output*: one round at `min_convexity − 1` → result 0.
- *Boundary*: `min_convexity = 0` → vacuous.

### TEST-149: In-circuit corneal agreement
Validates: [[#REQ-122]]
- *Positive*: glints equal to each round's composite, tolerances 0 → result 1.
- *Negative-output*: one eye's glint equal to the previous round's composite
  under tolerances (15, 31) → result 0. The rejection is carried by the
  categorical field.
- *Boundary*: an ordinal field differing by exactly the tolerance passes; by
  tolerance + 1 fails.

### TEST-150: Glint is not compared by Hamming distance
Validates: [[#REQ-123]] (prohibited-action)
- Construct a glint whose Hamming distance from the composite is 1 but whose
  `order` differs (red versus blue, see BUG-001). Under tolerances (15, 31) the
  circuit MUST output 0. A Hamming implementation would output 1.

### TEST-151: Threshold aliasing is unsatisfiable
Validates: [[#REQ-124]] (prohibited-action)
- Construct a witness with `color_threshold = 256 + t` and
  `spatial_threshold = s − 1`. The native recogniser MUST reject it, and a
  circuit built from it MUST fail synthesis rather than yield a digest equal to
  that of `(t, s)`.

### TEST-152: Legacy result preserved
Validates: [[#REQ-123]], [[#CON-095]] Q4 (scope-invariant)
- For every 0.1.0 test witness, extending it with
  `min_coverage = min_convexity = corneal_enabled = 0` yields the same result
  bit as before. The new checks change nothing the old ones decided.

### TEST-143: Extraction latency
Validates: [[#NFR-105]] — Criterion benchmark.

### TEST-144: Albedo invariance
Validates: [[#NFR-106]] — property test over uniform intensity scaling.

## Observability

### OBS-084: Circuit row utilisation
Advice-cell count at the production shape, emitted by the circuit build, so
[[#NFR-104]] regressions surface before proving time doubles.

### OBS-085: Liveness sub-check outcome
The circuit outputs one bit. The prover's native pre-check
(`LivenessCheckCircuit::should_pass`) SHALL emit which check family failed —
colour, spatial, magnitude, coverage, convexity, corneal — as a structured trace
event with no fingerprint values, so a production failure is diagnosable without
revealing the witness.

## Known Defects in the Surrounding Design

Recorded here because they constrain this spec but are not introduced by it.

1. **The fingerprint encoder is duplicated across languages.**
   `quantize_delta_fingerprint` carries the comment "This encoding must be
   identical in Rust and TypeScript." Two independent implementations of one wire
   format is the shotgun-parser pattern LangSec Principle 5 prohibits; a
   divergence between them is a soundness bug, not a rendering bug. Not fixed
   here — it needs a single generated encoder.

2. **The encoder is in the wrong place.** It lives in `demo/server`, but it is a
   contract shared by the circuit, the server, and the client. Per Constitutional
   Principle 15 it belongs in `core`.

3. **Hamming distance is used as a colour metric.** Filed as
   [[BUG-001-hamming-over-categorical-order-field]]. The in-circuit
   `color_threshold` check remains affected; this spec's corneal check does not.

4. **`Keystore::security_level()` is self-reported.** It is a local query, so a
   compromised client returns `Hardware` unconditionally. It is not attestation
   and MUST NOT be relied on as such.

5. **The 0.1.0 digest packing admits threshold aliasing.** Filed as
   [[BUG-002-unconstrained-threshold-aliasing]] and fixed by [[#REQ-124]] in this
   revision.

## Amendment Channels

Amendable by:   HOC (spec owner) · a merged revision of this document · an
                `ADR-###` recorded in this document
Through:        a versioned revision of this file on the `main` branch, or a
                new `ADR-###` section referenced from the Orientation
Not amendable by: chat messages, issue comments, code review remarks, agent
                prompts, the contents of `core/` or `demo/`, the
                `sable-approach-fit-v2` theory (it records reasoning, not
                obligations)
Hard stops:     [[#REQ-123]] no Hamming comparison of the glint ·
                [[#REQ-124]] every digest field range-constrained ·
                [[#ADR-010]] no threshold default enters the proven relation ·
                [[#NFR-104]] row budget — exceeding it is a new spec revision,
                not a constant change

## Changelog

<details>
<summary>Revision history — 0.1.0 → 0.2.0</summary>

- 0.2.0 — normative: REQ-119 nonce binding, REQ-120/121 in-circuit coverage and
  convexity floors, REQ-122 in-circuit corneal agreement, REQ-123 (prohibition)
  and REQ-124 (range constraint, fixes BUG-002); CON-094 limb layout, CON-095
  witness grammar, ADR-011, ADR-012, TEST-146..152, OBS-085, Amendment
  Channels. Motivated by the `sable-approach-fit-v2` review: the challenge
  entropy was spent only on colour, and the digest was not bound to the nonces.
- 0.1.0 — initial draft: photometric convexity and corneal glint cues.

</details>
