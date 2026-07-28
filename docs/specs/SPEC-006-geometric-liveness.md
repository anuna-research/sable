# SPEC-006: Geometric and Corneal Liveness Cues

| Field | Value |
|-------|-------|
| id | SPEC-006 |
| title | Geometric and Corneal Liveness Cues |
| status | draft |
| version | 0.1.0 |
| last-updated | 2026-07-28 |
| review-tier | 1 (no-go area: cryptography, authentication core, privacy-sensitive transforms) |

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT,
RECOMMENDED, MAY, and OPTIONAL in this document are to be interpreted as
described in BCP 14 (RFC 2119, RFC 8174) when, and only when, they appear in all
capitals.

## Orientation

**Intent:** The existing spatial-flash check proves that face quadrants reflect
*different colours*. It does not prove the face has *shape*. This spec adds two
cues that do — a geometric one derived from light already being emitted, and a
corneal one — without new capture hardware.

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
  │ [[#CON-093]]     │  (existing encoder) │ [[#CON-094]] k=16  │
  └──────────────────┘                     └────────────────────┘
        arrows point inward → the circuit never calls the extractors
```

**Decisions:** [[#ADR-007]] response contrast instead of an explicit normal
solve · [[#ADR-008]] reuse the existing quantiser for the glint · [[#ADR-009]]
Poseidon digest replaces the 216-bit packing · [[#ADR-010]] thresholds ship unset

**Load-bearing:** [[#REQ-113]] convexity discriminator · [[#REQ-115]] corneal
agreement · [[#REQ-117]] digest migration · [[#NFR-104]] circuit row budget

**Open:**
- Operating thresholds cannot be set without a presentation-attack study —
  see [[#ADR-010]] (owner: HOC). This spec ships the mechanism, not the constants.
- Eye localisation is out of scope; [[#CON-093]] takes a pre-cropped region.
  Selecting a [[Face Landmark Model]] is deferred (owner: HOC).
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

The system SHALL include the patch codes, convexity scores, and glint
fingerprints in the challenge digest, SO THAT a prover cannot substitute values
not agreed with the verifier.

Trace: [[#TEST-140]] · [[#CON-094]]

### REQ-117: Challenge digest migration

The system SHALL compute the challenge digest as a Poseidon hash over the
parameter vector INSTEAD OF a bit-packing into a single field element.

Rationale: the existing packing consumes 216 of 254 available bits
(`12×16 + 3×8`). The witness fields added by [[#REQ-116]] exceed the remainder.

Trace: [[#TEST-141]] · [[#CON-094]] · [[#ADR-009]]

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
Interface: challenge_digest(witness) -> Fr
Pre-conditions:
  P1. all witness field widths are within their declared bit budgets
Post-conditions:
  Q1. digest = Poseidon(fp[0..12] ‖ patch_codes ‖ convexity ‖ glints ‖ thresholds)
  Q2. digest is collision-resistant over the full witness           (REQ-117)
  Q3. changing any single witness field changes the digest          (REQ-116)
Error model: total function over well-typed input.
```

Implements: [[#REQ-116]], [[#REQ-117]]
Verified by: [[#TEST-140]], [[#TEST-141]]

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
- *Negative-output*: mutating any single witness field changes the digest
  (property-based over all fields).

### TEST-141: Digest migration
Validates: [[#REQ-117]]
- *Positive*: digest is stable for identical input across runs.
- *Negative-output*: two distinct witnesses producing an equal digest fails.

### TEST-142: Circuit row budget
Validates: [[#NFR-104]] — measured advice-cell count stays within budget.

### TEST-143: Extraction latency
Validates: [[#NFR-105]] — Criterion benchmark.

### TEST-144: Albedo invariance
Validates: [[#NFR-106]] — property test over uniform intensity scaling.

## Observability

### OBS-084: Circuit row utilisation
Advice-cell count at the production shape, emitted by the circuit build, so
[[#NFR-104]] regressions surface before proving time doubles.

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

## Changelog

<details>
<summary>Revision history — 0.1.0</summary>

- 0.1.0 — initial draft: photometric convexity and corneal glint cues.

</details>
