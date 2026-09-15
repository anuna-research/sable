---
id: SPEC-008
title: Rolling-Shutter Temporal Challenge
status: approved
version: 0.1.0
last-updated: 2026-09-15
---

# SPEC-008: Rolling-Shutter Temporal Challenge

The key words **MUST**, **MUST NOT**, **SHALL**, **SHALL NOT**, **SHOULD**, and
**MAY** are interpreted as described by BCP 14.

## Orientation

SABLE's spatial flash relation has no sub-frame time axis. A replay can therefore
present a challenge-consistent still image after learning the coin-flip output.
This specification adds a twelve-symbol colour waveform with unique cyclic
four-symbol windows and proves that twelve private row-band observations match
one ordered rotation of that waveform. One private initial phase selects the
rotation; two private inter-frame tick deltas must agree with verifier-issued
timing targets. The verifier binds the waveform, timing profile, error budget,
and enable bit into the existing Poseidon challenge digest.

For example, with expected symbols `R,G,B,W,...`, phase `2`, and four samples per
frame, the first observed sample must match `B`; the remaining samples follow the
same cyclic order across all three frames. The prover cannot select a different
phase for each frame. If the error budget is two, a third mismatch makes the
public liveness result zero.

This relation proves consistency of submitted temporal evidence. It does not
prove that a camera produced the rows or timestamps. Applications that treat the
result as physical-capture evidence must provide the protected capture-and-timing
path described by [[SPEC-003-platform-security-integration]].

**Load-bearing:** [[SPEC-008-rolling-shutter-temporal-challenge#REQ-133]] ordered
symbols · [[SPEC-008-rolling-shutter-temporal-challenge#REQ-135]] one phase ·
[[SPEC-008-rolling-shutter-temporal-challenge#REQ-136]] frame timing ·
[[SPEC-008-rolling-shutter-temporal-challenge#REQ-138]] transcript binding.

**Controls:** [[SPEC-008-rolling-shutter-temporal-challenge#REQ-135]] one phase
for the whole burst · [[SPEC-008-rolling-shutter-temporal-challenge#REQ-137]]
error budget below half the minimum inter-rotation distance ·
[[SPEC-008-rolling-shutter-temporal-challenge#REQ-139]] disabled by default ·
[[SPEC-008-rolling-shutter-temporal-challenge#REQ-140]] rejection requires a
verifier-owned capture-validation decision.

## Failure mode

The current three-frame spatial relation discards row time. An attacker that
learns the challenge and can synthesize input pixels can satisfy spatial checks
without reproducing the display-to-sensor timing response. The temporal relation
adds that ordering. Its ceiling is explicit: an attacker that can
also synthesize the temporal witness still satisfies the relation unless an
external capture boundary validates the evidence.

## Requirements

### REQ-133: Deterministic no-repeat waveform

The joint client/server nonce SHALL derive exactly twelve symbols over
`{R,G,B,W}` with adjacent symbols unequal, full cyclic period twelve, and twelve
distinct cyclic windows of length four. It SHALL use HKDF-SHA256 with
`IKM = c_nonce || s_nonce`, UTF-8 salt `sable-rolling-shutter-v1`, UTF-8 info
`temporal-symbols`, and rejection sampling from a 4,080-byte expansion. Bytes
`0..=255` map without bias modulo four for the first symbol; transition bytes
`0..=254` map without bias modulo three, while byte 255 is discarded.

Acceptance: Rust and TypeScript derive identical fixed vectors; every adjacent
pair differs.

Trace: [[SPEC-008-rolling-shutter-temporal-challenge#CON-098]] ·
[[SPEC-008-rolling-shutter-temporal-challenge#TEST-160]].

### REQ-134: Fixed-size private observation

The proof witness SHALL contain twelve two-bit observed symbols, grouped as four
ordered row bands in each of three frames.

Trace: [[SPEC-008-rolling-shutter-temporal-challenge#CON-099]] ·
[[SPEC-008-rolling-shutter-temporal-challenge#TEST-161]].

### REQ-135: Single phase across the burst

The proof SHALL select one initial phase in `[0,11]` and apply that rotation to
all twelve observations. The circular distance from the verifier-issued phase
SHALL be no greater than a tolerance in `[0,1]`. The relation SHALL expose no
independent per-frame phase choice: acceptance means the complete observation is
within the one global rotation's symbol-error budget. A splice MAY therefore
pass only when every symbol it changes fits within that same explicit budget.

Trace: [[SPEC-008-rolling-shutter-temporal-challenge#TEST-162]] ·
[[SPEC-008-rolling-shutter-temporal-challenge#TEST-163]].

### REQ-136: Frame progression

The witness SHALL contain two inter-frame tick deltas. In profile version 0.1.0,
each delta SHALL equal four display-refresh ticks and the public tolerance SHALL
equal zero. The second frame therefore begins at observation index four and the
third at index eight; the same initial phase determines all twelve expected
indices. Comparisons SHALL use overflow-safe integer constraints.

Trace: [[SPEC-008-rolling-shutter-temporal-challenge#CON-099]] ·
[[SPEC-008-rolling-shutter-temporal-challenge#TEST-164]].

### REQ-137: Bounded symbol errors

The temporal check SHALL pass only when the number of symbol mismatches is no
greater than the verifier-issued error budget. The recogniser SHALL compute the
minimum Hamming distance `d_min` between distinct cyclic rotations of the issued
waveform and require `2t < d_min`. This keeps accepted Hamming balls for distinct
phases disjoint.

Trace: [[SPEC-008-rolling-shutter-temporal-challenge#TEST-165]].

### REQ-138: Complete policy binding

The challenge digest SHALL bind the twelve expected symbols, expected phase,
phase tolerance, frame-delta tolerance, symbol-error budget, temporal enable bit,
and capture-validated bit using the same range-constrained cells consumed by the
checks.

Trace: [[SPEC-008-rolling-shutter-temporal-challenge#TEST-166]].

### REQ-139: Explicit enable path

The temporal check SHALL remain disabled unless the application supplies a
complete recognised temporal observation, explicitly enables its policy, and the
verifier independently sets `capture_validated = true`. The web demo MAY expose
unprotected evidence in observe-only mode, but SHALL keep both the circuit gate
and rejection path disabled. Disabling the integration policy is the rollback
path.

Trace: [[SPEC-008-rolling-shutter-temporal-challenge#CON-100]] ·
[[SPEC-008-rolling-shutter-temporal-challenge#TEST-167]].

### REQ-140: Provenance boundary

No API response or documentation SHALL describe the temporal relation alone as
camera attestation or proof of physical capture. A production authentication
decision SHALL NOT reject or accept solely because of temporal evidence when the
verifier's independently constructed policy has `capture_validated = false`.
Only verifier-owned policy construction MAY set that bit after validating
protected capture evidence bound to the same challenge and frame hashes. The
untrusted proof-request grammar SHALL NOT contain the bit. This repository's
0.1.0 integrations implement no such validator and SHALL set it to false.

Trace: [[SPEC-008-rolling-shutter-temporal-challenge#TEST-168]] ·
[[SPEC-008-rolling-shutter-temporal-challenge#TEST-169]] ·
[[SPEC-008-rolling-shutter-temporal-challenge#OBS-087]].

## Contracts

### CON-098: Waveform derivation

Input grammar: two byte strings of exactly 32 bytes. Output grammar: twelve
integers in `[0,3]`; adjacent values differ; the cyclic period is twelve; and all
twelve cyclic windows of length four are distinct.

Candidates consume unbiased bytes as described by
[[SPEC-008-rolling-shutter-temporal-challenge#REQ-133]]. The first candidate that
meets the output grammar is returned. Exhausting the expansion without a valid
candidate is an explicit derivation error.

### CON-099: Circuit witness and policy

Private grammar:

```text
observed_symbols = u2[12]
initial_phase = u4 where value <= 11
frame_tick_deltas = u16[2]
```

Public policy grammar:

```text
expected_symbols = u2[12], adjacent values unequal
expected_phase = u4 where value <= 11
phase_tolerance = bit
frame_tick_tolerance = bit constrained to zero in profile 0.1.0
max_symbol_errors = u4 where 2 * value < minimum inter-rotation distance
enabled = bit
capture_validated = bit, with enabled <= capture_validated
```

The expected waveform also satisfies
[[SPEC-008-rolling-shutter-temporal-challenge#CON-098]]. Frame deltas compare
against the fixed value four. Phase distance is `min(|a-b|, 12-|a-b|)`. Full
recognition precedes proof generation or challenge-state mutation.

### CON-100: Demo JSON extension

When temporal mode is enabled, `/api/auth/prove` accepts:

```json
{
  "rolling_shutter": {
    "observed_symbols": [2, 1, 3, 0, 3, 2, 1, 3, 1, 2, 1, 0],
    "initial_phase": 0,
    "frame_tick_deltas": [4, 4]
  }
}
```

The object uses a Serde struct with `deny_unknown_fields`; fixed arrays reject
wrong lengths, duplicate keys are rejected, and JSON numbers must fit their
unsigned integer target types. The existing request-body limit applies to the
complete endpoint body. Structurally malformed objects are rejected before the
stored challenge is removed. In observe-only mode, an absent object or a
well-formed observation outside the semantic symbol/phase grammar does not
change authentication; the latter is reported as a failed observation.

## Decisions

### ADR-016: One cyclic phase selector

The circuit uses twelve equality selectors to choose one cyclic rotation of the
public waveform. Full-period and unique-window recognition plus the derived
error cap prevent ambiguous accepted rotations. This is small at twelve symbols,
avoids dynamic indexing, and makes a per-frame substring choice impossible.

### ADR-017: Timing ticks are profile units

Timing values are display-refresh ticks rather than wall-clock milliseconds.
Three frames contribute four ordered samples each, so their required start
progression is fixed at exactly four ticks in profile 0.1.0. A mobile
integration can derive these integers from sensor timestamps and exposure
metadata without introducing floating point into the circuit.

### ADR-018: Observe-only rollout

The web path defaults temporal mode off because hardware thresholds and browser
timestamp provenance have not been validated. `SABLE_ROLLING_SHUTTER_OBSERVE`
enables reporting only and cannot set `capture_validated`. A mobile verifier may
arm rejection only after its protected capture validator sets that bit in the
independently constructed policy. Rollback disables that validator or policy.

## Tests

### TEST-160: Cross-platform RLL vectors — core

Validates [[SPEC-008-rolling-shutter-temporal-challenge#REQ-133]]. Fixed nonces
produce the same twelve symbols in Rust and TypeScript; adjacency is checked.

### TEST-161: Temporal grammar — core

Validates [[SPEC-008-rolling-shutter-temporal-challenge#REQ-134]]. Symbols above
three, phases above eleven, error budgets above twelve, and incomplete JSON fail.

### TEST-162: Ordered match — core

Validates [[SPEC-008-rolling-shutter-temporal-challenge#REQ-135]]. A correctly
rotated twelve-symbol observation passes at zero errors.

### TEST-163: Per-frame realignment rejected — core

Validates [[SPEC-008-rolling-shutter-temporal-challenge#REQ-135]]. Three
individually matching four-symbol windows drawn from different rotations fail at
error budget zero. The test waveform has full period and unique cyclic
four-symbol windows.

### TEST-164: Timing progression — core

Validates [[SPEC-008-rolling-shutter-temporal-challenge#REQ-136]]. Deltas four
pass, deltas three and five fail, and a non-zero profile tolerance is rejected.

### TEST-165: Error budget — core

Validates [[SPEC-008-rolling-shutter-temporal-challenge#REQ-137]]. Exactly `t`
mismatches pass and `t+1` fail, and a budget with `2t >= d_min` is rejected by
the recogniser.

### TEST-166: Digest mutation — core

Validates [[SPEC-008-rolling-shutter-temporal-challenge#REQ-138]]. Mutating each
public temporal field changes the challenge digest; mutating private fields does
not. The circuit test also mutates a checked field while retaining the old digest
as its public instance and requires verification failure, demonstrating that the
checked and hashed value is the same assigned cell.

### TEST-167: Enable and rollback — core

Validates [[SPEC-008-rolling-shutter-temporal-challenge#REQ-139]] and
[[SPEC-008-rolling-shutter-temporal-challenge#REQ-140]]. Disabled mode preserves
legacy acceptance; enabled mode rejects absent or malformed evidence; unprotected
demo evidence remains observe-only; and `enabled = true, capture_validated = false`
is unsatisfiable.

### TEST-168: Hardware channel — depth

Provides depth evidence for [[SPEC-008-rolling-shutter-temporal-challenge#REQ-140]]. Execute
[[EXP-002-rolling-shutter-hardware]] on supported iOS and Android devices and
measure joint APCER/BPCER with protected capture metadata before enabling a
production rejection policy.

### TEST-169: Capture authority boundary — core and demo

Validates [[SPEC-008-rolling-shutter-temporal-challenge#REQ-140]]. The untrusted
proof-request schema rejects a caller-supplied `capture_validated` field; the
circuit rejects `enabled = true, capture_validated = false`; and demo responses
describe results as observe-only rather than camera attestation.

## Observability

### OBS-087: Temporal relation result

Record only bucketed, population-level temporal enabled/pass rates and mismatch
or timing-residual histograms, retained for at most thirty days. Do not log raw
images, row chromaticities, nonces, phases, per-attempt symbol strings, account
identifiers, or stable pseudonyms. This signal measures relation behaviour, not
camera provenance.

## Purity boundary

Nonce-to-waveform derivation and circuit evaluation are deterministic and pure.
Image decoding, row-band extraction, sensor metadata validation, environment
policy, challenge-state consumption, and logging are outside that boundary.

## Amendment Channels

The repository owner may amend waveform size, policy grammar, or rollout state by
updating this specification and its traced tests. Application operators may tune
only explicitly exposed tolerances. No amendment channel may waive input
recognition, complete digest binding, single-phase enforcement, or the provenance
boundary.

Open: the mobile integration owner must define and validate one protected
capture-and-timing profile per supported device family through
[[EXP-002-rolling-shutter-hardware]] before setting `capture_validated` in a
production verifier policy.
