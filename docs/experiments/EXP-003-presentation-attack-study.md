# EXP-003: Presentation-attack study — fixing the liveness thresholds

| Field | Value |
|-------|-------|
| id | EXP-003 |
| status | open |
| opened | 2026-09-14 |
| owner | HOC (needs subjects, artefacts, devices) |
| timebox | pilot: 5 subjects × 3 devices × 4 presentations, one week |
| governs | the operating constants that [[SPEC-006-geometric-liveness#ADR-010]] leaves unset |

Run under [[PROTO-001-usdd-agent-protocol#Experiment Governance (When Required)]].
Decision factors: data uncertainty High (no measurements exist), safety High
(the constants become a proven guarantee), novelty Low.

## Hypothesis

For the existing reflectance thresholds, the convexity floor
([[SPEC-006-geometric-liveness#REQ-121]]), the coverage floor
([[SPEC-006-geometric-liveness#REQ-120]]) and the corneal tolerances
([[SPEC-006-geometric-liveness#REQ-122]]), there exist per-device-model values
at which bona fide presentations pass at ≥ 95 % and printed photos, screen
replays, and one silicone or resin mask pass at ≤ 5 %, measured on the CPU
extractors as they stand.

If no such values exist for a cue, that cue is not ready for the circuit and
the `sable-approach-fit-v2` theory's `thresholds-unvalidated` premise stands.

## Why this is the critical path

Every in-circuit check in SPEC-006 0.2.0 ships with its threshold at zero. A
threshold of zero is a check that does not run. Nothing in steps 1 to 3 of the
current plan can be turned on until this experiment produces numbers, and it
needs no circuit work to begin: the extractors are pure functions over frame
pairs.

## Approach

1. **Presentations.** Per subject, per device: bona fide (live face), printed
   photo (matte and glossy), screen replay (a second phone showing a recording
   of the subject's own enrolment session), and one 3D mask where available.
2. **Capture.** The existing demo flow: baseline frame plus three flash rounds
   under the joint coin-flip pattern. Ambient at roughly 40, 150, and 400 lux.
   Eye regions cropped by hand for the pilot, since the landmark model is not
   chosen; record the crop boxes so the pilot can be rerun automatically later.
3. **Extraction.** Run `photometric::extract` (4×4 grid), `corneal::glint_fingerprint`
   and `expected_composite`, and the existing `compute_liveness_fingerprints`
   over every capture. Store scores, coverage counts, glint fields, and device
   model. No frames are retained beyond the session.
4. **Analysis.** Per device model and per cue, sweep the threshold and report
   the bona fide pass rate and attack pass rate curves. Report the pair of
   two-sided brackets the `design-bracketed-tolerances` finding asks for, not a
   single one-sided cut.
5. **Fairness.** Record self-reported skin-tone group per subject and report
   the bona fide pass rate per group at the chosen threshold
   ([[SPEC-006-geometric-liveness#NFR-106]] claims invariance; measure it).

## Metrics and exit criteria

| Metric | Threshold |
|--------|-----------|
| Bona fide pass rate at chosen threshold | ≥ 95 % per device model |
| Attack pass rate at chosen threshold | ≤ 5 % per attack type |
| Bona fide pass rate spread across skin-tone groups | ≤ 5 percentage points |
| Coverage floor | the smallest value at which the convexity curve is stable |

**Exit — proceed:** thresholds found for at least the convexity and coverage
floors on at least two device models. They enter the theory as
`(verified threshold-<cue>-<device>)` facts and SPEC-006 records them in a new
ADR with the curves attached.

**Exit — cue not ready:** a cue with no threshold meeting both rates on any
device stays at zero. Record which and why.

## Isolation

Consent from every subject; frames deleted after extraction; only derived scores
and crop boxes retained. No production system involved. No network.

## AI trust boundary

- Brief authored by Claude Fable 5.1. Analysis scripts, once written, are
  checked in under `bench/pad/` and record model metadata if model-assisted.
- Threshold selection is a human decision on the curves; the agent does not pick
  a constant.

## Findings

To be written to `EXP-003-findings.md` after the pilot. Not before.
