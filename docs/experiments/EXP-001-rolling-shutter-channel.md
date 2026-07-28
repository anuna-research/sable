# EXP-001: Rolling-shutter symbol channel — feasibility

| Field | Value |
|-------|-------|
| id | EXP-001 |
| status | complete |
| opened | 2026-07-28 |
| timebox | one session; simulation only, no hardware |
| governs | whether [[SPEC-006-geometric-liveness]] gains a rolling-shutter challenge |

Run under [[PROTO-001]] Experiment Governance because two of the decision factors
are High: technical novelty (no precedent in the SABLE codebase) and data
uncertainty (the light budget is not analytically decidable).

## Hypothesis

A phone display can encode an unpredictable symbol sequence that a CMOS rolling
shutter renders as *vertically stacked bands* within a single camera frame, and
that sequence can be recovered from row means at exposure and illuminance levels
achievable on a front camera at arm's length.

If true, SABLE gains a **timing** channel: the bands are imposed by sensor
physics, so a replayed video carries the attacker's display timing and cannot
match a challenge chosen after recording.

## What this experiment can and cannot settle

**Can:** map the feasibility envelope over refresh rate, sensor readout time,
exposure, face size, and illuminance; identify which parameter is binding; produce
the decision boundary that a hardware test should target.

**Cannot:** prove it works on a real device. Auto-exposure behaviour, HDR frame
fusion, temporal denoise, and OLED PWM dimming are all unmodelled and any of them
can destroy the signal. **Hardware measurement remains required** — this
experiment exists to make that measurement cheap and targeted, not to replace it.

## Approach

A forward simulator (`rolling_shutter_sim.py`, checked in beside this brief):

1. Display emits one alphabet colour per display frame from a pseudorandom
   sequence.
2. Row *r* of the sensor integrates emitted light over
   `[t0 + r·T_ro/H, t0 + r·T_ro/H + T_exp]` — the rolling-shutter model.
3. Reflected signal is converted to photoelectrons through a sensor model
   anchored to a well-exposed reference, then corrupted with Poisson shot noise
   and Gaussian read noise.
4. Row means are decoded to nearest alphabet colour and compared against ground
   truth.

## Metrics and exit criteria

| Metric | Threshold |
|--------|-----------|
| Symbol recovery accuracy | ≥ 99 % over 200 trials for the configuration to count as recoverable |
| Symbols per camera frame | ≥ 2, else the channel carries no sequence |
| Binding constraint identified | named, with the parameter value at which it binds |

**Exit:** recommend hardware measurement if any commodity-plausible configuration
(refresh ≤ 120 Hz, T_ro ≤ 33 ms, T_exp achievable under ~40 lux) clears both
thresholds. Recommend abandoning if none does.

## Isolation

Simulation only. No production writes, no captured biometric data, no network. The
simulator is deterministic under a seed and touches nothing outside its own
process.

## AI trust boundary

- Model: Claude Opus 5 (1M context)
- Detection/synthesis method: forward simulation authored from the rolling-shutter
  integral and a sensor model anchored to a stated reference exposure
- The sensor anchor is an *estimate*, not a measurement — see Findings, confidence

## Findings

See `EXP-001-findings.md`, written after the sweep.
