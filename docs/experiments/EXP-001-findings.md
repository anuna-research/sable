# EXP-001 findings: rolling-shutter symbol channel

| Field | Value |
|-------|-------|
| experiment | [[EXP-001-rolling-shutter-channel]] |
| date | 2026-07-28 |
| method | forward simulation, `rolling_shutter_sim.py`, seed 20260728 |
| confidence | **medium** — simulation only; sensor anchor is an estimate |
| recommendation | proceed to hardware measurement, with a narrowed target |

## Headline

The channel works, and **the binding constraint is exposure time, not light**.
That contradicts the concern that motivated the experiment.

## Results

Sequence recovery per frame, 600 px face width, 40 lux:

| refresh | T_ro | T_exp 0.5 ms | 1 ms | 2 ms | symbols/frame |
|---------|------|--------------|------|------|---------------|
| 60 Hz | 20 ms | 91.1 % | 74.3 % | 53.1 % | 1.20 |
| 60 Hz | 33 ms | **100.0 %** | 97.6 % | 96.5 % | 1.98 |
| 120 Hz | 20 ms | 98.2 % | 94.5 % | 79.0 % | 2.40 |
| 120 Hz | 33 ms | 96.8 % | 92.8 % | 90.2 % | 3.96 |

Illuminance at 20, 40 and 80 lux produced **no material difference** at any
configuration.

## What the numbers mean

**Light is not the constraint.** This was the experiment's main question and the
answer is no. At 1 ms and 40 lux a pixel collects only ~59 e⁻ — around five stops
underexposed, visually near-black — but the decoder works on *row means*, and
averaging 600 px gives an SNR of ~188. Chromaticity is recoverable long after the
image stops being viewable. The earlier reasoning that treated a well-exposed
image as the requirement was measuring the wrong thing.

**Exposure is the constraint, through temporal blur.** Recovery falls from 98 % to
79 % between 0.5 ms and 2 ms at 120 Hz / 20 ms readout. Each row must integrate
within roughly one display frame; beyond that, adjacent symbols merge. The
practical requirement is **T_exp ≤ 1 ms**, which needs manual or locked exposure —
auto-exposure will not choose it, because it is optimising for a viewable image.

**120 Hz is required for symbol count, not for accuracy.** 60 Hz at 33 ms readout
scores best in the table (100 %) but carries only 1.98 symbols per frame — below
the two-symbol floor, so it transmits a level, not a sequence. Accuracy without
symbols is not a channel.

## Pre-registered exit criterion: not met

No configuration reached the pre-registered ≥ 99 % with ≥ 2 symbols. The best
qualifying configuration is 120 Hz / 20 ms / 0.5 ms at **98.2 %**.

Recording that plainly rather than moving the bar. Two observations on it, offered
as interpretation and not as a revision:

- 98 % per *frame* is not 98 % per *attempt*. A challenge spanning several frames
  and requiring k-of-n recovery composes to effectively certain, so the criterion
  may have been set at the wrong granularity when the failure structure was
  unknown.
- The residual failures are dominated by band-boundary quantisation at 64 sampled
  rows. A real sensor has 1000+ rows and would resolve boundaries far more finely.
  The simulation is likely pessimistic here.

Neither observation is evidence. The honest position is that the criterion was not
met and the hardware measurement should settle it.

## Corrections made during the run

Recorded because the intermediate results were wrong in ways that mattered, and
because the trajectory is evidence per [[PROTO-001]] AI Trust Boundaries.

1. **Per-row accuracy was the wrong metric.** It counts rows straddling a symbol
   boundary as errors, though they are inherently ambiguous. Replaced with
   sequence recovery after segmentation.
2. **`segment()` dropped short runs without re-merging.** One glitched row inside
   a run split it, reporting `['G','G']` for a single `G` band. This alone
   produced a false 0-recoverable result.
3. **Uniformly random sequences allow adjacent repeats**, which merge two display
   frames into one band and destroy the timing information. Replaced with a
   run-length-limited sequence — which is a genuine encoder requirement, not a
   harness convenience, and belongs in any spec that follows.
4. **Edge bands are partial**, clipped by the frame boundary, so their extent is
   not set by display timing. Now discarded before comparison.

## Recommendation

Proceed to hardware measurement, with the target narrowed by the above:

- **Device:** 120 Hz display, front camera with manual exposure control.
- **Setting:** exposure locked at ≤ 1 ms, AE and AWB locked, face ~600 px wide.
- **Measure first:** the sensor's actual rolling-shutter readout time `T_ro`,
  which the table shows is as decisive as exposure and is not published by
  vendors. Measure it by photographing a known-frequency flashing source and
  counting bands.
- **Decide on:** whether a locked 1 ms exposure is reachable through the platform
  camera API at all. This is an API question, not a physics one, and it is now the
  single highest-risk unknown.

Browser capture is out: it cannot lock exposure or guarantee frame timing. This
adds to the case for the native path.

## Open questions the simulation cannot answer

- HDR frame fusion and temporal denoise may destroy row-level modulation before
  the application sees a frame.
- OLED PWM dimming adds its own kHz modulation that will beat with the sensor.
- Rolling-shutter direction and readout rate vary per device — this feeds directly
  into the device-profile bracketing discussion.
- Whether a locked 1 ms exposure is exposed by Android Camera2 and iOS
  AVFoundation across the target device set.

## Disposition

Not yet converted to SDD assets. On a successful hardware measurement this becomes
a REQ set under [[SPEC-006-geometric-liveness]] or its own spec; the
run-length-limited sequence constraint and the `T_exp ≤ 1 ms` bound are the two
findings that would carry straight into it.

The simulator stays checked in as the model of record. It is not production code
and is not wired into the build.
