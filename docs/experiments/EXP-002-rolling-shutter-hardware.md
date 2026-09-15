# EXP-002: Rolling-shutter symbol channel — hardware measurement

| Field | Value |
|-------|-------|
| id | EXP-002 |
| status | open |
| opened | 2026-09-14 |
| owner | HOC (needs physical devices) |
| timebox | one session per device, three devices maximum |
| governs | whether the timing axis enters [[SPEC-006-geometric-liveness]] as a REQ set |
| predecessors | [[EXP-001-rolling-shutter-channel]] — feasibility; [[EXP-004-rolling-shutter-information-theory]] — entropy and phase analysis |

Run under [[PROTO-001-usdd-agent-protocol#Experiment Governance (When Required)]].
Decision factors: technical novelty High, data uncertainty High (readout time is
unpublished), performance risk Medium.

## Hypothesis

On at least one commodity phone with a 120 Hz display, the front camera under a
locked exposure of ≤ 1 ms renders a run-length-limited colour symbol sequence as
row bands from which an ordered multi-frame attempt recovers enough
verifier-positioned symbols for at least 20 bits of conservative fixed-replay
security after its declared error/erasure budget, and the platform camera API
exposes that exposure lock.

The simulation in [[EXP-001-findings]] said light is not the constraint and
exposure is. It could not answer whether the exposure lock is reachable, what the
sensor readout time is, or whether HDR fusion, temporal denoise, or OLED PWM
destroy the banding. This experiment answers those four.

## What this experiment can and cannot settle

**Can:** measure `T_ro` per device; determine whether a ≤ 1 ms locked exposure
is reachable through Camera2 and AVFoundation; observe whether ISP frame fusion
survives; measure sequence recovery against the simulator's prediction; retain
the issued/decoded strings, erasures and phase estimates needed to calculate
`H(X)`, `I(X;Y)`, min-entropy and attempt-level replay bounds.

**Cannot:** set operating thresholds for production (that is
[[EXP-003-presentation-attack-study]]); validate against an attacker with a
matched-refresh display (a follow-up if the channel works).

## Approach

1. **Readout time.** Photograph a known-frequency flashing source (an LED driven
   at 1 kHz square wave from a signal generator, or a second phone's screen at a
   known refresh) with the front camera at 1 ms exposure. Count bands per frame;
   `T_ro = bands / f_source`. Repeat at three exposures to confirm the count is
   exposure-independent.
2. **Exposure lock.** From a native capture session, request manual exposure
   at 1 ms, 0.5 ms, and the platform minimum. Record what the API grants
   (requested versus actual) and whether AE/AWB lock holds across ≥ 60 frames.
3. **Channel calibration.** Display a continuous run-length-limited 4-symbol
   sequence (R, G, B, W with no adjacent repeat), one symbol per display frame.
   Capture 2,000 frames at the best exposure from step 2 with a face ~600 px
   wide at ~40 lux ambient. For every frame retain the issued string, decoded
   string, erasures, row means, sensor timestamp, actual exposure and phase
   estimate. Decode with the [[EXP-001-rolling-shutter-channel]] segmenter
   (`rolling_shutter_sim.py`, `segment()` and `recover()`), unchanged.
4. **Attempt protocol.** Run 200 fresh-seed attempts. Start capture before the
   sequence, maintain one continuous phase/timeline across every frame, and
   continue until at least 16 verifier-positioned symbols have been observed or
   the attempt times out. A missing position is an erasure, not permission to
   select a different substring. Calculate the conservative RLL codebook bound
   after the measured error/erasure budget. Sixteen fixed positions retain
   20.16 bits under the conservative one-symbol-error bound from EXP-004.
5. **ISP.** Repeat step 3 with HDR and any "night" or "smart" mode toggled on,
   to see whether frame fusion erases the bands.

## Metrics and exit criteria

| Metric | Threshold |
|--------|-----------|
| Exposure lock granted at ≤ 1 ms | yes/no per platform; `no` on both platforms abandons the axis |
| Measured `T_ro` | recorded per device, with the band count and source frequency |
| Complete interior symbols per camera frame | distribution, not a security threshold |
| Sequence recovery over 2,000 calibration frames | ≥ 98 % with a 95 % interval |
| Channel information | `H(X)`, `I(X;Y)` and `H_inf(X)` with raw counts retained |
| Attempt security | ≥ 20 conservative fixed-position bits after errors and erasures |
| Phase handling | one initial phase and bounded timestamp-derived progression; no per-frame free alignment |
| Bands survive HDR / fusion mode | yes/no; `no` means the spec must require those modes off |

**Exit — proceed:** one device meets ≥ 98 % calibration recovery and ≥ 20-bit
attempt security with a granted exposure lock and a continuous phase model.
Convert to a REQ set under [[SPEC-006-geometric-liveness]] (or a successor spec)
carrying the RLL code, explicit error/erasure accounting, fixed-position timeline
and the `T_exp ≤ 1 ms` bound.

**Exit — abandon:** no device grants the exposure lock, or none reaches 2
complete symbols per frame often enough to construct a ≥ 20-bit attempt within
the latency budget. Record `(discovered rolling-shutter-not-reachable)` in the
theory and stop spending on the axis.

## Isolation

No production writes. Captures contain the operator's own face only and are
deleted after decoding; only row-mean arrays, issued/decoded strings, erasures,
timestamps, exposure metadata and phase estimates are retained.
No network. Cost is operator time and two to three handsets.

## AI trust boundary

- Brief authored by Claude Fable 5.1 from [[EXP-001-findings]] and the
  `sable-approach-fit-v2` theory; the decoding code is EXP-001's, unchanged.
- Measurements are human-taken. Any model-assisted analysis records model,
  prompt, and inputs in the findings file.

## Findings

To be written to `EXP-002-findings.md` after the measurement. Not before.
