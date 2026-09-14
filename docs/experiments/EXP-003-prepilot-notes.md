# EXP-003 pre-pilot notes — first live runs of the wired demo

| Field | Value |
|-------|-------|
| id | EXP-003 pre-pilot notes |
| status | informal; **not** findings (the brief forbids findings before the pilot) |
| date | 2026-09-14 |
| subject | HOC, one subject, one device (MacBook webcam 640×480, indoor ambient) |
| build | `feat/SPEC-006-geometric-liveness` at `3f8f08d` plus the gate reorder that followed |

These are the numbers from the first end-to-end runs after the photometric and
corneal extractors were wired into the demo server. They exist to shape the
pilot, not to set a threshold. n = 4 bona fide (plus 4 weak-capture rejections), n = 5 phone-screen attempts (3 with geometric evidence).

## Bona fide (real face), spatial check passed

| Run | Round | Patches /16 | Convexity (Q15 → [0,2]) | Glint order L / R vs expected |
|-----|-------|-------------|--------------------------|-------------------------------|
| 05:44 | 1 | 12 | 11149 → 0.340 | match / **miss** (R,B near-equal in composite) |
| 05:44 | 2 | 11 | 9116 → 0.278 | match / match |
| 05:44 | 3 | 11 | 7651 → 0.233 | match / match |
| 05:55 | 1 | 13 | 10339 → 0.316 | miss / miss |
| 05:55 | 2 | 14 | 13384 → 0.408 | miss / miss |
| 05:55 | 3 | 10 | 8058 → 0.246 | miss / miss |

Third bona fide run (06:1x, after the BUG-003 fix, defaults 5/1/3, scale 128):

| Run | Round | Patches /16 | Convexity | Raw mean delta TL / TR / BL / BR (RGB) | Expected quadrant colours |
|-----|-------|-------------|-----------|----------------------------------------|---------------------------|
| 3 | 1 | 16 | 0.098 | (3.0,6.2,6.5) (2.6,5.0,5.2) (2.2,7.2,7.9) (2.3,6.2,6.6) | blue-magenta, green, green, blue |
| 3 | 2 | 16 | 0.216 | (5.5,6.9,6.9) (3.9,6.6,7.3) (4.5,6.2,5.4) (4.6,6.5,7.3) | — |
| 3 | 3 | 16 | 0.153 | (5.7,4.9,10.9) (3.6,4.3,9.0) (6.4,6.1,14.3) (5.7,5.3,10.6) | — |

In-circuit liveness bit still **0**, failing the colour check in round 1.
Every quadrant's delta is the same common-mode brightening with a slight
blue-green cast; the per-quadrant tint is below one RGB unit. The server's
cosine test scored 0.37–0.92 and passed. Its spatial-differentiation score was
0.996 (mean cosine between adjacent quadrant deltas, i.e. nearly parallel) and
passed only because the ceiling is 0.9995.

Weak-capture episode (06:21, four attempts, bright afternoon sun through a
window): quadrant deltas 1–3 RGB units (camera noise) on three attempts and a
grey ±12 left/right split on the fourth (subject motion or a lamp). Server
cosine check rejected all four at 0.60, 0.37, 0.16, 0.04. Coverage 3–10.

Fourth bona fide run (06:25, blind partly closed, demo profile
`SABLE_LIVENESS_THRESHOLDS=11,0,0 SABLE_GEOMETRY_FLOORS=8,0`):

| Run | Round | Patches /16 | Convexity | Raw mean delta TL / TR / BL / BR (RGB) |
|-----|-------|-------------|-----------|----------------------------------------|
| 4 | 1 | 10 | 0.232 | (2.4,0.2,4.0) (1.6,0.0,6.5) (3.4,0.3,4.9) (2.5,0.2,6.3) |
| 4 | 2 | 10 | 0.253 | (1.9,1.7,−0.5) (2.7,5.1,0.0) (3.0,2.6,−0.4) (3.8,6.2,−0.1) |
| 4 | 3 | 11 | 0.320 | (1.7,2.6,2.7) (2.8,5.1,6.2) (2.1,3.6,3.8) (2.9,4.6,5.5) |

**In-circuit liveness bit 1** for the first time, on the coverage floor
alone (legacy checks vacuous, digest binds `min_coverage = 8`). Deltas were
2–6 units, weaker than run 3's 3–14, and coverage sat only two patches above
the floor.

Glint magnitude was 1–2 on every eye in every round (max channel delta of
roughly 4–8 RGB units). Observed glint order in the 05:55 run was
blue-dominant in all six eye-rounds regardless of the challenge colour.

Both runs: server floating-point spatial check passed (0.970, 0.965);
in-circuit liveness bit **0** on both, per [[BUG-003-expected-fingerprint-magnitude-mismatch]].

## Presentation attack (phone screen showing a photo of the subject)

| Attempt | Face Hamming | Spatial diff per round | Spatial score | Outcome |
|---------|--------------|------------------------|---------------|---------|
| 05:54:16 | 441 | 0.0035, 0.0003, 0.0060 | 0.0033 | rejected by spatial check |
| 05:54:36 | 446 | 0.7448, 0.8878, 0.0287 | 0.5538 | rejected by spatial check |

No photometric or corneal values were recorded for either attempt: the
extractors ran only after the spatial gate until the reorder in `9f7fce1`.

Third attempt, after the reorder (same phone, same photo):

| Attempt | Face Hamming | Spatial score | Round | Patches /16 | Convexity | Glint magnitude L / R |
|---------|--------------|---------------|-------|-------------|-----------|------------------------|
| 05:59:50 | **110** | 0.0468 (rejected) | 1 | **5** | 11780 → 0.359 | 0 / 1 |
| | | | 2 | **5** | 8666 → 0.264 | 0 / 0 |
| | | | 3 | **6** | 10389 → 0.317 | 0 / 0 |

Fourth attempt (same phone, same photo):

| Attempt | Face Hamming | Spatial score | Round | Patches /16 | Convexity | Glint magnitude L / R |
|---------|--------------|---------------|-------|-------------|-----------|------------------------|
| 06:00:30 | **85** | 0.4193 (rejected) | 1 | **4** | 251 → 0.008 | 0 / 2 |
| | | | 2 | **4** | 18573 → 0.567 | 0 / 4 |
| | | | 3 | **4** | 19404 → 0.592 | 0 / 1 |

Fifth attempt (06:26, demo profile with coverage floor 8):

| Attempt | Face Hamming | Spatial score | Round | Patches /16 | Convexity |
|---------|--------------|---------------|-------|-------------|-----------|
| 06:26:49 | 182 | 0.0603 (rejected) | 1 | **4** | 0.143 |
| | | | 2 | **5** | 0.287 |
| | | | 3 | **5** | 0.477 |

Coverage 4–5 against the floor of 8: the circuit would have set liveness = 0
on the Coverage check. The server's cosine gate rejected the request first,
so no proof was produced; the OBS-085 pre-check now runs before that gate so
later attempts log the circuit's would-be verdict.

The phone photo matched the enrolled template *better* than the live face
on two of three measured attempts (Hamming 110, 85, 182 against 185–230).

For reference, bona fide face Hamming distances in the same session were
185–230 against a threshold of 2048; the phone-screen photo **passed the face
match** at 441–446.

## What these runs suggest for the pilot design

1. **Coverage and convexity look stable on one subject.** Two runs ten minutes
   apart gave 10–14 patches and 0.23–0.41 convexity. The pilot can expect the
   bona fide distribution to be tight enough that a floor is meaningful.
2. **The legacy spatial cosine check separated the phone screen every time**
   (0.003, 0.55, 0.047 against 0.97 and 0.965 bona fide).
2a. **Convexity alone does not separate; coverage does.** The phone attempt
   scored 0.26–0.36 convexity, inside the bona fide band, but on only 5–6
   responding patches against 10–14 for the face. With five patches the
   "mean deviation of mixes" is the spread of five noisy vectors, not
   geometry. This is precisely the REQ-118 argument for gating convexity on
   coverage, now observed rather than argued: the convexity floor is only
   meaningful above a coverage floor, and on this device a coverage floor
   anywhere in 7–9 would have rejected the attack with margin on both sides.
   The fourth attempt makes the point harder: on four patches the convexity
   score ranged from 0.008 to 0.592 across three rounds of the same
   presentation, straddling and exceeding the whole bona fide band. Below
   the coverage floor the convexity number carries no information at all.
   The pilot should sweep coverage first and report convexity curves only
   for captures above the chosen coverage floor. Coverage on this device:
   bona fide 10–14, phone screen 4–6, two attempts each.
3. **The corneal cue is not usable at this capture geometry.** One run matched
   order 5/6, the next 0/6, with magnitude 1–2 throughout. At that signal level
   even the categorical order field is noise. Before the pilot spends effort
   on hand-cropped eyes, the capture side needs a brighter flash, a closer
   camera, or a higher-resolution crop, and BUG-003 needs fixing so the
   magnitude field can be compared at all. Record the raw mean RGB delta per
   eye in the pilot, not only the fingerprint.
4. **The face-match threshold admits a phone photo of the subject, and on the
   measured attempts preferred it** (Hamming 110 and 85 for the photo against
   185–230 for the live face). A screen replay of the enrolment session is the canonical
   attack and the matcher cannot see it by construction. Not this experiment's
   question, but liveness is carrying the whole load in the demo, and the
   threshold recalibration noted in the thermometer work is not optional.
4a. **The fingerprint colour check cannot be made faithful to the server's
   cosine check by tuning.** The fingerprint encodes the direction of the
   whole delta, which on a webcam is the common-mode brightening shared by all
   quadrants; the server's cosine passes because that brightening projects
   positively onto every saturated colour. SPEC-006 REQ-126 / ADR-013 record
   the replacement (cosine bound on raw signed deltas in circuit). Meanwhile
   the demo runs the legacy checks vacuous (`SABLE_LIVENESS_THRESHOLDS=11,0,0`)
   and the coverage floor armed at 8 (`SABLE_GEOMETRY_FLOORS=8,0`) as a
   labelled demo setting, because coverage is the one cue these runs
   separate on (bona fide 10–16, phone 4–6).
4c. **Coverage cannot tell "flat" from "barely lit".** Under direct sun the
   bona fide coverage fell to 3–10, overlapping the phone's 4–6, because the
   flash was a small fraction of the light on the face. REQ-118 anticipated
   this. The pilot needs a client-side illumination pre-check before the
   sequence runs (for example: mean absolute quadrant delta on a trial flash
   ≥ some units, else ask the subject to dim the room or move closer), so a
   dim capture is retried, not scored. Ambient at 40/150/400 lux in the brief
   already spans this; add a "direct sunlight" condition explicitly.
4b. **The server's spatial-differentiation check is nearly vacuous** at a
   0.9995 ceiling; the phone was rejected by negative colour cosines, not by
   geometry. The pilot should not treat that check as evidence of anything.
5. **Attack captures must be logged even when an earlier gate rejects them.**
   Done in the server; the pilot's extraction step should run over every
   capture unconditionally, as the brief already says.

Nothing here changes a constant. The pilot as briefed stands.
