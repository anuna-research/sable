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
pilot, not to set a threshold. n = 2 bona fide, n = 2 phone-screen attempts.

## Bona fide (real face), spatial check passed

| Run | Round | Patches /16 | Convexity (Q15 → [0,2]) | Glint order L / R vs expected |
|-----|-------|-------------|--------------------------|-------------------------------|
| 05:44 | 1 | 12 | 11149 → 0.340 | match / **miss** (R,B near-equal in composite) |
| 05:44 | 2 | 11 | 9116 → 0.278 | match / match |
| 05:44 | 3 | 11 | 7651 → 0.233 | match / match |
| 05:55 | 1 | 13 | 10339 → 0.316 | miss / miss |
| 05:55 | 2 | 14 | 13384 → 0.408 | miss / miss |
| 05:55 | 3 | 10 | 8058 → 0.246 | miss / miss |

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

The phone photo matched the enrolled template *better* than the live face
(Hamming 110 against 185–230).

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
   The pilot should sweep coverage first and report convexity curves only
   for captures above the chosen coverage floor.
3. **The corneal cue is not usable at this capture geometry.** One run matched
   order 5/6, the next 0/6, with magnitude 1–2 throughout. At that signal level
   even the categorical order field is noise. Before the pilot spends effort
   on hand-cropped eyes, the capture side needs a brighter flash, a closer
   camera, or a higher-resolution crop, and BUG-003 needs fixing so the
   magnitude field can be compared at all. Record the raw mean RGB delta per
   eye in the pilot, not only the fingerprint.
4. **The face-match threshold admits a phone photo of the subject, and on the
   third attempt preferred it** (Hamming 110 for the photo against 185–230 for
   the live face). A screen replay of the enrolment session is the canonical
   attack and the matcher cannot see it by construction. Not this experiment's
   question, but liveness is carrying the whole load in the demo, and the
   threshold recalibration noted in the thermometer work is not optional.
5. **Attack captures must be logged even when an earlier gate rejects them.**
   Done in the server; the pilot's extraction step should run over every
   capture unconditionally, as the brief already says.

Nothing here changes a constant. The pilot as briefed stands.
