# SABLE Web Demo

Interactive demonstration of SABLE's privacy-preserving biometric authentication using zero-knowledge proofs.

## Overview

This demo showcases how SABLE enables biometric authentication without exposing actual biometric data. Users can:

1. **Enroll** - Capture your face via webcam, thermometer-encode the embedding, and register a Poseidon template commitment (plus a Pedersen commitment, or a fuzzy-extractor commitment in the opt-in mode)
2. **Authenticate** - Recapture your face, run the four-quadrant flash liveness challenge, and generate a Halo2 proof that computes the biometric distance in-circuit, binds the template commitment, and carries a liveness bit bound to the challenge
3. **Verify** - Verify the proof and see what was proven vs. what stayed private

## Architecture

```
┌─────────────────────┐         ┌─────────────────────┐
│  Browser (TS/HTML)  │  HTTP   │  Rust Backend       │
│  - Webcam + Human   │ ◄─────► │  - sable-core       │
│  - Flash challenge  │         │  - Halo2 prover     │
│  - Iris crops       │         │  - Session state    │
└─────────────────────┘         └─────────────────────┘
```

The server-side prover was chosen because:
- Proof generation takes ~1-1.5s and a few hundred MB on a laptop - fine on a server, not yet in the browser
- halo2-lib has no WASM build in this project
- Mirrors production architecture where the prover runs on a trusted device

## Quick Start

### Prerequisites

- Nightly Rust via rustup (`rust-toolchain.toml` pins it)
- Node.js 18+ with npm

### Running the Demo

1. **Start the backend server:**

```bash
cd demo/server
cargo run --release --features halo2-proofs
```

The server will start on `http://localhost:3001` (override with `PORT`). Keygen for the Halo2 circuit runs once at startup and takes a couple of seconds.

2. **Start the frontend (in a new terminal):**

```bash
cd demo/web
npm install
npm run dev
```

The frontend will start on `http://localhost:5173`.

3. **Open the demo:**

Navigate to `http://localhost:5173` in your browser.

### Geometric liveness (SPEC-006)

The prove endpoint also runs the photometric convexity extractor on the fixed
central 60% face region of each flash round, matching the spatial gate. The
cropped region must be at least 64×64 pixels. This excludes the outer background;
it remains a fixed capture region, not a detected face mask. When the client sends
iris crops, the server also runs the corneal glint extractor. The browser crops
from retained camera canvases before JPEG compression and encodes the crops as
PNG. When `SABLE_CORNEAL_TOLERANCE` is configured, missing flash evidence or
missing/invalid eye crops reject the request instead of disabling the check. Both
are reported in the prove response (`photometric_rounds`, `corneal_rounds`) and
in the server log. Their circuit floors ship at zero (ADR-010), so they do not
gate the proof unless enabled:

```bash
# Legacy liveness thresholds in the circuit: colour (max Hamming distance over
# the 11 direction bits), spatial (min Hamming distance between adjacent
# quadrants), magnitude (min observed magnitude). Defaults 5,1,3.
SABLE_LIVENESS_THRESHOLDS=6,1,1 \
# Delta quantiser scale: the channel delta that maps to magnitude 31. Default
# 128; a webcam reflects the flash as a 4-8 unit delta, so 16-32 is realistic.
SABLE_MAGNITUDE_SCALE=32 \
# Arm the in-circuit corneal check: max ordinal delta on the ratio fields, then
# the minimum observed glint magnitude (a floor; the composite has none).
SABLE_CORNEAL_TOLERANCE=15,1 \
# Arm the geometry floors: minimum responding patches (of 16), minimum
# convexity (Q15 over [0,2]). Zero disables each.
SABLE_GEOMETRY_FLOORS=8,0 \
cargo run --release --features halo2-proofs
```

**Demo profile that yields liveness = 1 for a real face on a webcam** (the
legacy fingerprint checks made vacuous, the coverage floor armed; see SPEC-006
REQ-126 for why the fingerprint checks cannot pass on webcam data):

```bash
SABLE_LIVENESS_THRESHOLDS=11,0,0 SABLE_GEOMETRY_FLOORS=8,0 \
cargo run --release --features halo2-proofs
```

The result screen shows which checks were live for each proof and, when the
in-circuit bit is 0, which check failed in which round.

### Rolling-shutter temporal extension (SPEC-008)

The core library derives a 12-symbol red/green/blue/white waveform from the same
client and server nonces and constrains one cyclic phase across three four-band
frames. Frame starts must be exactly four display ticks apart. Applications may
enable this relation only after a verifier-owned platform capture validator has
bound protected camera evidence to the same challenge and frame hashes.

The web server has no protected camera channel. Setting
`SABLE_ROLLING_SHUTTER_OBSERVE=true` lets `/api/auth/prove` accept an optional
decoded `rolling_shutter` object and return `rolling_shutter_observation`
diagnostics when it is present.
The report is explicitly `observe-only`; it keeps `enabled_in_circuit` and
`capture_validated` false. Its match result does not change authentication. The
proof request schema has no field through which a client can claim capture
validation.

Every value above is a demo guess; none is validated (SPEC-006 ADR-010, BUG-003).
The server logs the raw mean RGB delta per quadrant on each prove request so
the scale can be calibrated from real captures.

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/health` | GET | Health check |
| `/api/enroll` | POST | Create biometric enrollment |
| `/api/auth/challenge` | POST | Get authentication challenge |
| `/api/auth/prove` | POST | Generate ZK proof |
| `/api/verify` | POST | Verify ZK proof |

### Example: Enrollment

```bash
curl -X POST http://localhost:3001/api/enroll \
  -H "Content-Type: application/json" \
  -d '{"user_id": "demo-user"}'
```

Response:
```json
{
  "session_id": "uuid...",
  "commitment_hex": "a1b2c3...",
  "feature_preview": [0.5, -0.3, ...],
  "quality_score": 0.85,
  "timings": {
    "feature_generation_ms": 0.1,
    "poseidon_hash_ms": 16.2,
    "pedersen_commit_ms": 0.14,
    "total_ms": 16.5
  }
}
```

## Cryptographic Building Blocks

### Poseidon Hash (~16ms)
ZK-friendly hash function that maps 512 biometric features to a single BLS12-381 field element.

### Pedersen Commitment (~140μs)
Hiding commitment: `C = g^hash × h^salt`
- **Binding**: Can't find two messages with same commitment
- **Hiding**: Commitment reveals nothing about the message

### Halo2 proof (~1-1.5s proof, ~2ms verify, 2KB)
Transparent-setup proof on BN254 whose circuit constrains:
- The enrolled template matches its Poseidon commitment (a public input)
- The Hamming distance between thermometer-encoded embeddings is within the public threshold
- The reflectance fingerprints and geometric evidence satisfy the liveness relation, yielding one public liveness bit
- The challenge nonces and every liveness parameter hash to the public challenge digest

## What's Proven vs. What's Hidden

### Proven (Public)
- The live embedding is within the Hamming threshold of the committed template
- Which template: its Poseidon commitment
- One liveness bit, and the digest naming the challenge and the parameters it was checked under
- Server-side only, not in the proof: scan quality and the floating-point reflectance check

### Hidden (Private)
- Actual biometric feature values (512 floats)
- Cryptographic salt
- Exact distance value
- Any identifying biometric patterns

## Security Model & Limitations

### Coin-Flip Spatial Liveness Protocol

The demo implements a challenge-response liveness protocol based on Tang et al. (NDSS 2018) with a **coin-flip commitment scheme** and **split-screen spatial verification**. Neither party alone can predict or control the flash pattern.

#### Protocol Steps

```
1. COMMIT    POST /api/auth/challenge
             Client sends: {session_id, client_commitment: SHA-256(c_nonce)}
             Server generates s_nonce, stores client_commitment
             Server returns: {challenge_id, nonce_hex: s_nonce}

2. FLASH     Client computes: pattern = HKDF-SHA256(c_nonce || s_nonce)
               → 3 rounds × 2 regions (top/bottom) = 6 RGB colors
             Client captures baseline frame (ambient lighting)
             Client flashes 3 split-screen rounds, captures one frame per round
             Total flash time: ~1.3s

3. VERIFY    POST /api/auth/prove
             Client reveals: {challenge_id, c_nonce, flash_frames, face_embedding}
             Server checks:
               a. SHA-256(c_nonce) == stored client_commitment  (commit binding)
               b. Recompute pattern = HKDF-SHA256(c_nonce || s_nonce)
               c. Per-region color shift verification (upper/lower face halves)
               d. Spatial differentiation check (3D geometry proof)
               e. Laplacian smoothness + Halo2 biometric ZK proof
             Returns: {proof_hex, liveness_passed, region_match_scores, ...}
```

#### Trust Model

| Property | Mechanism | Guarantees |
|---|---|---|
| Server cannot predict pattern alone | Coin-flip: pattern = HKDF(c_nonce \|\| s_nonce); server never sees c_nonce until reveal | Server cannot pre-select a "friendly" challenge |
| Client cannot predict pattern alone | Commit-before-reveal: client commits SHA-256(c_nonce) before seeing s_nonce | Client cannot choose c_nonce to produce a known pattern |
| No enrollment salt exposure | Flash derivation uses only session nonces, not the enrollment salt | Salt compromise in one protocol has zero propagation |
| 3D geometry verification | Split-screen top/bottom colors produce different reflectance on curved faces | Flat surfaces (photos, screens) reflect both regions identically and fail |

#### Attack Analysis

| Attack | Old Model (single white flash) | Coin-Flip Spatial Model |
|---|---|---|
| **Pre-recorded frame replay** | Succeeds (flash is always white, pairs are replayable) | Fails: attacker cannot predict the 6-color pattern before commit |
| **Photo held to honest webcam** | Detected by Laplacian smoothness check | Detected by Laplacian + spatial differentiation (flat surface) |
| **Screen displaying a face video** | Detected by Laplacian smoothness check | Detected by Laplacian + spatial differentiation (flat surface) |
| **Server collusion / biased challenge** | N/A (no challenge) | Fails: server cannot bias pattern without knowing c_nonce |
| **Client-controlled capture (modified browser)** | Succeeds | Partially mitigated: must synthesize spatially consistent 3D reflectance for an unpredictable pattern in real time (see Remaining Limitations below) |

#### Message Space

The protocol's unpredictability stems from the color pattern entropy:

- ~30 distinguishable color directions per region (limited by camera noise floor and skin reflectance bandwidth)
- 6 independent region-challenges (3 rounds x 2 regions)
- **Total: 30^6 = 729,000,000 possible patterns (~30 bits)**
- Plus: spatial consistency constraint (flat surfaces fail regardless of color match)

For comparison, a single white flash provides 1 bit (flash vs. no-flash).

#### Comparison to Previous Single-White-Flash Model

| Dimension | Single White Flash | Coin-Flip Spatial |
|---|---|---|
| Challenge entropy | ~1 bit | ~30 bits |
| Replay resistance | None (static pattern) | Yes (unpredictable pattern per session) |
| Server trust required | Low (no challenge to bias) | None (coin-flip prevents bias) |
| 3D geometry check | No | Yes (split-screen differential) |
| Latency | ~0.5s (1 flash + 1 capture) | ~1.3s (3 rounds + baseline) |
| WCAG photosensitivity | Marginal (single bright flash) | Controlled (see safety measures below) |

#### Remaining Limitation: Client Controls Capture

The fundamental limitation of any browser-based liveness protocol is that the client controls the camera pipeline. A sufficiently sophisticated attacker who controls the browser can:

1. Intercept the derived pattern after both nonces are known
2. Render a synthetic face with correct spatially-varying reflectance
3. Submit the synthetic frames as if from the webcam

This attack requires **real-time 3D rendering** of plausible facial reflectance for an unpredictable pattern, which is a significantly higher bar than replaying static frames, but it is not impossible.

##### Hardware-Based Mitigations for the Client-Trust Gap

These approaches progressively close the gap, ordered by implementation complexity:

1. **Platform attestation (WebAuthn / Play Integrity / App Attest).** Verify the client application has not been tampered with. Shifts trust from "the software behaves correctly" to "the platform's attestation mechanism is sound."

2. **Signed camera frames (C2PA / Android Protected Confirmation).** Cryptographically signed sensor output proves the image came from real hardware at a specific time, preventing frame injection even on a compromised OS.

3. **Trusted Execution Environment (ARM TrustZone / Intel SGX).** Run capture and liveness analysis inside a TEE. Even a compromised OS cannot tamper with the capture pipeline. This is the architecture SABLE's core library targets for production.

4. **Dedicated NIR hardware with firmware attestation.** The core library's `NirLivenessExtractor` is designed for tamper-resistant NIR sensors that measure physiological signals (pulse, vein contrast). Combined with ZK proofs, the verifier trusts the hardware and the proof math rather than any software in between.

The production SABLE architecture targets options 3 and 4, where liveness signals are captured by trusted hardware and proven in zero-knowledge. The demo uses the coin-flip spatial protocol as the strongest purely software-based approach feasible in a browser.

#### WCAG 2.3.1 Photosensitive Safety

The flash sequence is designed to comply with WCAG 2.3.1 (Three Flashes or Below Threshold):

- **3 flashes over ~1.3s** stays within the "three flashes per second" safe limit
- Each flash uses **muted, mid-saturation colors** (not full-brightness white)
- Split-screen design means each region covers roughly half the viewport, reducing the flashing area
- A **prefers-reduced-motion** media query can disable the flash UI entirely (authentication falls back to ZK-only without liveness)

#### Mobile UX Considerations

- **Front camera field of view**: Mobile front cameras have wider FOV; the split-screen regions are sized to ensure the face occupies enough of each region for measurable reflectance
- **Screen brightness variance**: HKDF-derived colors are clamped to a luminance range that produces detectable reflectance across typical mobile brightness settings (40-100%)
- **Ambient light interference**: The baseline frame subtraction compensates for ambient light; the protocol works in indoor lighting but may degrade in direct sunlight
- **Battery and thermal**: 3 frames + 1 baseline is lightweight; no continuous video capture needed

## Development

### Backend Structure

```
demo/server/
├── Cargo.toml
└── src/
    ├── main.rs          # Axum server setup
    ├── handlers.rs      # API endpoint handlers
    ├── state.rs         # Session management
    └── simulation.rs    # Biometric simulation
```

### Frontend Structure

```
demo/web/
├── package.json
├── vite.config.ts
├── index.html
└── src/
    ├── main.ts          # App entry, state management
    ├── api.ts           # REST client
    ├── screens/         # UI screens
    └── styles/          # CSS
```

### Building for Production

```bash
# Build frontend
cd demo/web
npm run build

# Build backend (serves frontend from dist/)
cd demo/server
cargo build --release
```

## Performance Targets

| Operation | Target | Typical (Apple M4, release) |
|-----------|--------|-----------------------------|
| Poseidon hash | <20ms | ~16ms |
| Pedersen commit | <1ms | ~140μs |
| Halo2 keygen (once at startup) | <5s | ~2s |
| Proof generation (match + liveness, k=16) | <2s | ~1.0-1.5s |
| Verification | <20ms | ~2ms |

## License

Apache-2.0
