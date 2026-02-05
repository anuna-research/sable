# SABLE Web Demo

Interactive demonstration of SABLE's privacy-preserving biometric authentication using zero-knowledge proofs.

## Overview

This demo showcases how SABLE enables biometric authentication without exposing actual biometric data. Users can:

1. **Enroll** - Simulate a palm scan and create a cryptographic commitment
2. **Authenticate** - Generate a zero-knowledge proof that matches enrolled biometrics
3. **Verify** - Verify the proof and see what was proven vs. what stayed private

## Architecture

```
┌─────────────────────┐         ┌─────────────────────┐
│  Browser (TS/HTML)  │  HTTP   │  Rust Backend       │
│  - Enrollment UI    │ ◄─────► │  - sable-core       │
│  - Auth flow        │         │  - Groth16 proofs   │
│  - Visualizations   │         │  - Session state    │
└─────────────────────┘         └─────────────────────┘
```

The server-side architecture was chosen because:
- Proof generation requires ~850ms and 128MB memory - practical on server
- Complex dependencies (ark-groth16, blstrs) have WASM compilation challenges
- Mirrors production architecture where edge devices generate proofs

## Quick Start

### Prerequisites

- Rust 1.75+ with cargo
- Node.js 18+ with npm

### Running the Demo

1. **Start the backend server:**

```bash
cd demo/server
cargo run --release
```

The server will start on `http://localhost:3000`.

2. **Start the frontend (in a new terminal):**

```bash
cd demo/web
npm install
npm run dev
```

The frontend will start on `http://localhost:5173`.

3. **Open the demo:**

Navigate to `http://localhost:5173` in your browser.

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
curl -X POST http://localhost:3000/api/enroll \
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

### Groth16 ZK-SNARK (~850ms proof, ~12ms verify)
Succinct proof that demonstrates:
- Features hash to the committed value
- Distance between live and enrolled features is below threshold
- Capture timestamp is recent
- Quality score meets minimum threshold

## What's Proven vs. What's Hidden

### Proven (Public)
- User possesses matching biometric features
- Distance is below threshold (0.25)
- Scan was captured recently
- Quality meets minimum standard

### Hidden (Private)
- Actual biometric feature values (512 floats)
- Cryptographic salt
- Exact distance value
- Any identifying biometric patterns

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

| Operation | Target | Typical |
|-----------|--------|---------|
| Poseidon hash | <20ms | ~16ms |
| Pedersen commit | <1ms | ~140μs |
| Proof generation | <1s | ~850ms |
| Verification | <20ms | ~12ms |

## License

Apache-2.0
