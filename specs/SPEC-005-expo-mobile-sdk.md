# SPEC-005: SABLE Expo Mobile SDK

| Field | Value |
|-------|-------|
| **Document ID** | SPEC-005 |
| **Title** | SABLE Expo Mobile SDK |
| **Author** | Claude (AI-assisted) |
| **Date** | 2026-03-13 |
| **Status** | Draft |
| **Classification** | Feature Specification |

---

## 1. Executive Summary

This specification defines an Expo Module (`expo-sable`) that exposes SABLE's zero-knowledge proof primitives to React Native applications via native FFI. The module is a thin bridge — it wraps the existing Rust `staticlib`/`cdylib` (iOS/Android) and exposes commitment generation, 1:1 proof generation, 1:1 proof verification, fuzzy commitment enrollment/reproduction, and salt generation to JavaScript.

Set membership proofs (proving membership in a group of enrolled commitments without revealing which member matched) are an orthogonal concern managed by the enrollment authority, not the client SDK. See SPEC-006 (planned).

The module does **not** include biometric feature extraction, camera access, face embedding, or liveness detection. Those concerns belong to the application layer (e.g., `@vladmandic/human` with `tfjs-react-native`, or any model that produces a compatible embedding vector).

**Target audience**: Third-party developers building privacy-preserving biometric authentication into Expo apps.

**Distribution**: Published to npm as `expo-sable`.

---

## 2. User Profiles

### 2.1 Mobile App Developer

```
Role: React Native / Expo developer integrating biometric authentication
Goals:
  - Add privacy-preserving biometric verification to an existing Expo app
  - Generate and verify ZK proofs on-device without a server round-trip
  - Support both enrollment (commitment creation) and verification (proof generation)
Constraints:
  - May not have Rust or cryptography expertise
  - Needs a JS/TS-first API — no manual native module linking
  - Targets users on older devices (iPhone 8+, Android 7.0+)
  - Must work with Expo managed workflow (or at minimum, Expo prebuild)
Daily workflow:
  1. Install expo-sable via npm
  2. Import TypeScript API
  3. Pass feature vectors (from their own embedding pipeline) to SABLE functions
  4. Receive commitments, proofs, and verification results as typed JS objects
```

### 2.2 Security Auditor

```
Role: Security engineer reviewing an app that uses expo-sable
Goals:
  - Verify that private biometric data never leaves the device unprotected
  - Confirm that ZK proofs are generated and verified correctly
  - Audit the FFI boundary for memory safety and information leakage
Constraints:
  - Needs clear documentation of what is proven and what is not
  - Needs to understand the trust boundary between JS and native
Knowledge:
  - Familiar with ZK proof systems and biometric protocols
  - May not be familiar with Expo or React Native internals
```

---

## 3. Happy Paths

### 3.1 Enrollment (Pedersen Commitment)

```
Preconditions:
  - App has obtained a face embedding (e.g., 1024-dim float array from on-device model)
  - expo-sable is installed and imported

Steps:
  1. App calls Sable.initialize()
     → Module loads, Rust instance created, returns ready signal
  2. App calls Sable.generateSalt()
     → Returns 32-byte salt as Uint8Array
  3. App calls Sable.generateCommitment(features, salt)
     → Returns 48-byte Pedersen commitment as Uint8Array
  4. App stores commitment (public) and salt (private, in secure storage)

Postconditions:
  - Commitment is a 48-byte compressed BLS12-381 G1 point
  - Salt is securely stored on-device
  - No biometric data has left the device

Failure modes:
  - Feature vector wrong length → InvalidInput error with message
  - Salt generation fails (RNG unavailable) → SystemError
  - Device out of memory during commitment → ProcessingFailed
```

### 3.2 Authentication (Halo2 ZK Proof)

```
Preconditions:
  - Enrolled commitment and salt are available on-device
  - Fresh face embedding captured from camera

Steps:
  1. App calls Sable.generateProof(freshFeatures, salt, commitment, { threshold })
     → Returns proof object: { proofBytes: Uint8Array, verified: boolean }
  2. App calls Sable.verifyProof(proofBytes, commitment, { threshold })
     → Returns { verified: boolean }
  3. App acts on verification result (unlock, authorize, etc.)

Postconditions:
  - Proof demonstrates that freshFeatures are within threshold distance of enrolled features
  - Proof is zero-knowledge: verifier learns only the boolean result
  - Entire flow completed on-device, no network required

Failure modes:
  - Proof generation timeout on slow device → ProcessingFailed with timing info
  - Commitment bytes corrupted → InvalidInput
  - Features outside valid range → InvalidInput
```

### 3.3 Enrollment (Fuzzy Commitment)

```
Preconditions:
  - App has obtained a quantized feature vector (512-dim u8 array)
  - expo-sable is installed and imported

Steps:
  1. App calls Sable.initialize()
     → Module ready
  2. App calls Sable.fuzzyEnroll(quantizedFeatures, { errorTolerance })
     → Returns { commitment: Uint8Array, helperData: Uint8Array }
  3. App stores commitment (public) and helperData (public — safe to store alongside)

Postconditions:
  - Commitment is a 32-byte SHA-256 hash
  - Helper data is a code-offset sketch (safe to expose per security model)
  - Reproduction will succeed if fresh features differ in ≤ ~2*errorTolerance positions

Failure modes:
  - Feature vector not 512-dim → InvalidInput
  - errorTolerance out of valid range (0 < t ≤ 127) → InvalidInput
```

### 3.4 Reproduction (Fuzzy Commitment)

```
Preconditions:
  - Stored commitment and helperData from enrollment
  - Fresh quantized feature vector

Steps:
  1. App calls Sable.fuzzyVerify(freshFeatures, helperData, expectedCommitment)
     → Returns { matched: boolean }

Postconditions:
  - Returns true if fresh features are within error tolerance of enrolled features
  - Returns false (not an error) if features are too distant

Failure modes:
  - helperData corrupted or tampered → ProcessingFailed (RS decode failure)
  - Wrong vector length → InvalidInput
```

---

## 4. Requirements

### 4.1 Functional Requirements

```
REQ-001: Module Initialization

The system SHALL create a native SABLE instance when Sable.initialize() is called
and SHALL resolve a Promise upon successful initialization.
The instance SHALL persist for the lifetime of the module (singleton pattern).
Calling initialize() when already initialized SHALL resolve immediately (idempotent).

Trace:
- TEST-001
- CON-001
```

```
REQ-002: Salt Generation

The system SHALL generate a cryptographically secure 32-byte random salt using
the platform's secure RNG (SecRandomCopyBytes on iOS, SecureRandom on Android)
via the Rust SecureRng wrapper.

The salt SHALL be returned as a Uint8Array of exactly 32 bytes.

Trace:
- TEST-002
- CON-002
```

```
REQ-003: Pedersen Commitment Generation

The system SHALL accept a feature vector (Float64Array or number[]) and a 32-byte salt,
and SHALL return a 48-byte Pedersen commitment (compressed BLS12-381 G1 point) as Uint8Array.

The system SHALL accept feature vectors of length 1 to 1024.
If the input vector has more than 512 elements, the system SHALL reduce it to 512
by averaging adjacent pairs (e.g., 1024 → 512). This matches the web demo's conversion.

Trace:
- TEST-003
- CON-003
```

```
REQ-004: Halo2 ZK Proof Generation

The system SHALL accept a feature vector (1–1024 elements), salt, commitment, and threshold,
and SHALL return serialized proof bytes as Uint8Array.

If the feature vector has more than 512 elements, the system SHALL reduce it to 512
by averaging adjacent pairs before proof generation.

Proof generation SHALL execute on a background thread to avoid blocking the JS thread.

Trace:
- TEST-004
- CON-004
```

```
REQ-005: ZK Proof Verification

The system SHALL accept serialized proof bytes, a commitment, and a threshold,
and SHALL return a boolean indicating whether the proof is valid.

Verification SHALL execute on a background thread.

Trace:
- TEST-005
- CON-005
```

```
REQ-006: Fuzzy Commitment Enrollment

The system SHALL accept a 512-element Uint8Array (quantized features) and an error
tolerance parameter t, and SHALL return a commitment (32 bytes) and helper data.

The error tolerance t SHALL be validated: 0 < t ≤ 127.

Trace:
- TEST-006
- CON-006
```

```
REQ-007: Fuzzy Commitment Verification

The system SHALL accept a 512-element Uint8Array (fresh features), helper data,
and expected commitment, and SHALL return a boolean indicating whether the
fresh features reproduce the original commitment within error tolerance.

A mismatch SHALL return false (not throw), as it is a normal outcome.

Trace:
- TEST-007
- CON-007
```

```
REQ-008: Error Sanitization

The system SHALL NOT expose internal error details, file paths, stack traces,
or algorithm internals to the JavaScript layer.

Errors SHALL be mapped to one of three categories: InvalidInput, ProcessingFailed,
SystemError — consistent with the existing FFI error model (REQ-005 in sable-core).

Trace:
- TEST-008
- CON-009
```

```
REQ-009: Memory Safety at FFI Boundary

All data passed across the JS → Native → Rust boundary SHALL be validated
for length, null-safety, and type correctness before being forwarded to Rust FFI functions.

The module SHALL NOT expose raw pointers or manual memory management to JavaScript.
All Rust allocations returned via FFI SHALL be freed by the module, not by the caller.

Trace:
- TEST-009
```

```
REQ-010: Zeroization of Sensitive Data

Salt values and feature vectors SHALL be zeroized from native memory after use.
The module SHALL rely on sable-core's ZeroizeOnDrop implementations for Rust-side cleanup.

The module SHALL document that JavaScript callers are responsible for clearing their
own copies of sensitive data (salts, feature vectors), as the module cannot control
JS garbage collection.

Trace:
- TEST-010
```

### 4.2 Non-Functional Requirements

```
NFR-001: Proof Generation Latency

Proof generation (Halo2, face match) SHALL complete in ≤ 3000ms on devices
meeting the minimum hardware floor (iPhone 8 / A11 Bionic, Snapdragon 625, arm64).

On modern devices (iPhone 12+ / A14, Snapdragon 865+), proof generation
SHALL complete in ≤ 1000ms.

ARMv7 (32-bit Android) is best-effort — latency may exceed 3000ms on these devices.
The module SHALL still function correctly; only the latency target is relaxed.

Measurement: Wall-clock time from JS call to Promise resolution, 95th percentile,
measured over 100 sequential invocations in release mode.

Trace:
- TEST-012
- OBS-001
```

```
NFR-002: Verification Latency

Proof verification SHALL complete in ≤ 100ms on minimum-floor devices.
On modern devices, ≤ 50ms.

Measurement: Same methodology as NFR-001.

Trace:
- TEST-013
- OBS-002
```

```
NFR-003: Proof Size

Serialized Halo2 proof bytes SHALL be ≤ 10KB.

Trace:
- TEST-014
```

```
NFR-004: Binary Size

The native library (per-architecture) SHALL be ≤ 15MB after stripping symbols
and applying LTO.

The total npm package size (including all architectures) SHALL be ≤ 60MB.

Trace:
- TEST-015
```

```
NFR-005: Memory Consumption

Peak memory usage during proof generation SHALL be ≤ 128MB on all target devices.

On devices with < 2GB RAM (e.g., iPhone 8 with 2GB, low-end Android with 1.5GB),
the module SHALL not trigger OOM kills under normal operation.

Trace:
- TEST-016
- OBS-003
```

```
NFR-006: Platform Compatibility

The module SHALL support:
  - iOS 13.0+ (arm64)
  - iOS Simulator (arm64, x86_64)
  - Android API 24+ (arm64-v8a, armeabi-v7a, x86_64)
  - Expo SDK 50+
  - React Native 0.73+

The module SHALL work with Expo prebuild (expo-dev-client).
Expo managed workflow (Expo Go) is explicitly NOT supported due to native code requirement.

Trace:
- TEST-017
```

```
NFR-007: Thread Safety

All exported functions SHALL be safe to call from any JS thread.
Proof generation and verification SHALL execute on background threads
and SHALL NOT block the React Native bridge or JS event loop.

Multiple concurrent calls to different functions SHALL be safe.
Multiple concurrent calls to the same function SHALL be serialized
(single Rust instance, sequential proof generation).

Trace:
- TEST-018
```

```
NFR-008: Offline Operation

All module functions SHALL operate without network access.
The module SHALL NOT make any network requests, DNS lookups, or
phone-home telemetry calls.

Trace:
- TEST-019
```

---

## 5. Architecture Decisions

### ADR-001: Expo Module API vs React Native Turbo Module

**Decision**: Use Expo Modules API (`expo-modules-core`).

**Context**: Two options for native module integration — Expo Modules API and React Native's Turbo Modules (New Architecture). Both support synchronous and asynchronous calls across the JS-native bridge.

**Trade-offs**:

| Factor | Expo Modules API | Turbo Modules |
|--------|-----------------|---------------|
| Expo compatibility | First-class | Requires manual config |
| Swift/Kotlin support | Native | Via codegen layer |
| Async support | Built-in `AsyncFunction` | Via `Promise` |
| Adoption | Growing (Expo ecosystem) | Growing (RN core) |
| Managed workflow | `expo prebuild` | Manual linking |

**Rationale**: The target audience uses Expo. Expo Modules API provides the simplest integration path (`npx expo install expo-sable`), Swift/Kotlin-native authoring (matching existing `platform/ios/` and `platform/android/` bindings), and automatic linking via `expo prebuild`. Turbo Modules would work but add friction for Expo users.

### ADR-002: Halo2 (Transparent Setup) as Default Proof System

**Decision**: The Expo module exposes only the Halo2 proof system, not Groth16.

**Context**: sable-core supports both Groth16 (trusted setup, arkworks) and Halo2 (transparent setup, KZG/IPA). The existing `MobileSable` struct uses Groth16 via `SableGroth16`.

**Trade-offs**:

| Factor | Groth16 | Halo2 |
|--------|---------|-------|
| Trusted setup | Required (toxic waste) | Not required |
| Proof size | ~192 bytes | ~2KB |
| Prover time | ~500ms | ~250ms (Apple Silicon) |
| Verifier time | ~5ms | ~1.8ms |
| Binary size impact | arkworks ecosystem | halo2-base ecosystem |
| Liveness circuit | Not available | Available |

**Rationale**: Halo2's transparent setup eliminates the need to distribute or trust ceremony artifacts in a third-party SDK. Proof size (2KB vs 192B) is negligible for on-device use. Halo2 is faster for both prover and verifier. The liveness circuit is only available in Halo2. A future version could add Groth16 behind a feature flag if needed.

### ADR-003: Thin Bridge — No Feature Extraction in Module

**Decision**: The module exposes only ZK primitives. Feature extraction (camera → embedding) is the app developer's responsibility.

**Context**: The web demo uses `@vladmandic/human` for face embedding. We could bundle a face model into the module, or leave it out.

**Trade-offs**:

| Factor | Bundled embedding | Thin bridge |
|--------|------------------|-------------|
| Binary size | +50-100MB (TFLite model) | No additional size |
| Flexibility | Locked to one model | Any embedding pipeline |
| Maintenance | Model updates coupled to SDK | Decoupled |
| Scope | Full pipeline | Composable primitive |

**Rationale**: Bundling a specific face model constrains developers to one modality (face) and one model architecture. SABLE's ZK primitives work with any biometric modality that produces a feature vector. Keeping the module thin lets developers choose their embedding model (Human, MediaPipe, FaceNet, ArcFace, or non-face biometrics entirely). It also keeps binary size manageable for old devices.

### ADR-004: Data Serialization Across the Bridge

**Decision**: Use `Uint8Array` for all binary data (commitments, proofs, salts, helper data) and `Float64Array`/`number[]` for feature vectors.

**Context**: The Expo Modules bridge supports typed arrays. Binary cryptographic data must cross JS → Swift/Kotlin → Rust boundaries without loss.

**Rationale**: `Uint8Array` maps directly to `[u8]` in Rust and `Data`/`ByteArray` in Swift/Kotlin. `Float64Array` maps to `[f64]` / `[c_double]` in the existing FFI. No JSON serialization overhead. The existing FFI already operates on these types.

### ADR-005: Singleton Rust Instance

**Decision**: The module maintains a single `SableHandle` for the lifetime of the app process.

**Context**: The Rust instance holds cached proving/verification keys (~900ms to generate on first use). Creating multiple instances would waste memory and repeat keygen.

**Rationale**: Keygen cost is amortized over the process lifetime. Thread safety is handled by serializing proof generation calls (NFR-007). This matches the existing `MobileSable` usage pattern.

---

## 6. Contract Specifications

### CON-001: Module Lifecycle

```typescript
interface SableModule {
  /**
   * Initialize the native SABLE instance.
   * Idempotent — resolves immediately if already initialized.
   * First call triggers Halo2 key generation (~900ms).
   */
  initialize(): Promise<void>;

  /**
   * Check if the module is initialized and ready.
   */
  isReady(): boolean;
}
```

Implements: REQ-001
Verified by: TEST-001

### CON-002: Salt Generation

```typescript
interface SableModule {
  /**
   * Generate a cryptographically secure 32-byte salt.
   * @returns 32-byte salt
   * @throws SableError with code InvalidInput if RNG unavailable
   */
  generateSalt(): Promise<Uint8Array>;
}
```

Pre-conditions: Module initialized (REQ-001)
Post-conditions: Returns exactly 32 bytes of cryptographically random data
Error model: SystemError if platform RNG is unavailable

Implements: REQ-002
Verified by: TEST-002

### CON-003: Pedersen Commitment

```typescript
interface SableModule {
  /**
   * Generate a Pedersen commitment from a feature vector and salt.
   *
   * @param features - Biometric feature vector (1–512 elements, float64)
   * @param salt - 32-byte cryptographic salt
   * @returns 48-byte compressed BLS12-381 G1 point
   * @throws SableError with code InvalidInput if features or salt are invalid
   */
  generateCommitment(
    features: number[] | Float64Array,
    salt: Uint8Array
  ): Promise<Uint8Array>;
}
```

Pre-conditions:
- Module initialized
- `features.length` in [1, 1024]
- `salt.length === 32`

Post-conditions:
- Returns exactly 48 bytes
- If `features.length > 512`, features are reduced to 512 by averaging adjacent pairs
- Same (features, salt) always produces same commitment (deterministic)

Error model:
- InvalidInput: features empty, features.length > 1024, wrong salt length, feature values not finite
- ProcessingFailed: commitment computation fails
- SystemError: native crash (should not happen)

Implements: REQ-003
Verified by: TEST-003

### CON-004: Proof Generation

```typescript
interface ProofOptions {
  /** Distance threshold for match (0.0–1.0). Default: 0.25 */
  threshold?: number;
}

interface ProofResult {
  /** Serialized Halo2 proof */
  proofBytes: Uint8Array;
  /** Size of proof in bytes */
  proofSize: number;
  /** Wall-clock time for proof generation in milliseconds */
  durationMs: number;
}

interface SableModule {
  /**
   * Generate a Halo2 ZK proof that features match the enrolled commitment.
   * Runs on a background thread.
   *
   * @param features - Fresh biometric feature vector
   * @param salt - Salt used during enrollment
   * @param commitment - Commitment from enrollment (48 bytes)
   * @param options - Proof options (threshold)
   * @returns Proof result with serialized proof bytes
   */
  generateProof(
    features: number[] | Float64Array,
    salt: Uint8Array,
    commitment: Uint8Array,
    options?: ProofOptions
  ): Promise<ProofResult>;
}
```

Pre-conditions:
- Module initialized
- `features.length` in [1, 1024]
- `salt.length === 32`
- `commitment.length === 48`
- `threshold` in (0.0, 1.0] if provided

Post-conditions:
- `proofBytes.length <= 10240` (NFR-003)
- Proof is valid for the given commitment and threshold

Error model:
- InvalidInput: wrong dimensions, invalid commitment bytes, threshold out of range
- ProcessingFailed: circuit synthesis or proving failure

Implements: REQ-004
Verified by: TEST-004

### CON-005: Proof Verification

```typescript
interface VerifyResult {
  /** Whether the proof is valid */
  verified: boolean;
  /** Wall-clock time for verification in milliseconds */
  durationMs: number;
}

interface SableModule {
  /**
   * Verify a Halo2 ZK proof against a commitment.
   * Runs on a background thread.
   *
   * @param proofBytes - Serialized proof from generateProof()
   * @param commitment - Commitment from enrollment (48 bytes)
   * @param options - Must use same threshold as proof generation
   * @returns Verification result
   */
  verifyProof(
    proofBytes: Uint8Array,
    commitment: Uint8Array,
    options?: ProofOptions
  ): Promise<VerifyResult>;
}
```

Pre-conditions:
- Module initialized
- `proofBytes` is a valid serialized Halo2 proof
- `commitment.length === 48`
- `threshold` matches the value used in proof generation

Post-conditions:
- `verified === true` if and only if the proof is valid for the given commitment and threshold
- An invalid or malformed proof returns `verified: false` (not an error)

Error model:
- InvalidInput: commitment wrong length, threshold out of range
- ProcessingFailed: deserialization failure on severely corrupted proof bytes

Implements: REQ-005
Verified by: TEST-005

### CON-006: Fuzzy Commitment Enrollment

```typescript
interface FuzzyEnrollOptions {
  /** Error correction capacity per RS block. Default: 40.
   *  Total tolerance ≈ 2*t positions out of 512. Valid range: 1–127. */
  errorTolerance?: number;
}

interface FuzzyEnrollResult {
  /** 32-byte SHA-256 commitment */
  commitment: Uint8Array;
  /** Helper data (code-offset sketch). Safe to store publicly. */
  helperData: Uint8Array;
}

interface SableModule {
  /**
   * Enroll using fuzzy commitment (code-offset sketch + Reed-Solomon).
   *
   * @param features - 512-element quantized feature vector (u8 values)
   * @param options - Error tolerance parameter
   * @returns Commitment and helper data
   */
  fuzzyEnroll(
    features: Uint8Array,
    options?: FuzzyEnrollOptions
  ): Promise<FuzzyEnrollResult>;
}
```

Pre-conditions:
- Module initialized
- `features.length === 512`
- `errorTolerance` in [1, 127] if provided

Post-conditions:
- `commitment.length === 32`
- `helperData` is opaque but deterministic for given (features, internal random codeword)

Error model:
- InvalidInput: wrong feature length, errorTolerance out of range

Implements: REQ-006
Verified by: TEST-006

### CON-007: Fuzzy Commitment Verification

```typescript
interface SableModule {
  /**
   * Verify fresh features against a fuzzy commitment.
   *
   * @param features - 512-element quantized feature vector (u8 values)
   * @param helperData - Helper data from fuzzyEnroll()
   * @param expectedCommitment - Commitment from fuzzyEnroll() (32 bytes)
   * @returns true if features reproduce the commitment within tolerance
   */
  fuzzyVerify(
    features: Uint8Array,
    helperData: Uint8Array,
    expectedCommitment: Uint8Array
  ): Promise<boolean>;
}
```

Pre-conditions:
- `features.length === 512`
- `expectedCommitment.length === 32`
- `helperData` was produced by `fuzzyEnroll()`

Post-conditions:
- Returns `true` if Hamming distance between fresh and enrolled features ≤ tolerance
- Returns `false` otherwise (not an error)

Error model:
- InvalidInput: wrong feature length, wrong commitment length
- ProcessingFailed: helperData corrupted (RS decode failure)

Implements: REQ-007
Verified by: TEST-007

### CON-008: Error Model

```typescript
enum SableErrorCode {
  InvalidInput = 1,
  ProcessingFailed = 2,
  SystemError = 3,
}

class SableError extends Error {
  readonly code: SableErrorCode;
  readonly message: string; // Sanitized, no internal details (REQ-008)
}
```

Error messages are generic and do not reveal:
- File paths or line numbers
- Algorithm names or parameters
- Internal state or memory addresses
- Timing information beyond what is in ProofResult.durationMs

Implements: REQ-008
Verified by: TEST-008

---

## 7. Purity Boundary Map

### Pure Core (no I/O, no shared state, deterministic)

- `sable-core` Rust library: all commitment, proof, and verification logic
- Feature quantization (f64 → u8)
- Pedersen commitment: `C = g^f × h^s`
- Halo2 circuit synthesis and proving
- Fuzzy commitment Gen/Rep
- Reed-Solomon encode/decode

### Effectful Shell (orchestrates I/O, calls pure core)

- Expo Module native layer (Swift/Kotlin): FFI calls, thread dispatch, memory management
- `SecureRng` (platform RNG access for salt generation)
- JS bridge: type conversion, Promise resolution

### Boundary Contracts (data crossing the boundary)

| Type | Direction | Format |
|------|-----------|--------|
| Feature vector | JS → Native → Rust | `Float64Array` → `[c_double]` → `&[f64]` |
| Quantized features | JS → Native → Rust | `Uint8Array` → `[c_uchar]` → `&[u8]` |
| Salt | JS → Native → Rust | `Uint8Array(32)` → `[c_uchar; 32]` → `Salt` |
| Commitment | Both directions | `Uint8Array(48)` → `[c_uchar; 48]` → `PedersenCommitment` |
| Proof bytes | Both directions | `Uint8Array` → `Vec<u8>` |
| Helper data | Both directions | `Uint8Array` → `Vec<u8>` |
| Error code | Rust → Native → JS | `SableErrorCode` → `Int` → `SableError` |

### Dependency Rule

Dependencies point inward: JS → Native Bridge → Rust Core. Rust core MUST NOT import from the native bridge or JS layer.

### Enforcement

- Rust: `sable-core` has no dependency on Expo, React Native, or platform-specific code (gated behind `mobile` feature)
- Native: Swift/Kotlin modules import the Rust staticlib/cdylib but Rust does not import Swift/Kotlin
- JS: TypeScript layer imports from Expo Modules; native layer does not import JS

---

## 8. Test Specifications

```
TEST-001: Module Initialization

Verify that initialize() resolves successfully on first call.
Verify that initialize() is idempotent (second call resolves immediately).
Verify that isReady() returns false before init and true after.

Implements: REQ-001
```

```
TEST-002: Salt Generation

Verify that generateSalt() returns exactly 32 bytes.
Verify that two sequential calls produce different salts (with overwhelming probability).
Verify that salt bytes are not all zeros.

Implements: REQ-002
```

```
TEST-003: Pedersen Commitment

Verify that generateCommitment(features, salt) returns exactly 48 bytes.
Verify determinism: same (features, salt) → same commitment.
Verify that different features → different commitment.
Verify that different salt → different commitment.
Verify InvalidInput error for empty features, features.length > 512, salt.length ≠ 32.
Verify InvalidInput error for NaN or Infinity in features.

Implements: REQ-003
```

```
TEST-004: Proof Generation

Verify that generateProof() returns proofBytes of ≤ 10KB.
Verify that durationMs is populated and > 0.
Verify that proof generation does not block the JS thread (measure main thread frame drops).
Verify InvalidInput error for mismatched commitment length, invalid threshold.

Implements: REQ-004
```

```
TEST-005: Proof Verification

Verify that a proof generated with matching features verifies as true.
Verify that a proof generated with distant features verifies as false.
Verify that a tampered proofBytes returns verified: false (not an error).
Verify that a completely random byte array returns verified: false or ProcessingFailed.
Verify that threshold mismatch between prove and verify produces verified: false.

Implements: REQ-005
```

```
TEST-006: Fuzzy Enrollment

Verify that fuzzyEnroll() returns 32-byte commitment and non-empty helperData.
Verify that same features with default tolerance produce consistent commitment.
Verify InvalidInput for features.length ≠ 512.
Verify InvalidInput for errorTolerance = 0 or errorTolerance = 128.

Implements: REQ-006
```

```
TEST-007: Fuzzy Verification

Verify that fuzzyVerify() returns true for identical features.
Verify that fuzzyVerify() returns true for features differing in ≤ 2*t positions.
Verify that fuzzyVerify() returns false for features differing in > 2*t positions.
Verify that corrupted helperData produces ProcessingFailed.

Implements: REQ-007
```

```
TEST-008: Error Sanitization

Verify that no error message contains file paths, function names, or stack traces.
Verify that all errors are instances of SableError with a valid SableErrorCode.
Verify that error messages are human-readable but generic.

Implements: REQ-008
```

```
TEST-009: Memory Safety

Verify no memory leaks across 1000 sequential commitment + proof cycles (measure RSS).
Verify that passing null/undefined for required parameters produces InvalidInput, not a crash.
Verify that passing oversized arrays does not cause buffer overflows.

Implements: REQ-009
```

```
TEST-010: Zeroization

Verify (via native instrumentation) that salt memory is zeroed after FFI call completes.
Verify that feature vector memory is not retained in native heap after call completes.

Implements: REQ-010
```

```
TEST-012: Proof Generation Latency (NFR-001)

Benchmark proof generation on minimum-floor device (or simulator profile).
Assert: p95 ≤ 3000ms over 100 invocations.
Benchmark on modern device.
Assert: p95 ≤ 1000ms over 100 invocations.

Implements: NFR-001
```

```
TEST-013: Verification Latency (NFR-002)

Benchmark verification on minimum-floor device.
Assert: p95 ≤ 100ms.
Benchmark on modern device.
Assert: p95 ≤ 50ms.

Implements: NFR-002
```

```
TEST-014: Proof Size (NFR-003)

Assert: proofBytes.length ≤ 10240 for all generated proofs.

Implements: NFR-003
```

```
TEST-015: Binary Size (NFR-004)

Measure stripped .a (iOS) and .so (Android) per architecture.
Assert: each ≤ 15MB.
Measure npm package tarball size.
Assert: ≤ 60MB.

Implements: NFR-004
```

```
TEST-016: Memory Consumption (NFR-005)

Profile peak RSS during proof generation on minimum-floor device.
Assert: peak RSS increase ≤ 128MB.

Implements: NFR-005
```

```
TEST-017: Platform Compatibility (NFR-006)

Build and run test suite on:
  - iOS 13 simulator (arm64)
  - iOS 17 device (arm64)
  - Android API 24 emulator (x86_64)
  - Android API 34 device (arm64-v8a)

Implements: NFR-006
```

```
TEST-018: Thread Safety (NFR-007)

Call generateProof() and verifyProof() concurrently from JS.
Verify no crashes, deadlocks, or data corruption.
Verify JS thread remains responsive (< 16ms frame time).

Implements: NFR-007
```

```
TEST-019: Offline Operation (NFR-008)

Run full enrollment + authentication flow with network disabled (airplane mode).
Verify all operations succeed.
Verify no DNS lookups or network socket creation (via network monitor).

Implements: NFR-008
```

---

## 9. Observability

```
OBS-001: Proof Generation Duration

Metric: sable.proof.generate.duration_ms
Type: Histogram
Labels: device_model, os_version, feature_count
Purpose: Track proof generation latency across device population to validate NFR-001.
```

```
OBS-002: Verification Duration

Metric: sable.proof.verify.duration_ms
Type: Histogram
Labels: device_model, os_version
Purpose: Track verification latency to validate NFR-002.
```

```
OBS-003: Peak Memory

Metric: sable.proof.generate.peak_memory_bytes
Type: Gauge
Labels: device_model, os_version
Purpose: Monitor memory consumption to validate NFR-005 and detect regression.
```

**Note**: These metrics are exposed via the `ProofResult.durationMs` and `VerifyResult.durationMs` fields. The module itself does not transmit telemetry (NFR-008). It is the app developer's responsibility to collect and report these metrics if desired.

---

## 10. Project Structure

```
sable/
  platform/
    expo/                          ← Expo Module package
      package.json                 # expo-sable npm package
      tsconfig.json
      expo-module.config.json      # Expo module manifest
      src/
        index.ts                   # Public TypeScript API
        Sable.types.ts             # Type definitions
        SableModule.ts             # Native module binding
      ios/
        SableModule.swift          # Expo Module definition (iOS)
        SableModule.podspec        # CocoaPods spec linking libsable_core.a
      android/
        src/main/java/.../
          SableModule.kt           # Expo Module definition (Android)
        build.gradle               # Links libsable_core.so via JNI
      scripts/
        build-rust.sh              # Cross-compile Rust for all targets
  demo/
    mobile/                        ← Expo demo app (separate from module)
      app/
      package.json                 # depends on expo-sable
```

---

## 11. Open Questions

All open questions have been resolved:

1. **Halo2 on ARMv7**: Keep 32-bit Android support. Accept higher latency on ARMv7 devices — NFR-001 latency targets apply to the minimum floor (arm64), with ARMv7 treated as best-effort.

2. **Proving key distribution**: Runtime generation. The proving key is generated on first `initialize()` call (~900ms). No pre-bundled keys in the npm package. This keeps package size smaller and avoids versioning issues when circuit parameters change.

3. **Feature vector dimensionality**: The module handles 1024→512 conversion internally. If a 1024-element feature vector is passed, the module averages adjacent pairs to produce 512 elements (matching the web demo's conversion). Feature vectors of 1–512 elements are passed through unchanged.

---

**END OF SPECIFICATION**
