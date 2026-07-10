# SPEC-004: SABLE Codebase Audit — Features, Issues, and Improvement Roadmap

| Field | Value |
|-------|-------|
| **Document ID** | SPEC-004 |
| **Title** | SABLE Codebase Audit |
| **Author** | Claude (AI-assisted) |
| **Date** | 2026-02-16 |
| **Status** | Draft |
| **Branch** | `feat/reusable-fuzzy-extractor` |
| **Classification** | Engineering Audit |

---

## 1. Executive Summary

SABLE (Secure Attested Biometric Library for Edge) is a privacy-preserving biometric verification system using zero-knowledge proofs. The codebase spans ~47 Rust source files across `sable-core` and `demo-server`, plus a TypeScript web frontend. This audit inventories the current feature set, identifies issues and gaps, and proposes concrete improvements organized by priority.

**Key findings:**
- The cryptographic core (Pedersen, Poseidon, Halo2 ZK, fuzzy commitment) is functional and well-tested (568 tests passing: 547 lib + 21 integration, across 52 files)
- The demo server is a working E2E showcase but leaks internal error details to clients
- Several modules (P2P, attestation, mobile FFI, palm biometrics) are architecturally complete but lack real-world integration testing
- No CI/CD pipeline exists — builds are only validated locally
- Security-critical areas (unsafe FFI, NEON intrinsics, key management) need tighter hardening

---

## 2. Current Feature Inventory

### 2.1 Cryptographic Core (`core/src/crypto/`)

| Module | File | Status | Description |
|--------|------|--------|-------------|
| BLS12-381 | `bls381.rs` | Complete | Curve ops, hash-to-curve (RFC 9380), MSM, serialization |
| Pedersen | `pedersen.rs` | Complete | `C = g^f × h^s`, batch ops, 48-byte compressed format |
| Poseidon | `poseidon.rs` | Complete | 8 full + 56 partial rounds, 512-element vector support, NEON SIMD |
| RNG | `rng.rs` | Complete | `getrandom`-backed, 256-bit salt, nonce generation |
| Groth16 | `groth16.rs` | Complete | 199,273 R1CS constraints, Arkworks ecosystem |
| Hashing | `hashing.rs` | Complete | IETF hash-to-curve for generator derivation |
| GF(256) | `gf256.rs` | Complete | Log/exp tables, poly 0x11D, field arithmetic |
| Reed-Solomon | `reed_solomon.rs` | Complete | RS(255, k) encoder/decoder, Berlekamp-Massey |
| Fuzzy Commitment | `fuzzy_commitment.rs` | Complete | Code-offset sketch, Gen/Rep/deterministic Gen |

### 2.2 Zero-Knowledge Proof System (`core/src/zk/halo2/`)

| Module | File | Status | Description |
|--------|------|--------|-------------|
| Quantizer | `quantizer.rs` | Complete | f64 → u8 feature quantization, 512-dim |
| Poseidon Circuit | `poseidon.rs` | Complete | ZK-friendly hash inside circuit |
| Hamming Distance | `hamming.rs` | Complete | Bitwise distance circuit |
| Threshold Check | `threshold_check.rs` | Complete | d ≤ threshold constraint |
| Liveness Circuit | `liveness.rs` | Complete | 16-bit delta fingerprint verification |
| Proof System | `proof.rs` | Complete | IPA-based (transparent setup), ~250ms prove, ~1.8ms verify |
| Hello Circuit | `hello.rs` | Complete | Smoke-test circuit |

### 2.3 Biometric Processing (`core/src/biometric/`)

| Module | File | Status | Description |
|--------|------|--------|-------------|
| Feature Extraction | `feature_extraction.rs` | Complete | Gabor filters, thinning, geometric features |
| Palm Processing | `palm.rs` | Complete | Vein (512-dim) + print (256-dim) extraction |
| Fusion | `fusion.rs` | Complete | Score-level fusion (0.6 vein + 0.4 print) |
| Screen Flash | `screen_flash.rs` | Complete | Reflectance ratio liveness (Tang et al., NDSS 2018) |
| Liveness (NIR) | `liveness.rs` | Complete | NIR pulse/vein temporal analysis |
| Constant-Time | `constant_time.rs` | Complete | Side-channel resistant distance |
| Preprocessing | `preprocessing.rs` | Complete | Image normalization, quality assessment |
| Thresholds | `thresholds.rs` | Complete | Research-validated biometric thresholds |

### 2.4 Protocol & Platform (`core/src/p2p/`, `attestation/`, `mobile/`)

| Module | File | Status | Description |
|--------|------|--------|-------------|
| NFC Transport | `nfc.rs` | Scaffold | NDEF format, simulated transport |
| BLE Transport | `ble.rs` | Scaffold | MTU-aware chunking, simulated |
| Session Mgmt | `session.rs` | Complete | X25519 ECDH + ChaCha20-Poly1305, nonce tracking |
| Fragmentation | `fragmentation.rs` | Complete | Large message reassembly |
| X.509 | `x509.rs` | Complete | Custom OID extensions (L1-L5), cert generation |
| Chain Validation | `chain.rs` | Complete | Path validation, signature verification |
| Trust Store | `truststore.rs` | Complete | Root CA management, pinning |
| Mobile FFI | `ffi.rs` | Complete | C-ABI, unsafe boundary (audited) |
| Keystore | `keystore.rs` | Stub | `TODO: Implement Android/iOS integration` |
| Sensors | `sensors.rs` | Stub | `TODO: Add other sensors` |
| Energy | `energy.rs` | Complete | Power consumption profiling |

### 2.5 Demo Application (`demo/`)

| Component | Status | Description |
|-----------|--------|-------------|
| Axum Server | Complete | REST API: enroll, challenge, prove, verify, liveness, fuzzy |
| Flash Challenge | Complete | HKDF-derived split-screen color, commit-reveal protocol |
| Web Frontend | Complete | TypeScript/Vite, webcam, Human face embeddings |
| Docker Compose | Present | `demo/docker-compose.yml` |

---

## 3. Issues and Findings

### 3.1 Critical — Security

#### OBS-001: Demo Server Leaks Internal Error Details

**Severity:** High
**Location:** `demo/server/src/handlers.rs` (multiple locations)

The demo server returns detailed internal error messages to clients:

```rust
error: format!("Poseidon hash failed: {}", e),     // line 89
error: format!("Halo2 proof generation failed: {}", e), // line 623
```

Despite `sable-core` implementing `PublicError` / `to_public_error()` (REQ-005), the demo server bypasses this entirely and formats raw `SableError` messages into HTTP responses.

**Impact:** Information leakage about internal algorithm names, error states, and code paths.

**Trace:**
- REQ-005 (Error sanitization)
- `core/src/error.rs:111` (`to_public_error()` defined but unused in demo)

---

#### OBS-002: Unsafe NEON Intrinsics Without `#[target_feature]` Guards

**Severity:** Medium
**Location:** `core/src/crypto/poseidon.rs:59-127`

The NEON SIMD code uses `unsafe` blocks with raw intrinsics (`vdupq_n_f32`, `vld1q_f32`, etc.) but is gated only by `#[cfg(target_arch = "aarch64")]`. There are no `#[target_feature(enable = "neon")]` annotations and no runtime feature detection fallback for aarch64 targets that lack NEON (e.g., some embedded ARM64 boards).

**Impact:** UB on aarch64 without NEON; no graceful degradation path.

---

#### OBS-003: Mobile Keystore Integration Is Stubbed

**Severity:** Medium
**Location:** `core/src/mobile/keystore.rs:175,182`

```rust
// TODO: Implement Android Keystore integration
// TODO: Implement iOS Keychain/Secure Enclave integration
```

The keystore trait system is architecturally sound but the actual platform backends are placeholder stubs.

**Impact:** Private keys and biometric templates are not protected by hardware-backed storage on real devices.

---

#### OBS-004: FFI Layer Uses Raw Pointer Dereference Without Null Checks

**Severity:** Medium
**Location:** `core/src/mobile/ffi.rs:163`

```rust
let sable = unsafe { &*handle };
```

The handle is dereferenced without checking for null. A null handle from a caller would cause immediate UB.

**Impact:** Memory safety violation at FFI boundary if called incorrectly.

---

### 3.2 High — Architecture and Correctness

#### OBS-005: No CI/CD Pipeline

**Severity:** High

There are no GitHub Actions, Forgejo CI, Woodpecker, or any other CI configuration files in the repository. The `ci/` directory does not exist. All testing is local only.

**Impact:** No automated regression detection. PRs can merge with broken tests. No automated clippy/fmt/audit checks.

---

#### OBS-006: Dual ZK Proof Systems (Groth16 + Halo2)

**Severity:** Medium
**Location:** `core/Cargo.toml:13-14`, `core/src/crypto/groth16.rs`, `core/src/zk/halo2/`

The codebase maintains both the original Arkworks Groth16 implementation (199,273 R1CS constraints, requires trusted setup) and the newer Halo2 IPA-based system (transparent setup, ~250ms proofs). The demo uses only Halo2. Groth16 remains as dead weight.

**Impact:** Increased compile time, dependency bloat (6 `ark-*` crates always compiled), confusion about which system is canonical.

**Recommendation:** Deprecate Groth16 behind a `legacy-groth16` feature flag or remove entirely.

---

#### OBS-007: Test Count Discrepancy in Documentation

**Severity:** Low
**Location:** `README.md:12`, `IMPLEMENTATION_STATUS.md:49`, `README.md:391`

Documentation reports inconsistent test counts:
- README badge: "519 passing"
- README body: "519 tests passing | 77 Halo2-specific tests"
- `IMPLEMENTATION_STATUS.md`: "396 tests passing (388 lib + 8 integration)"
- Memory notes: "522+ tests total, ~95 halo2-specific"

The actual count has grown as features were added but docs were not updated consistently.

---

#### OBS-008: P2P Transports Are Simulated Only

**Severity:** Medium
**Location:** `core/src/p2p/{nfc.rs, ble.rs}`

NFC and BLE transports implement the `Transport` trait but use in-memory channels. There is no actual platform binding to CoreBluetooth (iOS), Android BLE stack, or NFC hardware.

**Impact:** P2P protocol cannot be used on real devices.

---

### 3.3 Medium — Code Quality and Maintenance

#### OBS-009: Feature Flag Inconsistency Between Core and Demo

**Severity:** Medium
**Location:** `core/Cargo.toml:14`, `demo/server/Cargo.toml:11`

The demo server has its own `halo2-proofs` feature flag (line 11) that is never used — it always compiles `sable-core` with `features = ["zk", "halo2"]`. The `fast-demo` flag is also defined but unused.

---

#### OBS-010: Missing `#[deny(clippy::unwrap_used)]`

**Severity:** Medium
**Location:** `demo/server/src/handlers.rs:775,781`

The demo server uses `unwrap_or()` on parsed integers but elsewhere uses `unwrap()` in non-obvious paths. The core library properly denies unsafe code and requires docs, but doesn't enforce `unwrap` prohibition.

---

#### OBS-011: No Fuzz Target for Halo2 Proof System

**Severity:** Medium
**Location:** `fuzz/fuzz_targets/`

Existing fuzz targets cover: Poseidon hash, fusion, feature normalization, Pedersen commit, feature extraction, FFI API. No fuzz target for Halo2 proof generation/verification or the fuzzy commitment scheme.

**Impact:** New code paths (most complex in the system) lack fuzzing coverage.

---

#### OBS-012: Doc-Tests Have Pre-Existing Failures

**Severity:** Low
**Location:** `core/src/attestation/`, `core/src/mobile/`, `core/src/p2p/`

Three modules have failing doc-tests (noted in memory). These are skipped by convention but indicate documentation drift.

---

#### OBS-013: `sable-presentation.md` in Root Is Stale

**Severity:** Low
**Location:** `/sable-presentation.md`

The presentation file references "Groth16 trusted setup" and older performance numbers that predate the Halo2 migration.

---

### 3.4 Low — Enhancement Opportunities

#### OBS-014: No Structured Logging in Core Library

The core library uses `tracing` only in the demo server. The library itself has no instrumentation spans or events, making production debugging difficult.

---

#### OBS-015: No `no_std` Validation

The library declares `#![cfg_attr(not(feature = "std"), no_std)]` but no CI job or test validates that the `no_std` configuration actually compiles, especially with the Halo2 dependency chain which likely requires `std`.

---

#### OBS-016: Docker Compose Has No Dockerfile

`demo/docker-compose.yml` exists but there is no `Dockerfile` for the demo server, making containerized deployment incomplete.

---

#### OBS-017: BBS+ Selective Disclosure Not Implemented

The README prominently features BBS+ selective disclosure as a key differentiator, but no BBS+ code exists in the codebase. This is mentioned only in the roadmap.

---

#### OBS-018: No Rate Limiting or Session Expiry Cleanup

The demo server stores sessions in memory (`HashMap`) with no TTL eviction or garbage collection. In a long-running demo, memory will grow unbounded.

---

#### OBS-019: Inconsistent GF(256) Polynomial Documentation

**Location:** `core/src/crypto/gf256.rs:1-10`

The module doc comment says "AES irreducible polynomial: x^8 + x^4 + x^3 + x + 1 (0x11B)" but the actual constant is `0x11D` (x^8 + x^4 + x^3 + x^2 + 1) and the code comment correctly documents this. The file-level doc is stale.

---

## 4. Requirements for Improvement

### REQ-101: Implement CI/CD Pipeline

The system SHALL execute automated build, lint, and test checks on every push and pull request WITHIN 10 minutes FOR all contributors WITH all tests passing as success criteria.

**Acceptance criteria:**
- `cargo fmt --check` enforced
- `cargo clippy --all-features -- -D warnings` enforced
- `cargo test --features halo2 -p sable-core --lib --test integration` passes
- Demo server builds successfully
- Runs on Forgejo CI or GitHub Actions

Trace:
- TEST-101: CI pipeline validates on clean checkout
- OBS-005

---

### REQ-102: Sanitize Demo Server Error Responses

The system SHALL use `SableError::to_public_error()` for all client-facing error responses WITHIN the demo server handler layer FOR all HTTP error paths WITH no internal implementation details in response bodies.

**Acceptance criteria:**
- All `format!("...failed: {}", e)` patterns in handlers.rs replaced with `to_public_error()` calls
- Internal errors logged via `tracing::error!` for debugging
- HTTP responses contain only generic error codes (1001, 1002, 1003)

Trace:
- TEST-102: Verify no internal details in error responses
- REQ-005, OBS-001

---

### REQ-103: Add FFI Null-Safety Guards

The system SHALL validate all FFI pointer arguments for null before dereference FOR all public C-ABI functions WITH immediate error return on null input.

Trace:
- TEST-103: FFI null pointer test cases
- OBS-004

---

### REQ-104: Deprecate or Remove Groth16

The system SHALL gate the Groth16 implementation behind a `legacy-groth16` feature flag that is OFF by default FOR reduced compile time and dependency footprint WITH no impact on the Halo2-based proof system.

Trace:
- TEST-104: Build succeeds with and without `legacy-groth16`
- OBS-006

---

### REQ-105: Add Halo2 and Fuzzy Commitment Fuzz Targets

The system SHALL include fuzz targets for Halo2 proof generation/verification and fuzzy commitment Gen/Rep FOR improved coverage of security-critical code paths WITH at least 1 hour of corpus-building without crashes as success criteria.

Trace:
- TEST-105: Fuzz targets build and run
- OBS-011

---

### REQ-106: Fix Documentation Inconsistencies

The system SHALL update README badges, IMPLEMENTATION_STATUS.md, and sable-presentation.md to reflect current test counts, proof system (Halo2 only), and performance numbers FOR accurate project representation.

Trace:
- TEST-106: Documentation matches actual test output
- OBS-007, OBS-013

---

### REQ-107: Session TTL and Garbage Collection

The system SHALL expire enrollment sessions and challenges after a configurable TTL (default: 1 hour) and run periodic garbage collection FOR bounded memory usage WITH no stale sessions persisting beyond 2× TTL.

Trace:
- TEST-107: Sessions are cleaned up after TTL
- OBS-018

---

### REQ-108: Fix GF(256) Documentation Inconsistency

The system SHALL correct the module-level doc comment in `gf256.rs` to accurately reflect the 0x11D polynomial FOR accurate documentation.

Trace:
- TEST-108: Doc comment matches `POLYNOMIAL` constant
- OBS-019

---

### REQ-109: Add `no_std` Compilation Check

The system SHALL validate that `sable-core` with `default-features = false` compiles under `no_std` FOR embedded target compatibility WITH CI enforcement.

Trace:
- TEST-109: `cargo build --no-default-features -p sable-core` succeeds
- OBS-015

---

### REQ-110: Implement BBS+ Selective Disclosure (Roadmap)

The system SHALL implement BBS+ signatures for Verifiable Credential selective disclosure FOR predicate proofs over government-issued attributes WITH integration into the Halo2 composite proof.

**Note:** This is a roadmap item requiring significant cryptographic work. Listed here for traceability.

Trace:
- TEST-110: BBS+ sign/verify/selective-disclose roundtrip
- OBS-017

---

## 5. Architecture Decision Records

### ADR-004: Deprecate Groth16 in Favor of Halo2

**Context:** SABLE originally used Arkworks Groth16 (trusted setup, 199K constraints). The Halo2 IPA system was added later with transparent setup, faster proofs (~250ms vs ~850ms), and smaller proofs (2KB). The demo exclusively uses Halo2.

**Decision:** Gate Groth16 behind `legacy-groth16` feature flag, OFF by default. Remove after one release cycle with no downstream usage.

**Consequences:**
- **Positive:** ~30% faster compile time, fewer dependencies, clearer canonical proof system
- **Negative:** Users relying on Groth16 must opt in; migration path needed
- **Risk:** Low — no known external consumers of Groth16 API

### ADR-005: CI/CD on Forgejo

**Context:** Code is hosted on Codeberg (Forgejo). No CI exists.

**Decision:** Implement Forgejo CI with Woodpecker or Forgejo Actions. Three jobs: lint, test, build-demo.

**Consequences:**
- **Positive:** Automated regression detection, contributor confidence
- **Negative:** CI compute costs, nightly Rust dependency requires managed runner
- **Risk:** Halo2 compile time (~3-5 min) may require caching strategy

---

## 6. Non-Functional Requirements

### NFR-101: CI Build Time

CI pipeline build + test time SHALL be ≤ 15 minutes UNDER cold cache WITH 95th percentile.

### NFR-102: Demo Server Memory

Demo server memory usage SHALL be ≤ 512MB UNDER 100 concurrent sessions WITH session TTL enabled.

### NFR-103: Fuzz Coverage

Fuzz targets SHALL cover all public API entry points of security-critical modules (crypto, zk, fuzzy_commitment) WITH at least 1 hour of crash-free fuzzing per target.

---

## 7. Priority Matrix

| Priority | ID | Title | Effort |
|----------|----|-------|--------|
| P0 (Critical) | REQ-102 | Sanitize demo server errors | 2h |
| P0 (Critical) | REQ-103 | FFI null-safety guards | 1h |
| P1 (High) | REQ-101 | CI/CD pipeline | 4h |
| P1 (High) | REQ-104 | Deprecate Groth16 | 3h |
| P1 (High) | REQ-105 | Halo2 + fuzzy fuzz targets | 3h |
| P2 (Medium) | REQ-106 | Fix doc inconsistencies | 1h |
| P2 (Medium) | REQ-107 | Session TTL + GC | 2h |
| P2 (Medium) | REQ-108 | Fix GF(256) doc | 15m |
| P2 (Medium) | REQ-109 | `no_std` validation | 2h |
| P3 (Roadmap) | REQ-110 | BBS+ selective disclosure | Weeks |

---

## 8. Test Specifications

### TEST-101: CI Pipeline Validation

**Preconditions:** Fresh clone of repository
**Steps:**
1. Run `cargo fmt --check` → exit 0
2. Run `cargo clippy --all-features -- -D warnings` → exit 0
3. Run `cargo test --features halo2 -p sable-core --lib --test integration` → all tests pass
4. Run `cargo build -p demo-server --release` → exit 0
**Postconditions:** All four checks pass

### TEST-102: Error Sanitization

**Preconditions:** Demo server running
**Steps:**
1. Send invalid enrollment request → response contains only code 1001
2. Trigger proof generation failure → response contains only code 1002
3. Verify no response contains "Poseidon", "Halo2", "BLS", or stack traces
**Postconditions:** All error responses use PublicErrorCode format

### TEST-105: Fuzz Target Execution

**Preconditions:** `cargo-fuzz` installed
**Steps:**
1. `cargo +nightly fuzz run fuzz_halo2_proof -- -max_total_time=60` → no crashes
2. `cargo +nightly fuzz run fuzz_fuzzy_commitment -- -max_total_time=60` → no crashes
**Postconditions:** Both targets run for 60s without panics or crashes

---

## 9. Traceability Matrix

```
REQ-101 → TEST-101 → OBS-005
REQ-102 → TEST-102 → OBS-001, REQ-005
REQ-103 → TEST-103 → OBS-004
REQ-104 → TEST-104 → OBS-006
REQ-105 → TEST-105 → OBS-011
REQ-106 → TEST-106 → OBS-007, OBS-013
REQ-107 → TEST-107 → OBS-018
REQ-108 → TEST-108 → OBS-019
REQ-109 → TEST-109 → OBS-015
REQ-110 → TEST-110 → OBS-017
```
