# SABLE Security Audit Checklist

**Document Version:** 1.0
**Last Updated:** 2026-02-02
**Prepared For:** Formal Security Audit

## Overview

This checklist documents all cryptographic and biometric components requiring security audit review. Items are organized by component with specific code locations, security properties to verify, and known issues for auditor attention.

---

## Cryptographic Components

### BLS12-381 Implementation (`core/src/crypto/bls381.rs`)

- [ ] **Curve operations correctness**
  - Verify `blstrs` library integration is correct
  - Validate point serialization/deserialization (compressed 48-byte format)
  - Check multi-scalar multiplication implementation

- [ ] **IETF hash-to-curve compliance (RFC 9380)**
  - Verify deterministic generator derivation (g, h)
  - Validate domain separation tags
  - Confirm hash function parameters match specification

- [ ] **Constant-time operations**
  - Review all scalar multiplication for timing side-channels
  - Verify no early-exit conditions in curve operations
  - Audit conditional branches in point operations

- [ ] **Independent generator verification**
  - Confirm generators g and h have no known discrete log relationship
  - Verify derivation from nothing-up-my-sleeve values

### Poseidon Hash Function (`core/src/crypto/poseidon.rs`)

- [ ] **Parameter validation**
  - Verify 8 full rounds + 56 partial rounds configuration
  - Validate S-box function (x^5) implementation
  - Confirm MDS matrix dimensions and constants

- [ ] **Security margin verification**
  - Validate parameters against known cryptanalytic attacks
  - Verify round constants are derived deterministically
  - Check state width and rate parameters

- [ ] **512-element biometric vector support**
  - Verify correct chunking/padding for large inputs
  - Confirm domain separation for different input sizes
  - Validate fixed-point arithmetic for mobile compatibility

- [ ] **Z-score feature normalization**
  - Review statistical normalization implementation
  - Verify no information leakage through normalization

### Pedersen Commitments (`core/src/crypto/pedersen.rs`)

- [ ] **Binding property**
  - Verify computational binding: infeasible to find (f1, s1) != (f2, s2) where C(f1, s1) = C(f2, s2)
  - Review for any weaknesses in commitment scheme

- [ ] **Hiding property**
  - Verify perfect hiding: C reveals no information about f
  - Confirm randomness source for blinding factor s

- [ ] **Commitment computation: C = g^f * h^s**
  - Validate exponentiation correctness
  - Verify group operations are performed correctly
  - Check for point-at-infinity handling

- [ ] **Homomorphic addition properties**
  - Verify C1 + C2 = C(f1 + f2, s1 + s2)
  - Review batch commitment operations

- [ ] **Serialization security (48-byte compressed format)**
  - Verify point compression is correct
  - Check for malleability in serialization format

- [ ] **Memory zeroing for secrets**
  - Audit `zeroize` usage on scalar/salt types
  - Verify Drop implementations clear sensitive data

### Groth16 Implementation (`core/src/crypto/groth16.rs`)

- [ ] **Circuit soundness**
  - Verify R1CS constraint system is correct
  - Check for constraint under-specification
  - Audit witness assignment logic

- [ ] **Zero-knowledge property**
  - Confirm proof reveals nothing beyond statement validity
  - Verify no information leakage in proof construction

- [ ] **Trusted setup ceremony security**
  - Review `TrustedSetupCeremony` implementation
  - Verify contribution verification logic
  - Audit toxic waste attestation collection
  - See ADR-003 for ceremony protocol documentation

- [ ] **Arkworks integration**
  - Verify ark-groth16, ark-snark, ark-relations usage
  - Check for version-specific vulnerabilities
  - Audit custom circuit implementations

- [ ] **Circuit components**
  - [ ] Poseidon hash constraints
  - [ ] Pedersen commitment verification in R1CS
  - [ ] Euclidean distance calculation constraints
  - [ ] Range proofs for threshold compliance
  - [ ] Temporal verification constraints

### Random Number Generation (`core/src/crypto/rng.rs`)

- [ ] **Entropy source audit**
  - Verify `getrandom` crate usage is correct
  - Confirm platform entropy sources are adequate
  - Check fallback behavior on entropy exhaustion

- [ ] **256-bit salt generation**
  - Verify uniform distribution
  - Check for bias in generation

- [ ] **Secure memory types**
  - Audit `SecureRng` zeroization on drop
  - Verify no copies of sensitive data remain in memory

- [ ] **Thread safety**
  - Review concurrent access patterns
  - Verify no race conditions in RNG state

---

## Biometric Components

### Feature Extraction (`core/src/biometric/feature_extraction.rs`)

- [ ] **Feature extraction determinism**
  - Verify same input produces same output
  - Check for floating-point non-determinism
  - Audit any randomized components

- [ ] **Input validation**
  - [ ] **KNOWN ISSUE (CRITICAL):** Missing bounds checking on image dimensions
  - [ ] **KNOWN ISSUE (CRITICAL):** No validation of feature vector sizes
  - Recommend: Add comprehensive input validation

- [ ] **CNN simulation security**
  - [ ] **KNOWN ISSUE (CRITICAL):** `feature_extraction.rs:540` uses PRNG instead of real CNN
  - This is acceptable for testing but MUST be replaced for production

- [ ] **Hardcoded confidence values**
  - [ ] **KNOWN ISSUE (CRITICAL):** `feature_extraction.rs:35,60` uses fixed 0.95/0.92
  - Should calculate actual quality metrics

### Constant-Time Distance Calculations (`core/src/biometric/constant_time.rs`)

- [ ] **Timing side-channel resistance**
  - Verify `constant_time_euclidean_distance` has no data-dependent branches
  - Check `constant_time_cosine_similarity` for timing leaks
  - Audit `constant_time_normalized_distance`

- [ ] **Implementation correctness**
  - Verify `subtle` crate usage is correct
  - Check `Choice` and `ConditionallySelectable` usage
  - Audit `ct_select_f64` implementation

- [ ] **Fixed iteration count**
  - Confirm no early exit conditions
  - Verify all vector elements are processed

- [ ] **Known limitation:**
  - [ ] `ct_f64_gt` uses branch-based comparison (see line 226-227)
  - This may introduce timing variance; requires validation

### Quality Threshold Validation (`core/src/biometric/thresholds.rs`, `preprocessing.rs`)

- [ ] **Threshold values**
  - Quality score threshold: 0.70 (see ADR-002)
  - Completeness threshold: 0.80
  - Maximum FAR: 0.001 (0.1%)
  - Expected FRR: 0.05 (5%)
  - Minimum SNR: 18 dB

- [ ] **Research validation**
  - See ADR-002 for peer-reviewed references
  - [ ] **KNOWN ISSUE:** Threshold inconsistency - global 0.77 vs individual 0.75/0.80

- [ ] **Fusion weight validation**
  - [ ] **KNOWN ISSUE:** No verification that weights sum to 1.0
  - Review `core/src/biometric/fusion.rs`

### Template Security (`core/src/biometric/palm.rs`)

- [ ] **Template storage format**
  - Verify templates are commitment-protected
  - Check for plaintext feature exposure

- [ ] **Template lifecycle**
  - Audit template creation timestamp handling
  - Verify secure deletion mechanisms

---

## Mobile Integration

### FFI Boundary Security (`core/src/mobile/ffi.rs`)

- [ ] **Memory safety at FFI boundary**
  - Audit all `unsafe` blocks
  - Verify pointer validity checks (null pointer handling)
  - Check array bounds validation

- [ ] **Error sanitization (REQ-005)**
  - Verify `SableErrorCode` does not leak implementation details
  - Audit `sanitize_error` function
  - Confirm error messages are generic

- [ ] **Handle lifecycle management**
  - Verify `sable_new()` / `sable_free()` pairing
  - Check for use-after-free vulnerabilities
  - Audit `sable_free_result()` for memory leaks

- [ ] **Input validation**
  - Check all input parameters for validity
  - Verify buffer length parameters are correct

### Memory Management (`core/src/mobile/`)

- [ ] **Zeroization of sensitive data**
  - Audit `SessionKey` zeroization (`ZeroizeOnDrop`)
  - Verify salt zeroization after use
  - Check feature vector clearing

- [ ] **No-std compatibility**
  - Verify heap allocations are minimized
  - Check for stack-based secret handling

### Keystore Integration (`core/src/mobile/keystore.rs`)

- [ ] **Android Keystore abstraction**
  - Verify key storage policies are correct
  - Audit biometric authentication requirements

- [ ] **iOS Keychain integration**
  - Verify Keychain access controls
  - Audit Touch ID/Face ID integration

- [ ] **Access policy enforcement**
  - Check biometric/PIN/both policies
  - Verify policy cannot be bypassed

---

## P2P Protocol

### Session Key Exchange (`core/src/p2p/session.rs`)

- [ ] **X25519 ECDH implementation**
  - Verify `x25519_dalek` usage is correct
  - Audit ephemeral key generation
  - Check shared secret derivation

- [ ] **Key derivation**
  - [ ] **RECOMMENDATION:** Consider HKDF for additional key derivation (see line 135)
  - Verify session key is properly derived from shared secret

- [ ] **Perfect Forward Secrecy**
  - Verify ephemeral keys are used
  - Confirm keys are destroyed after session

### Replay Attack Prevention

- [ ] **Nonce management**
  - Verify 96-bit nonce uniqueness
  - Audit `nonces_seen` HashSet for correctness
  - Check nonce storage bounds (potential memory exhaustion)

- [ ] **Session timeout (30 seconds)**
  - Verify `SESSION_TIMEOUT` enforcement
  - Check for time-of-check/time-of-use issues

- [ ] **Nonce reuse detection**
  - Verify replay attack detection works correctly
  - Audit error handling for replayed messages

### Message Integrity

- [ ] **ChaCha20-Poly1305 AEAD**
  - Verify `chacha20poly1305` crate usage
  - Check authentication tag verification
  - Audit ciphertext tampering detection

- [ ] **Message format security**
  - Verify no length-extension attacks possible
  - Check for ciphertext malleability

---

## Known Issues for Auditor Review

### Critical Security Issues (Biometric Module)

| ID | Issue | Location | Severity | Status |
|----|-------|----------|----------|--------|
| SEC-001 | Hardcoded confidence values | `feature_extraction.rs:35,60` | CRITICAL | Open |
| SEC-002 | Missing input validation | Multiple biometric files | CRITICAL | Open |
| SEC-003 | Deterministic CNN simulation | `feature_extraction.rs:540` | CRITICAL | Open |
| SEC-004 | Side-channel vulnerabilities | Distance calculations | HIGH | Partially Mitigated |
| SEC-005 | Information leakage in errors | Error handling | MEDIUM | Mitigated (REQ-005) |
| SEC-006 | Incomplete implementations | Ridge/minutiae extraction | HIGH | Open |

### Correctness Issues (Biometric Module)

| ID | Issue | Location | Severity | Status |
|----|-------|----------|----------|--------|
| COR-001 | Poor feature normalization | Feature extraction | MEDIUM | Open |
| COR-002 | Fusion weight validation | `fusion.rs` | LOW | Open |
| COR-003 | Threshold inconsistency | Global vs modality thresholds | MEDIUM | Open |
| COR-004 | Quality threshold validation | Acceptance criteria | LOW | Documented (ADR-002) |

### Ongoing Improvements

| ID | Item | Status | Notes |
|----|------|--------|-------|
| IMP-001 | Full 14,000 constraint implementation | In Progress | Currently simplified demo |
| IMP-002 | Better secret zeroing for scalars | Planned | Best effort currently |
| IMP-003 | SIMD/NEON optimizations | Planned | Mobile ARM processors |
| IMP-004 | HKDF for session key derivation | Recommended | Currently uses raw shared secret |

---

## Audit Scope Recommendations

### Priority 1: Critical Path Components
1. Pedersen commitment scheme
2. Groth16 circuit soundness
3. Trusted setup ceremony
4. Random number generation

### Priority 2: Biometric Security
1. Constant-time distance calculations
2. Feature extraction input validation
3. Template security

### Priority 3: Mobile/P2P Integration
1. FFI memory safety
2. Session key exchange
3. Replay prevention

---

## Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-02-02 | SABLE Team | Initial audit preparation document |

---

## Related Documents

- [ADR-002: Biometric Quality Thresholds](../adr/ADR-002-quality-thresholds.md)
- [ADR-003: Trusted Setup Ceremony Protocol](../adr/ADR-003-trusted-setup-ceremony.md)
- [THREAT_MODEL.md](./THREAT_MODEL.md)
- [IMPLEMENTATION_STATUS.md](../../IMPLEMENTATION_STATUS.md)
