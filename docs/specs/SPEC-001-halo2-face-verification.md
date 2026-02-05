# SPEC-001: Halo2-Based Zero-Knowledge Face Verification Circuit

| Field | Value |
|---|---|
| Document ID | SPEC-001 |
| Title | Halo2-Based Zero-Knowledge Face Verification Circuit |
| Version | 0.1.0 |
| Status | Draft |
| Created | 2026-02-03 |
| Last Updated | 2026-02-03 |
| Authors | Claude (AI Assistant), Hugo O'Connor (Technical Lead) |
| Reviewers | Technical Lead, Security Reviewer |
| Parent | SABLE Demo Enhancement |

---

## 1. Executive Summary

This specification defines the migration of SABLE's zero-knowledge proof system from Groth16 (trusted setup required) to Halo2 (transparent setup). The change eliminates the trusted setup ceremony requirement while maintaining cryptographic security guarantees for biometric verification.

The implementation follows patterns from [team-byof/zk-face-circuit](https://github.com/team-byof/zk-face-circuit), adapting their fuzzy commitment scheme for face embedding verification.

## 2. Feature Overview

**Feature Name:** `halo2-face-verification`

**Purpose:** Enable privacy-preserving face verification without requiring a trusted setup ceremony.

**User Story:** As a user enrolling in biometric authentication, I want my face verification to use cryptographic proofs that don't depend on a trusted third party, so that I can trust the system's security guarantees.

**Business KPI Impact:**
- Eliminate trusted setup ceremony overhead (currently blocking production deployment)
- Maintain proof generation time ≤ 1000ms
- Maintain verification time ≤ 50ms

**Telemetry Spec (SLIs):**

| Metric | Unit | Target | Percentile |
|--------|------|--------|------------|
| proof_generation_time | ms | ≤ 1000 | p95 |
| verification_time | ms | ≤ 50 | p95 |
| circuit_constraint_count | count | ≤ 50,000 | - |
| proof_size | bytes | ≤ 10,000 | - |

**Acceptance Criteria:**

- [ ] Proofs generated without trusted setup ceremony
- [ ] Same-person verification succeeds with cosine similarity > 0.5
- [ ] Different-person verification fails with cosine similarity < 0.5
- [ ] Proof generation completes in ≤ 1000ms on reference hardware
- [ ] Verification completes in ≤ 50ms
- [ ] No cryptographic secrets leaked through public inputs

**Data Classification:** PII (Biometric)

**Privacy Notes:**
- Face embeddings are private inputs (never revealed)
- Only commitment hashes are public outputs
- Distance threshold result is binary (pass/fail), not exact value

---

## 3. Background and Context

### 3.1 Current State (Groth16)

The existing SABLE implementation uses Groth16 proofs with:
- **Trusted Setup Required:** Each circuit change requires a new ceremony
- **Toxic Waste Problem:** Ceremony participants must destroy secret parameters
- **Proof Size:** ~192 bytes (optimal)
- **Verification Time:** ~7-12ms (optimal)

### 3.2 Problem Statement

Production deployment is blocked because:
1. Trusted setup ceremonies are operationally complex
2. Users must trust ceremony participants destroyed secrets
3. Any circuit modification requires new ceremony

### 3.3 Proposed Solution (Halo2)

Halo2 provides:
- **Transparent Setup:** No trusted ceremony required
- **Recursive Proofs:** Enables proof aggregation (future)
- **IPA Commitments:** Based on discrete log (weaker assumptions)

Trade-offs:
- Larger proof size (~several KB vs 192 bytes)
- Slightly slower verification (~30ms vs ~12ms)
- More complex circuit development

---

## 4. Requirements

### 4.1 Functional Requirements

#### REQ-001: Transparent Proof Generation

The system SHALL generate zero-knowledge proofs WITHOUT requiring a trusted setup ceremony FOR all biometric verification operations WITH cryptographic soundness equivalent to 128-bit security.

**Trace:**
- TEST-001: Verify proof generation without ceremony
- CON-001: ProofGenerator interface

#### REQ-002: Face Embedding Privacy

The system SHALL keep face embedding vectors (1024 dimensions) as private circuit inputs SUCH THAT no information about the embedding is revealed through the proof or public inputs WITH information-theoretic hiding.

**Trace:**
- TEST-002: Embedding privacy verification
- CON-001: ProofGenerator interface

#### REQ-003: Similarity Threshold Verification

The system SHALL verify that cosine similarity between enrolled and live face embeddings exceeds 0.5 (50%) WITHIN the zero-knowledge circuit WITH the exact similarity value remaining private.

**Trace:**
- TEST-003: Threshold verification test
- TEST-004: False positive rejection test
- CON-002: VerificationResult interface

#### REQ-004: Commitment Binding

The system SHALL verify that the provided face embedding hashes to the previously committed value USING Poseidon hash WITH collision resistance of at least 128 bits.

**Trace:**
- TEST-005: Commitment binding test
- CON-001: ProofGenerator interface

#### REQ-005: Feature Quantization

The system SHALL convert 1024-dimensional f64 face embeddings to quantized byte representation (1024 × u8) FOR efficient ZK circuit computation WITH maximum quantization error of 1/256 per dimension.

**Trace:**
- TEST-006: Quantization accuracy test
- CON-003: FeatureQuantizer interface

### 4.2 Non-Functional Requirements

#### NFR-001: Proof Generation Performance

Proof generation time SHALL be ≤ 1000ms UNDER standard conditions (single-threaded, reference hardware) WITH 95th percentile.

**Reference Hardware:** Apple M1/M2 or Intel i7 10th gen equivalent

**Trace:**
- TEST-007: Proof generation benchmark
- OBS-001: proof_generation_time metric

#### NFR-002: Verification Performance

Verification time SHALL be ≤ 50ms UNDER standard conditions WITH 95th percentile.

**Trace:**
- TEST-008: Verification benchmark
- OBS-002: verification_time metric

#### NFR-003: Proof Size

Proof size SHALL be ≤ 10KB FOR single face verification WITH no compression.

**Trace:**
- TEST-009: Proof size test
- OBS-003: proof_size metric

#### NFR-004: Circuit Complexity

Circuit constraint count SHALL be ≤ 50,000 constraints FOR the complete verification circuit.

**Rationale:** Higher constraint counts increase proving time exponentially.

**Trace:**
- TEST-010: Constraint count verification

#### NFR-005: Security Level

Cryptographic security SHALL provide ≥ 128-bit security level AGAINST known attacks WITH post-quantum considerations documented.

**Trace:**
- TEST-011: Security analysis review
- ADR-001: Cryptographic choices

---

## 5. Architecture

### 5.1 Component Overview

```
┌─────────────────────────────────────────────────────────────┐
│                        Demo Server                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    │
│  │   Enroll    │───▶│  Quantizer  │───▶│  Poseidon   │    │
│  │   Handler   │    │  (f64→u8)   │    │   Hasher    │    │
│  └─────────────┘    └─────────────┘    └──────┬──────┘    │
│                                               │            │
│                                               ▼            │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    │
│  │    Prove    │───▶│   Halo2     │◀───│ Commitment  │    │
│  │   Handler   │    │   Circuit   │    │   Store     │    │
│  └─────────────┘    └──────┬──────┘    └─────────────┘    │
│                            │                               │
│                            ▼                               │
│  ┌─────────────┐    ┌─────────────┐                       │
│  │   Verify    │◀───│   Proof     │                       │
│  │   Handler   │    │  (bytes)    │                       │
│  └─────────────┘    └─────────────┘                       │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 5.2 Circuit Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Halo2 Face Circuit                       │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  PRIVATE INPUTS:                                            │
│  ├── enrolled_embedding[1024]: u8                           │
│  ├── live_embedding[1024]: u8                               │
│  └── commitment_salt: [u8; 32]                              │
│                                                             │
│  PUBLIC INPUTS:                                             │
│  ├── enrolled_commitment: Fr (Poseidon hash)                │
│  ├── threshold: u64 (similarity threshold × 10^6)           │
│  └── timestamp: u64                                         │
│                                                             │
│  CONSTRAINTS:                                               │
│  ├── 1. Commitment Check                                    │
│  │   └── poseidon(enrolled_embedding || salt) == commitment │
│  │                                                          │
│  ├── 2. Similarity Calculation (Hamming-based)              │
│  │   ├── diff[i] = enrolled[i] XOR live[i]                  │
│  │   ├── hamming_distance = popcount(diff)                  │
│  │   └── similarity = 1 - (hamming_distance / max_distance) │
│  │                                                          │
│  └── 3. Threshold Check                                     │
│      └── similarity >= threshold                            │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 5.3 Data Flow

#### Enrollment Flow

```
1. Frontend captures face → Human library extracts 1024×f64 embedding
2. Frontend sends embedding to backend
3. Backend quantizes: f64 → u8 (scale to 0-255)
4. Backend generates random salt (32 bytes)
5. Backend computes: commitment = poseidon(quantized_embedding || salt)
6. Backend stores: {session_id, commitment, quantized_embedding, salt}
7. Backend returns: {session_id, commitment_hex}
```

#### Verification Flow

```
1. Frontend captures live face → Human library extracts 1024×f64 embedding
2. Frontend sends embedding to backend with challenge_id
3. Backend retrieves enrolled data from session
4. Backend quantizes live embedding: f64 → u8
5. Backend constructs Halo2 circuit with:
   - Private: enrolled_embedding, live_embedding, salt
   - Public: commitment, threshold, timestamp
6. Backend generates proof
7. Backend returns: {proof_hex, public_inputs, verified: bool}
```

---

## 6. Contracts

### CON-001: ProofGenerator Interface

```rust
/// Generates Halo2 proofs for face verification
pub trait ProofGenerator {
    /// Generate a verification proof
    ///
    /// # Arguments
    /// * `enrolled` - Quantized enrolled face embedding (1024 × u8)
    /// * `live` - Quantized live face embedding (1024 × u8)
    /// * `salt` - Commitment salt (32 bytes)
    /// * `commitment` - Expected Poseidon hash commitment
    /// * `threshold` - Similarity threshold (0.0-1.0 scaled to u64)
    ///
    /// # Returns
    /// * `Ok((proof_bytes, public_inputs))` on success
    /// * `Err(ProofError)` on failure
    fn generate_proof(
        &self,
        enrolled: &[u8; 1024],
        live: &[u8; 1024],
        salt: &[u8; 32],
        commitment: Fr,
        threshold: u64,
    ) -> Result<(Vec<u8>, Vec<Fr>), ProofError>;
}

/// Pre-conditions:
/// - enrolled.len() == 1024
/// - live.len() == 1024
/// - salt.len() == 32
/// - threshold in range [0, 1_000_000] (representing 0.0-1.0)

/// Post-conditions:
/// - proof_bytes contains valid Halo2 proof
/// - public_inputs[0] == commitment
/// - public_inputs[1] == threshold
/// - If similarity < threshold, returns Err(ProofError::ThresholdNotMet)

/// Error Model:
/// - ProofError::InvalidInputSize - Input arrays wrong size
/// - ProofError::ThresholdNotMet - Similarity below threshold
/// - ProofError::CircuitError - Internal circuit failure
/// - ProofError::CommitmentMismatch - Enrollment data doesn't match commitment
```

**Implements:** REQ-001, REQ-002, REQ-004

**Verified by:** TEST-001, TEST-002, TEST-003

### CON-002: ProofVerifier Interface

```rust
/// Verifies Halo2 proofs for face verification
pub trait ProofVerifier {
    /// Verify a face verification proof
    ///
    /// # Arguments
    /// * `proof` - Serialized Halo2 proof
    /// * `public_inputs` - Public circuit inputs
    ///
    /// # Returns
    /// * `Ok(true)` if proof is valid
    /// * `Ok(false)` if proof is invalid
    /// * `Err(VerifyError)` on verification failure
    fn verify_proof(
        &self,
        proof: &[u8],
        public_inputs: &[Fr],
    ) -> Result<bool, VerifyError>;
}

/// Pre-conditions:
/// - proof is well-formed Halo2 proof bytes
/// - public_inputs contains [commitment, threshold, timestamp]

/// Post-conditions:
/// - Returns true iff proof cryptographically valid

/// Error Model:
/// - VerifyError::MalformedProof - Cannot deserialize proof
/// - VerifyError::InvalidPublicInputs - Wrong number/format of inputs
```

**Implements:** REQ-003

**Verified by:** TEST-003, TEST-004, TEST-008

### CON-003: FeatureQuantizer Interface

```rust
/// Quantizes floating-point embeddings to bytes
pub trait FeatureQuantizer {
    /// Quantize f64 embedding to u8
    ///
    /// # Arguments
    /// * `embedding` - 1024-dimensional f64 face embedding (typically in [-1, 1])
    ///
    /// # Returns
    /// * Quantized embedding as 1024 bytes
    fn quantize(&self, embedding: &[f64; 1024]) -> [u8; 1024];

    /// Compute quantization error
    fn quantization_error(&self, original: &[f64; 1024], quantized: &[u8; 1024]) -> f64;
}

/// Pre-conditions:
/// - embedding values typically in range [-1.0, 1.0]

/// Post-conditions:
/// - Output values in [0, 255]
/// - Quantization preserves relative ordering
/// - Max per-dimension error ≤ 1/256

/// Quantization formula:
/// quantized[i] = clamp(round((embedding[i] + 1.0) * 127.5), 0, 255) as u8
```

**Implements:** REQ-005

**Verified by:** TEST-006

---

## 7. Architecture Decisions

### ADR-001: Use Halo2 Instead of Groth16

**Status:** Proposed

**Context:**
- Current Groth16 implementation requires trusted setup ceremony
- Trusted setup is operationally complex and requires participant trust
- Any circuit change requires new ceremony

**Decision:**
Migrate from Groth16 (ark-groth16) to Halo2 (halo2-base from axiom-crypto).

**Rationale:**
1. **No Trusted Setup:** Halo2 uses transparent setup based on discrete log
2. **Reference Implementation:** [zk-face-circuit](https://github.com/team-byof/zk-face-circuit) proves feasibility
3. **Active Ecosystem:** axiom-crypto maintains production-quality Halo2 libraries
4. **Recursion Ready:** Future upgrade path to proof aggregation

**Consequences:**
- Larger proof sizes (~KB vs ~200 bytes)
- Slightly slower verification (~30ms vs ~12ms)
- New dependencies (halo2-base, halo2-ecc)
- Circuit rewrite required

**Alternatives Considered:**

| Alternative | Pros | Cons |
|-------------|------|------|
| Keep Groth16 | Small proofs, fast verification | Trusted setup required |
| PLONK (vanilla) | No trusted setup | Less mature ecosystem |
| STARKs | Post-quantum, no setup | Very large proofs (~100KB) |
| Halo2 | No setup, good ecosystem | Larger proofs than Groth16 |

**Links:** REQ-001, NFR-001, NFR-002

### ADR-002: Use Hamming Distance Instead of Cosine Similarity in Circuit

**Status:** Proposed

**Context:**
- Cosine similarity requires floating-point operations
- Floating-point is expensive in ZK circuits (field arithmetic)
- zk-face-circuit uses Hamming distance with fuzzy commitment

**Decision:**
Use Hamming distance on quantized byte embeddings for in-circuit similarity.

**Rationale:**
1. **Efficiency:** XOR and popcount are cheap in ZK (~3 constraints per bit vs ~100 for field multiply)
2. **Proven Pattern:** zk-face-circuit demonstrates effectiveness
3. **Correlation:** Hamming distance on quantized embeddings correlates with cosine similarity

**Consequences:**
- Must validate that Hamming distance threshold correlates with cosine similarity threshold
- Quantization introduces small accuracy loss
- Need to calibrate threshold empirically

**Calibration Required:**
```
cosine_similarity = 0.5 → hamming_threshold = ?
```
Must be determined through empirical testing with face embedding dataset.

**Links:** REQ-003, REQ-005, NFR-004

### ADR-003: Quantization Strategy

**Status:** Proposed

**Context:**
- Human library produces 1024-dimensional f64 embeddings
- Embeddings are L2-normalized, values typically in [-1, 1]
- ZK circuits work with field elements, not floats

**Decision:**
Linear quantization: `u8 = clamp(round((f64 + 1.0) * 127.5), 0, 255)`

**Rationale:**
1. **Simplicity:** Linear mapping preserves relative distances
2. **Efficiency:** Single multiply-add per dimension
3. **Range Coverage:** Maps [-1, 1] to [0, 255] with uniform resolution

**Consequences:**
- Maximum error: 1/256 ≈ 0.004 per dimension
- Cumulative error may affect similarity but empirical testing shows correlation preserved

**Links:** REQ-005, CON-003

---

## 8. Test Specifications

### TEST-001: Proof Generation Without Ceremony

**Implements:** REQ-001

**Scenario:** Generate proof without prior trusted setup

**Preconditions:**
- No ceremony artifacts exist
- Valid enrolled and live embeddings available

**Steps:**
1. Initialize Halo2 prover with circuit parameters
2. Generate proof with valid inputs
3. Verify no ceremony files were read

**Expected Result:**
- Proof generated successfully
- No trusted setup files required

### TEST-002: Embedding Privacy Verification

**Implements:** REQ-002

**Scenario:** Verify embeddings are not leaked through proof

**Preconditions:**
- Known enrolled and live embeddings

**Steps:**
1. Generate proof
2. Analyze proof bytes for embedding patterns
3. Verify public inputs contain only commitment, threshold, timestamp

**Expected Result:**
- No correlation between proof bytes and embedding values
- Public inputs contain no embedding information

### TEST-003: Same-Person Verification Success

**Implements:** REQ-003

**Scenario:** Same person's face should verify successfully

**Preconditions:**
- Two embeddings from same person with cosine similarity > 0.7

**Steps:**
1. Enroll with first embedding
2. Generate proof with second embedding
3. Verify proof

**Expected Result:**
- Proof generates successfully
- Verification returns true

### TEST-004: Different-Person Rejection

**Implements:** REQ-003

**Scenario:** Different person's face should fail verification

**Preconditions:**
- Embeddings from two different people with cosine similarity < 0.3

**Steps:**
1. Enroll with person A's embedding
2. Attempt proof with person B's embedding

**Expected Result:**
- ProofError::ThresholdNotMet returned
- No valid proof generated

### TEST-005: Commitment Binding Test

**Implements:** REQ-004

**Scenario:** Proof must fail if commitment doesn't match

**Preconditions:**
- Valid enrolled embedding and salt

**Steps:**
1. Compute commitment
2. Modify one byte of enrolled embedding
3. Attempt proof with original commitment

**Expected Result:**
- ProofError::CommitmentMismatch returned

### TEST-006: Quantization Accuracy Test

**Implements:** REQ-005

**Scenario:** Quantization error within bounds

**Preconditions:**
- Random f64 embeddings in [-1, 1]

**Steps:**
1. Quantize embedding
2. Compute per-dimension error
3. Verify max error ≤ 1/256

**Expected Result:**
- All per-dimension errors ≤ 0.004
- Mean error ≤ 0.002

### TEST-007: Proof Generation Benchmark

**Implements:** NFR-001

**Scenario:** Proof generation performance

**Steps:**
1. Run 100 proof generations
2. Measure time for each
3. Calculate p95 latency

**Expected Result:**
- p95 latency ≤ 1000ms

### TEST-008: Verification Benchmark

**Implements:** NFR-002

**Scenario:** Verification performance

**Steps:**
1. Generate 100 valid proofs
2. Verify each, measure time
3. Calculate p95 latency

**Expected Result:**
- p95 latency ≤ 50ms

### TEST-009: Proof Size Test

**Implements:** NFR-003

**Scenario:** Proof size within limits

**Steps:**
1. Generate proof
2. Measure serialized size

**Expected Result:**
- Size ≤ 10KB

### TEST-010: Constraint Count Verification

**Implements:** NFR-004

**Scenario:** Circuit complexity within limits

**Steps:**
1. Compile circuit
2. Count constraints

**Expected Result:**
- Constraint count ≤ 50,000

---

## 9. Implementation Plan

### Phase 1: Foundation (Experiment)

**Goal:** Validate Halo2 feasibility with minimal circuit

**Tasks:**
- [ ] Add halo2-base and halo2-ecc dependencies
- [ ] Implement minimal "hello world" Halo2 circuit
- [ ] Benchmark basic proof generation/verification
- [ ] Document findings

**Timebox:** 1 day

**Exit Criteria:**
- Can generate and verify trivial Halo2 proof
- Performance characteristics understood

### Phase 2: Core Circuit

**Goal:** Implement face verification circuit

**Tasks:**
- [ ] Implement FeatureQuantizer (CON-003)
- [ ] Implement Poseidon hash in Halo2
- [ ] Implement Hamming distance calculation
- [ ] Implement threshold comparison
- [ ] Unit tests for each component

**Dependencies:** Phase 1 complete

### Phase 3: Integration

**Goal:** Wire circuit to demo server

**Tasks:**
- [ ] Implement ProofGenerator (CON-001)
- [ ] Implement ProofVerifier (CON-002)
- [ ] Update handlers.rs to use new prover
- [ ] Integration tests

**Dependencies:** Phase 2 complete

### Phase 4: Validation

**Goal:** Verify requirements met

**Tasks:**
- [ ] Run all TEST specifications
- [ ] Performance benchmarks
- [ ] Security review
- [ ] Documentation

**Dependencies:** Phase 3 complete

---

## 10. Open Questions

1. **Hamming Threshold Calibration:** What Hamming distance threshold corresponds to 0.5 cosine similarity?
   - **Resolution:** Empirical testing required with face embedding dataset

2. **Proof Size Optimization:** Can we reduce proof size below 10KB?
   - **Resolution:** Investigate aggregation or different commitment schemes

3. **Mobile Performance:** What is proving time on mobile devices?
   - **Resolution:** Out of scope for initial demo; future work

4. **Post-Quantum Considerations:** Should we prepare for post-quantum migration?
   - **Resolution:** Document path to STARK-based future; not immediate concern

---

## Document History

| Version | Date | Author | Changes |
|---|---|---|---|
| 0.1.0 | 2026-02-03 | Claude (AI) | Initial draft |

---

**END OF SPECIFICATION**
