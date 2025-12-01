# SABLE Implementation TODO

Code review findings from implementation analysis.

---

## New Issues Found (Code Review 2025-12-01)

### Critical Security Issues

### 18. ⚠️ OPEN: Circuit Witness Values Not Computed
- **File:** `core/src/crypto/groth16.rs:351-374, 467-491, 500-521, 571-593`
- **Issue:** Circuit witness variables are allocated with `Ok(Fr::zero())` placeholder values instead of being computed from actual witness data. This affects:
  - Poseidon state variables in `constrain_poseidon_hash`
  - S-box intermediate values (x², x⁴, x⁵) in `sbox_constraint`
  - MDS matrix output variables in `mds_mix`
  - Distance difference variables in `constrain_euclidean_distance`
- **Impact:** The circuit constraints are syntactically correct but semantically incorrect - proofs may not verify correctly with real witness data
- **Fix Required:** Implement proper witness computation that evaluates the actual values based on the circuit inputs

### 19. ⚠️ OPEN: Commitment Binding Constraint is Reflexive (No-op)
- **File:** `core/src/crypto/groth16.rs:304-308`
- **Issue:** The constraint `binding + commitment_derived = binding + commitment_derived` is always satisfied (tautology). This does not actually bind the commitment to the computed hash.
- **Impact:** The commitment verification in-circuit provides no security guarantee
- **Fix Required:** Implement proper commitment binding that actually constrains the relationship between the hash, salt, and public commitment

---

### High Priority Issues

### 20. ⚠️ OPEN: Poseidon Round Constants Use Non-Cryptographic Hash
- **File:** `core/src/crypto/poseidon.rs:122-159`
- **Issue:** `get_round_constants` uses `std::collections::hash_map::DefaultHasher` (SipHash) which is not cryptographically secure. Round constants should be derived using SHA-256 or another cryptographic hash per the Poseidon specification.
- **Impact:** May weaken the collision resistance of the Poseidon hash

### 21. ⚠️ OPEN: Groth16 Round Constants Use Weak Derivation
- **File:** `core/src/crypto/groth16.rs:526-534`
- **Issue:** The `get_round_constant` function uses simple wrapping arithmetic (`wrapping_mul`, `wrapping_add`) which is not cryptographically secure. Should use proper Poseidon specification constants.
- **Impact:** May weaken the security of the in-circuit Poseidon computation

### 22. ⚠️ OPEN: MobileSable Ignores Salt Parameter
- **File:** `core/src/mobile/mod.rs:86-88`
- **Issue:** The `generate_commitment` function accepts `salt_bytes` but generates a new random `randomness` value instead. The provided salt is not used for the commitment.
- **Impact:** Callers cannot control commitment randomness, breaking expected API behavior

### 23. ⚠️ OPEN: FFI References Non-existent Type
- **File:** `core/src/mobile/ffi.rs:199`
- **Issue:** References `crate::crypto::pedersen::PedersenCommitment::from_bytes` but the type in `pedersen.rs` is `Commitment`, not `PedersenCommitment`
- **Impact:** Compilation error if this code path is exercised

---

### Medium Priority Issues

### 24. ⚠️ OPEN: MDS Inverse Fallback Breaks Security
- **File:** `core/src/crypto/groth16.rs:551`
- **Issue:** If modular inverse fails, `unwrap_or(Fr::from(1u64))` is used. While this shouldn't happen with valid inputs, the fallback value would break the MDS property.
- **Fix:** Use `expect()` to panic on impossible case, or prove the inverse always exists

### 25. ⚠️ OPEN: Feature Type Precision Loss
- **File:** `core/src/mobile/mod.rs:76`
- **Issue:** Features are converted from `f64` to `f32` which may lose precision for biometric applications requiring high accuracy
- **Fix:** Consider keeping f64 precision or documenting the precision requirements

### 26. ⚠️ OPEN: Temporal Validity Witness Not Computed
- **File:** `core/src/crypto/groth16.rs:728`
- **Issue:** The `time_diff` variable is allocated as `Fr::zero()` rather than computed from `current_time - timestamp`
- **Impact:** Temporal validity constraints don't function correctly

---

### Low Priority Issues

### 27. ⚠️ OPEN: Inconsistent Error Type Naming
- **File:** `core/src/error.rs`
- **Issue:** Both `CryptoError(String)` and `Cryptographic(String)` exist as error variants. Should consolidate to one.

### 28. ⚠️ OPEN: BiometricFeature::from Redundant Operation
- **File:** `core/src/types.rs:21-23`
- **Issue:** `(value as u16).min(65535)` - the `.min(65535)` is redundant since `as u16` already truncates to u16 range

### 29. ⚠️ OPEN: Test Acknowledges Unsatisfied Constraints
- **File:** `core/src/crypto/groth16.rs:1170-1174`
- **Issue:** Test comment says "In the simplified implementation, constraints may not be fully satisfied but they should at least compile and run without panicking" - this should be a test failure in production
- **Fix:** Either fix the circuit to be satisfiable or mark test as expected failure with clear documentation

---

## Previously Fixed Issues

### Critical Security Issues

### 1. ✅ FIXED: Entropy Loss in Scalar Conversion
- **File:** `core/src/crypto/groth16.rs:626-634`
- **Issue:** `scalar_from_bytes` only used the first byte of a 32-byte salt
- **Fix:** Now uses `Fr::from_le_bytes_mod_order(&padded)` to use all 32 bytes

### 2. ✅ FIXED: Placeholder Commitment Allocation
- **File:** `core/src/crypto/groth16.rs:244-256`
- **Issue:** `allocate_commitment` returned placeholder zeros
- **Fix:** Implemented `commitment_to_field_elements()` to properly serialize G1 points to field elements

### 3. ✅ FIXED: Non-functional Circuit Constraints
- **File:** `core/src/crypto/groth16.rs:259-764`
- **Issue:** Circuit constraints were simplified placeholders
- **Fix:** Implemented:
  - Proper Poseidon hash with x^5 S-box and MDS matrix
  - Commitment binding verification
  - Tree-based efficient sum for distance calculation
  - Bit decomposition range proofs for non-negativity
  - Proper absolute value constraints for temporal validity

### 4. ✅ FIXED: Zero Public Inputs in Proof Generation
- **File:** `core/src/crypto/groth16.rs:829-850`
- **Issue:** `prove()` created public_inputs with zeros
- **Fix:** Now properly computes commitment field elements and all public inputs

---

### High Priority Issues

### 5. ✅ FIXED: Missing Zeroization of Sensitive Data
- **File:** `core/src/crypto/pedersen.rs:114-138`
- **Issue:** `CommitmentOpening::Drop` was empty
- **Fix:** Implemented memory zeroing using `ptr::write_bytes` with compiler fence

### 6. ✅ FIXED: Weak Poseidon Round Constants
- **File:** `core/src/crypto/poseidon.rs:107-163`
- **Issue:** Round constants used simple LFSR
- **Fix:** Now derives constants using multiple hash rounds with domain separator

### 7. ✅ FIXED: Simplified MDS Matrix
- **File:** `core/src/crypto/poseidon.rs:165-195`
- **Issue:** MDS matrix didn't provide optimal diffusion
- **Fix:** Implemented proper Cauchy matrix: M[i,j] = 1/(x_i + y_j) with modular inverse

### 8. ✅ FIXED: FFI Memory Safety Issue
- **File:** `core/src/mobile/ffi.rs:54-75, 297-316`
- **Issue:** `sable_free_result` used wrong Vec reconstruction
- **Fix:** Uses `Box::from_raw(slice_ptr)` with proper slice type matching allocation

### 9. ✅ FIXED: Memory Leak in Error Messages
- **File:** `core/src/mobile/ffi.rs:318-354`
- **Issue:** `sable_error_message` leaked CString allocations
- **Fix:** Now uses static byte strings that never need freeing

---

### Medium Priority Issues

### 10. ✅ FIXED: Mobile Module Type Mismatches
- **File:** `core/src/mobile/mod.rs`
- **Issue:** References to non-existent methods and types
- **Fix:** Rewrote module with correct types from groth16, pedersen, and poseidon modules

### 11. ✅ FIXED: Placeholder Biometric Functions
- **File:** `core/src/biometric/feature_extraction.rs:721-1004`
- **Issue:** Palm print functions returned hardcoded values
- **Fix:** Implemented:
  - `enhance_palm_ridges`: Uses 8 orientations × 3 frequencies Gabor filter bank
  - `extract_minutiae`: Uses crossing number method for ridge ending/bifurcation detection
  - `extract_texture_features`: Implements GLCM, LBP, and Gabor energy features

### 12. ✅ FIXED: Simulated CNN Feature Extraction
- **File:** `core/src/biometric/feature_extraction.rs:553-701`
- **Issue:** CNN features used PRNG seeded from image mean
- **Fix:** Implemented multi-scale feature extraction with:
  - Global statistics (mean, variance, skewness, kurtosis)
  - Block-based features (4×4 grid)
  - Gradient features (8 directions)
  - Histogram features (16 bins)
  - LBP-like features (32 bins)
  - Multi-scale analysis

### 13. ✅ FIXED: Incomplete Feature Processing in Circuit
- **File:** `core/src/crypto/groth16.rs:554-674`
- **Issue:** Only processed 8-16 features instead of all
- **Fix:** Now processes all features with tree-based efficient summation

### 14. ✅ FIXED: Missing Range Proofs
- **File:** `core/src/crypto/groth16.rs:677-713`
- **Issue:** Threshold checks lacked proper range proofs
- **Fix:** Implemented bit decomposition with boolean constraints for non-negativity

---

### Low Priority Issues

### 15. ✅ FIXED: Square Image Assumption
- **File:** `core/src/biometric/feature_extraction.rs:168-216`
- **Issue:** `combine_gabor_responses` assumed square images via sqrt
- **Fix:** Renamed to `combine_gabor_responses_with_dims` accepting explicit width/height

### 16. ✅ FIXED: Test Coverage Gaps
- **File:** `core/src/crypto/groth16.rs:969-1095`
- **Issue:** Tests skipped actual proof generation
- **Fix:** Added comprehensive tests:
  - `test_proof_generation_api`: Tests full circuit creation and setup
  - `test_commitment_field_element_roundtrip`: Verifies commitment serialization
  - `test_scalar_from_bytes_full_entropy`: Verifies all bytes are used

### 17. ✅ FIXED: Hardcoded Feature Limits
- **File:** `core/src/crypto/groth16.rs:561-563`
- **Issue:** Hardcoded 16 instead of using feature vector length
- **Fix:** Now uses `features1.len().min(features2.len())` for all features

---

## Summary

| Severity | Total | Fixed | Open |
|----------|-------|-------|------|
| Critical | 6 | 4 | 2 |
| High | 9 | 5 | 4 |
| Medium | 7 | 4 | 3 |
| Low | 7 | 4 | 3 |
| **Total** | **29** | **17** | **12** |

### Key Findings from Latest Review:

The most significant issues are:

1. **Circuit Witness Computation (Critical):** The ZK circuit has correct constraint structure but witness values are placeholders. This means proofs cannot be generated correctly with real biometric data.

2. **Commitment Binding (Critical):** The in-circuit commitment verification is a no-op tautology that provides no security.

3. **Round Constants (High):** Both the standalone Poseidon hash and the in-circuit Poseidon use weak/non-cryptographic derivation for round constants.

4. **Mobile API Issues (High):** The FFI layer has type mismatches and the salt parameter is ignored in `generate_commitment`.

### Recommendations:

1. **Priority 1:** Fix witness computation in `groth16.rs` - the circuit needs to actually compute intermediate values
2. **Priority 2:** Implement proper commitment binding constraint
3. **Priority 3:** Use cryptographically secure round constant derivation (SHA-256 based)
4. **Priority 4:** Fix mobile API type mismatches and salt usage
