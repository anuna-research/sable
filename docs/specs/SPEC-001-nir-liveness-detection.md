# SPEC-001: Passive NIR Liveness Detection for Zero-Knowledge Biometric Proofs

## Overview

This specification defines the integration of passive Near-Infrared (NIR) liveness
detection signals into SABLE's Groth16 zero-knowledge proof circuit. The liveness
signals are captured alongside biometric features and proven in zero-knowledge,
ensuring that the verifier learns only that liveness checks passed—never the
underlying physiological measurements.

---

## User Profile

### User: Security-Conscious Authenticator

**Role:** End user authenticating via palm biometrics on mobile device

**Goals:**
- Complete authentication quickly (< 2 seconds total)
- Ensure their biometric data remains private
- Trust that the system cannot be fooled by presentation attacks

**Constraints:**
- Mobile device with NIR sensor (common in palm vein scanners)
- Variable lighting conditions
- May have cold hands (affects blood flow visibility)

**Daily Workflow:**
1. Opens application requiring biometric authentication
2. Places palm over NIR sensor
3. Single capture session (~500ms)
4. Receives authentication result
5. Proceeds with authorized action

### User: Enterprise Security Administrator

**Role:** Deploys and monitors SABLE authentication infrastructure

**Goals:**
- Ensure presentation attack resistance meets compliance requirements
- Monitor liveness detection effectiveness via observability signals
- Tune thresholds based on deployment environment

**Constraints:**
- Must meet ISO/IEC 30107-3 PAD Level 2 requirements
- Cannot access raw biometric data (privacy regulation)
- Needs aggregate metrics for security posture assessment

---

## Happy Path: Liveness-Verified Authentication

**Preconditions:**
- User has enrolled palm biometrics (commitment stored)
- Device has NIR sensor with pulse detection capability
- Proving key loaded on device

**Steps:**

1. User initiates authentication
   → System activates NIR sensor and begins capture

2. NIR sensor captures palm image sequence (3 frames, ~100ms apart)
   → System extracts biometric features from each frame
   → System extracts liveness signals (pulse, vein contrast variance)

3. System validates liveness signals meet thresholds
   → Pulse frequency within 0.5-3.0 Hz
   → Pulse amplitude above noise floor (> 0.1 normalized)
   → Vein contrast shows temporal variance (> 0.02 normalized)
   → Inter-frame similarity 0.85-0.99 (similar but not identical)

4. System generates ZK proof including liveness constraints
   → Proof binds liveness signals to biometric commitment
   → Proof generation completes in < 1200ms

5. Verifier validates proof
   → Confirms biometric match, quality, temporal validity, AND liveness
   → Returns accept/reject decision only

**Postconditions:**
- User authenticated with liveness assurance
- No biometric or liveness data transmitted
- Liveness verification logged (pass/fail only)

**Failure Modes:**
- F1: Pulse not detected (cold hands, poor sensor contact) → Retry with guidance
- F2: Static image detected (presentation attack) → Reject with generic error
- F3: Inter-frame similarity too high (video replay) → Reject with generic error
- F4: Proof generation timeout → Retry or fall back to alternative auth

---

## Requirements

### REQ-020: NIR Liveness Signal Extraction

The system SHALL extract the following liveness signals from NIR palm image
sequences WITHIN 150ms FOR authentication users WITH pulse detection accuracy
≥ 95% under normal operating conditions.

**Liveness Signals:**

| Signal | Description | Extraction Method | Unit |
|--------|-------------|-------------------|------|
| Pulse Amplitude | Peak-to-peak variation in vein intensity | Temporal FFT of ROI pixels | Normalized [0,1] |
| Pulse Frequency | Dominant frequency of vein pulsation | FFT peak detection | Hz |
| Vein Contrast Variance | Standard deviation of vein/background ratio across frames | Statistical analysis | Normalized [0,1] |
| Inter-Frame Motion | Euclidean distance between consecutive feature vectors | Constant-time distance | Normalized [0,1] |

**Acceptance Criteria:**
- AC-1: Pulse detection succeeds for ≥ 95% of live presentations under controlled conditions (23°C, normal blood pressure)
- AC-2: Extraction completes within 150ms including all 4 signals
- AC-3: Signals are quantized to 16-bit fixed-point for circuit compatibility
- AC-4: All intermediate data is zeroized after extraction

**Trace:**
- TEST-020, TEST-021, TEST-022
- CON-020
- OBS-020

---

### REQ-021: Liveness Threshold Enforcement

The system SHALL enforce the following liveness thresholds in the ZK circuit
FOR all authentication attempts WITH rejection of samples failing any threshold.

**Threshold Specification:**

| Signal | Threshold | Rationale | Reference |
|--------|-----------|-----------|-----------|
| Pulse Frequency | 0.5 - 3.0 Hz | Human heart rate 30-180 BPM | ISO/IEC 30107-3 Annex B |
| Pulse Amplitude | ≥ 0.10 | Above sensor noise floor | Vendor calibration |
| Vein Contrast Variance | ≥ 0.02 | Living tissue shows temporal variation | Tome et al. (2015) |
| Inter-Frame Similarity | 0.85 - 0.99 | Natural micro-movement, not static | Kumar & Zhou (2012) |

**Acceptance Criteria:**
- AC-1: Circuit rejects proofs where pulse frequency is outside [0.5, 3.0] Hz
- AC-2: Circuit rejects proofs where pulse amplitude < 0.10
- AC-3: Circuit rejects proofs where vein contrast variance < 0.02
- AC-4: Circuit rejects proofs where inter-frame similarity < 0.85 or > 0.99
- AC-5: All threshold comparisons use constant-time operations

**Trace:**
- TEST-023, TEST-024, TEST-025
- CON-021
- ADR-004

---

### REQ-022: ZK Circuit Extension for Liveness

The system SHALL extend the BiometricCircuit to include liveness constraints
WITHIN 3,000 additional R1CS constraints FOR privacy-preserving liveness
verification WITH zero information leakage about liveness signals.

**Circuit Inputs:**

*Private Inputs (Witness):*
```
pulse_amplitude: Fr        // 16-bit fixed-point
pulse_frequency: Fr        // 16-bit fixed-point (Hz * 2^16)
vein_contrast_variance: Fr // 16-bit fixed-point
frame_features: [Fr; 512 * 3]  // 3 consecutive frames
```

*Public Inputs:*
```
liveness_check_passed: Fr  // Boolean (0 or 1)
frame_timestamps: [Fr; 3]  // Microsecond precision
```

**Constraint Breakdown:**

| Component | Constraints | Purpose |
|-----------|-------------|---------|
| Pulse frequency range check | ~200 | Verify 0.5-3.0 Hz |
| Pulse amplitude threshold | ~100 | Verify ≥ 0.10 |
| Vein contrast variance | ~200 | Verify ≥ 0.02 |
| Inter-frame similarity (2 pairs) | ~2,000 | Distance calculation with range check |
| Timestamp sequencing | ~300 | Verify frames are temporally ordered |
| Boolean output derivation | ~200 | Aggregate to single pass/fail |
| **Total** | **~3,000** | |

**Acceptance Criteria:**
- AC-1: Total circuit size ≤ 17,000 R1CS constraints (14,000 existing + 3,000 liveness)
- AC-2: Proof generation time ≤ 1,200ms on reference mobile device
- AC-3: Proof size remains 192 bytes (Groth16 constant)
- AC-4: Verifier learns only liveness_check_passed, not individual signals
- AC-5: Circuit is compatible with existing trusted setup (same curve)

**Trace:**
- TEST-026, TEST-027, TEST-028
- CON-022
- ADR-004

---

### REQ-023: Presentation Attack Detection Metrics

The system SHALL achieve the following presentation attack detection metrics
FOR the attack types specified WITH statistical confidence ≥ 95%.

**Attack Type Performance:**

| Attack Type | Detection Rate | False Reject Rate | Reference |
|-------------|---------------|-------------------|-----------|
| Printed photo | ≥ 99.9% | ≤ 1% | ISO/IEC 30107-3 Level 2 |
| Screen display | ≥ 99.5% | ≤ 1% | ISO/IEC 30107-3 Level 2 |
| Latex/silicone replica | ≥ 98% | ≤ 2% | Tome et al. (2015) |
| Video replay | ≥ 99% | ≤ 1% | Inter-frame analysis |

**Aggregate Metrics:**
- Attack Presentation Classification Error Rate (APCER): ≤ 1%
- Bona Fide Presentation Classification Error Rate (BPCER): ≤ 5%

**Acceptance Criteria:**
- AC-1: System detects printed photos with ≥ 99.9% accuracy (no pulse, no variance)
- AC-2: System detects screen displays with ≥ 99.5% accuracy (fixed refresh artifacts)
- AC-3: System detects silicone replicas with ≥ 98% accuracy (no blood flow)
- AC-4: System detects video replay with ≥ 99% accuracy (identical inter-frame features)
- AC-5: False reject rate for genuine users ≤ 5% at target operating point

**Trace:**
- TEST-029, TEST-030, TEST-031, TEST-032
- OBS-021

---

### REQ-024: Multi-Frame Capture Protocol

The system SHALL capture exactly 3 consecutive NIR frames FOR liveness analysis
WITHIN 350ms total capture time WITH frame spacing of 80-120ms.

**Capture Specification:**

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Frame count | 3 | Minimum for temporal analysis |
| Inter-frame interval | 100ms ± 20ms | Captures ~10% of cardiac cycle |
| Total capture time | ≤ 350ms | User experience constraint |
| Frame resolution | 640 × 480 minimum | Sufficient for vein extraction |
| Bit depth | 8-bit grayscale | NIR sensor standard |

**Acceptance Criteria:**
- AC-1: System captures exactly 3 frames per authentication attempt
- AC-2: Inter-frame timing is 80-120ms (jitter tolerance for mobile scheduling)
- AC-3: All frames have identical resolution and bit depth
- AC-4: Frame timestamps are recorded with microsecond precision
- AC-5: Capture failure triggers retry, not partial analysis

**Trace:**
- TEST-033, TEST-034
- CON-020

---

## Non-Functional Requirements

### NFR-020: Liveness Extraction Latency

Liveness signal extraction SHALL complete in ≤ 150ms UNDER normal operating
conditions WITH 99th percentile ≤ 200ms.

**Measurement:**
- Clock starts: First frame available in memory
- Clock stops: All 4 liveness signals computed and quantized
- Excludes: Sensor capture time, proof generation time

**Trace:**
- TEST-035
- OBS-020

---

### NFR-021: Proof Generation Overhead

The additional proof generation time for liveness constraints SHALL be ≤ 350ms
UNDER mobile device conditions WITH total proof time ≤ 1,200ms.

**Breakdown:**
- Base circuit (14,000 constraints): ~850ms
- Liveness circuit (3,000 constraints): ~350ms
- Total: ≤ 1,200ms

**Trace:**
- TEST-036
- OBS-022

---

### NFR-022: Memory Overhead

The liveness feature memory footprint SHALL be ≤ 16MB additional UNDER mobile
device conditions WITH peak total memory ≤ 144MB.

**Breakdown:**
- 3 frames × 640 × 480 × 1 byte = ~900KB raw
- Feature vectors: 3 × 512 × 8 bytes = ~12KB
- Circuit witness extension: ~15MB
- Total additional: ~16MB

**Trace:**
- TEST-037
- OBS-023

---

### NFR-023: Liveness Signal Privacy

The system SHALL NOT transmit, log, or expose individual liveness signal values
UNDER any operating condition WITH only aggregate pass/fail visible to verifier.

**Privacy Guarantees:**
- Pulse amplitude: Never leaves device
- Pulse frequency: Never leaves device
- Vein contrast variance: Never leaves device
- Inter-frame features: Never leaves device
- Only liveness_check_passed (boolean) is a public circuit input

**Trace:**
- TEST-038
- ADR-004

---

## Architecture Decision Record

### ADR-004: Passive NIR Liveness Detection in ZK Circuit

#### Status

Proposed

#### Context

SABLE's current biometric verification circuit (REQ-011) proves biometric match,
quality, and temporal validity but does not include explicit liveness detection.
While the multi-modal fusion (60% vein + 40% print) provides inherent resistance
to simple presentation attacks, sophisticated attacks using high-quality replicas
or video replay could potentially succeed.

Presentation Attack Detection (PAD) is mandated by:
- ISO/IEC 30107-3:2017 for biometric PAD testing
- NIST SP 800-76-2 for high-assurance identity verification
- PCI DSS 4.0 for payment authentication

The challenge is incorporating liveness detection while maintaining:
1. Zero-knowledge property (verifier learns nothing about biometric or liveness data)
2. Mobile performance targets (< 1.5s total authentication)
3. Compatibility with existing trusted setup ceremony

#### Decision

We adopt **passive NIR liveness detection** integrated directly into the Groth16
circuit with the following design:

**1. Passive vs. Active Liveness**

We choose passive liveness (analyzing inherent physiological signals) over active
liveness (challenge-response) because:
- No user interaction required (faster, better UX)
- Harder to spoof (attacker cannot predict what signal to fake)
- Compatible with single capture gesture
- NIR sensors already capture blood flow information

**2. Multi-Frame Temporal Analysis**

We capture 3 consecutive frames (~100ms apart) to detect:
- Blood pulse (periodic vein intensity variation)
- Natural micro-movements (living hands are never perfectly still)
- Temporal consistency (not static image or identical replay)

**3. Liveness Signals**

| Signal | Attack Defeated | Circuit Cost |
|--------|-----------------|--------------|
| Pulse amplitude | Printed photos, silicone replicas | ~100 constraints |
| Pulse frequency | Non-physiological artifacts | ~200 constraints |
| Vein contrast variance | Static displays | ~200 constraints |
| Inter-frame similarity | Video replay | ~2,000 constraints |

**4. Privacy-Preserving Verification**

All liveness signals are private circuit inputs (witness). The circuit outputs
only a single boolean `liveness_check_passed`. This ensures:
- Verifier cannot learn heart rate (medical privacy)
- Verifier cannot profile user's physiological patterns
- Failed attempts reveal only "liveness failed", not which signal failed

**5. Threshold Selection**

Thresholds are derived from peer-reviewed research:

| Threshold | Value | Source |
|-----------|-------|--------|
| Pulse frequency | 0.5-3.0 Hz | ISO/IEC 30107-3 physiological bounds |
| Pulse amplitude | ≥ 0.10 | Tome et al. (2015) palm vein liveness |
| Contrast variance | ≥ 0.02 | Kumar & Zhou (2012) temporal analysis |
| Frame similarity | 0.85-0.99 | Empirical calibration |

#### Alternatives Considered

**Alternative A: Hardware Attestation Only**

*Pros:* Minimal circuit changes, leverages TEE
*Cons:* Shifts trust to hardware vendor, not all devices have suitable TEE,
attestation keys can be extracted

*Decision:* Rejected as primary method; may complement NIR liveness

**Alternative B: Challenge-Response Liveness**

*Pros:* Highly effective, standard approach
*Cons:* Requires user interaction (head movement, blink), adds 200-500ms latency,
poor accessibility

*Decision:* Rejected for palm biometrics; better suited for face recognition

**Alternative C: Active Illumination Variation**

*Pros:* Detects 3D vs 2D surfaces effectively
*Cons:* Requires controllable illumination hardware, inconsistent across devices,
patent encumbered

*Decision:* Rejected due to hardware requirements

#### Consequences

**Positive:**

1. **Comprehensive PAD:** Addresses printed, displayed, replica, and replay attacks
2. **Privacy Preserved:** Liveness signals never leave device or appear in proof
3. **No UX Impact:** Single-gesture authentication maintained
4. **Standards Alignment:** Meets ISO/IEC 30107-3 Level 2 requirements
5. **Extensible:** Circuit structure allows adding more signals if needed

**Negative:**

1. **Circuit Size Increase:** ~3,000 additional constraints (~21% increase)
2. **Proof Generation Time:** ~350ms additional latency
3. **Memory Increase:** ~16MB additional for multi-frame processing
4. **Sensor Requirement:** Requires NIR sensor with sufficient temporal resolution
5. **Cold Environment Sensitivity:** Pulse detection degrades below 15°C ambient

**Mitigations:**

- Memory: Chunked processing already in place (REQ-013)
- Cold environments: Adaptive thresholds based on detected signal strength
- Sensor compatibility: Graceful degradation to quality-only verification if
  NIR pulse detection unavailable

#### Implementation Notes

**Circuit Integration Point:**
`core/src/crypto/groth16.rs` - Extend `BiometricCircuit` struct

**New Module:**
`core/src/biometric/liveness.rs` - NIR signal extraction algorithms

**Trusted Setup:**
Existing ceremony parameters remain valid (same curve, larger circuit fits
within MPC constraints)

#### References

1. ISO/IEC 30107-3:2017 - Biometric presentation attack detection - Part 3: Testing and reporting
2. Tome, P. et al. (2015). "On the Vulnerability of Palm Vein Recognition to Spoofing Attacks."
   IEEE International Conference on Biometrics.
3. Kumar, A. & Zhou, Y. (2012). "Human Identification Using Palm-Vein Images."
   IEEE Trans. Information Forensics and Security.
4. NIST SP 800-76-2 - Biometric Specifications for Personal Identity Verification

---

## Contract Specifications

### CON-020: LivenessSignalExtractor Interface

**Interface:** `LivenessSignalExtractor`

**Location:** `core/src/biometric/liveness.rs`

```rust
/// Extracts liveness signals from multi-frame NIR capture
pub trait LivenessSignalExtractor {
    /// Extract all liveness signals from frame sequence
    ///
    /// # Arguments
    /// * `frames` - Exactly 3 consecutive NIR frames
    /// * `timestamps` - Capture timestamps in microseconds
    ///
    /// # Returns
    /// * `LivenessSignals` on success
    /// * `SableError::LivenessExtraction` on failure
    ///
    /// # Errors
    /// * Frame count != 3
    /// * Frames have inconsistent dimensions
    /// * Timestamps not monotonically increasing
    /// * Signal extraction algorithm failure
    fn extract_signals(
        &self,
        frames: &[PalmImage; 3],
        timestamps: &[u64; 3],
    ) -> Result<LivenessSignals>;

    /// Validate extracted signals against thresholds
    ///
    /// # Returns
    /// * `true` if all thresholds passed
    /// * `false` if any threshold failed (does not indicate which)
    fn validate_signals(&self, signals: &LivenessSignals) -> bool;
}

/// Liveness signal values (all 16-bit fixed-point)
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct LivenessSignals {
    /// Pulse amplitude (peak-to-peak normalized)
    pub pulse_amplitude: u16,
    /// Pulse frequency in Hz (fixed-point: value / 65536)
    pub pulse_frequency: u16,
    /// Vein contrast temporal variance (normalized)
    pub vein_contrast_variance: u16,
    /// Inter-frame similarity scores [frame0-1, frame1-2]
    pub inter_frame_similarity: [u16; 2],
    /// Feature vectors for circuit witness
    pub frame_features: [[BiometricFeature; 512]; 3],
}
```

**Pre-conditions:**
- Frames array contains exactly 3 valid PalmImage instances
- All frames have identical dimensions (width, height, channels)
- Timestamps are monotonically increasing with gaps in [80_000, 120_000] μs
- NIR sensor captured frames (not RGB)

**Post-conditions:**
- All signal values are in valid fixed-point range [0, 65535]
- Frame features are normalized to [0, 1] range
- Intermediate buffers are zeroized
- Extraction time ≤ 150ms

**Error Model:**
- `SableError::LivenessExtraction(String)` - Generic error (REQ-005 compliant)
- Error message does not reveal which signal failed or threshold values

**Implements:**
- REQ-020
- REQ-024

**Verified by:**
- TEST-020, TEST-021, TEST-022

---

### CON-021: LivenessThresholds Configuration

**Interface:** `LivenessThresholds`

**Location:** `core/src/biometric/liveness.rs`

```rust
/// Research-validated liveness detection thresholds
/// See ADR-004 for threshold derivation and references
pub struct LivenessThresholds {
    /// Minimum pulse frequency in Hz (0.5 Hz = 30 BPM)
    pub pulse_frequency_min: u16,  // Fixed-point: 0x8000 = 0.5 Hz
    /// Maximum pulse frequency in Hz (3.0 Hz = 180 BPM)
    pub pulse_frequency_max: u16,  // Fixed-point: 0x30000 = 3.0 Hz
    /// Minimum pulse amplitude (above noise floor)
    pub pulse_amplitude_min: u16,  // Fixed-point: 0x199A = 0.10
    /// Minimum vein contrast variance
    pub vein_contrast_variance_min: u16,  // Fixed-point: 0x051F = 0.02
    /// Minimum inter-frame similarity (not too different)
    pub inter_frame_similarity_min: u16,  // Fixed-point: 0xD99A = 0.85
    /// Maximum inter-frame similarity (not identical)
    pub inter_frame_similarity_max: u16,  // Fixed-point: 0xFD71 = 0.99
}

impl Default for LivenessThresholds {
    fn default() -> Self {
        Self {
            pulse_frequency_min: 32768,   // 0.5 Hz
            pulse_frequency_max: 196608,  // 3.0 Hz
            pulse_amplitude_min: 6554,    // 0.10
            vein_contrast_variance_min: 1311,  // 0.02
            inter_frame_similarity_min: 55706, // 0.85
            inter_frame_similarity_max: 64881, // 0.99
        }
    }
}
```

**Implements:**
- REQ-021

**Verified by:**
- TEST-023, TEST-024, TEST-025

---

### CON-022: BiometricCircuit Liveness Extension

**Interface:** Extended `BiometricCircuit`

**Location:** `core/src/crypto/groth16.rs`

```rust
/// Extended biometric circuit with liveness constraints
/// Total constraints: ~17,000 (14,000 base + 3,000 liveness)
pub struct BiometricCircuit {
    // ... existing fields from REQ-011 ...

    // === NEW: Liveness Private Inputs (Witness) ===

    /// Pulse amplitude (16-bit fixed-point, private)
    pub pulse_amplitude: Option<u16>,
    /// Pulse frequency (16-bit fixed-point Hz, private)
    pub pulse_frequency: Option<u16>,
    /// Vein contrast variance (16-bit fixed-point, private)
    pub vein_contrast_variance: Option<u16>,
    /// Inter-frame similarity scores (private)
    pub inter_frame_similarity: Option<[u16; 2]>,
    /// Multi-frame feature vectors (private)
    pub frame_features: Option<[[BiometricFeature; 512]; 3]>,
    /// Frame timestamps in microseconds (private)
    pub frame_timestamps: Option<[u64; 3]>,

    // === NEW: Liveness Public Inputs ===

    /// Aggregate liveness check result (public)
    pub liveness_passed: bool,
    /// Liveness thresholds for verification (public)
    pub liveness_thresholds: LivenessThresholds,
}

impl BiometricCircuit {
    /// Constrain liveness signals (~3,000 constraints)
    fn constrain_liveness_full(
        &self,
        cs: ConstraintSystemRef<Fr>,
        pulse_amplitude_var: Variable,
        pulse_frequency_var: Variable,
        vein_contrast_var: Variable,
        similarity_vars: &[Variable; 2],
        frame_feature_vars: &[[Variable; 512]; 3],
        threshold_vars: &LivenessThresholdVars,
    ) -> Result<Variable, SynthesisError>;
}
```

**Pre-conditions:**
- All private inputs provided for proving mode
- Only public inputs required for verification mode
- Trusted setup ceremony completed with sufficient constraint capacity

**Post-conditions:**
- Proof includes liveness verification
- Proof size remains 192 bytes
- Verification time ≤ 15ms

**Error Model:**
- `SynthesisError::Unsatisfiable` - Liveness constraints not met
- Does not reveal which specific constraint failed

**Implements:**
- REQ-022

**Verified by:**
- TEST-026, TEST-027, TEST-028

---

## Test Specifications

### TEST-020: Pulse Amplitude Extraction Accuracy

**Objective:** Verify pulse amplitude extraction achieves ≥ 95% detection rate

**Test Type:** Unit test with synthetic and real data

**Setup:**
- Synthetic NIR frames with known pulse amplitude (0.05, 0.10, 0.15, 0.20)
- Real captured frames from 100 subjects under controlled conditions

**Procedure:**
1. Generate synthetic frames with injected pulse signal
2. Extract pulse amplitude using LivenessSignalExtractor
3. Compare extracted value to ground truth
4. Repeat with real subject data

**Expected Results:**
- Synthetic: Extracted amplitude within ±5% of injected value
- Real: Detection rate ≥ 95% for subjects with normal circulation

**Pass Criteria:**
- Synthetic accuracy ≥ 95%
- Real detection rate ≥ 95%
- No false positives on static images

**Traces:** REQ-020

---

### TEST-021: Pulse Frequency Extraction Accuracy

**Objective:** Verify pulse frequency extraction within physiological bounds

**Test Type:** Unit test

**Setup:**
- Synthetic frames with pulse frequencies: 0.3, 0.5, 1.0, 2.0, 3.0, 3.5 Hz

**Procedure:**
1. Generate 3-frame sequence with known pulse frequency
2. Extract frequency using FFT-based algorithm
3. Verify extracted value matches input

**Expected Results:**
- Frequencies in [0.5, 3.0] Hz: Extracted within ±0.1 Hz
- Frequencies outside range: Correctly flagged as invalid

**Pass Criteria:**
- Accuracy ≥ 95% for valid frequencies
- 100% rejection of out-of-range frequencies

**Traces:** REQ-020

---

### TEST-022: Liveness Extraction Latency

**Objective:** Verify extraction completes within 150ms

**Test Type:** Performance test

**Setup:**
- Mobile device reference platform (Snapdragon 8 Gen 2 or equivalent)
- 640×480 NIR frames

**Procedure:**
1. Load 3 frames into memory
2. Start timer
3. Call extract_signals()
4. Stop timer
5. Repeat 1000 times

**Expected Results:**
- Mean latency ≤ 100ms
- 99th percentile ≤ 150ms
- Max latency ≤ 200ms

**Pass Criteria:**
- 99% of extractions complete in ≤ 150ms

**Traces:** REQ-020, NFR-020

---

### TEST-023: Pulse Frequency Threshold Enforcement

**Objective:** Verify circuit rejects out-of-range pulse frequencies

**Test Type:** Circuit constraint test

**Setup:**
- Test frequencies: 0.0, 0.4, 0.5, 1.5, 3.0, 3.1, 5.0 Hz

**Procedure:**
1. Create circuit with test frequency as witness
2. Attempt proof generation
3. Verify proof succeeds/fails as expected

**Expected Results:**
| Frequency | Expected Result |
|-----------|-----------------|
| 0.0 Hz | Proof fails (unsatisfiable) |
| 0.4 Hz | Proof fails |
| 0.5 Hz | Proof succeeds |
| 1.5 Hz | Proof succeeds |
| 3.0 Hz | Proof succeeds |
| 3.1 Hz | Proof fails |
| 5.0 Hz | Proof fails |

**Pass Criteria:**
- 100% correct accept/reject decisions

**Traces:** REQ-021

---

### TEST-024: Inter-Frame Similarity Threshold Enforcement

**Objective:** Verify circuit enforces similarity bounds

**Test Type:** Circuit constraint test

**Setup:**
- Test similarities: 0.50, 0.84, 0.85, 0.92, 0.99, 1.00

**Procedure:**
1. Generate frame pairs with controlled similarity
2. Create circuit with similarity as witness
3. Verify constraint satisfaction

**Expected Results:**
| Similarity | Expected Result |
|------------|-----------------|
| 0.50 | Proof fails (too different) |
| 0.84 | Proof fails |
| 0.85 | Proof succeeds |
| 0.92 | Proof succeeds |
| 0.99 | Proof succeeds |
| 1.00 | Proof fails (identical = replay) |

**Pass Criteria:**
- 100% correct boundary enforcement

**Traces:** REQ-021

---

### TEST-025: Constant-Time Threshold Comparison

**Objective:** Verify threshold comparisons have constant timing

**Test Type:** Timing analysis

**Setup:**
- Values at threshold boundary (pass/fail cases)
- High-precision timer

**Procedure:**
1. Measure time for threshold check with passing value
2. Measure time for threshold check with failing value
3. Statistical comparison of timing distributions

**Expected Results:**
- Timing variance < 1 microsecond between pass/fail cases
- No statistically significant timing difference (p > 0.05)

**Pass Criteria:**
- Timing distributions indistinguishable

**Traces:** REQ-021

---

### TEST-026: Circuit Constraint Count

**Objective:** Verify liveness adds ≤ 3,000 constraints

**Test Type:** Circuit analysis

**Procedure:**
1. Synthesize base BiometricCircuit
2. Count R1CS constraints
3. Synthesize extended circuit with liveness
4. Count constraints
5. Calculate difference

**Expected Results:**
- Base circuit: ~14,000 constraints
- Extended circuit: ≤ 17,000 constraints
- Liveness overhead: ≤ 3,000 constraints

**Pass Criteria:**
- Total constraints ≤ 17,000

**Traces:** REQ-022

---

### TEST-027: Extended Proof Generation Time

**Objective:** Verify proof generation ≤ 1,200ms

**Test Type:** Performance test

**Setup:**
- Mobile reference platform
- Full witness with liveness signals

**Procedure:**
1. Create circuit with all inputs
2. Start timer
3. Generate Groth16 proof
4. Stop timer
5. Repeat 100 times

**Expected Results:**
- Mean time ≤ 1,000ms
- 95th percentile ≤ 1,200ms
- Max time ≤ 1,500ms

**Pass Criteria:**
- 95% of proofs generated in ≤ 1,200ms

**Traces:** REQ-022, NFR-021

---

### TEST-028: Proof Privacy Verification

**Objective:** Verify liveness signals are not extractable from proof

**Test Type:** Cryptographic analysis

**Procedure:**
1. Generate proofs with different liveness signal values
2. Analyze proof bytes for correlation with inputs
3. Attempt statistical distinguishing attack

**Expected Results:**
- No correlation between proof bytes and signal values
- Statistical distinguisher has advantage ≤ negligible(λ)

**Pass Criteria:**
- Passes zero-knowledge simulation argument

**Traces:** REQ-022, NFR-023

---

### TEST-029: Printed Photo Attack Detection

**Objective:** Verify ≥ 99.9% detection of printed photo attacks

**Test Type:** Presentation attack test

**Setup:**
- 1000 high-quality printed palm photos (laser, inkjet, varying paper)
- 1000 genuine live presentations for comparison

**Procedure:**
1. Present printed photo to sensor
2. Capture 3 frames
3. Extract liveness signals
4. Verify rejection

**Expected Results:**
- Detection rate ≥ 99.9% (≤ 1 miss per 1000)
- False reject rate ≤ 1% on genuine presentations

**Pass Criteria:**
- APCER ≤ 0.1% for printed photos

**Traces:** REQ-023

---

### TEST-030: Screen Display Attack Detection

**Objective:** Verify ≥ 99.5% detection of screen display attacks

**Test Type:** Presentation attack test

**Setup:**
- 500 attacks using LCD displays (phone, tablet, monitor)
- 500 attacks using OLED displays
- Various display refresh rates (60Hz, 90Hz, 120Hz)

**Procedure:**
1. Display palm image/video on screen
2. Present to sensor
3. Capture and analyze

**Expected Results:**
- LCD detection ≥ 99.5%
- OLED detection ≥ 99.5%
- No correlation with refresh rate

**Pass Criteria:**
- APCER ≤ 0.5% for all display types

**Traces:** REQ-023

---

### TEST-031: Silicone Replica Attack Detection

**Objective:** Verify ≥ 98% detection of silicone/latex replicas

**Test Type:** Presentation attack test

**Setup:**
- 200 silicone replicas (varying quality, with/without embedded vein patterns)
- Professional-grade presentation attack instruments

**Procedure:**
1. Present replica to sensor
2. Capture 3 frames
3. Verify no pulse detected
4. Verify rejection

**Expected Results:**
- Detection rate ≥ 98%
- High-quality replicas (with printed veins) still rejected (no blood flow)

**Pass Criteria:**
- APCER ≤ 2% for replicas

**Traces:** REQ-023

---

### TEST-032: Video Replay Attack Detection

**Objective:** Verify ≥ 99% detection of video replay attacks

**Test Type:** Presentation attack test

**Setup:**
- Genuine palm videos captured from enrolled users
- Replay on high-quality displays

**Procedure:**
1. Capture genuine authentication video
2. Replay on display
3. Verify inter-frame similarity = 1.0 (identical frames repeat)
4. Verify rejection

**Expected Results:**
- Detection rate ≥ 99%
- Correctly identifies frame repetition pattern

**Pass Criteria:**
- APCER ≤ 1% for video replay

**Traces:** REQ-023

---

### TEST-033: Multi-Frame Capture Timing

**Objective:** Verify frame capture meets timing requirements

**Test Type:** Integration test

**Setup:**
- NIR sensor with capture API
- High-precision timer

**Procedure:**
1. Initiate capture
2. Record timestamp for each frame
3. Calculate inter-frame intervals
4. Verify total time

**Expected Results:**
- Exactly 3 frames captured
- Inter-frame interval: 80-120ms
- Total capture time ≤ 350ms

**Pass Criteria:**
- 100% compliance with timing spec

**Traces:** REQ-024

---

### TEST-034: Multi-Frame Resolution Consistency

**Objective:** Verify all frames have identical dimensions

**Test Type:** Unit test

**Procedure:**
1. Capture 3 frames
2. Compare dimensions
3. Compare bit depth

**Expected Results:**
- All frames: same width, height, channels
- All frames: 8-bit grayscale

**Pass Criteria:**
- 100% dimensional consistency

**Traces:** REQ-024

---

### TEST-035: Extraction Latency Distribution

**Objective:** Profile extraction latency distribution

**Test Type:** Performance profiling

**Setup:**
- 10,000 extraction operations
- Various input conditions

**Procedure:**
1. Measure extraction time for each operation
2. Compute statistics (mean, median, percentiles)
3. Identify outliers

**Expected Results:**
- Mean ≤ 100ms
- Median ≤ 90ms
- 99th percentile ≤ 150ms
- 99.9th percentile ≤ 200ms

**Pass Criteria:**
- NFR-020 met

**Traces:** NFR-020

---

### TEST-036: Proof Generation Overhead Measurement

**Objective:** Isolate liveness circuit overhead

**Test Type:** A/B performance comparison

**Procedure:**
1. Generate 100 proofs without liveness (base circuit)
2. Generate 100 proofs with liveness (extended circuit)
3. Calculate difference

**Expected Results:**
- Base mean: ~850ms
- Extended mean: ≤ 1,200ms
- Overhead: ≤ 350ms

**Pass Criteria:**
- NFR-021 met

**Traces:** NFR-021

---

### TEST-037: Memory Footprint Measurement

**Objective:** Verify memory overhead ≤ 16MB

**Test Type:** Memory profiling

**Setup:**
- Memory profiler (heaptrack or equivalent)

**Procedure:**
1. Profile base extraction and proof generation
2. Profile extended extraction and proof generation
3. Calculate peak memory difference

**Expected Results:**
- Additional peak memory ≤ 16MB
- Total peak memory ≤ 144MB

**Pass Criteria:**
- NFR-022 met

**Traces:** NFR-022

---

### TEST-038: Signal Privacy Audit

**Objective:** Verify liveness signals are never exposed

**Test Type:** Code audit + runtime verification

**Procedure:**
1. Static analysis: grep for signal value logging
2. Runtime: instrument all network/IPC calls
3. Verify only liveness_passed boolean transmitted

**Expected Results:**
- No logging of signal values
- No network transmission of signals
- Only boolean result in proof public inputs

**Pass Criteria:**
- Zero exposure of signal values

**Traces:** NFR-023

---

## Observability Requirements

### OBS-020: Liveness Extraction Metrics

**Metrics:**

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `sable_liveness_extraction_duration_ms` | Histogram | device_model | Time to extract all signals |
| `sable_liveness_extraction_success_total` | Counter | - | Successful extractions |
| `sable_liveness_extraction_failure_total` | Counter | error_type | Failed extractions |

**Logs:**

| Event | Level | Fields | PII |
|-------|-------|--------|-----|
| liveness_extraction_started | DEBUG | session_id, frame_count | No |
| liveness_extraction_completed | INFO | session_id, duration_ms, passed | No |
| liveness_extraction_failed | WARN | session_id, error_code | No |

**Note:** Signal values are NEVER logged (NFR-023 compliance)

**Traces:** REQ-020, NFR-020

---

### OBS-021: Presentation Attack Detection Metrics

**Metrics:**

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `sable_liveness_pass_total` | Counter | - | Liveness checks passed |
| `sable_liveness_fail_total` | Counter | - | Liveness checks failed |
| `sable_pad_detection_rate` | Gauge | attack_type | Rolling detection rate (7 days) |

**Alerts:**

| Alert | Condition | Severity |
|-------|-----------|----------|
| LivenessFailureSpike | fail_rate > 20% over 1hr | Warning |
| PotentialAttackCampaign | fail_rate > 50% over 15min | Critical |

**Traces:** REQ-023

---

### OBS-022: Proof Generation Performance

**Metrics:**

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `sable_proof_generation_duration_ms` | Histogram | circuit_type | Proof generation time |
| `sable_proof_liveness_overhead_ms` | Histogram | - | Liveness-specific overhead |

**Traces:** NFR-021

---

### OBS-023: Memory Usage Tracking

**Metrics:**

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `sable_liveness_memory_bytes` | Gauge | phase | Current memory usage |
| `sable_liveness_memory_peak_bytes` | Gauge | - | Peak memory this session |

**Traces:** NFR-022

---

## Implementation Plan

### Phase 1: Liveness Signal Extraction (Week 1-2)

1. Create `core/src/biometric/liveness.rs` module
2. Implement `LivenessSignalExtractor` trait
3. Implement pulse detection algorithm (FFT-based)
4. Implement vein contrast variance calculation
5. Implement inter-frame similarity calculation
6. Add unit tests (TEST-020, TEST-021)

### Phase 2: Circuit Extension (Week 3-4)

1. Extend `BiometricCircuit` struct with liveness fields
2. Implement `constrain_pulse_frequency_range()`
3. Implement `constrain_pulse_amplitude_threshold()`
4. Implement `constrain_vein_contrast_variance()`
5. Implement `constrain_inter_frame_similarity()`
6. Implement `constrain_liveness_full()` aggregator
7. Add circuit tests (TEST-023, TEST-024, TEST-025, TEST-026)

### Phase 3: Integration & Performance (Week 5-6)

1. Integrate liveness extraction into capture pipeline
2. Integrate circuit extension into proof generation
3. Performance optimization for mobile
4. Performance tests (TEST-022, TEST-027, TEST-035, TEST-036)
5. Memory profiling (TEST-037)

### Phase 4: PAD Testing & Hardening (Week 7-8)

1. Presentation attack testing (TEST-029, TEST-030, TEST-031, TEST-032)
2. Threshold calibration based on test results
3. Privacy audit (TEST-038)
4. Documentation and ADR finalization

---

## References

1. ISO/IEC 30107-3:2017 - Biometric presentation attack detection - Part 3: Testing and reporting
2. ISO/IEC 29794-1:2016 - Biometric sample quality - Part 1: Framework
3. NIST SP 800-76-2 - Biometric Specifications for Personal Identity Verification
4. Tome, P. et al. (2015). "On the Vulnerability of Palm Vein Recognition to Spoofing Attacks."
5. Kumar, A. & Zhou, Y. (2012). "Human Identification Using Palm-Vein Images."
6. Grother, P. & Tabassi, E. (2007). "Performance of Biometric Quality Measures."

---

**Document Version:** 1.0.0
**Last Updated:** 2026-02-03
**Author:** SABLE Development Team
**Review Status:** Pending stakeholder validation
