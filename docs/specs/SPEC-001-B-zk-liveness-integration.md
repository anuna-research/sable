# SPEC-001-B: Zero-Knowledge Liveness Integration

**Amendment to:** SPEC-001 (NIR Liveness), SPEC-001-A (RGB Liveness)
**Dependencies:** SPEC-003 (Platform Security Integration)
**Status:** Draft
**Created:** 2026-02-03
**Authors:** SABLE Development Team

---

## Amendment Summary

This specification defines which liveness signals can be verified within zero-knowledge
proofs and establishes a hybrid trust model combining ZK-verifiable signals, TEE
attestation, and interactive challenges. The goal is to provide meaningful liveness
guarantees while respecting the computational constraints of ZK circuits.

---

## Problem Statement

### Computational Reality

ZK circuits (Groth16 in SABLE) operate on finite field arithmetic. Many liveness
detection operations are computationally infeasible in ZK:

| Operation | Native ZK Support | Constraint Cost | Feasibility |
|-----------|-------------------|-----------------|-------------|
| Field addition | ✅ Native | 0 | ✅ Free |
| Field multiplication | ✅ Native | 1 | ✅ Trivial |
| Comparison (< > ≤ ≥) | ⚠️ Bit decomposition | ~254 | ✅ Feasible |
| Division | ⚠️ Inverse + multiply | ~500 | ✅ Feasible |
| Square root | ⚠️ Newton iteration | ~2,000 | ⚠️ Expensive |
| Floating point | ❌ Emulated | ~10,000+ | ❌ Impractical |
| Trigonometry (sin/cos) | ❌ Taylor series | ~50,000+ | ❌ Impractical |
| FFT (N points) | ❌ N log N trig ops | Millions | ❌ Impractical |
| CNN layer (small) | ❌ Matrix ops | Millions | ❌ Impractical |

### Current SABLE Circuit Budget

| Component | Constraints | Notes |
|-----------|-------------|-------|
| Biometric commitment | ~8,000 | Pedersen + Poseidon |
| Distance calculation | ~4,000 | 512-dim Euclidean |
| Threshold comparison | ~500 | Bit decomposition |
| NIR liveness (SPEC-001) | ~3,000 | 4 threshold checks |
| **Current Total** | **~15,500** | Proving time ~2-3s mobile |

**Target:** Keep total circuit under 25,000 constraints for acceptable mobile proving time.

### Trust Model Gap

Without ZK-verified liveness, an attacker controlling the device can:

```
Attacker's Device
┌─────────────────────────────────────────────────┐
│                                                 │
│  ┌─────────┐    ┌─────────┐    ┌─────────┐    │
│  │ Spoofed │───▶│ Forged  │───▶│  Valid  │    │
│  │  Photo  │    │ Signals │    │  Proof  │    │
│  └─────────┘    └─────────┘    └─────────┘    │
│                                                 │
│  Liveness "passes" with no real human present  │
│                                                 │
└─────────────────────────────────────────────────┘
```

---

## Hybrid Trust Architecture

### Three-Layer Defense

```
┌─────────────────────────────────────────────────────────────────────┐
│                     SABLE Liveness Trust Model                       │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Layer 1: ZK-Verified Signals (Trustless)                          │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │ • Temporal variance      • Color statistics                 │   │
│  │ • Edge metrics           • Motion consistency               │   │
│  │ Constraint budget: ~2,500                                   │   │
│  │ Trust: NONE REQUIRED - mathematically verified              │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                              │                                      │
│                              ▼                                      │
│  Layer 2: TEE-Attested Results (Hardware Trust)                    │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │ • Full RGB/NIR liveness pipeline                            │   │
│  │ • CNN-based texture analysis                                │   │
│  │ • rPPG signal extraction                                    │   │
│  │ Constraint budget: ~1,500 (attestation verification)        │   │
│  │ Trust: TEE hardware integrity                               │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                              │                                      │
│                              ▼                                      │
│  Layer 3: Interactive Challenge (Session Binding)                  │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │ • Challenge-response before proof generation                │   │
│  │ • Random challenge commitment in proof                      │   │
│  │ Constraint budget: ~500 (commitment verification)           │   │
│  │ Trust: Real-time interaction occurred                       │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  Total Additional Constraints: ~4,500                              │
│  Combined with base circuit: ~20,000 (within budget)               │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Trust Assumptions

| Layer | Trust Assumption | Failure Mode | Mitigation |
|-------|------------------|--------------|------------|
| Layer 1 | Math is correct | None (trustless) | N/A |
| Layer 2 | TEE not compromised | TEE exploit | Multiple signal fusion |
| Layer 3 | Real-time session | Replay attack | Timestamp + randomness |

---

## Requirements

### Layer 1: ZK-Verifiable Signals

#### REQ-080: Temporal Variance Signal

The circuit SHALL verify temporal variance indicating frame-to-frame changes:

```rust
/// Temporal variance computation (ZK-friendly)
///
/// Detects static images (photos) which have zero temporal variance.
/// Uses fixed-point arithmetic suitable for field operations.
///
/// # Circuit Implementation
/// - Input: Sequence of N frame hashes + variance value
/// - Verify: variance was computed correctly from frame differences
/// - Constraints: ~600
pub struct TemporalVarianceSignal {
    /// Frame commitment hashes (Poseidon)
    pub frame_commitments: Vec<FieldElement>,

    /// Computed variance (fixed-point, scaled by 2^16)
    /// Real variance = value / 65536
    pub variance_fp: u64,

    /// Number of frames in sequence
    pub frame_count: u32,

    /// Minimum frame interval (milliseconds)
    pub min_interval_ms: u32,
}

/// ZK circuit for temporal variance verification
///
/// # Constraints breakdown:
/// - Frame hash verification: N × 200 constraints
/// - Difference computation: (N-1) × 50 constraints
/// - Variance aggregation: 100 constraints
/// - Threshold comparison: 254 constraints
/// Total for N=5 frames: ~600 constraints
pub mod temporal_variance_circuit {
    use super::*;

    /// Minimum variance for live subject (fixed-point)
    /// 0.001 * 65536 = 65
    pub const MIN_VARIANCE_FP: u64 = 65;

    /// Maximum variance (reject camera shake / scene change)
    /// 0.5 * 65536 = 32768
    pub const MAX_VARIANCE_FP: u64 = 32768;
}
```

**What it detects:**
- Static photos (variance ≈ 0)
- Frozen video frames
- Image injection attacks

**What it cannot detect:**
- Video replay (has temporal variance)
- High-quality deepfakes

**Acceptance Criteria:**
- [ ] Detects static image attacks with 99%+ accuracy
- [ ] Circuit constraints ≤ 700
- [ ] No false rejections from natural micro-movements

**Traces:** CON-080, TEST-120

---

#### REQ-081: Color Channel Statistics

The circuit SHALL verify color channel statistics detecting screen displays:

```rust
/// Color channel statistics (ZK-friendly)
///
/// Screens have correlated RGB subpixels with characteristic patterns.
/// Real scenes have independent color channel variations.
///
/// # Circuit Implementation
/// - Input: Per-channel mean and variance statistics
/// - Verify: Channel independence metric
/// - Constraints: ~400
pub struct ColorChannelSignal {
    /// Red channel mean (fixed-point, 0-255 scaled to field)
    pub r_mean_fp: u64,
    /// Green channel mean
    pub g_mean_fp: u64,
    /// Blue channel mean
    pub b_mean_fp: u64,

    /// Cross-channel correlation coefficient (fixed-point)
    /// High correlation indicates screen display
    pub rg_correlation_fp: i64,
    pub rb_correlation_fp: i64,
    pub gb_correlation_fp: i64,

    /// Subpixel periodicity score (0 = no periodicity)
    pub periodicity_score_fp: u64,
}

pub mod color_channel_circuit {
    /// Maximum allowed channel correlation (fixed-point)
    /// Screens typically show correlation > 0.9
    /// 0.85 * 65536 = 55705
    pub const MAX_CORRELATION_FP: i64 = 55705;

    /// Maximum periodicity score
    /// 0.2 * 65536 = 13107
    pub const MAX_PERIODICITY_FP: u64 = 13107;
}
```

**What it detects:**
- LCD/OLED screen patterns
- Projector displays
- Some screen recordings

**What it cannot detect:**
- High-end displays with anti-detection
- Printed photos (no periodicity)

**Acceptance Criteria:**
- [ ] Detects screen replay with ≥ 85% accuracy
- [ ] Circuit constraints ≤ 500
- [ ] Works across different screen technologies

**Traces:** CON-081, TEST-121

---

#### REQ-082: Edge Frequency Metric

The circuit SHALL verify edge frequency characteristics:

```rust
/// Edge frequency metric (ZK-friendly)
///
/// Printed photos have characteristic edge artifacts from printing process.
/// Uses simplified Sobel-like edge detection suitable for ZK.
///
/// # Circuit Implementation
/// - Input: Edge histogram buckets (pre-computed)
/// - Verify: Histogram matches expected distribution
/// - Constraints: ~500
pub struct EdgeFrequencySignal {
    /// Edge magnitude histogram (8 buckets, fixed-point counts)
    pub edge_histogram: [u64; 8],

    /// High-frequency edge ratio
    /// Print artifacts show spike in certain frequency bands
    pub hf_ratio_fp: u64,

    /// Edge sharpness metric
    /// Prints often have unnaturally sharp or soft edges
    pub sharpness_fp: u64,

    /// Halftone pattern indicator (0-65536)
    pub halftone_score_fp: u64,
}

pub mod edge_frequency_circuit {
    /// Maximum halftone score (printed material detection)
    /// 0.15 * 65536 = 9830
    pub const MAX_HALFTONE_FP: u64 = 9830;

    /// Expected high-frequency ratio range for natural images
    pub const MIN_HF_RATIO_FP: u64 = 6554;   // 0.1
    pub const MAX_HF_RATIO_FP: u64 = 45875;  // 0.7
}
```

**What it detects:**
- Inkjet print halftone patterns
- Laser print artifacts
- Paper texture interference

**What it cannot detect:**
- High-quality photo prints
- Screen displays (different attack vector)

**Acceptance Criteria:**
- [ ] Detects print attacks with ≥ 80% accuracy
- [ ] Circuit constraints ≤ 600
- [ ] Low false positive rate on natural textures

**Traces:** CON-082, TEST-122

---

#### REQ-083: Motion Consistency Signal

The circuit SHALL verify motion consistency across frames:

```rust
/// Motion consistency signal (ZK-friendly)
///
/// Real 3D objects exhibit consistent motion parallax.
/// 2D spoofs (photos, screens) show uniform motion without parallax.
///
/// # Circuit Implementation
/// - Input: Motion vectors for tracked points
/// - Verify: Motion field consistency with 3D geometry
/// - Constraints: ~800
pub struct MotionConsistencySignal {
    /// Number of tracked feature points
    pub num_points: u32,

    /// Motion vector variance (should be non-zero for 3D)
    /// Fixed-point scaled by 2^16
    pub motion_variance_fp: u64,

    /// Parallax consistency score
    /// High score = motion consistent with 3D object
    pub parallax_score_fp: u64,

    /// Rigidity score (2D objects move rigidly)
    /// Low rigidity = flexible 3D object (good)
    pub rigidity_score_fp: u64,
}

pub mod motion_consistency_circuit {
    /// Minimum motion variance for 3D subject
    /// 0.02 * 65536 = 1311
    pub const MIN_MOTION_VARIANCE_FP: u64 = 1311;

    /// Minimum parallax score
    /// 0.3 * 65536 = 19661
    pub const MIN_PARALLAX_FP: u64 = 19661;

    /// Maximum rigidity (reject flat objects)
    /// 0.8 * 65536 = 52429
    pub const MAX_RIGIDITY_FP: u64 = 52429;
}
```

**What it detects:**
- Flat photo attacks (no parallax)
- Screen attacks (rigid motion)
- Some video replays (inconsistent parallax)

**Acceptance Criteria:**
- [ ] Detects 2D attacks with ≥ 85% accuracy
- [ ] Circuit constraints ≤ 900
- [ ] Handles natural head/hand movement

**Traces:** CON-083, TEST-123

---

#### REQ-084: Combined ZK Liveness Score

The circuit SHALL combine all ZK-verifiable signals:

```rust
/// Combined ZK-verifiable liveness signals
pub struct ZkLivenessSignals {
    pub temporal: TemporalVarianceSignal,
    pub color: ColorChannelSignal,
    pub edge: EdgeFrequencySignal,
    pub motion: MotionConsistencySignal,
}

/// ZK liveness verification result
pub struct ZkLivenessResult {
    /// Individual signal pass/fail
    pub temporal_pass: bool,
    pub color_pass: bool,
    pub edge_pass: bool,
    pub motion_pass: bool,

    /// Combined score (weighted, fixed-point)
    pub combined_score_fp: u64,

    /// Overall ZK liveness decision
    pub zk_liveness_pass: bool,
}

/// Circuit weights for signal fusion (must sum to 65536)
pub mod zk_fusion_weights {
    pub const TEMPORAL_WEIGHT: u64 = 16384;  // 0.25
    pub const COLOR_WEIGHT: u64 = 16384;     // 0.25
    pub const EDGE_WEIGHT: u64 = 13107;      // 0.20
    pub const MOTION_WEIGHT: u64 = 19661;    // 0.30

    /// Minimum combined score to pass ZK liveness
    /// 0.6 * 65536 = 39322
    pub const MIN_COMBINED_SCORE_FP: u64 = 39322;
}

/// Total ZK liveness circuit constraints
pub mod zk_liveness_constraints {
    pub const TEMPORAL_CONSTRAINTS: usize = 600;
    pub const COLOR_CONSTRAINTS: usize = 400;
    pub const EDGE_CONSTRAINTS: usize = 500;
    pub const MOTION_CONSTRAINTS: usize = 800;
    pub const FUSION_CONSTRAINTS: usize = 200;

    pub const TOTAL_ZK_LIVENESS: usize = 2500;
}
```

**Acceptance Criteria:**
- [ ] Total constraints ≤ 2,500
- [ ] Combined detection rate ≥ 75% (ZK layer alone)
- [ ] No single-point-of-failure in signal fusion

**Traces:** CON-084, TEST-124, TEST-125

---

### Layer 2: TEE-Attested Liveness

#### REQ-085: TEE Liveness Attestation Structure

The system SHALL support TEE-attested liveness results:

```rust
/// TEE-attested liveness result
///
/// Full liveness pipeline runs inside TEE (Secure Enclave / TrustZone).
/// Result is signed by hardware-backed key.
pub struct TeeAttestedLiveness {
    /// Liveness decision from full pipeline
    pub is_live: bool,

    /// Confidence score (0-100)
    pub confidence: u8,

    /// Which checks passed (bitmask)
    pub checks_passed: LivenessCheckFlags,

    /// Hash of input frames (proves what was analyzed)
    pub input_hash: [u8; 32],

    /// Timestamp (prevents replay)
    pub timestamp_ms: u64,

    /// Session nonce (binds to specific verification session)
    pub session_nonce: [u8; 32],

    /// TEE signature over above fields
    pub attestation_signature: TeeSignature,

    /// TEE public key certificate chain (for verification)
    pub attestation_chain: AttestationChain,
}

/// Liveness check flags (which checks the TEE performed)
#[derive(Debug, Clone, Copy)]
pub struct LivenessCheckFlags(u32);

impl LivenessCheckFlags {
    pub const TEXTURE_ANALYSIS: u32 = 1 << 0;
    pub const MOIRE_DETECTION: u32 = 1 << 1;
    pub const REFLECTION_ANALYSIS: u32 = 1 << 2;
    pub const RPPG_DETECTION: u32 = 1 << 3;
    pub const MICRO_MOVEMENT: u32 = 1 << 4;
    pub const BLINK_DETECTION: u32 = 1 << 5;
    pub const DEPTH_CHECK: u32 = 1 << 6;
    pub const NIR_SIGNALS: u32 = 1 << 7;

    /// Minimum required checks for TEE attestation
    pub const MINIMUM_CHECKS: u32 =
        Self::TEXTURE_ANALYSIS | Self::MICRO_MOVEMENT;
}
```

**Traces:** CON-085, TEST-126

---

#### REQ-086: TEE Attestation Verification in ZK

The circuit SHALL verify TEE attestation signatures:

```rust
/// TEE attestation verification in ZK circuit
///
/// # Circuit Implementation
/// - Verify signature over attestation data
/// - Verify certificate chain to known root
/// - Verify timestamp freshness
/// - Constraints: ~1,500
pub mod tee_attestation_circuit {
    use super::*;

    /// Supported TEE attestation types
    #[derive(Debug, Clone, Copy)]
    pub enum TeeType {
        /// Android KeyStore with StrongBox
        AndroidStrongBox,
        /// Android KeyStore (TEE-backed)
        AndroidTee,
        /// iOS Secure Enclave
        IosSecureEnclave,
        /// Intel SGX (desktop)
        IntelSgx,
    }

    /// Circuit inputs for attestation verification
    pub struct AttestationCircuitInputs {
        /// Attestation data (public input)
        pub attestation: TeeAttestedLiveness,

        /// Expected session nonce (public input)
        pub expected_nonce: [u8; 32],

        /// Current timestamp for freshness check (public input)
        pub current_timestamp_ms: u64,

        /// Maximum allowed attestation age (e.g., 30 seconds)
        pub max_age_ms: u64,

        /// Trusted TEE root public keys (circuit constant)
        pub trusted_roots: Vec<PublicKey>,
    }

    /// Attestation verification constraints
    pub const SIGNATURE_VERIFY_CONSTRAINTS: usize = 800;
    pub const CERT_CHAIN_CONSTRAINTS: usize = 500;
    pub const FRESHNESS_CHECK_CONSTRAINTS: usize = 100;
    pub const NONCE_CHECK_CONSTRAINTS: usize = 100;

    pub const TOTAL_ATTESTATION_CONSTRAINTS: usize = 1500;
}
```

**Verification Steps:**
1. Verify attestation signature with TEE public key
2. Verify TEE public key chains to trusted root
3. Verify timestamp within acceptable window
4. Verify session nonce matches expected value
5. Verify minimum liveness checks were performed

**Acceptance Criteria:**
- [ ] Supports Android StrongBox attestation
- [ ] Supports iOS Secure Enclave attestation
- [ ] Circuit constraints ≤ 1,500
- [ ] Attestation age limit configurable (default 30s)

**Traces:** CON-086, TEST-127, TEST-128

---

#### REQ-087: TEE Liveness Pipeline

The TEE SHALL execute the full liveness pipeline from SPEC-001-A:

```rust
/// Liveness pipeline executed inside TEE
///
/// This runs in the Trusted Execution Environment, isolated from
/// the main application. Results are signed before leaving TEE.
pub trait TeeLivenessPipeline {
    /// Execute full liveness assessment inside TEE
    ///
    /// # Security Properties
    /// - Input frames never leave TEE unencrypted
    /// - Intermediate computations protected
    /// - Only signed result exported
    fn assess_liveness(
        &self,
        frames: &[EncryptedFrame],
        session_nonce: &[u8; 32],
    ) -> Result<TeeAttestedLiveness, TeeError>;

    /// Get TEE capabilities
    fn capabilities(&self) -> TeeCapabilities;
}

/// TEE capabilities for liveness
pub struct TeeCapabilities {
    /// TEE type
    pub tee_type: TeeType,

    /// Supported liveness checks
    pub supported_checks: LivenessCheckFlags,

    /// Maximum frame resolution
    pub max_resolution: (u32, u32),

    /// Maximum frames per assessment
    pub max_frames: u32,

    /// Processing time estimate (ms)
    pub estimated_time_ms: u32,
}
```

**Acceptance Criteria:**
- [ ] Full SPEC-001-A pipeline runs in TEE
- [ ] Frame data never exposed to main application
- [ ] Attestation signed before TEE exit

**Traces:** CON-087, TEST-129

---

### Layer 3: Interactive Challenge Binding

#### REQ-088: Challenge Commitment

The circuit SHALL verify that an interactive challenge was completed:

```rust
/// Interactive challenge commitment for ZK proof
///
/// Challenge-response happens BEFORE proof generation.
/// The challenge and response are committed in the proof to prevent replay.
pub struct ChallengeCommitment {
    /// Random challenge issued by verifier/server
    pub challenge_id: [u8; 32],

    /// Challenge type that was requested
    pub challenge_type: ChallengeType,

    /// Timestamp when challenge was issued
    pub issued_at_ms: u64,

    /// Timestamp when response was received
    pub completed_at_ms: u64,

    /// Hash of challenge response data
    pub response_hash: [u8; 32],

    /// Server signature over challenge (proves server issued it)
    pub server_signature: Signature,
}

#[derive(Debug, Clone, Copy)]
pub enum ChallengeType {
    Blink,
    TurnLeft,
    TurnRight,
    NodUp,
    NodDown,
    Smile,
    RandomSequence,
}

pub mod challenge_circuit {
    /// Maximum time between challenge issue and completion
    pub const MAX_CHALLENGE_DURATION_MS: u64 = 10_000;  // 10 seconds

    /// Challenge verification constraints
    pub const CHALLENGE_CONSTRAINTS: usize = 500;
}
```

**Protocol Flow:**
```
1. Client requests verification session
2. Server generates random challenge_id and challenge_type
3. Server signs and sends challenge to client
4. Client performs challenge (blink, turn head, etc.)
5. Client captures response, computes response_hash
6. Client includes ChallengeCommitment in ZK proof
7. Circuit verifies:
   - Server signature valid
   - Timestamps within bounds
   - Response hash matches claimed response
```

**Acceptance Criteria:**
- [ ] Challenge unpredictable to attacker
- [ ] Replay of old challenges detected
- [ ] Circuit constraints ≤ 500
- [ ] Maximum challenge window configurable

**Traces:** CON-088, TEST-130

---

#### REQ-089: Session Binding

The proof SHALL be bound to a specific verification session:

```rust
/// Session binding for verification proof
///
/// Prevents proof from being replayed in different sessions.
pub struct SessionBinding {
    /// Unique session identifier
    pub session_id: [u8; 32],

    /// Server-provided session nonce
    pub server_nonce: [u8; 32],

    /// Client-provided session nonce
    pub client_nonce: [u8; 32],

    /// Combined session commitment
    /// H(session_id || server_nonce || client_nonce || timestamp)
    pub session_commitment: [u8; 32],

    /// Session creation timestamp
    pub created_at_ms: u64,

    /// Session expiry timestamp
    pub expires_at_ms: u64,
}

pub mod session_circuit {
    /// Default session validity period
    pub const DEFAULT_SESSION_VALIDITY_MS: u64 = 60_000;  // 1 minute

    /// Session binding constraints
    pub const SESSION_CONSTRAINTS: usize = 300;
}
```

**Acceptance Criteria:**
- [ ] Proof cannot be used in different session
- [ ] Session expiry enforced
- [ ] Dual-nonce prevents server or client manipulation

**Traces:** CON-089, TEST-131

---

### Combined Circuit

#### REQ-090: Integrated Liveness Circuit

The complete liveness verification circuit SHALL combine all layers:

```rust
/// Complete liveness verification circuit inputs
pub struct LivenessCircuitInputs {
    // === Layer 1: ZK-Verifiable Signals ===
    pub zk_signals: ZkLivenessSignals,

    // === Layer 2: TEE Attestation ===
    pub tee_attestation: Option<TeeAttestedLiveness>,

    // === Layer 3: Challenge Binding ===
    pub challenge: ChallengeCommitment,
    pub session: SessionBinding,

    // === Biometric Data (existing) ===
    pub biometric_commitment: BiometricCommitment,

    // === Public Inputs ===
    pub current_timestamp_ms: u64,
    pub verifier_public_key: PublicKey,
}

/// Liveness circuit outputs
pub struct LivenessCircuitOutputs {
    /// Overall liveness verified
    pub liveness_verified: bool,

    /// Verification confidence level
    pub confidence_level: ConfidenceLevel,

    /// Which layers contributed to decision
    pub layers_verified: LayerFlags,
}

#[derive(Debug, Clone, Copy)]
pub enum ConfidenceLevel {
    /// Only ZK signals (no TEE) - lower confidence
    ZkOnly,
    /// ZK + TEE attestation - medium confidence
    ZkPlusTee,
    /// ZK + TEE + depth sensor - high confidence
    ZkPlusTeePlusDepth,
    /// Full NIR pipeline (SPEC-001) - highest confidence
    FullNir,
}

pub struct LayerFlags(u8);
impl LayerFlags {
    pub const ZK_SIGNALS: u8 = 1 << 0;
    pub const TEE_ATTESTATION: u8 = 1 << 1;
    pub const CHALLENGE_RESPONSE: u8 = 1 << 2;
    pub const DEPTH_AUGMENTED: u8 = 1 << 3;
    pub const NIR_SIGNALS: u8 = 1 << 4;
}
```

**Constraint Budget:**

| Component | Constraints | Cumulative |
|-----------|-------------|------------|
| Biometric (existing) | 12,500 | 12,500 |
| ZK Liveness Signals | 2,500 | 15,000 |
| TEE Attestation | 1,500 | 16,500 |
| Challenge Binding | 500 | 17,000 |
| Session Binding | 300 | 17,300 |
| Decision Logic | 200 | 17,500 |
| **Total** | **17,500** | - |

**Proving Time Estimate:** ~3-4 seconds on modern mobile device

**Acceptance Criteria:**
- [ ] Total circuit ≤ 20,000 constraints
- [ ] Mobile proving time ≤ 5 seconds
- [ ] Graceful degradation when TEE unavailable

**Traces:** CON-090, TEST-132, TEST-133

---

### Fallback Modes

#### REQ-091: Degraded Mode Operation

The system SHALL support operation when some layers unavailable:

```rust
/// Liveness verification modes based on available capabilities
#[derive(Debug, Clone, Copy)]
pub enum LivenessMode {
    /// Full verification: ZK + TEE + Challenge
    /// Confidence: High
    Full {
        zk_weight: f32,      // 0.3
        tee_weight: f32,     // 0.5
        challenge_weight: f32, // 0.2
    },

    /// No TEE available: ZK + Challenge only
    /// Confidence: Medium
    /// Risk: TEE signals cannot be verified
    NoTee {
        zk_weight: f32,      // 0.6
        challenge_weight: f32, // 0.4
    },

    /// Minimal: ZK signals only (emergency fallback)
    /// Confidence: Low
    /// Risk: Sophisticated attacks may bypass
    ZkOnly {
        zk_weight: f32,      // 1.0
        required_score: f32, // Higher threshold: 0.8
    },
}

impl LivenessMode {
    /// Select mode based on device capabilities
    pub fn select(caps: &DeviceCapabilities) -> Self {
        if caps.has_tee && caps.tee_attestation_supported {
            LivenessMode::Full {
                zk_weight: 0.3,
                tee_weight: 0.5,
                challenge_weight: 0.2,
            }
        } else if caps.supports_challenges {
            LivenessMode::NoTee {
                zk_weight: 0.6,
                challenge_weight: 0.4,
            }
        } else {
            LivenessMode::ZkOnly {
                zk_weight: 1.0,
                required_score: 0.8,
            }
        }
    }

    /// Get minimum acceptable confidence for this mode
    pub fn min_confidence(&self) -> ConfidenceLevel {
        match self {
            LivenessMode::Full { .. } => ConfidenceLevel::ZkPlusTee,
            LivenessMode::NoTee { .. } => ConfidenceLevel::ZkOnly,
            LivenessMode::ZkOnly { .. } => ConfidenceLevel::ZkOnly,
        }
    }
}
```

**Policy Considerations:**

| Mode | Use Case | Risk Level | Recommended For |
|------|----------|------------|-----------------|
| Full | Default | Low | All verifications |
| NoTee | Older devices | Medium | Low-value transactions |
| ZkOnly | Emergency | High | Should require admin approval |

**Acceptance Criteria:**
- [ ] Mode selection automatic based on capabilities
- [ ] Higher thresholds in degraded modes
- [ ] Audit log records which mode was used

**Traces:** CON-091, TEST-134

---

## Contracts

### CON-080: Temporal Variance Contract

```rust
/// Contract: Temporal variance signal verification
///
/// # Preconditions
/// - Frame sequence of N ≥ 3 frames provided
/// - Frames captured at ≥ 10ms intervals
/// - Frame commitments computed with Poseidon hash
///
/// # Postconditions
/// - Variance correctly computed from frame differences
/// - Static images (variance < MIN) rejected
/// - Excessive motion (variance > MAX) rejected
///
/// # Circuit Guarantees
/// - Computation verified in ZK (trustless)
/// - Constraints ≤ 700
#[contract]
pub fn verify_temporal_variance(
    signal: &TemporalVarianceSignal
) -> bool;
```

**Traces:** REQ-080, TEST-120

---

### CON-081: Color Channel Contract

```rust
/// Contract: Color channel statistics verification
///
/// # Preconditions
/// - Color statistics computed from face/palm ROI
/// - Statistics in fixed-point format
///
/// # Postconditions
/// - Screen displays detected via correlation/periodicity
/// - Natural images pass correlation check
///
/// # Circuit Guarantees
/// - Constraints ≤ 500
#[contract]
pub fn verify_color_channels(
    signal: &ColorChannelSignal
) -> bool;
```

**Traces:** REQ-081, TEST-121

---

### CON-082: Edge Frequency Contract

```rust
/// Contract: Edge frequency metric verification
///
/// # Preconditions
/// - Edge histogram computed from input image
/// - Histogram buckets normalized
///
/// # Postconditions
/// - Print halftone patterns detected
/// - Natural edge distributions pass
///
/// # Circuit Guarantees
/// - Constraints ≤ 600
#[contract]
pub fn verify_edge_frequency(
    signal: &EdgeFrequencySignal
) -> bool;
```

**Traces:** REQ-082, TEST-122

---

### CON-083: Motion Consistency Contract

```rust
/// Contract: Motion consistency verification
///
/// # Preconditions
/// - Motion vectors tracked across ≥ 5 frames
/// - Sufficient feature points detected (≥ 10)
///
/// # Postconditions
/// - 2D flat objects rejected (no parallax)
/// - 3D objects with natural motion pass
///
/// # Circuit Guarantees
/// - Constraints ≤ 900
#[contract]
pub fn verify_motion_consistency(
    signal: &MotionConsistencySignal
) -> bool;
```

**Traces:** REQ-083, TEST-123

---

### CON-084: Combined ZK Liveness Contract

```rust
/// Contract: Combined ZK liveness verification
///
/// # Preconditions
/// - All four signal types provided
/// - Signals computed from same frame sequence
///
/// # Postconditions
/// - Weighted fusion computed correctly
/// - Combined score meets threshold
/// - Individual signal failures handled per policy
///
/// # Circuit Guarantees
/// - Total constraints ≤ 2,500
/// - Deterministic output for same inputs
#[contract]
pub fn verify_zk_liveness(
    signals: &ZkLivenessSignals
) -> ZkLivenessResult;
```

**Traces:** REQ-084, TEST-124, TEST-125

---

### CON-085: TEE Attestation Structure Contract

```rust
/// Contract: TEE attestation data structure
///
/// # Preconditions
/// - Liveness assessment completed in TEE
/// - TEE signing key available
///
/// # Postconditions
/// - All required fields populated
/// - Signature covers all data fields
/// - Timestamp reflects actual assessment time
/// - Session nonce matches verification session
///
/// # Security Invariants
/// - Private signing key never leaves TEE
/// - Input frames never leave TEE unencrypted
#[contract]
pub fn create_tee_attestation(
    result: LivenessResult,
    session_nonce: &[u8; 32],
) -> TeeAttestedLiveness;
```

**Traces:** REQ-085, TEST-126

---

### CON-086: TEE Attestation Verification Contract

```rust
/// Contract: TEE attestation verification in ZK
///
/// # Preconditions
/// - Attestation data provided
/// - Trusted root keys configured
/// - Current timestamp available
///
/// # Postconditions
/// - Signature verified against TEE public key
/// - Certificate chain verified to trusted root
/// - Timestamp within freshness window
/// - Session nonce matches expected value
///
/// # Circuit Guarantees
/// - Constraints ≤ 1,500
/// - Supports multiple TEE types
#[contract]
pub fn verify_tee_attestation(
    attestation: &TeeAttestedLiveness,
    expected_nonce: &[u8; 32],
    current_time: u64,
    max_age_ms: u64,
) -> bool;
```

**Traces:** REQ-086, TEST-127, TEST-128

---

### CON-087: TEE Pipeline Contract

```rust
/// Contract: TEE liveness pipeline execution
///
/// # Preconditions
/// - Encrypted frames provided to TEE
/// - TEE initialized and attestation capable
/// - Session nonce provided
///
/// # Postconditions
/// - Full liveness pipeline executed
/// - Result signed with TEE key
/// - Frames securely disposed after processing
///
/// # Security Invariants
/// - Frame plaintext never leaves TEE
/// - Intermediate results protected
/// - Attestation unforgeable without TEE key
#[contract]
pub fn execute_tee_liveness(
    frames: &[EncryptedFrame],
    session_nonce: &[u8; 32],
) -> TeeAttestedLiveness;
```

**Traces:** REQ-087, TEST-129

---

### CON-088: Challenge Commitment Contract

```rust
/// Contract: Interactive challenge commitment
///
/// # Preconditions
/// - Challenge issued by server with signature
/// - User completed challenge action
/// - Response data captured and hashed
///
/// # Postconditions
/// - Server signature valid
/// - Completion within time window
/// - Response hash correctly computed
///
/// # Circuit Guarantees
/// - Constraints ≤ 500
/// - Replay of old challenges detected
#[contract]
pub fn verify_challenge_commitment(
    commitment: &ChallengeCommitment,
    server_pubkey: &PublicKey,
    current_time: u64,
) -> bool;
```

**Traces:** REQ-088, TEST-130

---

### CON-089: Session Binding Contract

```rust
/// Contract: Session binding verification
///
/// # Preconditions
/// - Session created with server and client nonces
/// - Session commitment computed correctly
///
/// # Postconditions
/// - Session not expired
/// - Commitment matches expected value
/// - Proof bound to this specific session
///
/// # Circuit Guarantees
/// - Constraints ≤ 300
#[contract]
pub fn verify_session_binding(
    binding: &SessionBinding,
    current_time: u64,
) -> bool;
```

**Traces:** REQ-089, TEST-131

---

### CON-090: Integrated Liveness Circuit Contract

```rust
/// Contract: Complete liveness verification circuit
///
/// # Preconditions
/// - All available inputs provided
/// - Timestamps synchronized
/// - Public inputs match verifier expectations
///
/// # Postconditions
/// - All layers verified according to mode
/// - Confidence level accurately reflects inputs
/// - Binary liveness decision made
///
/// # Circuit Guarantees
/// - Total constraints ≤ 20,000
/// - Proving time ≤ 5 seconds mobile
/// - Verification time < 10ms
#[contract]
pub fn verify_liveness_complete(
    inputs: &LivenessCircuitInputs,
) -> LivenessCircuitOutputs;
```

**Traces:** REQ-090, TEST-132, TEST-133

---

### CON-091: Degraded Mode Contract

```rust
/// Contract: Degraded mode operation
///
/// # Preconditions
/// - Device capabilities detected
/// - Mode selected based on capabilities
///
/// # Postconditions
/// - Appropriate mode selected
/// - Thresholds adjusted for mode
/// - Mode recorded in proof outputs
///
/// # Security Invariants
/// - Cannot upgrade mode without capabilities
/// - Degraded modes have stricter thresholds
/// - Audit trail of mode selection
#[contract]
pub fn select_liveness_mode(
    capabilities: &DeviceCapabilities,
) -> LivenessMode;
```

**Traces:** REQ-091, TEST-134

---

## Test Cases

### ZK Signal Tests

#### TEST-120: Temporal Variance

| ID | Description | Input | Expected | Validation |
|----|-------------|-------|----------|------------|
| TEST-120-1 | Static image detection | Single image, 5 copies | variance < MIN, reject | Assert |
| TEST-120-2 | Live subject | Real face, 5 frames | variance in range, pass | Assert |
| TEST-120-3 | Excessive motion | Shaky video | variance > MAX, reject | Assert |
| TEST-120-4 | Video replay | Recorded video | variance in range (passes this check) | Assert |
| TEST-120-5 | Constraint count | Any input | ≤ 700 constraints | Measure |

#### TEST-121: Color Channel Statistics

| ID | Description | Input | Expected | Validation |
|----|-------------|-------|----------|------------|
| TEST-121-1 | LCD screen detection | Face on LCD | correlation > MAX, reject | Assert |
| TEST-121-2 | OLED screen detection | Face on OLED | periodicity > MAX, reject | Assert |
| TEST-121-3 | Natural scene | Real face | correlation < MAX, pass | Assert |
| TEST-121-4 | Printed photo | Inkjet print | May pass (print attack vector) | Note |
| TEST-121-5 | Constraint count | Any input | ≤ 500 constraints | Measure |

#### TEST-122: Edge Frequency

| ID | Description | Input | Expected | Validation |
|----|-------------|-------|----------|------------|
| TEST-122-1 | Inkjet print | Printed photo | halftone > MAX, reject | Assert |
| TEST-122-2 | Laser print | Printed photo | halftone > MAX, reject | Assert |
| TEST-122-3 | Natural face | Real face | halftone < MAX, pass | Assert |
| TEST-122-4 | Screen display | Face on screen | May pass (screen attack vector) | Note |
| TEST-122-5 | Constraint count | Any input | ≤ 600 constraints | Measure |

#### TEST-123: Motion Consistency

| ID | Description | Input | Expected | Validation |
|----|-------------|-------|----------|------------|
| TEST-123-1 | Flat photo | Photo moved in front of camera | rigidity > MAX, reject | Assert |
| TEST-123-2 | Real 3D face | Live subject with motion | parallax > MIN, pass | Assert |
| TEST-123-3 | Screen held flat | Screen moved | rigidity > MAX, reject | Assert |
| TEST-123-4 | Constraint count | Any input | ≤ 900 constraints | Measure |

#### TEST-124: Combined ZK Liveness

| ID | Description | Input | Expected | Validation |
|----|-------------|-------|----------|------------|
| TEST-124-1 | All signals pass | Live subject | combined > threshold, pass | Assert |
| TEST-124-2 | Photo attack | Static photo | temporal fails, overall reject | Assert |
| TEST-124-3 | Screen attack | Screen replay | color fails, overall reject | Assert |
| TEST-124-4 | Print attack | Printed photo | edge fails, overall reject | Assert |
| TEST-124-5 | 2D flat attack | Photo with motion | motion fails, overall reject | Assert |

#### TEST-125: ZK Liveness Accuracy

| ID | Description | Input | Expected | Validation |
|----|-------------|-------|----------|------------|
| TEST-125-1 | Live acceptance rate | 1000 live subjects | ≥ 95% pass | Statistical |
| TEST-125-2 | Photo rejection rate | 500 photo attacks | ≥ 90% reject | Statistical |
| TEST-125-3 | Screen rejection rate | 500 screen attacks | ≥ 80% reject | Statistical |
| TEST-125-4 | Print rejection rate | 500 print attacks | ≥ 75% reject | Statistical |
| TEST-125-5 | Total constraint count | Full ZK liveness | ≤ 2,500 | Measure |

---

### TEE Attestation Tests

#### TEST-126: TEE Attestation Structure

| ID | Description | Input | Expected | Validation |
|----|-------------|-------|----------|------------|
| TEST-126-1 | Valid attestation | Live liveness result | All fields populated | Assert |
| TEST-126-2 | Signature covers all fields | Modify any field | Signature invalid | Assert |
| TEST-126-3 | Timestamp accuracy | Real-time assessment | Timestamp within 1s | Assert |
| TEST-126-4 | Nonce binding | Wrong nonce | Verification fails | Assert |

#### TEST-127: TEE Signature Verification

| ID | Description | Input | Expected | Validation |
|----|-------------|-------|----------|------------|
| TEST-127-1 | Valid Android attestation | StrongBox signed | Signature valid | Assert |
| TEST-127-2 | Valid iOS attestation | Secure Enclave signed | Signature valid | Assert |
| TEST-127-3 | Forged signature | Fake signature | Verification fails | Assert |
| TEST-127-4 | Wrong key | Different TEE key | Verification fails | Assert |

#### TEST-128: Attestation Freshness

| ID | Description | Input | Expected | Validation |
|----|-------------|-------|----------|------------|
| TEST-128-1 | Fresh attestation | 5 seconds old | Passes freshness check | Assert |
| TEST-128-2 | Stale attestation | 60 seconds old | Fails freshness check | Assert |
| TEST-128-3 | Future timestamp | Timestamp in future | Fails validation | Assert |
| TEST-128-4 | Replay old attestation | Valid but old | Session nonce mismatch | Assert |

#### TEST-129: TEE Pipeline Execution

| ID | Description | Input | Expected | Validation |
|----|-------------|-------|----------|------------|
| TEST-129-1 | Pipeline completes | Live subject frames | Attestation returned | Assert |
| TEST-129-2 | Frames disposed | After execution | No frame data accessible | Memory check |
| TEST-129-3 | Attack detection | Spoof frames | is_live = false | Assert |

---

### Challenge Tests

#### TEST-130: Challenge Commitment

| ID | Description | Input | Expected | Validation |
|----|-------------|-------|----------|------------|
| TEST-130-1 | Valid challenge | Server-issued, completed | Verification passes | Assert |
| TEST-130-2 | Invalid server signature | Forged challenge | Verification fails | Assert |
| TEST-130-3 | Timeout exceeded | Completed after 15s | Verification fails | Assert |
| TEST-130-4 | Wrong response hash | Mismatched response | Verification fails | Assert |
| TEST-130-5 | Replay old challenge | Previously used | Session mismatch | Assert |

#### TEST-131: Session Binding

| ID | Description | Input | Expected | Validation |
|----|-------------|-------|----------|------------|
| TEST-131-1 | Valid session | Fresh session | Binding valid | Assert |
| TEST-131-2 | Expired session | 2 minutes old | Binding rejected | Assert |
| TEST-131-3 | Wrong session | Different session_id | Binding rejected | Assert |
| TEST-131-4 | Tampered commitment | Modified commitment | Hash mismatch | Assert |

---

### Integration Tests

#### TEST-132: Full Circuit Integration

| ID | Description | Input | Expected | Validation |
|----|-------------|-------|----------|------------|
| TEST-132-1 | Full mode verification | All layers present | Proof valid, high confidence | Assert |
| TEST-132-2 | NoTee mode | ZK + challenge only | Proof valid, medium confidence | Assert |
| TEST-132-3 | ZkOnly mode | ZK signals only | Proof valid, low confidence | Assert |
| TEST-132-4 | Circuit constraint count | Full circuit | ≤ 20,000 | Measure |

#### TEST-133: Proving Performance

| ID | Description | Input | Expected | Validation |
|----|-------------|-------|----------|------------|
| TEST-133-1 | Mobile proving time | iPhone 14 | ≤ 5 seconds | Timing |
| TEST-133-2 | Mobile proving time | Pixel 7 | ≤ 5 seconds | Timing |
| TEST-133-3 | Desktop proving time | M1 MacBook | ≤ 2 seconds | Timing |
| TEST-133-4 | Verification time | Any platform | ≤ 10ms | Timing |

#### TEST-134: Degraded Mode Selection

| ID | Description | Input | Expected | Validation |
|----|-------------|-------|----------|------------|
| TEST-134-1 | Full capabilities | TEE + camera | Full mode selected | Assert |
| TEST-134-2 | No TEE | Camera only | NoTee mode selected | Assert |
| TEST-134-3 | Minimal device | Basic camera | ZkOnly mode selected | Assert |
| TEST-134-4 | Mode in proof | Any mode | Mode recorded in output | Assert |

---

## Security Analysis

### SEC-080: Attack Surface Analysis

| Attack | ZK Layer | TEE Layer | Challenge Layer | Combined |
|--------|----------|-----------|-----------------|----------|
| Static photo | ✅ Temporal variance | ✅ Full detection | ⚠️ May pass blink | ✅ Blocked |
| Screen replay | ⚠️ Color may miss | ✅ Full detection | ✅ Motion fails | ✅ Blocked |
| Video replay | ❌ Has variance | ✅ Texture analysis | ⚠️ If pre-recorded | ✅ Blocked |
| 3D mask | ⚠️ Motion may pass | ⚠️ 70-85% detection | ⚠️ May complete | ⚠️ Partial |
| Deepfake injection | ❌ Bypasses camera | ⚠️ TEE may detect | ✅ Real-time required | ⚠️ Partial |
| TEE exploit | N/A | ❌ Compromised | N/A | ⚠️ Degrades to ZK |
| Signal forgery | ✅ Math verified | ✅ Attested | ✅ Server signed | ✅ Blocked |

### SEC-081: Residual Risks

| Risk | Severity | Mitigation |
|------|----------|------------|
| 3D mask attacks | Medium | Require depth sensor when available |
| TEE vulnerabilities | Low | Multi-layer defense, ZK signals still valid |
| Deepfake injection | Medium | TEE camera access, OS integrity |
| Sophisticated adversary | High | Consider multi-factor authentication |

### SEC-082: Recommendations by Risk Level

| Risk Level | Recommended Mode | Additional Measures |
|------------|------------------|---------------------|
| Low (social media) | ZkOnly acceptable | Basic liveness |
| Medium (financial) | Full mode required | Rate limiting |
| High (identity) | Full + depth | Multi-factor, human review |
| Critical (government) | Full NIR (SPEC-001) | In-person verification |

---

## Observability

### OBS-080: ZK Liveness Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `sable_zk_liveness_signal_score` | Histogram | signal_type | Individual signal scores |
| `sable_zk_liveness_combined_score` | Histogram | - | Combined ZK liveness score |
| `sable_zk_liveness_result_total` | Counter | result, mode | ZK liveness outcomes |
| `sable_zk_liveness_constraints` | Gauge | - | Circuit constraint count |

### OBS-081: TEE Attestation Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `sable_tee_attestation_total` | Counter | tee_type, result | Attestation outcomes |
| `sable_tee_attestation_age_ms` | Histogram | - | Attestation age at verification |
| `sable_tee_pipeline_duration_ms` | Histogram | tee_type | TEE liveness pipeline time |
| `sable_tee_availability` | Gauge | tee_type | TEE availability on devices |

### OBS-082: Challenge Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `sable_challenge_issued_total` | Counter | challenge_type | Challenges issued |
| `sable_challenge_completed_total` | Counter | challenge_type, result | Challenge outcomes |
| `sable_challenge_duration_ms` | Histogram | challenge_type | Time to complete |
| `sable_challenge_timeout_total` | Counter | challenge_type | Timeouts |

### OBS-083: Mode Selection Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `sable_liveness_mode_selected_total` | Counter | mode | Mode selection distribution |
| `sable_liveness_confidence_level` | Histogram | mode | Confidence by mode |
| `sable_liveness_proof_time_ms` | Histogram | mode | Proving time by mode |

---

## Implementation Plan

### Phase ZK-1: ZK Signal Implementation (Week 1-3)

1. Implement fixed-point arithmetic library for ZK
2. Implement temporal variance circuit
3. Implement color channel circuit
4. Implement edge frequency circuit
5. Implement motion consistency circuit
6. Unit tests for each circuit component
7. Constraint count validation

### Phase ZK-2: Signal Extraction (Week 4-5)

1. Implement temporal variance extraction (off-circuit)
2. Implement color statistics extraction
3. Implement edge histogram extraction
4. Implement motion vector extraction
5. Integration tests: extraction → circuit

### Phase ZK-3: TEE Integration (Week 6-8)

1. Android StrongBox attestation integration
2. iOS Secure Enclave attestation integration
3. TEE liveness pipeline implementation
4. Attestation verification circuit
5. Cross-platform testing

### Phase ZK-4: Challenge System (Week 9-10)

1. Challenge issuance server component
2. Challenge commitment structure
3. Challenge verification circuit
4. Session binding implementation
5. Protocol integration tests

### Phase ZK-5: Circuit Integration (Week 11-12)

1. Combine all circuit components
2. Implement mode selection logic
3. Implement degraded mode handling
4. Full circuit proving tests
5. Performance optimization

### Phase ZK-6: Security Review (Week 13-14)

1. Formal security analysis
2. Penetration testing
3. Constraint audit
4. Documentation
5. Final acceptance testing

---

## References

1. Groth16: On the Size of Pairing-based Non-interactive Arguments - Groth (2016)
2. Circom: A Robust and Scalable Language for Building ZK Applications
3. ARM TrustZone Security White Paper
4. Apple Secure Enclave Security Guide
5. Android Keystore System Architecture
6. Fixed-Point Arithmetic in Zero-Knowledge Proofs - various
7. EZKL: Easy Zero-Knowledge Machine Learning

---

**Document Version:** 1.0.0
**Last Updated:** 2026-02-03
**Author:** SABLE Development Team
**Review Status:** Draft - Requires cryptographic review
