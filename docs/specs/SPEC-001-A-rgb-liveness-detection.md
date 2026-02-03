# SPEC-001-A: RGB-Based Liveness Detection for Consumer Devices

**Amendment to:** SPEC-001 (NIR Liveness Detection)
**Status:** Draft
**Created:** 2026-02-03
**Authors:** SABLE Development Team

---

## Amendment Summary

SPEC-001 specifies NIR-based liveness detection requiring specialized Near-Infrared
cameras. This amendment extends liveness detection to work with standard RGB cameras
found on commodity consumer smartphones, enabling broader deployment while maintaining
presentation attack resistance.

---

## Motivation

### Hardware Reality

| Device Category | NIR Camera | RGB Camera | Depth Sensor |
|-----------------|------------|------------|--------------|
| Dedicated palm scanners | ✅ | ✅ | Sometimes |
| iPhone (TrueDepth) | ✅ (locked) | ✅ | ✅ (locked) |
| iPhone (standard) | ❌ | ✅ | ❌ |
| Android flagship | Rare | ✅ | Sometimes |
| Android mid-range | ❌ | ✅ | ❌ |
| Android budget | ❌ | ✅ | ❌ |

**Key constraints:**
- ~95% of consumer smartphones lack accessible NIR cameras
- iPhone TrueDepth IR/depth data not accessible to third-party apps
- Only RGB camera is universally available and accessible

### Threat Model for RGB Liveness

| Attack Type | Description | Difficulty | Prevalence |
|-------------|-------------|------------|------------|
| **Print attack** | Photo printed on paper | Low | High |
| **Screen replay** | Video/photo on another screen | Low | High |
| **Paper mask** | Printed face cutout with eye holes | Medium | Medium |
| **3D mask** | Silicone or resin face replica | High | Low |
| **Deepfake injection** | Synthetic video injected into camera stream | High | Emerging |

---

## User Profiles

### UP-RGB-001: Mobile App User

**Description:** End user enrolling/verifying biometrics using a standard smartphone
with only RGB cameras available.

**Characteristics:**
- Uses mid-range Android or standard iPhone
- No specialized biometric hardware
- Variable lighting conditions (indoor, outdoor, low-light)
- May be unfamiliar with biometric enrollment

**Happy Path - Face Liveness:**
1. User opens app and initiates face verification
2. App detects RGB camera only, selects RGB liveness pipeline
3. App guides user to position face in frame
4. Passive liveness checks run (texture, reflection, micro-movement)
5. If passive confidence < threshold, active challenge issued
6. User completes challenge (blink, head turn)
7. Liveness verified, proceeds to embedding extraction

**Happy Path - Palm Liveness:**
1. User opens app and initiates palm verification
2. App guides user to present palm to rear camera
3. App captures multi-frame sequence with slight motion
4. Passive liveness checks run (skin texture, color variation, specular reflection)
5. Liveness verified, proceeds to palm print extraction

---

## Requirements

### Capability Detection

#### REQ-060: Hardware Capability Detection

The system SHALL detect available camera capabilities at runtime:

```rust
/// Camera capabilities detected at runtime
#[derive(Debug, Clone)]
pub struct CameraCapabilities {
    /// RGB camera available
    pub has_rgb: bool,
    /// NIR camera available and accessible
    pub has_nir: bool,
    /// Depth sensor available and accessible
    pub has_depth: bool,
    /// Front-facing camera available
    pub has_front_camera: bool,
    /// Rear camera available
    pub has_rear_camera: bool,
    /// Maximum resolution (megapixels)
    pub max_resolution_mp: f32,
    /// Supports manual exposure control
    pub manual_exposure: bool,
    /// Supports torch/flash control
    pub has_torch: bool,
    /// Minimum frame rate for video capture
    pub min_fps: u32,
    /// Maximum frame rate for video capture
    pub max_fps: u32,
}

/// Liveness pipeline selection based on capabilities
pub enum LivenessPipeline {
    /// Full NIR pipeline (SPEC-001)
    NirFull,
    /// RGB with depth augmentation
    RgbWithDepth,
    /// RGB-only passive + active
    RgbPassiveActive,
    /// RGB-only passive (minimum viable)
    RgbPassiveOnly,
}

impl CameraCapabilities {
    /// Select optimal liveness pipeline for available hardware
    pub fn select_pipeline(&self) -> LivenessPipeline {
        if self.has_nir {
            LivenessPipeline::NirFull
        } else if self.has_depth {
            LivenessPipeline::RgbWithDepth
        } else if self.max_fps >= 15 {
            LivenessPipeline::RgbPassiveActive
        } else {
            LivenessPipeline::RgbPassiveOnly
        }
    }
}
```

**Acceptance Criteria:**
- [ ] Detects NIR camera availability on supported devices
- [ ] Detects depth sensor availability (ToF, structured light)
- [ ] Falls back gracefully when capabilities unavailable
- [ ] Capability detection completes in < 100ms

**Traces:** CON-060, TEST-100

---

### RGB Face Liveness

#### REQ-061: Passive Texture Analysis

The system SHALL analyze facial texture to detect print and screen attacks:

```rust
/// Texture analysis signals for face liveness
#[derive(Debug, Clone)]
pub struct FaceTextureSignals {
    /// Moiré pattern detection score (0.0 = no moiré, 1.0 = strong moiré)
    /// Moiré indicates screen display attack
    pub moire_score: f32,

    /// Print artifact score (0.0 = no artifacts, 1.0 = strong artifacts)
    /// Detects halftone patterns, paper texture, ink bleeding
    pub print_artifact_score: f32,

    /// Skin texture naturalness (0.0 = artificial, 1.0 = natural)
    /// Based on pore visibility, micro-texture patterns
    pub skin_texture_score: f32,

    /// Color distribution naturalness (0.0 = artificial, 1.0 = natural)
    /// Real skin has subsurface scattering, color variation
    pub color_naturalness_score: f32,

    /// High-frequency noise analysis
    /// Screens and prints have characteristic noise patterns
    pub noise_pattern_score: f32,
}

/// Texture analysis thresholds (research-calibrated)
pub mod texture_thresholds {
    /// Maximum moiré score to pass (screen detection)
    pub const MAX_MOIRE_SCORE: f32 = 0.15;
    /// Maximum print artifact score to pass
    pub const MAX_PRINT_ARTIFACT_SCORE: f32 = 0.20;
    /// Minimum skin texture naturalness
    pub const MIN_SKIN_TEXTURE_SCORE: f32 = 0.60;
    /// Minimum color naturalness
    pub const MIN_COLOR_NATURALNESS_SCORE: f32 = 0.55;
}
```

**Detection Methods:**

1. **Moiré Pattern Detection:**
   - Apply 2D FFT to face region
   - Detect periodic peaks indicating screen subpixel patterns
   - Screen refresh can cause temporal moiré in video

2. **Print Artifact Detection:**
   - Analyze high-frequency components for halftone patterns
   - Detect paper fiber texture in background
   - Check for unnatural color quantization

3. **Skin Texture Analysis:**
   - Use Local Binary Patterns (LBP) for micro-texture
   - Verify presence of pores, fine wrinkles
   - CNN-based texture classifier as secondary check

**Acceptance Criteria:**
- [ ] Detects screen replay attacks with ≥ 95% accuracy
- [ ] Detects print attacks with ≥ 97% accuracy
- [ ] False rejection rate on live faces < 3%
- [ ] Processing time < 50ms per frame

**Traces:** CON-061, TEST-101, TEST-102

---

#### REQ-062: Specular Reflection Analysis

The system SHALL analyze light reflections to distinguish real faces from spoofs:

```rust
/// Specular reflection signals
#[derive(Debug, Clone)]
pub struct ReflectionSignals {
    /// Number of specular highlights detected
    pub highlight_count: u32,

    /// Highlight position consistency across frames
    /// Real highlights move with head motion
    pub highlight_motion_consistency: f32,

    /// Highlight shape naturalness (real skin = soft edges)
    pub highlight_shape_score: f32,

    /// Screen glare detection (flat rectangular reflections)
    pub screen_glare_detected: bool,

    /// Paper glare detection (diffuse matte reflection)
    pub paper_glare_pattern: bool,
}
```

**Detection Methods:**

1. **Highlight Detection:**
   - Threshold high-intensity regions
   - Analyze shape (real skin: soft, curved; screen: sharp, geometric)

2. **Motion Parallax:**
   - Track highlight positions across frames
   - Real highlights move with 3D head geometry
   - Screen highlights remain fixed relative to screen surface

3. **Glare Pattern Analysis:**
   - Screens produce characteristic rectangular glare
   - Paper produces diffuse, uniform reflection
   - Real skin produces localized, curved specular highlights

**Acceptance Criteria:**
- [ ] Detects screen glare patterns with ≥ 90% accuracy
- [ ] Processes reflection analysis in < 30ms per frame
- [ ] Works under variable lighting conditions

**Traces:** CON-062, TEST-103

---

#### REQ-063: Micro-Movement Analysis

The system SHALL detect natural micro-movements present in live faces:

```rust
/// Micro-movement signals from temporal analysis
#[derive(Debug, Clone)]
pub struct MicroMovementSignals {
    /// Subtle facial movement magnitude
    /// Live faces have involuntary micro-movements
    pub micro_movement_magnitude: f32,

    /// Movement naturalness score
    /// Distinguishes natural movement from video playback
    pub movement_naturalness: f32,

    /// Pulse-induced color variation (remote PPG)
    /// Detects blood flow through subtle color changes
    pub color_variation_detected: bool,
    pub estimated_pulse_confidence: f32,

    /// Eye micro-saccade detection
    pub eye_movement_detected: bool,

    /// Breathing motion detection (chest/shoulder)
    pub breathing_detected: bool,
}

/// Temporal analysis configuration
pub struct TemporalAnalysisConfig {
    /// Minimum frames required for analysis
    pub min_frames: u32,  // Default: 10 frames
    /// Analysis window duration in milliseconds
    pub window_ms: u32,   // Default: 500ms
    /// Frame rate for temporal signals
    pub target_fps: u32,  // Default: 20 fps
}
```

**Detection Methods:**

1. **Remote Photoplethysmography (rPPG):**
   - Extract subtle color variations from face ROI
   - Apply bandpass filter (0.7-4 Hz, 42-240 BPM range)
   - Detect periodic signal indicating blood flow
   - Works on RGB cameras with adequate lighting

2. **Micro-Saccade Detection:**
   - Track eye position at high temporal resolution
   - Detect involuntary micro-movements (< 1°)
   - Static images and most videos lack natural saccades

3. **Micro-Expression Analysis:**
   - Detect subtle involuntary facial movements
   - Use optical flow on facial landmark regions
   - Compare against expected natural movement patterns

**Acceptance Criteria:**
- [ ] Detects rPPG signal in ≥ 80% of live subjects (good lighting)
- [ ] Falls back gracefully in poor lighting (no false reject)
- [ ] Detects video replay with ≥ 92% accuracy via temporal analysis
- [ ] Analysis window ≤ 1 second

**Traces:** CON-063, TEST-104, TEST-105

---

#### REQ-064: Active Challenge-Response

The system SHALL support active liveness challenges when passive confidence is insufficient:

```rust
/// Active liveness challenge types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LivenessChallenge {
    /// Blink eyes naturally
    Blink,
    /// Turn head left
    TurnLeft,
    /// Turn head right
    TurnRight,
    /// Nod head up
    NodUp,
    /// Nod head down
    NodDown,
    /// Smile
    Smile,
    /// Open mouth
    OpenMouth,
    /// Random sequence of above
    RandomSequence(u8),  // Number of challenges in sequence
}

/// Challenge-response result
#[derive(Debug, Clone)]
pub struct ChallengeResult {
    /// Challenge that was issued
    pub challenge: LivenessChallenge,
    /// Whether challenge was completed correctly
    pub completed: bool,
    /// Time to complete challenge (ms)
    pub response_time_ms: u32,
    /// Natural motion score (0.0 = robotic, 1.0 = natural)
    pub motion_naturalness: f32,
    /// Confidence in challenge completion
    pub confidence: f32,
}

/// Challenge configuration
pub struct ChallengeConfig {
    /// Maximum time allowed to complete challenge (ms)
    pub timeout_ms: u32,  // Default: 3000ms
    /// Minimum motion naturalness to accept
    pub min_naturalness: f32,  // Default: 0.5
    /// Number of challenges in random sequence
    pub sequence_length: u8,  // Default: 2
    /// Randomize challenge selection
    pub randomize: bool,  // Default: true
}
```

**Challenge Detection Methods:**

1. **Blink Detection:**
   - Track Eye Aspect Ratio (EAR) over time
   - Detect natural blink pattern (closure → opening)
   - Verify blink duration within natural range (100-400ms)

2. **Head Pose Estimation:**
   - Use facial landmarks to estimate 3D head pose
   - Track yaw (left/right) and pitch (up/down)
   - Verify smooth, natural motion trajectory

3. **Expression Detection:**
   - Track mouth landmarks for smile/open detection
   - Use expression classifier for verification
   - Check for natural muscle movement patterns

**Acceptance Criteria:**
- [ ] Challenge detection accuracy ≥ 98% for genuine attempts
- [ ] Rejects pre-recorded challenge videos with ≥ 95% accuracy
- [ ] Average challenge completion time < 2 seconds
- [ ] Provides clear user feedback during challenge

**Traces:** CON-064, TEST-106, TEST-107

---

#### REQ-065: Combined Face Liveness Score

The system SHALL combine passive and active signals into a final liveness decision:

```rust
/// Combined RGB face liveness assessment
#[derive(Debug, Clone)]
pub struct RgbFaceLivenessResult {
    /// Overall liveness decision
    pub is_live: bool,

    /// Combined confidence score (0.0 to 1.0)
    pub confidence: f32,

    /// Individual signal scores
    pub texture_signals: FaceTextureSignals,
    pub reflection_signals: ReflectionSignals,
    pub micro_movement_signals: MicroMovementSignals,

    /// Active challenge results (if performed)
    pub challenge_results: Option<Vec<ChallengeResult>>,

    /// Detected attack type (if rejected)
    pub detected_attack: Option<DetectedAttackType>,

    /// Pipeline used for this assessment
    pub pipeline: LivenessPipeline,
}

#[derive(Debug, Clone, Copy)]
pub enum DetectedAttackType {
    PrintAttack,
    ScreenReplay,
    PaperMask,
    SuspectedDeepfake,
    Unknown,
}

/// Liveness decision thresholds
pub mod liveness_thresholds {
    /// Minimum passive confidence to skip active challenge
    pub const PASSIVE_CONFIDENCE_THRESHOLD: f32 = 0.85;

    /// Minimum combined confidence to accept as live
    pub const FINAL_ACCEPTANCE_THRESHOLD: f32 = 0.75;

    /// Maximum confidence for rejection without active challenge
    pub const PASSIVE_REJECTION_THRESHOLD: f32 = 0.30;
}
```

**Fusion Strategy:**

```
Score Calculation:
1. texture_score = weighted_avg(moire, print, skin, color, noise)
2. reflection_score = weighted_avg(highlight, motion, glare)
3. temporal_score = weighted_avg(rppg, saccade, micro_expression)
4. passive_score = 0.4 * texture + 0.3 * reflection + 0.3 * temporal

Decision Logic:
- IF passive_score ≥ 0.85 → ACCEPT (high confidence live)
- IF passive_score ≤ 0.30 → REJECT (high confidence spoof)
- ELSE → Issue active challenge
  - IF challenge_passed AND passive_score ≥ 0.50 → ACCEPT
  - ELSE → REJECT
```

**Acceptance Criteria:**
- [ ] Combined detection rate ≥ 96% for live subjects
- [ ] Combined attack detection ≥ 94% across all attack types
- [ ] False acceptance rate < 3%
- [ ] Provides actionable feedback on rejection

**Traces:** CON-065, TEST-108, TEST-109

---

### RGB Palm Liveness

#### REQ-066: Palm Texture Analysis

The system SHALL analyze palm texture to detect print and artificial palm attacks:

```rust
/// Palm texture analysis for RGB liveness
#[derive(Debug, Clone)]
pub struct PalmTextureSignals {
    /// Skin texture score (pores, fine lines)
    pub skin_texture_score: f32,

    /// Print detection score (halftone, paper texture)
    pub print_detection_score: f32,

    /// Silicone/latex detection score
    pub artificial_material_score: f32,

    /// Natural color variation (blood perfusion)
    pub color_variation_score: f32,

    /// Ridge clarity and depth appearance
    pub ridge_depth_score: f32,
}

/// Palm texture thresholds
pub mod palm_texture_thresholds {
    pub const MIN_SKIN_TEXTURE: f32 = 0.55;
    pub const MAX_PRINT_SCORE: f32 = 0.25;
    pub const MAX_ARTIFICIAL_SCORE: f32 = 0.20;
    pub const MIN_COLOR_VARIATION: f32 = 0.40;
}
```

**Detection Methods:**

1. **Skin Texture Analysis:**
   - Analyze micro-texture using Gabor filters
   - Verify presence of sweat pores
   - Check for natural skin wrinkle patterns

2. **Print Detection:**
   - Detect halftone dot patterns in frequency domain
   - Identify paper fiber texture
   - Check for unnatural edge sharpness

3. **Material Classification:**
   - CNN-based classifier for skin vs silicone vs paper
   - Analyze subsurface scattering characteristics
   - Check color response under different angles

**Acceptance Criteria:**
- [ ] Detects printed palm attacks with ≥ 97% accuracy
- [ ] Detects silicone palm replicas with ≥ 90% accuracy
- [ ] False rejection of live palms < 2%

**Traces:** CON-066, TEST-110

---

#### REQ-067: Palm Color Dynamics

The system SHALL analyze color dynamics indicating blood flow:

```rust
/// Palm color dynamics for liveness
#[derive(Debug, Clone)]
pub struct PalmColorDynamics {
    /// Detected color variation over time
    pub temporal_color_variation: f32,

    /// Pressure response detected (blanching)
    pub pressure_response: bool,

    /// Consistent with blood perfusion patterns
    pub perfusion_pattern_score: f32,

    /// rPPG signal detected from palm
    pub rppg_detected: bool,
    pub rppg_confidence: f32,
}
```

**Detection Methods:**

1. **Temporal Color Analysis:**
   - Capture palm over 0.5-1 second window
   - Analyze subtle color changes from blood flow
   - Real palms show rhythmic color variation

2. **Pressure Response (Optional):**
   - Guide user to press palm slightly
   - Detect blanching (whitening) response
   - Verify color return after pressure release

3. **Palm rPPG:**
   - Extract pulse signal from palm skin
   - Palm has strong blood perfusion, good rPPG signal
   - Verify signal matches physiological range

**Acceptance Criteria:**
- [ ] Detects color dynamics in ≥ 85% of live palms
- [ ] rPPG detection in ≥ 75% of live palms (good lighting)
- [ ] Graceful degradation in poor lighting

**Traces:** CON-067, TEST-111

---

#### REQ-068: Palm Specular Response

The system SHALL analyze specular reflection behavior of palm surface:

```rust
/// Palm specular reflection analysis
#[derive(Debug, Clone)]
pub struct PalmSpecularSignals {
    /// Specular highlight characteristics
    pub highlight_softness: f32,  // Real skin: soft; paper: sharp

    /// Reflection angle consistency
    pub angle_consistency: f32,

    /// Subsurface scattering evidence
    pub subsurface_scattering: f32,

    /// Detected material type
    pub material_classification: PalmMaterial,
}

#[derive(Debug, Clone, Copy)]
pub enum PalmMaterial {
    RealSkin,
    Paper,
    Silicone,
    Screen,
    Unknown,
}
```

**Detection Methods:**

1. **Guided Illumination (with torch):**
   - Use phone torch/flash during capture
   - Analyze reflection pattern changes
   - Real skin has characteristic BRDF

2. **Multi-Angle Analysis:**
   - Guide user to slightly tilt palm
   - Observe specular highlight movement
   - 2D prints don't exhibit correct 3D reflection

**Acceptance Criteria:**
- [ ] Material classification accuracy ≥ 92%
- [ ] Works with and without torch illumination

**Traces:** CON-068, TEST-112

---

#### REQ-069: Palm Motion Analysis

The system SHALL verify natural palm motion characteristics:

```rust
/// Palm motion analysis signals
#[derive(Debug, Clone)]
pub struct PalmMotionSignals {
    /// Natural hand tremor detected
    pub tremor_detected: bool,
    pub tremor_frequency: f32,  // Expected: 8-12 Hz

    /// Finger micro-movement detected
    pub finger_movement: bool,

    /// 3D motion parallax consistent with real hand
    pub parallax_score: f32,

    /// Flexibility observed (not rigid like printout)
    pub flexibility_score: f32,
}
```

**Detection Methods:**

1. **Physiological Tremor:**
   - All humans have involuntary hand tremor (8-12 Hz)
   - Detect micro-oscillations in palm position
   - Printed photos are perfectly still

2. **Flexibility Test:**
   - Guide user to slightly flex fingers
   - Observe natural palm surface deformation
   - 2D printouts cannot flex

3. **Motion Parallax:**
   - Analyze apparent motion of palm features
   - Real 3D hand shows depth-consistent parallax
   - Flat printouts show uniform motion

**Acceptance Criteria:**
- [ ] Tremor detection in ≥ 90% of live palms
- [ ] Flexibility test catches ≥ 95% of print attacks
- [ ] Total motion analysis < 1 second

**Traces:** CON-069, TEST-113

---

#### REQ-070: Combined Palm Liveness Score

The system SHALL combine all palm liveness signals:

```rust
/// Combined RGB palm liveness result
#[derive(Debug, Clone)]
pub struct RgbPalmLivenessResult {
    /// Overall liveness decision
    pub is_live: bool,

    /// Combined confidence
    pub confidence: f32,

    /// Individual signals
    pub texture_signals: PalmTextureSignals,
    pub color_dynamics: PalmColorDynamics,
    pub specular_signals: PalmSpecularSignals,
    pub motion_signals: PalmMotionSignals,

    /// Detected attack type if rejected
    pub detected_attack: Option<PalmAttackType>,
}

#[derive(Debug, Clone, Copy)]
pub enum PalmAttackType {
    PrintedPhoto,
    ScreenDisplay,
    SiliconeMold,
    LatexGlove,
    Unknown,
}
```

**Fusion Weights:**
```
palm_liveness = 0.30 * texture_score
             + 0.25 * color_dynamics_score
             + 0.20 * specular_score
             + 0.25 * motion_score
```

**Acceptance Criteria:**
- [ ] Combined palm liveness detection ≥ 95%
- [ ] Attack detection rate ≥ 93%
- [ ] Total palm liveness assessment < 2 seconds

**Traces:** CON-070, TEST-114

---

### Depth Augmentation (When Available)

#### REQ-071: Depth-Augmented Liveness

When depth sensors are available, the system SHALL use depth data to augment RGB liveness:

```rust
/// Depth-augmented liveness signals
#[derive(Debug, Clone)]
pub struct DepthLivenessSignals {
    /// Face/palm detected at expected depth
    pub depth_consistent: bool,

    /// 3D structure matches expected geometry
    pub geometry_score: f32,

    /// Depth edges align with RGB edges
    pub depth_rgb_consistency: f32,

    /// Flat surface detection (screen/paper)
    pub flat_surface_detected: bool,

    /// Depth variation within face/palm region
    pub depth_variation: f32,
}

/// Depth augmentation configuration
pub struct DepthConfig {
    /// Minimum depth for valid capture (cm)
    pub min_depth_cm: f32,  // Default: 15
    /// Maximum depth for valid capture (cm)
    pub max_depth_cm: f32,  // Default: 60
    /// Minimum depth variation for 3D object
    pub min_depth_variation_cm: f32,  // Default: 1.0
}
```

**Benefits of Depth:**
- Immediately detects flat attacks (prints, screens)
- Verifies 3D face/palm geometry
- Improves confidence significantly when available

**Acceptance Criteria:**
- [ ] Depth augmentation improves detection rate by ≥ 15%
- [ ] Flat attack detection ≥ 99% with depth
- [ ] Graceful operation when depth unavailable

**Traces:** CON-071, TEST-115

---

## Contracts

### CON-060: Hardware Capability Detection Contract

```rust
/// Contract: Hardware capability detection
///
/// # Preconditions
/// - Camera permission granted
/// - At least one camera available
///
/// # Postconditions
/// - CameraCapabilities accurately reflects device hardware
/// - Pipeline selection matches available capabilities
/// - Detection completes within 100ms
///
/// # Invariants
/// - has_rgb is true for all supported devices
/// - Pipeline never requires unavailable hardware
#[contract]
pub fn detect_capabilities() -> CameraCapabilities;
```

**Traces:** REQ-060, TEST-100

---

### CON-061: Face Texture Analysis Contract

```rust
/// Contract: Face texture analysis for spoof detection
///
/// # Preconditions
/// - Face detected and cropped from frame
/// - Image resolution ≥ 224x224 pixels
/// - Face occupies ≥ 20% of crop area
///
/// # Postconditions
/// - All texture signals computed
/// - moire_score in [0.0, 1.0]
/// - print_artifact_score in [0.0, 1.0]
/// - skin_texture_score in [0.0, 1.0]
/// - Processing time < 50ms
///
/// # Invariants
/// - Scores are deterministic for same input
/// - No biometric data retained after analysis
#[contract]
pub fn analyze_face_texture(face_crop: &FaceCrop) -> FaceTextureSignals;
```

**Traces:** REQ-061, TEST-101, TEST-102

---

### CON-062: Reflection Analysis Contract

```rust
/// Contract: Specular reflection analysis
///
/// # Preconditions
/// - Frame sequence available (≥ 3 frames)
/// - Adequate lighting (mean brightness ≥ 50)
///
/// # Postconditions
/// - Highlight detection completed
/// - Screen glare pattern evaluated
/// - Processing time < 30ms per frame
#[contract]
pub fn analyze_reflections(frames: &[Frame]) -> ReflectionSignals;
```

**Traces:** REQ-062, TEST-103

---

### CON-063: Micro-Movement Analysis Contract

```rust
/// Contract: Temporal micro-movement analysis
///
/// # Preconditions
/// - Frame sequence with ≥ 10 frames
/// - Frame rate ≥ 15 fps
/// - Face tracked across all frames
///
/// # Postconditions
/// - Micro-movement signals extracted
/// - rPPG attempted if lighting adequate
/// - No false rejection due to rPPG failure alone
#[contract]
pub fn analyze_micro_movements(
    frames: &[Frame],
    face_tracks: &[FaceTrack]
) -> MicroMovementSignals;
```

**Traces:** REQ-063, TEST-104, TEST-105

---

### CON-064: Challenge-Response Contract

```rust
/// Contract: Active liveness challenge
///
/// # Preconditions
/// - User informed of upcoming challenge
/// - Camera streaming at ≥ 15 fps
/// - Challenge selected (random or specified)
///
/// # Postconditions
/// - Challenge result determined within timeout
/// - Natural motion evaluated
/// - User feedback provided throughout
///
/// # Invariants
/// - Challenge type is unpredictable to attacker
/// - Same challenge not repeated consecutively
#[contract]
pub fn execute_challenge(
    challenge: LivenessChallenge,
    config: &ChallengeConfig
) -> ChallengeResult;
```

**Traces:** REQ-064, TEST-106, TEST-107

---

### CON-065: Combined Face Liveness Contract

```rust
/// Contract: Combined face liveness decision
///
/// # Preconditions
/// - Face detected in input
/// - Minimum quality requirements met
///
/// # Postconditions
/// - Binary liveness decision made
/// - Confidence score in [0.0, 1.0]
/// - Attack type identified if rejected
/// - Total time < 3 seconds (passive + active if needed)
///
/// # Security Invariants
/// - False acceptance rate < 3% under standard attacks
/// - No biometric data persisted
#[contract]
pub fn assess_face_liveness(
    input: &LivenessInput,
    config: &LivenessConfig
) -> RgbFaceLivenessResult;
```

**Traces:** REQ-065, TEST-108, TEST-109

---

### CON-066: Palm Texture Analysis Contract

```rust
/// Contract: Palm texture analysis
///
/// # Preconditions
/// - Palm ROI extracted from frame
/// - ROI resolution ≥ 200x200 pixels
///
/// # Postconditions
/// - Texture signals computed
/// - Print detection evaluated
/// - Material classification attempted
#[contract]
pub fn analyze_palm_texture(palm_roi: &PalmRoi) -> PalmTextureSignals;
```

**Traces:** REQ-066, TEST-110

---

### CON-067: Palm Color Dynamics Contract

```rust
/// Contract: Palm color dynamics analysis
///
/// # Preconditions
/// - Frame sequence ≥ 15 frames over ≥ 0.5 seconds
/// - Palm tracked across frames
/// - Adequate lighting for color analysis
///
/// # Postconditions
/// - Temporal color variation measured
/// - rPPG attempted from palm region
/// - Graceful result if poor lighting
#[contract]
pub fn analyze_palm_color_dynamics(
    frames: &[Frame],
    palm_tracks: &[PalmTrack]
) -> PalmColorDynamics;
```

**Traces:** REQ-067, TEST-111

---

### CON-068: Palm Specular Response Contract

```rust
/// Contract: Palm specular reflection analysis
///
/// # Preconditions
/// - Palm captured with consistent lighting
/// - Optional: torch illumination available
///
/// # Postconditions
/// - Specular characteristics analyzed
/// - Material classification provided
#[contract]
pub fn analyze_palm_specular(
    palm_frames: &[Frame],
    torch_used: bool
) -> PalmSpecularSignals;
```

**Traces:** REQ-068, TEST-112

---

### CON-069: Palm Motion Analysis Contract

```rust
/// Contract: Palm motion analysis
///
/// # Preconditions
/// - Frame sequence ≥ 20 frames at ≥ 20 fps
/// - Palm and fingers visible
///
/// # Postconditions
/// - Tremor analysis completed
/// - Parallax evaluated
/// - Flexibility indicators assessed
#[contract]
pub fn analyze_palm_motion(
    frames: &[Frame],
    palm_tracks: &[PalmTrack]
) -> PalmMotionSignals;
```

**Traces:** REQ-069, TEST-113

---

### CON-070: Combined Palm Liveness Contract

```rust
/// Contract: Combined palm liveness decision
///
/// # Preconditions
/// - Palm detected and tracked
/// - Frame sequence captured
///
/// # Postconditions
/// - Binary liveness decision
/// - Confidence score provided
/// - Attack type if rejected
/// - Total assessment < 2 seconds
#[contract]
pub fn assess_palm_liveness(
    input: &PalmLivenessInput,
    config: &PalmLivenessConfig
) -> RgbPalmLivenessResult;
```

**Traces:** REQ-070, TEST-114

---

### CON-071: Depth Augmentation Contract

```rust
/// Contract: Depth-augmented liveness
///
/// # Preconditions
/// - Depth sensor available and calibrated
/// - RGB-depth alignment known
///
/// # Postconditions
/// - Depth signals extracted
/// - Flat surface detection completed
/// - RGB liveness confidence augmented
#[contract]
pub fn augment_with_depth(
    rgb_result: &LivenessResult,
    depth_frames: &[DepthFrame]
) -> DepthLivenessSignals;
```

**Traces:** REQ-071, TEST-115

---

## Test Cases

### Capability Detection Tests

#### TEST-100: Hardware Capability Detection

| ID | Description | Input | Expected | Validation |
|----|-------------|-------|----------|------------|
| TEST-100-1 | Detect RGB camera | Any smartphone | has_rgb = true | Assert |
| TEST-100-2 | Detect missing NIR | Standard phone | has_nir = false | Assert |
| TEST-100-3 | Pipeline selection RGB-only | No NIR, no depth | RgbPassiveActive | Assert |
| TEST-100-4 | Pipeline selection with depth | RGB + depth | RgbWithDepth | Assert |
| TEST-100-5 | Detection latency | Any device | < 100ms | Timing |

---

### Face Texture Analysis Tests

#### TEST-101: Screen Replay Detection

| ID | Description | Input | Expected | Validation |
|----|-------------|-------|----------|------------|
| TEST-101-1 | Detect phone screen | Face on phone | moire_score > 0.5 | Assert |
| TEST-101-2 | Detect tablet screen | Face on tablet | moire_score > 0.4 | Assert |
| TEST-101-3 | Detect laptop screen | Face on laptop | moire_score > 0.3 | Assert |
| TEST-101-4 | Pass live face | Real face | moire_score < 0.15 | Assert |
| TEST-101-5 | Various screen types | LCD, OLED, IPS | Detection rate ≥ 95% | Statistical |

#### TEST-102: Print Attack Detection

| ID | Description | Input | Expected | Validation |
|----|-------------|-------|----------|------------|
| TEST-102-1 | Inkjet print | Printed face photo | print_artifact_score > 0.5 | Assert |
| TEST-102-2 | Laser print | Printed face photo | print_artifact_score > 0.4 | Assert |
| TEST-102-3 | Glossy photo | Photo paper print | print_artifact_score > 0.3 | Assert |
| TEST-102-4 | Pass live face | Real face | print_artifact_score < 0.2 | Assert |
| TEST-102-5 | Print attack corpus | 100 print attacks | Detection rate ≥ 97% | Statistical |

---

### Reflection Analysis Tests

#### TEST-103: Specular Reflection Detection

| ID | Description | Input | Expected | Validation |
|----|-------------|-------|----------|------------|
| TEST-103-1 | Screen glare | Face on screen | screen_glare_detected = true | Assert |
| TEST-103-2 | Natural highlights | Live face | highlight_softness > 0.6 | Assert |
| TEST-103-3 | Moving highlights | Live face + motion | highlight_motion_consistency > 0.7 | Assert |
| TEST-103-4 | Variable lighting | Low/medium/high | All conditions pass | Multi-condition |

---

### Temporal Analysis Tests

#### TEST-104: Remote PPG Detection

| ID | Description | Input | Expected | Validation |
|----|-------------|-------|----------|------------|
| TEST-104-1 | Good lighting rPPG | Live face, bright | rppg_detected = true | Assert |
| TEST-104-2 | Pulse range | Live face | 40-180 BPM | Range check |
| TEST-104-3 | Photo no rPPG | Static photo | rppg_detected = false | Assert |
| TEST-104-4 | Video no rPPG | Recorded video | Low confidence | Assert |
| TEST-104-5 | Low light graceful | Live, dim | No false reject | Assert |

#### TEST-105: Micro-Movement Detection

| ID | Description | Input | Expected | Validation |
|----|-------------|-------|----------|------------|
| TEST-105-1 | Natural micro-movement | Live face | micro_movement_magnitude > 0.1 | Assert |
| TEST-105-2 | Saccade detection | Live face | eye_movement_detected = true | Assert |
| TEST-105-3 | Static image | Photo | micro_movement_magnitude < 0.02 | Assert |
| TEST-105-4 | Video playback | Recorded video | movement_naturalness < 0.5 | Assert |

---

### Challenge-Response Tests

#### TEST-106: Blink Challenge

| ID | Description | Input | Expected | Validation |
|----|-------------|-------|----------|------------|
| TEST-106-1 | Natural blink | Live user blinks | completed = true | Assert |
| TEST-106-2 | Blink timing | Live blink | 100-400ms duration | Range |
| TEST-106-3 | No blink timeout | Photo | completed = false | Assert |
| TEST-106-4 | Video blink | Pre-recorded | motion_naturalness < 0.5 | Assert |

#### TEST-107: Head Pose Challenge

| ID | Description | Input | Expected | Validation |
|----|-------------|-------|----------|------------|
| TEST-107-1 | Turn left | Live user turns | completed = true | Assert |
| TEST-107-2 | Turn right | Live user turns | completed = true | Assert |
| TEST-107-3 | Natural motion | Live user | motion_naturalness > 0.7 | Assert |
| TEST-107-4 | Photo attack | Static photo | completed = false | Assert |
| TEST-107-5 | Video attack | Pre-recorded turn | motion_naturalness < 0.6 | Assert |

---

### Combined Face Liveness Tests

#### TEST-108: End-to-End Face Liveness

| ID | Description | Input | Expected | Validation |
|----|-------------|-------|----------|------------|
| TEST-108-1 | Live face accepted | Real user | is_live = true | Assert |
| TEST-108-2 | Print rejected | Printed photo | is_live = false | Assert |
| TEST-108-3 | Screen rejected | Face on screen | is_live = false | Assert |
| TEST-108-4 | Paper mask rejected | Cutout mask | is_live = false | Assert |

#### TEST-109: Face Liveness Performance

| ID | Description | Input | Expected | Validation |
|----|-------------|-------|----------|------------|
| TEST-109-1 | Live detection rate | 1000 live users | ≥ 96% | Statistical |
| TEST-109-2 | Print attack rate | 500 print attacks | ≥ 97% detected | Statistical |
| TEST-109-3 | Screen attack rate | 500 screen attacks | ≥ 95% detected | Statistical |
| TEST-109-4 | FAR | Mixed attacks | < 3% | Statistical |

---

### Palm Liveness Tests

#### TEST-110: Palm Texture Analysis

| ID | Description | Input | Expected | Validation |
|----|-------------|-------|----------|------------|
| TEST-110-1 | Live palm texture | Real palm | skin_texture_score > 0.6 | Assert |
| TEST-110-2 | Printed palm | Photo | print_detection_score > 0.5 | Assert |
| TEST-110-3 | Silicone palm | Fake palm | artificial_material_score > 0.5 | Assert |

#### TEST-111: Palm Color Dynamics

| ID | Description | Input | Expected | Validation |
|----|-------------|-------|----------|------------|
| TEST-111-1 | Live color variation | Real palm | temporal_color_variation > 0.1 | Assert |
| TEST-111-2 | Palm rPPG | Real palm, good light | rppg_detected = true | Assert |
| TEST-111-3 | Photo no dynamics | Printed palm | temporal_color_variation < 0.02 | Assert |

#### TEST-112: Palm Specular Response

| ID | Description | Input | Expected | Validation |
|----|-------------|-------|----------|------------|
| TEST-112-1 | Skin highlight | Real palm | highlight_softness > 0.6 | Assert |
| TEST-112-2 | Paper highlight | Printed palm | highlight_softness < 0.3 | Assert |
| TEST-112-3 | Material classification | Various inputs | accuracy ≥ 92% | Statistical |

#### TEST-113: Palm Motion Analysis

| ID | Description | Input | Expected | Validation |
|----|-------------|-------|----------|------------|
| TEST-113-1 | Tremor detection | Live palm | tremor_detected = true | Assert |
| TEST-113-2 | Tremor frequency | Live palm | 8-12 Hz | Range |
| TEST-113-3 | Photo no tremor | Printed palm | tremor_detected = false | Assert |
| TEST-113-4 | Flexibility test | Live palm flex | flexibility_score > 0.7 | Assert |

#### TEST-114: Combined Palm Liveness

| ID | Description | Input | Expected | Validation |
|----|-------------|-------|----------|------------|
| TEST-114-1 | Live palm accepted | Real palm | is_live = true | Assert |
| TEST-114-2 | Print rejected | Printed palm | is_live = false | Assert |
| TEST-114-3 | Silicone rejected | Fake palm | is_live = false | Assert |
| TEST-114-4 | Combined accuracy | Test corpus | ≥ 95% | Statistical |

---

### Depth Augmentation Tests

#### TEST-115: Depth-Augmented Liveness

| ID | Description | Input | Expected | Validation |
|----|-------------|-------|----------|------------|
| TEST-115-1 | Flat surface detection | Photo with depth | flat_surface_detected = true | Assert |
| TEST-115-2 | 3D face geometry | Live face + depth | geometry_score > 0.8 | Assert |
| TEST-115-3 | Improved accuracy | RGB + depth | +15% improvement | Statistical |
| TEST-115-4 | Screen attack | Screen + depth | flat_surface_detected = true | Assert |

---

## Observability

### OBS-060: RGB Liveness Metrics

**Metrics:**

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `sable_rgb_liveness_result_total` | Counter | biometric_type, result, pipeline | Liveness outcomes |
| `sable_rgb_liveness_duration_ms` | Histogram | biometric_type, pipeline | Total assessment time |
| `sable_rgb_passive_score` | Histogram | biometric_type | Passive score distribution |
| `sable_rgb_challenge_issued_total` | Counter | challenge_type | Active challenges issued |
| `sable_rgb_challenge_result_total` | Counter | challenge_type, result | Challenge outcomes |
| `sable_rgb_attack_detected_total` | Counter | biometric_type, attack_type | Detected attack types |
| `sable_rgb_texture_score` | Histogram | biometric_type, signal_type | Texture signal distribution |
| `sable_rgb_temporal_score` | Histogram | biometric_type, signal_type | Temporal signal distribution |
| `sable_rppg_detection_rate` | Gauge | biometric_type | rPPG success rate |
| `sable_depth_available_total` | Counter | result | Depth sensor availability |

**Logs:**

| Event | Level | Fields |
|-------|-------|--------|
| liveness_assessment_started | INFO | biometric_type, pipeline, session_id |
| passive_assessment_complete | DEBUG | biometric_type, passive_score, signals_summary |
| challenge_issued | INFO | challenge_type, reason |
| challenge_completed | INFO | challenge_type, result, duration_ms |
| liveness_accepted | INFO | biometric_type, confidence, pipeline |
| liveness_rejected | WARN | biometric_type, confidence, attack_type, pipeline |
| attack_detected | WARN | biometric_type, attack_type, confidence |
| rppg_detection_failed | DEBUG | biometric_type, reason |
| depth_augmentation_applied | DEBUG | improvement_delta |

**Alerts:**

| Alert | Condition | Severity |
|-------|-----------|----------|
| High attack rate | attack_detected_total > 10/min | Warning |
| Low liveness rate | accepted_rate < 90% over 1h | Warning |
| Challenge timeout spike | challenge_timeout_rate > 20% | Warning |

**Traces:** REQ-060 through REQ-071

---

## Security Considerations

### SEC-060: RGB Liveness Limitations

RGB-based liveness has inherent limitations compared to NIR or depth-based methods:

| Attack Type | NIR Detection | RGB Detection | Mitigation |
|-------------|---------------|---------------|------------|
| Print attack | 99%+ | 97%+ | Texture + motion analysis |
| Screen replay | 99%+ | 95%+ | Moiré + reflection + temporal |
| 3D mask | 95%+ | 70-85% | Challenge-response + texture |
| Deepfake injection | N/A | 60-80% | Camera API integrity checks |

**Recommendations:**
1. Use depth when available (significant improvement)
2. Implement camera stream integrity checks (detect injection)
3. Consider risk-based authentication (high-value = stricter)
4. Combine with other factors for high-security scenarios

### SEC-061: Anti-Spoofing Best Practices

1. **Randomized challenges:** Never use predictable challenge sequences
2. **Temporal analysis:** Always require multi-frame analysis
3. **Score fusion:** Never rely on single signal
4. **Threshold tuning:** Adjust thresholds based on deployment risk profile
5. **Continuous improvement:** Update models with new attack samples

### SEC-062: Privacy Preservation

All RGB liveness checks maintain privacy guarantees:
- No images stored beyond immediate analysis
- No embedding extraction until liveness confirmed
- Aggregate metrics only (no individual tracking)
- Liveness signals discarded after decision

---

## Implementation Plan

### Phase RGB-1: Core Framework (Week 1-2)

1. Implement `CameraCapabilities` detection
2. Implement `LivenessPipeline` selection
3. Define signal structures and thresholds
4. Create test harnesses for spoofing scenarios
5. Unit tests for capability detection

### Phase RGB-2: Face Texture Analysis (Week 3-4)

1. Implement moiré pattern detection (FFT-based)
2. Implement print artifact detection
3. Implement skin texture analysis (LBP)
4. Train/integrate texture CNN classifier
5. Integration tests with spoof database

### Phase RGB-3: Face Temporal Analysis (Week 5-6)

1. Implement reflection analysis
2. Implement rPPG extraction pipeline
3. Implement micro-movement detection
4. Implement micro-saccade tracking
5. Temporal analysis tests

### Phase RGB-4: Active Challenges (Week 7-8)

1. Implement blink detection
2. Implement head pose challenge
3. Implement expression challenges
4. Implement challenge UI guidance
5. Challenge response tests

### Phase RGB-5: Palm RGB Liveness (Week 9-10)

1. Implement palm texture analysis
2. Implement palm color dynamics
3. Implement palm specular analysis
4. Implement palm motion/tremor detection
5. Palm liveness integration tests

### Phase RGB-6: Fusion & Integration (Week 11-12)

1. Implement score fusion logic
2. Integrate with SPEC-001 (fallback to NIR when available)
3. Integrate with SPEC-002 (embedding pipeline)
4. Add depth augmentation (when available)
5. End-to-end testing on device matrix

### Phase RGB-7: Validation & Tuning (Week 13-14)

1. Collect attack corpus (prints, screens, masks)
2. Tune thresholds for target FAR/FRR
3. Device compatibility testing
4. Performance optimization
5. Security review

---

## References

1. Face Anti-Spoofing Using Patch and Depth-Based CNNs - Atoum et al. (2017)
2. Learning Deep Models for Face Anti-Spoofing - Liu et al. (2018)
3. Remote Photoplethysmography: Evaluation of Contactless Heart Rate Measurement - Verkruysse et al. (2008)
4. Face Liveness Detection from a Single Image via Moiré Pattern Analysis - Patel et al. (2015)
5. Deep Learning for Face Anti-Spoofing: A Survey - Yu et al. (2022)
6. ISO/IEC 30107-3: Presentation Attack Detection Methods

---

**Document Version:** 1.0.0
**Last Updated:** 2026-02-03
**Author:** SABLE Development Team
**Review Status:** Draft - Pending security review
