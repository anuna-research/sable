# SPEC-002: Generalized Biometric Embeddings

## Overview

This specification defines a pluggable architecture for biometric feature extraction
in SABLE, enabling support for multiple embedding models, modalities, and providers.
The system abstracts the embedding generation process behind a unified trait interface,
allowing the ZK proof circuit to work with any conforming embedding without modification
to the core cryptographic layer.

**Motivation:**

- Support emerging neural network embedding models (e.g., transformer-based)
- Enable multi-modal biometrics beyond palm (face, voice, iris, behavioral)
- Allow enterprise customers to bring their own embedding models
- Future-proof against advances in biometric representation learning
- Enable A/B testing of embedding models without protocol changes

---

## User Profiles

### User: Biometric System Integrator

**Role:** Enterprise developer integrating SABLE into existing identity infrastructure

**Goals:**
- Use organization's existing biometric embedding model with SABLE
- Maintain compatibility with enrolled biometric templates
- Minimize re-enrollment when upgrading embedding models
- Achieve consistent security guarantees across different models

**Constraints:**
- Existing enrollment database uses proprietary 256-dim embeddings
- Cannot share embedding model weights (IP protection)
- Must support both on-device and server-side embedding extraction
- Compliance requirement for model versioning and audit trail

**Daily Workflow:**
1. Receives new embedding model from ML team
2. Registers model with SABLE embedding registry
3. Validates model meets security requirements (dimension, distance metric)
4. Deploys to staging for A/B testing against current model
5. Monitors FAR/FRR metrics during canary rollout
6. Promotes to production with gradual traffic shift

---

### User: ML Research Engineer

**Role:** Develops and improves biometric embedding models

**Goals:**
- Easily benchmark new embedding architectures in SABLE
- Compare ZK proof performance across different dimensions
- Test embedding robustness against presentation attacks
- Iterate quickly without modifying core SABLE code

**Constraints:**
- Models vary from 128-dim to 2048-dim
- Some models require GPU inference
- Need to test both ONNX and TensorFlow Lite formats
- Must preserve privacy during benchmarking (no raw biometric export)

---

### User: End User (Multi-Modal Authentication)

**Role:** Authenticates using multiple biometric modalities

**Goals:**
- Seamless authentication regardless of which modality is used
- Consistent experience across palm, face, and voice
- Fallback options when primary modality unavailable
- Single enrollment covers all modalities

**Constraints:**
- Different devices have different sensors
- Environmental conditions affect modality reliability
- Privacy preference may exclude certain modalities

---

### User: Face Biometric User

**Role:** End user authenticating via front-facing camera

**Goals:**
- Quick authentication using device camera (< 2 seconds)
- Works in varied lighting conditions
- No special hardware required beyond standard smartphone
- Privacy preserved (face data never leaves device)

**Constraints:**
- Glasses, masks, facial hair may affect recognition
- Low-light environments degrade quality
- Camera resolution varies across devices (2MP to 12MP+)
- Presentation attack concerns (photos, videos, masks)

**Daily Workflow:**
1. Opens app requiring authentication
2. Points front camera at face
3. App detects and frames face automatically
4. Single capture extracts embedding
5. ZK proof generated and verified
6. Access granted

---

## Happy Path: Face Biometric Enrollment

**Preconditions:**
- Device has front-facing camera (minimum 2MP)
- MediaPipe/ML Kit face detection available
- MobileFaceNet or equivalent model loaded

**Steps:**

1. User initiates face enrollment
   → App requests camera permission
   → Face detection model loads

2. User positions face in camera frame
   → Real-time face detection provides guidance
   → "Move closer", "Center your face", "Better lighting needed"

3. App captures multiple angles (optional, improves robustness)
   → Frontal capture (primary)
   → Slight left/right turn (±15°) for 3D understanding

4. Face preprocessing pipeline executes
   → Face detection extracts bounding box
   → Landmark detection (68 or 468 points)
   → Face alignment to canonical pose (112×112 or 160×160)
   → Quality assessment (blur, lighting, occlusion)

5. Embedding extraction via TFLite model
   → MobileFaceNet produces 128-dim embedding
   → Embedding normalized to unit vector (L2 norm = 1)

6. SABLE commitment generated
   → Pedersen(Poseidon(embedding), salt)
   → Salt encrypted with platform biometric key (SPEC-003)

7. Enrollment stored
   → Commitment (public), encrypted salt, model ID, version

**Postconditions:**
- Face embedding committed, original data discarded
- User can authenticate with face
- Multiple faces can be enrolled (different lighting, with/without glasses)

**Failure Modes:**
- F1: No face detected → Provide positioning guidance
- F2: Multiple faces → "Only one face allowed"
- F3: Quality too low → "Better lighting needed" / "Hold steady"
- F4: Occlusion detected → "Remove mask/sunglasses"
- F5: Liveness check failed → "Please blink" or reject

---

## Happy Path: Face Biometric Authentication

**Preconditions:**
- User has enrolled face biometric
- Ambient lighting sufficient (> 50 lux)

**Steps:**

1. User initiates authentication
   → Camera activates, face detection starts

2. Face detected and captured
   → Single frame sufficient for authentication
   → Liveness check (blink detection, head movement, or passive analysis)

3. Face aligned and embedding extracted
   → Same preprocessing as enrollment
   → MobileFaceNet inference (~18ms)

4. ZK proof generated
   → Proves embedding matches commitment within threshold
   → Proves quality above minimum
   → Proves liveness check passed

5. Proof verified
   → Server/relying party validates proof
   → Authentication succeeds

**Postconditions:**
- User authenticated
- No face image or embedding transmitted
- Only 192-byte proof sent to verifier

---

## Happy Path: Custom Embedding Model Registration

**Preconditions:**
- Organization has trained custom 384-dim face embedding model
- Model exported to ONNX format
- SABLE SDK installed with embedding extension

**Steps:**

1. Integrator creates embedding adapter implementing `BiometricEmbedding` trait
   → Specifies dimension (384), distance metric (cosine), model ID

2. Integrator registers model with SABLE registry
   → System validates model interface compliance
   → System generates model-specific proving parameters (if needed)

3. Integrator configures enrollment pipeline to use new model
   → New enrollments create 384-dim commitments
   → Existing enrollments remain valid with original model

4. User enrolls with new model
   → Face image captured → ONNX inference → 384-dim embedding
   → Embedding committed via Pedersen commitment
   → Model ID stored with commitment for verification routing

5. User authenticates
   → System detects model ID from stored commitment
   → Routes to appropriate embedding extractor
   → Generates ZK proof with model-specific circuit
   → Verification succeeds

**Postconditions:**
- Custom model fully integrated with ZK verification
- No modification to SABLE core required
- Model versioning enables future upgrades

**Failure Modes:**
- F1: Model dimension exceeds circuit maximum → Reject registration with guidance
- F2: Model produces non-normalized embeddings → Warn, auto-normalize, log
- F3: Model inference timeout → Fall back to cached embedding or retry
- F4: Model ID mismatch at verification → Reject with "enrollment required" error

---

## Happy Path: Multi-Modal Enrollment and Authentication

**Preconditions:**
- User has device with palm scanner, front camera, and microphone
- Organization configured for palm + face + voice multi-modal

**Steps:**

1. User initiates enrollment
   → System detects available sensors and modalities

2. User enrolls palm biometric
   → Palm image → 512-dim embedding (PalmVeinExtractor)
   → Commitment C_palm generated

3. User enrolls face biometric
   → Face image → 768-dim embedding (FaceNetExtractor)
   → Commitment C_face generated

4. User enrolls voice biometric
   → Voice sample → 256-dim embedding (VoicePrintExtractor)
   → Commitment C_voice generated

5. System creates unified identity binding
   → Links {C_palm, C_face, C_voice} to single identity
   → Stores modality preferences and fallback order

6. User authenticates (palm unavailable due to gloves)
   → System detects palm sensor blocked
   → Falls back to face modality
   → Face embedding extracted, proof generated against C_face
   → Authentication succeeds

**Postconditions:**
- User enrolled with 3 modalities
- Any single modality sufficient for authentication
- Modality selection transparent to user

---

## Requirements

### REQ-030: Biometric Embedding Trait Interface

The system SHALL define a `BiometricEmbedding` trait that abstracts embedding
extraction FOR all biometric modalities WITH the following interface.

**Trait Definition:**

```rust
pub trait BiometricEmbedding: Send + Sync {
    /// Returns the fixed dimensionality of embeddings produced by this model.
    /// Must be constant for a given model instance.
    fn dimension(&self) -> usize;

    /// Returns a unique identifier for this model (e.g., "palm-vein-v2", "facenet-512").
    /// Used for routing verification to correct circuit parameters.
    fn model_id(&self) -> &str;

    /// Returns the model version for audit and compatibility tracking.
    fn model_version(&self) -> Version;

    /// Returns the recommended distance metric for comparing embeddings.
    fn distance_metric(&self) -> DistanceMetric;

    /// Returns the modality this embedding model supports.
    fn modality(&self) -> BiometricModality;

    /// Extracts an embedding from the given biometric input.
    /// Returns normalized embedding vector with confidence score.
    fn extract(&self, input: &BiometricInput) -> Result<Embedding>;

    /// Validates that input is suitable for this extractor.
    fn validate_input(&self, input: &BiometricInput) -> Result<()>;

    /// Returns extraction performance characteristics for capacity planning.
    fn performance_hints(&self) -> PerformanceHints;
}
```

**Acceptance Criteria:**
- AC-1: Trait is object-safe (supports `dyn BiometricEmbedding`)
- AC-2: All methods have default timeout of 5 seconds
- AC-3: Trait requires `Send + Sync` for concurrent extraction
- AC-4: Model ID format follows `{modality}-{algorithm}-v{version}` convention
- AC-5: Dimension must be in range [64, 2048]

**Trace:**
- TEST-040, TEST-041
- CON-030
- ADR-005

---

### REQ-031: Embedding Vector Normalization

The system SHALL normalize all embedding vectors to unit length (L2 norm = 1.0)
BEFORE commitment generation FOR consistent distance calculations WITH
normalization variance < 1e-10.

**Normalization Specification:**

| Property | Requirement |
|----------|-------------|
| L2 Norm | 1.0 ± 1e-10 |
| Value Range | [-1.0, 1.0] per dimension |
| NaN/Inf Handling | Reject with error |
| Zero Vector | Reject with error |

**Acceptance Criteria:**
- AC-1: All embeddings satisfy ||e||₂ = 1.0 ± 1e-10 after normalization
- AC-2: Normalization is idempotent (normalizing twice = normalizing once)
- AC-3: Non-finite values (NaN, Inf) cause immediate rejection
- AC-4: Zero vectors are rejected before normalization attempt
- AC-5: Original embedding preserved; normalization returns new vector

**Trace:**
- TEST-042, TEST-043
- CON-031

---

### REQ-032: Supported Distance Metrics

The system SHALL support the following distance metrics FOR embedding comparison
WITH constant-time implementations FOR each metric.

**Distance Metrics:**

| Metric | Formula | Use Case | Circuit Cost |
|--------|---------|----------|--------------|
| Euclidean | √(Σ(aᵢ - bᵢ)²) | Traditional CV embeddings | ~2n constraints |
| Cosine | 1 - (a·b)/(||a|| ||b||) | Neural embeddings | ~3n constraints |
| Squared Euclidean | Σ(aᵢ - bᵢ)² | Circuit optimization | ~n constraints |

**Acceptance Criteria:**
- AC-1: All three metrics implemented with constant-time guarantees
- AC-2: Metric selection determined by `BiometricEmbedding::distance_metric()`
- AC-3: Circuit automatically selects optimal constraint structure per metric
- AC-4: Cosine distance assumes pre-normalized vectors (L2 norm = 1)
- AC-5: Timing variance < 1μs across all input values

**Trace:**
- TEST-044, TEST-045, TEST-046
- CON-032

---

### REQ-033: Embedding Model Registry

The system SHALL maintain a registry of available embedding models FOR dynamic
model selection WITH runtime registration and validation.

**Registry Operations:**

| Operation | Description | Complexity |
|-----------|-------------|------------|
| `register(model)` | Add new model to registry | O(1) |
| `get(model_id)` | Retrieve model by ID | O(1) |
| `list(modality)` | List models for modality | O(n) |
| `validate(model)` | Check model compliance | O(dim) |
| `unregister(model_id)` | Remove model (soft delete) | O(1) |

**Registry Metadata:**

```rust
pub struct ModelRegistration {
    pub model_id: String,
    pub model_version: Version,
    pub modality: BiometricModality,
    pub dimension: usize,
    pub distance_metric: DistanceMetric,
    pub registered_at: Timestamp,
    pub registered_by: String,
    pub status: ModelStatus,  // Active, Deprecated, Disabled
    pub proving_key_hash: Option<[u8; 32]>,  // If model-specific setup required
}
```

**Acceptance Criteria:**
- AC-1: Registry supports concurrent read access (RwLock)
- AC-2: Model registration validates trait compliance before acceptance
- AC-3: Duplicate model_id registration returns error
- AC-4: Soft delete preserves audit trail; hard delete requires admin
- AC-5: Registry persists across process restarts (optional file backing)

**Trace:**
- TEST-047, TEST-048
- CON-033
- OBS-030

---

### REQ-034: Parameterized ZK Circuit

The system SHALL support ZK circuits parameterized by embedding dimension
FOR different model configurations WITH the following dimension tiers.

**Dimension Tiers:**

| Tier | Dimensions | Use Case | Proving Key Size | Proof Time |
|------|------------|----------|------------------|------------|
| Small | 64, 128 | Behavioral biometrics | ~2MB | ~200ms |
| Medium | 256, 384 | Voice, lightweight face | ~4MB | ~400ms |
| Standard | 512 | Palm vein (default) | ~8MB | ~850ms |
| Large | 768, 1024 | Modern neural embeddings | ~16MB | ~1200ms |
| XLarge | 1536, 2048 | Transformer embeddings | ~32MB | ~2000ms |

**Circuit Structure:**

```rust
pub struct ParameterizedBiometricCircuit<const DIM: usize> {
    // Private inputs
    pub features: Option<[Fr; DIM]>,
    pub reference_features: Option<[Fr; DIM]>,
    pub salt: Option<Salt>,
    pub reference_salt: Option<Salt>,

    // Public inputs (dimension-independent)
    pub commitment: Option<Commitment>,
    pub reference_commitment: Option<Commitment>,
    pub distance_threshold: Fr,
    pub distance_metric: DistanceMetric,

    // Liveness (optional, from SPEC-001)
    pub liveness_witness: Option<LivenessWitness>,
}
```

**Acceptance Criteria:**
- AC-1: Circuits instantiable for all tier dimensions via const generics
- AC-2: Proving key generated once per dimension tier (not per model)
- AC-3: Single verifying key works for all models of same dimension
- AC-4: Proof size constant (192 bytes) regardless of dimension
- AC-5: Dimension mismatch between enrollment and verification detected at proof time

**Trace:**
- TEST-049, TEST-050, TEST-051
- CON-034
- ADR-005

---

### REQ-035: Biometric Input Abstraction

The system SHALL define a polymorphic input type supporting multiple biometric
modalities FOR unified extraction interface WITH type-safe modality handling.

**Input Types:**

```rust
pub enum BiometricInput {
    /// Palm image (grayscale or NIR)
    Palm(PalmImage),

    /// Face image (RGB)
    Face(FaceImage),

    /// Voice audio samples
    Voice(VoiceSamples),

    /// Iris image (NIR)
    Iris(IrisImage),

    /// Fingerprint image
    Fingerprint(FingerprintImage),

    /// Behavioral pattern (keystroke, gait, etc.)
    Behavioral(BehavioralSample),

    /// Pre-computed embedding (for testing, migration)
    PreComputed {
        embedding: Vec<f64>,
        model_id: String,
    },
}
```

**Acceptance Criteria:**
- AC-1: Each variant contains modality-specific metadata
- AC-2: `BiometricInput::modality()` returns corresponding `BiometricModality`
- AC-3: Type mismatch between input and extractor returns clear error
- AC-4: PreComputed variant allows embedding injection for testing
- AC-5: All variants implement `Zeroize` for secure cleanup

**Trace:**
- TEST-052, TEST-053
- CON-035

---

### REQ-036: Embedding Output Structure

The system SHALL define a standardized embedding output structure FOR all
extractors WITH metadata sufficient for verification routing.

**Embedding Structure:**

```rust
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Embedding {
    /// Normalized embedding values
    pub values: Vec<f64>,

    /// Embedding dimensionality (redundant but useful for validation)
    pub dimension: usize,

    /// Model that produced this embedding
    pub model_id: String,

    /// Model version for compatibility tracking
    pub model_version: Version,

    /// Extraction confidence score [0.0, 1.0]
    pub confidence: f64,

    /// Extraction timestamp
    pub extracted_at: Timestamp,

    /// Quality metrics from extraction
    pub quality: EmbeddingQuality,
}

pub struct EmbeddingQuality {
    /// Input quality score [0.0, 1.0]
    pub input_quality: f64,

    /// Model-specific quality indicators
    pub model_quality_scores: HashMap<String, f64>,

    /// Estimated false accept rate at this quality
    pub estimated_far: f64,
}
```

**Acceptance Criteria:**
- AC-1: Embedding values always normalized (L2 = 1.0)
- AC-2: dimension field matches values.len()
- AC-3: model_id matches producing extractor's model_id()
- AC-4: confidence in [0.0, 1.0] range
- AC-5: Entire struct zeroized on drop

**Trace:**
- TEST-054, TEST-055
- CON-036

---

### REQ-037: Model Version Compatibility

The system SHALL enforce version compatibility between enrolled embeddings and
verification embeddings FOR preventing cross-version verification errors WITH
semantic versioning rules.

**Compatibility Rules:**

| Enrolled Version | Verification Version | Compatible | Reason |
|------------------|---------------------|------------|--------|
| 1.0.0 | 1.0.0 | ✓ | Exact match |
| 1.0.0 | 1.0.1 | ✓ | Patch compatible |
| 1.0.0 | 1.1.0 | ✓ | Minor compatible (backward) |
| 1.0.0 | 2.0.0 | ✗ | Major incompatible |
| 1.2.0 | 1.1.0 | ✗ | Minor incompatible (forward) |

**Version Encoding:**

```rust
pub struct Version {
    pub major: u16,  // Breaking changes
    pub minor: u16,  // Backward-compatible additions
    pub patch: u16,  // Bug fixes, no embedding change
}

impl Version {
    pub fn is_compatible_with(&self, other: &Version) -> bool {
        self.major == other.major && self.minor <= other.minor
    }
}
```

**Acceptance Criteria:**
- AC-1: Version stored with commitment at enrollment
- AC-2: Version checked before proof generation
- AC-3: Incompatible version returns clear "re-enrollment required" error
- AC-4: Version compatibility logged for audit
- AC-5: Deprecation warnings issued for old minor versions

**Trace:**
- TEST-056, TEST-057
- CON-037
- OBS-031

---

### REQ-038: Built-in Embedding Implementations

The system SHALL provide built-in implementations FOR common biometric modalities
WITH the following extractors available by default.

**Built-in Extractors:**

| Extractor | Modality | Dimension | Algorithm | Status |
|-----------|----------|-----------|-----------|--------|
| `PalmVeinExtractor` | Palm | 512 | Gabor + CNN hybrid | Stable |
| `PalmPrintExtractor` | Palm | 256 | Ridge pattern analysis | Stable |
| `FusedPalmExtractor` | Palm | 512 | 60% vein + 40% print | Stable |
| `MobileFaceNetExtractor` | Face | 128 | MobileFaceNet TFLite | Stable |
| `FaceNetExtractor` | Face | 512 | FaceNet TFLite | Beta |
| `ArcFaceExtractor` | Face | 512 | ArcFace-MobileNet TFLite | Beta |
| `OnnxEmbedding` | Any | Configurable | ONNX Runtime inference | Stable |
| `TfLiteEmbedding` | Any | Configurable | TensorFlow Lite inference | Beta |
| `MockEmbedding` | Any | Configurable | Testing/benchmarking | Test only |

**Face Extractor Details:**

| Model | Size | Inference | Input Size | Accuracy (LFW) |
|-------|------|-----------|------------|----------------|
| MobileFaceNet | 4MB | 18ms | 112×112 | 99.55% |
| FaceNet | 95MB | 200ms | 160×160 | 99.63% |
| ArcFace-MobileNet | 24MB | 45ms | 112×112 | 99.50% |

**Acceptance Criteria:**
- AC-1: All built-in extractors implement `BiometricEmbedding` trait
- AC-2: Built-in extractors registered automatically at startup
- AC-3: OnnxEmbedding supports models from ONNX Model Zoo
- AC-4: MockEmbedding produces deterministic output for testing
- AC-5: Each extractor has comprehensive documentation
- AC-6: Face extractors include integrated face detection
- AC-7: Face extractors bundle TFLite model files

**Trace:**
- TEST-058, TEST-059, TEST-060, TEST-072, TEST-073, TEST-074
- CON-038, CON-042

---

### REQ-039: ONNX Model Integration

The system SHALL support ONNX-format neural network models FOR embedding extraction
WITH the following runtime requirements.

**ONNX Requirements:**

| Requirement | Specification |
|-------------|---------------|
| ONNX Version | ≥ 1.12 |
| Opset Version | 13-18 |
| Input Shape | [1, C, H, W] or [1, N] |
| Output Shape | [1, DIM] |
| Data Type | float32 |
| Execution Provider | CPU (default), CoreML (iOS), NNAPI (Android) |

**OnnxEmbedding Configuration:**

```rust
pub struct OnnxEmbeddingConfig {
    /// Path to .onnx model file
    pub model_path: PathBuf,

    /// Expected output dimension
    pub dimension: usize,

    /// Input preprocessing
    pub preprocess: PreprocessConfig,

    /// Execution provider preference
    pub execution_provider: ExecutionProvider,

    /// Inference timeout
    pub timeout: Duration,

    /// Model ID override (default: derived from filename)
    pub model_id: Option<String>,
}
```

**Acceptance Criteria:**
- AC-1: ONNX models loaded and validated at registration time
- AC-2: Input/output shape mismatch detected before inference
- AC-3: Inference timeout enforced (default 5s)
- AC-4: GPU execution provider used when available
- AC-5: Model file integrity verified via hash

**Trace:**
- TEST-061, TEST-062, TEST-063
- CON-039

---

### REQ-040: Face Detection Integration

The system SHALL integrate with on-device face detection frameworks FOR locating
faces in camera frames WITH support for MediaPipe, ML Kit, and Vision Framework.

**Supported Face Detection Backends:**

| Backend | Platform | Landmarks | Performance | Notes |
|---------|----------|-----------|-------------|-------|
| MediaPipe Face Detector | Android, iOS | 6 key points | ~5ms | Recommended |
| MediaPipe Face Mesh | Android, iOS | 468 3D points | ~15ms | For alignment |
| Google ML Kit | Android | 133 contour points | ~10ms | Play Services req. |
| Apple Vision | iOS | 76 landmarks | ~8ms | Native, no deps |

**Face Detection Output:**

```rust
pub struct FaceDetectionResult {
    /// Bounding box in image coordinates
    pub bounding_box: Rectangle,

    /// Detection confidence [0.0, 1.0]
    pub confidence: f32,

    /// Facial landmarks for alignment
    pub landmarks: FaceLandmarks,

    /// Head pose estimation (if available)
    pub head_pose: Option<HeadPose>,

    /// Face ID for tracking across frames
    pub tracking_id: Option<u32>,
}

pub struct FaceLandmarks {
    /// Left eye center
    pub left_eye: Point2D,
    /// Right eye center
    pub right_eye: Point2D,
    /// Nose tip
    pub nose_tip: Point2D,
    /// Mouth center
    pub mouth_center: Point2D,
    /// Left ear tragion (optional)
    pub left_ear: Option<Point2D>,
    /// Right ear tragion (optional)
    pub right_ear: Option<Point2D>,
    /// Extended landmarks (68, 133, or 468 points)
    pub extended: Option<Vec<Point2D>>,
}

pub struct HeadPose {
    /// Rotation around vertical axis (looking left/right)
    pub yaw: f32,
    /// Rotation around horizontal axis (looking up/down)
    pub pitch: f32,
    /// Rotation around depth axis (tilting head)
    pub roll: f32,
}
```

**Acceptance Criteria:**
- AC-1: Face detected within 20ms on mobile device
- AC-2: Minimum face size 100×100 pixels for detection
- AC-3: Landmarks accurate to ±3 pixels at 640×480 resolution
- AC-4: Works with partial occlusion (up to 30% of face)
- AC-5: Graceful fallback if preferred backend unavailable

**Trace:**
- TEST-068, TEST-069
- CON-040

---

### REQ-041: Face Alignment and Preprocessing

The system SHALL align detected faces to a canonical pose FOR consistent embedding
extraction WITH the following preprocessing pipeline.

**Alignment Pipeline:**

```
┌─────────────────────────────────────────────────────────────┐
│                  Face Preprocessing Pipeline                 │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  1. Detect Face                                              │
│     └── Bounding box + landmarks                            │
│                                                              │
│  2. Estimate Affine Transform                                │
│     └── Map detected landmarks to canonical positions       │
│     └── Canonical: eyes horizontal, nose centered           │
│                                                              │
│  3. Apply Transform (Warp)                                   │
│     └── Affine warp to target size                          │
│     └── Bilinear interpolation                              │
│                                                              │
│  4. Crop to Model Input Size                                 │
│     ├── MobileFaceNet: 112×112                              │
│     ├── FaceNet: 160×160                                    │
│     └── ArcFace: 112×112                                    │
│                                                              │
│  5. Normalize Pixel Values                                   │
│     ├── Scale to [0, 1] or [-1, 1]                          │
│     └── Apply model-specific mean/std                       │
│                                                              │
│  6. Quality Assessment                                       │
│     ├── Blur detection (Laplacian variance)                 │
│     ├── Lighting assessment (histogram analysis)            │
│     └── Occlusion detection (landmark confidence)           │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

**Canonical Landmark Positions (112×112):**

| Landmark | X | Y | Notes |
|----------|---|---|-------|
| Left eye center | 38.2 | 51.7 | Based on MTCNN alignment |
| Right eye center | 73.5 | 51.5 | |
| Nose tip | 56.0 | 71.7 | |
| Left mouth corner | 41.5 | 92.4 | |
| Right mouth corner | 70.7 | 92.2 | |

**Acceptance Criteria:**
- AC-1: Alignment normalizes inter-ocular distance to fixed value
- AC-2: Output images have consistent eye positions (±2 pixels)
- AC-3: Preprocessing completes within 10ms per face
- AC-4: Handles head rotation up to ±30° yaw
- AC-5: Quality score reflects alignment success

**Trace:**
- TEST-070, TEST-071
- CON-041

---

### REQ-042: Face Embedding Extraction

The system SHALL extract face embeddings using TensorFlow Lite models FOR on-device
face recognition WITH the following model support.

**Supported Face Embedding Models:**

| Model | Dimensions | Model Size | Inference Time | Accuracy (LFW) |
|-------|------------|------------|----------------|----------------|
| MobileFaceNet | 128 | **4MB** | **18ms** | 99.55% |
| MobileFaceNet-Large | 512 | 12MB | 35ms | 99.60% |
| FaceNet (Inception) | 128/512 | 95MB | 200ms | 99.63% |
| ArcFace-MobileNet | 512 | 24MB | 45ms | 99.50% |
| ArcFace-ResNet50 | 512 | 166MB | 350ms | 99.82% |

**Recommended Default: MobileFaceNet (128-dim)**

Rationale:
- Smallest model size (4MB) - suitable for mobile bundling
- Fastest inference (18ms) - real-time capable
- High accuracy (99.55% on LFW) - production quality
- Well-documented and widely deployed

**Embedding Properties:**

```rust
pub struct FaceEmbedding {
    /// Embedding vector (L2 normalized)
    pub values: Vec<f32>,

    /// Embedding dimension (128 or 512)
    pub dimension: usize,

    /// Model that produced this embedding
    pub model_id: String,

    /// Face quality score [0.0, 1.0]
    pub quality: f32,

    /// Alignment confidence
    pub alignment_confidence: f32,

    /// Head pose at capture
    pub head_pose: Option<HeadPose>,
}
```

**Acceptance Criteria:**
- AC-1: MobileFaceNet inference ≤ 30ms on mid-range mobile device
- AC-2: Embeddings L2-normalized (||e||₂ = 1.0 ± 1e-6)
- AC-3: Same face produces embeddings with cosine similarity > 0.6
- AC-4: Different faces produce embeddings with cosine similarity < 0.4
- AC-5: Model hot-swappable without app restart

**Trace:**
- TEST-072, TEST-073, TEST-074
- CON-042

---

### REQ-043: Face Quality Assessment

The system SHALL assess face image quality FOR rejecting low-quality captures
WITH the following quality metrics.

**Quality Metrics:**

| Metric | Range | Threshold | Method |
|--------|-------|-----------|--------|
| Blur Score | [0, 1] | ≥ 0.5 | Laplacian variance |
| Lighting Score | [0, 1] | ≥ 0.4 | Histogram spread |
| Pose Score | [0, 1] | ≥ 0.7 | Head pose deviation |
| Occlusion Score | [0, 1] | ≥ 0.8 | Landmark confidence |
| Resolution Score | [0, 1] | ≥ 0.6 | Face size in pixels |
| **Overall Quality** | [0, 1] | ≥ 0.6 | Weighted average |

**Quality Weights:**

```rust
pub struct FaceQualityWeights {
    pub blur: f32,       // 0.25 - Sharpness is important
    pub lighting: f32,   // 0.20 - Affects feature visibility
    pub pose: f32,       // 0.20 - Frontal faces work best
    pub occlusion: f32,  // 0.20 - Full face needed
    pub resolution: f32, // 0.15 - Minimum detail required
}

impl Default for FaceQualityWeights {
    fn default() -> Self {
        Self {
            blur: 0.25,
            lighting: 0.20,
            pose: 0.20,
            occlusion: 0.20,
            resolution: 0.15,
        }
    }
}
```

**Acceptance Criteria:**
- AC-1: Quality assessment completes within 5ms
- AC-2: Blur detection correctly rejects motion blur
- AC-3: Lighting assessment handles backlit conditions
- AC-4: Occlusion detects masks, sunglasses, hands
- AC-5: Quality score correlates with recognition accuracy (r > 0.7)

**Trace:**
- TEST-075, TEST-076
- CON-043

---

### REQ-044: Face Liveness Detection

The system SHALL detect presentation attacks FOR face biometrics WITH passive
and active liveness methods.

**Liveness Methods:**

| Method | Type | Detection Rate | User Friction | Implementation |
|--------|------|---------------|---------------|----------------|
| Texture Analysis | Passive | 95% | None | Detect print/screen moiré |
| Depth Estimation | Passive | 92% | None | Single-image depth cues |
| Blink Detection | Active | 98% | Low | Prompt user to blink |
| Head Movement | Active | 97% | Medium | Track pose change |
| Challenge-Response | Active | 99% | High | Random expressions |

**Recommended: Passive Texture + Blink Detection**

```rust
pub struct FaceLivenessConfig {
    /// Enable passive texture analysis (always recommended)
    pub passive_texture: bool,

    /// Enable blink detection (low friction)
    pub blink_detection: bool,

    /// Enable head movement tracking (medium friction)
    pub head_movement: bool,

    /// Timeout for active challenges
    pub challenge_timeout: Duration,

    /// Minimum confidence for liveness pass
    pub min_confidence: f32,
}

impl Default for FaceLivenessConfig {
    fn default() -> Self {
        Self {
            passive_texture: true,
            blink_detection: true,
            head_movement: false,
            challenge_timeout: Duration::from_secs(5),
            min_confidence: 0.8,
        }
    }
}

pub struct FaceLivenessResult {
    /// Overall liveness confidence [0.0, 1.0]
    pub confidence: f32,

    /// Whether liveness check passed
    pub is_live: bool,

    /// Individual check results
    pub checks: Vec<LivenessCheck>,

    /// Detected attack type (if any)
    pub attack_type: Option<AttackType>,
}

pub enum AttackType {
    PrintedPhoto,
    ScreenDisplay,
    PaperMask,
    SiliconMask,
    VideoReplay,
    Deepfake,
    Unknown,
}
```

**Acceptance Criteria:**
- AC-1: Printed photo detection ≥ 95% (APCER ≤ 5%)
- AC-2: Screen display detection ≥ 92% (APCER ≤ 8%)
- AC-3: Blink detection accuracy ≥ 98%
- AC-4: False rejection rate ≤ 3% for genuine users
- AC-5: Liveness integrated into ZK proof (signals private)

**Trace:**
- TEST-077, TEST-078, TEST-079
- CON-044
- Integration with SPEC-001 (NIR liveness concepts applied to RGB)

---

### REQ-045: Face Biometric Privacy

The system SHALL protect face biometric data FOR user privacy WITH the following
guarantees.

**Privacy Requirements:**

| Requirement | Implementation |
|-------------|----------------|
| No raw image storage | Images discarded after embedding extraction |
| No cloud processing | All inference on-device |
| No embedding transmission | Only ZK proofs transmitted |
| Template protection | Embeddings stored only as commitments |
| Revocability | User can delete enrollment at any time |

**Data Lifecycle:**

```
┌─────────────────────────────────────────────────────────────┐
│                  Face Data Lifecycle                         │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  [Camera Frame] ──► Exists only in memory (< 100ms)         │
│        │                                                     │
│        ▼                                                     │
│  [Aligned Face] ──► Exists only in memory (< 50ms)          │
│        │                                                     │
│        ▼                                                     │
│  [Embedding] ──► Exists only in memory (< 500ms)            │
│        │           Zeroized after commitment                 │
│        ▼                                                     │
│  [Commitment] ──► Stored permanently (public, safe)         │
│        │                                                     │
│        ▼                                                     │
│  [Salt] ──► Encrypted in secure storage                     │
│              Protected by platform biometric                 │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

**Acceptance Criteria:**
- AC-1: Raw face images never written to disk
- AC-2: Embeddings zeroized within 1 second of use
- AC-3: No network calls during embedding extraction
- AC-4: Memory scanning cannot recover face data after operation
- AC-5: Audit log records operations but not biometric data

**Trace:**
- TEST-080, TEST-081
- CON-045
- OBS-035

---

## Non-Functional Requirements

### NFR-030: Embedding Extraction Latency

Embedding extraction SHALL complete within the following latency bounds
UNDER specified conditions WITH 95th percentile guarantees.

**Latency Targets:**

| Extractor Type | P50 | P95 | P99 | Conditions |
|----------------|-----|-----|-----|------------|
| Traditional CV | 50ms | 100ms | 150ms | CPU, 640x480 input |
| ONNX (CPU) | 100ms | 200ms | 300ms | 4-core CPU, 224x224 input |
| ONNX (GPU) | 20ms | 50ms | 100ms | Mobile GPU, 224x224 input |
| TFLite (NPU) | 15ms | 30ms | 50ms | Neural accelerator |

**Trace:**
- TEST-064
- OBS-032

---

### NFR-031: Memory Footprint per Extractor

Each loaded extractor SHALL consume memory within the following bounds
UNDER mobile device constraints.

**Memory Budgets:**

| Extractor Type | Model Size | Runtime Overhead | Peak Inference |
|----------------|------------|------------------|----------------|
| Traditional CV | N/A | 2MB | 10MB |
| ONNX Small (<10M params) | 40MB | 20MB | 80MB |
| ONNX Medium (10-50M params) | 200MB | 50MB | 300MB |
| ONNX Large (>50M params) | Not recommended for mobile |

**Trace:**
- TEST-065
- OBS-033

---

### NFR-032: Extractor Hot-Swap

The system SHALL support replacing extractors at runtime WITHOUT service restart
WITH zero dropped requests during transition.

**Hot-Swap Requirements:**
- New extractor registered while old extractor active
- Traffic gradually shifted (canary deployment)
- Old extractor deregistered after drain period
- Rollback supported within 5 minutes

**Trace:**
- TEST-066
- OBS-034

---

### NFR-033: Embedding Determinism

Embedding extraction SHALL be deterministic FOR identical inputs WITH
variance < 1e-10 between extractions.

**Determinism Guarantees:**
- Same input + same model = same embedding (within floating-point epsilon)
- Determinism verified by test suite
- Non-deterministic models (with dropout) must disable randomness at inference

**Trace:**
- TEST-067

---

## Architecture Decision Record

### ADR-005: Pluggable Biometric Embedding Architecture

#### Status

Proposed

#### Context

SABLE's current architecture tightly couples biometric feature extraction with
the cryptographic layer. The `extract_vein_features()` and `extract_print_features()`
functions produce fixed-dimension vectors that feed directly into the ZK circuit.

This coupling creates several limitations:

1. **Model Lock-in:** Cannot easily adopt improved embedding models
2. **Dimension Rigidity:** Circuit hardcoded for 512-dimension vectors
3. **Single Modality Focus:** Adding face/voice requires significant changes
4. **Testing Difficulty:** Cannot mock embeddings for integration tests
5. **Enterprise Barriers:** Customers cannot use proprietary models

Industry trends suggest increasing use of:
- Transformer-based embeddings (768-2048 dimensions)
- Multi-modal fusion at embedding level
- Federated learning with model personalization
- On-device neural processing units (NPUs)

#### Decision

We adopt a **pluggable embedding architecture** with the following components:

**1. Trait-Based Abstraction**

All embedding extractors implement the `BiometricEmbedding` trait, enabling:
- Polymorphic dispatch via `dyn BiometricEmbedding`
- Compile-time optimization via generics where beneficial
- Easy testing with mock implementations

**2. Dimension-Tiered Circuits**

Rather than a single circuit, we provide parameterized circuits for common dimensions:

```
BiometricCircuit<64>   → Behavioral
BiometricCircuit<256>  → Voice, lightweight
BiometricCircuit<512>  → Palm (default)
BiometricCircuit<768>  → Face, neural
BiometricCircuit<1024> → Large neural
```

Each tier has its own proving key generated via trusted setup. Verification keys
are small (~1KB) and can be bundled together.

**3. Model Registry**

A runtime registry maps model IDs to extractor instances:

```
model_id → (extractor, dimension, distance_metric, proving_key)
```

This enables:
- Dynamic model registration
- Version-based routing
- Gradual model upgrades
- Multi-model support in single deployment

**4. Commitment Metadata**

Commitments now include model metadata:

```rust
struct EnhancedCommitment {
    commitment: Commitment,        // Pedersen commitment
    model_id: String,             // e.g., "palm-vein-v2"
    model_version: Version,       // e.g., 1.2.0
    dimension: u16,               // e.g., 512
    distance_metric: u8,          // 0=Euclidean, 1=Cosine
}
```

This metadata routes verification to the correct circuit and extractor.

**5. Migration Strategy**

Existing enrollments (without metadata) assume:
- model_id: "palm-vein-v1"
- dimension: 512
- distance_metric: Euclidean

New enrollments include full metadata. Gradual migration via re-enrollment
or parallel enrollment with new models.

#### Alternatives Considered

**Alternative A: Single Flexible Circuit**

Use a single circuit with maximum dimension (2048) and pad smaller embeddings.

*Pros:* Single trusted setup, simpler deployment
*Cons:* Wasted constraints for small embeddings, longer proof times, larger
proving keys for everyone

*Decision:* Rejected due to mobile performance impact

**Alternative B: Dynamic Circuit Compilation**

Compile circuits on-demand for arbitrary dimensions.

*Pros:* Maximum flexibility
*Cons:* Trusted setup per dimension, compilation latency, complexity

*Decision:* Rejected; tier approach provides sufficient flexibility

**Alternative C: Embedding-Agnostic Protocol**

Treat embeddings as opaque blobs, verify only commitment matches.

*Pros:* Complete model independence
*Cons:* Cannot verify distance threshold in ZK, loses core security property

*Decision:* Rejected; distance verification is fundamental to biometric ZK

#### Consequences

**Positive:**

1. **Future-Proof:** New embedding models integrate without core changes
2. **Multi-Modal Ready:** Face, voice, iris supported with same infrastructure
3. **Enterprise Friendly:** Bring-your-own-model enables proprietary algorithms
4. **Testable:** Mock embeddings simplify integration testing
5. **Upgradeable:** Model versions enable gradual migration

**Negative:**

1. **Complexity:** More moving parts than monolithic design
2. **Multiple Proving Keys:** ~5 keys instead of 1 (still manageable)
3. **Routing Logic:** Must correctly map model_id to circuit
4. **Version Management:** Must track compatibility matrices

**Mitigations:**

- Provide sensible defaults (512-dim palm remains default)
- Automate proving key distribution
- Validate routing at registration time
- Clear deprecation policy for old versions

#### Implementation Notes

**Phase 1:** Define traits and interfaces (no circuit changes)
**Phase 2:** Implement model registry and routing
**Phase 3:** Add dimension-tiered circuits
**Phase 4:** ONNX integration
**Phase 5:** Multi-modal support

#### References

1. ONNX Runtime Documentation - https://onnxruntime.ai/docs/
2. TensorFlow Lite Guide - https://www.tensorflow.org/lite/guide
3. FaceNet Paper - Schroff et al. (2015)
4. ArcFace Paper - Deng et al. (2019)

---

## Contract Specifications

### CON-030: BiometricEmbedding Trait

**Interface:** `BiometricEmbedding`

**Location:** `core/src/biometric/embedding.rs`

```rust
/// Core trait for biometric embedding extraction.
///
/// Implementors provide a way to convert raw biometric input into a
/// fixed-dimension embedding vector suitable for ZK commitment and verification.
///
/// # Thread Safety
///
/// Implementations must be `Send + Sync` to support concurrent extraction
/// across multiple authentication requests.
///
/// # Example
///
/// ```rust
/// use sable_core::biometric::embedding::*;
///
/// struct MyCustomExtractor { /* ... */ }
///
/// impl BiometricEmbedding for MyCustomExtractor {
///     fn dimension(&self) -> usize { 384 }
///     fn model_id(&self) -> &str { "my-custom-v1" }
///     // ... implement remaining methods
/// }
/// ```
pub trait BiometricEmbedding: Send + Sync {
    /// Returns the dimensionality of embeddings produced by this model.
    ///
    /// Must be constant for the lifetime of this instance.
    /// Valid range: [64, 2048].
    fn dimension(&self) -> usize;

    /// Returns a unique identifier for this model.
    ///
    /// Format: `{modality}-{algorithm}-v{major}`
    /// Example: "palm-vein-v2", "face-arcface-v1"
    fn model_id(&self) -> &str;

    /// Returns the semantic version of this model.
    fn model_version(&self) -> Version;

    /// Returns the distance metric for comparing embeddings from this model.
    fn distance_metric(&self) -> DistanceMetric;

    /// Returns the biometric modality this extractor handles.
    fn modality(&self) -> BiometricModality;

    /// Extracts an embedding from biometric input.
    ///
    /// # Arguments
    ///
    /// * `input` - Biometric data matching this extractor's modality
    ///
    /// # Returns
    ///
    /// * `Ok(Embedding)` - Normalized embedding with metadata
    /// * `Err(SableError::EmbeddingExtraction)` - On extraction failure
    ///
    /// # Errors
    ///
    /// * Input modality mismatch
    /// * Input quality too low
    /// * Model inference failure
    /// * Timeout exceeded
    fn extract(&self, input: &BiometricInput) -> Result<Embedding>;

    /// Validates input without performing extraction.
    ///
    /// Use for fast-fail before expensive extraction.
    fn validate_input(&self, input: &BiometricInput) -> Result<()>;

    /// Returns performance characteristics for capacity planning.
    fn performance_hints(&self) -> PerformanceHints {
        PerformanceHints::default()
    }

    /// Returns minimum input quality threshold.
    fn min_quality_threshold(&self) -> f64 {
        0.7  // Default from REQ-010
    }
}

/// Performance characteristics for an embedding extractor.
#[derive(Debug, Clone)]
pub struct PerformanceHints {
    /// Expected extraction latency (P50)
    pub expected_latency: Duration,
    /// Peak memory during extraction
    pub peak_memory_bytes: usize,
    /// Whether GPU acceleration is used
    pub uses_gpu: bool,
    /// Whether batching is supported
    pub supports_batching: bool,
    /// Optimal batch size (if batching supported)
    pub optimal_batch_size: usize,
}

impl Default for PerformanceHints {
    fn default() -> Self {
        Self {
            expected_latency: Duration::from_millis(100),
            peak_memory_bytes: 50 * 1024 * 1024,  // 50MB
            uses_gpu: false,
            supports_batching: false,
            optimal_batch_size: 1,
        }
    }
}
```

**Pre-conditions:**
- Extractor initialized with valid model/configuration
- Input matches extractor's modality

**Post-conditions:**
- Embedding is L2-normalized
- Embedding dimension matches `dimension()`
- Embedding includes valid metadata

**Error Model:**
- `SableError::EmbeddingExtraction(String)` - Generic extraction error
- `SableError::ModalityMismatch` - Input/extractor modality mismatch
- `SableError::QualityTooLow` - Input below quality threshold
- `SableError::Timeout` - Extraction exceeded time limit

**Implements:**
- REQ-030

**Verified by:**
- TEST-040, TEST-041

---

### CON-031: Embedding Normalization

**Interface:** `normalize_embedding`

**Location:** `core/src/biometric/embedding.rs`

```rust
/// Normalizes an embedding vector to unit L2 norm.
///
/// # Arguments
///
/// * `values` - Raw embedding values from model
///
/// # Returns
///
/// * `Ok(Vec<f64>)` - Normalized values with ||v||₂ = 1.0
/// * `Err` - If input contains NaN/Inf or is zero vector
///
/// # Example
///
/// ```rust
/// let raw = vec![3.0, 4.0];
/// let normalized = normalize_embedding(&raw)?;
/// assert!((normalized[0] - 0.6).abs() < 1e-10);
/// assert!((normalized[1] - 0.8).abs() < 1e-10);
/// ```
pub fn normalize_embedding(values: &[f64]) -> Result<Vec<f64>>;

/// Validates embedding values are finite and non-zero.
pub fn validate_embedding_values(values: &[f64]) -> Result<()>;

/// Computes L2 norm of a vector.
pub fn l2_norm(values: &[f64]) -> f64;
```

**Implements:**
- REQ-031

**Verified by:**
- TEST-042, TEST-043

---

### CON-032: Distance Metric Implementations

**Interface:** Distance calculation functions

**Location:** `core/src/biometric/distance.rs`

```rust
/// Distance metrics for embedding comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DistanceMetric {
    /// Euclidean (L2) distance: sqrt(sum((a-b)²))
    Euclidean,
    /// Cosine distance: 1 - (a·b)/(||a|| ||b||)
    /// Assumes normalized vectors, simplifies to: 1 - a·b
    Cosine,
    /// Squared Euclidean: sum((a-b)²)
    /// More efficient in circuits (no sqrt)
    SquaredEuclidean,
}

impl DistanceMetric {
    /// Compute distance between two embeddings using this metric.
    ///
    /// All implementations are constant-time (REQ-004).
    pub fn compute(&self, a: &[f64], b: &[f64]) -> Result<f64>;

    /// Returns the threshold interpretation for this metric.
    ///
    /// For Euclidean/SquaredEuclidean: smaller = more similar
    /// For Cosine: smaller = more similar (0 = identical)
    pub fn threshold_direction(&self) -> ThresholdDirection;

    /// Returns estimated circuit constraint count for this metric.
    pub fn circuit_constraints(&self, dimension: usize) -> usize;
}

/// Constant-time Euclidean distance.
pub fn euclidean_distance_ct(a: &[f64], b: &[f64]) -> f64;

/// Constant-time cosine distance (assumes normalized inputs).
pub fn cosine_distance_ct(a: &[f64], b: &[f64]) -> f64;

/// Constant-time squared Euclidean distance.
pub fn squared_euclidean_distance_ct(a: &[f64], b: &[f64]) -> f64;
```

**Implements:**
- REQ-032

**Verified by:**
- TEST-044, TEST-045, TEST-046

---

### CON-033: Model Registry

**Interface:** `EmbeddingRegistry`

**Location:** `core/src/biometric/registry.rs`

```rust
/// Thread-safe registry of embedding models.
///
/// Provides dynamic registration, lookup, and lifecycle management
/// for embedding extractors.
pub struct EmbeddingRegistry {
    models: RwLock<HashMap<String, RegisteredModel>>,
    dimension_circuits: HashMap<usize, CircuitParameters>,
}

/// A registered embedding model with metadata.
pub struct RegisteredModel {
    pub extractor: Arc<dyn BiometricEmbedding>,
    pub registration: ModelRegistration,
}

/// Model registration metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelRegistration {
    pub model_id: String,
    pub model_version: Version,
    pub modality: BiometricModality,
    pub dimension: usize,
    pub distance_metric: DistanceMetric,
    pub registered_at: Timestamp,
    pub registered_by: String,
    pub status: ModelStatus,
    pub config_hash: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelStatus {
    Active,
    Deprecated,
    Disabled,
}

impl EmbeddingRegistry {
    /// Create a new registry with built-in models.
    pub fn new() -> Self;

    /// Register a new embedding model.
    ///
    /// # Errors
    ///
    /// * Model ID already registered
    /// * Dimension not supported (no circuit available)
    /// * Model validation failed
    pub fn register(
        &self,
        extractor: Arc<dyn BiometricEmbedding>,
        registered_by: &str,
    ) -> Result<ModelRegistration>;

    /// Get extractor by model ID.
    pub fn get(&self, model_id: &str) -> Option<Arc<dyn BiometricEmbedding>>;

    /// Get registration metadata.
    pub fn get_registration(&self, model_id: &str) -> Option<ModelRegistration>;

    /// List all models for a modality.
    pub fn list_by_modality(&self, modality: BiometricModality) -> Vec<ModelRegistration>;

    /// List all active models.
    pub fn list_active(&self) -> Vec<ModelRegistration>;

    /// Update model status (deprecate, disable, reactivate).
    pub fn update_status(&self, model_id: &str, status: ModelStatus) -> Result<()>;

    /// Check if dimension tier is supported.
    pub fn supports_dimension(&self, dimension: usize) -> bool;

    /// Get circuit parameters for dimension.
    pub fn circuit_for_dimension(&self, dimension: usize) -> Option<&CircuitParameters>;
}
```

**Implements:**
- REQ-033

**Verified by:**
- TEST-047, TEST-048

---

### CON-034: Parameterized Circuit

**Interface:** `ParameterizedBiometricCircuit`

**Location:** `core/src/crypto/groth16.rs`

```rust
/// Biometric verification circuit parameterized by embedding dimension.
///
/// Supports different embedding sizes via const generics, allowing
/// a single codebase to handle multiple model dimensions.
///
/// # Type Parameters
///
/// * `DIM` - Embedding dimension (64, 128, 256, 384, 512, 768, 1024, 1536, 2048)
///
/// # Example
///
/// ```rust
/// // 512-dimension circuit for palm biometrics
/// type PalmCircuit = ParameterizedBiometricCircuit<512>;
///
/// // 768-dimension circuit for face biometrics
/// type FaceCircuit = ParameterizedBiometricCircuit<768>;
/// ```
pub struct ParameterizedBiometricCircuit<const DIM: usize> {
    // === Private Inputs (Witness) ===

    /// User's embedding features
    pub features: Option<[Fr; DIM]>,

    /// Reference (enrolled) embedding features
    pub reference_features: Option<[Fr; DIM]>,

    /// Salt for user's commitment
    pub salt: Option<Salt>,

    /// Salt for reference commitment
    pub reference_salt: Option<Salt>,

    /// Timestamp of capture
    pub timestamp: Option<Timestamp>,

    /// Quality score (fixed-point)
    pub quality_score: Option<u64>,

    /// Liveness signals (if enabled)
    pub liveness: Option<LivenessWitness>,

    // === Public Inputs ===

    /// User's embedding commitment
    pub commitment: Option<Commitment>,

    /// Reference embedding commitment
    pub reference_commitment: Option<Commitment>,

    /// Distance threshold for matching
    pub distance_threshold: Fr,

    /// Distance metric to use
    pub distance_metric: DistanceMetric,

    /// Quality threshold
    pub quality_threshold: u64,

    /// Time window for validity
    pub time_window: u64,

    /// Current verification time
    pub current_time: Timestamp,
}

impl<const DIM: usize> ParameterizedBiometricCircuit<DIM> {
    /// Create circuit for proving with all inputs.
    pub fn new_proving(/* ... */) -> Self;

    /// Create circuit for verification (public inputs only).
    pub fn new_verifying(/* ... */) -> Self;

    /// Get the dimension of this circuit.
    pub const fn dimension() -> usize { DIM }

    /// Estimate constraint count for this dimension.
    pub const fn estimated_constraints() -> usize {
        // Base: ~6000 (Poseidon, Pedersen, temporal, quality)
        // Per-dimension: ~10 constraints (distance calculation)
        6000 + DIM * 10
    }
}

impl<const DIM: usize> ConstraintSynthesizer<Fr> for ParameterizedBiometricCircuit<DIM> {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError>;
}

/// Type aliases for common dimensions.
pub type Circuit64 = ParameterizedBiometricCircuit<64>;
pub type Circuit128 = ParameterizedBiometricCircuit<128>;
pub type Circuit256 = ParameterizedBiometricCircuit<256>;
pub type Circuit384 = ParameterizedBiometricCircuit<384>;
pub type Circuit512 = ParameterizedBiometricCircuit<512>;
pub type Circuit768 = ParameterizedBiometricCircuit<768>;
pub type Circuit1024 = ParameterizedBiometricCircuit<1024>;
```

**Implements:**
- REQ-034

**Verified by:**
- TEST-049, TEST-050, TEST-051

---

### CON-035: Biometric Input Types

**Interface:** `BiometricInput`

**Location:** `core/src/biometric/input.rs`

```rust
/// Polymorphic biometric input supporting multiple modalities.
///
/// Each variant contains modality-specific data and metadata.
/// Use `BiometricInput::modality()` to determine the type at runtime.
#[derive(Clone)]
pub enum BiometricInput {
    /// Palm image (grayscale or NIR)
    Palm(PalmInputData),

    /// Face image (RGB)
    Face(FaceInputData),

    /// Voice audio samples
    Voice(VoiceInputData),

    /// Iris image (NIR)
    Iris(IrisInputData),

    /// Fingerprint image
    Fingerprint(FingerprintInputData),

    /// Behavioral biometric sample
    Behavioral(BehavioralInputData),

    /// Pre-computed embedding (for testing/migration)
    PreComputed(PreComputedData),
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PalmInputData {
    pub image: PalmImage,
    pub capture_timestamp: Timestamp,
    pub sensor_id: String,
    /// Multi-frame data for liveness (optional)
    pub liveness_frames: Option<[PalmImage; 3]>,
    pub liveness_timestamps: Option<[u64; 3]>,
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct FaceInputData {
    pub image: RgbImage,
    pub capture_timestamp: Timestamp,
    pub sensor_id: String,
    /// Face detection bounding box
    pub face_rect: Option<Rectangle>,
    /// Facial landmarks (if pre-detected)
    pub landmarks: Option<FaceLandmarks>,
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct VoiceInputData {
    pub samples: Vec<f32>,
    pub sample_rate: u32,
    pub channels: u8,
    pub duration: Duration,
    pub capture_timestamp: Timestamp,
}

#[derive(Clone)]
pub struct PreComputedData {
    pub embedding: Vec<f64>,
    pub model_id: String,
    pub model_version: Version,
    pub original_modality: BiometricModality,
}

impl BiometricInput {
    /// Returns the modality of this input.
    pub fn modality(&self) -> BiometricModality;

    /// Returns capture timestamp if available.
    pub fn capture_timestamp(&self) -> Option<Timestamp>;

    /// Validates input is well-formed (dimensions, ranges, etc.).
    pub fn validate(&self) -> Result<()>;
}

// Implement Zeroize for the enum
impl Zeroize for BiometricInput {
    fn zeroize(&mut self) {
        match self {
            Self::Palm(data) => data.zeroize(),
            Self::Face(data) => data.zeroize(),
            Self::Voice(data) => data.zeroize(),
            // ... etc
        }
    }
}
```

**Implements:**
- REQ-035

**Verified by:**
- TEST-052, TEST-053

---

### CON-036: Embedding Output Structure

**Interface:** `Embedding`

**Location:** `core/src/biometric/embedding.rs`

```rust
/// A biometric embedding with metadata.
///
/// Embeddings are always L2-normalized (||e||₂ = 1.0).
/// Sensitive data is zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Embedding {
    /// Normalized embedding values.
    #[zeroize(drop)]
    pub values: Vec<f64>,

    /// Dimensionality (equals values.len()).
    pub dimension: usize,

    /// Model that produced this embedding.
    pub model_id: String,

    /// Model version.
    pub model_version: Version,

    /// Extraction confidence [0.0, 1.0].
    pub confidence: f64,

    /// When extraction occurred.
    pub extracted_at: Timestamp,

    /// Quality metrics.
    pub quality: EmbeddingQuality,
}

/// Quality metrics for an embedding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddingQuality {
    /// Input quality score [0.0, 1.0].
    pub input_quality: f64,

    /// Estimated false accept rate at this quality.
    pub estimated_far: f64,

    /// Model-specific quality indicators.
    pub model_scores: HashMap<String, f64>,
}

impl Embedding {
    /// Create a new embedding (normalizes values).
    pub fn new(
        values: Vec<f64>,
        model_id: String,
        model_version: Version,
        confidence: f64,
        quality: EmbeddingQuality,
    ) -> Result<Self>;

    /// Validate embedding integrity.
    pub fn validate(&self) -> Result<()>;

    /// Convert to circuit witness format.
    pub fn to_witness(&self) -> Vec<Fr>;

    /// Check if embedding is compatible with another (same model family).
    pub fn is_compatible_with(&self, other: &Embedding) -> bool;
}
```

**Implements:**
- REQ-036

**Verified by:**
- TEST-054, TEST-055

---

### CON-037: Version Compatibility

**Interface:** `Version`

**Location:** `core/src/biometric/version.rs`

```rust
/// Semantic version for embedding models.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Version {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

impl Version {
    pub const fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self { major, minor, patch }
    }

    /// Check if this version can verify against enrolled version.
    ///
    /// Compatible if:
    /// - Same major version
    /// - This minor >= enrolled minor (backward compatible)
    pub fn is_compatible_with(&self, enrolled: &Version) -> bool {
        self.major == enrolled.major && self.minor >= enrolled.minor
    }

    /// Check if this is a newer version.
    pub fn is_newer_than(&self, other: &Version) -> bool {
        (self.major, self.minor, self.patch) > (other.major, other.minor, other.patch)
    }

    /// Parse from string "major.minor.patch".
    pub fn parse(s: &str) -> Result<Self>;
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// Version compatibility check result.
#[derive(Debug, Clone)]
pub enum CompatibilityResult {
    /// Versions are compatible.
    Compatible,
    /// Major version mismatch - re-enrollment required.
    MajorMismatch { enrolled: Version, current: Version },
    /// Forward compatibility issue - enrolled is newer.
    ForwardIncompatible { enrolled: Version, current: Version },
}
```

**Implements:**
- REQ-037

**Verified by:**
- TEST-056, TEST-057

---

### CON-038: Built-in Extractors

**Interface:** Built-in `BiometricEmbedding` implementations

**Location:** `core/src/biometric/extractors/`

```rust
// === core/src/biometric/extractors/mod.rs ===

pub mod palm_vein;
pub mod palm_print;
pub mod fused_palm;
pub mod onnx;
pub mod mock;

pub use palm_vein::PalmVeinExtractor;
pub use palm_print::PalmPrintExtractor;
pub use fused_palm::FusedPalmExtractor;
pub use onnx::OnnxEmbedding;
pub use mock::MockEmbedding;

/// Register all built-in extractors with the registry.
pub fn register_builtins(registry: &EmbeddingRegistry) -> Result<()> {
    registry.register(Arc::new(PalmVeinExtractor::new()), "system")?;
    registry.register(Arc::new(PalmPrintExtractor::new()), "system")?;
    registry.register(Arc::new(FusedPalmExtractor::new()), "system")?;
    Ok(())
}

// === core/src/biometric/extractors/palm_vein.rs ===

/// Palm vein embedding extractor using Gabor filters and CNN.
///
/// Produces 512-dimensional embeddings optimized for Euclidean distance.
pub struct PalmVeinExtractor {
    gabor_bank: GaborFilterBank,
}

impl BiometricEmbedding for PalmVeinExtractor {
    fn dimension(&self) -> usize { 512 }
    fn model_id(&self) -> &str { "palm-vein-gabor-v1" }
    fn model_version(&self) -> Version { Version::new(1, 0, 0) }
    fn distance_metric(&self) -> DistanceMetric { DistanceMetric::Euclidean }
    fn modality(&self) -> BiometricModality { BiometricModality::PalmVein }

    fn extract(&self, input: &BiometricInput) -> Result<Embedding> {
        // Delegates to existing feature_extraction::extract_vein_features
    }

    fn validate_input(&self, input: &BiometricInput) -> Result<()> {
        match input {
            BiometricInput::Palm(_) => Ok(()),
            _ => Err(SableError::ModalityMismatch),
        }
    }
}

// === core/src/biometric/extractors/mock.rs ===

/// Mock extractor for testing.
///
/// Produces deterministic embeddings based on input hash.
/// NOT FOR PRODUCTION USE.
#[cfg(any(test, feature = "test-utils"))]
pub struct MockEmbedding {
    dimension: usize,
    model_id: String,
}

impl MockEmbedding {
    pub fn new(dimension: usize, model_id: &str) -> Self {
        Self {
            dimension,
            model_id: model_id.to_string(),
        }
    }
}

impl BiometricEmbedding for MockEmbedding {
    fn dimension(&self) -> usize { self.dimension }
    fn model_id(&self) -> &str { &self.model_id }
    fn model_version(&self) -> Version { Version::new(0, 0, 1) }
    fn distance_metric(&self) -> DistanceMetric { DistanceMetric::Euclidean }
    fn modality(&self) -> BiometricModality { BiometricModality::PalmMultiModal }

    fn extract(&self, input: &BiometricInput) -> Result<Embedding> {
        // Deterministic embedding from input hash
        let hash = hash_input(input);
        let values = expand_hash_to_embedding(&hash, self.dimension);
        Embedding::new(values, self.model_id.clone(), self.model_version(), 1.0, EmbeddingQuality::default())
    }

    fn validate_input(&self, _input: &BiometricInput) -> Result<()> {
        Ok(())  // Accept any input for testing
    }
}
```

**Implements:**
- REQ-038

**Verified by:**
- TEST-058, TEST-059, TEST-060

---

### CON-039: ONNX Integration

**Interface:** `OnnxEmbedding`

**Location:** `core/src/biometric/extractors/onnx.rs`

```rust
/// ONNX Runtime-based embedding extractor.
///
/// Supports any ONNX model that produces fixed-dimension embeddings.
pub struct OnnxEmbedding {
    session: ort::Session,
    config: OnnxEmbeddingConfig,
}

/// Configuration for ONNX embedding extractor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnnxEmbeddingConfig {
    /// Path to .onnx model file.
    pub model_path: PathBuf,

    /// Model identifier.
    pub model_id: String,

    /// Model version.
    pub model_version: Version,

    /// Expected output dimension.
    pub dimension: usize,

    /// Biometric modality this model handles.
    pub modality: BiometricModality,

    /// Distance metric for this model's embeddings.
    pub distance_metric: DistanceMetric,

    /// Input preprocessing configuration.
    pub preprocess: PreprocessConfig,

    /// Execution provider preference.
    pub execution_provider: ExecutionProvider,

    /// Inference timeout.
    pub timeout: Duration,
}

/// Input preprocessing configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreprocessConfig {
    /// Target input size (height, width).
    pub input_size: (u32, u32),

    /// Normalization mean (per channel).
    pub normalize_mean: Vec<f32>,

    /// Normalization std (per channel).
    pub normalize_std: Vec<f32>,

    /// Whether to convert to grayscale.
    pub grayscale: bool,
}

/// Execution provider for ONNX Runtime.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ExecutionProvider {
    Cpu,
    CoreML,    // iOS/macOS
    Nnapi,     // Android
    Cuda,      // NVIDIA GPU
    TensorRT,  // NVIDIA optimized
}

impl OnnxEmbedding {
    /// Load ONNX model from configuration.
    ///
    /// Validates model inputs/outputs match configuration.
    pub fn load(config: OnnxEmbeddingConfig) -> Result<Self>;

    /// Load from model path with auto-detected settings.
    pub fn load_auto(model_path: &Path, modality: BiometricModality) -> Result<Self>;
}

impl BiometricEmbedding for OnnxEmbedding {
    fn dimension(&self) -> usize { self.config.dimension }
    fn model_id(&self) -> &str { &self.config.model_id }
    fn model_version(&self) -> Version { self.config.model_version }
    fn distance_metric(&self) -> DistanceMetric { self.config.distance_metric }
    fn modality(&self) -> BiometricModality { self.config.modality }

    fn extract(&self, input: &BiometricInput) -> Result<Embedding> {
        self.validate_input(input)?;

        // Preprocess input to tensor
        let tensor = self.preprocess_input(input)?;

        // Run inference with timeout
        let output = tokio::time::timeout(
            self.config.timeout,
            self.session.run(tensor),
        ).await??;

        // Extract and normalize embedding
        let values = self.extract_embedding_from_output(&output)?;
        let normalized = normalize_embedding(&values)?;

        Embedding::new(
            normalized,
            self.config.model_id.clone(),
            self.config.model_version,
            self.compute_confidence(&output),
            self.compute_quality(input),
        )
    }

    fn validate_input(&self, input: &BiometricInput) -> Result<()> {
        if input.modality() != self.config.modality {
            return Err(SableError::ModalityMismatch);
        }
        Ok(())
    }

    fn performance_hints(&self) -> PerformanceHints {
        PerformanceHints {
            expected_latency: match self.config.execution_provider {
                ExecutionProvider::Cpu => Duration::from_millis(200),
                ExecutionProvider::CoreML | ExecutionProvider::Nnapi => Duration::from_millis(50),
                ExecutionProvider::Cuda | ExecutionProvider::TensorRT => Duration::from_millis(20),
            },
            uses_gpu: !matches!(self.config.execution_provider, ExecutionProvider::Cpu),
            ..Default::default()
        }
    }
}
```

**Implements:**
- REQ-039

**Verified by:**
- TEST-061, TEST-062, TEST-063

---

### CON-040: Face Detection Interface

**Interface:** `FaceDetector`

**Location:** `core/src/biometric/face/detection.rs`

```rust
/// Cross-platform face detection interface.
///
/// Abstracts MediaPipe, ML Kit, and Vision Framework backends.
pub trait FaceDetector: Send + Sync {
    /// Detect faces in an image.
    ///
    /// # Arguments
    /// * `image` - RGB image data
    ///
    /// # Returns
    /// * Vector of detected faces (may be empty)
    fn detect(&self, image: &RgbImage) -> Result<Vec<FaceDetectionResult>>;

    /// Get the detection backend being used.
    fn backend(&self) -> FaceDetectorBackend;

    /// Check if backend is available on this device.
    fn is_available(&self) -> bool;
}

#[derive(Debug, Clone, Copy)]
pub enum FaceDetectorBackend {
    MediaPipe,
    MlKit,
    AppleVision,
    Mock,
}

/// Detected face with bounding box and landmarks.
#[derive(Debug, Clone)]
pub struct FaceDetectionResult {
    /// Bounding box in image coordinates [x, y, width, height]
    pub bounding_box: [f32; 4],

    /// Detection confidence [0.0, 1.0]
    pub confidence: f32,

    /// Facial landmarks
    pub landmarks: FaceLandmarks,

    /// Estimated head pose (if available)
    pub head_pose: Option<HeadPose>,

    /// Tracking ID for video sequences
    pub tracking_id: Option<u32>,
}

/// Facial landmark positions.
#[derive(Debug, Clone)]
pub struct FaceLandmarks {
    /// Left eye center (x, y)
    pub left_eye: [f32; 2],
    /// Right eye center (x, y)
    pub right_eye: [f32; 2],
    /// Nose tip
    pub nose_tip: [f32; 2],
    /// Mouth center
    pub mouth_center: [f32; 2],
    /// Left ear (optional)
    pub left_ear: Option<[f32; 2]>,
    /// Right ear (optional)
    pub right_ear: Option<[f32; 2]>,
    /// Full landmark set (68, 133, or 468 points)
    pub full_landmarks: Option<Vec<[f32; 2]>>,
}

/// Head pose estimation.
#[derive(Debug, Clone, Copy)]
pub struct HeadPose {
    /// Yaw: looking left (-) or right (+), in degrees
    pub yaw: f32,
    /// Pitch: looking down (-) or up (+), in degrees
    pub pitch: f32,
    /// Roll: tilting left (-) or right (+), in degrees
    pub roll: f32,
}

impl HeadPose {
    /// Check if pose is within acceptable range for recognition.
    pub fn is_frontal(&self, tolerance: f32) -> bool {
        self.yaw.abs() <= tolerance &&
        self.pitch.abs() <= tolerance &&
        self.roll.abs() <= tolerance
    }
}
```

**Implements:**
- REQ-040

**Verified by:**
- TEST-068, TEST-069

---

### CON-041: Face Alignment Pipeline

**Interface:** `FaceAligner`

**Location:** `core/src/biometric/face/alignment.rs`

```rust
/// Face alignment for embedding extraction.
pub struct FaceAligner {
    /// Target output size
    target_size: (u32, u32),
    /// Canonical landmark positions
    canonical_landmarks: CanonicalLandmarks,
}

/// Canonical landmark positions for alignment.
#[derive(Debug, Clone)]
pub struct CanonicalLandmarks {
    pub left_eye: [f32; 2],
    pub right_eye: [f32; 2],
    pub nose_tip: [f32; 2],
    pub left_mouth: [f32; 2],
    pub right_mouth: [f32; 2],
}

impl CanonicalLandmarks {
    /// Standard 112×112 alignment (MobileFaceNet, ArcFace)
    pub fn standard_112() -> Self {
        Self {
            left_eye: [38.2946, 51.6963],
            right_eye: [73.5318, 51.5014],
            nose_tip: [56.0252, 71.7366],
            left_mouth: [41.5493, 92.3655],
            right_mouth: [70.7299, 92.2041],
        }
    }

    /// FaceNet 160×160 alignment
    pub fn facenet_160() -> Self {
        // Scaled from 112×112
        let scale = 160.0 / 112.0;
        Self {
            left_eye: [38.2946 * scale, 51.6963 * scale],
            right_eye: [73.5318 * scale, 51.5014 * scale],
            nose_tip: [56.0252 * scale, 71.7366 * scale],
            left_mouth: [41.5493 * scale, 92.3655 * scale],
            right_mouth: [70.7299 * scale, 92.2041 * scale],
        }
    }
}

impl FaceAligner {
    /// Create aligner for MobileFaceNet (112×112)
    pub fn mobilefacenet() -> Self {
        Self {
            target_size: (112, 112),
            canonical_landmarks: CanonicalLandmarks::standard_112(),
        }
    }

    /// Create aligner for FaceNet (160×160)
    pub fn facenet() -> Self {
        Self {
            target_size: (160, 160),
            canonical_landmarks: CanonicalLandmarks::facenet_160(),
        }
    }

    /// Align a detected face to canonical pose.
    ///
    /// # Arguments
    /// * `image` - Source RGB image
    /// * `landmarks` - Detected facial landmarks
    ///
    /// # Returns
    /// * Aligned face image at target size
    pub fn align(
        &self,
        image: &RgbImage,
        landmarks: &FaceLandmarks,
    ) -> Result<AlignedFace> {
        // 1. Estimate affine transform from detected to canonical
        let transform = self.estimate_transform(landmarks)?;

        // 2. Warp image using bilinear interpolation
        let warped = self.warp_affine(image, &transform)?;

        // 3. Crop to target size
        let cropped = self.crop_center(&warped)?;

        Ok(AlignedFace {
            pixels: cropped,
            width: self.target_size.0,
            height: self.target_size.1,
            transform,
        })
    }

    fn estimate_transform(&self, landmarks: &FaceLandmarks) -> Result<AffineTransform> {
        // Similarity transform estimation using least squares
        // Maps 5 detected landmarks to canonical positions
        todo!()
    }

    fn warp_affine(&self, image: &RgbImage, transform: &AffineTransform) -> Result<RgbImage> {
        // Apply affine transformation with bilinear interpolation
        todo!()
    }

    fn crop_center(&self, image: &RgbImage) -> Result<Vec<u8>> {
        // Crop to target size from center
        todo!()
    }
}

/// Aligned face ready for embedding extraction.
#[derive(Clone)]
pub struct AlignedFace {
    /// RGB pixel data (row-major, 3 channels)
    pub pixels: Vec<u8>,
    /// Width in pixels
    pub width: u32,
    /// Height in pixels
    pub height: u32,
    /// Transform applied for alignment
    pub transform: AffineTransform,
}

/// 2D affine transformation matrix.
#[derive(Debug, Clone, Copy)]
pub struct AffineTransform {
    /// 2×3 transformation matrix
    pub matrix: [[f32; 3]; 2],
}
```

**Implements:**
- REQ-041

**Verified by:**
- TEST-070, TEST-071

---

### CON-042: Face Embedding Extractor

**Interface:** `MobileFaceNetExtractor`

**Location:** `core/src/biometric/face/embedding.rs`

```rust
/// MobileFaceNet-based face embedding extractor.
///
/// Produces 128-dimensional embeddings optimized for mobile devices.
/// Model size: 4MB, Inference time: ~18ms
pub struct MobileFaceNetExtractor {
    /// TFLite interpreter
    interpreter: TfLiteInterpreter,
    /// Face aligner
    aligner: FaceAligner,
    /// Face detector
    detector: Box<dyn FaceDetector>,
    /// Quality assessor
    quality: FaceQualityAssessor,
}

impl MobileFaceNetExtractor {
    /// Load MobileFaceNet model from bundled assets.
    pub fn load_bundled() -> Result<Self> {
        let model_bytes = include_bytes!("../models/mobilefacenet.tflite");
        Self::load_from_bytes(model_bytes)
    }

    /// Load from external model file.
    pub fn load_from_path(path: &Path) -> Result<Self> {
        let model_bytes = std::fs::read(path)?;
        Self::load_from_bytes(&model_bytes)
    }

    fn load_from_bytes(model_bytes: &[u8]) -> Result<Self> {
        let interpreter = TfLiteInterpreter::new(model_bytes)?;

        // Verify model dimensions
        let input_shape = interpreter.input_shape(0)?;
        if input_shape != [1, 112, 112, 3] {
            return Err(SableError::InvalidModel("Unexpected input shape".into()));
        }

        let output_shape = interpreter.output_shape(0)?;
        if output_shape != [1, 128] {
            return Err(SableError::InvalidModel("Unexpected output shape".into()));
        }

        Ok(Self {
            interpreter,
            aligner: FaceAligner::mobilefacenet(),
            detector: create_platform_detector()?,
            quality: FaceQualityAssessor::default(),
        })
    }

    /// Extract embedding from RGB image.
    fn extract_from_image(&self, image: &RgbImage) -> Result<FaceEmbedding> {
        // 1. Detect face
        let faces = self.detector.detect(image)?;
        if faces.is_empty() {
            return Err(SableError::FaceNotDetected);
        }
        if faces.len() > 1 {
            return Err(SableError::MultipleFacesDetected);
        }

        let face = &faces[0];

        // 2. Assess quality
        let quality = self.quality.assess(image, face)?;
        if !quality.is_acceptable() {
            return Err(SableError::QualityTooLow);
        }

        // 3. Align face
        let aligned = self.aligner.align(image, &face.landmarks)?;

        // 4. Preprocess for model
        let input_tensor = self.preprocess(&aligned)?;

        // 5. Run inference
        let output = self.interpreter.invoke(&input_tensor)?;

        // 6. Normalize embedding
        let embedding = normalize_l2(&output);

        Ok(FaceEmbedding {
            values: embedding,
            dimension: 128,
            model_id: "face-mobilefacenet-v1".to_string(),
            quality: quality.overall,
            alignment_confidence: face.confidence,
            head_pose: face.head_pose,
        })
    }

    fn preprocess(&self, aligned: &AlignedFace) -> Result<Vec<f32>> {
        // Convert to float and normalize to [-1, 1]
        let mut tensor = Vec::with_capacity(112 * 112 * 3);
        for pixel in aligned.pixels.chunks(3) {
            tensor.push((pixel[0] as f32 - 127.5) / 128.0);
            tensor.push((pixel[1] as f32 - 127.5) / 128.0);
            tensor.push((pixel[2] as f32 - 127.5) / 128.0);
        }
        Ok(tensor)
    }
}

impl BiometricEmbedding for MobileFaceNetExtractor {
    fn dimension(&self) -> usize { 128 }

    fn model_id(&self) -> &str { "face-mobilefacenet-v1" }

    fn model_version(&self) -> Version { Version::new(1, 0, 0) }

    fn distance_metric(&self) -> DistanceMetric { DistanceMetric::Cosine }

    fn modality(&self) -> BiometricModality { BiometricModality::Face }

    fn extract(&self, input: &BiometricInput) -> Result<Embedding> {
        let BiometricInput::Face(face_data) = input else {
            return Err(SableError::ModalityMismatch);
        };

        let face_embedding = self.extract_from_image(&face_data.image)?;

        Embedding::new(
            face_embedding.values.into_iter().map(|v| v as f64).collect(),
            self.model_id().to_string(),
            self.model_version(),
            face_embedding.quality as f64,
            EmbeddingQuality {
                input_quality: face_embedding.quality as f64,
                estimated_far: estimate_far_from_quality(face_embedding.quality),
                model_scores: HashMap::from([
                    ("alignment".to_string(), face_embedding.alignment_confidence as f64),
                ]),
            },
        )
    }

    fn validate_input(&self, input: &BiometricInput) -> Result<()> {
        match input {
            BiometricInput::Face(data) => {
                if data.image.width < 320 || data.image.height < 240 {
                    return Err(SableError::InvalidInput("Image too small".into()));
                }
                Ok(())
            }
            _ => Err(SableError::ModalityMismatch),
        }
    }

    fn performance_hints(&self) -> PerformanceHints {
        PerformanceHints {
            expected_latency: Duration::from_millis(30), // detection + alignment + inference
            peak_memory_bytes: 20 * 1024 * 1024, // ~20MB
            uses_gpu: false, // TFLite CPU by default
            supports_batching: false,
            optimal_batch_size: 1,
        }
    }
}

/// Face-specific embedding with additional metadata.
pub struct FaceEmbedding {
    pub values: Vec<f32>,
    pub dimension: usize,
    pub model_id: String,
    pub quality: f32,
    pub alignment_confidence: f32,
    pub head_pose: Option<HeadPose>,
}
```

**Implements:**
- REQ-042

**Verified by:**
- TEST-072, TEST-073, TEST-074

---

### CON-043: Face Quality Assessor

**Interface:** `FaceQualityAssessor`

**Location:** `core/src/biometric/face/quality.rs`

```rust
/// Assesses face image quality for recognition suitability.
pub struct FaceQualityAssessor {
    /// Quality thresholds
    thresholds: FaceQualityThresholds,
    /// Metric weights
    weights: FaceQualityWeights,
}

/// Quality thresholds for face images.
#[derive(Debug, Clone)]
pub struct FaceQualityThresholds {
    pub min_blur_score: f32,      // 0.5
    pub min_lighting_score: f32,  // 0.4
    pub min_pose_score: f32,      // 0.7
    pub min_occlusion_score: f32, // 0.8
    pub min_resolution_score: f32, // 0.6
    pub min_overall_score: f32,   // 0.6
}

impl Default for FaceQualityThresholds {
    fn default() -> Self {
        Self {
            min_blur_score: 0.5,
            min_lighting_score: 0.4,
            min_pose_score: 0.7,
            min_occlusion_score: 0.8,
            min_resolution_score: 0.6,
            min_overall_score: 0.6,
        }
    }
}

/// Weights for combining quality metrics.
#[derive(Debug, Clone)]
pub struct FaceQualityWeights {
    pub blur: f32,
    pub lighting: f32,
    pub pose: f32,
    pub occlusion: f32,
    pub resolution: f32,
}

impl Default for FaceQualityWeights {
    fn default() -> Self {
        Self {
            blur: 0.25,
            lighting: 0.20,
            pose: 0.20,
            occlusion: 0.20,
            resolution: 0.15,
        }
    }
}

/// Quality assessment result.
#[derive(Debug, Clone)]
pub struct FaceQualityResult {
    /// Individual metric scores
    pub blur_score: f32,
    pub lighting_score: f32,
    pub pose_score: f32,
    pub occlusion_score: f32,
    pub resolution_score: f32,

    /// Weighted overall score
    pub overall: f32,

    /// Specific issues detected
    pub issues: Vec<QualityIssue>,
}

#[derive(Debug, Clone)]
pub enum QualityIssue {
    TooBlurry,
    PoorLighting,
    BackLit,
    NotFrontal { yaw: f32, pitch: f32 },
    PartialOcclusion { region: String },
    FaceTooSmall { size_pixels: u32 },
}

impl FaceQualityResult {
    pub fn is_acceptable(&self) -> bool {
        self.overall >= 0.6 && self.issues.is_empty()
    }
}

impl FaceQualityAssessor {
    pub fn new(thresholds: FaceQualityThresholds, weights: FaceQualityWeights) -> Self {
        Self { thresholds, weights }
    }

    /// Assess quality of a detected face.
    pub fn assess(
        &self,
        image: &RgbImage,
        detection: &FaceDetectionResult,
    ) -> Result<FaceQualityResult> {
        let mut issues = Vec::new();

        // 1. Blur detection (Laplacian variance)
        let blur_score = self.assess_blur(image, &detection.bounding_box)?;
        if blur_score < self.thresholds.min_blur_score {
            issues.push(QualityIssue::TooBlurry);
        }

        // 2. Lighting assessment (histogram analysis)
        let lighting_score = self.assess_lighting(image, &detection.bounding_box)?;
        if lighting_score < self.thresholds.min_lighting_score {
            issues.push(QualityIssue::PoorLighting);
        }

        // 3. Pose assessment
        let pose_score = self.assess_pose(detection)?;
        if pose_score < self.thresholds.min_pose_score {
            if let Some(pose) = &detection.head_pose {
                issues.push(QualityIssue::NotFrontal {
                    yaw: pose.yaw,
                    pitch: pose.pitch,
                });
            }
        }

        // 4. Occlusion detection (landmark confidence)
        let occlusion_score = self.assess_occlusion(detection)?;
        if occlusion_score < self.thresholds.min_occlusion_score {
            issues.push(QualityIssue::PartialOcclusion {
                region: "unknown".to_string(),
            });
        }

        // 5. Resolution assessment
        let resolution_score = self.assess_resolution(&detection.bounding_box)?;
        if resolution_score < self.thresholds.min_resolution_score {
            let size = detection.bounding_box[2].min(detection.bounding_box[3]) as u32;
            issues.push(QualityIssue::FaceTooSmall { size_pixels: size });
        }

        // Calculate weighted overall score
        let overall = self.weights.blur * blur_score
            + self.weights.lighting * lighting_score
            + self.weights.pose * pose_score
            + self.weights.occlusion * occlusion_score
            + self.weights.resolution * resolution_score;

        Ok(FaceQualityResult {
            blur_score,
            lighting_score,
            pose_score,
            occlusion_score,
            resolution_score,
            overall,
            issues,
        })
    }

    fn assess_blur(&self, image: &RgbImage, bbox: &[f32; 4]) -> Result<f32> {
        // Laplacian variance method
        // Higher variance = sharper image
        todo!()
    }

    fn assess_lighting(&self, image: &RgbImage, bbox: &[f32; 4]) -> Result<f32> {
        // Histogram spread analysis
        // Well-lit images have broad histogram
        todo!()
    }

    fn assess_pose(&self, detection: &FaceDetectionResult) -> Result<f32> {
        if let Some(pose) = &detection.head_pose {
            // Score based on deviation from frontal
            let yaw_penalty = (pose.yaw.abs() / 30.0).min(1.0);
            let pitch_penalty = (pose.pitch.abs() / 20.0).min(1.0);
            let roll_penalty = (pose.roll.abs() / 15.0).min(1.0);
            Ok(1.0 - (yaw_penalty + pitch_penalty + roll_penalty) / 3.0)
        } else {
            // No pose info, assume acceptable
            Ok(0.8)
        }
    }

    fn assess_occlusion(&self, detection: &FaceDetectionResult) -> Result<f32> {
        // Based on landmark detection confidence
        // Low confidence often indicates occlusion
        Ok(detection.confidence)
    }

    fn assess_resolution(&self, bbox: &[f32; 4]) -> Result<f32> {
        let face_size = bbox[2].min(bbox[3]);
        // Minimum 100px, optimal 200px+
        let score = ((face_size - 50.0) / 150.0).clamp(0.0, 1.0);
        Ok(score)
    }
}
```

**Implements:**
- REQ-043

**Verified by:**
- TEST-075, TEST-076

---

### CON-044: Face Liveness Detector

**Interface:** `FaceLivenessDetector`

**Location:** `core/src/biometric/face/liveness.rs`

```rust
/// Face liveness detection for presentation attack prevention.
pub struct FaceLivenessDetector {
    config: FaceLivenessConfig,
    texture_analyzer: TextureAnalyzer,
    blink_detector: Option<BlinkDetector>,
}

/// Liveness detection configuration.
#[derive(Debug, Clone)]
pub struct FaceLivenessConfig {
    /// Enable passive texture analysis
    pub passive_texture: bool,
    /// Enable blink detection
    pub blink_detection: bool,
    /// Enable head movement tracking
    pub head_movement: bool,
    /// Timeout for active challenges
    pub challenge_timeout: Duration,
    /// Minimum confidence to pass
    pub min_confidence: f32,
}

impl Default for FaceLivenessConfig {
    fn default() -> Self {
        Self {
            passive_texture: true,
            blink_detection: true,
            head_movement: false,
            challenge_timeout: Duration::from_secs(5),
            min_confidence: 0.8,
        }
    }
}

/// Liveness check result.
#[derive(Debug, Clone)]
pub struct FaceLivenessResult {
    /// Overall confidence [0.0, 1.0]
    pub confidence: f32,
    /// Whether liveness passed
    pub is_live: bool,
    /// Individual check results
    pub checks: Vec<LivenessCheckResult>,
    /// Detected attack type (if any)
    pub attack_type: Option<FaceAttackType>,
}

#[derive(Debug, Clone)]
pub struct LivenessCheckResult {
    pub check_type: LivenessCheckType,
    pub passed: bool,
    pub confidence: f32,
}

#[derive(Debug, Clone, Copy)]
pub enum LivenessCheckType {
    TextureAnalysis,
    BlinkDetection,
    HeadMovement,
    DepthEstimation,
}

#[derive(Debug, Clone, Copy)]
pub enum FaceAttackType {
    PrintedPhoto,
    ScreenDisplay,
    PaperMask,
    SiliconMask,
    VideoReplay,
    Deepfake,
    Unknown,
}

impl FaceLivenessDetector {
    pub fn new(config: FaceLivenessConfig) -> Self {
        Self {
            texture_analyzer: TextureAnalyzer::new(),
            blink_detector: if config.blink_detection {
                Some(BlinkDetector::new())
            } else {
                None
            },
            config,
        }
    }

    /// Check liveness from a single frame (passive checks only).
    pub fn check_single_frame(
        &self,
        image: &RgbImage,
        face: &FaceDetectionResult,
    ) -> Result<FaceLivenessResult> {
        let mut checks = Vec::new();
        let mut total_confidence = 0.0;
        let mut check_count = 0;

        // Passive texture analysis
        if self.config.passive_texture {
            let texture_result = self.texture_analyzer.analyze(image, face)?;
            checks.push(LivenessCheckResult {
                check_type: LivenessCheckType::TextureAnalysis,
                passed: texture_result.is_live,
                confidence: texture_result.confidence,
            });
            total_confidence += texture_result.confidence;
            check_count += 1;
        }

        let avg_confidence = if check_count > 0 {
            total_confidence / check_count as f32
        } else {
            0.0
        };

        let is_live = avg_confidence >= self.config.min_confidence
            && checks.iter().all(|c| c.passed);

        let attack_type = if !is_live {
            self.detect_attack_type(&checks)
        } else {
            None
        };

        Ok(FaceLivenessResult {
            confidence: avg_confidence,
            is_live,
            checks,
            attack_type,
        })
    }

    /// Check liveness from a frame sequence (passive + active checks).
    pub async fn check_sequence(
        &mut self,
        frames: &[TimestampedFrame],
        faces: &[FaceDetectionResult],
    ) -> Result<FaceLivenessResult> {
        let mut checks = Vec::new();

        // Passive texture on first frame
        if self.config.passive_texture && !frames.is_empty() {
            let texture_result = self.texture_analyzer.analyze(&frames[0].image, &faces[0])?;
            checks.push(LivenessCheckResult {
                check_type: LivenessCheckType::TextureAnalysis,
                passed: texture_result.is_live,
                confidence: texture_result.confidence,
            });
        }

        // Blink detection across frames
        if let Some(ref mut blink_detector) = self.blink_detector {
            if frames.len() >= 3 {
                let blink_result = blink_detector.detect_blink(frames, faces)?;
                checks.push(LivenessCheckResult {
                    check_type: LivenessCheckType::BlinkDetection,
                    passed: blink_result.blink_detected,
                    confidence: blink_result.confidence,
                });
            }
        }

        // Head movement tracking
        if self.config.head_movement && faces.len() >= 2 {
            let movement = self.analyze_head_movement(faces)?;
            checks.push(LivenessCheckResult {
                check_type: LivenessCheckType::HeadMovement,
                passed: movement.natural_movement,
                confidence: movement.confidence,
            });
        }

        let total_confidence: f32 = checks.iter().map(|c| c.confidence).sum();
        let avg_confidence = if !checks.is_empty() {
            total_confidence / checks.len() as f32
        } else {
            0.0
        };

        let is_live = avg_confidence >= self.config.min_confidence
            && checks.iter().filter(|c| !c.passed).count() == 0;

        Ok(FaceLivenessResult {
            confidence: avg_confidence,
            is_live,
            checks,
            attack_type: if !is_live { Some(FaceAttackType::Unknown) } else { None },
        })
    }

    fn detect_attack_type(&self, checks: &[LivenessCheckResult]) -> Option<FaceAttackType> {
        // Heuristic attack type detection based on which checks failed
        for check in checks {
            if !check.passed {
                match check.check_type {
                    LivenessCheckType::TextureAnalysis => {
                        return Some(FaceAttackType::PrintedPhoto);
                    }
                    LivenessCheckType::BlinkDetection => {
                        return Some(FaceAttackType::ScreenDisplay);
                    }
                    _ => {}
                }
            }
        }
        Some(FaceAttackType::Unknown)
    }

    fn analyze_head_movement(&self, faces: &[FaceDetectionResult]) -> Result<HeadMovementResult> {
        // Analyze pose changes across frames
        // Natural movement has smooth, continuous changes
        todo!()
    }
}

/// Texture analysis for print/screen detection.
pub struct TextureAnalyzer {
    // Model or algorithm state
}

impl TextureAnalyzer {
    pub fn new() -> Self {
        Self {}
    }

    pub fn analyze(
        &self,
        image: &RgbImage,
        face: &FaceDetectionResult,
    ) -> Result<TextureAnalysisResult> {
        // Analyze texture patterns
        // - Moiré patterns indicate screens
        // - Lack of micro-texture indicates prints
        // - Specular reflections differ for 2D vs 3D
        todo!()
    }
}

pub struct TextureAnalysisResult {
    pub is_live: bool,
    pub confidence: f32,
    pub texture_score: f32,
    pub moire_detected: bool,
    pub print_artifacts: bool,
}

/// Blink detection across frame sequence.
pub struct BlinkDetector {
    // Eye aspect ratio history
}

impl BlinkDetector {
    pub fn new() -> Self {
        Self {}
    }

    pub fn detect_blink(
        &mut self,
        frames: &[TimestampedFrame],
        faces: &[FaceDetectionResult],
    ) -> Result<BlinkDetectionResult> {
        // Track eye aspect ratio (EAR) across frames
        // Blink: EAR drops below threshold then recovers
        todo!()
    }
}

pub struct BlinkDetectionResult {
    pub blink_detected: bool,
    pub confidence: f32,
    pub blink_count: u32,
}

pub struct HeadMovementResult {
    pub natural_movement: bool,
    pub confidence: f32,
}

/// Frame with timestamp for sequence analysis.
pub struct TimestampedFrame {
    pub image: RgbImage,
    pub timestamp: Duration,
}
```

**Implements:**
- REQ-044

**Verified by:**
- TEST-077, TEST-078, TEST-079

---

### CON-045: Face Input Data

**Interface:** `FaceInputData`

**Location:** `core/src/biometric/input.rs`

```rust
/// Face biometric input data.
#[derive(Clone)]
pub struct FaceInputData {
    /// RGB image data
    pub image: RgbImage,

    /// Capture timestamp
    pub capture_timestamp: Timestamp,

    /// Camera/sensor identifier
    pub sensor_id: String,

    /// Pre-detected face (if available)
    pub detection: Option<FaceDetectionResult>,

    /// Multi-frame sequence for liveness (optional)
    pub frame_sequence: Option<Vec<TimestampedFrame>>,

    /// Camera intrinsics (for depth estimation)
    pub camera_intrinsics: Option<CameraIntrinsics>,
}

/// RGB image data.
#[derive(Clone)]
pub struct RgbImage {
    /// Pixel data (row-major, RGB, 3 bytes per pixel)
    pub data: Vec<u8>,
    /// Width in pixels
    pub width: u32,
    /// Height in pixels
    pub height: u32,
}

impl RgbImage {
    pub fn new(width: u32, height: u32, data: Vec<u8>) -> Result<Self> {
        let expected_size = (width * height * 3) as usize;
        if data.len() != expected_size {
            return Err(SableError::InvalidInput("Image data size mismatch".into()));
        }
        Ok(Self { data, width, height })
    }

    /// Get pixel at (x, y)
    pub fn get_pixel(&self, x: u32, y: u32) -> Option<[u8; 3]> {
        if x >= self.width || y >= self.height {
            return None;
        }
        let idx = ((y * self.width + x) * 3) as usize;
        Some([self.data[idx], self.data[idx + 1], self.data[idx + 2]])
    }

    /// Convert to grayscale
    pub fn to_grayscale(&self) -> Vec<u8> {
        self.data
            .chunks(3)
            .map(|rgb| {
                // ITU-R BT.601 luma coefficients
                (0.299 * rgb[0] as f32 + 0.587 * rgb[1] as f32 + 0.114 * rgb[2] as f32) as u8
            })
            .collect()
    }
}

impl Zeroize for RgbImage {
    fn zeroize(&mut self) {
        self.data.zeroize();
    }
}

impl Zeroize for FaceInputData {
    fn zeroize(&mut self) {
        self.image.zeroize();
        if let Some(ref mut frames) = self.frame_sequence {
            for frame in frames {
                frame.image.zeroize();
            }
        }
    }
}

/// Camera intrinsic parameters.
#[derive(Debug, Clone, Copy)]
pub struct CameraIntrinsics {
    /// Focal length X (pixels)
    pub fx: f32,
    /// Focal length Y (pixels)
    pub fy: f32,
    /// Principal point X
    pub cx: f32,
    /// Principal point Y
    pub cy: f32,
}
```

**Implements:**
- REQ-045

**Verified by:**
- TEST-080, TEST-081

---

## Test Specifications

### TEST-040: Trait Interface Compliance

**Objective:** Verify BiometricEmbedding trait implementations meet interface contract

**Test Type:** Unit test (property-based)

**Procedure:**
1. For each built-in extractor:
   - Verify dimension() returns constant value
   - Verify model_id() matches expected format
   - Verify modality() returns correct enum variant
   - Verify extract() produces embedding of correct dimension
   - Verify extracted embedding is normalized

**Pass Criteria:**
- All built-in extractors pass all checks
- No panics during extraction

**Traces:** REQ-030

---

### TEST-041: Thread Safety Verification

**Objective:** Verify extractors are safe for concurrent use

**Test Type:** Stress test

**Procedure:**
1. Create extractor instance
2. Spawn 100 concurrent extraction tasks
3. Verify all complete without data races
4. Verify embeddings are independent (no cross-contamination)

**Pass Criteria:**
- All extractions complete successfully
- No data races detected (run with ThreadSanitizer)

**Traces:** REQ-030

---

### TEST-042: L2 Normalization Accuracy

**Objective:** Verify embedding normalization produces unit vectors

**Test Type:** Unit test

**Setup:**
- Test vectors: random, near-zero, very large values

**Procedure:**
1. Normalize each test vector
2. Compute L2 norm of result
3. Verify |norm - 1.0| < 1e-10

**Pass Criteria:**
- All normalized vectors have L2 norm within tolerance

**Traces:** REQ-031

---

### TEST-043: Normalization Edge Cases

**Objective:** Verify normalization handles edge cases correctly

**Test Type:** Unit test

**Setup:**
- Zero vector, NaN values, Inf values, single element

**Procedure:**
1. Attempt normalization of each edge case
2. Verify appropriate error returned

**Pass Criteria:**
- Zero vector: Error
- NaN values: Error
- Inf values: Error
- Single element: Success (normalized to ±1.0)

**Traces:** REQ-031

---

### TEST-044: Euclidean Distance Correctness

**Objective:** Verify Euclidean distance calculation

**Test Type:** Unit test with known values

**Setup:**
- Vector pairs with known distances

**Procedure:**
1. Compute distance using implementation
2. Compare to expected value
3. Verify constant-time property

**Pass Criteria:**
- Distance within 1e-10 of expected
- Timing variance < 1μs

**Traces:** REQ-032

---

### TEST-045: Cosine Distance Correctness

**Objective:** Verify cosine distance calculation

**Test Type:** Unit test

**Setup:**
- Identical vectors (distance = 0)
- Orthogonal vectors (distance = 1)
- Opposite vectors (distance = 2)

**Procedure:**
1. Normalize all vectors
2. Compute cosine distance
3. Verify results

**Pass Criteria:**
- Identical: distance < 1e-10
- Orthogonal: |distance - 1.0| < 1e-10
- Opposite: |distance - 2.0| < 1e-10

**Traces:** REQ-032

---

### TEST-046: Distance Metric Constant-Time

**Objective:** Verify distance calculations are constant-time

**Test Type:** Timing analysis

**Procedure:**
1. Compute distances for vectors with:
   - All zeros
   - All ones
   - Random values
   - Maximum distance
2. Statistical analysis of timing distributions

**Pass Criteria:**
- No statistically significant timing difference (p > 0.05)
- Max variance < 1μs

**Traces:** REQ-032

---

### TEST-047: Registry Registration

**Objective:** Verify model registration works correctly

**Test Type:** Unit test

**Procedure:**
1. Register model with valid configuration
2. Verify model retrievable by ID
3. Verify registration metadata correct
4. Attempt duplicate registration
5. Verify error returned

**Pass Criteria:**
- Registration succeeds for valid model
- Duplicate returns error
- Metadata preserved correctly

**Traces:** REQ-033

---

### TEST-048: Registry Concurrent Access

**Objective:** Verify registry handles concurrent operations

**Test Type:** Stress test

**Procedure:**
1. Spawn 50 reader threads (get operations)
2. Spawn 10 writer threads (register operations)
3. Run for 10 seconds
4. Verify no deadlocks or corruption

**Pass Criteria:**
- All operations complete
- Final state consistent

**Traces:** REQ-033

---

### TEST-049: Parameterized Circuit Dimensions

**Objective:** Verify circuit works for all dimension tiers

**Test Type:** Circuit test

**Procedure:**
For each dimension [64, 128, 256, 384, 512, 768, 1024]:
1. Create circuit with random witness
2. Generate proof
3. Verify proof
4. Measure constraint count

**Pass Criteria:**
- All dimension tiers produce valid proofs
- Constraint counts match estimates

**Traces:** REQ-034

---

### TEST-050: Circuit Dimension Mismatch Detection

**Objective:** Verify circuit detects dimension mismatches

**Test Type:** Negative test

**Procedure:**
1. Enroll with 512-dim circuit
2. Attempt verification with 768-dim circuit
3. Verify rejection with clear error

**Pass Criteria:**
- Mismatch detected before proof generation
- Error message indicates dimension issue

**Traces:** REQ-034

---

### TEST-051: Proof Size Consistency

**Objective:** Verify proof size is constant regardless of dimension

**Test Type:** Unit test

**Procedure:**
1. Generate proofs for all dimension tiers
2. Measure proof size in bytes
3. Verify all are 192 bytes (Groth16)

**Pass Criteria:**
- All proofs exactly 192 bytes

**Traces:** REQ-034

---

### TEST-052: Input Type Validation

**Objective:** Verify BiometricInput validates modality constraints

**Test Type:** Unit test

**Procedure:**
1. Create PalmVeinExtractor
2. Pass FaceInputData
3. Verify ModalityMismatch error

**Pass Criteria:**
- Mismatch detected at validation
- Error before extraction attempted

**Traces:** REQ-035

---

### TEST-053: Input Zeroization

**Objective:** Verify BiometricInput is zeroized on drop

**Test Type:** Memory test

**Procedure:**
1. Create BiometricInput with known values
2. Get raw pointer to data
3. Drop the input
4. Read memory at pointer
5. Verify zeroed

**Pass Criteria:**
- Memory contains zeros after drop

**Traces:** REQ-035

---

### TEST-054: Embedding Validation

**Objective:** Verify Embedding validates its invariants

**Test Type:** Unit test

**Procedure:**
1. Create embedding with dimension mismatch
2. Create embedding with non-normalized values
3. Verify validation catches both

**Pass Criteria:**
- Dimension mismatch: Error
- Non-normalized: Error or auto-fix with warning

**Traces:** REQ-036

---

### TEST-055: Embedding Zeroization

**Objective:** Verify Embedding values are zeroized on drop

**Test Type:** Memory test

**Procedure:**
1. Create Embedding
2. Drop it
3. Verify values memory zeroed

**Pass Criteria:**
- Embedding values zeroed after drop

**Traces:** REQ-036

---

### TEST-056: Version Compatibility Matrix

**Objective:** Verify version compatibility rules

**Test Type:** Unit test

**Setup:**
| Enrolled | Verification | Expected |
|----------|--------------|----------|
| 1.0.0 | 1.0.0 | Compatible |
| 1.0.0 | 1.0.1 | Compatible |
| 1.0.0 | 1.1.0 | Compatible |
| 1.0.0 | 2.0.0 | Incompatible |
| 1.2.0 | 1.1.0 | Incompatible |

**Procedure:**
1. Test each combination
2. Verify result matches expected

**Pass Criteria:**
- All combinations return correct result

**Traces:** REQ-037

---

### TEST-057: Version Mismatch Handling

**Objective:** Verify graceful handling of version mismatches

**Test Type:** Integration test

**Procedure:**
1. Enroll with version 1.0.0
2. Upgrade extractor to version 2.0.0
3. Attempt verification
4. Verify clear "re-enrollment required" error

**Pass Criteria:**
- Error clearly indicates version mismatch
- Suggests re-enrollment action

**Traces:** REQ-037

---

### TEST-058: PalmVeinExtractor Output

**Objective:** Verify PalmVeinExtractor produces correct embeddings

**Test Type:** Integration test

**Procedure:**
1. Process reference palm image
2. Verify 512-dimension output
3. Verify L2 normalized
4. Verify deterministic (same input = same output)

**Pass Criteria:**
- Dimension = 512
- L2 norm = 1.0
- Deterministic output

**Traces:** REQ-038

---

### TEST-059: MockEmbedding Determinism

**Objective:** Verify MockEmbedding produces deterministic output

**Test Type:** Unit test

**Procedure:**
1. Create MockEmbedding
2. Extract embedding from same input twice
3. Verify identical results

**Pass Criteria:**
- Embeddings exactly equal

**Traces:** REQ-038

---

### TEST-060: Built-in Registration

**Objective:** Verify all built-in extractors register successfully

**Test Type:** Integration test

**Procedure:**
1. Create fresh registry
2. Call register_builtins()
3. Verify all expected models present
4. Verify models functional

**Pass Criteria:**
- All built-ins registered
- All produce valid embeddings

**Traces:** REQ-038

---

### TEST-061: ONNX Model Loading

**Objective:** Verify ONNX models load correctly

**Test Type:** Integration test

**Setup:**
- Sample ONNX model (MobileNetV2 feature extractor)

**Procedure:**
1. Load model with configuration
2. Verify dimension matches config
3. Extract embedding from test image
4. Verify output dimension correct

**Pass Criteria:**
- Model loads without error
- Extraction produces correct dimension

**Traces:** REQ-039

---

### TEST-062: ONNX Invalid Model Rejection

**Objective:** Verify invalid ONNX models are rejected

**Test Type:** Negative test

**Setup:**
- Corrupted .onnx file
- Model with wrong output shape
- Model with unsupported ops

**Procedure:**
1. Attempt to load each invalid model
2. Verify appropriate error returned

**Pass Criteria:**
- Corrupted: Load error
- Wrong shape: Validation error
- Unsupported ops: Runtime error

**Traces:** REQ-039

---

### TEST-063: ONNX Inference Timeout

**Objective:** Verify ONNX inference respects timeout

**Test Type:** Integration test

**Setup:**
- Model with slow inference (or artificially delayed)
- Timeout set to 100ms

**Procedure:**
1. Trigger extraction
2. Verify timeout error after ~100ms

**Pass Criteria:**
- Extraction fails with timeout error
- Returns within 2x timeout period

**Traces:** REQ-039

---

### TEST-064: Extraction Latency Benchmarks

**Objective:** Measure extraction latency for all extractor types

**Test Type:** Performance benchmark

**Procedure:**
1. For each extractor type:
   - Run 1000 extractions
   - Measure P50, P95, P99 latency
2. Compare against NFR-030 targets

**Pass Criteria:**
- All extractors meet latency targets

**Traces:** NFR-030

---

### TEST-065: Memory Footprint Measurement

**Objective:** Measure memory usage per extractor

**Test Type:** Memory profiling

**Procedure:**
1. Baseline memory before loading
2. Load each extractor
3. Measure delta
4. Run extraction, measure peak
5. Compare against NFR-031

**Pass Criteria:**
- All extractors within memory budget

**Traces:** NFR-031

---

### TEST-066: Hot-Swap Without Downtime

**Objective:** Verify extractors can be swapped at runtime

**Test Type:** Integration test

**Procedure:**
1. Start with ExtractorV1
2. Register ExtractorV2 while V1 active
3. Switch traffic to V2
4. Unregister V1
5. Verify zero failed requests

**Pass Criteria:**
- All requests during swap succeed
- No observable downtime

**Traces:** NFR-032

---

### TEST-067: Embedding Determinism Verification

**Objective:** Verify embeddings are deterministic

**Test Type:** Unit test

**Procedure:**
1. Extract embedding from input 10 times
2. Compute variance across extractions
3. Verify variance < 1e-10

**Pass Criteria:**
- All extractions produce identical embeddings

**Traces:** NFR-033

---

### TEST-068: Face Detection Accuracy

**Objective:** Verify face detection finds faces reliably

**Test Type:** Integration test with face dataset

**Setup:**
- LFW (Labeled Faces in the Wild) test subset
- Images with varying pose, lighting, occlusion

**Procedure:**
1. Run face detection on 1000 images with known face locations
2. Compare detected bounding boxes to ground truth
3. Calculate precision, recall, IoU

**Pass Criteria:**
- Precision ≥ 99%
- Recall ≥ 95%
- Mean IoU ≥ 0.85

**Traces:** REQ-040

---

### TEST-069: Face Detection Latency

**Objective:** Verify face detection meets latency targets

**Test Type:** Performance test

**Procedure:**
1. Run face detection on 100 frames
2. Measure detection time per frame
3. Compute statistics

**Pass Criteria:**
- P50 < 10ms
- P95 < 20ms

**Traces:** REQ-040

---

### TEST-070: Face Alignment Consistency

**Objective:** Verify aligned faces have consistent eye positions

**Test Type:** Unit test

**Procedure:**
1. Align same face from different source images
2. Measure eye position in output
3. Verify consistency

**Pass Criteria:**
- Eye positions within ±2 pixels across alignments

**Traces:** REQ-041

---

### TEST-071: Face Alignment with Head Rotation

**Objective:** Verify alignment handles rotated faces

**Test Type:** Unit test

**Setup:**
- Face images at 0°, ±15°, ±30° yaw

**Procedure:**
1. Align each rotated face
2. Verify output is frontal
3. Measure eye position accuracy

**Pass Criteria:**
- Handles up to ±30° yaw
- Eye positions correct within ±3 pixels

**Traces:** REQ-041

---

### TEST-072: MobileFaceNet Embedding Extraction

**Objective:** Verify MobileFaceNet produces valid embeddings

**Test Type:** Integration test

**Procedure:**
1. Load MobileFaceNet model
2. Extract embedding from test face
3. Verify dimension, normalization

**Pass Criteria:**
- Embedding dimension = 128
- L2 norm = 1.0 ± 1e-6
- Inference time ≤ 30ms

**Traces:** REQ-042

---

### TEST-073: Face Embedding Similarity - Same Person

**Objective:** Verify same person embeddings are similar

**Test Type:** Integration test

**Setup:**
- 10 different photos of same person

**Procedure:**
1. Extract embeddings from all photos
2. Compute pairwise cosine similarity
3. Verify all pairs exceed threshold

**Pass Criteria:**
- All same-person pairs have cosine similarity > 0.6

**Traces:** REQ-042

---

### TEST-074: Face Embedding Dissimilarity - Different People

**Objective:** Verify different people have distinct embeddings

**Test Type:** Integration test

**Setup:**
- Photos of 100 different people

**Procedure:**
1. Extract embeddings from each person
2. Compute cross-person similarities
3. Verify below threshold

**Pass Criteria:**
- All different-person pairs have cosine similarity < 0.4

**Traces:** REQ-042

---

### TEST-075: Face Quality - Blur Detection

**Objective:** Verify blur detection rejects motion-blurred images

**Test Type:** Unit test

**Setup:**
- Sharp face image
- Same image with Gaussian blur (various σ)
- Same image with motion blur

**Procedure:**
1. Assess quality of each image
2. Verify sharp image passes
3. Verify blurred images fail

**Pass Criteria:**
- Sharp image: blur score ≥ 0.7
- σ=3 blur: blur score < 0.5
- Motion blur: blur score < 0.4

**Traces:** REQ-043

---

### TEST-076: Face Quality - Pose Rejection

**Objective:** Verify non-frontal poses are scored appropriately

**Test Type:** Unit test

**Setup:**
- Faces at various yaw angles (0°, 15°, 30°, 45°, 60°)

**Procedure:**
1. Assess quality of each pose
2. Verify score decreases with angle

**Pass Criteria:**
- 0° yaw: pose score ≥ 0.9
- 30° yaw: pose score ≥ 0.6
- 45° yaw: pose score < 0.5

**Traces:** REQ-043

---

### TEST-077: Face Liveness - Printed Photo Detection

**Objective:** Verify printed photos are rejected

**Test Type:** Presentation attack test

**Setup:**
- 100 printed photos (various paper types, printers)
- 100 genuine live faces

**Procedure:**
1. Run liveness detection on all samples
2. Calculate detection rates

**Pass Criteria:**
- Print detection ≥ 95%
- False rejection ≤ 3%

**Traces:** REQ-044

---

### TEST-078: Face Liveness - Screen Display Detection

**Objective:** Verify screen-displayed faces are rejected

**Test Type:** Presentation attack test

**Setup:**
- Face images displayed on LCD, OLED screens
- Various screen sizes and refresh rates

**Procedure:**
1. Capture screen-displayed faces
2. Run liveness detection
3. Verify rejection

**Pass Criteria:**
- Screen detection ≥ 92%

**Traces:** REQ-044

---

### TEST-079: Face Liveness - Blink Detection

**Objective:** Verify blink detection works reliably

**Test Type:** Integration test

**Setup:**
- Video sequences with natural blinks
- Video sequences without blinks (eyes always open)

**Procedure:**
1. Run blink detection on sequences
2. Verify blinks detected in genuine sequences
3. Verify no false positives in eyes-open sequences

**Pass Criteria:**
- Blink detection accuracy ≥ 98%
- False positive rate ≤ 2%

**Traces:** REQ-044

---

### TEST-080: Face Image Not Persisted

**Objective:** Verify face images are never written to disk

**Test Type:** Security audit test

**Procedure:**
1. Perform face enrollment and authentication
2. Search filesystem for image files
3. Monitor file system writes during operation

**Pass Criteria:**
- No face images found on disk
- No writes to persistent storage during biometric operations

**Traces:** REQ-045

---

### TEST-081: Face Embedding Zeroization

**Objective:** Verify face embeddings are zeroized after use

**Test Type:** Memory test

**Procedure:**
1. Extract face embedding
2. Use embedding for commitment
3. Force drop of embedding
4. Scan memory for embedding values

**Pass Criteria:**
- Embedding memory contains zeros after drop

**Traces:** REQ-045

---

## Observability Requirements

### OBS-030: Model Registry Metrics

**Metrics:**

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `sable_embedding_registry_models_total` | Gauge | status, modality | Number of registered models |
| `sable_embedding_registry_registrations_total` | Counter | result | Registration attempts |
| `sable_embedding_registry_lookups_total` | Counter | model_id, result | Model lookup attempts |

**Logs:**

| Event | Level | Fields |
|-------|-------|--------|
| model_registered | INFO | model_id, version, modality, dimension, registered_by |
| model_deprecated | WARN | model_id, version, reason |
| model_disabled | WARN | model_id, version, reason |

**Traces:** REQ-033

---

### OBS-031: Version Compatibility Events

**Metrics:**

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `sable_embedding_version_checks_total` | Counter | result | Version compatibility checks |
| `sable_embedding_version_mismatches_total` | Counter | enrolled_major, current_major | Mismatch events |

**Logs:**

| Event | Level | Fields |
|-------|-------|--------|
| version_compatible | DEBUG | enrolled, current |
| version_mismatch | WARN | enrolled, current, action_required |

**Traces:** REQ-037

---

### OBS-032: Extraction Latency

**Metrics:**

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `sable_embedding_extraction_duration_ms` | Histogram | model_id, modality | Extraction latency |
| `sable_embedding_extraction_success_total` | Counter | model_id | Successful extractions |
| `sable_embedding_extraction_failure_total` | Counter | model_id, error_type | Failed extractions |

**Traces:** NFR-030

---

### OBS-033: Memory Usage

**Metrics:**

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `sable_embedding_model_memory_bytes` | Gauge | model_id | Memory per loaded model |
| `sable_embedding_extraction_peak_memory_bytes` | Histogram | model_id | Peak memory during extraction |

**Traces:** NFR-031

---

### OBS-034: Hot-Swap Events

**Metrics:**

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `sable_embedding_hotswap_total` | Counter | result | Hot-swap attempts |
| `sable_embedding_hotswap_duration_ms` | Histogram | - | Time to complete swap |

**Logs:**

| Event | Level | Fields |
|-------|-------|--------|
| hotswap_started | INFO | old_model_id, new_model_id |
| hotswap_completed | INFO | old_model_id, new_model_id, duration_ms |
| hotswap_failed | ERROR | old_model_id, new_model_id, error |

**Traces:** NFR-032

---

### OBS-035: Face Biometric Metrics

**Metrics:**

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `sable_face_detection_duration_ms` | Histogram | backend | Face detection latency |
| `sable_face_detection_count` | Counter | result | Detection outcomes (found/not_found) |
| `sable_face_alignment_duration_ms` | Histogram | - | Face alignment latency |
| `sable_face_embedding_duration_ms` | Histogram | model_id | Embedding extraction latency |
| `sable_face_quality_score` | Histogram | - | Quality score distribution |
| `sable_face_quality_rejection_total` | Counter | reason | Quality rejection reasons |
| `sable_face_liveness_result_total` | Counter | result, check_type | Liveness check outcomes |
| `sable_face_liveness_attack_detected_total` | Counter | attack_type | Detected attack types |

**Logs:**

| Event | Level | Fields |
|-------|-------|--------|
| face_detected | DEBUG | confidence, bbox, landmarks_count |
| face_not_detected | WARN | frame_quality |
| face_quality_rejected | INFO | overall_score, issues |
| face_liveness_passed | INFO | confidence, checks_passed |
| face_liveness_failed | WARN | confidence, attack_type |
| face_embedding_extracted | DEBUG | model_id, dimension, quality |

**Privacy Note:** Face images and embeddings are NEVER logged. Only metadata
and aggregate metrics are captured.

**Traces:** REQ-040, REQ-042, REQ-043, REQ-044, REQ-045

---

## Implementation Plan

### Phase 1: Core Abstractions (Week 1-2)

1. Define `BiometricEmbedding` trait
2. Define `Embedding` struct with normalization
3. Define `BiometricInput` enum
4. Define `DistanceMetric` with implementations
5. Define `Version` with compatibility rules
6. Unit tests for all core types

### Phase 2: Model Registry (Week 3)

1. Implement `EmbeddingRegistry`
2. Add concurrent access handling
3. Implement registration validation
4. Add observability hooks
5. Integration tests

### Phase 3: Refactor Built-ins (Week 4-5)

1. Wrap `PalmVeinExtractor` in trait
2. Wrap `PalmPrintExtractor` in trait
3. Wrap `FusedPalmExtractor` in trait
4. Create `MockEmbedding` for testing
5. Migrate existing code to use registry
6. Backward compatibility tests

### Phase 4: Parameterized Circuits (Week 6-7)

1. Refactor `BiometricCircuit` to const generic
2. Create circuit type aliases for tiers
3. Generate proving keys for each tier
4. Update proof generation to use routing
5. Circuit tests for all dimensions

### Phase 5: ONNX Integration (Week 8-9)

1. Add ort (ONNX Runtime) dependency
2. Implement `OnnxEmbedding`
3. Implement preprocessing pipeline
4. Add execution provider selection
5. Integration tests with sample models

### Phase 6: Documentation & Migration (Week 10)

1. API documentation
2. Migration guide from v1
3. Example implementations
4. Performance benchmarks
5. Security review

### Phase 7: Face Detection & Alignment (Week 11-12)

1. Integrate face detection backend (MediaPipe or ML Kit)
2. Implement `FaceDetector` trait and concrete implementations
3. Implement 5-point landmark detection
4. Build face alignment pipeline with affine transformation
5. Implement `FaceAligner` with 112x112 normalized output
6. Add quality assessment for detected faces
7. Unit tests for detection and alignment
8. Device compatibility tests (Android/iOS)

### Phase 8: Face Embedding Extraction (Week 13-14)

1. Implement `MobileFaceNetExtractor` (128-dim, TFLite)
2. Implement `FaceNetExtractor` (512-dim, ONNX)
3. Implement `ArcFaceExtractor` (512-dim, ONNX)
4. Add model loading and caching
5. Implement preprocessing pipeline (normalization, tensor conversion)
6. Add execution provider selection (CPU/GPU/NPU)
7. Integration tests with reference face images
8. Embedding quality validation tests

### Phase 9: Face Quality & Liveness (Week 15-16)

1. Implement `FaceQualityAssessor` with ICAO-compliant checks
2. Add pose angle estimation and validation
3. Add illumination quality assessment
4. Add occlusion detection (glasses, masks)
5. Implement face liveness detection (blink, texture analysis)
6. Integrate liveness signals into ZK proof pipeline
7. Anti-spoofing tests (print, screen, 3D mask)
8. End-to-end face verification tests

### Phase 10: Face Privacy & Integration (Week 17-18)

1. Implement face image immediate disposal
2. Add embedding encryption for at-rest storage
3. Integrate face extractors with `EmbeddingRegistry`
4. Add face biometric circuits to dimension tiers
5. Update proof generation for face modality
6. Cross-modality fusion support (palm + face)
7. Privacy compliance validation
8. Full security review for face pipeline

---

## References

1. ONNX Runtime - https://onnxruntime.ai/
2. TensorFlow Lite - https://www.tensorflow.org/lite
3. FaceNet: A Unified Embedding for Face Recognition - Schroff et al. (2015)
4. ArcFace: Additive Angular Margin Loss - Deng et al. (2019)
5. Semantic Versioning 2.0.0 - https://semver.org/
6. MobileFaceNets: Efficient CNNs for Accurate Real-Time Face Verification - Chen et al. (2018)
7. MediaPipe Face Detection - https://developers.google.com/mediapipe/solutions/vision/face_detector
8. ICAO Doc 9303: Machine Readable Travel Documents - Part 9: Deployment of Biometric Data
9. ISO/IEC 19795-1: Biometric Performance Testing and Reporting

---

**Document Version:** 1.1.0
**Last Updated:** 2026-02-03
**Author:** SABLE Development Team
**Review Status:** Pending stakeholder validation
