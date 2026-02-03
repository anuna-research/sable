# SPEC-003: Platform Security Integration

## Overview

This specification defines the integration of SABLE with native platform security
features on Android and iOS. The integration leverages hardware-backed key storage,
biometric-bound access controls, and device attestation to provide defense-in-depth
security while maintaining SABLE's privacy-preserving properties.

**Key Insight:** Platform biometric APIs (Face ID, Touch ID, Android BiometricPrompt)
do not provide raw biometric data—they only return authentication results. SABLE
uses these APIs to **protect enrollment data**, not to generate ZK proofs.

**Architecture:**

```
┌─────────────────────────────────────────────────────────────┐
│                    SABLE Authentication                      │
├─────────────────────────────────────────────────────────────┤
│  Platform Biometric ──► Unlocks Keys ──► SABLE ZK Proof    │
│  (Face ID, etc.)        (in TEE/SE)      (palm biometric)   │
└─────────────────────────────────────────────────────────────┘
```

---

## User Profiles

### User: Security-Conscious Consumer

**Role:** End user authenticating on personal mobile device

**Goals:**
- Single gesture authentication (no passwords)
- Assurance that biometric data cannot be stolen
- Works even if phone is compromised at OS level
- Seamless experience across app updates

**Constraints:**
- May have older device without StrongBox/Secure Enclave
- May disable platform biometrics for privacy reasons
- Expects instant authentication (< 2 seconds)

**Daily Workflow:**
1. Opens banking/identity app
2. Platform biometric prompt appears (Face ID or fingerprint)
3. Upon success, palm scanner activates
4. Places palm over sensor
5. ZK proof generated and verified
6. Access granted

---

### User: Enterprise Security Architect

**Role:** Designs authentication policies for regulated organization

**Goals:**
- Verify device integrity before allowing authentication
- Ensure keys are hardware-backed (not software-extractable)
- Audit trail of device security posture
- Compliance with NIST 800-63B AAL3

**Constraints:**
- Must support diverse device fleet (Android 8+ to 14, iOS 14+)
- Cannot mandate specific device models
- Must handle rooted/jailbroken device detection
- Regulatory requirement for hardware attestation

---

### User: Mobile App Developer

**Role:** Integrates SABLE SDK into application

**Goals:**
- Simple API that abstracts platform differences
- Clear error handling for missing hardware features
- Graceful degradation on older devices
- Testable without physical secure hardware

**Constraints:**
- Cannot access raw platform biometric data
- Must handle permission requests correctly
- App Store/Play Store policy compliance
- Minimize SDK binary size

---

## Happy Path: Biometric-Protected Enrollment

**Preconditions:**
- User has device with Face ID/Touch ID or Android BiometricPrompt
- Platform biometrics enrolled on device
- SABLE SDK initialized

**Steps:**

1. User initiates SABLE enrollment
   → App requests platform biometric authentication
   → User authenticates with Face ID/fingerprint

2. Platform unlocks key generation capability
   → SABLE generates enrollment key pair in TEE/Secure Enclave
   → Key bound to biometric authentication requirement

3. User captures palm biometric via SABLE sensor
   → 512-dim embedding extracted
   → Pedersen commitment generated

4. SABLE encrypts sensitive enrollment data
   → Commitment salt encrypted with hardware-backed key
   → Encrypted data stored in app keychain/keystore
   → Raw salt never touches main memory unencrypted

5. Enrollment complete
   → User can now authenticate with palm + platform biometric

**Postconditions:**
- Enrollment data protected by hardware security
- Salt only accessible after biometric authentication
- Keys bound to this specific device (non-exportable)

---

## Happy Path: Biometric-Protected Authentication

**Preconditions:**
- User previously enrolled
- Device security posture unchanged (not rooted/jailbroken)

**Steps:**

1. User initiates authentication
   → App checks device attestation (optional, policy-based)
   → If attestation fails, authentication blocked

2. Platform biometric prompt displayed
   → "Authenticate to access SABLE identity"
   → User provides Face ID/fingerprint

3. Platform unlocks SABLE enrollment key
   → Decryption key available in secure hardware
   → Salt decrypted within TEE/Secure Enclave

4. SABLE palm biometric captured
   → Embedding extracted
   → Commitment generated using decrypted salt

5. ZK proof generated
   → Proves biometric match without revealing data
   → Proof includes freshness (timestamp, nonce)

6. Proof verified by relying party
   → Authentication succeeds

**Postconditions:**
- User authenticated with two factors (platform biometric + palm)
- No biometric data transmitted
- Salt re-encrypted/cleared from secure memory

---

## Happy Path: Hardware Attestation Verification

**Preconditions:**
- Server configured with attestation root certificates
- Device supports key attestation (Android 7+) or App Attest (iOS 14+)

**Steps:**

1. Server generates attestation challenge
   → Random nonce sent to device

2. Device generates attestation
   → Creates key pair with challenge embedded
   → TEE/SE signs attestation certificate chain

3. Device sends attestation to server
   → Certificate chain + key attestation extension

4. Server validates attestation
   → Verifies chain to Google/Apple root
   → Checks security level (TEE, StrongBox, Secure Enclave)
   → Verifies device not rooted/jailbroken (via verified boot state)
   → Checks challenge matches

5. Server records device security posture
   → Allows/denies based on policy

**Postconditions:**
- Server has cryptographic proof of device security
- Can enforce "hardware-backed keys only" policy
- Attestation result cached (with expiry)

---

## Requirements

### REQ-050: Cross-Platform Security Abstraction

The system SHALL provide a unified abstraction layer FOR platform security features
WITH consistent behavior across Android and iOS.

**Abstraction Interface:**

```rust
/// Cross-platform secure key storage and biometric authentication
pub trait PlatformSecurity: Send + Sync {
    /// Check if hardware-backed key storage is available
    fn has_hardware_security(&self) -> HardwareSecurityLevel;

    /// Check if biometric authentication is available and enrolled
    fn biometric_status(&self) -> BiometricStatus;

    /// Generate a biometric-protected key pair
    fn generate_protected_key(
        &self,
        key_id: &str,
        config: KeyConfig,
    ) -> Result<KeyHandle>;

    /// Encrypt data using biometric-protected key
    /// Triggers biometric prompt if key requires authentication
    fn encrypt(
        &self,
        key_handle: &KeyHandle,
        plaintext: &[u8],
        auth_context: &AuthContext,
    ) -> Result<EncryptedData>;

    /// Decrypt data using biometric-protected key
    /// Triggers biometric prompt if key requires authentication
    fn decrypt(
        &self,
        key_handle: &KeyHandle,
        ciphertext: &EncryptedData,
        auth_context: &AuthContext,
    ) -> Result<Vec<u8>>;

    /// Request device attestation
    fn attest(
        &self,
        challenge: &[u8],
        config: AttestationConfig,
    ) -> Result<Attestation>;

    /// Delete a key from secure storage
    fn delete_key(&self, key_id: &str) -> Result<()>;
}

/// Hardware security capability levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum HardwareSecurityLevel {
    /// No hardware security (software-only keys)
    None,
    /// Trusted Execution Environment (Android TEE, older iOS)
    Tee,
    /// Dedicated secure element (Android StrongBox, iOS Secure Enclave)
    SecureElement,
}

/// Biometric enrollment and availability status
#[derive(Debug, Clone)]
pub struct BiometricStatus {
    pub available: bool,
    pub enrolled: bool,
    pub biometric_type: BiometricType,
    pub strong_biometric: bool,  // Class 3 on Android
}

#[derive(Debug, Clone, Copy)]
pub enum BiometricType {
    None,
    Fingerprint,
    Face,
    Iris,
    Multiple,  // Device supports multiple types
}
```

**Acceptance Criteria:**
- AC-1: Same API works on Android (API 23+) and iOS (13+)
- AC-2: Platform-specific errors mapped to unified error types
- AC-3: Graceful degradation when hardware security unavailable
- AC-4: No platform-specific code in SABLE core
- AC-5: Mock implementation available for testing

**Trace:**
- TEST-070, TEST-071
- CON-050
- ADR-006

---

### REQ-051: Biometric-Bound Key Generation

The system SHALL generate cryptographic keys bound to biometric authentication
FOR protecting SABLE enrollment data WITH the following properties.

**Key Properties:**

| Property | Android | iOS | Requirement |
|----------|---------|-----|-------------|
| Algorithm | AES-256-GCM | AES-256-GCM | Symmetric encryption |
| Storage | AndroidKeyStore | Keychain | Platform secure storage |
| Hardware backing | TEE/StrongBox | Secure Enclave | When available |
| Auth binding | `setUserAuthenticationRequired(true)` | `biometryCurrentSet` | Requires biometric |
| Auth validity | 0 (every use) | Per-operation | No timeout caching |
| Exportable | Never | Never | Keys stay in hardware |

**Key Configuration:**

```rust
pub struct KeyConfig {
    /// Unique identifier for this key
    pub key_id: String,

    /// Require biometric authentication for every use
    pub require_biometric: bool,

    /// Allow device passcode as fallback
    pub allow_passcode_fallback: bool,

    /// Invalidate key if biometrics change (re-enrollment)
    pub invalidate_on_biometric_change: bool,

    /// Require hardware backing (fail if unavailable)
    pub require_hardware_backing: bool,

    /// Android: prefer StrongBox over TEE
    pub prefer_strongbox: bool,
}

impl Default for KeyConfig {
    fn default() -> Self {
        Self {
            key_id: String::new(),
            require_biometric: true,
            allow_passcode_fallback: false,
            invalidate_on_biometric_change: true,
            require_hardware_backing: false,  // Graceful degradation
            prefer_strongbox: true,
        }
    }
}
```

**Acceptance Criteria:**
- AC-1: Keys generated in hardware when available
- AC-2: Keys require biometric auth for every crypto operation
- AC-3: Keys invalidated when biometrics re-enrolled
- AC-4: Keys non-exportable (cannot be extracted from device)
- AC-5: Key generation fails gracefully on unsupported devices

**Trace:**
- TEST-072, TEST-073, TEST-074
- CON-051

---

### REQ-052: SABLE Enrollment Data Protection

The system SHALL encrypt SABLE enrollment data using biometric-protected keys
FOR preventing unauthorized access WITH the following data protection scheme.

**Protected Data:**

| Data | Sensitivity | Protection | Storage |
|------|-------------|------------|---------|
| Commitment salt (256-bit) | Critical | AES-256-GCM, biometric-bound | Keychain/Keystore |
| Model ID | Low | Plaintext | App preferences |
| Model version | Low | Plaintext | App preferences |
| Enrollment timestamp | Low | Plaintext | App preferences |
| Commitment (public) | None | Plaintext | App storage |

**Encryption Flow:**

```
┌─────────────────────────────────────────────────────────────┐
│                    Enrollment Flow                           │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  [Salt Generated] ──► [Encrypt with HW Key] ──► [Store]     │
│        │                      │                    │         │
│        │              [Biometric Required]         │         │
│        │                      │                    │         │
│        ▼                      ▼                    ▼         │
│   256-bit random      TEE/Secure Enclave    Keychain/       │
│   (SecureRng)         AES-256-GCM           Keystore        │
│                                                              │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                  Authentication Flow                         │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  [Load Encrypted] ──► [Biometric Prompt] ──► [Decrypt]      │
│        │                      │                    │         │
│        │              [User Authenticates]         │         │
│        │                      │                    │         │
│        ▼                      ▼                    ▼         │
│   From Keychain/      Face ID/Fingerprint    Salt in        │
│   Keystore            unlocks key            secure memory  │
│                                                              │
│                              │                               │
│                              ▼                               │
│                    [Generate ZK Proof]                       │
│                              │                               │
│                              ▼                               │
│                    [Zeroize Salt]                            │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

**Acceptance Criteria:**
- AC-1: Salt never exists in plaintext outside secure hardware
- AC-2: Decryption requires successful biometric authentication
- AC-3: Decrypted salt zeroized immediately after proof generation
- AC-4: Multiple enrollments supported (different identities)
- AC-5: Enrollment data migrates correctly on app update

**Trace:**
- TEST-075, TEST-076, TEST-077
- CON-052

---

### REQ-053: Android Keystore Integration

The system SHALL integrate with Android Keystore FOR key storage and biometric
binding WITH support for API level 23+ and StrongBox when available.

**Android-Specific Implementation:**

```kotlin
// Key generation with biometric binding
val keyGenerator = KeyGenerator.getInstance(
    KeyProperties.KEY_ALGORITHM_AES,
    "AndroidKeyStore"
)

val builder = KeyGenParameterSpec.Builder(
    keyAlias,
    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
)
    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
    .setKeySize(256)
    .setUserAuthenticationRequired(true)
    .setUserAuthenticationParameters(
        0,  // Timeout: 0 = every use
        KeyProperties.AUTH_BIOMETRIC_STRONG
    )
    .setInvalidatedByBiometricEnrollment(true)

// Request StrongBox if available (API 28+)
if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
    builder.setIsStrongBoxBacked(true)
}

keyGenerator.init(builder.build())
val secretKey = keyGenerator.generateKey()
```

**BiometricPrompt Integration:**

```kotlin
val biometricPrompt = BiometricPrompt(
    activity,
    executor,
    object : BiometricPrompt.AuthenticationCallback() {
        override fun onAuthenticationSucceeded(result: AuthenticationResult) {
            // Cipher now authorized for one operation
            val cipher = result.cryptoObject?.cipher
            val decrypted = cipher?.doFinal(encryptedSalt)
            // Use salt for SABLE proof generation
            // Zeroize immediately after
        }
    }
)

val promptInfo = BiometricPrompt.PromptInfo.Builder()
    .setTitle("SABLE Authentication")
    .setSubtitle("Verify identity to continue")
    .setNegativeButtonText("Cancel")
    .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
    .build()

val cipher = Cipher.getInstance("AES/GCM/NoPadding")
cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(128, iv))

biometricPrompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
```

**Acceptance Criteria:**
- AC-1: Works on Android API 23+ (Marshmallow and later)
- AC-2: Uses StrongBox on API 28+ when available
- AC-3: Falls back to TEE when StrongBox unavailable
- AC-4: Handles `StrongBoxUnavailableException` gracefully
- AC-5: Uses `BIOMETRIC_STRONG` (Class 3) authenticators only

**Trace:**
- TEST-078, TEST-079, TEST-080
- CON-053

---

### REQ-054: iOS Secure Enclave Integration

The system SHALL integrate with iOS Secure Enclave and LocalAuthentication
FOR key storage and biometric binding WITH support for iOS 13+.

**iOS-Specific Implementation:**

```swift
// Key generation with biometric binding
let access = SecAccessControlCreateWithFlags(
    nil,
    kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    [.privateKeyUsage, .biometryCurrentSet],
    nil
)!

// For symmetric encryption, we use Secure Enclave to wrap a data key
// (SE only supports P-256, so we derive symmetric key from ECDH)
let privateKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(
    accessControl: access
)

// Store key reference in Keychain
let query: [String: Any] = [
    kSecClass as String: kSecClassKey,
    kSecAttrApplicationTag as String: "com.sable.enrollment.\(keyId)",
    kSecValueRef as String: privateKey,
    kSecAttrAccessControl as String: access,
]
SecItemAdd(query as CFDictionary, nil)
```

**LocalAuthentication Integration:**

```swift
let context = LAContext()
context.localizedReason = "Authenticate to access SABLE identity"

// Check biometric availability
var error: NSError?
guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
    throw SableError.biometricUnavailable
}

// Authenticate and access key
context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics,
                       localizedReason: "Verify identity") { success, error in
    guard success else {
        // Handle authentication failure
        return
    }

    // Access Secure Enclave key (now authorized)
    // Key operations will succeed for limited time
}
```

**Key Derivation for Symmetric Encryption:**

```swift
// Secure Enclave only supports P-256, so derive AES key via ECDH
let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(
    with: serverPublicKey
)

let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(
    using: SHA256.self,
    salt: Data(),
    sharedInfo: "SABLE-Enrollment-Key".data(using: .utf8)!,
    outputByteCount: 32
)

// Use symmetricKey for AES-GCM encryption of salt
let sealedBox = try AES.GCM.seal(saltData, using: symmetricKey)
```

**Acceptance Criteria:**
- AC-1: Works on iOS 13+ and macOS 10.15+
- AC-2: Uses Secure Enclave on supported devices (iPhone 5S+)
- AC-3: Keys bound to current biometric enrollment
- AC-4: Keys invalidated on biometric re-enrollment
- AC-5: Handles Secure Enclave unavailable (simulator, old devices)

**Trace:**
- TEST-081, TEST-082, TEST-083
- CON-054

---

### REQ-055: Hardware Attestation

The system SHALL support hardware attestation FOR verifying device security posture
WITH validation of TEE/Secure Enclave key protection.

**Attestation Data Model:**

```rust
/// Device attestation result
pub struct Attestation {
    /// Platform-specific attestation blob
    pub attestation_data: Vec<u8>,

    /// Certificate chain (Android) or attestation object (iOS)
    pub certificate_chain: Vec<Certificate>,

    /// Challenge that was signed
    pub challenge: [u8; 32],

    /// Attestation timestamp
    pub timestamp: Timestamp,

    /// Parsed attestation properties
    pub properties: AttestationProperties,
}

/// Parsed attestation properties (platform-normalized)
pub struct AttestationProperties {
    /// Security level of key storage
    pub security_level: HardwareSecurityLevel,

    /// Device verified boot state
    pub boot_state: BootState,

    /// Whether device is rooted/jailbroken (best effort)
    pub integrity_status: IntegrityStatus,

    /// OS version
    pub os_version: String,

    /// Patch level (Android) or build number (iOS)
    pub patch_level: String,

    /// Device model
    pub device_model: String,

    /// Attestation format version
    pub attestation_version: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootState {
    /// Verified boot chain intact
    Verified,
    /// Boot chain modified (unlocked bootloader)
    Unverified,
    /// Cannot determine boot state
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntegrityStatus {
    /// Device appears unmodified
    Intact,
    /// Device may be rooted/jailbroken
    Compromised,
    /// Cannot determine integrity
    Unknown,
}
```

**Android Key Attestation:**

```kotlin
// Generate attestation key with challenge
val keyPairGenerator = KeyPairGenerator.getInstance(
    KeyProperties.KEY_ALGORITHM_EC,
    "AndroidKeyStore"
)

keyPairGenerator.initialize(
    KeyGenParameterSpec.Builder(attestationKeyAlias, KeyProperties.PURPOSE_SIGN)
        .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
        .setDigests(KeyProperties.DIGEST_SHA256)
        .setAttestationChallenge(challenge)  // Server-provided nonce
        .build()
)

val keyPair = keyPairGenerator.generateKeyPair()

// Get attestation certificate chain
val keyStore = KeyStore.getInstance("AndroidKeyStore")
keyStore.load(null)
val chain = keyStore.getCertificateChain(attestationKeyAlias)

// Parse attestation extension from leaf certificate
val attestationExtension = parseAttestationExtension(chain[0])
// Contains: securityLevel, verifiedBootState, osVersion, patchLevel, etc.
```

**iOS App Attest:**

```swift
// Generate attestation key
let service = DCAppAttestService.shared
guard service.isSupported else {
    throw SableError.attestationUnsupported
}

let keyId = try await service.generateKey()

// Attest key with server challenge
let clientDataHash = Data(SHA256.hash(data: challenge))
let attestation = try await service.attestKey(keyId, clientDataHash: clientDataHash)

// Send attestation to server for validation
// Server verifies against Apple's attestation root
```

**Acceptance Criteria:**
- AC-1: Android Key Attestation supported (API 24+)
- AC-2: iOS App Attest supported (iOS 14+)
- AC-3: Attestation includes server-provided challenge (replay prevention)
- AC-4: Security level (TEE/StrongBox/SE) verifiable
- AC-5: Boot state / integrity status available

**Trace:**
- TEST-084, TEST-085, TEST-086
- CON-055
- ADR-006

---

### REQ-056: Attestation Verification

The system SHALL verify attestation certificates FOR server-side policy enforcement
WITH the following validation steps.

**Verification Flow:**

```
┌─────────────────────────────────────────────────────────────┐
│                 Attestation Verification                     │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  1. Verify Certificate Chain                                 │
│     └── Chain terminates at Google/Apple root CA            │
│                                                              │
│  2. Verify Challenge                                         │
│     └── Challenge in attestation matches server nonce       │
│                                                              │
│  3. Parse Attestation Extension                              │
│     └── Extract security properties from certificate        │
│                                                              │
│  4. Apply Security Policy                                    │
│     ├── Minimum security level (TEE, StrongBox, SE)        │
│     ├── Boot state requirement (verified only)              │
│     ├── Minimum OS/patch level                              │
│     └── Device model allowlist (optional)                   │
│                                                              │
│  5. Return Verification Result                               │
│     ├── Allowed: Device meets policy                        │
│     └── Denied: Policy violation (with reason)              │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

**Verification API:**

```rust
pub struct AttestationVerifier {
    /// Google hardware attestation root certificates
    google_roots: Vec<Certificate>,
    /// Apple App Attest root certificates
    apple_roots: Vec<Certificate>,
    /// Security policy to enforce
    policy: AttestationPolicy,
}

pub struct AttestationPolicy {
    /// Minimum required security level
    pub min_security_level: HardwareSecurityLevel,
    /// Require verified boot
    pub require_verified_boot: bool,
    /// Minimum Android API level
    pub min_android_api: Option<u32>,
    /// Minimum Android security patch
    pub min_android_patch: Option<String>,
    /// Minimum iOS version
    pub min_ios_version: Option<String>,
    /// Allowed device models (None = all allowed)
    pub allowed_models: Option<Vec<String>>,
    /// Maximum attestation age before re-attestation required
    pub max_attestation_age: Duration,
}

impl AttestationVerifier {
    /// Verify attestation against policy
    pub fn verify(
        &self,
        attestation: &Attestation,
        expected_challenge: &[u8; 32],
    ) -> Result<VerificationResult>;
}

pub enum VerificationResult {
    /// Attestation valid, device meets policy
    Valid(AttestationProperties),
    /// Attestation cryptographically valid but policy violated
    PolicyViolation {
        properties: AttestationProperties,
        violations: Vec<PolicyViolation>,
    },
    /// Attestation invalid (bad signature, expired, etc.)
    Invalid(AttestationError),
}

pub enum PolicyViolation {
    SecurityLevelTooLow { required: HardwareSecurityLevel, actual: HardwareSecurityLevel },
    UnverifiedBoot,
    OsVersionTooOld { required: String, actual: String },
    PatchLevelTooOld { required: String, actual: String },
    DeviceNotAllowed { model: String },
    AttestationExpired { age: Duration },
}
```

**Acceptance Criteria:**
- AC-1: Cryptographic verification of certificate chain
- AC-2: Challenge verification prevents replay attacks
- AC-3: Configurable security policy
- AC-4: Clear violation reporting for debugging
- AC-5: Root certificates updated via configuration (not hardcoded)

**Trace:**
- TEST-087, TEST-088, TEST-089
- CON-056

---

### REQ-057: Graceful Degradation

The system SHALL gracefully degrade FOR devices without hardware security
WITH clear user communication and policy-based decisions.

**Degradation Levels:**

| Level | Hardware | Biometric | Key Storage | Recommendation |
|-------|----------|-----------|-------------|----------------|
| 1 (Best) | StrongBox/SE | Strong | Hardware | Full security |
| 2 | TEE | Strong | Hardware | Acceptable |
| 3 | TEE | Weak | Hardware | Warn user |
| 4 | None | Any | Software | Policy decision |
| 5 | None | None | Software | Discourage use |

**Degradation API:**

```rust
pub struct SecurityAssessment {
    /// Overall security level
    pub level: SecurityLevel,
    /// Detailed capabilities
    pub capabilities: SecurityCapabilities,
    /// Recommendations for user/admin
    pub recommendations: Vec<Recommendation>,
    /// Whether SABLE should proceed
    pub proceed: ProceedDecision,
}

pub struct SecurityCapabilities {
    pub hardware_security: HardwareSecurityLevel,
    pub biometric_strength: BiometricStrength,
    pub attestation_available: bool,
    pub secure_boot_verified: Option<bool>,
}

pub enum SecurityLevel {
    /// Full hardware security
    High,
    /// Hardware security with limitations
    Medium,
    /// Software-only security
    Low,
    /// Insufficient for SABLE
    Insufficient,
}

pub enum ProceedDecision {
    /// Proceed normally
    Allow,
    /// Proceed with warning to user
    AllowWithWarning(String),
    /// Require explicit user consent
    RequireConsent(String),
    /// Block based on policy
    Deny(String),
}

impl PlatformSecurity {
    /// Assess device security capabilities
    fn assess_security(&self) -> SecurityAssessment;
}
```

**Acceptance Criteria:**
- AC-1: Security level assessed before enrollment
- AC-2: User informed of device security limitations
- AC-3: Policy can require minimum security level
- AC-4: Degraded mode still protects against casual attacks
- AC-5: Enterprise can mandate hardware security

**Trace:**
- TEST-090, TEST-091
- CON-057

---

### REQ-058: Biometric Change Detection

The system SHALL detect biometric re-enrollment FOR invalidating compromised keys
WITH automatic re-enrollment workflow.

**Detection Mechanisms:**

| Platform | Mechanism | Behavior |
|----------|-----------|----------|
| Android | `setInvalidatedByBiometricEnrollment(true)` | Key becomes unusable |
| iOS | `.biometryCurrentSet` access control | Key access denied |

**Re-enrollment Flow:**

```
┌─────────────────────────────────────────────────────────────┐
│              Biometric Change Detection                      │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  [User Changes Biometrics on Device]                         │
│                │                                             │
│                ▼                                             │
│  [Next SABLE Auth Attempt]                                   │
│                │                                             │
│                ▼                                             │
│  [Key Access Fails: KeyPermanentlyInvalidatedException]     │
│                │                                             │
│                ▼                                             │
│  [SABLE Detects Biometric Change]                           │
│                │                                             │
│                ▼                                             │
│  [Prompt User for Re-enrollment]                            │
│  "Your device biometrics have changed.                      │
│   Please re-enroll your SABLE identity."                    │
│                │                                             │
│                ▼                                             │
│  [Delete Old Keys] ──► [New Enrollment Flow]                │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

**Acceptance Criteria:**
- AC-1: Biometric change detected on next auth attempt
- AC-2: Clear user communication about why re-enrollment needed
- AC-3: Old keys securely deleted
- AC-4: Re-enrollment uses same identity (if server allows)
- AC-5: Audit log records biometric change event

**Trace:**
- TEST-092, TEST-093
- CON-058
- OBS-050

---

## Non-Functional Requirements

### NFR-050: Biometric Prompt Latency

Biometric authentication prompt SHALL appear within 200ms of user action
UNDER normal device conditions WITH 95th percentile < 500ms.

**Breakdown:**
- Intent/API call: < 50ms
- System UI rendering: < 100ms
- Biometric sensor activation: < 50ms

**Trace:**
- TEST-094
- OBS-051

---

### NFR-051: Key Operation Latency

Cryptographic operations using hardware-backed keys SHALL complete within
the following bounds UNDER normal conditions.

| Operation | Target | P95 | P99 |
|-----------|--------|-----|-----|
| Key generation | 500ms | 1000ms | 2000ms |
| Encryption (256 bytes) | 50ms | 100ms | 200ms |
| Decryption (256 bytes) | 50ms | 100ms | 200ms |
| Attestation generation | 1000ms | 2000ms | 5000ms |

**Note:** StrongBox operations may be slower than TEE due to secure element
communication overhead.

**Trace:**
- TEST-095
- OBS-052

---

### NFR-052: Key Storage Limits

The system SHALL operate within platform key storage limits
WITH graceful handling of storage exhaustion.

| Platform | Limit | SABLE Usage |
|----------|-------|-------------|
| Android Keystore | ~10,000 keys | 1 key per enrollment |
| iOS Keychain | Effectively unlimited | 1 key per enrollment |
| Secure Enclave | 4MB total | ~1KB per key |

**Trace:**
- TEST-096

---

### NFR-053: Platform Compatibility

The system SHALL support the following minimum platform versions
WITH documented limitations on older versions.

| Platform | Minimum Version | Full Features | Notes |
|----------|-----------------|---------------|-------|
| Android | API 23 (6.0) | API 28+ (9.0) | StrongBox requires API 28 |
| iOS | 13.0 | 14.0+ | App Attest requires iOS 14 |

**Feature Availability:**

| Feature | Android 23-27 | Android 28+ | iOS 13 | iOS 14+ |
|---------|---------------|-------------|--------|---------|
| Hardware keys | TEE only | TEE + StrongBox | SE | SE |
| Biometric binding | ✓ | ✓ | ✓ | ✓ |
| Strong biometric only | ✗ | ✓ | ✓ | ✓ |
| Key attestation | API 24+ | ✓ | ✗ | ✓ |

**Trace:**
- TEST-097

---

## Architecture Decision Record

### ADR-006: Platform Security Integration Strategy

#### Status

Proposed

#### Context

SABLE requires secure storage for sensitive enrollment data (commitment salt)
on mobile devices. The platform biometric APIs (Face ID, BiometricPrompt) do
not provide raw biometric data—they only authenticate the user. However, they
can protect cryptographic keys.

Key questions:
1. How do we protect SABLE enrollment data on device?
2. How do we verify device security posture?
3. How do we handle devices without hardware security?
4. How do we abstract platform differences?

#### Decision

We adopt a **layered security model** using platform security as the outer layer:

**1. Platform Biometrics Protect Keys, Not Identity**

Platform biometrics (Face ID, fingerprint) are used to unlock keys that protect
SABLE enrollment data. They do NOT replace SABLE's palm biometric verification.

```
Authentication = Platform Biometric (unlock keys) + SABLE Palm (prove identity)
```

This provides:
- Two-factor authentication (something you have + something you are × 2)
- Hardware protection for sensitive data
- Privacy preservation (palm data never leaves device)

**2. Hardware-Backed Keys When Available**

Keys are stored in the most secure hardware available:
- **Android:** StrongBox > TEE > Software Keystore
- **iOS:** Secure Enclave > Software Keychain

Keys are bound to biometric authentication, requiring user presence for every
decryption operation.

**3. Abstraction Layer for Cross-Platform**

A unified `PlatformSecurity` trait abstracts platform differences:

```rust
trait PlatformSecurity {
    fn generate_protected_key(...) -> Result<KeyHandle>;
    fn encrypt(...) -> Result<EncryptedData>;
    fn decrypt(...) -> Result<Vec<u8>>;
    fn attest(...) -> Result<Attestation>;
}
```

Platform-specific implementations:
- `AndroidPlatformSecurity` using JNI to Android Keystore
- `IosPlatformSecurity` using Swift/Objective-C to Keychain/SE
- `MockPlatformSecurity` for testing

**4. Attestation for Device Verification**

Server-side verification uses hardware attestation to:
- Confirm keys are hardware-backed
- Verify device boot integrity
- Detect rooted/jailbroken devices
- Enforce minimum OS version policies

Attestation is optional but recommended for high-security deployments.

**5. Graceful Degradation**

For devices without hardware security:
- Keys stored in software keystore/keychain (encrypted)
- User warned about reduced security
- Enterprise policy can block software-only devices

#### Alternatives Considered

**Alternative A: Require Hardware Security**

Only support devices with TEE/Secure Enclave.

*Pros:* Maximum security guarantee
*Cons:* Excludes many Android devices, poor user experience

*Decision:* Rejected; graceful degradation preferred

**Alternative B: Custom Secure Storage**

Implement our own encrypted storage without platform APIs.

*Pros:* Full control, consistent behavior
*Cons:* Less secure than hardware-backed, reinventing the wheel

*Decision:* Rejected; platform security is more robust

**Alternative C: Server-Stored Salt**

Store commitment salt on server instead of device.

*Pros:* Simpler device implementation
*Cons:* Server compromise exposes all salts, requires connectivity

*Decision:* Rejected; local storage with hardware protection preferred

#### Consequences

**Positive:**

1. **Defense in Depth:** Multiple security layers
2. **Hardware Protection:** Salt protected by TEE/SE when available
3. **Platform Integration:** Leverages billions of dollars of platform security investment
4. **User Familiarity:** Uses standard biometric prompts
5. **Compliance:** Supports NIST 800-63B AAL3 requirements

**Negative:**

1. **Platform Dependency:** Behavior varies by OS version
2. **Complexity:** Two biometric systems (platform + SABLE)
3. **JNI/FFI Overhead:** Cross-language calls for platform APIs
4. **Testing Difficulty:** Hardware security not available in simulators

**Mitigations:**

- Comprehensive platform compatibility testing matrix
- Clear user communication about security levels
- Mock implementations for development/testing
- Attestation to verify actual device capabilities

#### Implementation Notes

**FFI Strategy:**

```
┌────────────────────────────────────────────────────────┐
│                    Rust Core                            │
│  ┌──────────────────────────────────────────────────┐  │
│  │ PlatformSecurity trait                           │  │
│  │ └── platform_security_ffi.rs                     │  │
│  └──────────────────────────────────────────────────┘  │
└─────────────────────┬──────────────────────────────────┘
                      │ C ABI
                      ▼
┌────────────────────────────────────────────────────────┐
│              Platform-Specific Wrappers                 │
├────────────────────────┬───────────────────────────────┤
│  Android (Kotlin/JNI)  │  iOS (Swift/Objective-C)      │
│  - KeyStore access     │  - Keychain access            │
│  - BiometricPrompt     │  - LocalAuthentication        │
│  - Key attestation     │  - App Attest                 │
└────────────────────────┴───────────────────────────────┘
```

#### References

1. [Android Keystore System](https://developer.android.com/privacy-and-security/keystore)
2. [Android Key Attestation](https://developer.android.com/privacy-and-security/security-key-attestation)
3. [iOS Secure Enclave](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave)
4. [iOS App Attest](https://developer.apple.com/documentation/devicecheck/establishing-your-app-s-integrity)
5. [NIST SP 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html)

---

## Contract Specifications

### CON-050: PlatformSecurity Trait

**Interface:** `PlatformSecurity`

**Location:** `core/src/platform/mod.rs`

```rust
/// Cross-platform abstraction for secure key storage and biometric authentication.
///
/// Implementations provided for:
/// - Android via JNI (AndroidKeyStore + BiometricPrompt)
/// - iOS via FFI (Keychain + LocalAuthentication + Secure Enclave)
/// - Mock for testing
///
/// # Thread Safety
///
/// Implementations must be `Send + Sync` for use across async boundaries.
/// Platform API calls may block; use async wrappers where appropriate.
pub trait PlatformSecurity: Send + Sync {
    /// Returns the highest hardware security level available on this device.
    fn hardware_security_level(&self) -> HardwareSecurityLevel;

    /// Returns biometric authentication status.
    fn biometric_status(&self) -> BiometricStatus;

    /// Generates a new biometric-protected key.
    ///
    /// # Arguments
    ///
    /// * `key_id` - Unique identifier for this key
    /// * `config` - Key generation configuration
    ///
    /// # Returns
    ///
    /// * `Ok(KeyHandle)` - Handle to the generated key
    /// * `Err(PlatformError::HardwareUnavailable)` - Hardware security required but unavailable
    /// * `Err(PlatformError::BiometricNotEnrolled)` - Biometric required but not enrolled
    fn generate_protected_key(
        &self,
        key_id: &str,
        config: KeyConfig,
    ) -> Result<KeyHandle, PlatformError>;

    /// Encrypts data using a biometric-protected key.
    ///
    /// May trigger biometric authentication prompt.
    ///
    /// # Arguments
    ///
    /// * `key_handle` - Handle to the encryption key
    /// * `plaintext` - Data to encrypt
    /// * `auth_context` - Authentication context (prompt text, etc.)
    ///
    /// # Returns
    ///
    /// * `Ok(EncryptedData)` - Ciphertext with IV/nonce
    /// * `Err(PlatformError::AuthenticationFailed)` - User did not authenticate
    /// * `Err(PlatformError::KeyInvalidated)` - Key invalidated (biometric changed)
    fn encrypt(
        &self,
        key_handle: &KeyHandle,
        plaintext: &[u8],
        auth_context: &AuthContext,
    ) -> Result<EncryptedData, PlatformError>;

    /// Decrypts data using a biometric-protected key.
    ///
    /// Triggers biometric authentication prompt.
    ///
    /// # Arguments
    ///
    /// * `key_handle` - Handle to the decryption key
    /// * `ciphertext` - Data to decrypt
    /// * `auth_context` - Authentication context (prompt text, etc.)
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - Decrypted plaintext (caller must zeroize)
    /// * `Err(PlatformError::AuthenticationFailed)` - User did not authenticate
    /// * `Err(PlatformError::AuthenticationCanceled)` - User canceled prompt
    /// * `Err(PlatformError::KeyInvalidated)` - Key invalidated (biometric changed)
    fn decrypt(
        &self,
        key_handle: &KeyHandle,
        ciphertext: &EncryptedData,
        auth_context: &AuthContext,
    ) -> Result<Vec<u8>, PlatformError>;

    /// Generates device attestation.
    ///
    /// # Arguments
    ///
    /// * `challenge` - Server-provided nonce for freshness
    /// * `config` - Attestation configuration
    ///
    /// # Returns
    ///
    /// * `Ok(Attestation)` - Attestation data for server verification
    /// * `Err(PlatformError::AttestationUnavailable)` - Device doesn't support attestation
    fn attest(
        &self,
        challenge: &[u8; 32],
        config: AttestationConfig,
    ) -> Result<Attestation, PlatformError>;

    /// Deletes a key from secure storage.
    fn delete_key(&self, key_id: &str) -> Result<(), PlatformError>;

    /// Lists all SABLE keys in secure storage.
    fn list_keys(&self) -> Result<Vec<String>, PlatformError>;

    /// Checks if a specific key exists.
    fn key_exists(&self, key_id: &str) -> bool;

    /// Assesses overall device security posture.
    fn assess_security(&self) -> SecurityAssessment;
}

/// Handle to a key stored in platform secure storage.
/// Does not contain key material; only a reference.
#[derive(Debug, Clone)]
pub struct KeyHandle {
    pub key_id: String,
    pub created_at: Timestamp,
    pub security_level: HardwareSecurityLevel,
    pub requires_biometric: bool,
}

/// Encrypted data with associated metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedData {
    /// Ciphertext (AES-GCM encrypted)
    pub ciphertext: Vec<u8>,
    /// Initialization vector / nonce
    pub iv: [u8; 12],
    /// Authentication tag
    pub tag: [u8; 16],
    /// Key ID used for encryption
    pub key_id: String,
}

/// Context for authentication prompts.
#[derive(Debug, Clone)]
pub struct AuthContext {
    /// Title shown in biometric prompt
    pub title: String,
    /// Subtitle/description
    pub subtitle: Option<String>,
    /// Negative button text (cancel)
    pub cancel_text: String,
    /// Allow device passcode as fallback
    pub allow_passcode: bool,
}

/// Platform-specific errors.
#[derive(Debug, thiserror::Error)]
pub enum PlatformError {
    #[error("Hardware security unavailable")]
    HardwareUnavailable,

    #[error("Biometric authentication not enrolled")]
    BiometricNotEnrolled,

    #[error("Biometric authentication failed")]
    AuthenticationFailed,

    #[error("User canceled authentication")]
    AuthenticationCanceled,

    #[error("Key invalidated due to biometric change")]
    KeyInvalidated,

    #[error("Key not found: {0}")]
    KeyNotFound(String),

    #[error("Attestation not available on this device")]
    AttestationUnavailable,

    #[error("Platform error: {0}")]
    PlatformSpecific(String),
}
```

**Implements:**
- REQ-050

**Verified by:**
- TEST-070, TEST-071

---

### CON-051: Key Configuration

**Interface:** `KeyConfig`

**Location:** `core/src/platform/config.rs`

```rust
/// Configuration for generating a biometric-protected key.
#[derive(Debug, Clone)]
pub struct KeyConfig {
    /// Unique identifier for this key
    pub key_id: String,

    /// Key algorithm and size
    pub algorithm: KeyAlgorithm,

    /// Require biometric authentication for every use
    pub require_biometric: bool,

    /// Allow device passcode as fallback to biometric
    pub allow_passcode_fallback: bool,

    /// Invalidate key if device biometrics are re-enrolled
    pub invalidate_on_biometric_change: bool,

    /// Require hardware-backed storage (fail if unavailable)
    pub require_hardware_backing: bool,

    /// Android: Prefer StrongBox over TEE
    /// iOS: Ignored (always uses Secure Enclave if available)
    pub prefer_strongbox: bool,

    /// Android: Use BIOMETRIC_STRONG only (Class 3)
    /// iOS: Ignored (Face ID/Touch ID are always strong)
    pub require_strong_biometric: bool,
}

#[derive(Debug, Clone, Copy)]
pub enum KeyAlgorithm {
    /// AES-256 symmetric key (for encryption)
    Aes256,
    /// ECDSA P-256 key pair (for signing)
    EcdsaP256,
    /// ECDH P-256 key pair (for key agreement)
    EcdhP256,
}

impl Default for KeyConfig {
    fn default() -> Self {
        Self {
            key_id: String::new(),
            algorithm: KeyAlgorithm::Aes256,
            require_biometric: true,
            allow_passcode_fallback: false,
            invalidate_on_biometric_change: true,
            require_hardware_backing: false,
            prefer_strongbox: true,
            require_strong_biometric: true,
        }
    }
}

impl KeyConfig {
    /// Configuration for SABLE enrollment key.
    pub fn sable_enrollment(key_id: &str) -> Self {
        Self {
            key_id: key_id.to_string(),
            algorithm: KeyAlgorithm::Aes256,
            require_biometric: true,
            allow_passcode_fallback: false,
            invalidate_on_biometric_change: true,
            require_hardware_backing: false,  // Graceful degradation
            prefer_strongbox: true,
            require_strong_biometric: true,
        }
    }

    /// High-security configuration requiring hardware.
    pub fn high_security(key_id: &str) -> Self {
        Self {
            key_id: key_id.to_string(),
            algorithm: KeyAlgorithm::Aes256,
            require_biometric: true,
            allow_passcode_fallback: false,
            invalidate_on_biometric_change: true,
            require_hardware_backing: true,  // Fail if no hardware
            prefer_strongbox: true,
            require_strong_biometric: true,
        }
    }
}
```

**Implements:**
- REQ-051

**Verified by:**
- TEST-072

---

### CON-052: Enrollment Data Protection

**Interface:** `ProtectedEnrollment`

**Location:** `core/src/platform/enrollment.rs`

```rust
/// SABLE enrollment data with platform-protected sensitive fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectedEnrollment {
    /// Enrollment identifier
    pub enrollment_id: String,

    /// Biometric model used
    pub model_id: String,

    /// Model version
    pub model_version: Version,

    /// Public commitment (not sensitive)
    pub commitment: Commitment,

    /// Encrypted salt (protected by platform biometric)
    pub encrypted_salt: EncryptedData,

    /// Key ID used to encrypt salt
    pub protection_key_id: String,

    /// Enrollment timestamp
    pub enrolled_at: Timestamp,

    /// Device info at enrollment time
    pub device_info: DeviceInfo,
}

/// Device information captured at enrollment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub platform: Platform,
    pub os_version: String,
    pub security_level: HardwareSecurityLevel,
    pub device_model: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum Platform {
    Android,
    Ios,
    Unknown,
}

impl ProtectedEnrollment {
    /// Create a new protected enrollment.
    ///
    /// Generates protection key and encrypts salt.
    pub async fn create(
        platform: &dyn PlatformSecurity,
        enrollment_id: &str,
        model_id: &str,
        model_version: Version,
        commitment: Commitment,
        salt: &Salt,
    ) -> Result<Self, PlatformError> {
        let key_id = format!("sable_enrollment_{}", enrollment_id);

        // Generate biometric-protected key
        let key_config = KeyConfig::sable_enrollment(&key_id);
        let key_handle = platform.generate_protected_key(&key_id, key_config)?;

        // Encrypt salt (requires biometric)
        let auth_context = AuthContext {
            title: "Protect SABLE Identity".to_string(),
            subtitle: Some("Authenticate to secure your enrollment".to_string()),
            cancel_text: "Cancel".to_string(),
            allow_passcode: false,
        };

        let encrypted_salt = platform.encrypt(
            &key_handle,
            salt.as_bytes(),
            &auth_context,
        )?;

        Ok(Self {
            enrollment_id: enrollment_id.to_string(),
            model_id: model_id.to_string(),
            model_version,
            commitment,
            encrypted_salt,
            protection_key_id: key_id,
            enrolled_at: Timestamp::now(),
            device_info: DeviceInfo {
                platform: detect_platform(),
                os_version: get_os_version(),
                security_level: platform.hardware_security_level(),
                device_model: get_device_model(),
            },
        })
    }

    /// Decrypt salt for proof generation.
    ///
    /// Triggers biometric authentication.
    /// Caller MUST zeroize returned salt after use.
    pub async fn decrypt_salt(
        &self,
        platform: &dyn PlatformSecurity,
    ) -> Result<Salt, PlatformError> {
        let key_handle = KeyHandle {
            key_id: self.protection_key_id.clone(),
            created_at: self.enrolled_at,
            security_level: self.device_info.security_level,
            requires_biometric: true,
        };

        let auth_context = AuthContext {
            title: "SABLE Authentication".to_string(),
            subtitle: Some("Verify your identity".to_string()),
            cancel_text: "Cancel".to_string(),
            allow_passcode: false,
        };

        let salt_bytes = platform.decrypt(
            &key_handle,
            &self.encrypted_salt,
            &auth_context,
        )?;

        Salt::from_bytes(&salt_bytes)
            .map_err(|_| PlatformError::PlatformSpecific("Invalid salt data".into()))
    }

    /// Delete enrollment and associated keys.
    pub async fn delete(
        &self,
        platform: &dyn PlatformSecurity,
    ) -> Result<(), PlatformError> {
        platform.delete_key(&self.protection_key_id)
    }
}
```

**Implements:**
- REQ-052

**Verified by:**
- TEST-075, TEST-076, TEST-077

---

### CON-053: Android Implementation

**Interface:** `AndroidPlatformSecurity`

**Location:** `platforms/android/src/platform_security.rs`

```rust
/// Android implementation of PlatformSecurity.
///
/// Uses JNI to call Android Keystore and BiometricPrompt APIs.
pub struct AndroidPlatformSecurity {
    /// JNI environment reference
    jni_env: Mutex<JniEnv>,
    /// Cached security assessment
    security_assessment: OnceCell<SecurityAssessment>,
}

impl AndroidPlatformSecurity {
    /// Create new instance with JNI environment.
    pub fn new(jni_env: JniEnv) -> Self {
        Self {
            jni_env: Mutex::new(jni_env),
            security_assessment: OnceCell::new(),
        }
    }

    /// Check if StrongBox is available.
    fn has_strongbox(&self) -> bool {
        // Call PackageManager.hasSystemFeature(FEATURE_STRONGBOX_KEYSTORE)
        self.call_jni_bool("hasStrongBox")
    }

    /// Get Android API level.
    fn api_level(&self) -> u32 {
        self.call_jni_int("getApiLevel") as u32
    }
}

impl PlatformSecurity for AndroidPlatformSecurity {
    fn hardware_security_level(&self) -> HardwareSecurityLevel {
        if self.has_strongbox() {
            HardwareSecurityLevel::SecureElement
        } else if self.api_level() >= 23 {
            HardwareSecurityLevel::Tee
        } else {
            HardwareSecurityLevel::None
        }
    }

    fn biometric_status(&self) -> BiometricStatus {
        // Call BiometricManager.canAuthenticate()
        let can_auth = self.call_jni_int("canAuthenticate");
        BiometricStatus {
            available: can_auth == 0, // BIOMETRIC_SUCCESS
            enrolled: can_auth == 0,
            biometric_type: self.detect_biometric_type(),
            strong_biometric: self.api_level() >= 30, // R+ has strong biometric enforcement
        }
    }

    fn generate_protected_key(
        &self,
        key_id: &str,
        config: KeyConfig,
    ) -> Result<KeyHandle, PlatformError> {
        // Call KeyGenerator with KeyGenParameterSpec
        // See REQ-053 for Kotlin implementation details
        self.call_jni_generate_key(key_id, &config)
    }

    fn encrypt(
        &self,
        key_handle: &KeyHandle,
        plaintext: &[u8],
        auth_context: &AuthContext,
    ) -> Result<EncryptedData, PlatformError> {
        // 1. Get key from KeyStore
        // 2. Initialize Cipher
        // 3. Show BiometricPrompt with CryptoObject
        // 4. On success, encrypt data
        self.call_jni_encrypt(key_handle, plaintext, auth_context)
    }

    fn decrypt(
        &self,
        key_handle: &KeyHandle,
        ciphertext: &EncryptedData,
        auth_context: &AuthContext,
    ) -> Result<Vec<u8>, PlatformError> {
        // Similar to encrypt, but DECRYPT_MODE
        self.call_jni_decrypt(key_handle, ciphertext, auth_context)
    }

    fn attest(
        &self,
        challenge: &[u8; 32],
        config: AttestationConfig,
    ) -> Result<Attestation, PlatformError> {
        if self.api_level() < 24 {
            return Err(PlatformError::AttestationUnavailable);
        }
        // Generate attestation key with challenge
        // Return certificate chain
        self.call_jni_attest(challenge, &config)
    }

    // ... remaining implementations
}
```

**Implements:**
- REQ-053

**Verified by:**
- TEST-078, TEST-079, TEST-080

---

### CON-054: iOS Implementation

**Interface:** `IosPlatformSecurity`

**Location:** `platforms/ios/src/platform_security.rs`

```rust
/// iOS implementation of PlatformSecurity.
///
/// Uses Swift/Objective-C bridging to call Keychain, LocalAuthentication,
/// and Secure Enclave APIs.
pub struct IosPlatformSecurity {
    /// FFI handle to Swift implementation
    swift_impl: *mut c_void,
}

impl IosPlatformSecurity {
    /// Create new instance.
    ///
    /// # Safety
    ///
    /// Must be called on main thread for UI operations.
    pub fn new() -> Self {
        let swift_impl = unsafe { sable_ios_platform_security_create() };
        Self { swift_impl }
    }

    /// Check if Secure Enclave is available.
    fn has_secure_enclave(&self) -> bool {
        unsafe { sable_ios_has_secure_enclave(self.swift_impl) }
    }
}

impl PlatformSecurity for IosPlatformSecurity {
    fn hardware_security_level(&self) -> HardwareSecurityLevel {
        if self.has_secure_enclave() {
            HardwareSecurityLevel::SecureElement
        } else {
            HardwareSecurityLevel::None
        }
    }

    fn biometric_status(&self) -> BiometricStatus {
        let status = unsafe { sable_ios_biometric_status(self.swift_impl) };
        BiometricStatus {
            available: status.available,
            enrolled: status.enrolled,
            biometric_type: match status.biometry_type {
                1 => BiometricType::Fingerprint, // Touch ID
                2 => BiometricType::Face,        // Face ID
                _ => BiometricType::None,
            },
            strong_biometric: true, // iOS biometrics are always "strong"
        }
    }

    fn generate_protected_key(
        &self,
        key_id: &str,
        config: KeyConfig,
    ) -> Result<KeyHandle, PlatformError> {
        // Create key with SecAccessControl flags
        // .biometryCurrentSet for biometric binding
        // Store in Keychain or Secure Enclave
        unsafe { sable_ios_generate_key(self.swift_impl, key_id, &config) }
    }

    fn encrypt(
        &self,
        key_handle: &KeyHandle,
        plaintext: &[u8],
        auth_context: &AuthContext,
    ) -> Result<EncryptedData, PlatformError> {
        // For Secure Enclave: use ECIES with P-256
        // For Keychain-only: use AES-GCM directly
        unsafe {
            sable_ios_encrypt(
                self.swift_impl,
                key_handle,
                plaintext.as_ptr(),
                plaintext.len(),
                auth_context,
            )
        }
    }

    fn decrypt(
        &self,
        key_handle: &KeyHandle,
        ciphertext: &EncryptedData,
        auth_context: &AuthContext,
    ) -> Result<Vec<u8>, PlatformError> {
        // Triggers LAContext evaluation
        unsafe {
            sable_ios_decrypt(
                self.swift_impl,
                key_handle,
                ciphertext,
                auth_context,
            )
        }
    }

    fn attest(
        &self,
        challenge: &[u8; 32],
        config: AttestationConfig,
    ) -> Result<Attestation, PlatformError> {
        // Use DCAppAttestService (iOS 14+)
        unsafe { sable_ios_attest(self.swift_impl, challenge, &config) }
    }

    // ... remaining implementations
}

impl Drop for IosPlatformSecurity {
    fn drop(&mut self) {
        unsafe { sable_ios_platform_security_destroy(self.swift_impl) };
    }
}

// FFI declarations
extern "C" {
    fn sable_ios_platform_security_create() -> *mut c_void;
    fn sable_ios_platform_security_destroy(ptr: *mut c_void);
    fn sable_ios_has_secure_enclave(ptr: *mut c_void) -> bool;
    fn sable_ios_biometric_status(ptr: *mut c_void) -> FfiBiometricStatus;
    fn sable_ios_generate_key(
        ptr: *mut c_void,
        key_id: *const c_char,
        config: *const KeyConfig,
    ) -> FfiResult<KeyHandle>;
    // ... etc
}
```

**Implements:**
- REQ-054

**Verified by:**
- TEST-081, TEST-082, TEST-083

---

### CON-055: Attestation Data Structures

**Interface:** Attestation types

**Location:** `core/src/platform/attestation.rs`

```rust
/// Device attestation data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attestation {
    /// Platform that generated this attestation
    pub platform: Platform,

    /// Raw attestation data (platform-specific format)
    pub raw_attestation: Vec<u8>,

    /// Certificate chain (X.509 DER encoded)
    pub certificate_chain: Vec<Vec<u8>>,

    /// Challenge that was signed
    pub challenge: [u8; 32],

    /// When attestation was generated
    pub generated_at: Timestamp,

    /// Parsed properties (for convenience)
    pub properties: AttestationProperties,
}

/// Parsed attestation properties (normalized across platforms).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationProperties {
    /// Security level of attested key
    pub security_level: HardwareSecurityLevel,

    /// Device boot state
    pub boot_state: BootState,

    /// Device integrity status
    pub integrity_status: IntegrityStatus,

    /// Operating system version
    pub os_version: String,

    /// Security patch level (Android) or build (iOS)
    pub patch_level: String,

    /// Device model identifier
    pub device_model: String,

    /// Attestation format version
    pub attestation_version: u32,

    /// Platform-specific properties
    pub platform_properties: PlatformAttestationProperties,
}

/// Platform-specific attestation properties.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PlatformAttestationProperties {
    Android(AndroidAttestationProperties),
    Ios(IosAttestationProperties),
}

/// Android-specific attestation properties.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AndroidAttestationProperties {
    /// Attestation security level (Software, TEE, StrongBox)
    pub attestation_security_level: u32,
    /// Keymaster security level
    pub keymaster_security_level: u32,
    /// Verified boot state
    pub verified_boot_state: u32,
    /// Verified boot key hash
    pub verified_boot_key: Option<Vec<u8>>,
    /// Device locked status
    pub device_locked: bool,
    /// OS version
    pub os_version: u32,
    /// OS patch level (YYYYMM format)
    pub os_patch_level: u32,
    /// Vendor patch level
    pub vendor_patch_level: Option<u32>,
    /// Boot patch level
    pub boot_patch_level: Option<u32>,
}

/// iOS-specific attestation properties.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IosAttestationProperties {
    /// App ID (team ID + bundle ID)
    pub app_id: String,
    /// Whether this is a development or production attestation
    pub environment: IosEnvironment,
    /// Risk metric (if available)
    pub risk_metric: Option<u32>,
    /// Counter value
    pub counter: u32,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum IosEnvironment {
    Development,
    Production,
}

/// Configuration for attestation generation.
#[derive(Debug, Clone)]
pub struct AttestationConfig {
    /// Whether to include device properties
    pub include_device_info: bool,
    /// Android: prefer StrongBox attestation
    pub prefer_strongbox: bool,
    /// Timeout for attestation generation
    pub timeout: Duration,
}

impl Default for AttestationConfig {
    fn default() -> Self {
        Self {
            include_device_info: true,
            prefer_strongbox: true,
            timeout: Duration::from_secs(30),
        }
    }
}
```

**Implements:**
- REQ-055

**Verified by:**
- TEST-084, TEST-085, TEST-086

---

### CON-056: Attestation Verifier

**Interface:** `AttestationVerifier`

**Location:** `core/src/platform/verification.rs`

```rust
/// Server-side attestation verifier.
pub struct AttestationVerifier {
    /// Google hardware attestation root certificates
    google_roots: Vec<X509Certificate>,
    /// Apple App Attest root certificates
    apple_roots: Vec<X509Certificate>,
    /// Security policy
    policy: AttestationPolicy,
}

impl AttestationVerifier {
    /// Create verifier with default root certificates.
    pub fn new(policy: AttestationPolicy) -> Self {
        Self {
            google_roots: load_google_roots(),
            apple_roots: load_apple_roots(),
            policy,
        }
    }

    /// Create verifier with custom root certificates.
    pub fn with_roots(
        google_roots: Vec<X509Certificate>,
        apple_roots: Vec<X509Certificate>,
        policy: AttestationPolicy,
    ) -> Self {
        Self {
            google_roots,
            apple_roots,
            policy,
        }
    }

    /// Verify attestation against policy.
    pub fn verify(
        &self,
        attestation: &Attestation,
        expected_challenge: &[u8; 32],
    ) -> VerificationResult {
        // 1. Verify challenge matches
        if attestation.challenge != *expected_challenge {
            return VerificationResult::Invalid(
                AttestationError::ChallengeMismatch
            );
        }

        // 2. Verify certificate chain
        let chain_result = match attestation.platform {
            Platform::Android => self.verify_android_chain(attestation),
            Platform::Ios => self.verify_ios_chain(attestation),
            Platform::Unknown => return VerificationResult::Invalid(
                AttestationError::UnknownPlatform
            ),
        };

        if let Err(e) = chain_result {
            return VerificationResult::Invalid(e);
        }

        // 3. Check policy compliance
        let violations = self.check_policy(&attestation.properties);
        if violations.is_empty() {
            VerificationResult::Valid(attestation.properties.clone())
        } else {
            VerificationResult::PolicyViolation {
                properties: attestation.properties.clone(),
                violations,
            }
        }
    }

    fn verify_android_chain(&self, attestation: &Attestation) -> Result<(), AttestationError> {
        // Parse X.509 certificate chain
        // Verify signatures up to Google root
        // Parse attestation extension (OID 1.3.6.1.4.1.11129.2.1.17)
        // Verify extension contents
        todo!()
    }

    fn verify_ios_chain(&self, attestation: &Attestation) -> Result<(), AttestationError> {
        // Verify attestation object format (CBOR)
        // Verify certificate chain to Apple root
        // Verify App ID matches expected
        todo!()
    }

    fn check_policy(&self, props: &AttestationProperties) -> Vec<PolicyViolation> {
        let mut violations = Vec::new();

        // Check security level
        if props.security_level < self.policy.min_security_level {
            violations.push(PolicyViolation::SecurityLevelTooLow {
                required: self.policy.min_security_level,
                actual: props.security_level,
            });
        }

        // Check boot state
        if self.policy.require_verified_boot && props.boot_state != BootState::Verified {
            violations.push(PolicyViolation::UnverifiedBoot);
        }

        // Check OS version (platform-specific)
        // Check patch level
        // Check device allowlist

        violations
    }
}

/// Attestation security policy.
#[derive(Debug, Clone)]
pub struct AttestationPolicy {
    /// Minimum hardware security level
    pub min_security_level: HardwareSecurityLevel,
    /// Require verified boot chain
    pub require_verified_boot: bool,
    /// Minimum Android API level
    pub min_android_api: Option<u32>,
    /// Minimum Android security patch (YYYYMM)
    pub min_android_patch: Option<u32>,
    /// Minimum iOS version
    pub min_ios_version: Option<String>,
    /// Allowed device models (None = all)
    pub allowed_models: Option<HashSet<String>>,
    /// Maximum age of attestation before requiring refresh
    pub max_attestation_age: Duration,
}

impl Default for AttestationPolicy {
    fn default() -> Self {
        Self {
            min_security_level: HardwareSecurityLevel::Tee,
            require_verified_boot: false,
            min_android_api: Some(28), // Android 9+
            min_android_patch: None,
            min_ios_version: Some("14.0".to_string()),
            allowed_models: None,
            max_attestation_age: Duration::from_secs(86400), // 24 hours
        }
    }
}

impl AttestationPolicy {
    /// Strict policy for high-security deployments.
    pub fn strict() -> Self {
        Self {
            min_security_level: HardwareSecurityLevel::SecureElement,
            require_verified_boot: true,
            min_android_api: Some(30), // Android 11+
            min_android_patch: Some(202301), // Jan 2023+
            min_ios_version: Some("16.0".to_string()),
            allowed_models: None,
            max_attestation_age: Duration::from_secs(3600), // 1 hour
        }
    }
}
```

**Implements:**
- REQ-056

**Verified by:**
- TEST-087, TEST-088, TEST-089

---

### CON-057: Security Assessment

**Interface:** `SecurityAssessment`

**Location:** `core/src/platform/assessment.rs`

```rust
/// Device security capability assessment.
#[derive(Debug, Clone)]
pub struct SecurityAssessment {
    /// Overall security level
    pub level: SecurityLevel,
    /// Detailed capabilities
    pub capabilities: SecurityCapabilities,
    /// User-facing recommendations
    pub recommendations: Vec<Recommendation>,
    /// Whether to proceed with SABLE operations
    pub proceed: ProceedDecision,
}

/// Detailed security capabilities.
#[derive(Debug, Clone)]
pub struct SecurityCapabilities {
    /// Hardware security level
    pub hardware_security: HardwareSecurityLevel,
    /// Biometric strength
    pub biometric_strength: BiometricStrength,
    /// Attestation availability
    pub attestation_available: bool,
    /// Verified boot status (if known)
    pub verified_boot: Option<bool>,
    /// Platform version
    pub platform_version: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BiometricStrength {
    /// No biometric available
    None,
    /// Weak biometric (Android Class 1/2)
    Weak,
    /// Strong biometric (Android Class 3, iOS Face ID/Touch ID)
    Strong,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SecurityLevel {
    /// Full hardware security (StrongBox/Secure Enclave + strong biometric)
    High,
    /// Hardware security with limitations (TEE + biometric)
    Medium,
    /// Software-only security
    Low,
    /// Insufficient for SABLE
    Insufficient,
}

/// Recommendation for user or administrator.
#[derive(Debug, Clone)]
pub struct Recommendation {
    pub severity: RecommendationSeverity,
    pub message: String,
    pub action: Option<String>,
}

#[derive(Debug, Clone, Copy)]
pub enum RecommendationSeverity {
    Info,
    Warning,
    Critical,
}

/// Decision on whether SABLE should proceed.
#[derive(Debug, Clone)]
pub enum ProceedDecision {
    /// Proceed with full functionality
    Allow,
    /// Proceed but warn user about limitations
    AllowWithWarning(String),
    /// Require explicit user consent before proceeding
    RequireConsent {
        message: String,
        implications: Vec<String>,
    },
    /// Block operation based on policy
    Deny(String),
}

impl SecurityAssessment {
    /// Assess device security for SABLE operations.
    pub fn assess(platform: &dyn PlatformSecurity, policy: &SecurityPolicy) -> Self {
        let hw_level = platform.hardware_security_level();
        let bio_status = platform.biometric_status();

        let capabilities = SecurityCapabilities {
            hardware_security: hw_level,
            biometric_strength: if bio_status.strong_biometric {
                BiometricStrength::Strong
            } else if bio_status.available {
                BiometricStrength::Weak
            } else {
                BiometricStrength::None
            },
            attestation_available: hw_level >= HardwareSecurityLevel::Tee,
            verified_boot: None, // Requires attestation to determine
            platform_version: get_platform_version(),
        };

        let level = Self::calculate_level(&capabilities);
        let recommendations = Self::generate_recommendations(&capabilities, &level);
        let proceed = Self::determine_proceed(&level, policy);

        Self {
            level,
            capabilities,
            recommendations,
            proceed,
        }
    }

    fn calculate_level(caps: &SecurityCapabilities) -> SecurityLevel {
        match (caps.hardware_security, caps.biometric_strength) {
            (HardwareSecurityLevel::SecureElement, BiometricStrength::Strong) => SecurityLevel::High,
            (HardwareSecurityLevel::Tee, BiometricStrength::Strong) => SecurityLevel::Medium,
            (HardwareSecurityLevel::Tee, BiometricStrength::Weak) => SecurityLevel::Low,
            (HardwareSecurityLevel::None, _) => SecurityLevel::Low,
            (_, BiometricStrength::None) => SecurityLevel::Insufficient,
        }
    }

    fn generate_recommendations(
        caps: &SecurityCapabilities,
        level: &SecurityLevel,
    ) -> Vec<Recommendation> {
        let mut recs = Vec::new();

        if caps.hardware_security == HardwareSecurityLevel::None {
            recs.push(Recommendation {
                severity: RecommendationSeverity::Warning,
                message: "Device lacks hardware security module".to_string(),
                action: Some("Consider using a device with TEE or Secure Element".to_string()),
            });
        }

        if caps.biometric_strength == BiometricStrength::Weak {
            recs.push(Recommendation {
                severity: RecommendationSeverity::Warning,
                message: "Device biometric is not Class 3 (strong)".to_string(),
                action: None,
            });
        }

        if !caps.attestation_available {
            recs.push(Recommendation {
                severity: RecommendationSeverity::Info,
                message: "Hardware attestation not available".to_string(),
                action: Some("Update to Android 7+ or iOS 14+ for attestation".to_string()),
            });
        }

        recs
    }

    fn determine_proceed(level: &SecurityLevel, policy: &SecurityPolicy) -> ProceedDecision {
        match level {
            SecurityLevel::High => ProceedDecision::Allow,
            SecurityLevel::Medium => {
                if policy.require_secure_element {
                    ProceedDecision::Deny(
                        "Policy requires Secure Element but device only has TEE".to_string()
                    )
                } else {
                    ProceedDecision::Allow
                }
            }
            SecurityLevel::Low => {
                if policy.allow_software_keys {
                    ProceedDecision::AllowWithWarning(
                        "Keys are not hardware-protected on this device".to_string()
                    )
                } else {
                    ProceedDecision::RequireConsent {
                        message: "This device has limited security capabilities".to_string(),
                        implications: vec![
                            "Keys may be extractable if device is compromised".to_string(),
                            "Biometric verification may be less reliable".to_string(),
                        ],
                    }
                }
            }
            SecurityLevel::Insufficient => {
                ProceedDecision::Deny(
                    "Device does not meet minimum security requirements".to_string()
                )
            }
        }
    }
}

/// Policy for security requirements.
#[derive(Debug, Clone)]
pub struct SecurityPolicy {
    /// Require Secure Element (StrongBox/SE)
    pub require_secure_element: bool,
    /// Allow software-only key storage
    pub allow_software_keys: bool,
    /// Require strong biometric
    pub require_strong_biometric: bool,
}

impl Default for SecurityPolicy {
    fn default() -> Self {
        Self {
            require_secure_element: false,
            allow_software_keys: true,
            require_strong_biometric: false,
        }
    }
}
```

**Implements:**
- REQ-057

**Verified by:**
- TEST-090, TEST-091

---

### CON-058: Biometric Change Handler

**Interface:** `BiometricChangeHandler`

**Location:** `core/src/platform/biometric_change.rs`

```rust
/// Handles biometric re-enrollment detection and recovery.
pub struct BiometricChangeHandler {
    platform: Arc<dyn PlatformSecurity>,
}

impl BiometricChangeHandler {
    pub fn new(platform: Arc<dyn PlatformSecurity>) -> Self {
        Self { platform }
    }

    /// Check if enrollment is still valid.
    ///
    /// Returns `Err(BiometricChanged)` if biometrics were re-enrolled.
    pub fn check_enrollment_validity(
        &self,
        enrollment: &ProtectedEnrollment,
    ) -> Result<(), BiometricChangeError> {
        // Try to access the key
        // If KeyPermanentlyInvalidatedException / errSecAuthFailed, biometric changed
        if !self.platform.key_exists(&enrollment.protection_key_id) {
            return Err(BiometricChangeError::KeyDeleted);
        }

        // Attempt minimal operation to verify key is usable
        // This might trigger biometric prompt on some platforms
        match self.platform.decrypt(
            &KeyHandle {
                key_id: enrollment.protection_key_id.clone(),
                ..Default::default()
            },
            &enrollment.encrypted_salt,
            &AuthContext::silent(), // No prompt if possible
        ) {
            Ok(_) => Ok(()),
            Err(PlatformError::KeyInvalidated) => {
                Err(BiometricChangeError::BiometricChanged)
            }
            Err(PlatformError::AuthenticationCanceled) => {
                // User canceled, not a biometric change
                Err(BiometricChangeError::UserCanceled)
            }
            Err(e) => Err(BiometricChangeError::Other(e)),
        }
    }

    /// Handle biometric change by initiating re-enrollment.
    pub async fn handle_biometric_change(
        &self,
        enrollment: &ProtectedEnrollment,
    ) -> Result<ReEnrollmentResult, BiometricChangeError> {
        // 1. Delete old keys
        let _ = self.platform.delete_key(&enrollment.protection_key_id);

        // 2. Return re-enrollment required status
        Ok(ReEnrollmentResult::ReEnrollmentRequired {
            enrollment_id: enrollment.enrollment_id.clone(),
            reason: "Device biometrics changed".to_string(),
            previous_enrollment_time: enrollment.enrolled_at,
        })
    }
}

#[derive(Debug)]
pub enum BiometricChangeError {
    /// Biometrics were re-enrolled on device
    BiometricChanged,
    /// Key was deleted (manual or by system)
    KeyDeleted,
    /// User canceled authentication
    UserCanceled,
    /// Other platform error
    Other(PlatformError),
}

pub enum ReEnrollmentResult {
    /// Re-enrollment is required
    ReEnrollmentRequired {
        enrollment_id: String,
        reason: String,
        previous_enrollment_time: Timestamp,
    },
}
```

**Implements:**
- REQ-058

**Verified by:**
- TEST-092, TEST-093

---

## Test Specifications

### TEST-070: Cross-Platform API Consistency

**Objective:** Verify PlatformSecurity trait behaves consistently across platforms

**Test Type:** Integration test (run on both Android and iOS)

**Procedure:**
1. Execute same test sequence on both platforms
2. Verify API returns equivalent results
3. Verify error types map correctly

**Pass Criteria:**
- Same operations produce logically equivalent results
- Error handling is consistent

**Traces:** REQ-050

---

### TEST-071: Mock Implementation Completeness

**Objective:** Verify MockPlatformSecurity implements all trait methods

**Test Type:** Unit test

**Procedure:**
1. Instantiate MockPlatformSecurity
2. Call every trait method
3. Verify sensible responses

**Pass Criteria:**
- No unimplemented methods
- Mock is suitable for testing

**Traces:** REQ-050

---

### TEST-072: Key Generation with Biometric Binding

**Objective:** Verify keys require biometric authentication

**Test Type:** Integration test

**Procedure:**
1. Generate key with `require_biometric: true`
2. Attempt encryption without authentication
3. Verify operation fails or prompts for biometric

**Pass Criteria:**
- Key operations require biometric

**Traces:** REQ-051

---

### TEST-073: Key Generation Hardware Backing

**Objective:** Verify keys are hardware-backed when available

**Test Type:** Integration test

**Procedure:**
1. Generate key with `prefer_strongbox: true`
2. Query key properties
3. Verify security level matches device capability

**Pass Criteria:**
- Key in StrongBox/SE on capable devices
- Key in TEE on TEE-only devices

**Traces:** REQ-051

---

### TEST-074: Key Non-Exportability

**Objective:** Verify keys cannot be exported

**Test Type:** Security test

**Procedure:**
1. Generate hardware-backed key
2. Attempt to extract raw key material
3. Verify extraction fails

**Pass Criteria:**
- Key material never accessible

**Traces:** REQ-051

---

### TEST-075: Salt Encryption Flow

**Objective:** Verify salt is encrypted correctly

**Test Type:** Unit test

**Procedure:**
1. Create enrollment with known salt
2. Verify encrypted_salt is not equal to plaintext
3. Decrypt and verify matches original

**Pass Criteria:**
- Salt encrypted and recoverable

**Traces:** REQ-052

---

### TEST-076: Salt Never in Plaintext Memory

**Objective:** Verify salt is zeroized after use

**Test Type:** Memory analysis test

**Procedure:**
1. Decrypt salt for proof generation
2. Complete proof generation
3. Scan process memory for salt value

**Pass Criteria:**
- Salt not found in memory after operation

**Traces:** REQ-052

---

### TEST-077: Multiple Enrollment Support

**Objective:** Verify multiple identities can be enrolled

**Test Type:** Integration test

**Procedure:**
1. Create enrollment A
2. Create enrollment B
3. Authenticate with both
4. Verify no cross-contamination

**Pass Criteria:**
- Both enrollments work independently

**Traces:** REQ-052

---

### TEST-078: Android Keystore Integration

**Objective:** Verify Android Keystore operations work correctly

**Test Type:** Platform-specific integration test

**Procedure:**
1. Generate key in AndroidKeyStore
2. Encrypt/decrypt data
3. Verify BiometricPrompt shown

**Pass Criteria:**
- Operations succeed on Android device

**Traces:** REQ-053

---

### TEST-079: Android StrongBox Fallback

**Objective:** Verify graceful fallback when StrongBox unavailable

**Test Type:** Integration test on TEE-only device

**Procedure:**
1. Request StrongBox-backed key
2. Verify StrongBoxUnavailableException caught
3. Verify fallback to TEE

**Pass Criteria:**
- Key created in TEE when StrongBox unavailable

**Traces:** REQ-053

---

### TEST-080: Android BIOMETRIC_STRONG Enforcement

**Objective:** Verify only strong biometrics accepted

**Test Type:** Integration test

**Procedure:**
1. Configure for BIOMETRIC_STRONG only
2. Attempt authentication
3. Verify weak biometrics rejected

**Pass Criteria:**
- Only Class 3 biometrics accepted

**Traces:** REQ-053

---

### TEST-081: iOS Secure Enclave Integration

**Objective:** Verify Secure Enclave operations work correctly

**Test Type:** Platform-specific integration test

**Procedure:**
1. Generate key in Secure Enclave
2. Encrypt/decrypt data
3. Verify LocalAuthentication prompt shown

**Pass Criteria:**
- Operations succeed on iOS device

**Traces:** REQ-054

---

### TEST-082: iOS Keychain Fallback

**Objective:** Verify fallback on devices without Secure Enclave

**Test Type:** Integration test (simulator)

**Procedure:**
1. Request SE-backed key on simulator
2. Verify fallback to software keychain
3. Verify warning logged

**Pass Criteria:**
- Operations succeed with reduced security

**Traces:** REQ-054

---

### TEST-083: iOS Biometric Invalidation

**Objective:** Verify key invalidated on biometric re-enrollment

**Test Type:** Manual test

**Procedure:**
1. Create enrollment with .biometryCurrentSet
2. Add new fingerprint/face to device
3. Attempt to use key
4. Verify key access fails

**Pass Criteria:**
- Key invalidated after biometric change

**Traces:** REQ-054

---

### TEST-084: Android Key Attestation

**Objective:** Verify attestation generation on Android

**Test Type:** Integration test

**Procedure:**
1. Generate attestation key with challenge
2. Retrieve certificate chain
3. Parse attestation extension

**Pass Criteria:**
- Valid attestation with challenge embedded

**Traces:** REQ-055

---

### TEST-085: iOS App Attest

**Objective:** Verify attestation generation on iOS

**Test Type:** Integration test

**Procedure:**
1. Generate attestation key
2. Attest key with challenge
3. Verify attestation object format

**Pass Criteria:**
- Valid attestation returned

**Traces:** REQ-055

---

### TEST-086: Attestation Challenge Binding

**Objective:** Verify attestation includes server challenge

**Test Type:** Unit test

**Procedure:**
1. Generate attestation with known challenge
2. Verify challenge present in attestation
3. Verify different challenge produces different attestation

**Pass Criteria:**
- Challenge correctly bound

**Traces:** REQ-055

---

### TEST-087: Attestation Chain Verification

**Objective:** Verify certificate chain validation

**Test Type:** Unit test

**Procedure:**
1. Verify valid chain (terminates at root)
2. Verify invalid chain (missing intermediate)
3. Verify expired certificate

**Pass Criteria:**
- Valid chains accepted, invalid rejected

**Traces:** REQ-056

---

### TEST-088: Attestation Policy Enforcement

**Objective:** Verify policy violations detected

**Test Type:** Unit test

**Procedure:**
1. Create attestation with low security level
2. Verify against strict policy
3. Check violation reported

**Pass Criteria:**
- Policy violations correctly identified

**Traces:** REQ-056

---

### TEST-089: Attestation Challenge Replay Prevention

**Objective:** Verify old attestations rejected

**Test Type:** Security test

**Procedure:**
1. Generate attestation with challenge A
2. Verify with challenge B
3. Verify rejection

**Pass Criteria:**
- Challenge mismatch detected

**Traces:** REQ-056

---

### TEST-090: Security Level Assessment

**Objective:** Verify correct security level calculation

**Test Type:** Unit test

**Procedure:**
1. Test all combinations of hardware/biometric
2. Verify level matches expected

**Pass Criteria:**
- Levels calculated correctly

**Traces:** REQ-057

---

### TEST-091: Graceful Degradation Messaging

**Objective:** Verify user receives clear security information

**Test Type:** UI test

**Procedure:**
1. Run on device with limited security
2. Verify warning displayed
3. Verify recommendations actionable

**Pass Criteria:**
- User informed of limitations

**Traces:** REQ-057

---

### TEST-092: Biometric Change Detection

**Objective:** Verify biometric change is detected

**Test Type:** Manual integration test

**Procedure:**
1. Enroll with biometric-bound key
2. Change device biometrics
3. Attempt authentication
4. Verify change detected

**Pass Criteria:**
- KeyInvalidated error returned

**Traces:** REQ-058

---

### TEST-093: Re-enrollment Workflow

**Objective:** Verify re-enrollment after biometric change

**Test Type:** Integration test

**Procedure:**
1. Detect biometric change
2. Delete old keys
3. Complete new enrollment
4. Verify new enrollment works

**Pass Criteria:**
- Smooth re-enrollment experience

**Traces:** REQ-058

---

### TEST-094: Biometric Prompt Latency

**Objective:** Verify prompt appears quickly

**Test Type:** Performance test

**Procedure:**
1. Measure time from API call to prompt visible
2. Run 100 iterations

**Pass Criteria:**
- P50 < 200ms, P95 < 500ms

**Traces:** NFR-050

---

### TEST-095: Key Operation Latency

**Objective:** Verify crypto operations meet latency targets

**Test Type:** Performance test

**Procedure:**
1. Benchmark key generation (100 iterations)
2. Benchmark encrypt/decrypt (1000 iterations)
3. Compare against targets

**Pass Criteria:**
- Meets NFR-051 targets

**Traces:** NFR-051

---

### TEST-096: Key Storage Limits

**Objective:** Verify behavior at storage limits

**Test Type:** Stress test

**Procedure:**
1. Create keys until storage full
2. Verify graceful error handling
3. Verify deletion frees space

**Pass Criteria:**
- Clear error when limit reached

**Traces:** NFR-052

---

### TEST-097: Platform Version Compatibility

**Objective:** Verify minimum version enforcement

**Test Type:** Compatibility test

**Procedure:**
1. Run on minimum supported versions
2. Verify core functionality works
3. Document any limitations

**Pass Criteria:**
- Works on Android 23+, iOS 13+

**Traces:** NFR-053

---

## Observability Requirements

### OBS-050: Biometric Change Events

**Metrics:**

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `sable_biometric_change_detected_total` | Counter | platform | Biometric change events |
| `sable_reenrollment_required_total` | Counter | platform, reason | Re-enrollment triggers |

**Logs:**

| Event | Level | Fields |
|-------|-------|--------|
| biometric_change_detected | WARN | enrollment_id, platform |
| reenrollment_started | INFO | enrollment_id |
| reenrollment_completed | INFO | enrollment_id, duration_ms |

**Traces:** REQ-058

---

### OBS-051: Biometric Prompt Latency

**Metrics:**

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `sable_biometric_prompt_duration_ms` | Histogram | platform, result | Time to complete prompt |
| `sable_biometric_prompt_result_total` | Counter | platform, result | Prompt outcomes |

**Traces:** NFR-050

---

### OBS-052: Key Operation Performance

**Metrics:**

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `sable_key_generation_duration_ms` | Histogram | platform, hw_level | Key generation time |
| `sable_key_encrypt_duration_ms` | Histogram | platform, hw_level | Encryption time |
| `sable_key_decrypt_duration_ms` | Histogram | platform, hw_level | Decryption time |

**Traces:** NFR-051

---

### OBS-053: Attestation Events

**Metrics:**

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `sable_attestation_requests_total` | Counter | platform | Attestation attempts |
| `sable_attestation_verification_result_total` | Counter | result | Verification outcomes |
| `sable_attestation_policy_violations_total` | Counter | violation_type | Policy violations |

**Logs:**

| Event | Level | Fields |
|-------|-------|--------|
| attestation_generated | DEBUG | platform, security_level |
| attestation_verified | INFO | result, security_level |
| attestation_policy_violation | WARN | violation_type, details |

**Traces:** REQ-055, REQ-056

---

## Implementation Plan

### Phase 1: Core Abstractions (Week 1-2)

1. Define `PlatformSecurity` trait
2. Define key configuration types
3. Define attestation types
4. Implement `MockPlatformSecurity`
5. Unit tests for all types

### Phase 2: Android Implementation (Week 3-4)

1. Set up JNI infrastructure
2. Implement AndroidKeyStore integration
3. Implement BiometricPrompt integration
4. Implement key attestation
5. Android-specific tests

### Phase 3: iOS Implementation (Week 5-6)

1. Set up Swift/Objective-C bridging
2. Implement Keychain integration
3. Implement LocalAuthentication integration
4. Implement Secure Enclave key generation
5. Implement App Attest
6. iOS-specific tests

### Phase 4: Enrollment Integration (Week 7)

1. Implement `ProtectedEnrollment`
2. Integrate with existing SABLE enrollment flow
3. Implement biometric change detection
4. End-to-end tests

### Phase 5: Attestation Verification (Week 8)

1. Implement server-side `AttestationVerifier`
2. Add Google/Apple root certificates
3. Implement policy enforcement
4. Security review

### Phase 6: Documentation & Polish (Week 9-10)

1. API documentation
2. Integration guide
3. Security considerations document
4. Performance benchmarks
5. Release preparation

---

## References

1. [Android Keystore System](https://developer.android.com/privacy-and-security/keystore)
2. [Android BiometricPrompt](https://developer.android.com/identity/sign-in/biometric-auth)
3. [Android Key Attestation](https://developer.android.com/privacy-and-security/security-key-attestation)
4. [iOS LocalAuthentication](https://developer.apple.com/documentation/localauthentication)
5. [iOS Secure Enclave](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave)
6. [iOS App Attest](https://developer.apple.com/documentation/devicecheck/establishing-your-app-s-integrity)
7. [NIST SP 800-63B - Authentication and Lifecycle Management](https://pages.nist.gov/800-63-3/sp800-63b.html)
8. [FIDO Alliance - Hardware-Backed Keystore White Paper](https://fidoalliance.org/white-papers/)

---

**Document Version:** 1.0.0
**Last Updated:** 2026-02-03
**Author:** SABLE Development Team
**Review Status:** Pending stakeholder validation
