//! # SABLE Android Integration Example
//!
//! This example demonstrates how to integrate SABLE with Android applications
//! using JNI (Java Native Interface). It shows the complete workflow from
//! biometric capture to zero-knowledge proof verification.
//!
//! ## Android Project Setup
//!
//! 1. Add SABLE to your Android project's `Cargo.toml`:
//!    ```toml
//!    [dependencies]
//!    sable-core = { version = "0.1", features = ["mobile", "zk"] }
//!    ```
//!
//! 2. Configure NDK targets in `.cargo/config.toml`:
//!    ```toml
//!    [target.aarch64-linux-android]
//!    linker = "aarch64-linux-android21-clang"
//!
//!    [target.armv7-linux-androideabi]
//!    linker = "armv7a-linux-androideabi21-clang"
//!    ```
//!
//! 3. Build for Android:
//!    ```bash
//!    cargo build --target aarch64-linux-android --release --features mobile,zk
//!    ```
//!
//! ## JNI Bridge (Kotlin Side)
//!
//! ```kotlin
//! // SableLib.kt
//! object SableLib {
//!     init {
//!         System.loadLibrary("sable_android")
//!     }
//!
//!     // Native method declarations
//!     external fun initialize(): Long  // Returns handle
//!     external fun destroy(handle: Long)
//!     external fun generateSalt(): ByteArray
//!     external fun generateCommitment(handle: Long, features: DoubleArray, salt: ByteArray): ByteArray
//!     external fun generateProof(
//!         handle: Long,
//!         features: DoubleArray,
//!         salt: ByteArray,
//!         commitment: ByteArray,
//!         threshold: Double,
//!         timestamp: Long
//!     ): ByteArray
//!     external fun verifyProof(
//!         handle: Long,
//!         proof: ByteArray,
//!         commitment: ByteArray,
//!         threshold: Double,
//!         timestamp: Long
//!     ): Boolean
//! }
//! ```
//!
//! ## Usage Example (Kotlin)
//!
//! ```kotlin
//! class BiometricVerificationActivity : AppCompatActivity() {
//!     private var sableHandle: Long = 0
//!
//!     override fun onCreate(savedInstanceState: Bundle?) {
//!         super.onCreate(savedInstanceState)
//!         sableHandle = SableLib.initialize()
//!     }
//!
//!     override fun onDestroy() {
//!         super.onDestroy()
//!         SableLib.destroy(sableHandle)
//!     }
//!
//!     fun enrollUser(palmImage: Bitmap) {
//!         val features = extractBiometricFeatures(palmImage)
//!         val salt = SableLib.generateSalt()
//!         val commitment = SableLib.generateCommitment(sableHandle, features, salt)
//!
//!         // Store salt in Android Keystore (hardware-backed)
//!         storeInKeystore("user_salt", salt)
//!
//!         // Store commitment (can be stored on server)
//!         saveCommitment(commitment)
//!     }
//!
//!     fun verifyUser(palmImage: Bitmap): Boolean {
//!         val features = extractBiometricFeatures(palmImage)
//!         val salt = retrieveFromKeystore("user_salt")
//!         val commitment = loadCommitment()
//!
//!         val proof = SableLib.generateProof(
//!             sableHandle,
//!             features,
//!             salt,
//!             commitment,
//!             0.25,  // threshold
//!             System.currentTimeMillis() / 1000
//!         )
//!
//!         return SableLib.verifyProof(
//!             sableHandle,
//!             proof,
//!             commitment,
//!             0.25,
//!             System.currentTimeMillis() / 1000
//!         )
//!     }
//! }
//! ```

use std::time::{SystemTime, UNIX_EPOCH};

// Import SABLE modules
use sable_core::biometric::{
    BiometricModality, BiometricQuality, ModalityFeatureVector, PalmBiometricTemplate, PalmImage,
};
use sable_core::crypto::pedersen::PedersenCommitment;
use sable_core::crypto::rng::SecureRng;
use sable_core::error::Result;
use sable_core::mobile::keystore::{AccessPolicy, Keystore, MemoryKeystore, SableKeystore};
use sable_core::mobile::MobileSable;
use sable_core::types::{BiometricFeature, Distance, Salt, Timestamp};

/// Simulates the Android Keystore for demonstration purposes.
/// In production, this would use the actual Android Keystore System APIs.
struct AndroidKeystoreSimulator {
    keystore: SableKeystore,
}

impl AndroidKeystoreSimulator {
    fn new() -> Self {
        Self {
            keystore: SableKeystore::new(),
        }
    }

    /// Store salt with biometric protection (requires fingerprint/face to retrieve)
    fn store_salt_with_biometric(&mut self, user_id: &str, salt: Salt) -> Result<()> {
        self.keystore.store_salt(user_id, salt)
    }

    /// Retrieve salt (would require biometric auth in real Android)
    fn retrieve_salt(&self, user_id: &str) -> Result<Salt> {
        self.keystore.get_salt(user_id)
    }

    /// Store commitment (doesn't need biometric, can be backed up)
    fn store_commitment(&mut self, user_id: &str, commitment: PedersenCommitment) -> Result<()> {
        self.keystore.store_commitment(user_id, commitment)
    }

    fn retrieve_commitment(&self, user_id: &str) -> Result<PedersenCommitment> {
        self.keystore.get_commitment(user_id)
    }
}

/// Simulates palm biometric capture from Android camera
fn simulate_android_palm_capture() -> PalmImage {
    println!("  [Android] Requesting camera permission...");
    println!("  [Android] Opening camera preview for palm capture...");
    println!("  [Android] Palm detected, capturing image...");

    // Create simulated palm image data
    let width = 640;
    let height = 480;
    let channels = 1; // Grayscale

    let mut data = Vec::with_capacity((width * height) as usize);
    for y in 0..height {
        for x in 0..width {
            // Simulate palm vein patterns
            let base = 128u8;
            let vein = if (x % 25 < 4) && (y % 35 < 30) { 30 } else { 0 };
            let ridge = ((x + y) % 8) as u8;
            let noise = ((x * 7 + y * 13) % 15) as u8;
            data.push(base.saturating_sub(vein).wrapping_add(ridge).wrapping_add(noise));
        }
    }

    println!("  [Android] Image captured: {}x{} grayscale", width, height);
    PalmImage::new(width, height, channels, data)
}

/// Extract biometric features from palm image
fn extract_features_from_palm(image: &PalmImage) -> Result<Vec<f64>> {
    println!("  [Android] Processing palm image...");
    println!("  [Android] Extracting vein patterns (512-dim)...");
    println!("  [Android] Extracting ridge patterns (256-dim)...");

    // Create PalmBiometricTemplate from image
    let template = PalmBiometricTemplate::from_palm_image(image.clone())?;

    println!(
        "  [Android] Quality assessment: {:.2}",
        template.quality.score
    );

    // Convert to feature vector for SABLE crypto
    let sable_features = template.generate_sable_features()?;
    let features: Vec<f64> = sable_features.iter().map(|f| f.0 as f64 / 65535.0).collect();

    println!("  [Android] Feature extraction complete: {} features", features.len());
    Ok(features)
}

/// Main demonstration of Android integration workflow
fn main() -> Result<()> {
    println!("=======================================================");
    println!("     SABLE Android Integration Example (REQ-025)");
    println!("=======================================================\n");

    // =========================================================================
    // STEP 1: Initialize SABLE and Android Keystore
    // =========================================================================
    println!("STEP 1: Initialize SABLE and Android Keystore");
    println!("-----------------------------------------------");

    let sable = MobileSable::new()?;
    println!("  [SABLE] Mobile instance initialized");

    let mut keystore = AndroidKeystoreSimulator::new();
    println!("  [Android] Keystore initialized (TEE-backed simulation)");
    println!("  [Android] Security level: {:?}", keystore.keystore.security_level());

    let user_id = "android_user_001";
    println!("  [App] User ID: {}\n", user_id);

    // =========================================================================
    // STEP 2: Enrollment - Capture palm and generate commitment
    // =========================================================================
    println!("STEP 2: Biometric Enrollment");
    println!("-----------------------------------------------");

    // Capture palm image
    let enrollment_image = simulate_android_palm_capture();

    // Extract biometric features
    let enrollment_features = extract_features_from_palm(&enrollment_image)?;

    // Generate cryptographic salt
    let mut rng = SecureRng::new()?;
    let salt = Salt::random(&mut rng);
    println!("  [SABLE] Generated 256-bit cryptographic salt");

    // Generate Pedersen commitment: C = g^hash(features) * h^salt
    let commitment = sable.generate_commitment(&enrollment_features, &salt)?;
    println!("  [SABLE] Generated Pedersen commitment (48 bytes)");

    // Store salt in Android Keystore (requires biometric to access)
    keystore.store_salt_with_biometric(user_id, salt.clone())?;
    println!("  [Android] Salt stored in Keystore (biometric-protected)");

    // Store commitment (can be synced to server)
    keystore.store_commitment(user_id, commitment.clone())?;
    println!("  [Android] Commitment stored (can be backed up)");

    println!("\n  Enrollment complete!");
    println!("  - Biometric data: PRIVATE (never leaves device)");
    println!("  - Salt: PRIVATE (hardware-protected)");
    println!("  - Commitment: PUBLIC (can be stored on server)\n");

    // =========================================================================
    // STEP 3: Verification - Generate zero-knowledge proof
    // =========================================================================
    println!("STEP 3: Biometric Verification");
    println!("-----------------------------------------------");

    // Simulate user presenting palm for verification
    println!("  [App] User presenting palm for verification...\n");

    // Capture new palm image
    let verification_image = simulate_android_palm_capture();

    // Extract features from live capture
    let live_features = extract_features_from_palm(&verification_image)?;

    // Retrieve salt from Android Keystore (would trigger biometric prompt)
    println!("\n  [Android] Requesting biometric authentication to access salt...");
    println!("  [Android] Biometric authenticated (fingerprint/face)");
    let stored_salt = keystore.retrieve_salt(user_id)?;

    // Retrieve commitment
    let stored_commitment = keystore.retrieve_commitment(user_id)?;

    // Set verification parameters
    let threshold = Distance::new(0.25); // Euclidean distance threshold
    let current_time = Timestamp::now();

    println!("\n  [SABLE] Generating zero-knowledge proof...");
    println!("  [SABLE] - Threshold: 0.25 (Euclidean distance)");
    println!("  [SABLE] - Timestamp: {:?}", current_time);

    // Generate ZK proof
    let proof = sable.generate_proof(
        &live_features,
        &stored_salt,
        &stored_commitment,
        threshold,
        current_time,
    )?;

    println!("  [SABLE] Proof generated ({} bytes)", proof.len());
    println!("\n  Zero-knowledge proof proves:");
    println!("  1. User knows biometric data matching the commitment");
    println!("  2. Live capture matches enrolled template within threshold");
    println!("  3. Capture occurred within acceptable time window");
    println!("  ALL WITHOUT REVEALING THE ACTUAL BIOMETRIC DATA!\n");

    // =========================================================================
    // STEP 4: Verify proof (could be done on server)
    // =========================================================================
    println!("STEP 4: Proof Verification");
    println!("-----------------------------------------------");

    println!("  [Verifier] Received proof from device");
    println!("  [Verifier] Verifying against stored commitment...");

    let is_valid = sable.verify_proof(&proof, &stored_commitment, threshold, current_time)?;

    println!(
        "\n  [Verifier] Verification result: {}",
        if is_valid { "VALID" } else { "INVALID" }
    );

    // =========================================================================
    // STEP 5: Android-specific integration notes
    // =========================================================================
    println!("\n=======================================================");
    println!("     Android Integration Notes");
    println!("=======================================================\n");

    println!("JNI FUNCTION EXPORTS (in lib.rs with #[no_mangle]):");
    println!("--------------------------------------------------");
    println!("  sable_new()               -> SableHandle");
    println!("  sable_free(handle)        -> void");
    println!("  sable_generate_salt(out)  -> int");
    println!("  sable_generate_commitment(handle, features, salt) -> SableResult");
    println!("  sable_generate_proof(handle, features, salt, commitment, threshold, time) -> SableResult");
    println!("  sable_verify_proof(handle, proof, commitment, threshold, time) -> int");
    println!("  sable_free_result(result) -> void\n");

    println!("ANDROID KEYSTORE INTEGRATION:");
    println!("--------------------------------------------------");
    println!("  - Store salt with BiometricPrompt authentication");
    println!("  - Use setUserAuthenticationRequired(true)");
    println!("  - Set KeyGenParameterSpec with PURPOSE_ENCRYPT | PURPOSE_DECRYPT");
    println!("  - Use StrongBox for maximum security (if available)\n");

    println!("BUILD CONFIGURATION:");
    println!("--------------------------------------------------");
    println!("  # Build for ARM64 (most modern Android devices)");
    println!("  cargo build --target aarch64-linux-android --release");
    println!("");
    println!("  # Build for ARMv7 (older devices)");
    println!("  cargo build --target armv7-linux-androideabi --release");
    println!("");
    println!("  # Copy to Android project");
    println!("  cp target/aarch64-linux-android/release/libsable.so \\");
    println!("     android/app/src/main/jniLibs/arm64-v8a/\n");

    println!("MEMORY MANAGEMENT:");
    println!("--------------------------------------------------");
    println!("  - Always call sable_free(handle) in Activity.onDestroy()");
    println!("  - Use sable_free_result() to free returned byte arrays");
    println!("  - Salt is zeroized when Salt object is dropped\n");

    println!("=======================================================");
    println!("     Example Complete - Android Integration Ready");
    println!("=======================================================");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_android_workflow() {
        // Initialize
        let sable = MobileSable::new().unwrap();
        let mut keystore = AndroidKeystoreSimulator::new();

        // Generate test data
        let mut rng = SecureRng::new().unwrap();
        let salt = Salt::random(&mut rng);
        let features: Vec<f64> = (0..512).map(|i| (i as f64) / 512.0).collect();

        // Generate commitment
        let commitment = sable.generate_commitment(&features, &salt).unwrap();

        // Store in keystore
        keystore
            .store_salt_with_biometric("test_user", salt.clone())
            .unwrap();
        keystore
            .store_commitment("test_user", commitment.clone())
            .unwrap();

        // Retrieve and verify
        let retrieved_salt = keystore.retrieve_salt("test_user").unwrap();
        let retrieved_commitment = keystore.retrieve_commitment("test_user").unwrap();

        // Generate and verify proof
        let threshold = Distance::new(0.25);
        let timestamp = Timestamp::now();

        let proof = sable
            .generate_proof(&features, &retrieved_salt, &retrieved_commitment, threshold, timestamp)
            .unwrap();

        let valid = sable
            .verify_proof(&proof, &retrieved_commitment, threshold, timestamp)
            .unwrap();

        assert!(valid, "Proof should verify successfully");
    }
}
