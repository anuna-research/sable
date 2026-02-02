//! # SABLE iOS Integration Example
//!
//! This example demonstrates how to integrate SABLE with iOS applications
//! using Swift FFI. It shows the complete workflow from biometric capture
//! to zero-knowledge proof verification, including Keychain and Secure Enclave integration.
//!
//! ## iOS Project Setup
//!
//! 1. Add SABLE as a static library to your Xcode project:
//!    ```bash
//!    # Build for iOS simulator (arm64)
//!    cargo build --target aarch64-apple-ios-sim --release --features mobile,zk
//!
//!    # Build for iOS device (arm64)
//!    cargo build --target aarch64-apple-ios --release --features mobile,zk
//!
//!    # Create universal binary
//!    lipo -create \
//!      target/aarch64-apple-ios/release/libsable.a \
//!      target/aarch64-apple-ios-sim/release/libsable.a \
//!      -output libsable_universal.a
//!    ```
//!
//! 2. Generate Swift bindings header (sable.h):
//!    ```bash
//!    cbindgen --lang c --output sable.h
//!    ```
//!
//! 3. Add to Xcode:
//!    - Drag libsable.a and sable.h to your project
//!    - Add to "Link Binary With Libraries"
//!    - Create bridging header importing sable.h
//!
//! ## Swift Wrapper
//!
//! ```swift
//! // SableWrapper.swift
//! import Foundation
//! import LocalAuthentication
//!
//! class SableWrapper {
//!     private var handle: OpaquePointer?
//!
//!     init?() {
//!         handle = sable_new()
//!         guard handle != nil else { return nil }
//!     }
//!
//!     deinit {
//!         if let handle = handle {
//!             sable_free(handle)
//!         }
//!     }
//!
//!     func generateSalt() -> Data? {
//!         var saltBuffer = [UInt8](repeating: 0, count: 32)
//!         let result = sable_generate_salt(&saltBuffer)
//!         guard result == 0 else { return nil }
//!         return Data(saltBuffer)
//!     }
//!
//!     func generateCommitment(features: [Double], salt: Data) -> Data? {
//!         guard let handle = handle else { return nil }
//!
//!         var result = SableResult()
//!         salt.withUnsafeBytes { saltPtr in
//!             result = sable_generate_commitment(
//!                 handle,
//!                 features,
//!                 Int32(features.count),
//!                 saltPtr.baseAddress?.assumingMemoryBound(to: UInt8.self)
//!             )
//!         }
//!
//!         defer { sable_free_result(&result) }
//!
//!         guard result.error_code == .success else { return nil }
//!         return Data(bytes: result.data, count: Int(result.data_len))
//!     }
//!
//!     func generateProof(
//!         features: [Double],
//!         salt: Data,
//!         commitment: Data,
//!         threshold: Double,
//!         timestamp: UInt64
//!     ) -> Data? {
//!         guard let handle = handle else { return nil }
//!
//!         var result = SableResult()
//!         salt.withUnsafeBytes { saltPtr in
//!             commitment.withUnsafeBytes { commitmentPtr in
//!                 result = sable_generate_proof(
//!                     handle,
//!                     features,
//!                     Int32(features.count),
//!                     saltPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
//!                     commitmentPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
//!                     threshold,
//!                     timestamp
//!                 )
//!             }
//!         }
//!
//!         defer { sable_free_result(&result) }
//!
//!         guard result.error_code == .success else { return nil }
//!         return Data(bytes: result.data, count: Int(result.data_len))
//!     }
//!
//!     func verifyProof(
//!         proof: Data,
//!         commitment: Data,
//!         threshold: Double,
//!         timestamp: UInt64
//!     ) -> Bool {
//!         guard let handle = handle else { return false }
//!
//!         let result = proof.withUnsafeBytes { proofPtr in
//!             commitment.withUnsafeBytes { commitmentPtr in
//!                 sable_verify_proof(
//!                     handle,
//!                     proofPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
//!                     Int32(proof.count),
//!                     commitmentPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
//!                     threshold,
//!                     timestamp
//!                 )
//!             }
//!         }
//!
//!         return result == 1
//!     }
//! }
//! ```
//!
//! ## Keychain + Secure Enclave Integration
//!
//! ```swift
//! // SecureStorage.swift
//! import Security
//! import LocalAuthentication
//!
//! class SecureStorage {
//!     // Store salt in Secure Enclave (requires Face ID/Touch ID)
//!     static func storeSaltSecurely(salt: Data, userId: String) throws {
//!         let access = SecAccessControlCreateWithFlags(
//!             nil,
//!             kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
//!             [.privateKeyUsage, .biometryCurrentSet],
//!             nil
//!         )!
//!
//!         let query: [String: Any] = [
//!             kSecClass as String: kSecClassGenericPassword,
//!             kSecAttrAccount as String: "sable.salt.\(userId)",
//!             kSecAttrService as String: "com.sable.biometric",
//!             kSecValueData as String: salt,
//!             kSecAttrAccessControl as String: access,
//!             kSecUseAuthenticationContext as String: LAContext()
//!         ]
//!
//!         let status = SecItemAdd(query as CFDictionary, nil)
//!         guard status == errSecSuccess else {
//!             throw KeychainError.unableToStore
//!         }
//!     }
//!
//!     // Retrieve salt (triggers Face ID/Touch ID prompt)
//!     static func retrieveSalt(userId: String) throws -> Data {
//!         let context = LAContext()
//!         context.localizedReason = "Authenticate to access biometric data"
//!
//!         let query: [String: Any] = [
//!             kSecClass as String: kSecClassGenericPassword,
//!             kSecAttrAccount as String: "sable.salt.\(userId)",
//!             kSecAttrService as String: "com.sable.biometric",
//!             kSecReturnData as String: true,
//!             kSecUseAuthenticationContext as String: context
//!         ]
//!
//!         var result: AnyObject?
//!         let status = SecItemCopyMatching(query as CFDictionary, &result)
//!
//!         guard status == errSecSuccess, let data = result as? Data else {
//!             throw KeychainError.unableToRetrieve
//!         }
//!
//!         return data
//!     }
//! }
//! ```
//!
//! ## Full iOS Usage Example
//!
//! ```swift
//! // BiometricViewController.swift
//! class BiometricViewController: UIViewController {
//!     private var sable: SableWrapper?
//!
//!     override func viewDidLoad() {
//!         super.viewDidLoad()
//!         sable = SableWrapper()
//!     }
//!
//!     @IBAction func enrollTapped(_ sender: Any) {
//!         Task {
//!             await enrollUser()
//!         }
//!     }
//!
//!     func enrollUser() async {
//!         guard let sable = sable else { return }
//!
//!         // Capture palm image (using AVFoundation)
//!         let palmImage = await capturePalmImage()
//!
//!         // Extract features using Core ML model
//!         let features = await extractFeatures(from: palmImage)
//!
//!         // Generate salt and commitment
//!         guard let salt = sable.generateSalt(),
//!               let commitment = sable.generateCommitment(features: features, salt: salt) else {
//!             showError("Failed to generate commitment")
//!             return
//!         }
//!
//!         // Store salt in Secure Enclave
//!         do {
//!             try SecureStorage.storeSaltSecurely(salt: salt, userId: currentUserId)
//!             // Commitment can be stored in CloudKit or sent to server
//!             try storeCommitment(commitment)
//!             showSuccess("Enrollment complete!")
//!         } catch {
//!             showError("Failed to store credentials")
//!         }
//!     }
//!
//!     func verifyUser() async -> Bool {
//!         guard let sable = sable else { return false }
//!
//!         // Capture live palm
//!         let palmImage = await capturePalmImage()
//!         let features = await extractFeatures(from: palmImage)
//!
//!         // Retrieve salt (triggers Face ID)
//!         guard let salt = try? SecureStorage.retrieveSalt(userId: currentUserId),
//!               let commitment = try? loadCommitment() else {
//!             return false
//!         }
//!
//!         // Generate proof
//!         let timestamp = UInt64(Date().timeIntervalSince1970)
//!         guard let proof = sable.generateProof(
//!             features: features,
//!             salt: salt,
//!             commitment: commitment,
//!             threshold: 0.25,
//!             timestamp: timestamp
//!         ) else {
//!             return false
//!         }
//!
//!         // Verify (could be done on server)
//!         return sable.verifyProof(
//!             proof: proof,
//!             commitment: commitment,
//!             threshold: 0.25,
//!             timestamp: timestamp
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
use sable_core::mobile::keystore::{AccessPolicy, Keystore, SableKeystore, SecurityLevel};
use sable_core::mobile::MobileSable;
use sable_core::types::{BiometricFeature, Distance, Salt, Timestamp};

/// Simulates iOS Keychain with Secure Enclave backing.
/// In production, this would use Security.framework APIs.
struct IOSKeychainSimulator {
    keystore: SableKeystore,
}

impl IOSKeychainSimulator {
    fn new() -> Self {
        println!("  [iOS] Initializing Keychain Services...");
        println!("  [iOS] Secure Enclave available: true (simulated)");
        Self {
            keystore: SableKeystore::new(),
        }
    }

    /// Store salt with Secure Enclave protection (kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly)
    fn store_salt_secure_enclave(&mut self, user_id: &str, salt: Salt) -> Result<()> {
        println!("  [iOS] Storing salt in Secure Enclave...");
        println!("  [iOS] Access control: biometryCurrentSet + privateKeyUsage");
        self.keystore.store_salt(user_id, salt)
    }

    /// Retrieve salt (triggers LocalAuthentication prompt)
    fn retrieve_salt_with_biometric(&self, user_id: &str) -> Result<Salt> {
        println!("  [iOS] Retrieving salt from Secure Enclave...");
        println!("  [iOS] LAContext: Requesting Face ID/Touch ID authentication...");
        println!("  [iOS] Biometric authentication successful");
        self.keystore.get_salt(user_id)
    }

    /// Store commitment in Keychain (can be backed up to iCloud Keychain)
    fn store_commitment_icloud(&mut self, user_id: &str, commitment: PedersenCommitment) -> Result<()> {
        println!("  [iOS] Storing commitment in Keychain...");
        println!("  [iOS] Sync to iCloud Keychain: enabled");
        self.keystore.store_commitment(user_id, commitment)
    }

    fn retrieve_commitment(&self, user_id: &str) -> Result<PedersenCommitment> {
        self.keystore.get_commitment(user_id)
    }
}

/// Simulates palm capture using AVFoundation on iOS
fn simulate_ios_palm_capture() -> PalmImage {
    println!("  [iOS] Initializing AVCaptureSession...");
    println!("  [iOS] Configuring camera for NIR palm imaging...");
    println!("  [iOS] Starting capture preview...");
    println!("  [iOS] Palm region detected (Core ML Vision)");
    println!("  [iOS] Capturing high-resolution frame...");

    // Create simulated palm image
    let width = 640;
    let height = 480;
    let channels = 1;

    let mut data = Vec::with_capacity((width * height) as usize);
    for y in 0..height {
        for x in 0..width {
            let base = 130u8;
            let vein = if (x % 22 < 3) && (y % 32 < 28) { 35 } else { 0 };
            let ridge = ((x * 2 + y) % 7) as u8;
            let noise = ((x * 11 + y * 17) % 12) as u8;
            data.push(base.saturating_sub(vein).wrapping_add(ridge).wrapping_add(noise));
        }
    }

    println!("  [iOS] Frame captured: {}x{} @ 8-bit grayscale", width, height);
    PalmImage::new(width, height, channels, data)
}

/// Extract features using Core ML model (simulated)
fn extract_features_coreml(image: &PalmImage) -> Result<Vec<f64>> {
    println!("  [iOS] Loading PalmFeatureExtractor.mlmodelc...");
    println!("  [iOS] Running inference on Neural Engine...");
    println!("  [iOS] Extracting 512-dimensional feature vector...");

    let template = PalmBiometricTemplate::from_palm_image(image.clone())?;
    let sable_features = template.generate_sable_features()?;
    let features: Vec<f64> = sable_features.iter().map(|f| f.0 as f64 / 65535.0).collect();

    println!(
        "  [iOS] Feature extraction complete (Neural Engine: {:.1}ms simulated)",
        45.2
    );
    Ok(features)
}

fn main() -> Result<()> {
    println!("=======================================================");
    println!("       SABLE iOS Integration Example (REQ-025)");
    println!("=======================================================\n");

    // =========================================================================
    // STEP 1: Initialize SABLE and iOS Keychain
    // =========================================================================
    println!("STEP 1: Initialize SABLE and iOS Secure Storage");
    println!("-----------------------------------------------");

    let sable = MobileSable::new()?;
    println!("  [SABLE] Mobile instance initialized");

    let mut keychain = IOSKeychainSimulator::new();

    let user_id = "ios_user_001";
    println!("  [App] User ID: {}\n", user_id);

    // =========================================================================
    // STEP 2: Enrollment with Secure Enclave
    // =========================================================================
    println!("STEP 2: Biometric Enrollment (Secure Enclave)");
    println!("-----------------------------------------------");

    // Capture palm using AVFoundation
    let enrollment_image = simulate_ios_palm_capture();

    // Extract features using Core ML
    let enrollment_features = extract_features_coreml(&enrollment_image)?;

    // Generate cryptographic salt
    let mut rng = SecureRng::new()?;
    let salt = Salt::random(&mut rng);
    println!("\n  [SABLE] Generated 256-bit cryptographic salt");

    // Generate commitment
    let commitment = sable.generate_commitment(&enrollment_features, &salt)?;
    println!("  [SABLE] Generated Pedersen commitment");

    // Store salt in Secure Enclave (hardware-protected, non-extractable)
    keychain.store_salt_secure_enclave(user_id, salt.clone())?;

    // Store commitment (can sync via iCloud Keychain)
    keychain.store_commitment_icloud(user_id, commitment.clone())?;

    println!("\n  Enrollment Summary:");
    println!("  - Salt: Stored in Secure Enclave (A-series chip)");
    println!("  - Access: Requires Face ID/Touch ID");
    println!("  - Commitment: Stored in Keychain (iCloud sync enabled)");
    println!("  - Biometrics: Never leave device\n");

    // =========================================================================
    // STEP 3: Verification with Face ID/Touch ID gate
    // =========================================================================
    println!("STEP 3: Biometric Verification (Face ID Gate)");
    println!("-----------------------------------------------");

    println!("  [App] User initiating verification...\n");

    // Capture live palm
    let verification_image = simulate_ios_palm_capture();

    // Extract features
    let live_features = extract_features_coreml(&verification_image)?;

    // Retrieve salt (triggers Face ID/Touch ID)
    println!("\n  [iOS] Presenting LocalAuthentication dialog...");
    println!("  [iOS] \"Authenticate to verify your identity\"");
    let stored_salt = keychain.retrieve_salt_with_biometric(user_id)?;

    // Retrieve commitment
    let stored_commitment = keychain.retrieve_commitment(user_id)?;

    // Generate zero-knowledge proof
    let threshold = Distance::new(0.25);
    let current_time = Timestamp::now();

    println!("\n  [SABLE] Generating zero-knowledge proof...");
    let proof = sable.generate_proof(
        &live_features,
        &stored_salt,
        &stored_commitment,
        threshold,
        current_time,
    )?;
    println!("  [SABLE] Proof generated ({} bytes)", proof.len());

    // =========================================================================
    // STEP 4: Verify proof
    // =========================================================================
    println!("\nSTEP 4: Proof Verification");
    println!("-----------------------------------------------");

    let is_valid = sable.verify_proof(&proof, &stored_commitment, threshold, current_time)?;
    println!(
        "  [SABLE] Verification result: {}",
        if is_valid { "VALID" } else { "INVALID" }
    );

    // =========================================================================
    // STEP 5: iOS-specific integration details
    // =========================================================================
    println!("\n=======================================================");
    println!("       iOS Integration Reference");
    println!("=======================================================\n");

    println!("C HEADER (sable.h) - Generated with cbindgen:");
    println!("--------------------------------------------------");
    println!("  typedef void* SableHandle;");
    println!("");
    println!("  typedef enum {{");
    println!("      Success = 0,");
    println!("      InvalidInput = 1,");
    println!("      ProcessingFailed = 2,");
    println!("      SystemError = 3,");
    println!("  }} SableErrorCode;");
    println!("");
    println!("  typedef struct {{");
    println!("      SableErrorCode error_code;");
    println!("      uint8_t* data;");
    println!("      int32_t data_len;");
    println!("  }} SableResult;");
    println!("");
    println!("  SableHandle sable_new(void);");
    println!("  void sable_free(SableHandle handle);");
    println!("  int32_t sable_generate_salt(uint8_t* salt_out);");
    println!("  SableResult sable_generate_commitment(");
    println!("      SableHandle handle,");
    println!("      const double* features,");
    println!("      int32_t features_len,");
    println!("      const uint8_t* salt");
    println!("  );");
    println!("  // ... more functions ...\n");

    println!("SECURE ENCLAVE BEST PRACTICES:");
    println!("--------------------------------------------------");
    println!("  1. Use kSecAttrTokenIDSecureEnclave for key generation");
    println!("  2. Set kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly");
    println!("  3. Include .biometryCurrentSet in SecAccessControlCreateFlags");
    println!("  4. Always use LAContext for pre-authentication");
    println!("  5. Handle LAError.biometryLockout gracefully\n");

    println!("BUILD COMMANDS:");
    println!("--------------------------------------------------");
    println!("  # iOS Device (arm64)");
    println!("  cargo build --target aarch64-apple-ios --release");
    println!("");
    println!("  # iOS Simulator (arm64 for M1/M2 Macs)");
    println!("  cargo build --target aarch64-apple-ios-sim --release");
    println!("");
    println!("  # Generate Swift-compatible header");
    println!("  cbindgen --config cbindgen.toml --output include/sable.h\n");

    println!("XCODE PROJECT SETUP:");
    println!("--------------------------------------------------");
    println!("  1. Add libsable.a to 'Link Binary With Libraries'");
    println!("  2. Add include/ to 'Header Search Paths'");
    println!("  3. Create YourApp-Bridging-Header.h with:");
    println!("     #import \"sable.h\"");
    println!("  4. Set 'Objective-C Bridging Header' build setting");
    println!("  5. Add 'Security.framework' for Keychain APIs");
    println!("  6. Add 'LocalAuthentication.framework' for Face ID\n");

    println!("PRIVACY ENTITLEMENTS (Info.plist):");
    println!("--------------------------------------------------");
    println!("  <key>NSFaceIDUsageDescription</key>");
    println!("  <string>Authenticate to access your biometric credentials</string>");
    println!("");
    println!("  <key>NSCameraUsageDescription</key>");
    println!("  <string>Capture palm image for biometric verification</string>\n");

    println!("=======================================================");
    println!("       Example Complete - iOS Integration Ready");
    println!("=======================================================");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ios_workflow() {
        // Initialize
        let sable = MobileSable::new().unwrap();
        let mut keychain = IOSKeychainSimulator::new();

        // Generate test data
        let mut rng = SecureRng::new().unwrap();
        let salt = Salt::random(&mut rng);
        let features: Vec<f64> = (0..512).map(|i| (i as f64) / 512.0).collect();

        // Enrollment
        let commitment = sable.generate_commitment(&features, &salt).unwrap();
        keychain
            .store_salt_secure_enclave("test_user", salt.clone())
            .unwrap();
        keychain
            .store_commitment_icloud("test_user", commitment.clone())
            .unwrap();

        // Verification
        let retrieved_salt = keychain.retrieve_salt_with_biometric("test_user").unwrap();
        let retrieved_commitment = keychain.retrieve_commitment("test_user").unwrap();

        let threshold = Distance::new(0.25);
        let timestamp = Timestamp::now();

        let proof = sable
            .generate_proof(&features, &retrieved_salt, &retrieved_commitment, threshold, timestamp)
            .unwrap();

        let valid = sable
            .verify_proof(&proof, &retrieved_commitment, threshold, timestamp)
            .unwrap();

        assert!(valid);
    }

    #[test]
    fn test_secure_enclave_simulation() {
        let mut keychain = IOSKeychainSimulator::new();
        let mut rng = SecureRng::new().unwrap();
        let salt = Salt::random(&mut rng);

        // Store and retrieve
        keychain
            .store_salt_secure_enclave("se_test", salt.clone())
            .unwrap();
        let retrieved = keychain.retrieve_salt_with_biometric("se_test").unwrap();

        assert_eq!(
            salt.to_bytes().unwrap(),
            retrieved.to_bytes().unwrap()
        );
    }
}
