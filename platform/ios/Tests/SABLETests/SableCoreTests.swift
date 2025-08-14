// SABLE iOS Tests

import XCTest
@testable import SABLE

final class SableCoreTests: XCTestCase {
    
    func testSableCoreInitialization() {
        do {
            let sable = try SableCore()
            XCTAssertNotNil(sable)
        } catch {
            XCTFail("Failed to initialize SABLE: \(error)")
        }
    }
    
    func testSaltGeneration() {
        do {
            let salt = try SableCore.generateSalt()
            XCTAssertEqual(salt.count, 32)
            
            // Generate another salt and ensure they're different
            let salt2 = try SableCore.generateSalt()
            XCTAssertNotEqual(salt, salt2)
        } catch {
            XCTFail("Salt generation failed: \(error)")
        }
    }
    
    func testVersionString() {
        let version = SableCore.getVersion()
        XCTAssertFalse(version.isEmpty)
        XCTAssertTrue(version.contains("SABLE"))
    }
    
    func testBiometricAvailability() {
        // This will depend on simulator vs device
        let available = SableCore.isBiometricAvailable()
        let biometricType = SableCore.getBiometricType()
        
        // Just ensure these don't crash
        XCTAssertNotNil(available)
        XCTAssertNotNil(biometricType)
    }
    
    func testCommitmentGeneration() {
        do {
            let sable = try SableCore()
            let features = Array(repeating: 0.5, count: 128)
            let salt = try SableCore.generateSalt()
            
            let commitment = try sable.generateCommitment(features: features, salt: salt)
            XCTAssertEqual(commitment.count, 48)
        } catch {
            XCTFail("Commitment generation failed: \(error)")
        }
    }
    
    func testInvalidSaltLength() {
        do {
            let sable = try SableCore()
            let features = Array(repeating: 0.5, count: 128)
            let invalidSalt = Data(repeating: 0, count: 16) // Wrong size
            
            _ = try sable.generateCommitment(features: features, salt: invalidSalt)
            XCTFail("Should have thrown an error for invalid salt length")
        } catch SableError.invalidInput {
            // Expected error
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }
    
    func testKeychainOperations() {
        do {
            let sable = try SableCore()
            let testData = "Hello, SABLE!".data(using: .utf8)!
            let testKey = "test_sable_key"
            
            // Store data (without biometric requirement for testing)
            try sable.storeSecurely(testData, forKey: testKey, requireBiometric: false)
            
            // Retrieve data
            let retrievedData = try sable.retrieveSecurely(forKey: testKey)
            XCTAssertEqual(testData, retrievedData)
            
            // Delete data
            try sable.deleteSecurely(forKey: testKey)
            
            // Verify deletion
            XCTAssertThrowsError(try sable.retrieveSecurely(forKey: testKey))
            
        } catch {
            XCTFail("Keychain operations failed: \(error)")
        }
    }
    
    func testProofGenerationAndVerification() {
        do {
            let sable = try SableCore()
            let features = (0..<128).map { _ in Double.random(in: 0...1) }
            let salt = try SableCore.generateSalt()
            
            // Generate commitment
            let commitment = try sable.generateCommitment(features: features, salt: salt)
            
            // Generate proof
            let threshold = 0.5
            let currentTime = UInt64(Date().timeIntervalSince1970)
            let proof = try sable.generateProof(
                features: features,
                salt: salt,
                commitment: commitment,
                threshold: threshold,
                currentTime: currentTime
            )
            
            XCTAssertGreaterThan(proof.count, 0)
            
            // Verify proof
            let isValid = try sable.verifyProof(
                proof: proof,
                commitment: commitment,
                threshold: threshold,
                currentTime: currentTime
            )
            
            XCTAssertTrue(isValid)
            
        } catch {
            XCTFail("Proof generation/verification failed: \(error)")
        }
    }
    
    func testProofVerificationWithWrongCommitment() {
        do {
            let sable = try SableCore()
            let features = (0..<128).map { _ in Double.random(in: 0...1) }
            let salt = try SableCore.generateSalt()
            
            // Generate commitment
            let commitment = try sable.generateCommitment(features: features, salt: salt)
            
            // Generate proof
            let threshold = 0.5
            let currentTime = UInt64(Date().timeIntervalSince1970)
            let proof = try sable.generateProof(
                features: features,
                salt: salt,
                commitment: commitment,
                threshold: threshold,
                currentTime: currentTime
            )
            
            // Create wrong commitment
            let wrongFeatures = features.map { $0 + 0.1 }
            let wrongCommitment = try sable.generateCommitment(features: wrongFeatures, salt: salt)
            
            // Verify proof with wrong commitment
            let isValid = try sable.verifyProof(
                proof: proof,
                commitment: wrongCommitment,
                threshold: threshold,
                currentTime: currentTime
            )
            
            XCTAssertFalse(isValid)
            
        } catch {
            XCTFail("Proof verification test failed: \(error)")
        }
    }
}
