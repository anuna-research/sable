// SABLE iOS Swift Interface
//
// Swift wrapper for SABLE biometric authentication library

import Foundation
import Security
import LocalAuthentication
import SableCCore

/// SABLE error types
public enum SableError: Error, LocalizedError {
    case initializationFailed
    case invalidInput(String)
    case cryptographicError(String)
    case serializationError(String)
    case outOfMemory
    case unknownError(Int)
    
    public var errorDescription: String? {
        switch self {
        case .initializationFailed:
            return "Failed to initialize SABLE"
        case .invalidInput(let message):
            return "Invalid input: \(message)"
        case .cryptographicError(let message):
            return "Cryptographic error: \(message)"
        case .serializationError(let message):
            return "Serialization error: \(message)"
        case .outOfMemory:
            return "Out of memory"
        case .unknownError(let code):
            return "Unknown error: \(code)"
        }
    }
}

/// SABLE Core class for biometric operations
public final class SableCore {
    
    private var handle: OpaquePointer?
    
    /// Initialize SABLE instance
    public init() throws {
        handle = sable_new()
        if handle == nil {
            throw SableError.initializationFailed
        }
    }
    
    deinit {
        if let handle = handle {
            sable_free(handle)
        }
    }
    
    /// Generate biometric commitment
    /// - Parameters:
    ///   - features: Array of normalized biometric features (0.0-1.0)
    ///   - salt: 32-byte salt for commitment generation
    /// - Returns: 48-byte commitment data
    /// - Throws: SableError on failure
    public func generateCommitment(features: [Double], salt: Data) throws -> Data {
        guard let handle = handle else {
            throw SableError.initializationFailed
        }
        
        guard salt.count == 32 else {
            throw SableError.invalidInput("Salt must be 32 bytes")
        }
        
        let result = salt.withUnsafeBytes { saltBytes in
            features.withUnsafeBufferPointer { featuresPtr in
                sable_generate_commitment(
                    handle,
                    featuresPtr.baseAddress,
                    Int32(features.count),
                    saltBytes.bindMemory(to: UInt8.self).baseAddress
                )
            }
        }
        
        defer { sable_free_result(UnsafeMutablePointer(mutating: &result)) }
        
        guard result.error_code == SABLE_SUCCESS else {
            throw mapError(result.error_code)
        }
        
        guard let data = result.data, result.data_len > 0 else {
            throw SableError.cryptographicError("No commitment data returned")
        }
        
        return Data(bytes: data, count: Int(result.data_len))
    }
    
    /// Generate zero-knowledge proof
    /// - Parameters:
    ///   - features: Array of biometric features
    ///   - salt: 32-byte salt used in commitment
    ///   - commitment: 48-byte commitment data
    ///   - threshold: Distance threshold for matching
    ///   - currentTime: Current timestamp in seconds
    /// - Returns: Proof data
    /// - Throws: SableError on failure
    public func generateProof(features: [Double], salt: Data, commitment: Data, 
                             threshold: Double, currentTime: UInt64) throws -> Data {
        guard let handle = handle else {
            throw SableError.initializationFailed
        }
        
        guard salt.count == 32 else {
            throw SableError.invalidInput("Salt must be 32 bytes")
        }
        
        guard commitment.count == 48 else {
            throw SableError.invalidInput("Commitment must be 48 bytes")
        }
        
        let result = salt.withUnsafeBytes { saltBytes in
            commitment.withUnsafeBytes { commitmentBytes in
                features.withUnsafeBufferPointer { featuresPtr in
                    sable_generate_proof(
                        handle,
                        featuresPtr.baseAddress,
                        Int32(features.count),
                        saltBytes.bindMemory(to: UInt8.self).baseAddress,
                        commitmentBytes.bindMemory(to: UInt8.self).baseAddress,
                        threshold,
                        currentTime
                    )
                }
            }
        }
        
        defer { sable_free_result(UnsafeMutablePointer(mutating: &result)) }
        
        guard result.error_code == SABLE_SUCCESS else {
            throw mapError(result.error_code)
        }
        
        guard let data = result.data, result.data_len > 0 else {
            throw SableError.cryptographicError("No proof data returned")
        }
        
        return Data(bytes: data, count: Int(result.data_len))
    }
    
    /// Verify zero-knowledge proof
    /// - Parameters:
    ///   - proof: Proof data to verify
    ///   - commitment: 48-byte commitment data
    ///   - threshold: Distance threshold for matching
    ///   - currentTime: Current timestamp in seconds
    /// - Returns: True if proof is valid, false otherwise
    /// - Throws: SableError on verification error
    public func verifyProof(proof: Data, commitment: Data, 
                           threshold: Double, currentTime: UInt64) throws -> Bool {
        guard let handle = handle else {
            throw SableError.initializationFailed
        }
        
        guard commitment.count == 48 else {
            throw SableError.invalidInput("Commitment must be 48 bytes")
        }
        
        let result = proof.withUnsafeBytes { proofBytes in
            commitment.withUnsafeBytes { commitmentBytes in
                sable_verify_proof(
                    handle,
                    proofBytes.bindMemory(to: UInt8.self).baseAddress,
                    Int32(proof.count),
                    commitmentBytes.bindMemory(to: UInt8.self).baseAddress,
                    threshold,
                    currentTime
                )
            }
        }
        
        guard result != -1 else {
            throw SableError.cryptographicError("Proof verification failed")
        }
        
        return result == 1
    }
    
    /// Generate random 32-byte salt
    /// - Returns: Random salt data
    /// - Throws: SableError on generation failure
    public static func generateSalt() throws -> Data {
        var salt = Data(count: 32)
        
        let result = salt.withUnsafeMutableBytes { saltBytes in
            sable_generate_salt(saltBytes.bindMemory(to: UInt8.self).baseAddress)
        }
        
        guard result == 0 else {
            throw SableError.cryptographicError("Salt generation failed")
        }
        
        return salt
    }
    
    /// Get SABLE library version
    /// - Returns: Version string
    public static func getVersion() -> String {
        guard let versionCString = sable_get_version() else {
            return "Unknown"
        }
        return String(cString: versionCString)
    }
    
    // MARK: - Private Helper Methods
    
    private func mapError(_ errorCode: SableErrorCode) -> SableError {
        switch errorCode {
        case SABLE_INVALID_INPUT:
            return .invalidInput("Invalid parameters")
        case SABLE_CRYPTO_ERROR:
            return .cryptographicError("Cryptographic operation failed")
        case SABLE_SERIALIZATION_ERROR:
            return .serializationError("Data serialization failed")
        case SABLE_OUT_OF_MEMORY:
            return .outOfMemory
        default:
            return .unknownError(Int(errorCode.rawValue))
        }
    }
}

// MARK: - iOS Keychain Integration

extension SableCore {
    
    /// Store data securely in iOS Keychain
    /// - Parameters:
    ///   - data: Data to store
    ///   - key: Keychain key identifier
    ///   - requireBiometric: Whether to require biometric authentication
    /// - Throws: SableError on storage failure
    public func storeSecurely(_ data: Data, forKey key: String, requireBiometric: Bool = true) throws {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]
        
        if requireBiometric {
            query[kSecAttrAccessControl as String] = SecAccessControlCreateWithFlags(
                nil,
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                .biometryAny,
                nil
            )
        }
        
        // Delete existing item first
        let deleteQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key
        ]
        SecItemDelete(deleteQuery as CFDictionary)
        
        // Add new item
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw SableError.cryptographicError("Keychain storage failed: \(status)")
        }
    }
    
    /// Retrieve data securely from iOS Keychain
    /// - Parameter key: Keychain key identifier
    /// - Returns: Retrieved data
    /// - Throws: SableError on retrieval failure
    public func retrieveSecurely(forKey key: String) throws -> Data {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        guard status == errSecSuccess else {
            throw SableError.cryptographicError("Keychain retrieval failed: \(status)")
        }
        
        guard let data = result as? Data else {
            throw SableError.cryptographicError("Invalid data type from keychain")
        }
        
        return data
    }
    
    /// Delete data from iOS Keychain
    /// - Parameter key: Keychain key identifier
    /// - Throws: SableError on deletion failure
    public func deleteSecurely(forKey key: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key
        ]
        
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw SableError.cryptographicError("Keychain deletion failed: \(status)")
        }
    }
}

// MARK: - Biometric Authentication

extension SableCore {
    
    /// Check if biometric authentication is available
    /// - Returns: True if biometrics are available
    public static func isBiometricAvailable() -> Bool {
        let context = LAContext()
        var error: NSError?
        
        return context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
    }
    
    /// Get available biometric type
    /// - Returns: Biometric type description
    public static func getBiometricType() -> String {
        let context = LAContext()
        var error: NSError?
        
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            return "None"
        }
        
        switch context.biometryType {
        case .faceID:
            return "Face ID"
        case .touchID:
            return "Touch ID"
        case .none:
            return "None"
        @unknown default:
            return "Unknown"
        }
    }
    
    /// Request biometric authentication
    /// - Parameter reason: Reason for authentication request
    /// - Returns: Authentication success
    public static func authenticateWithBiometrics(reason: String) async throws -> Bool {
        let context = LAContext()
        
        do {
            let result = try await context.evaluatePolicy(
                .deviceOwnerAuthenticationWithBiometrics,
                localizedReason: reason
            )
            return result
        } catch {
            throw SableError.cryptographicError("Biometric authentication failed: \(error.localizedDescription)")
        }
    }
}
