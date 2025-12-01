// SABLE Mobile FFI Layer
//
// C-compatible Foreign Function Interface for mobile platforms.
// Provides memory-safe bindings for Android JNI and iOS Swift integration.

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_double, c_int, c_uchar};
use std::ptr;
use std::slice;

use super::MobileSable;
use crate::crypto::rng::SecureRng;
use crate::types::{Distance, Salt, Timestamp};

// Opaque handles for mobile platforms
pub type SableHandle = *mut MobileSable;

/// Error codes for mobile FFI
#[repr(C)]
pub enum SableErrorCode {
    Success = 0,
    InvalidInput = 1,
    CryptoError = 2,
    SerializationError = 3,
    OutOfMemory = 4,
    Unknown = 99,
}

impl From<crate::error::SableError> for SableErrorCode {
    fn from(error: crate::error::SableError) -> Self {
        match error {
            crate::error::SableError::InvalidFeature => SableErrorCode::InvalidInput,
            crate::error::SableError::CryptoError(_) => SableErrorCode::CryptoError,
            crate::error::SableError::SerializationError(_) => SableErrorCode::SerializationError,
            crate::error::SableError::InvalidCommitment(_) => SableErrorCode::CryptoError,
            crate::error::SableError::ProofGeneration(_) => SableErrorCode::CryptoError,
            crate::error::SableError::ProofVerification(_) => SableErrorCode::CryptoError,
            crate::error::SableError::Cryptographic(_) => SableErrorCode::CryptoError,
            crate::error::SableError::InvalidInput(_) => SableErrorCode::InvalidInput,
            crate::error::SableError::RandomGeneration => SableErrorCode::CryptoError,
        }
    }
}

/// FFI result structure (for internal use only)
#[repr(C)]
#[doc(hidden)]
pub struct SableResult {
    pub error_code: SableErrorCode,
    pub data: *mut c_uchar,
    pub data_len: c_int,
}

impl SableResult {
    fn success(data: Vec<u8>) -> Self {
        let data_len = data.len() as c_int;
        // Convert Vec to boxed slice, then leak as raw pointer
        // This ensures the allocation matches what we'll free later
        let boxed_slice = data.into_boxed_slice();
        let data_ptr = Box::into_raw(boxed_slice) as *mut c_uchar;

        Self {
            error_code: SableErrorCode::Success,
            data: data_ptr,
            data_len,
        }
    }

    fn error(code: SableErrorCode) -> Self {
        Self {
            error_code: code,
            data: ptr::null_mut(),
            data_len: 0,
        }
    }
}

// Core SABLE FFI functions

/// Create new SABLE instance
/// Returns opaque handle or null on error
#[no_mangle]
pub extern "C" fn sable_new() -> SableHandle {
    match MobileSable::new() {
        Ok(sable) => Box::into_raw(Box::new(sable)),
        Err(_) => ptr::null_mut(),
    }
}

/// Free SABLE instance
#[no_mangle]
pub extern "C" fn sable_free(handle: SableHandle) {
    if !handle.is_null() {
        unsafe {
            let _ = Box::from_raw(handle);
        }
    }
}

/// Generate biometric commitment
/// 
/// # Arguments
/// * `handle` - SABLE instance handle
/// * `features` - Array of biometric features (f64)
/// * `features_len` - Number of features
/// * `salt` - 32-byte salt array
/// 
/// # Returns
/// SableResult with commitment data (48 bytes) or error
#[no_mangle]
pub extern "C" fn sable_generate_commitment(
    handle: SableHandle,
    features: *const c_double,
    features_len: c_int,
    salt: *const c_uchar,
) -> SableResult {
    if handle.is_null() || features.is_null() || salt.is_null() {
        return SableResult::error(SableErrorCode::InvalidInput);
    }
    
    let sable = unsafe { &*handle };
    
    // Convert features from C array
    let features_slice = unsafe {
        slice::from_raw_parts(features, features_len as usize)
    };
    
    // Convert salt from C array (32 bytes)
    let salt_slice = unsafe {
        slice::from_raw_parts(salt, 32)
    };
    
    let salt = match Salt::from_bytes(salt_slice) {
        Ok(s) => s,
        Err(_) => return SableResult::error(SableErrorCode::InvalidInput),
    };
    
    // Generate commitment
    match sable.generate_commitment(features_slice, &salt) {
        Ok(commitment) => {
            // Serialize commitment to 48-byte format
            match commitment.to_bytes() {
                Ok(bytes) => SableResult::success(bytes),
                Err(e) => SableResult::error(e.into()),
            }
        }
        Err(e) => SableResult::error(e.into()),
    }
}

/// Generate zero-knowledge proof
///
/// # Arguments
/// * `handle` - SABLE instance handle  
/// * `features` - Array of biometric features
/// * `features_len` - Number of features
/// * `salt` - 32-byte salt array
/// * `commitment` - 48-byte commitment array
/// * `threshold` - Distance threshold (f64)
/// * `current_time` - Current timestamp (u64)
///
/// # Returns
/// SableResult with proof data or error
#[no_mangle]
pub extern "C" fn sable_generate_proof(
    handle: SableHandle,
    features: *const c_double,
    features_len: c_int,
    salt: *const c_uchar,
    commitment: *const c_uchar,
    threshold: c_double,
    current_time: u64,
) -> SableResult {
    if handle.is_null() || features.is_null() || salt.is_null() || commitment.is_null() {
        return SableResult::error(SableErrorCode::InvalidInput);
    }
    
    let sable = unsafe { &*handle };
    
    // Convert inputs from C
    let features_slice = unsafe {
        slice::from_raw_parts(features, features_len as usize)
    };
    
    let salt_slice = unsafe {
        slice::from_raw_parts(salt, 32)
    };
    
    let commitment_slice = unsafe {
        slice::from_raw_parts(commitment, 48)
    };
    
    // Parse inputs
    let salt = match Salt::from_bytes(salt_slice) {
        Ok(s) => s,
        Err(_) => return SableResult::error(SableErrorCode::InvalidInput),
    };
    
    let commitment = match crate::crypto::pedersen::PedersenCommitment::from_bytes(commitment_slice) {
        Ok(c) => c,
        Err(e) => return SableResult::error(e.into()),
    };
    
    let threshold = Distance::new(threshold);
    let timestamp = Timestamp::from_unix(current_time);
    
    // Generate proof
    match sable.generate_proof(features_slice, &salt, &commitment, threshold, timestamp) {
        Ok(proof_bytes) => SableResult::success(proof_bytes),
        Err(e) => SableResult::error(e.into()),
    }
}

/// Verify zero-knowledge proof
///
/// # Arguments
/// * `handle` - SABLE instance handle
/// * `proof` - Proof data bytes
/// * `proof_len` - Proof data length
/// * `commitment` - 48-byte commitment array
/// * `threshold` - Distance threshold (f64)
/// * `current_time` - Current timestamp (u64)
///
/// # Returns
/// 1 if verification succeeds, 0 if fails, -1 on error
#[no_mangle]
pub extern "C" fn sable_verify_proof(
    handle: SableHandle,
    proof: *const c_uchar,
    proof_len: c_int,
    commitment: *const c_uchar,
    threshold: c_double,
    current_time: u64,
) -> c_int {
    if handle.is_null() || proof.is_null() || commitment.is_null() {
        return -1; // Error
    }
    
    let sable = unsafe { &*handle };
    
    // Convert inputs from C
    let proof_slice = unsafe {
        slice::from_raw_parts(proof, proof_len as usize)
    };
    
    let commitment_slice = unsafe {
        slice::from_raw_parts(commitment, 48)
    };
    
    // Parse inputs
    let commitment = match crate::crypto::pedersen::PedersenCommitment::from_bytes(commitment_slice) {
        Ok(c) => c,
        Err(_) => return -1,
    };
    
    let threshold = Distance::new(threshold);
    let timestamp = Timestamp::from_unix(current_time);
    
    // Verify proof
    match sable.verify_proof(proof_slice, &commitment, threshold, timestamp) {
        Ok(true) => 1,   // Verification succeeded
        Ok(false) => 0,  // Verification failed
        Err(_) => -1,    // Error occurred
    }
}

/// Generate random salt for commitment
/// 
/// # Arguments
/// * `salt_out` - Output buffer for 32-byte salt
///
/// # Returns
/// 0 on success, -1 on error
#[no_mangle]
pub extern "C" fn sable_generate_salt(salt_out: *mut c_uchar) -> c_int {
    if salt_out.is_null() {
        return -1;
    }
    
    let mut rng = match SecureRng::new() {
        Ok(r) => r,
        Err(_) => return -1,
    };
    let salt = Salt::random(&mut rng);
    
    match salt.to_bytes() {
        Ok(bytes) => {
            unsafe {
                ptr::copy_nonoverlapping(bytes.as_ptr(), salt_out, 32);
            }
            0
        }
        Err(_) => -1,
    }
}

/// Free result data allocated by SABLE FFI functions
///
/// # Safety
/// The result must have been created by a SABLE FFI function.
/// The data pointer must not have been modified or freed.
#[no_mangle]
pub extern "C" fn sable_free_result(result: &mut SableResult) {
    if !result.data.is_null() && result.data_len > 0 {
        unsafe {
            // Reconstruct the boxed slice that was created in SableResult::success()
            // This is safe because:
            // 1. We created the pointer with Box::into_raw(data.into_boxed_slice())
            // 2. The data_len matches the original slice length
            let slice_ptr = std::ptr::slice_from_raw_parts_mut(result.data, result.data_len as usize);
            let _ = Box::from_raw(slice_ptr);
        }
        result.data = ptr::null_mut();
        result.data_len = 0;
    }
}

/// Get error message string (for debugging)
///
/// Returns a pointer to a static string - DO NOT free this pointer.
/// The returned pointer is valid for the lifetime of the program.
#[no_mangle]
pub extern "C" fn sable_error_message(error_code: SableErrorCode) -> *const c_char {
    // Use static strings to avoid memory leaks
    // These are null-terminated C strings stored in static memory
    static SUCCESS: &[u8] = b"Success\0";
    static INVALID_INPUT: &[u8] = b"Invalid input parameters\0";
    static CRYPTO_ERROR: &[u8] = b"Cryptographic operation failed\0";
    static SERIALIZATION_ERROR: &[u8] = b"Serialization error\0";
    static OUT_OF_MEMORY: &[u8] = b"Out of memory\0";
    static UNKNOWN: &[u8] = b"Unknown error\0";

    let message: &[u8] = match error_code {
        SableErrorCode::Success => SUCCESS,
        SableErrorCode::InvalidInput => INVALID_INPUT,
        SableErrorCode::CryptoError => CRYPTO_ERROR,
        SableErrorCode::SerializationError => SERIALIZATION_ERROR,
        SableErrorCode::OutOfMemory => OUT_OF_MEMORY,
        SableErrorCode::Unknown => UNKNOWN,
    };

    message.as_ptr() as *const c_char
}

/// Free error message string (DEPRECATED - no longer needed)
///
/// This function is kept for backwards compatibility but does nothing.
/// Error messages now use static strings that do not need to be freed.
#[no_mangle]
#[deprecated(note = "Error messages now use static strings and do not need to be freed")]
pub extern "C" fn sable_free_error_message(_message: *mut c_char) {
    // No-op: error messages are now static strings
    // This function is kept for backwards compatibility with existing code
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_ffi_sable_creation() {
        let handle = sable_new();
        assert!(!handle.is_null());
        sable_free(handle);
    }
    
    #[test]
    fn test_ffi_salt_generation() {
        let mut salt = [0u8; 32];
        let result = sable_generate_salt(salt.as_mut_ptr());
        assert_eq!(result, 0);
        
        // Salt should not be all zeros
        assert!(salt.iter().any(|&x| x != 0));
    }
}
