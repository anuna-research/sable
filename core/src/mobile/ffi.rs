// SABLE Mobile FFI Layer
//
// C-compatible Foreign Function Interface for mobile platforms.
// Provides memory-safe bindings for Android JNI and iOS Swift integration.
//
// REQ-005: Error messages are sanitized to prevent information leakage.
// Only generic error codes are exposed to external callers.
// Detailed errors should be logged internally before conversion.

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_double, c_int, c_uchar};
use std::ptr;
use std::slice;

use super::MobileSable;
use crate::crypto::rng::SecureRng;
use crate::error::{PublicErrorCode, SableError};
use crate::types::{Distance, Salt, Timestamp};

// Opaque handles for mobile platforms
pub type SableHandle = *mut MobileSable;

/// Error codes for mobile FFI (REQ-005: Sanitized for external exposure)
///
/// These error codes do not reveal implementation details, file paths,
/// internal state, timing information, or algorithm details.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SableErrorCode {
    /// Operation completed successfully
    Success = 0,
    /// Invalid input parameters or data format
    InvalidInput = 1,
    /// Processing operation failed
    ProcessingFailed = 2,
    /// Internal system error
    SystemError = 3,
}

impl From<SableError> for SableErrorCode {
    /// Convert internal SableError to sanitized FFI error code (REQ-005)
    ///
    /// NOTE: The original error should be logged internally before this conversion
    /// for administrator access to detailed error information.
    fn from(error: SableError) -> Self {
        // Map using PublicError to ensure consistent sanitization
        match error.to_public_error().code {
            PublicErrorCode::InvalidInput => SableErrorCode::InvalidInput,
            PublicErrorCode::ProcessingFailed => SableErrorCode::ProcessingFailed,
            PublicErrorCode::SystemError => SableErrorCode::SystemError,
        }
    }
}

impl From<PublicErrorCode> for SableErrorCode {
    fn from(code: PublicErrorCode) -> Self {
        match code {
            PublicErrorCode::InvalidInput => SableErrorCode::InvalidInput,
            PublicErrorCode::ProcessingFailed => SableErrorCode::ProcessingFailed,
            PublicErrorCode::SystemError => SableErrorCode::SystemError,
        }
    }
}

/// Internal helper to log error details before sanitization (REQ-005)
///
/// This function logs the detailed error information for administrator access
/// before converting to a sanitized error code for external exposure.
///
/// In production, this should integrate with a secure logging framework
/// that is only accessible to authorized administrators.
#[cfg(feature = "internal-logging")]
fn log_internal_error(error: &SableError, context: &str) {
    // Log detailed error for administrators
    // This log should only be accessible to authorized personnel
    eprintln!("[INTERNAL] {} - Error: {:?}", context, error);
}

#[cfg(not(feature = "internal-logging"))]
fn log_internal_error(_error: &SableError, _context: &str) {
    // Logging disabled - errors are silently sanitized
}

/// Convert SableError to FFI error code with internal logging (REQ-005)
fn sanitize_error(error: SableError, context: &str) -> SableErrorCode {
    log_internal_error(&error, context);
    error.into()
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
        let data_ptr = Box::into_raw(data.into_boxed_slice()) as *mut c_uchar;
        
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
                Err(e) => SableResult::error(sanitize_error(e, "commitment_serialization")),
            }
        }
        Err(e) => SableResult::error(sanitize_error(e, "generate_commitment")),
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
        Err(e) => return SableResult::error(sanitize_error(e, "parse_commitment")),
    };

    let threshold = Distance::new(threshold);
    let timestamp = Timestamp::from_unix(current_time);

    // Generate proof
    match sable.generate_proof(features_slice, &salt, &commitment, threshold, timestamp) {
        Ok(proof_bytes) => SableResult::success(proof_bytes),
        Err(e) => SableResult::error(sanitize_error(e, "generate_proof")),
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
#[no_mangle]
pub extern "C" fn sable_free_result(result: &mut SableResult) {
    if !result.data.is_null() {
        unsafe {
            let _ = Vec::from_raw_parts(result.data, result.data_len as usize, result.data_len as usize);
        }
        result.data = ptr::null_mut();
        result.data_len = 0;
    }
}

/// Get error message string (REQ-005: Sanitized for external exposure)
///
/// Returns generic error messages that do not reveal implementation details,
/// file paths, internal state, timing information, or algorithm details.
#[no_mangle]
pub extern "C" fn sable_error_message(error_code: SableErrorCode) -> *const c_char {
    // REQ-005: Use generic messages that don't leak implementation details
    let message = match error_code {
        SableErrorCode::Success => "Success",
        SableErrorCode::InvalidInput => "Invalid input provided",
        SableErrorCode::ProcessingFailed => "Operation could not be completed",
        SableErrorCode::SystemError => "An internal error occurred",
    };

    match CString::new(message) {
        Ok(c_str) => c_str.into_raw(),
        Err(_) => ptr::null(),
    }
}

/// Free error message string
#[no_mangle]
pub extern "C" fn sable_free_error_message(message: *mut c_char) {
    if !message.is_null() {
        unsafe {
            let _ = CString::from_raw(message);
        }
    }
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
