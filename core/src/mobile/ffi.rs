//! Withdrawn mobile C ABI. Compiled only by the rejecting-backend test harness.
//! No production export is restored by the boundary repairs.
//!
//! All pointer-taking exports are unsafe: C callers must provide live, initialized,
//! correctly sized allocations with valid aliasing/lifetime and ownership. Numeric
//! checks cannot validate arbitrary addresses, stale handles or forged allocations.
//! Output buffers belong to SABLE and must be returned exactly once, unmodified,
//! through sable_free_result; never use the host allocator to release them.
#![allow(unsafe_code)]
#![allow(missing_docs)]

#[cfg(panic = "abort")]
compile_error!("SABLE FFI requires panic=unwind for its ABI panic boundary");

#[path = "ffi_boundary.rs"]
mod boundary;

use super::MobileSable;
use crate::{
    crypto::{pedersen::PedersenCommitment, rng::SecureRng},
    error::{PublicErrorCode, SableError},
    types::{Distance, Salt, Timestamp},
};
use boundary::{check_region, guard, input, output};
use std::{
    os::raw::{c_char, c_double, c_int, c_uchar},
    ptr,
};

const FEATURES: usize = 512;
const MAX_PROOF: usize = 10 * 1024;

pub type SableHandle = *mut MobileSable;

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SableErrorCode {
    Success = 0,
    InvalidInput = 1,
    ProcessingFailed = 2,
    SystemError = 3,
}

impl From<SableError> for SableErrorCode {
    fn from(error: SableError) -> Self {
        match error.to_public_error().code {
            PublicErrorCode::InvalidInput => Self::InvalidInput,
            PublicErrorCode::ProcessingFailed => Self::ProcessingFailed,
            PublicErrorCode::SystemError => Self::SystemError,
        }
    }
}

#[repr(C)]
pub struct SableResult {
    pub error_code: SableErrorCode,
    pub data: *mut c_uchar,
    pub data_len: c_int,
}

impl SableResult {
    fn error(code: SableErrorCode) -> Self {
        Self {
            error_code: code,
            data: ptr::null_mut(),
            data_len: 0,
        }
    }

    fn success(data: Vec<u8>) -> Self {
        if data.is_empty() || data.len() > MAX_PROOF {
            return Self::error(SableErrorCode::ProcessingFailed);
        }
        let Ok(data_len) = c_int::try_from(data.len()) else {
            return Self::error(SableErrorCode::SystemError);
        };
        Self {
            error_code: SableErrorCode::Success,
            data: Box::into_raw(data.into_boxed_slice()).cast(),
            data_len,
        }
    }
}

fn result(operation: impl FnOnce() -> Result<Vec<u8>, SableErrorCode>) -> SableResult {
    guard(
        SableResult::error(SableErrorCode::SystemError),
        || match operation() {
            Ok(data) => SableResult::success(data),
            Err(code) => SableResult::error(code),
        },
    )
}

fn valid<T>(pointer: *const T, len: c_int, min: usize, max: usize) -> Result<(), SableErrorCode> {
    check_region(pointer, len, min..=max)
        .map(|_| ())
        .ok_or(SableErrorCode::InvalidInput)
}

#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn sable_new() -> SableHandle {
    guard(ptr::null_mut(), || {
        MobileSable::new()
            .map(|value| Box::into_raw(Box::new(value)))
            .unwrap_or(ptr::null_mut())
    })
}

/// # Safety
/// Handle must be null or a live handle returned by sable_new, uniquely owned and
/// not concurrently used. A freed/copied/forged handle is invalid.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn sable_free(handle: SableHandle) {
    guard((), || {
        if check_region(handle, 1, 1..=1).is_some() {
            unsafe {
                drop(Box::from_raw(handle));
            }
        }
    })
}

/// # Safety
/// Handle must be live; features must hold features_len initialized f64 values
/// and salt must hold 32 bytes. Inputs may not be mutated during this call.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn sable_generate_commitment(
    handle: SableHandle,
    features: *const c_double,
    features_len: c_int,
    salt: *const c_uchar,
) -> SableResult {
    result(|| {
        // Validate every numerical boundary before the first pointer dereference.
        valid(features, features_len, FEATURES, FEATURES)?;
        valid(salt, 32, 32, 32)?;
        valid(handle, 1, 1, 1)?;
        let features = unsafe { input(features, features_len, FEATURES..=FEATURES) }
            .ok_or(SableErrorCode::InvalidInput)?;
        if features.iter().any(|f| !f.is_finite()) {
            return Err(SableErrorCode::InvalidInput);
        }
        let salt = Salt::from_bytes(
            unsafe { input(salt, 32, 32..=32) }.ok_or(SableErrorCode::InvalidInput)?,
        )
        .map_err(SableErrorCode::from)?;
        let sable = &unsafe { input(handle, 1, 1..=1) }.ok_or(SableErrorCode::InvalidInput)?[0];
        let commitment = sable
            .generate_commitment(features, &salt)
            .map_err(SableErrorCode::from)?;
        Ok(commitment.to_bytes().to_vec())
    })
}

/// # Safety
/// As for sable_generate_commitment; commitment must also hold 48 readable bytes.
/// This remains the withdrawn legacy proof API, not the policy-aware replacement.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn sable_generate_proof(
    handle: SableHandle,
    features: *const c_double,
    features_len: c_int,
    salt: *const c_uchar,
    commitment: *const c_uchar,
    threshold: c_double,
    current_time: u64,
) -> SableResult {
    result(|| {
        valid(features, features_len, FEATURES, FEATURES)?;
        valid(salt, 32, 32, 32)?;
        valid(commitment, 48, 48, 48)?;
        valid(handle, 1, 1, 1)?;
        if !threshold.is_finite() || !(0.0..=1.0).contains(&threshold) {
            return Err(SableErrorCode::InvalidInput);
        }
        let features = unsafe { input(features, features_len, FEATURES..=FEATURES) }
            .ok_or(SableErrorCode::InvalidInput)?;
        if features.iter().any(|f| !f.is_finite()) {
            return Err(SableErrorCode::InvalidInput);
        }
        let salt = Salt::from_bytes(
            unsafe { input(salt, 32, 32..=32) }.ok_or(SableErrorCode::InvalidInput)?,
        )
        .map_err(SableErrorCode::from)?;
        let bytes =
            unsafe { input(commitment, 48, 48..=48) }.ok_or(SableErrorCode::InvalidInput)?;
        let commitment = PedersenCommitment::from_bytes(
            bytes.try_into().map_err(|_| SableErrorCode::InvalidInput)?,
        )
        .map_err(SableErrorCode::from)?;
        let sable = &unsafe { input(handle, 1, 1..=1) }.ok_or(SableErrorCode::InvalidInput)?[0];
        sable
            .generate_proof(
                features,
                &salt,
                &commitment,
                Distance::new(threshold),
                Timestamp::from_unix(current_time),
            )
            .map_err(SableErrorCode::from)
    })
}

/// # Safety
/// Handle must be live; proof must hold proof_len readable bytes and commitment
/// must hold 48 readable bytes. No concurrent mutation of inputs is permitted.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn sable_verify_proof(
    handle: SableHandle,
    proof: *const c_uchar,
    proof_len: c_int,
    commitment: *const c_uchar,
    threshold: c_double,
    current_time: u64,
) -> c_int {
    guard(-1, || {
        let operation = || -> Option<c_int> {
            valid(proof, proof_len, 1, MAX_PROOF).ok()?;
            valid(commitment, 48, 48, 48).ok()?;
            valid(handle, 1, 1, 1).ok()?;
            if !threshold.is_finite() || !(0.0..=1.0).contains(&threshold) {
                return None;
            }
            let proof = unsafe { input(proof, proof_len, 1..=MAX_PROOF) }?;
            let bytes = unsafe { input(commitment, 48, 48..=48) }?;
            let commitment = PedersenCommitment::from_bytes(bytes.try_into().ok()?).ok()?;
            let sable = &unsafe { input(handle, 1, 1..=1) }?[0];
            sable
                .verify_proof(
                    proof,
                    &commitment,
                    Distance::new(threshold),
                    Timestamp::from_unix(current_time),
                )
                .ok()
                .map(c_int::from)
        };
        operation().unwrap_or(-1)
    })
}

/// # Safety
/// salt_out must point to an exclusively writable, initialized 32-byte buffer.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn sable_generate_salt(salt_out: *mut c_uchar) -> c_int {
    guard(-1, || {
        if valid(salt_out, 32, 32, 32).is_err() {
            return -1;
        }
        let Ok(mut rng) = SecureRng::new() else {
            return -1;
        };
        let Ok(bytes) = Salt::random(&mut rng).to_bytes() else {
            return -1;
        };
        let Some(destination) = (unsafe { output(salt_out, 32, 32..=32) }) else {
            return -1;
        };
        destination.copy_from_slice(&bytes);
        0
    })
}

/// # Safety
/// result must be null or an exclusively writable initialized result from SABLE.
/// Its data pointer and length must be unmodified, and the allocation must not
/// have been freed through another copy. Repeated calls on the SAME cleared
/// result are harmless; copying an owning result does not duplicate ownership.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn sable_free_result(result: *mut SableResult) {
    guard((), || {
        let Some(result) = (unsafe { output(result, 1, 1..=1) }) else {
            return;
        };
        let result = &mut result[0];
        if result.data.is_null() {
            result.data_len = 0;
            return;
        }
        let Some(len) = check_region(result.data, result.data_len, 1..=MAX_PROOF) else {
            result.error_code = SableErrorCode::InvalidInput;
            return; // Never reconstruct an allocation from an invalid length.
        };
        let pointer = result.data;
        result.data = ptr::null_mut();
        result.data_len = 0;
        // Match the exact Box<[u8]> allocator/layout used by success(), not a
        // guessed Vec capacity. Allocation provenance is the caller contract.
        unsafe {
            drop(Box::from_raw(ptr::slice_from_raw_parts_mut(pointer, len)));
        }
    })
}

/// Borrowed static string; callers must not free it with their allocator.
/// An integer parameter avoids undefined behavior for unknown C enum values.
#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn sable_error_message(error_code: c_int) -> *const c_char {
    guard(ptr::null(), || {
        let message: &'static [u8] = match error_code {
            0 => b"Success\0",
            1 => b"Invalid input provided\0",
            2 => b"Operation could not be completed\0",
            _ => b"An internal error occurred\0",
        };
        message.as_ptr().cast()
    })
}

/// Compatibility no-op: error messages are borrowed static strings.
#[cfg_attr(not(test), no_mangle)]
pub extern "C" fn sable_free_error_message(_message: *mut c_char) {}

#[cfg(test)]
mod allocation_tests {
    use super::*;

    #[test]
    fn boxed_output_uses_matching_free_and_clears_owner() {
        let mut bytes = Vec::with_capacity(1024);
        bytes.extend_from_slice(&[1, 2, 3]);
        let mut result = SableResult::success(bytes);
        assert_eq!(result.data_len, 3);
        assert_eq!(
            unsafe { input(result.data, result.data_len, 1..=MAX_PROOF) }.unwrap(),
            &[1, 2, 3]
        );
        unsafe {
            sable_free_result(&mut result);
        }
        assert!(result.data.is_null());
        assert_eq!(result.data_len, 0);
        unsafe {
            sable_free_result(&mut result);
        }
    }

    #[test]
    fn invalid_output_length_is_rejected_before_allocator_reconstruction() {
        for len in [c_int::MIN, -1, 0, c_int::MAX, MAX_PROOF as c_int + 1] {
            let mut result = SableResult::success(vec![42; 3]);
            let pointer = result.data;
            result.data_len = len;
            unsafe {
                sable_free_result(&mut result);
            }
            assert_eq!(result.error_code, SableErrorCode::InvalidInput);
            assert_eq!(result.data, pointer);
            // Restore the real allocation descriptor to release it legitimately.
            result.data_len = 3;
            unsafe {
                sable_free_result(&mut result);
            }
        }
    }

    #[test]
    fn output_size_is_bounded_before_ownership_transfer() {
        for bytes in [vec![], vec![0; MAX_PROOF + 1]] {
            let result = SableResult::success(bytes);
            assert_ne!(result.error_code, SableErrorCode::Success);
            assert!(result.data.is_null());
            assert_eq!(result.data_len, 0);
        }
        let mut result = SableResult::success(vec![0; MAX_PROOF]);
        assert_eq!(result.error_code, SableErrorCode::Success);
        unsafe {
            sable_free_result(&mut result);
        }
    }
}
