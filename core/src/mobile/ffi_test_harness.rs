//! ABI plumbing tests only. This backend NEVER generates or accepts a proof.
//! It cannot establish mobile support or the correctness of the legacy backend.
#![allow(unsafe_code)]

use crate::{
    crypto::pedersen::PedersenCommitment,
    types::{Distance, Salt, Timestamp},
    Result, SableError,
};
use std::cell::Cell;

#[path = "ffi.rs"]
mod ffi;

thread_local! {
    static CALLS: Cell<usize> = const { Cell::new(0) };
    static PANIC: Cell<bool> = const { Cell::new(false) };
}

struct MobileSable {
    _marker: u8,
}

impl MobileSable {
    fn new() -> Result<Self> {
        Ok(Self { _marker: 1 })
    }
    fn reject<T>() -> Result<T> {
        CALLS.set(CALLS.get() + 1);
        assert!(!PANIC.get(), "rejecting backend panic fixture");
        Err(SableError::InvalidInput(
            "test backend rejects all operations".into(),
        ))
    }
    fn generate_commitment(&self, _: &[f64], _: &Salt) -> Result<PedersenCommitment> {
        Self::reject()
    }
    fn generate_proof(
        &self,
        _: &[f64],
        _: &Salt,
        _: &PedersenCommitment,
        _: Distance,
        _: Timestamp,
    ) -> Result<Vec<u8>> {
        Self::reject()
    }
    fn verify_proof(
        &self,
        _: &[u8],
        _: &PedersenCommitment,
        _: Distance,
        _: Timestamp,
    ) -> Result<bool> {
        Self::reject()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ffi::*;
    use std::{ffi::CStr, os::raw::c_int, ptr};

    struct Handle(SableHandle);
    impl Handle {
        fn new() -> Self {
            let handle = sable_new();
            assert!(!handle.is_null());
            Self(handle)
        }
    }
    impl Drop for Handle {
        fn drop(&mut self) {
            unsafe {
                sable_free(self.0);
            }
        }
    }

    fn commitment() -> [u8; 48] {
        use crate::crypto::{bls381::Fr, pedersen};
        pedersen::commit(Fr::from(1), Fr::from(2), &pedersen::Generators::default()).to_bytes()
    }

    #[test]
    fn negative_and_out_of_protocol_lengths_never_reach_backend() {
        let handle = Handle::new();
        let features = [0.0; 512];
        let salt = [0; 32];
        let commitment = commitment();
        CALLS.set(0);
        for length in [c_int::MIN, -1, 0, 511, 513, c_int::MAX] {
            let result = unsafe {
                sable_generate_commitment(handle.0, features.as_ptr(), length, salt.as_ptr())
            };
            assert_eq!(result.error_code, SableErrorCode::InvalidInput);
            assert!(result.data.is_null());
            let result = unsafe {
                sable_generate_proof(
                    handle.0,
                    features.as_ptr(),
                    length,
                    salt.as_ptr(),
                    commitment.as_ptr(),
                    0.25,
                    0,
                )
            };
            assert_eq!(result.error_code, SableErrorCode::InvalidInput);
        }
        for length in [c_int::MIN, -1, 0, 10241, c_int::MAX] {
            assert_eq!(
                unsafe {
                    sable_verify_proof(
                        handle.0,
                        [1u8].as_ptr(),
                        length,
                        commitment.as_ptr(),
                        0.25,
                        0,
                    )
                },
                -1
            );
        }
        assert_eq!(CALLS.get(), 0);
    }

    #[test]
    fn null_and_misaligned_inputs_are_rejected() {
        let handle = Handle::new();
        let salt = [0; 32];
        for pointer in [ptr::null(), 1usize as *const f64] {
            let result =
                unsafe { sable_generate_commitment(handle.0, pointer, 512, salt.as_ptr()) };
            assert_eq!(result.error_code, SableErrorCode::InvalidInput);
        }
        let result = unsafe {
            sable_generate_commitment(ptr::null_mut(), [0.0; 512].as_ptr(), 512, salt.as_ptr())
        };
        assert_eq!(result.error_code, SableErrorCode::InvalidInput);
        assert_eq!(unsafe { sable_generate_salt(ptr::null_mut()) }, -1);
        unsafe {
            sable_free_result(ptr::null_mut());
            sable_free(ptr::null_mut());
        }
    }

    #[test]
    fn nonfinite_features_and_invalid_thresholds_are_rejected_before_backend() {
        let handle = Handle::new();
        let salt = [0; 32];
        let commitment = commitment();
        CALLS.set(0);
        for invalid in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            let mut features = [0.0; 512];
            features[511] = invalid;
            assert_eq!(
                unsafe {
                    sable_generate_commitment(handle.0, features.as_ptr(), 512, salt.as_ptr())
                }
                .error_code,
                SableErrorCode::InvalidInput
            );
        }
        for threshold in [f64::NAN, f64::INFINITY, -0.1, 1.1] {
            assert_eq!(
                unsafe {
                    sable_generate_proof(
                        handle.0,
                        [0.0; 512].as_ptr(),
                        512,
                        salt.as_ptr(),
                        commitment.as_ptr(),
                        threshold,
                        0,
                    )
                }
                .error_code,
                SableErrorCode::InvalidInput
            );
            assert_eq!(
                unsafe {
                    sable_verify_proof(
                        handle.0,
                        [1u8].as_ptr(),
                        1,
                        commitment.as_ptr(),
                        threshold,
                        0,
                    )
                },
                -1
            );
        }
        assert_eq!(CALLS.get(), 0);
    }

    #[test]
    fn actual_exports_contain_backend_panics() {
        let handle = Handle::new();
        let salt = [0; 32];
        let features = [0.0; 512];
        let commitment = commitment();
        PANIC.set(true);
        let a =
            unsafe { sable_generate_commitment(handle.0, features.as_ptr(), 512, salt.as_ptr()) };
        let b = unsafe {
            sable_generate_proof(
                handle.0,
                features.as_ptr(),
                512,
                salt.as_ptr(),
                commitment.as_ptr(),
                0.25,
                0,
            )
        };
        let c = unsafe {
            sable_verify_proof(handle.0, [1u8].as_ptr(), 1, commitment.as_ptr(), 0.25, 0)
        };
        PANIC.set(false);
        assert_eq!(a.error_code, SableErrorCode::SystemError);
        assert_eq!(b.error_code, SableErrorCode::SystemError);
        assert!(a.data.is_null() && b.data.is_null());
        assert_eq!(c, -1);
    }

    #[test]
    fn valid_inputs_still_cannot_generate_or_accept_a_stub_proof() {
        let handle = Handle::new();
        let commitment = commitment();
        let result = unsafe {
            sable_generate_proof(
                handle.0,
                [0.0; 512].as_ptr(),
                512,
                [0u8; 32].as_ptr(),
                commitment.as_ptr(),
                0.25,
                0,
            )
        };
        assert_ne!(result.error_code, SableErrorCode::Success);
        assert!(result.data.is_null());
        assert_eq!(
            unsafe {
                sable_verify_proof(handle.0, [1u8].as_ptr(), 1, commitment.as_ptr(), 0.25, 0)
            },
            -1
        );
    }

    #[test]
    fn unknown_error_integers_and_static_message_release_are_safe() {
        for code in [c_int::MIN, -1, 0, 1, 2, 3, c_int::MAX] {
            let message = sable_error_message(code);
            assert!(!message.is_null());
            assert!(unsafe { CStr::from_ptr(message) }.to_bytes().len() > 0);
            sable_free_error_message(message.cast_mut());
            assert_eq!(message, sable_error_message(code));
        }
    }

    #[test]
    fn salt_writes_exactly_the_fixed_buffer() {
        let mut destination = [0xA5; 34];
        assert_eq!(
            unsafe { sable_generate_salt(destination[1..33].as_mut_ptr()) },
            0
        );
        assert_eq!((destination[0], destination[33]), (0xA5, 0xA5));
        assert!(destination[1..33].iter().any(|byte| *byte != 0xA5));
    }
}
