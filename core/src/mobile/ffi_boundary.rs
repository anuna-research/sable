//! Checked raw-memory boundary shared by the withdrawn FFI and its test harness.
//! Numeric checks cannot establish allocation provenance or pointer validity.
#![allow(unsafe_code)]

use std::{
    mem::{align_of, size_of},
    ops::RangeInclusive,
    os::raw::c_int,
};

fn checked_bytes(len: usize, element_size: usize) -> Option<usize> {
    let bytes = len.checked_mul(element_size)?;
    if element_size == 0 || bytes > isize::MAX as usize {
        return None;
    }
    Some(bytes)
}

pub(super) fn checked_len<T>(len: c_int, allowed: RangeInclusive<usize>) -> Option<usize> {
    let len = usize::try_from(len).ok()?;
    checked_bytes(len, size_of::<T>())?;
    if !allowed.contains(&len) {
        return None;
    }
    Some(len)
}

pub(super) fn check_region<T>(
    ptr: *const T,
    len: c_int,
    allowed: RangeInclusive<usize>,
) -> Option<usize> {
    let len = checked_len::<T>(len, allowed)?;
    let address = ptr as usize;
    if ptr.is_null() || address % align_of::<T>() != 0 {
        return None;
    }
    address.checked_add(len.checked_mul(size_of::<T>())?)?;
    Some(len)
}

/// Caller must supply one live, initialized allocation, readable for the returned
/// borrow, and prevent incompatible mutation. Checks do not validate those facts.
pub(super) unsafe fn input<'a, T>(
    ptr: *const T,
    len: c_int,
    allowed: RangeInclusive<usize>,
) -> Option<&'a [T]> {
    let len = check_region(ptr, len, allowed)?;
    // SAFETY: numerical bounds/alignment checked above; allocation and lifetime
    // requirements are the caller's documented unsafe contract.
    Some(unsafe { std::slice::from_raw_parts(ptr, len) })
}

/// Caller must supply one live initialized allocation, exclusively writable for
/// the returned borrow. Checks do not validate provenance, aliasing or lifetime.
pub(super) unsafe fn output<'a, T>(
    ptr: *mut T,
    len: c_int,
    allowed: RangeInclusive<usize>,
) -> Option<&'a mut [T]> {
    let len = check_region(ptr.cast_const(), len, allowed)?;
    Some(unsafe { std::slice::from_raw_parts_mut(ptr, len) })
}

pub(super) fn guard<T>(fallback: T, operation: impl FnOnce() -> T) -> T {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(operation)) {
        Ok(value) => value,
        Err(payload) => {
            // A user-defined panic payload may itself panic on Drop. Do not let
            // that secondary panic cross C. Only the exceptional payload leaks.
            std::mem::forget(payload);
            fallback
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_lengths_and_protocol_bounds() {
        for len in [c_int::MIN, -1, 0, 511, 513, c_int::MAX] {
            assert_eq!(checked_len::<f64>(len, 512..=512), None);
        }
        assert_eq!(checked_len::<f64>(512, 512..=512), Some(512));
        assert_eq!(checked_len::<u8>(10240, 1..=10240), Some(10240));
        assert_eq!(checked_len::<u8>(10241, 1..=10240), None);
    }

    #[test]
    fn arithmetic_alignment_null_and_zero_sized_types() {
        assert!(checked_bytes(usize::MAX, 8).is_none());
        assert!(checked_bytes(isize::MAX as usize + 1, 1).is_none());
        assert_eq!(
            checked_bytes(isize::MAX as usize, 1),
            Some(isize::MAX as usize)
        );
        assert!(checked_len::<()>(1, 0..=2).is_none());
        assert!(check_region::<u8>(std::ptr::null(), 0, 0..=10).is_none());
        assert!(check_region::<f64>(1usize as *const f64, 512, 512..=512).is_none());
        assert!(check_region::<u8>(usize::MAX as *const u8, 1, 1..=1).is_none());
    }

    #[test]
    fn valid_allocations_are_borrowed_and_panic_is_contained() {
        let mut bytes = [1u8, 2];
        assert_eq!(unsafe { input(bytes.as_ptr(), 2, 2..=2) }.unwrap(), &[1, 2]);
        unsafe { output(bytes.as_mut_ptr(), 2, 2..=2) }.unwrap()[0] = 3;
        assert_eq!(bytes, [3, 2]);
        assert_eq!(guard(-1, || 42), 42);
        assert_eq!(guard(-1, || panic!("boundary regression")), -1);
        struct PanicOnDrop;
        impl Drop for PanicOnDrop {
            fn drop(&mut self) {
                panic!("secondary panic");
            }
        }
        assert_eq!(guard(-1, || std::panic::panic_any(PanicOnDrop)), -1);
    }
}
