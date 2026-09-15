# Withdrawn FFI boundary repairs

SBL-RT-008's signed-length conversions have been removed from the actual legacy
wrapper. This does not restore mobile support. The normal crate still has no mobile
module; the mobile build paths and release gates still reject distribution.

## Current checks

`ffi_boundary.rs` checks nonnegative signed lengths, protocol ranges, multiplication
overflow, the `isize::MAX` byte bound, non-null aligned pointers and address overflow
before constructing slices. Features require exactly 512 doubles; proofs require
1–10,240 bytes. Salt and commitment inputs require 32 and 48 bytes respectively.
Feature values must be finite and the legacy normalized threshold must be finite
and within [0, 1]. These are legacy-wrapper bounds, not a new proof-policy interface.

The wrapper validates all input regions numerically before its first input
dereference. Raw slice creation is centralized in unsafe helpers. Pointer-taking
Rust exports are explicitly unsafe and document allocation/lifetime/aliasing
requirements. Numeric validation cannot prove those requirements.

Returned data is a SABLE-owned `Box<[u8]>`, released with the same allocation layout
through `sable_free_result`. The result is cleared before deallocation. A caller
must return the original, unmodified pointer and length exactly once. Releasing the
same cleared result twice is harmless; releasing a copied owning descriptor is not.
Invalid numeric lengths are rejected without constructing an allocation to free.
An invalid release descriptor may therefore retain memory until the caller restores
the original descriptor. No host allocator may free SABLE data.

Error messages are borrowed static NUL-terminated strings. Their compatibility
release function is a no-op. The error-message entry takes an integer, avoiding an
invalid Rust enum discriminant for unknown C error values.

Unwinding panics are caught inside the C boundary and produce null/error returns.
Panic payloads are deliberately forgotten because their destructors can themselves
panic. This may leak an exceptional payload. `panic=abort` is rejected when compiling
the wrapper; allocation aborts, signals and invalid-memory faults are not caught.
The process panic hook is not disabled or made safe for sensitive logging by this
change. Reusing a backend after panic needs review before reintroduction.

## Verification and limits

`ffi_test_harness.rs` compiles the real wrapper against an explicitly rejecting
backend. It never creates or validates a proof. Thirteen tests pass normally and
under macOS ARM64 AddressSanitizer; commands are in the remediation record.
The host library build contains no legacy C exports.

Before reintroduction: replace the legacy proof interface with verifier-owned policy,
reconcile native headers/wrappers (including error values and buffer contracts),
review handle lifecycle and copied/forged descriptors, and run Android/iOS ABI and
sanitizer tests. Fixed-size input types should be used in the replacement ABI where
compatible. This host harness does not establish mobile security or memory safety
for callers violating pointer/ownership requirements.
