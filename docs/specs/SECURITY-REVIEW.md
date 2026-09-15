# Halo2 security review — prior conclusion withdrawn

Updated 2026-09-15. The 2026-02-03 review's production recommendation and blanket
soundness/completeness claims are withdrawn. The historical text is available in
Git history; it is not current security assurance.

## Current conclusion

**Not approved for production or security-critical authentication.**

The [2026-09-14 red-team assessment](../security/RED-TEAM-FINDINGS-2026-09-14.md)
identified critical and high issues outside the coverage of the earlier threshold
tests. The [remediation record](../security/REMEDIATION-2026-09-14.md) contains scoped
test evidence and outstanding work. Some unsafe APIs are now withdrawn; that does
not establish a working secure replacement.

## What the evidence supports

| Area | Status | Evidence and limitation |
|---|---|---|
| Verifier policy enforcement | implemented and tested | [policy.rs](../../core/src/zk/halo2/policy.rs) checks five exact canonical instances against independently supplied expectations; real-proof and negative tests are recorded. |
| Public verifier API restriction | implemented and tested | [proof.rs](../../core/src/zk/halo2/proof.rs), [compile-fail tests](../../core/src/zk/halo2/mod.rs); policy-free methods and raw-key constructor are not public. |
| Missing-witness rejection | implemented and tested | [proof.rs](../../core/src/zk/halo2/proof.rs) rejects omitted liveness; scalar synthetic proof APIs are test-only. |
| Physical capture authentication | planned | No attested sensor input. A satisfying witness is not proof of a live camera capture. |
| End-to-end biometric privacy | planned | Browser embeddings/images reach the server, which generates the proof. Server-side data controls are not client-side proving. |
| Complete circuit soundness and side-channel analysis | implemented but unverified | Narrow unit/integration tests do not establish the absence of underconstraints, leakage or implementation vulnerabilities. |
| Production trusted setup/key lifecycle | planned | [ProofSetup::new](../../core/src/zk/halo2/proof.rs) locally generates BN254 KZG parameters. This is not a transparent setup or an independently verified ceremony. |

The proof exposes the face-match result, threshold, liveness result, challenge
digest and enrollment-template commitment, not just two fields. A public threshold
must be checked against verifier-owned policy; visibility alone is not authorization.
Tests observing distinct hash outputs do not prove collision or preimage resistance.

## Required next assessment

Review complete circuits and protocol composition, including malicious witnesses,
canonical encoding, policy/version binding, freshness and replay state. Establish
capture provenance and the privacy boundary, complete attestation and authenticated
transport replacements, and verify trusted setup provenance. Include independent
cryptographic review, adversarial integration tests and applicable deployment and
device testing.

The [threat model](../security/THREAT_MODEL.md) describes the current trust boundaries.
The [release gate](../../ci/security-release-gate.sh) blocks distribution through the
repository's deployment-image path. Its deliberate failure is not an audit result,
and its regression tests cannot confer production approval.
