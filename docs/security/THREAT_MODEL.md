# SABLE threat model — research build

Updated 2026-09-15. This replaces the unsupported control claims in version 1.0.
SABLE is not approved for security-critical authentication or public deployment.
The [red-team assessment](RED-TEAM-FINDINGS-2026-09-14.md) remains the baseline;
the [remediation record](REMEDIATION-2026-09-14.md) distinguishes containment from
completed replacement. Test results are scoped evidence, not a system security audit.

## Assets, actors and trust boundaries

The sensitive assets are captured frames, eye crops, embeddings, quantized templates,
operator credentials, enrollment mappings, challenge state, proving material and
identity trust anchors. Threat actors include network attackers, malicious browser
clients, malicious provers with stolen templates, compromised servers/operators,
compromised devices and supply-chain attackers.

The current browser is untrusted. It sends enrollment embeddings and authentication
embeddings/images to a trusted-for-processing server. That server converts features,
extracts liveness measurements, generates proofs and verifies them. Proof privacy
does not hide those inputs from the server, its operator or its TLS terminator.

The server owns principal-scoped enrollment/challenge state and the expected proof
policy. Bearer credentials authorize access to this research API; they do not attest
a device, camera, human identity or physical presence. A stolen bearer credential is
usable until the operator removes it and restarts the process.

The Halo2 circuit proves relations among witness values, not their physical origin.
A prover possessing the enrollment template can fabricate satisfying measurements.
See [capture boundary](CAPTURE-TRUST-BOUNDARY.md). Software liveness is unvalidated
presentation-attack risk reduction, not cryptographic capture authentication.
Device and attestation policies are separate application concerns, not assumptions
baked into SABLE. Core remediation does not depend on selecting such a provider.

## Current control evidence

Statuses describe the stated control only:

- **implemented and tested**: specific implementation and scoped tests exist;
- **implemented but unverified**: code exists without sufficient validation;
- **planned**: missing or withdrawn functionality, not available protection;
- **demo only**: research behavior, not an authentication assurance.

| Control | Status | Evidence and limits |
|---|---|---|
| Principal authentication and rate limits before protected body processing | implemented and tested | [auth.rs](../../demo/server/src/auth.rs), [routes.rs](../../demo/server/src/routes.rs); credential, router and principal-isolation tests. Operator-provisioned bearer tokens, not device attestation. |
| Bounded principal-scoped enrollment/challenge state | implemented and tested | [state.rs](../../demo/server/src/state.rs), [cache.rs](../../demo/server/src/cache.rs); quota, expiry, drop and non-consumption tests. Enrollment availability is 15 minutes; eviction every five seconds. |
| Verifier-owned exact public-input policy | implemented and tested | [policy.rs](../../core/src/zk/halo2/policy.rs), [proof.rs](../../core/src/zk/halo2/proof.rs), [handlers.rs](../../demo/server/src/handlers.rs); substitution, expiry, canonical-decoding and real-proof tests. [Full synthetic route test](../../demo/server/src/route_round_trip_tests.rs) checks real proof acceptance, owner isolation and replay rejection. Physical-camera validation remains. |
| Reject omitted embedding/liveness inputs | implemented and tested | [handlers.rs](../../demo/server/src/handlers.rs), [proof.rs](../../core/src/zk/halo2/proof.rs); omission tests and compile-fail checks for public scalar simulation APIs. Does not authenticate supplied capture data. |
| Body, image and concurrent-work bounds | implemented and tested | [admission.rs](../../demo/server/src/admission.rs), [images.rs](../../demo/server/src/images.rs); busy, timeout, permit-retention, dimension and malformed-image tests. Not image fuzzing or deployed capacity certification. |
| Enrollment buffer zeroization on drop | implemented but unverified | [state.rs](../../demo/server/src/state.rs) invokes zeroization; drop/expiry paths have tests, but memory erasure has not been instrumented. Does not cover all parser/decoder copies, active requests, dumps, swap or a compromised operator. |
| Centralized feature conversion, liveness extraction and proving | demo only | [browser API](../../demo/web/src/api.ts), [handlers.rs](../../demo/server/src/handlers.rs). Biometric data leaves the browser. |
| Physical capture provenance | separate integration concern | Outside the core proof guarantee by product decision. No device or attestation provider is assumed; applications needing this assurance must supply and validate an independently bound capture policy. [Capture boundary](CAPTURE-TRUST-BOUNDARY.md). |
| Client-only biometric processing/proving | planned | Current browser sends embeddings and images. A native/WASM proving client and commitment/proof-only server interface are required. |
| Withdrawal of legacy attestation, Groth16, mobile and deterministic fuzzy APIs | implemented and tested | [core exports](../../core/src/lib.rs), [crypto exports](../../core/src/crypto/mod.rs), compiler gates and compile-fail tests in the remediation record. Withdrawal is not a working replacement. |
| Internal real-X.509 chain/revocation validation | demo only | [validated_x509.rs](../../core/src/attestation/validated_x509.rs); 12 tests with real DER chains and signed CRLs. Strict Ed25519 client-auth/DNS profile; no attestation API exported. |
| Internal certificate-key possession and Noise binding | demo only | [peer_binding.rs](../../core/src/attestation/peer_binding.rs); nine tests include exact policy binding, one-use challenge, expiry ceilings and a mutual Noise exchange. Does not establish issuer-authorized biometric enrollment. |
| Issuer-authorized biometric binding and trust rollback protection | planned | Persistent authenticated trust/CRL versions, persistent challenge uniqueness, trusted enrollment and platform integration remain. |
| Withdrawal of unauthenticated P2P and BLE/NFC wrappers | implemented and tested | [P2P exports](../../core/src/p2p/mod.rs); six compile-fail import tests. No public authenticated channel is available. |
| Internal certificate-bound Noise replacement | demo only | [authenticated.rs](../../core/src/p2p/authenticated.rs); 14 focused tests plus a combined certificate-possession exchange. Test-only; persistent trust/challenge state, transport integration and independent review remain. |
| Withdrawn FFI numerical/allocator/panic boundary | implemented and tested | [ffi.rs](../../core/src/mobile/ffi.rs), [boundary helpers](../../core/src/mobile/ffi_boundary.rs); 13 rejecting-backend tests also pass under host AddressSanitizer. No production exports or valid mobile proof backend. |
| Mobile integration and hardware keystore adapters | planned | Mobile builds explicitly reject compilation. No available or tested device security boundary; native ABI/ownership review and device instrumentation remain. |
| Complete circuit soundness, side-channel resistance and biometric accuracy | implemented but unverified | Research implementations and tests are not independent constraint review, timing analysis or population-level FAR/PAD validation. |
| Production release hold | implemented and tested | [release gate](../../ci/security-release-gate.sh), [gate tests](../../ci/security-release-gate.test.mjs), package publish prohibitions and deployment Dockerfile. Does not revoke existing deployed binaries. |

## Data retention and transport

Enrollment stores raw embeddings and matcher templates in
server memory. TTLs limit lookup availability, not all copies' lifetime. Active
requests may retain data until completion. Requests and decoded images contain
biometrics even if the server does not deliberately persist them to disk.

Never log request bodies, authorization headers, embeddings or capture data.
Deployment operators must account for reverse-proxy logs, telemetry, crash dumps,
swap, backups and TLS termination; repository tests do not establish those controls.
See [demo access](DEMO-ACCESS.md). Browser credential handling requires HTTPS except
loopback, but that is not proof of a deployed server's transport configuration.

Proofs expose the match result, threshold, liveness result, challenge digest and
enrollment-template commitment. A stable template commitment can permit linkage;
a hash/commitment is not evidence of biometric entropy or unlinkability. The
randomized fuzzy API remains experimental; deterministic fuzzy enrollment and
deduplication are withdrawn.

## Cryptographic and operational assumptions

The active proof backend is BN254 KZG through Halo2, not a transparent-setup backend.
[ProofSetup::new](../../core/src/zk/halo2/proof.rs) creates local KZG parameters using
the OS RNG. There is no verified production ceremony provenance or distributed
verification-key lifecycle. Production assurance cannot be inferred from the name
Halo2, valid unit proofs or an assumed curve-security number.

RNG reliability, correct primitives, complete constraints, canonical encodings,
trusted verifier state and a trustworthy clock are prerequisites. Device isolation,
government PKI integration and authenticated sensors are not implemented assumptions
that this build can guarantee.

## Residual risks and release conditions

Critical/high remediation remains incomplete. Major residual risks are server-side
biometric exposure, fabricated physical-capture witnesses, absent attestation and
revocation, unavailable authenticated P2P/mobile, unvalidated matcher/PAD thresholds,
and incomplete end-to-end, fuzz, capacity and device testing. No numerical residual
risk rating or production approval is asserted.

The release gate intentionally fails. Lifting it requires a reviewed change with
requirement-by-requirement evidence for the original findings, current dependency
and circuit assessment, deployed transport/data-handling checks, and applicable
platform/interoperability testing. Editing a status table or passing the gate's
regression tests cannot grant approval.
