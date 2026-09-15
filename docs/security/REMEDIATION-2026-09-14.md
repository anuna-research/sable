# Red-team remediation record

Scope: all four critical and six high findings in
[RED-TEAM-FINDINGS-2026-09-14.md](RED-TEAM-FINDINGS-2026-09-14.md).
This is an implementation record, not production approval. The original assessment
is preserved. No deployment or external service has been changed.

## Current status

| Finding | State | Evidence and remaining work |
|---|---|---|
| SBL-RT-001 | Quarantined; replacement in progress | Legacy attestation, chain and trust-store modules remain test-only. Real DER validation requires explicit key usage, name policy and signed current full-chain CRLs. Internal certificate-key possession signatures now bind a verifier-owned template, audience, challenge, session, role and Noise key; nine binding tests include a combined Noise round trip. Persistent trust/CRL rollback protection, issuer-authorized biometric binding/profile and production integration remain; no attestation API is exported. |
| SBL-RT-002 | Implemented; synthetic route tested | Enrollment and authentication require valid embeddings; authentication additionally requires a nonce commitment and four frames, rejects simulation fields and requires a validated liveness witness. All server biometric simulation generators are test-only. Core proof generation rejects missing liveness before key generation; scalar-distance simulation methods are absent from the public API. Operator credentials authenticate principals before body processing; enrollment and challenge state is principal-scoped. A production-router test now completes enrollment, challenge, synthetic JPEG capture, real proving and verification. Physical-camera validation remains. |
| SBL-RT-003 | Implemented; synthetic route tested | `ExpectedPolicy` checks exact template, threshold, liveness, challenge digest, circuit identifier and expiry before proof verification. Demo verifies against a single-use principal-scoped stored policy and exactly five canonical instances, with no request-derived defaults. Wrong-principal attempts cannot consume the policy. Stored policies retain the original challenge's monotonic deadline through proving; expiry is checked before and after proof verification, independently of wall-clock rollback. Policy-free verification methods and the raw-key constructor are unavailable to consumers; verifier construction accepts only the supported 512-byte thermometer circuit. The synthetic capture/prove/verify route test checks an independently registered template, wrong-principal non-consumption and explicit replay rejection; physical-camera coverage remains. |
| SBL-RT-004 | Withdrawn | No Rust module declaration for Groth16 or mobile; `zk`/`mobile` features explicitly fail compilation. Direct Groth16 dependencies removed. Mobile script, Gradle, CMake, Swift package and native wrappers reject builds. Reintroduction gates below. |
| SBL-RT-005 | In progress | Public-facing docs and active screens disclose centralized processing. Converted enrollment-feature copies, redundant embedding clones, feature previews, unused stored salts and per-request handler logs are removed; rejection errors omit biometric scores. Enrollment buffers zeroize on drop and records have bounded TTLs. Successful research responses still expose diagnostics to the authenticated participant. Complete sensitive-data controls, deployment logging audit and client-side proving remain. |
| SBL-RT-006 | Core boundary defined; provenance separated by product decision | On 2026-09-15 the user directed that no device or attestation assumptions be baked into SABLE. `CAPTURE-TRUST-BOUNDARY.md` records capture provenance as a separate integration concern. Core proof acceptance certifies the verifier-approved relation, not physical origin; synthetic route tests demonstrate this limit. Mandatory witnesses and verifier policy remain enforced. No platform selection is required to continue core remediation. This is an explicit scope decision, not evidence that fabricated captures are prevented. |
| SBL-RT-007 | Quarantined; replacement in progress | Legacy session manager and BLE/NFC wrappers remain unavailable to consumers. Internal Noise XX can consume a checked certificate-key possession binding; it binds certificate digests to roles/session and enforces the earliest binding/certificate/CRL deadline. Directional HKDF keys protect counter-based records with authenticated headers. Persistent trust/challenge storage, issuer authorization, transport integration, interoperability and independent review remain. No public channel is restored. |
| SBL-RT-008 | Boundary repaired; mobile still withdrawn | The actual wrapper now uses centralized signed-length, protocol-size, checked-byte-count, alignment and address-range checks before input dereferences. Returned buffers use matching boxed-slice ownership; panics map to error returns and abort-mode compilation is rejected. A rejecting-backend harness tests the wrapper normally and under host AddressSanitizer. Native ABI/header reconciliation, stale-handle/ownership review and instrumented device tests remain; no production FFI symbols are restored. |
| SBL-RT-009 | In progress | Private bounded TTL caches cap enrollment at 128 records/15 minutes and each challenge-related cache at 256 records/30 seconds. Periodic eviction runs every five seconds. Expensive routes admit one operation with no waiting queue, an 8 MiB body limit, a 10-second body deadline and a 30-second response deadline. Blocking work retains its permit after timeout. Image header, size and allocation limits precede RGB expansion. Credential authentication precedes body reads and admission. Each principal has twelve operations per minute, four enrollments, and eight records per challenge-related cache. CORS is same-origin by default; API operation responses use no-store. Fly config now has soft/hard concurrency 1/4. Live capacity/timeout testing and remaining sensitive-data controls remain. |
| SBL-RT-010 | Withdrawn | Deterministic generation exists only as a private unit-test fixture. Server fuzzy enrollment/verification/deduplication handlers and routes, stored helper data, browser mode and client API methods are removed. Compile-fail coverage proves library consumers cannot import the deterministic generator. Randomized fuzzy code remains explicitly experimental, with offline-guessing and unmeasured entropy/unlinkability limitations documented. |

## Verification

- Latest `cargo test -p demo-server --release --lib -- --include-ignored`:
  66 passed. `verification_policy::tests` exercises exact deadline rejection,
  a verification operation crossing expiry, forward wall-clock expiry and backward
  wall-clock movement with deterministic clock arguments. The handler/state test
  rejects a policy already past its original monotonic challenge deadline even
  when its wall expiry is future. These are policy/state tests, not manipulation
  of the host clock. The full real-proof route still passes. Handlers recheck both
  clocks after cryptographic verification before returning a result.

- `cargo test -p demo-server --release --lib -- --include-ignored`: 65 passed,
  including the real-proof synthetic route test after removing the stored
  converted-feature copy, optional enrolled-embedding state and simulated-distance
  fallback. Enrollment moves its embedding into storage; authentication borrows
  the live embedding instead of cloning it. A scoped source regression checks
  these retention/fallback properties; it is not a memory-erasure audit.
- `cargo test -p demo-server --release --doc`: 1 passed, demonstrating that the
  now-private, test-only simulation module cannot be imported by consumers.
  `cargo check -p demo-server` also passes.

- `cargo test -p sable-core --lib attestation::peer_binding`: 9 passed. Tests
  cover possession, every trusted binding field, substituted certificate/Noise
  keys, malformed signatures, single-use failure consumption, lifetime limits,
  certificate/CRL validity ceilings and a certificate-bound mutual Noise handshake
  with bidirectional encrypted records. No persistent challenge/trust store or
  issuer-authorized biometric enrollment participates in these tests.

- `cargo test -p sable-core --lib attestation::validated_x509`: 12 passed using
  real Ed25519 DER chains and signed CRLs generated by rcgen. Tests cover valid
  chains, modified TBS/signatures, 32 fixed-signature candidates, wrong root/name,
  missing intermediate, non-CA and invalid key usage, wrong/missing EKU, validity,
  name/path constraints, unsupported leaf keys, unknown critical extensions,
  revoked leaf/intermediate, missing/stale/future/tampered/ambiguous CRLs, a CRL
  signed by the wrong key under the same issuer name, trailing bytes and size caps.
  This does not validate attestation binding, possession or persistent rollback state.

- `cargo test -p sable-core --lib ffi_test_harness`: 13 passed. These compile the
  actual withdrawn wrapper against a backend that never generates or accepts a
  proof. Coverage includes signed bounds, byte-count overflow, alignment/nulls,
  nonfinite inputs, pre-backend rejection, panic containment, exact salt writes,
  boxed-buffer release/clearing, invalid release lengths and unknown error integers.
- `RUSTFLAGS='-Zsanitizer=address' cargo test --offline -p sable-core --lib --target aarch64-apple-darwin --target-dir target/ffi-asan ffi_test_harness`:
  the same 13 tests pass under host AddressSanitizer. This is not Android/iOS
  instrumentation, a stale-pointer test or proof-backend validation.
- `cargo build -p sable-core` succeeds; `nm -gUj target/debug/libsable_core.dylib`
  reports no legacy `sable_*` FFI exports. Default doctests still pass (21 tests),
  including the compile-fail mobile import.

- `node --test ci/security-release-gate.test.mjs`: 5 passed. The gate rejects
  ordinary and attempted-override invocations; source checks cover package
  publishing prohibitions, gate placement before image compilation, selected
  withdrawn assurance claims and landing-page anchors. These are scoped regression
  checks, not a semantic audit of all documentation or an executed Docker build.
- `cargo metadata --no-deps --format-version 1`: both workspace packages report
  `publish: []`, confirming registry publishing is prohibited. `cargo check --workspace`
  still passes. No registry operation, image build or external deployment was performed.

- `cargo test -p sable-core --lib p2p::authenticated`: 14 passed. Covers mutual
  pinned-key authentication, both roles' static-key substitution, low-order
  ephemeral rejection, context mismatch, incomplete/expired/malformed handshakes,
  transcript tampering, fresh keys with unchanged static keys/context, directional
  counters, header AAD, replay/reflection/reordering/type mismatch, expiry,
  exhaustion, maximum payload, truncation and propagation/enforcement of a checked
  binding's absolute deadline. These test the private replacement,
  not attestation provisioning, public transports or interoperability.

- `cargo test -p demo-server --lib images::tests`: 3 passed, covering normal JPEG
  frames/PNG crops, oversized dimensions in small valid files, malformed encodings,
  unsupported formats and oversized encoded inputs.
- `cargo test -p demo-server --lib admission::tests`: 3 passed, covering immediate
  busy rejection, declared/actual oversized bodies, no-store responses, and retention
  of the permit after timeout until the original worker exits.
- `cargo test -p demo-server --lib handlers::liveness_input_tests`: 2 passed with
  bounded image decoding. These are focused checks, not image fuzzing or a deployed
  capacity certification.
- `cargo test -p demo-server --release --lib`: 63 passed, 1 ignored, including source regressions for
  handler logging and scored rejection messages, enrollment input omission
  and numeric validation, credential parsing,
  rate-budget isolation, actual-router unauthorized/owner/mismatched-owner cases,
  wrong-principal challenge and policy non-consumption, per-principal enrollment
  quotas, cache capacity, expiry,
  single-use consumption and value-drop tests, and direct handler tests for
  the challenge-only attack, missing commitment, policy mismatch, expired policy
  insertion and reuse of a consumed verification policy. These do not yet cover
  a complete valid camera-capture round trip.
- `cargo test -p demo-server --release --lib route_round_trip_tests -- --ignored`:
  1 passed. The actual authenticated router completes enrollment, challenge,
  JPEG decoding/liveness extraction, real Halo2 proof generation and verification
  against the independently registered template. Wrong-owner verification returns
  the exact missing-policy error without consuming Alice's policy; subsequent
  verification and proving replays return the exact consumed-policy/challenge
  errors. Every response is checked for `no-store`. The default-threshold capture
  is fabricated RGB data, not a physical camera or capture-provenance test.
- `cargo test -p sable-core --features halo2 --lib --release zk::halo2::policy`:
  5 passed. Includes a real proof accepted with independently calculated template
  and challenge expectations, and rejected for a wrong registration, expiry or
  corrupted transcript. Structural tests cover all five instance substitutions,
  wrong counts, non-canonical fields and policy downgrades. Verifier construction
  rejects unsupported embedding dimensions and disabled thermometer constraints.
- `cargo test -p sable-core --features halo2 --doc`: 28 passed, 3 ignored,
  including compile-fail checks for both removed scalar-distance simulation APIs,
  all four legacy policy-free verification methods and the raw-key constructor.
- Core tests compile with `--features halo2 --tests --no-run`; benchmark targets
  compile with `cargo check -p sable-core --features halo2 --benches`. Synthetic
  vectors for these consumers are now explicit test fixtures rather than public
  prover methods. `cargo check -p sable-core --features halo2 --tests --benches`
  also passes after migrating verification callers to independently built policies.
- `cargo test -p sable-core --features halo2 --release --test integration halo2_integration`:
  7 passed after migrating scalar-distance generation to test-only fixtures and
  all authentication verification to `verify_expected`. Policies are calculated
  from trusted fixture inputs, not returned proof metadata. The former
  backwards-compatibility test is now named `test_halo2_explicit_synthetic_fixture`;
  production missing-witness requests are separately rejected.

- `cargo test -p sable-core --lib attestation`: 95 passed: 74 legacy/signature
  fixture tests, 12 real-X.509 tests and 9 certificate/Noise binding tests. Legacy chain/trust fixtures
  are not evidence that their quarantined implementation is safe to restore.
- `cargo check -p sable-core --features zk,mobile`: intentionally fails with the
  withdrawal diagnostic; no former mobile compiler errors or Groth16 implementation
  are reached.
- `cargo check --workspace`: passes after removing the demo's unused `zk` feature.
- `cargo test -p sable-core --doc`: 21 passed, including compile-fail checks proving
  Groth16, mobile, legacy attestation and deterministic fuzzy APIs cannot be imported
  by consumers, and six checks for removed session/BLE/NFC imports.
- `cargo test -p sable-core --lib crypto::fuzzy_commitment`: 13 passed; retained
  algorithm tests do not establish biometric entropy or unlinkability.
- Browser `npm run build` and `npm test -- --run`: pass after withdrawing the fuzzy
  UI and API and updating privacy notices. Two browser tests cover capture crops
  and credential use, omission on health, clearing, HTTPS enforcement and redirect
  rejection. Checked-in browser assets regenerated.
- Mobile build script, CMake configuration, Android FFI header, iOS C wrapper and
  Swift package manifest: each fails with the explicit withdrawal diagnostic.
  Gradle is unavailable locally; its unconditional build rejection was inspected.
- Ed25519 known-answer test source:
  [RFC 8032 section 7.1, test 1](https://www.rfc-editor.org/rfc/rfc8032#section-7.1).

## Reintroduction gates for withdrawn APIs

Attestation must integrate the real-X.509 replacement with a reviewed identity and
biometric/Noise-key binding profile, proof of key possession, and authenticated
monotonic trust/revocation updates. The current strict Ed25519 client-auth/DNS
profile is an internal validation foundation, not a government certificate or
platform-attestation integration. See [X.509 replacement notes](X509-REPLACEMENT.md).

Registry publication and the repository's deployment image are explicitly blocked.
`ci/security-release-gate.sh` has no runtime bypass; its deliberate failure is the
release hold, not an automatically inferred audit verdict. Lifting it requires a
reviewed source change after the original critical/high requirements are verified.
The old `docs/specs/SECURITY-REVIEW.md` approval is withdrawn; current control evidence
is in `THREAT_MODEL.md`. Legacy audit/milestone logs are labelled historical.

P2P must bind Noise static keys to validated, current attestation identities and
enforce both peer authorization and credential expiry/revocation. The private
replacement in `core/src/p2p/authenticated.rs` is test-only: callers cannot use
manually supplied pins as a substitute for the missing attestation integration.
BLE/NFC framing, bounded reassembly, session admission and on-device interoperability
must be migrated and tested before restoring their public APIs. Independent review
must cover the application key derivation/record layer, not just Noise itself.
See [P2P replacement notes](P2P-REPLACEMENT.md) for current mechanisms and limits.

Groth16 must use audited curve gadgets, canonical commitment decoding, a reviewed
public-input schema, constraint-level adversarial tests and independent cryptographic
review. Repairing the placeholder field equations is not sufficient.

Mobile must use the reviewed proof API, reconcile C/JNI/Swift declarations and
compile in Android/iOS CI. The new length/allocator/panic checks have host test
coverage but still require unsafe-boundary review and instrumented device tests.
Raw handle and result ownership contracts do not validate arbitrary addresses,
stale handles or copied ownership. Hardware-keystore support cannot be claimed
from an OS-version check or a software map. Existing local artifacts are not
approved for distribution. See [FFI boundary notes](FFI-BOUNDARY.md).

Deterministic fuzzy deduplication is not retained as a product requirement. Any
future deduplication design requires measured population entropy and helper-data
leakage, independent per-domain records, strictly bounded error correction, and
either a scoped secret pepper or a reviewed privacy-preserving protocol. Random
codewords alone are not a substitute. Already exposed helper data cannot be made
secret by this repository change; no existing external enrollment records have
been deleted or migrated.
