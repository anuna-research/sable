# SABLE Red-Team Findings

| Field | Value |
|---|---|
| Assessment date | 2026-09-14 |
| Commit | `1791c0312896f0de9cd2fae12708ed502f79da8c` |
| Branch | `feat/SPEC-006-geometric-liveness` |
| Scope | Rust core, Halo2 and Groth16 proof APIs, attestation and trust store, P2P sessions, mobile FFI and keystore, demo server and browser client |
| Method | Manual source review, attack-path analysis, targeted certificate forgery test, build and test checks, RustSec and npm advisory scans |

## Executive assessment

SABLE must not be used for security-critical authentication or exposed as an Internet service in its current form. The assessment found four critical, six high, and three medium findings.

The most direct compromise is in the attestation layer: signature verification does not verify a signature. An attacker-chosen 64-byte value was accepted under an unrelated public key in a targeted test. This permits forged biometric certificates and forged signed trust-store updates.

The demo's authentication flow is also bypassable. A caller who knows an enrollment session ID can request a challenge, omit the live face and all liveness inputs, and have the server synthesize a matching sample and a passing liveness witness. Separately, `/api/verify` accepts the security policy and identity binding from the request instead of reconstructing them from trusted server state.

Several security statements in `README.md` and `docs/security/THREAT_MODEL.md` describe intended architecture rather than current behavior. In the browser demo, face embeddings and captured images leave the device, the server stores biometric material and commitment salt in plaintext memory, P2P key exchange is unauthenticated, hardware keystore integration is absent, and the mobile feature does not compile.

## Findings overview

| ID | Severity | Finding | Affected surface |
|---|---|---|---|
| SBL-RT-001 | Critical | Attacker-chosen signatures are accepted | Attestation, certificate chains, trust-store updates |
| SBL-RT-002 | Critical | Missing biometric and liveness inputs yield an authentication proof | Demo API |
| SBL-RT-003 | Critical | Verifiers accept attacker-selected policy and identity bindings | Halo2 API, demo verifier |
| SBL-RT-004 | Critical | Legacy Groth16 does not bind real commitments or curve operations | Groth16, mobile proof path |
| SBL-RT-005 | High | Claimed on-device biometric privacy is violated by the demo data flow | Browser demo, server state |
| SBL-RT-006 | High | A malicious prover can fabricate the private “live capture” witness | Halo2 liveness and face matching |
| SBL-RT-007 | High | P2P sessions are vulnerable to active man-in-the-middle attacks | P2P session layer |
| SBL-RT-008 | High | Negative FFI lengths can create invalid Rust slices | Mobile FFI |
| SBL-RT-009 | High | Unauthenticated expensive endpoints and unbounded state enable denial of service | Demo deployment |
| SBL-RT-010 | High | Deterministic fuzzy commitments support offline guessing and cross-matching | Fuzzy enrollment and deduplication |
| SBL-RT-011 | Medium | Mobile builds and hardware-backed storage controls are unavailable | Mobile SDK |
| SBL-RT-012 | Medium | Locked Rust dependencies include three known vulnerabilities | Supply chain |
| SBL-RT-013 | Medium | Security documentation records absent controls as implemented | Security assurance |

## Detailed findings

### SBL-RT-001 — Attacker-chosen signatures are accepted

**Severity:** Critical
**Impact:** Forged government attestations, arbitrary trust anchors, commitment substitution, and loss of certificate-chain authenticity.

`SigningKey` is described as Ed25519 but implements a custom two-stage SHA-256 construction ([x509.rs](../../core/src/attestation/x509.rs#L86)). `VerifyingKey::verify` computes a value using the public key and message, stores it in `_verification_hash`, and never compares it with anything. Acceptance depends only on weak properties of the attacker-supplied bytes ([x509.rs](../../core/src/attestation/x509.rs#L196)).

The same function authenticates certificate chains ([chain.rs](../../core/src/attestation/chain.rs#L572)) and signed trust-store imports ([truststore.rs](../../core/src/attestation/truststore.rs#L501)). Revocation data is also represented as unsigned local structures, and an unknown or stale OCSP status fails open as “not revoked” ([chain.rs](../../core/src/attestation/chain.rs#L529)).

**Reproduction:** A targeted integration test created a certificate, replaced its final 64 signature bytes with a deterministic attacker-chosen sequence, parsed it, and verified it with an unrelated public key. Candidate `2` was accepted. The temporary probe was removed after execution.

**Required fix:** Remove this attestation implementation from all security decisions immediately. Replace it with a maintained Ed25519 implementation and a real X.509 validation library, including canonical encoding, issuer and basic-constraints enforcement, key usage, name constraints, and authenticated OCSP/CRL handling. Add negative tests for modified TBS fields, random signatures, wrong keys, non-CA intermediates, stale revocation data, and trust-store rollback.

### SBL-RT-002 — Missing biometric and liveness inputs yield an authentication proof

**Severity:** Critical
**Impact:** Anyone holding or learning a session ID can obtain a valid authentication proof without presenting a face or completing liveness.

`/api/auth/challenge` requires only a session ID and returns a challenge ([handlers.rs](../../demo/server/src/handlers.rs#L199)). In `/api/auth/prove`, omission of `face_embedding` calls `generate_similar_features` with the enrolled feature vector ([handlers.rs](../../demo/server/src/handlers.rs#L489)). Omission of `c_nonce` and `flash_frames` skips the spatial-liveness block entirely. The proof API then substitutes `LivenessWitness::dummy_pass` for a missing witness ([proof.rs](../../core/src/zk/halo2/proof.rs#L264)).

Attack path:

1. Send `{"session_id":"<target>"}` to `/api/auth/challenge`.
2. Send only the returned `challenge_id` to `/api/auth/prove`.
3. The server derives a close biometric from the stored target template and generates a proof whose liveness bit passes.

No authentication binds the requester to the session. Permissive CORS makes the API callable from any browser origin unless the operator sets `ALLOWED_ORIGINS` ([main.rs](../../demo/server/src/main.rs#L27)).

**Required fix:** Delete simulation fallbacks from deployed routes. Require a complete, validated liveness transcript and a live embedding for every authentication attempt. Bind the challenge to an authenticated principal or device credential. Keep simulation behavior behind a compile-time demo feature on a separate route that cannot be enabled in deployed builds.

### SBL-RT-003 — Verifiers accept attacker-selected policy and identity bindings

**Severity:** Critical
**Impact:** A cryptographically valid proof can be accepted under an attacker-selected match threshold, liveness result, challenge, and enrolled-template commitment.

The demo verifier reconstructs all Halo2 public inputs from `public_inputs_hex` supplied by the request. Missing or malformed values fall back to permissive defaults, including liveness pass ([handlers.rs](../../demo/server/src/handlers.rs#L1142)). It does not load the expected threshold, challenge digest, or enrolled commitment from server state. `challenge_id` is used only to display a separately stored liveness result and does not affect `valid` ([handlers.rs](../../demo/server/src/handlers.rs#L1240)).

The reusable `FaceVerificationVerifier::verify` returns only whether public input zero equals one ([proof.rs](../../core/src/zk/halo2/proof.rs#L398)). `verify_bound` adds an enrolled-commitment comparison but still does not enforce an expected threshold, required liveness bit, or expected challenge digest ([proof.rs](../../core/src/zk/halo2/proof.rs#L477)). Making a value public binds the proof to that value; it does not prove the verifier approved the value.

**Required fix:** Introduce a single fail-closed verifier API that requires an `ExpectedPolicy` containing the registered template digest, exact matcher threshold, exact challenge digest, required liveness result, circuit/version identifier, and proof expiry. Reject missing, extra, non-canonical, or mismatched instances before proof verification. The demo must look up these values from the consumed challenge and enrollment records, never from request metadata.

### SBL-RT-004 — Legacy Groth16 does not bind real commitments or curve operations

**Severity:** Critical
**Impact:** If the legacy/mobile proof path is restored to a compiling state, its proof statement does not authenticate the supplied Pedersen commitments.

The circuit converts every supplied commitment to public coordinates `(1, 1)` regardless of its bytes ([groth16.rs](../../core/src/crypto/groth16.rs#L1683)), and proof generation repeats those constants in the public input vector ([groth16.rs](../../core/src/crypto/groth16.rs#L2366)). The purported scalar multiplication uses fixed field coefficients instead of group arithmetic ([groth16.rs](../../core/src/crypto/groth16.rs#L1945)). The point-addition gadget does not constrain points to the BLS12-381 curve or handle exceptional cases ([groth16.rs](../../core/src/crypto/groth16.rs#L1980)). These are placeholder equations, not a Pedersen-opening proof.

The mobile module still selects this path ([mod.rs](../../core/src/mobile/mod.rs#L75)). Its current failure to compile prevents immediate exploitation but does not reduce the severity of shipping an API documented as a secure proof system.

**Required fix:** Remove the legacy Groth16 and mobile proof API from distributable builds. Do not repair the placeholder equations incrementally. Reintroduce the feature only around audited curve gadgets, canonical commitment decoding, a reviewed public-input schema, constraint-level adversarial tests, and independent cryptographic review.

### SBL-RT-005 — Claimed on-device biometric privacy is violated by the demo data flow

**Severity:** High
**Impact:** A server compromise, memory disclosure, request logging, or transport endpoint compromise exposes irrevocable biometric material and liveness imagery.

The browser sends the 1024-value enrollment embedding to `/api/enroll` ([main.ts](../../demo/web/src/main.ts#L325)). Authentication sends the live embedding, four captured frames, and optional eye crops to `/api/auth/prove` ([main.ts](../../demo/web/src/main.ts#L563)). The server retains the raw embedding, derived feature vector, quantized template, and Pedersen salt for the life of the process ([state.rs](../../demo/server/src/state.rs#L17)). Proof generation therefore occurs on the server.

This contradicts claims such as “Biometric data never leaves the user's device” in `README.md` and “The captured frames never leave the prover” in the API response ([handlers.rs](../../demo/server/src/handlers.rs#L1090)). In the deployed demo, the browser is the capture device and the server receives the data.

**Required fix:** Move feature conversion, liveness extraction, and proof generation into a native client or browser WASM worker. The server should receive only enrollment commitments and later proofs with verifier-approved public inputs. Until that exists, describe the demo as centralized biometric processing, apply sensitive-data controls, and remove statements that promise on-device privacy.

### SBL-RT-006 — A malicious prover can fabricate the private “live capture” witness

**Severity:** High
**Impact:** Challenge freshness and a valid ZK proof do not establish that a camera observed a live person.

The Halo2 circuit constrains relationships among private embeddings, fingerprints, coverage counts, convexity scores, and glint fingerprints. It has no authenticated input from a camera, TEE, or remote attestation key. A malicious prover that possesses the enrolled template can use it as both enrolled and live embeddings and can choose private liveness fields that satisfy the public expected pattern. `LivenessWitness::dummy_pass` demonstrates that such a satisfying witness can be constructed without a capture ([liveness.rs](../../core/src/zk/halo2/liveness.rs#L178)). A fresh nonce prevents replay of an old proof but does not prove physical provenance of newly fabricated witness values.

**Required fix:** Define the trust boundary explicitly. Bind the challenge and capture measurements to a hardware-backed device key and verify platform attestation and capture policy, or have a trusted verifier-controlled sensor produce the measurements. Treat software-only camera liveness as presentation-attack risk reduction rather than a cryptographic proof of capture.

### SBL-RT-007 — P2P sessions are vulnerable to active man-in-the-middle attacks

**Severity:** High
**Impact:** An active nearby attacker can establish separate sessions with both peers, read and modify proofs, results, and metadata, and impersonate either role.

The protocol accepts any peer X25519 public key without authenticating it ([session.rs](../../core/src/p2p/session.rs#L224)). The raw Diffie-Hellman output is used directly as the ChaCha20-Poly1305 key without HKDF, transcript binding, role separation, or directional keys ([session.rs](../../core/src/p2p/session.rs#L127)). Encryption uses no associated data to bind the session ID, sender role, message type, or protocol version ([session.rs](../../core/src/p2p/session.rs#L249)).

**Required fix:** Use a reviewed authenticated handshake such as Noise XX/IK, with long-term keys bound to the attestation identity. Derive separate send and receive keys through HKDF using the transcript, roles, session ID, and protocol version. Use monotonic per-direction nonce counters and authenticate message metadata as AEAD associated data.

### SBL-RT-008 — Negative FFI lengths can create invalid Rust slices

**Severity:** High
**Impact:** A malformed or compromised native caller can trigger undefined behavior, process abort, or memory disclosure at the Rust boundary.

The C ABI accepts `features_len` and `proof_len` as signed `c_int`. It checks pointers but casts lengths directly to `usize` before `slice::from_raw_parts` ([ffi.rs](../../core/src/mobile/ffi.rs#L153), [ffi.rs](../../core/src/mobile/ffi.rs#L269)). A negative value becomes a huge length, violating Rust slice validity requirements. The functions also lack a panic boundary, so any reachable panic can terminate the host process.

**Required fix:** Validate every length before entering `unsafe`: require non-negative values, exact or bounded protocol sizes, `len <= isize::MAX`, and checked byte-size multiplication. Centralize pointer-to-slice conversion in small audited helpers. Use fixed-size pointer types where the ABI permits, return owned buffers with one documented allocator contract, and prevent unwinding across the ABI.

### SBL-RT-009 — Unauthenticated expensive endpoints and unbounded state enable denial of service

**Severity:** High
**Impact:** A remote client can exhaust the 512 MB deployment's memory and CPU or starve legitimate proof requests.

All API routes are unauthenticated ([main.rs](../../demo/server/src/main.rs#L45)). Enrollment sessions never expire, and challenges and liveness results are removed only on selected success/error paths; all three maps are unbounded ([state.rs](../../demo/server/src/state.rs#L69)). Proof generation is expensive and occurs while holding the single global prover write lock ([handlers.rs](../../demo/server/src/handlers.rs#L963)). Image helpers fully decode attacker-controlled images before checking dimensions, and general flash frames have no explicit dimension limit ([handlers.rs](../../demo/server/src/handlers.rs#L1637)). The Fly configuration admits up to 250 concurrent requests on one shared CPU and 512 MB RAM ([fly.toml](../../fly.toml#L15)).

**Required fix:** Authenticate and rate-limit enrollment and proof operations; use a small semaphore and per-principal quotas. Add bounded TTL caches with periodic eviction and hard global caps. Enforce request-byte limits and decoder allocation/dimension limits before RGB expansion. Set timeouts, reject oversized image metadata, and reduce deployment concurrency to the tested proof capacity.

### SBL-RT-010 — Deterministic fuzzy commitments support offline guessing and cross-matching

**Severity:** High
**Impact:** Public helper data enables offline testing of candidate biometric templates and creates a stable identifier across relying parties.

`gen_deterministic` derives Reed-Solomon messages entirely from `SHA-256(biometric)` and publishes the code-offset delta and resulting commitment ([fuzzy_commitment.rs](../../core/src/crypto/fuzzy_commitment.rs#L295)). An attacker with helper data can quantize candidate embeddings, reproduce the deterministic construction, and compare the delta or commitment offline. The demo further reduces each dimension to a sign bit and defaults to correcting about 200 of 510 positions ([handlers.rs](../../demo/server/src/handlers.rs#L1837)). This is not equivalent to storing a high-entropy password hash; biometric distributions are structured and irrevocable.

**Required fix:** Do not expose deterministic fuzzy commitments as a privacy-preserving authentication primitive. Define a measured entropy and unlinkability model before retaining deduplication. If deduplication is required, use a scoped secret pepper or a dedicated privacy-preserving protocol, derive independent per-domain records, strictly cap error-correction parameters, and document helper-data leakage using real population data.

### SBL-RT-011 — Mobile builds and hardware-backed storage controls are unavailable

**Severity:** Medium
**Impact:** Documented Android/iOS security properties cannot be delivered or tested.

`cargo check -p sable-core --features mobile` fails with 36 compiler errors. Failures include unsafe-code lint placement, stale Groth16 method calls, incompatible proof serialization, commitment conversion mismatches, and a sensor lifetime error. The generic keystore factory always returns `MemoryKeystore`, which reports software security and stores entries in a process `HashMap` ([keystore.rs](../../core/src/mobile/keystore.rs#L92)). Android hardware-keystore detection unconditionally returns true ([sable_jni.cpp](../../platform/android/src/main/cpp/sable_jni.cpp#L222)).

**Required fix:** Mark mobile support unavailable in release documentation and packaging. Establish compiling Android and iOS CI targets before restoring the support claim. Implement platform keystore adapters, verify hardware-backed key attestation rather than OS version, and add device tests for access policy, backup exclusion, lock state, biometric invalidation, and rooted/jailbroken behavior.

### SBL-RT-012 — Locked Rust dependencies include three known vulnerabilities

**Severity:** Medium
**Impact:** Reachability-dependent denial of service, invalid pointer dereference, incorrect arithmetic behavior, and terminal log injection remain in the dependency graph.

`cargo deny check advisories` reported:

| Advisory | Locked package | Fixed version | Direct path |
|---|---|---|---|
| RUSTSEC-2026-0204 | `crossbeam-epoch 0.9.18` | `>= 0.9.20` | Halo2/crossbeam and Rayon |
| RUSTSEC-2026-0220 | `ruint 1.17.2` | `>= 1.20.0` | `snark-verifier` |
| RUSTSEC-2025-0055 | `tracing-subscriber 0.2.25` | `>= 0.3.20` | Arkworks 0.3 |

The scan also found four unmaintained packages (`bincode 1.3.3`, `derivative 2.2.0`, `paste 1.0.15`, and `proc-macro-error2 2.0.1`) and two yanked packages (`keccak 0.1.5` and `spin 0.9.8`). The frontend production dependency audit reported zero vulnerabilities.

**Required fix:** Update the lockfile and direct dependency constraints, remove the duplicate Halo2 dependency versions, and retire the Arkworks 0.3/Groth16 path where it keeps vulnerable legacy dependencies reachable. Add `cargo deny check advisories` to CI with a reviewed exception process.

### SBL-RT-013 — Security documentation records absent controls as implemented

**Severity:** Medium
**Impact:** Reviewers and integrators can make risk decisions based on controls that do not exist.

The threat model records FFI bounds checks, use-after-free handling, hardware keystore, authenticated P2P, full circuit constraints, and on-device-only biometric data as implemented ([THREAT_MODEL.md](THREAT_MODEL.md#L123)). The code evidence in SBL-RT-001 through SBL-RT-011 contradicts those statuses. `SECURITY-REVIEW.md` also recommends production approval despite the placeholder attestation and legacy proof code.

**Required fix:** Change control status to one of `implemented and tested`, `implemented but unverified`, `planned`, or `demo only`, with a test or code reference for every implemented claim. Add release gates that prevent production-approval language while any critical finding is open.

## Remediation order

1. Quarantine attestation, trust-store import, legacy Groth16, mobile packages, and the deployed demo from security use.
2. Close SBL-RT-002 and SBL-RT-003 together by defining one verifier-owned policy object and removing all simulation/default-pass paths.
3. Decide the physical-capture trust model for SBL-RT-006 before further liveness circuit work; threshold tuning cannot establish witness provenance.
4. Move proof generation and biometric processing to the client, then redesign authenticated P2P transport.
5. Harden availability, FFI, fuzzy records, and dependencies before external testing.
6. Repeat the assessment with adversarial circuit tests, live protocol interception, malformed-image fuzzing, and instrumented mobile builds.

## Validation record

| Check | Result |
|---|---|
| Targeted forged-certificate probe | Passed as an exploit: attacker-chosen signature accepted under unrelated key; temporary test removed |
| `cargo test -p demo-server --lib` | 46 passed |
| `npm test -- --run` | 1 passed |
| `npm audit --omit=dev --json` | 0 production vulnerabilities |
| `cargo deny check advisories` | Failed: 3 vulnerabilities, 4 unmaintained packages, 2 yanked packages |
| `cargo check -p sable-core --features mobile` | Failed: 36 errors, 12 warnings |

## Assessment limits

This was a source-assisted review of the checked-out commit. It did not attack a live deployment, inspect cloud configuration outside this repository, formally verify the Halo2 constraints, measure biometric false-accept rates, test presentation attacks against physical devices, or evaluate Android/iOS hardware behavior. Findings are therefore a lower bound, not a certification of unaffected code.
