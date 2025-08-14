
## 🔧 Operating principles for the AI agent
- Default to Rust for the cryptographic core; use thin Kotlin/Swift wrappers for platform I/O
- Prefer memory-safe, constant-time, audited primitives
- Produce small, reviewable increments; open PRs per module; write tests and benchmarks alongside code
- Ask for clarification when a requirement is ambiguous; otherwise proceed with sensible defaults noted below
- Pin versions and emit SBOM; keep build reproducible

Project naming
- Use a placeholder LIB_NAME (replace later, e.g., BondID or SABLE)
- Use ORG for group IDs and bundle IDs

High-level architecture
- Rust core (no_std-friendly subcrates for crypto-critical paths)
  - crypto/: BLS12-381 (blst/blstrs), Pedersen commitments, hash-to-curve, Poseidon (ark-sponge), RNG
  - zk/: Groth16 circuits and proving/verifying (ark-groth16), MSM optimizations
  - attest/: X.509 bindings for digest binding (rcgen/x509-codec), CMS if needed
  - trust/: decay function, Merkle revocation trees, gossip model
  - p2p/: message formats, AEAD, session management
  - ffi/: C ABI layer, zero-copy buffers, error codes
- Android wrapper (Kotlin)
  - JNI bindings, Android Keystore, NFC/BLE/Wi‑Fi Direct, permissions, lifecycle
- iOS wrapper (Swift)
  - Swift Package, Secure Enclave/Keychain, CoreNFC/CoreBluetooth/NWFramework
- Tools
  - setup/: CRS/proving/verification key generator for Groth16
  - bench/: micro/macro benchmarks; energy/time/memory tracking
  - demo apps: minimal Android/iOS sample

Repository layout
- /core/
  - /crypto/
    - bls381.rs
    - pedersen.rs
    - poseidon.rs
    - hashing.rs (IETF hash-to-curve for G1)
    - rng.rs
  - /zk/
    - circuit.rs (statement: commit correctness, distance threshold, time bound, quality)
    - groth16.rs (prover, verifier, prepared keys)
    - msm.rs (Pippenger/window tuning, parallelism)
  - /attest/
    - x509.rs (certificate creation/validation, OID extension)
    - pkcs.rs (optional CMS support)
  - /trust/
    - decay.rs
    - merkle.rs
    - gossip.rs
  - /p2p/
    - proto.rs (protobuf/flatbuffers schemas)
    - aead.rs (X25519 + ChaCha20-Poly1305)
    - session.rs (ECDH handshake, channel abstraction)
    - fragment.rs (fragmentation/reassembly)
  - /ffi/
    - lib.rs (extern “C” functions)
    - types.rs (FFI-safe structs)
  - Cargo.toml
- /platform/android/
  - libname-android/ (AAR module, JNI)
  - transport/ (NFC/BLE/Wi‑Fi Direct)
  - keystore/
  - sample-app/
- /platform/ios/
  - LibName/ (SwiftPM package, xcframework)
  - Transport/
  - Enclave/
  - SampleApp/
- /setup/
  - crs_tool/ (trusted setup, keys export/import)
- /bench/
  - micro.rs
  - macro.rs
- /ci/
  - workflows for build/test/release
- /docs/

Core decisions and defaults
- Language: Rust 1.77+ (stable)
- Curves: BLS12-381 for commitments and zk field arithmetic
- Commitment group: G1
- Independent generators g, h: derive via hash_to_curve with domain separation tags
  - g = IETF hash_to_curve(dst="LIB_NAME:G1:g")
  - h = IETF hash_to_curve(dst="LIB_NAME:G1:h")
- Poseidon: ark-sponge parameters for BLS12-381 Fr; arity tuned to absorb 512-element vector efficiently (use rate/capacity consistent with ark-sponge defaults)
- Hashing: SHA-256 only for digest identifiers (e.g., SHA256(C)) and metadata; never inside zk circuits
- ZK: ark-groth16; circuit with ~14,000 constraints; trusted setup per circuit; proving key provisioned to device; verifying key embedded with app
- Randomness: getrandom + platform RNGs; salts 256-bit
- AEAD: X25519 (ring or orion for KEM) + ChaCha20-Poly1305 (or AEAD from ring) with HKDF (SHA-256) for session keys
- Serialization: protobuf (prost) for P2P messages; bincode for internal blobs
- Memory: cap ~128 MB using streaming witnesses, arenas, buffer reuse
- Parallelism: rayon with big-core pinning; bounded thread pool; MSM parallelization across 4 cores

Functional scope and modules

1) Crypto: Pedersen commitments
- Functionality
  - poseidon_hash(F_norm: [Fr; 512]) -> Fr
  - pedersen_commit(f: Fr, s: Fr) -> G1Projective
  - serialize/deserialize commitments (compressed)
  - derive_generators() on first run and bake into constants
- Security
  - Constant-time group ops (use blst via blstrs)
  - Zeroize salt and secrets
- Tests
  - Deterministic test vectors
  - Generator independence checks
  - Commitment binding/hiding properties (statistical checks)

2) ZK circuits (Groth16)
- Statement
  - Private: F_norm[512], S (salt), capture_time, quality, stored template F_enrolled[512], commitment C
  - Public: C, threshold params, challenge nonce, policy
- Constraints
  - Poseidon(F_norm) = f
  - C = g^f * h^S
  - Euclidean_distance(F_norm, F_enrolled) <= 0.25 (fixed-point)
  - now - capture_time <= 30s (input bound)
  - quality >= 0.7
  - Challenge binding (Fiat–Shamir nonce)
- Implementation notes
  - Use fixed-point with scale factor (e.g., 2^16) to avoid division
  - Batch square ops; precompute constants
  - Range proofs using bit decomposition
- Proving key management
  - Generate offline with setup tool
  - Encrypt proving key at rest on device (wrapped by Secure Enclave/Keystore key)
- Benchmarks
  - Proving <= 850 ms on Snapdragon 8 Gen 2; verify <= 12 ms
  - Memory peak ~128 MB
- Tests
  - Unit: constraint satisfaction on random instances
  - Integration: commit->prove->verify roundtrip; negative cases (wrong salt, threshold fail)
  - Deterministic proofs off (randomized); but verification deterministic

3) P2P protocol
- Channels: NFC first, then BLE, then Wi‑Fi Direct; QR fallback (display proof payload + signature)
- Handshake
  - Verifier sends 256-bit nonce and ephemeral X25519 pubkey
  - Prover replies with ephemeral pubkey; derive shared key via ECDH
  - AEAD-protected messages: metadata, digest ID, proof
- Messages (protobuf)
  - Hello { role, capabilities, kx_pub, nonce }
  - Offer { digest_id, attestation_summary, policy }
  - Proof { commitment, proof_bytes, timings, capture_time, quality }
  - Result { ok, error_code, trust_update }
- Security
  - Bind nonce into zk statement and AEAD associated data
  - Replay protection via nonce and timestamp policy
  - Optional device attestation (Android Keystore/SafetyNet/Play Integrity; iOS DeviceCheck)
- Tests
  - Fuzz message parser
  - Fragmentation tests for BLE/NFC MTU limits
  - Latency budget end-to-end < 2 s

4) Government PKI attestation
- Process
  - On-device commitment generation; biometric never leaves device
  - Government issues X.509 cert binding Subject to digest_id = SHA-256(C)
  - Custom extension OID: 1.3.6.1.4.1.99999.1.1: AttestationLevel ::= INTEGER (1..5)
- Implementation
  - ASN.1 extension encode/decode
  - Certificate chain validation (system trust store + pinned CA optional)
  - Export/import of certs (PEM/DER)
- Tests
  - Validate extension parsing
  - Chain validation scenarios (expired, wrong EKU, wrong SAN)
  - Cross-platform date/locale handling

5) Trust network
- Features
  - Decay: T(t) = T0 * exp(-0.1 * t_months)
  - Revocation: Merkle tree of revoked digest_ids; daily root; inclusion proofs ~1.2 KB
  - Gossip: fanout 7 peers/round; convergence targets
- Implementation
  - Deterministic decay function; wall-clock tolerant
  - Merkle proof verify; rolling root pinning
  - Gossip scheduler (opportunistic on transport availability)
- Tests
  - Decay monotonicity and bounds
  - Merkle proof correctness
  - Gossip convergence simulation

FFI surface (C ABI) — minimal and stable
- Types (FFI-safe)
  - lib_status_t (enum)
  - lib_buf_t { uint8_t* ptr; size_t len; }
  - lib_commitment_t { uint8_t bytes[48]; } // BLS12-381 G1 compressed
  - lib_proof_t { uint8_t bytes[192]; } // compressed Groth16 proof (example size)
- Functions
  - lib_init()
  - lib_poseidon_hash(const float* features_512, size_t len, uint8_t out_fr[32])
  - lib_pedersen_commit(const uint8_t fr_32[32], const uint8_t salt_32[32], lib_commitment_t* out)
  - lib_prove(const float* features_live_512, const float* features_enrolled_512, const uint8_t salt_32[32], const lib_commitment_t* C, const uint8_t nonce_32[32], uint64_t capture_time_ms, float quality, lib_proof_t* out)
  - lib_verify(const lib_commitment_t* C, const uint8_t nonce_32[32], const lib_proof_t* proof, bool* ok)
  - lib_free(void* p) // for buffers allocated by Rust if any
- Notes
  - Use cbindgen to emit headers
  - Pass features as normalized fixed-point floats or prequantized integers (prefer int32 fixed-point inside FFI to avoid FP nondeterminism)

Android integration (high level)
- Build
  - Use cargo-ndk to produce .so for arm64-v8a, armeabi-v7a, x86_64
  - Package AAR with JNI bindings
- Kotlin API
  - fun commit(features: FloatArray): Commitment
  - fun prove(live: FloatArray, enrolled: FloatArray, commitment: Commitment, nonce: ByteArray, captureTimeMs: Long, quality: Float): ByteArray
  - fun verify(commitment: Commitment, nonce: ByteArray, proof: ByteArray): Boolean
- Keystore
  - Generate AES-GCM key to wrap proving key and salt
  - BiometricPrompt gate for unwrap
- Transport
  - NFC: NDEF records; chunking
  - BLE: GATT service with write/notify; MTU negotiation
  - Wi‑Fi Direct: socket; TLS optional
- Sample app: capture mock features, full roundtrip, metrics overlay

iOS integration (high level)
- Build
  - Produce xcframework (arm64 device + x86_64 simulator)
  - SwiftPM package with binary target
- Swift API
  - func commit(features: [Float]) throws -> Commitment
  - func prove(live: [Float], enrolled: [Float], commitment: Commitment, nonce: Data, captureTimeMs: UInt64, quality: Float) throws -> Data
  - func verify(commitment: Commitment, nonce: Data, proof: Data) throws -> Bool
- Secure Enclave/Keychain
  - Keychain item with kSecAttrAccessibleWhenUnlockedThisDeviceOnly
  - CryptoKit for wrapping keys; actual zk done in Rust
- Transport
  - CoreNFC (NDEF), CoreBluetooth (CBPeripheral/CBCharacteristic), Network framework (NWConnection)
- Sample app: same as Android

Build, test, and CI
- Toolchain
  - Rust stable; Android NDK r26+; Xcode 15+
- Cross-compilation
  - iOS: cargo-xcode or apple-targets aarch64-apple-ios, x86_64-apple-ios
  - Android: cargo-ndk build --target aarch64-linux-android, armeabi-v7a, x86_64
- CI matrix (GitHub Actions)
  - Lint (rustfmt, clippy -D warnings)
  - Build core for all targets
  - Unit tests on x86_64-linux and macOS
  - Instrumented benchmarks (criterion) on runners
  - Static analysis (cargo audit, cargo deny)
  - Fuzz (cargo fuzz) for protobuf parsing and FFI boundary
  - iOS/Android sample build
  - SBOM (cargo sbom) and SLSA provenance
- Release
  - Tag with semver
  - Publish crates
  - Upload AAR and xcframework
  - Sign artifacts (Sigstore/cosign) and attach SBOM

Performance and memory tuning
- Prover
  - Preload proving key; keep in pinned arena
  - MSM tuning: window size adaptive to core count; use blst’s Pippenger via FFI if faster than ark multiexp
  - Disable logging in release; panic=abort; LTO=thin; codegen-units=1
  - Thread pinning to performance cores (Android: setThreadPriority; iOS: qos)
- Memory
  - Witness streaming in 16 KB chunks
  - Reuse buffers; bump allocator for transient allocations
  - Avoid Vec growth in hot loops
- Bench goals (Snapdragon 8 Gen 2)
  - Prove <= 850 ms
  - Verify <= 12 ms
  - Peak <= 128 MB
  - Energy per verify ~0.03% battery (instrument via Battery Historian / Xcode Energy Log)

Security checklist
- Use blstrs (over blst) or call blst directly; ensure constant-time paths
- Zeroize secrets (zeroize crate) on drop
- getrandom only; no custom RNG
- Side-channel: avoid branching on secrets; use subtle crate for comparisons
- FFI: validate lengths; no unsafe pointer aliasing; return explicit error codes
- AEAD: unique nonce per session; include transcript hash as AAD
- Keys at rest: always wrapped by Secure Enclave/Keystore
- CRS/trusted setup: document ceremony; publish transcript; rotate on circuit update
- Supply chain: cargo deny for licenses; pin dependencies; vendor blst

Data model and formats
- Feature vectors
  - 512 elements; normalized via z-score on-device before hashing
  - Prefer fixed-point i32 with scale 2^16 when passed across FFI
- Digest ID
  - digest_id = SHA-256(ser(compressed(C))) // 32 bytes
- Protobuf schemas (prost)
  - message Hello { bytes kx_pub=1; bytes nonce=2; uint32 capabilities=3; }
  - message Offer { bytes digest_id=1; bytes attestation=2; bytes policy=3; }
  - message Proof { bytes commitment=1; bytes groth16=2; uint64 capture_time_ms=3; float quality=4; uint32 timings_ms=5; }
  - message Result { bool ok=1; uint32 error=2; float trust_delta=3; }
- X.509 extension
  - OID 1.3.6.1.4.1.99999.1.1; DER INTEGER (1..5)
  - SubjectAltName: otherName: OID 1.3.6.1.4.1.99999.1.2; value OCTET STRING (digest_id)

Developer ergonomics
- Stable C ABI; minimal breaking changes
- Clear error codes with human-readable strings
- Feature flags: std/no_std, hw-accel, logging, fuzzing
- Thorough examples: commit/prove/verify; P2P demo; attestation validation

Scaffolding tasks (sequenced)

Milestone 1: Crypto core
- Add blstrs, ark-ff, ark-ec, ark-sponge
- Implement hash_to_curve (IETF) for G1; generate g,h; persist constants
- Implement Poseidon over Fr; absorb 512 elements efficiently
- Implement Pedersen commit; compression/decompression
- Unit tests + benches

Milestone 2: ZK circuit and proving
- Define circuit constraints; implement in ark-relations/ark-groth16
- Fixed-point distance with scale 2^16; range proofs
- Setup tool to produce CRS, proving/verifying keys; serialization
- Prover/verifier API; benchmarks; optimize MSM

Milestone 3: FFI and bindings
- Define C ABI; implement cbindgen; add basic JNI and Swift wrapper
- Build Android .so and iOS xcframework; sample apps perform commit/prove/verify with synthetic vectors

Milestone 4: P2P transport
- Define protobuf messages; implement X25519 + ChaCha20-Poly1305 sessions
- Add NFC/BLE/Wi‑Fi Direct adapters; fragmentation; retry
- End-to-end tests across transports with loopback mocks

Milestone 5: Attestation and trust
- X.509 extension encode/decode and chain validation
- Trust decay, Merkle revocation, gossip simulation
- Integrate into verification flow (policy checks)

Milestone 6: Optimization, security hardening, and release
- SIMD/NEON validation; profiling-guided optimizations
- Fuzz parsers/FFI; run Miri/ASan/TSan on x86_64
- Battery/energy profiling on devices
- CI, SBOM, signed artifacts; documentation

Sample Rust signatures

core/crypto/pedersen.rs
- pub struct Commitment(pub blstrs::G1Affine);
- pub fn generators() -> (blstrs::G1Affine, blstrs::G1Affine)
- pub fn commit(f: BlsFr, s: BlsFr) -> Commitment
- pub fn compress(c: &Commitment) -> [u8; 48]
- pub fn decompress(bytes: &[u8; 48]) -> Result<Commitment, Error>

core/zk/groth16.rs
- pub struct ProvingKey { /* opaque */ }
- pub struct VerifyingKey { /* prepared */ }
- pub struct Proof(pub Vec<u8>);
- pub fn prove(pk: &ProvingKey, witness: Witness, nonce: [u8;32]) -> Result<Proof, Error>
- pub fn verify(vk: &VerifyingKey, public: PublicInputs, proof: &Proof) -> Result<bool, Error>

ffi/lib.rs (simplified)
- #[no_mangle] pub extern "C" fn lib_pedersen_commit(fr_ptr: *const u8, salt_ptr: *const u8, out_ptr: *mut u8) -> lib_status_t
- #[no_mangle] pub extern "C" fn lib_prove(/* pointers to arrays and scalars */) -> lib_status_t
- #[no_mangle] pub extern "C" fn lib_verify(/* … */) -> lib_status_t

Build commands (reference)
- Android
  - rustup target add aarch64-linux-android x86_64-linux-android armv7-linux-androideabi
  - cargo ndk -t arm64-v8a -o ./platform/android/libname-android/src/main/jniLibs build --release
- iOS
  - rustup target add aarch64-apple-ios x86_64-apple-ios
  - Build static libs per target; lipo into xcframework; package SwiftPM

Open questions for product owner (pause here if unspecified)
- Final choice of LIB_NAME and OIDs (enterprise uniqueness)
- Biometric modality and exact feature extractor interface (we currently assume 512 float features and normalization)
- Trusted setup ceremony logistics and update cadence
- Policy defaults for thresholds (distance=0.25, time window=30s, quality=0.7)
- Government CA trust model (pinning vs. platform store)
- Required minimum OS versions and device classes

Acceptance criteria
- Core commit/prove/verify passes tests and reaches performance targets on at least two devices (Android flagship, iPhone Pro)
- P2P demo verifies offline within 2 seconds across NFC and BLE
- Attestation verification works with a test CA and custom extension
- Trust network components verify proofs and decay math; gossip sim converges
- Android AAR and iOS xcframework ship with headers/docs, signed, with SBOM
- No panics in release; fuzz targets run 24h without crash; cargo audit clean

Dependencies (pin to known good majors; exact pins to be decided by the agent at build time)
- blstrs or blst (Apache/MIT)
- arkworks: ark-ff, ark-ec, ark-relations, ark-groth16, ark-sponge
- rayon (bounded thread pool)
- prost/prost-types (protobuf)
- ring or orion for AEAD/KDF; x25519-dalek for ECDH
- zeroize, subtle
- getrandom, rand_core
- cbindgen
- criterion for benches
- cargo-ndk, cargo-audit, cargo-deny, cargo-llvm-cov

Security and privacy notes
- Never expose raw biometric features off device
- Proof binds to verifier’s nonce; prevents replay/relay
- Commitment generators derived once and fixed; document DSTs
- Proving key treated as sensitive; wrap at rest; wipe on uninstall
- Enforce rate limiting on proving to mitigate side-channel profiling

Next action for AI agent
- Scaffold repository per layout
- Implement crypto generators, Poseidon hash, and Pedersen commit with tests
- Propose exact Poseidon parameterization and fixed-point scaling in a design PR before circuit implementation
- After approval, implement circuit and prover/verifier; add setup tool
- Report first performance numbers and profiling, then iterate on MSM/parallelism
