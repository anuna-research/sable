# P2P replacement status

The old raw-X25519 session API and the BLE/NFC wrappers that use it are withdrawn
from production builds. Fragmentation remains available as an unauthenticated
transport primitive. No deployed service or existing binary has been updated.

`core/src/p2p/authenticated.rs` is private, test-only implementation work toward
SBL-RT-007, not completion of that finding. Snow and the additional HKDF dependency
are development dependencies while this integration is incomplete.

## Implemented mechanism

The handshake uses Snow 0.10's `Noise_XX_25519_ChaChaPoly_SHA256`. XX authenticates
possession of static keys; our wrapper compares the received static key against an
independently supplied expected key before permitting completion. An internal
constructor now accepts a checked certificate-key possession binding from
`attestation/peer_binding.rs`, consumes it for the exact session/role, and places
the certificate digests in the prologue. A combined test validates both peers'
certificates/signatures, completes Noise and exchanges protected records. This is
not issuer-authorized biometric enrollment or platform capture attestation. There is no
trust-on-first-use fallback and no early application data.

The prologue binds a fixed protocol/version domain, a shared session ID and ordered
initiator/responder identity digests. The wrapper rejects low-order X25519 pins and
incoming ephemeral keys explicitly. The default resolver did not reject the
all-zero ephemeral key in our response-generation regression test.

After completed, pinned XX, the wrapper consumes the handshake and uses Snow's raw
split keys only for the application record layer. HKDF-SHA256 derives independent
directional keys using the domain, complete handshake hash, context and sender role.
It does not also create a Noise transport using the same split keys. This application
record layer is not the standard Noise transport and needs independent review.

Each record authenticates a 35-byte header as ChaCha20-Poly1305 associated data:
four-byte magic, one-byte version, 16-byte session ID, one-byte sender role,
one-byte message type, eight-byte sequence and four-byte plaintext length. Integers
are big-endian. The receiver checks the expected message type and exact next sequence.
Per-direction counters start at zero; the nonce is four zero bytes followed by the
eight-byte sequence. No caller-selected nonce or counter reset is exposed.

Payloads are capped at 64 KiB. Handshakes expire after 30 seconds; records expire
after 30 seconds of inactivity. Certificate-bound channels additionally enforce an
absolute monotonic deadline capped by the binding and certificate/CRL expiry;
activity cannot extend that deadline. Any protocol, authentication, size, exhaustion or
timeout error invalidates the affected state and drops its application keys. The
current record protocol requires ordered reliable delivery; loss or reordering
requires a new session rather than counter resynchronization.

## Outstanding release gates

- Complete issuer-authorized identity/biometric binding, persistent trust/revocation
  rollback protection and persistent single-use challenges around the internal
  checked-binding constructor. Test-fixture pins remain internal and are not a
  production trust-provisioning path.
- Migrate BLE/NFC wrappers, bound session/reassembly resources and authenticate
  the relevant transport/message types. Verify on-device interoperability.
- Review domain separation, key lifecycle, Noise secret cleanup, counter policy,
  parser behavior and denial-of-service limits; add independent vectors and fuzzing.
- Test version mismatch and identity lifecycle changes across complete endpoints.

The original finding stays open until these gates are satisfied. Withdrawal is
containment, not evidence that the requested authenticated P2P capability exists.

## References

The [Noise framework](https://noiseprotocol.org/noise.html) defines XX, prologue and
handshake transcript processing. The implementation uses Snow's
[handshake API](https://docs.rs/snow/0.10.0/snow/struct.HandshakeState.html); the raw
split operation is opt-in through its `risky-raw-split` feature. These dependencies
do not constitute a security audit of SABLE's wrapper or application record layer.
