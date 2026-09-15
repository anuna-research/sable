# Internal X.509 replacement

`core/src/attestation/validated_x509.rs` is test-only work toward SBL-RT-001.
It does not reuse the custom legacy certificate encoding or its chain/trust logic.
No certificate-validation result is currently available to production consumers.

## Validation profile

The current foundation supports Ed25519 public keys and certificate signatures.
It requires explicit digital-signature key usage and client-auth EKU on a non-CA
leaf; issuer certificates must be CAs with certificate-signing and CRL-signing
usage. The expected DNS subject is verifier-owned input and must match the SAN.
This deliberately narrow profile is not a government identity or platform
attestation profile.

The wrapper bounds certificate/CRL sizes and counts, rejects trailing input and
duplicate certificate extension OIDs, checks validity using a trusted caller clock,
and rejects unsupported key encodings. `rustls-webpki` verifies signatures, builds
the chain to supplied trusted anchors, and enforces intermediate name/path
constraints and critical-extension handling.

CRLs are mandatory for every non-root certificate. Revocation options explicitly
deny unknown status, check the full chain and enforce expiration. The wrapper also
rejects future `thisUpdate`, absent/expired `nextUpdate`, malformed inputs and
ambiguous multiple CRLs for one issuer. CRL signatures are verified by the chain
validator, not trusted because the issuer name matches.

Inputs are bounded to 16 roots, four intermediates, 16 CRLs, 16 KiB per certificate
and 256 KiB per CRL. These limits have focused tests, not parser fuzzing or a
production capacity certification. Unsupported/unknown revocation is a rejection;
there is no OCSP soft-fail path. OCSP-specific support is not implemented.

## Evidence and remaining work

Twelve tests generate real DER certificates/CRLs with rcgen and cover valid chains,
signature forgery, issuer/name/key-usage/EKU/validity/name/path constraints, revoked
leaves/intermediates, wrong-key and stale/missing CRLs, malformed input and bounds.
Commands and results are in the remediation record. X.509 parsing uses
`x509-parser`; path/signature verification uses `rustls-webpki` with Ring. These
dependencies remain development dependencies while the integration is incomplete.

Chain validation alone establishes only the stated chain/name/revocation policy
at the supplied time. A separate internal `peer_binding.rs` now verifies an Ed25519
possession signature over a domain/version, certificate digest, expected DNS identity,
verifier-registered template, audience, fresh challenge, session, sender role,
issuance/expiry and Noise public key. It does not accept those policy fields from
untrusted proof metadata. The signature message uses fixed-width fields and an
explicitly length-prefixed DNS name.

The in-memory challenge is consumed before checking even a failed attempt. A checked,
non-cloneable peer token can be consumed by one Noise handshake for the exact session
and peer role. Its absolute/monotonic deadline is at most 30 seconds and is capped
by certificate and CRL validity. The channel enforces that deadline on handshake and
record operations. Nine binding tests include a complete two-peer protected exchange.

This proves certificate-key possession and binds that signer to verifier-supplied
registration data. It does not prove that a government issuer attested the biometric
template, authenticate physical capture or establish trusted enrollment. An
issuer-authorized binding/profile, relying-party authorization and platform
integration remain required. There is no exported attestation/channel API.

The caller currently supplies trusted anchors. Authenticated trust-store updates,
durable monotonic versions, crash/rollback handling, CRL version rollback protection
and key rotation are not implemented here. A still-current older CRL must not become
an accepted rollback after deployment; time checking alone does not solve that.
Those controls, persistent single-use challenge storage, production protocol
integration, independent review and fuzzing must precede any public attestation API.

## Primary references

The [WebPKI verification API](https://docs.rs/rustls-webpki/0.103.15/webpki/struct.EndEntityCert.html)
separates chain/usage validation, subject-name validation and proof-of-possession
signature verification. All applicable steps remain required by a consuming protocol.
[Revocation options](https://docs.rs/rustls-webpki/0.103.15/webpki/struct.RevocationOptionsBuilder.html)
allow explicit expiration and unknown-status policy; this wrapper selects rejection.
