# SABLE Threat Model

**Document Version:** 1.0
**Last Updated:** 2026-02-02
**Classification:** Security Documentation

## Overview

This document describes the threat model for SABLE (Secure Authentication via Biometric Linkage and Encryption), a privacy-preserving biometric authentication system using zero-knowledge proofs. It identifies attack surfaces, threat actors, and mitigations implemented or planned.

---

## System Architecture Summary

SABLE consists of the following major components:

1. **Cryptographic Core**: BLS12-381 operations, Poseidon hash, Pedersen commitments, Groth16 zk-SNARKs
2. **Biometric Processing**: Palm vein/print feature extraction, template generation, matching
3. **Mobile Integration**: Android JNI, iOS Swift bindings, hardware keystore integration
4. **P2P Protocol**: Session management, encrypted communication, replay prevention

---

## Threat Actors

### TA-1: Passive Network Attacker
**Capability:** Can observe all network traffic between devices
**Motivation:** Steal biometric data, identify users, track authentication attempts
**Resources:** Network monitoring tools, traffic analysis capabilities

### TA-2: Active Network Attacker (Man-in-the-Middle)
**Capability:** Can intercept, modify, and inject network traffic
**Motivation:** Impersonate users, forge authentication, disrupt service
**Resources:** Network position, cryptographic tools, protocol knowledge

### TA-3: Malicious Verifier
**Capability:** Legitimate verifier role, receives proofs and commitments
**Motivation:** Extract biometric information, link identities across sessions
**Resources:** Multiple verification sessions, computational resources

### TA-4: Malicious Prover
**Capability:** Attempts to authenticate without valid biometrics
**Motivation:** Unauthorized access, identity fraud
**Resources:** Stolen commitments, cryptographic tools, social engineering

### TA-5: Compromised Device Attacker
**Capability:** Full access to one endpoint device (mobile phone)
**Motivation:** Extract biometric templates, keys, or forge local authentication
**Resources:** Root access, memory inspection tools, debuggers

### TA-6: Insider Threat (Ceremony Participant)
**Capability:** Participates in trusted setup ceremony
**Motivation:** Forge proofs by retaining toxic waste
**Resources:** Ceremony participation, collusion with others

### TA-7: Side-Channel Attacker
**Capability:** Physical or remote observation of device during operations
**Motivation:** Extract secrets through timing, power, or EM emissions
**Resources:** Timing measurement tools, EM probes, specialized equipment

---

## Attack Surfaces

### AS-1: Cryptographic Primitives

#### AS-1.1: Pedersen Commitments
| Threat | Description | Mitigation | Status |
|--------|-------------|------------|--------|
| Binding Break | Find collision (f1,s1) != (f2,s2) with same commitment | Use proven BLS12-381 curve with 128-bit security | Implemented |
| Hiding Break | Extract feature information from commitment | Perfect hiding via random blinding factor | Implemented |
| Weak Randomness | Predictable salt enables commitment forgery | SecureRng with platform entropy (getrandom) | Implemented |

#### AS-1.2: Groth16 zk-SNARKs
| Threat | Description | Mitigation | Status |
|--------|-------------|------------|--------|
| Forged Proofs | Create valid proof without valid witness | Groth16 soundness + proper circuit design | Implemented |
| Knowledge Extraction | Extract biometric features from proof | Zero-knowledge property of Groth16 | Implemented |
| Circuit Under-constraint | Missing constraints allow invalid proofs | Circuit soundness review (pending audit) | Needs Review |
| Toxic Waste Attack | Ceremony participant forges proofs | MPC ceremony with one-honest-participant model | Implemented |

#### AS-1.3: Poseidon Hash
| Threat | Description | Mitigation | Status |
|--------|-------------|------------|--------|
| Collision Finding | Find two inputs with same hash | 8 full + 56 partial rounds per security analysis | Implemented |
| Preimage Attack | Recover input from hash output | Poseidon security margin against known attacks | Implemented |
| Parameter Weakness | Weak MDS matrix or round constants | Deterministic derivation from nothing-up-my-sleeve values | Implemented |

### AS-2: Biometric Processing

#### AS-2.1: Feature Extraction
| Threat | Description | Mitigation | Status |
|--------|-------------|------------|--------|
| Raw Biometric Exposure | Plaintext biometric data leaked | Features immediately hashed/committed | Implemented |
| Template Reconstruction | Recreate biometric from template | One-way feature extraction + commitment | Implemented |
| Quality Bypass | Accept low-quality samples to reduce security | Quality thresholds (FAR < 0.1%) | Implemented |
| Input Injection | Malformed image causes buffer overflow | Input validation on image dimensions | **OPEN** |

#### AS-2.2: Biometric Matching
| Threat | Description | Mitigation | Status |
|--------|-------------|------------|--------|
| Timing Attack | Measure distance calculation time to infer similarity | Constant-time distance calculations (subtle crate) | Implemented |
| Threshold Manipulation | Modify threshold to accept invalid matches | Threshold included in zk-SNARK public inputs | Implemented |
| Replay Attack | Reuse old biometric capture | Temporal validity in proof (time window) | Implemented |

### AS-3: P2P Communication

#### AS-3.1: Key Exchange
| Threat | Description | Mitigation | Status |
|--------|-------------|------------|--------|
| Eavesdropping | Passive attacker reads session keys | X25519 ECDH ephemeral key exchange | Implemented |
| Key Compromise Impersonation | Past key compromise enables future attacks | Perfect forward secrecy via ephemeral keys | Implemented |
| MITM During Exchange | Active attacker substitutes public keys | Out-of-band verification recommended | Partial |

#### AS-3.2: Session Security
| Threat | Description | Mitigation | Status |
|--------|-------------|------------|--------|
| Message Replay | Reuse captured encrypted messages | 96-bit nonce tracking, reject duplicates | Implemented |
| Message Tampering | Modify ciphertext to alter plaintext | ChaCha20-Poly1305 AEAD authentication | Implemented |
| Session Hijacking | Take over established session | 30-second session timeout, session binding | Implemented |
| Nonce Exhaustion | Memory exhaustion via nonce tracking | Session timeout limits nonce accumulation | Implemented |

### AS-4: Mobile Platform

#### AS-4.1: FFI Boundary
| Threat | Description | Mitigation | Status |
|--------|-------------|------------|--------|
| Buffer Overflow | Malformed input causes memory corruption | Bounds checking, null pointer validation | Implemented |
| Use-After-Free | Access freed memory via handle | Handle lifecycle management | Implemented |
| Information Leakage | Error messages reveal internals | Sanitized error codes (REQ-005) | Implemented |
| Double-Free | Free same allocation twice | Single ownership model | Implemented |

#### AS-4.2: Key Storage
| Threat | Description | Mitigation | Status |
|--------|-------------|------------|--------|
| Key Extraction | Extract keys from device storage | Hardware keystore (Android Keystore/iOS Keychain) | Implemented |
| Biometric Bypass | Bypass biometric to access keys | Keystore access policies require biometric | Implemented |
| Root/Jailbreak Attack | Elevated privileges extract secrets | Hardware-backed keys resist root access | Partial |

### AS-5: Trusted Setup Ceremony

| Threat | Description | Mitigation | Status |
|--------|-------------|------------|--------|
| Single Point of Failure | One party controls all toxic waste | Multi-party computation (MPC) | Implemented |
| Collusion Attack | All participants collude | One-honest-participant security model | Implemented |
| Toxic Waste Retention | Participant keeps toxic waste | Attestation collection, verification | Implemented |
| Ceremony Manipulation | Inject malicious contributions | Contribution verification before acceptance | Implemented |

---

## Data Flow Security Analysis

### Enrollment Flow

```
[Raw Biometric] --> [Feature Extraction] --> [512-dim Vector] --> [Poseidon Hash] --> [Pedersen Commitment]
                           |                        |                    |                    |
                           v                        v                    v                    v
                    Zeroize after use      Zeroize after use    Hash stored      Commitment stored
```

**Security Properties:**
- Raw biometric is never stored
- Feature vector is cleared immediately after commitment
- Only commitment is persisted
- Salt is stored securely in keystore

### Verification Flow

```
[Stored Commitment] + [Fresh Biometric] --> [zk-SNARK Proof Generation] --> [Proof + Public Inputs]
                                                                                      |
                                                                                      v
[Verifier] <-- [P2P Encrypted Channel] <-- [Proof Transmission] <--------------- [Prover]
     |
     v
[Groth16 Verification] --> Accept/Reject
```

**Security Properties:**
- Fresh biometric never leaves device
- Proof reveals nothing about features (zero-knowledge)
- P2P channel is authenticated and encrypted
- Verifier learns only pass/fail result

---

## Mitigations Summary

### Implemented Mitigations

| ID | Mitigation | Threats Addressed | Implementation |
|----|------------|-------------------|----------------|
| M-01 | Pedersen commitments | Biometric exposure | `crypto/pedersen.rs` |
| M-02 | Groth16 zk-SNARKs | Feature extraction from proofs | `crypto/groth16.rs` |
| M-03 | Constant-time operations | Timing side-channels | `biometric/constant_time.rs` |
| M-04 | X25519 ECDH + ChaCha20-Poly1305 | Network eavesdropping | `p2p/session.rs` |
| M-05 | Nonce tracking | Replay attacks | `p2p/session.rs` |
| M-06 | 30-second session timeout | Session hijacking | `p2p/session.rs` |
| M-07 | MPC trusted setup | Toxic waste attacks | `crypto/groth16.rs` |
| M-08 | Hardware keystore | Key extraction | `mobile/keystore.rs` |
| M-09 | Error sanitization | Information leakage | `mobile/ffi.rs` |
| M-10 | Quality thresholds | Low-quality bypass | `biometric/preprocessing.rs` |
| M-11 | Temporal validity | Biometric replay | `crypto/groth16.rs` |
| M-12 | Memory zeroization | Memory forensics | Multiple (zeroize crate) |

### Planned/Recommended Mitigations

| ID | Mitigation | Threats Addressed | Status |
|----|------------|-------------------|--------|
| M-13 | HKDF key derivation | Weak key derivation | Recommended |
| M-14 | Input validation hardening | Buffer overflow | Open |
| M-15 | Full circuit constraint audit | Circuit under-constraint | Pending Audit |
| M-16 | Certificate pinning for P2P | MITM during exchange | Planned |
| M-17 | Rate limiting | Brute force attacks | Planned |
| M-18 | Secure boot verification | Compromised device | Planned |

---

## Risk Assessment Matrix

| Risk | Likelihood | Impact | Severity | Mitigation Status |
|------|------------|--------|----------|-------------------|
| Biometric data exposure | Low | Critical | High | Mitigated (M-01, M-02) |
| Proof forgery | Very Low | Critical | Medium | Mitigated (M-02, M-07) |
| Timing side-channel | Medium | High | Medium | Mitigated (M-03) |
| Network eavesdropping | Medium | High | Medium | Mitigated (M-04) |
| Replay attack (network) | Medium | Medium | Medium | Mitigated (M-05) |
| Replay attack (biometric) | Low | High | Medium | Mitigated (M-11) |
| Session hijacking | Low | Medium | Low | Mitigated (M-06) |
| MITM attack | Low | High | Medium | Partial (M-04, M-16 planned) |
| Key extraction (device) | Low | Critical | Medium | Mitigated (M-08) |
| Input validation bypass | Medium | Medium | Medium | **Open (M-14)** |
| Toxic waste attack | Very Low | Critical | Low | Mitigated (M-07) |
| Information leakage | Medium | Low | Low | Mitigated (M-09) |

---

## Security Assumptions

1. **Cryptographic Assumptions:**
   - Discrete logarithm problem is hard on BLS12-381
   - Poseidon hash is collision-resistant with chosen parameters
   - Groth16 is secure under knowledge-of-exponent assumption

2. **Platform Assumptions:**
   - Hardware keystore provides tamper resistance
   - Platform RNG provides adequate entropy
   - No physical tampering with user device

3. **Operational Assumptions:**
   - Trusted setup ceremony has at least one honest participant
   - Users do not share their biometrics with attackers
   - Verifiers are properly authenticated

---

## Audit Recommendations

### Priority 1 (Critical)
1. Review Groth16 circuit soundness for constraint completeness
2. Validate Pedersen commitment implementation
3. Audit trusted setup ceremony security

### Priority 2 (High)
1. Verify constant-time implementations with timing analysis
2. Review FFI boundary for memory safety issues
3. Validate biometric input validation

### Priority 3 (Medium)
1. Review session management for race conditions
2. Audit nonce tracking for memory exhaustion
3. Validate quality threshold enforcement

---

## Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-02-02 | SABLE Team | Initial threat model document |

---

## Related Documents

- [SECURITY_AUDIT_CHECKLIST.md](./SECURITY_AUDIT_CHECKLIST.md)
- [ADR-002: Biometric Quality Thresholds](../adr/ADR-002-quality-thresholds.md)
- [ADR-003: Trusted Setup Ceremony Protocol](../adr/ADR-003-trusted-setup-ceremony.md)
- [IMPLEMENTATION_STATUS.md](../../IMPLEMENTATION_STATUS.md)
