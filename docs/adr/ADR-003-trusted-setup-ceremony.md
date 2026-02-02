# ADR-003: Trusted Setup Ceremony Protocol

## Status

Accepted

## Context

SABLE uses Groth16 zk-SNARKs for zero-knowledge biometric verification. Groth16
requires a trusted setup phase that generates proving and verifying keys. This
setup produces "toxic waste" - random values that, if known to an attacker,
would allow forging proofs.

REQ-012 mandates a secure multi-party computation (MPC) ceremony for trusted
setup parameter generation with verifiable randomness and toxic waste disposal
documentation.

## Decision

We implement a sequential MPC ceremony protocol with the following properties:

### Ceremony Structure

1. **Coordinator** initializes the ceremony with circuit parameters
2. **Participants** contribute entropy sequentially
3. Each contribution is **verified** before acceptance
4. **Transcript** records all contributions for auditability
5. **Finalization** produces the proving and verifying keys
6. **Toxic waste attestations** are collected from participants

### Security Model: One-Honest-Participant

The ceremony guarantees security if **at least one participant**:
- Generated truly random entropy
- Properly destroyed their toxic waste
- Did not collude with all other participants

This is a fundamental property of MPC ceremonies for Groth16 and is why we
require multiple independent participants.

### Minimum Requirements

- **Minimum participants**: 3 (configurable via `MIN_CEREMONY_PARTICIPANTS`)
- **Maximum participants**: 64 (configurable via `MAX_CEREMONY_PARTICIPANTS`)
- **Entropy size**: 256 bits (32 bytes) per participant

### Contribution Protocol

Each participant must:

1. **Generate entropy** using a cryptographically secure RNG
   - Recommended: Hardware RNG, multiple independent entropy sources
   - Air-gapped machine preferred for high-security setups

2. **Submit contribution** via `TrustedSetupCeremony::contribute()`
   - Contribution is verified before acceptance
   - Invalid contributions are rejected

3. **Destroy toxic waste** immediately after contribution
   - The entropy used must be securely erased
   - Use `zeroize` crate for secure memory clearing
   - Physical destruction of media for highest security

4. **Provide attestation** of toxic waste destruction
   - Document the destruction method
   - Optional: witness signatures, timestamps

### Verification

Each contribution is verified:
- Entropy length is correct (32 bytes)
- Entropy hash is computed correctly
- Entropy is not degenerate (not all zeros or all ones)

The transcript maintains a chain of parameter hashes that can be independently
verified.

### Toxic Waste Disposal

**Critical Security Requirement**: Each participant MUST destroy their
randomness after contributing.

Acceptable destruction methods:
- `SecureMemoryWipe` - Using zeroize crate
- `HsmClear` - Hardware Security Module key deletion
- `PhysicalDestruction` - Physical destruction of storage media
- `AirGappedMachineDestruction` - Destruction of air-gapped machine
- `MultipleMethodsCombined` - Combination of methods

Attestations are collected via `TrustedSetupCeremony::add_toxic_waste_attestation()`.

### Transcript Format

The ceremony transcript includes:
- Ordered list of contribution hashes
- Verification proofs for each contribution
- Chain of parameter hashes
- Start and end timestamps
- Ceremony version identifier
- Optional metadata

## Consequences

### Positive

1. **Provable Security**: One-honest-participant security model provides
   strong guarantees.

2. **Auditability**: Complete transcript allows independent verification.

3. **Flexibility**: Supports variable number of participants.

4. **Documentation**: Toxic waste attestations provide audit trail.

5. **Determinism**: Same contributions produce same parameters, enabling
   verification.

### Negative

1. **Sequential Protocol**: Participants must contribute one at a time,
   which may slow large ceremonies.

2. **Trust in Attestations**: Toxic waste attestations are self-reported
   and cannot be cryptographically verified.

3. **Coordination Overhead**: Requires organizing multiple independent
   participants.

### Neutral

1. **Single Ceremony**: Parameters must be regenerated if circuit changes.

2. **Storage**: Transcript and attestations require storage.

## Implementation

The ceremony is implemented in `core/src/crypto/groth16.rs`:

```rust
// Create ceremony
let params = CircuitParams::default();
let mut ceremony = TrustedSetupCeremony::new(params);

// Add contributions
for participant in participants {
    let entropy = participant.generate_entropy();
    ceremony.contribute(&entropy)?;

    // Participant must destroy entropy here!
    entropy.zeroize();

    // Submit attestation
    ceremony.add_toxic_waste_attestation(
        participant.id,
        ToxicWasteAttestation {
            participant_id: participant.id,
            destruction_method: ToxicWasteDestructionMethod::SecureMemoryWipe,
            destruction_timestamp: now(),
            witness_info: None,
            signature: participant.sign_attestation(),
        }
    )?;
}

// Finalize
let proving_key = ceremony.finalize()?;
let verifying_key = ceremony.get_verifying_key().unwrap();

// Verify ceremony
assert!(ceremony.verify_ceremony()?);
```

## Key Types

- `TrustedSetupCeremony` - Main ceremony coordinator
- `Contribution` - A participant's entropy contribution
- `CeremonyTranscript` - Audit log of all contributions
- `ToxicWasteAttestation` - Participant's destruction attestation
- `ToxicWasteDisposal` - Collection of all attestations

## References

1. Bowe, S., Gabizon, A., & Miers, I. (2017). "Scalable Multi-party
   Computation for zk-SNARK Parameters in the Random Beacon Model."
   IACR Cryptology ePrint Archive.

2. Ben-Sasson, E., et al. (2014). "Succinct Non-Interactive Zero Knowledge
   for a von Neumann Architecture." USENIX Security.

3. Groth, J. (2016). "On the Size of Pairing-based Non-interactive Arguments."
   EUROCRYPT.

4. Zcash Powers of Tau Ceremony documentation.

5. Ethereum KZG Ceremony documentation.
