//! Verifier-owned expectations for authentication proofs.
//!
//! Construct this from trusted registration and challenge state, never from proof
//! metadata. The caller must also consume the challenge atomically to prevent replay.

use super::{Halo2Fr, Proof};
use crate::{Result, SableError};
use ff::PrimeField;

/// Identifier of the retired pre-temporal thermometer/liveness circuit.
pub const AUTH_CIRCUIT_V1: &str = "sable/thermometer-liveness/1";
/// Identifier of the thermometer/liveness circuit with the SPEC-008 temporal limb.
pub const AUTH_CIRCUIT_V2: &str = "sable/thermometer-liveness/2";

/// Trusted expectations required when accepting an authentication proof.
#[derive(Clone, Debug)]
pub struct ExpectedPolicy {
    /// Template digest loaded from the registered enrollment.
    pub registered_template: Halo2Fr,
    /// Exact matcher threshold chosen by the verifier.
    pub threshold: u64,
    /// Challenge digest computed independently of the proof.
    pub challenge_digest: Halo2Fr,
    /// Authentication policies must require liveness success.
    pub required_liveness: bool,
    /// Circuit selected by the verifier, not negotiated by the prover.
    pub circuit_id: String,
    /// Exclusive proof expiry in Unix seconds, derived from challenge issuance.
    pub expires_at: u64,
}

impl ExpectedPolicy {
    /// Reject malformed or mismatched instances before expensive proof checking.
    ///
    /// `now` is the verifier's trusted clock. This checks the complete field
    /// elements, not truncated integers or duplicated display metadata.
    pub fn validate(&self, proof: &Proof, now: u64) -> Result<()> {
        if self.circuit_id != AUTH_CIRCUIT_V2
            || !self.required_liveness
            || now >= self.expires_at
            || self.threshold > 4096
            || proof.proof_bytes.is_empty()
            || !proof.meets_size_requirement()
        {
            return Err(SableError::ProofVerification("Invalid or expired authentication policy".into()));
        }
        let expected = [
            Halo2Fr::from(1),
            Halo2Fr::from(self.threshold),
            Halo2Fr::from(1),
            self.challenge_digest,
            self.registered_template,
        ];
        if proof.public_inputs.as_slice() != expected
            || !proof.liveness_passed
            || proof.challenge_digest != self.challenge_digest
            || proof.commitment != self.registered_template
        {
            return Err(SableError::ProofVerification("Proof does not match verifier policy".into()));
        }
        Ok(())
    }
}

/// Decode exactly five canonically encoded field elements, without reduction or defaults.
pub fn decode_instances(encoded: &[[u8; 32]]) -> Result<Vec<Halo2Fr>> {
    if encoded.len() != 5 {
        return Err(SableError::InvalidInput("Exactly five public instances are required".into()));
    }
    encoded.iter().map(|bytes| {
        Option::<Halo2Fr>::from(Halo2Fr::from_repr(*bytes))
            .ok_or_else(|| SableError::InvalidInput("Non-canonical public instance".into()))
    }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifier_rejects_unsupported_circuit_configurations() {
        use crate::zk::halo2::{FaceVerificationProver, FaceVerificationVerifier};
        for (dimension, thermometer) in [(64, true), (512, false)] {
            let mut prover = FaceVerificationProver::with_config(dimension, thermometer);
            assert!(FaceVerificationVerifier::from_prover(&mut prover).is_err());
        }
    }

    #[test]
    fn real_proof_requires_registered_policy_and_valid_transcript() {
        use crate::zk::halo2::{FaceVerificationProver, FaceVerificationVerifier, LivenessWitness, challenge_digest, poseidon_commit_bytes_value};
        let enrolled = vec![0; 512];
        let mut witness = LivenessWitness::dummy_pass();
        let temporal = crate::biometric::rolling_shutter::derive_temporal_symbols(
            &[0x11; 32],
            &[0xA5; 32],
        )
        .unwrap();
        witness.temporal_expected_symbols = temporal;
        witness.temporal_observed_symbols = temporal;
        witness.temporal_max_symbol_errors =
            crate::biometric::rolling_shutter::maximum_unambiguous_errors(&temporal);
        witness.temporal_enabled = true;
        witness.temporal_capture_validated = true;
        let policy = ExpectedPolicy {
            registered_template: poseidon_commit_bytes_value(&enrolled),
            threshold: 200,
            challenge_digest: challenge_digest(&witness),
            required_liveness: true,
            circuit_id: AUTH_CIRCUIT_V2.into(),
            expires_at: 100,
        };
        let mut prover = FaceVerificationProver::new();
        assert!(prover.prove_with_embeddings(&enrolled, &enrolled, 200, None).is_err());
        let mut proof = prover.prove_with_embeddings(&enrolled, &enrolled, 200, Some(witness)).unwrap();
        let verifier = FaceVerificationVerifier::from_prover(&mut prover).unwrap();
        assert!(verifier.verify_expected(&proof, &policy, 99).unwrap());
        let mut other = policy.clone();
        other.registered_template += Halo2Fr::from(1);
        assert!(verifier.verify_expected(&proof, &other, 99).is_err());
        assert!(verifier.verify_expected(&proof, &policy, 100).is_err());
        proof.proof_bytes[0] ^= 1;
        assert!(verifier.verify_expected(&proof, &policy, 99).is_err());
    }

    fn fixture() -> (ExpectedPolicy, Proof) {
        let policy = ExpectedPolicy {
            registered_template: Halo2Fr::from(17),
            threshold: 2048,
            challenge_digest: Halo2Fr::from(23),
            required_liveness: true,
            circuit_id: AUTH_CIRCUIT_V2.into(),
            expires_at: 100,
        };
        let proof = Proof {
            proof_bytes: vec![1], // Policy checking does not claim cryptographic validity.
            public_inputs: vec![Halo2Fr::from(1), Halo2Fr::from(2048), Halo2Fr::from(1), policy.challenge_digest, policy.registered_template],
            liveness_passed: true,
            challenge_digest: policy.challenge_digest,
            commitment: policy.registered_template,
        };
        (policy, proof)
    }

    #[test]
    fn rejects_every_instance_substitution_and_wrong_shape() {
        let (policy, proof) = fixture();
        assert!(policy.validate(&proof, 99).is_ok());
        for index in 0..5 {
            let mut altered = proof.clone();
            altered.public_inputs[index] += Halo2Fr::from(1);
            assert!(policy.validate(&altered, 99).is_err(), "instance {index}");
        }
        for count in [0, 1, 2, 3, 4, 6] {
            let mut altered = proof.clone();
            altered.public_inputs.resize(count, Halo2Fr::from(1));
            assert!(policy.validate(&altered, 99).is_err());
        }
    }

    #[test]
    fn rejects_expiry_downgrades_and_oversized_proofs() {
        let (mut policy, mut proof) = fixture();
        assert!(policy.validate(&proof, 100).is_err());
        policy.required_liveness = false;
        assert!(policy.validate(&proof, 99).is_err());
        policy.required_liveness = true;
        policy.circuit_id = "other".into();
        assert!(policy.validate(&proof, 99).is_err());
        policy.circuit_id = AUTH_CIRCUIT_V2.into();
        proof.proof_bytes.resize(10 * 1024 + 1, 0);
        assert!(policy.validate(&proof, 99).is_err());
    }

    #[test]
    fn canonical_instance_decoding_rejects_modulus_reduction_and_wrong_count() {
        assert!(decode_instances(&[[0; 32]; 5]).is_ok());
        assert!(decode_instances(&[[0xff; 32]; 5]).is_err());
        assert!(decode_instances(&[[0; 32]; 4]).is_err());
        assert!(decode_instances(&[[0; 32]; 6]).is_err());
    }
}
