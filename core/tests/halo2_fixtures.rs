//! Explicit synthetic witnesses for tests and benchmarks, never a library API.
#![cfg(feature = "halo2")]
#![allow(dead_code)]
use sable_core::{Result, SableError};
use sable_core::zk::halo2::{FaceVerificationProver, LivenessWitness, Proof};

pub fn fixture_policy(threshold: u64, witness: &LivenessWitness) -> sable_core::zk::halo2::ExpectedPolicy {
    use sable_core::zk::halo2::{ExpectedPolicy, AUTH_CIRCUIT_V1, challenge_digest, poseidon_commit_bytes_value};
    ExpectedPolicy {
        registered_template: poseidon_commit_bytes_value(&vec![0; 512]),
        threshold, challenge_digest: challenge_digest(witness), required_liveness: true,
        circuit_id: AUTH_CIRCUIT_V1.into(), expires_at: 1000,
    }
}

pub fn default_policy(threshold: u64) -> sable_core::zk::halo2::ExpectedPolicy {
    fixture_policy(threshold, &LivenessWitness::dummy_pass())
}

pub trait SyntheticFixture {
    fn prove(&mut self, distance: u64, threshold: u64) -> Result<Proof>;
    fn prove_with_liveness(&mut self, distance: u64, threshold: u64, witness: Option<LivenessWitness>) -> Result<Proof>;
}

impl SyntheticFixture for FaceVerificationProver {
    fn prove(&mut self, distance: u64, threshold: u64) -> Result<Proof> {
        self.prove_with_liveness(distance, threshold, Some(LivenessWitness::dummy_pass()))
    }

    fn prove_with_liveness(&mut self, distance: u64, threshold: u64, witness: Option<LivenessWitness>) -> Result<Proof> {
        if distance > 4096 { return Err(SableError::InvalidInput("Fixture distance exceeds 512 bytes".into())); }
        let enrolled = vec![0; 512];
        let mut live = vec![0; 512];
        for (index, byte) in live.iter_mut().enumerate() {
            let bits = distance.saturating_sub(index as u64 * 8).min(8);
            *byte = ((1u16 << bits) - 1) as u8;
        }
        self.prove_with_embeddings(&enrolled, &live, threshold, Some(witness.unwrap_or_else(LivenessWitness::dummy_pass)))
    }
}
