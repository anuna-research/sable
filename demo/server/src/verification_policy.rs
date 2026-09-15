//! Preserve the original challenge deadline across proving, caching and verification.
use sable_core::zk::halo2::{ExpectedPolicy, Proof};
use std::time::{Duration, Instant};

pub(crate) struct PendingVerification {
    pub expected: ExpectedPolicy,
    deadline: Instant,
}

impl PendingVerification {
    pub fn new(expected: ExpectedPolicy, challenge_created_at: Instant) -> Result<Self, String> {
        let deadline = challenge_created_at
            .checked_add(Duration::from_secs(30))
            .ok_or("Challenge deadline overflow")?;
        Ok(Self { expected, deadline })
    }

    pub fn is_current(&self, wall_now: u64, monotonic_now: Instant) -> bool {
        wall_now < self.expected.expires_at && monotonic_now < self.deadline
    }

    pub fn validate(
        &self,
        proof: &Proof,
        wall_now: u64,
        monotonic_now: Instant,
    ) -> Result<(), String> {
        if !self.is_current(wall_now, monotonic_now) {
            return Err("Verification policy expired".into());
        }
        self.expected
            .validate(proof, wall_now)
            .map_err(|_| "Proof does not match active verifier policy".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sable_core::zk::halo2::{Halo2Fr, AUTH_CIRCUIT_V1};

    #[test]
    fn deadline_survives_proving_delay_and_wall_clock_rollback() {
        let issued = Instant::now();
        let pending = PendingVerification::new(
            ExpectedPolicy {
                registered_template: Halo2Fr::from(17),
                threshold: 200,
                challenge_digest: Halo2Fr::from(23),
                required_liveness: true,
                circuit_id: AUTH_CIRCUIT_V1.into(),
                expires_at: 130,
            },
            issued,
        )
        .unwrap();
        let proof = Proof {
            proof_bytes: vec![1],
            public_inputs: vec![
                Halo2Fr::from(1),
                Halo2Fr::from(200),
                Halo2Fr::from(1),
                Halo2Fr::from(23),
                Halo2Fr::from(17),
            ],
            liveness_passed: true,
            challenge_digest: Halo2Fr::from(23),
            commitment: Halo2Fr::from(17),
        };
        // Structural policy checks only: these bytes are deliberately not a ZK proof.
        assert!(pending
            .validate(&proof, 129, issued + Duration::from_secs(29))
            .is_ok());
        // A proof operation that crosses the deadline must not be accepted.
        assert!(pending
            .validate(&proof, 129, issued + Duration::from_secs(30))
            .is_err());
        assert!(pending
            .validate(&proof, 90, issued + Duration::from_secs(31))
            .is_err());
        assert!(pending
            .validate(&proof, 130, issued + Duration::from_secs(29))
            .is_err());
    }
}
