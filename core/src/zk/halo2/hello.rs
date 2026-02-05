//! # Hello World Halo2 Circuit
//!
//! A minimal Halo2 circuit to validate the setup works.
//! This circuit proves knowledge of two private values (a, b) such that a + b = c,
//! where c is a public output.
//!
//! ## Purpose
//!
//! This module exists to:
//! 1. Validate that Halo2 dependencies are correctly configured
//! 2. Provide a reference implementation for more complex circuits
//! 3. Benchmark basic proof generation/verification times
//!
//! ## Example
//!
//! ```rust,ignore
//! use sable_core::zk::halo2::hello::HelloCircuit;
//!
//! // Create circuit with private inputs
//! let circuit = HelloCircuit::new(3, 5); // a=3, b=5, proves a+b=8
//!
//! // Test the circuit (mock prover)
//! assert!(circuit.test_circuit().is_ok());
//! ```

use halo2_base::gates::circuit::builder::BaseCircuitBuilder;
use halo2_base::gates::circuit::BaseCircuitParams;
use halo2_base::gates::GateChip;
use halo2_base::gates::GateInstructions;
use halo2_base::halo2_proofs::dev::MockProver;
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use halo2_base::AssignedValue;

use crate::error::{Result, SableError};

/// Circuit parameters for the hello world circuit.
const K: u32 = 8; // 2^8 = 256 rows (small for testing)
const NUM_ADVICE: usize = 1;
const NUM_LOOKUP_ADVICE: usize = 0;
const NUM_FIXED: usize = 1;
const LOOKUP_BITS: usize = 8;

/// Hello World circuit that proves a + b = c.
///
/// Private inputs: a, b
/// Public output: c = a + b
pub struct HelloCircuit {
    /// Private input a
    a: u64,
    /// Private input b
    b: u64,
}

impl HelloCircuit {
    /// Create a new hello world circuit.
    ///
    /// # Arguments
    /// * `a` - First private input
    /// * `b` - Second private input
    pub fn new(a: u64, b: u64) -> Self {
        Self { a, b }
    }

    /// Get the expected public output (c = a + b).
    pub fn expected_output(&self) -> u64 {
        self.a.wrapping_add(self.b)
    }

    /// Build the circuit logic.
    fn build_circuit(&self, builder: &mut BaseCircuitBuilder<Fr>) -> AssignedValue<Fr> {
        let ctx = builder.main(0);
        let gate = GateChip::<Fr>::default();

        // Load private inputs as witnesses
        let a = ctx.load_witness(Fr::from(self.a));
        let b = ctx.load_witness(Fr::from(self.b));

        // Compute c = a + b
        let c = gate.add(ctx, a, b);

        // Return c as public output
        c
    }

    /// Generate circuit parameters.
    fn circuit_params() -> BaseCircuitParams {
        BaseCircuitParams {
            k: K as usize,
            num_advice_per_phase: vec![NUM_ADVICE],
            num_lookup_advice_per_phase: vec![NUM_LOOKUP_ADVICE],
            num_fixed: NUM_FIXED,
            lookup_bits: Some(LOOKUP_BITS),
            num_instance_columns: 1,
        }
    }

    /// Test the circuit using the mock prover.
    ///
    /// This validates that the circuit constraints are satisfied without
    /// generating a real proof. Useful for development and testing.
    ///
    /// # Returns
    /// * `Ok(())` if the circuit is valid
    /// * `Err` if constraints are not satisfied
    pub fn test_circuit(&self) -> Result<()> {
        // Build circuit
        let mut builder = BaseCircuitBuilder::new(false)
            .use_params(Self::circuit_params());
        let c = self.build_circuit(&mut builder);

        // Make c a public instance
        builder.assigned_instances[0].push(c);

        // Get expected public output
        let expected = Fr::from(self.expected_output());

        // Run mock prover
        let prover = MockProver::run(K, &builder, vec![vec![expected]])
            .map_err(|e| SableError::ProofGeneration(format!("Mock prover failed: {:?}", e)))?;

        // Verify the circuit
        prover
            .verify()
            .map_err(|e| SableError::ProofVerification(format!("Circuit verification failed: {:?}", e)))?;

        Ok(())
    }

    /// Get the public output value (c = a + b).
    pub fn public_output(&self) -> Fr {
        Fr::from(self.expected_output())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hello_circuit_basic() {
        // Test that 3 + 5 = 8
        let circuit = HelloCircuit::new(3, 5);
        assert_eq!(circuit.expected_output(), 8);
        circuit.test_circuit().expect("Circuit should be valid");
    }

    #[test]
    fn test_hello_circuit_zero() {
        // Test that 0 + 0 = 0
        let circuit = HelloCircuit::new(0, 0);
        assert_eq!(circuit.expected_output(), 0);
        circuit.test_circuit().expect("Circuit should be valid");
    }

    #[test]
    fn test_hello_circuit_large_values() {
        // Test with larger values
        let circuit = HelloCircuit::new(1_000_000, 2_000_000);
        assert_eq!(circuit.expected_output(), 3_000_000);
        circuit.test_circuit().expect("Circuit should be valid");
    }

    #[test]
    fn test_hello_circuit_max_u64() {
        // Test with maximum u64 value (field can represent larger values)
        let circuit = HelloCircuit::new(u64::MAX, 0);
        assert_eq!(circuit.expected_output(), u64::MAX);
        circuit.test_circuit().expect("Circuit should be valid");
    }
}
