//! # Halo2 Performance Benchmarks
//!
//! Benchmarks basic proof generation and verification times for Halo2 circuits.
//! This validates NFR-001 (≤1000ms prove) and NFR-002 (≤50ms verify).

use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};

#[cfg(feature = "halo2")]
#[path = "../tests/halo2_fixtures.rs"]
mod halo2_fixtures;

#[cfg(feature = "halo2")]
mod halo2_benches {
    use super::halo2_fixtures::{SyntheticFixture, default_policy};
    use super::*;
    use sable_core::zk::halo2::{HelloCircuit, FaceVerificationProver, FaceVerificationVerifier};

    /// Benchmark the mock prover (circuit validation without real proof).
    pub fn bench_mock_prover(c: &mut Criterion) {
        let mut group = c.benchmark_group("halo2_mock_prover");

        // Test different input sizes
        let test_cases = [
            ("small", 3u64, 5u64),
            ("medium", 1_000_000u64, 2_000_000u64),
            ("large", u64::MAX / 2, u64::MAX / 4),
        ];

        for (name, a, b) in test_cases {
            let circuit = HelloCircuit::new(a, b);

            group.bench_with_input(
                BenchmarkId::from_parameter(name),
                &circuit,
                |bench, circuit| {
                    bench.iter(|| {
                        circuit.test_circuit().expect("Circuit should be valid")
                    });
                },
            );
        }

        group.finish();
    }

    /// Benchmark circuit construction time.
    pub fn bench_circuit_construction(c: &mut Criterion) {
        c.bench_function("halo2_circuit_construction", |b| {
            b.iter(|| {
                let circuit = HelloCircuit::new(42, 58);
                criterion::black_box(circuit.expected_output())
            });
        });
    }

    /// Benchmark real proof generation (NFR-001: ≤1000ms).
    pub fn bench_proof_generation(c: &mut Criterion) {
        let mut group = c.benchmark_group("halo2_proof_generation");
        group.sample_size(10); // Fewer samples due to longer runtime

        // Pre-create prover (key generation happens once)
        let mut prover = FaceVerificationProver::new();
        // Warm up - generate one proof to create keys
        let _ = prover.prove(100, 200).expect("Warmup should succeed");

        let test_cases = [
            ("passing", 100u64, 200u64),
            ("failing", 300u64, 200u64),
            ("boundary", 200u64, 200u64),
        ];

        for (name, distance, threshold) in test_cases {
            group.bench_with_input(
                BenchmarkId::from_parameter(name),
                &(distance, threshold),
                |bench, &(d, t)| {
                    bench.iter(|| {
                        prover.prove(d, t).expect("Proof generation should succeed")
                    });
                },
            );
        }

        group.finish();
    }

    /// Benchmark proof verification (NFR-002: ≤50ms).
    pub fn bench_proof_verification(c: &mut Criterion) {
        let mut group = c.benchmark_group("halo2_proof_verification");

        // Generate a proof to verify
        let mut prover = FaceVerificationProver::new();
        let proof = prover.prove(100, 200).expect("Proof generation should succeed");
        let verifier = FaceVerificationVerifier::from_prover(&mut prover).expect("Verifier creation should succeed");
        let policy = default_policy(200);

        group.bench_function("verify", |b| {
            b.iter(|| {
                verifier.verify_expected(&proof, &policy, 0).expect("Verification should succeed")
            });
        });

        group.finish();
    }

    /// Benchmark proof size (NFR-003: ≤10KB).
    pub fn bench_proof_size(c: &mut Criterion) {
        let mut prover = FaceVerificationProver::new();
        let proof = prover.prove(100, 200).expect("Proof generation should succeed");

        println!("\n=== Proof Size Metrics ===");
        println!("Proof size: {} bytes ({:.2} KB)", proof.size(), proof.size() as f64 / 1024.0);
        println!("Meets NFR-003 (≤10KB): {}", proof.meets_size_requirement());
        println!("==========================\n");

        c.bench_function("proof_size_check", |b| {
            b.iter(|| {
                criterion::black_box(proof.size())
            });
        });
    }
}

#[cfg(feature = "halo2")]
criterion_group!(
    benches,
    halo2_benches::bench_mock_prover,
    halo2_benches::bench_circuit_construction,
    halo2_benches::bench_proof_generation,
    halo2_benches::bench_proof_verification,
    halo2_benches::bench_proof_size,
);

#[cfg(feature = "halo2")]
criterion_main!(benches);

// Stub for when halo2 feature is disabled
#[cfg(not(feature = "halo2"))]
fn main() {
    eprintln!("Halo2 benchmarks require --features halo2");
}
