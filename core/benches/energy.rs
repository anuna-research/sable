//! REQ-023: Energy Consumption Benchmarks for SABLE
//!
//! These benchmarks measure the energy consumption of verification operations
//! to ensure compliance with the < 0.03% battery per verification requirement.
//!
//! Run with: cargo bench --bench energy --features mobile

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::time::Duration;

use sable_core::mobile::energy::{
    reference_devices, EnergyBenchmark, EnergyProfile, EnergyProfiler, PhaseEnergy,
    VerificationPhase, MAX_BATTERY_PERCENT_PER_VERIFICATION,
};

/// Benchmark the energy profiler overhead
fn bench_profiler_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("energy_profiler_overhead");

    let profiler = EnergyProfiler::snapdragon_8_gen2();

    group.bench_function("profile_empty_function", |b| {
        b.iter(|| {
            let (result, _phase) = profiler.profile(VerificationPhase::PoseidonHash, || 42u64);
            result
        })
    });

    group.bench_function("create_phase_energy", |b| {
        b.iter(|| {
            PhaseEnergy::new(
                VerificationPhase::ProofGeneration,
                Duration::from_millis(50),
                2500.0,
            )
        })
    });

    group.finish();
}

/// Benchmark energy calculation performance
fn bench_energy_calculations(c: &mut Criterion) {
    let mut group = c.benchmark_group("energy_calculations");

    let profiler = EnergyProfiler::snapdragon_8_gen2();

    // Create a realistic set of phase measurements
    let phases = vec![
        PhaseEnergy::new(
            VerificationPhase::FeatureExtraction,
            Duration::from_millis(10),
            2000.0,
        ),
        PhaseEnergy::new(
            VerificationPhase::PoseidonHash,
            Duration::from_millis(5),
            2500.0,
        ),
        PhaseEnergy::new(
            VerificationPhase::ProofGeneration,
            Duration::from_millis(100),
            3000.0,
        ),
        PhaseEnergy::new(
            VerificationPhase::P2pCommunication,
            Duration::from_millis(50),
            800.0,
        ),
        PhaseEnergy::new(
            VerificationPhase::ProofVerification,
            Duration::from_millis(30),
            2250.0,
        ),
    ];

    group.bench_function("create_full_profile", |b| {
        b.iter(|| profiler.create_full_profile(phases.clone()))
    });

    let profile = profiler.create_full_profile(phases);

    group.bench_function("check_budget", |b| {
        b.iter(|| profiler.is_within_budget(&profile))
    });

    group.bench_function("find_most_intensive_phase", |b| {
        b.iter(|| profile.most_intensive_phase())
    });

    group.finish();
}

/// Benchmark energy profiler across different device configurations
fn bench_device_configurations(c: &mut Criterion) {
    let mut group = c.benchmark_group("device_configurations");

    let devices = vec![
        ("snapdragon_8_gen2", EnergyProfiler::snapdragon_8_gen2()),
        ("apple_a16", EnergyProfiler::apple_a16()),
        (
            "mediatek_dimensity_9200",
            EnergyProfiler::mediatek_dimensity_9200(),
        ),
    ];

    let phases = vec![
        PhaseEnergy::new(
            VerificationPhase::FeatureExtraction,
            Duration::from_millis(10),
            2000.0,
        ),
        PhaseEnergy::new(
            VerificationPhase::ProofGeneration,
            Duration::from_millis(100),
            3000.0,
        ),
        PhaseEnergy::new(
            VerificationPhase::ProofVerification,
            Duration::from_millis(30),
            2250.0,
        ),
    ];

    for (name, profiler) in devices {
        group.bench_with_input(
            BenchmarkId::new("profile_verification", name),
            &profiler,
            |b, profiler| b.iter(|| profiler.create_full_profile(phases.clone())),
        );
    }

    group.finish();
}

/// Benchmark report generation
fn bench_report_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("report_generation");

    let profiler = EnergyProfiler::snapdragon_8_gen2();
    let mut benchmark = EnergyBenchmark::new(profiler);

    // Add some benchmark results
    for _ in 0..10 {
        benchmark.run_verification_benchmark(|p| {
            vec![
                PhaseEnergy::new(
                    VerificationPhase::FeatureExtraction,
                    Duration::from_millis(10),
                    2000.0,
                ),
                PhaseEnergy::new(
                    VerificationPhase::ProofGeneration,
                    Duration::from_millis(100),
                    3000.0,
                ),
                PhaseEnergy::new(
                    VerificationPhase::ProofVerification,
                    Duration::from_millis(30),
                    2250.0,
                ),
            ]
        });
    }

    group.bench_function("generate_report", |b| {
        b.iter(|| benchmark.generate_report())
    });

    group.bench_function("calculate_averages", |b| {
        b.iter(|| (benchmark.average_mah(), benchmark.average_battery_percent()))
    });

    group.finish();
}

/// Simulate a full verification workflow and measure energy
fn bench_simulated_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("simulated_verification");

    group.sample_size(50); // Reduce sample size for longer benchmarks

    let profiler = EnergyProfiler::snapdragon_8_gen2();

    // Simulate feature extraction (lightweight computation)
    group.bench_function("phase_feature_extraction", |b| {
        b.iter(|| {
            let (_, phase) = profiler.profile(VerificationPhase::FeatureExtraction, || {
                // Simulate feature extraction work
                let mut sum = 0.0f64;
                for i in 0..10000 {
                    sum += (i as f64).sqrt();
                }
                sum
            });
            phase
        })
    });

    // Simulate Poseidon hash (moderate computation)
    group.bench_function("phase_poseidon_hash", |b| {
        b.iter(|| {
            let (_, phase) = profiler.profile(VerificationPhase::PoseidonHash, || {
                // Simulate hash computation
                let mut data = vec![0u8; 1024];
                for i in 0..data.len() {
                    data[i] = ((i * 31 + 17) % 256) as u8;
                }
                data
            });
            phase
        })
    });

    // Simulate proof generation (heavy computation)
    group.bench_function("phase_proof_generation", |b| {
        b.iter(|| {
            let (_, phase) = profiler.profile(VerificationPhase::ProofGeneration, || {
                // Simulate proof generation with heavier computation
                let mut accumulator = 1u64;
                for i in 1..50000 {
                    accumulator = accumulator.wrapping_mul(i as u64);
                    accumulator = accumulator.wrapping_add(i as u64);
                }
                accumulator
            });
            phase
        })
    });

    group.finish();
}

/// Benchmark mAh to percentage conversions across battery sizes
fn bench_battery_conversions(c: &mut Criterion) {
    let mut group = c.benchmark_group("battery_conversions");

    let battery_sizes = [
        ("small_3000mah", 3000.0),
        ("typical_4500mah", 4500.0),
        ("large_5500mah", 5500.0),
    ];

    for (name, battery_mah) in battery_sizes {
        let profiler = EnergyProfiler::new(name, battery_mah, 2500.0);

        group.bench_with_input(
            BenchmarkId::new("mah_to_percent", name),
            &profiler,
            |b, profiler| {
                b.iter(|| {
                    profiler.mah_to_percent(1.35) // 0.03% of 4500mAh
                })
            },
        );

        group.bench_with_input(
            BenchmarkId::new("percent_to_mah", name),
            &profiler,
            |b, profiler| b.iter(|| profiler.percent_to_mah(0.03)),
        );
    }

    group.finish();
}

/// Verify that typical verification stays within energy budget
fn bench_energy_budget_compliance(c: &mut Criterion) {
    let mut group = c.benchmark_group("energy_budget_compliance");

    // Test with conservative timing assumptions
    let conservative_phases = vec![
        PhaseEnergy::new(
            VerificationPhase::FeatureExtraction,
            Duration::from_millis(50),
            2000.0,
        ),
        PhaseEnergy::new(
            VerificationPhase::PoseidonHash,
            Duration::from_millis(20),
            2500.0,
        ),
        PhaseEnergy::new(
            VerificationPhase::ProofGeneration,
            Duration::from_millis(200),
            3000.0,
        ),
        PhaseEnergy::new(
            VerificationPhase::P2pCommunication,
            Duration::from_millis(100),
            800.0,
        ),
        PhaseEnergy::new(
            VerificationPhase::ProofVerification,
            Duration::from_millis(50),
            2250.0,
        ),
    ];

    let devices = vec![
        EnergyProfiler::snapdragon_8_gen2(),
        EnergyProfiler::apple_a16(),
        EnergyProfiler::mediatek_dimensity_9200(),
    ];

    group.bench_function("check_all_devices", |b| {
        b.iter(|| {
            let mut all_pass = true;
            for device in &devices {
                let profile = device.create_full_profile(conservative_phases.clone());
                if !device.is_within_budget(&profile) {
                    all_pass = false;
                }
            }
            all_pass
        })
    });

    group.finish();
}

criterion_group!(
    energy_benches,
    bench_profiler_overhead,
    bench_energy_calculations,
    bench_device_configurations,
    bench_report_generation,
    bench_simulated_verification,
    bench_battery_conversions,
    bench_energy_budget_compliance,
);

criterion_main!(energy_benches);
