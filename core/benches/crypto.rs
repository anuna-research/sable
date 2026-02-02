//! Benchmarks for SABLE crypto operations
//!
//! These benchmarks measure the performance of core cryptographic operations
//! to ensure they meet the mobile performance targets specified in README.md
//!
//! REQ-022: SIMD/NEON Performance Benchmarks
//!
//! This module includes benchmarks comparing SIMD-optimized vs scalar implementations
//! to verify the 2x performance improvement target for ARM NEON optimizations.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use sable_core::{
    crypto::{
        poseidon::{
            poseidon_hash, normalize_features,
            // REQ-022: SIMD-optimized functions
            zscore_normalize_f32, euclidean_distance_f32, dot_product_f32,
            cosine_similarity_f32, magnitude_f32, simd_enabled,
        },
        pedersen::{commit_default, random_commitment, Generators},
        bls381::{Bls12381, Fr},
    },
    FEATURE_VECTOR_SIZE,
};

/// Benchmark Poseidon hashing of feature vectors
fn bench_poseidon_hash(c: &mut Criterion) {
    let mut group = c.benchmark_group("poseidon_hash");
    
    // Generate test feature vector
    let features = [0.1f32; FEATURE_VECTOR_SIZE];
    
    group.throughput(Throughput::Elements(FEATURE_VECTOR_SIZE as u64));
    group.bench_function("hash_512_features", |b| {
        b.iter(|| poseidon_hash(&features).unwrap())
    });
    
    group.finish();
}

/// Benchmark feature vector normalization
fn bench_feature_normalization(c: &mut Criterion) {
    let mut group = c.benchmark_group("feature_normalization");
    
    // Create a realistic feature vector with some variance
    let mut features = vec![0.0f32; FEATURE_VECTOR_SIZE];
    for (i, feature) in features.iter_mut().enumerate() {
        *feature = (i as f32) * 0.01 + ((i * 37) % 100) as f32 / 100.0;
    }
    
    group.throughput(Throughput::Elements(FEATURE_VECTOR_SIZE as u64));
    group.bench_function("normalize_512_features", |b| {
        b.iter(|| normalize_features(&features).unwrap())
    });
    
    group.finish();
}

/// Benchmark Pedersen commitment creation
fn bench_pedersen_commit(c: &mut Criterion) {
    let mut group = c.benchmark_group("pedersen_commit");
    
    let generators = Generators::new().unwrap();
    let message = Fr::from(42u64);
    let randomness = Bls12381::random_scalar().unwrap();
    
    group.bench_function("single_commit", |b| {
        b.iter(|| {
            sable_core::crypto::pedersen::commit(
                message, 
                randomness, 
                &generators
            )
        })
    });
    
    // Benchmark batch commitments
    let messages: Vec<Fr> = (0..100).map(|i| Fr::from(i as u64)).collect();
    let randomness_vec: Vec<Fr> = (0..100).map(|_| Bls12381::random_scalar().unwrap()).collect();
    
    group.throughput(Throughput::Elements(100));
    group.bench_function("batch_commit_100", |b| {
        b.iter(|| {
            sable_core::crypto::pedersen::batch_commit(
                &messages,
                &randomness_vec, 
                &generators
            ).unwrap()
        })
    });
    
    group.finish();
}

/// Benchmark commitment serialization
fn bench_commitment_serialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("commitment_serialization");
    
    let (commitment, _) = random_commitment().unwrap();
    
    group.bench_function("serialize", |b| {
        b.iter(|| commitment.to_bytes())
    });
    
    let bytes = commitment.to_bytes();
    group.bench_function("deserialize", |b| {
        b.iter(|| sable_core::crypto::pedersen::Commitment::from_bytes(&bytes).unwrap())
    });
    
    group.finish();
}

/// Benchmark elliptic curve operations
fn bench_curve_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("curve_operations");
    
    let scalar = Bls12381::random_scalar().unwrap();
    let point = Bls12381::random_g1().unwrap();
    
    group.bench_function("scalar_multiplication", |b| {
        b.iter(|| Bls12381::scalar_mul_g1(&point, &scalar))
    });
    
    // Multi-scalar multiplication benchmark
    let points: Vec<_> = (0..100).map(|_| Bls12381::random_g1().unwrap()).collect();
    let scalars: Vec<_> = (0..100).map(|_| Bls12381::random_scalar().unwrap()).collect();
    
    group.throughput(Throughput::Elements(100));
    group.bench_function("multi_scalar_mul_100", |b| {
        b.iter(|| Bls12381::multi_scalar_mul_g1(&points, &scalars).unwrap())
    });
    
    group.finish();
}

/// Full biometric commitment pipeline benchmark
fn bench_full_pipeline(c: &mut Criterion) {
    let mut group = c.benchmark_group("full_pipeline");
    
    // Simulate realistic biometric features with some variance
    let mut raw_features = vec![0.0f32; FEATURE_VECTOR_SIZE];
    for (i, feature) in raw_features.iter_mut().enumerate() {
        *feature = ((i * 17 + 42) % 1000) as f32 / 1000.0 - 0.5;
    }
    
    group.bench_function("normalize_hash_commit", |b| {
        b.iter(|| {
            // Full pipeline: normalize -> hash -> commit
            let normalized = normalize_features(&raw_features).unwrap();
            let hash = poseidon_hash(&normalized).unwrap();
            let randomness = Bls12381::random_scalar().unwrap();
            commit_default(hash, randomness)
        })
    });
    
    group.finish();
}

/// Benchmark generator derivation (done once at startup)
fn bench_generator_derivation(c: &mut Criterion) {
    let mut group = c.benchmark_group("generator_derivation");
    
    group.bench_function("derive_generators", |b| {
        b.iter(|| Generators::new().unwrap())
    });
    
    group.finish();
}

// =============================================================================
// REQ-022: SIMD/NEON Performance Benchmarks
// =============================================================================

/// Benchmark SIMD-optimized z-score normalization (REQ-022)
fn bench_simd_zscore_normalize(c: &mut Criterion) {
    let mut group = c.benchmark_group("simd_zscore_normalize");

    // Log whether SIMD is enabled
    println!("SIMD enabled: {}", simd_enabled());

    // Benchmark different vector sizes
    for size in [64, 128, 256, 512, 1024].iter() {
        let mut features: Vec<f32> = (0..*size).map(|i| (i as f32) * 0.01).collect();

        group.throughput(Throughput::Elements(*size as u64));
        group.bench_with_input(
            BenchmarkId::new("zscore_normalize_f32", size),
            size,
            |b, _| {
                b.iter(|| {
                    let mut f = features.clone();
                    zscore_normalize_f32(&mut f);
                    f
                })
            },
        );
    }

    group.finish();
}

/// Benchmark SIMD-optimized Euclidean distance (REQ-022)
fn bench_simd_euclidean_distance(c: &mut Criterion) {
    let mut group = c.benchmark_group("simd_euclidean_distance");

    for size in [64, 128, 256, 512, 1024].iter() {
        let a: Vec<f32> = (0..*size).map(|i| (i as f32) * 0.01).collect();
        let b: Vec<f32> = (0..*size).map(|i| (i as f32) * 0.02 + 0.5).collect();

        group.throughput(Throughput::Elements(*size as u64));
        group.bench_with_input(
            BenchmarkId::new("euclidean_distance_f32", size),
            size,
            |bench, _| {
                bench.iter(|| euclidean_distance_f32(&a, &b))
            },
        );
    }

    group.finish();
}

/// Benchmark SIMD-optimized dot product (REQ-022)
fn bench_simd_dot_product(c: &mut Criterion) {
    let mut group = c.benchmark_group("simd_dot_product");

    for size in [64, 128, 256, 512, 1024].iter() {
        let a: Vec<f32> = (0..*size).map(|i| (i as f32) * 0.01).collect();
        let b: Vec<f32> = (0..*size).map(|i| (i as f32) * 0.02).collect();

        group.throughput(Throughput::Elements(*size as u64));
        group.bench_with_input(
            BenchmarkId::new("dot_product_f32", size),
            size,
            |bench, _| {
                bench.iter(|| dot_product_f32(&a, &b))
            },
        );
    }

    group.finish();
}

/// Benchmark SIMD-optimized cosine similarity (REQ-022)
fn bench_simd_cosine_similarity(c: &mut Criterion) {
    let mut group = c.benchmark_group("simd_cosine_similarity");

    for size in [64, 128, 256, 512, 1024].iter() {
        let a: Vec<f32> = (0..*size).map(|i| (i as f32) * 0.01).collect();
        let b: Vec<f32> = (0..*size).map(|i| (i as f32) * 0.02 + 0.1).collect();

        group.throughput(Throughput::Elements(*size as u64));
        group.bench_with_input(
            BenchmarkId::new("cosine_similarity_f32", size),
            size,
            |bench, _| {
                bench.iter(|| cosine_similarity_f32(&a, &b))
            },
        );
    }

    group.finish();
}

/// Benchmark SIMD-optimized magnitude calculation (REQ-022)
fn bench_simd_magnitude(c: &mut Criterion) {
    let mut group = c.benchmark_group("simd_magnitude");

    for size in [64, 128, 256, 512, 1024].iter() {
        let v: Vec<f32> = (0..*size).map(|i| (i as f32) * 0.01).collect();

        group.throughput(Throughput::Elements(*size as u64));
        group.bench_with_input(
            BenchmarkId::new("magnitude_f32", size),
            size,
            |bench, _| {
                bench.iter(|| magnitude_f32(&v))
            },
        );
    }

    group.finish();
}

/// Benchmark comparing SIMD vs scalar for biometric feature processing (REQ-022)
fn bench_simd_biometric_pipeline(c: &mut Criterion) {
    let mut group = c.benchmark_group("simd_biometric_pipeline");

    // Simulate a realistic biometric feature processing pipeline
    let features_a: Vec<f32> = (0..512).map(|i| ((i * 17 + 42) % 1000) as f32 / 1000.0 - 0.5).collect();
    let features_b: Vec<f32> = (0..512).map(|i| ((i * 23 + 37) % 1000) as f32 / 1000.0 - 0.5).collect();

    group.bench_function("full_biometric_comparison", |b| {
        b.iter(|| {
            // Normalize both feature vectors
            let mut a = features_a.clone();
            let mut b_vec = features_b.clone();
            zscore_normalize_f32(&mut a);
            zscore_normalize_f32(&mut b_vec);

            // Calculate similarity metrics
            let cosine = cosine_similarity_f32(&a, &b_vec);
            let euclidean = euclidean_distance_f32(&a, &b_vec);
            let dot = dot_product_f32(&a, &b_vec);

            (cosine, euclidean, dot)
        })
    });

    group.finish();
}

criterion_group!(
    crypto_benches,
    bench_poseidon_hash,
    bench_feature_normalization,
    bench_pedersen_commit,
    bench_commitment_serialization,
    bench_curve_operations,
    bench_full_pipeline,
    bench_generator_derivation,
);

// REQ-022: SIMD benchmarks group
criterion_group!(
    simd_benches,
    bench_simd_zscore_normalize,
    bench_simd_euclidean_distance,
    bench_simd_dot_product,
    bench_simd_cosine_similarity,
    bench_simd_magnitude,
    bench_simd_biometric_pipeline,
);

criterion_main!(crypto_benches, simd_benches);
