//! Benchmarks for zero-knowledge proof operations

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use sable_core::crypto::groth16::*;
use sable_core::crypto::pedersen::{commit, Generators};
use sable_core::types::*;
use sable_core::crypto::bls381::Fr;
use heapless::Vec as HeaplessVec;
use ark_std::test_rng;

fn bench_circuit_setup(c: &mut Criterion) {
    let mut rng = test_rng();
    
    let params = CircuitParams {
        distance_threshold: Distance::from(1000),
        time_window: 300,
        feature_count: 128,
    };
    
    let groth16 = SableGroth16::new(params);
    
    c.bench_function("groth16_setup", |b| {
        b.iter(|| {
            black_box(groth16.setup(&mut rng).unwrap())
        })
    });
}

fn bench_constraint_generation(c: &mut Criterion) {
    use ark_relations::r1cs::ConstraintSystem;
    
    let feature_sizes = [16, 32, 64, 128, 256];
    
    for &size in &feature_sizes {
        c.bench_with_input(
            BenchmarkId::new("constraint_generation", size),
            &size,
            |b, &size| {
                b.iter(|| {
                    let cs = ConstraintSystem::<Fr>::new_ref();
                    let circuit = create_test_circuit(size);
                    black_box(circuit.generate_constraints(cs).unwrap())
                })
            },
        );
    }
}

fn bench_proof_generation(c: &mut Criterion) {
    let mut rng = test_rng();
    
    let params = CircuitParams {
        distance_threshold: Distance::from(1000),
        time_window: 300,
        feature_count: 64, // Smaller for benchmarking
    };
    
    let groth16 = SableGroth16::new(params);
    let (pk, _vk) = groth16.setup(&mut rng).unwrap();
    
    // Prepare test data
    let (features, salt, ref_features, ref_salt, commitment, ref_commitment) = 
        create_test_data(64);
    
    let timestamp = Timestamp::from(1000);
    let current_time = Timestamp::from(1100);
    
    c.bench_function("groth16_prove", |b| {
        b.iter(|| {
            black_box(groth16.prove(
                &pk,
                features.clone(),
                salt,
                ref_features.clone(), 
                ref_salt,
                timestamp,
                commitment,
                ref_commitment,
                current_time,
                &mut rng,
            ))
        })
    });
}

fn bench_proof_verification(c: &mut Criterion) {
    let mut rng = test_rng();
    
    let params = CircuitParams {
        distance_threshold: Distance::from(1000),
        time_window: 300,
        feature_count: 64,
    };
    
    let groth16 = SableGroth16::new(params);
    let (pk, vk) = groth16.setup(&mut rng).unwrap();
    
    // Generate a proof to verify
    let (features, salt, ref_features, ref_salt, commitment, ref_commitment) = 
        create_test_data(64);
    
    let timestamp = Timestamp::from(1000);
    let current_time = Timestamp::from(1100);
    
    let (proof, public_inputs) = groth16.prove(
        &pk,
        features,
        salt,
        ref_features,
        ref_salt,
        timestamp,
        commitment,
        ref_commitment,
        current_time,
        &mut rng,
    ).unwrap();
    
    c.bench_function("groth16_verify", |b| {
        b.iter(|| {
            black_box(groth16.verify(&vk, &proof, &public_inputs).unwrap())
        })
    });
}

fn bench_full_zk_workflow(c: &mut Criterion) {
    let mut rng = test_rng();
    
    let params = CircuitParams {
        distance_threshold: Distance::from(1000),
        time_window: 300,
        feature_count: 32, // Small for full workflow benchmark
    };
    
    c.bench_function("full_zk_workflow", |b| {
        b.iter(|| {
            let groth16 = SableGroth16::new(params.clone());
            let (pk, vk) = groth16.setup(&mut rng).unwrap();
            
            let (features, salt, ref_features, ref_salt, commitment, ref_commitment) = 
                create_test_data(32);
            
            let timestamp = Timestamp::from(1000);
            let current_time = Timestamp::from(1100);
            
            let (proof, public_inputs) = groth16.prove(
                &pk,
                features,
                salt,
                ref_features,
                ref_salt,
                timestamp,
                commitment,
                ref_commitment,
                current_time,
                &mut rng,
            ).unwrap();
            
            let verified = groth16.verify(&vk, &proof, &public_inputs).unwrap();
            black_box(verified)
        })
    });
}

// Helper functions
fn create_test_circuit(feature_count: usize) -> BiometricCircuit {
    let mut features = HeaplessVec::new();
    let mut ref_features = HeaplessVec::new();
    
    for i in 0..feature_count.min(MAX_FEATURES) {
        features.push(BiometricFeature::from(100 + i as u32)).unwrap();
        ref_features.push(BiometricFeature::from(105 + i as u32)).unwrap();
    }
    
    BiometricCircuit::new_proving(
        features,
        Salt([42u8; 32]),
        ref_features,
        Salt([43u8; 32]),
        Timestamp::from(1000),
        commit(Fr::from(123), Fr::from(456), Generators::get()),
        commit(Fr::from(789), Fr::from(321), Generators::get()),
        Distance::from(1000),
        300,
        Timestamp::from(1100),
    )
}

fn create_test_data(feature_count: usize) -> (
    HeaplessVec<BiometricFeature, MAX_FEATURES>,
    Salt,
    HeaplessVec<BiometricFeature, MAX_FEATURES>,
    Salt,
    sable_core::crypto::pedersen::Commitment,
    sable_core::crypto::pedersen::Commitment,
) {
    let mut features = HeaplessVec::new();
    let mut ref_features = HeaplessVec::new();
    
    for i in 0..feature_count.min(MAX_FEATURES) {
        features.push(BiometricFeature::from(100 + i as u32)).unwrap();
        ref_features.push(BiometricFeature::from(105 + i as u32)).unwrap();
    }
    
    let salt = Salt([42u8; 32]);
    let ref_salt = Salt([43u8; 32]);
    
    let generators = Generators::get();
    let commitment = commit(Fr::from(123), Fr::from(456), &generators);
    let ref_commitment = commit(Fr::from(789), Fr::from(321), &generators);
    
    (features, salt, ref_features, ref_salt, commitment, ref_commitment)
}

criterion_group!(
    benches,
    bench_circuit_setup,
    bench_constraint_generation,
    bench_proof_generation,
    bench_proof_verification,
    bench_full_zk_workflow
);
criterion_main!(benches);
