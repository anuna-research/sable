//! Basic usage example for SABLE core library
//! 
//! This example demonstrates the complete workflow for biometric commitment:
//! 1. Feature vector normalization
//! 2. Poseidon hashing
//! 3. Pedersen commitment generation
//! 4. Verification and serialization

use sable_core::{
    crypto::{
        poseidon::{normalize_features, poseidon_hash},
        pedersen::{CommitmentOpening, Generators, commit_with_opening},
        bls381::Fr,
        rng::SecureRng,
    },
    Result, FEATURE_VECTOR_SIZE,
};
use rand_core::RngCore;

fn main() -> Result<()> {
    println!("🔐 SABLE Core - Biometric Commitment Example");
    println!("===========================================\n");

    // Step 1: Simulate biometric feature extraction
    println!("📊 Step 1: Generating simulated biometric features...");
    let raw_features = generate_realistic_features()?;
    println!("   Generated {} features with range [{:.3}, {:.3}]", 
             raw_features.len(),
             raw_features.iter().fold(f32::INFINITY, |a, &b| a.min(b)),
             raw_features.iter().fold(f32::NEG_INFINITY, |a, &b| a.max(b)));

    // Step 2: Normalize features using z-score normalization
    println!("\n🧮 Step 2: Normalizing features...");
    let normalized = normalize_features(&raw_features)?;
    let mean: f32 = normalized.iter().sum::<f32>() / normalized.len() as f32;
    let variance: f32 = normalized.iter()
        .map(|x| (x - mean).powi(2))
        .sum::<f32>() / normalized.len() as f32;
    println!("   Normalized: mean = {:.6}, std_dev = {:.6}", mean, variance.sqrt());

    // Step 3: Hash features using Poseidon
    println!("\n🔢 Step 3: Computing Poseidon hash...");
    let start_time = std::time::Instant::now();
    let feature_hash = poseidon_hash(&normalized)?;
    let hash_duration = start_time.elapsed();
    println!("   Hash computed in {:.2}ms", hash_duration.as_secs_f64() * 1000.0);
    println!("   Hash value: {:?}", hex::encode(&feature_hash.to_bytes_le()));

    // Step 4: Generate Pedersen commitment with random salt
    println!("\n🔐 Step 4: Creating Pedersen commitment...");
    let start_time = std::time::Instant::now();
    let opening = CommitmentOpening::new_with_random_salt(feature_hash)?;
    let generators = Generators::new()?;
    let commitment = commit_with_opening(&opening, &generators);
    let commit_duration = start_time.elapsed();
    println!("   Commitment created in {:.2}ms", commit_duration.as_secs_f64() * 1000.0);

    // Step 5: Verify the commitment
    println!("\n✅ Step 5: Verifying commitment...");
    let start_time = std::time::Instant::now();
    let is_valid = opening.verify(&commitment, &generators);
    let verify_duration = start_time.elapsed();
    println!("   Verification result: {}", if is_valid { "✅ VALID" } else { "❌ INVALID" });
    println!("   Verification completed in {:.2}μs", verify_duration.as_secs_f64() * 1_000_000.0);

    // Step 6: Serialize commitment
    println!("\n💾 Step 6: Serializing commitment...");
    let commitment_bytes = commitment.to_bytes();
    println!("   Serialized size: {} bytes", commitment_bytes.len());
    println!("   Commitment: {}", hex::encode(&commitment_bytes));

    // Step 7: Demonstrate biometric template matching scenario
    println!("\n🎯 Step 7: Biometric template matching simulation...");
    demonstrate_template_matching(&normalized)?;

    // Step 8: Show commitment properties
    println!("\n🧬 Step 8: Demonstrating commitment properties...");
    demonstrate_commitment_properties(&generators)?;

    println!("\n✨ Example completed successfully!");
    Ok(())
}

/// Generate realistic biometric-like features with some structure
fn generate_realistic_features() -> Result<Vec<f32>> {
    let mut rng = SecureRng::new()?;
    let mut features = Vec::with_capacity(FEATURE_VECTOR_SIZE);
    
    // Generate features with some realistic patterns
    for i in 0..FEATURE_VECTOR_SIZE {
        let base_value = (i as f32).sin() * 0.5; // Base pattern
        let noise = ((rng.next_u32() as f32) / (u32::MAX as f32) - 0.5) * 0.2; // Random noise
        let structured_component = if i % 64 < 32 { 0.3 } else { -0.3 }; // Block structure
        
        features.push(base_value + noise + structured_component);
    }
    
    Ok(features)
}

/// Demonstrate biometric template matching with similar but not identical features
fn demonstrate_template_matching(enrolled_template: &[f32; FEATURE_VECTOR_SIZE]) -> Result<()> {
    let mut rng = SecureRng::new()?;
    
    // Create a "live" capture with small variations (simulating real biometric capture)
    let mut live_features = *enrolled_template;
    let mut changes = 0;
    
    for feature in &mut live_features {
        // Add small noise to simulate natural variation
        let noise = ((rng.next_u32() as f32) / (u32::MAX as f32) - 0.5) * 0.05;
        *feature += noise;
        changes += 1;
    }
    
    // Hash both templates
    let enrolled_hash = poseidon_hash(enrolled_template)?;
    let live_hash = poseidon_hash(&live_features)?;
    
    // Create commitments
    let generators = Generators::new()?;
    let enrolled_opening = CommitmentOpening::new_with_random_salt(enrolled_hash)?;
    let live_opening = CommitmentOpening::new_with_random_salt(live_hash)?;
    
    let enrolled_commitment = commit_with_opening(&enrolled_opening, &generators);
    let live_commitment = commit_with_opening(&live_opening, &generators);
    
    println!("   Enrolled template hash: {}", hex::encode(&enrolled_hash.to_bytes_le()));
    println!("   Live capture hash:      {}", hex::encode(&live_hash.to_bytes_le()));
    println!("   Template commitments:   {}", 
             if enrolled_commitment == live_commitment { "IDENTICAL" } else { "DIFFERENT" });
    println!("   Note: Different due to different randomness - this is expected!");
    println!("   In a real system, a zk-SNARK would prove similarity without revealing hashes.");
    
    Ok(())
}

/// Demonstrate key properties of Pedersen commitments
fn demonstrate_commitment_properties(generators: &Generators) -> Result<()> {
    // Property 1: Deterministic with same inputs
    println!("   🔄 Testing determinism...");
    let message = Fr::from(12345u64);
    let randomness = Fr::from(67890u64);
    
    let commitment1 = sable_core::crypto::pedersen::commit(message, randomness, generators);
    let commitment2 = sable_core::crypto::pedersen::commit(message, randomness, generators);
    
    println!("      Same inputs → Same commitment: {}", commitment1 == commitment2);
    
    // Property 2: Different randomness gives different commitments (hiding)
    println!("   🎭 Testing hiding property...");
    let different_randomness = Fr::from(11111u64);
    let commitment3 = sable_core::crypto::pedersen::commit(message, different_randomness, generators);
    
    println!("      Same message, different randomness → Different commitment: {}", 
             commitment1 != commitment3);
    
    // Property 3: Different messages give different commitments (binding)
    println!("   🔒 Testing binding property...");
    let different_message = Fr::from(54321u64);
    let commitment4 = sable_core::crypto::pedersen::commit(different_message, randomness, generators);
    
    println!("      Different message, same randomness → Different commitment: {}", 
             commitment1 != commitment4);
    
    // Property 4: Homomorphic addition
    println!("   ➕ Testing homomorphic properties...");
    let msg1 = Fr::from(100u64);
    let rand1 = Fr::from(200u64);
    let commit_a = sable_core::crypto::pedersen::commit(msg1, rand1, generators);
    
    let msg2 = Fr::from(300u64);
    let rand2 = Fr::from(400u64);
    let commit_b = sable_core::crypto::pedersen::commit(msg2, rand2, generators);
    
    let sum_commitment = commit_a.add(&commit_b);
    let expected_commitment = sable_core::crypto::pedersen::commit(msg1 + msg2, rand1 + rand2, generators);
    
    println!("      C₁ + C₂ = C(m₁+m₂, r₁+r₂): {}", sum_commitment == expected_commitment);
    
    Ok(())
}

/// Utility function to format bytes as hex
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>()
}

mod hex {
    pub fn encode(data: &[u8]) -> String {
        data.iter()
            .map(|byte| format!("{:02x}", byte))
            .collect()
    }
}
