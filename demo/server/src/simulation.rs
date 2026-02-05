use sable_core::FEATURE_VECTOR_SIZE;

/// Simulates biometric feature extraction from a palm scan.
/// In production, this would come from actual biometric sensors.
pub fn generate_simulated_features(seed: u64) -> [f32; FEATURE_VECTOR_SIZE] {
    let mut features = [0.0f32; FEATURE_VECTOR_SIZE];

    // Use a simple deterministic pseudo-random generator seeded by the input
    // This simulates consistent biometric features for a given "user"
    let mut state = seed;

    for i in 0..FEATURE_VECTOR_SIZE {
        // LCG parameters (same as glibc)
        state = state.wrapping_mul(1103515245).wrapping_add(12345);

        // Convert to float in range [-2.0, 2.0] (typical normalized biometric range)
        let normalized = ((state >> 16) & 0x7FFF) as f32 / 32767.0;
        features[i] = (normalized - 0.5) * 4.0;
    }

    features
}

/// Simulates a "live" biometric scan that's similar but not identical to enrolled features.
/// Adds realistic noise to simulate sensor variance.
pub fn generate_similar_features(base_features: &[f32; FEATURE_VECTOR_SIZE], noise_level: f32) -> [f32; FEATURE_VECTOR_SIZE] {
    let mut features = *base_features;

    // Use current time as noise seed for variability
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;

    let mut state = seed;

    for feature in features.iter_mut() {
        state = state.wrapping_mul(1103515245).wrapping_add(12345);
        let noise = ((state >> 16) & 0x7FFF) as f32 / 32767.0 - 0.5;
        *feature += noise * noise_level;
    }

    features
}

/// Generates completely different features (for a different "user")
#[allow(dead_code)]
pub fn generate_different_features(original_seed: u64) -> [f32; FEATURE_VECTOR_SIZE] {
    // Use a completely different seed
    generate_simulated_features(original_seed.wrapping_add(0xDEADBEEF12345678))
}

/// Calculate Euclidean distance between two feature vectors
pub fn calculate_distance(a: &[f32; FEATURE_VECTOR_SIZE], b: &[f32; FEATURE_VECTOR_SIZE]) -> f32 {
    let sum_sq: f32 = a.iter()
        .zip(b.iter())
        .map(|(x, y)| (x - y).powi(2))
        .sum();

    (sum_sq / FEATURE_VECTOR_SIZE as f32).sqrt()
}

/// Quality score simulation (0.0 to 1.0)
pub fn calculate_quality_score(features: &[f32; FEATURE_VECTOR_SIZE]) -> f32 {
    // Simulate quality based on variance - real systems would analyze image clarity, etc.
    let mean: f32 = features.iter().sum::<f32>() / FEATURE_VECTOR_SIZE as f32;
    let variance: f32 = features.iter()
        .map(|x| (x - mean).powi(2))
        .sum::<f32>() / FEATURE_VECTOR_SIZE as f32;

    // Higher variance = more distinctive features = higher quality
    // Clamp to [0.7, 1.0] for demo purposes
    (0.7 + variance.sqrt() * 0.1).min(1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_feature_generation_deterministic() {
        let features1 = generate_simulated_features(12345);
        let features2 = generate_simulated_features(12345);
        assert_eq!(features1, features2);
    }

    #[test]
    fn test_similar_features_close() {
        let base = generate_simulated_features(12345);
        let similar = generate_similar_features(&base, 0.1);
        let distance = calculate_distance(&base, &similar);
        // Should be close (< 0.2 for 0.1 noise level)
        assert!(distance < 0.25, "Distance was {}", distance);
    }

    #[test]
    fn test_different_features_far() {
        let original = generate_simulated_features(12345);
        let different = generate_different_features(12345);
        let distance = calculate_distance(&original, &different);
        // Should be significantly different
        assert!(distance > 0.5, "Distance was {}", distance);
    }
}
