// SABLE Energy Consumption Profiling (REQ-023)
//
// Provides energy consumption profiling for verification operations on mobile devices.
// Target: Consume < 0.03% battery per verification on reference devices.
//
// This module implements power profiling benchmarks to ensure SABLE verification
// operations remain within acceptable energy budgets for mobile deployment.

use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

/// Maximum allowed battery consumption per verification (0.03%)
pub const MAX_BATTERY_PERCENT_PER_VERIFICATION: f64 = 0.03;

/// Energy consumption estimate for a verification operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnergyProfile {
    /// Total CPU time spent on verification
    pub cpu_time: Duration,
    /// Estimated milliamp-hours consumed
    pub estimated_mah: f64,
    /// Estimated battery percentage consumed
    pub estimated_battery_percent: f64,
    /// Breakdown by verification phase
    pub phase_breakdown: Vec<PhaseEnergy>,
}

impl EnergyProfile {
    /// Check if this profile is within the 0.03% battery budget
    pub fn is_within_budget(&self) -> bool {
        self.estimated_battery_percent <= MAX_BATTERY_PERCENT_PER_VERIFICATION
    }

    /// Get the most energy-intensive phase
    pub fn most_intensive_phase(&self) -> Option<&PhaseEnergy> {
        self.phase_breakdown.iter().max_by(|a, b| {
            a.estimated_energy_mwh()
                .partial_cmp(&b.estimated_energy_mwh())
                .unwrap()
        })
    }

    /// Total duration of all phases
    pub fn total_duration(&self) -> Duration {
        self.phase_breakdown.iter().map(|p| p.duration).sum()
    }
}

/// Energy consumption for a single verification phase
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhaseEnergy {
    /// The verification phase
    pub phase: VerificationPhase,
    /// Duration of this phase
    pub duration: Duration,
    /// Estimated power draw in milliwatts
    pub estimated_power_mw: f64,
}

impl PhaseEnergy {
    /// Create a new phase energy measurement
    pub fn new(phase: VerificationPhase, duration: Duration, power_mw: f64) -> Self {
        Self {
            phase,
            duration,
            estimated_power_mw: power_mw,
        }
    }

    /// Calculate energy consumed in milliwatt-hours
    pub fn estimated_energy_mwh(&self) -> f64 {
        let hours = self.duration.as_secs_f64() / 3600.0;
        self.estimated_power_mw * hours
    }

    /// Calculate energy consumed in milliamp-hours (assuming 3.7V nominal)
    pub fn estimated_mah(&self) -> f64 {
        self.estimated_energy_mwh() / reference_devices::NOMINAL_BATTERY_VOLTAGE
    }
}

/// Phases of the SABLE verification process
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationPhase {
    /// Biometric feature extraction from sensor data
    FeatureExtraction,
    /// Poseidon hash computation
    PoseidonHash,
    /// Zero-knowledge proof generation
    ProofGeneration,
    /// P2P communication for distributed verification
    P2pCommunication,
    /// Proof verification
    ProofVerification,
}

impl VerificationPhase {
    /// Get typical power multiplier for this phase (1.0 = baseline CPU)
    /// Different phases have different power characteristics
    pub fn power_multiplier(&self) -> f64 {
        match self {
            VerificationPhase::FeatureExtraction => 0.8, // Moderate CPU, some memory
            VerificationPhase::PoseidonHash => 1.0,      // CPU-intensive
            VerificationPhase::ProofGeneration => 1.2,   // Most intensive (crypto ops)
            VerificationPhase::P2pCommunication => 0.3,  // Low CPU, radio active
            VerificationPhase::ProofVerification => 0.9, // CPU-intensive but lighter than generation
        }
    }

    /// Get display name for this phase
    pub fn name(&self) -> &'static str {
        match self {
            VerificationPhase::FeatureExtraction => "Feature Extraction",
            VerificationPhase::PoseidonHash => "Poseidon Hash",
            VerificationPhase::ProofGeneration => "Proof Generation",
            VerificationPhase::P2pCommunication => "P2P Communication",
            VerificationPhase::ProofVerification => "Proof Verification",
        }
    }
}

/// Energy profiler for verification operations
#[derive(Debug, Clone)]
pub struct EnergyProfiler {
    /// Reference battery capacity in mAh (e.g., 4000-5000 mAh)
    reference_battery_mah: f64,
    /// CPU power draw in mW at full load
    cpu_power_mw: f64,
    /// Device identifier for this profiler configuration
    device_name: String,
}

impl EnergyProfiler {
    /// Create a new energy profiler with device-specific parameters
    pub fn new(device_name: &str, battery_mah: f64, cpu_power_mw: f64) -> Self {
        Self {
            reference_battery_mah: battery_mah,
            cpu_power_mw,
            device_name: device_name.to_string(),
        }
    }

    /// Create profiler for Snapdragon 8 Gen2 reference device
    pub fn snapdragon_8_gen2() -> Self {
        Self::new(
            "Snapdragon 8 Gen2",
            reference_devices::TYPICAL_BATTERY_MAH,
            reference_devices::SNAPDRAGON_8_GEN2_POWER_MW,
        )
    }

    /// Create profiler for Apple A16 reference device
    pub fn apple_a16() -> Self {
        Self::new(
            "Apple A16",
            reference_devices::TYPICAL_BATTERY_MAH,
            reference_devices::APPLE_A16_POWER_MW,
        )
    }

    /// Create profiler for MediaTek Dimensity 9200 reference device
    pub fn mediatek_dimensity_9200() -> Self {
        Self::new(
            "MediaTek Dimensity 9200",
            reference_devices::TYPICAL_BATTERY_MAH,
            reference_devices::MEDIATEK_DIMENSITY_9200_POWER_MW,
        )
    }

    /// Get the device name for this profiler
    pub fn device_name(&self) -> &str {
        &self.device_name
    }

    /// Profile a verification phase operation
    ///
    /// Executes the provided function and measures its duration,
    /// returning both the result and energy profile for the phase.
    pub fn profile<F, T>(&self, phase: VerificationPhase, f: F) -> (T, PhaseEnergy)
    where
        F: FnOnce() -> T,
    {
        let start = Instant::now();
        let result = f();
        let duration = start.elapsed();

        // Calculate power draw based on phase characteristics
        let power_mw = self.cpu_power_mw * phase.power_multiplier();

        let phase_energy = PhaseEnergy::new(phase, duration, power_mw);

        (result, phase_energy)
    }

    /// Profile a verification phase that may fail
    pub fn profile_result<F, T, E>(
        &self,
        phase: VerificationPhase,
        f: F,
    ) -> (Result<T, E>, PhaseEnergy)
    where
        F: FnOnce() -> Result<T, E>,
    {
        let start = Instant::now();
        let result = f();
        let duration = start.elapsed();

        let power_mw = self.cpu_power_mw * phase.power_multiplier();
        let phase_energy = PhaseEnergy::new(phase, duration, power_mw);

        (result, phase_energy)
    }

    /// Calculate battery percentage from mAh consumption
    pub fn mah_to_percent(&self, mah: f64) -> f64 {
        (mah / self.reference_battery_mah) * 100.0
    }

    /// Calculate mAh from battery percentage
    pub fn percent_to_mah(&self, percent: f64) -> f64 {
        (percent / 100.0) * self.reference_battery_mah
    }

    /// Check if a verification profile is within the 0.03% battery budget
    pub fn is_within_budget(&self, profile: &EnergyProfile) -> bool {
        profile.estimated_battery_percent <= MAX_BATTERY_PERCENT_PER_VERIFICATION
    }

    /// Get the maximum allowed mAh for a single verification on this device
    pub fn max_allowed_mah(&self) -> f64 {
        self.percent_to_mah(MAX_BATTERY_PERCENT_PER_VERIFICATION)
    }

    /// Create a complete verification profile from phase measurements
    pub fn create_full_profile(&self, phases: Vec<PhaseEnergy>) -> EnergyProfile {
        let cpu_time: Duration = phases.iter().map(|p| p.duration).sum();

        // Calculate total mAh from all phases
        let estimated_mah: f64 = phases.iter().map(|p| p.estimated_mah()).sum();

        let estimated_battery_percent = self.mah_to_percent(estimated_mah);

        EnergyProfile {
            cpu_time,
            estimated_mah,
            estimated_battery_percent,
            phase_breakdown: phases,
        }
    }

    /// Estimate energy for a given duration at average power
    pub fn estimate_energy(&self, duration: Duration) -> f64 {
        let hours = duration.as_secs_f64() / 3600.0;
        let energy_mwh = self.cpu_power_mw * hours;
        energy_mwh / reference_devices::NOMINAL_BATTERY_VOLTAGE
    }
}

impl Default for EnergyProfiler {
    fn default() -> Self {
        Self::snapdragon_8_gen2()
    }
}

/// Reference device configurations for power profiling benchmarks
pub mod reference_devices {
    /// Nominal battery voltage (3.7V for Li-ion)
    pub const NOMINAL_BATTERY_VOLTAGE: f64 = 3.7;

    /// Snapdragon 8 Gen2 peak CPU power draw (mW)
    pub const SNAPDRAGON_8_GEN2_POWER_MW: f64 = 2500.0;

    /// Apple A16 peak CPU power draw (mW)
    pub const APPLE_A16_POWER_MW: f64 = 2200.0;

    /// MediaTek Dimensity 9200 peak CPU power draw (mW)
    pub const MEDIATEK_DIMENSITY_9200_POWER_MW: f64 = 2400.0;

    /// Typical flagship battery capacity (mAh)
    pub const TYPICAL_BATTERY_MAH: f64 = 4500.0;

    /// Small device battery capacity (mAh)
    pub const SMALL_BATTERY_MAH: f64 = 3000.0;

    /// Large device battery capacity (mAh)
    pub const LARGE_BATTERY_MAH: f64 = 5500.0;

    /// Radio (WiFi/5G) power draw during P2P communication (mW)
    pub const RADIO_POWER_MW: f64 = 800.0;
}

/// Power profiling benchmark runner
#[derive(Debug)]
pub struct EnergyBenchmark {
    profiler: EnergyProfiler,
    results: Vec<EnergyProfile>,
}

impl EnergyBenchmark {
    /// Create a new benchmark runner for a device
    pub fn new(profiler: EnergyProfiler) -> Self {
        Self {
            profiler,
            results: Vec::new(),
        }
    }

    /// Run a complete verification benchmark
    pub fn run_verification_benchmark<F>(&mut self, verification_fn: F) -> &EnergyProfile
    where
        F: FnOnce(&EnergyProfiler) -> Vec<PhaseEnergy>,
    {
        let phases = verification_fn(&self.profiler);
        let profile = self.profiler.create_full_profile(phases);
        self.results.push(profile);
        self.results.last().unwrap()
    }

    /// Get all benchmark results
    pub fn results(&self) -> &[EnergyProfile] {
        &self.results
    }

    /// Calculate average energy consumption across all runs
    pub fn average_mah(&self) -> f64 {
        if self.results.is_empty() {
            return 0.0;
        }
        let total: f64 = self.results.iter().map(|p| p.estimated_mah).sum();
        total / self.results.len() as f64
    }

    /// Calculate average battery percentage across all runs
    pub fn average_battery_percent(&self) -> f64 {
        if self.results.is_empty() {
            return 0.0;
        }
        let total: f64 = self
            .results
            .iter()
            .map(|p| p.estimated_battery_percent)
            .sum();
        total / self.results.len() as f64
    }

    /// Check if all runs are within budget
    pub fn all_within_budget(&self) -> bool {
        self.results.iter().all(|p| p.is_within_budget())
    }

    /// Get the worst-case (highest energy) run
    pub fn worst_case(&self) -> Option<&EnergyProfile> {
        self.results
            .iter()
            .max_by(|a, b| a.estimated_mah.partial_cmp(&b.estimated_mah).unwrap())
    }

    /// Generate a benchmark report
    pub fn generate_report(&self) -> BenchmarkReport {
        BenchmarkReport {
            device_name: self.profiler.device_name().to_string(),
            num_runs: self.results.len(),
            average_mah: self.average_mah(),
            average_battery_percent: self.average_battery_percent(),
            max_battery_percent: self
                .results
                .iter()
                .map(|p| p.estimated_battery_percent)
                .fold(0.0, f64::max),
            all_within_budget: self.all_within_budget(),
            budget_limit_percent: MAX_BATTERY_PERCENT_PER_VERIFICATION,
        }
    }
}

/// Benchmark report summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkReport {
    /// Device used for benchmark
    pub device_name: String,
    /// Number of benchmark runs
    pub num_runs: usize,
    /// Average mAh consumed per verification
    pub average_mah: f64,
    /// Average battery percentage per verification
    pub average_battery_percent: f64,
    /// Maximum battery percentage observed
    pub max_battery_percent: f64,
    /// Whether all runs were within budget
    pub all_within_budget: bool,
    /// The budget limit (0.03%)
    pub budget_limit_percent: f64,
}

impl BenchmarkReport {
    /// Check if this benchmark passes the REQ-023 requirement
    pub fn passes_requirement(&self) -> bool {
        self.all_within_budget && self.max_battery_percent <= MAX_BATTERY_PERCENT_PER_VERIFICATION
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_energy_profiler_creation() {
        let profiler = EnergyProfiler::snapdragon_8_gen2();
        assert_eq!(profiler.device_name(), "Snapdragon 8 Gen2");

        let profiler = EnergyProfiler::apple_a16();
        assert_eq!(profiler.device_name(), "Apple A16");
    }

    #[test]
    fn test_phase_profiling() {
        let profiler = EnergyProfiler::default();

        let (result, phase_energy) = profiler.profile(VerificationPhase::PoseidonHash, || {
            // Simulate some work
            let mut sum = 0u64;
            for i in 0..10000 {
                sum = sum.wrapping_add(i);
            }
            sum
        });

        assert!(result > 0);
        assert_eq!(phase_energy.phase, VerificationPhase::PoseidonHash);
        assert!(phase_energy.duration.as_nanos() > 0);
    }

    #[test]
    fn test_energy_calculation() {
        let phase = PhaseEnergy::new(
            VerificationPhase::ProofGeneration,
            Duration::from_millis(100),
            2500.0,
        );

        // 100ms at 2500mW = 0.0694 mWh
        let energy_mwh = phase.estimated_energy_mwh();
        assert!(energy_mwh > 0.0);
        assert!(energy_mwh < 1.0); // Should be small for 100ms

        // mAh = mWh / 3.7V
        let mah = phase.estimated_mah();
        assert!(mah > 0.0);
    }

    #[test]
    fn test_full_profile_creation() {
        let profiler = EnergyProfiler::snapdragon_8_gen2();

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
                Duration::from_millis(50),
                3000.0,
            ),
            PhaseEnergy::new(
                VerificationPhase::ProofVerification,
                Duration::from_millis(20),
                2250.0,
            ),
        ];

        let profile = profiler.create_full_profile(phases);

        assert_eq!(profile.cpu_time, Duration::from_millis(85));
        assert!(profile.estimated_mah > 0.0);
        assert!(profile.estimated_battery_percent > 0.0);
        assert_eq!(profile.phase_breakdown.len(), 4);
    }

    #[test]
    fn test_budget_check() {
        let profiler = EnergyProfiler::new("Test Device", 4500.0, 2500.0);

        // Create a profile that should be within budget
        // 0.03% of 4500mAh = 1.35mAh max
        // At 3.7V, that's about 5mWh
        // At 2500mW, that's about 7.2 seconds max
        let fast_phases = vec![PhaseEnergy::new(
            VerificationPhase::ProofGeneration,
            Duration::from_millis(50),
            2500.0,
        )];
        let fast_profile = profiler.create_full_profile(fast_phases);
        assert!(profiler.is_within_budget(&fast_profile));

        // Create a profile that exceeds budget (unrealistically slow)
        let slow_phases = vec![PhaseEnergy::new(
            VerificationPhase::ProofGeneration,
            Duration::from_secs(60),
            2500.0,
        )];
        let slow_profile = profiler.create_full_profile(slow_phases);
        assert!(!profiler.is_within_budget(&slow_profile));
    }

    #[test]
    fn test_mah_to_percent_conversion() {
        let profiler = EnergyProfiler::new("Test", 4000.0, 2000.0);

        // 40 mAh should be 1% of 4000 mAh battery
        assert!((profiler.mah_to_percent(40.0) - 1.0).abs() < 0.001);

        // 1% of 4000 mAh should be 40 mAh
        assert!((profiler.percent_to_mah(1.0) - 40.0).abs() < 0.001);
    }

    #[test]
    fn test_max_allowed_mah() {
        let profiler = EnergyProfiler::new("Test", 4500.0, 2500.0);

        // 0.03% of 4500 mAh = 1.35 mAh
        let max = profiler.max_allowed_mah();
        assert!((max - 1.35).abs() < 0.001);
    }

    #[test]
    fn test_phase_power_multipliers() {
        assert_eq!(VerificationPhase::FeatureExtraction.power_multiplier(), 0.8);
        assert_eq!(VerificationPhase::PoseidonHash.power_multiplier(), 1.0);
        assert_eq!(VerificationPhase::ProofGeneration.power_multiplier(), 1.2);
        assert_eq!(VerificationPhase::P2pCommunication.power_multiplier(), 0.3);
        assert_eq!(VerificationPhase::ProofVerification.power_multiplier(), 0.9);
    }

    #[test]
    fn test_most_intensive_phase() {
        let profiler = EnergyProfiler::default();

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
                Duration::from_millis(20),
                2250.0,
            ),
        ];

        let profile = profiler.create_full_profile(phases);
        let most_intensive = profile.most_intensive_phase().unwrap();

        assert_eq!(most_intensive.phase, VerificationPhase::ProofGeneration);
    }

    #[test]
    fn test_benchmark_runner() {
        let profiler = EnergyProfiler::snapdragon_8_gen2();
        let mut benchmark = EnergyBenchmark::new(profiler);

        // Run a few benchmarks
        for _ in 0..3 {
            benchmark.run_verification_benchmark(|p| {
                let (_, phase1) = p.profile(VerificationPhase::FeatureExtraction, || {
                    thread::sleep(Duration::from_micros(100));
                });
                let (_, phase2) = p.profile(VerificationPhase::ProofGeneration, || {
                    thread::sleep(Duration::from_micros(200));
                });
                vec![phase1, phase2]
            });
        }

        assert_eq!(benchmark.results().len(), 3);
        assert!(benchmark.average_mah() > 0.0);

        let report = benchmark.generate_report();
        assert_eq!(report.num_runs, 3);
        assert_eq!(report.device_name, "Snapdragon 8 Gen2");
    }

    #[test]
    fn test_benchmark_report() {
        let profiler = EnergyProfiler::default();
        let mut benchmark = EnergyBenchmark::new(profiler);

        benchmark.run_verification_benchmark(|p| {
            vec![PhaseEnergy::new(
                VerificationPhase::ProofGeneration,
                Duration::from_millis(10),
                2500.0,
            )]
        });

        let report = benchmark.generate_report();
        assert!(report.passes_requirement()); // 10ms should be well within budget
    }

    #[test]
    fn test_reference_device_constants() {
        assert!(reference_devices::SNAPDRAGON_8_GEN2_POWER_MW > 0.0);
        assert!(reference_devices::APPLE_A16_POWER_MW > 0.0);
        assert!(reference_devices::TYPICAL_BATTERY_MAH > 0.0);
        assert_eq!(reference_devices::NOMINAL_BATTERY_VOLTAGE, 3.7);
    }

    #[test]
    fn test_verification_phase_names() {
        assert_eq!(
            VerificationPhase::FeatureExtraction.name(),
            "Feature Extraction"
        );
        assert_eq!(VerificationPhase::PoseidonHash.name(), "Poseidon Hash");
        assert_eq!(
            VerificationPhase::ProofGeneration.name(),
            "Proof Generation"
        );
        assert_eq!(
            VerificationPhase::P2pCommunication.name(),
            "P2P Communication"
        );
        assert_eq!(
            VerificationPhase::ProofVerification.name(),
            "Proof Verification"
        );
    }
}
