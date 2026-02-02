# SABLE Fuzzing Suite (REQ-024)

This directory contains cargo-fuzz targets for comprehensive fuzzing of SABLE's public APIs.

## Requirements

- Rust nightly toolchain (for cargo-fuzz)
- cargo-fuzz installed: `cargo install cargo-fuzz`

## Fuzz Targets

| Target | Description | Coverage |
|--------|-------------|----------|
| `fuzz_poseidon_hash` | Poseidon hash function | Edge cases, boundary values, invalid inputs |
| `fuzz_pedersen_commit` | Pedersen commitments | Creation, serialization, homomorphism, batch ops |
| `fuzz_feature_extraction` | Biometric feature extraction | Image validation, quality metrics, dimensions |
| `fuzz_feature_normalization` | Z-score normalization | Edge cases, constant vectors, extreme values |
| `fuzz_fusion` | Multi-modal biometric fusion | Weight validation, score computation, decision fusion |
| `fuzz_ffi_api` | API-level operations | Commitment workflow, serialization, edge cases |

## Running Fuzz Tests

```bash
# Run a specific fuzz target
cargo +nightly fuzz run fuzz_poseidon_hash

# Run with time limit (10 minutes)
cargo +nightly fuzz run fuzz_poseidon_hash -- -max_total_time=600

# Run all fuzz targets sequentially
for target in fuzz_poseidon_hash fuzz_pedersen_commit fuzz_feature_extraction \
              fuzz_feature_normalization fuzz_fusion fuzz_ffi_api; do
    cargo +nightly fuzz run $target -- -max_total_time=60
done
```

## Coverage Goals

Each fuzz target aims for 100% edge case coverage for input validation:

- **Input boundary conditions**: Minimum/maximum values, empty inputs
- **Numeric edge cases**: Zero, NaN, Infinity, subnormal numbers
- **Serialization**: Invalid bytes, round-trip stability
- **API invariants**: Determinism, homomorphic properties

## Corpus

Fuzzing corpus is stored in `corpus/<target_name>/`. Initial seed inputs can be added manually or will be generated during fuzzing.

## Crash Reproduction

Crashes are saved in `artifacts/<target_name>/`. To reproduce:

```bash
cargo +nightly fuzz run <target> artifacts/<target>/<crash_file>
```
