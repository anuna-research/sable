// SABLE C Implementation for iOS
//
// This file will link to the Rust SABLE core library compiled as a static library

#error "SABLE mobile packages are withdrawn (SBL-RT-004/008)."

#include "sable_c.h"
#include <stdlib.h>
#include <string.h>

// These symbols will be provided by the linked Rust static library
// When building, we need to link against libsable_core.a

// For now, provide stub implementations that will be replaced during build
// The actual implementations are in core/src/mobile/ffi.rs

__attribute__((weak))
SableHandle sable_new(void) {
    // This will be replaced by the Rust implementation
    return NULL;
}

__attribute__((weak))
void sable_free(SableHandle handle) {
    // This will be replaced by the Rust implementation
}

__attribute__((weak))
SableResult sable_generate_commitment(
    SableHandle handle,
    const double* features,
    int32_t features_len,
    const uint8_t* salt
) {
    // This will be replaced by the Rust implementation
    SableResult result = {SABLE_UNKNOWN_ERROR, NULL, 0};
    return result;
}

__attribute__((weak))
SableResult sable_generate_proof(
    SableHandle handle,
    const double* features,
    int32_t features_len,
    const uint8_t* salt,
    const uint8_t* commitment,
    double threshold,
    uint64_t current_time
) {
    // This will be replaced by the Rust implementation
    SableResult result = {SABLE_UNKNOWN_ERROR, NULL, 0};
    return result;
}

__attribute__((weak))
int32_t sable_verify_proof(
    SableHandle handle,
    const uint8_t* proof,
    int32_t proof_len,
    const uint8_t* commitment,
    double threshold,
    uint64_t current_time
) {
    // This will be replaced by the Rust implementation
    return -1;
}

__attribute__((weak))
int32_t sable_generate_salt(uint8_t* salt_out) {
    // This will be replaced by the Rust implementation
    return -1;
}

__attribute__((weak))
void sable_free_result(SableResult* result) {
    // This will be replaced by the Rust implementation
    if (result && result->data) {
        free(result->data);
        result->data = NULL;
        result->data_len = 0;
    }
}

__attribute__((weak))
const char* sable_get_version(void) {
    return "SABLE 0.1.0 (iOS)";
}

__attribute__((weak))
const char* sable_error_message(SableErrorCode error_code) {
    switch (error_code) {
        case SABLE_SUCCESS:
            return "Success";
        case SABLE_INVALID_INPUT:
            return "Invalid input parameters";
        case SABLE_CRYPTO_ERROR:
            return "Cryptographic operation failed";
        case SABLE_SERIALIZATION_ERROR:
            return "Serialization error";
        case SABLE_OUT_OF_MEMORY:
            return "Out of memory";
        default:
            return "Unknown error";
    }
}

__attribute__((weak))
void sable_free_error_message(char* message) {
    // Static strings don't need to be freed
    // This will be replaced by the Rust implementation for dynamic strings
}
