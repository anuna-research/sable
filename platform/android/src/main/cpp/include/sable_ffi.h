// SABLE C FFI Header
// 
// C-compatible interface for SABLE mobile integration

#ifndef SABLE_FFI_H
#define SABLE_FFI_H

#error "SABLE mobile FFI is withdrawn (SBL-RT-004/008)."

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Opaque handle type
typedef void* SableHandle;

// Error codes
typedef enum {
    SABLE_SUCCESS = 0,
    SABLE_INVALID_INPUT = 1,
    SABLE_CRYPTO_ERROR = 2,
    SABLE_SERIALIZATION_ERROR = 3,
    SABLE_OUT_OF_MEMORY = 4,
    SABLE_UNKNOWN_ERROR = 99
} SableErrorCode;

// Result structure
typedef struct {
    SableErrorCode error_code;
    uint8_t* data;
    int data_len;
} SableResult;

// Core SABLE functions
SableHandle sable_new(void);
void sable_free(SableHandle handle);

SableResult sable_generate_commitment(
    SableHandle handle,
    const double* features,
    int features_len,
    const uint8_t* salt
);

SableResult sable_generate_proof(
    SableHandle handle,
    const double* features,
    int features_len,
    const uint8_t* salt,
    const uint8_t* commitment,
    double threshold,
    uint64_t current_time
);

int sable_verify_proof(
    SableHandle handle,
    const uint8_t* proof,
    int proof_len,
    const uint8_t* commitment,
    double threshold,
    uint64_t current_time
);

int sable_generate_salt(uint8_t* salt_out);

void sable_free_result(SableResult* result);

const char* sable_error_message(SableErrorCode error_code);
void sable_free_error_message(char* message);

#ifdef __cplusplus
}
#endif

#endif // SABLE_FFI_H
