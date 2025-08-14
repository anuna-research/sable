// SABLE C Interface for iOS
//
// C-compatible interface for iOS Swift integration

#ifndef SABLE_C_H
#define SABLE_C_H

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
    int32_t data_len;
} SableResult;

// Core SABLE functions
SableHandle sable_new(void);
void sable_free(SableHandle handle);

SableResult sable_generate_commitment(
    SableHandle handle,
    const double* features,
    int32_t features_len,
    const uint8_t* salt
);

SableResult sable_generate_proof(
    SableHandle handle,
    const double* features,
    int32_t features_len,
    const uint8_t* salt,
    const uint8_t* commitment,
    double threshold,
    uint64_t current_time
);

int32_t sable_verify_proof(
    SableHandle handle,
    const uint8_t* proof,
    int32_t proof_len,
    const uint8_t* commitment,
    double threshold,
    uint64_t current_time
);

int32_t sable_generate_salt(uint8_t* salt_out);

void sable_free_result(SableResult* result);

const char* sable_get_version(void);
const char* sable_error_message(SableErrorCode error_code);
void sable_free_error_message(char* message);

#ifdef __cplusplus
}
#endif

#endif // SABLE_C_H
