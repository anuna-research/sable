// SABLE Android JNI Implementation
//
// C++ JNI bindings connecting Java to Rust SABLE core library

#include <jni.h>
#include <string>
#include <vector>
#include <memory>
#include <android/log.h>

// Include SABLE C FFI header
extern "C" {
    #include "sable_ffi.h"
}

#define LOG_TAG "SableJNI"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// Helper to create Java SableResult object
jobject createSableResult(JNIEnv* env, int errorCode, const uint8_t* data, int dataLen) {
    jclass resultClass = env->FindClass("com/sable/core/SableCore$SableResult");
    if (!resultClass) return nullptr;
    
    jmethodID constructor = env->GetMethodID(resultClass, "<init>", "(I[B)V");
    if (!constructor) return nullptr;
    
    jbyteArray dataArray = nullptr;
    if (data && dataLen > 0) {
        dataArray = env->NewByteArray(dataLen);
        if (dataArray) {
            env->SetByteArrayRegion(dataArray, 0, dataLen, reinterpret_cast<const jbyte*>(data));
        }
    }
    
    return env->NewObject(resultClass, constructor, errorCode, dataArray);
}

extern "C" {

// Create new SABLE instance
JNIEXPORT jlong JNICALL
Java_com_sable_core_SableCore_nativeNew(JNIEnv* env, jclass clazz) {
    LOGI("Creating new SABLE instance");
    
    SableHandle handle = sable_new();
    if (!handle) {
        LOGE("Failed to create SABLE instance");
        return 0;
    }
    
    return reinterpret_cast<jlong>(handle);
}

// Free SABLE instance  
JNIEXPORT void JNICALL
Java_com_sable_core_SableCore_nativeFree(JNIEnv* env, jclass clazz, jlong handle) {
    LOGI("Freeing SABLE instance");
    
    if (handle != 0) {
        sable_free(reinterpret_cast<SableHandle>(handle));
    }
}

// Generate commitment
JNIEXPORT jobject JNICALL
Java_com_sable_core_SableCore_nativeGenerateCommitment(JNIEnv* env, jclass clazz,
                                                       jlong handle, jdoubleArray features, jbyteArray salt) {
    LOGI("Generating biometric commitment");
    
    if (handle == 0 || !features || !salt) {
        return createSableResult(env, 1, nullptr, 0); // Invalid input
    }
    
    // Convert Java arrays to C arrays
    jsize featuresLen = env->GetArrayLength(features);
    jdouble* featuresPtr = env->GetDoubleArrayElements(features, nullptr);
    
    jsize saltLen = env->GetArrayLength(salt);
    if (saltLen != 32) {
        env->ReleaseDoubleArrayElements(features, featuresPtr, JNI_ABORT);
        return createSableResult(env, 1, nullptr, 0); // Invalid salt length
    }
    
    jbyte* saltPtr = env->GetByteArrayElements(salt, nullptr);
    
    // Call SABLE FFI function
    SableResult result = sable_generate_commitment(
        reinterpret_cast<SableHandle>(handle),
        featuresPtr,
        featuresLen,
        reinterpret_cast<const uint8_t*>(saltPtr)
    );
    
    // Create Java result object
    jobject javaResult = createSableResult(env, static_cast<int>(result.error_code), 
                                          result.data, result.data_len);
    
    // Free native result
    sable_free_result(&result);
    
    // Release Java arrays
    env->ReleaseDoubleArrayElements(features, featuresPtr, JNI_ABORT);
    env->ReleaseByteArrayElements(salt, saltPtr, JNI_ABORT);
    
    return javaResult;
}

// Generate proof
JNIEXPORT jobject JNICALL
Java_com_sable_core_SableCore_nativeGenerateProof(JNIEnv* env, jclass clazz,
                                                  jlong handle, jdoubleArray features, jbyteArray salt,
                                                  jbyteArray commitment, jdouble threshold, jlong currentTime) {
    LOGI("Generating zero-knowledge proof");
    
    if (handle == 0 || !features || !salt || !commitment) {
        return createSableResult(env, 1, nullptr, 0); // Invalid input
    }
    
    // Convert Java arrays
    jsize featuresLen = env->GetArrayLength(features);
    jdouble* featuresPtr = env->GetDoubleArrayElements(features, nullptr);
    
    jsize saltLen = env->GetArrayLength(salt);
    if (saltLen != 32) {
        env->ReleaseDoubleArrayElements(features, featuresPtr, JNI_ABORT);
        return createSableResult(env, 1, nullptr, 0);
    }
    jbyte* saltPtr = env->GetByteArrayElements(salt, nullptr);
    
    jsize commitmentLen = env->GetArrayLength(commitment);
    if (commitmentLen != 48) {
        env->ReleaseDoubleArrayElements(features, featuresPtr, JNI_ABORT);
        env->ReleaseByteArrayElements(salt, saltPtr, JNI_ABORT);
        return createSableResult(env, 1, nullptr, 0);
    }
    jbyte* commitmentPtr = env->GetByteArrayElements(commitment, nullptr);
    
    // Call SABLE FFI function
    SableResult result = sable_generate_proof(
        reinterpret_cast<SableHandle>(handle),
        featuresPtr,
        featuresLen,
        reinterpret_cast<const uint8_t*>(saltPtr),
        reinterpret_cast<const uint8_t*>(commitmentPtr),
        threshold,
        static_cast<uint64_t>(currentTime)
    );
    
    // Create Java result
    jobject javaResult = createSableResult(env, static_cast<int>(result.error_code),
                                          result.data, result.data_len);
    
    // Cleanup
    sable_free_result(&result);
    env->ReleaseDoubleArrayElements(features, featuresPtr, JNI_ABORT);
    env->ReleaseByteArrayElements(salt, saltPtr, JNI_ABORT);
    env->ReleaseByteArrayElements(commitment, commitmentPtr, JNI_ABORT);
    
    return javaResult;
}

// Verify proof
JNIEXPORT jint JNICALL
Java_com_sable_core_SableCore_nativeVerifyProof(JNIEnv* env, jclass clazz,
                                                jlong handle, jbyteArray proof, jbyteArray commitment,
                                                jdouble threshold, jlong currentTime) {
    LOGI("Verifying zero-knowledge proof");
    
    if (handle == 0 || !proof || !commitment) {
        return -1; // Error
    }
    
    // Convert Java arrays
    jsize proofLen = env->GetArrayLength(proof);
    jbyte* proofPtr = env->GetByteArrayElements(proof, nullptr);
    
    jsize commitmentLen = env->GetArrayLength(commitment);
    if (commitmentLen != 48) {
        env->ReleaseByteArrayElements(proof, proofPtr, JNI_ABORT);
        return -1;
    }
    jbyte* commitmentPtr = env->GetByteArrayElements(commitment, nullptr);
    
    // Call SABLE FFI function
    int result = sable_verify_proof(
        reinterpret_cast<SableHandle>(handle),
        reinterpret_cast<const uint8_t*>(proofPtr),
        proofLen,
        reinterpret_cast<const uint8_t*>(commitmentPtr),
        threshold,
        static_cast<uint64_t>(currentTime)
    );
    
    // Cleanup
    env->ReleaseByteArrayElements(proof, proofPtr, JNI_ABORT);
    env->ReleaseByteArrayElements(commitment, commitmentPtr, JNI_ABORT);
    
    return result;
}

// Generate salt
JNIEXPORT jint JNICALL
Java_com_sable_core_SableCore_nativeGenerateSalt(JNIEnv* env, jclass clazz, jbyteArray saltOut) {
    if (!saltOut || env->GetArrayLength(saltOut) != 32) {
        return -1;
    }
    
    jbyte* saltPtr = env->GetByteArrayElements(saltOut, nullptr);
    int result = sable_generate_salt(reinterpret_cast<uint8_t*>(saltPtr));
    env->ReleaseByteArrayElements(saltOut, saltPtr, 0);
    
    return result;
}

// Get version
JNIEXPORT jstring JNICALL
Java_com_sable_core_SableCore_getVersion(JNIEnv* env, jclass clazz) {
    return env->NewStringUTF("SABLE 0.1.0");
}

// Check hardware keystore availability
JNIEXPORT jboolean JNICALL
Java_com_sable_core_SableCore_isHardwareKeystoreAvailable(JNIEnv* env, jclass clazz, jobject context) {
    // TODO: Implement Android keystore hardware detection
    // For now, assume hardware keystore is available on Android 8.0+
    return JNI_TRUE;
}

} // extern "C"
