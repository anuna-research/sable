// SABLE Android JNI Interface
//
// Java bindings for SABLE biometric authentication library

package com.sable.core;

import android.content.Context;
import android.util.Log;
import java.util.Arrays;

/**
 * SABLE Core - Privacy-preserving biometric authentication library
 */
public class SableCore {
    private static final String TAG = "SableCore";
    
    // Load native library
    static {
        try {
            System.loadLibrary("sable_android");
            Log.i(TAG, "SABLE native library loaded successfully");
        } catch (UnsatisfiedLinkError e) {
            Log.e(TAG, "Failed to load SABLE native library", e);
            throw new RuntimeException("Cannot load SABLE native library", e);
        }
    }
    
    // Native handle for SABLE instance
    private long nativeHandle = 0;
    
    /**
     * Create new SABLE instance
     */
    public SableCore() throws SableException {
        this.nativeHandle = nativeNew();
        if (this.nativeHandle == 0) {
            throw new SableException("Failed to create SABLE instance");
        }
    }
    
    /**
     * Generate biometric commitment from features
     * 
     * @param features Array of biometric features (normalized 0-1)
     * @param salt 32-byte salt for commitment
     * @return 48-byte commitment data
     */
    public byte[] generateCommitment(double[] features, byte[] salt) throws SableException {
        if (nativeHandle == 0) {
            throw new SableException("SABLE instance not initialized");
        }
        if (salt.length != 32) {
            throw new SableException("Salt must be 32 bytes");
        }
        
        SableResult result = nativeGenerateCommitment(nativeHandle, features, salt);
        if (result.errorCode != 0) {
            throw new SableException("Failed to generate commitment: " + getErrorMessage(result.errorCode));
        }
        
        return result.data;
    }
    
    /**
     * Generate zero-knowledge proof for biometric verification
     * 
     * @param features Array of biometric features
     * @param salt 32-byte salt used in commitment  
     * @param commitment 48-byte commitment data
     * @param threshold Distance threshold for matching
     * @param currentTime Current timestamp in seconds
     * @return Proof data bytes
     */
    public byte[] generateProof(double[] features, byte[] salt, byte[] commitment, 
                               double threshold, long currentTime) throws SableException {
        if (nativeHandle == 0) {
            throw new SableException("SABLE instance not initialized");
        }
        if (salt.length != 32) {
            throw new SableException("Salt must be 32 bytes");
        }
        if (commitment.length != 48) {
            throw new SableException("Commitment must be 48 bytes");
        }
        
        SableResult result = nativeGenerateProof(nativeHandle, features, salt, 
                                                commitment, threshold, currentTime);
        if (result.errorCode != 0) {
            throw new SableException("Failed to generate proof: " + getErrorMessage(result.errorCode));
        }
        
        return result.data;
    }
    
    /**
     * Verify zero-knowledge proof
     * 
     * @param proof Proof data bytes
     * @param commitment 48-byte commitment data
     * @param threshold Distance threshold for matching
     * @param currentTime Current timestamp in seconds
     * @return true if proof is valid, false otherwise
     */
    public boolean verifyProof(byte[] proof, byte[] commitment, 
                              double threshold, long currentTime) throws SableException {
        if (nativeHandle == 0) {
            throw new SableException("SABLE instance not initialized");
        }
        if (commitment.length != 48) {
            throw new SableException("Commitment must be 48 bytes");
        }
        
        int result = nativeVerifyProof(nativeHandle, proof, commitment, threshold, currentTime);
        if (result == -1) {
            throw new SableException("Error during proof verification");
        }
        
        return result == 1;
    }
    
    /**
     * Generate random 32-byte salt
     * 
     * @return Random salt bytes
     */
    public static byte[] generateSalt() throws SableException {
        byte[] salt = new byte[32];
        int result = nativeGenerateSalt(salt);
        if (result != 0) {
            throw new SableException("Failed to generate salt");
        }
        return salt;
    }
    
    /**
     * Get library version information
     * 
     * @return Version string
     */
    public static native String getVersion();
    
    /**
     * Check if hardware keystore is available
     * 
     * @param context Android context
     * @return true if hardware keystore is supported
     */
    public static native boolean isHardwareKeystoreAvailable(Context context);
    
    /**
     * Close SABLE instance and free resources
     */
    public void close() {
        if (nativeHandle != 0) {
            nativeFree(nativeHandle);
            nativeHandle = 0;
        }
    }
    
    @Override
    protected void finalize() throws Throwable {
        close();
        super.finalize();
    }
    
    // Native method declarations
    private static native long nativeNew();
    private static native void nativeFree(long handle);
    private static native SableResult nativeGenerateCommitment(long handle, double[] features, byte[] salt);
    private static native SableResult nativeGenerateProof(long handle, double[] features, byte[] salt, 
                                                          byte[] commitment, double threshold, long currentTime);
    private static native int nativeVerifyProof(long handle, byte[] proof, byte[] commitment, 
                                               double threshold, long currentTime);
    private static native int nativeGenerateSalt(byte[] saltOut);
    
    /**
     * Get error message for error code
     */
    private String getErrorMessage(int errorCode) {
        switch (errorCode) {
            case 1: return "Invalid input parameters";
            case 2: return "Cryptographic operation failed";
            case 3: return "Serialization error";
            case 4: return "Out of memory";
            default: return "Unknown error (" + errorCode + ")";
        }
    }
    
    /**
     * Result structure for native calls
     */
    private static class SableResult {
        public int errorCode;
        public byte[] data;
        
        public SableResult(int errorCode, byte[] data) {
            this.errorCode = errorCode;
            this.data = data;
        }
    }
}
