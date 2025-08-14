// SABLE Exception class for Android

package com.sable.core;

/**
 * Exception thrown by SABLE operations
 */
public class SableException extends Exception {
    
    public SableException(String message) {
        super(message);
    }
    
    public SableException(String message, Throwable cause) {
        super(message, cause);
    }
    
    public SableException(Throwable cause) {
        super(cause);
    }
}
