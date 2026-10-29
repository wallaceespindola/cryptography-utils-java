package com.wallaceespindola.crypto;

/** Unchecked wrapper for failures from the JCA, such as a failed authentication tag. */
public final class CryptoException extends RuntimeException {

    public CryptoException(String message, Throwable cause) {
        super(message, cause);
    }
}
