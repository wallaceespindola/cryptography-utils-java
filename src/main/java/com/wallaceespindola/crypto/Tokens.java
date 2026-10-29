package com.wallaceespindola.crypto;

import java.security.SecureRandom;

/** Random tokens from {@link SecureRandom}, encoded as URL-safe Base64 without padding. */
public final class Tokens {

    private static final int DEFAULT_BYTES = 32;
    private static final SecureRandom RANDOM = new SecureRandom();

    private Tokens() {
    }

    /** 256 bits of randomness, 43 characters. */
    public static String random() {
        return random(DEFAULT_BYTES);
    }

    public static String random(int bytes) {
        if (bytes < 1) {
            throw new IllegalArgumentException("bytes must be positive");
        }
        byte[] raw = new byte[bytes];
        RANDOM.nextBytes(raw);
        return Codec.base64Url(raw);
    }
}
