package com.wallaceespindola.crypto;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * PBKDF2-HMAC-SHA256 password hashing with a random 16-byte salt. The result is a single string,
 * {@code pbkdf2-sha256$iterations$salt$hash}, so the parameters can be raised later and old hashes still verify.
 */
public final class PasswordHasher {

    // OWASP Password Storage Cheat Sheet value for PBKDF2-HMAC-SHA256
    static final int ITERATIONS = 600_000;
    private static final String PREFIX = "pbkdf2-sha256";
    private static final String SEPARATOR = "\\$";
    private static final int SALT_BYTES = 16;
    private static final int HASH_BITS = 256;
    private static final SecureRandom RANDOM = new SecureRandom();

    private PasswordHasher() {
    }

    public static String hash(char[] password) {
        byte[] salt = new byte[SALT_BYTES];
        RANDOM.nextBytes(salt);
        byte[] hash = derive(password, salt, ITERATIONS, HASH_BITS);
        Base64.Encoder b64 = Base64.getEncoder().withoutPadding();
        return String.join("$", PREFIX, String.valueOf(ITERATIONS), b64.encodeToString(salt),
                b64.encodeToString(hash));
    }

    /** Returns false for a wrong password and for a malformed stored value. Compares in constant time. */
    public static boolean verify(char[] password, String stored) {
        try {
            String[] parts = stored.split(SEPARATOR);
            if (parts.length != 4 || !PREFIX.equals(parts[0])) {
                return false;
            }
            int iterations = Integer.parseInt(parts[1]);
            byte[] salt = Base64.getDecoder().decode(parts[2]);
            byte[] expected = Base64.getDecoder().decode(parts[3]);
            byte[] actual = derive(password, salt, iterations, expected.length * Byte.SIZE);
            return MessageDigest.isEqual(expected, actual);
        } catch (IllegalArgumentException e) {
            // bad number, bad Base64 or invalid PBKDF2 parameters in the stored value
            return false;
        }
    }

    private static byte[] derive(char[] password, byte[] salt, int iterations, int bits) {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, bits);
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
        } catch (GeneralSecurityException e) {
            throw new CryptoException("PBKDF2 failed", e);
        } finally {
            spec.clearPassword();
        }
    }
}
