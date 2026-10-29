package com.wallaceespindola.crypto;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** SHA-256, SHA3-256 and HMAC-SHA256. Not for passwords, use {@link PasswordHasher} for those. */
public final class Digests {

    private static final String HMAC = "HmacSHA256";

    private Digests() {
    }

    public static byte[] sha256(byte[] data) {
        return digest("SHA-256", data);
    }

    public static byte[] sha3_256(byte[] data) {
        return digest("SHA3-256", data);
    }

    public static byte[] hmacSha256(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance(HMAC);
            mac.init(new SecretKeySpec(key, HMAC));
            return mac.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw new CryptoException("HMAC failed", e);
        }
    }

    /** Constant-time check of a received MAC. */
    public static boolean hmacSha256Matches(byte[] key, byte[] data, byte[] mac) {
        return MessageDigest.isEqual(hmacSha256(key, data), mac);
    }

    private static byte[] digest(String algorithm, byte[] data) {
        try {
            return MessageDigest.getInstance(algorithm).digest(data);
        } catch (GeneralSecurityException e) {
            throw new CryptoException(algorithm + " unavailable", e);
        }
    }
}
