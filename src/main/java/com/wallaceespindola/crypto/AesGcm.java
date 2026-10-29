package com.wallaceespindola.crypto;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * AES-256-GCM authenticated encryption. Every call to {@code encrypt} draws a fresh random 12-byte IV
 * and returns {@code IV || ciphertext || tag}, so the output is self-contained.
 */
public final class AesGcm {

    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int KEY_BITS = 256;
    private static final int IV_BYTES = 12;
    private static final int TAG_BITS = 128;
    private static final SecureRandom RANDOM = new SecureRandom();

    private AesGcm() {
    }

    public static SecretKey newKey() {
        try {
            KeyGenerator generator = KeyGenerator.getInstance("AES");
            generator.init(KEY_BITS, RANDOM);
            return generator.generateKey();
        } catch (GeneralSecurityException e) {
            throw new CryptoException("AES key generation failed", e);
        }
    }

    /** Rebuilds a key from 32 raw bytes, for example output of {@link Hkdf}. */
    public static SecretKey keyFrom(byte[] raw) {
        if (raw.length != KEY_BITS / Byte.SIZE) {
            throw new IllegalArgumentException("AES-256 key must be 32 bytes");
        }
        return new SecretKeySpec(raw, "AES");
    }

    public static byte[] encrypt(SecretKey key, byte[] plaintext) {
        return encrypt(key, plaintext, new byte[0]);
    }

    /** {@code aad} is authenticated but not encrypted; pass the same value to {@code decrypt}. */
    public static byte[] encrypt(SecretKey key, byte[] plaintext, byte[] aad) {
        try {
            byte[] iv = new byte[IV_BYTES];
            RANDOM.nextBytes(iv);
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));
            cipher.updateAAD(aad);
            byte[] body = cipher.doFinal(plaintext);
            byte[] out = Arrays.copyOf(iv, IV_BYTES + body.length);
            System.arraycopy(body, 0, out, IV_BYTES, body.length);
            return out;
        } catch (GeneralSecurityException e) {
            throw new CryptoException("encryption failed", e);
        }
    }

    public static byte[] decrypt(SecretKey key, byte[] data) {
        return decrypt(key, data, new byte[0]);
    }

    /** Throws {@link CryptoException} if the key, AAD or data is wrong or the data was modified. */
    public static byte[] decrypt(SecretKey key, byte[] data, byte[] aad) {
        if (data.length < IV_BYTES + TAG_BITS / Byte.SIZE) {
            throw new CryptoException("ciphertext too short", null);
        }
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, data, 0, IV_BYTES));
            cipher.updateAAD(aad);
            return cipher.doFinal(data, IV_BYTES, data.length - IV_BYTES);
        } catch (GeneralSecurityException e) {
            throw new CryptoException("decryption failed", e);
        }
    }
}
