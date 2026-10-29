package com.wallaceespindola.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import javax.crypto.SecretKey;
import org.junit.jupiter.api.Test;

class AesGcmTest {

    private static final byte[] PLAIN = "attack at dawn".getBytes(StandardCharsets.UTF_8);

    @Test
    void roundTrip_returnsOriginal() {
        SecretKey key = AesGcm.newKey();
        assertArrayEquals(PLAIN, AesGcm.decrypt(key, AesGcm.encrypt(key, PLAIN)));
        assertEquals(32, key.getEncoded().length);
    }

    @Test
    void encrypt_samePlaintextTwice_differentOutput() {
        SecretKey key = AesGcm.newKey();
        assertFalse(Arrays.equals(AesGcm.encrypt(key, PLAIN), AesGcm.encrypt(key, PLAIN)));
    }

    @Test
    void decrypt_tamperedData_throws() {
        SecretKey key = AesGcm.newKey();
        byte[] data = AesGcm.encrypt(key, PLAIN);
        data[data.length - 1] ^= 1;
        assertThrows(CryptoException.class, () -> AesGcm.decrypt(key, data));
    }

    @Test
    void decrypt_wrongKey_throws() {
        byte[] data = AesGcm.encrypt(AesGcm.newKey(), PLAIN);
        SecretKey other = AesGcm.newKey();
        assertThrows(CryptoException.class, () -> AesGcm.decrypt(other, data));
    }

    @Test
    void decrypt_aadMismatch_throws() {
        SecretKey key = AesGcm.newKey();
        byte[] data = AesGcm.encrypt(key, PLAIN, new byte[] {1});
        assertArrayEquals(PLAIN, AesGcm.decrypt(key, data, new byte[] {1}));
        assertThrows(CryptoException.class, () -> AesGcm.decrypt(key, data, new byte[] {2}));
    }

    @Test
    void decrypt_tooShort_throws() {
        SecretKey key = AesGcm.newKey();
        assertThrows(CryptoException.class, () -> AesGcm.decrypt(key, new byte[5]));
    }

    @Test
    void keyFrom_wrongLength_throws() {
        assertThrows(IllegalArgumentException.class, () -> AesGcm.keyFrom(new byte[16]));
        assertEquals(32, AesGcm.keyFrom(new byte[32]).getEncoded().length);
    }
}
