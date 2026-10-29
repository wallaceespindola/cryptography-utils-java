package com.wallaceespindola.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Arrays;
import org.junit.jupiter.api.Test;

class HkdfTest {

    @Test
    void derive_rfc5869Case1_matchesKnownVector() {
        byte[] ikm = new byte[22];
        Arrays.fill(ikm, (byte) 0x0b);
        byte[] okm = Hkdf.derive(ikm, Codec.fromHex("000102030405060708090a0b0c"),
                Codec.fromHex("f0f1f2f3f4f5f6f7f8f9"), 42);
        assertEquals("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
                Codec.hex(okm));
    }

    @Test
    void derive_lengthTooLarge_throws() {
        assertThrows(CryptoException.class, () -> Hkdf.derive(new byte[32], new byte[0], new byte[0], 8161));
    }
}
