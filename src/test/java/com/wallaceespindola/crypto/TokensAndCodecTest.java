package com.wallaceespindola.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class TokensAndCodecTest {

    @Test
    void random_default_is43UrlSafeCharsAndUnique() {
        String token = Tokens.random();
        assertEquals(43, token.length());
        assertTrue(token.matches("[A-Za-z0-9_-]+"));
        assertNotEquals(token, Tokens.random());
    }

    @Test
    void random_customSize_andInvalidSize() {
        assertEquals(22, Tokens.random(16).length());
        assertThrows(IllegalArgumentException.class, () -> Tokens.random(0));
    }

    @Test
    void codec_roundTrips() {
        byte[] data = {(byte) 0xfb, (byte) 0xff, 0x00, 0x10};
        assertArrayEquals(data, Codec.fromBase64(Codec.base64(data)));
        assertArrayEquals(data, Codec.fromBase64Url(Codec.base64Url(data)));
        assertArrayEquals(data, Codec.fromHex(Codec.hex(data)));
        assertEquals("fbff0010", Codec.hex(data));
        assertEquals("-_8AEA", Codec.base64Url(data));
    }
}
