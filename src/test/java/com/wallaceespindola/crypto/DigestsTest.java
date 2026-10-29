package com.wallaceespindola.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class DigestsTest {

    private static byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    @Test
    void sha256_abc_matchesKnownVector() {
        assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                Codec.hex(Digests.sha256(utf8("abc"))));
    }

    @Test
    void sha3_256_abc_matchesKnownVector() {
        assertEquals("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
                Codec.hex(Digests.sha3_256(utf8("abc"))));
    }

    @Test
    void hmacSha256_rfc4231Case2_matchesKnownVector() {
        byte[] mac = Digests.hmacSha256(utf8("Jefe"), utf8("what do ya want for nothing?"));
        assertEquals("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", Codec.hex(mac));
    }

    @Test
    void hmacSha256Matches_goodAndBadMac() {
        byte[] key = utf8("k");
        byte[] mac = Digests.hmacSha256(key, utf8("m"));
        assertTrue(Digests.hmacSha256Matches(key, utf8("m"), mac));
        assertFalse(Digests.hmacSha256Matches(key, utf8("other"), mac));
    }
}
