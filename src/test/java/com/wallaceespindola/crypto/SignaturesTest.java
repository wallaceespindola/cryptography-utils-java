package com.wallaceespindola.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import org.junit.jupiter.api.Test;

class SignaturesTest {

    private static final byte[] MSG = "pay 10 EUR".getBytes(StandardCharsets.UTF_8);

    @Test
    void verify_validSignature_true() {
        KeyPair pair = Signatures.newKeyPair();
        byte[] sig = Signatures.sign(pair.getPrivate(), MSG);
        assertEquals(64, sig.length);
        assertTrue(Signatures.verify(pair.getPublic(), MSG, sig));
    }

    @Test
    void verify_tamperedMessageOrWrongKey_false() {
        KeyPair pair = Signatures.newKeyPair();
        byte[] sig = Signatures.sign(pair.getPrivate(), MSG);
        assertFalse(Signatures.verify(pair.getPublic(), "pay 99 EUR".getBytes(StandardCharsets.UTF_8), sig));
        assertFalse(Signatures.verify(Signatures.newKeyPair().getPublic(), MSG, sig));
    }

    @Test
    void verify_malformedSignature_false() {
        assertFalse(Signatures.verify(Signatures.newKeyPair().getPublic(), MSG, new byte[3]));
    }

    @Test
    void sign_nonEd25519Key_throws() throws Exception {
        var rsa = java.security.KeyPairGenerator.getInstance("RSA").generateKeyPair();
        assertThrows(CryptoException.class, () -> Signatures.sign(rsa.getPrivate(), MSG));
        assertThrows(CryptoException.class, () -> Signatures.verify(rsa.getPublic(), MSG, new byte[64]));
    }
}
