package com.wallaceespindola.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class PasswordHasherTest {

    @Test
    void verify_correctPassword_true() {
        String stored = PasswordHasher.hash("s3cret".toCharArray());
        assertTrue(stored.startsWith("pbkdf2-sha256$" + PasswordHasher.ITERATIONS + "$"));
        assertTrue(PasswordHasher.verify("s3cret".toCharArray(), stored));
    }

    @Test
    void verify_wrongPassword_false() {
        assertFalse(PasswordHasher.verify("nope".toCharArray(), PasswordHasher.hash("s3cret".toCharArray())));
    }

    @Test
    void hash_samePasswordTwice_differentSalts() {
        char[] pw = "s3cret".toCharArray();
        assertNotEquals(PasswordHasher.hash(pw), PasswordHasher.hash(pw));
        assertEquals(4, PasswordHasher.hash(pw).split("\\$").length);
    }

    @Test
    void verify_malformedStoredValue_false() {
        char[] pw = "x".toCharArray();
        assertFalse(PasswordHasher.verify(pw, ""));
        assertFalse(PasswordHasher.verify(pw, "md5$1$aa$bb"));
        assertFalse(PasswordHasher.verify(pw, "pbkdf2-sha256$abc$AAAA$AAAA"));
        assertFalse(PasswordHasher.verify(pw, "pbkdf2-sha256$0$AAAA$AAAA"));
        assertFalse(PasswordHasher.verify(pw, "pbkdf2-sha256$1000$!!$AAAA"));
    }
}
