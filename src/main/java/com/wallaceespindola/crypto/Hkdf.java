package com.wallaceespindola.crypto;

import java.security.GeneralSecurityException;
import javax.crypto.KDF;
import javax.crypto.spec.HKDFParameterSpec;

/** HKDF-SHA256 (RFC 5869) through the JDK 25 {@link KDF} API. Derives sub-keys from high-entropy input. */
public final class Hkdf {

    private Hkdf() {
    }

    /**
     * @param ikm  input key material with real entropy (never a password)
     * @param salt optional, may be empty
     * @param info context label so different uses get different keys
     * @param length output size in bytes, at most 8160
     */
    public static byte[] derive(byte[] ikm, byte[] salt, byte[] info, int length) {
        try {
            return KDF.getInstance("HKDF-SHA256").deriveData(
                    HKDFParameterSpec.ofExtract().addIKM(ikm).addSalt(salt).thenExpand(info, length));
        } catch (GeneralSecurityException e) {
            throw new CryptoException("HKDF failed", e);
        }
    }
}
