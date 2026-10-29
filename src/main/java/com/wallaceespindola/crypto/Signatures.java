package com.wallaceespindola.crypto;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

/** Ed25519 signatures (RFC 8032). Keys are standard JCA keys: {@code getEncoded()} gives PKCS#8 and X.509. */
public final class Signatures {

    private static final String ALGORITHM = "Ed25519";

    private Signatures() {
    }

    public static KeyPair newKeyPair() {
        try {
            return KeyPairGenerator.getInstance(ALGORITHM).generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new CryptoException("Ed25519 key generation failed", e);
        }
    }

    public static byte[] sign(PrivateKey key, byte[] message) {
        try {
            Signature signature = Signature.getInstance(ALGORITHM);
            signature.initSign(key);
            signature.update(message);
            return signature.sign();
        } catch (GeneralSecurityException e) {
            throw new CryptoException("signing failed", e);
        }
    }

    /** Returns false for a bad or malformed signature, throws only for a key that is not Ed25519. */
    public static boolean verify(PublicKey key, byte[] message, byte[] signatureBytes) {
        try {
            Signature signature = Signature.getInstance(ALGORITHM);
            signature.initVerify(key);
            signature.update(message);
            return signature.verify(signatureBytes);
        } catch (SignatureException e) {
            return false;
        } catch (GeneralSecurityException e) {
            throw new CryptoException("verification failed", e);
        }
    }
}
