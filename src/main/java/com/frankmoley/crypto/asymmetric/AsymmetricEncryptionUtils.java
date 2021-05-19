package com.frankmoley.crypto.asymmetric;

import javax.crypto.Cipher;
import java.security.*;

public class AsymmetricEncryptionUtils {

    private static final String RSA = "RSA";
    private static final int KEYSIZE_4096 = 4096;

    public static KeyPair generateRSAKeyPair() throws Exception {
        return generateRSAKeyPair(KEYSIZE_4096);
    }

    public static KeyPair generateRSAKeyPair(int keySize) throws Exception {
        SecureRandom secureRandom = new SecureRandom();
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA);
        keyPairGenerator.initialize(keySize, secureRandom);
        return keyPairGenerator.generateKeyPair();
    }

    public static byte[] performRSAEncryption(String plainText, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance(RSA);
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        return cipher.doFinal(plainText.getBytes());
    }

    public static String performRSADecryption(byte[] cipherText, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance(RSA);
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        byte[] result = cipher.doFinal(cipherText);
        return new String(result);
    }
}
