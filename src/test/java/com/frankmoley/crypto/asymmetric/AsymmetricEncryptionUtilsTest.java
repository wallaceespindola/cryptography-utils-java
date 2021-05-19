package com.frankmoley.crypto.asymmetric;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import javax.xml.bind.DatatypeConverter;
import java.security.KeyPair;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

//@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class AsymmetricEncryptionUtilsTest {

    @Test
    void generateRSAKeyPair_KeySize1024() throws Exception {
        int keySize = 1024;
        System.out.println("Using Key Size:  " + keySize);
        long before = System.currentTimeMillis();
        KeyPair keyPair = AsymmetricEncryptionUtils.generateRSAKeyPair(keySize);
        assertNotNull(keyPair);
        System.out.println("Private Key: " + DatatypeConverter.printHexBinary(keyPair.getPrivate().getEncoded()));
        System.out.println("Public Key:  " + DatatypeConverter.printHexBinary(keyPair.getPublic().getEncoded()));
        long after = System.currentTimeMillis();
        System.out.println("Duration in seconds: " + (after - before) / 1000);
    }

    @Test
    void testRSACryptoRoutine_KeySize1024() throws Exception {
        int keySize = 1024;
        System.out.println("Using Key Size:  " + keySize);
        long before = System.currentTimeMillis();
        KeyPair keyPair = AsymmetricEncryptionUtils.generateRSAKeyPair(keySize);
        String plainText = "This is the text we are going to hide in plain sight";
        byte[] cipherText = AsymmetricEncryptionUtils.performRSAEncryption(plainText, keyPair.getPrivate());
        assertNotNull(cipherText);
        System.out.println("Plain Text:  " + plainText);
        System.out.println("Cipher Text: " + DatatypeConverter.printHexBinary(cipherText));
        String decryptedText = AsymmetricEncryptionUtils.performRSADecryption(cipherText, keyPair.getPublic());
        assertEquals(plainText, decryptedText);
        long after = System.currentTimeMillis();
        System.out.println("Duration in seconds: " + (after - before) / 1000);
    }

    @Test
    void generateRSAKeyPair_KeySize2048() throws Exception {
        int keySize = 2048;
        System.out.println("Using Key Size:  " + keySize);
        long before = System.currentTimeMillis();
        KeyPair keyPair = AsymmetricEncryptionUtils.generateRSAKeyPair(keySize);
        assertNotNull(keyPair);
        System.out.println("Private Key: " + DatatypeConverter.printHexBinary(keyPair.getPrivate().getEncoded()));
        System.out.println("Public Key:  " + DatatypeConverter.printHexBinary(keyPair.getPublic().getEncoded()));
        long after = System.currentTimeMillis();
        System.out.println("Duration in seconds: " + (after - before) / 1000);
    }

    @Test
    void testRSACryptoRoutine_KeySize2048() throws Exception {
        int keySize = 2048;
        System.out.println("Using Key Size:  " + keySize);
        long before = System.currentTimeMillis();
        KeyPair keyPair = AsymmetricEncryptionUtils.generateRSAKeyPair(keySize);
        String plainText = "This is the text we are going to hide in plain sight";
        byte[] cipherText = AsymmetricEncryptionUtils.performRSAEncryption(plainText, keyPair.getPrivate());
        assertNotNull(cipherText);
        System.out.println("Plain Text:  " + plainText);
        System.out.println("Cipher Text: " + DatatypeConverter.printHexBinary(cipherText));
        String decryptedText = AsymmetricEncryptionUtils.performRSADecryption(cipherText, keyPair.getPublic());
        assertEquals(plainText, decryptedText);
        long after = System.currentTimeMillis();
        System.out.println("Duration in seconds: " + (after - before) / 1000);
    }

    @Test
    void generateRSAKeyPair_KeySize4096() throws Exception {
        System.out.println("Using Key Size:  4096");
        long before = System.currentTimeMillis();
        KeyPair keyPair = AsymmetricEncryptionUtils.generateRSAKeyPair();
        assertNotNull(keyPair);
        System.out.println("Private Key: " + DatatypeConverter.printHexBinary(keyPair.getPrivate().getEncoded()));
        System.out.println("Public Key:  " + DatatypeConverter.printHexBinary(keyPair.getPublic().getEncoded()));
        long after = System.currentTimeMillis();
        System.out.println("Duration in seconds: " + (after - before) / 1000);
    }

    @Test
    void testRSACryptoRoutine_KeySize4096() throws Exception {
        System.out.println("Using Key Size:  4096");
        long before = System.currentTimeMillis();
        KeyPair keyPair = AsymmetricEncryptionUtils.generateRSAKeyPair();
        String plainText = "This is the text we are going to hide in plain sight";
        byte[] cipherText = AsymmetricEncryptionUtils.performRSAEncryption(plainText, keyPair.getPrivate());
        assertNotNull(cipherText);
        System.out.println("Plain Text:  " + plainText);
        System.out.println("Cipher Text: " + DatatypeConverter.printHexBinary(cipherText));
        String decryptedText = AsymmetricEncryptionUtils.performRSADecryption(cipherText, keyPair.getPublic());
        assertEquals(plainText, decryptedText);
        long after = System.currentTimeMillis();
        System.out.println("Duration in seconds: " + (after - before) / 1000);
    }

    @Disabled
    @Test
    void generateRSAKeyPair_KeySize8192() throws Exception {
        int keySize = 8192;
        System.out.println("Using Key Size:  " + keySize);
        long before = System.currentTimeMillis();
        KeyPair keyPair = AsymmetricEncryptionUtils.generateRSAKeyPair(keySize);
        assertNotNull(keyPair);
        System.out.println("Private Key: " + DatatypeConverter.printHexBinary(keyPair.getPrivate().getEncoded()));
        System.out.println("Public Key:  " + DatatypeConverter.printHexBinary(keyPair.getPublic().getEncoded()));
        long after = System.currentTimeMillis();
        System.out.println("Duration in seconds: " + (after - before) / 1000);
    }

    @Disabled
    @Test
    void testRSACryptoRoutine_KeySize8192() throws Exception {
        int keySize = 8192;
        System.out.println("Using Key Size:  " + keySize);
        long before = System.currentTimeMillis();
        KeyPair keyPair = AsymmetricEncryptionUtils.generateRSAKeyPair(keySize);
        String plainText = "This is the text we are going to hide in plain sight";
        byte[] cipherText = AsymmetricEncryptionUtils.performRSAEncryption(plainText, keyPair.getPrivate());
        assertNotNull(cipherText);
        System.out.println("Plain Text:  " + plainText);
        System.out.println("Cipher Text: " + DatatypeConverter.printHexBinary(cipherText));
        String decryptedText = AsymmetricEncryptionUtils.performRSADecryption(cipherText, keyPair.getPublic());
        assertEquals(plainText, decryptedText);
        long after = System.currentTimeMillis();
        System.out.println("Duration in seconds: " + (after - before) / 1000);
    }
}