package com.wallaceespindola.crypto;

import java.util.Base64;
import java.util.HexFormat;

/** Thin wrappers over the JDK encoders so call sites read the same everywhere. */
public final class Codec {

    private Codec() {
    }

    public static String base64(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    public static byte[] fromBase64(String text) {
        return Base64.getDecoder().decode(text);
    }

    /** URL and filename safe alphabet, no padding. */
    public static String base64Url(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    public static byte[] fromBase64Url(String text) {
        return Base64.getUrlDecoder().decode(text);
    }

    public static String hex(byte[] data) {
        return HexFormat.of().formatHex(data);
    }

    public static byte[] fromHex(String text) {
        return HexFormat.of().parseHex(text);
    }
}
