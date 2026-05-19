package com.pqid;

import java.util.Arrays;

/**
 * Encoders and decoders for the two PQID text forms.
 *
 * <p>Base64URL: 55 chars, RFC 4648 §5 alphabet, no padding. Trailing 4 bits of value
 * with 2 zero pad-bits in the final char; decoders MUST reject non-zero padding.
 *
 * <p>Crockford Base32: 66 chars, case-insensitive on decode, with I/L→1 and O→0
 * confusables canonicalized. Final char carries 3 bits of value plus 2 pad bits.
 */
public final class Codec {

    // ---- Base64URL ----------------------------------------------------------

    private static final char[] B64URL_ALPHABET =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".toCharArray();

    private static final int[] B64URL_INV = new int[128];
    static {
        Arrays.fill(B64URL_INV, -1);
        for (int i = 0; i < B64URL_ALPHABET.length; i++) {
            B64URL_INV[B64URL_ALPHABET[i]] = i;
        }
    }

    public static String encodeBase64Url(Pqid id) {
        return encodeBase64Url(id.bytesNoCopy());
    }

    static String encodeBase64Url(byte[] in) {
        // 41 bytes -> 55 chars. 13 full groups of 3 bytes (=52 chars) + 2 trailing bytes (=3 chars).
        char[] out = new char[55];
        int oi = 0;
        int i = 0;
        for (; i + 3 <= 41; i += 3) {
            int b0 = in[i]   & 0xFF;
            int b1 = in[i+1] & 0xFF;
            int b2 = in[i+2] & 0xFF;
            int v = (b0 << 16) | (b1 << 8) | b2;
            out[oi++] = B64URL_ALPHABET[(v >>> 18) & 0x3F];
            out[oi++] = B64URL_ALPHABET[(v >>> 12) & 0x3F];
            out[oi++] = B64URL_ALPHABET[(v >>>  6) & 0x3F];
            out[oi++] = B64URL_ALPHABET[ v         & 0x3F];
        }
        // Remaining 2 bytes -> 3 chars (16 value bits + 2 zero pad bits in last char)
        int b0 = in[i]   & 0xFF;
        int b1 = in[i+1] & 0xFF;
        int v  = (b0 << 8) | b1;             // 16 bits
        out[oi++] = B64URL_ALPHABET[(v >>> 10) & 0x3F];
        out[oi++] = B64URL_ALPHABET[(v >>>  4) & 0x3F];
        out[oi]   = B64URL_ALPHABET[(v <<   2) & 0x3F];   // low 4 bits of v + 2 zero pad
        return new String(out);
    }

    public static Pqid decodeBase64Url(String s) {
        if (s == null || s.length() != 55) {
            throw new IllegalArgumentException("Base64URL PQID must be exactly 55 characters");
        }
        byte[] out = new byte[41];
        int oi = 0;
        int i = 0;
        // 13 full groups of 4 chars -> 3 bytes
        for (; i + 4 <= 52; i += 4) {
            int v0 = lookupB64(s.charAt(i));
            int v1 = lookupB64(s.charAt(i+1));
            int v2 = lookupB64(s.charAt(i+2));
            int v3 = lookupB64(s.charAt(i+3));
            int v = (v0 << 18) | (v1 << 12) | (v2 << 6) | v3;
            out[oi++] = (byte)((v >>> 16) & 0xFF);
            out[oi++] = (byte)((v >>>  8) & 0xFF);
            out[oi++] = (byte)( v         & 0xFF);
        }
        // Final 3 chars -> 2 bytes, with 2 zero pad bits in low end of last char
        int v0 = lookupB64(s.charAt(i));
        int v1 = lookupB64(s.charAt(i+1));
        int v2 = lookupB64(s.charAt(i+2));
        if ((v2 & 0x03) != 0) {
            throw new IllegalArgumentException("Non-zero padding bits in trailing Base64URL char");
        }
        int v = (v0 << 10) | (v1 << 4) | (v2 >>> 2);  // 16 bits
        out[oi++] = (byte)((v >>> 8) & 0xFF);
        out[oi]   = (byte)( v        & 0xFF);
        return new Pqid(out);
    }

    private static int lookupB64(char c) {
        if (c >= 128 || B64URL_INV[c] < 0) {
            throw new IllegalArgumentException("Invalid Base64URL character: '" + c + "'");
        }
        return B64URL_INV[c];
    }

    // ---- Crockford Base32 ---------------------------------------------------

    private static final char[] CROCKFORD_ALPHABET =
        "0123456789ABCDEFGHJKMNPQRSTVWXYZ".toCharArray();

    private static final int[] CROCKFORD_INV = new int[128];
    static {
        Arrays.fill(CROCKFORD_INV, -1);
        for (int i = 0; i < CROCKFORD_ALPHABET.length; i++) {
            char c = CROCKFORD_ALPHABET[i];
            CROCKFORD_INV[c] = i;
            CROCKFORD_INV[Character.toLowerCase(c)] = i;
        }
        // Confusable canonicalization
        CROCKFORD_INV['I'] = CROCKFORD_INV['i'] = 1;
        CROCKFORD_INV['L'] = CROCKFORD_INV['l'] = 1;
        CROCKFORD_INV['O'] = CROCKFORD_INV['o'] = 0;
    }

    public static String encodeCrockford(Pqid id) {
        return encodeCrockford(id.bytesNoCopy());
    }

    static String encodeCrockford(byte[] in) {
        // 41 bytes -> 66 chars (5 bits per char, ceil(41*8/5) = 66; trailing 8-bit byte
        // becomes 2 chars: top 5 bits + low 3 bits left-shifted by 2).
        char[] out = new char[66];
        int oi = 0;
        // Process 5-byte groups -> 8 chars each. 41 = 8*5 + 1.
        int i = 0;
        for (; i + 5 <= 40; i += 5) {
            long b0 = in[i]   & 0xFFL;
            long b1 = in[i+1] & 0xFFL;
            long b2 = in[i+2] & 0xFFL;
            long b3 = in[i+3] & 0xFFL;
            long b4 = in[i+4] & 0xFFL;
            long v = (b0 << 32) | (b1 << 24) | (b2 << 16) | (b3 << 8) | b4;
            out[oi++] = CROCKFORD_ALPHABET[(int)((v >>> 35) & 0x1F)];
            out[oi++] = CROCKFORD_ALPHABET[(int)((v >>> 30) & 0x1F)];
            out[oi++] = CROCKFORD_ALPHABET[(int)((v >>> 25) & 0x1F)];
            out[oi++] = CROCKFORD_ALPHABET[(int)((v >>> 20) & 0x1F)];
            out[oi++] = CROCKFORD_ALPHABET[(int)((v >>> 15) & 0x1F)];
            out[oi++] = CROCKFORD_ALPHABET[(int)((v >>> 10) & 0x1F)];
            out[oi++] = CROCKFORD_ALPHABET[(int)((v >>>  5) & 0x1F)];
            out[oi++] = CROCKFORD_ALPHABET[(int)( v         & 0x1F)];
        }
        // Final 1 byte -> 2 chars
        int b = in[40] & 0xFF;
        out[oi++] = CROCKFORD_ALPHABET[(b >>> 3) & 0x1F];
        out[oi]   = CROCKFORD_ALPHABET[(b <<  2) & 0x1F];
        return new String(out);
    }

    public static Pqid decodeCrockford(String s) {
        if (s == null || s.length() != 66) {
            throw new IllegalArgumentException("Crockford Base32 PQID must be exactly 66 characters");
        }
        byte[] out = new byte[41];
        int oi = 0;
        int i = 0;
        for (; i + 8 <= 64; i += 8) {
            long v = 0;
            for (int j = 0; j < 8; j++) {
                v = (v << 5) | lookupCrockford(s.charAt(i + j));
            }
            // 40 bits -> 5 bytes
            out[oi++] = (byte)((v >>> 32) & 0xFF);
            out[oi++] = (byte)((v >>> 24) & 0xFF);
            out[oi++] = (byte)((v >>> 16) & 0xFF);
            out[oi++] = (byte)((v >>>  8) & 0xFF);
            out[oi++] = (byte)( v         & 0xFF);
        }
        // Final 2 chars -> 1 byte (top 5 bits + low 3 bits)
        int v0 = lookupCrockford(s.charAt(64));
        int v1 = lookupCrockford(s.charAt(65));
        if ((v1 & 0x03) != 0) {
            throw new IllegalArgumentException("Non-zero padding bits in trailing Crockford char");
        }
        out[oi] = (byte)(((v0 << 3) | (v1 >>> 2)) & 0xFF);
        return new Pqid(out);
    }

    private static int lookupCrockford(char c) {
        if (c >= 128 || CROCKFORD_INV[c] < 0) {
            throw new IllegalArgumentException("Invalid Crockford Base32 character: '" + c + "'");
        }
        return CROCKFORD_INV[c];
    }

    private Codec() {}
}
