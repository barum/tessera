package com.pqid;

/**
 * Codec for PQHash text encodings (Base64URL and Crockford Base32).
 * Mirrors {@link Codec} for PQID. Enforces canonical padding bits.
 */
public final class PQHashCodec {

    private static final char[] B64URL_ALPHABET =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".toCharArray();
    private static final int[] B64URL_INV = new int[128];
    static {
        java.util.Arrays.fill(B64URL_INV, -1);
        for (int i = 0; i < B64URL_ALPHABET.length; i++) B64URL_INV[B64URL_ALPHABET[i]] = i;
    }

    public static String encodeBase64Url(PQHash p) {
        return encodeBase64Url(p.bytesNoCopy());
    }

    static String encodeBase64Url(byte[] in) {
        // 73 = 24*3 + 1. 24 groups of 3 bytes → 96 chars; trailing byte → 2 chars.
        char[] out = new char[PQHash.ENCODED_LENGTH_B64];
        int oi = 0, i = 0;
        for (; i + 3 <= 72; i += 3) {
            int v = ((in[i] & 0xFF) << 16) | ((in[i+1] & 0xFF) << 8) | (in[i+2] & 0xFF);
            out[oi++] = B64URL_ALPHABET[(v >>> 18) & 0x3F];
            out[oi++] = B64URL_ALPHABET[(v >>> 12) & 0x3F];
            out[oi++] = B64URL_ALPHABET[(v >>>  6) & 0x3F];
            out[oi++] = B64URL_ALPHABET[ v         & 0x3F];
        }
        int v = in[i] & 0xFF;
        out[oi++] = B64URL_ALPHABET[(v >>> 2) & 0x3F];
        out[oi++] = B64URL_ALPHABET[(v << 4)  & 0x3F];
        return new String(out);
    }

    public static PQHash decodeBase64Url(String s) {
        if (s.length() != PQHash.ENCODED_LENGTH_B64) {
            throw new IllegalArgumentException("Base64URL PQHash must be exactly 98 characters");
        }
        byte[] out = new byte[PQHash.SIZE_BYTES];
        int oi = 0, i = 0;
        for (; i + 4 <= 96; i += 4) {
            int a = lookupB64(s.charAt(i));
            int b = lookupB64(s.charAt(i+1));
            int c = lookupB64(s.charAt(i+2));
            int d = lookupB64(s.charAt(i+3));
            int v = (a << 18) | (b << 12) | (c << 6) | d;
            out[oi++] = (byte)((v >>> 16) & 0xFF);
            out[oi++] = (byte)((v >>>  8) & 0xFF);
            out[oi++] = (byte)( v         & 0xFF);
        }
        int a = lookupB64(s.charAt(i));
        int b = lookupB64(s.charAt(i+1));
        if ((b & 0x0F) != 0) {
            throw new IllegalArgumentException("Non-zero padding bits in trailing Base64URL char");
        }
        out[oi++] = (byte)((a << 2) | (b >>> 4));
        return new PQHash(out);
    }

    private static int lookupB64(char c) {
        if (c >= 128 || B64URL_INV[c] < 0) {
            throw new IllegalArgumentException("Invalid Base64URL character: '" + c + "'");
        }
        return B64URL_INV[c];
    }

    // ---- Crockford Base32 ----

    private static final char[] CROCKFORD_ALPHABET =
        "0123456789ABCDEFGHJKMNPQRSTVWXYZ".toCharArray();
    private static final int[] CROCKFORD_INV = new int[128];
    static {
        java.util.Arrays.fill(CROCKFORD_INV, -1);
        for (int i = 0; i < CROCKFORD_ALPHABET.length; i++) {
            CROCKFORD_INV[CROCKFORD_ALPHABET[i]] = i;
            char c = CROCKFORD_ALPHABET[i];
            if (c >= 'A' && c <= 'Z') CROCKFORD_INV[Character.toLowerCase(c)] = i;
        }
        CROCKFORD_INV['I'] = 1; CROCKFORD_INV['i'] = 1;
        CROCKFORD_INV['L'] = 1; CROCKFORD_INV['l'] = 1;
        CROCKFORD_INV['O'] = 0; CROCKFORD_INV['o'] = 0;
    }

    public static String encodeCrockford(PQHash p) {
        byte[] in = p.bytesNoCopy();
        char[] out = new char[PQHash.ENCODED_LENGTH_B32];
        long buf = 0;
        int bits = 0;
        int idx = 0;
        for (int i = 0; i < PQHash.SIZE_BYTES; i++) {
            buf = (buf << 8) | (in[i] & 0xFF);
            bits += 8;
            while (bits >= 5) {
                bits -= 5;
                out[idx++] = CROCKFORD_ALPHABET[(int)((buf >>> bits) & 0x1F)];
            }
        }
        if (bits > 0) {
            out[idx++] = CROCKFORD_ALPHABET[(int)((buf << (5 - bits)) & 0x1F)];
        }
        return new String(out);
    }

    public static PQHash decodeCrockford(String s) {
        if (s.length() != PQHash.ENCODED_LENGTH_B32) {
            throw new IllegalArgumentException("Crockford Base32 PQHash must be exactly 117 characters");
        }
        byte[] out = new byte[PQHash.SIZE_BYTES];
        long buf = 0;
        int bits = 0;
        int idx = 0;
        for (int i = 0; i < s.length(); i++) {
            char ch = s.charAt(i);
            if (ch >= 128 || CROCKFORD_INV[ch] < 0) {
                throw new IllegalArgumentException("Invalid Crockford Base32 character: '" + ch + "'");
            }
            int v = CROCKFORD_INV[ch];
            buf = (buf << 5) | v;
            bits += 5;
            if (bits >= 8) {
                bits -= 8;
                if (idx >= PQHash.SIZE_BYTES) {
                    throw new IllegalArgumentException("Crockford overflow");
                }
                out[idx++] = (byte)((buf >>> bits) & 0xFF);
            }
        }
        if (idx != PQHash.SIZE_BYTES) {
            throw new IllegalArgumentException("Crockford decode short");
        }
        if (bits > 0 && (buf & ((1L << bits) - 1)) != 0) {
            throw new IllegalArgumentException("Non-zero padding bits in trailing Crockford char");
        }
        return new PQHash(out);
    }

    private PQHashCodec() {}
}
