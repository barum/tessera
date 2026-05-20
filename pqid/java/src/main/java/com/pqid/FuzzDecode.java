package com.pqid;

/**
 * Java decoder fuzz harness.
 *
 * Drives randomized inputs into Codec.decodeBase64Url, Codec.decodeCrockford,
 * and the Pqid constructor for ITERS iterations. Asserts no panic (any
 * non-PqidError exception is a failure), bijection on success, and
 * round-trip on constructed valid PQIDs.
 *
 * Run: make fuzz   (or: java -cp build com.pqid.FuzzDecode [ITERS])
 *   ITERS defaults to 200000.
 */
public final class FuzzDecode {

    private static final String B64_ALPHA =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    private static final String CR_ALPHA =
        "0123456789ABCDEFGHJKMNPQRSTVWXYZabcdefghjkmnpqrstvwxyzILOilo";

    // Deterministic xoshiro128**-style PRNG.
    private static int[] rngState = new int[4];

    private static void rngSeed(long seed) {
        rngState[0] = (int)(seed & 0xffffffffL);
        rngState[1] = (int)((seed >>> 32) & 0xffffffffL);
        rngState[2] = rngState[0] * 0x9E3779B9;
        rngState[3] = rngState[1] * 0x85EBCA77;
    }
    private static int rngNext() {
        int r = (Integer.rotateLeft(rngState[0] * 5, 7)) * 9;
        int t = rngState[1] << 9;
        rngState[2] ^= rngState[0]; rngState[3] ^= rngState[1];
        rngState[1] ^= rngState[2]; rngState[0] ^= rngState[3];
        rngState[2] ^= t;
        rngState[3] = Integer.rotateLeft(rngState[3], 11);
        return r;
    }
    private static int rngRange(int n) { return n == 0 ? 0 : (rngNext() & 0x7fffffff) % n; }

    private static void fuzzB64() {
        StringBuilder sb = new StringBuilder(55);
        for (int i = 0; i < 55; i++) sb.append(B64_ALPHA.charAt(rngRange(64)));
        String s = sb.toString();
        try {
            Pqid p = Codec.decodeBase64Url(s);
            String reEnc = Codec.encodeBase64Url(p);
            if (!reEnc.equals(s)) {
                System.err.println("b64 not bijective: in=" + s + " out=" + reEnc);
                System.exit(1);
            }
        } catch (IllegalArgumentException e) {
            // Rejection is acceptable for non-canonical inputs.
        } catch (RuntimeException e) {
            System.err.println("b64 unexpected exception: " + e + " on " + s);
            System.exit(1);
        }
    }

    private static void fuzzCrockford() {
        StringBuilder sb = new StringBuilder(66);
        for (int i = 0; i < 66; i++) sb.append(CR_ALPHA.charAt(rngRange(CR_ALPHA.length())));
        String s = sb.toString();
        try {
            Pqid p = Codec.decodeCrockford(s);
            String canonical = Codec.encodeCrockford(p);
            Pqid p2 = Codec.decodeCrockford(canonical);
            if (!p.equals(p2)) {
                System.err.println("crockford canonical roundtrip mismatch");
                System.exit(1);
            }
        } catch (IllegalArgumentException e) {
            // Rejection is acceptable.
        } catch (RuntimeException e) {
            System.err.println("crockford unexpected exception: " + e + " on " + s);
            System.exit(1);
        }
    }

    private static void fuzzValid() {
        long ts = ((long)(rngNext() & 0xFFFF) << 32) | (rngNext() & 0xffffffffL);
        ts &= (1L << 48) - 1;
        byte variant = (rngNext() & 1) != 0 ? Pqid.VARIANT_HLC : Pqid.VARIANT_STANDARD;
        int counter = rngNext() & 0xFFFF;
        byte[] raw = new byte[Pqid.SIZE_BYTES];
        raw[0] = (byte)((ts >>> 40) & 0xFF);
        raw[1] = (byte)((ts >>> 32) & 0xFF);
        raw[2] = (byte)((ts >>> 24) & 0xFF);
        raw[3] = (byte)((ts >>> 16) & 0xFF);
        raw[4] = (byte)((ts >>>  8) & 0xFF);
        raw[5] = (byte)( ts         & 0xFF);
        raw[6] = variant;
        raw[7] = (byte)((counter >>> 8) & 0xFF);
        raw[8] = (byte)( counter        & 0xFF);
        for (int i = 9; i < Pqid.SIZE_BYTES; i++) raw[i] = (byte)(rngNext() & 0xFF);
        Pqid p = new Pqid(raw);
        // Round-trip via Base64URL.
        String s = Codec.encodeBase64Url(p);
        Pqid p2 = Codec.decodeBase64Url(s);
        if (!p.equals(p2)) {
            System.err.println("constructed PQID failed roundtrip");
            System.exit(1);
        }
    }

    public static void main(String[] args) {
        int iters = args.length > 0 ? Integer.parseInt(args[0]) : 200_000;
        long seed = Long.parseLong(System.getenv().getOrDefault("PQID_FUZZ_SEED", "20260519"));
        rngSeed(seed);
        System.out.println("fuzz_decode: ITERS=" + iters + " SEED=" + seed);
        for (int i = 0; i < iters; i++) {
            fuzzB64();
            fuzzCrockford();
            fuzzValid();
            if (i > 0 && i % 10_000 == 0) System.out.println("  " + i + " iterations OK");
        }
        System.out.println("OK: " + iters + " iterations × 3 cases = " + (iters * 3) + " ops");
    }
}
