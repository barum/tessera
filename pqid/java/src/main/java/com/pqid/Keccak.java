package com.pqid;

/**
 * Vendored minimal Keccak-f[1600] + SHAKE-256.
 *
 * Java's stdlib MessageDigest does not expose SHAKE; rather than pull in
 * Bouncy Castle as a runtime dependency, we ship a ~120-line public-domain
 * implementation. Verified byte-for-byte against Python's hashlib.shake_256
 * by the conformance harness (pqid/conformance/vectors/pqhash_hash_only.json).
 *
 * Constant-time in the sense that all operations are on fixed-shape state
 * regardless of input. Not optimized for SIMD; sufficient for the rates
 * PQHash targets.
 */
public final class Keccak {

    private static final long[] RC = {
        0x0000000000000001L, 0x0000000000008082L, 0x800000000000808AL,
        0x8000000080008000L, 0x000000000000808BL, 0x0000000080000001L,
        0x8000000080008081L, 0x8000000000008009L, 0x000000000000008AL,
        0x0000000000000088L, 0x0000000080008009L, 0x000000008000000AL,
        0x000000008000808BL, 0x800000000000008BL, 0x8000000000008089L,
        0x8000000000008003L, 0x8000000000008002L, 0x8000000000000080L,
        0x000000000000800AL, 0x800000008000000AL, 0x8000000080008081L,
        0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L,
    };

    private static final int[] ROT = {
         0,  1, 62, 28, 27,
        36, 44,  6, 55, 20,
         3, 10, 43, 25, 39,
        41, 45, 15, 21,  8,
        18,  2, 61, 56, 14,
    };

    private static long rol64(long x, int n) {
        // Java rotation: Long.rotateLeft is well-defined for n in [0, 63].
        return Long.rotateLeft(x, n);
    }

    private static void keccakF1600(long[] s) {
        for (int round = 0; round < 24; ++round) {
            long[] C = new long[5];
            long[] D = new long[5];
            long[] B = new long[25];

            for (int x = 0; x < 5; ++x) {
                C[x] = s[x] ^ s[x + 5] ^ s[x + 10] ^ s[x + 15] ^ s[x + 20];
            }
            for (int x = 0; x < 5; ++x) {
                D[x] = C[(x + 4) % 5] ^ rol64(C[(x + 1) % 5], 1);
            }
            for (int i = 0; i < 25; ++i) s[i] ^= D[i % 5];

            for (int x = 0; x < 5; ++x) {
                for (int y = 0; y < 5; ++y) {
                    int newIdx = y + ((2 * x + 3 * y) % 5) * 5;
                    B[newIdx] = rol64(s[x + 5 * y], ROT[x + 5 * y]);
                }
            }

            for (int y = 0; y < 5; ++y) {
                for (int x = 0; x < 5; ++x) {
                    s[x + 5 * y] = B[x + 5 * y] ^ ((~B[((x + 1) % 5) + 5 * y]) & B[((x + 2) % 5) + 5 * y]);
                }
            }

            s[0] ^= RC[round];
        }
    }

    private static final int SHAKE256_RATE = 136;
    private static final int SHAKE_SUFFIX = 0x1F;

    /** SHAKE-256 over {@code input}, output {@code outLen} bytes into {@code output}. */
    public static void shake256(byte[] input, byte[] output, int outLen) {
        long[] state = new long[25];

        int off = 0;
        int remaining = input.length;
        while (remaining >= SHAKE256_RATE) {
            for (int i = 0; i < SHAKE256_RATE / 8; ++i) {
                long lane = 0;
                for (int b = 0; b < 8; ++b) {
                    lane |= ((long)(input[off + i * 8 + b] & 0xFF)) << (8 * b);
                }
                state[i] ^= lane;
            }
            keccakF1600(state);
            off += SHAKE256_RATE;
            remaining -= SHAKE256_RATE;
        }

        byte[] block = new byte[SHAKE256_RATE];
        if (remaining > 0) System.arraycopy(input, off, block, 0, remaining);
        block[remaining] = (byte) SHAKE_SUFFIX;
        block[SHAKE256_RATE - 1] |= (byte) 0x80;
        for (int i = 0; i < SHAKE256_RATE / 8; ++i) {
            long lane = 0;
            for (int b = 0; b < 8; ++b) {
                lane |= ((long)(block[i * 8 + b] & 0xFF)) << (8 * b);
            }
            state[i] ^= lane;
        }

        int outOff = 0;
        while (outLen > 0) {
            keccakF1600(state);
            int chunk = Math.min(outLen, SHAKE256_RATE);
            byte[] laneBytes = new byte[SHAKE256_RATE];
            for (int i = 0; i < SHAKE256_RATE / 8; ++i) {
                long lane = state[i];
                for (int b = 0; b < 8; ++b) {
                    laneBytes[i * 8 + b] = (byte)(lane >>> (8 * b));
                }
            }
            System.arraycopy(laneBytes, 0, output, outOff, chunk);
            outOff += chunk;
            outLen -= chunk;
        }
    }

    public static byte[] shake256(byte[] input, int outLen) {
        byte[] out = new byte[outLen];
        shake256(input, out, outLen);
        return out;
    }

    private Keccak() {}
}
