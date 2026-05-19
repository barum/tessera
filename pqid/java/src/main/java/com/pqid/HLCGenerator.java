package com.pqid;

import java.security.SecureRandom;

/**
 * Generator for HLC PQIDs (variant 0x02). Maintains a hybrid logical clock
 * that combines wall time with a logical counter and absorbs peer observations.
 *
 * <p>Always serialized: HLC's read-modify-write of (l, c) requires it. Methods
 * synchronize on {@code this}.
 *
 * <p>Default drift bound is 60,000 ms — observations more than that ahead of
 * the local physical clock are rejected via {@link DriftExceededException}.
 */
public class HLCGenerator {
    public static final long DEFAULT_MAX_DRIFT_MS = 60_000L;

    /**
     * Test-only clock override. Long.MIN_VALUE means "use real clock".
     * Conformance tests set this to drive HLC overflow scenarios deterministically.
     */
    public static volatile long nowMsOverride = Long.MIN_VALUE;

    public static void setNowMsForTesting(long valueMs) {
        nowMsOverride = valueMs;
    }

    private static long currentMillis() {
        long o = nowMsOverride;
        return o != Long.MIN_VALUE ? o : System.currentTimeMillis();
    }

    private final SecureRandom rng;
    private final long maxDriftMs;
    private long l = 0L;   // logical time, ms-grained
    private int  c = 0;    // 16-bit logical counter

    public HLCGenerator() {
        this(new SecureRandom(), DEFAULT_MAX_DRIFT_MS);
    }

    public HLCGenerator(SecureRandom rng, long maxDriftMs) {
        this.rng = rng;
        this.maxDriftMs = maxDriftMs;
    }

    /** Test-only: force internal (l, c) state. */
    public synchronized void setStateForTesting(long lNew, int cNew) {
        this.l = lNew;
        this.c = cNew;
    }

    /** Generate a new HLC PQID without peer observation. */
    public synchronized Pqid next() {
        return generate(null);
    }

    /** Generate a new HLC PQID after observing a peer's HLC value. */
    public synchronized Pqid nextObserving(long peerL, int peerC) {
        return generate(new long[] { peerL, peerC });
    }

    /** Snapshot the current (l, c) for transmission to peers. */
    public synchronized long[] currentHLC() {
        return new long[] { l, c };
    }

    private Pqid generate(long[] observe) {
        byte[] rnd = new byte[32];
        rng.nextBytes(rnd);

        long pt = currentMillis();
        long lOld = l;
        int  cOld = c;

        long lNew;
        int  cNew;

        if (observe != null) {
            long lMsg = observe[0];
            int  cMsg = (int)(observe[1] & 0xFFFFL);
            if (lMsg > pt && (lMsg - pt) > maxDriftMs) {
                throw new DriftExceededException(
                    "HLC observation " + lMsg + " exceeds local " + pt + " by more than "
                    + maxDriftMs + "ms drift bound");
            }
            lNew = Math.max(Math.max(lOld, lMsg), pt);
            if (lNew == lOld && lNew == lMsg) {
                cNew = Math.max(cOld, cMsg) + 1;
            } else if (lNew == lOld) {
                cNew = cOld + 1;
            } else if (lNew == lMsg) {
                cNew = cMsg + 1;
            } else {
                cNew = 0;
            }
        } else {
            lNew = Math.max(lOld, pt);
            cNew = (lNew == lOld) ? (cOld + 1) : 0;
        }

        if (cNew > 0xFFFF) {
            lNew += 1;
            cNew = 0;
        }

        l = lNew;
        c = cNew;

        byte[] out = new byte[Pqid.SIZE_BYTES];
        out[0] = (byte)((lNew >>> 40) & 0xFF);
        out[1] = (byte)((lNew >>> 32) & 0xFF);
        out[2] = (byte)((lNew >>> 24) & 0xFF);
        out[3] = (byte)((lNew >>> 16) & 0xFF);
        out[4] = (byte)((lNew >>>  8) & 0xFF);
        out[5] = (byte)( lNew         & 0xFF);
        out[6] = Pqid.VARIANT_HLC;
        out[7] = (byte)((cNew >>> 8) & 0xFF);
        out[8] = (byte)( cNew        & 0xFF);
        System.arraycopy(rnd, 0, out, 9, 32);

        return new Pqid(out);
    }

    public static final class DriftExceededException extends RuntimeException {
        public DriftExceededException(String msg) { super(msg); }
    }
}
