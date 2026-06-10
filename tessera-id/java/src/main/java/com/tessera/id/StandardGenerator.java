package com.tessera.id;

import java.security.SecureRandom;

/**
 * Generator for Standard TesseraIDs (variant 0x01). Wall-clock time source.
 *
 * <p><b>Thread-safety: NOT internally locked.</b> This matches the documented
 * cross-language contract ("StandardGenerator is not internally locked —
 * one-per-thread, or caller wraps it"). Use one generator per thread, guard
 * calls with external synchronization, or use
 * {@link SynchronizedStandardGenerator} for a drop-in internally-synchronized
 * convenience wrapper. Sharing a plain {@code StandardGenerator} across
 * threads without synchronization may corrupt the (lastTs, counter) state and
 * break per-generator monotonicity; it never weakens the 256-bit random tail
 * ({@link SecureRandom} is itself thread-safe).
 *
 * <p>Behavior matches the reference algorithm in the spec:
 * <ul>
 *   <li>Clamp on regression: if wall clock moves backward, reuse last_ts.
 *   <li>Within a single ms, counter steps by a random amount in [1, 16].
 *   <li>Counter exhaustion (rare) spins on the wall clock until it advances
 *       strictly past last_ts ({@code while now <= last_ts}, per spec §3) —
 *       strict monotonicity holds even when exhaustion coincides with a
 *       backward clock jump.
 * </ul>
 */
public class StandardGenerator {

    /**
     * Test-only clock override. {@code Long.MIN_VALUE} means "use real clock".
     * Mirrors the C reference's {@code tessera_id_set_now_ms_for_testing()} and
     * the override already exposed by {@link HLCGenerator}. Never set this in
     * production code.
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
    private long lastTs = 0L;
    private int  counter = 0;        // 16-bit unsigned, held in an int

    public StandardGenerator() {
        this(new SecureRandom());
    }

    public StandardGenerator(SecureRandom rng) {
        this.rng = rng;
    }

    /**
     * @deprecated {@code StandardGenerator} is now unsynchronized by default,
     * matching the cross-language locking contract; this method returns
     * {@code this}. For an internally locked generator, construct a
     * {@link SynchronizedStandardGenerator} instead.
     */
    @Deprecated
    public StandardGenerator unsynchronized() {
        return this;
    }

    /**
     * Generates the next Standard TesseraID. <b>Not synchronized</b> — see the
     * class javadoc for the thread-safety contract.
     */
    public TesseraId next() {
        byte[] rnd = new byte[33];
        rng.nextBytes(rnd);

        long ts = currentMillis();
        if (ts < lastTs) {
            ts = lastTs;          // clamp on regression
        }

        int newCounter;
        if (ts == lastTs) {
            int step = 1 + (rnd[0] & 0x0F);
            int next = counter + step;
            if (next > 0xFFFF) {
                // Counter exhausted: spin until the wall clock advances
                // strictly past lastTs (spec §3: while now <= last_ts).
                do {
                    Thread.onSpinWait();
                    ts = currentMillis();
                } while (ts <= lastTs);
                newCounter = rnd[0] & 0xFF;   // reseed at small value
            } else {
                newCounter = next;
            }
        } else {
            newCounter = rnd[0] & 0xFF;       // randomized initial offset
        }

        lastTs = ts;
        counter = newCounter;

        byte[] out = new byte[TesseraId.SIZE_BYTES];
        // 48-bit big-endian timestamp at offsets 0..5
        out[0] = (byte)((ts >>> 40) & 0xFF);
        out[1] = (byte)((ts >>> 32) & 0xFF);
        out[2] = (byte)((ts >>> 24) & 0xFF);
        out[3] = (byte)((ts >>> 16) & 0xFF);
        out[4] = (byte)((ts >>>  8) & 0xFF);
        out[5] = (byte)( ts         & 0xFF);
        // variant
        out[6] = TesseraId.VARIANT_STANDARD;
        // 16-bit counter at offsets 7..8
        out[7] = (byte)((newCounter >>> 8) & 0xFF);
        out[8] = (byte)( newCounter        & 0xFF);
        // 32 bytes of random tail at offsets 9..40
        System.arraycopy(rnd, 1, out, 9, 32);

        return new TesseraId(out);
    }
}
