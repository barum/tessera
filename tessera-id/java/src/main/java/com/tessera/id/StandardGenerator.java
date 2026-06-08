package com.tessera.id;

import java.security.SecureRandom;

/**
 * Generator for Standard TesseraIDs (variant 0x01). Wall-clock time source.
 *
 * <p>Thread-safe: methods synchronize on {@code this}. For high-throughput
 * single-thread workloads, prefer {@link #unsynchronized()} or one generator
 * per thread.
 *
 * <p>Behavior matches the reference algorithm in the spec:
 * <ul>
 *   <li>Clamp on regression: if wall clock moves backward, reuse last_ts.
 *   <li>Within a single ms, counter steps by a random amount in [1, 16].
 *   <li>Counter exhaustion (rare) spins on the wall clock.
 * </ul>
 */
public class StandardGenerator {

    private final SecureRandom rng;
    private long lastTs = 0L;
    private int  counter = 0;        // 16-bit unsigned, held in an int

    public StandardGenerator() {
        this(new SecureRandom());
    }

    public StandardGenerator(SecureRandom rng) {
        this.rng = rng;
    }

    /** Returns a thin un-synchronized wrapper for single-thread hot paths. */
    public StandardGenerator unsynchronized() {
        return new UnsyncStandardGenerator(rng);
    }

    public synchronized TesseraId next() {
        return generate();
    }

    TesseraId generate() {
        byte[] rnd = new byte[33];
        rng.nextBytes(rnd);

        long ts = System.currentTimeMillis();
        if (ts < lastTs) {
            ts = lastTs;          // clamp on regression
        }

        int newCounter;
        if (ts == lastTs) {
            int step = 1 + (rnd[0] & 0x0F);
            int next = counter + step;
            if (next > 0xFFFF) {
                // Counter exhausted: spin until wall clock advances
                while (System.currentTimeMillis() <= lastTs) {
                    Thread.onSpinWait();
                }
                ts = System.currentTimeMillis();
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

    private static final class UnsyncStandardGenerator extends StandardGenerator {
        UnsyncStandardGenerator(SecureRandom rng) { super(rng); }
        @Override public TesseraId next() { return generate(); }
    }
}
