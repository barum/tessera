package com.tessera.hash;

import com.tessera.common.Keccak;

/**
 * Generator for TesseraHash identifiers (variant 0x03). Wall-clock time source.
 *
 * <p>Mirrors the locked Go ({@code TesseraHashGenerator}) and Rust
 * ({@code TesseraHashGenerator}) generator shape:
 * <ul>
 *   <li>State is a (last_ts, counter) pair; the 2-byte counter increments
 *       deterministically — no randomness is involved.
 *   <li>Clamp on regression: if the wall clock moves backward, reuse last_ts.
 *   <li>Within a single ms, the counter increments by exactly 1.
 *   <li>Counter exhaustion (more than 65,536 hashes in one ms) spins to the
 *       next ms using {@code <= last_ts} semantics, then resets the counter
 *       to 0.
 * </ul>
 *
 * <p>Thread safety: this class IS internally synchronized, per the
 * cross-language contract ("internally locked where the language has
 * shared-memory threading"). The SHAKE-256 digest is computed outside the
 * lock; only the (last_ts, counter) read-modify-write is serialized.
 */
public class TesseraHashGenerator {

    /** Maximum 16-bit counter value (inclusive). */
    public static final int MAX_COUNTER = 0xFFFF;

    private long lastTs  = 0L;
    private int  counter = 0;        // 16-bit unsigned, held in an int

    /** Returns a TesseraHash over the given content using the live clock. */
    public TesseraHash next(byte[] content) {
        byte[] tail = Keccak.shake256(content, TesseraHash.TAIL_BYTES);

        long ts;
        int  ctr;
        synchronized (this) {
            ts = System.currentTimeMillis();
            if (ts < lastTs) {
                ts = lastTs;          // clamp on regression
            }
            if (ts == lastTs) {
                int next = counter + 1;
                if (next > MAX_COUNTER) {
                    // Counter exhausted: spin until the wall clock advances
                    // past last_ts (Go/Rust "<= last_ts" spin semantics).
                    while (System.currentTimeMillis() <= lastTs) {
                        Thread.onSpinWait();
                    }
                    ts = System.currentTimeMillis();
                    counter = 0;
                } else {
                    counter = next;
                }
            } else {
                counter = 0;          // new ms: counter resets
            }
            lastTs = ts;
            ctr = counter;
        }

        byte[] out = new byte[TesseraHash.SIZE_BYTES];
        out[0] = (byte)((ts >>> 40) & 0xFF);
        out[1] = (byte)((ts >>> 32) & 0xFF);
        out[2] = (byte)((ts >>> 24) & 0xFF);
        out[3] = (byte)((ts >>> 16) & 0xFF);
        out[4] = (byte)((ts >>>  8) & 0xFF);
        out[5] = (byte)( ts         & 0xFF);
        out[6] = TesseraHash.VARIANT;
        out[7] = (byte)((ctr >>> 8) & 0xFF);
        out[8] = (byte)( ctr        & 0xFF);
        System.arraycopy(tail, 0, out, TesseraHash.TAIL_OFFSET, TesseraHash.TAIL_BYTES);
        return new TesseraHash(out);
    }

    /**
     * Forces the generator's internal state. Test hook; mirrors Go
     * {@code SetStateForTesting} / Rust {@code set_state_for_testing}.
     */
    public synchronized void setStateForTesting(long ts, int counter) {
        if (counter < 0 || counter > MAX_COUNTER) {
            throw new IllegalArgumentException("counter out of range [0, 65535]");
        }
        this.lastTs  = ts;
        this.counter = counter;
    }
}
