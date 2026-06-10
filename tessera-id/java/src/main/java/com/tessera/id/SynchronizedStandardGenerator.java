package com.tessera.id;

import java.security.SecureRandom;

/**
 * Internally synchronized convenience wrapper around {@link StandardGenerator}.
 *
 * <p>The base {@link StandardGenerator} is deliberately <b>not</b> internally
 * locked (cross-language contract: one generator per thread, or the caller
 * wraps it). This class is the explicit "caller wraps it" affordance: every
 * {@link #next()} call synchronizes on {@code this}, so a single instance may
 * be shared across threads while preserving per-generator strict monotonicity.
 *
 * <p>For high-throughput single-thread hot paths, prefer the plain
 * {@link StandardGenerator}.
 */
public final class SynchronizedStandardGenerator extends StandardGenerator {

    public SynchronizedStandardGenerator() {
        super();
    }

    public SynchronizedStandardGenerator(SecureRandom rng) {
        super(rng);
    }

    /** Generates the next Standard TesseraID, serialized on {@code this}. */
    @Override
    public synchronized TesseraId next() {
        return super.next();
    }
}
