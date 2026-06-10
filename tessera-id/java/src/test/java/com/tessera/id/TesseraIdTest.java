package com.tessera.id;

import java.util.HashSet;
import java.util.Set;

/**
 * Self-contained test runner. Run via {@code java com.tessera.id.TesseraIdTest}.
 * Reports pass/fail per test and exits non-zero on any failure.
 */
public class TesseraIdTest {

    private static int passed = 0;
    private static int failed = 0;

    public static void main(String[] args) {
        run("size",                       TesseraIdTest::testSize);
        run("variant_byte_standard",      TesseraIdTest::testVariantByteStandard);
        run("variant_byte_hlc",           TesseraIdTest::testVariantByteHlc);
        run("variant_byte_rejected",      TesseraIdTest::testVariantByteRejected);
        run("uniqueness_100k",            TesseraIdTest::testUniqueness);
        run("monotonicity_10k",           TesseraIdTest::testMonotonicity);
        run("base64url_roundtrip",        TesseraIdTest::testB64Roundtrip);
        run("base64url_length_55",        TesseraIdTest::testB64Length);
        run("crockford_roundtrip",        TesseraIdTest::testCrockfordRoundtrip);
        run("crockford_length_66",        TesseraIdTest::testCrockfordLength);
        run("crockford_case_insensitive", TesseraIdTest::testCrockfordCaseInsensitive);
        run("crockford_confusables",      TesseraIdTest::testCrockfordConfusables);
        run("crockford_sort_preserving",  TesseraIdTest::testCrockfordSortPreserving);
        run("hlc_observation_advances",   TesseraIdTest::testHLCObservation);
        run("hlc_drift_rejected",         TesseraIdTest::testHLCDriftRejected);
        run("hlc_observe_decoded_id",     TesseraIdTest::testHLCObserveDecodedId);
        run("hlc_observe_decoded_drift_rejected", TesseraIdTest::testHLCObserveDecodedDriftRejected);
        run("hlc_drift_bound_relax_rejected",     TesseraIdTest::testHLCDriftBoundRelaxRejected);
        run("hlc_drift_bound_stricter_allowed",   TesseraIdTest::testHLCDriftBoundStricterAllowed);
        run("b64_decode_rejects_unknown_variant",       TesseraIdTest::testB64DecodeRejectsUnknownVariant);
        run("crockford_decode_rejects_unknown_variant", TesseraIdTest::testCrockfordDecodeRejectsUnknownVariant);
        run("standard_clock_regression_clamps",     TesseraIdTest::testStandardClockRegressionClamps);
        run("standard_regression_exhaust_monotonic", TesseraIdTest::testStandardRegressionExhaustMonotonic);
        run("locking_contract",           TesseraIdTest::testLockingContract);
        run("synchronized_wrapper_concurrent",    TesseraIdTest::testSynchronizedWrapperConcurrent);
        run("decoder_rejects_short",      TesseraIdTest::testDecoderRejectsShort);
        run("decoder_rejects_bad_char",   TesseraIdTest::testDecoderRejectsBadChar);
        run("decoder_rejects_bad_pad",    TesseraIdTest::testDecoderRejectsBadPad);
        run("timestamp_extraction",       TesseraIdTest::testTimestampExtraction);
        run("counter_extraction",         TesseraIdTest::testCounterExtraction);

        System.out.printf("%n%d passed, %d failed%n", passed, failed);
        System.exit(failed == 0 ? 0 : 1);
    }

    private static void run(String name, Runnable r) {
        try {
            r.run();
            System.out.println("  PASS  " + name);
            passed++;
        } catch (Throwable t) {
            System.out.println("  FAIL  " + name + " : " + t.getMessage());
            failed++;
        }
    }

    private static void assertTrue(boolean b, String msg) {
        if (!b) throw new AssertionError(msg);
    }

    private static void testSize() {
        TesseraId p = new StandardGenerator().next();
        assertTrue(p.toBytes().length == 41, "size != 41");
    }

    private static void testVariantByteStandard() {
        TesseraId p = new StandardGenerator().next();
        assertTrue(p.variant() == 0x01, "variant byte != 0x01");
    }

    private static void testVariantByteHlc() {
        TesseraId p = new HLCGenerator().next();
        assertTrue(p.variant() == 0x02, "variant byte != 0x02");
    }

    private static void testVariantByteRejected() {
        byte[] bad = new byte[41];
        bad[6] = 0x05;  // not 0x01 or 0x02
        try {
            new TesseraId(bad);
            throw new AssertionError("expected rejection of variant 0x05");
        } catch (IllegalArgumentException expected) {
            // ok
        }
    }

    private static void testUniqueness() {
        StandardGenerator g = new StandardGenerator();
        Set<String> seen = new HashSet<>(100_000);
        for (int i = 0; i < 100_000; i++) {
            String s = Codec.encodeBase64Url(g.next());
            assertTrue(seen.add(s), "duplicate at i=" + i);
        }
    }

    private static void testMonotonicity() {
        StandardGenerator g = new StandardGenerator();
        TesseraId prev = g.next();
        for (int i = 1; i < 10_000; i++) {
            TesseraId cur = g.next();
            assertTrue(cur.compareTo(prev) > 0, "non-monotonic at i=" + i);
            prev = cur;
        }
    }

    private static void testB64Roundtrip() {
        StandardGenerator g = new StandardGenerator();
        for (int i = 0; i < 1000; i++) {
            TesseraId p = g.next();
            String s = Codec.encodeBase64Url(p);
            TesseraId decoded = Codec.decodeBase64Url(s);
            assertTrue(p.equals(decoded), "roundtrip failed at i=" + i);
        }
    }

    private static void testB64Length() {
        TesseraId p = new StandardGenerator().next();
        assertTrue(Codec.encodeBase64Url(p).length() == 55, "B64URL length != 55");
    }

    private static void testCrockfordRoundtrip() {
        StandardGenerator g = new StandardGenerator();
        for (int i = 0; i < 1000; i++) {
            TesseraId p = g.next();
            String s = Codec.encodeCrockford(p);
            TesseraId decoded = Codec.decodeCrockford(s);
            assertTrue(p.equals(decoded), "Crockford roundtrip failed at i=" + i);
        }
    }

    private static void testCrockfordLength() {
        TesseraId p = new StandardGenerator().next();
        assertTrue(Codec.encodeCrockford(p).length() == 66, "Crockford length != 66");
    }

    private static void testCrockfordCaseInsensitive() {
        TesseraId p = new StandardGenerator().next();
        String upper = Codec.encodeCrockford(p);
        String lower = upper.toLowerCase();
        TesseraId d1 = Codec.decodeCrockford(upper);
        TesseraId d2 = Codec.decodeCrockford(lower);
        assertTrue(d1.equals(d2), "case-insensitive decode mismatch");
    }

    private static void testCrockfordConfusables() {
        TesseraId p = new StandardGenerator().next();
        String s = Codec.encodeCrockford(p);
        // Replace any '1' with 'I' or 'L'; should still decode equal
        // Replace any '0' with 'O'; should still decode equal
        String mangled = s.replace('1', 'I').replace('0', 'O');
        TesseraId d = Codec.decodeCrockford(mangled);
        assertTrue(p.equals(d), "confusable canonicalization failed");
    }

    private static void testCrockfordSortPreserving() {
        StandardGenerator g = new StandardGenerator();
        String prev = Codec.encodeCrockford(g.next());
        for (int i = 1; i < 100; i++) {
            String cur = Codec.encodeCrockford(g.next());
            assertTrue(cur.compareTo(prev) > 0, "Crockford not sort-preserving at i=" + i);
            prev = cur;
        }
    }

    private static void testHLCObservation() {
        HLCGenerator h = new HLCGenerator();
        TesseraId first = h.next();
        long[] snap = h.currentHLC();
        TesseraId afterObserve = h.nextObserving(snap[0], (int)snap[1]);
        assertTrue(afterObserve.compareTo(first) > 0, "HLC didn't advance after observation");
    }

    private static void testHLCDriftRejected() {
        HLCGenerator h = new HLCGenerator();
        long farFuture = System.currentTimeMillis() + 120_000L;  // 2 minutes ahead
        try {
            h.nextObserving(farFuture, 0);
            throw new AssertionError("expected drift rejection");
        } catch (HLCGenerator.HLCDriftError expected) {
            // ok
        }
    }

    private static void testHLCObserveDecodedId() {
        HLCGenerator a = new HLCGenerator();
        HLCGenerator b = new HLCGenerator();
        TesseraId first = a.next();
        TesseraId peer = b.next();
        TesseraId merged = a.nextObserving(peer);
        assertTrue(merged.compareTo(first) > 0, "HLC didn't advance after decoded observation");
        assertTrue(merged.timestampMs() >= peer.timestampMs(), "merged l below observed l");
        try {
            a.nextObserving((TesseraId) null);
            throw new AssertionError("expected null-observation rejection");
        } catch (IllegalArgumentException expected) { }
    }

    private static void testHLCObserveDecodedDriftRejected() {
        HLCGenerator h = new HLCGenerator();
        long far = System.currentTimeMillis() + 120_000L;  // 2 minutes ahead
        byte[] raw = new byte[41];
        raw[0] = (byte)((far >>> 40) & 0xFF);
        raw[1] = (byte)((far >>> 32) & 0xFF);
        raw[2] = (byte)((far >>> 24) & 0xFF);
        raw[3] = (byte)((far >>> 16) & 0xFF);
        raw[4] = (byte)((far >>>  8) & 0xFF);
        raw[5] = (byte)( far         & 0xFF);
        raw[6] = TesseraId.VARIANT_HLC;
        TesseraId peer = new TesseraId(raw);  // valid length + variant, far-future HLC
        try {
            h.nextObserving(peer);
            throw new AssertionError("expected drift rejection for decoded observation");
        } catch (HLCGenerator.HLCDriftError expected) {
            // ok
        }
    }

    private static void testHLCDriftBoundRelaxRejected() {
        // The normative 60 000 ms bound may be tightened, never relaxed.
        long[] invalid = { 60_001L, 120_000L, 0L, -1L };
        for (long bound : invalid) {
            try {
                new HLCGenerator(new java.security.SecureRandom(), bound);
                throw new AssertionError("expected rejection of maxDriftMs=" + bound);
            } catch (IllegalArgumentException expected) { }
        }
        // The normative default itself is accepted.
        new HLCGenerator(new java.security.SecureRandom(), HLCGenerator.DEFAULT_MAX_DRIFT_MS);
    }

    private static void testHLCDriftBoundStricterAllowed() {
        HLCGenerator strict = new HLCGenerator(new java.security.SecureRandom(), 30_000L);
        try {
            strict.nextObserving(System.currentTimeMillis() + 45_000L, 0);
            throw new AssertionError("expected stricter-bound rejection at +45s");
        } catch (HLCGenerator.HLCDriftError expected) { }
        strict.nextObserving(System.currentTimeMillis() + 10_000L, 0);   // within 30s: ok
        HLCGenerator dflt = new HLCGenerator();
        dflt.nextObserving(System.currentTimeMillis() + 45_000L, 0);     // within normative 60s: ok
    }

    private static final byte[] UNKNOWN_VARIANTS = { 0x00, 0x03, 0x05, (byte) 0xFF };

    private static void testB64DecodeRejectsUnknownVariant() {
        for (byte v : UNKNOWN_VARIANTS) {
            byte[] raw = new byte[41];
            raw[6] = v;
            String s = Codec.encodeBase64Url(raw);
            try {
                Codec.decodeBase64Url(s);
                throw new AssertionError(String.format(
                    "expected b64 decode rejection of variant 0x%02X", v));
            } catch (IllegalArgumentException expected) { }
        }
    }

    private static void testCrockfordDecodeRejectsUnknownVariant() {
        for (byte v : UNKNOWN_VARIANTS) {
            byte[] raw = new byte[41];
            raw[6] = v;
            String s = Codec.encodeCrockford(raw);
            try {
                Codec.decodeCrockford(s);
                throw new AssertionError(String.format(
                    "expected Crockford decode rejection of variant 0x%02X", v));
            } catch (IllegalArgumentException expected) { }
        }
    }

    private static void testStandardClockRegressionClamps() {
        final long t0 = 1_750_000_000_000L;
        try {
            StandardGenerator.setNowMsForTesting(t0);
            StandardGenerator g = new StandardGenerator();
            TesseraId first = g.next();
            assertTrue(first.timestampMs() == t0, "ts != t0");
            // Regress the test clock 30 s; the generator must clamp to lastTs.
            StandardGenerator.setNowMsForTesting(t0 - 30_000L);
            TesseraId second = g.next();
            assertTrue(second.timestampMs() == t0, "regressed clock leaked into timestamp");
            assertTrue(second.compareTo(first) > 0, "non-monotonic across regression");
        } finally {
            StandardGenerator.setNowMsForTesting(Long.MIN_VALUE);
        }
    }

    /**
     * TP-025 contract: when the counter exhausts while the wall clock has
     * regressed, the generator must spin on {@code now <= last_ts} (spec §3) —
     * never emit an ID with a regressed timestamp. A buggy {@code now == ts}
     * spin would exit immediately during regression and break monotonicity.
     */
    private static void testStandardRegressionExhaustMonotonic() {
        final long t0 = 1_750_000_000_000L;
        Thread releaser = null;
        try {
            StandardGenerator.setNowMsForTesting(t0);
            StandardGenerator g = new StandardGenerator();
            TesseraId prev = g.next();
            assertTrue(prev.timestampMs() == t0, "ts != t0");

            // Regress the test clock 5 s and drive the counter to exhaustion.
            StandardGenerator.setNowMsForTesting(t0 - 5_000L);
            boolean advanced = false;
            for (int i = 0; i < 80_000; i++) {
                TesseraId cur = g.next();
                assertTrue(cur.compareTo(prev) > 0, "non-monotonic at i=" + i
                    + " prevTs=" + prev.timestampMs() + " curTs=" + cur.timestampMs());
                if (cur.timestampMs() > t0) {
                    // Exhaust path taken: the spin only exits once the clock
                    // moves strictly past lastTs, never on the regressed value.
                    assertTrue(cur.timestampMs() == t0 + 1,
                        "unexpected post-spin timestamp " + cur.timestampMs());
                    advanced = true;
                    break;
                }
                assertTrue(cur.timestampMs() == t0, "timestamp regressed at i=" + i);
                prev = cur;
                if (releaser == null && cur.counter() >= 0xFFF0) {
                    // Exhaustion is at most 16 calls away (step is 1..16).
                    // Arm a watcher that advances the clock so a spec-correct
                    // spin can exit; a buggy '==' spin exits immediately with
                    // the regressed timestamp and fails the asserts above
                    // long before this watcher fires.
                    releaser = new Thread(() -> {
                        try { Thread.sleep(250); } catch (InterruptedException ignored) { }
                        StandardGenerator.setNowMsForTesting(t0 + 1);
                    });
                    releaser.setDaemon(true);
                    releaser.start();
                }
            }
            assertTrue(advanced, "counter never exhausted within 80k iterations");
        } finally {
            if (releaser != null) {
                try { releaser.join(2_000); } catch (InterruptedException ignored) { }
            }
            StandardGenerator.setNowMsForTesting(Long.MIN_VALUE);
        }
    }

    private static void testLockingContract() {
        try {
            java.lang.reflect.Method base = StandardGenerator.class.getDeclaredMethod("next");
            assertTrue(!java.lang.reflect.Modifier.isSynchronized(base.getModifiers()),
                "StandardGenerator.next() must NOT be synchronized (cross-language contract)");
            java.lang.reflect.Method wrap = SynchronizedStandardGenerator.class.getDeclaredMethod("next");
            assertTrue(java.lang.reflect.Modifier.isSynchronized(wrap.getModifiers()),
                "SynchronizedStandardGenerator.next() must be synchronized");
            java.lang.reflect.Method hlc = HLCGenerator.class.getDeclaredMethod("next");
            assertTrue(java.lang.reflect.Modifier.isSynchronized(hlc.getModifiers()),
                "HLCGenerator.next() must be synchronized (cross-language contract)");
        } catch (NoSuchMethodException e) {
            throw new AssertionError(e);
        }
    }

    private static void testSynchronizedWrapperConcurrent() {
        final SynchronizedStandardGenerator g = new SynchronizedStandardGenerator();
        final int nThreads = 8;
        final int perThread = 5_000;
        final Set<String> all = java.util.Collections.synchronizedSet(
            new HashSet<>(nThreads * perThread * 2));
        final java.util.concurrent.atomic.AtomicBoolean dup =
            new java.util.concurrent.atomic.AtomicBoolean(false);
        Thread[] workers = new Thread[nThreads];
        for (int t = 0; t < nThreads; t++) {
            workers[t] = new Thread(() -> {
                for (int i = 0; i < perThread; i++) {
                    if (!all.add(Codec.encodeBase64Url(g.next()))) {
                        dup.set(true);
                    }
                }
            });
            workers[t].start();
        }
        for (Thread w : workers) {
            try { w.join(); } catch (InterruptedException e) { throw new RuntimeException(e); }
        }
        assertTrue(!dup.get(), "duplicate ID from shared synchronized generator");
        assertTrue(all.size() == nThreads * perThread, "lost IDs under concurrency");
    }

    private static void testDecoderRejectsShort() {
        try {
            Codec.decodeBase64Url("tooshort");
            throw new AssertionError("expected length rejection");
        } catch (IllegalArgumentException expected) { }
    }

    private static void testDecoderRejectsBadChar() {
        TesseraId p = new StandardGenerator().next();
        String s = Codec.encodeBase64Url(p);
        // Substitute a definitely-invalid character
        String bad = "*" + s.substring(1);
        try {
            Codec.decodeBase64Url(bad);
            throw new AssertionError("expected character rejection");
        } catch (IllegalArgumentException expected) { }
    }

    private static void testDecoderRejectsBadPad() {
        // Construct a valid B64URL string and corrupt the trailing pad bits.
        TesseraId p = new StandardGenerator().next();
        String s = Codec.encodeBase64Url(p);
        // The last char's low 2 bits MUST be zero. Find a char that has nonzero low 2 bits and
        // substitute it for the last char to force a bad-pad rejection.
        // 'B' = index 1, low 2 bits = 0b01 != 0 -> non-zero pad
        String bad = s.substring(0, 54) + "B";
        try {
            Codec.decodeBase64Url(bad);
            throw new AssertionError("expected pad-bit rejection");
        } catch (IllegalArgumentException expected) { }
    }

    private static void testTimestampExtraction() {
        long before = System.currentTimeMillis();
        TesseraId p = new StandardGenerator().next();
        long after = System.currentTimeMillis();
        long ts = p.timestampMs();
        assertTrue(ts >= before && ts <= after, "timestamp out of range: " + ts);
    }

    private static void testCounterExtraction() {
        TesseraId p = new StandardGenerator().next();
        int c = p.counter();
        assertTrue(c >= 0 && c <= 0xFFFF, "counter out of range: " + c);
    }
}
