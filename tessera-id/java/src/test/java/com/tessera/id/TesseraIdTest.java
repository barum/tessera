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
        } catch (HLCGenerator.DriftExceededException expected) {
            // ok
        }
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
