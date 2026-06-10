package com.tessera.hash;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * Self-contained test runner. Run via {@code java com.tessera.hash.TesseraHashTest}.
 * Reports pass/fail per test and exits non-zero on any failure.
 */
public class TesseraHashTest {

    private static int passed = 0;
    private static int failed = 0;

    public static void main(String[] args) {
        run("hash_only_kat_empty",            TesseraHashTest::testHashOnlyKatEmpty);
        run("generator_roundtrip",            TesseraHashTest::testGeneratorRoundtrip);
        run("generator_tail_equals_hash_only", TesseraHashTest::testGeneratorTailEqualsHashOnly);
        run("counter_increments_within_ms",   TesseraHashTest::testCounterIncrementsWithinMs);
        run("counter_resets_on_new_ms",       TesseraHashTest::testCounterResetsOnNewMs);
        run("counter_exhaust_spins_to_next_ms", TesseraHashTest::testCounterExhaustSpins);
        run("generator_monotonic_10k",        TesseraHashTest::testGeneratorMonotonic);
        run("generator_concurrent_uniqueness", TesseraHashTest::testGeneratorConcurrentUniqueness);
        run("unknown_variant_rejected_binary", TesseraHashTest::testUnknownVariantRejectedBinary);
        run("unknown_variant_rejected_b64",   TesseraHashTest::testUnknownVariantRejectedB64);
        run("unknown_variant_rejected_crockford", TesseraHashTest::testUnknownVariantRejectedCrockford);
        run("hash_at_out_of_range_timestamp", TesseraHashTest::testHashAtOutOfRangeTimestamp);
        run("hash_at_out_of_range_counter",   TesseraHashTest::testHashAtOutOfRangeCounter);
        run("hash_at_field_extraction",       TesseraHashTest::testHashAtFieldExtraction);
        run("base64url_roundtrip_98",         TesseraHashTest::testB64Roundtrip);
        run("crockford_roundtrip_117",        TesseraHashTest::testCrockfordRoundtrip);
        run("verify_content",                 TesseraHashTest::testVerifyContent);

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

    private static void assertThrows(Runnable r, String msg) {
        try {
            r.run();
        } catch (IllegalArgumentException expected) {
            return;
        }
        throw new AssertionError(msg);
    }

    private static byte[] content(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    // ---- SHAKE-256 KAT ----

    /** SHAKE-256(""), 64-byte output — canonical Keccak test vector. */
    private static final String SHAKE256_EMPTY_64 =
        "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f" +
        "d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be";

    private static void testHashOnlyKatEmpty() {
        byte[] tail = TesseraHash.hashOnly(new byte[0]);
        assertTrue(tail.length == 64, "hashOnly digest must be 64 bytes");
        assertTrue(SHAKE256_EMPTY_64.equals(hex(tail)), "SHAKE-256 empty-input KAT mismatch");
    }

    // ---- Generator ----

    private static void testGeneratorRoundtrip() {
        TesseraHashGenerator g = new TesseraHashGenerator();
        TesseraHash h = g.next(content("tessera generator roundtrip"));
        assertTrue(h.toBytes().length == 73, "size != 73");
        assertTrue(h.variant() == TesseraHash.VARIANT, "variant != 0x03");

        String b64 = TesseraHashCodec.encodeBase64Url(h);
        assertTrue(b64.length() == 98, "b64 length != 98");
        assertTrue(h.equals(TesseraHashCodec.decodeBase64Url(b64)), "b64 roundtrip mismatch");

        String b32 = TesseraHashCodec.encodeCrockford(h);
        assertTrue(b32.length() == 117, "crockford length != 117");
        assertTrue(h.equals(TesseraHashCodec.decodeCrockford(b32)), "crockford roundtrip mismatch");
    }

    private static void testGeneratorTailEqualsHashOnly() {
        byte[] c = content("hashOnly equivalence");
        TesseraHashGenerator g = new TesseraHashGenerator();
        TesseraHash h = g.next(c);
        assertTrue(Arrays.equals(h.tail(), TesseraHash.hashOnly(c)),
            "generator tail != hashOnly(content)");
        assertTrue(h.verify(c), "generator output must verify against content");
    }

    private static void testCounterIncrementsWithinMs() {
        // Pin last_ts 10 s in the future: the regression clamp keeps ts == last_ts,
        // so successive calls exercise the same-ms counter path deterministically.
        long future = System.currentTimeMillis() + 10_000L;
        TesseraHashGenerator g = new TesseraHashGenerator();
        g.setStateForTesting(future, 0);

        byte[] c = content("same-ms counter");
        TesseraHash h1 = g.next(c);
        TesseraHash h2 = g.next(c);
        assertTrue(h1.timestampMs() == future, "ts must clamp to last_ts");
        assertTrue(h2.timestampMs() == future, "ts must stay clamped to last_ts");
        assertTrue(h1.counter() == 1, "first same-ms counter != 1, got " + h1.counter());
        assertTrue(h2.counter() == 2, "second same-ms counter != 2, got " + h2.counter());
    }

    private static void testCounterResetsOnNewMs() {
        TesseraHashGenerator g = new TesseraHashGenerator();
        g.setStateForTesting(1_700_000_000_000L, 1234);   // far in the past
        TesseraHash h = g.next(content("new ms resets counter"));
        assertTrue(h.timestampMs() > 1_700_000_000_000L, "ts must advance past stale last_ts");
        assertTrue(h.counter() == 0, "counter must reset to 0 on new ms, got " + h.counter());
    }

    private static void testCounterExhaustSpins() {
        long ts0 = System.currentTimeMillis();
        TesseraHashGenerator g = new TesseraHashGenerator();
        g.setStateForTesting(ts0, TesseraHashGenerator.MAX_COUNTER);
        TesseraHash h = g.next(content("counter exhaust"));
        // Whether the clock already advanced or the generator had to spin,
        // the result must land in a later ms with a reset counter.
        assertTrue(h.timestampMs() > ts0, "exhausted counter must spin to a later ms");
        assertTrue(h.counter() == 0, "counter must reset to 0 after exhaust spin");
    }

    private static void testGeneratorMonotonic() {
        TesseraHashGenerator g = new TesseraHashGenerator();
        byte[] c = content("monotonicity");
        TesseraHash prev = g.next(c);
        for (int i = 0; i < 10_000; i++) {
            TesseraHash cur = g.next(c);
            assertTrue(prev.compareTo(cur) < 0, "sequence not strictly increasing at i=" + i);
            prev = cur;
        }
    }

    private static void testGeneratorConcurrentUniqueness() {
        final TesseraHashGenerator g = new TesseraHashGenerator();
        final int threads = 4;
        final int perThread = 5_000;
        final String[][] out = new String[threads][perThread];
        Thread[] ts = new Thread[threads];
        for (int t = 0; t < threads; t++) {
            final int ti = t;
            ts[t] = new Thread(() -> {
                byte[] c = content("concurrent");
                for (int i = 0; i < perThread; i++) {
                    out[ti][i] = TesseraHashCodec.encodeBase64Url(g.next(c));
                }
            });
            ts[t].start();
        }
        for (Thread th : ts) {
            try {
                th.join();
            } catch (InterruptedException e) {
                throw new AssertionError("interrupted");
            }
        }
        Set<String> all = new HashSet<>(threads * perThread * 2);
        for (String[] lane : out) {
            for (String s : lane) {
                assertTrue(all.add(s), "duplicate TesseraHash under concurrency: " + s);
            }
        }
        assertTrue(all.size() == threads * perThread, "lost IDs under concurrency");
    }

    // ---- Variant rejection (binary + both text forms; TP-028 contract) ----

    /** Valid 73-byte buffer except for a non-0x03 variant byte. */
    private static byte[] rawWithVariant(byte variant) {
        byte[] raw = TesseraHash.hashAt(content("variant rejection"), 1_750_000_000_000L, 7).toBytes();
        raw[6] = variant;
        return raw;
    }

    private static final byte[] BAD_VARIANTS = {
        (byte)0x00,                 // permanently reserved
        (byte)0x01, (byte)0x02,     // TesseraID Standard / HLC — must be rejected here
        (byte)0x04,                 // TesseraSeal — must be rejected here
        (byte)0x05, (byte)0x7F,     // reserved-future
        (byte)0xFF,                 // permanently reserved
    };

    private static void testUnknownVariantRejectedBinary() {
        for (byte v : BAD_VARIANTS) {
            final byte[] raw = rawWithVariant(v);
            assertThrows(() -> new TesseraHash(raw),
                String.format("variant 0x%02X must be rejected (binary)", v));
        }
    }

    private static void testUnknownVariantRejectedB64() {
        for (byte v : BAD_VARIANTS) {
            final String s = TesseraHashCodec.encodeBase64Url(rawWithVariant(v));
            assertThrows(() -> TesseraHashCodec.decodeBase64Url(s),
                String.format("variant 0x%02X must be rejected at Base64URL decode", v));
        }
    }

    private static void testUnknownVariantRejectedCrockford() {
        for (byte v : BAD_VARIANTS) {
            final String s = TesseraHashCodec.encodeCrockford(rawWithVariant(v));
            assertThrows(() -> TesseraHashCodec.decodeCrockford(s),
                String.format("variant 0x%02X must be rejected at Crockford decode", v));
        }
    }

    // ---- hashAt range validation (TP-036 parity) ----

    private static void testHashAtOutOfRangeTimestamp() {
        final byte[] c = content("range");
        assertThrows(() -> TesseraHash.hashAt(c, 1L << 48, 0),
            "timestamp 2^48 must raise, not mask");
        assertThrows(() -> TesseraHash.hashAt(c, -1L, 0),
            "negative timestamp must raise");
        // Boundary: max 48-bit timestamp is valid.
        TesseraHash h = TesseraHash.hashAt(c, (1L << 48) - 1, 0);
        assertTrue(h.timestampMs() == (1L << 48) - 1, "max 48-bit timestamp must round-trip");
    }

    private static void testHashAtOutOfRangeCounter() {
        final byte[] c = content("range");
        assertThrows(() -> TesseraHash.hashAt(c, 1_750_000_000_000L, 0x10000),
            "counter 0x10000 must raise");
        assertThrows(() -> TesseraHash.hashAt(c, 1_750_000_000_000L, -1),
            "negative counter must raise");
        TesseraHash h = TesseraHash.hashAt(c, 1_750_000_000_000L, 0xFFFF);
        assertTrue(h.counter() == 0xFFFF, "max counter must round-trip");
    }

    private static void testHashAtFieldExtraction() {
        byte[] c = content("field extraction");
        TesseraHash h = TesseraHash.hashAt(c, 1_751_234_567_890L, 0xBEEF);
        assertTrue(h.timestampMs() == 1_751_234_567_890L, "timestamp extraction mismatch");
        assertTrue(h.counter() == 0xBEEF, "counter extraction mismatch");
        assertTrue(h.variant() == TesseraHash.VARIANT, "variant mismatch");
        assertTrue(Arrays.equals(h.tail(), TesseraHash.hashOnly(c)), "tail mismatch");
    }

    // ---- Codec round-trips ----

    private static void testB64Roundtrip() {
        TesseraHash h = TesseraHash.hashAt(content("b64"), 1_750_000_000_000L, 42);
        String s = TesseraHashCodec.encodeBase64Url(h);
        assertTrue(s.length() == 98, "b64 length != 98");
        assertTrue(h.equals(TesseraHashCodec.decodeBase64Url(s)), "b64 roundtrip mismatch");
    }

    private static void testCrockfordRoundtrip() {
        TesseraHash h = TesseraHash.hashAt(content("b32"), 1_750_000_000_000L, 42);
        String s = TesseraHashCodec.encodeCrockford(h);
        assertTrue(s.length() == 117, "crockford length != 117");
        assertTrue(h.equals(TesseraHashCodec.decodeCrockford(s)), "crockford roundtrip mismatch");
        assertTrue(h.equals(TesseraHashCodec.decodeCrockford(s.toLowerCase())),
            "crockford decode must be case-insensitive");
    }

    private static void testVerifyContent() {
        byte[] c = content("verify me");
        TesseraHash h = TesseraHash.hashAt(c, 1_750_000_000_000L, 0);
        assertTrue(h.verify(c), "verify(content) must be true");
        assertTrue(!h.verify(content("verify me NOT")), "verify(other) must be false");
    }
}
