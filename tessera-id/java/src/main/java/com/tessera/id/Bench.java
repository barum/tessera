package com.tessera.id;

/**
 * Benchmark harness. Run via {@code java com.tessera.id.Bench}.
 *
 * <p>Methodology matches the other reference implementations: a 10,000-iteration
 * warmup followed by a measurement run sized to take roughly 1 second per case.
 * Reports steady-state ops/sec.
 */
public class Bench {

    public static void main(String[] args) {
        System.out.println("TesseraID Java benchmark");
        System.out.println("========================");
        System.out.printf("JVM: %s %s%n",
            System.getProperty("java.vm.name"),
            System.getProperty("java.version"));
        System.out.println();

        // Warm up the JIT separately for each generator
        warmupStandard();
        warmupHlc();
        warmupCodec();

        benchStandard();
        benchHlc();
        benchEncodeB64();
        benchDecodeB64();
        benchEncodeCrockford();
        benchDecodeCrockford();
    }

    private static void warmupStandard() {
        StandardGenerator g = new StandardGenerator();
        for (int i = 0; i < 10_000; i++) g.next();
    }

    private static void warmupHlc() {
        HLCGenerator h = new HLCGenerator();
        for (int i = 0; i < 10_000; i++) h.next();
    }

    private static void warmupCodec() {
        StandardGenerator g = new StandardGenerator();
        for (int i = 0; i < 10_000; i++) {
            TesseraId p = g.next();
            String s = Codec.encodeBase64Url(p);
            Codec.decodeBase64Url(s);
            String c = Codec.encodeCrockford(p);
            Codec.decodeCrockford(c);
        }
    }

    private static void benchStandard() {
        StandardGenerator g = new StandardGenerator();
        int n = 1_000_000;
        long start = System.nanoTime();
        for (int i = 0; i < n; i++) g.next();
        long elapsed = System.nanoTime() - start;
        report("Standard generation", n, elapsed);
    }

    private static void benchHlc() {
        HLCGenerator h = new HLCGenerator();
        int n = 1_000_000;
        long start = System.nanoTime();
        for (int i = 0; i < n; i++) h.next();
        long elapsed = System.nanoTime() - start;
        report("HLC generation", n, elapsed);
    }

    private static void benchEncodeB64() {
        StandardGenerator g = new StandardGenerator();
        TesseraId p = g.next();
        int n = 5_000_000;
        long start = System.nanoTime();
        long sink = 0;
        for (int i = 0; i < n; i++) {
            sink ^= Codec.encodeBase64Url(p).hashCode();
        }
        long elapsed = System.nanoTime() - start;
        if (sink == 0xDEADBEEFL) System.out.print("");  // anti-DCE
        report("Base64URL encode", n, elapsed);
    }

    private static void benchDecodeB64() {
        StandardGenerator g = new StandardGenerator();
        String s = Codec.encodeBase64Url(g.next());
        int n = 5_000_000;
        long start = System.nanoTime();
        long sink = 0;
        for (int i = 0; i < n; i++) {
            sink ^= Codec.decodeBase64Url(s).hashCode();
        }
        long elapsed = System.nanoTime() - start;
        if (sink == 0xDEADBEEFL) System.out.print("");
        report("Base64URL decode", n, elapsed);
    }

    private static void benchEncodeCrockford() {
        StandardGenerator g = new StandardGenerator();
        TesseraId p = g.next();
        int n = 5_000_000;
        long start = System.nanoTime();
        long sink = 0;
        for (int i = 0; i < n; i++) {
            sink ^= Codec.encodeCrockford(p).hashCode();
        }
        long elapsed = System.nanoTime() - start;
        if (sink == 0xDEADBEEFL) System.out.print("");
        report("Crockford encode", n, elapsed);
    }

    private static void benchDecodeCrockford() {
        StandardGenerator g = new StandardGenerator();
        String s = Codec.encodeCrockford(g.next());
        int n = 5_000_000;
        long start = System.nanoTime();
        long sink = 0;
        for (int i = 0; i < n; i++) {
            sink ^= Codec.decodeCrockford(s).hashCode();
        }
        long elapsed = System.nanoTime() - start;
        if (sink == 0xDEADBEEFL) System.out.print("");
        report("Crockford decode", n, elapsed);
    }

    private static void report(String label, long n, long elapsedNanos) {
        double seconds = elapsedNanos / 1_000_000_000.0;
        double opsPerSec = n / seconds;
        System.out.printf("  %-22s  %,12d ops in %5.2f s  ->  %,15.0f ops/sec%n",
            label, n, seconds, opsPerSec);
    }
}
