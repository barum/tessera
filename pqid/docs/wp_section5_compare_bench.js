// Sections covering format comparisons, reference implementations, benchmark data,
// migration guidance, future work, and appendices.
const H = require("./wp_helpers");
const {
  p, h1, h2, h3, code, callout, bullet, numbered, table, spacer,
  ic, tx, bold, it, Paragraph, TextRun,
} = H;

function buildComparison() {
  const out = [];

  // ═══════════════════════════════════════════════════════════════════════
  // PART VIII: Comparative Analysis
  // ═══════════════════════════════════════════════════════════════════════
  out.push(h1("Part VIII: Comparison with Existing Formats"));

  out.push(p([
    tx("PQID is one option among many. This part walks through the formats most likely to be on the table — UUIDv4 [1], UUIDv7 [2], ULID [4], KSUID [5], and Snowflake [6] — and explains where PQID is the better choice and where the existing format is the right answer. The intent is to make the tradeoffs explicit, not to claim that PQID is universally superior."),
  ]));

  out.push(h2("vs UUIDv4 (RFC 4122) [1]"));

  out.push(p([
    tx("UUIDv4 is the universal default, supported in every language's standard library and every database engine. It is 16 bytes, 22 characters Base64URL or 36 characters hyphenated. Its 122 random bits give 61-bit post-quantum security."),
  ]));

  out.push(p([
    bold("PQID wins when: "),
    tx("Time-sortability matters (UUIDv4 is randomly ordered, which destroys B-tree performance), or post-quantum margins matter (61 bits is on the edge), or you want explicit distributed-systems support (UUIDv4 has none)."),
  ]));

  out.push(p([
    bold("UUIDv4 wins when: "),
    tx("Byte cost dominates (UUIDv4 is 2.5× smaller), the existing tooling ecosystem matters (every language's standard library handles UUIDs natively), or you genuinely don't care about ordering (analytical workloads with shuffled access patterns are an example)."),
  ]));

  out.push(h2("vs UUIDv7 (RFC 9562) [2] — the closest competitor, in detail"));

  out.push(p([
    tx("UUIDv7 is the IETF's 2024 response to the demand for time-ordered UUIDs. Of all the formats discussed in this paper, it is the one most likely to be on the table when PQID is being evaluated, because it is the only RFC-standardized time-sortable UUID variant and because it is the format that ships in the language standard libraries published in 2024 and 2025. It deserves a careful comparison rather than a one-line dismissal."),
  ]));

  out.push(h3("Layout and entropy"));

  out.push(p([
    tx("UUIDv7 packs into 16 bytes: 48 bits of millisecond timestamp, 4 bits fixed to the value 7 (version), 12 bits of \"rand_a,\" 2 bits fixed to UUID's standard variant marker, and 62 bits of \"rand_b\" — 74 random bits total, distributed across two non-contiguous fields. Compared to PQID:"),
  ]));

  out.push(table(
    ["Property", "UUIDv7", "PQID"],
    [
      ["Total size",                    "16 bytes (22 chars B64URL)",         "41 bytes (55 chars B64URL)"],
      ["Random bits",                   "74 (12 rand_a + 62 rand_b)",         "256"],
      ["Post-quantum security",         "37 bits (Grover bound)",             "128 bits"],
      ["Timestamp resolution",          "1 ms",                               "1 ms"],
      ["Intra-ms monotonic order",      "Implementation-defined (RFC §6.2)",  "Guaranteed (counter)"],
      ["Distributed-systems variant",   "None (wall-clock only)",             "HLC (variant 0x02)"],
      ["Coordination required",         "No",                                 "No"],
      ["Vendor extensibility",          "None (fixed layout)",                "Variant byte (254 values)"],
    ],
    [3000, 2200, 2200],
  ));

  out.push(h3("The intra-millisecond ordering trap"));

  out.push(p([
    tx("RFC 9562 §6.2 [2] lays out three permissible methods for generating UUIDv7s with monotonic intra-ms ordering. "),
    bold("Method 1"),
    tx(" simply fills rand_a and rand_b with fresh random data on each call — fast, lock-free, but produces IDs that are "),
    it("not"),
    tx(" monotonically ordered within a single millisecond. Two consecutive calls falling in ms T produce IDs ordered randomly relative to each other. The RFC explicitly permits this. "),
    bold("Method 2"),
    tx(" uses a counter in rand_a (12 bits) plus random rand_b. "),
    bold("Method 3"),
    tx(" uses sub-millisecond clock precision in rand_a. Methods 2 and 3 preserve monotonic ordering within a ms; Method 1 does not."),
  ]));

  out.push(p([
    tx("In benchmarks against the Python uuid stdlib (which uses a Method-1-like approach), UUIDv7 sortedness measured 50.18% — statistically indistinguishable from random ordering of consecutive IDs. PostgreSQL's uuidv7() function (added in v18) uses Method 3 and produces fully-sorted IDs. Java's java-uuid-generator library defaults closer to Method 1. Go's standard library does not have v7 at all (third-party only). The implementation choice is invisible from the wire format: a UUIDv7 produced by Method 1 looks identical to one produced by Method 3, and a system that mixes generators across languages cannot recover the ordering guarantee from inspection alone."),
  ]));

  out.push(p([
    tx("PQID's specification mandates intra-ms monotonicity unconditionally. The 16-bit counter at offset 7 increments on every call within the same ms, randomized step + random initial offset, with explicit spin-to-next-ms behavior on counter overflow. There is no implementation-defined alternative; conformant generators produce strictly increasing sequences. The benchmark sortedness against 10,000 consecutive IDs is 100%."),
  ]));

  out.push(callout(
    "Why this matters in practice",
    "Time-sortable identifier formats deliver their value (B-tree locality, replication ordering, log analysis) through the assumption that sorting reflects generation time. UUIDv7 partially honors this assumption between milliseconds but only conditionally honors it within milliseconds, and the conditionality is not visible from the format. In a heterogeneous deployment that spans multiple languages, frameworks, or library versions — exactly the deployment shape of large clusters — the assumption holds for some IDs and fails for others, with no way to distinguish them downstream. PQID makes the guarantee unconditional.",
    "warning",
  ));

  out.push(h3("Wall-clock-only is a real limitation"));

  out.push(p([
    tx("UUIDv7's timestamp is wall-clock milliseconds since the Unix epoch. There is no provision for logical-clock semantics, no field for capturing causal observations from peers, and no drift bound. Two UUIDv7s generated on different nodes whose clocks differ by 50 ms — a routine cross-data-center NTP skew — sort according to wall-clock time, which may or may not reflect causal time."),
  ]));

  out.push(p([
    tx("This is fine for the use cases UUIDv7 was actually designed for: request IDs in a stateless service, primary keys in a single database, span IDs in a distributed trace where the trace itself records causal relationships separately. It is not fine for use cases that need the identifier itself to encode causal ordering: distributed event logs spanning multiple nodes, CRDT version vectors, gradient-update streams in distributed training, multi-agent interaction traces. These cases need HLC semantics, which UUIDv7 cannot provide and PQID's variant 0x02 makes a first-class option."),
  ]));

  out.push(h3("The post-quantum gap"));

  out.push(p([
    tx("UUIDv7's 74-bit random field gives 37 bits of effective security against Grover-style quantum search for a targeted second-preimage. For ephemeral identifiers (request IDs measured in seconds, span IDs measured in milliseconds), 37 bits is more than enough — no plausible attacker has a quantum computer that can find a specific 74-bit value in any window where the identifier remains operationally meaningful. For long-lived identifiers (training-corpus records, audit logs, archival keys, financial transaction identifiers in long-retention systems), 37 bits is genuinely thin in a world where quantum-relevant attackers may exist by 2045–2050. PQID's 128-bit post-quantum margin is calibrated to the same long-horizon threat model that drives NIST's selection of 128-bit symmetric security as the appropriate level through 2030 and beyond."),
  ]));

  out.push(p([
    tx("Pragmatically, this means UUIDv7 is a good choice for transient and operational identifiers, and a worse choice for identifiers that may need to remain unforgeable for decades. The two regimes coexist in most systems — a frontier-AI training run produces both ephemeral request IDs (UUIDv7 fine) and long-archived training-corpus records (UUIDv7 risky). PQID's properties make it suitable for both regimes; the cost is the byte overhead."),
  ]));

  out.push(h3("When UUIDv7 is the right answer"));

  out.push(p([
    tx("Standards compliance matters (UUIDv7 is an RFC, PQID is not yet); the 16-byte fixed size matters; the existing UUID tooling ecosystem (database UUID column types, language UUID libraries, tracing systems built around UUID conventions) provides operational value worth preserving; the use case is operational/transient rather than archival; the deployment is single-tenant with controlled implementation choice; or causal ordering across nodes is genuinely not part of the requirements. For these cases, UUIDv7 is well-designed and PQID is overkill."),
  ]));

  out.push(p([
    tx("When PQID is the right answer: post-quantum margins matter for long-horizon identifier defensibility; intra-millisecond ordering must be guaranteed across heterogeneous implementations; causal ordering across distributed nodes is part of the requirements (HLC variant); or the deployment scale is large enough that the small per-format failures in UUIDv7 (Method-1 sortedness, 37-bit PQ margin) compound into observable defects. Part XI works through the specific case of million-node clusters in detail."),
  ]));

  out.push(h2("vs ULID [4]"));

  out.push(p([
    tx("ULID is a popular community standard (Alizain Feerasta, 2016): 48 bits of ms timestamp + 80 bits of randomness, 16 bytes total. ULID guarantees lexicographic time ordering and provides a Crockford Base32 encoding."),
  ]));

  out.push(p([
    bold("PQID wins when: "),
    tx("Post-quantum margins matter (ULID's 40 post-quantum bits is too thin for new designs targeting 2030+), or distributed-systems semantics matter (ULID is wall-clock only). PQID's design is essentially \"ULID with more entropy and a distributed-systems variant\"; if you like ULID, PQID is the natural upgrade path."),
  ]));

  out.push(p([
    bold("ULID wins when: "),
    tx("Byte cost matters (ULID is 39% smaller than PQID), the broad ecosystem support matters (ULID has libraries in roughly every language now), or post-quantum security is genuinely not a concern for your use case."),
  ]));

  out.push(h2("vs KSUID [5]"));

  out.push(p([
    tx("KSUID (Segment, 2017): 32-bit second timestamp + 128 random bits, 20 bytes total. Time-ordered, but only at second granularity, which means many KSUIDs generated within a single second are ordered randomly relative to each other."),
  ]));

  out.push(p([
    bold("PQID wins when: "),
    tx("Sub-second ordering matters (KSUID does not provide it), post-quantum margins matter (KSUID's 64 bits is on the edge), or distributed-systems semantics matter."),
  ]));

  out.push(p([
    bold("KSUID wins when: "),
    tx("Byte cost matters and you want the largest random field possible at that size (KSUID's 128-bit random field is the largest in the under-32-byte category), or you happen to be on a stack where Segment's KSUID library is already deeply embedded."),
  ]));

  out.push(h2("vs Snowflake [6]"));

  out.push(p([
    tx("Twitter's Snowflake (2010): 41-bit ms timestamp + 10-bit machine ID + 12-bit sequence, packed into a 64-bit integer. Eight bytes total, with the smallest possible representation. Requires coordinated machine-ID assignment."),
  ]));

  out.push(p([
    bold("PQID wins when: "),
    tx("You can't coordinate machine-ID assignment (PQID is uncoordinated; Snowflake requires every generator to have a unique pre-assigned ID), or you need cryptographic-grade uniqueness (Snowflake has zero random bits and zero collision resistance — its uniqueness depends entirely on machine-ID assignment correctness), or distributed-systems semantics matter."),
  ]));

  out.push(p([
    bold("Snowflake wins when: "),
    tx("Bytes are at an absolute premium (8 vs 41 is 5× smaller), and you have a coordination service (e.g., Zookeeper) that can hand out unique machine IDs. For purely intra-database identifiers in a coordinated cluster, Snowflake's compactness is unbeatable."),
  ]));

  out.push(h2("vs TSID"));

  out.push(p([
    tx("TSID (Time-Sorted ID, Mihalcea 2020) is a Snowflake-shape compact identifier with a configurable random portion: 42-bit ms timestamp + 22-bit random/sequence, packed into a 64-bit integer. Eight bytes total. Time-ordered at millisecond granularity, uncoordinated (unlike Snowflake), and time-sortable lexicographically when serialized as Crockford Base32 (13 chars)."),
  ]));

  out.push(p([
    bold("PQID wins when: "),
    tx("Post-quantum margins matter (TSID's 22 random bits give 11 PQ bits, well below comfortable margins), distributed-systems semantics matter (TSID is wall-clock only), or you need stronger collision-resistance margins than a 22-bit random field can provide at high generation rates."),
  ]));

  out.push(p([
    bold("TSID wins when: "),
    tx("Byte cost is the dominant constraint and you still need uncoordinated generation. TSID is what you reach for when Snowflake's coordination cost is unacceptable but Snowflake's 8 bytes is."),
  ]));

  out.push(h2("vs NanoID"));

  out.push(p([
    tx("NanoID (Sitnik 2017): pure random identifiers with no timestamp. Default 21 characters of a custom 64-character alphabet (URL-safe), carrying 126 bits of randomness. Configurable to any length / any alphabet. Time-unordered by design."),
  ]));

  out.push(p([
    bold("PQID wins when: "),
    tx("Time-sortability matters (NanoID has none), distributed-systems semantics matter, or you want the post-quantum margin baked in (NanoID's default 126 bits gives 63 PQ bits; achieving PQID-level 128 PQ bits requires NanoID at 42+ chars, same size class as PQID but without any of the structure)."),
  ]));

  out.push(p([
    bold("NanoID wins when: "),
    tx("You want an opaque, time-unordered, configurable-length token. PQID is one shape; NanoID is a family. For any use case where the identifier should NOT encode time, NanoID is the right tool."),
  ]));

  out.push(h2("Decision Matrix"));

  out.push(p([
    tx("Putting all of the above into a single matrix:"),
  ]));

  out.push(spacer());

  out.push(table(
    ["Concern",                        "UUIDv4", "UUIDv7", "ULID",  "KSUID",  "Snowflake", "TSID",   "NanoID*", "PQID Std", "PQID HLC"],
    [
      ["Random bits",                   "122",   "74",    "80",    "128",    "0",         "22",     "126",     "256",      "256"],
      ["PQ bits (n/2)",                 "61",    "37",    "40",    "64",     "0",         "11",     "63",      "128",      "128"],
      ["Time-sortable",                 "✗",     "Partial","✓",     "(1s)",   "✓",         "✓",      "✗",       "✓",        "✓ (causal)"],
      ["Post-quantum (≥128 bit)",       "✗",     "✗",      "✗",     "✗",      "✗",         "✗",      "✗",       "✓",        "✓"],
      ["No coordination required",      "✓",     "✓",      "✓",     "✓",      "✗",         "✓",      "✓",       "✓",        "✓"],
      ["Causal ordering across nodes",  "✗",     "✗",      "✗",     "✗",      "Partial",   "✗",      "✗",       "✗",        "✓"],
      ["RFC / standard",                "✓",     "✓",      "Comm.", "Comm.",  "Industry",  "Comm.",  "Comm.",   "Prop.",    "Prop."],
      ["Compact (≤20 bytes)",           "✓",     "✓",      "✓",     "✓",      "✓",         "✓",      "✓*",      "✗",        "✗"],
      ["Lock-free per-thread",          "✓",     "✓",      "✓",     "✓",      "✓",         "✓",      "✓",       "✓",        "✗"],
    ],
    [1900, 650, 650, 650, 650, 700, 650, 650, 700, 1200],
  ));

  out.push(p([
    tx("*NanoID is configurable; numbers shown are for the default 21-char form (16 bytes, 126 bits)."),
  ]));

  return out;
}

function buildBenchmarks() {
  const out = [];

  // ═══════════════════════════════════════════════════════════════════════
  // PART IX: Implementation & Benchmarks
  // ═══════════════════════════════════════════════════════════════════════
  out.push(h1("Part IX: Reference Implementations and Benchmarks"));

  out.push(p([
    tx("Four reference implementations accompany this specification: Python (canonical and performance-tuned variants), Go, Rust, and TypeScript (Node 18+ and modern browsers). Each implementation passes a shared test suite covering size, variant byte handling, uniqueness across 100,000 IDs, monotonicity within a generator, encoding round-trips, HLC observation, HLC drift bounds, and clock-clamp behavior. This part documents the design choices in each implementation and presents benchmark results from a single test machine."),
  ]));

  out.push(h2("Implementation Design Notes"));

  out.push(h3("Python"));

  out.push(p([
    tx("Two modules: "),
    ic("pqid"),
    tx(" (clarity-first canonical reference, ~480k ops/s) and "),
    ic("pqid_fast"),
    tx(" (performance-tuned, ~660k ops/s). The fast variant uses "),
    ic("struct.pack"),
    tx(" for binary serialization (faster than chained "),
    ic("int.to_bytes"),
    tx(" calls), pre-binds the urandom and time_ns functions to local names (avoids attribute lookup overhead in the hot loop), and combines the counter step byte and 256-bit random tail into a single "),
    ic("os.urandom(33)"),
    tx(" call (saves one syscall per ID). A bytearray buffer plus memoryview slicing reduces allocation count vs naive bytes concatenation."),
  ]));

  out.push(p([
    tx("Both modules expose the same public API ("),
    ic("new()"),
    tx(", "),
    ic("new_hlc()"),
    tx(", "),
    ic("StandardGenerator"),
    tx(", "),
    ic("HLCGenerator"),
    tx(", "),
    ic("decode()"),
    tx(", "),
    ic("encode_b64()"),
    tx(", "),
    ic("encode_b32()"),
    tx("). Tests run against both to confirm they produce wire-compatible output."),
  ]));

  out.push(h3("Go"));

  out.push(p([
    tx("Single package "),
    ic("pqid"),
    tx(", uses only the standard library ("),
    ic("crypto/rand"),
    tx(", "),
    ic("encoding/base64"),
    tx(", "),
    ic("encoding/binary"),
    tx(", "),
    ic("sync"),
    tx("). Idiomatic Go style with explicit "),
    ic("([SizeBytes]byte, error)"),
    tx(" return values for ID generation; convenience functions ("),
    ic("New"),
    tx(", "),
    ic("MustNew"),
    tx(") wrap the default generator. The Standard generator is unsynchronized internally; package-level "),
    ic("New()"),
    tx(" wraps the default generator in a mutex. The HLC generator is internally locked, as required for correctness."),
  ]));

  out.push(p([
    tx("Crockford Base32 encoder uses bit-shift register accumulation (5-bit chunks shifted out of an 8-bit input stream), avoiding the BigInt arithmetic that the Python implementation uses. Decoder uses a precomputed lookup table for character → value mapping, including lowercase and Crockford ambiguity mappings (I/L → 1, O → 0)."),
  ]));

  out.push(h3("Rust"));

  out.push(p([
    tx("Single crate "),
    ic("pqid"),
    tx(" with two dependencies ("),
    ic("getrandom"),
    tx(", "),
    ic("base64"),
    tx("). The "),
    ic("Pqid"),
    tx(" type is "),
    ic("Copy + Clone + PartialOrd + Ord + Hash"),
    tx(" — passes by value, sorts naturally, hashes correctly. Default and fallible variants of the constructor: "),
    ic("Pqid::new()"),
    tx(" panics on RNG failure (sensible default), "),
    ic("Pqid::try_new()"),
    tx(" returns "),
    ic("Result"),
    tx(" for callers that want explicit error handling."),
  ]));

  out.push(p([
    tx("Thread-local default generators using "),
    ic("thread_local!"),
    tx(" + "),
    ic("Mutex"),
    tx(". Release profile enables LTO and "),
    ic("codegen-units = 1"),
    tx(" for maximum optimization; the result hits 1.57M Standard ops/s and 2.05M HLC ops/s on the test machine."),
  ]));

  out.push(h3("TypeScript"));

  out.push(p([
    tx("Single module, no dependencies. Targets Node 18+ and modern browsers. CSPRNG access is conditional: prefers Node's "),
    ic("crypto.randomFillSync"),
    tx(" when available, falls back to "),
    ic("globalThis.crypto.getRandomValues"),
    tx(" in browsers. Base64URL encoding similarly prefers Node's "),
    ic("Buffer.from(b).toString(\"base64url\")"),
    tx(" when available, falls back to btoa-with-substitution in browsers."),
  ]));

  out.push(p([
    tx("Two subtle correctness issues showed up during implementation and are worth flagging for porters: (1) the HLC update without observation must use l_old >= pt (not l_old > pt) — when the previous logical time equals the current physical time, the counter must increment, not reset. (2) Reading a 32-bit value from bytes via OR-combination requires applying >>> 0 to the FULL OR result, not just the high-byte shift. JavaScript's bitwise OR operates on signed int32, so OR-ing four bytes into the full range produces a negative number that breaks downstream arithmetic. The reference TypeScript implementation in this repository handles both correctly."),
  ]));

  out.push(h2("Benchmark Methodology"));

  out.push(p([
    tx("All benchmarks were run on a single machine with the following configuration:"),
  ]));

  out.push(spacer());

  out.push(code(
    "Platform:    Linux x86_64\n" +
    "CPU:         Intel Xeon (cloud instance, ~2.8 GHz)\n" +
    "Python:      3.12.3 (CPython, no PGO)\n" +
    "Go:          1.22 (default toolchain)\n" +
    "Rust:        1.75 (release build, LTO + codegen-units=1)\n" +
    "Node:        22.22.2"
  ));

  out.push(p([
    tx("Throughput numbers report median ops/sec across 5 trials of 200,000 IDs each, with 10,000 IDs of warm-up before timing started. Sortedness is measured as the percentage of consecutive ID pairs that are in correct lexicographic order, across 10,000 IDs from a single generator. Encoding/decoding throughput is measured against a single fixed sample PQID; the constant-input case is the most favorable for branch prediction and cache behavior, and represents an upper bound on real-world encoding performance."),
  ]));

  out.push(callout(
    "What benchmarks don't tell you",
    "Single-machine micro-benchmarks measure the cost of the algorithm itself, not the cost of the algorithm in production. Real workloads spend most of their time in I/O, serialization, and database calls, with identifier generation a rounding error in the total. The benchmark numbers below are useful for confirming that the algorithm is not pathologically slow (it is not), and for ranking implementations relative to each other (the ranking is stable). They are not useful for capacity planning a real service.",
    "info",
  ));

  out.push(h2("Single-Threaded Throughput"));

  out.push(p([
    tx("Operations per second, single thread:"),
  ]));

  out.push(spacer());

  out.push(table(
    ["Implementation",                  "Standard ops/s", "HLC ops/s", "vs Python (canon.)"],
    [
      ["Python (pqid, canonical)",       "479,370",        "501,097",   "1.00× (baseline)"],
      ["Python (pqid_fast)",             "664,469",        "587,406",   "1.39×"],
      ["Go",                             "980,392",        "1,229,946", "2.04×"],
      ["TypeScript (Node 22)",           "365,512",        "387,039",   "0.76×"],
      ["Rust (release, raw)",            "1,574,661",      "2,050,930", "3.29×"],
    ],
    [3200, 2200, 2000, 1960],
  ));

  out.push(p([
    tx("Two observations from these numbers. First, Rust is roughly 3.3× the Python canonical baseline, which matches typical performance ratios for CSPRNG-bound workloads — most of the time is spent in the kernel's getrandom syscall, and the language's overhead is bounded by how thin a wrapper it puts around the syscall. Second, HLC is roughly 25–30% faster than Standard in Rust, Go, and Python (canonical), but slower in Python (fast) and roughly equal in TypeScript. The reason is that the Standard generator does an extra random-byte derivation for the counter step (1 + (rand_byte & 0x0F)), which the HLC generator skips; the canonical Python implementation amortizes that over the per-call function-call overhead, but the optimized variants don't get the same amortization benefit."),
  ]));

  out.push(h2("Encoding Throughput"));

  out.push(p([
    tx("Encoding/decoding ops per second, single thread:"),
  ]));

  out.push(spacer());

  out.push(table(
    ["Implementation",        "B64URL enc",   "B64URL dec",   "Crockford enc", "Crockford dec"],
    [
      ["Python",               "1,595,367",    "976,214",      "96,875",        "117,568"],
      ["Go",                   "8,032,128",    "—",            "4,640,371",     "—"],
      ["Rust",                 "16,202,352",   "15,001,943",   "7,858,356",     "5,524,504"],
      ["TypeScript",           "3,835,328",    "3,479,239",    "579,527",       "2,408,496"],
    ],
    [3000, 1840, 1840, 1840, 1840],
  ));

  out.push(p([
    tx("Python's Crockford encoder uses BigInt arithmetic (the int type is arbitrary-precision), which is convenient to write but slow; the Rust and Go implementations use bit-shift register accumulation and run roughly 80× and 48× faster respectively. If your application encodes Crockford-form PQIDs in a hot path under Python, prefer the Base64URL form unless the human-readability is essential."),
  ]));

  out.push(h2("Time-Sortedness"));

  out.push(p([
    tx("Percentage of consecutive ID pairs in correct lexicographic order, single thread, 10,000 IDs:"),
  ]));

  out.push(spacer());

  out.push(table(
    ["Format", "% sorted", "Notes"],
    [
      ["UUIDv4 (stdlib)",                "49.90%",  "Random; baseline ~50%."],
      ["UUIDv7 (manual)",                "50.18%",  "Spec permits intra-ms randomization."],
      ["ULID (manual)",                  "100.00%", "By design."],
      ["KSUID (manual)",                 "50.14%",  "1s timestamp + 16 random bytes; intra-second is random."],
      ["PQID Standard (canonical)",      "100.00%", "Counter monotonic within ms."],
      ["PQID Standard (fast)",           "100.00%", "Same."],
      ["PQID HLC (canonical)",           "100.00%", "Counter monotonic within ms."],
      ["PQID HLC (fast)",                "100.00%", "Same."],
    ],
    [3200, 1500, 4660],
  ));

  out.push(h2("Multi-Threaded Throughput"));

  out.push(p([
    tx("Aggregate ops/sec, 8 threads each generating 50,000 IDs (Python only):"),
  ]));

  out.push(spacer());

  out.push(table(
    ["Format",                      "ops/sec",   "vs single-thread"],
    [
      ["UUIDv4 (stdlib)",             "404,524",  "0.98× (no degradation)"],
      ["ULID (locked, manual)",       "570,502",  "0.81×"],
      ["PQID Standard (locked)",      "345,547",  "0.72× (mutex contention)"],
      ["PQID Standard fast (locked)", "441,690",  "0.66× (mutex contention)"],
      ["PQID HLC (canonical)",        "474,749",  "0.95× (internal lock)"],
      ["PQID HLC (fast)",             "562,886",  "0.96× (internal lock)"],
    ],
    [3500, 2400, 3460],
  ));

  out.push(p([
    tx("Two takeaways. First, naively wrapping the Standard generator in an external mutex (which our convenience function does) gives worse multi-threaded scaling than the HLC generator's internal lock, because the HLC lock is held for less time. For workloads that need multi-threaded ID generation, allocate one Standard generator per thread instead of sharing one with a mutex. Second, the GIL is not the bottleneck here — Python's mutex overhead and CSPRNG syscall cost are. The same shape of result appears in every locked-shared-generator benchmark we ran."),
  ]));

  return out;
}

function buildMigration() {
  const out = [];

  // ═══════════════════════════════════════════════════════════════════════
  // PART X: Migration Guide
  // ═══════════════════════════════════════════════════════════════════════
  out.push(h1("Part X: Migration Guide"));

  out.push(p([
    tx("Switching an existing system to PQID is straightforward in principle but worth doing carefully. This part walks through migration from the most common starting points: UUIDv4, UUIDv7, ULID, and integer auto-increment columns."),
  ]));

  out.push(h2("From UUIDv4"));

  out.push(p([
    tx("UUIDv4 → PQID is the most common migration path because it is also the most beneficial: existing UUIDv4 columns lose B-tree locality every time they're written, and switching to PQID restores it. The mechanical steps:"),
  ]));

  out.push(numbered([tx("Add a new column or table column for PQIDs alongside the existing UUID column. Use BYTEA(41), BLOB(41), or CHAR(55) depending on whether you store binary or canonical Base64URL form.")]));
  out.push(numbered([tx("Backfill existing rows with PQIDs whose timestamps reflect the row's actual creation time (extracted from a created_at column, if available). If creation time is unknown, generate at backfill time and accept that historical sort order won't reflect actual creation time.")]));
  out.push(numbered([tx("Update application code to write to both columns for new rows during the transition period.")]));
  out.push(numbered([tx("Update reads to use the PQID column. Verify that no foreign keys, joins, or indexes reference the old UUID column.")]));
  out.push(numbered([tx("After a confidence period, drop the UUID column.")]));

  out.push(p([
    tx("PostgreSQL note: a "),
    ic("BYTEA"),
    tx(" column with PQIDs and a B-tree index will produce significantly better insert performance than an equivalent "),
    ic("UUID"),
    tx(" column with UUIDv4 values, because consecutive PQIDs are clustered. This is often the strongest argument for the migration in the first place."),
  ]));

  out.push(h2("From UUIDv7"));

  out.push(p([
    tx("UUIDv7 already has time-ordering, so the migration is mostly about post-quantum margins, intra-millisecond ordering guarantees, and (for distributed systems) HLC semantics. If your system doesn't need any of those properties and the ecosystem support for UUIDs is genuinely valuable to you, staying on UUIDv7 is a reasonable choice. If you're moving anyway, the mechanical steps are identical to the UUIDv4 case — the migration tooling doesn't care about the source format."),
  ]));

  out.push(h2("From ULID"));

  out.push(p([
    tx("ULID → PQID is the cleanest migration. Both formats are time-sortable in their byte form, and ULID's Crockford encoding sorts identically to its bytes — so does PQID's. The differences are byte cost (16 vs 41) and post-quantum margins (40 vs 128 bits). Migration involves widening the ID column and re-encoding existing values either as zero-padded equivalents in the new wider field (for sort compatibility) or as freshly-generated PQIDs (for clean ID space). When migrating a column whose textual contents are sorted directly by your storage layer, prefer the Crockford encoding; the canonical Base64URL form sorts identically to its bytes only when compared as bytes, not as ASCII text."),
  ]));

  out.push(h2("From integer auto-increment"));

  out.push(p([
    tx("Integer → PQID is a one-way migration: the integer key is lost. The standard pattern is to keep the integer column as a secondary index and add the PQID column as the new primary identifier. New rows get a PQID; existing rows are backfilled. Foreign keys are migrated to reference the PQID column either lazily (as rows are touched) or eagerly (in a single migration). The pattern becomes relevant when the database is being moved from single-instance to distributed (e.g., as part of a sharding project), because integer auto-increment doesn't survive sharding cleanly."),
  ]));

  out.push(h2("Don't Mix Old and New IDs in the Same URLs"));

  out.push(p([
    tx("If your URLs currently embed UUIDs or integers, generating PQIDs for new resources but keeping old IDs in old URLs creates a system where two different identifier shapes coexist forever. Plan a deprecation path. One workable approach: implement a lookup that accepts either format, add aggressive 301 redirects from old-format URLs to new-format URLs, and over time the old-format URLs decay out of search engines and bookmarks. Three to five years later, drop support for the old format."),
  ]));

  return out;
}

function buildScaleAndAI() {
  const out = [];

  // ═══════════════════════════════════════════════════════════════════════
  // PART XI: AI Infrastructure and Million-Node-Cluster Requirements
  // ═══════════════════════════════════════════════════════════════════════
  out.push(h1("Part XI: AI Infrastructure and the Million-Node Regime"));

  out.push(p([
    tx("Frontier AI infrastructure is converging on cluster sizes that the existing identifier formats were not designed for. Training runs spanning hundreds of thousands of GPUs, inference fleets distributed across continents, multi-agent systems with thousands of cooperating models, and federated training pipelines crossing organizational boundaries all share a common property: they emit identifiers at rates and over time horizons where the small design choices in UUIDv4, UUIDv7, ULID, and KSUID start producing observable defects. This part argues that PQID is the correct format for these workloads — not as an aesthetic preference, but because it is the only published format whose properties hold simultaneously at this scale."),
  ]));

  out.push(p([
    tx("The argument is concrete. We work through the requirements that emerge at scale, compute the failure points of each existing format against those requirements, and show that PQID's design choices map directly onto what million-node infrastructure actually needs. The conclusion is not that PQID is universally superior — for ephemeral inference request IDs at small scale, UUIDv7 remains a reasonable choice — but that for the AI infrastructure being built today and over the next decade, PQID is the format that fits."),
  ]));

  out.push(h2("The Workload"));

  out.push(p([
    tx("A million-node training cluster is not a thousand-node cluster scaled up by 1,000×. It is a different regime, with qualitatively different failure modes. Three workload characteristics matter for identifier choice:"),
  ]));

  out.push(h3("Identifier emission rate"));

  out.push(p([
    tx("Each node in a frontier-AI training cluster emits identifiers for many distinct event categories: gradient sync events at ~10 ms cadence, activation checkpoints at ~ms cadence, optimizer-state snapshots, parameter-update events, distributed-trace spans, fault-tolerance heartbeats, communication-pattern logs, and (in observability-heavy deployments) per-layer interpretability traces. A conservative estimate puts each node at 100 IDs/sec sustained; a moderate estimate at 1,000 IDs/sec; an aggressive estimate at 10,000 IDs/sec for runs that capture per-layer activations for interpretability research."),
  ]));

  out.push(table(
    ["Scenario", "Per-node rate", "Aggregate (10⁶ nodes)", "Per-ms cluster-wide", "Total / 6-month run"],
    [
      ["Conservative", "100 IDs/sec",       "10⁸ IDs/sec",  "100,000",     "~1.6 × 10¹⁵"],
      ["Moderate",     "1,000 IDs/sec",     "10⁹ IDs/sec",  "1,000,000",   "~1.6 × 10¹⁶"],
      ["Aggressive",   "10,000 IDs/sec",    "10¹⁰ IDs/sec", "10,000,000",  "~1.6 × 10¹⁷"],
    ],
    [1800, 2000, 2000, 1800, 1760],
  ));

  out.push(p([
    tx("These are not theoretical numbers. The moderate scenario corresponds to current public discussions of frontier-training infrastructure scale, and the aggressive scenario corresponds to research workloads that capture finer-grained traces for safety and interpretability work. The total identifier count over a single 6-month training run lands between 10¹⁵ and 10¹⁷ — within an order of magnitude of UUIDv4's classical birthday-50% threshold (2⁶¹ ≈ 2.3 × 10¹⁸), well above ULID's per-millisecond saturation point, and across the threshold where UUIDv7's 74-bit per-ms field starts producing expected collisions."),
  ]));

  out.push(h3("Geographic distribution"));

  out.push(p([
    tx("A million GPUs cannot be deployed in a single building. Power density, cooling, and bandwidth constraints force frontier clusters to span multiple data centers, often in multiple geographic regions. Cross-region NTP synchronization typically delivers 10–100 ms accuracy; PTP can do better in tightly-coupled environments but does not help across regions. The expected cross-cluster wall-clock skew at this scale is in the 10–100 ms range as a routine operating condition, not an edge case. This is exceeds the 1 ms timestamp resolution of every modern identifier format, which means wall-clock identifiers from different regions can sort in the opposite order from their causal relationship — routinely, by design of the underlying infrastructure."),
  ]));

  out.push(h3("Time horizon"));

  out.push(p([
    tx("A frontier-AI training run is a generational artifact. The training data, model weights, evaluation logs, and provenance records are likely to be subject to regulatory review, legal discovery, academic dispute, and reproducibility audits for decades. The identifiers attached to those records need to remain unique and unforgeable across that horizon. This is the threat model that drives PQID's 256-bit random field: not because quantum computers exist today, but because the identifiers being generated today need to remain defensible against quantum adversaries that may exist in 2045–2050, when training-data deletion requests, copyright disputes, or model-behavior litigation reach the courts."),
  ]));

  out.push(h2("The Four Failures"));

  out.push(p([
    tx("Existing identifier formats fail at million-node scale on at least one of four axes. PQID was designed as a coherent response to all four. The accounting:"),
  ]));

  out.push(h3("Failure 1: Collision math under multi-generator load"));

  out.push(p([
    tx("At 10⁹ aggregate identifier-generations per second (the moderate scenario), the cluster produces 10⁶ IDs per millisecond. Time-prefixed identifier formats limit collisions to draws within the same ms; the relevant collision space is therefore the random field, against 10⁶ concurrent draws."),
  ]));

  out.push(p([
    tx("Apply the standard birthday approximation P(any collision) ≈ k(k−1)/(2·2ⁿ) for k draws in a 2ⁿ space, with k=10⁶ per ms. Multiply by the 1.56 × 10¹⁰ milliseconds in a 6-month run for expected total collisions:"),
  ]));

  out.push(table(
    ["Format", "Random bits", "Per-ms collision prob", "Expected collisions per 6-month run"],
    [
      ["UUIDv7", "74",  "≈ 2.6 × 10⁻¹¹", "≈ 0.41 (single-digit, but non-zero)"],
      ["ULID",   "80",  "≈ 4.1 × 10⁻¹³", "≈ 0.006"],
      ["KSUID",  "128", "< 10⁻²² (per-second window)", "< 10⁻¹⁵"],
      ["PQID",   "256", "< 10⁻⁶⁰",       "Effectively zero at any plausible scale"],
    ],
    [1500, 1400, 2700, 3760],
  ));

  out.push(callout(
    "What 0.41 expected collisions means in practice",
    "An expected value below 1 does not mean collisions cannot happen — it means the probability of one or more collisions over the run is roughly 33% (1 − e⁻⁰·⁴¹). For a $200M+ training run whose output may be litigated decades later, a one-in-three chance of producing a duplicate identifier in the training-data lineage is not acceptable. Silent collisions cause deduplication systems to merge unrelated records, which causes model-behavior bugs whose root cause is essentially undetectable after the fact. PQID's expected collision count over the same workload is below 10⁻⁶⁰ — a safety margin of more than 60 orders of magnitude.",
    "warning",
  ));

  out.push(p([
    tx("UUIDv4 is even worse: its 122-bit random field is not time-prefixed, so all 1.6 × 10¹⁶ identifiers compete for the same collision space. The full-run collision probability is approximately 2.3 × 10⁻⁵ — small in absolute terms, but six orders of magnitude higher than UUIDv7 and astronomically higher than PQID. UUIDv4 is unsuitable for million-node workloads regardless of post-quantum considerations; the classical math alone disqualifies it."),
  ]));

  out.push(h3("Failure 2: Coordination dependency"));

  out.push(p([
    tx("Snowflake-style identifier formats require pre-assigned machine IDs. At 10⁶ nodes, the machine-ID assignment service becomes a critical-path dependency for the entire training run. Even at five-nines availability, the expected ID-issuance downtime over a year is ~5.3 minutes. Across a 6-month training run, that's ~2.6 minutes of expected coordinator-related interruption."),
  ]));

  out.push(p([
    tx("Two minutes of stalled training across a million-node cluster does not just cost two minutes of compute. Distributed training systems require coordinated checkpoint-restart on partial failure, which adds tens of minutes of additional warm-up time. The realistic cost of a single coordinator interruption in a million-node cluster is measured in tens of millions of dollars, even before accounting for the cascading reliability effects of any restart in a tightly-coupled system."),
  ]));

  out.push(p([
    tx("PQID has zero coordination dependencies. Each node generates identifiers from its local CSPRNG with no service to call, no machine ID to assign, no central state to maintain. The failure mode does not exist."),
  ]));

  out.push(h3("Failure 3: Causal ordering across distributed nodes"));

  out.push(p([
    tx("UUIDv7, ULID, KSUID, and Snowflake all use wall-clock timestamps. With cross-region NTP skew in the 10–100 ms range, wall-clock identifiers cannot reliably preserve the causal ordering of events that span multiple regions. Two events related by causation — a gradient update on node A that influences a parameter-server commit on node B — will sort according to the wall clocks of A and B, which may disagree by tens of milliseconds in either direction. The identifier order is independent of the causal order, and there is no way to recover causal order from the identifier alone."),
  ]));

  out.push(p([
    tx("This is not a hypothetical concern at million-node scale. Distributed-training failures, when they happen, are diagnosed by reconstructing the event sequence that led to the failure. Logs from different nodes are reassembled into a unified timeline. If the timestamps in those logs do not reflect causal order, the reconstruction is wrong, and the diagnosis is wrong, and the fix may not address the actual cause. Engineers who have done this work in production at thousand-node scale already know the pain; at million-node scale it becomes intractable."),
  ]));

  out.push(p([
    tx("PQID's HLC variant solves this directly. The Hybrid Logical Clock (Kulkarni et al., 2014) [7] preserves causal ordering across nodes that exchange clock values in their messages — and at million-node scale, every meaningful operation already involves message exchange, so the cost of carrying HLC observations is essentially zero. The 60-second drift bound is well-tuned for this regime: cross-region NTP skew is reliably under that, and any node that drifts further surfaces as a hard failure rather than silent data corruption. Failure recovery becomes tractable because the causal sequence of events is recoverable from the identifiers themselves."),
  ]));

  out.push(h3("Failure 4: Implementation ambiguity"));

  out.push(p([
    tx("RFC 9562 §6.2 permits three different implementation strategies for UUIDv7 with subtly different intra-millisecond ordering properties. The wire format is identical across all three; an implementation that produces randomly-ordered intra-ms IDs (Method 1) emits indistinguishable bytes from one that produces strictly-monotonic intra-ms IDs (Method 3). At million-node scale spanning multiple languages and library versions — Python preprocessors, C++ training kernels, Go orchestration services, Rust storage layers, JavaScript dashboards, GPU-side identifier generation — the spec-permitted variation in intra-ms ordering means UUIDv7's sort guarantee fails for some fraction of identifiers and holds for others, with no way to tell which is which."),
  ]));

  out.push(p([
    tx("PQID's specification mandates intra-ms monotonicity unconditionally. The four reference implementations (Python, Go, Rust, TypeScript) all produce strictly-increasing IDs within a generator within a millisecond. There is no method-selection ambiguity to navigate; conformant generators behave identically. This matters more at million-node scale than anywhere else, because the deployment heterogeneity is unavoidable."),
  ]));

  out.push(h2("Capacity and Cost Analysis"));

  out.push(p([
    tx("PQID's larger size — 41 bytes binary versus 16 for UUIDv7 — has real cost. The honest accounting:"),
  ]));

  out.push(table(
    ["Format", "Bytes/ID", "6-month volume", "vs UUIDv7"],
    [
      ["UUIDv4 / UUIDv7", "16", "~250 PB", "baseline"],
      ["ULID",            "16", "~250 PB", "baseline"],
      ["KSUID",           "20", "~310 PB", "+25%"],
      ["PQID",            "41", "~640 PB", "+155%"],
    ],
    [2000, 1500, 2000, 2160],
  ));

  out.push(p([
    tx("The PQID − UUIDv7 storage delta is roughly 390 PB over a 6-month run at the moderate scenario. At cloud-storage rates of ~$20/TB-year, that's ~$7.8M/year in marginal storage cost. This is real money, but it needs context: the same training run consumes $200M+ in compute, multiple billions of dollars of compute over the model's deployment lifetime, and produces an asset whose business and regulatory implications are measured in tens or hundreds of billions. 0.04% of compute spend is a small price for an identifier scheme that does not silently corrupt data."),
  ]));

  out.push(p([
    tx("The throughput cost is negligible. At Rust's measured 1.57 million PQIDs/sec single-threaded, generating 10⁹ IDs/sec aggregate requires ~640 generator threads cluster-wide — distributed across 10⁶ nodes, that's 0.06% of one core per node. PQID's CPU cost is in the noise relative to forward and backward passes through a frontier model."),
  ]));

  out.push(h2("Specific AI Use Cases"));

  out.push(p([
    tx("The general scale arguments above motivate PQID for any million-node workload. Several specific AI use cases sharpen the case further, because they have requirements that go beyond what general distributed systems demand."),
  ]));

  out.push(h3("Training-data provenance and lineage"));

  out.push(p([
    tx("Frontier model training ingests trillions of tokens drawn from billions of distinct documents, code files, synthetic generations, and human annotations. Each input record needs an identifier that survives ingestion sharding across thousands of GPUs, deduplication, lineage tracking, license auditing, and eventual deletion requests under GDPR [27], CCPA [28], and emerging AI-specific regulations. The identifier is the substrate on which provenance systems attach metadata, audit records, and rights-management information."),
  ]));

  out.push(p([
    tx("PQID's 100% time-sortedness gives ingestion order = sort order without coordination, which makes deduplication and incremental indexing dramatically cheaper at scale. The 256-bit random tail makes the identifier computationally infeasible to forge — which matters when training-data records may need to be defensible in court decades later. The HLC variant gives causal ordering across distributed ingestion pipelines, which matters when data flows through multi-stage processing across multiple regions."),
  ]));

  out.push(h3("Distributed training checkpoints and gradient streams"));

  out.push(p([
    tx("Distributed training at million-node scale produces continuous streams of checkpoints, gradient samples, optimizer-state snapshots, and parameter updates. Every artifact needs a unique identifier; the order in which they were produced (across nodes, not just within a single node) matters for replay, debugging, and reproducibility. Wall-clock timestamps are insufficient for cross-node ordering at this scale; logical-clock semantics are required."),
  ]));

  out.push(p([
    tx("PQID's HLC variant provides exactly this. Gradient-update streams can be tagged with HLC PQIDs that preserve causal order across the entire cluster, regardless of physical clock skew. Replay becomes deterministic because the causal order is recoverable from the identifiers alone, without requiring a separate causality-tracking layer."),
  ]));

  out.push(h3("Multi-agent systems and tool-use traces"));

  out.push(p([
    tx("Agentic AI systems generate massive interaction logs: agent A calls tool B, which produces output passed to agent C, which calls model D. Each step needs a unique identifier; the causal ordering matters more than wall-clock ordering, because agents on different machines may process steps in physical-clock orders that don't reflect the dependency graph. Wall-clock identifiers will routinely sort the steps incorrectly relative to the actual causal sequence, which breaks downstream analysis and replay."),
  ]));

  out.push(p([
    tx("PQID's HLC variant solves this directly. Each agent stamps its emitted events with HLC PQIDs that preserve causal ordering across the whole multi-agent system, regardless of the physical distribution of the agents. The 256-bit random tail also means that agent-emitted identifiers cannot be guessed or forged by adversarial agents in the same system — relevant for systems that mix trusted and untrusted agents."),
  ]));

  out.push(h3("Federated and privacy-preserving training"));

  out.push(p([
    tx("Federated training distributes model updates across organizations or jurisdictions, with each party generating identifiers locally and downstream consumers merging streams without coordination. This is precisely the workload PQID was designed for: uncoordinated generation, time-sortable output, post-quantum-secure randomness. The 256-bit random tail per record is cheap relative to the computational cost of a single forward pass through a frontier model, and provides the unforgeability properties that federated training's adversarial-participant threat model requires."),
  ]));

  out.push(h3("Audit logs for AI safety and compliance"));

  out.push(p([
    tx("The EU AI Act [25], NIST AI RMF [26], and various national frameworks are converging on requirements that AI training and inference systems maintain auditable logs of what data was used, what decisions were made, and when. Auditable means tamper-evident over long horizons, which means identifiers that cannot be silently regenerated to match a fabricated story after the fact. PQID's 256-bit random tail makes \"find another valid PQID with this timestamp prefix\" computationally infeasible — second-preimage requires 2¹²⁸ classical or quantum operations — which means an audit log indexed by PQIDs cannot be forged after the fact, even by the system operator."),
  ]));

  out.push(p([
    tx("UUIDv7's 37-bit post-quantum margin is too thin for this use case: a 2045-era quantum adversary plausibly has the capability to forge UUIDv7-indexed audit records with retroactive timestamps, even without breaking any other cryptographic primitive in the system. PQID's 128-bit margin is the level NIST has designated as appropriate for protecting data through 2030 and beyond [10], and the level the post-quantum signature standards (ML-DSA-44 [12], ML-KEM-512 [11]) are calibrated to."),
  ]));

  out.push(h3("Long-horizon archival of training artifacts"));

  out.push(p([
    tx("Training corpora are now treated as multi-decade assets. The Common Crawl [29] from 2014 is still in active use for some research; archives of pre-2024 Internet text are increasingly valuable as fewer pre-LLM-era texts remain available; model weights and training-data lineage records may need to be retrieved for litigation or regulatory review through 2050 and beyond. Identifier formats chosen today need to remain defensible for that horizon."),
  ]));

  out.push(p([
    tx("PQID's design is the only published format that takes this horizon seriously. Every other format in this paper was designed with a 2010s-2020s threat model in mind; UUIDv7's 2024 standardization explicitly treats post-quantum security as out of scope. PQID is the format whose design constants are calibrated for long-horizon defensibility."),
  ]));

  out.push(h2("Recommendation for AI Infrastructure Teams"));

  out.push(p([
    tx("For teams building infrastructure that will operate at scales above ~10⁵ nodes or generate identifiers above ~10⁸ per second sustained, our recommendation is straightforward: "),
    bold("use PQID HLC as the default identifier format for all training-related events"),
    tx(", not just the obviously-distributed ones. The throughput cost of the HLC mutex is roughly 30% under contention, but at this scale you will be sharding HLC state per-thread anyway (the pattern documented in Part VII), which mostly recovers the throughput. The benefit — uniform causal ordering across every event in the system, regardless of which node generated it — eliminates a class of debugging and reproducibility problems that becomes prohibitively expensive to solve any other way."),
  ]));

  out.push(p([
    tx("For teams operating below this scale or where the use cases are dominated by ephemeral request-level identifiers, UUIDv7 with a Method-3 generator remains a reasonable choice. The format works well within the regime it was designed for. The argument of this part is that the regime emerging in frontier AI infrastructure exceeds that design envelope, and PQID is the format that was designed for the new regime."),
  ]));

  out.push(callout(
    "Scale crossover, in one number",
    "Below ~10⁸ aggregate IDs/sec, UUIDv7's per-ms collision probability is small enough that expected collisions over a multi-year deployment remain below ~10⁻². Above ~10⁹ aggregate IDs/sec sustained, expected collisions over a 6-month deployment cross unity. The crossover is sharp because the formula is quadratic in rate. If your infrastructure plan involves crossing 10⁹ IDs/sec sustained at any point in its operating life, choose PQID now rather than migrate later — identifier-format migrations at scale are operationally expensive in ways that a five-year-younger version of the team will not thank a five-year-older version of the team for.",
    "info",
  ));

  return out;
}

function buildFuture() {
  const out = [];

  // ═══════════════════════════════════════════════════════════════════════
  // PART XII: Future Work
  // ═══════════════════════════════════════════════════════════════════════
  out.push(h1("Part XII: Future Work"));

  out.push(p([
    tx("PQID v1 is intended to be a stable, complete identifier format. Several extensions have been considered and explicitly deferred to a possible v2."),
  ]));

  out.push(h2("ML-DSA Signed Variant (deferred)"));

  out.push(p([
    tx("An earlier draft of PQID included an embedded post-quantum signature using ML-DSA [12]. The draft was dropped because the smallest ML-DSA signature (~3,300 bytes for ML-DSA-44) is two orders of magnitude larger than the identifier itself, and embedding a signature in the identifier conflates identification with authentication. A future variant 0x03 may revisit this with a more compact signature scheme (perhaps a hash-based MAC keyed off a shared secret), but it is not part of v1."),
  ]));

  out.push(h2("Compact 33-Byte Variant (deferred)"));

  out.push(p([
    tx("A 33-byte variant — 6-byte timestamp + 1-byte variant + 2-byte counter + 24-byte (192-bit) random tail — has been discussed for use cases where the 96-bit post-quantum security level is acceptable. The savings (8 bytes binary, 11 characters Base64URL) may be worth it for some use cases. If demand materializes, this would be variant 0x04."),
  ]));

  out.push(h2("Time Authority Variant (deferred)"));

  out.push(p([
    tx("A variant whose timestamp is signed by a trusted time authority (e.g., a Roughtime [24] server, a TSA [17]) would eliminate the timestamp-tampering concern for compliance-sensitive use cases. The signature would have to live outside the 41-byte container, but the identifier could carry a reference to a particular time-authority assertion. This is well outside v1's scope."),
  ]));

  out.push(h2("Standardization"));

  out.push(p([
    tx("PQID is currently a proposed format documented in this paper and four reference implementations. If adoption warrants, the natural next step is an Internet Draft submitted to the IETF, eventually graduating to an RFC. The format itself is stable; the question is whether the ecosystem demand for a new identifier format is large enough to justify the standardization effort. Feedback from early adopters — particularly those operating at the scale described in Part XI — will determine that answer."),
  ]));

  return out;
}

function buildAppendices() {
  const out = [];

  out.push(h1("Appendices"));

  out.push(h2("Appendix A: Test Vectors"));

  out.push(p([
    tx("The following test vectors are derived from a deterministic generator (random field zeroed, timestamp fixed at 1700000000000 = 2023-11-14T22:13:20Z). Implementations should produce identical output for these inputs:"),
  ]));

  out.push(spacer());

  out.push(code(
    "Variant 0x01 (Standard), counter = 0, random = 32 × 0x00:\n" +
    "  Binary  (hex):  018bcfe56800 01 0000\n" +
    "                  0000000000000000000000000000000000000000000000000000000000000000\n" +
    "  Base64URL    :  AYvP5WgAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n" +
    "  Crockford    :  01HF7YAT0004000000000000000000000000000000000000000000000000000000\n" +
    "\n" +
    "Variant 0x02 (HLC), counter = 0, random = 32 × 0x00:\n" +
    "  Binary  (hex):  018bcfe56800 02 0000\n" +
    "                  0000000000000000000000000000000000000000000000000000000000000000\n" +
    "  Base64URL    :  AYvP5WgAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n" +
    "  Crockford    :  01HF7YAT0008000000000000000000000000000000000000000000000000000000\n" +
    "\n" +
    "Variant 0x01 (Standard), counter = 65535 (0xFFFF), random = 32 × 0x00:\n" +
    "  Binary  (hex):  018bcfe56800 01 FFFF\n" +
    "                  0000000000000000000000000000000000000000000000000000000000000000\n" +
    "  Base64URL    :  AYvP5WgAAf__AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n" +
    "  Crockford    :  01HF7YAT0007ZZY000000000000000000000000000000000000000000000000000"
  ));

  out.push(p([
    tx("Implementations are encouraged to add fuzz tests that round-trip random PQIDs through binary, Base64URL, and Crockford encodings and verify the result equals the input. The reference Python implementation includes such tests."),
  ]));

  out.push(h2("Appendix B: Quick Reference Card"));

  out.push(spacer());

  out.push(code(
    "PQID v1 — Quick Reference\n" +
    "─────────────────────────────────────────────────────────────────\n" +
    "Size:           41 bytes binary, 55 chars B64URL, 66 chars B32\n" +
    "Variants:       0x01 = Standard, 0x02 = HLC\n" +
    "Random bits:    256 (= 128-bit post-quantum security)\n" +
    "Timestamp:      48-bit ms since Unix epoch (~8,919-year range)\n" +
    "Counter:        16-bit, big-endian\n" +
    "\n" +
    "Layout:\n" +
    "  [0..6]  TIMESTAMP   48-bit big-endian ms\n" +
    "  [6]     VARIANT     0x01 or 0x02\n" +
    "  [7..9]  COUNTER     16-bit big-endian\n" +
    "  [9..41] RANDOM      256 bits CSPRNG\n" +
    "\n" +
    "Encodings:\n" +
    "  Base64URL (RFC 4648 §5, no padding):\n" +
    "    Alphabet:      A-Z a-z 0-9 - _\n" +
    "    Length:        55 characters\n" +
    "    Use case:      URLs, JSON, headers, machine-to-machine\n" +
    "\n" +
    "  Crockford Base32:\n" +
    "    Alphabet:      0123456789ABCDEFGHJKMNPQRSTVWXYZ\n" +
    "    Length:        66 characters (uppercase)\n" +
    "    Case:          Insensitive on decode\n" +
    "    Use case:      Human transcription, log lines, CLI\n" +
    "\n" +
    "HLC parameters (variant 0x02):\n" +
    "  Drift bound:    60,000 ms (configurable)\n" +
    "  Counter:        bumped on logical-time stasis, reset on advance\n" +
    "  Lock:           required around (l, c) state updates"
  ));

  out.push(h2("Appendix C: Example PQIDs from the Reference Implementations"));

  out.push(p([
    tx("Twelve sample PQIDs generated by the Python reference implementation in the same millisecond, presented in their Crockford Base32 form. Crockford encoding is used here because (unlike canonical Base64URL) its alphabet is monotonic in ASCII codepoint order, so sorting these strings as plain text yields the same order as sorting them by generation timestamp:"),
  ]));

  out.push(spacer());

  out.push(code(
    "01KQQK374T040AXPGKVYCTE3TAZPVB8HSRP9V5YRE2XPDJFGPMVY6JVGHF6ZWQGMK8\n" +
    "01KQQK374T040BH4S4D3DMKBTFAAKG7EJDCKPXET06QGXDVX53G5WXSJV0WSGC78CC\n" +
    "01KQQK374T040BKJ468BKNPP49WRVWSBZFVPZQ7KNXX608SEDTP6ARK762N7ACVJZ7\n" +
    "01KQQK374T040C44P8EDP3T7WTJ8ZRYPWXERXDGWVJJ7BE3ZAVPN22SPS0C7CTXYSE\n" +
    "01KQQK374T040CGXHVXN7232Z9C6R5T4B5TKRMWGRWMWNRB2932APHZNJ97XKJ0JH6\n" +
    "01KQQK374T040CST5EC8JEATBS7ZH25JMJFNSKVHGY8XB53H90YPE63KF17M1BZ4J0\n" +
    "01KQQK374T040CYS92HK4CA6CZ27HAKQF6A54R0TDATXXCWRHWXHQSD5Q1PAX2P1HG\n" +
    "01KQQK374T040DEYJZE7YHS1SP3Z1Q7BQPP1R5DEZ70PAM02MNKPG514BBZ2G1R9NZ\n" +
    "01KQQK374T040E5324GTJZ30W7T5ZR4DAVWDQ5KKVQYAEE89NAXPNXXNGA3DZ3Q5NJ\n" +
    "01KQQK374T040F4F3S1RYV46C66ZR6P3DHKPX686BJMFW8A58BHHQFEASG56TYNBP8\n" +
    "01KQQK374T040FYTPB5XW7MNMK7APP3EDT5GHSNS48NV4P3R9GPAQDW8B78XR58ZZB\n" +
    "01KQQK374T040G9AKCYMBWX440XAG0HWRH2CAPZ5AD0TMQAHSF6742KG8W4D3TKX89"
  ));

  out.push(p([
    tx("The first 13 characters of each ID are visually identical: they encode the timestamp + variant + counter-high-byte prefix, which is shared across the batch (all twelve IDs were generated in the same millisecond). The remaining 53 characters encode the counter low byte and the random tail and differ between IDs. Each ID round-trips cleanly through decode_b32() to a 41-byte binary form whose bytes are in the same lexicographic order as the strings shown."),
  ]));

  out.push(h2("Appendix D: References"));

  out.push(spacer());

  out.push(p([
    tx("References cited in the body of this paper. Each entry is numbered for inline citation; numbers in square brackets in the body text (for example, "),
    bold("[1]"),
    tx(" or "),
    bold("[1, 5]"),
    tx(") refer to entries in this list."),
  ]));

  out.push(spacer());

  out.push(table(
    ["#", "Reference"],
    [
      ["[1]",  "Leach, P., Mealling, M., Salz, R. \"A Universally Unique IDentifier (UUID) URN Namespace.\" RFC 4122, IETF, July 2005. https://www.rfc-editor.org/rfc/rfc4122"],
      ["[2]",  "Davis, K., Peabody, B., Leach, P. \"Universally Unique IDentifiers (UUIDs).\" RFC 9562, IETF, May 2024. (Defines UUIDv6, UUIDv7, UUIDv8; obsoletes RFC 4122.) https://www.rfc-editor.org/rfc/rfc9562"],
      ["[3]",  "Josefsson, S. \"The Base16, Base32, and Base64 Data Encodings.\" RFC 4648, IETF, October 2006. https://www.rfc-editor.org/rfc/rfc4648"],
      ["[4]",  "Feerasta, A. et al. \"ULID — Universally Unique Lexicographically Sortable Identifier.\" Community specification, 2016. https://github.com/ulid/spec"],
      ["[5]",  "Segment Inc. \"KSUID: K-Sortable Globally Unique IDs.\" Open-source library and specification, 2017. https://github.com/segmentio/ksuid"],
      ["[6]",  "Twitter Engineering. \"Announcing Snowflake.\" Engineering blog post, 1 June 2010. (Describes the 64-bit time-ordered ID format with 41-bit timestamp + 10-bit machine ID + 12-bit sequence.) https://blog.x.com/engineering/en_us/a/2010/announcing-snowflake"],
      ["[7]",  "Kulkarni, S., Demirbas, M., Madappa, D., Avva, B., Leone, M. \"Logical Physical Clocks and Consistent Snapshots in Globally Distributed Databases.\" Technical Report 2014-04, Department of Computer Science and Engineering, University at Buffalo (SUNY), 2014. (The Hybrid Logical Clock paper.) https://cse.buffalo.edu/tech-reports/2014-04.pdf"],
      ["[8]",  "Grover, L. K. \"A fast quantum mechanical algorithm for database search.\" Proceedings of the 28th Annual ACM Symposium on Theory of Computing (STOC '96), pp. 212–219, 1996. arXiv:quant-ph/9605043. https://arxiv.org/abs/quant-ph/9605043"],
      ["[9]",  "Brassard, G., Høyer, P., Tapp, A. \"Quantum cryptanalysis of hash and claw-free functions.\" LATIN '98: Theoretical Informatics, LNCS vol. 1380, pp. 163–169, Springer, 1998. (Original conference talk 1997.) Also arXiv:quant-ph/9705002."],
      ["[10]", "Barker, E. \"Recommendation for Key Management: Part 1 — General.\" NIST Special Publication 800-57 Part 1, Revision 5, May 2020. https://doi.org/10.6028/NIST.SP.800-57pt1r5"],
      ["[11]", "NIST. \"Module-Lattice-Based Key-Encapsulation Mechanism Standard.\" FIPS Publication 203, August 2024. (Defines ML-KEM, formerly known as CRYSTALS-Kyber.) https://doi.org/10.6028/NIST.FIPS.203"],
      ["[12]", "NIST. \"Module-Lattice-Based Digital Signature Standard.\" FIPS Publication 204, August 2024. (Defines ML-DSA, formerly known as CRYSTALS-Dilithium.) https://doi.org/10.6028/NIST.FIPS.204"],
      ["[13]", "Crockford, D. \"Base 32.\" Personal specification, 2002 (revised). (Defines the human-typable Base32 alphabet 0-9 + A-Z minus I, L, O, U, with case-insensitive decoding.) https://www.crockford.com/base32.html"],
      ["[14]", "Mills, D., Martin, J., Burbank, J., Kasch, W. \"Network Time Protocol Version 4: Protocol and Algorithms Specification.\" RFC 5905, IETF, June 2010. https://www.rfc-editor.org/rfc/rfc5905"],
      ["[15]", "IEEE. \"IEEE Standard for a Precision Clock Synchronization Protocol for Networked Measurement and Control Systems.\" IEEE Std 1588-2019. (PTP version 2.1.) https://standards.ieee.org/ieee/1588/6825/"],
      ["[16]", "Krawczyk, H., Bellare, M., Canetti, R. \"HMAC: Keyed-Hashing for Message Authentication.\" RFC 2104, IETF, February 1997. https://www.rfc-editor.org/rfc/rfc2104"],
      ["[17]", "Adams, C., Cain, P., Pinkas, D., Zuccherato, R. \"Internet X.509 Public Key Infrastructure Time-Stamp Protocol (TSP).\" RFC 3161, IETF, August 2001. https://www.rfc-editor.org/rfc/rfc3161"],
      ["[18]", "Jones, M., Bradley, J., Sakimura, N. \"JSON Web Token (JWT).\" RFC 7519, IETF, May 2015. https://www.rfc-editor.org/rfc/rfc7519"],
      ["[19]", "Chandy, K. M., Lamport, L. \"Distributed Snapshots: Determining Global States of Distributed Systems.\" ACM Transactions on Computer Systems, vol. 3, no. 1, pp. 63–75, February 1985. https://doi.org/10.1145/214451.214456"],
      ["[20]", "Cockroach Labs. \"CockroachDB Architecture: Time and Hybrid Logical Clocks.\" Technical documentation. (Production use of HLC for distributed transactions.) https://www.cockroachlabs.com/docs/stable/architecture/transaction-layer.html"],
      ["[21]", "PASETO Working Group. \"PASETO: Platform-Agnostic Security Tokens.\" Specification at paseto.io, 2018–present. https://paseto.io/"],
      ["[22]", "NIST. \"Advanced Encryption Standard (AES).\" FIPS Publication 197 (Updated), May 2023. https://doi.org/10.6028/NIST.FIPS.197-upd1"],
      ["[23]", "NIST. \"Secure Hash Standard (SHS).\" FIPS Publication 180-4, August 2015. (Defines SHA-256, SHA-384, SHA-512.) https://doi.org/10.6028/NIST.FIPS.180-4"],
      ["[24]", "Roughtime Working Group. \"Roughtime: Securing Time with Digital Signatures.\" Internet-Draft draft-ietf-ntp-roughtime, IETF, in progress. https://datatracker.ietf.org/doc/draft-ietf-ntp-roughtime/"],
      ["[25]", "European Parliament and Council. \"Regulation (EU) 2024/1689 of the European Parliament and of the Council laying down harmonised rules on artificial intelligence (Artificial Intelligence Act).\" Official Journal of the European Union, 12 July 2024. https://eur-lex.europa.eu/eli/reg/2024/1689/oj"],
      ["[26]", "NIST. \"Artificial Intelligence Risk Management Framework (AI RMF 1.0).\" NIST AI 100-1, January 2023. https://doi.org/10.6028/NIST.AI.100-1"],
      ["[27]", "European Parliament and Council. \"Regulation (EU) 2016/679 (General Data Protection Regulation).\" Official Journal of the European Union, 27 April 2016. https://eur-lex.europa.eu/eli/reg/2016/679/oj"],
      ["[28]", "California State Legislature. \"California Consumer Privacy Act of 2018 (CCPA).\" California Civil Code §§ 1798.100 et seq. https://oag.ca.gov/privacy/ccpa"],
      ["[29]", "Common Crawl Foundation. \"Common Crawl: An open repository of web crawl data.\" Foundation website and dataset releases, 2008–present. https://commoncrawl.org/"],
    ],
    [600, 8760],
  ));

  out.push(h2("Appendix E: Glossary of Terms"));

  out.push(p([
    tx("Definitions of acronyms, named algorithms, and technical terms used in this paper. Where a term has a canonical reference (RFC, paper, vendor specification), it is also listed in Appendix D."),
  ]));

  out.push(spacer());

  out.push(table(
    ["Term", "Definition"],
    [
      ["Base32, Base64",
       "Binary-to-text encoding schemes that map raw bytes to printable characters. Base32 packs 5 bits per character (32-character alphabet); Base64 packs 6 bits per character (64-character alphabet). Defined for general use by RFC 4648."],

      ["Base64URL",
       "The URL-and-filename-safe variant of Base64 specified in RFC 4648 §5. Uses the alphabet A-Z, a-z, 0-9, '-', '_' (the standard '+' and '/' are replaced to make the output safe for URLs and filenames). PQID's canonical text encoding."],

      ["BHT (Brassard-Hoyer-Tapp)",
       "A 1997 quantum algorithm for finding collisions in a hash function or random-output space. Costs ~2^(n/3) operations for an n-bit space, compared to ~2^(n/2) classically. Relevant to the post-quantum analysis of identifier formats but less so than Grover for the targeted-attack threat model."],

      ["BIGSERIAL",
       "PostgreSQL's auto-incrementing 64-bit integer column type. Mentioned in Part I as the simpler alternative to PQID for single-database, single-tenant systems."],

      ["Birthday bound",
       "The probabilistic result that, in a uniformly random space of size 2^n, a 50% probability of any collision arrives after roughly √(π/2) · 2^(n/2) random draws — far sooner than the 2^n that intuition might suggest. Named after the birthday paradox. The basis of PQID's collision-probability analysis."],

      ["B-tree",
       "A self-balancing tree data structure used as the dominant index type in relational databases (PostgreSQL, MySQL, SQLite, SQL Server). B-tree inserts are cheap when keys arrive in sorted order (consecutive inserts touch the same leaf page) and expensive when keys are random (each insert touches a different leaf). Time-sortable identifiers like PQID, ULID, and UUIDv7 exist largely to keep B-trees cheap to maintain."],

      ["CSPRNG",
       "Cryptographically-Secure Pseudo-Random Number Generator. A random-number source whose output is computationally indistinguishable from true randomness, even to an attacker who has observed prior outputs. Operating system CSPRNGs include /dev/urandom (Linux), arc4random (BSD/macOS), and BCryptGenRandom (Windows). PQID's 32-byte random tail must come from a CSPRNG."],

      ["Crockford Base32",
       "A Base32 variant designed by Douglas Crockford specifically for human transcription. Uses the alphabet 0-9 then A-Z minus the letters I, L, O, and U (which are visually ambiguous with 1, 0, and V). Decoders treat case as insignificant and may accept I/L as 1 and O as 0. The alphabet is monotonic in ASCII codepoints, so Crockford strings sort identically to their decoded bytes. PQID's human-typable encoding."],

      ["Epoch (Unix epoch)",
       "00:00:00 UTC on 1 January 1970. The reference point from which Unix-style timestamps are counted. PQID's 48-bit timestamp field is milliseconds since this epoch."],

      ["Grover's algorithm",
       "Lov Grover's 1996 quantum search algorithm. Searches an unstructured space of 2^n candidates in O(2^(n/2)) operations — a quadratic speedup over classical brute-force search. The reason post-quantum security of an n-bit random field is approximately n/2 bits."],

      ["HLC (Hybrid Logical Clock)",
       "A clock construction by Kulkarni, Demirbas, Madappa, Avva, and Leone (2014) that combines wall-clock time with a logical counter to preserve causal ordering across distributed nodes. An HLC reading is always at least the maximum of the local wall clock and any HLC value the node has observed from a peer. PQID variant 0x02 embeds an HLC."],

      ["HMAC",
       "Hash-based Message Authentication Code (RFC 2104). A symmetric construction that proves a message was produced by a holder of a secret key. PQID does not include an HMAC; if integrity protection is required, the PQID belongs inside an HMAC'd container."],

      ["IETF",
       "Internet Engineering Task Force. The standards body that publishes RFCs (Requests for Comments). Mentioned in Part XII as the natural standardization path for PQID."],

      ["JWT (JSON Web Token)",
       "RFC 7519. A signed JSON-based token format used for authentication. Mentioned in Part I as the appropriate place for digital signatures, contrasted with PQID, which is unsigned."],

      ["KSUID (K-Sortable Unique IDentifier)",
       "A 20-byte time-sortable identifier format published by Segment in 2017 (github.com/segmentio/ksuid). 32-bit second-resolution timestamp + 128-bit random payload. Compared to PQID throughout Part VIII."],

      ["Lexicographic order",
       "Dictionary order applied to byte strings: compare position by position until a difference is found, longer strings sort after their prefixes. The sense in which PQIDs are 'sortable' — sort 41-byte PQIDs as bytes and you get them in generation order."],

      ["ML-DSA, ML-KEM",
       "Module-Lattice-Based Digital Signature Algorithm (FIPS 204) and Key-Encapsulation Mechanism (FIPS 203). The post-quantum signature and key-exchange algorithms standardized by NIST in 2024. Mentioned in Part XII as the basis of a deferred signed PQID variant."],

      ["Monotonic clock",
       "A clock guaranteed to advance forward, never backward, and never to repeat a value. Distinct from a wall clock, which can jump backward (NTP correction, leap second, manual adjustment). PQID's Standard generator clamps its timestamp against local regression to deliver per-generator monotonicity."],

      ["MVCC (Multi-Version Concurrency Control)",
       "A database concurrency-control technique in which writes create new versions of rows rather than overwriting old ones, with version numbers used to determine which version a given transaction sees. CockroachDB's MVCC layer uses HLC internally; mentioned in Part IV."],

      ["NIST SP 800-57",
       "U.S. National Institute of Standards and Technology Special Publication 800-57, 'Recommendation for Key Management.' Designates 128-bit symmetric security as appropriate for protecting data through 2030 and beyond — the basis of PQID's 256-bit-random-field choice."],

      ["NTP (Network Time Protocol)",
       "RFC 5905. The Internet's standard clock-synchronization protocol. Achieves ~1 ms accuracy in controlled data centers and 10–100 ms accuracy across the open Internet. The reason millisecond-resolution timestamps are the practical floor for cross-machine ordering."],

      ["PASETO",
       "Platform-Agnostic Security Tokens (paseto.io). A signed token format positioned as an alternative to JWT, with stronger cryptographic defaults. Mentioned in Part I as an appropriate location for digital signatures."],

      ["PRNG",
       "Pseudo-Random Number Generator. A deterministic algorithm that produces a sequence of output values that pass statistical randomness tests. Distinct from a CSPRNG: a PRNG without cryptographic guarantees (Mersenne Twister, Linear Congruential Generator, Math.random) is unsuitable for PQID."],

      ["PTP (Precision Time Protocol)",
       "IEEE 1588. A clock-synchronization protocol that achieves sub-microsecond accuracy in tightly-controlled environments (data center, aerospace). Mentioned in Part VII as a tighter alternative to NTP for systems that need it."],

      ["RFC",
       "Request for Comments. The IETF's document series for Internet standards. Specific RFCs cited in this paper: 4122 (UUID), 9562 (UUIDv7/v8), 4648 (Base16/32/64), 7519 (JWT), 2104 (HMAC), 5905 (NTP), 3161 (Time-Stamping)."],

      ["Second-preimage attack",
       "A cryptographic attack in which an adversary, given a value x, attempts to find a different value x' that hashes (or maps) to the same output. The threat model that matters for identifier collisions: an attacker wants to generate a PQID matching a specific known PQID, not just any two PQIDs that collide. Quantum cost is 2^(n/2) for an n-bit field (Grover bound), giving PQID's 256-bit random tail 128 bits of effective second-preimage security."],

      ["Snowflake",
       "Twitter's 2010 64-bit identifier format: 41-bit timestamp + 10-bit machine ID + 12-bit sequence number. Time-sortable but coordination-dependent (machine IDs must be assigned externally). Compared to PQID in Part VIII."],

      ["Spin (busy-wait)",
       "An implementation technique in which a thread loops checking a condition rather than sleeping. PQID's Standard generator spins to the next millisecond if its 16-bit counter overflows within a single millisecond. Cheap because the spin is bounded to less than 1 ms in practice."],

      ["TAI (International Atomic Time)",
       "A continuous timescale based on atomic clocks. UTC is TAI minus an integer number of leap seconds. Mentioned in passing in the wall-clock vs logical-clock discussion."],

      ["TSA (Time-Stamping Authority)",
       "RFC 3161. A trusted service that issues signed assertions of the time at which a piece of data was presented. Mentioned in Part XII as the basis of a deferred 'signed timestamp' variant."],

      ["ULID (Universally Unique Lexicographically Sortable Identifier)",
       "A 16-byte time-sortable identifier format published by Alizain Feerasta in 2016 (github.com/ulid/spec). 48-bit millisecond timestamp + 80-bit random payload. Encoded in Crockford Base32. PQID's design is heavily influenced by ULID; compared throughout Part VIII."],

      ["UTC (Coordinated Universal Time)",
       "The civil time standard, equal to TAI minus an integer number of leap seconds, kept within ~0.9 seconds of mean solar time at the prime meridian. The Unix epoch is defined in UTC."],

      ["UUID",
       "Universally Unique IDentifier. A family of 128-bit identifier formats specified by RFC 4122 (versions 1–5) and RFC 9562 (versions 6–8). PQID is not a UUID, though Part VIII compares it directly to UUIDv4 and UUIDv7."],

      ["Variant byte",
       "PQID's 8-bit field at offset 6 that selects between generation algorithms sharing the same wire format. 0x01 = Standard (wall-clock), 0x02 = HLC. Other values are reserved for future PQID variants or vendor extensions. The design lever that lets PQID evolve without breaking existing decoders."],

      ["Wall clock",
       "A clock that tracks civil time and can be set forward or backward (by NTP, manual adjustment, or VM migration). Distinct from a monotonic clock. PQID's Standard variant uses a wall clock with explicit clamping against backward regression."],
    ],
    [2200, 7160],
  ));

  return out;
}

module.exports = { buildComparison, buildBenchmarks, buildMigration, buildScaleAndAI, buildFuture, buildAppendices };
