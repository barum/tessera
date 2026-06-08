// Sections covering rationale ("why each choice") and decision guidance ("when").
const H = require("./wp_helpers");
const {
  p, h1, h2, h3, code, callout, bullet, numbered, table, spacer,
  ic, tx, bold, it, Paragraph, TextRun,
} = H;

function buildRationale() {
  const out = [];

  // ═══════════════════════════════════════════════════════════════════════
  // PART III: Why Each Choice
  // ═══════════════════════════════════════════════════════════════════════
  out.push(h1("Part III: Why Each Choice"));

  out.push(p([
    tx("Specifications often present numeric choices as if they fell from the sky. This part walks through each significant number in TesseraID and explains why that number, and not a slightly different one, is in the spec. The intent is to give future implementers enough context to evaluate proposed extensions and to give reviewers enough material to push back if the reasoning fails to convince."),
  ]));

  out.push(h2("Why 256 Bits of Randomness?"));

  out.push(p([
    tx("The standard collision argument for n-bit random identifiers is the birthday bound: the probability of any collision approaches 50% after roughly 2"),
    new TextRun({ text: "n/2", size: 22, superScript: true }),
    tx(" generations. UUIDv4's 122 random bits give a 50% collision probability around 2"),
    new TextRun({ text: "61", size: 22, superScript: true }),
    tx(" ≈ 2.3 × 10"),
    new TextRun({ text: "18", size: 22, superScript: true }),
    tx(" identifiers — generously enough for any classical use case. The post-quantum analysis is different. Grover's algorithm searches an n-bit space in 2"),
    new TextRun({ text: "n/2", size: 22, superScript: true }),
    tx(" steps; combined with a quantum birthday attack (BHT, 1997) [9] the effective security against quantum collision-finding is approximately 2"),
    new TextRun({ text: "n/3", size: 22, superScript: true }),
    tx(" — though for the use case that matters here, namely targeted second-preimage (\"find another TesseraID with the same random field as this one\"), the quantum cost is 2"),
    new TextRun({ text: "n/2", size: 22, superScript: true }),
    tx(", giving each random bit half its classical value."),
  ]));

  out.push(p([
    tx("That gives the rule of thumb that the field's effective security under quantum search is "),
    bold("half its bit length"),
    tx(". UUIDv4: 61 bits. UUIDv7: 37 bits. ULID: 40 bits. KSUID: 64 bits. TesseraID: 128 bits. The 128-bit target is not arbitrary; it is the level NIST has designated as adequate for symmetric cryptographic primitives through 2030 and beyond [10], and it is the level the post-quantum signature standards (ML-DSA-44 [12], ML-KEM-512 [11]) are calibrated to. Choosing less for a new identifier means accepting that the identifier becomes the weakest cryptographic component of any system that combines it with AES-128 [22] or stronger."),
  ]));

  out.push(p([
    tx("Could a smaller field have worked? Probably yes, in narrow circumstances. But identifier formats are sticky — once millions of records are created with a given format, migrating away is expensive — and the cost of overshooting on entropy is sixteen extra bytes per identifier. In an era where average JSON payloads are kilobytes, the cost is genuinely negligible compared to the cost of regretting an undersized random field a decade from now."),
  ]));

  out.push(callout(
    "Birthday math, concrete numbers",
    "Apply the standard birthday bound to the 256-bit random field: a 50% probability of any collision arrives after roughly √(π/2) · 2^128 ≈ 4.27 × 10^38 generations. At one billion TesseraIDs generated per second (more than the entire AWS S3 namespace per day), the expected time to a single random-field collision is approximately 1.35 × 10^22 years — about one trillion times the current age of the universe. The 256-bit field is not a marketing number; it is genuinely beyond the reach of any plausible attacker, including ones with quantum computers operating at theoretical limits.",
    "info",
  ));

  out.push(h2("Why Milliseconds, Not Microseconds or Nanoseconds?"));

  out.push(p([
    tx("It is tempting to put a higher-resolution clock in the timestamp field. A 48-bit nanosecond timestamp gives a range of about 78 hours, so that's not an option, but a 64-bit nanosecond field is workable. Why not use it?"),
  ]));

  out.push(p([
    tx("The argument against is that finer resolution creates an "),
    it("illusion"),
    tx(" of ordering that the underlying clock infrastructure cannot deliver. NTP synchronizes machine clocks to roughly 1ms in a controlled data center and 10–100ms across the open internet. A nanosecond timestamp on a machine whose clock is 10ms off NTP is precise to nine decimal places about a value that is wrong in the third. Worse, two events on different nodes that occurred 1µs apart in physical time will routinely receive nanosecond timestamps from those nodes that order them hundreds of milliseconds in the wrong direction. The fine granularity is mathematically expressive but causally meaningless."),
  ]));

  out.push(p([
    tx("Millisecond resolution is roughly the floor below which clock synchronization stops being useful. TesseraIDs generated within the same millisecond are disambiguated by the per-generator counter, which is monotonic by construction; TesseraIDs generated more than a millisecond apart are ordered correctly to within the synchronization quality of the underlying clocks. Going finer doesn't help and arguably hurts."),
  ]));

  out.push(p([
    tx("If you genuinely need finer ordering across nodes — closer to single-microsecond — the right tool is the HLC variant, which captures causal ordering through message exchange rather than relying on synchronized clocks. The Standard variant accepts that wall-clock granularity below a millisecond is a fiction and stops there."),
  ]));

  out.push(h2("Why a Variant Byte?"));

  out.push(p([
    tx("Two design choices were considered for the relationship between Standard and HLC TesseraIDs: separate identifier formats with separate names, or a single format with a discriminator byte. The variant-byte approach won on three grounds."),
  ]));

  out.push(p([
    bold("Wire-format compatibility. "),
    tx("Both variants are 41 bytes, both encode and decode identically, and both are lexicographically sortable. A consumer that has no opinion about whether an identifier was generated against a wall clock or an HLC can treat all TesseraIDs as opaque sortable bytes; only consumers that care about the timestamp's semantics need to read the variant byte. This minimizes the surface area producers and consumers must agree on."),
  ]));

  out.push(p([
    bold("Database column compatibility. "),
    tx("A single column type (CHAR(55), BYTEA(41), or whatever) holds both variants. Mixing variants in the same table is permitted and the rows still sort correctly across variants — though we caution users against doing this in practice (see Part VII for why mixing HLC and Standard TesseraIDs in the same ordered stream introduces some subtle gotchas)."),
  ]));

  out.push(p([
    bold("Future-proofing. "),
    tx("The variant byte gives 254 unused values for future TesseraID variants without breaking the 41-byte commitment. If we discover in 2030 that 256 bits of randomness is no longer enough, we can define a variant 0x03 with a different layout — perhaps 384 random bits at the cost of a smaller timestamp range — and existing decoders will reject it cleanly rather than silently misinterpreting it. The discipline is: every variant MUST share the 6-byte timestamp at offset 0 (so byte-comparison ordering is preserved across variants), but the rest of the layout is free to evolve."),
  ]));

  out.push(p([
    tx("The cost is one byte per identifier — a price we are happy to pay for the option value of future evolution and the immediate value of letting Standard and HLC coexist in a single deployable format."),
  ]));

  out.push(h2("Why HLC as a Co-Equal Variant, Not an Optional Extension?"));

  out.push(p([
    tx("Hybrid Logical Clocks (Kulkarni et al., 2014) [7] are not a new idea, but they are conspicuously absent from existing identifier formats. ULID, KSUID, and UUIDv7 all use wall-clock timestamps with no logical-clock layer. A few production systems (CockroachDB [20], MongoDB cluster time, FoundationDB) have built HLCs internally but not exposed them in their identifier formats."),
  ]));

  out.push(p([
    tx("TesseraID elevates HLC to a co-equal variant rather than an extension because we believe distributed-systems use cases are common enough — and HLC's semantic value clear enough — that the format should make HLC a first-class option. The Standard variant remains the default for the 95% of cases where wall-clock semantics are what users actually want; the HLC variant is there for the 5% where causal ordering across nodes is a real requirement."),
  ]));

  out.push(p([
    tx("A subtle but important property of this design: a system can start with Standard TesseraIDs and upgrade individual generators or services to HLC without rewriting consumers. The wire format is unchanged, the encoding is unchanged, and lexicographic ordering still works. Consumers that want to take advantage of HLC's causal ordering can read the variant byte; consumers that don't can ignore it."),
  ]));

  out.push(h2("Why Two Encodings?"));

  out.push(p([
    tx("Base64URL is the canonical encoding because it is the most efficient encoding that is safe in URLs, JSON, headers, and most filesystems. At 55 characters, it is also short enough to remain workable in primary-key columns and log lines. It is the format that should appear in serialized data, network protocols, and storage."),
  ]));

  out.push(p([
    tx("Crockford Base32 exists for two related use cases. The first is human transcription. The Base64URL alphabet contains characters that are visually ambiguous in many fonts (lowercase l vs uppercase I, lowercase o vs digit 0) and is case-sensitive. A user who reads a TesseraID from a sticker, a paper printout, or a printed receipt and types it back in is significantly more error-prone with Base64URL than with Crockford Base32. Crockford's alphabet drops the ambiguous letters entirely and treats case as insignificant; the I/L/O/0 confusables are explicitly canonicalized by the decoder. The second use case is text-level lexicographic sort. Crockford's alphabet (0-9 then A-Z minus I/L/O/U) is monotonic in ASCII, so sorting Crockford strings as text yields the same order as sorting their decoded bytes. The Base64URL alphabet does not have that property, so a database column whose contents are sorted as text rather than as bytes will not produce time-ordered results from canonical Base64URL strings. The cost of Crockford is 11 extra characters per identifier (66 vs 55), which we consider acceptable for the use cases that need either property."),
  ]));

  out.push(p([
    tx("Implementations SHOULD support both. Systems that never expose identifiers to humans MAY choose to skip the Crockford encoder; systems that do expose identifiers to humans SHOULD prefer Crockford for those interfaces while continuing to use Base64URL for machine-to-machine transport."),
  ]));

  out.push(h2("Why a 16-bit Counter, Not 32-bit or 8-bit?"));

  out.push(p([
    tx("The counter exists to disambiguate IDs generated in the same millisecond by the same generator. Sixteen bits gives 65,536 distinct values per millisecond — sufficient to distinguish IDs at a generation rate of 65 million per second from a single generator. Above that rate, the spec requires the generator to spin to the next millisecond before continuing; in practice, no TesseraID implementation we've benchmarked comes close to exhausting the counter budget within a millisecond on commodity hardware."),
  ]));

  out.push(p([
    tx("Eight bits would have been too tight: at 256 IDs per millisecond, even modest single-machine workloads would routinely hit the spin path. Thirty-two bits would have been wasteful: most of the bits would always be zero, and the wasted bytes would not buy any practical capacity. Sixteen bits is the smallest value that comfortably exceeds plausible generation rates while remaining tightly packed."),
  ]));

  out.push(callout(
    "The counter's randomization rule",
    "The counter does not start at zero each millisecond. Implementations randomize the initial value within each new millisecond and increment by a small random step (1 + (rand_byte & 0x0F)). This is a defense against an outside observer reconstructing generator throughput from observed identifier streams — a side channel that doesn't matter for most use cases, but costs nothing to defend against and pays off if it ever does.",
    "info",
  ));

  return out;
}

function buildWhen() {
  const out = [];

  // ═══════════════════════════════════════════════════════════════════════
  // PART IV: When to Use What
  // ═══════════════════════════════════════════════════════════════════════
  out.push(h1("Part IV: When to Use What"));

  out.push(p([
    tx("This part is the practical decision guide. We work through the question \"should I use TesseraID, and if so, which variant?\" in three layers: when TesseraID is the right format at all, when to choose Standard vs HLC, and when to reach for something else."),
  ]));

  out.push(h2("When TesseraID is the Right Choice"));

  out.push(p("TesseraID is a good fit when at least two of the following are true:"));

  out.push(numbered([
    tx("The identifier needs to be globally unique without a coordination service."),
  ]));
  out.push(numbered([
    tx("Lexicographic ordering of the identifier should reflect generation time (for B-tree index efficiency, replication ordering, log analysis, or human readability)."),
  ]));
  out.push(numbered([
    tx("The identifier will be exposed in URLs, APIs, or storage that may persist for ten or more years."),
  ]));
  out.push(numbered([
    tx("The system has multiple generators (different machines, different processes, different threads) producing identifiers concurrently."),
  ]));
  out.push(numbered([
    tx("The cost of an identifier collision is high (data corruption, security failure, audit-log integrity loss)."),
  ]));

  out.push(p([
    tx("If your system has only one of these, simpler formats are worth considering. UUIDv4 is great when ordering doesn't matter and you want minimal byte cost. ULID is great when ordering matters but post-quantum margins don't. A `BIGSERIAL` PostgreSQL column is great when you have a single database and no horizontal scaling pressure. TesseraID's value increases with the number of these constraints that apply simultaneously."),
  ]));

  out.push(h2("Choosing Between Standard and HLC"));

  out.push(p([
    bold("Default to Standard. "),
    tx("The Standard variant is the right answer for the overwhelming majority of identifier use cases: database primary keys, request IDs, log line correlations, file names, trace spans, idempotency keys, S3 object names, message-bus message IDs, audit records. It is lock-free per thread, runs at full CSPRNG-bound throughput, and produces wall-clock-ordered output that does what users expect."),
  ]));

  out.push(p([
    bold("Choose HLC when you have a real causality requirement. "),
    tx("Specifically: your system has multiple nodes that exchange messages, the order in which one node's events were observed by another node matters for correctness, and you are willing to plumb HLC observation through your message-passing layer (every message carries the sender's HLC, every receiver observes that HLC before generating its next ID). If any of these is missing, you don't get HLC's value, and you pay HLC's costs (mutex contention, drift bounds, harder debugging) for nothing."),
  ]));

  out.push(p([
    tx("Concrete examples where HLC earns its keep:"),
  ]));

  out.push(bullet([
    bold("CRDTs and conflict-free replicated data types. "),
    tx("HLC is the standard tool for ordering concurrent updates in a way that preserves causality. CRDTs that use HLC as their version vector get correct merge semantics for free."),
  ]));

  out.push(bullet([
    bold("Distributed databases. "),
    tx("CockroachDB's MVCC layer uses HLC internally; exposing TesseraIDs in the HLC variant gives a natural primary-key format with built-in version semantics."),
  ]));

  out.push(bullet([
    bold("Event sourcing across services. "),
    tx("When events from multiple services flow into a unified log, HLC IDs preserve the cross-service causal order that wall-clock IDs cannot."),
  ]));

  out.push(bullet([
    bold("Distributed snapshots and consistent backups. "),
    tx("Algorithms like Chandy-Lamport [19] need a way to determine which events happened before a snapshot cut; HLC provides exactly that."),
  ]));

  out.push(p([
    tx("Concrete examples where HLC is overkill:"),
  ]));

  out.push(bullet([
    bold("Single-database web applications. "),
    tx("If the only thing generating IDs is the database tier, you have implicit serialization through the database; you don't need a logical clock."),
  ]));

  out.push(bullet([
    bold("API request IDs in stateless services. "),
    tx("There is no causal relationship to preserve — each request is independent. Wall-clock ordering is what you want."),
  ]));

  out.push(bullet([
    bold("Log line IDs within a single process. "),
    tx("The local monotonic clock plus a per-thread counter is enough; cross-process causality is not at stake."),
  ]));

  out.push(h2("When Not to Use TesseraID"));

  out.push(p([
    tx("TesseraID is not a good choice in three classes of situation."),
  ]));

  out.push(h3("When byte cost matters more than future-proofing"));

  out.push(p([
    tx("TesseraID is 41 bytes binary, 55 characters Base64URL. UUIDv4 is 16 bytes, 22 characters. KSUID is 20 bytes, 27 characters. If you are storing billions of identifiers per gigabyte of headroom, or transmitting identifier-dense streams over bandwidth-constrained links, the size difference matters. Common cases where TesseraID's size is unacceptable: embedded systems with kilobyte-scale storage budgets, real-time wire protocols where every byte counts, and high-frequency trading systems where serialization latency is bound by byte count. In these cases, ULID or KSUID is usually the right answer."),
  ]));

  out.push(h3("When you need privacy-preserving opaque tokens"));

  out.push(p([
    tx("TesseraID's timestamp is recoverable from the identifier. An attacker who sees a TesseraID learns within ~1ms when it was generated. For systems that need to hide creation time (anti-enumeration tokens, share links, magic login URLs), TesseraID is the wrong choice. Use a 256-bit random nonce, possibly indexed by a separate non-leaking key, instead."),
  ]));

  out.push(h3("When you need unforgeable identifiers"));

  out.push(p([
    tx("Anyone with a CSPRNG can produce a TesseraID that looks valid. The format does not authenticate the producer. For unforgeable identifiers (capability tokens, signed object identifiers, audit-log entries that must not be repudiated), use a signed token format like PASETO [21], JWT [18], or a custom MAC-protected format. TesseraIDs can be valuable as the "),
    it("identifier"),
    tx(" inside such a signed envelope, but they are not themselves a substitute for the envelope."),
  ]));

  out.push(h2("Decision Flowchart"));

  out.push(p("In flowchart form:"));

  out.push(spacer());

  out.push(code(
    "Q1: Does the identifier need lexicographic ordering by time?\n" +
    "    No  → Use UUIDv4 (or TesseraID Standard if post-quantum margin matters).\n" +
    "    Yes → Q2.\n" +
    "\n" +
    "Q2: Will the identifier be exposed beyond a 5-year horizon, or will it\n" +
    "    secure something with > 64 bits of value (financial records,\n" +
    "    long-term archival, regulatory data)?\n" +
    "    No  → Consider ULID (16 bytes) or KSUID (20 bytes) for size.\n" +
    "    Yes → Q3 (TesseraID is the candidate).\n" +
    "\n" +
    "Q3: Does the system have multiple nodes that exchange messages, and\n" +
    "    does cross-node causal ordering of events matter?\n" +
    "    No  → TesseraID Standard (variant 0x01).\n" +
    "    Yes → Q4.\n" +
    "\n" +
    "Q4: Are you willing to plumb HLC observation through the message-passing\n" +
    "    layer (every message carries the sender's HLC, every receiver\n" +
    "    observes it before generating its next ID)?\n" +
    "    No  → TesseraID Standard (you won't get HLC's value without observation).\n" +
    "    Yes → TesseraID HLC (variant 0x02).\n"
  ));

  return out;
}

module.exports = { buildRationale, buildWhen };
