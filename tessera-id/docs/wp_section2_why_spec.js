// Sections covering Why, the wire format spec, and rationale.
const H = require("./wp_helpers");
const {
  p, h1, h2, h3, code, callout, bullet, numbered, table, spacer,
  ic, tx, bold, it, Paragraph, TextRun,
} = H;

function buildWhy() {
  const out = [];

  // ═══════════════════════════════════════════════════════════════════════
  // PART I: Why
  // ═══════════════════════════════════════════════════════════════════════
  out.push(h1("Part I: Why a New Identifier?"));

  out.push(p([
    tx("Every identifier format reflects the constraints and assumptions of the moment it was designed. The decisions baked into UUIDv4 [1] in 2005 — 128 bits total, 122 bits of entropy, no time component, no ordering — made sense when distributed databases were rare, quantum computers were a footnote, and 'unique' meant 'unique in this rack.' Twenty years later, the constraints have shifted enough that even the carefully-chosen successors to UUIDv4 (UUIDv7 [2], ULID [4], KSUID [5]) leave gaps. TesseraID is an attempt to fill the remaining gaps in a single, coherent format — not by adding features, but by making slightly different choices on three numbers: the size of the random field, the granularity of the timestamp, and the semantics of the version byte."),
  ]));

  out.push(h2("The Three Constraints That Drive TesseraID"));

  out.push(h3("1. Quantum search is no longer hypothetical"));

  out.push(p([
    tx("Grover's algorithm [8] gives a quantum computer a quadratic speedup over classical search: finding a single matching value among 2"),
    new TextRun({ text: "n", size: 22, superScript: true }),
    tx(" candidates takes O(2"),
    new TextRun({ text: "n/2", size: 22, superScript: true }),
    tx(") operations instead of O(2"),
    new TextRun({ text: "n", size: 22, superScript: true }),
    tx("). For random identifiers, this means the effective security level under quantum search is "),
    bold("half the bit length of the random field"),
    tx(". UUIDv4's 122-bit random field gives 61 bits of post-quantum security; UUIDv7's 74-bit field gives 37; ULID's 80-bit field gives 40. None of these are catastrophic, but none provide the comfortable 128-bit margin that modern cryptographic systems target."),
  ]));

  out.push(p([
    tx("TesseraID uses 256 bits of randomness. Under Grover, that is "),
    bold("128 bits of effective security"),
    tx(" — the same level the cryptographic community has converged on for symmetric primitives like AES-256 [22] and SHA-256-based [23] hashes. The cost is sixteen extra bytes per identifier. In an era where average HTTP responses are kilobytes and average database row sizes are hundreds of bytes, sixteen bytes is unremarkable."),
  ]));

  out.push(callout(
    "Why 128 bits is the target",
    "NIST Special Publication 800-57 [10] designates 128-bit symmetric security as the appropriate level for protecting data through 2030 and beyond. The post-quantum cryptography standards selected by NIST in 2024 (ML-KEM [11], ML-DSA [12]) are also targeted at 128-bit security. Choosing anything less for a new identifier format means accepting that the identifier will be the weakest cryptographic object in any system that uses it.",
    "info",
  ));

  out.push(h3("2. Time-sortability is a feature, not a side effect"));

  out.push(p([
    tx("Random identifiers like UUIDv4 are catastrophic for B-tree indexes. Each new insert lands at a random point in the tree, causing scattered page writes, poor cache behavior, and eventually fragmentation that degrades read performance. The fix is well-understood: prefix the identifier with a timestamp so consecutive inserts land near each other. ULID, KSUID, and UUIDv7 all do this. TesseraID does too."),
  ]));

  out.push(p([
    tx("But there's a subtlety. ULID and KSUID expose lexicographic byte ordering as a first-class property: sorting their bytes (or, in ULID's case, their Crockford-encoded strings) yields time-ordering. UUIDv7's RFC permits implementations that randomize within a millisecond in ways that break this property; the spec only guarantees ordering "),
    it("between"),
    tx(" milliseconds, not "),
    it("within"),
    tx(" them. TesseraID guarantees both. Within a single millisecond, a per-generator counter makes consecutive IDs strictly increasing; across milliseconds, the timestamp dominates. The result is 100% time-sortedness across consecutive IDs from a single generator (binary order, and ASCII order in the Crockford encoding), measured against 10,000 consecutive IDs in the benchmark suite and against 100,000 unique IDs in the uniqueness test."),
  ]));

  out.push(h3("3. Distributed systems need clock semantics, not just clock values"));

  out.push(p([
    tx("Wall-clock timestamps are useful but lie about ordering across nodes. Two events at \"the same time\" on different machines are likely a few hundred microseconds apart from one machine's perspective and a few hundred microseconds the other way from the other's. NTP can synchronize clocks to roughly 1ms in a data center and 10–100ms across the open internet, but the residual error is large enough that wall-clock millisecond timestamps cannot reliably order events that are causally related."),
  ]));

  out.push(p([
    tx("The standard solution is the "),
    bold("Hybrid Logical Clock"),
    tx(" (Kulkarni, Demirbas, Madappa, Avva, Leone, 2014) [7], which combines physical time with a logical counter. An HLC reading is always at least the maximum of the local wall clock and any HLC value the node has observed from a peer; the counter increments whenever logical time fails to advance. The result is a clock that stays close to physical time, always moves forward, and preserves causal ordering across nodes that exchange HLC values in their messages."),
  ]));

  out.push(p([
    tx("TesseraID embeds the choice between wall-clock and HLC semantics in a "),
    bold("variant byte"),
    tx(" at offset 6. Variant 0x01 (Standard) is wall-clock; variant 0x02 (HLC) is hybrid logical clock. The wire format is identical otherwise, so consumers can ignore the variant byte and treat all TesseraIDs as opaque sortable identifiers. Producers that need causal ordering across nodes opt into HLC; producers that don't get the simpler, lock-free Standard generator."),
  ]));

  out.push(h2("Threat model and what TesseraID is not"));

  out.push(p([
    bold("TesseraID is an identifier, not a cryptographic hash, not a MAC, and not a content fingerprint."),
    tx(" The post-quantum security claim is narrow, and conflating it with hash-function properties leads to misuse. The math is in Part VI; this section pins down the boundary."),
  ]));

  out.push(p([
    bold("Targeted second-preimage is the right threat."),
    tx(" An attacker who knows a specific target TesseraID and wants to produce a different generator output equal to it must brute-force the 256-bit random tail. Under Grover that costs Θ(2"),
    new TextRun({ text: "128", size: 22, superScript: true }),
    tx(") quantum operations. This is the "),
    it("only"),
    tx(" security claim TesseraID makes for its random field, and it is the one that matters for identifier use cases such as opaque references, audit-log row keys, and capability tokens."),
  ]));

  out.push(p([
    bold("Collision resistance is statistical, not cryptographic."),
    tx(" Two TesseraIDs colliding (any two, not a specific one) is the BHT regime: Θ(2"),
    new TextRun({ text: "n/3", size: 22, superScript: true }),
    tx(") = 2"),
    new TextRun({ text: "85", size: 22, superScript: true }),
    tx(" for n=256. UUIDv7's equivalent is 2"),
    new TextRun({ text: "25", size: 22, superScript: true }),
    tx("; ULID's is 2"),
    new TextRun({ text: "27", size: 22, superScript: true }),
    tx("; KSUID's is 2"),
    new TextRun({ text: "43", size: 22, superScript: true }),
    tx(". TesseraID's 2"),
    new TextRun({ text: "85", size: 22, superScript: true }),
    tx(" is large enough that a deployment producing 10⁹ IDs/s would run for 10¹⁸ years before the expected collision count reached 1. But it is not the second-preimage number, and it is not what the headline claim is about."),
  ]));

  out.push(p([
    bold("Do not use TesseraID where you would use a hash."),
    tx(" TesseraID is not a SHA-2, SHA-3, BLAKE3, or KMAC substitute. The random tail has no relation to any input the generator has seen; TesseraID cannot be used to fingerprint content, prove possession of a preimage, derive a key, or authenticate a message. The 128-bit number applies "),
    it("only"),
    tx(" to the brute-force-the-random-tail game, not to any of the cryptographic-hash games. If a system needs second-preimage resistance against an adversary who controls the input, use a hash function. If it needs message authentication, use a MAC. If it needs an identifier whose post-quantum brute-force cost is at parity with AES-128, TesseraID is the right tool."),
  ]));

  out.push(h2("What TesseraID is Not"));

  out.push(p([
    tx("TesseraID is "),
    bold("not"),
    tx(" a signed identifier. There is no field for a digital signature, no key material, no proof of origin. Earlier drafts considered an embedded ML-DSA signature for post-quantum authenticity, but signing a 40-byte payload with ML-DSA-65 produces a roughly 3,300-byte signature — eighty times the size of the payload. SLH-DSA signatures are even larger. Bundling a signature into the identifier conflates two distinct concerns: identification (what is this thing?) and authentication (who created it?). The latter belongs in a token format like PASETO or JWT, where signatures are amortized over multi-claim payloads. TesseraID is the identifier; signed envelopes that "),
    it("contain"),
    tx(" TesseraIDs are a separate layer."),
  ]));

  out.push(p([
    tx("TesseraID is also "),
    bold("not"),
    tx(" a privacy-preserving identifier. The 48-bit timestamp is recoverable from the identifier, which means a TesseraID leaks the moment it was generated to anyone who can read it. For systems that need identifier opacity (anti-enumeration tokens, privacy-sensitive resource handles), use a separate format derived from a random or encrypted source. TesseraID's design assumes that the timestamp is either non-sensitive or already exposed elsewhere."),
  ]));

  out.push(p([
    tx("Finally, TesseraID is "),
    bold("not"),
    tx(" a replacement for sequential numeric IDs in single-database, single-tenant systems. If your system has one PostgreSQL instance, no horizontal scaling pressure, and a `BIGSERIAL` column is meeting your needs, TesseraID adds complexity without paying for itself. Reach for TesseraID when your system has any of: distributed generation, replication that depends on lexicographic ordering, identifiers exposed in URLs or APIs, or long-term archival where future-proofing the entropy budget matters."),
  ]));

  out.push(h2("How TesseraID Compares at a Glance"));

  out.push(p("Before diving into the specification, here is the set of identifier formats we benchmark against and how they sit relative to TesseraID on the dimensions that matter most:"));

  out.push(spacer());

  out.push(table(
    ["Format", "Bytes", "B64URL", "Random bits", "Post-Quantum bits", "Time-sortable", "Distributed-aware"],
    [
      ["UUIDv4",       "16", "22", "122",  "61",  "No",       "No"],
      ["UUIDv7",       "16", "22",  "74",  "37",  "Partial",  "No"],
      ["ULID",         "16", "22",  "80",  "40",  "Yes",      "No"],
      ["KSUID",        "20", "27", "128",  "64",  "Yes (1s)", "No"],
      ["Snowflake",     "8", "11",   "0",   "0",  "Yes",      "Yes (coordinated)"],
      ["TesseraID Standard","41", "55", "256", "128", "Yes (1ms)", "Locally"],
      ["TesseraID HLC",     "41", "55", "256", "128", "Yes (HLC)", "Yes (uncoordinated)"],
    ],
    [1500, 800, 900, 1200, 1500, 1500, 1960],
  ));

  out.push(p([
    tx("TesseraID's distinguishing properties are the 256-bit random field — the only format in this list with comfortable post-quantum margins — and the dual-variant design that makes the same wire format usable for both centralized and distributed generation. The cost is byte-count: at 41 bytes binary or 55 characters Base64URL, TesseraID is roughly 2.5× the size of UUIDv4. We discuss when this cost is acceptable and when it isn't in Part IV."),
  ]));

  return out;
}

function buildSpec() {
  const out = [];

  // ═══════════════════════════════════════════════════════════════════════
  // PART II: The Specification
  // ═══════════════════════════════════════════════════════════════════════
  out.push(h1("Part II: The TesseraID Specification"));

  out.push(p([
    tx("This part is the normative reference. Implementations that conform to this specification produce and consume identifiers with the byte layout, semantics, and encoding rules described below. Where this document uses RFC 2119 keywords (MUST, SHOULD, MAY), they carry the standard meanings."),
  ]));

  out.push(h2("Wire Format"));

  out.push(p([
    tx("A TesseraID is exactly "),
    bold("41 bytes"),
    tx(" in its binary representation. The bytes are organized into four fields:"),
  ]));

  out.push(spacer());

  out.push(code(
    "Offset  Length  Field         Description\n" +
    "──────  ──────  ────────────  ────────────────────────────────────────\n" +
    "  0      6      TIMESTAMP     48-bit big-endian milliseconds\n" +
    "  6      1      VARIANT       0x01 = Standard, 0x02 = HLC\n" +
    "  7      2      COUNTER       16-bit big-endian per-tick counter\n" +
    "  9     32      RANDOM        256-bit CSPRNG output\n" +
    "                              (= 41 bytes total)"
  ));

  out.push(spacer());

  out.push(p([
    tx("The fields are laid out timestamp-first specifically so that "),
    bold("lexicographic byte comparison"),
    tx(" of two TesseraIDs orders them by generation time. The variant byte sits between the timestamp and the counter so that a corruption or accidental version mismatch surfaces early, and so that the variant byte is encoded into the same nibble of the canonical Base64URL representation regardless of timestamp value (predictable to debug)."),
  ]));

  out.push(h3("TIMESTAMP field (48 bits)"));

  out.push(p([
    tx("A big-endian unsigned integer giving milliseconds since the Unix epoch (1970-01-01T00:00:00Z). The 48-bit width gives a usable range of approximately 8,919 years (2^48 milliseconds = ~3.26 million days); with the epoch fixed at 1970, TesseraIDs can represent every millisecond up to year ~10889. The field MUST be encoded big-endian. Implementations MUST NOT use a custom epoch — interoperability of timestamps across systems is a primary goal of the design."),
  ]));

  out.push(p([
    tx("For variant 0x01 (Standard), the timestamp is wall-clock milliseconds, possibly clamped against backward jumps as described in Part V. For variant 0x02 (HLC), the timestamp is the "),
    it("logical time"),
    tx(" component of a Hybrid Logical Clock — distinct from but always close to wall-clock time. The wire format does not distinguish the two cases at the bit level; the variant byte makes the semantic distinction."),
  ]));

  out.push(h3("VARIANT byte (8 bits)"));

  out.push(p("Defined values:"));

  out.push(spacer());

  out.push(table(
    ["Value", "Variant", "Semantics"],
    [
      ["0x01", "Standard",      "Wall-clock timestamp, ms-scoped monotonic counter. Lock-free per-thread generation."],
      ["0x02", "HLC",           "Hybrid Logical Clock: logical time + counter that captures causality across nodes."],
      ["0x00",            "Permanently reserved", "MUST be rejected by decoders. Reserved defensively so zero-filled buffers cannot be confused with valid TesseraIDs. MUST NOT be assigned in any future revision."],
      ["0xFF",            "Permanently reserved", "MUST be rejected by decoders. Reserved defensively so all-ones uninitialized memory cannot be confused with valid TesseraIDs. MUST NOT be assigned in any future revision."],
      ["0x03",            "TesseraHash (sibling format)", "Allocated 2026. TesseraID decoders MUST reject 0x03 — a 0x03 buffer is a TesseraHash (73 bytes), not a TesseraID (41 bytes). See the TesseraHash section below."],
      ["0x04–0xFE",       "Reserved for future variants", "MUST be rejected by decoders until a future revision of this specification assigns them."],
    ],
    [1100, 1500, 6760],
  ));

  out.push(p([
    tx("The variant byte is mandatory. Decoders MUST verify the variant before interpreting the rest of the identifier — an unknown variant indicates either corruption or a future format the decoder does not understand, and in either case the safe behavior is to reject. The permanent reservation of 0x00 and 0xFF gives TesseraID a small but free defensive property: a 41-byte buffer of all zeroes or all ones cannot accidentally pass validation."),
  ]));

  out.push(h3("COUNTER field (16 bits)"));

  out.push(p([
    tx("A big-endian unsigned 16-bit integer. Its semantics depend on the variant:"),
  ]));

  out.push(bullet([
    bold("Standard (0x01): "),
    tx("a per-millisecond counter that increments to disambiguate IDs generated in the same millisecond by the same generator. The counter SHOULD start at a small random offset within each new millisecond to avoid leaking generator throughput patterns to outside observers, and SHOULD increment by a small random step (1 + (rand_byte & 0x0F)) for the same reason. When the counter overflows within a single millisecond, the generator MUST spin to the next millisecond before producing another ID."),
  ]));

  out.push(bullet([
    bold("HLC (0x02): "),
    tx("the logical counter c of the Hybrid Logical Clock, incremented when logical time stays the same and reset to 0 when logical time advances strictly. The HLC counter is not random; its predictable progression is a feature of the algorithm and is what allows ordering across nodes to be reconstructed."),
  ]));

  out.push(h3("RANDOM field (256 bits)"));

  out.push(p([
    tx("Thirty-two bytes drawn from a "),
    bold("cryptographically-secure pseudorandom number generator (CSPRNG)"),
    tx(". This is the only field carrying the post-quantum security claim, so the requirements are normative:"),
  ]));

  out.push(bullet([
    bold("Source. "),
    tx("Implementations MUST draw the random tail from one of: getrandom(2) (Linux 3.17+), getentropy(3) or arc4random_buf (BSDs and macOS), BCryptGenRandom (Windows), the language wrappers around these (os.urandom, crypto/rand.Read, getrandom::fill, crypto.getRandomValues, SecureRandom), or — as a last-resort portable fallback — /dev/urandom. Implementations MUST NOT use a non-cryptographic userspace PRNG (Math.random, rand(), Mersenne Twister, Xoshiro, etc.) under any circumstance."),
  ]));

  out.push(bullet([
    bold("Failure. "),
    tx("If the CSPRNG returns an error or refuses to produce 32 bytes, the generator MUST surface the error to the caller and MUST NOT emit a TesseraID. There is no fallback path."),
  ]));

  out.push(bullet([
    bold("Partial reads. "),
    tx("A read that returns fewer than 32 bytes MUST be retried until either 32 bytes are obtained or an unrecoverable error is returned."),
  ]));

  out.push(bullet([
    bold("Independence. "),
    tx("Each TesseraID's random tail MUST be drawn independently. A generator MAY combine the 32-byte tail with a small additional read (1–2 bytes) used for the counter step in the same syscall as an optimization; this is unrelated to the cryptographic claim and does not weaken it because the OS CSPRNG output is uniform."),
  ]));

  out.push(p([
    tx("The current implementations call: os.urandom (Python), getrandom / getentropy (C and C++), crypto/rand.Read (Go), getrandom::fill (Rust), crypto.getRandomValues / randomFillSync (TypeScript), SecureRandom (Java), and the underlying C reference (CPython extension). A test vector cannot directly verify entropy quality, but conformance reviewers SHOULD spot-check each implementation's call site against the rules above."),
  ]));

  out.push(p([
    tx("The random field is what makes TesseraIDs collision-resistant. With 256 bits and a perfect CSPRNG, the expected number of identifiers required to encounter a single random-field collision is approximately 2"),
    new TextRun({ text: "128", size: 22, superScript: true }),
    tx(" — well beyond any practical generation rate. Within a single millisecond, the counter and timestamp together provide an additional 16 bits of disambiguation, so even under astronomical generation loads, collisions occur only when the random fields collide."),
  ]));

  out.push(h2("Encodings"));

  out.push(p([
    tx("TesseraID defines two text encodings. Both round-trip cleanly to the same 41-byte binary form and neither uses padding. They differ in their behavior under string sort: Crockford Base32 [13] is ASCII-sort-preserving (sorting the strings as text gives generation-time order), while canonical Base64URL is sort-preserving only when its bytes are compared, not when its text is compared as ASCII. The reason is that the RFC 4648 Section 5 [3] alphabet (A-Z, a-z, 0-9, -, _) maps alphabet values 0..63 to ASCII codepoints that are not monotonic — A-Z (65..90), a-z (97..122), 0-9 (48..57), '-' (45), '_' (95) interleave, so a string-level ASCII sort produces an order different from the underlying byte order. Crockford's alphabet (0-9 then A-Z minus I/L/O/U) is monotonic in ASCII and so its strings sort identically to their decoded bytes. Choose accordingly: machine-to-machine paths use Base64URL and sort the bytes (or simply preserve insertion order); human-facing or text-sorted columns use Crockford."),
  ]));

  out.push(h3("Canonical: Base64URL (55 characters)"));

  out.push(p([
    tx("RFC 4648 Section 5 (\"Base 64 Encoding with URL and Filename Safe Alphabet\"), no padding. Encoding 41 bytes produces ceil(41 × 8 / 6) = 55 characters; the final character carries 4 bits of value plus 2 bits of zero padding. The alphabet is "),
    ic("A-Za-z0-9-_"),
    tx(" — URL-safe, JSON-safe, header-safe, filename-safe in any reasonable filesystem."),
  ]));

  out.push(spacer());

  out.push(code(
    "Example TesseraID, Base64URL form:\n" +
    "  AZ3vM1-cAQDTktcO1KNnge-F_JWHb0CxCKqLomE-_305fZqKzdvgZ7Y"
  ));

  out.push(p([
    tx("Decoders MUST accept exactly 55 characters and MUST reject input with padding characters. Decoders MAY accept inputs with whitespace stripped, but the canonical form for serialization, comparison, and hashing is the bare 55-character string."),
  ]));

  out.push(h3("Human-typable: Crockford Base32 (66 characters)"));

  out.push(p([
    tx("Douglas Crockford's Base32 alphabet ("),
    ic("0123456789ABCDEFGHJKMNPQRSTVWXYZ"),
    tx(") deliberately omits the letters I, L, O, and U to reduce transcription errors. Decoders MUST accept the lowercase form as equivalent to uppercase, and SHOULD accept the ambiguous characters I, L → 1 and O → 0 as a courtesy to humans transcribing IDs from displays."),
  ]));

  out.push(p([
    tx("Encoding 41 bytes (328 bits) at 5 bits per character produces 66 characters, with the final character carrying 3 bits of value plus 2 bits of zero padding. Decoders MUST verify that those padding bits are zero and SHOULD reject inputs whose decoded byte sequence has a variant byte outside the defined values."),
  ]));

  out.push(spacer());

  out.push(code(
    "Example TesseraID, Crockford Base32 form (same bytes as the Base64URL example above):\n" +
    "  01KQQK6QWW040D74PQ1VAA6SW1XY2ZS5C7DX0B225AHEH62FQZFMWQV6MASQDY0SXP"
  ));

  out.push(p([
    tx("The Crockford form is intended for use cases where humans handle the identifier directly: pasted into chat messages, read aloud over phones, written on paper, or appearing in CLI tools where mixed-case is hostile. The Base64URL form is intended for everything else."),
  ]));

  // ============================================================
  // TesseraHash subsection
  // ============================================================
  out.push(h2("TesseraHash — sibling content-identifier format (variant 0x03)"));

  out.push(p([
    bold("TesseraHash is a sibling format to TesseraID"),
    tx(", sharing TesseraID's 9-byte header layout but extending the wire size and replacing the random tail with a deterministic content digest. TesseraHash is "),
    it("additive"),
    tx(": it does not change TesseraID, and the two formats are guaranteed to not cross-decode."),
  ]));

  out.push(h3("Wire layout (73 bytes)"));

  out.push(p(
    "  0       6      7       9                                            73\n" +
    "  +-------+------+-------+--------------------------------------------+\n" +
    "  |  TS   | 0x03 |  CTR  |              SHAKE256(content, 64B)        |\n" +
    "  | 48 b  |  8 b | 16 b  |                       512 b                |\n" +
    "  +-------+------+-------+--------------------------------------------+\n"
  ));

  out.push(bullet([
    bold("Timestamp (0–5): "),
    tx("Provenance metadata — when this identifier was assigned. NOT a security claim."),
  ]));
  out.push(bullet([
    bold("Variant (6): "),
    tx("Fixed at 0x03, allocated from TesseraID's reserved-future range."),
  ]));
  out.push(bullet([
    bold("Counter (7–8): "),
    tx("Same-ms disambiguator within a generator."),
  ]));
  out.push(bullet([
    bold("Tail (9–72): "),
    tx("64 bytes (512 bits) of SHAKE-256(content), output truncated to 64 bytes. Deterministic from the content alone: two callers that TesseraHash the same content produce the same tail, regardless of generator or timestamp."),
  ]));

  out.push(h3("Security claim"));

  out.push(p("The 512-bit tail gives:"));
  out.push(bullet([
    tx("2"),
    new TextRun({ text: "256", size: 22, superScript: true }),
    tx(" classical and post-quantum (Grover) second-preimage resistance."),
  ]));
  out.push(bullet([
    tx("2"),
    new TextRun({ text: "256", size: 22, superScript: true }),
    tx(" classical collision resistance (birthday)."),
  ]));
  out.push(bullet([
    tx("2"),
    new TextRun({ text: "170", size: 22, superScript: true }),
    tx(" post-quantum collision resistance (BHT). This is the surface that matters for content addressing across multi-decade archival horizons."),
  ]));

  out.push(p([
    bold("What TesseraHash is NOT: "),
    tx("not a hash function (use SHAKE-256 directly), not a MAC (use KMAC256), not a signature (use ML-DSA / SLH-DSA). TesseraHash is a content identifier with provenance metadata; the timestamp carries no security claim."),
  ]));

  out.push(h3("Cross-format non-overlap"));

  out.push(p([
    tx("TesseraID and TesseraHash MUST NOT cross-decode. TesseraID is exactly 41 bytes with variant 0x01 or 0x02; conformant TesseraID decoders reject 73-byte buffers (length error) and reject the 0x03 variant byte. TesseraHash is exactly 73 bytes with variant 0x03; conformant TesseraHash decoders reject 41-byte buffers (length error) and any variant other than 0x03."),
  ]));

  out.push(p("An application that may receive either format dispatches at the boundary:"));
  out.push(p(
    "  if len(buf) == 73 and buf[6] == 0x03:  TesseraHash.decode(buf)\n" +
    "  elif len(buf) == 41 and buf[6] in {0x01, 0x02}:  TesseraID.decode(buf)\n" +
    "  else: error\n"
  ));

  out.push(h3("Encodings"));

  out.push(bullet([
    bold("Base64URL: 98 characters. "),
    tx("ceil(73*8/6) = 98. Final character carries 4 bits of value plus 4 bits of zero padding. Decoders MUST reject inputs whose final character carries non-zero padding bits."),
  ]));
  out.push(bullet([
    bold("Crockford Base32: 117 characters. "),
    tx("ceil(73*8/5) = 117. 584 input bits → 585 output bits with 1 zero pad bit at the bottom of the final character. Case-insensitive with the same I/L→1 and O→0 confusables as TesseraID."),
  ]));

  out.push(h3("Verify"));

  out.push(p([
    tx("A conformant TesseraHash implementation MUST expose a "),
    bold("verify(raw, content)"),
    tx(" predicate that returns true iff raw is a 73-byte TesseraHash with variant 0x03 AND its tail equals SHAKE-256(content) truncated to 64 bytes. The tail comparison MUST be constant-time on the 64-byte input to avoid timing oracles. Malformed buffers return false rather than raising."),
  ]));

  return out;
}

module.exports = { buildWhy, buildSpec };
