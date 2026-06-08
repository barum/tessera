// Sections 1-4 of the whitepaper: cover, TL;DR, executive summary, and the "Why" part.
const H = require("./wp_helpers");
const {
  p, h1, h2, h3, code, callout, bullet, numbered, table, spacer,
  ic, tx, bold, it, Paragraph, TextRun, AlignmentType, PageBreak,
} = H;

function buildCoverAndIntro() {
  const out = [];

  // ── Cover page ─────────────────────────────────────────────────────────
  out.push(
    new Paragraph({ spacing: { before: 2400, after: 0 }, children: [new TextRun("")] }),
    new Paragraph({
      alignment: AlignmentType.CENTER,
      spacing: { before: 0, after: 240 },
      children: [new TextRun({ text: "TesseraID", size: 96, bold: true, color: H.COLORS.primary })],
    }),
    new Paragraph({
      alignment: AlignmentType.CENTER,
      spacing: { before: 0, after: 480 },
      children: [new TextRun({ text: "Post-Quantum Identifier", size: 40, color: H.COLORS.accent })],
    }),
    new Paragraph({
      alignment: AlignmentType.CENTER,
      spacing: { before: 0, after: 240 },
      children: [new TextRun({
        text: "A 41-byte time-sortable identifier with 256 bits of post-quantum-resistant randomness, two operational variants for centralized and distributed systems, and reference implementations in Python, Go, Rust, and TypeScript.",
        size: 26, italics: true, color: H.COLORS.muted,
      })],
    }),
    new Paragraph({ spacing: { before: 1800, after: 0 }, children: [new TextRun("")] }),
    new Paragraph({
      alignment: AlignmentType.CENTER,
      spacing: { before: 0, after: 120 },
      children: [new TextRun({ text: "Specification, Rationale, and Reference Implementations", size: 28, bold: true })],
    }),
    new Paragraph({
      alignment: AlignmentType.CENTER,
      spacing: { before: 0, after: 240 },
      children: [new TextRun({ text: "Version 1.0", size: 24, color: H.COLORS.muted })],
    }),
    new Paragraph({
      alignment: AlignmentType.CENTER,
      spacing: { before: 0, after: 0 },
      children: [new TextRun({ text: new Date().toISOString().slice(0, 10), size: 22, color: H.COLORS.muted })],
    }),
  );

  // ── TL;DR ──────────────────────────────────────────────────────────────
  out.push(h1("TL;DR"));

  out.push(p([
    bold("TesseraID"),
    tx(" is a 41-byte, lexicographically-sortable identifier designed to be useful for the next thirty years of distributed systems. It pairs a 48-bit millisecond timestamp with 256 bits of cryptographically-strong randomness — the smallest random field that retains 128 bits of effective security under Grover's quantum search algorithm [8]. A version byte and a 16-bit per-millisecond counter sit between them. Two variants of the format share the same wire layout: "),
    bold("Standard"),
    tx(" (variant 0x01) for centralized generation against a wall clock, and "),
    bold("Hybrid Logical Clock"),
    tx(" (variant 0x02) [7] for distributed systems where causal ordering across nodes matters."),
  ]));

  out.push(p([
    tx("Each TesseraID encodes to "),
    bold("55 characters"),
    tx(" of canonical Base64URL or "),
    bold("66 characters"),
    tx(" of human-typable Crockford Base32 [13]. Both encodings round-trip to identical 41-byte binary values, and binary sort and Crockford ASCII sort both reflect generation time. (Canonical Base64URL [3] preserves byte order only when compared as bytes — its alphabet ordering does not match ASCII codepoint order, so consumers that need a textual column to sort by time should use Crockford or sort the underlying bytes.) The 55-character Base64URL form fits comfortably in URL paths, JSON, headers, and database primary-key columns; the Crockford form is meant for human transcription, log lines, CLI tools, and any column where lexicographic text sort must reflect generation time."),
  ]));

  out.push(p([
    tx("Reference implementations exist in Python, Go, Rust, and TypeScript. Single-threaded throughput on a Xeon at 2.8 GHz ranges from "),
    bold("360,000 IDs/sec"),
    tx(" in TypeScript to "),
    bold("1.57 million IDs/sec"),
    tx(" in Rust. The bottleneck across every implementation is the OS CSPRNG, not TesseraID's own logic. Time-sortedness across consecutive IDs is 100% by construction, matching ULID [4] and beating UUIDv4 [1], UUIDv7 [2], and KSUID [5]."),
  ]));

  out.push(p([
    bold("At million-node scale"),
    tx(" — the regime emerging in frontier-AI training clusters and globally-distributed inference fleets — TesseraID is the only published format whose collision math, coordination model, causal-ordering semantics, and post-quantum margins all hold simultaneously. UUIDv4 fails on collision math (the 122-bit random field is undersized for trillions of identifiers per training run). UUIDv7 fails on intra-millisecond sort guarantees (RFC 9562 §6.2 [2] permits implementations that randomize within a ms) and on causal ordering across geographically-distributed nodes. ULID and KSUID fail on entropy. Snowflake [6] fails on coordination requirements. Part XI makes this case in detail."),
  ]));

  out.push(callout(
    "When to reach for TesseraID",
    "Choose Standard (the default) for primary keys, request IDs, log lines, traces, file names, and anywhere else that needs a unique, time-sortable, post-quantum-resistant identifier. Choose HLC when you are building a distributed system where event ordering across nodes matters — CRDTs, distributed databases, event sourcing, distributed snapshots, multi-agent AI systems, federated training pipelines — and you are willing to wire up clock observation between communicating peers.",
    "info",
  ));

  // ── Executive Summary ──────────────────────────────────────────────────
  out.push(h1("Executive Summary"));

  out.push(p([
    tx("Identifier formats accumulate technical debt slowly. UUIDv4 was published in 2005, ULID in 2016, KSUID in 2017, and UUIDv7 became RFC 9562 in 2024. Each addressed a real problem with its predecessor — UUIDv4 traded ordering for uniqueness, ULID restored ordering, KSUID widened the random field, UUIDv7 brought ordering into the official UUID family — but none of them made entropy decisions with quantum search in mind, and only ULID and KSUID exposed lexicographic ordering as a first-class property. Most also bundle wall-clock and logical-clock semantics into a single shape, leaving distributed systems to retrofit causal ordering on top."),
  ]));

  out.push(p([
    tx("TesseraID is a deliberate redesign for the operating environment of the late 2020s and 2030s: cloud-native services that span continents, consumer cryptography that must survive the eventual arrival of cryptographically-relevant quantum computers, and identifier streams large enough that birthday-bound math on 80- or 128-bit fields no longer feels generous. Its 256-bit random tail is sized for "),
    bold("128-bit post-quantum security"),
    tx(", giving the identifier the same effective uniqueness guarantee under Grover's algorithm that UUIDv4's 122-bit random field gives under classical search."),
  ]));

  out.push(p([
    tx("The format also takes a position on a question most identifier specs duck: how should a single identifier serve both centralized and distributed generation? TesseraID's answer is a "),
    bold("variant byte"),
    tx(" — a single byte at offset 6 that selects between two algorithmically-distinct generation strategies that share the same wire layout. The Standard variant uses a wall-clock timestamp clamped against local monotonic regression; the HLC variant uses a Hybrid Logical Clock whose 48-bit field carries logical (not physical) time. Both variants encode and decode identically; consumers that don't care can ignore the variant byte and treat all TesseraIDs as opaque sortable bytes."),
  ]));

  out.push(p([
    tx("This document is intended as the canonical reference for TesseraID v1. It covers the wire format, the rationale for every numeric choice, when to use each variant, how to implement generators correctly, the security model, the distributed-systems model, and detailed comparisons against UUIDv4, UUIDv7, ULID, KSUID, and Snowflake. It closes with reference implementations and benchmark data from four languages."),
  ]));

  return out;
}

module.exports = { buildCoverAndIntro };
