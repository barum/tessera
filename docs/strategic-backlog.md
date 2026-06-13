# Strategic backlog — deferred Wave 9 items (recorded 2026-06-10)

The 2026-06-10 remediation closed every correctness, truthfulness, packaging, and governance item
(see [remediation-plan-2026-06-10.md](remediation-plan-2026-06-10.md)). The strategic/market items
below were deliberately **deferred, not dropped**. Each entry records current readiness, the first
concrete step, and the blocking dependency, so any future session can pick one up cold. Ticket IDs
refer to the remediation plan; per-item detail lives there.

## TP-121 — Hybrid suite 0x06: C port (TSEAL-00030)

- **Readiness:** UNBLOCKED. CI builds OpenSSL 3.5+ (TESS-00006), which already exposes X25519 via
  `EVP_PKEY` — zero new dependencies. Python/Rust/Go hybrid KATs are frozen and consumable today.
- **First step:** follow the porting playbook in
  [.claude/skills/tessera-seal-impl/SKILL.md](../.claude/skills/tessera-seal-impl/SKILL.md)
  ("How to port hybrid suite 0x06 to a new language"): separate `tessera_seal_pub_hybrid_t`/
  `tessera_seal_priv_hybrid_t` structs + dedicated entry points, preserving the v1.0/v1.1 ABI.
- **Blocked by:** nothing technical; maintainer prioritization only. EU-regulator order says C first.

## TP-122 — Hybrid suite 0x06: Java port (TSEAL-00032)

- **Readiness:** ready once TP-121 sets the C-family shape; SunJCE already ships both halves
  (XDH/JEP 339 for X25519, ML-KEM/JEP 452) — no new dependencies.
- **First step:** same playbook; add the X25519 half to the key classes, flip `hybrid_supported()`
  java entry, consume `hybrid_*.json` byte-identically.
- **Blocked by:** TP-121 (sequencing choice, not a hard dependency).

## TP-123 — Hybrid suite 0x06: TypeScript port (TSEAL-00031)

- **Readiness:** ready; `@noble/curves` was removed as an unused dep (TP-105) and must return
  exactly pinned when this lands.
- **First step:** re-add `@noble/curves` (exact pin, supply-chain note in PR), implement per
  playbook, flip `hybrid_supported()` ts entry, KATs byte-identical.
- **Blocked by:** TP-122 (recommended order); supply-chain review for the re-added pin.

## TP-124 — Hybrid suite 0x06: C++ + CPython ext ports

- **Readiness:** both wrap the C reference, so they are mechanical once TP-121 lands. Completes the
  8/8 hybrid matrix and retires the "really 4+4" honesty gap in `hybrid_supported()`.
- **First step:** after TP-121, surface the hybrid structs/entry points in C++ and the ext, flip
  both `hybrid_supported()` entries, run the full-8 harness.
- **Blocked by:** TP-121 (hard dependency — they compile against `c/tessera_seal.c`).

## TP-125 — ASCII armor for envelopes

- **Readiness:** spec-first feature, no design started. Unlocks the secrets-in-git/config use case
  that built age's user base (sops).
- **First step:** whitepaper section (header/footer lines + base64 body, fixed width), then Python
  reference + KAT records (append-only), then lockstep ports + CLI `--armor`.
- **Blocked by:** nothing; pure prioritization. Days of work, large adoption unlock.

## TP-126 — v2 multi-recipient committing envelope (the leapfrog thesis)

- **Readiness:** verified market gap as of 2026-06: age v1.3 shipped native PQ recipients but its
  multi-recipient mode still uses a non-committing AEAD — its documented open weakness. Nobody
  ships a multi-recipient PQ envelope *with* key commitment. v1 wire carries exactly one KEM_CT.
- **First step:** spec draft — new VARIANT byte from 0x05–0xFE (a v2 envelope is a new variant, not
  a suite tweak), N recipient stanzas, per-recipient KEM_CT + committing wrap of `K_session`,
  preserving single-`DecryptionError` discipline and per-recipient UtC commitment.
- **Blocked by:** TP-119 submission (freeze v1 publicly before designing v2 against it).

## TP-127 — v2 streaming committing AEAD

- **Readiness:** design dependencies understood (age STREAM, Tink streaming AEAD, AWS ESDK framing
  as prior art); v1 interim chunking recipe shipped (TSEAL-00047) and is the documented stopgap.
- **First step:** v2 spec section — STREAM-style nonce-counter chained chunks with per-chunk or
  chained commitment, 4 GiB cap removed; supersede the chunking recipe.
- **Blocked by:** TP-126 (same v2 variant-byte design effort; do them as one spec).

## TP-128 — TesseraSign: ML-DSA-87 detached-signature envelope

- **Readiness:** every pinned library family already ships ML-DSA (OpenSSL 3.5+, JDK 24+,
  RustCrypto, @noble); CNSA 2.0's binding 2025–2027 milestones are signing-centric. New project,
  new variant byte, same polyglot-KAT discipline. Completes "one Keccak family to audit".
- **First step:** pre-spec memo — variant-byte allocation request, wire layout sketch, library pin
  table per language; then whitepaper + Python reference + vectors.
- **Blocked by:** TP-119 (registry should be externally citable before allocating into it).

## TP-130 — age-plugin-tessera + sops keysource

- **Readiness:** the existing plugin protocol deliberately imitates age's; Python packaging (TP-070)
  landed, so a plugin binary has a home. Pitch: "age gives hybrid-768 without commitment; this
  plugin gives CNSA-aligned 1024 WITH commitment."
- **First step:** implement the age plugin protocol handshake over the existing keyfile code; verify
  age encrypt/decrypt round-trip through the plugin; then a sops keysource PR.
- **Blocked by:** TP-006 (plugin name is user-facing); publication posture (TP-085).

## TP-131 — Unified `tessera` CLI + Homebrew

- **Readiness:** per-project Python CLIs shipped (TID-00022) as the ergonomic floor; the killer-CLI
  vehicle (one static Go or Rust binary: seal/unseal, id new/decode, hash sum/verify) is unstarted.
- **First step:** pick Go vs Rust (recommend Go: stdlib mlkem + ecdh, single static binary), scaffold
  `tessera` with the three verb families, reuse conformance vectors as CLI integration tests.
- **Blocked by:** TP-006/TP-085 (publishing channel + name); TP-125 for `--armor` parity.

## TP-132 — Postgres extension for TesseraID

- **Readiness:** highest-leverage ID adoption move (Postgres 18's `uuidv7()` proves DB-native
  generation is the lever). C reference is warning-clean and ABI-stable — wrappable today.
- **First step:** scaffold a `tesseraid` extension: native 41-byte type + btree opclass, server-side
  standard/HLC generators, timestamp extraction, casts to/from both text forms; PK demo + index
  benchmark vs uuid.
- **Blocked by:** TP-006 (extension name is public); otherwise ready.

## TP-134 — UUIDv8 compatibility profile

- **Readiness:** doc repositioning (TP-133) is done and names this as the coexistence story for
  legacy uuid-typed schemas/ORMs. Design is a documented lossy down-mapping (48-bit ts + top 62
  random bits), not a wire change.
- **First step:** spec section defining the mapping + reference helpers in Python/Go/Rust + vectors.
- **Blocked by:** nothing; small, self-contained.

## TP-135 — TypeID-style prefix layer

- **Readiness:** zero wire cost (prefix excluded from the 41-byte format) — purely a text-grammar
  spec (`prefix_` + Crockford) plus parser support. The most-loved DX feature in the ID space.
- **First step:** spec the text grammar (charset, max prefix length, canonical lowercase), add
  parse/format helpers in the reference languages + vectors for accept/reject cases.
- **Blocked by:** nothing; sequence with TP-134 to touch text-form docs once.

## TP-136 — Masked-timestamp variant

- **Readiness:** addresses the timestamp-leak critique TesseraID inherits from UUIDv7 (cleartext
  48-bit creation time). Brooker-style `unix_ts_ms XOR H(key, ts >> N)` design sketch exists in the
  plan; needs a NEW variant byte — security-relevant, whitepaper + registry update.
- **First step:** spec memo: keying model, window size N trade-off, sortability scope, registry
  allocation request; then Python reference + vectors.
- **Blocked by:** registry governance (TP-119) recommended first; `sec(...)` review required.

## TP-138 — Multicodec + in-toto DigestSet bridges

- **Readiness:** both are permissionless one-PR integrations: a multicodec code registration makes
  TesseraHash content IPFS-pinnable (lossless ↔ multihash/CIDv1 converter); a `tesseraHash`
  DigestSet algorithm name + cosign attestation example buys supply-chain relevance.
- **First step:** draft the multiformats/multicodec table PR + write the two converters with KATs.
- **Blocked by:** TP-006 (registered names are permanent); publication (registrations cite the repo).

## TP-139 — TesseraHash streaming/Merkle tree variant

- **Readiness:** the streaming gap is documented honestly in the whitepaper (one-shot today,
  TP-067). Disqualifying gap vs BLAKE3/bao and CID DAGs for large artifacts. Needs a future variant
  byte for a SHAKE-256 tree/chunked mode (Sakura/K12-style) — single-primitive discipline preserved.
- **First step:** design memo comparing fixed-chunk Merkle over SHAKE-256 vs K12-style tree, with
  range-verification semantics; then spec + reference + vectors.
- **Blocked by:** registry governance (TP-119); larger design effort than TP-134/135.

## TP-140 — Evidence-manifest flagship application

- **Readiness:** the anchor-application thesis (RFC 6920's failure = formats without a flagship
  deployment go nowhere). Targets the legal/regulated-archive niche: TesseraHash digests +
  RFC 3161/Roughtime timestamps + Merkle transparency log.
- **First step:** one-page product memo (ingest → manifest → timestamp → log → verify), then CLI
  verbs inside TP-131's binary.
- **Blocked by:** TP-131 (vehicle) and TP-138 (interop bridges) land first.

## TP-141 — tessera-vectors standalone + CCTV contribution

- **Readiness:** HIGH — the vectors are already frozen append-only (`check-vector-freeze.sh`),
  schema-stable, and runner-protocol-documented; making them a standalone versioned artifact is
  mostly packaging (Wycheproof model: make the harness the product).
- **First step:** carve out vectors + schema + runner-protocol doc into a publishable artifact;
  open the CCTV PR with the negative-vector suite (reserved bytes, BadKey, malformed envelopes).
- **Blocked by:** publication posture (TP-085); pairs naturally with the TP-119 C2SP PR.

## TP-142 — Independent implementer recruitment

- **Readiness:** all interop claims remain self-attested (one author, 8 implementations). The
  recruiting kit is effectively done: frozen vectors, truthful spec, porting playbooks.
- **First step:** once public, pitch one external implementer (the age/rage dynamic) on a single
  format — TesseraID is the smallest surface — and feature their repo as the interop proof.
- **Blocked by:** EXTERNAL — requires a public repo (TP-085/TP-116) and a willing third party;
  TP-141's standalone vector kit is the enabler.

## TP-143 — Third-party security audit (~$50k)

- **Readiness:** honesty debt is burned down (TP-031/TP-050 done) — an auditor no longer finds the
  docs lying, which was the precondition. Scope memo target: Python + C TesseraSeal references.
- **First step:** write the audit RFP (scope, threat model pointer, frozen commit); pursue funding
  routes — OpenSats/Sovereign Tech Fund-style grants or a single corporate sponsor (noble/libsodium
  playbook). Publish the report verbatim when done.
- **Blocked by:** EXTERNAL — funding and firm availability; publication posture for the engagement.

## TP-144 — Machine-checked composition proof (Tamarin / hax)

- **Readiness:** cheaper than the code audit and independent of publication: model the TesseraSeal
  composition (KEM + HKDF + AEAD + UtC commit) and state precisely what is/isn't proven. 2026
  differentiation — even liboqs has only primitive-level proofs.
- **First step:** choose Tamarin vs hax/F* (recommend Tamarin for protocol-level composition),
  transcribe the §5–§9 spec into a model, prove session-key secrecy + commitment binding.
- **Blocked by:** specialist time; no repo dependency.

## TP-148 — IETF Independent-Submission I-Ds

- **Readiness:** sequenced explicitly after C2SP (TP-119): an I-D for the TesseraID wire format +
  variant registry (the ULID lesson — informal specs get displaced by RFCs), and a short
  TesseraHash "verification profile" I-D (one algorithm, one length, mandatory reject —
  WireGuard's no-agility precedent).
- **First step:** after the C2SP spec freezes, convert it with kramdown-rfc and submit to the
  Independent Stream.
- **Blocked by:** TP-119 merged; TP-006 name finality.

## TP-149 — Rust AES-NI/ARMv8 intrinsics (TSEAL-00027/00034)

- **Readiness:** behavior-identical optimization for the 1 MiB throughput gap; requires `aes-gcm`
  0.11 (the 0.10 `aes` feature alone does NOT enable ARMv8 intrinsics on stable) — i.e. a pinned
  crypto-dependency bump, which is a supply-chain review event per CLAUDE.md invariant 7.
- **First step:** PR bumping `aes-gcm` 0.10 → 0.11 with a "Security considerations" section, KATs
  green, before/after benchmark delta published.
- **Blocked by:** supply-chain review of the 0.11 pin; no wire change permitted.
