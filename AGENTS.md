# AGENTS.md

## Project Shape

`pqtoolkit` is a specification-first, polyglot monorepo of post-quantum-era data formats.
Each project under this root is an independent spec with its own normative wire format and
byte-identical polyglot reference implementations:

- **[pqid/](pqid/)** — a 41-byte time-sortable identifier (Standard + HLC variants).
- **[pqhash/](pqhash/)** — a 73-byte SHAKE-256 content hash.
- **[pqcrypt/](pqcrypt/)** — a post-quantum encryption envelope (ML-KEM-1024 + AES-256-GCM + UtC commit).

Repo-wide conventions and the full security-invariant list live in [CLAUDE.md](CLAUDE.md);
per-project invariants live in each project's `CLAUDE.md`
([pqid/CLAUDE.md](pqid/CLAUDE.md), [pqhash/CLAUDE.md](pqhash/CLAUDE.md), [pqcrypt/CLAUDE.md](pqcrypt/CLAUDE.md)).
Treat the project whitepaper → Python reference → C header as the authority order; never
change the spec to match an outlier implementation.

Start with [README.md](README.md) for the language tree, then use each project's whitepaper
and reference implementations as the source of truth:

- [PQID_Whitepaper.pdf](PQID_Whitepaper.pdf), [pqid/python/pqid.py](pqid/python/pqid.py), [pqid/c/pqid.h](pqid/c/pqid.h)
- [pqhash/latex/PQHash_Whitepaper.pdf](pqhash/latex/PQHash_Whitepaper.pdf), [pqhash/python/pqhash.py](pqhash/python/pqhash.py), [pqhash/c/pqhash.h](pqhash/c/pqhash.h)
- [pqcrypt/latex/PQCrypt_Whitepaper.pdf](pqcrypt/latex/PQCrypt_Whitepaper.pdf), [pqcrypt/python/pqcrypt.py](pqcrypt/python/pqcrypt.py), [pqcrypt/c/pqcrypt.h](pqcrypt/c/pqcrypt.h)

## What To Preserve

- Wire formats are fixed: PQID 41 bytes, PQHash 73 bytes, PQCrypt 16-byte header + variable body.
- **Shared variant-byte namespace** (offset 6 in PQID/PQHash; `VAR` byte in the PQCrypt header).
  Every project's decoder rejects every byte it does not own:

  | Byte | Owner | Meaning |
  |------|-------|---------|
  | `0x00` | — | **Permanently reserved**, never assign |
  | `0x01` | PQID | Standard generator |
  | `0x02` | PQID | HLC generator |
  | `0x03` | PQHash | SHAKE-256 content hash |
  | `0x04` | PQCrypt | Encryption envelope v1 |
  | `0x05`–`0xFE` | — | Reserved-future (current decoders MUST reject) |
  | `0xFF` | — | **Permanently reserved**, never assign |

  Hybrid suite byte `0x06` is a **PQCrypt suite byte** (offset 7 in the PQCrypt header), NOT a
  top-level variant byte. The PQCrypt variant byte is always `0x04`. A new variant byte is an
  ABI break and requires a whitepaper update.

- Canonical encodings: PQID uses Base64URL (55 chars) and Crockford Base32 (66 chars); PQHash
  uses analogous fixed-length encodings; PQCrypt v1 ships binary-only.
- StandardGenerator is intentionally not internally locked; HLCGenerator must be internally locked.
- HLC drift handling is part of the PQID contract and must stay bounded at 60 seconds (`HLC_MAX_DRIFT_MS = 60_000`);
  out-of-bounds peer HLC is a hard error, never clamped.
- All randomness (PQID's 32-byte tail, ML-KEM/X25519 internal randomness) MUST come from an OS
  CSPRNG (getrandom / getentropy / BCryptGenRandom / os.urandom / SecureRandom /
  crypto.getRandomValues / `/dev/urandom`). NO userspace PRNG fallback; CSPRNG failure surfaces
  an error and produces no output.
- PQCrypt invariants (key-committing AEAD, single `DecryptionError`, deterministic nonce, no
  "Kyber"/"ECDH"/"Curve25519" naming in public APIs) are detailed in
  [pqcrypt/CLAUDE.md](pqcrypt/CLAUDE.md) and [CLAUDE.md](CLAUDE.md) §Security invariants.

## Work Style

- Use the reference implementations to confirm behavior before changing any other language.
- Keep implementations aligned across languages when changing wire format, encoding, validation,
  or generator semantics. Wire output from one language MUST decode byte-identically in every other.
- Prefer the smallest change that keeps tests and benchmarks consistent with the spec.
- One project per PR. Do not duplicate material from the whitepapers in this file; link to the
  authoritative docs instead.
- Run the cross-language conformance harness before pushing wire/encoding/generator changes:
  `bash tools/conformance/run.sh`.

## Useful Commands

Per-language test/bench commands live in each project's `CLAUDE.md`. Examples:

- PQID Python: `cd pqid/python && python3 -m pytest test_pqid.py -v`
- PQHash Python: `cd pqhash/python && python3 -m pytest test_pqhash.py -v`
- PQCrypt Python: `cd pqcrypt/python && python3 -m pytest test_pqcrypt.py -v`
- Conformance harness (all languages × all 3 projects): `bash tools/conformance/run.sh`

## Testing Signals

When behavior changes, make sure tests still cover:

- variant-byte validation and cross-rejection (each project rejects bytes it does not own)
- PQID monotonicity, sort order, clock regressions, HLC drift rejection, concurrency for shared generators
- binary/text round-trips and encoding malleability guards
- PQCrypt round-trip per suite, AD binding, header bit-flip rejection, suite-byte cross-rejection

## Docs To Update

If public behavior changes, update the relevant whitepaper LaTeX, project `CLAUDE.md`, release
notes under `<project>/docs/release-notes/`, and the applicable READMEs alongside the code. See
the documentation-surfaces discipline in [CLAUDE.md](CLAUDE.md).
