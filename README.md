# PQID — Post-Quantum Identifier

A 41-byte, time-sortable identifier with a 256-bit random tail, designed to retain
~128-bit security against Grover-style quantum search while remaining a practical
drop-in for ULID/UUIDv7-shaped workloads.

This repository is **specification-first and polyglot**: the wire format is fixed,
and every language directory under [pqid/](pqid/) is a reference implementation of
that single contract.

- Whitepaper (published PDF): [PQID_Whitepaper.pdf](PQID_Whitepaper.pdf)
- Whitepaper sources: [pqid/latex/](pqid/latex/) (LaTeX) and [pqid/docs/](pqid/docs/) (DOCX pipeline)
- Implementations index: [pqid/README.md](pqid/README.md)
- Agent / contributor guide: [AGENTS.md](AGENTS.md)

## Wire format (41 bytes)

```
0       6      7       9                              41
+-------+------+-------+------------------------------+
|  TS   | VAR  |  CTR  |          Random              |
| 48 b  |  8 b | 16 b  |           256 b              |
+-------+------+-------+------------------------------+
```

- `VARIANT_STANDARD = 0x01` — wall-clock ms + ms-scoped counter
- `VARIANT_HLC      = 0x02` — Hybrid Logical Clock for distributed causality

## Encodings

| Form              | Length    | Use                                  |
|-------------------|-----------|--------------------------------------|
| Base64URL         | 55 chars  | Canonical wire form, no padding      |
| Crockford Base32  | 66 chars  | Human-typable, case-insensitive      |

Crockford decode folds the standard confusables (`I`/`L` → `1`, `O` → `0`) and
rejects inputs whose top 2 bits (of the 330-bit decoded value) are non-zero.

## Variants at a glance

- **Standard (0x01)** — single-node or per-thread generators. Lock-free by design:
  one generator instance per thread, or wrap externally. Counter starts at a random
  offset each new millisecond; same-ms collisions bump by a small random step so
  values stay opaque to outside observers.
- **HLC (0x02)** — distributed causality. Generator is internally locked because
  `(l, c)` must be read-modify-written atomically. Observing a peer HLC more than
  60 s ahead of local physical time is a hard error (`HLCDriftError`), never a
  silent clamp.

See [pqid/python/pqid.py](pqid/python/pqid.py) for the readable reference, and
[pqid/c/pqid.h](pqid/c/pqid.h) for the canonical C ABI.

## Languages

| Language    | Path                                       | Notes                                       |
|-------------|--------------------------------------------|---------------------------------------------|
| Python      | [pqid/python/](pqid/python/)               | Reference impl + `pqid_fast.py` for benches |
| C           | [pqid/c/](pqid/c/)                         | Canonical C ABI, offsets defined in `pqid.h` |
| C++         | [pqid/cpp/](pqid/cpp/)                     | Header-only (`pqid.hpp`)                    |
| Go          | [pqid/go/](pqid/go/)                       | Idiomatic Go, `go test ./...`               |
| Rust        | [pqid/rust/](pqid/rust/)                   | `no_std`-friendly core                      |
| TypeScript  | [pqid/typescript/](pqid/typescript/)       | Node 18+ / browser                          |
| Java        | [pqid/java/](pqid/java/)                   | Plain `make`-driven build                   |
| CPython ext | [pqid/cpython/](pqid/cpython/)             | C extension mirroring `pqid_fast.py`        |

Benchmark snapshots from each language live in [pqid/benchmarks/](pqid/benchmarks/).

## Quick start

```bash
# Python reference + tests
cd pqid/python && python3 -m pytest test_pqid.py -v

# Go
cd pqid/go && go test ./... && go test -bench=.

# Rust (release for accurate benches)
cd pqid/rust && cargo test --release && cargo bench

# TypeScript
cd pqid/typescript && npm install && npm test
```

The full per-language command matrix (including C, C++, Java, CPython extension,
and how to run a single test) is in [CLAUDE.md](CLAUDE.md).

## Contributing

The wire format, variant bytes, encoding lengths, generator locking contract, and
60 s HLC drift bound are **hard invariants**. Changing any of them is a spec
change: update the whitepaper sources under [pqid/latex/](pqid/latex/) and
[pqid/docs/](pqid/docs/), then port the change to **every** language so a PQID
generated in one decodes identically in all the others.

For optimization or bug-fix work confined to a single language, keep observable
behavior identical — if a test had to be modified to accept your change, it's a
spec change, not an implementation change.

See [AGENTS.md](AGENTS.md) and [CLAUDE.md](CLAUDE.md) for the full rules.

## License

Apache-2.0 — see [LICENSE](LICENSE).
