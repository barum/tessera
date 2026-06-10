# tessera-seal/benchmarks

One `.txt` file per language, refreshed when a performance-relevant change lands. Format mirrors
`tessera-id/benchmarks/` exactly: left-aligned operation name (~40 chars), right-aligned ops/sec,
ns/op in parentheses. Captures exist for the four languages that have a bench harness today:
Python, C, Go, Rust.

## Provenance rules

- **Captured outputs are verbatim tool output; never hand-edited.** If a number needs to change,
  re-run the bench and overwrite the whole capture file. Captures are stdout-only.
- Every re-run on different hardware MUST update the hardware section below in the same change.

## Hardware (current captures)

| Field | Value |
|-------|-------|
| Machine | Apple M4 Max (physical, `sysctl -n machdep.cpu.brand_string`) |
| Cores | 14 (`sysctl -n hw.ncpu`) |
| OS | macOS 26.5.1 (build 25F80, `sw_vers`) |
| CPU governor | n/a (macOS performs its own frequency management; no isolation/pinning applied) |
| Toolchains | Python 3.14.3 (kyber-py), OpenSSL 3.6.2 (Homebrew, C leg), Go 1.26.1, Rust/cargo 1.96.0 |
| Captured | 2026-06-10 |

Earlier captures in this directory (May–June 2026) were produced in a virtualized AI-agent sandbox
(generic KVM CPU string); they were regenerated from scratch on the hardware above (TESS-00011).

## Operations measured per language

| Operation | Target |
|-----------|--------|
| `keygen` | ML-KEM-1024 keypair generation |
| `encrypt_1KB` | Encrypt 1 KiB plaintext under fresh recipient |
| `encrypt_1MB` | Encrypt 1 MiB plaintext under fresh recipient |
| `decrypt_1KB` | Decrypt the 1 KiB envelope |
| `decrypt_1MB` | Decrypt the 1 MiB envelope |
| `peek_header` | Parse header without authentication |
| `encrypt/decrypt_1KB` (ChaCha20-Poly1305) | Suite `0x02` 1 KiB round-trip legs |
| `keygen / encrypt_1KB / decrypt_1KB` (hybrid `0x06`) | X25519+ML-KEM-1024 — Python/Go/Rust (C: TSEAL-00030) |
| `encrypt_with_tessera_id_ad` | Same as `encrypt_1KB` but with a 41-byte TesseraID as AD (Python harness only today) |

The 1 MiB rows are dominated by AEAD throughput; the 1 KiB rows by ML-KEM-1024
encapsulation/decapsulation. Python's absolute numbers are orders of magnitude below the compiled
languages because `kyber-py` is a pure-Python readability-first ML-KEM — that is expected and
documented (the Python reference optimizes for spec readability, not speed).

## How to reproduce

Per-language commands (each capture is harness stdout only; full run is well under two minutes
per language on the hardware above — iteration counts are fixed in each harness source):

```bash
# Python (iteration counts documented at the top of python/bench.py)
cd tessera-seal/python && python3 bench.py > ../benchmarks/python.txt

# C (needs OpenSSL 3.5+; Homebrew openssl@3 is auto-discovered by the Makefile)
cd tessera-seal/c && make bench_tessera_seal && ./bench_tessera_seal > ../benchmarks/c.txt

# Go
cd tessera-seal/go && go test -bench=. -benchmem > ../benchmarks/go.txt

# Rust (the bench is the `tessera-seal-bench` [[bin]] target, not a `cargo bench` target)
cd tessera-seal/rust && cargo run --release --bin tessera-seal-bench > ../benchmarks/rust.txt
```

## Headline numbers (2026-06-10 captures, suite 0x01 unless noted)

| Op (ops/sec) | Python | C (OpenSSL) | Go | Rust |
|--------------|--------|-------------|-----|------|
| `keygen` | 422 | 25,560 | 21,736 | 30,374 |
| `encrypt_1KB` | 343 | 19,569 | 17,624 | 23,385 |
| `decrypt_1KB` | 263 | 8,669 | 17,555 | 21,495 |
| `encrypt_1MB` | 241 | 394 | 673 | 161 |
| `decrypt_1MB` | 189 | 420 | 748 | 160 |
| `peek_header` | 1,188,008 | 489,763,934 | 208,985,372 | 532,571,146 |

Go rows are derived from `go test -bench` ns/op (1e9 / ns/op); all other rows are the harnesses'
own ops/sec output. See the per-language `.txt` files for the verbatim captures, including the
ChaCha20-Poly1305 and hybrid `0x06` rows. Whitepaper/doc tables should cite these capture files
rather than copying numbers forward.
