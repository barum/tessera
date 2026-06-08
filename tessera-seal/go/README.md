# tessera-seal/go

Go reference implementation of TesseraSeal v1.

## Status

- Implementation: complete (TSEAL-00006).
- Tests: ~70 pass (self-contained + KAT consumption from `../conformance/vectors/`).
- Cross-language interop confirmed in both directions (Python ↔ Go) and transitively with C (Python KATs consumed by both).

## Dependencies

- Go 1.26+ (uses `crypto/mlkem` from the stdlib — no `filippo.io/mlkem` external dep needed).
- `golang.org/x/crypto/sha3` — SHA3-256 and SHAKE-256.
- `golang.org/x/crypto/chacha20poly1305` — optional ChaCha suite.

## Build / test

```bash
cd tessera-seal/go
go test ./...               # full test suite
go test -bench=. -benchmem  # microbenchmarks
```

Tests read `../conformance/vectors/*.json` at runtime; run from `tessera-seal/go/`.

## ML-KEM key encoding

Go's `crypto/mlkem` exposes `DecapsulationKey1024.Bytes()` as the **64-byte FIPS 203 seed** (d || z), not the expanded 3168-byte private key. The conformance vectors emit both forms:

- `private_key_seed_hex` (64 B) — what Go consumes via `mlkem.NewDecapsulationKey1024(seed)`.
- `private_key_hex` (3168 B) — what Python and C consume directly.

Either form yields the same envelope decryptions; the seed form is the canonical FIPS 203 representation.

## Authority

The Python reference at `../python/tessera_seal.py` is the readable canonical source. The C header at `../c/tessera_seal.h` pins the canonical ABI for stack-level FFI ports; this Go package mirrors that ABI in idiomatic Go.
