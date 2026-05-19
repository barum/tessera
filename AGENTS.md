# AGENTS.md

## Project Shape
PQID is a polyglot reference repository for a 41-byte post-quantum sortable identifier.
Start with [pqid/README.md](pqid/README.md) for the language tree, then use the whitepaper and reference implementations below as the source of truth:

- [PQID_Whitepaper.pdf](PQID_Whitepaper.pdf)
- [pqid/docs/](pqid/docs/)
- [pqid/python/pqid.py](pqid/python/pqid.py)
- [pqid/c/pqid.h](pqid/c/pqid.h)

## What To Preserve
- Wire format is fixed at 41 bytes.
- Variant bytes are `0x01` for Standard and `0x02` for HLC.
- Canonical encodings are Base64URL (55 chars) and Crockford Base32 (66 chars).
- StandardGenerator is intentionally not internally locked; HLCGenerator must be internally locked.
- HLC drift handling is part of the contract and must stay bounded at 60 seconds.

## Work Style
- Use the reference implementations to confirm behavior before changing any other language.
- Keep implementations aligned across languages when changing wire format, encoding, validation, or generator semantics.
- Prefer the smallest change that keeps tests and benchmarks consistent with the spec.
- Do not duplicate material from the whitepaper in this file; link to the authoritative docs instead.

## Useful Commands
- Python: `cd pqid/python && python3 -m pytest test_pqid.py -v`
- Python bench: `cd pqid/python && python bench.py`
- Go: `cd pqid/go && go test ./...`
- Go bench: `cd pqid/go && go test -bench=.`
- Rust: `cd pqid/rust && cargo test --release`
- Rust bench: `cd pqid/rust && cargo bench`
- TypeScript: `cd pqid/typescript && npm install && npm test`
- TypeScript bench: `cd pqid/typescript && npm run bench`
- C: `cd pqid/c && make test`
- C bench: `cd pqid/c && make bench`
- C++: `cd pqid/cpp && make test`
- C++ bench: `cd pqid/cpp && make bench`
- Java: `cd pqid/java && make test`
- Java bench: `cd pqid/java && make bench`
- CPython extension: `cd pqid/cpython && python3 setup.py build_ext --inplace && python test_pqid_ext.py`

## Testing Signals
When behavior changes, make sure tests still cover:
- variant byte validation
- monotonicity and sort order
- binary/text round-trips
- clock regressions
- HLC drift rejection
- concurrency for shared generator paths

## Docs To Update
If public behavior changes, update the relevant source docs under [pqid/docs/](pqid/docs/) and the applicable implementation README or reference comments alongside the code.