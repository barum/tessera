# pqid — CLAUDE.md

Project-specific guidance for the PQID identifier format. The repo-wide umbrella file is at [../CLAUDE.md](../CLAUDE.md).

## What this project is

PQID is a **41-byte sortable, post-quantum-era identifier**. The wire format is normative; the per-language code is a reference implementation. Authoritative sources, in order:

1. The whitepaper PDF at [../PQID_Whitepaper.pdf](../PQID_Whitepaper.pdf) and its LaTeX source at [latex/](latex/).
2. The Python reference at [python/pqid.py](python/pqid.py) and the C header at [c/pqid.h](c/pqid.h) — these define the canonical API shape.
3. [../AGENTS.md](../AGENTS.md) — invariants that MUST NOT be silently broken.

When sources disagree, whitepaper wins, then Python, then C.

## Hard invariants (do not change without spec update)

These are checked by tests in every language. Breaking them in one implementation is a bug in that implementation, not a design decision:

- **41 bytes total**, laid out as `TS(6) || VARIANT(1) || CTR(2) || RANDOM(32)`, big-endian.
- **Variant byte**: `0x01` = Standard, `0x02` = HLC. Any other value is a decode error (`UnknownVariant` / `PQID_E_UNKNOWN_VARIANT`). `0x00` and `0xFF` are **permanently reserved** and MUST NOT be assigned in future revisions (they defensively prevent zero-filled / all-ones buffers from passing validation). `0x03`–`0xFE` are reserved-future.
- **Canonical encodings**: Base64URL → exactly 55 chars, no padding. Crockford Base32 → exactly 66 chars, case-insensitive on decode, `I/L→1`, `O→0` confusables accepted.
- **Crockford decode** must reject inputs whose top 2 bits (of the 330-bit decoded value) are non-zero — the 41-byte payload occupies only 328 bits.
- **HLC drift bound**: `HLC_MAX_DRIFT_MS = 60_000`. Observing a peer HLC more than 60s ahead of local physical time is a hard error (`HLCDriftError`), not a silent clamp.
- **Locking contract**:
  - `StandardGenerator` is **not** internally locked. One-per-thread, or caller wraps it. The module-level `new()` in Python does its own locking — don't push that locking into the class.
  - `HLCGenerator` **is** internally locked. The (l, c) read-modify-write must be atomic.
- **Counter behavior**:
  - Standard: random starting offset per new ms; small random step (1..16) on same-ms collisions; on counter exhaust, spin to next ms and reseed.
  - HLC: counter increments are deterministic from (l_old, l_msg, pt) — see [python/pqid.py:170-225](python/pqid.py#L170-L225) for the canonical merge rule. Counter overflow bumps `l` by 1 and resets `c` to 0.

If a change is meant to alter any of the above, it is a spec change: update [latex/](latex/), the [docs/](docs/) sources, AND every language implementation in lockstep.

## Files to keep aligned

When changing wire/encoding/validation:

- [python/pqid.py](python/pqid.py) and [python/pqid_fast.py](python/pqid_fast.py) (the optimized variant used in benches)
- [c/pqid.h](c/pqid.h), [c/pqid.c](c/pqid.c)
- [cpp/pqid.hpp](cpp/pqid.hpp)
- [go/pqid.go](go/pqid.go)
- [rust/src/lib.rs](rust/src/lib.rs)
- [typescript/pqid.ts](typescript/pqid.ts)
- [java/src/](java/src/)
- [cpython/pqid_ext.c](cpython/pqid_ext.c) (must match `pqid_fast.py`'s API, not `pqid.py`'s)

## Build, test, bench

Per-language commands (run from repo root):

| Lang        | Test                                                                  | Bench                          |
|-------------|-----------------------------------------------------------------------|--------------------------------|
| Python      | `cd pqid/python && python3 -m pytest test_pqid.py -v`                 | `cd pqid/python && python bench.py` |
| Go          | `cd pqid/go && go test ./...`                                         | `cd pqid/go && go test -bench=.` |
| Rust        | `cd pqid/rust && cargo test --release`                                | `cd pqid/rust && cargo bench`  |
| TypeScript  | `cd pqid/typescript && npm install && npm test`                       | `cd pqid/typescript && npm run bench` |
| C           | `cd pqid/c && make test`                                              | `cd pqid/c && make bench`      |
| C++         | `cd pqid/cpp && make test`                                            | `cd pqid/cpp && make bench`    |
| Java        | `cd pqid/java && make test`                                           | `cd pqid/java && make bench`   |
| CPython ext | `cd pqid/cpython && python3 setup.py build_ext --inplace && python test_pqid_ext.py` | `python bench_pqid_ext.py` |

Run a single Python test: `cd pqid/python && python3 -m pytest test_pqid.py::TestName::test_method -v`.
Run a single Go test: `cd pqid/go && go test -run TestName ./...`.
Run a single Rust test: `cd pqid/rust && cargo test --release test_name -- --nocapture`.

Bench output is checked into [benchmarks/](benchmarks/) (one file per language) — refresh the matching file when you re-run benches that are meaningful to a change.

## Tests that must keep passing in every language

When changing generator, encoder, or decoder code, the test surface that has to stay green is:

- Variant byte validation (accept 0x01/0x02, reject everything else).
- Strict monotonicity / sort order within a single generator across ≥10k IDs.
- Binary ↔ Base64URL round-trip (55 chars, no padding).
- Binary ↔ Crockford Base32 round-trip (66 chars, including confusable folding).
- Clock-regression handling for Standard (timestamp clamps, never goes backward).
- HLC drift rejection (peer 60s+ ahead → error).
- Concurrency for shared-generator paths (HLC, and Python module-level `new`).

If you add a new test, mirror it to the other languages.

## Whitepaper

The whitepaper has two source forms that must agree:

- LaTeX (typeset PDF): [latex/main.tex](latex/main.tex) with per-section `secNN_*.tex` files; build with `cd pqid/latex && make`.
- DOCX-generation JS pipeline: [docs/build_whitepaper.js](docs/build_whitepaper.js) plus `wp_section*.js` modules; produces [docs/PQID_Whitepaper.docx](docs/PQID_Whitepaper.docx).

The root [../PQID_Whitepaper.pdf](../PQID_Whitepaper.pdf) is the published artifact. When the spec changes, both source pipelines must be updated.

## Scope discipline

- Do not introduce a new wire variant, new encoding, or new field without first updating the whitepaper and aligning every language.
- Do not change `StandardGenerator` to be internally locked, even if it looks like a bug. It is deliberate — see [python/pqid.py:96-104](python/pqid.py#L96-L104).
- Do not relax the Crockford 2-bit overflow check or the 60s HLC drift bound without a spec change.
- Optimization PRs that only touch one language are fine and don't require porting, **as long as observable behavior is identical**.
