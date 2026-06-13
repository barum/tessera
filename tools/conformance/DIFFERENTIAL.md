# Differential fuzzing across the 8 conformance runners

`tools/scripts/differential-fuzz.sh` (TESS-00016 / TP-097) is a cryptofuzz-style
differential oracle layered on top of the existing cross-language conformance
runners. It exists because Tessera has something almost no other greenfield
format project has: **eight first-party reference implementations of the same
normative wire format.** That redundancy is a correctness asset — feed the same
structured input to all eight and any disagreement is, by definition, a bug in
at least one of them.

## What it does

1. **Generate** `N` random *structured* inputs from the **Python reference**
   (the repo authority after the whitepaper): random valid TesseraIDs and
   TesseraHashes, plus targeted mutations —
   - wrong / reserved variant byte (`0x00`, `0x03`–`0xFF` as appropriate),
   - truncated and over-long binary buffers,
   - non-canonical Base64URL pad bits (low 2 bits of the final char set),
   - non-canonical Crockford pad bits (low 2 bits of the final char set),
   - confusable folding (`I/L → 1`, `O → 0`).
2. **Pin the oracle.** Each record's *expected* result is exactly what the
   Python reference does with that input — a clean decode (with the decoded
   fields) or a rejection (`validate_invalid`). The generator **confirms**
   Python's behavior before emitting each record, so the vector can never claim
   an expectation Python doesn't actually produce. If a mutation Python happens
   to accept slips through, it is dropped rather than mislabeled.
3. **Write** the records to a single throwaway vector file under `$TMPDIR`
   (e.g. `/tmp/tessera-differential.XXXXXX/differential.json`). **This is never
   written to a repo `conformance/vectors/` directory** — the shipped KAT
   vectors are the frozen, append-only compatibility contract
   (`tools/scripts/check-vector-freeze.sh`); differential inputs are disposable
   noise by construction and must not pollute it.
4. **Feed the same file to every language's general conformance runner**
   (`python c cpp go rust typescript java cpython`) and collect each runner's
   `PASS`/`FAIL`/`SKIP` lines.
5. **Diff.** Because *expected* is the Python oracle, a `FAIL` line from any
   language is precisely a divergence from Python (different decoded bytes, or
   accept-vs-reject disagreement). A crash (non-zero exit with no `FAIL` line)
   is also treated as a divergence.

A clean run exits `0`. **Any** divergence writes a minimal repro vector
(only the diverging records) and exits `1`, leaving the work directory in place
for inspection.

## Surface covered

The differential covers the decode surfaces **all eight** implementations share
— TesseraID and TesseraHash:

| op | what it differentiates |
|----|------------------------|
| `decode` / `tessera_hash_decode` | binary wire-form field parsing |
| `decode_b64` / `tessera_hash_decode_b64` | Base64URL decode + canonical pad-bit guard |
| `decode_crockford` / `tessera_hash_decode_crockford` | Crockford decode + confusable folding + pad-bit guard |
| `validate_invalid` / `tessera_hash_validate_invalid` | reject-path agreement (variant, length, non-canonical encodings) |

TesseraSeal is intentionally **out of differential scope** here: only four
languages (Python, C, Go, Rust) ship a `tessera_seal_runner`, and the seal
decode path is exercised by the per-language structured fuzzers instead
(`tessera-seal/{rust/fuzz,go/fuzz_test.go,c/fuzz_decrypt.c}`, TP-096). A 4-way
seal differential is a natural follow-up once the C++/TS/Java/CPython seal ports
land (TSEAL-00030 series).

## Usage

```bash
# 200 inputs across all 8 languages (the acceptance run)
bash tools/scripts/differential-fuzz.sh

# More inputs
N=500 bash tools/scripts/differential-fuzz.sh

# Reproducible: pin the seed (printed on every run)
TESSERA_DIFF_SEED=20260610 bash tools/scripts/differential-fuzz.sh

# Subset of languages (quick local loop)
TESSERA_DIFF_LANGS="python go rust" bash tools/scripts/differential-fuzz.sh

# Skip slow toolchains
TESSERA_DIFF_SKIP="cpython java" bash tools/scripts/differential-fuzz.sh
```

The seed is **logged on every run** and is the only state needed to reproduce a
campaign — there are no hidden fixed seeds (cf. TP-101). Re-run with
`TESSERA_DIFF_SEED=<printed value>` to regenerate the exact same inputs.

## When it finds a divergence

The script writes `repro.json` (the diverging records only) into the work dir
and prints the path. To reproduce one language in isolation, feed that file to
the language's runner the same way `run.sh` does, e.g.:

```bash
python3 tools/conformance/python/python_runner.py /tmp/tessera-differential.XXXX/repro.json
node    tools/conformance/typescript/dist/conformance_runner.js /tmp/.../repro.json
target/release/conformance_runner /tmp/.../repro.json
```

Then resolve per the repo authority order (whitepaper → Python → C → rest):
the implementation that disagrees with Python is the one to fix — **never**
change the spec or the Python reference to match an outlier.

If the divergence represents a genuine, newly-discovered edge case, promote the
minimized input into the **frozen KAT vectors** as a *new appended record* (per
TP-023 append-only freeze discipline — `check-vector-freeze.sh`), so the
regression is locked in permanently. The differential vector itself stays in
`/tmp`; only the curated, minimized record graduates into
`conformance/vectors/`.

## CI

This is a manual-dispatch tool (cost control, consistent with the per-language
workflows being `workflow_dispatch`-only). Run it before releases and after any
change to a decoder, encoder, or validation path. It is not on the
auto-triggered `conformance.yml` gate; the frozen KAT vectors remain the
blocking contract.

## Latest local run

`N=200`, all 8 languages, seed `20260610`: **clean** — all 200 structured
inputs decoded byte-identically across `python c cpp go rust typescript java
cpython`. (Numbers are local until CI confirms; CI for this tool is manual
dispatch.)
