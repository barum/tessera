---
name: tessera-conformance
description: This skill should be used when the user wants to "run the conformance harness", "regenerate KAT vectors", "add a new conformance test", "debug a cross-language mismatch", "fix a failing conformance runner", "skip a language in conformance", "update conformance for a new variant", "add a hybrid_*.json vector", "flip a language to hybrid-supported", or any task that touches tools/conformance/, the per-language runners, or the JSON KAT vectors under tessera-id/conformance/vectors/, tessera-hash/conformance/vectors/, and tessera-seal/conformance/vectors/.
version: 1.3.0
created: 2026-05-20T00:00:00Z
updated: 2026-06-10T00:00:00Z
---

# tessera-conformance — Cross-language KAT harness

The conformance harness is the single quality signal that catches polyglot drift. It's the automatic CI gate (`.github/workflows/conformance.yml` runs on every pull_request and push to main — the only auto-triggered workflow; the blocking step is the 4-language alpha run, the full-8 step is informational) and should be the first thing you run when changing wire/encoding/generator behavior. See umbrella discipline in [../../../CLAUDE.md](../../../CLAUDE.md).

## Layout

- **Entrypoint**: [tools/conformance/run.sh](../../../tools/conformance/run.sh)
- **Runners**: [tools/conformance/<lang>/](../../../tools/conformance/) — one per language: python, c, cpp, go, rust, typescript, java, cpython. TesseraSeal has dedicated per-language runners **only** for python, c, go, rust at `tools/conformance/<lang>/tessera_seal_runner*`. C++/TypeScript/Java/CPython ext have **no** tessera-seal runner, so the harness **skips** the TesseraSeal vector directory for them (they run tessera-id/tessera-hash only). There is no Python-runner fallback for TesseraSeal.
- **Vectors**:
  - TesseraID: [tessera-id/conformance/vectors/](../../../tessera-id/conformance/vectors/)
    - `decode.json` — 41-byte hex → field decomposition
    - `encode_b64url.json`, `decode_b64url.json` — Base64URL round-trip
    - `encode_crockford.json`, `decode_crockford.json` — Crockford Base32 round-trip
    - `invalid.json` — malformed inputs, expected per-impl errors (includes TesseraSeal `0x04` cross-rejection)
    - `hlc_overflow.json` — HLC counter saturation regression (TESSERA_ID-00001)
    - `min_timestamp.json` — `MIN_TIMESTAMP_MS` helper vectors (TESSERA_ID-00013)
  - TesseraHash: [tessera-hash/conformance/vectors/](../../../tessera-hash/conformance/vectors/) — analogous coverage. Includes TesseraSeal `0x04` cross-rejection in `tessera_hash_invalid.json`.
  - TesseraSeal: [tessera-seal/conformance/vectors/](../../../tessera-seal/conformance/vectors/)
    - `decrypt.json` — KAT round-trip for suites 0x01/0x02
    - `ad_binding.json` — positive + negative AD binding
    - `peek_header.json` — structural header parsing
    - `invalid.json` — bad variant, bad suite, truncated, AD mismatch
    - `commitment.json` — UtC tag KATs
    - `min_timestamp.json` — shape-based helper vector

    A `kyberslash_regression.json` KyberSlash-class timing-regression vector is **planned/backlog, not yet shipped** — the current set above does not include it. KyberSlash posture today rests on the pinned post-patch ML-KEM libraries plus the manual timing-histogram check (open item in `tessera-seal/docs/security-audit-v1.2.md`).
    - `hybrid_decrypt.json` (4 records) — KAT round-trip for hybrid suite `0x06`
    - `hybrid_ad_binding.json` (4 records) — hybrid AD binding positive + negative
    - `hybrid_peek_header.json` (1 record) — hybrid header parse
- **Schema docs**: [tessera-id/conformance/README.md](../../../tessera-id/conformance/README.md), [tessera-seal/conformance/README.md](../../../tessera-seal/conformance/README.md).

## Hybrid suite `0x06` skip logic

`tools/conformance/run.sh` filters `hybrid_*.json` vector files per language via [`hybrid_supported()`](../../../tools/conformance/run.sh):

```bash
hybrid_supported() {
    case "$1" in
        python) return 0 ;;   # TSEAL-00021, v1.2
        rust)   return 0 ;;   # TSEAL-00028, v1.3
        go)     return 0 ;;   # TSEAL-00029, v1.3
        *)      return 1 ;;   # C/C++/TS/Java/CPython ext — v1.4 backlog
    esac
}
```

Languages without hybrid skip the `hybrid_*.json` files entirely and must reject suite `0x06` as `UNKNOWN_SUITE` for non-hybrid envelopes. When porting hybrid to a new language: (1) implement hybrid in the language, (2) update the language's conformance runner to accept 96-byte seeds (the standard runners hard-coded `len(seed) != 64`), (3) flip the language's `hybrid_supported()` entry, (4) verify the language's PASS count rises by 9 (the three hybrid_*.json files).

## Latest state (v1.3, 2026-06-08, TSEAL-00035)

```
language         PASS     FAIL
python            267        0       (258 standard + 9 hybrid)
c                 258        0       (no hybrid yet; TSEAL-00030 backlog)
go                267        0       (258 + 9 hybrid; TSEAL-00029)
rust              267        0       (258 + 9 hybrid; TSEAL-00028)
```

C++, TypeScript, Java, CPython ext have no tessera-seal runner, so they **skip the TesseraSeal vector directory entirely** (they run tessera-id/tessera-hash only, `207 0` each). Only python/c/go/rust run TesseraSeal conformance. The full 8-language run is green. The two new TesseraSeal `invalid.json` records (`suite_0x05_rejected`, `bad_key_suite_mismatch`, TSEAL-00035) raised each alpha language by +2.

## Run it

```bash
# Full harness (8 languages × 3 projects: tessera-id + tessera-hash + tessera-seal)
bash tools/conformance/run.sh

# Skip slow toolchains locally — useful when CPython ext or Java JDK isn't installed
TESSERA_CONFORMANCE_SKIP="cpython java" bash tools/conformance/run.sh

# Per-language manual run (after building the runner)
tools/conformance/python/run.py tessera-id/conformance/vectors/decode.json
```

Exit code 0 = all languages green. Anything else = at least one runner failed; the runner prints the offending vector record.

## When to update vectors

You **regenerate vectors** when:

- A new variant byte is allocated ([[variant-bytes]] in memory).
- A new encoding length / form is added.
- An error message or error-code mapping changes for `invalid.json`.
- A new property is being asserted (e.g., monotonicity under a specific clock pattern).

You **don't** regenerate when fixing a per-language bug that brings an outlier back to the spec — the vectors are already right; the outlier was wrong.

### Regeneration workflow

1. Land the change in the Python reference first (`tessera-id/python/tessera_id.py` or `tessera-hash/python/tessera_hash.py`).
2. Use the Python reference to emit fresh JSON vectors. Each vector file has a `tools/`-side generator under `tessera-id/conformance/` or a script noted in `tessera-id/conformance/README.md`.
3. Commit the regenerated JSON **verbatim** — don't reformat. Vector files are byte-pinned by design.
4. Run `bash tools/conformance/run.sh` until all languages pass against the new vectors.
5. If a language can't pass without a port: do the port. Don't widen the vector to accept the outlier's output.

## When to add a new vector

For any bug fix or new feature: add at least one positive and one negative KAT entry that would have caught the bug. Specifically:

- **Variant byte work** → entry in `invalid.json` for each newly-reserved byte (TesseraID and TesseraHash decoders both).
- **Encoding work** → entry in the relevant encode/decode file with the exact string and 41/73-byte payload.
- **Generator work (timing, locking, drift)** → entry in `hlc_overflow.json` or a new file documented in the conformance README.
- **Helper functions** (`min_timestamp` style) → dedicated vector file, indexed in the conformance README.

## Schema reminder

Each vector file is a JSON array of records. Common fields:

```json
{
  "name": "human-readable id, must be unique within the file",
  "op": "decode | encode_b64url | encode_crockford | ...",
  "input_hex": "...",          // for decode-from-bytes
  "input_str": "...",          // for decode-from-encoded
  "expected": { ... },         // op-specific
  "should_fail": false,
  "error_kind": "UNKNOWN_VARIANT | BAD_LENGTH | ..."   // when should_fail
}
```

TesseraHash op-name strings in the `op` field are `tessera_hash_*` (e.g. `tessera_hash_decode`, `tessera_hash_encode_b64url`); these must match the dispatch keys in every runner exactly. Refer to [tessera-id/conformance/README.md](../../../tessera-id/conformance/README.md) for the authoritative schema.

## Debugging a red runner

1. `bash tools/conformance/run.sh 2>&1 | tee /tmp/conf.log`
2. Find the first failing record — runners print `FAIL <file>#<index>: <name>` then a diff.
3. Open the offending vector. Compare against the Python reference output for the same input.
4. If Python disagrees with the vector: the vector is out of date — regenerate.
5. If Python matches the vector but another language disagrees: fix that language. Per [[authority-order]], Python is right.
6. After the fix, re-run the full harness — don't trust a single-language pass.

## Skipping locally

`TESSERA_CONFORMANCE_SKIP="lang1 lang2 ..."` — space-separated language ids matching subdirs of `tools/conformance/`. Useful when:

- CPython extension isn't built (`cpython`).
- Java toolchain not installed (`java`).
- TypeScript deps not installed (`typescript`).

**CI skip shape.** `.github/workflows/conformance.yml` uses `TESSERA_CONFORMANCE_SKIP="cpython java cpp typescript"` for its blocking alpha step (Python+C+Go+Rust) and runs the full 8 languages with no skips in the informational step. Never add skips to the blocking step beyond those four. Unknown skip tokens now produce a WARNING. The summary table has a SKIP column (doc pseudo-records + records a runner cannot execute).

## When you're done

In the PR / commit summary, name:

- Vector files touched (path + brief).
- New positive/negative records added.
- Output of `bash tools/conformance/run.sh` (paste the green tail).
- Whether the Python reference was the source of the new vectors (it should be).

If a PR changes vectors but doesn't touch Python first, that's a process bug — block on it.
