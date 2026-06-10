# TesseraHash Conformance Test Vectors

Cross-language Known-Answer Tests (KATs) for the TesseraHash wire format.

The Python reference (`tessera-hash/python/tessera_hash.py`) is the source of truth. Vectors
in `vectors/*.json` were generated against that reference and committed verbatim. Every
other implementation (C, C++, Go, Rust, TypeScript, Java) MUST hash, encode, decode, and
validate them byte-identically.

This README documents the `tessera_hash_*` op schema; the sibling
[tessera-id/conformance/README.md](../../tessera-id/conformance/README.md) documents the
shared harness conventions (PASS/FAIL/SKIP line protocol, freeze policy, runner CLI shape) —
they apply here unchanged.

## Layout

    vectors/
      tessera_hash_hash_only.json         # content bytes → 64-byte SHAKE-256 tail
      tessera_hash_decode.json            # 73-byte hex → {variant, timestamp_ms, counter, tail_hex}
      tessera_hash_encode_b64.json        # 73-byte hex → 98-char Base64URL
      tessera_hash_decode_b64.json        # 98-char Base64URL → 73-byte hex
      tessera_hash_encode_crockford.json  # 73-byte hex → 117-char Crockford Base32
      tessera_hash_decode_crockford.json  # 117-char Crockford Base32 → 73-byte hex (incl. confusable folding)
      tessera_hash_verify.json            # (hash, content) → accept/reject
      tessera_hash_invalid.json           # malformed inputs and the error class each implementation must raise

## Vector record schema

Each file is a JSON array of records. Common fields:

- `name` — short, unique within the file.
- `op`   — one of: `tessera_hash_hash_only`, `tessera_hash_decode`, `tessera_hash_encode_b64`,
  `tessera_hash_decode_b64`, `tessera_hash_encode_crockford`, `tessera_hash_decode_crockford`,
  `tessera_hash_verify`, `tessera_hash_validate_invalid`.
- `doc`  — optional human-readable note. Records consisting only of documentation are
  emitted as explicit `SKIP` lines by every runner (TESS-00007), never fake-passed.

Op-specific fields:

| op | inputs | expectation |
|----|--------|-------------|
| `tessera_hash_hash_only` | `input_hex` (content bytes) | `expected_tail_hex` — the 64-byte SHAKE-256 tail |
| `tessera_hash_decode` | `input_hex` (73-byte wire form) | `expected` object: `variant`, `timestamp_ms`, `counter`, `tail_hex` |
| `tessera_hash_encode_b64` | `input_hex` | `expected_str` — exactly 98 chars, no padding |
| `tessera_hash_decode_b64` | `input_str` | `expected_hex` — the 73 wire bytes |
| `tessera_hash_encode_crockford` | `input_hex` | `expected_str` — exactly 117 chars |
| `tessera_hash_decode_crockford` | `input_str` (incl. lowercase / `I`/`L`/`O` confusables) | `expected_hex` |
| `tessera_hash_verify` | `input_hex` (hash) + `content_hex` | `expected` — boolean: tail matches content |
| `tessera_hash_validate_invalid` | `input_kind` (`raw`/`b64`/`crockford`) + `input_hex` or `input_str` | `expected_error` — the error class the implementation must raise (invalid length, unknown variant incl. reserved bytes 0x05/0x10/0x7F/0xFE, non-zero pad bits, bad characters) |

## Running the harness

    bash tools/conformance/run.sh

The cross-project harness at [../../tools/conformance/](../../tools/conformance/) consumes
this directory for every language with a runner; per-language runners live there (this
project keeps no runners of its own).

## Regenerating vectors

    python3 tessera-hash/conformance/scripts/generate_tessera_hash.py            # dry run (default)
    python3 tessera-hash/conformance/scripts/generate_tessera_hash.py --write    # actually rewrite vectors/*.json

The default invocation is a dry run, so `--help` or an accidental run can never silently
rewrite vectors. After `--write`, run `bash tools/scripts/check-vector-freeze.sh` —
committed records are **frozen append-only** (regeneration may add records or files but
MUST NOT change any existing record's bytes). Commit the result verbatim. If any other
implementation disagrees, that implementation has a bug — not the reference.
