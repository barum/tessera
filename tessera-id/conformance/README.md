# TesseraID Conformance Test Vectors

Cross-language Known-Answer Tests (KATs) for the TesseraID wire format.

The Python reference (`tessera-id/python/tessera_id.py`) is the source of truth. Vectors
in `vectors/*.json` were generated against that reference and committed
verbatim. Every other implementation (C, C++, Go, Rust, TypeScript, Java,
CPython extension) MUST decode, encode, and validate them byte-identically.

## Layout

    vectors/
      decode.json              # 41-byte hex → {variant, timestamp_ms, counter, random_hex}
      encode_b64url.json       # 41-byte hex → 55-char Base64URL
      encode_crockford.json    # 41-byte hex → 66-char Crockford Base32
      decode_b64url.json       # 55-char Base64URL → 41-byte hex
      decode_crockford.json    # 66-char Crockford Base32 → 41-byte hex
      invalid.json             # malformed inputs and the error each implementation must raise
      hlc_overflow.json        # HLC counter-overflow regression (TesseraID-00001 detector)
      min_timestamp.json       # MIN_TIMESTAMP_MS helper vectors (added in TesseraID-00013)

## Vector record schema

Each file is a JSON array of records. Required fields:

  - `name` — short, unique within file
  - `op`   — one of: `decode`, `encode_b64`, `decode_b64`, `encode_crockford`,
             `decode_crockford`, `validate_invalid`, `hlc_overflow`,
             `validate_min_timestamp`

Op-specific fields are documented in each vector file's first record.

## Running the harness

    bash tessera-id/conformance/run.sh

This iterates every language adapter over every vector file and aggregates
results. Exit code 0 means all green; non-zero means at least one
language disagreed with the spec.

Each language adapter is a small CLI:

    <runner> <path-to-vectors.json>

It emits one line per vector — `PASS <name>` or `FAIL <name> got=<x> want=<y>`
— and exits non-zero on any FAIL.

## Regenerating vectors

Vectors are deterministic given a fixed input. To extend the set, modify
`scripts/generate.py` and re-run:

    python3 tessera-id/conformance/scripts/generate.py

This rewrites `vectors/*.json` from the Python reference. Commit the
result. If any other implementation disagrees, that implementation has a
bug — not the reference.

## Why this exists

Per-language tests catch per-language bugs. They do not catch
cross-language divergence: a Go encoder that produces a bit-different
Base64URL than Python is still self-consistent. The KAT harness is the
only place that pins the wire format across the polyglot fleet.

The first vector this caught: `hlc_overflow.json` — Go and Rust silently
wrapped the HLC counter at `MAX_COUNTER` while Python and C bumped the
logical time. See TesseraID-00001 for the fix.
