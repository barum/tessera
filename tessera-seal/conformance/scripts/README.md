# tessera-seal/conformance/scripts

Vector-generation scripts for TesseraSeal v1.

## Status

- `generate.py` — complete (PQCK-00003). Produces six KAT files under `../vectors/`.

## Run

```bash
cd tessera-seal
python3 conformance/scripts/generate.py
```

Output goes to `../vectors/` and replaces any existing files. Re-running on the same code **must** produce byte-identical JSON: the script seeds ML-KEM's internal DRBG with a fixed 48-byte NIST CAVS-style seed and freezes the timestamp clock to `1700000000000`.

Verify determinism:

```bash
python3 conformance/scripts/generate.py > /dev/null
shasum -a 256 ../vectors/*.json > /tmp/sha1
python3 conformance/scripts/generate.py > /dev/null
shasum -a 256 ../vectors/*.json > /tmp/sha2
diff /tmp/sha1 /tmp/sha2   # must be empty
```

If the diff is non-empty, the generator regressed and must be fixed before the regenerated vectors are committed.

## Pattern

Every generator function follows the same shape:

1. `_reset_kat_drbg()` — re-seed ML-KEM's DRBG so the function's ML-KEM outputs are deterministic regardless of prior calls.
2. Use the Python reference at `../../python/tessera_seal.py` to produce envelopes / commit tags / header bytes.
3. Append records to a list with the schema documented in `../README.md`.
4. Call `_write(VECTORS_DIR / "<file>.json", records)` — pretty-printed JSON, trailing newline.

The frozen clock (`KAT_TS_MS`) is set once at `main()` entry and unfrozen in the same function's `finally` block. Individual generator functions must NOT call `set_now_ms_for_testing(None)` or they will desync subsequent generators' headers.

## Adding a new vector file

1. Add a `make_<name>_vectors()` function following the pattern above.
2. Add a `_write(VECTORS_DIR / "<name>.json", records)` at the end.
3. Call it from `main()`.
4. Document the schema in `../README.md`.
5. Update every language conformance runner under `tools/conformance/<lang>/` to consume the new file.
