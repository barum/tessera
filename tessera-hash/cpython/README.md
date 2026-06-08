# tessera-hash/cpython/

Placeholder for a standalone CPython extension binding for TesseraHash.

## Current state

TesseraHash bindings are not yet a standalone extension. They ship inside
[`tessera-id/cpython/tessera_id_ext.c`](../../tessera-id/cpython/tessera_id_ext.c),
which currently exposes both TesseraID and TesseraHash from a single module
called `tessera_id_ext`.

This is a known inconsistency with the rest of the monorepo (every other
language has cleanly separated bindings under `tessera-id/<lang>/` and
`tessera-hash/<lang>/`). It is preserved during the monorepo restructure because
splitting the C extension into `tessera_id_ext` + `tessera_hash_ext` requires
re-partitioning the module init code and migrating consumer imports — a
follow-up change.

## What goes here when split happens

When `tessera_hash_ext` becomes a real extension, this directory will contain:

- `tessera_hash_ext.c` — module init + method table (tessera_hash-only).
- `setup.py` — builds against `../c/tessera_hash.c` and `../../common/c/keccak.c`.
- `test_tessera_hash_ext.py`
- `bench_tessera_hash_ext.py`

Until then, all CPython-level testing of TesseraHash goes through `tessera_id_ext`.
