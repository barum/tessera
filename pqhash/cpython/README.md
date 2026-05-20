# pqhash/cpython/

Placeholder for a standalone CPython extension binding for PQHash.

## Current state

PQHash bindings are not yet a standalone extension. They ship inside
[`pqid/cpython/pqid_ext.c`](../../pqid/cpython/pqid_ext.c), which currently
exposes both PQID and PQHash from a single module called `pqid_ext`.

This is a known inconsistency with the rest of the monorepo (every other
language has cleanly separated bindings under `pqid/<lang>/` and
`pqhash/<lang>/`). It is preserved during the monorepo restructure because
splitting the C extension into `pqid_ext` + `pqhash_ext` requires
re-partitioning the module init code and migrating consumer imports — a
follow-up change.

## What goes here when split happens

When `pqhash_ext` becomes a real extension, this directory will contain:

- `pqhash_ext.c` — module init + method table (pqhash-only).
- `setup.py` — builds against `../c/pqhash.c` and `../../common/c/keccak.c`.
- `test_pqhash_ext.py`
- `bench_pqhash_ext.py`

Until then, all CPython-level testing of PQHash goes through `pqid_ext`.
